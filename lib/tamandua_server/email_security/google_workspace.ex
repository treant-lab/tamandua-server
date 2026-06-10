defmodule TamanduaServer.EmailSecurity.GoogleWorkspace do
  @moduledoc """
  Google Workspace Email Security Integration.

  Provides integration with Google Workspace APIs for:
  - Gmail API for email access and search
  - Admin SDK for email logs and reports
  - DLP policy integration
  - Gmail quarantine management
  - Phishing and spam detection

  This module implements a GenServer that periodically polls Google Workspace
  for email security events and forwards them to the detection engine.

  ## Configuration

  Required configuration in config.exs:

      config :tamandua_server, TamanduaServer.EmailSecurity.GoogleWorkspace,
        service_account_key: "/path/to/service-account.json",
        admin_email: "admin@domain.com",
        poll_interval_ms: 60_000

  ## Required Google Workspace API Scopes

  - https://www.googleapis.com/auth/gmail.readonly
  - https://www.googleapis.com/auth/admin.reports.audit.readonly
  - https://www.googleapis.com/auth/admin.directory.user.readonly
  """

  use GenServer
  require Logger

  alias TamanduaServer.EmailSecurity.EmailEvent
  alias TamanduaServer.Detection.PhishingTriage

  @default_poll_interval :timer.seconds(60)
  @gmail_base_url "https://gmail.googleapis.com/gmail/v1"
  @admin_base_url "https://admin.googleapis.com/admin/reports/v1"
  @directory_base_url "https://admin.googleapis.com/admin/directory/v1"
  @token_url "https://oauth2.googleapis.com/token"

  # State structure
  defstruct [
    :service_account_key,
    :admin_email,
    :access_token,
    :token_expires_at,
    :last_poll_time,
    :poll_interval,
    :organization_id,
    :customer_id,
    :enabled,
    :stats
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  @doc """
  Start the Google Workspace integration.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Get the current connection status.
  """
  @spec get_status() :: {:ok, map()} | {:error, :not_connected}
  def get_status do
    GenServer.call(__MODULE__, :get_status)
  end

  @doc """
  Manually trigger a poll for new email events.
  """
  @spec poll_events() :: {:ok, integer()} | {:error, term()}
  def poll_events do
    GenServer.call(__MODULE__, :poll_events, 30_000)
  end

  @doc """
  Get Gmail audit logs from Admin SDK.
  """
  @spec get_gmail_logs(DateTime.t(), DateTime.t(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def get_gmail_logs(start_time, end_time, opts \\ []) do
    GenServer.call(__MODULE__, {:get_gmail_logs, start_time, end_time, opts}, 60_000)
  end

  @doc """
  Get email details for a user.
  """
  @spec get_email(String.t(), String.t()) :: {:ok, map()} | {:error, term()}
  def get_email(user_email, message_id) do
    GenServer.call(__MODULE__, {:get_email, user_email, message_id})
  end

  @doc """
  Search emails for a user.
  """
  @spec search_emails(String.t(), String.t(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def search_emails(user_email, query, opts \\ []) do
    GenServer.call(__MODULE__, {:search_emails, user_email, query, opts}, 60_000)
  end

  @doc """
  List messages in spam folder.
  """
  @spec list_spam(String.t(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def list_spam(user_email, opts \\ []) do
    GenServer.call(__MODULE__, {:list_spam, user_email, opts}, 30_000)
  end

  @doc """
  Report a message as phishing.
  """
  @spec report_phishing(String.t(), String.t()) :: :ok | {:error, term()}
  def report_phishing(user_email, message_id) do
    GenServer.call(__MODULE__, {:report_phishing, user_email, message_id})
  end

  @doc """
  Move a message to spam.
  """
  @spec move_to_spam(String.t(), String.t()) :: :ok | {:error, term()}
  def move_to_spam(user_email, message_id) do
    GenServer.call(__MODULE__, {:move_to_spam, user_email, message_id})
  end

  @doc """
  Get DLP incidents.
  """
  @spec get_dlp_incidents(keyword()) :: {:ok, [map()]} | {:error, term()}
  def get_dlp_incidents(opts \\ []) do
    GenServer.call(__MODULE__, {:get_dlp_incidents, opts}, 30_000)
  end

  @doc """
  Get user security info.
  """
  @spec get_user_security(String.t()) :: {:ok, map()} | {:error, term()}
  def get_user_security(user_email) do
    GenServer.call(__MODULE__, {:get_user_security, user_email})
  end

  @doc """
  Get login audit events.
  """
  @spec get_login_events(keyword()) :: {:ok, [map()]} | {:error, term()}
  def get_login_events(opts \\ []) do
    GenServer.call(__MODULE__, {:get_login_events, opts}, 30_000)
  end

  @doc """
  Get integration statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Update integration configuration.
  """
  @spec update_config(map()) :: :ok | {:error, term()}
  def update_config(config) do
    GenServer.call(__MODULE__, {:update_config, config})
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    config = Application.get_env(:tamandua_server, __MODULE__, [])

    state = %__MODULE__{
      service_account_key: Keyword.get(config, :service_account_key) || Keyword.get(opts, :service_account_key),
      admin_email: Keyword.get(config, :admin_email) || Keyword.get(opts, :admin_email),
      poll_interval: Keyword.get(config, :poll_interval_ms, @default_poll_interval),
      organization_id: Keyword.get(opts, :organization_id),
      customer_id: Keyword.get(config, :customer_id, "my_customer"),
      enabled: Keyword.get(config, :enabled, false),
      access_token: nil,
      token_expires_at: nil,
      last_poll_time: nil,
      stats: %{
        emails_collected: 0,
        threats_detected: 0,
        dlp_incidents: 0,
        api_calls: 0,
        errors: 0,
        last_error: nil
      }
    }

    # Schedule initial poll if enabled and configured
    if state.enabled and state.service_account_key and state.admin_email do
      Process.send_after(self(), :authenticate, 1_000)
    end

    Logger.info("Google Workspace Email Security integration initialized (enabled: #{state.enabled})")
    {:ok, state}
  end

  @impl true
  def handle_call(:get_status, _from, state) do
    status = %{
      connected: state.access_token != nil and not token_expired?(state),
      enabled: state.enabled,
      admin_email: mask_email(state.admin_email),
      last_poll: state.last_poll_time,
      stats: state.stats
    }
    {:reply, {:ok, status}, state}
  end

  @impl true
  def handle_call(:poll_events, _from, state) do
    case do_poll_events(state) do
      {:ok, count, new_state} ->
        {:reply, {:ok, count}, new_state}
      {:error, reason, new_state} ->
        {:reply, {:error, reason}, new_state}
    end
  end

  @impl true
  def handle_call({:get_gmail_logs, start_time, end_time, opts}, _from, state) do
    case ensure_token(state) do
      {:ok, state} ->
        result = fetch_gmail_logs(state, start_time, end_time, opts)
        {:reply, result, update_stats(state, :api_calls)}
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:get_email, user_email, message_id}, _from, state) do
    case ensure_token(state) do
      {:ok, state} ->
        result = fetch_email(state, user_email, message_id)
        {:reply, result, update_stats(state, :api_calls)}
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:search_emails, user_email, query, opts}, _from, state) do
    case ensure_token(state) do
      {:ok, state} ->
        result = do_search_emails(state, user_email, query, opts)
        {:reply, result, update_stats(state, :api_calls)}
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:list_spam, user_email, opts}, _from, state) do
    case ensure_token(state) do
      {:ok, state} ->
        result = fetch_spam(state, user_email, opts)
        {:reply, result, update_stats(state, :api_calls)}
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:report_phishing, user_email, message_id}, _from, state) do
    case ensure_token(state) do
      {:ok, state} ->
        result = do_report_phishing(state, user_email, message_id)
        {:reply, result, update_stats(state, :api_calls)}
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:move_to_spam, user_email, message_id}, _from, state) do
    case ensure_token(state) do
      {:ok, state} ->
        result = do_move_to_spam(state, user_email, message_id)
        {:reply, result, update_stats(state, :api_calls)}
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:get_dlp_incidents, opts}, _from, state) do
    case ensure_token(state) do
      {:ok, state} ->
        result = fetch_dlp_incidents(state, opts)
        {:reply, result, update_stats(state, :api_calls)}
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:get_user_security, user_email}, _from, state) do
    case ensure_token(state) do
      {:ok, state} ->
        result = fetch_user_security(state, user_email)
        {:reply, result, update_stats(state, :api_calls)}
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:get_login_events, opts}, _from, state) do
    case ensure_token(state) do
      {:ok, state} ->
        result = fetch_login_events(state, opts)
        {:reply, result, update_stats(state, :api_calls)}
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  @impl true
  def handle_call({:update_config, config}, _from, state) do
    new_state = %{state |
      service_account_key: Map.get(config, :service_account_key, state.service_account_key),
      admin_email: Map.get(config, :admin_email, state.admin_email),
      poll_interval: Map.get(config, :poll_interval_ms, state.poll_interval),
      enabled: Map.get(config, :enabled, state.enabled),
      # Clear token to force re-auth with new credentials
      access_token: nil,
      token_expires_at: nil
    }

    if new_state.enabled and new_state.service_account_key and new_state.admin_email do
      Process.send_after(self(), :authenticate, 1_000)
    end

    {:reply, :ok, new_state}
  end

  @impl true
  def handle_info(:authenticate, state) do
    case authenticate(state) do
      {:ok, new_state} ->
        schedule_poll(new_state.poll_interval)
        {:noreply, new_state}
      {:error, reason} ->
        Logger.error("Google Workspace authentication failed: #{inspect(reason)}")
        # Retry authentication after a delay
        Process.send_after(self(), :authenticate, :timer.minutes(5))
        {:noreply, update_error(state, reason)}
    end
  end

  @impl true
  def handle_info(:poll, state) do
    case do_poll_events(state) do
      {:ok, _count, new_state} ->
        schedule_poll(new_state.poll_interval)
        {:noreply, new_state}
      {:error, _reason, new_state} ->
        schedule_poll(new_state.poll_interval)
        {:noreply, new_state}
    end
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Authentication
  # ============================================================================

  defp authenticate(state) do
    case load_service_account_key(state.service_account_key) do
      {:ok, key_data} ->
        case generate_jwt(key_data, state.admin_email) do
          {:ok, jwt} ->
            exchange_jwt_for_token(jwt, state)
          {:error, reason} ->
            {:error, {:jwt_generation_failed, reason}}
        end
      {:error, reason} ->
        {:error, {:key_load_failed, reason}}
    end
  end

  defp load_service_account_key(nil), do: {:error, :key_not_configured}
  defp load_service_account_key(path) when is_binary(path) do
    case File.read(path) do
      {:ok, content} -> Jason.decode(content)
      {:error, reason} -> {:error, reason}
    end
  end
  defp load_service_account_key(key_data) when is_map(key_data) do
    {:ok, key_data}
  end

  defp generate_jwt(key_data, admin_email) do
    # JWT claims for service account
    now = System.system_time(:second)

    claims = %{
      "iss" => key_data["client_email"],
      "sub" => admin_email,
      "scope" => Enum.join([
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/admin.reports.audit.readonly",
        "https://www.googleapis.com/auth/admin.directory.user.readonly"
      ], " "),
      "aud" => @token_url,
      "iat" => now,
      "exp" => now + 3600
    }

    # In production, use JOSE or similar for JWT signing
    # This is a simplified version
    private_key = key_data["private_key"]

    if private_key do
      # Sign JWT with RS256
      header = Base.url_encode64(Jason.encode!(%{"alg" => "RS256", "typ" => "JWT"}), padding: false)
      payload = Base.url_encode64(Jason.encode!(claims), padding: false)
      signing_input = "#{header}.#{payload}"

      case sign_with_rsa(signing_input, private_key) do
        {:ok, signature} ->
          {:ok, "#{signing_input}.#{signature}"}
        {:error, reason} ->
          {:error, reason}
      end
    else
      {:error, :missing_private_key}
    end
  end

  defp sign_with_rsa(data, private_key_pem) do
    try do
      # Decode the PEM private key
      [entry] = :public_key.pem_decode(private_key_pem)
      private_key = :public_key.pem_entry_decode(entry)

      # Sign with SHA256
      signature = :public_key.sign(data, :sha256, private_key)
      encoded = Base.url_encode64(signature, padding: false)
      {:ok, encoded}
    rescue
      e -> {:error, Exception.message(e)}
    end
  end

  defp exchange_jwt_for_token(jwt, state) do
    body = URI.encode_query(%{
      "grant_type" => "urn:ietf:params:oauth:grant-type:jwt-bearer",
      "assertion" => jwt
    })

    headers = [{"Content-Type", "application/x-www-form-urlencoded"}]

    case http_post(@token_url, body, headers) do
      {:ok, %{status: 200, body: response_body}} ->
        case Jason.decode(response_body) do
          {:ok, %{"access_token" => token, "expires_in" => expires_in}} ->
            expires_at = DateTime.add(DateTime.utc_now(), expires_in, :second)
            Logger.info("Google Workspace authentication successful")
            {:ok, %{state | access_token: token, token_expires_at: expires_at}}
          {:error, reason} ->
            {:error, {:json_decode_error, reason}}
        end
      {:ok, %{status: status, body: body}} ->
        {:error, {:auth_failed, status, body}}
      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  defp ensure_token(state) do
    if token_expired?(state) do
      authenticate(state)
    else
      {:ok, state}
    end
  end

  defp token_expired?(state) do
    is_nil(state.access_token) or
    is_nil(state.token_expires_at) or
    DateTime.compare(DateTime.utc_now(), state.token_expires_at) == :gt
  end

  # ============================================================================
  # Event Polling
  # ============================================================================

  defp do_poll_events(state) do
    case ensure_token(state) do
      {:ok, state} ->
        # Poll multiple sources
        {:ok, gmail_events} = fetch_gmail_activity(state)
        {:ok, suspicious_logins} = fetch_suspicious_logins(state)

        all_events = gmail_events ++ suspicious_logins
        count = length(all_events)

        # Process events through phishing triage and detection
        Enum.each(all_events, &process_email_event/1)

        new_state = %{state |
          last_poll_time: DateTime.utc_now(),
          stats: %{state.stats |
            emails_collected: state.stats.emails_collected + count,
            api_calls: state.stats.api_calls + 2
          }
        }

        Logger.debug("Google Workspace poll complete: #{count} events collected")
        {:ok, count, new_state}

      {:error, reason} ->
        {:error, reason, update_error(state, reason)}
    end
  end

  defp fetch_gmail_activity(state) do
    # Use Admin SDK Reports API for Gmail activity
    now = DateTime.utc_now()
    start_time = DateTime.add(now, -state.poll_interval, :millisecond)

    url = "#{@admin_base_url}/activity/users/all/applications/gmail?" <>
          URI.encode_query(%{
            "startTime" => DateTime.to_iso8601(start_time),
            "endTime" => DateTime.to_iso8601(now),
            "eventName" => "email_received",
            "maxResults" => 100
          })

    case google_request(state, :get, url) do
      {:ok, %{"items" => items}} when is_list(items) ->
        normalized = Enum.map(items, &normalize_gmail_event/1)
        {:ok, normalized}
      {:ok, _} ->
        {:ok, []}
      {:error, reason} ->
        Logger.warning("Failed to fetch Gmail activity: #{inspect(reason)}")
        {:ok, []}
    end
  end

  defp fetch_suspicious_logins(state) do
    # Get suspicious login events
    now = DateTime.utc_now()
    start_time = DateTime.add(now, -state.poll_interval, :millisecond)

    url = "#{@admin_base_url}/activity/users/all/applications/login?" <>
          URI.encode_query(%{
            "startTime" => DateTime.to_iso8601(start_time),
            "endTime" => DateTime.to_iso8601(now),
            "eventName" => "suspicious_login",
            "maxResults" => 100
          })

    case google_request(state, :get, url) do
      {:ok, %{"items" => items}} when is_list(items) ->
        normalized = Enum.map(items, &normalize_login_event/1)
        {:ok, normalized}
      {:ok, _} ->
        {:ok, []}
      {:error, _reason} ->
        {:ok, []}
    end
  end

  defp normalize_gmail_event(event) do
    actor = event["actor"] || %{}
    parameters = extract_parameters(event["events"])

    %EmailEvent{
      id: event["id"]["uniqueQualifier"],
      source: :google_workspace,
      event_type: :email_received,
      timestamp: parse_datetime(event["id"]["time"]),
      sender: parameters["sender"] || parameters["from"],
      recipient: actor["email"],
      subject: parameters["subject"],
      message_id: parameters["message_id"],
      threat_type: classify_gmail_threat(parameters),
      severity: map_gmail_severity(parameters),
      verdict: map_gmail_verdict(parameters),
      confidence: 0.85,
      urls: [],
      attachments: [],
      raw_data: event
    }
  end

  defp normalize_login_event(event) do
    actor = event["actor"] || %{}
    parameters = extract_parameters(event["events"])

    %EmailEvent{
      id: event["id"]["uniqueQualifier"],
      source: :google_workspace,
      event_type: :suspicious_login,
      timestamp: parse_datetime(event["id"]["time"]),
      sender: nil,
      recipient: actor["email"],
      subject: "Suspicious Login Detected",
      message_id: nil,
      threat_type: "suspicious_login",
      severity: :high,
      verdict: :suspicious,
      confidence: 0.8,
      urls: [],
      attachments: [],
      raw_data: event
    }
  end

  defp extract_parameters(nil), do: %{}
  defp extract_parameters([]), do: %{}
  defp extract_parameters([event | _]) do
    (event["parameters"] || [])
    |> Enum.reduce(%{}, fn param, acc ->
      Map.put(acc, param["name"], param["value"] || param["boolValue"] || param["intValue"])
    end)
  end

  defp classify_gmail_threat(parameters) do
    cond do
      parameters["is_spam"] == true -> "spam"
      parameters["is_phishing"] == true -> "phishing"
      parameters["has_virus"] == true -> "malware"
      true -> nil
    end
  end

  defp map_gmail_severity(parameters) do
    cond do
      parameters["is_phishing"] == true -> :high
      parameters["has_virus"] == true -> :critical
      parameters["is_spam"] == true -> :low
      true -> :info
    end
  end

  defp map_gmail_verdict(parameters) do
    cond do
      parameters["is_phishing"] == true -> :malicious
      parameters["has_virus"] == true -> :malicious
      parameters["is_spam"] == true -> :suspicious
      true -> :benign
    end
  end

  defp process_email_event(%EmailEvent{} = event) do
    # Forward to phishing triage for analysis
    email_data = %{
      event_id: event.id,
      from: event.sender,
      subject: event.subject,
      headers: %{
        "from" => event.sender,
        "to" => event.recipient,
        "subject" => event.subject,
        "message-id" => event.message_id
      },
      attachments: Enum.map(event.attachments, fn att ->
        %{
          filename: att["name"] || att["fileName"],
          sha256: att["sha256"],
          content_type: att["contentType"]
        }
      end),
      organization_id: nil,
      source: :google_workspace
    }

    Task.start(fn ->
      case PhishingTriage.analyze_email(email_data) do
        {:ok, _result} -> :ok
        {:error, reason} ->
          Logger.warning("Failed to analyze Google Workspace email event: #{inspect(reason)}")
      end
    end)
  end

  # ============================================================================
  # Gmail Logs
  # ============================================================================

  defp fetch_gmail_logs(state, start_time, end_time, opts) do
    url = "#{@admin_base_url}/activity/users/all/applications/gmail?" <>
          URI.encode_query(%{
            "startTime" => DateTime.to_iso8601(start_time),
            "endTime" => DateTime.to_iso8601(end_time),
            "maxResults" => Keyword.get(opts, :limit, 100)
          })

    case google_request(state, :get, url) do
      {:ok, %{"items" => items}} when is_list(items) ->
        {:ok, Enum.map(items, &normalize_log_entry/1)}
      {:ok, _} ->
        {:ok, []}
      {:error, reason} ->
        {:error, reason}
    end
  end

  defp normalize_log_entry(entry) do
    actor = entry["actor"] || %{}
    parameters = extract_parameters(entry["events"])

    %{
      id: get_in(entry, ["id", "uniqueQualifier"]),
      timestamp: parse_datetime(get_in(entry, ["id", "time"])),
      user: actor["email"],
      event_name: get_in(entry, ["events", Access.at(0), "name"]),
      parameters: parameters,
      ip_address: entry["ipAddress"]
    }
  end

  # ============================================================================
  # Email Operations
  # ============================================================================

  defp fetch_email(state, user_email, message_id) do
    url = "#{@gmail_base_url}/users/#{URI.encode(user_email)}/messages/#{message_id}?" <>
          URI.encode_query(%{"format" => "full"})

    case google_request(state, :get, url) do
      {:ok, email} ->
        {:ok, normalize_gmail_message(email)}
      {:error, reason} ->
        {:error, reason}
    end
  end

  defp normalize_gmail_message(message) do
    headers = extract_message_headers(message["payload"]["headers"] || [])

    %{
      id: message["id"],
      thread_id: message["threadId"],
      subject: headers["subject"],
      from: headers["from"],
      to: headers["to"],
      date: headers["date"],
      message_id: headers["message-id"],
      snippet: message["snippet"],
      label_ids: message["labelIds"] || [],
      internal_date: message["internalDate"],
      size_estimate: message["sizeEstimate"],
      has_attachments: has_attachments?(message["payload"]),
      headers: headers
    }
  end

  defp extract_message_headers(headers) do
    headers
    |> Enum.reduce(%{}, fn header, acc ->
      Map.put(acc, String.downcase(header["name"]), header["value"])
    end)
  end

  defp has_attachments?(nil), do: false
  defp has_attachments?(payload) do
    parts = payload["parts"] || []
    Enum.any?(parts, fn part ->
      part["filename"] && part["filename"] != ""
    end)
  end

  defp do_search_emails(state, user_email, query, opts) do
    url = "#{@gmail_base_url}/users/#{URI.encode(user_email)}/messages?" <>
          URI.encode_query(%{
            "q" => query,
            "maxResults" => Keyword.get(opts, :limit, 25)
          })

    case google_request(state, :get, url) do
      {:ok, %{"messages" => messages}} when is_list(messages) ->
        # Fetch full message details
        results = Enum.map(messages, fn msg ->
          case fetch_email(state, user_email, msg["id"]) do
            {:ok, email} -> email
            {:error, _} -> nil
          end
        end)
        |> Enum.reject(&is_nil/1)

        {:ok, results}
      {:ok, _} ->
        {:ok, []}
      {:error, reason} ->
        {:error, reason}
    end
  end

  defp fetch_spam(state, user_email, opts) do
    url = "#{@gmail_base_url}/users/#{URI.encode(user_email)}/messages?" <>
          URI.encode_query(%{
            "labelIds" => "SPAM",
            "maxResults" => Keyword.get(opts, :limit, 50)
          })

    case google_request(state, :get, url) do
      {:ok, %{"messages" => messages}} when is_list(messages) ->
        results = Enum.map(messages, fn msg ->
          case fetch_email(state, user_email, msg["id"]) do
            {:ok, email} -> email
            {:error, _} -> nil
          end
        end)
        |> Enum.reject(&is_nil/1)

        {:ok, results}
      {:ok, _} ->
        {:ok, []}
      {:error, reason} ->
        {:error, reason}
    end
  end

  defp do_report_phishing(state, user_email, message_id) do
    # Move to spam and mark as phishing
    url = "#{@gmail_base_url}/users/#{URI.encode(user_email)}/messages/#{message_id}/modify"

    body = %{
      "addLabelIds" => ["SPAM"],
      "removeLabelIds" => ["INBOX"]
    }

    case google_request(state, :post, url, body) do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp do_move_to_spam(state, user_email, message_id) do
    url = "#{@gmail_base_url}/users/#{URI.encode(user_email)}/messages/#{message_id}/modify"

    body = %{
      "addLabelIds" => ["SPAM"],
      "removeLabelIds" => ["INBOX"]
    }

    case google_request(state, :post, url, body) do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  # ============================================================================
  # DLP Incidents
  # ============================================================================

  defp fetch_dlp_incidents(state, opts) do
    # DLP incidents via Admin SDK
    url = "#{@admin_base_url}/activity/users/all/applications/rules?" <>
          URI.encode_query(%{
            "eventName" => "rule_match",
            "maxResults" => Keyword.get(opts, :limit, 100)
          })

    case google_request(state, :get, url) do
      {:ok, %{"items" => items}} when is_list(items) ->
        {:ok, Enum.map(items, &normalize_dlp_incident/1)}
      {:ok, _} ->
        {:ok, []}
      {:error, reason} ->
        {:error, reason}
    end
  end

  defp normalize_dlp_incident(item) do
    actor = item["actor"] || %{}
    parameters = extract_parameters(item["events"])

    %{
      id: get_in(item, ["id", "uniqueQualifier"]),
      timestamp: parse_datetime(get_in(item, ["id", "time"])),
      user: actor["email"],
      rule_name: parameters["rule_name"],
      action_taken: parameters["action_taken"],
      trigger_type: parameters["trigger_type"],
      resource_type: parameters["resource_type"],
      resource_name: parameters["resource_name"],
      matched_detectors: parameters["matched_detectors"]
    }
  end

  # ============================================================================
  # User Security
  # ============================================================================

  defp fetch_user_security(state, user_email) do
    url = "#{@directory_base_url}/users/#{URI.encode(user_email)}?" <>
          URI.encode_query(%{
            "projection" => "full"
          })

    case google_request(state, :get, url) do
      {:ok, user} ->
        {:ok, %{
          email: user["primaryEmail"],
          name: get_in(user, ["name", "fullName"]),
          is_admin: user["isAdmin"] || false,
          is_delegated_admin: user["isDelegatedAdmin"] || false,
          is_2fa_enrolled: user["isEnrolledIn2Sv"] || false,
          is_2fa_enforced: user["isEnforcedIn2Sv"] || false,
          suspended: user["suspended"] || false,
          creation_time: parse_datetime(user["creationTime"]),
          last_login_time: parse_datetime(user["lastLoginTime"]),
          recovery_email: user["recoveryEmail"],
          recovery_phone: user["recoveryPhone"]
        }}
      {:error, reason} ->
        {:error, reason}
    end
  end

  defp fetch_login_events(state, opts) do
    now = DateTime.utc_now()
    start_time = Keyword.get(opts, :start_time, DateTime.add(now, -24, :hour))

    url = "#{@admin_base_url}/activity/users/all/applications/login?" <>
          URI.encode_query(%{
            "startTime" => DateTime.to_iso8601(start_time),
            "endTime" => DateTime.to_iso8601(now),
            "maxResults" => Keyword.get(opts, :limit, 100)
          })

    case google_request(state, :get, url) do
      {:ok, %{"items" => items}} when is_list(items) ->
        {:ok, Enum.map(items, &normalize_login_log/1)}
      {:ok, _} ->
        {:ok, []}
      {:error, reason} ->
        {:error, reason}
    end
  end

  defp normalize_login_log(item) do
    actor = item["actor"] || %{}
    parameters = extract_parameters(item["events"])

    %{
      id: get_in(item, ["id", "uniqueQualifier"]),
      timestamp: parse_datetime(get_in(item, ["id", "time"])),
      user: actor["email"],
      event_type: get_in(item, ["events", Access.at(0), "name"]),
      ip_address: item["ipAddress"],
      login_type: parameters["login_type"],
      is_suspicious: parameters["is_suspicious"] || false,
      is_second_factor: parameters["is_second_factor"] || false
    }
  end

  # ============================================================================
  # HTTP Helpers
  # ============================================================================

  defp google_request(state, method, url, body \\ nil) do
    headers = [
      {"Authorization", "Bearer #{state.access_token}"},
      {"Content-Type", "application/json"}
    ]

    result = case method do
      :get -> http_get(url, headers)
      :post -> http_post(url, Jason.encode!(body), headers)
      :patch -> http_patch(url, Jason.encode!(body), headers)
      :delete -> http_delete(url, headers)
    end

    case result do
      {:ok, %{status: status, body: response_body}} when status in 200..299 ->
        if response_body == "" do
          {:ok, %{}}
        else
          Jason.decode(response_body)
        end
      {:ok, %{status: 401}} ->
        {:error, :unauthorized}
      {:ok, %{status: 403}} ->
        {:error, :forbidden}
      {:ok, %{status: 404}} ->
        {:error, :not_found}
      {:ok, %{status: status, body: body}} ->
        {:error, {:api_error, status, body}}
      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  defp http_get(url, headers) do
    do_http_request(:get, url, nil, headers)
  end

  defp http_post(url, body, headers) do
    do_http_request(:post, url, body, headers)
  end

  defp http_patch(url, body, headers) do
    do_http_request(:patch, url, body, headers)
  end

  defp http_delete(url, headers) do
    do_http_request(:delete, url, nil, headers)
  end

  defp do_http_request(method, url, body, headers) do
    request = Finch.build(method, url, headers, body)

    case Finch.request(request, TamanduaServer.Finch, receive_timeout: 30_000) do
      {:ok, %Finch.Response{status: status, body: resp_body}} ->
        {:ok, %{status: status, body: resp_body}}

      {:error, reason} ->
        Logger.error("Google Workspace HTTP #{method} #{url} failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  # ============================================================================
  # Helpers
  # ============================================================================

  defp schedule_poll(interval) do
    Process.send_after(self(), :poll, interval)
  end

  defp update_stats(state, key) do
    new_stats = Map.update(state.stats, key, 1, &(&1 + 1))
    %{state | stats: new_stats}
  end

  defp update_error(state, reason) do
    new_stats = %{state.stats |
      errors: state.stats.errors + 1,
      last_error: %{
        reason: inspect(reason),
        time: DateTime.utc_now()
      }
    }
    %{state | stats: new_stats}
  end

  defp mask_email(nil), do: nil
  defp mask_email(email) when is_binary(email) do
    case String.split(email, "@") do
      [local, domain] ->
        masked_local = String.slice(local, 0, 2) <> "***"
        "#{masked_local}@#{domain}"
      _ ->
        "***"
    end
  end

  defp parse_datetime(nil), do: nil
  defp parse_datetime(str) when is_binary(str) do
    case DateTime.from_iso8601(str) do
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end
  defp parse_datetime(epoch) when is_integer(epoch) do
    DateTime.from_unix!(div(epoch, 1000), :millisecond)
  end
end
