defmodule TamanduaServer.EmailSecurity.Microsoft365 do
  @moduledoc """
  Microsoft 365 Email Security Integration.

  Provides integration with Microsoft Graph API and Microsoft 365 Defender for:
  - Email event collection and monitoring
  - Message trace logs
  - Threat intelligence from M365 Defender
  - Quarantine management
  - Safe Links and Safe Attachments status

  This module implements a GenServer that periodically polls Microsoft Graph API
  for email security events and forwards them to the detection engine.

  ## Configuration

  Required configuration in config.exs:

      config :tamandua_server, TamanduaServer.EmailSecurity.Microsoft365,
        tenant_id: "your-tenant-id",
        client_id: "your-client-id",
        client_secret: "your-client-secret",
        poll_interval_ms: 60_000

  ## Required Microsoft Graph API Permissions

  - Mail.Read
  - MailboxSettings.Read
  - SecurityEvents.Read.All
  - ThreatIndicators.Read.All
  - Quarantine.Read
  """

  use GenServer
  require Logger

  alias TamanduaServer.EmailSecurity.EmailEvent
  alias TamanduaServer.Detection.PhishingTriage

  @default_poll_interval :timer.seconds(60)
  @graph_base_url "https://graph.microsoft.com/v1.0"
  @security_base_url "https://graph.microsoft.com/v1.0/security"
  @token_url "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"

  # State structure
  defstruct [
    :tenant_id,
    :client_id,
    :client_secret,
    :access_token,
    :token_expires_at,
    :last_poll_time,
    :poll_interval,
    :organization_id,
    :enabled,
    :stats
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  @doc """
  Start the Microsoft 365 integration.
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
  Get message trace logs for a specific time period.
  """
  @spec get_message_trace(DateTime.t(), DateTime.t(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def get_message_trace(start_time, end_time, opts \\ []) do
    GenServer.call(__MODULE__, {:get_message_trace, start_time, end_time, opts}, 60_000)
  end

  @doc """
  Get threat intelligence from M365 Defender.
  """
  @spec get_threat_intel(keyword()) :: {:ok, [map()]} | {:error, term()}
  def get_threat_intel(opts \\ []) do
    GenServer.call(__MODULE__, {:get_threat_intel, opts}, 30_000)
  end

  @doc """
  List quarantined emails.
  """
  @spec list_quarantine(keyword()) :: {:ok, [map()]} | {:error, term()}
  def list_quarantine(opts \\ []) do
    GenServer.call(__MODULE__, {:list_quarantine, opts}, 30_000)
  end

  @doc """
  Release an email from quarantine.
  """
  @spec release_from_quarantine(String.t(), keyword()) :: :ok | {:error, term()}
  def release_from_quarantine(message_id, opts \\ []) do
    GenServer.call(__MODULE__, {:release_quarantine, message_id, opts})
  end

  @doc """
  Delete an email from quarantine.
  """
  @spec delete_from_quarantine(String.t()) :: :ok | {:error, term()}
  def delete_from_quarantine(message_id) do
    GenServer.call(__MODULE__, {:delete_quarantine, message_id})
  end

  @doc """
  Get Safe Links status for a URL.
  """
  @spec check_safe_link(String.t()) :: {:ok, map()} | {:error, term()}
  def check_safe_link(url) do
    GenServer.call(__MODULE__, {:check_safe_link, url})
  end

  @doc """
  Get email details by message ID.
  """
  @spec get_email(String.t(), String.t()) :: {:ok, map()} | {:error, term()}
  def get_email(user_id, message_id) do
    GenServer.call(__MODULE__, {:get_email, user_id, message_id})
  end

  @doc """
  Search emails across the organization.
  """
  @spec search_emails(String.t(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def search_emails(query, opts \\ []) do
    GenServer.call(__MODULE__, {:search_emails, query, opts}, 60_000)
  end

  @doc """
  Get security alerts from M365 Defender.
  """
  @spec get_security_alerts(keyword()) :: {:ok, [map()]} | {:error, term()}
  def get_security_alerts(opts \\ []) do
    GenServer.call(__MODULE__, {:get_security_alerts, opts}, 30_000)
  end

  @doc """
  Report a message as phishing to Microsoft.
  """
  @spec report_phishing(String.t(), String.t(), keyword()) :: :ok | {:error, term()}
  def report_phishing(user_id, message_id, opts \\ []) do
    GenServer.call(__MODULE__, {:report_phishing, user_id, message_id, opts})
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
      tenant_id: Keyword.get(config, :tenant_id) || Keyword.get(opts, :tenant_id),
      client_id: Keyword.get(config, :client_id) || Keyword.get(opts, :client_id),
      client_secret: Keyword.get(config, :client_secret) || Keyword.get(opts, :client_secret),
      poll_interval: Keyword.get(config, :poll_interval_ms, @default_poll_interval),
      organization_id: Keyword.get(opts, :organization_id),
      enabled: Keyword.get(config, :enabled, false),
      access_token: nil,
      token_expires_at: nil,
      last_poll_time: nil,
      stats: %{
        emails_collected: 0,
        threats_detected: 0,
        quarantine_actions: 0,
        api_calls: 0,
        errors: 0,
        last_error: nil
      }
    }

    # Schedule initial poll if enabled and configured
    if state.enabled and state.tenant_id and state.client_id do
      Process.send_after(self(), :authenticate, 1_000)
    end

    Logger.info("Microsoft 365 Email Security integration initialized (enabled: #{state.enabled})")
    {:ok, state}
  end

  @impl true
  def handle_call(:get_status, _from, state) do
    status = %{
      connected: state.access_token != nil and not token_expired?(state),
      enabled: state.enabled,
      tenant_id: mask_id(state.tenant_id),
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
  def handle_call({:get_message_trace, start_time, end_time, opts}, _from, state) do
    case ensure_token(state) do
      {:ok, state} ->
        result = fetch_message_trace(state, start_time, end_time, opts)
        {:reply, result, update_stats(state, :api_calls)}
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:get_threat_intel, opts}, _from, state) do
    case ensure_token(state) do
      {:ok, state} ->
        result = fetch_threat_intel(state, opts)
        {:reply, result, update_stats(state, :api_calls)}
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:list_quarantine, opts}, _from, state) do
    case ensure_token(state) do
      {:ok, state} ->
        result = fetch_quarantine(state, opts)
        {:reply, result, update_stats(state, :api_calls)}
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:release_quarantine, message_id, opts}, _from, state) do
    case ensure_token(state) do
      {:ok, state} ->
        result = do_release_quarantine(state, message_id, opts)
        new_state = if match?(:ok, result), do: update_stats(state, :quarantine_actions), else: state
        {:reply, result, update_stats(new_state, :api_calls)}
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:delete_quarantine, message_id}, _from, state) do
    case ensure_token(state) do
      {:ok, state} ->
        result = do_delete_quarantine(state, message_id)
        new_state = if match?(:ok, result), do: update_stats(state, :quarantine_actions), else: state
        {:reply, result, update_stats(new_state, :api_calls)}
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:check_safe_link, url}, _from, state) do
    case ensure_token(state) do
      {:ok, state} ->
        result = do_check_safe_link(state, url)
        {:reply, result, update_stats(state, :api_calls)}
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:get_email, user_id, message_id}, _from, state) do
    case ensure_token(state) do
      {:ok, state} ->
        result = fetch_email(state, user_id, message_id)
        {:reply, result, update_stats(state, :api_calls)}
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:search_emails, query, opts}, _from, state) do
    case ensure_token(state) do
      {:ok, state} ->
        result = do_search_emails(state, query, opts)
        {:reply, result, update_stats(state, :api_calls)}
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:get_security_alerts, opts}, _from, state) do
    case ensure_token(state) do
      {:ok, state} ->
        result = fetch_security_alerts(state, opts)
        {:reply, result, update_stats(state, :api_calls)}
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:report_phishing, user_id, message_id, opts}, _from, state) do
    case ensure_token(state) do
      {:ok, state} ->
        result = do_report_phishing(state, user_id, message_id, opts)
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
      tenant_id: Map.get(config, :tenant_id, state.tenant_id),
      client_id: Map.get(config, :client_id, state.client_id),
      client_secret: Map.get(config, :client_secret, state.client_secret),
      poll_interval: Map.get(config, :poll_interval_ms, state.poll_interval),
      enabled: Map.get(config, :enabled, state.enabled),
      # Clear token to force re-auth with new credentials
      access_token: nil,
      token_expires_at: nil
    }

    if new_state.enabled and new_state.tenant_id and new_state.client_id do
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
        Logger.error("Microsoft 365 authentication failed: #{inspect(reason)}")
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
    url = String.replace(@token_url, "{tenant}", state.tenant_id)

    body = URI.encode_query(%{
      "client_id" => state.client_id,
      "client_secret" => state.client_secret,
      "scope" => "https://graph.microsoft.com/.default",
      "grant_type" => "client_credentials"
    })

    headers = [{"Content-Type", "application/x-www-form-urlencoded"}]

    case http_post(url, body, headers) do
      {:ok, %{status: 200, body: response_body}} ->
        case Jason.decode(response_body) do
          {:ok, %{"access_token" => token, "expires_in" => expires_in}} ->
            expires_at = DateTime.add(DateTime.utc_now(), expires_in, :second)
            Logger.info("Microsoft 365 authentication successful")
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
        {:ok, security_events} = fetch_security_events(state)
        {:ok, email_threats} = fetch_email_threats(state)

        all_events = security_events ++ email_threats
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

        Logger.debug("M365 poll complete: #{count} events collected")
        {:ok, count, new_state}

      {:error, reason} ->
        {:error, reason, update_error(state, reason)}
    end
  end

  defp fetch_security_events(state) do
    url = "#{@security_base_url}/alerts_v2?" <>
          URI.encode_query(%{
            "$filter" => "category eq 'Phishing' or category eq 'Malware'",
            "$top" => "100",
            "$orderby" => "createdDateTime desc"
          })

    case graph_request(state, :get, url) do
      {:ok, %{"value" => events}} ->
        normalized = Enum.map(events, &normalize_security_event/1)
        {:ok, normalized}
      {:ok, _} ->
        {:ok, []}
      {:error, reason} ->
        Logger.warning("Failed to fetch M365 security events: #{inspect(reason)}")
        {:ok, []}
    end
  end

  defp fetch_email_threats(state) do
    # Use Exchange Online Protection threat data
    url = "#{@graph_base_url}/security/threatSubmissions/emailThreats?" <>
          URI.encode_query(%{
            "$top" => "100",
            "$orderby" => "createdDateTime desc"
          })

    case graph_request(state, :get, url) do
      {:ok, %{"value" => threats}} ->
        normalized = Enum.map(threats, &normalize_email_threat/1)
        {:ok, normalized}
      {:ok, _} ->
        {:ok, []}
      {:error, _reason} ->
        # This endpoint may not be available in all tenants
        {:ok, []}
    end
  end

  defp normalize_security_event(event) do
    %EmailEvent{
      id: event["id"],
      source: :microsoft365,
      event_type: :security_alert,
      timestamp: parse_datetime(event["createdDateTime"]),
      sender: get_in(event, ["evidence", "emailDetails", "sender"]),
      recipient: get_in(event, ["evidence", "emailDetails", "recipient"]),
      subject: get_in(event, ["evidence", "emailDetails", "subject"]),
      message_id: get_in(event, ["evidence", "emailDetails", "messageId"]),
      threat_type: event["category"],
      severity: map_severity(event["severity"]),
      verdict: map_verdict(event["status"]),
      confidence: event["confidence"] || 0.8,
      urls: extract_urls_from_event(event),
      attachments: extract_attachments_from_event(event),
      raw_data: event
    }
  end

  defp normalize_email_threat(threat) do
    %EmailEvent{
      id: threat["id"],
      source: :microsoft365,
      event_type: :email_threat,
      timestamp: parse_datetime(threat["createdDateTime"]),
      sender: threat["sender"],
      recipient: threat["recipientEmailAddress"],
      subject: threat["subject"],
      message_id: threat["internetMessageId"],
      threat_type: threat["threatType"],
      severity: map_threat_severity(threat["threatType"]),
      verdict: map_threat_verdict(threat["result"]),
      confidence: 0.9,
      urls: threat["urls"] || [],
      attachments: threat["attachments"] || [],
      raw_data: threat
    }
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
      organization_id: nil,  # Will be looked up
      source: :microsoft365
    }

    # Trigger analysis
    Task.start(fn ->
      case PhishingTriage.analyze_email(email_data) do
        {:ok, _result} -> :ok
        {:error, reason} ->
          Logger.warning("Failed to analyze M365 email event: #{inspect(reason)}")
      end
    end)
  end

  # ============================================================================
  # Message Trace
  # ============================================================================

  defp fetch_message_trace(state, start_time, end_time, opts) do
    # Message trace requires Exchange Online PowerShell or Reporting API
    # Using Graph API mail search as alternative
    filter = build_message_trace_filter(start_time, end_time, opts)

    url = "#{@graph_base_url}/security/threatAssessmentRequests?" <>
          URI.encode_query(%{
            "$filter" => filter,
            "$top" => Keyword.get(opts, :limit, 100)
          })

    case graph_request(state, :get, url) do
      {:ok, %{"value" => messages}} ->
        {:ok, Enum.map(messages, &normalize_trace_message/1)}
      {:ok, _} ->
        {:ok, []}
      {:error, reason} ->
        {:error, reason}
    end
  end

  defp build_message_trace_filter(start_time, end_time, opts) do
    filters = [
      "createdDateTime ge #{DateTime.to_iso8601(start_time)}",
      "createdDateTime le #{DateTime.to_iso8601(end_time)}"
    ]

    if sender = Keyword.get(opts, :sender) do
      filters ++ ["contains(sender, '#{sender}')"]
    else
      filters
    end
    |> Enum.join(" and ")
  end

  defp normalize_trace_message(msg) do
    %{
      id: msg["id"],
      sender: msg["sender"],
      recipient: msg["recipientEmailAddress"],
      subject: msg["subject"],
      received_time: parse_datetime(msg["receivedDateTime"]),
      status: msg["status"],
      size: msg["size"],
      direction: msg["directionality"]
    }
  end

  # ============================================================================
  # Threat Intelligence
  # ============================================================================

  defp fetch_threat_intel(state, opts) do
    url = "#{@security_base_url}/tiIndicators?" <>
          URI.encode_query(%{
            "$top" => Keyword.get(opts, :limit, 100),
            "$orderby" => "lastReportedDateTime desc"
          })

    case graph_request(state, :get, url) do
      {:ok, %{"value" => indicators}} ->
        {:ok, Enum.map(indicators, &normalize_threat_indicator/1)}
      {:ok, _} ->
        {:ok, []}
      {:error, reason} ->
        {:error, reason}
    end
  end

  defp normalize_threat_indicator(indicator) do
    %{
      id: indicator["id"],
      type: indicator["indicatorType"],
      value: get_indicator_value(indicator),
      action: indicator["action"],
      severity: indicator["severity"],
      confidence: indicator["confidence"],
      description: indicator["description"],
      expires_at: parse_datetime(indicator["expirationDateTime"]),
      source: "Microsoft 365 Defender",
      tags: indicator["tags"] || []
    }
  end

  defp get_indicator_value(indicator) do
    indicator["networkDestinationIPv4"] ||
    indicator["networkDestinationIPv6"] ||
    indicator["url"] ||
    indicator["domainName"] ||
    indicator["emailSenderAddress"] ||
    indicator["fileHashValue"]
  end

  # ============================================================================
  # Quarantine Management
  # ============================================================================

  defp fetch_quarantine(state, opts) do
    # Using Exchange Online Protection quarantine API
    url = "#{@graph_base_url}/security/quarantineMessages?" <>
          URI.encode_query(%{
            "$top" => Keyword.get(opts, :limit, 100),
            "$orderby" => "receivedDateTime desc"
          })

    case graph_request(state, :get, url) do
      {:ok, %{"value" => messages}} ->
        {:ok, Enum.map(messages, &normalize_quarantine_message/1)}
      {:ok, _} ->
        {:ok, []}
      {:error, reason} ->
        {:error, reason}
    end
  end

  defp normalize_quarantine_message(msg) do
    %{
      id: msg["id"],
      sender: msg["senderAddress"],
      recipient: msg["recipientAddress"],
      subject: msg["subject"],
      received_at: parse_datetime(msg["receivedDateTime"]),
      quarantine_reason: msg["quarantineReason"],
      release_status: msg["releaseStatus"],
      policy_name: msg["policyName"],
      expires_at: parse_datetime(msg["expiresDateTime"])
    }
  end

  defp do_release_quarantine(state, message_id, opts) do
    url = "#{@graph_base_url}/security/quarantineMessages/#{message_id}/release"

    body = %{
      "allowSender" => Keyword.get(opts, :allow_sender, false),
      "reportFalsePositive" => Keyword.get(opts, :report_false_positive, false)
    }

    case graph_request(state, :post, url, body) do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp do_delete_quarantine(state, message_id) do
    url = "#{@graph_base_url}/security/quarantineMessages/#{message_id}"

    case graph_request(state, :delete, url) do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  # ============================================================================
  # Safe Links
  # ============================================================================

  defp do_check_safe_link(state, url) do
    request_url = "#{@graph_base_url}/security/threatAssessmentRequests"

    body = %{
      "@odata.type" => "#microsoft.graph.urlAssessmentRequest",
      "url" => url,
      "category" => "phishing"
    }

    case graph_request(state, :post, request_url, body) do
      {:ok, result} ->
        {:ok, %{
          url: url,
          status: result["status"],
          result: result["result"],
          category: result["category"],
          assessed_at: DateTime.utc_now()
        }}
      {:error, reason} ->
        {:error, reason}
    end
  end

  # ============================================================================
  # Email Operations
  # ============================================================================

  defp fetch_email(state, user_id, message_id) do
    url = "#{@graph_base_url}/users/#{user_id}/messages/#{message_id}"

    case graph_request(state, :get, url) do
      {:ok, email} ->
        {:ok, normalize_email(email)}
      {:error, reason} ->
        {:error, reason}
    end
  end

  defp normalize_email(email) do
    %{
      id: email["id"],
      internet_message_id: email["internetMessageId"],
      subject: email["subject"],
      sender: get_in(email, ["sender", "emailAddress", "address"]),
      from: get_in(email, ["from", "emailAddress", "address"]),
      to: Enum.map(email["toRecipients"] || [], &get_in(&1, ["emailAddress", "address"])),
      cc: Enum.map(email["ccRecipients"] || [], &get_in(&1, ["emailAddress", "address"])),
      received_at: parse_datetime(email["receivedDateTime"]),
      sent_at: parse_datetime(email["sentDateTime"]),
      has_attachments: email["hasAttachments"],
      body_preview: email["bodyPreview"],
      importance: email["importance"],
      internet_headers: email["internetMessageHeaders"] || [],
      attachments: email["attachments"] || []
    }
  end

  defp do_search_emails(state, query, opts) do
    url = "#{@graph_base_url}/search/query"

    body = %{
      "requests" => [
        %{
          "entityTypes" => ["message"],
          "query" => %{
            "queryString" => query
          },
          "from" => Keyword.get(opts, :offset, 0),
          "size" => Keyword.get(opts, :limit, 25)
        }
      ]
    }

    case graph_request(state, :post, url, body) do
      {:ok, %{"value" => [%{"hitsContainers" => [%{"hits" => hits}]}]}} ->
        results = Enum.map(hits, fn hit ->
          resource = hit["resource"]
          %{
            id: resource["id"],
            subject: resource["subject"],
            sender: resource["sender"],
            received_at: resource["receivedDateTime"],
            summary: hit["summary"],
            rank: hit["rank"]
          }
        end)
        {:ok, results}
      {:ok, _} ->
        {:ok, []}
      {:error, reason} ->
        {:error, reason}
    end
  end

  # ============================================================================
  # Security Alerts
  # ============================================================================

  defp fetch_security_alerts(state, opts) do
    filter = build_alert_filter(opts)

    url = "#{@security_base_url}/alerts_v2?" <>
          URI.encode_query(%{
            "$filter" => filter,
            "$top" => Keyword.get(opts, :limit, 100),
            "$orderby" => "createdDateTime desc"
          })

    case graph_request(state, :get, url) do
      {:ok, %{"value" => alerts}} ->
        {:ok, Enum.map(alerts, &normalize_security_alert/1)}
      {:ok, _} ->
        {:ok, []}
      {:error, reason} ->
        {:error, reason}
    end
  end

  defp build_alert_filter(opts) do
    filters = []

    filters = if category = Keyword.get(opts, :category) do
      ["category eq '#{category}'" | filters]
    else
      filters
    end

    filters = if severity = Keyword.get(opts, :severity) do
      ["severity eq '#{severity}'" | filters]
    else
      filters
    end

    filters = if status = Keyword.get(opts, :status) do
      ["status eq '#{status}'" | filters]
    else
      filters
    end

    if Enum.empty?(filters), do: "", else: Enum.join(filters, " and ")
  end

  defp normalize_security_alert(alert) do
    %{
      id: alert["id"],
      title: alert["title"],
      description: alert["description"],
      category: alert["category"],
      severity: alert["severity"],
      status: alert["status"],
      created_at: parse_datetime(alert["createdDateTime"]),
      first_activity: parse_datetime(alert["firstActivityDateTime"]),
      last_activity: parse_datetime(alert["lastActivityDateTime"]),
      service_source: alert["serviceSource"],
      detection_source: alert["detectionSource"],
      assigned_to: alert["assignedTo"],
      evidence: alert["evidence"] || []
    }
  end

  # ============================================================================
  # Phishing Report
  # ============================================================================

  defp do_report_phishing(state, user_id, message_id, opts) do
    url = "#{@graph_base_url}/security/threatAssessmentRequests"

    body = %{
      "@odata.type" => "#microsoft.graph.emailFileAssessmentRequest",
      "recipientEmail" => user_id,
      "contentData" => message_id,
      "category" => "phishing",
      "expectedAssessment" => Keyword.get(opts, :expected_assessment, "block")
    }

    case graph_request(state, :post, url, body) do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  # ============================================================================
  # HTTP Helpers
  # ============================================================================

  defp graph_request(state, method, url, body \\ nil) do
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
        Logger.error("M365 HTTP #{method} #{url} failed: #{inspect(reason)}")
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

  defp mask_id(nil), do: nil
  defp mask_id(id) when is_binary(id) and byte_size(id) > 8 do
    String.slice(id, 0, 4) <> "..." <> String.slice(id, -4, 4)
  end
  defp mask_id(id), do: id

  defp parse_datetime(nil), do: nil
  defp parse_datetime(str) when is_binary(str) do
    case DateTime.from_iso8601(str) do
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end

  defp map_severity("high"), do: :high
  defp map_severity("medium"), do: :medium
  defp map_severity("low"), do: :low
  defp map_severity("informational"), do: :info
  defp map_severity(_), do: :medium

  defp map_threat_severity("Phishing"), do: :high
  defp map_threat_severity("Malware"), do: :critical
  defp map_threat_severity("Spam"), do: :low
  defp map_threat_severity(_), do: :medium

  defp map_verdict("resolved"), do: :benign
  defp map_verdict("active"), do: :malicious
  defp map_verdict("investigating"), do: :suspicious
  defp map_verdict(_), do: :unknown

  defp map_threat_verdict("Block"), do: :malicious
  defp map_threat_verdict("Allow"), do: :benign
  defp map_threat_verdict(_), do: :suspicious

  defp extract_urls_from_event(event) do
    evidence = event["evidence"] || []
    Enum.flat_map(evidence, fn e ->
      case e["@odata.type"] do
        "#microsoft.graph.security.urlEvidence" -> [e["url"]]
        _ -> []
      end
    end)
  end

  defp extract_attachments_from_event(event) do
    evidence = event["evidence"] || []
    Enum.flat_map(evidence, fn e ->
      case e["@odata.type"] do
        "#microsoft.graph.security.fileEvidence" ->
          [%{
            "name" => e["fileName"],
            "sha256" => get_in(e, ["fileDetails", "sha256"]),
            "sha1" => get_in(e, ["fileDetails", "sha1"]),
            "md5" => get_in(e, ["fileDetails", "md5"])
          }]
        _ -> []
      end
    end)
  end
end
