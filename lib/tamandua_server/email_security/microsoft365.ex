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
  alias TamanduaServer.EmailSecurity.RuntimeConfigStore
  alias TamanduaServer.EmailSecurity.RuntimeSupervisor
  alias TamanduaServer.Detection.PhishingTriage

  @default_poll_interval :timer.seconds(60)
  @min_poll_interval :timer.seconds(10)
  @max_poll_interval :timer.hours(24)
  @graph_base_url "https://graph.microsoft.com/v1.0"
  @security_base_url "https://graph.microsoft.com/v1.0/security"
  @token_url "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
  @poll_adapter_env :microsoft365_email_security_poll_adapter

  # State structure
  @derive {Inspect, except: [:client_secret, :access_token]}
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
    :config_revision,
    :config_generation,
    :auth_timer_ref,
    :poll_timer_ref,
    :poll_adapter,
    :stats
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  @doc """
  Start the Microsoft 365 integration.
  """
  def start_link(opts \\ []) do
    organization_id = Keyword.fetch!(opts, :organization_id)

    GenServer.start_link(__MODULE__, opts,
      name: RuntimeSupervisor.via(__MODULE__, organization_id)
    )
  end

  @doc """
  Get the current connection status.
  """
  @spec get_status(String.t()) :: {:ok, map()} | {:error, term()}
  def get_status(organization_id) do
    call(organization_id, :get_status)
  end

  @doc """
  Manually trigger a poll for new email events.
  """
  @spec poll_events(String.t()) :: {:ok, integer()} | {:error, term()}
  def poll_events(organization_id) do
    call(organization_id, :poll_events, 30_000)
  end

  @doc """
  Get message trace logs for a specific time period.
  """
  @spec get_message_trace(String.t(), DateTime.t(), DateTime.t(), keyword()) ::
          {:ok, [map()]} | {:error, term()}
  def get_message_trace(organization_id, start_time, end_time, opts \\ []) do
    call(organization_id, {:get_message_trace, start_time, end_time, opts}, 60_000)
  end

  @doc """
  Get threat intelligence from M365 Defender.
  """
  @spec get_threat_intel(String.t(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def get_threat_intel(organization_id, opts \\ []) do
    call(organization_id, {:get_threat_intel, opts}, 30_000)
  end

  @doc """
  List quarantined emails.
  """
  @spec list_quarantine(String.t(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def list_quarantine(organization_id, opts \\ []) do
    call(organization_id, {:list_quarantine, opts}, 30_000)
  end

  @doc """
  Release an email from quarantine.
  """
  @spec release_from_quarantine(String.t(), String.t(), keyword()) :: :ok | {:error, term()}
  def release_from_quarantine(organization_id, message_id, opts \\ []) do
    call(organization_id, {:release_quarantine, message_id, opts})
  end

  @doc """
  Delete an email from quarantine.
  """
  @spec delete_from_quarantine(String.t(), String.t()) :: :ok | {:error, term()}
  def delete_from_quarantine(organization_id, message_id) do
    call(organization_id, {:delete_quarantine, message_id})
  end

  @doc """
  Get Safe Links status for a URL.
  """
  @spec check_safe_link(String.t(), String.t()) :: {:ok, map()} | {:error, term()}
  def check_safe_link(organization_id, url) do
    call(organization_id, {:check_safe_link, url})
  end

  @doc """
  Get email details by message ID.
  """
  @spec get_email(String.t(), String.t(), String.t()) :: {:ok, map()} | {:error, term()}
  def get_email(organization_id, user_id, message_id) do
    call(organization_id, {:get_email, user_id, message_id})
  end

  @doc """
  Search emails across the organization.
  """
  @spec search_emails(String.t(), String.t(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def search_emails(organization_id, query, opts \\ []) do
    call(organization_id, {:search_emails, query, opts}, 60_000)
  end

  @doc """
  Get security alerts from M365 Defender.
  """
  @spec get_security_alerts(String.t(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def get_security_alerts(organization_id, opts \\ []) do
    call(organization_id, {:get_security_alerts, opts}, 30_000)
  end

  @doc """
  Report a message as phishing to Microsoft.
  """
  @spec report_phishing(String.t(), String.t(), String.t(), keyword()) :: :ok | {:error, term()}
  def report_phishing(organization_id, user_id, message_id, opts \\ []) do
    call(organization_id, {:report_phishing, user_id, message_id, opts})
  end

  @doc """
  Get integration statistics.
  """
  @spec get_stats(String.t()) :: map() | {:error, term()}
  def get_stats(organization_id) do
    call(organization_id, :get_stats)
  end

  @doc """
  Update integration configuration.
  """
  @spec update_config(String.t(), map()) :: :ok | {:error, term()}
  def update_config(organization_id, config) do
    with {:ok, prepared_config} <- prepare_config_patch(organization_id, config) do
      case RuntimeSupervisor.update_config(__MODULE__, organization_id, prepared_config) do
        {:ok, _pid, _status, _revision} ->
          :ok

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  defp call(organization_id, request, timeout \\ 5_000) do
    with {:ok, pid} <- RuntimeSupervisor.lookup(__MODULE__, organization_id) do
      GenServer.call(pid, request, timeout)
    end
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    organization_id = Keyword.fetch!(opts, :organization_id)

    with {:ok, revision, config} <- RuntimeConfigStore.fetch(__MODULE__, organization_id) do
      state = %__MODULE__{
        tenant_id: Map.get(config, :tenant_id),
        client_id: Map.get(config, :client_id),
        client_secret: Map.get(config, :client_secret),
        poll_interval:
          normalize_poll_interval(
            Map.get(config, :poll_interval_ms, @default_poll_interval),
            @default_poll_interval
          ),
        organization_id: organization_id,
        enabled: Map.get(config, :enabled, false),
        config_revision: revision,
        config_generation: revision,
        auth_timer_ref: nil,
        poll_timer_ref: nil,
        poll_adapter: Application.get_env(:tamandua_server, @poll_adapter_env, __MODULE__),
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

      state = maybe_schedule_authentication(state, 1_000)

      Logger.info(
        "Microsoft 365 Email Security integration initialized (enabled: #{state.enabled})"
      )

      {:ok, state}
    else
      {:error, reason} -> {:stop, reason}
    end
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

        new_state =
          if match?(:ok, result), do: update_stats(state, :quarantine_actions), else: state

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

        new_state =
          if match?(:ok, result), do: update_stats(state, :quarantine_actions), else: state

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
  def handle_call({:reload_config, revision}, _from, state)
      when revision <= state.config_revision do
    {:reply, :ok, state}
  end

  def handle_call({:reload_config, revision}, _from, state) do
    case RuntimeConfigStore.fetch(__MODULE__, state.organization_id) do
      {:ok, current_revision, config} when current_revision >= revision ->
        apply_runtime_config(current_revision, config, state)

      {:error, reason} ->
        {:reply, {:error, reason}, state}

      _stale_store ->
        {:reply, {:error, :runtime_config_unavailable}, state}
    end
  end

  defp apply_runtime_config(revision, config, state) do
    state = cancel_runtime_timers(state)

    new_state = %{
      state
      | tenant_id: Map.get(config, :tenant_id, state.tenant_id),
        client_id: Map.get(config, :client_id, state.client_id),
        client_secret: Map.get(config, :client_secret, state.client_secret),
        poll_interval:
          normalize_poll_interval(
            Map.get(config, :poll_interval_ms, state.poll_interval),
            state.poll_interval
          ),
        enabled: Map.get(config, :enabled, state.enabled),
        config_revision: revision,
        config_generation: revision,
        # Clear token to force re-auth with new credentials
        access_token: nil,
        token_expires_at: nil
    }

    {:reply, :ok, maybe_schedule_authentication(new_state, 1_000)}
  end

  @impl true
  def handle_info({:authenticate, generation}, %{config_generation: generation} = state) do
    state = %{state | auth_timer_ref: nil}

    if runtime_configured?(state) do
      authenticate_current_generation(state)
    else
      {:noreply, state}
    end
  end

  def handle_info({:authenticate, _stale_generation}, state), do: {:noreply, state}

  @impl true
  def handle_info({:poll, generation}, %{config_generation: generation} = state) do
    state = %{state | poll_timer_ref: nil}

    if runtime_configured?(state) do
      poll_current_generation(state)
    else
      {:noreply, state}
    end
  end

  def handle_info({:poll, _stale_generation}, state), do: {:noreply, state}

  def handle_info(_msg, state), do: {:noreply, state}

  defp authenticate_current_generation(state) do
    case authenticate(state) do
      {:ok, new_state} ->
        {:noreply, schedule_poll(new_state, new_state.poll_interval)}

      {:error, reason} ->
        Logger.error("Microsoft 365 authentication failed: #{inspect(sanitize_error(reason))}")
        {:noreply, schedule_authentication(update_error(state, reason), :timer.minutes(5))}
    end
  end

  defp poll_current_generation(state) do
    case do_poll_events(state) do
      {:ok, _count, new_state} ->
        {:noreply, schedule_poll(new_state, new_state.poll_interval)}

      {:error, _reason, new_state} ->
        {:noreply, schedule_poll(new_state, new_state.poll_interval)}
    end
  end

  # ============================================================================
  # Authentication
  # ============================================================================

  defp authenticate(state) do
    url = String.replace(@token_url, "{tenant}", state.tenant_id)

    body =
      URI.encode_query(%{
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

      {:ok, %{status: status}} ->
        {:error, {:auth_failed, status}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  defp ensure_token(state) do
    cond do
      not state.enabled -> {:error, :integration_disabled}
      not credentials_configured?(state) -> {:error, :integration_not_configured}
      token_expired?(state) -> authenticate(state)
      true -> {:ok, state}
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
        with {:ok, security_events} <- state.poll_adapter.fetch_security_events(state),
             {:ok, email_threats} <- state.poll_adapter.fetch_email_threats(state) do
          all_events = security_events ++ email_threats
          count = length(all_events)

          Enum.each(all_events, &process_email_event(&1, state))

          new_state = %{
            state
            | last_poll_time: DateTime.utc_now(),
              stats: %{
                state.stats
                | emails_collected: state.stats.emails_collected + count,
                  api_calls: state.stats.api_calls + 2
              }
          }

          Logger.debug("M365 poll complete: #{count} events collected")
          {:ok, count, new_state}
        else
          {:error, reason} -> {:error, sanitize_error(reason), update_error(state, reason)}
        end

      {:error, reason} ->
        {:error, reason, update_error(state, reason)}
    end
  end

  defp fetch_security_events_from_api(state) do
    url =
      "#{@security_base_url}/alerts_v2?" <>
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
        {:error, :invalid_provider_response}

      {:error, reason} ->
        Logger.warning("Failed to fetch M365 security events: #{inspect(sanitize_error(reason))}")
        {:error, reason}
    end
  end

  @doc false
  def fetch_security_events(state), do: fetch_security_events_from_api(state)

  defp fetch_email_threats_from_api(state) do
    # Use Exchange Online Protection threat data
    url =
      "#{@graph_base_url}/security/threatSubmissions/emailThreats?" <>
        URI.encode_query(%{
          "$top" => "100",
          "$orderby" => "createdDateTime desc"
        })

    case graph_request(state, :get, url) do
      {:ok, %{"value" => threats}} ->
        normalized = Enum.map(threats, &normalize_email_threat/1)
        {:ok, normalized}

      {:ok, _} ->
        {:error, :invalid_provider_response}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc false
  def fetch_email_threats(state), do: fetch_email_threats_from_api(state)

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

  defp process_email_event(%EmailEvent{} = event, %__MODULE__{} = state) do
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
      attachments:
        Enum.map(event.attachments, fn att ->
          %{
            filename: att["name"] || att["fileName"],
            sha256: att["sha256"],
            content_type: att["contentType"]
          }
        end),
      organization_id: state.organization_id,
      source: :microsoft365
    }

    # Trigger analysis
    Task.start(fn ->
      case PhishingTriage.analyze_email_for_organization(state.organization_id, email_data) do
        {:ok, _result} ->
          :ok

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

    url =
      "#{@graph_base_url}/security/threatAssessmentRequests?" <>
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
    url =
      "#{@security_base_url}/tiIndicators?" <>
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
    url =
      "#{@graph_base_url}/security/quarantineMessages?" <>
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
        {:ok,
         %{
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
        results =
          Enum.map(hits, fn hit ->
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

    url =
      "#{@security_base_url}/alerts_v2?" <>
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

    filters =
      if category = Keyword.get(opts, :category) do
        ["category eq '#{category}'" | filters]
      else
        filters
      end

    filters =
      if severity = Keyword.get(opts, :severity) do
        ["severity eq '#{severity}'" | filters]
      else
        filters
      end

    filters =
      if status = Keyword.get(opts, :status) do
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

    result =
      case method do
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

      {:ok, %{status: status}} ->
        {:error, {:api_error, status}}

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

  defp maybe_schedule_authentication(state, delay) do
    if runtime_configured?(state), do: schedule_authentication(state, delay), else: state
  end

  defp schedule_authentication(state, delay) do
    state = cancel_timer(state, :auth_timer_ref)
    ref = Process.send_after(self(), {:authenticate, state.config_generation}, delay)
    %{state | auth_timer_ref: ref}
  end

  defp schedule_poll(state, interval) do
    state = cancel_timer(state, :poll_timer_ref)
    ref = Process.send_after(self(), {:poll, state.config_generation}, interval)
    %{state | poll_timer_ref: ref}
  end

  defp cancel_runtime_timers(state) do
    state
    |> cancel_timer(:auth_timer_ref)
    |> cancel_timer(:poll_timer_ref)
  end

  defp cancel_timer(state, field) do
    if ref = Map.get(state, field), do: Process.cancel_timer(ref)
    Map.put(state, field, nil)
  end

  defp runtime_configured?(state) do
    state.enabled and credentials_configured?(state)
  end

  defp credentials_configured?(state) do
    present?(state.tenant_id) and present?(state.client_id) and present?(state.client_secret)
  end

  defp present?(value), do: is_binary(value) and byte_size(String.trim(value)) > 0

  defp normalize_poll_interval(value, fallback) when is_binary(value) do
    case Integer.parse(value) do
      {parsed, ""} -> normalize_poll_interval(parsed, fallback)
      _ -> fallback
    end
  end

  defp normalize_poll_interval(value, _fallback) when is_integer(value) do
    value |> max(@min_poll_interval) |> min(@max_poll_interval)
  end

  defp normalize_poll_interval(_value, fallback), do: fallback

  defp prepare_config_patch(organization_id, config) when is_map(config) do
    cond do
      Map.has_key?(config, :client_secret) and is_nil(config.client_secret) ->
        {:error, :secret_cannot_be_null}

      true ->
        with {:ok, current} <- current_runtime_config(organization_id) do
          fallback = Map.get(current, :poll_interval_ms, @default_poll_interval)

          prepared =
            if Map.has_key?(config, :poll_interval_ms) do
              Map.put(
                config,
                :poll_interval_ms,
                normalize_poll_interval(config.poll_interval_ms, fallback)
              )
            else
              config
            end

          {:ok, prepared}
        end
    end
  end

  defp prepare_config_patch(_organization_id, _config), do: {:error, :invalid_config}

  defp current_runtime_config(organization_id) do
    case RuntimeConfigStore.fetch(__MODULE__, organization_id) do
      {:ok, _revision, config} -> {:ok, config}
      {:error, :integration_not_configured} -> {:ok, %{}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp update_stats(state, key) do
    new_stats = Map.update(state.stats, key, 1, &(&1 + 1))
    %{state | stats: new_stats}
  end

  defp update_error(state, reason) do
    new_stats = %{
      state.stats
      | errors: state.stats.errors + 1,
        last_error: %{
          reason: inspect(sanitize_error(reason)),
          time: DateTime.utc_now()
        }
    }

    %{state | stats: new_stats}
  end

  defp sanitize_error({:auth_failed, status, _body}), do: {:auth_failed, status}
  defp sanitize_error({:api_error, status, _body}), do: {:api_error, status}
  defp sanitize_error({:http_error, reason}), do: {:http_error, error_kind(reason)}
  defp sanitize_error(reason), do: reason

  defp error_kind(reason) when is_atom(reason), do: reason
  defp error_kind(%{__struct__: module}) when is_atom(module), do: module
  defp error_kind(_reason), do: :request_failed

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
          [
            %{
              "name" => e["fileName"],
              "sha256" => get_in(e, ["fileDetails", "sha256"]),
              "sha1" => get_in(e, ["fileDetails", "sha1"]),
              "md5" => get_in(e, ["fileDetails", "md5"])
            }
          ]

        _ ->
          []
      end
    end)
  end
end
