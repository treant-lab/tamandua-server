defmodule TamanduaServer.Integrations.WebhookReceiver do
  @moduledoc """
  Webhook Receiver for bidirectional synchronization with SIEM/SOAR/Ticketing systems.

  Processes incoming webhooks from external systems to synchronize alert status,
  enrichment data, and investigation updates back into Tamandua.

  ## Features

  - Generic webhook endpoint with integration-specific routing
  - Authentication via HMAC signatures, API keys, OAuth tokens
  - Payload parsing and validation
  - Deduplication via webhook ID tracking
  - Integration-specific parsers (Splunk, QRadar, Jira, ServiceNow, PagerDuty, Slack)
  - Automatic alert status mapping and synchronization
  - PubSub broadcasting for real-time UI updates
  - Comprehensive audit logging
  - Rate limiting per integration
  - Replay attack prevention (timestamp validation)

  ## Supported Integrations

  - **Splunk**: Alert closed/updated webhooks
  - **QRadar**: Offense updated webhooks
  - **Jira**: Issue status changed webhooks
  - **ServiceNow**: Incident/ticket resolved webhooks
  - **PagerDuty**: Incident acknowledged/resolved webhooks
  - **Slack**: Interactive button responses
  - **Microsoft Sentinel**: Incident status webhooks
  - **Generic**: Configurable webhook format

  ## Usage

      # Process an incoming webhook
      WebhookReceiver.process_webhook(integration_id, payload, headers)

      # Verify webhook signature
      WebhookReceiver.verify_webhook_signature(integration, payload, signature)
  """

  use GenServer
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Integrations.{Config, WebhookDelivery, IntegrationSyncState}
  alias TamanduaServer.Integrations.WebhookParsers

  import Ecto.Query

  @rate_limit_per_minute 120
  @replay_attack_window_seconds 300 # 5 minutes
  @dedup_window_hours 24

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Process an incoming webhook from an external integration.

  ## Parameters

  - `integration_type` - Integration type atom (:splunk, :jira, :pagerduty, etc.)
  - `integration_id` - UUID of the integration configuration
  - `payload` - The webhook payload (map)
  - `opts` - Options:
    - `:headers` - Request headers map
    - `:raw_body` - Raw request body string (for signature verification)
    - `:remote_ip` - Remote IP address for rate limiting

  ## Returns

  - `{:ok, result}` - Successfully processed webhook
  - `{:error, reason}` - Failed to process webhook
  """
  @spec process_webhook(atom(), binary(), map(), keyword()) :: {:ok, map()} | {:error, term()}
  def process_webhook(integration_type, integration_id, payload, opts \\ []) do
    GenServer.call(__MODULE__, {
      :process_webhook,
      integration_type,
      integration_id,
      payload,
      opts
    }, 30_000)
  end

  @doc """
  Verify a webhook signature for authentication.

  ## Parameters

  - `integration` - Integration config struct
  - `raw_body` - Raw request body string
  - `signature` - Signature from request header
  - `opts` - Additional options (e.g., `:timestamp` for replay protection)

  ## Returns

  - `:ok` - Signature is valid
  - `{:error, reason}` - Signature is invalid or verification failed
  """
  @spec verify_webhook_signature(map(), binary(), binary(), keyword()) :: :ok | {:error, term()}
  def verify_webhook_signature(integration, raw_body, signature, opts \\ []) do
    # SECURITY: Get secret from server-side config (integration.config) ONLY
    # Never accept secrets from request payload or opts
    case integration.config["webhook_secret"] || integration.config[:webhook_secret] do
      nil ->
        # No secret configured - fail closed in production
        if allow_insecure_webhook?() do
          Logger.warning("[WebhookReceiver] No webhook secret configured for integration #{integration.id} - allowing in insecure mode")
          :ok
        else
          Logger.warning("[WebhookReceiver] No webhook secret configured for integration #{integration.id} - rejecting")
          {:error, :no_secret_configured}
        end

      secret ->
        # Extract algorithm from config (default SHA256)
        algorithm = get_signature_algorithm(integration)

        # Verify HMAC signature
        case verify_hmac_signature(raw_body, signature, secret, algorithm) do
          true ->
            # Check for replay attacks if timestamp is provided
            verify_timestamp(opts[:timestamp])

          false ->
            {:error, :invalid_signature}
        end
    end
  end

  # Only allow insecure webhooks in dev/test with explicit config
  defp allow_insecure_webhook? do
    Application.get_env(:tamandua_server, :webhook_insecure_mode, false) and
      Application.get_env(:tamandua_server, :env) in [:dev, :test]
  end

  @doc """
  Get webhook delivery history for an integration.
  """
  @spec get_webhook_history(binary(), keyword()) :: {:ok, list(), non_neg_integer()}
  def get_webhook_history(integration_id, opts \\ []) do
    GenServer.call(__MODULE__, {:get_webhook_history, integration_id, opts})
  end

  @doc """
  Get sync state for an alert and integration.
  """
  @spec get_sync_state(binary(), binary()) :: {:ok, map()} | {:error, :not_found}
  def get_sync_state(alert_id, integration_id) do
    case Repo.get_by(IntegrationSyncState, alert_id: alert_id, integration_id: integration_id) do
      nil -> {:error, :not_found}
      state -> {:ok, state}
    end
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    Logger.info("[WebhookReceiver] Starting webhook receiver")

    state = %{
      rate_limits: %{},
      stats: %{
        total_received: 0,
        total_processed: 0,
        total_failed: 0,
        by_integration: %{}
      }
    }

    # Schedule periodic cleanup
    schedule_cleanup()

    {:ok, state}
  end

  @impl true
  def handle_call({:process_webhook, integration_type, integration_id, payload, opts}, _from, state) do
    start_time = System.monotonic_time(:millisecond)

    result = with :ok <- check_rate_limit(integration_id, state),
                  {:ok, integration} <- get_integration(integration_id),
                  :ok <- verify_authentication(integration, payload, opts),
                  :ok <- check_deduplication(integration_type, payload),
                  {:ok, parsed} <- parse_webhook(integration_type, payload, opts),
                  {:ok, _delivery} <- record_webhook_delivery(integration, parsed, opts, start_time) do
      # Process the webhook action
      process_webhook_action(integration, parsed)
    end

    # Update stats
    new_state = update_stats(state, integration_type, result)

    {:reply, result, new_state}
  end

  @impl true
  def handle_call({:get_webhook_history, integration_id, opts}, _from, state) do
    limit = Keyword.get(opts, :limit, 50)
    offset = Keyword.get(opts, :offset, 0)
    status_filter = Keyword.get(opts, :status)

    query = from d in WebhookDelivery,
      where: d.integration_id == ^integration_id and d.direction == "inbound",
      order_by: [desc: d.inserted_at],
      limit: ^limit,
      offset: ^offset

    query = if status_filter do
      from d in query, where: d.status == ^status_filter
    else
      query
    end

    deliveries = Repo.all(query)

    total = Repo.one(
      from d in WebhookDelivery,
      where: d.integration_id == ^integration_id and d.direction == "inbound",
      select: count(d.id)
    )

    {:reply, {:ok, deliveries, total}, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    cleanup_old_deliveries()
    schedule_cleanup()
    {:noreply, state}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions - Authentication
  # ============================================================================

  defp verify_authentication(integration, payload, opts) do
    headers = Keyword.get(opts, :headers, %{})
    raw_body = Keyword.get(opts, :raw_body)

    cond do
      # HMAC signature verification
      signature = get_signature_header(headers, integration) ->
        verify_webhook_signature(integration, raw_body || Jason.encode!(payload), signature, opts)

      # API key verification
      api_key = get_api_key_header(headers, integration) ->
        verify_api_key(integration, api_key)

      # OAuth token verification
      token = get_bearer_token(headers) ->
        verify_oauth_token(integration, token)

      # IP whitelist check
      remote_ip = Keyword.get(opts, :remote_ip) ->
        verify_ip_whitelist(integration, remote_ip)

      # No authentication configured
      true ->
        :ok
    end
  end

  defp verify_hmac_signature(body, signature, secret, algorithm) do
    expected = compute_hmac(body, secret, algorithm)

    # Support multiple signature formats:
    # - "sha256=abc123"
    # - "abc123"
    signature_clean = String.replace(signature, ~r/^(sha1|sha256|sha512)=/, "")
    expected_clean = String.replace(expected, ~r/^(sha1|sha256|sha512)=/, "")

    Plug.Crypto.secure_compare(expected_clean, signature_clean)
  end

  defp compute_hmac(body, secret, algorithm) do
    algo = case algorithm do
      :sha256 -> :sha256
      :sha512 -> :sha512
      :sha1 -> :sha
      "sha256" -> :sha256
      "sha512" -> :sha512
      "sha1" -> :sha
      _ -> :sha256
    end

    mac = :crypto.mac(:hmac, algo, secret, body)
    hash = Base.encode16(mac, case: :lower)

    "#{algorithm}=#{hash}"
  end

  defp verify_api_key(integration, provided_key) do
    expected_key = integration.config["api_key"] || integration.config[:api_key]

    if expected_key && Plug.Crypto.secure_compare(expected_key, provided_key) do
      :ok
    else
      {:error, :invalid_api_key}
    end
  end

  defp verify_oauth_token(integration, token) do
    # TODO: Implement OAuth token verification
    # For now, just check if token matches configured token
    expected_token = integration.config["oauth_token"] || integration.config[:oauth_token]

    if expected_token && Plug.Crypto.secure_compare(expected_token, token) do
      :ok
    else
      {:error, :invalid_token}
    end
  end

  defp verify_ip_whitelist(integration, remote_ip) do
    whitelist = integration.config["ip_whitelist"] || integration.config[:ip_whitelist]

    case whitelist do
      nil -> :ok
      [] -> :ok
      ips when is_list(ips) ->
        if remote_ip in ips do
          :ok
        else
          {:error, :ip_not_whitelisted}
        end
      _ -> :ok
    end
  end

  defp verify_timestamp(nil), do: :ok
  defp verify_timestamp(timestamp) when is_binary(timestamp) do
    case Integer.parse(timestamp) do
      {ts, _} -> verify_timestamp(ts)
      :error -> {:error, :invalid_timestamp}
    end
  end
  defp verify_timestamp(timestamp) when is_integer(timestamp) do
    now = System.system_time(:second)
    diff = abs(now - timestamp)

    if diff <= @replay_attack_window_seconds do
      :ok
    else
      {:error, :replay_attack}
    end
  end

  defp get_signature_header(headers, integration) do
    header_name = integration.config["signature_header"] || integration.config[:signature_header] || "x-signature"

    headers[header_name] || headers[String.downcase(header_name)] || headers[String.upcase(header_name)]
  end

  defp get_api_key_header(headers, integration) do
    header_name = integration.config["api_key_header"] || integration.config[:api_key_header] || "x-api-key"

    headers[header_name] || headers[String.downcase(header_name)] || headers[String.upcase(header_name)]
  end

  defp get_bearer_token(headers) do
    case headers["authorization"] || headers["Authorization"] do
      "Bearer " <> token -> token
      _ -> nil
    end
  end

  defp get_signature_algorithm(integration) do
    integration.config["signature_algorithm"] || integration.config[:signature_algorithm] || :sha256
  end

  # ============================================================================
  # Private Functions - Deduplication
  # ============================================================================

  defp check_deduplication(integration_type, payload) do
    webhook_id = extract_webhook_id(integration_type, payload)

    if webhook_id do
      cutoff = DateTime.add(DateTime.utc_now(), -@dedup_window_hours * 3600, :second)

      existing = Repo.one(
        from d in WebhookDelivery,
        where: d.webhook_id == ^webhook_id
          and d.integration_type == ^to_string(integration_type)
          and d.direction == "inbound"
          and d.inserted_at > ^cutoff
      )

      if existing do
        {:error, :duplicate_webhook}
      else
        :ok
      end
    else
      # No webhook ID - allow duplicate
      :ok
    end
  end

  defp extract_webhook_id(:splunk, payload) do
    payload["sid"] || payload["search_id"]
  end

  defp extract_webhook_id(:jira, payload) do
    get_in(payload, ["webhookEvent"]) <> "_" <> get_in(payload, ["issue", "id"])
  end

  defp extract_webhook_id(:servicenow, payload) do
    get_in(payload, ["sys_id"])
  end

  defp extract_webhook_id(:pagerduty, payload) do
    get_in(payload, ["event", "id"]) || get_in(payload, ["id"])
  end

  defp extract_webhook_id(:slack, payload) do
    payload["callback_id"] || payload["message_ts"]
  end

  defp extract_webhook_id(:sentinel, payload) do
    get_in(payload, ["properties", "incidentNumber"]) || payload["name"]
  end

  defp extract_webhook_id(:qradar, payload) do
    to_string(payload["id"])
  end

  defp extract_webhook_id(_, payload) do
    payload["id"] || payload["event_id"] || payload["webhook_id"]
  end

  # ============================================================================
  # Private Functions - Parsing
  # ============================================================================

  defp parse_webhook(integration_type, payload, opts) do
    parser = WebhookParsers.get_parser(integration_type)

    if parser && function_exported?(parser, :parse, 2) do
      parser.parse(payload, opts)
    else
      # Fallback to generic parser
      WebhookParsers.Generic.parse(payload, opts)
    end
  end

  # ============================================================================
  # Private Functions - Processing
  # ============================================================================

  defp process_webhook_action(integration, parsed_webhook) do
    case parsed_webhook.action_type do
      :alert_status_update ->
        update_alert_status(parsed_webhook, integration)

      :alert_enrichment ->
        enrich_alert(parsed_webhook, integration)

      :alert_comment ->
        add_alert_comment(parsed_webhook, integration)

      :incident_sync ->
        sync_incident_state(parsed_webhook, integration)

      :interactive_response ->
        handle_interactive_response(parsed_webhook, integration)

      _ ->
        {:ok, %{action: :logged}}
    end
  end

  defp update_alert_status(parsed, integration) do
    with {:ok, alert} <- find_alert(parsed.alert_reference, integration),
         {:ok, tamandua_status} <- map_external_status(parsed.external_status, integration.type),
         {:ok, updated_alert} <- update_alert(alert, tamandua_status, parsed) do

      # Update sync state
      update_sync_state(alert.id, integration.id, parsed)

      # Broadcast to UI
      broadcast_alert_update(updated_alert)

      {:ok, %{alert: updated_alert, action: :status_updated}}
    end
  end

  defp enrich_alert(parsed, integration) do
    with {:ok, alert} <- find_alert(parsed.alert_reference, integration) do
      enrichment = Map.merge(alert.enrichment || %{}, parsed.enrichment_data || %{})

      alert
      |> Alert.changeset(%{enrichment: enrichment})
      |> Repo.update()
      |> case do
        {:ok, updated_alert} ->
          broadcast_alert_update(updated_alert)
          {:ok, %{alert: updated_alert, action: :enriched}}

        error ->
          error
      end
    end
  end

  defp add_alert_comment(parsed, integration) do
    with {:ok, alert} <- find_alert(parsed.alert_reference, integration) do
      # Add comment to resolution notes
      comment = format_comment(parsed, integration)
      existing_notes = alert.resolution_notes || ""
      new_notes = "#{existing_notes}\n\n#{comment}" |> String.trim()

      alert
      |> Alert.changeset(%{resolution_notes: new_notes})
      |> Repo.update()
      |> case do
        {:ok, updated_alert} ->
          broadcast_alert_update(updated_alert)
          {:ok, %{alert: updated_alert, action: :comment_added}}

        error ->
          error
      end
    end
  end

  defp sync_incident_state(parsed, integration) do
    with {:ok, alert} <- find_alert(parsed.alert_reference, integration) do
      # Update or create sync state
      attrs = %{
        integration_id: integration.id,
        alert_id: alert.id,
        external_id: parsed.external_id,
        external_url: parsed.external_url,
        external_status: parsed.external_status,
        last_synced_at: DateTime.utc_now(),
        metadata: parsed.metadata || %{}
      }

      case Repo.get_by(IntegrationSyncState, integration_id: integration.id, alert_id: alert.id) do
        nil ->
          %IntegrationSyncState{}
          |> IntegrationSyncState.changeset(attrs)
          |> Repo.insert()

        existing ->
          existing
          |> IntegrationSyncState.changeset(attrs)
          |> Repo.update()
      end
      |> case do
        {:ok, sync_state} ->
          {:ok, %{sync_state: sync_state, action: :synced}}

        error ->
          error
      end
    end
  end

  defp handle_interactive_response(parsed, integration) do
    # Handle interactive responses (e.g., Slack button clicks)
    Logger.info("[WebhookReceiver] Interactive response: #{inspect(parsed)}")
    {:ok, %{action: :interactive_handled, response: parsed}}
  end

  # ============================================================================
  # Private Functions - Alert Helpers
  # ============================================================================

  defp find_alert(reference, integration) do
    cond do
      # Try finding by external ID in sync state
      reference[:external_id] ->
        case Repo.get_by(IntegrationSyncState,
          integration_id: integration.id,
          external_id: reference[:external_id]
        ) do
          %{alert_id: alert_id} ->
            case Repo.get(Alert, alert_id) do
              nil -> {:error, :alert_not_found}
              alert -> {:ok, alert}
            end
          nil -> {:error, :alert_not_found}
        end

      # Try finding by Tamandua alert ID
      reference[:alert_id] ->
        case Repo.get(Alert, reference[:alert_id]) do
          nil -> {:error, :alert_not_found}
          alert -> {:ok, alert}
        end

      # Try finding by title/description match
      reference[:title] ->
        query = from a in Alert,
          where: a.title == ^reference[:title],
          order_by: [desc: a.inserted_at],
          limit: 1

        case Repo.one(query) do
          nil -> {:error, :alert_not_found}
          alert -> {:ok, alert}
        end

      true ->
        {:error, :invalid_alert_reference}
    end
  end

  defp map_external_status(external_status, integration_type) do
    mapping = case integration_type do
      :jira ->
        %{
          "Done" => "resolved",
          "Resolved" => "resolved",
          "Closed" => "resolved",
          "In Progress" => "investigating",
          "To Do" => "new",
          "Open" => "new"
        }

      :servicenow ->
        %{
          "6" => "resolved", # Resolved
          "7" => "resolved", # Closed
          "2" => "investigating", # In Progress
          "1" => "new" # New
        }

      :pagerduty ->
        %{
          "resolved" => "resolved",
          "acknowledged" => "investigating",
          "triggered" => "new"
        }

      :splunk ->
        %{
          "5" => "resolved", # Closed
          "4" => "false_positive", # False Positive
          "2" => "investigating", # In Progress
          "1" => "new" # New
        }

      :sentinel ->
        %{
          "Closed" => "resolved",
          "Active" => "investigating",
          "New" => "new"
        }

      :qradar ->
        %{
          "CLOSED" => "resolved",
          "OPEN" => "investigating",
          "HIDDEN" => "false_positive"
        }

      _ ->
        %{}
    end

    status = mapping[external_status] || external_status

    if status in ~w(new investigating resolved false_positive) do
      {:ok, status}
    else
      {:error, :invalid_status}
    end
  end

  defp update_alert(alert, status, parsed) do
    attrs = %{status: status}

    # Add resolution notes if provided
    attrs = if parsed[:resolution_notes] do
      Map.put(attrs, :resolution_notes, parsed[:resolution_notes])
    else
      attrs
    end

    alert
    |> Alert.changeset(attrs)
    |> Repo.update()
  end

  defp format_comment(parsed, integration) do
    timestamp = DateTime.utc_now() |> DateTime.to_iso8601()
    source = integration.name || to_string(integration.type)
    user = parsed.user || "System"
    comment = parsed.comment || parsed.notes || "Status updated"

    "[#{timestamp}] #{source} - #{user}: #{comment}"
  end

  defp broadcast_alert_update(alert) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "alerts:#{alert.organization_id}",
      {:alert_updated, alert}
    )

    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "alert:#{alert.id}",
      {:alert_updated, alert}
    )

    :ok
  end

  defp update_sync_state(alert_id, integration_id, parsed) do
    attrs = %{
      integration_id: integration_id,
      alert_id: alert_id,
      external_id: parsed.external_id,
      external_url: parsed.external_url,
      external_status: parsed.external_status,
      last_synced_at: DateTime.utc_now(),
      metadata: Map.get(parsed, :metadata, %{})
    }

    case Repo.get_by(IntegrationSyncState, integration_id: integration_id, alert_id: alert_id) do
      nil ->
        %IntegrationSyncState{}
        |> IntegrationSyncState.changeset(attrs)
        |> Repo.insert()

      existing ->
        existing
        |> IntegrationSyncState.changeset(attrs)
        |> Repo.update()
    end
  end

  # ============================================================================
  # Private Functions - Helpers
  # ============================================================================

  defp get_integration(integration_id) do
    Config.get_integration(integration_id)
  end

  defp check_rate_limit(integration_id, state) do
    now = System.system_time(:second)
    minute_key = div(now, 60)
    key = {integration_id, minute_key}

    count = Map.get(state.rate_limits, key, 0)

    if count >= @rate_limit_per_minute do
      {:error, :rate_limited}
    else
      :ok
    end
  end

  defp record_webhook_delivery(integration, parsed, opts, start_time) do
    duration_ms = System.monotonic_time(:millisecond) - start_time
    webhook_id = extract_webhook_id(integration.type, parsed.raw_payload || %{})

    attrs = %{
      integration_id: integration.id,
      integration_type: to_string(integration.type),
      direction: "inbound",
      source: to_string(integration.type),
      event_type: to_string(parsed.action_type),
      status: "delivered",
      payload_size: estimate_payload_size(parsed),
      request_headers: Keyword.get(opts, :headers, %{}),
      duration_ms: duration_ms,
      webhook_id: webhook_id,
      signature_verified: Keyword.get(opts, :signature_verified, false),
      raw_payload: parsed.raw_payload,
      alert_id: parsed[:alert_id],
      organization_id: integration.organization_id,
      metadata: %{
        external_id: parsed[:external_id],
        external_status: parsed[:external_status]
      }
    }

    %WebhookDelivery{}
    |> WebhookDelivery.changeset(attrs)
    |> Repo.insert()
  end

  defp estimate_payload_size(payload) when is_map(payload) do
    case Jason.encode(payload) do
      {:ok, json} -> byte_size(json)
      _ -> 0
    end
  end
  defp estimate_payload_size(_), do: 0

  defp update_stats(state, integration_type, result) do
    stats = state.stats
    |> Map.update!(:total_received, &(&1 + 1))

    stats = case result do
      {:ok, _} ->
        stats
        |> Map.update!(:total_processed, &(&1 + 1))
        |> update_in([:by_integration, integration_type, :processed], &((&1 || 0) + 1))

      {:error, _} ->
        stats
        |> Map.update!(:total_failed, &(&1 + 1))
        |> update_in([:by_integration, integration_type, :failed], &((&1 || 0) + 1))
    end

    %{state | stats: stats}
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, :timer.hours(1))
  end

  defp cleanup_old_deliveries do
    cutoff = DateTime.add(DateTime.utc_now(), -30 * 24 * 3600, :second) # 30 days

    from(d in WebhookDelivery,
      where: d.inserted_at < ^cutoff
    )
    |> Repo.delete_all()
  end
end
