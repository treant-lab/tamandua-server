defmodule TamanduaServer.Integrations.Webhook.InboundRouter do
  @moduledoc """
  Inbound webhook processor for receiving events from external SIEM/SOAR platforms.

  Provides:
  - `process_webhook/3` - Route incoming webhooks by source type
  - Support for sources: splunk, sentinel, qradar, pagerduty, slack, generic
  - Event normalization: map external format to internal alert/enrichment
  - Signature verification (HMAC-SHA256 for authenticated sources)
  - Rate limiting per source
  - Audit logging of all inbound webhooks

  Uses an ETS table to track webhook audit history and per-source rate limits.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Integrations.IntegrationLog

  @ets_table :inbound_webhook_audit
  @rate_limit_table :inbound_webhook_rates
  @default_rate_limit_per_minute 120
  @cleanup_interval :timer.hours(1)
  @retention_seconds 7 * 24 * 60 * 60

  @known_sources ~w(splunk sentinel qradar pagerduty slack generic)

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Process an incoming webhook payload from an external source.

  ## Parameters

  - `source` - Source identifier: "splunk", "sentinel", "qradar", "pagerduty", "slack", "generic"
  - `payload` - The raw webhook payload (map)
  - `opts` - Optional: `:signature` (HMAC), `:secret` (for verification), `:headers` (raw headers)

  ## Returns

  `{:ok, normalized}` with the normalized event(s), or `{:error, reason}` on failure.
  """
  @spec process_webhook(String.t(), map(), keyword()) :: {:ok, map()} | {:error, term()}
  def process_webhook(source, payload, opts \\ []) do
    source = normalize_source(source)

    with :ok <- check_rate_limit(source),
         :ok <- verify_signature(source, payload, opts) do
      start_time = System.monotonic_time(:millisecond)

      result = normalize_payload(source, payload)

      duration = System.monotonic_time(:millisecond) - start_time
      record_audit(source, payload, result, duration)
      increment_rate(source)

      result
    end
  end

  @doc """
  Get webhook audit history with optional filtering.

  ## Parameters

  - `opts` - Optional: `:source`, `:status`, `:limit` (default 100), `:offset` (default 0)

  ## Returns

  `{entries, total}` tuple.
  """
  @spec webhook_history(keyword()) :: {list(map()), non_neg_integer()}
  def webhook_history(opts \\ []) do
    source_filter = Keyword.get(opts, :source)
    status_filter = Keyword.get(opts, :status)
    limit = Keyword.get(opts, :limit, 100)
    offset = Keyword.get(opts, :offset, 0)

    ensure_table_exists(@ets_table)

    all =
      :ets.tab2list(@ets_table)
      |> Enum.map(fn {_id, entry} -> entry end)
      |> Enum.filter(fn entry ->
        (is_nil(source_filter) or entry.source == source_filter) and
          (is_nil(status_filter) or entry.status == status_filter)
      end)
      |> Enum.sort_by(& &1.timestamp, {:desc, DateTime})

    total = length(all)
    entries = all |> Enum.drop(offset) |> Enum.take(limit)
    {entries, total}
  end

  @doc """
  Verify an HMAC-SHA256 signature against a payload.

  ## Parameters

  - `payload_body` - Raw body string
  - `signature` - The signature header value (e.g., "sha256=abcdef...")
  - `secret` - The shared secret

  ## Returns

  `true` if valid, `false` otherwise.
  """
  @spec verify_hmac(String.t(), String.t(), String.t()) :: boolean()
  def verify_hmac(payload_body, signature, secret) do
    expected =
      :crypto.mac(:hmac, :sha256, secret, payload_body)
      |> Base.encode16(case: :lower)

    expected_prefixed = "sha256=#{expected}"

    Plug.Crypto.secure_compare(expected_prefixed, signature) or
      Plug.Crypto.secure_compare(expected, signature)
  end

  @doc """
  List known webhook source types.
  """
  @spec known_sources() :: list(String.t())
  def known_sources, do: @known_sources

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    ensure_table_exists(@ets_table)
    ensure_table_exists(@rate_limit_table)
    schedule_cleanup()
    Logger.info("[InboundRouter] Started webhook inbound router")
    {:ok, %{}}
  end

  @impl true
  def handle_info(:cleanup, state) do
    cleanup_old_entries()
    cleanup_rate_limits()
    schedule_cleanup()
    {:noreply, state}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private: Payload Normalization
  # ============================================================================

  defp normalize_payload("splunk", payload) do
    # Splunk alert webhook format
    result = %{
      source: "splunk",
      type: determine_splunk_type(payload),
      title: payload["search_name"] || payload["name"] || "Splunk Alert",
      description: payload["message"] || payload["description"],
      severity: map_splunk_severity(payload["severity"] || payload["priority"]),
      raw_data: payload,
      events: extract_splunk_events(payload),
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
    }

    {:ok, result}
  end

  defp normalize_payload("sentinel", payload) do
    # Azure Sentinel Logic App / Alert Rule webhook
    properties = payload["properties"] || payload

    result = %{
      source: "sentinel",
      type: :alert,
      title: properties["alertDisplayName"] || properties["title"] || "Sentinel Alert",
      description: properties["description"],
      severity: map_sentinel_severity(properties["severity"]),
      incident_id: properties["incidentNumber"] || payload["name"],
      tactics: properties["tactics"] || [],
      raw_data: payload,
      timestamp: properties["createdTimeUtc"] || DateTime.utc_now() |> DateTime.to_iso8601()
    }

    {:ok, result}
  end

  defp normalize_payload("qradar", payload) do
    # QRadar SOAR / offense forwarding
    result = %{
      source: "qradar",
      type: :offense,
      title: payload["description"] || "QRadar Offense",
      description: payload["description"],
      severity: map_qradar_severity(payload["severity"] || payload["magnitude"]),
      offense_id: payload["id"],
      categories: payload["categories"] || [],
      source_ips: payload["source_address_ids"] || [],
      raw_data: payload,
      timestamp: format_qradar_timestamp(payload["start_time"])
    }

    {:ok, result}
  end

  defp normalize_payload("pagerduty", payload) do
    # PagerDuty webhook v3
    messages = payload["messages"] || [payload]

    events =
      Enum.map(messages, fn msg ->
        event = msg["event"] || msg
        incident = event["data"] || event["incident"] || event

        %{
          type: event["event_type"] || "incident",
          title: incident["title"] || "PagerDuty Incident",
          description: incident["description"] || incident["summary"],
          severity: map_pagerduty_severity(incident["urgency"]),
          incident_id: incident["id"],
          status: incident["status"],
          service: get_in(incident, ["service", "name"])
        }
      end)

    result = %{
      source: "pagerduty",
      type: :incident,
      events: events,
      raw_data: payload,
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
    }

    {:ok, result}
  end

  defp normalize_payload("slack", payload) do
    # Slack interactive message or slash command
    result = %{
      source: "slack",
      type: :interaction,
      action: payload["type"],
      user: get_in(payload, ["user", "name"]) || payload["user_name"],
      channel: get_in(payload, ["channel", "name"]) || payload["channel_name"],
      text: payload["text"],
      callback_id: payload["callback_id"],
      actions: payload["actions"] || [],
      raw_data: payload,
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
    }

    {:ok, result}
  end

  defp normalize_payload("generic", payload) do
    result = %{
      source: "generic",
      type: payload["type"] || :event,
      title: payload["title"] || payload["name"] || "External Webhook",
      description: payload["description"] || payload["message"],
      severity: payload["severity"] || "info",
      raw_data: payload,
      timestamp: payload["timestamp"] || DateTime.utc_now() |> DateTime.to_iso8601()
    }

    {:ok, result}
  end

  defp normalize_payload(source, payload) do
    # Unknown source: treat as generic
    normalize_payload("generic", Map.put(payload, "source_type", source))
  end

  # ============================================================================
  # Private: Source-Specific Helpers
  # ============================================================================

  defp determine_splunk_type(%{"result" => _}), do: :search_result
  defp determine_splunk_type(%{"sid" => _}), do: :saved_search
  defp determine_splunk_type(_), do: :alert

  defp extract_splunk_events(%{"result" => result}) when is_map(result), do: [result]
  defp extract_splunk_events(%{"results" => results}) when is_list(results), do: results
  defp extract_splunk_events(_), do: []

  defp map_splunk_severity(nil), do: "medium"
  defp map_splunk_severity(s) when is_integer(s) and s >= 8, do: "critical"
  defp map_splunk_severity(s) when is_integer(s) and s >= 6, do: "high"
  defp map_splunk_severity(s) when is_integer(s) and s >= 4, do: "medium"
  defp map_splunk_severity(s) when is_integer(s), do: "low"
  defp map_splunk_severity(s) when is_binary(s), do: String.downcase(s)
  defp map_splunk_severity(_), do: "medium"

  defp map_sentinel_severity("High"), do: "high"
  defp map_sentinel_severity("Medium"), do: "medium"
  defp map_sentinel_severity("Low"), do: "low"
  defp map_sentinel_severity("Informational"), do: "info"
  defp map_sentinel_severity(_), do: "medium"

  defp map_qradar_severity(nil), do: "medium"
  defp map_qradar_severity(s) when is_integer(s) and s >= 8, do: "critical"
  defp map_qradar_severity(s) when is_integer(s) and s >= 6, do: "high"
  defp map_qradar_severity(s) when is_integer(s) and s >= 4, do: "medium"
  defp map_qradar_severity(s) when is_integer(s), do: "low"
  defp map_qradar_severity(_), do: "medium"

  defp map_pagerduty_severity("high"), do: "high"
  defp map_pagerduty_severity("low"), do: "low"
  defp map_pagerduty_severity(_), do: "medium"

  defp format_qradar_timestamp(nil), do: DateTime.utc_now() |> DateTime.to_iso8601()
  defp format_qradar_timestamp(ms) when is_integer(ms) do
    DateTime.from_unix!(div(ms, 1000)) |> DateTime.to_iso8601()
  end
  defp format_qradar_timestamp(ts), do: to_string(ts)

  # ============================================================================
  # Private: Signature Verification
  # ============================================================================

  defp verify_signature(source, _payload, opts) do
    signature = Keyword.get(opts, :signature)
    raw_body = Keyword.get(opts, :raw_body)

    # SECURITY: Get secret from server-side config ONLY, never from request
    # This prevents attackers from bypassing signature verification by
    # supplying their own secret in the request payload
    secret = get_webhook_secret_for_source(source)

    cond do
      is_nil(secret) ->
        # No secret configured - fail closed in production
        if allow_insecure_webhook?() do
          Logger.warning("[InboundRouter] No secret configured for source #{source} - allowing in insecure mode")
          :ok
        else
          Logger.warning("[InboundRouter] No secret configured for source #{source} - rejecting webhook")
          {:error, :no_secret_configured}
        end

      is_nil(signature) ->
        if allow_insecure_webhook?() do
          Logger.warning("[InboundRouter] Missing signature for source #{source} - allowing in insecure mode")
          :ok
        else
          {:error, :missing_signature}
        end

      is_binary(signature) and is_binary(raw_body) ->
        if verify_hmac(raw_body, signature, secret) do
          :ok
        else
          {:error, :invalid_signature}
        end

      is_binary(signature) ->
        # No raw body available - cannot verify
        Logger.warning("[InboundRouter] No raw body available for signature verification")
        {:error, :invalid_signature}

      true ->
        {:error, :invalid_signature}
    end
  end

  # Get webhook secret from server-side configuration ONLY
  # NEVER accept secrets from request params/opts (security vulnerability)
  defp get_webhook_secret_for_source(source) do
    # Check application config for source-specific secrets
    config_key = String.to_atom("webhook_secret_#{source}")
    Application.get_env(:tamandua_server, config_key) ||
      Application.get_env(:tamandua_server, :webhook_secrets, %{})[source] ||
      Application.get_env(:tamandua_server, :default_webhook_secret)
  end

  # Only allow insecure webhooks in dev/test with explicit config
  defp allow_insecure_webhook? do
    Application.get_env(:tamandua_server, :webhook_insecure_mode, false) and
      Application.get_env(:tamandua_server, :env) in [:dev, :test]
  end

  # ============================================================================
  # Private: Rate Limiting
  # ============================================================================

  defp check_rate_limit(source) do
    ensure_table_exists(@rate_limit_table)
    now = System.system_time(:second)
    minute_key = {source, div(now, 60)}

    count =
      case :ets.lookup(@rate_limit_table, minute_key) do
        [{_, c}] -> c
        [] -> 0
      end

    if count >= @default_rate_limit_per_minute do
      {:error, :rate_limited}
    else
      :ok
    end
  end

  defp increment_rate(source) do
    ensure_table_exists(@rate_limit_table)
    now = System.system_time(:second)
    minute_key = {source, div(now, 60)}

    try do
      :ets.update_counter(@rate_limit_table, minute_key, {2, 1})
    catch
      :error, :badarg ->
        :ets.insert(@rate_limit_table, {minute_key, 1})
    end
  end

  # ============================================================================
  # Private: Audit Logging
  # ============================================================================

  defp record_audit(source, payload, result, duration_ms) do
    ensure_table_exists(@ets_table)

    status =
      case result do
        {:ok, _} -> "success"
        {:error, _} -> "error"
      end

    entry = %{
      id: generate_id(),
      source: source,
      status: status,
      payload_size: estimate_size(payload),
      duration_ms: duration_ms,
      error: extract_error(result),
      timestamp: DateTime.utc_now()
    }

    :ets.insert(@ets_table, {entry.id, entry})

    IntegrationLog.log_call("webhook_inbound:#{source}", "process_webhook", %{
      status: status,
      duration_ms: duration_ms,
      error_message: extract_error(result)
    })

    entry
  end

  defp extract_error({:error, reason}), do: inspect(reason)
  defp extract_error(_), do: nil

  defp estimate_size(payload) when is_map(payload) do
    case Jason.encode(payload) do
      {:ok, json} -> byte_size(json)
      _ -> 0
    end
  end

  defp estimate_size(_), do: 0

  # ============================================================================
  # Private: Utilities
  # ============================================================================

  defp normalize_source(source) when is_binary(source) do
    lower = String.downcase(source)
    if lower in @known_sources, do: lower, else: "generic"
  end

  defp normalize_source(_), do: "generic"

  defp ensure_table_exists(table_name) do
    case :ets.whereis(table_name) do
      :undefined ->
        :ets.new(table_name, [:named_table, :set, :public, read_concurrency: true, write_concurrency: true])

      _ ->
        :ok
    end
  rescue
    ArgumentError -> :ok
  end

  defp cleanup_old_entries do
    cutoff = DateTime.add(DateTime.utc_now(), -@retention_seconds, :second)

    case :ets.whereis(@ets_table) do
      :undefined ->
        :ok

      _ ->
        :ets.tab2list(@ets_table)
        |> Enum.each(fn {id, entry} ->
          if DateTime.compare(entry.timestamp, cutoff) == :lt do
            :ets.delete(@ets_table, id)
          end
        end)
    end
  end

  defp cleanup_rate_limits do
    now = System.system_time(:second)
    current_minute = div(now, 60)

    case :ets.whereis(@rate_limit_table) do
      :undefined ->
        :ok

      _ ->
        :ets.tab2list(@rate_limit_table)
        |> Enum.each(fn {{_source, minute} = key, _count} ->
          if minute < current_minute - 2 do
            :ets.delete(@rate_limit_table, key)
          end
        end)
    end
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval)
  end

  defp generate_id do
    "wh_" <> Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)
  end
end
