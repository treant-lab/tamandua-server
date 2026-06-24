defmodule TamanduaServerWeb.API.V1.IntegrationsController do
  @moduledoc """
  API Controller for SIEM, SOAR, and Ticketing Integrations.

  Provides endpoints for:
  - CRUD operations on integrations
  - Connection testing
  - Alert routing rules management
  - Integration logs and statistics
  """

  use TamanduaServerWeb, :controller
  require Logger

  alias TamanduaServer.Integrations.Config, as: IntegrationConfig
  alias TamanduaServer.Integrations.Router, as: AlertRouter

  action_fallback TamanduaServerWeb.FallbackController

  @allowed_integration_types ~w(siem soar ticketing webhook email slack teams pagerduty splunk elasticsearch)

  # ============================================================================
  # Integrations CRUD
  # ============================================================================

  @doc """
  List all integrations.
  """
  def index(conn, params) do
    opts = []
    opts = if params["type"] do
      case safe_to_existing_atom(params["type"], @allowed_integration_types) do
        nil -> opts
        type_atom -> [{:type, type_atom} | opts]
      end
    else
      opts
    end
    opts = if params["enabled"], do: [{:enabled, params["enabled"] == "true"} | opts], else: opts
    opts = if params["organization_id"], do: [{:organization_id, params["organization_id"]} | opts], else: opts

    integrations = IntegrationConfig.list_integrations(opts)
    |> Enum.map(&serialize_integration/1)

    json(conn, %{data: integrations})
  end

  @doc """
  Get a single integration by ID.
  """
  def show(conn, %{"id" => id}) do
    case IntegrationConfig.get_integration(id) do
      {:ok, integration} ->
        json(conn, %{data: serialize_integration(integration)})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Integration not found"})
    end
  end

  @doc """
  Create a new integration.
  """
  def create(conn, params) do
    attrs = %{
      type: safe_to_existing_atom(params["type"], @allowed_integration_types),
      name: params["name"],
      description: params["description"],
      config: params["config"] || %{},
      enabled: Map.get(params, "enabled", true),
      organization_id: params["organization_id"]
    }

    case IntegrationConfig.create_integration(attrs) do
      {:ok, integration} ->
        # Reload routing rules to pick up new integration
        AlertRouter.reload_rules()

        conn
        |> put_status(:created)
        |> json(%{data: serialize_integration(integration)})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Validation failed", details: format_errors(changeset)})
    end
  end

  @doc """
  Update an existing integration.
  """
  def update(conn, %{"id" => id} = params) do
    attrs = %{}
    attrs = if params["name"], do: Map.put(attrs, :name, params["name"]), else: attrs
    attrs = if params["description"], do: Map.put(attrs, :description, params["description"]), else: attrs
    attrs = if params["config"], do: Map.put(attrs, :config, params["config"]), else: attrs
    attrs = if Map.has_key?(params, "enabled"), do: Map.put(attrs, :enabled, params["enabled"]), else: attrs

    case IntegrationConfig.update_integration(id, attrs) do
      {:ok, integration} ->
        AlertRouter.reload_rules()
        json(conn, %{data: serialize_integration(integration)})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Integration not found"})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Validation failed", details: format_errors(changeset)})
    end
  end

  @doc """
  Delete an integration.
  """
  def delete(conn, %{"id" => id}) do
    case IntegrationConfig.delete_integration(id) do
      {:ok, _} ->
        AlertRouter.reload_rules()
        send_resp(conn, :no_content, "")

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Integration not found"})
    end
  end

  # ============================================================================
  # Integration Actions
  # ============================================================================

  @doc """
  Test an integration connection.
  """
  def test(conn, %{"id" => id}) do
    case IntegrationConfig.get_integration(id) do
      {:ok, integration} ->
        result = IntegrationConfig.test_integration_config(integration.type, integration.config)

        case result do
          :ok ->
            json(conn, %{success: true, message: "Connection successful"})

          {:ok, details} ->
            json(conn, %{success: true, message: "Connection successful", details: details})

          {:error, :test_not_supported} ->
            json(conn, %{success: false, message: "Connection test not supported for this integration type"})

          {:error, reason} ->
            json(conn, %{success: false, message: "Connection failed", error: to_string(reason)})
        end

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Integration not found"})
    end
  end

  @doc """
  Test integration configuration without saving.
  """
  def test_config(conn, params) do
    type = safe_to_existing_atom(params["type"], @allowed_integration_types)
    config = params["config"] || %{}

    result = IntegrationConfig.test_integration_config(type, config)

    case result do
      :ok ->
        json(conn, %{success: true, message: "Connection successful"})

      {:ok, details} ->
        json(conn, %{success: true, message: "Connection successful", details: details})

      {:error, :test_not_supported} ->
        json(conn, %{success: false, message: "Connection test not supported for this integration type"})

      {:error, reason} ->
        json(conn, %{success: false, message: "Connection failed", error: to_string(reason)})
    end
  end

  @doc """
  Enable an integration.
  """
  def enable(conn, %{"id" => id}) do
    case IntegrationConfig.enable_integration(id) do
      {:ok, integration} ->
        AlertRouter.reload_rules()
        json(conn, %{data: serialize_integration(integration)})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Integration not found"})
    end
  end

  @doc """
  Disable an integration.
  """
  def disable(conn, %{"id" => id}) do
    case IntegrationConfig.disable_integration(id) do
      {:ok, integration} ->
        AlertRouter.reload_rules()
        json(conn, %{data: serialize_integration(integration)})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Integration not found"})
    end
  end

  @doc """
  Get available integration types.
  """
  def types(conn, _params) do
    types = IntegrationConfig.available_types()
    json(conn, %{data: types})
  end

  # ============================================================================
  # Routing Rules
  # ============================================================================

  @doc """
  List routing rules.
  """
  def list_rules(conn, params) do
    opts = []
    opts = if params["enabled"], do: [{:enabled, params["enabled"] == "true"} | opts], else: opts
    opts = if params["organization_id"], do: [{:organization_id, params["organization_id"]} | opts], else: opts

    case AlertRouter.list_rules(opts) do
      {:ok, rules} ->
        json(conn, %{data: Enum.map(rules, &serialize_rule/1)})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: to_string(reason)})
    end
  end

  @doc """
  Create a routing rule.
  """
  def create_rule(conn, params) do
    rule_config = %{
      name: params["name"],
      description: params["description"],
      conditions: params["conditions"] || [],
      destinations: params["destinations"] || [],
      enabled: Map.get(params, "enabled", true),
      priority: params["priority"] || 50,
      organization_id: params["organization_id"]
    }

    case AlertRouter.add_rule(rule_config) do
      {:ok, rule} ->
        conn
        |> put_status(:created)
        |> json(%{data: serialize_rule(rule)})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: to_string(reason)})
    end
  end

  @doc """
  Update a routing rule.
  """
  def update_rule(conn, %{"id" => id} = params) do
    updates = params
    |> Map.take(["name", "description", "conditions", "destinations", "enabled", "priority"])
    |> Enum.map(fn {k, v} ->
      key = try do
        String.to_existing_atom(k)
      rescue
        ArgumentError -> k
      end
      {key, v}
    end)
    |> Map.new()

    case AlertRouter.update_rule(id, updates) do
      {:ok, rule} ->
        json(conn, %{data: serialize_rule(rule)})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Rule not found"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: to_string(reason)})
    end
  end

  @doc """
  Delete a routing rule.
  """
  def delete_rule(conn, %{"id" => id}) do
    case AlertRouter.remove_rule(id) do
      :ok ->
        send_resp(conn, :no_content, "")

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Rule not found"})
    end
  end

  @doc """
  Test routing for an alert (dry run).
  """
  def test_routing(conn, %{"alert" => alert}) do
    case AlertRouter.test_routing(alert) do
      {:ok, result} ->
        json(conn, %{data: result})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: to_string(reason)})
    end
  end

  # ============================================================================
  # Statistics
  # ============================================================================

  @doc """
  Get routing statistics.
  """
  def stats(conn, _params) do
    stats = AlertRouter.get_stats()

    json(conn, %{
      data: %{
        alerts_routed: stats.alerts_routed,
        rules_matched: stats.rules_matched,
        destinations_triggered: stats.destinations_triggered,
        errors: stats.errors,
        by_destination: stats.by_destination,
        by_rule: stats.by_rule,
        last_activity: stats.last_activity
      }
    })
  end

  @doc """
  Get integration health summary for the dashboard health tab.
  """
  def health(conn, _params) do
    integrations = IntegrationConfig.list_integrations([])
    stats = AlertRouter.get_stats()

    enabled_count =
      Enum.count(integrations, fn integration ->
        Map.get(integration, :enabled, false)
      end)

    disabled_count = length(integrations) - enabled_count
    error_count = integration_stat(stats, :errors, 0)
    degraded_count = if error_count > 0 and enabled_count > 0, do: 1, else: 0

    json(conn, %{
      healthy: max(enabled_count - degraded_count, 0),
      degraded: degraded_count,
      unhealthy: disabled_count,
      averageLatencyMs: 0,
      totalEventsPerMinute: 0,
      lastUpdated: DateTime.utc_now() |> DateTime.to_iso8601()
    })
  end

  @doc """
  Reload routing rules and integrations.
  """
  def reload(conn, _params) do
    AlertRouter.reload_rules()
    json(conn, %{success: true, message: "Rules and integrations reloaded"})
  end

  # ============================================================================
  # Integration Logs
  # ============================================================================

  @doc """
  Get integration logs with filtering and pagination.

  ## Query Parameters

  - `integration_name` - Filter by integration name (e.g., "tines", "servicenow", "jira")
  - `status` - Filter by status ("success", "error", "timeout")
  - `action` - Filter by action (e.g., "create_incident", "trigger_playbook")
  - `from` - Start of date range (ISO 8601)
  - `to` - End of date range (ISO 8601)
  - `limit` - Maximum entries to return (default 100, max 1000)
  - `offset` - Number of entries to skip (default 0)
  - `summary` - If "true", return aggregated summary instead of individual logs
  """
  def logs(conn, params) do
    alias TamanduaServer.Integrations.IntegrationLog

    if params["summary"] == "true" do
      summary = IntegrationLog.get_summary()
      json(conn, %{data: summary, meta: %{type: "summary"}})
    else
      limit = min(String.to_integer(params["limit"] || "100"), 1000)
      offset = String.to_integer(params["offset"] || "0")

      filter_opts = [
        integration_name: params["integration_name"],
        status: params["status"],
        action: params["action"],
        from: parse_datetime_param(params["from"]),
        to: parse_datetime_param(params["to"]),
        limit: limit,
        offset: offset
      ]
      |> Enum.reject(fn {_k, v} -> is_nil(v) end)

      {logs, total} = IntegrationLog.list_logs(filter_opts)

      serialized_logs = Enum.map(logs, fn log ->
        %{
          id: log.id,
          integration_name: log.integration_name,
          action: log.action,
          status: log.status,
          request_body: log.request_body,
          response_body: log.response_body,
          error_message: log.error_message,
          duration_ms: log.duration_ms,
          inserted_at: log.inserted_at && DateTime.to_iso8601(log.inserted_at)
        }
      end)

      json(conn, %{
        data: serialized_logs,
        meta: %{
          total: total,
          limit: limit,
          offset: offset,
          has_more: offset + limit < total
        }
      })
    end
  end

  defp parse_datetime_param(nil), do: nil
  defp parse_datetime_param(str) when is_binary(str) do
    case DateTime.from_iso8601(str) do
      {:ok, dt, _offset} -> dt
      _ -> nil
    end
  end

  # ============================================================================
  # SIEM/SOAR Bidirectional Integration
  # ============================================================================

  @allowed_siem_platforms ~w(splunk sentinel qradar)

  @doc """
  Test a SIEM connection by platform type.

  Expects `platform` ("splunk", "sentinel", "qradar") and `config` map.
  """
  def test_siem_connection(conn, %{"platform" => platform, "config" => config}) do
    case resolve_siem_module(platform) do
      {:ok, module} ->
        config_map = atomize_siem_config(config)

        case module.test_connection(config_map) do
          {:ok, details} ->
            json(conn, %{success: true, platform: platform, details: details})

          {:error, reason} ->
            json(conn, %{success: false, platform: platform, error: format_siem_error(reason)})
        end

      {:error, :unknown_platform} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Unknown SIEM platform: #{platform}. Supported: #{Enum.join(@allowed_siem_platforms, ", ")}"})
    end
  end

  def test_siem_connection(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required fields: platform, config"})
  end

  @doc """
  Forward an alert to a specific SIEM platform.

  Expects `platform`, `alert`, and `config`. Optionally accepts `mapping` for
  custom field mappings.
  """
  def forward_to_siem(conn, %{"platform" => platform, "alert" => alert, "config" => config} = params) do
    alias TamanduaServer.Integrations.FieldMapper

    case resolve_siem_module(platform) do
      {:ok, module} ->
        config_map = atomize_siem_config(config)

        # Apply field mapping if provided
        mapped_alert =
          case params["mapping"] do
            mappings when is_list(mappings) and mappings != [] ->
              FieldMapper.apply_mapping(alert, mappings)
            _ ->
              alert
          end

        result = apply(module, :send_alert, [mapped_alert, config_map, []])

        case result do
          :ok ->
            json(conn, %{success: true, platform: platform, message: "Alert forwarded"})

          {:ok, details} ->
            json(conn, %{success: true, platform: platform, details: details})

          {:error, reason} ->
            conn
            |> put_status(:bad_gateway)
            |> json(%{success: false, platform: platform, error: format_siem_error(reason)})
        end

      {:error, :unknown_platform} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Unknown SIEM platform: #{platform}"})
    end
  end

  def forward_to_siem(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required fields: platform, alert, config"})
  end

  @doc """
  Get aggregated SIEM integration statistics.

  Returns stats from IntegrationLog for all SIEM-related integrations.
  """
  def siem_stats(conn, _params) do
    alias TamanduaServer.Integrations.IntegrationLog

    summary = IntegrationLog.get_summary()

    siem_keys = ["splunk_hec", "sentinel", "qradar"]

    siem_summary =
      summary
      |> Enum.filter(fn {key, _} -> key in siem_keys end)
      |> Map.new()

    json(conn, %{
      data: %{
        platforms: siem_summary,
        total_calls: siem_summary |> Map.values() |> Enum.map(& &1.total) |> Enum.sum(),
        total_errors:
          siem_summary
          |> Map.values()
          |> Enum.map(&Map.get(&1, :error, 0))
          |> Enum.sum()
      }
    })
  end

  # ============================================================================
  # Inbound Webhooks
  # ============================================================================

  @doc """
  Receive an inbound webhook from an external SIEM/SOAR platform.

  The `:source` path parameter identifies the platform (splunk, sentinel,
  qradar, pagerduty, slack, generic).

  ## Security

  Signature verification is performed using HMAC signatures. The secret is
  looked up from server-side configuration (integration config or environment),
  NEVER from the request payload.

  Supported signature headers:
  - `X-Hub-Signature-256` (GitHub style)
  - `X-Webhook-Signature`
  - `X-Signature`
  - `X-Tines-Signature`
  - `X-Slack-Signature`

  ## Production Behavior

  In production, webhooks without a configured secret or valid signature are
  rejected. Set `webhook_insecure_mode: true` in config for dev/test only.
  """
  def receive_webhook(conn, %{"source" => source} = params) do
    alias TamanduaServer.Integrations.Webhook.InboundRouter

    # Get raw body for signature verification (stored by CacheBodyReader)
    raw_body = get_raw_body(conn)

    # Look up webhook secret from server-side config (NEVER from request params)
    # This prevents attackers from bypassing signature verification
    secret = get_webhook_secret_for_source(source)

    # Extract signature from headers - check multiple common header names
    signature = extract_signature_header(conn)

    # Verify signature if secret is configured
    case verify_webhook_authentication(raw_body, signature, secret) do
      :ok ->
        # Remove meta params, keep actual payload
        # IMPORTANT: Never include any secret-like params in processing
        payload = Map.drop(params, ["source", "secret", "token", "api_key"])

        opts = [
          signature: signature,
          raw_body: raw_body,
          signature_verified: is_binary(signature) and is_binary(secret)
        ]

        case InboundRouter.process_webhook(source, payload, opts) do
          {:ok, normalized} ->
            json(conn, %{success: true, source: source, data: normalized})

          {:error, :rate_limited} ->
            conn
            |> put_status(:too_many_requests)
            |> json(%{error: "Rate limit exceeded for source: #{source}"})

          {:error, reason} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: format_siem_error(reason)})
        end

      {:error, :no_secret_configured} ->
        if allow_insecure_webhook?() do
          Logger.warning("[IntegrationsController] Webhook for #{source} processed without signature verification (insecure mode)")
          payload = Map.drop(params, ["source", "secret", "token", "api_key"])
          opts = [raw_body: raw_body, signature_verified: false]

          case InboundRouter.process_webhook(source, payload, opts) do
            {:ok, normalized} ->
              json(conn, %{success: true, source: source, data: normalized, warning: "Signature not verified"})

            {:error, reason} ->
              conn
              |> put_status(:unprocessable_entity)
              |> json(%{error: format_siem_error(reason)})
          end
        else
          Logger.warning("[IntegrationsController] Webhook for #{source} rejected - no secret configured")
          conn
          |> put_status(:unauthorized)
          |> json(%{error: "Webhook not configured - contact administrator"})
        end

      {:error, :missing_signature} ->
        if allow_insecure_webhook?() do
          Logger.warning("[IntegrationsController] Webhook for #{source} processed without signature (insecure mode)")
          payload = Map.drop(params, ["source", "secret", "token", "api_key"])
          opts = [raw_body: raw_body, signature_verified: false]

          case InboundRouter.process_webhook(source, payload, opts) do
            {:ok, normalized} ->
              json(conn, %{success: true, source: source, data: normalized, warning: "Signature not verified"})

            {:error, reason} ->
              conn
              |> put_status(:unprocessable_entity)
              |> json(%{error: format_siem_error(reason)})
          end
        else
          conn
          |> put_status(:unauthorized)
          |> json(%{error: "Missing webhook signature"})
        end

      {:error, :invalid_signature} ->
        Logger.warning("[IntegrationsController] Invalid signature for #{source} webhook")
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "Invalid webhook signature"})
    end
  end

  # Get raw body, handling the CacheBodyReader format (list of chunks)
  defp get_raw_body(conn) do
    case conn.assigns[:raw_body] do
      chunks when is_list(chunks) -> Enum.join(Enum.reverse(chunks))
      body when is_binary(body) -> body
      _ -> conn.private[:raw_body]
    end
  end

  # Extract signature from multiple possible headers
  defp extract_signature_header(conn) do
    headers = [
      "x-hub-signature-256",
      "x-webhook-signature",
      "x-signature",
      "x-tines-signature",
      "x-slack-signature"
    ]

    Enum.find_value(headers, fn header ->
      case get_req_header(conn, header) do
        [sig | _] when is_binary(sig) and sig != "" -> sig
        _ -> nil
      end
    end)
  end

  # Look up webhook secret from server-side configuration ONLY
  # NEVER use secrets from request params (security vulnerability)
  defp get_webhook_secret_for_source(source) do
    # Check application config for source-specific secrets
    config_key = String.to_atom("webhook_secret_#{source}")
    Application.get_env(:tamandua_server, config_key) ||
      Application.get_env(:tamandua_server, :webhook_secrets, %{})[source] ||
      Application.get_env(:tamandua_server, :default_webhook_secret)
  end

  # Verify webhook authentication using HMAC
  defp verify_webhook_authentication(_raw_body, _signature, nil) do
    {:error, :no_secret_configured}
  end

  defp verify_webhook_authentication(_raw_body, nil, _secret) do
    {:error, :missing_signature}
  end

  defp verify_webhook_authentication(nil, _signature, _secret) do
    {:error, :invalid_signature}
  end

  defp verify_webhook_authentication(raw_body, signature, secret) do
    if verify_hmac_signature(raw_body, signature, secret) do
      :ok
    else
      {:error, :invalid_signature}
    end
  end

  # Verify HMAC signature with constant-time comparison
  defp verify_hmac_signature(body, signature, secret) do
    # Parse signature format (e.g., "sha256=abc123")
    {algorithm, expected_hash} = parse_signature_format(signature)

    # Compute expected signature
    algo = case algorithm do
      :sha256 -> :sha256
      :sha512 -> :sha512
      :sha1 -> :sha
      _ -> :sha256
    end

    computed = :crypto.mac(:hmac, algo, secret, body)
               |> Base.encode16(case: :lower)

    # Use constant-time comparison to prevent timing attacks
    Plug.Crypto.secure_compare(computed, expected_hash)
  end

  defp parse_signature_format(signature) do
    cond do
      String.starts_with?(signature, "sha256=") ->
        {:sha256, String.replace_prefix(signature, "sha256=", "")}

      String.starts_with?(signature, "sha512=") ->
        {:sha512, String.replace_prefix(signature, "sha512=", "")}

      String.starts_with?(signature, "sha1=") ->
        {:sha1, String.replace_prefix(signature, "sha1=", "")}

      String.starts_with?(signature, "v0=") ->
        # Slack format
        {:sha256, String.replace_prefix(signature, "v0=", "")}

      true ->
        # Assume SHA256 if no prefix
        {:sha256, signature}
    end
  end

  # Only allow insecure webhooks in dev/test with explicit config
  defp allow_insecure_webhook? do
    Application.get_env(:tamandua_server, :webhook_insecure_mode, false) and
      Application.get_env(:tamandua_server, :env) in [:dev, :test]
  end

  @doc """
  Get inbound webhook audit history.

  Query parameters: `source`, `status`, `limit`, `offset`.
  """
  def webhook_history(conn, params) do
    alias TamanduaServer.Integrations.Webhook.InboundRouter

    limit = min(String.to_integer(params["limit"] || "100"), 1000)
    offset = String.to_integer(params["offset"] || "0")

    opts = [
      source: params["source"],
      status: params["status"],
      limit: limit,
      offset: offset
    ]
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)

    {entries, total} = InboundRouter.webhook_history(opts)

    serialized =
      Enum.map(entries, fn entry ->
        %{
          id: entry.id,
          source: entry.source,
          status: entry.status,
          payload_size: entry.payload_size,
          duration_ms: entry.duration_ms,
          error: entry.error,
          timestamp: entry.timestamp && DateTime.to_iso8601(entry.timestamp)
        }
      end)

    json(conn, %{
      data: serialized,
      meta: %{
        total: total,
        limit: limit,
        offset: offset,
        has_more: offset + limit < total
      }
    })
  end

  # ============================================================================
  # Field Mappings
  # ============================================================================

  @doc """
  Validate a field mapping template.

  Expects `mapping` (list of rules) in the request body.
  Optionally `platform` to retrieve default mappings.
  """
  def validate_field_mapping(conn, params) do
    alias TamanduaServer.Integrations.FieldMapper

    mapping = params["mapping"]
    platform = params["platform"]

    cond do
      is_list(mapping) ->
        case FieldMapper.validate_mapping(mapping) do
          :ok ->
            # Optionally show a preview if test_data is provided
            preview =
              if params["test_data"] do
                FieldMapper.apply_mapping(params["test_data"], mapping)
              else
                nil
              end

            json(conn, %{valid: true, preview: preview})

          {:error, errors} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{valid: false, errors: errors})
        end

      is_binary(platform) ->
        default = FieldMapper.default_mappings(platform)
        json(conn, %{platform: platform, mapping: default})

      true ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Provide 'mapping' (list of rules) or 'platform' (string) to get defaults"})
    end
  end

  # ============================================================================
  # Private: SIEM Helpers
  # ============================================================================

  defp resolve_siem_module(platform) when platform in @allowed_siem_platforms do
    module =
      case platform do
        "splunk" -> TamanduaServer.Integrations.SIEM.SplunkHEC
        "sentinel" -> TamanduaServer.Integrations.SIEM.SentinelConnector
        "qradar" -> TamanduaServer.Integrations.SIEM.QRadar
      end

    {:ok, module}
  end

  defp resolve_siem_module(_), do: {:error, :unknown_platform}

  defp atomize_siem_config(config) when is_map(config) do
    Map.new(config, fn {k, v} ->
      key =
        if is_binary(k) do
          try do
            String.to_existing_atom(k)
          rescue
            ArgumentError -> String.to_atom(k)
          end
        else
          k
        end

      {key, v}
    end)
  end

  defp atomize_siem_config(_), do: %{}

  defp format_siem_error(reason) when is_binary(reason), do: reason
  defp format_siem_error(reason) when is_atom(reason), do: to_string(reason)
  defp format_siem_error({:auth_failed, reason}), do: "Authentication failed: #{inspect(reason)}"
  defp format_siem_error(reason), do: inspect(reason)

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp serialize_integration(integration) do
    %{
      id: integration.id,
      type: integration.type,
      name: integration.name,
      description: integration.description,
      # Don't expose sensitive config fields directly
      config: sanitize_config(integration.config, integration.type),
      enabled: integration.enabled,
      last_sync_at: integration.last_sync_at,
      last_error: integration.last_error,
      stats: integration.stats,
      organization_id: integration.organization_id,
      inserted_at: integration.inserted_at,
      updated_at: integration.updated_at
    }
  end

  defp sanitize_config(config, type) when is_map(config) do
    sensitive_keys = get_sensitive_keys(type)

    config
    |> Enum.map(fn {k, v} ->
      key = to_string(k)
      if key in sensitive_keys do
        {k, mask_value(v)}
      else
        {k, v}
      end
    end)
    |> Map.new()
  end

  defp sanitize_config(nil, _), do: %{}

  defp get_sensitive_keys(:splunk), do: ["hec_token", "soar_token", "rest_password"]
  defp get_sensitive_keys(:sentinel), do: ["shared_key", "client_secret"]
  defp get_sensitive_keys(:elastic), do: ["password", "api_key"]
  defp get_sensitive_keys(:webhook), do: ["secret"]
  defp get_sensitive_keys(:xsoar), do: ["api_key"]
  defp get_sensitive_keys(:swimlane), do: ["password", "token"]
  defp get_sensitive_keys(:tines), do: ["api_token", "token"]
  defp get_sensitive_keys(:servicenow), do: ["password", "client_secret"]
  defp get_sensitive_keys(:jira), do: ["api_token"]
  defp get_sensitive_keys(:pagerduty), do: ["routing_key", "api_token"]
  defp get_sensitive_keys(_), do: []

  defp mask_value(nil), do: nil
  defp mask_value(""), do: ""
  defp mask_value(value) when is_binary(value) do
    len = String.length(value)
    if len <= 4 do
      String.duplicate("*", len)
    else
      String.slice(value, 0, 4) <> String.duplicate("*", min(len - 4, 20))
    end
  end
  defp mask_value(_), do: "****"

  defp integration_stat(stats, key, default) when is_map(stats) do
    Map.get(stats, key) || Map.get(stats, Atom.to_string(key)) || default
  end

  defp integration_stat(_, _, default), do: default

  defp serialize_rule(rule) do
    %{
      id: rule.id,
      name: rule.name,
      description: rule.description,
      conditions: Enum.map(rule.conditions, fn c ->
        %{
          field: c.field,
          operator: c.operator,
          value: c.value
        }
      end),
      destinations: Enum.map(rule.destinations, &to_string/1),
      transform: rule.transform,
      enabled: rule.enabled,
      priority: rule.priority,
      organization_id: rule.organization_id
    }
  end

  defp format_errors(%Ecto.Changeset{} = changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end

  defp format_errors(error), do: error

end
