defmodule TamanduaServer.Integrations.SIEM.SentinelConnector do
  @moduledoc """
  Azure Sentinel connector for bidirectional SIEM integration.

  Provides:
  - `send_alert/3` - Forward alert to Log Analytics Data Collector API
  - `send_batch/3` - Batch events to a custom log table
  - `query_kql/3` - Execute KQL query via Log Analytics API
  - `create_incident/3` - Create a Sentinel incident from an alert
  - `test_connection/1` - Validate workspace ID and shared key

  Configurable: workspace_id, shared_key, custom_log_type, resource_group, tenant_id,
  client_id, client_secret, subscription_id.
  """

  require Logger

  alias TamanduaServer.Integrations.IntegrationLog

  @log_analytics_api_version "2016-04-01"
  @sentinel_api_version "2022-11-01"
  @log_analytics_query_api_version "v1"
  @azure_login_url "https://login.microsoftonline.com"
  @management_url "https://management.azure.com"
  @default_timeout_ms 30_000
  @default_log_type "TamanduaEDR"
  @max_retries 3
  @retry_base_delay_ms 1_000

  @type config :: %{
          optional(:workspace_id) => String.t(),
          optional(:shared_key) => String.t(),
          optional(:log_type) => String.t(),
          optional(:tenant_id) => String.t(),
          optional(:client_id) => String.t(),
          optional(:client_secret) => String.t(),
          optional(:subscription_id) => String.t(),
          optional(:resource_group) => String.t(),
          optional(:workspace_name) => String.t(),
          optional(:timeout_ms) => non_neg_integer()
        }

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Forward a single alert to the Log Analytics Data Collector API.

  ## Parameters

  - `alert` - Alert map
  - `config` - Sentinel configuration map
  - `opts` - Optional: `:log_type` override

  ## Returns

  `:ok` on success, `{:error, reason}` on failure.
  """
  @spec send_alert(map(), config(), keyword()) :: :ok | {:error, term()}
  def send_alert(alert, config, opts \\ []) do
    event = format_security_alert(alert)
    log_type = opts[:log_type] || "SecurityAlert"

    IntegrationLog.log_api_call("sentinel", "send_alert", Jason.encode!(event), fn ->
      send_to_log_analytics(config, [event], log_type)
    end)
  end

  @doc """
  Send a batch of events to a custom Log Analytics table.

  ## Parameters

  - `events` - List of event maps
  - `config` - Sentinel configuration map
  - `opts` - Optional: `:log_type` override

  ## Returns

  `:ok` on success, `{:error, reason}` on failure.
  """
  @spec send_batch(list(map()), config(), keyword()) :: :ok | {:error, term()}
  def send_batch(events, config, opts \\ []) when is_list(events) do
    log_type = opts[:log_type] || config[:log_type] || @default_log_type
    formatted = Enum.map(events, &format_log_analytics_event/1)

    IntegrationLog.log_api_call("sentinel", "send_batch", "#{length(events)} events", fn ->
      send_to_log_analytics(config, formatted, log_type)
    end)
  end

  @doc """
  Execute a KQL (Kusto Query Language) query via the Log Analytics API.

  ## Parameters

  - `kql_query` - KQL query string
  - `config` - Sentinel configuration map
  - `opts` - Optional: `:timespan` (ISO 8601 duration, e.g., "PT24H")

  ## Returns

  `{:ok, results}` on success, `{:error, reason}` on failure.
  """
  @spec query_kql(String.t(), config(), keyword()) :: {:ok, map()} | {:error, term()}
  def query_kql(kql_query, config, opts \\ []) do
    workspace_id = config[:workspace_id]
    url = "https://api.loganalytics.io/#{@log_analytics_query_api_version}/workspaces/#{workspace_id}/query"
    timeout = config[:timeout_ms] || @default_timeout_ms

    body_map = %{"query" => kql_query}
    body_map = if opts[:timespan], do: Map.put(body_map, "timespan", opts[:timespan]), else: body_map
    body = Jason.encode!(body_map)

    case get_bearer_token(config) do
      {:ok, token} ->
        headers = [
          {"Authorization", "Bearer #{token}"},
          {"Content-Type", "application/json"}
        ]

        IntegrationLog.log_api_call("sentinel", "query_kql", kql_query, fn ->
          case do_http(:post, url, headers, body, timeout) do
            {:ok, %{status: 200, body: resp_body}} ->
              {:ok, Jason.decode!(resp_body)}

            {:ok, %{status: status, body: resp_body}} ->
              {:error, "KQL query failed: HTTP #{status} - #{truncate(resp_body)}"}

            {:error, reason} ->
              {:error, reason}
          end
        end)

      {:error, reason} ->
        {:error, {:auth_failed, reason}}
    end
  end

  @doc """
  Create a Sentinel incident from an alert.

  Requires Azure AD credentials (tenant_id, client_id, client_secret) plus
  subscription_id, resource_group, and workspace_name.

  ## Parameters

  - `alert` - Alert map with `:title`, `:description`, `:severity`
  - `config` - Sentinel configuration map
  - `opts` - Optional overrides

  ## Returns

  `{:ok, incident_id}` on success, `{:error, reason}` on failure.
  """
  @spec create_incident(map(), config(), keyword()) :: {:ok, String.t()} | {:error, term()}
  def create_incident(alert, config, opts \\ []) do
    with {:ok, token} <- get_azure_management_token(config) do
      incident_id = UUID.uuid4()

      url =
        "#{@management_url}/subscriptions/#{config[:subscription_id]}" <>
          "/resourceGroups/#{config[:resource_group]}" <>
          "/providers/Microsoft.OperationalInsights/workspaces/#{config[:workspace_name]}" <>
          "/providers/Microsoft.SecurityInsights/incidents/#{incident_id}" <>
          "?api-version=#{@sentinel_api_version}"

      severity = map_severity(alert_field(alert, :severity))

      body =
        Jason.encode!(%{
          properties: %{
            title: opts[:title] || alert_field(alert, :title) || "Tamandua Alert",
            description: alert_field(alert, :description),
            severity: severity,
            status: "New",
            labels: [%{labelName: "Tamandua", labelType: "User"}]
          }
        })

      headers = [
        {"Authorization", "Bearer #{token}"},
        {"Content-Type", "application/json"}
      ]

      timeout = config[:timeout_ms] || @default_timeout_ms

      IntegrationLog.log_api_call("sentinel", "create_incident", body, fn ->
        case do_http(:put, url, headers, body, timeout) do
          {:ok, %{status: status}} when status in [200, 201] ->
            {:ok, incident_id}

          {:ok, %{status: status, body: resp_body}} ->
            {:error, "Create incident failed: HTTP #{status} - #{truncate(resp_body)}"}

          {:error, reason} ->
            {:error, reason}
        end
      end)
    end
  end

  @doc """
  Validate workspace ID and shared key by sending a test event.

  ## Parameters

  - `config` - Sentinel configuration map

  ## Returns

  `{:ok, %{status: "connected"}}` on success, `{:error, reason}` on failure.
  """
  @spec test_connection(config()) :: {:ok, map()} | {:error, term()}
  def test_connection(config) do
    test_event = %{
      TimeGenerated: DateTime.utc_now() |> DateTime.to_iso8601(),
      Message: "Tamandua EDR connection test",
      Source: "tamandua:test"
    }

    case send_to_log_analytics(config, [test_event], "TamanduaTest") do
      :ok -> {:ok, %{status: "connected", workspace_id: config[:workspace_id]}}
      {:error, reason} -> {:error, "Connection test failed: #{inspect(reason)}"}
    end
  rescue
    e -> {:error, "Connection test error: #{Exception.message(e)}"}
  end

  # ============================================================================
  # Private: Log Analytics Data Collector API
  # ============================================================================

  defp send_to_log_analytics(config, events, log_type) do
    body = Jason.encode!(events)
    date = format_rfc1123_date()
    content_length = byte_size(body)

    string_to_sign = "POST\n#{content_length}\napplication/json\nx-ms-date:#{date}\n/api/logs"
    signature = build_hmac_signature(config[:shared_key], string_to_sign)

    url =
      "https://#{config[:workspace_id]}.ods.opinsights.azure.com/api/logs?api-version=#{@log_analytics_api_version}"

    headers = [
      {"Authorization", "SharedKey #{config[:workspace_id]}:#{signature}"},
      {"Content-Type", "application/json"},
      {"Log-Type", log_type},
      {"x-ms-date", date},
      {"time-generated-field", "TimeGenerated"}
    ]

    timeout = config[:timeout_ms] || @default_timeout_ms
    do_with_retry(fn -> do_http(:post, url, headers, body, timeout) end, 0)
  end

  # ============================================================================
  # Private: Event Formatting
  # ============================================================================

  defp format_security_alert(alert) do
    %{
      TimeGenerated: extract_iso_timestamp(alert),
      AlertName: alert_field(alert, :title),
      Description: alert_field(alert, :description),
      Severity: map_severity(alert_field(alert, :severity)),
      Status: "New",
      VendorName: "Tamandua",
      ProductName: "Tamandua EDR",
      AlertType: "tamandua_edr_alert",
      CompromisedEntity: alert_field(alert, :hostname),
      Tactics: join_list(alert_field(alert, :mitre_tactics)),
      Techniques: join_list(alert_field(alert, :mitre_techniques)),
      ExtendedProperties:
        Jason.encode!(%{
          alert_id: alert_field(alert, :id),
          agent_id: alert_field(alert, :agent_id),
          threat_score: alert_field(alert, :threat_score)
        })
    }
  end

  defp format_log_analytics_event(event) do
    %{
      TimeGenerated: extract_iso_timestamp(event),
      EventType: alert_field(event, :event_type) || alert_field(event, :type),
      Severity: alert_field(event, :severity),
      AgentId: alert_field(event, :agent_id),
      Hostname: alert_field(event, :hostname),
      RawData: Jason.encode!(event)
    }
  end

  # ============================================================================
  # Private: Azure AD OAuth2
  # ============================================================================

  defp get_bearer_token(config) do
    # For Log Analytics query API, use AAD token with Log Analytics scope
    get_oauth_token(config, "https://api.loganalytics.io/.default")
  end

  defp get_azure_management_token(config) do
    get_oauth_token(config, "https://management.azure.com/.default")
  end

  defp get_oauth_token(config, scope) do
    unless config[:tenant_id] && config[:client_id] && config[:client_secret] do
      {:error, :azure_credentials_not_configured}
    else
      url = "#{@azure_login_url}/#{config[:tenant_id]}/oauth2/v2.0/token"

      body =
        URI.encode_query(%{
          "client_id" => config[:client_id],
          "client_secret" => config[:client_secret],
          "scope" => scope,
          "grant_type" => "client_credentials"
        })

      headers = [{"Content-Type", "application/x-www-form-urlencoded"}]
      timeout = config[:timeout_ms] || @default_timeout_ms

      case do_http(:post, url, headers, body, timeout) do
        {:ok, %{status: 200, body: resp_body}} ->
          response = Jason.decode!(resp_body)
          {:ok, response["access_token"]}

        {:ok, %{status: status, body: resp_body}} ->
          {:error, "OAuth token failed: HTTP #{status} - #{truncate(resp_body)}"}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  # ============================================================================
  # Private: HTTP with Retry
  # ============================================================================

  defp do_with_retry(fun, attempt) do
    case fun.() do
      {:ok, %{status: status}} when status in 200..299 ->
        :ok

      {:ok, %{status: status, body: _resp_body}} when attempt < @max_retries ->
        delay = @retry_base_delay_ms * round(:math.pow(2, attempt))
        Logger.warning("[Sentinel] HTTP #{status}, retrying in #{delay}ms (attempt #{attempt + 1}/#{@max_retries})")
        Process.sleep(delay)
        do_with_retry(fun, attempt + 1)

      {:ok, %{status: status, body: resp_body}} ->
        {:error, "HTTP #{status}: #{truncate(resp_body)}"}

      {:error, reason} when attempt < @max_retries ->
        delay = @retry_base_delay_ms * round(:math.pow(2, attempt))
        Logger.warning("[Sentinel] Error #{inspect(reason)}, retrying in #{delay}ms (attempt #{attempt + 1}/#{@max_retries})")
        Process.sleep(delay)
        do_with_retry(fun, attempt + 1)

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp do_http(method, url, headers, body, timeout) do
    request = Finch.build(method, url, headers, body)

    case Finch.request(request, TamanduaServer.Finch, receive_timeout: timeout) do
      {:ok, %Finch.Response{status: status, body: resp_body}} ->
        {:ok, %{status: status, body: resp_body}}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  # ============================================================================
  # Private: Helpers
  # ============================================================================

  defp build_hmac_signature(shared_key, string_to_sign) do
    decoded_key = Base.decode64!(shared_key)
    signature = :crypto.mac(:hmac, :sha256, decoded_key, string_to_sign)
    Base.encode64(signature)
  end

  defp format_rfc1123_date do
    Calendar.strftime(DateTime.utc_now(), "%a, %d %b %Y %H:%M:%S GMT")
  end

  defp map_severity("critical"), do: "High"
  defp map_severity("high"), do: "High"
  defp map_severity("medium"), do: "Medium"
  defp map_severity("low"), do: "Low"
  defp map_severity("info"), do: "Informational"
  defp map_severity(_), do: "Medium"

  defp extract_iso_timestamp(data) do
    ts = alert_field(data, :timestamp) || alert_field(data, :created_at) || alert_field(data, :inserted_at)

    case ts do
      %DateTime{} = dt -> DateTime.to_iso8601(dt)
      %NaiveDateTime{} = ndt -> NaiveDateTime.to_iso8601(ndt) <> "Z"
      s when is_binary(s) -> s
      n when is_integer(n) -> DateTime.from_unix!(n) |> DateTime.to_iso8601()
      _ -> DateTime.utc_now() |> DateTime.to_iso8601()
    end
  end

  defp join_list(nil), do: ""
  defp join_list(list) when is_list(list), do: Enum.join(list, ",")
  defp join_list(other), do: to_string(other)

  defp alert_field(data, key) when is_atom(key) do
    Map.get(data, key) || Map.get(data, to_string(key))
  end

  defp truncate(str) when is_binary(str) and byte_size(str) > 500 do
    String.slice(str, 0, 500) <> "..."
  end

  defp truncate(str) when is_binary(str), do: str
  defp truncate(other), do: inspect(other)
end
