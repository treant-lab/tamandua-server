defmodule TamanduaServer.Integrations.SIEM.SplunkHEC do
  @moduledoc """
  Splunk HTTP Event Collector (HEC) adapter for bidirectional SIEM integration.

  Provides:
  - `send_alert/3` - Forward a single alert as a Splunk HEC event
  - `send_batch/3` - Batch multiple events to Splunk HEC
  - `search/3` - Execute SPL search via Splunk REST API
  - `get_enrichment/2` - Retrieve enrichment data from Splunk lookups
  - `test_connection/1` - Validate HEC token and endpoint

  Configurable: HEC token, endpoint URL, index, sourcetype, SSL settings.
  Retry with exponential backoff (3 attempts).
  """

  require Logger

  alias TamanduaServer.Integrations.IntegrationLog

  @max_retries 3
  @retry_base_delay_ms 1_000
  @default_timeout_ms 30_000
  @default_sourcetype "tamandua:edr"
  @default_index "tamandua"

  @hec_event_endpoint "/services/collector/event"
  @hec_health_endpoint "/services/collector/health"
  @search_endpoint "/services/search/jobs"

  @type config :: %{
          optional(:hec_url) => String.t(),
          optional(:hec_token) => String.t(),
          optional(:index) => String.t(),
          optional(:sourcetype) => String.t(),
          optional(:verify_ssl) => boolean(),
          optional(:timeout_ms) => non_neg_integer(),
          optional(:rest_url) => String.t(),
          optional(:rest_username) => String.t(),
          optional(:rest_password) => String.t()
        }

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Forward a single alert as a Splunk HEC event.

  ## Parameters

  - `alert` - Alert map with keys like `:id`, `:title`, `:severity`, `:hostname`, etc.
  - `config` - Splunk configuration map with `:hec_url`, `:hec_token`, etc.
  - `opts` - Optional overrides: `:index`, `:sourcetype`, `:host`

  ## Returns

  `:ok` on success, `{:error, reason}` on failure.
  """
  @spec send_alert(map(), config(), keyword()) :: :ok | {:error, term()}
  def send_alert(alert, config, opts \\ []) do
    hec_event = format_alert(alert, config, opts)
    body = Jason.encode!(hec_event)

    IntegrationLog.log_api_call("splunk_hec", "send_alert", body, fn ->
      do_hec_post(config, body)
    end)
  end

  @doc """
  Batch multiple events to Splunk HEC.

  Events are concatenated as newline-delimited JSON (Splunk HEC batch format).

  ## Parameters

  - `events` - List of event maps
  - `config` - Splunk configuration map
  - `opts` - Optional overrides: `:index`, `:sourcetype`

  ## Returns

  `:ok` on success, `{:error, reason}` on failure.
  """
  @spec send_batch(list(map()), config(), keyword()) :: :ok | {:error, term()}
  def send_batch(events, config, opts \\ []) when is_list(events) do
    body =
      events
      |> Enum.map(fn event -> format_event(event, config, opts) end)
      |> Enum.map(&Jason.encode!/1)
      |> Enum.join("")

    IntegrationLog.log_api_call("splunk_hec", "send_batch", "#{length(events)} events", fn ->
      do_hec_post(config, body)
    end)
  end

  @doc """
  Execute an SPL search via the Splunk REST API.

  Requires `:rest_url`, `:rest_username`, `:rest_password` in config.

  ## Parameters

  - `spl_query` - SPL search string (e.g., `"search index=tamandua severity=critical"`)
  - `config` - Splunk configuration map
  - `opts` - Optional: `:earliest_time`, `:latest_time`, `:max_results`

  ## Returns

  `{:ok, results}` on success, `{:error, reason}` on failure.
  """
  @spec search(String.t(), config(), keyword()) :: {:ok, map()} | {:error, term()}
  def search(spl_query, config, opts \\ []) do
    with {:ok, _} <- validate_rest_config(config),
         {:ok, sid} <- dispatch_search(spl_query, config, opts),
         {:ok, results} <- poll_search_results(sid, config) do
      {:ok, results}
    end
  end

  @doc """
  Retrieve enrichment data from a Splunk KV store lookup or saved search.

  ## Parameters

  - `lookup_name` - Name of the Splunk lookup table or KV store collection
  - `config` - Splunk configuration map

  ## Returns

  `{:ok, data}` on success, `{:error, reason}` on failure.
  """
  @spec get_enrichment(String.t(), config()) :: {:ok, list(map())} | {:error, term()}
  def get_enrichment(lookup_name, config) do
    with {:ok, _} <- validate_rest_config(config) do
      url =
        "#{config[:rest_url]}/servicesNS/-/-/storage/collections/data/#{URI.encode(lookup_name)}?output_mode=json"

      headers = rest_auth_headers(config)
      timeout = config[:timeout_ms] || @default_timeout_ms

      IntegrationLog.log_api_call("splunk_hec", "get_enrichment", lookup_name, fn ->
        case do_http(:get, url, headers, nil, timeout) do
          {:ok, %{status: status, body: body}} when status in 200..299 ->
            {:ok, Jason.decode!(body)}

          {:ok, %{status: status, body: body}} ->
            {:error, "HTTP #{status}: #{body}"}

          {:error, reason} ->
            {:error, reason}
        end
      end)
    end
  end

  @doc """
  Validate HEC token and endpoint connectivity.

  ## Parameters

  - `config` - Splunk configuration map with `:hec_url` and `:hec_token`

  ## Returns

  `{:ok, %{status: "healthy"}}` on success, `{:error, reason}` on failure.
  """
  @spec test_connection(config()) :: {:ok, map()} | {:error, term()}
  def test_connection(config) do
    url = "#{config[:hec_url]}#{@hec_health_endpoint}"

    headers = [
      {"Authorization", "Splunk #{config[:hec_token]}"}
    ]

    timeout = config[:timeout_ms] || @default_timeout_ms

    case do_http(:get, url, headers, nil, timeout) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, Jason.decode!(body)}

      {:ok, %{status: status, body: body}} ->
        {:error, "HEC health check failed: HTTP #{status} - #{truncate(body)}"}

      {:error, reason} ->
        {:error, "Connection failed: #{inspect(reason)}"}
    end
  rescue
    e -> {:error, "Connection test error: #{Exception.message(e)}"}
  end

  # ============================================================================
  # Private: HEC Event Formatting
  # ============================================================================

  defp format_alert(alert, config, opts) do
    %{
      time: extract_timestamp(alert),
      source: "tamandua-edr",
      sourcetype: opts[:sourcetype] || config[:sourcetype] || "tamandua:alert",
      index: opts[:index] || config[:index] || @default_index,
      host: opts[:host] || alert_field(alert, :hostname),
      event: %{
        alert_id: alert_field(alert, :id),
        title: alert_field(alert, :title),
        description: alert_field(alert, :description),
        severity: alert_field(alert, :severity),
        status: alert_field(alert, :status),
        agent_id: alert_field(alert, :agent_id),
        hostname: alert_field(alert, :hostname),
        mitre_tactics: alert_field(alert, :mitre_tactics) || [],
        mitre_techniques: alert_field(alert, :mitre_techniques) || [],
        threat_score: alert_field(alert, :threat_score),
        evidence: alert_field(alert, :evidence) || %{}
      }
    }
  end

  defp format_event(event, config, opts) do
    %{
      time: extract_timestamp(event),
      source: "tamandua-edr",
      sourcetype: opts[:sourcetype] || config[:sourcetype] || @default_sourcetype,
      index: opts[:index] || config[:index] || @default_index,
      host: alert_field(event, :hostname),
      event: event
    }
  end

  defp extract_timestamp(data) do
    ts = alert_field(data, :timestamp) || alert_field(data, :created_at) || alert_field(data, :inserted_at)

    case ts do
      %DateTime{} = dt -> DateTime.to_unix(dt, :second)
      %NaiveDateTime{} = ndt -> NaiveDateTime.to_gregorian_seconds(ndt) - 62_167_219_200
      n when is_integer(n) -> n
      s when is_binary(s) ->
        case DateTime.from_iso8601(s) do
          {:ok, dt, _} -> DateTime.to_unix(dt, :second)
          _ -> System.os_time(:second)
        end
      _ -> System.os_time(:second)
    end
  end

  # ============================================================================
  # Private: HTTP with Retry
  # ============================================================================

  defp do_hec_post(config, body) do
    url = "#{config[:hec_url]}#{@hec_event_endpoint}"

    headers = [
      {"Authorization", "Splunk #{config[:hec_token]}"},
      {"Content-Type", "application/json"}
    ]

    timeout = config[:timeout_ms] || @default_timeout_ms
    do_with_retry(fn -> do_http(:post, url, headers, body, timeout) end, 0)
  end

  defp do_with_retry(fun, attempt) do
    case fun.() do
      {:ok, %{status: status}} when status in 200..299 ->
        :ok

      {:ok, %{status: status, body: _resp_body}} when attempt < @max_retries ->
        delay = @retry_base_delay_ms * round(:math.pow(2, attempt))
        Logger.warning("[SplunkHEC] HTTP #{status}, retrying in #{delay}ms (attempt #{attempt + 1}/#{@max_retries})")
        Process.sleep(delay)
        do_with_retry(fun, attempt + 1)

      {:ok, %{status: status, body: resp_body}} ->
        {:error, "HTTP #{status}: #{truncate(resp_body)}"}

      {:error, reason} when attempt < @max_retries ->
        delay = @retry_base_delay_ms * round(:math.pow(2, attempt))
        Logger.warning("[SplunkHEC] Error #{inspect(reason)}, retrying in #{delay}ms (attempt #{attempt + 1}/#{@max_retries})")
        Process.sleep(delay)
        do_with_retry(fun, attempt + 1)

      {:error, reason} ->
        {:error, reason}
    end
  end

  # ============================================================================
  # Private: SPL Search
  # ============================================================================

  defp dispatch_search(spl_query, config, opts) do
    url = "#{config[:rest_url]}#{@search_endpoint}?output_mode=json"
    headers = rest_auth_headers(config) ++ [{"Content-Type", "application/x-www-form-urlencoded"}]
    timeout = config[:timeout_ms] || @default_timeout_ms

    params = %{
      "search" => spl_query,
      "earliest_time" => opts[:earliest_time] || "-24h",
      "latest_time" => opts[:latest_time] || "now",
      "max_count" => opts[:max_results] || 1000
    }

    body = URI.encode_query(params)

    case do_http(:post, url, headers, body, timeout) do
      {:ok, %{status: 201, body: resp_body}} ->
        response = Jason.decode!(resp_body)
        {:ok, response["sid"]}

      {:ok, %{status: status, body: resp_body}} ->
        {:error, "Search dispatch failed: HTTP #{status} - #{truncate(resp_body)}"}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp poll_search_results(sid, config, attempts \\ 0) do
    if attempts > 60 do
      {:error, :search_timeout}
    else
      url = "#{config[:rest_url]}#{@search_endpoint}/#{sid}/results?output_mode=json"
      headers = rest_auth_headers(config)
      timeout = config[:timeout_ms] || @default_timeout_ms

      case do_http(:get, url, headers, nil, timeout) do
        {:ok, %{status: 200, body: body}} ->
          response = Jason.decode!(body)
          {:ok, %{sid: sid, results: response["results"] || [], count: length(response["results"] || [])}}

        {:ok, %{status: 204}} ->
          Process.sleep(1_000)
          poll_search_results(sid, config, attempts + 1)

        {:ok, %{status: status, body: body}} ->
          {:error, "Search results failed: HTTP #{status} - #{truncate(body)}"}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  # ============================================================================
  # Private: Helpers
  # ============================================================================

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

  defp rest_auth_headers(config) do
    auth = Base.encode64("#{config[:rest_username]}:#{config[:rest_password]}")
    [{"Authorization", "Basic #{auth}"}]
  end

  defp validate_rest_config(config) do
    if config[:rest_url] && config[:rest_username] do
      {:ok, config}
    else
      {:error, :rest_api_not_configured}
    end
  end

  defp alert_field(data, key) when is_atom(key) do
    Map.get(data, key) || Map.get(data, to_string(key))
  end

  defp truncate(str) when is_binary(str) and byte_size(str) > 500 do
    String.slice(str, 0, 500) <> "..."
  end

  defp truncate(str) when is_binary(str), do: str
  defp truncate(other), do: inspect(other)
end
