defmodule TamanduaServer.Integrations.Enrichment.URLScan do
  @moduledoc """
  URLScan.io Integration for URL/Website Analysis

  Provides enrichment capabilities using URLScan API:
  - URL submission for scanning
  - Screenshot capture
  - DOM analysis
  - Network requests analysis
  - Verdict and classification

  ## Configuration

      config :tamandua_server, TamanduaServer.Integrations.Enrichment.URLScan,
        api_key: "your-api-key",
        visibility: "public",  # or "unlisted", "private"
        cache_ttl_seconds: 3600

  """

  use GenServer
  require Logger

  @base_url "https://urlscan.io/api/v1"
  @default_timeout_ms 30_000
  @default_cache_ttl 3600

  defstruct [:config, :api_key, :cache, :stats]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Submit a URL for scanning.
  """
  @spec scan_url(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def scan_url(url, opts \\ []) do
    GenServer.call(__MODULE__, {:scan_url, url, opts}, 120_000)
  end

  @doc """
  Get scan results by UUID.
  """
  @spec get_result(String.t()) :: {:ok, map()} | {:error, term()}
  def get_result(uuid) do
    GenServer.call(__MODULE__, {:get_result, uuid}, 30_000)
  end

  @doc """
  Search for existing scans.
  """
  @spec search(String.t(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def search(query, opts \\ []) do
    GenServer.call(__MODULE__, {:search, query, opts}, 30_000)
  end

  @doc """
  Get DOM content from a scan.
  """
  @spec get_dom(String.t()) :: {:ok, String.t()} | {:error, term()}
  def get_dom(uuid) do
    GenServer.call(__MODULE__, {:get_dom, uuid}, 30_000)
  end

  @doc """
  Get screenshot URL from a scan.
  """
  @spec get_screenshot(String.t()) :: {:ok, String.t()} | {:error, term()}
  def get_screenshot(uuid) do
    GenServer.call(__MODULE__, {:get_screenshot, uuid}, 30_000)
  end

  @doc """
  Enrich multiple URLs.
  """
  @spec enrich_batch([String.t()]) :: {:ok, [map()]} | {:error, term()}
  def enrich_batch(urls) do
    GenServer.call(__MODULE__, {:enrich_batch, urls}, 300_000)
  end

  @spec test_connection() :: {:ok, String.t()} | {:error, term()}
  def test_connection do
    GenServer.call(__MODULE__, :test_connection, 30_000)
  end

  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    Logger.info("Starting URLScan Enrichment Integration")
    config = load_config(opts)

    state = %__MODULE__{
      config: config,
      api_key: config.api_key,
      cache: %{},
      stats: %{
        scans_submitted: 0,
        results_fetched: 0,
        searches: 0,
        cache_hits: 0,
        errors: 0,
        last_activity: nil
      }
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:scan_url, url, opts}, _from, state) do
    # Check if URL was already scanned recently
    reuse_existing = opts[:reuse_existing] != false

    case search_existing(state, url) do
      {:ok, [existing | _]} when is_map(existing) ->
        if reuse_existing do
          result = format_search_result(existing)
          {:reply, {:ok, result}, state}
        else
          do_submit_scan(state, url, opts)
        end

      _ ->
        do_submit_scan(state, url, opts)
    end
  end

  defp do_submit_scan(state, url, opts) do
    case submit_scan(state, url, opts) do
      {:ok, response} ->
        uuid = response["uuid"]

        # Poll for results
        case poll_for_results(state, uuid, opts[:timeout] || 60_000) do
          {:ok, result} ->
            new_stats = update_stat(state.stats, :scans_submitted)
            {:reply, {:ok, result}, %{state | stats: new_stats}}

          _error ->
            # Return pending status with UUID
            {:reply, {:ok, %{uuid: uuid, status: "pending", url: url}}, state}
        end

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:get_result, uuid}, _from, state) do
    case check_cache(state, {:result, uuid}) do
      {:hit, result} ->
        new_stats = update_stat(state.stats, :cache_hits)
        {:reply, {:ok, result}, %{state | stats: new_stats}}

      :miss ->
        case get_request(state, "/result/#{uuid}/") do
          {:ok, response} ->
            result = format_result(response)
            final_state = cache_result(state, {:result, uuid}, result)
            new_stats = update_stat(final_state.stats, :results_fetched)
            {:reply, {:ok, result}, %{final_state | stats: new_stats}}

          {:error, :not_found} ->
            {:reply, {:ok, %{uuid: uuid, status: "pending"}}, state}

          error ->
            {:reply, error, update_error_stat(state)}
        end
    end
  end

  @impl true
  def handle_call({:search, query, opts}, _from, state) do
    size = opts[:size] || 100

    case get_request(state, "/search/?q=#{URI.encode(query)}&size=#{size}") do
      {:ok, response} ->
        results = Enum.map(response["results"] || [], &format_search_result/1)
        new_stats = update_stat(state.stats, :searches)
        {:reply, {:ok, results}, %{state | stats: new_stats}}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:get_dom, uuid}, _from, state) do
    url = "https://urlscan.io/dom/#{uuid}/"

    case Finch.build(:get, url) |> Finch.request(TamanduaServer.Finch, receive_timeout: state.config.timeout_ms) do
      {:ok, %{status_code: 200, body: body}} ->
        {:reply, {:ok, body}, state}

      {:ok, %{status_code: 404}} ->
        {:reply, {:error, :not_found}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:get_screenshot, uuid}, _from, state) do
    screenshot_url = "https://urlscan.io/screenshots/#{uuid}.png"
    {:reply, {:ok, screenshot_url}, state}
  end

  @impl true
  def handle_call({:enrich_batch, urls}, _from, state) do
    results = Enum.map(urls, fn url ->
      # First search for existing scan
      case search_existing(state, url) do
        {:ok, [existing | _]} ->
          format_search_result(existing)

        _ ->
          # Submit new scan
          case submit_scan(state, url, []) do
            {:ok, response} ->
              uuid = response["uuid"]
              # Wait and poll
              case poll_for_results(state, uuid, 30_000) do
                {:ok, result} -> result
                _ -> %{uuid: uuid, url: url, status: "pending"}
              end

            _ ->
              %{url: url, error: "Failed to submit scan"}
          end
      end
    end)

    {:reply, {:ok, results}, state}
  end

  @impl true
  def handle_call(:test_connection, _from, state) do
    case get_request(state, "/search/?q=domain:example.com&size=1") do
      {:ok, _} -> {:reply, {:ok, "Connected to URLScan"}, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp load_config(opts) do
    app_config = Application.get_env(:tamandua_server, __MODULE__, [])

    %{
      api_key: opts[:api_key] || app_config[:api_key],
      visibility: opts[:visibility] || app_config[:visibility] || "public",
      cache_ttl: opts[:cache_ttl_seconds] || app_config[:cache_ttl_seconds] || @default_cache_ttl,
      timeout_ms: opts[:timeout_ms] || app_config[:timeout_ms] || @default_timeout_ms
    }
  end

  defp check_cache(state, key) do
    case Map.get(state.cache, key) do
      nil -> :miss
      {result, timestamp} ->
        age = DateTime.diff(DateTime.utc_now(), timestamp, :second)
        if age < state.config.cache_ttl, do: {:hit, result}, else: :miss
    end
  end

  defp cache_result(state, key, result) do
    new_cache = Map.put(state.cache, key, {result, DateTime.utc_now()})
    %{state | cache: new_cache}
  end

  defp search_existing(state, url) do
    query = "page.url:\"#{url}\""
    get_request(state, "/search/?q=#{URI.encode(query)}&size=1")
    |> case do
      {:ok, %{"results" => results}} when length(results) > 0 -> {:ok, results}
      _ -> {:error, :not_found}
    end
  end

  defp submit_scan(state, url, opts) do
    body = Jason.encode!(%{
      url: url,
      visibility: opts[:visibility] || state.config.visibility,
      tags: opts[:tags] || ["tamandua"]
    })

    headers = [
      {"API-Key", state.api_key},
      {"Content-Type", "application/json"}
    ]

    options = [timeout: state.config.timeout_ms, recv_timeout: state.config.timeout_ms]

    case Finch.build(:post, "#{@base_url}/scan/", headers, body) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000)) do
      {:ok, %{status_code: 200, body: resp_body}} ->
        {:ok, Jason.decode!(resp_body)}

      {:ok, %{status_code: code, body: resp_body}} ->
        {:error, "HTTP #{code}: #{resp_body}"}

      {:error, %{reason: reason}} ->
        {:error, reason}
    end
  end

  defp poll_for_results(state, uuid, timeout, elapsed \\ 0) do
    if elapsed >= timeout do
      {:error, :timeout}
    else
      case get_request(state, "/result/#{uuid}/") do
        {:ok, response} ->
          {:ok, format_result(response)}

        {:error, :not_found} ->
          Process.sleep(3000)
          poll_for_results(state, uuid, timeout, elapsed + 3000)

        error ->
          error
      end
    end
  end

  defp format_result(response) do
    %{
      uuid: get_in(response, ["task", "uuid"]),
      url: get_in(response, ["task", "url"]),
      domain: get_in(response, ["task", "domain"]),
      time: get_in(response, ["task", "time"]),
      screenshot: get_in(response, ["task", "screenshotURL"]),
      verdict: %{
        score: get_in(response, ["verdicts", "overall", "score"]),
        malicious: get_in(response, ["verdicts", "overall", "malicious"]),
        categories: get_in(response, ["verdicts", "overall", "categories"]) || [],
        brands: get_in(response, ["verdicts", "overall", "brands"]) || []
      },
      page: %{
        url: get_in(response, ["page", "url"]),
        domain: get_in(response, ["page", "domain"]),
        ip: get_in(response, ["page", "ip"]),
        country: get_in(response, ["page", "country"]),
        server: get_in(response, ["page", "server"]),
        title: get_in(response, ["page", "title"]),
        status: get_in(response, ["page", "status"])
      },
      stats: %{
        requests: get_in(response, ["stats", "requests"]) || 0,
        domains: get_in(response, ["stats", "domains"]) || 0,
        ips: get_in(response, ["stats", "ips"]) || 0,
        countries: get_in(response, ["stats", "countries"]) || 0,
        data_length: get_in(response, ["stats", "dataLength"]) || 0
      },
      lists: %{
        ips: get_in(response, ["lists", "ips"]) || [],
        domains: get_in(response, ["lists", "domains"]) || [],
        urls: get_in(response, ["lists", "urls"]) || [],
        asns: get_in(response, ["lists", "asns"]) || [],
        servers: get_in(response, ["lists", "servers"]) || []
      }
    }
  end

  defp format_search_result(result) do
    %{
      uuid: result["_id"],
      url: get_in(result, ["page", "url"]),
      domain: get_in(result, ["page", "domain"]),
      ip: get_in(result, ["page", "ip"]),
      country: get_in(result, ["page", "country"]),
      server: get_in(result, ["page", "server"]),
      status: get_in(result, ["page", "status"]),
      screenshot: result["screenshot"],
      time: get_in(result, ["task", "time"]),
      verdict: %{
        score: get_in(result, ["verdicts", "overall", "score"]),
        malicious: get_in(result, ["verdicts", "overall", "malicious"])
      }
    }
  end

  defp get_request(state, endpoint) do
    url = "#{@base_url}#{endpoint}"

    headers = if state.api_key do
      [{"API-Key", state.api_key}]
    else
      []
    end

    options = [timeout: state.config.timeout_ms, recv_timeout: state.config.timeout_ms]

    case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000)) do
      {:ok, %{status_code: 200, body: body}} -> {:ok, Jason.decode!(body)}
      {:ok, %{status_code: 404}} -> {:error, :not_found}
      {:ok, %{status_code: code, body: body}} ->
        Logger.error("URLScan API error: HTTP #{code} - #{body}")
        {:error, "HTTP #{code}: #{body}"}
      {:error, %{reason: reason}} ->
        Logger.error("URLScan connection error: #{inspect(reason)}")
        {:error, reason}
    end
  rescue
    e ->
      Logger.error("URLScan exception: #{inspect(e)}")
      {:error, Exception.message(e)}
  end

  defp update_stat(stats, key) do
    stats |> Map.update(key, 1, &(&1 + 1)) |> Map.put(:last_activity, DateTime.utc_now())
  end

  defp update_error_stat(state) do
    new_stats = Map.update(state.stats, :errors, 1, &(&1 + 1))
    %{state | stats: new_stats}
  end
end
