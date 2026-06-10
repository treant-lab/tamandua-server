defmodule TamanduaServer.Integrations.Enrichment.Shodan do
  @moduledoc """
  Shodan Integration for Infrastructure Enrichment

  Provides enrichment capabilities using Shodan API:
  - IP address lookup (services, ports, vulnerabilities)
  - Host search
  - DNS lookup
  - Exploit search
  - Vulnerability lookup

  ## Configuration

      config :tamandua_server, TamanduaServer.Integrations.Enrichment.Shodan,
        api_key: "your-api-key",
        cache_ttl_seconds: 3600

  """

  use GenServer
  require Logger

  @base_url "https://api.shodan.io"
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
  Lookup IP address information.
  """
  @spec lookup_ip(String.t()) :: {:ok, map()} | {:error, term()}
  def lookup_ip(ip) do
    GenServer.call(__MODULE__, {:lookup_ip, ip}, 30_000)
  end

  @doc """
  Search for hosts.
  """
  @spec search_hosts(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def search_hosts(query, opts \\ []) do
    GenServer.call(__MODULE__, {:search_hosts, query, opts}, 60_000)
  end

  @doc """
  Get DNS records for a domain.
  """
  @spec dns_lookup(String.t()) :: {:ok, map()} | {:error, term()}
  def dns_lookup(domain) do
    GenServer.call(__MODULE__, {:dns_lookup, domain}, 30_000)
  end

  @doc """
  Reverse DNS lookup.
  """
  @spec reverse_dns(String.t()) :: {:ok, [String.t()]} | {:error, term()}
  def reverse_dns(ip) do
    GenServer.call(__MODULE__, {:reverse_dns, ip}, 30_000)
  end

  @doc """
  Search for exploits.
  """
  @spec search_exploits(String.t()) :: {:ok, [map()]} | {:error, term()}
  def search_exploits(query) do
    GenServer.call(__MODULE__, {:search_exploits, query}, 30_000)
  end

  @doc """
  Get vulnerabilities for a host.
  """
  @spec get_vulnerabilities(String.t()) :: {:ok, [map()]} | {:error, term()}
  def get_vulnerabilities(ip) do
    GenServer.call(__MODULE__, {:get_vulnerabilities, ip}, 30_000)
  end

  @doc """
  Enrich multiple IPs in batch.
  """
  @spec enrich_batch([String.t()]) :: {:ok, [map()]} | {:error, term()}
  def enrich_batch(ips) do
    GenServer.call(__MODULE__, {:enrich_batch, ips}, 120_000)
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
    Logger.info("Starting Shodan Enrichment Integration")
    config = load_config(opts)

    state = %__MODULE__{
      config: config,
      api_key: config.api_key,
      cache: %{},
      stats: %{
        ip_lookups: 0,
        searches: 0,
        dns_lookups: 0,
        cache_hits: 0,
        errors: 0,
        last_activity: nil
      }
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:lookup_ip, ip}, _from, state) do
    case check_cache(state, {:ip, ip}) do
      {:hit, result} ->
        new_stats = update_stat(state.stats, :cache_hits)
        {:reply, {:ok, result}, %{state | stats: new_stats}}

      :miss ->
        case get_request(state, "/shodan/host/#{ip}") do
          {:ok, response} ->
            result = format_ip_result(response)
            final_state = cache_result(state, {:ip, ip}, result)
            new_stats = update_stat(final_state.stats, :ip_lookups)
            {:reply, {:ok, result}, %{final_state | stats: new_stats}}

          {:error, :not_found} ->
            {:reply, {:ok, %{found: false, ip: ip}}, state}

          error ->
            {:reply, error, update_error_stat(state)}
        end
    end
  end

  @impl true
  def handle_call({:search_hosts, query, opts}, _from, state) do
    params = [
      query: query,
      page: opts[:page] || 1,
      minify: opts[:minify] || false
    ]

    case get_request(state, "/shodan/host/search", params) do
      {:ok, response} ->
        result = format_search_result(response)
        new_stats = update_stat(state.stats, :searches)
        {:reply, {:ok, result}, %{state | stats: new_stats}}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:dns_lookup, domain}, _from, state) do
    case check_cache(state, {:dns, domain}) do
      {:hit, result} ->
        new_stats = update_stat(state.stats, :cache_hits)
        {:reply, {:ok, result}, %{state | stats: new_stats}}

      :miss ->
        case get_request(state, "/dns/resolve", hostnames: domain) do
          {:ok, response} ->
            result = %{domain: domain, ips: Map.get(response, domain, [])}
            final_state = cache_result(state, {:dns, domain}, result)
            new_stats = update_stat(final_state.stats, :dns_lookups)
            {:reply, {:ok, result}, %{final_state | stats: new_stats}}

          error ->
            {:reply, error, update_error_stat(state)}
        end
    end
  end

  @impl true
  def handle_call({:reverse_dns, ip}, _from, state) do
    case get_request(state, "/dns/reverse", ips: ip) do
      {:ok, response} ->
        hostnames = Map.get(response, ip, [])
        {:reply, {:ok, hostnames}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:search_exploits, query}, _from, state) do
    case get_request(state, "/api/search", query: query) do
      {:ok, response} ->
        exploits = response["matches"] || []
        {:reply, {:ok, exploits}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:get_vulnerabilities, ip}, _from, state) do
    case get_request(state, "/shodan/host/#{ip}") do
      {:ok, response} ->
        vulns = response["vulns"] || []
        formatted = Enum.map(vulns, fn vuln ->
          %{
            cve: vuln,
            cvss: response["vulns_info"][vuln]["cvss"] || nil,
            summary: response["vulns_info"][vuln]["summary"] || nil
          }
        end)
        {:reply, {:ok, formatted}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:enrich_batch, ips}, _from, state) do
    results = Enum.map(ips, fn ip ->
      case get_request(state, "/shodan/host/#{ip}") do
        {:ok, response} -> format_ip_result(response)
        _ -> %{found: false, ip: ip}
      end
    end)

    {:reply, {:ok, results}, state}
  end

  @impl true
  def handle_call(:test_connection, _from, state) do
    case get_request(state, "/api-info") do
      {:ok, _} -> {:reply, {:ok, "Connected to Shodan"}, state}
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

  defp format_ip_result(response) do
    %{
      found: true,
      ip: response["ip_str"],
      hostnames: response["hostnames"] || [],
      country: response["country_name"],
      country_code: response["country_code"],
      city: response["city"],
      org: response["org"],
      asn: response["asn"],
      isp: response["isp"],
      ports: response["ports"] || [],
      os: response["os"],
      tags: response["tags"] || [],
      vulns: response["vulns"] || [],
      last_update: response["last_update"],
      services: Enum.map(response["data"] || [], fn svc ->
        %{
          port: svc["port"],
          transport: svc["transport"],
          product: svc["product"],
          version: svc["version"],
          banner: String.slice(svc["data"] || "", 0, 500)
        }
      end)
    }
  end

  defp format_search_result(response) do
    %{
      total: response["total"],
      matches: Enum.map(response["matches"] || [], fn match ->
        %{
          ip: match["ip_str"],
          port: match["port"],
          org: match["org"],
          hostnames: match["hostnames"] || [],
          product: match["product"],
          os: match["os"]
        }
      end)
    }
  end

  defp get_request(state, endpoint, params \\ []) do
    params = Keyword.put(params, :key, state.api_key)
    query = URI.encode_query(params)
    url = "#{@base_url}#{endpoint}?#{query}"

    headers = [{"Accept", "application/json"}]
    options = [timeout: state.config.timeout_ms, recv_timeout: state.config.timeout_ms]

    case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000)) do
      {:ok, %{status_code: 200, body: body}} -> {:ok, Jason.decode!(body)}
      {:ok, %{status_code: 404}} -> {:error, :not_found}
      {:ok, %{status_code: code, body: body}} ->
        Logger.error("Shodan API error: HTTP #{code} - #{body}")
        {:error, "HTTP #{code}: #{body}"}
      {:error, %{reason: reason}} ->
        Logger.error("Shodan connection error: #{inspect(reason)}")
        {:error, reason}
    end
  rescue
    e ->
      Logger.error("Shodan exception: #{inspect(e)}")
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
