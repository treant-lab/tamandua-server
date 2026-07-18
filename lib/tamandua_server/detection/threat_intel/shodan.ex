defmodule TamanduaServer.Detection.ThreatIntel.Shodan do
  @moduledoc """
  Shodan API integration for IP enrichment and infrastructure intelligence.

  Provides IP lookups, port/service information, vulnerability data, and search capabilities
  using the Shodan API.

  ## API Limits
  - 1 request per second (recommended)
  - Varies by plan: Free (1 req/s), Small (10 req/s), etc.

  ## Usage

      # Configure API key
      Shodan.configure("your-shodan-api-key")

      # Lookup an IP address
      Shodan.lookup_ip("192.168.1.1")

      # Search for hosts
      Shodan.search("apache port:80 country:US")

      # Get host count for a query
      Shodan.count("port:22 country:US")

  ## Configuration

  Set the `SHODAN_API_KEY` environment variable or configure via:

      config :tamandua_server, :threat_intel,
        shodan_api_key: "your-api-key"
  """

  use GenServer
  require Logger

  @api_base "https://api.shodan.io"
  @recv_timeout 30_000

  # Rate limiting: 1 request per second for free tier
  @rate_limit_interval 1000  # milliseconds

  # Cache TTL: 12 hours for IP lookups
  @cache_ttl :timer.hours(12)

  @ets_table :shodan_cache

  # ============================================================================
  # Client API
  # ============================================================================

  @doc """
  Starts the Shodan integration GenServer.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Configure the Shodan API key.

  ## Examples

      iex> configure("your-shodan-api-key")
      :ok
  """
  @spec configure(String.t()) :: :ok
  def configure(api_key) when is_binary(api_key) do
    GenServer.call(__MODULE__, {:configure, api_key})
  end

  @doc """
  Lookup an IP address in Shodan.

  Returns information about the host including open ports, services, vulnerabilities,
  and geolocation data.

  ## Examples

      iex> lookup_ip("8.8.8.8")
      {:ok, %{
        ip: "8.8.8.8",
        ip_str: "8.8.8.8",
        org: "Google LLC",
        isp: "Google LLC",
        asn: "AS15169",
        hostnames: ["dns.google"],
        domains: ["google"],
        country_code: "US",
        country_name: "United States",
        city: "Mountain View",
        region_code: "CA",
        latitude: 37.4056,
        longitude: -122.0775,
        ports: [53, 443],
        vulns: ["CVE-2021-1234"],
        tags: ["cloud"],
        last_update: ~U[2024-01-20 15:30:00Z],
        services: [
          %{
            port: 53,
            transport: "udp",
            product: "Google DNS",
            version: nil,
            banner: "..."
          },
          ...
        ]
      }}

      iex> lookup_ip("10.0.0.1")
      {:ok, %{found: false, ip: "10.0.0.1"}}
  """
  @spec lookup_ip(String.t()) :: {:ok, map()} | {:error, term()}
  def lookup_ip(ip) when is_binary(ip) do
    GenServer.call(__MODULE__, {:lookup_ip, ip}, 60_000)
  end

  @doc """
  Lookup an IP address with minimal API credits (history excluded).

  Returns the same information as `lookup_ip/1` but without historical data.
  Uses fewer API credits.
  """
  @spec lookup_ip_minified(String.t()) :: {:ok, map()} | {:error, term()}
  def lookup_ip_minified(ip) when is_binary(ip) do
    GenServer.call(__MODULE__, {:lookup_ip_minified, ip}, 60_000)
  end

  @doc """
  Search Shodan for hosts matching a query.

  ## Query Examples
  - `"apache"` - Search for Apache servers
  - `"port:22"` - Search for SSH servers
  - `"apache country:US"` - Apache servers in the US
  - `"vuln:CVE-2021-1234"` - Hosts vulnerable to specific CVE
  - `"product:nginx version:1.19"` - Specific product version

  ## Options
  - `:page` - Page number for results (default: 1)
  - `:minify` - Return minimal results (default: true)
  - `:facets` - Comma-separated list of facets (e.g., "country,port")

  ## Examples

      iex> search("apache port:80 country:US", page: 1)
      {:ok, %{
        total: 12345,
        matches: [
          %{ip_str: "1.2.3.4", port: 80, ...},
          ...
        ],
        facets: %{}
      }}
  """
  @spec search(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def search(query, opts \\ []) when is_binary(query) do
    GenServer.call(__MODULE__, {:search, query, opts}, 60_000)
  end

  @doc """
  Get the number of hosts matching a search query.

  This is cheaper than `search/2` as it only returns counts.

  ## Options
  - `:facets` - Comma-separated list of facets to include

  ## Examples

      iex> count("port:22 country:US")
      {:ok, %{
        total: 1234567,
        facets: %{
          "country" => [%{value: "US", count: 500000}, ...]
        }
      }}
  """
  @spec count(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def count(query, opts \\ []) when is_binary(query) do
    GenServer.call(__MODULE__, {:count, query, opts}, 60_000)
  end

  @doc """
  Get DNS records for a domain.

  ## Examples

      iex> dns_resolve("google.com")
      {:ok, %{
        "google.com" => "142.250.185.238"
      }}
  """
  @spec dns_resolve(String.t() | [String.t()]) :: {:ok, map()} | {:error, term()}
  def dns_resolve(hostnames) when is_binary(hostnames) or is_list(hostnames) do
    GenServer.call(__MODULE__, {:dns_resolve, List.wrap(hostnames)}, 60_000)
  end

  @doc """
  Get reverse DNS for an IP address.

  ## Examples

      iex> dns_reverse("8.8.8.8")
      {:ok, %{
        "8.8.8.8" => ["dns.google"]
      }}
  """
  @spec dns_reverse(String.t() | [String.t()]) :: {:ok, map()} | {:error, term()}
  def dns_reverse(ips) when is_binary(ips) or is_list(ips) do
    GenServer.call(__MODULE__, {:dns_reverse, List.wrap(ips)}, 60_000)
  end

  @doc """
  Get information about the API key being used.

  ## Examples

      iex> api_info()
      {:ok, %{
        query_credits: 100,
        scan_credits: 10,
        plan: "dev",
        unlocked: true
      }}
  """
  @spec api_info() :: {:ok, map()} | {:error, term()}
  def api_info do
    GenServer.call(__MODULE__, :api_info, 60_000)
  end

  @doc """
  Get a list of ports that Shodan is scanning.

  ## Examples

      iex> ports()
      {:ok, [21, 22, 23, 25, 80, 443, ...]}
  """
  @spec ports() :: {:ok, [integer()]} | {:error, term()}
  def ports do
    GenServer.call(__MODULE__, :ports, 60_000)
  end

  @doc """
  Get a list of protocols that Shodan is scanning.

  ## Examples

      iex> protocols()
      {:ok, %{
        "dns-udp" => "DNS (UDP)",
        "http" => "HTTP",
        ...
      }}
  """
  @spec protocols() :: {:ok, map()} | {:error, term()}
  def protocols do
    GenServer.call(__MODULE__, :protocols, 60_000)
  end

  @doc """
  Get current service status including API credit info.

  ## Examples

      iex> get_status()
      %{
        configured: true,
        api_credits: %{query_credits: 100, scan_credits: 10},
        cache_size: 1234,
        stats: %{lookups: 100, cache_hits: 80, api_calls: 20}
      }
  """
  @spec get_status() :: map()
  def get_status do
    GenServer.call(__MODULE__, :get_status)
  end

  @doc """
  Clear the local cache.
  """
  @spec clear_cache() :: :ok
  def clear_cache do
    GenServer.call(__MODULE__, :clear_cache)
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    # Create ETS cache
    :ets.new(@ets_table, [:named_table, :set, :public, read_concurrency: true])

    api_key = Keyword.get(opts, :api_key) ||
              Application.get_env(:tamandua_server, :threat_intel)[:shodan_api_key] ||
              System.get_env("SHODAN_API_KEY")

    state = %{
      api_key: api_key,
      last_request: 0,  # timestamp of last request
      api_credits: nil,
      stats: %{
        lookups: 0,
        cache_hits: 0,
        api_calls: 0,
        errors: 0,
        rate_limited: 0
      }
    }

    Logger.info("[Shodan] Initialized, API key #{if api_key, do: "configured", else: "not configured"}")

    {:ok, state}
  end

  @impl true
  def handle_call({:configure, api_key}, _from, state) do
    Logger.info("[Shodan] API key configured")
    {:reply, :ok, %{state | api_key: api_key}}
  end

  @impl true
  def handle_call({:lookup_ip, ip}, _from, state) do
    state = update_stats(state, :lookup)

    case get_cached(:ip, ip) do
      {:ok, cached} ->
        state = update_stats(state, :cache_hit)
        {:reply, {:ok, cached}, state}

      :miss ->
        {result, state} = do_lookup_ip(ip, false, state)
        {:reply, result, state}
    end
  end

  @impl true
  def handle_call({:lookup_ip_minified, ip}, _from, state) do
    state = update_stats(state, :lookup)

    case get_cached(:ip, ip) do
      {:ok, cached} ->
        state = update_stats(state, :cache_hit)
        {:reply, {:ok, cached}, state}

      :miss ->
        {result, state} = do_lookup_ip(ip, true, state)
        {:reply, result, state}
    end
  end

  @impl true
  def handle_call({:search, query, opts}, _from, state) do
    {result, state} = do_search(query, opts, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:count, query, opts}, _from, state) do
    {result, state} = do_count(query, opts, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:dns_resolve, hostnames}, _from, state) do
    {result, state} = do_dns_resolve(hostnames, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:dns_reverse, ips}, _from, state) do
    {result, state} = do_dns_reverse(ips, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:api_info, _from, state) do
    {result, state} = do_api_info(state)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:ports, _from, state) do
    {result, state} = do_ports(state)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:protocols, _from, state) do
    {result, state} = do_protocols(state)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:get_status, _from, state) do
    status = %{
      configured: state.api_key != nil,
      api_credits: state.api_credits,
      cache_size: :ets.info(@ets_table, :size),
      stats: state.stats
    }
    {:reply, status, state}
  end

  @impl true
  def handle_call(:clear_cache, _from, state) do
    :ets.delete_all_objects(@ets_table)
    Logger.info("[Shodan] Cache cleared")
    {:reply, :ok, state}
  end

  # ============================================================================
  # Private Functions - API Calls
  # ============================================================================

  defp do_lookup_ip(ip, minify, state) do
    if state.api_key do
      state = wait_for_rate_limit(state)

      url = "#{@api_base}/shodan/host/#{ip}?key=#{state.api_key}"
      url = if minify, do: "#{url}&minify=true", else: url

      case execute_get_request(url, state) do
        {:ok, data, state} ->
          result = parse_host_response(data)
          cache_result(:ip, ip, result)
          {{:ok, result}, state}

        {:error, :not_found, state} ->
          result = %{found: false, ip: ip}
          cache_result(:ip, ip, result)
          {{:ok, result}, state}

        {:error, reason, state} ->
          {{:error, reason}, state}
      end
    else
      {{:error, :no_api_key}, state}
    end
  end

  defp do_search(query, opts, state) do
    if state.api_key do
      state = wait_for_rate_limit(state)

      page = Keyword.get(opts, :page, 1)
      minify = Keyword.get(opts, :minify, true)
      facets = Keyword.get(opts, :facets)

      url = "#{@api_base}/shodan/host/search?key=#{state.api_key}&query=#{URI.encode(query)}&page=#{page}"
      url = if minify, do: "#{url}&minify=true", else: url
      url = if facets, do: "#{url}&facets=#{facets}", else: url

      case execute_get_request(url, state) do
        {:ok, data, state} ->
          result = parse_search_response(data)
          {{:ok, result}, state}

        {:error, reason, state} ->
          {{:error, reason}, state}
      end
    else
      {{:error, :no_api_key}, state}
    end
  end

  defp do_count(query, opts, state) do
    if state.api_key do
      state = wait_for_rate_limit(state)

      facets = Keyword.get(opts, :facets)

      url = "#{@api_base}/shodan/host/count?key=#{state.api_key}&query=#{URI.encode(query)}"
      url = if facets, do: "#{url}&facets=#{facets}", else: url

      case execute_get_request(url, state) do
        {:ok, data, state} ->
          result = %{
            total: Map.get(data, "total", 0),
            facets: Map.get(data, "facets", %{})
          }
          {{:ok, result}, state}

        {:error, reason, state} ->
          {{:error, reason}, state}
      end
    else
      {{:error, :no_api_key}, state}
    end
  end

  defp do_dns_resolve(hostnames, state) do
    if state.api_key do
      state = wait_for_rate_limit(state)

      hostnames_param = Enum.join(hostnames, ",")
      url = "#{@api_base}/dns/resolve?key=#{state.api_key}&hostnames=#{URI.encode(hostnames_param)}"

      case execute_get_request(url, state) do
        {:ok, data, state} -> {{:ok, data}, state}
        {:error, reason, state} -> {{:error, reason}, state}
      end
    else
      {{:error, :no_api_key}, state}
    end
  end

  defp do_dns_reverse(ips, state) do
    if state.api_key do
      state = wait_for_rate_limit(state)

      ips_param = Enum.join(ips, ",")
      url = "#{@api_base}/dns/reverse?key=#{state.api_key}&ips=#{ips_param}"

      case execute_get_request(url, state) do
        {:ok, data, state} -> {{:ok, data}, state}
        {:error, reason, state} -> {{:error, reason}, state}
      end
    else
      {{:error, :no_api_key}, state}
    end
  end

  defp do_api_info(state) do
    if state.api_key do
      url = "#{@api_base}/api-info?key=#{state.api_key}"

      case execute_get_request(url, state) do
        {:ok, data, state} ->
          result = %{
            query_credits: Map.get(data, "query_credits"),
            scan_credits: Map.get(data, "scan_credits"),
            telnet: Map.get(data, "telnet"),
            https: Map.get(data, "https"),
            unlocked: Map.get(data, "unlocked"),
            unlocked_left: Map.get(data, "unlocked_left"),
            plan: Map.get(data, "plan"),
            usage_limits: Map.get(data, "usage_limits", %{})
          }

          # Update cached API credits
          state = %{state | api_credits: result}

          {{:ok, result}, state}

        {:error, reason, state} ->
          {{:error, reason}, state}
      end
    else
      {{:error, :no_api_key}, state}
    end
  end

  defp do_ports(state) do
    if state.api_key do
      state = wait_for_rate_limit(state)
      url = "#{@api_base}/shodan/ports?key=#{state.api_key}"

      case execute_get_request(url, state) do
        {:ok, data, state} when is_list(data) -> {{:ok, data}, state}
        {:ok, _, state} -> {{:ok, []}, state}
        {:error, reason, state} -> {{:error, reason}, state}
      end
    else
      {{:error, :no_api_key}, state}
    end
  end

  defp do_protocols(state) do
    if state.api_key do
      state = wait_for_rate_limit(state)
      url = "#{@api_base}/shodan/protocols?key=#{state.api_key}"

      case execute_get_request(url, state) do
        {:ok, data, state} when is_map(data) -> {{:ok, data}, state}
        {:ok, _, state} -> {{:ok, %{}}, state}
        {:error, reason, state} -> {{:error, reason}, state}
      end
    else
      {{:error, :no_api_key}, state}
    end
  end

  defp execute_get_request(url, state) do
    state = update_stats(state, :api_call)
    state = %{state | last_request: System.monotonic_time(:millisecond)}

    case Finch.build(:get, url) |> Finch.request(TamanduaServer.Finch, receive_timeout: @recv_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, data} -> {:ok, data, state}
          {:error, _} -> {:error, :json_parse_error, update_stats(state, :error)}
        end

      {:ok, %Finch.Response{status: 404}} ->
        {:error, :not_found, state}

      {:ok, %Finch.Response{status: 401}} ->
        Logger.warning("[Shodan] Invalid API key")
        {:error, :invalid_api_key, update_stats(state, :error)}

      {:ok, %Finch.Response{status: 403}} ->
        Logger.warning("[Shodan] Access denied - check API plan")
        {:error, :forbidden, update_stats(state, :error)}

      {:ok, %Finch.Response{status: 429}} ->
        Logger.warning("[Shodan] Rate limit exceeded")
        {:error, :rate_limited, update_stats(state, :rate_limited)}

      {:ok, %Finch.Response{status: status, body: body}} ->
        Logger.warning("[Shodan] HTTP #{status}: #{body}")
        {:error, {:http_error, status}, update_stats(state, :error)}

      {:error, reason} ->
        Logger.error("[Shodan] HTTP error: #{inspect(reason)}")
        {:error, reason, update_stats(state, :error)}
    end
  end

  # ============================================================================
  # Private Functions - Response Parsers
  # ============================================================================

  defp parse_host_response(data) do
    services = Map.get(data, "data", []) |> Enum.map(&parse_service/1)

    %{
      found: true,
      ip: Map.get(data, "ip"),
      ip_str: Map.get(data, "ip_str"),
      org: Map.get(data, "org"),
      isp: Map.get(data, "isp"),
      asn: Map.get(data, "asn"),
      hostnames: Map.get(data, "hostnames", []),
      domains: Map.get(data, "domains", []),
      country_code: Map.get(data, "country_code"),
      country_name: Map.get(data, "country_name"),
      city: Map.get(data, "city"),
      region_code: Map.get(data, "region_code"),
      postal_code: Map.get(data, "postal_code"),
      latitude: Map.get(data, "latitude"),
      longitude: Map.get(data, "longitude"),
      ports: Map.get(data, "ports", []),
      vulns: Map.get(data, "vulns") |> parse_vulns(),
      tags: Map.get(data, "tags", []),
      os: Map.get(data, "os"),
      last_update: parse_timestamp(Map.get(data, "last_update")),
      services: services,
      source: "shodan"
    }
  end

  defp parse_service(service) do
    %{
      port: Map.get(service, "port"),
      transport: Map.get(service, "transport"),
      protocol: Map.get(service, "protocol"),
      product: Map.get(service, "product"),
      version: Map.get(service, "version"),
      cpe: Map.get(service, "cpe", []),
      banner: Map.get(service, "banner") |> truncate_banner(),
      timestamp: parse_timestamp(Map.get(service, "timestamp")),
      ssl: parse_ssl(Map.get(service, "ssl")),
      http: parse_http(Map.get(service, "http")),
      vulns: Map.get(service, "vulns") |> parse_vulns(),
      devicetype: Map.get(service, "devicetype"),
      info: Map.get(service, "info"),
      tags: Map.get(service, "tags", [])
    }
  end

  defp parse_vulns(nil), do: []
  defp parse_vulns(vulns) when is_list(vulns), do: vulns
  defp parse_vulns(vulns) when is_map(vulns) do
    Enum.map(vulns, fn {cve, info} ->
      %{
        cve: cve,
        cvss: Map.get(info, "cvss"),
        summary: Map.get(info, "summary"),
        references: Map.get(info, "references", []),
        verified: Map.get(info, "verified", false)
      }
    end)
  end

  defp parse_ssl(nil), do: nil
  defp parse_ssl(ssl) do
    cert = Map.get(ssl, "cert", %{})
    %{
      versions: Map.get(ssl, "versions", []),
      cipher: Map.get(ssl, "cipher", %{}),
      cert: %{
        issuer: Map.get(cert, "issuer", %{}),
        subject: Map.get(cert, "subject", %{}),
        serial: Map.get(cert, "serial"),
        sig_alg: Map.get(cert, "sig_alg"),
        expires: Map.get(cert, "expires"),
        issued: Map.get(cert, "issued"),
        fingerprint: Map.get(cert, "fingerprint", %{})
      },
      ja3s: Map.get(ssl, "ja3s"),
      jarm: Map.get(ssl, "jarm")
    }
  end

  defp parse_http(nil), do: nil
  defp parse_http(http) do
    %{
      host: Map.get(http, "host"),
      title: Map.get(http, "title"),
      server: Map.get(http, "server"),
      status: Map.get(http, "status"),
      location: Map.get(http, "location"),
      robots: Map.get(http, "robots"),
      robots_hash: Map.get(http, "robots_hash"),
      favicon: Map.get(http, "favicon", %{}),
      sitemap: Map.get(http, "sitemap"),
      components: Map.get(http, "components", %{}),
      waf: Map.get(http, "waf"),
      redirects: Map.get(http, "redirects", [])
    }
  end

  defp parse_search_response(data) do
    matches = Map.get(data, "matches", [])
    |> Enum.map(&parse_search_match/1)

    %{
      total: Map.get(data, "total", 0),
      matches: matches,
      facets: Map.get(data, "facets", %{})
    }
  end

  defp parse_search_match(match) do
    %{
      ip: Map.get(match, "ip"),
      ip_str: Map.get(match, "ip_str"),
      port: Map.get(match, "port"),
      transport: Map.get(match, "transport"),
      product: Map.get(match, "product"),
      version: Map.get(match, "version"),
      hostnames: Map.get(match, "hostnames", []),
      domains: Map.get(match, "domains", []),
      org: Map.get(match, "org"),
      isp: Map.get(match, "isp"),
      asn: Map.get(match, "asn"),
      country_code: Map.get(match, "location", %{}) |> Map.get("country_code"),
      city: Map.get(match, "location", %{}) |> Map.get("city"),
      os: Map.get(match, "os"),
      timestamp: parse_timestamp(Map.get(match, "timestamp")),
      vulns: Map.get(match, "vulns") |> parse_vulns(),
      tags: Map.get(match, "tags", [])
    }
  end

  defp truncate_banner(nil), do: nil
  defp truncate_banner(banner) when is_binary(banner) do
    if String.length(banner) > 500 do
      String.slice(banner, 0, 500) <> "..."
    else
      banner
    end
  end

  # ============================================================================
  # Private Functions - Caching
  # ============================================================================

  defp get_cached(type, key) do
    cache_key = {type, key}

    case :ets.lookup(@ets_table, cache_key) do
      [{^cache_key, data, inserted_at}] ->
        age = System.monotonic_time(:millisecond) - inserted_at
        if age < @cache_ttl do
          {:ok, data}
        else
          :ets.delete(@ets_table, cache_key)
          :miss
        end

      [] ->
        :miss
    end
  end

  defp cache_result(type, key, data) do
    cache_key = {type, key}
    :ets.insert(@ets_table, {cache_key, data, System.monotonic_time(:millisecond)})
  end

  # ============================================================================
  # Private Functions - Rate Limiting
  # ============================================================================

  defp wait_for_rate_limit(state) do
    now = System.monotonic_time(:millisecond)
    elapsed = now - state.last_request

    if elapsed < @rate_limit_interval and state.last_request > 0 do
      wait_time = @rate_limit_interval - elapsed
      Logger.debug("[Shodan] Rate limiting: waiting #{wait_time}ms")
      Process.sleep(wait_time)
    end

    state
  end

  # ============================================================================
  # Private Functions - Helpers
  # ============================================================================

  defp update_stats(state, type) do
    case type do
      :lookup -> update_in(state.stats.lookups, &(&1 + 1))
      :cache_hit -> update_in(state.stats.cache_hits, &(&1 + 1))
      :api_call -> update_in(state.stats.api_calls, &(&1 + 1))
      :error -> update_in(state.stats.errors, &(&1 + 1))
      :rate_limited -> update_in(state.stats.rate_limited, &(&1 + 1))
    end
  end

  defp parse_timestamp(nil), do: nil
  defp parse_timestamp(""), do: nil
  defp parse_timestamp(%DateTime{} = dt), do: dt
  defp parse_timestamp(str) when is_binary(str) do
    case DateTime.from_iso8601(str) do
      {:ok, dt, _} -> dt
      _ ->
        case NaiveDateTime.from_iso8601(str) do
          {:ok, ndt} -> DateTime.from_naive!(ndt, "Etc/UTC")
          _ -> nil
        end
    end
  end
  defp parse_timestamp(_), do: nil
end
