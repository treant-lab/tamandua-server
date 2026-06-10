defmodule TamanduaServer.ThreatIntel.Feeds.GreyNoise do
  @moduledoc """
  GreyNoise API Integration.

  GreyNoise helps classify IP addresses as internet background noise,
  legitimate scanners, or malicious actors. This reduces false positives
  by filtering out benign internet scanning activity.

  ## GreyNoise Classifications

  - **Noise**: Benign internet scanners (Shodan, Censys, research)
  - **Riot**: Known legitimate services (CDNs, cloud providers, common business IPs)
  - **Malicious**: IPs conducting malicious activity

  ## API Tiers

  - **Community (Free)**: 50 requests/day, basic IP lookups
  - **Researcher**: 5000 requests/day, full context
  - **Enterprise**: Unlimited, bulk lookups, GNQL queries

  ## Usage

      # Configure API key
      GreyNoise.configure("your-greynoise-api-key")

      # Lookup an IP
      GreyNoise.lookup_ip("1.2.3.4")

      # Bulk lookup (Enterprise only)
      GreyNoise.bulk_lookup(["1.2.3.4", "5.6.7.8"])

      # Check RIOT status (legitimate services)
      GreyNoise.riot_lookup("8.8.8.8")

      # Query with GNQL
      GreyNoise.query("last_seen:1d malicious")
  """

  use GenServer
  require Logger

  alias TamanduaServer.ThreatIntel.Aggregator

  @api_base "https://api.greynoise.io"
  @community_api "https://api.greynoise.io/v3/community"
  @http_timeout 30_000

  # Rate limiting (community tier: 50 req/day = ~2 req/hour)
  @rate_limit_interval :timer.seconds(30)
  @cache_ttl :timer.hours(24)

  @ets_table :greynoise_cache

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Configure the GreyNoise API key.
  """
  @spec configure(String.t()) :: :ok
  def configure(api_key) when is_binary(api_key) do
    GenServer.call(__MODULE__, {:configure, api_key})
  end

  @doc """
  Lookup an IP address in GreyNoise.

  Returns classification, actor information, tags, and context.

  ## Examples

      iex> lookup_ip("1.2.3.4")
      {:ok, %{
        ip: "1.2.3.4",
        seen: true,
        classification: "malicious",
        name: "unknown",
        actor: "cobalt_strike",
        tags: ["c2", "exploit"],
        first_seen: ~U[2024-01-15T10:00:00Z],
        last_seen: ~U[2024-01-20T15:30:00Z],
        metadata: %{
          asn: "AS12345",
          country: "CN",
          city: "Beijing",
          organization: "Example ISP"
        },
        raw_data: %{
          protocols: ["tcp/445", "tcp/3389"],
          web_paths: ["/admin", "/login"]
        }
      }}
  """
  @spec lookup_ip(String.t()) :: {:ok, map()} | {:error, term()}
  def lookup_ip(ip) when is_binary(ip) do
    GenServer.call(__MODULE__, {:lookup_ip, ip}, 60_000)
  end

  @doc """
  Lookup multiple IPs in bulk (Enterprise tier only).

  ## Examples

      iex> bulk_lookup(["1.2.3.4", "5.6.7.8"])
      {:ok, [
        %{ip: "1.2.3.4", classification: "malicious", ...},
        %{ip: "5.6.7.8", classification: "benign", ...}
      ]}
  """
  @spec bulk_lookup([String.t()]) :: {:ok, [map()]} | {:error, term()}
  def bulk_lookup(ips) when is_list(ips) do
    GenServer.call(__MODULE__, {:bulk_lookup, ips}, 120_000)
  end

  @doc """
  Check if an IP is in the RIOT dataset (known legitimate services).

  RIOT identifies IPs from common services that should generally be trusted:
  - CDN providers (Cloudflare, Akamai, etc.)
  - Cloud providers (AWS, GCP, Azure)
  - Common business services (Google, Microsoft, etc.)

  ## Examples

      iex> riot_lookup("8.8.8.8")
      {:ok, %{
        riot: true,
        category: "public_dns",
        name: "Google Public DNS",
        description: "Google's public DNS service",
        trust_level: "high"
      }}
  """
  @spec riot_lookup(String.t()) :: {:ok, map()} | {:error, term()}
  def riot_lookup(ip) when is_binary(ip) do
    GenServer.call(__MODULE__, {:riot_lookup, ip}, 60_000)
  end

  @doc """
  Query GreyNoise using GNQL (GreyNoise Query Language).

  Requires Enterprise tier.

  ## Query Examples

  - `"last_seen:1d malicious"` - Malicious IPs seen in last day
  - `"classification:malicious tags:exploit"` - Malicious exploit scanners
  - `"metadata.country:CN"` - IPs from China
  - `"raw_data.scan.port:3389"` - IPs scanning RDP

  ## Examples

      iex> query("last_seen:1d classification:malicious", size: 100)
      {:ok, %{
        count: 1234,
        query: "last_seen:1d classification:malicious",
        data: [%{ip: "1.2.3.4", ...}, ...]
      }}
  """
  @spec query(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def query(gnql, opts \\ []) when is_binary(gnql) do
    GenServer.call(__MODULE__, {:query, gnql, opts}, 120_000)
  end

  @doc """
  Get community API information about an IP (free tier).

  ## Examples

      iex> community_lookup("1.2.3.4")
      {:ok, %{
        ip: "1.2.3.4",
        noise: true,
        riot: false,
        classification: "malicious",
        name: "unknown",
        link: "https://viz.greynoise.io/ip/1.2.3.4",
        last_seen: "2024-01-20",
        message: "Success"
      }}
  """
  @spec community_lookup(String.t()) :: {:ok, map()} | {:error, term()}
  def community_lookup(ip) when is_binary(ip) do
    GenServer.call(__MODULE__, {:community_lookup, ip}, 60_000)
  end

  @doc """
  Sync all malicious IPs from GreyNoise and import as IOCs.

  This is called by the OSINTFeedManager for scheduled syncs.
  """
  @spec sync_all() :: :ok
  def sync_all do
    GenServer.cast(__MODULE__, :sync_all)
  end

  @doc """
  Get current status.
  """
  @spec get_status() :: map()
  def get_status do
    GenServer.call(__MODULE__, :get_status)
  end

  @doc """
  Clear the cache.
  """
  @spec clear_cache() :: :ok
  def clear_cache do
    GenServer.call(__MODULE__, :clear_cache)
  end

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  @impl true
  def init(opts) do
    # Create ETS cache
    :ets.new(@ets_table, [:named_table, :set, :public, read_concurrency: true])

    api_key = Keyword.get(opts, :api_key) ||
              System.get_env("GREYNOISE_API_KEY")

    state = %{
      api_key: api_key,
      tier: determine_tier(api_key),
      last_request: 0,
      stats: %{
        lookups: 0,
        cache_hits: 0,
        api_calls: 0,
        errors: 0,
        rate_limited: 0
      }
    }

    Logger.info("[GreyNoise] Initialized (tier: #{state.tier})")

    {:ok, state}
  end

  @impl true
  def handle_call({:configure, api_key}, _from, state) do
    tier = determine_tier(api_key)
    Logger.info("[GreyNoise] API key configured (tier: #{tier})")
    {:reply, :ok, %{state | api_key: api_key, tier: tier}}
  end

  @impl true
  def handle_call({:lookup_ip, ip}, _from, state) do
    state = update_stats(state, :lookup)

    case get_cached(ip) do
      {:ok, cached} ->
        state = update_stats(state, :cache_hit)
        {:reply, {:ok, cached}, state}

      :miss ->
        {result, state} = do_lookup_ip(ip, state)
        {:reply, result, state}
    end
  end

  @impl true
  def handle_call({:bulk_lookup, ips}, _from, state) do
    if state.tier == :enterprise do
      {result, state} = do_bulk_lookup(ips, state)
      {:reply, result, state}
    else
      {:reply, {:error, :enterprise_only}, state}
    end
  end

  @impl true
  def handle_call({:riot_lookup, ip}, _from, state) do
    {result, state} = do_riot_lookup(ip, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:query, gnql, opts}, _from, state) do
    if state.tier in [:researcher, :enterprise] do
      {result, state} = do_query(gnql, opts, state)
      {:reply, result, state}
    else
      {:reply, {:error, :paid_tier_required}, state}
    end
  end

  @impl true
  def handle_call({:community_lookup, ip}, _from, state) do
    {result, state} = do_community_lookup(ip, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:get_status, _from, state) do
    status = %{
      configured: state.api_key != nil,
      tier: state.tier,
      cache_size: :ets.info(@ets_table, :size),
      stats: state.stats
    }
    {:reply, status, state}
  end

  @impl true
  def handle_call(:clear_cache, _from, state) do
    :ets.delete_all_objects(@ets_table)
    Logger.info("[GreyNoise] Cache cleared")
    {:reply, :ok, state}
  end

  @impl true
  def handle_cast(:sync_all, state) do
    Task.start(fn -> do_sync(state) end)
    {:noreply, state}
  end

  # ============================================================================
  # Private Functions - API Calls
  # ============================================================================

  defp do_lookup_ip(ip, state) do
    if state.api_key do
      state = wait_for_rate_limit(state)

      url = "#{@api_base}/v2/noise/context/#{ip}"

      case execute_get_request(url, state) do
        {:ok, data, state} ->
          result = parse_context_response(data)
          cache_result(ip, result)
          {{:ok, result}, state}

        {:error, :not_found, state} ->
          result = %{ip: ip, seen: false, noise: false}
          cache_result(ip, result)
          {{:ok, result}, state}

        {:error, reason, state} ->
          {{:error, reason}, state}
      end
    else
      {{:error, :no_api_key}, state}
    end
  end

  defp do_bulk_lookup(ips, state) do
    if state.api_key do
      state = wait_for_rate_limit(state)

      url = "#{@api_base}/v2/noise/multi/quick"
      body = Jason.encode!(%{ips: ips})

      case execute_post_request(url, body, state) do
        {:ok, data, state} ->
          results = Enum.map(data, &parse_quick_response/1)
          {{:ok, results}, state}

        {:error, reason, state} ->
          {{:error, reason}, state}
      end
    else
      {{:error, :no_api_key}, state}
    end
  end

  defp do_riot_lookup(ip, state) do
    if state.api_key do
      state = wait_for_rate_limit(state)

      url = "#{@api_base}/v2/riot/#{ip}"

      case execute_get_request(url, state) do
        {:ok, data, state} ->
          result = parse_riot_response(data)
          {{:ok, result}, state}

        {:error, :not_found, state} ->
          {{:ok, %{ip: ip, riot: false}}, state}

        {:error, reason, state} ->
          {{:error, reason}, state}
      end
    else
      {{:error, :no_api_key}, state}
    end
  end

  defp do_query(gnql, opts, state) do
    if state.api_key do
      state = wait_for_rate_limit(state)

      size = Keyword.get(opts, :size, 100)
      scroll = Keyword.get(opts, :scroll)

      url = "#{@api_base}/v2/experimental/gnql"
      body = Jason.encode!(%{query: gnql, size: size, scroll: scroll})

      case execute_post_request(url, body, state) do
        {:ok, data, state} ->
          result = %{
            count: Map.get(data, "count", 0),
            query: gnql,
            data: Map.get(data, "data", []) |> Enum.map(&parse_context_response/1),
            scroll: Map.get(data, "scroll")
          }
          {{:ok, result}, state}

        {:error, reason, state} ->
          {{:error, reason}, state}
      end
    else
      {{:error, :no_api_key}, state}
    end
  end

  defp do_community_lookup(ip, state) do
    # Community API doesn't require API key
    url = "#{@community_api}/#{ip}"

    case execute_get_request_community(url) do
      {:ok, data} ->
        result = parse_community_response(data)
        cache_result(ip, result)
        {{:ok, result}, update_stats(state, :api_call)}

      {:error, :not_found} ->
        result = %{ip: ip, noise: false, riot: false}
        {{:ok, result}, state}

      {:error, reason} ->
        {{:error, reason}, update_stats(state, :error)}
    end
  end

  defp do_sync(state) do
    Logger.info("[GreyNoise] Starting sync...")

    if state.tier in [:researcher, :enterprise] do
      # Query for recent malicious IPs
      case do_query("last_seen:7d classification:malicious", [size: 1000], state) do
        {{:ok, results}, _state} ->
          iocs = Enum.map(results.data, fn entry ->
            %{
              type: "ip",
              value: entry.ip,
              source: "greynoise",
              severity: classify_severity(entry),
              confidence: 0.8,
              tags: ["noise", entry.classification | (entry.tags || [])] |> Enum.reject(&is_nil/1),
              metadata: %{
                "actor" => entry.actor,
                "tags" => entry.tags,
                "first_seen" => entry.first_seen,
                "last_seen" => entry.last_seen,
                "asn" => get_in(entry, [:metadata, :asn]),
                "country" => get_in(entry, [:metadata, :country]),
                "provider" => "greynoise"
              }
            }
          end)

          Aggregator.ingest_batch("greynoise", iocs)
          Logger.info("[GreyNoise] Imported #{length(iocs)} malicious IPs")

        {{:error, reason}, _state} ->
          Logger.error("[GreyNoise] Sync failed: #{inspect(reason)}")
      end
    else
      Logger.warning("[GreyNoise] Sync requires Researcher or Enterprise tier")
    end
  end

  defp execute_get_request(url, state) do
    headers = [
      {"key", state.api_key},
      {"Accept", "application/json"}
    ]

    state = update_stats(state, :api_call)
    state = %{state | last_request: System.monotonic_time(:millisecond)}

    case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, data} -> {:ok, data, state}
          {:error, _} -> {:error, :json_parse_error, update_stats(state, :error)}
        end

      {:ok, %Finch.Response{status: 404}} ->
        {:error, :not_found, state}

      {:ok, %Finch.Response{status: 401}} ->
        Logger.warning("[GreyNoise] Invalid API key")
        {:error, :invalid_api_key, update_stats(state, :error)}

      {:ok, %Finch.Response{status: 429}} ->
        Logger.warning("[GreyNoise] Rate limit exceeded")
        {:error, :rate_limited, update_stats(state, :rate_limited)}

      {:ok, %Finch.Response{status: status}} ->
        Logger.warning("[GreyNoise] HTTP #{status}")
        {:error, {:http_error, status}, update_stats(state, :error)}

      {:error, reason} ->
        Logger.error("[GreyNoise] HTTP error: #{inspect(reason)}")
        {:error, reason, update_stats(state, :error)}
    end
  end

  defp execute_post_request(url, body, state) do
    headers = [
      {"key", state.api_key},
      {"Content-Type", "application/json"},
      {"Accept", "application/json"}
    ]

    state = update_stats(state, :api_call)
    state = %{state | last_request: System.monotonic_time(:millisecond)}

    case Finch.build(:post, url, headers, body) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
      {:ok, %Finch.Response{status: 200, body: response_body}} ->
        case Jason.decode(response_body) do
          {:ok, data} -> {:ok, data, state}
          {:error, _} -> {:error, :json_parse_error, update_stats(state, :error)}
        end

      {:ok, %Finch.Response{status: 429}} ->
        {:error, :rate_limited, update_stats(state, :rate_limited)}

      {:ok, %Finch.Response{status: status}} ->
        {:error, {:http_error, status}, update_stats(state, :error)}

      {:error, reason} ->
        {:error, reason, update_stats(state, :error)}
    end
  end

  defp execute_get_request_community(url) do
    case Finch.build(:get, url) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, data} -> {:ok, data}
          {:error, _} -> {:error, :json_parse_error}
        end

      {:ok, %Finch.Response{status: 404}} ->
        {:error, :not_found}

      {:ok, %Finch.Response{status: status}} ->
        {:error, {:http_error, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # ============================================================================
  # Private Functions - Response Parsers
  # ============================================================================

  defp parse_context_response(data) do
    %{
      ip: Map.get(data, "ip"),
      seen: Map.get(data, "seen", false),
      noise: Map.get(data, "seen", false),
      classification: Map.get(data, "classification"),
      name: Map.get(data, "name"),
      actor: Map.get(data, "actor"),
      tags: Map.get(data, "tags", []),
      first_seen: parse_timestamp(Map.get(data, "first_seen")),
      last_seen: parse_timestamp(Map.get(data, "last_seen")),
      metadata: parse_metadata(Map.get(data, "metadata")),
      raw_data: parse_raw_data(Map.get(data, "raw_data")),
      bot: Map.get(data, "bot", false),
      vpn: Map.get(data, "vpn", false),
      vpn_service: Map.get(data, "vpn_service"),
      source: "greynoise"
    }
  end

  defp parse_quick_response(data) do
    %{
      ip: Map.get(data, "ip"),
      noise: Map.get(data, "noise", false),
      riot: Map.get(data, "riot", false),
      code: Map.get(data, "code"),
      code_message: Map.get(data, "code_message")
    }
  end

  defp parse_riot_response(data) do
    %{
      ip: Map.get(data, "ip"),
      riot: Map.get(data, "riot", false),
      category: Map.get(data, "category"),
      name: Map.get(data, "name"),
      description: Map.get(data, "description"),
      explanation: Map.get(data, "explanation"),
      last_updated: parse_timestamp(Map.get(data, "last_updated")),
      logo_url: Map.get(data, "logo_url"),
      reference: Map.get(data, "reference"),
      trust_level: Map.get(data, "trust_level")
    }
  end

  defp parse_community_response(data) do
    %{
      ip: Map.get(data, "ip"),
      noise: Map.get(data, "noise", false),
      riot: Map.get(data, "riot", false),
      classification: Map.get(data, "classification"),
      name: Map.get(data, "name"),
      link: Map.get(data, "link"),
      last_seen: Map.get(data, "last_seen"),
      message: Map.get(data, "message"),
      source: "greynoise_community"
    }
  end

  defp parse_metadata(nil), do: nil
  defp parse_metadata(metadata) do
    %{
      asn: Map.get(metadata, "asn"),
      category: Map.get(metadata, "category"),
      city: Map.get(metadata, "city"),
      country: Map.get(metadata, "country"),
      country_code: Map.get(metadata, "country_code"),
      organization: Map.get(metadata, "organization"),
      rdns: Map.get(metadata, "rdns"),
      region: Map.get(metadata, "region"),
      tor: Map.get(metadata, "tor", false)
    }
  end

  defp parse_raw_data(nil), do: nil
  defp parse_raw_data(raw_data) do
    %{
      scan: Map.get(raw_data, "scan", []),
      web: Map.get(raw_data, "web", %{}),
      ja3: Map.get(raw_data, "ja3", []),
      hassh: Map.get(raw_data, "hassh", [])
    }
  end

  defp classify_severity(entry) do
    cond do
      entry.classification == "malicious" and entry.actor in ["cobalt_strike", "emotet", "trickbot"] -> "critical"
      entry.classification == "malicious" -> "high"
      entry.classification == "unknown" -> "medium"
      true -> "low"
    end
  end

  # ============================================================================
  # Private Functions - Caching & Helpers
  # ============================================================================

  defp get_cached(ip) do
    cache_key = {:ip, ip}

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

  defp cache_result(ip, data) do
    cache_key = {:ip, ip}
    :ets.insert(@ets_table, {cache_key, data, System.monotonic_time(:millisecond)})
  end

  defp wait_for_rate_limit(state) do
    now = System.monotonic_time(:millisecond)
    elapsed = now - state.last_request

    if elapsed < @rate_limit_interval and state.last_request > 0 do
      wait_time = @rate_limit_interval - elapsed
      Logger.debug("[GreyNoise] Rate limiting: waiting #{wait_time}ms")
      Process.sleep(wait_time)
    end

    state
  end

  defp update_stats(state, type) do
    case type do
      :lookup -> update_in(state.stats.lookups, &(&1 + 1))
      :cache_hit -> update_in(state.stats.cache_hits, &(&1 + 1))
      :api_call -> update_in(state.stats.api_calls, &(&1 + 1))
      :error -> update_in(state.stats.errors, &(&1 + 1))
      :rate_limited -> update_in(state.stats.rate_limited, &(&1 + 1))
    end
  end

  defp determine_tier(nil), do: :community
  defp determine_tier(""), do: :community
  defp determine_tier(_api_key) do
    # In production, you'd verify the tier by calling the API
    # For now, assume paid tier if API key is provided
    :researcher
  end

  defp parse_timestamp(nil), do: nil
  defp parse_timestamp(""), do: nil
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
