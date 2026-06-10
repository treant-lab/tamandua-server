defmodule TamanduaServer.ThreatIntel.AbuseCh do
  @moduledoc """
  Integration with Abuse.ch threat intelligence feeds.

  Feeds:
  - URLhaus: Malware distribution URLs
  - ThreatFox: IOCs (hashes, domains, IPs)
  - Feodo Tracker: Botnet C2 infrastructure
  - MalwareBazaar: Known malware samples

  ## Architecture

  This module provides a GenServer that periodically syncs threat intelligence
  from Abuse.ch feeds and stores them in ETS tables for fast lookups.

  ```
  [URLhaus Feed] ─────┐
  [ThreatFox Feed] ───┤
  [Feodo Tracker] ────┼──► [AbuseCh GenServer] ──► [ETS Tables]
  [MalwareBazaar] ────┘            │                    │
                                   │                    ▼
                              [Aggregator] <──── [Fast Lookups]
  ```

  ## Feed Details

  - **URLhaus**: Malicious URLs used for malware distribution
    - Updated every 5 minutes upstream
    - Provides URL, host, threat type, payloads

  - **ThreatFox**: IOC sharing platform
    - IP:port, domains, URLs, hashes
    - Filtered for stealers, crypto malware, RATs

  - **Feodo Tracker**: Banking trojan C2 servers
    - Dridex, Emotet, TrickBot, QakBot, BazarLoader
    - Provides IP, port, malware family, status

  - **MalwareBazaar**: Malware sample database
    - SHA256 hashes with signatures and metadata
    - Tagged with malware families

  ## Usage

      # Start the GenServer (usually via supervisor)
      AbuseCh.start_link()

      # Manual sync
      AbuseCh.sync_all()
      AbuseCh.sync_urlhaus()
      AbuseCh.sync_threatfox()
      AbuseCh.sync_feodo()

      # Fast lookups (O(1) via ETS)
      AbuseCh.check_url("http://evil.com/malware.exe")
      AbuseCh.check_hash("abc123...")
      AbuseCh.check_domain("evil.com")
      AbuseCh.check_ip("1.2.3.4")

      # Get status
      AbuseCh.get_status()
      AbuseCh.get_stats()
  """

  use GenServer
  require Logger

  alias TamanduaServer.ThreatIntel.Aggregator

  # ============================================================================
  # Configuration
  # ============================================================================

  @default_sync_interval :timer.hours(4)
  @http_timeout 120_000
  @rate_limit_delay :timer.seconds(2)

  # Feed URLs
  @urlhaus_json_url "https://urlhaus-api.abuse.ch/v1/urls/recent/"
  @threatfox_api_url "https://threatfox-api.abuse.ch/api/v1/"
  @feodo_json_url "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
  @malwarebazaar_api_url "https://mb-api.abuse.ch/api/v1/"

  # ETS table names
  @ets_urlhaus :abuse_ch_urlhaus
  @ets_threatfox :abuse_ch_threatfox
  @ets_feodo :abuse_ch_feodo
  @ets_malwarebazaar :abuse_ch_malwarebazaar
  @ets_domains :abuse_ch_domains
  @ets_ips :abuse_ch_ips
  @ets_hashes :abuse_ch_hashes

  # ThreatFox IOC type filters (focus on stealers, crypto malware, RATs)
  @threatfox_malware_filters [
    "AgentTesla",
    "AsyncRAT",
    "Azorult",
    "BazarLoader",
    "BitRAT",
    "Cobalt Strike",
    "CryptBot",
    "DarkComet",
    "Emotet",
    "FormBook",
    "IcedID",
    "Lokibot",
    "Lumma",
    "NanoCore",
    "NetWire",
    "njRAT",
    "Orcus",
    "QakBot",
    "Raccoon",
    "RedLine",
    "Remcos",
    "SmokeLoader",
    "TrickBot",
    "Vidar"
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Sync all Abuse.ch feeds.
  """
  @spec sync_all() :: :ok
  def sync_all do
    GenServer.cast(__MODULE__, :sync_all)
  end

  @doc """
  Sync URLhaus feed - malicious URLs.
  """
  @spec sync_urlhaus() :: {:ok, map()} | {:error, term()}
  def sync_urlhaus do
    GenServer.call(__MODULE__, :sync_urlhaus, @http_timeout * 2)
  end

  @doc """
  Sync ThreatFox feed - IOCs filtered for stealers/crypto malware.
  """
  @spec sync_threatfox() :: {:ok, map()} | {:error, term()}
  def sync_threatfox do
    GenServer.call(__MODULE__, :sync_threatfox, @http_timeout * 2)
  end

  @doc """
  Sync Feodo Tracker feed - botnet C2 IPs.
  """
  @spec sync_feodo() :: {:ok, map()} | {:error, term()}
  def sync_feodo do
    GenServer.call(__MODULE__, :sync_feodo, @http_timeout * 2)
  end

  @doc """
  Sync MalwareBazaar recent samples.
  """
  @spec sync_malwarebazaar() :: {:ok, map()} | {:error, term()}
  def sync_malwarebazaar do
    GenServer.call(__MODULE__, :sync_malwarebazaar, @http_timeout * 2)
  end

  @doc """
  Check if a URL is in URLhaus database.

  Returns match info if found, :not_found otherwise.

  ## Examples

      iex> check_url("http://evil.com/payload.exe")
      {:ok, %{url: "http://evil.com/payload.exe", threat: "malware_download", ...}}

      iex> check_url("http://safe.com")
      :not_found
  """
  @spec check_url(String.t()) :: {:ok, map()} | :not_found
  def check_url(url) when is_binary(url) do
    normalized = normalize_url(url)

    case :ets.lookup(@ets_urlhaus, normalized) do
      [{^normalized, data}] -> {:ok, data}
      [] -> :not_found
    end
  end

  @doc """
  Check if a SHA256 hash is in MalwareBazaar/ThreatFox database.

  ## Examples

      iex> check_hash("abc123...")
      {:ok, %{sha256: "abc123...", signature: "Emotet", source: "malwarebazaar", ...}}

      iex> check_hash("notfound")
      :not_found
  """
  @spec check_hash(String.t()) :: {:ok, map()} | :not_found
  def check_hash(hash) when is_binary(hash) do
    normalized = String.downcase(hash)

    case :ets.lookup(@ets_hashes, normalized) do
      [{^normalized, data}] -> {:ok, data}
      [] -> :not_found
    end
  end

  @doc """
  Check if a domain is in ThreatFox/URLhaus database.

  ## Examples

      iex> check_domain("evil.com")
      {:ok, %{domain: "evil.com", malware: "Emotet", source: "threatfox", ...}}

      iex> check_domain("safe.com")
      :not_found
  """
  @spec check_domain(String.t()) :: {:ok, map()} | :not_found
  def check_domain(domain) when is_binary(domain) do
    normalized = String.downcase(domain)

    case :ets.lookup(@ets_domains, normalized) do
      [{^normalized, data}] -> {:ok, data}
      [] -> :not_found
    end
  end

  @doc """
  Check if an IP is in Feodo Tracker/ThreatFox database.

  ## Examples

      iex> check_ip("1.2.3.4")
      {:ok, %{ip: "1.2.3.4", malware: "QakBot", port: 443, source: "feodo", ...}}

      iex> check_ip("8.8.8.8")
      :not_found
  """
  @spec check_ip(String.t()) :: {:ok, map()} | :not_found
  def check_ip(ip) when is_binary(ip) do
    # Also check for IP:port format
    base_ip = ip |> String.split(":") |> List.first()

    case :ets.lookup(@ets_ips, base_ip) do
      [{^base_ip, data}] -> {:ok, data}
      [] -> :not_found
    end
  end

  @doc """
  Batch check multiple indicators.

  Returns a map of {indicator => result}.

  ## Examples

      iex> batch_check([
      ...>   {:url, "http://evil.com/payload.exe"},
      ...>   {:hash, "abc123..."},
      ...>   {:ip, "1.2.3.4"}
      ...> ])
      %{
        "http://evil.com/payload.exe" => {:ok, %{...}},
        "abc123..." => :not_found,
        "1.2.3.4" => {:ok, %{...}}
      }
  """
  @spec batch_check([{:url | :hash | :domain | :ip, String.t()}]) :: map()
  def batch_check(indicators) when is_list(indicators) do
    Enum.reduce(indicators, %{}, fn {type, value}, acc ->
      result = case type do
        :url -> check_url(value)
        :hash -> check_hash(value)
        :domain -> check_domain(value)
        :ip -> check_ip(value)
        _ -> :not_found
      end

      Map.put(acc, value, result)
    end)
  end

  @doc """
  Get current status of the Abuse.ch integration.
  """
  @spec get_status() :: map()
  def get_status do
    GenServer.call(__MODULE__, :get_status)
  end

  @doc """
  Get detailed statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    %{
      urlhaus_count: safe_ets_size(@ets_urlhaus),
      threatfox_count: safe_ets_size(@ets_threatfox),
      feodo_count: safe_ets_size(@ets_feodo),
      malwarebazaar_count: safe_ets_size(@ets_malwarebazaar),
      domains_count: safe_ets_size(@ets_domains),
      ips_count: safe_ets_size(@ets_ips),
      hashes_count: safe_ets_size(@ets_hashes),
      total_iocs: safe_ets_size(@ets_urlhaus) + safe_ets_size(@ets_domains) +
                  safe_ets_size(@ets_ips) + safe_ets_size(@ets_hashes)
    }
  end

  @doc """
  Get all URLs matching a threat type.
  """
  @spec get_urls_by_threat(String.t()) :: [map()]
  def get_urls_by_threat(threat_type) when is_binary(threat_type) do
    :ets.foldl(fn {_key, data}, acc ->
      if data[:threat] == threat_type do
        [data | acc]
      else
        acc
      end
    end, [], @ets_urlhaus)
  end

  @doc """
  Get all IPs for a specific malware family.
  """
  @spec get_ips_by_malware(String.t()) :: [map()]
  def get_ips_by_malware(malware) when is_binary(malware) do
    malware_lower = String.downcase(malware)

    :ets.foldl(fn {_key, data}, acc ->
      if data[:malware] && String.downcase(data[:malware]) == malware_lower do
        [data | acc]
      else
        acc
      end
    end, [], @ets_ips)
  end

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  @impl true
  def init(opts) do
    # Create ETS tables
    create_ets_tables()

    state = %{
      enabled: Keyword.get(opts, :enabled, true),
      sync_interval: Keyword.get(opts, :sync_interval, @default_sync_interval),
      last_sync: nil,
      feed_status: %{
        urlhaus: %{status: :pending, last_sync: nil, count: 0, error: nil},
        threatfox: %{status: :pending, last_sync: nil, count: 0, error: nil},
        feodo: %{status: :pending, last_sync: nil, count: 0, error: nil},
        malwarebazaar: %{status: :pending, last_sync: nil, count: 0, error: nil}
      },
      stats: %{
        total_syncs: 0,
        successful_syncs: 0,
        failed_syncs: 0,
        total_iocs_imported: 0,
        by_feed: %{}
      }
    }

    if state.enabled do
      # Schedule initial sync with a small delay
      Process.send_after(self(), :initial_sync, :timer.seconds(30))
      schedule_sync(state.sync_interval)
      Logger.info("[AbuseCh] Initialized, scheduling sync every #{div(state.sync_interval, :timer.hours(1))} hours")
    end

    {:ok, state}
  end

  @impl true
  def handle_call(:sync_urlhaus, _from, state) do
    {result, new_state} = do_sync_urlhaus(state)
    {:reply, result, new_state}
  end

  @impl true
  def handle_call(:sync_threatfox, _from, state) do
    {result, new_state} = do_sync_threatfox(state)
    {:reply, result, new_state}
  end

  @impl true
  def handle_call(:sync_feodo, _from, state) do
    {result, new_state} = do_sync_feodo(state)
    {:reply, result, new_state}
  end

  @impl true
  def handle_call(:sync_malwarebazaar, _from, state) do
    {result, new_state} = do_sync_malwarebazaar(state)
    {:reply, result, new_state}
  end

  @impl true
  def handle_call(:get_status, _from, state) do
    status = %{
      enabled: state.enabled,
      last_sync: state.last_sync,
      next_sync: if(state.last_sync, do: DateTime.add(state.last_sync, state.sync_interval, :millisecond)),
      sync_interval_hours: div(state.sync_interval, :timer.hours(1)),
      feed_status: state.feed_status,
      stats: Map.merge(state.stats, get_stats())
    }

    {:reply, status, state}
  end

  @impl true
  def handle_cast(:sync_all, state) do
    Task.start(fn -> do_sync_all() end)
    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:initial_sync, state) do
    Logger.info("[AbuseCh] Starting initial sync...")
    Task.start(fn -> do_sync_all() end)
    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:periodic_sync, state) do
    Logger.info("[AbuseCh] Starting periodic sync...")
    Task.start(fn -> do_sync_all() end)
    schedule_sync(state.sync_interval)
    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info({:sync_result, feed, result}, state) do
    new_state = update_feed_status(state, feed, result)
    {:noreply, new_state}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private - ETS Management
  # ============================================================================

  defp create_ets_tables do
    tables = [
      @ets_urlhaus,
      @ets_threatfox,
      @ets_feodo,
      @ets_malwarebazaar,
      @ets_domains,
      @ets_ips,
      @ets_hashes
    ]

    Enum.each(tables, fn table ->
      if :ets.whereis(table) == :undefined do
        :ets.new(table, [:named_table, :set, :public, read_concurrency: true])
      end
    end)
  end

  defp safe_ets_size(table) do
    case :ets.whereis(table) do
      :undefined -> 0
      _tid -> :ets.info(table, :size)
    end
  end

  # ============================================================================
  # Private - Sync Functions
  # ============================================================================

  defp do_sync_all do
    Logger.info("[AbuseCh] Starting full sync of all feeds...")

    # Sync each feed with rate limiting
    results = [
      {:urlhaus, sync_urlhaus_internal()},
      {:threatfox, with_rate_limit(fn -> sync_threatfox_internal() end)},
      {:feodo, with_rate_limit(fn -> sync_feodo_internal() end)},
      {:malwarebazaar, with_rate_limit(fn -> sync_malwarebazaar_internal() end)}
    ]

    # Log summary
    total_iocs = Enum.reduce(results, 0, fn {_feed, result}, acc ->
      case result do
        {:ok, %{count: count}} -> acc + count
        _ -> acc
      end
    end)

    Logger.info("[AbuseCh] Sync complete. Total IOCs: #{total_iocs}")
  end

  defp with_rate_limit(fun) do
    Process.sleep(@rate_limit_delay)
    fun.()
  end

  defp do_sync_urlhaus(state) do
    result = sync_urlhaus_internal()
    new_state = update_feed_status(state, :urlhaus, result)
    {result, new_state}
  end

  defp do_sync_threatfox(state) do
    result = sync_threatfox_internal()
    new_state = update_feed_status(state, :threatfox, result)
    {result, new_state}
  end

  defp do_sync_feodo(state) do
    result = sync_feodo_internal()
    new_state = update_feed_status(state, :feodo, result)
    {result, new_state}
  end

  defp do_sync_malwarebazaar(state) do
    result = sync_malwarebazaar_internal()
    new_state = update_feed_status(state, :malwarebazaar, result)
    {result, new_state}
  end

  # ============================================================================
  # Private - URLhaus Sync
  # ============================================================================

  defp sync_urlhaus_internal do
    Logger.debug("[AbuseCh] Syncing URLhaus feed...")

    case http_get(@urlhaus_json_url) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, %{"urls" => urls}} when is_list(urls) ->
            count = process_urlhaus_urls(urls)
            Logger.info("[AbuseCh] URLhaus: imported #{count} URLs")
            {:ok, %{feed: :urlhaus, count: count, timestamp: DateTime.utc_now()}}

          {:ok, _} ->
            Logger.warning("[AbuseCh] URLhaus: unexpected response format")
            {:error, :unexpected_format}

          {:error, reason} ->
            Logger.error("[AbuseCh] URLhaus: JSON decode error - #{inspect(reason)}")
            {:error, {:json_error, reason}}
        end

      {:ok, %Finch.Response{status: status}} ->
        Logger.warning("[AbuseCh] URLhaus: HTTP #{status}")
        {:error, {:http_error, status}}

      {:error, reason} ->
        Logger.error("[AbuseCh] URLhaus: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp process_urlhaus_urls(urls) do
    iocs_for_aggregator = []

    count = Enum.reduce(urls, 0, fn url_data, acc ->
      url = url_data["url"]
      host = url_data["host"]

      if url && String.length(url) > 0 do
        normalized_url = normalize_url(url)

        data = %{
          url: url,
          host: host,
          url_status: url_data["url_status"],
          threat: url_data["threat"],
          tags: url_data["tags"] || [],
          date_added: url_data["dateadded"],
          reporter: url_data["reporter"],
          source: "urlhaus",
          severity: "high",
          confidence: 0.9,
          fetched_at: DateTime.utc_now()
        }

        # Store in URLhaus ETS
        :ets.insert(@ets_urlhaus, {normalized_url, data})

        # Also index by domain
        if host && String.length(host) > 0 do
          domain_data = %{
            domain: host,
            urls: [url],
            source: "urlhaus",
            threat: url_data["threat"],
            severity: "high",
            confidence: 0.85,
            fetched_at: DateTime.utc_now()
          }

          # Merge with existing domain data
          case :ets.lookup(@ets_domains, host) do
            [{^host, existing}] ->
              merged = Map.merge(existing, domain_data, fn
                :urls, old_urls, new_urls -> Enum.uniq(old_urls ++ new_urls) |> Enum.take(100)
                _key, _old, new -> new
              end)
              :ets.insert(@ets_domains, {host, merged})

            [] ->
              :ets.insert(@ets_domains, {host, domain_data})
          end
        end

        acc + 1
      else
        acc
      end
    end)

    # Send to aggregator for unified storage
    if length(iocs_for_aggregator) > 0 do
      spawn(fn -> Aggregator.ingest_batch("urlhaus", iocs_for_aggregator) end)
    end

    count
  end

  # ============================================================================
  # Private - ThreatFox Sync
  # ============================================================================

  defp sync_threatfox_internal do
    Logger.debug("[AbuseCh] Syncing ThreatFox feed...")

    body = Jason.encode!(%{query: "get_iocs", days: 7})
    headers = [{"Content-Type", "application/json"}]

    case http_post(@threatfox_api_url, body, headers) do
      {:ok, %Finch.Response{status: 200, body: response_body}} ->
        case Jason.decode(response_body) do
          {:ok, %{"query_status" => "ok", "data" => iocs}} when is_list(iocs) ->
            # Filter for relevant malware families
            filtered_iocs = Enum.filter(iocs, fn ioc ->
              malware = ioc["malware"] || ""
              malware_printable = ioc["malware_printable"] || ""

              Enum.any?(@threatfox_malware_filters, fn filter ->
                String.contains?(String.downcase(malware), String.downcase(filter)) or
                String.contains?(String.downcase(malware_printable), String.downcase(filter))
              end)
            end)

            count = process_threatfox_iocs(filtered_iocs)
            Logger.info("[AbuseCh] ThreatFox: imported #{count} IOCs (filtered from #{length(iocs)})")
            {:ok, %{feed: :threatfox, count: count, total_available: length(iocs), timestamp: DateTime.utc_now()}}

          {:ok, %{"query_status" => status}} ->
            Logger.warning("[AbuseCh] ThreatFox: API status #{status}")
            {:error, {:api_error, status}}

          {:error, reason} ->
            Logger.error("[AbuseCh] ThreatFox: JSON decode error - #{inspect(reason)}")
            {:error, {:json_error, reason}}
        end

      {:ok, %Finch.Response{status: status}} ->
        Logger.warning("[AbuseCh] ThreatFox: HTTP #{status}")
        {:error, {:http_error, status}}

      {:error, reason} ->
        Logger.error("[AbuseCh] ThreatFox: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp process_threatfox_iocs(iocs) do
    Enum.reduce(iocs, 0, fn ioc, acc ->
      ioc_value = ioc["ioc"]
      ioc_type = ioc["ioc_type"]

      if ioc_value && String.length(ioc_value) > 0 do
        data = %{
          ioc: ioc_value,
          ioc_type: ioc_type,
          threat_type: ioc["threat_type"],
          malware: ioc["malware_printable"] || ioc["malware"],
          confidence_level: ioc["confidence_level"] || 75,
          first_seen: ioc["first_seen"],
          last_seen: ioc["last_seen"],
          reporter: ioc["reporter"],
          reference: ioc["reference"],
          tags: ioc["tags"] || [],
          source: "threatfox",
          severity: severity_from_confidence(ioc["confidence_level"]),
          confidence: (ioc["confidence_level"] || 75) / 100,
          fetched_at: DateTime.utc_now()
        }

        # Store in ThreatFox ETS
        :ets.insert(@ets_threatfox, {ioc_value, data})

        # Also index by type
        case ioc_type do
          "ip:port" ->
            # Extract IP from IP:port format
            ip = ioc_value |> String.split(":") |> List.first()
            if ip do
              store_ip(ip, data)
            end

          "domain" ->
            store_domain(ioc_value, data)

          "url" ->
            normalized = normalize_url(ioc_value)
            :ets.insert(@ets_urlhaus, {normalized, Map.put(data, :url, ioc_value)})

            # Also extract domain
            case URI.parse(ioc_value) do
              %URI{host: host} when is_binary(host) and host != "" ->
                store_domain(host, data)
              _ ->
                :ok
            end

          hash_type when hash_type in ["md5_hash", "sha256_hash"] ->
            hash = String.downcase(ioc_value)
            :ets.insert(@ets_hashes, {hash, Map.put(data, :hash, hash)})

          _ ->
            :ok
        end

        acc + 1
      else
        acc
      end
    end)
  end

  defp store_domain(domain, data) when is_binary(domain) do
    normalized = String.downcase(domain)
    domain_data = Map.merge(data, %{domain: normalized})

    case :ets.lookup(@ets_domains, normalized) do
      [{^normalized, existing}] ->
        # Merge - keep higher confidence
        merged = if (data[:confidence] || 0) > (existing[:confidence] || 0) do
          Map.merge(existing, domain_data)
        else
          Map.merge(domain_data, existing)
        end
        :ets.insert(@ets_domains, {normalized, merged})

      [] ->
        :ets.insert(@ets_domains, {normalized, domain_data})
    end
  end

  defp store_ip(ip, data) when is_binary(ip) do
    ip_data = Map.merge(data, %{ip: ip})

    case :ets.lookup(@ets_ips, ip) do
      [{^ip, existing}] ->
        merged = if (data[:confidence] || 0) > (existing[:confidence] || 0) do
          Map.merge(existing, ip_data)
        else
          Map.merge(ip_data, existing)
        end
        :ets.insert(@ets_ips, {ip, merged})

      [] ->
        :ets.insert(@ets_ips, {ip, ip_data})
    end
  end

  # ============================================================================
  # Private - Feodo Tracker Sync
  # ============================================================================

  defp sync_feodo_internal do
    Logger.debug("[AbuseCh] Syncing Feodo Tracker feed...")

    case http_get(@feodo_json_url) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, c2_list} when is_list(c2_list) ->
            count = process_feodo_c2s(c2_list)
            Logger.info("[AbuseCh] Feodo: imported #{count} C2 IPs")
            {:ok, %{feed: :feodo, count: count, timestamp: DateTime.utc_now()}}

          {:error, reason} ->
            Logger.error("[AbuseCh] Feodo: JSON decode error - #{inspect(reason)}")
            {:error, {:json_error, reason}}
        end

      {:ok, %Finch.Response{status: status}} ->
        Logger.warning("[AbuseCh] Feodo: HTTP #{status}")
        {:error, {:http_error, status}}

      {:error, reason} ->
        Logger.error("[AbuseCh] Feodo: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp process_feodo_c2s(c2_list) do
    iocs_for_aggregator = []

    count = Enum.reduce(c2_list, 0, fn c2, acc ->
      ip = c2["ip_address"]

      if ip && valid_ip?(ip) do
        status = c2["status"] || "unknown"

        data = %{
          ip: ip,
          port: c2["port"],
          malware: c2["malware"],
          status: status,
          first_seen: c2["first_seen"],
          last_online: c2["last_online"],
          country: c2["country"],
          as_number: c2["as_number"],
          as_name: c2["as_name"],
          source: "feodo",
          severity: if(status == "online", do: "critical", else: "high"),
          confidence: if(status == "online", do: 0.95, else: 0.85),
          tags: ["feodo", c2["malware"] || "unknown", "c2", status],
          fetched_at: DateTime.utc_now()
        }

        # Store in Feodo ETS
        :ets.insert(@ets_feodo, {ip, data})

        # Also store in IPs index
        store_ip(ip, data)

        acc + 1
      else
        acc
      end
    end)

    # Send to aggregator
    if length(iocs_for_aggregator) > 0 do
      spawn(fn -> Aggregator.ingest_batch("feodo_tracker", iocs_for_aggregator) end)
    end

    count
  end

  # ============================================================================
  # Private - MalwareBazaar Sync
  # ============================================================================

  defp sync_malwarebazaar_internal do
    Logger.debug("[AbuseCh] Syncing MalwareBazaar feed...")

    body = URI.encode_query(%{query: "get_recent", selector: 1000})
    headers = [{"Content-Type", "application/x-www-form-urlencoded"}]

    case http_post(@malwarebazaar_api_url, body, headers) do
      {:ok, %Finch.Response{status: 200, body: response_body}} ->
        case Jason.decode(response_body) do
          {:ok, %{"query_status" => "ok", "data" => samples}} when is_list(samples) ->
            count = process_malwarebazaar_samples(samples)
            Logger.info("[AbuseCh] MalwareBazaar: imported #{count} hashes")
            {:ok, %{feed: :malwarebazaar, count: count, timestamp: DateTime.utc_now()}}

          {:ok, %{"query_status" => status}} ->
            Logger.warning("[AbuseCh] MalwareBazaar: API status #{status}")
            {:error, {:api_error, status}}

          {:error, reason} ->
            Logger.error("[AbuseCh] MalwareBazaar: JSON decode error - #{inspect(reason)}")
            {:error, {:json_error, reason}}
        end

      {:ok, %Finch.Response{status: status}} ->
        Logger.warning("[AbuseCh] MalwareBazaar: HTTP #{status}")
        {:error, {:http_error, status}}

      {:error, reason} ->
        Logger.error("[AbuseCh] MalwareBazaar: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp process_malwarebazaar_samples(samples) do
    Enum.reduce(samples, 0, fn sample, acc ->
      sha256 = sample["sha256_hash"]

      if sha256 && String.length(sha256) == 64 do
        normalized_hash = String.downcase(sha256)

        data = %{
          sha256: normalized_hash,
          sha1: sample["sha1_hash"],
          md5: sample["md5_hash"],
          file_type: sample["file_type"],
          file_type_mime: sample["file_type_mime"],
          file_size: sample["file_size"],
          file_name: sample["file_name"],
          signature: sample["signature"],
          first_seen: sample["first_seen"],
          reporter: sample["reporter"],
          tags: sample["tags"] || [],
          delivery_method: sample["delivery_method"],
          source: "malwarebazaar",
          severity: "critical",
          confidence: 0.95,
          fetched_at: DateTime.utc_now()
        }

        # Store in MalwareBazaar ETS
        :ets.insert(@ets_malwarebazaar, {normalized_hash, data})

        # Also store in hashes index
        :ets.insert(@ets_hashes, {normalized_hash, data})

        # Index MD5 and SHA1 too
        if sample["md5_hash"] do
          md5 = String.downcase(sample["md5_hash"])
          :ets.insert(@ets_hashes, {md5, data})
        end

        if sample["sha1_hash"] do
          sha1 = String.downcase(sample["sha1_hash"])
          :ets.insert(@ets_hashes, {sha1, data})
        end

        acc + 1
      else
        acc
      end
    end)
  end

  # ============================================================================
  # Private - HTTP Helpers
  # ============================================================================

  defp http_get(url) do
    headers = [
      {"User-Agent", "Tamandua-EDR/1.0 (ThreatIntel)"},
      {"Accept", "application/json"}
    ]

    Finch.build(:get, url, headers)
    |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout)
  end

  defp http_post(url, body, headers) do
    full_headers = [{"User-Agent", "Tamandua-EDR/1.0 (ThreatIntel)"} | headers]

    Finch.build(:post, url, full_headers, body)
    |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout)
  end

  # ============================================================================
  # Private - Helpers
  # ============================================================================

  defp normalize_url(url) when is_binary(url) do
    url
    |> String.trim()
    |> String.downcase()
    |> String.replace_trailing("/", "")
  end

  defp valid_ip?(ip) when is_binary(ip) do
    case :inet.parse_address(String.to_charlist(ip)) do
      {:ok, _} -> true
      _ -> false
    end
  end

  defp severity_from_confidence(confidence) when is_integer(confidence) do
    cond do
      confidence >= 90 -> "critical"
      confidence >= 70 -> "high"
      confidence >= 50 -> "medium"
      true -> "low"
    end
  end

  defp severity_from_confidence(_), do: "medium"

  defp update_feed_status(state, feed, result) do
    status = case result do
      {:ok, %{count: count}} ->
        %{status: :ok, last_sync: DateTime.utc_now(), count: count, error: nil}

      {:error, reason} ->
        %{status: :error, last_sync: DateTime.utc_now(), count: 0, error: inspect(reason)}
    end

    new_feed_status = Map.put(state.feed_status, feed, status)

    # Update overall stats
    new_stats = case result do
      {:ok, %{count: count}} ->
        %{state.stats |
          total_syncs: state.stats.total_syncs + 1,
          successful_syncs: state.stats.successful_syncs + 1,
          total_iocs_imported: state.stats.total_iocs_imported + count,
          by_feed: Map.update(state.stats.by_feed, feed, count, &(&1 + count))
        }

      {:error, _} ->
        %{state.stats |
          total_syncs: state.stats.total_syncs + 1,
          failed_syncs: state.stats.failed_syncs + 1
        }
    end

    %{state | feed_status: new_feed_status, stats: new_stats}
  end

  defp schedule_sync(interval) do
    Process.send_after(self(), :periodic_sync, interval)
  end
end
