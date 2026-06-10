defmodule TamanduaServer.Detection.ThreatIntel.Feeds do
  @moduledoc """
  Integration with external threat intelligence feeds.

  Supported feeds and providers:
  - Abuse.ch (MalwareBazaar, URLhaus, ThreatFox) - Free, no API key required
  - VirusTotal - Requires API key (VT_API_KEY)
  - AlienVault OTX - Requires API key (OTX_API_KEY)
  - Shodan - Requires API key for IP enrichment (SHODAN_API_KEY)

  This module manages periodic feed synchronization, caching of IOCs,
  and provides lookup functions for real-time enrichment.

  ## Architecture

  - GenServer for managing feed state and scheduling
  - ETS table for fast IOC lookups
  - PostgreSQL cache for persistence and historical queries
  - Background tasks for feed synchronization
  - Parallel queries to multiple threat intel providers

  ## Usage

      # Start the feeds service (usually via supervision tree)
      ThreatIntel.Feeds.start_link([])

      # Quick check if a hash is known malware (local cache only)
      case ThreatIntel.Feeds.check_hash("abc123...") do
        {:ok, %{found: true, threat_type: "malware", ...}} -> # Known bad
        {:ok, %{found: false}} -> # Not in feeds
      end

      # Full enrichment using all providers (VirusTotal, OTX, Shodan, feeds)
      {:ok, enrichment} = ThreatIntel.Feeds.enrich(:ip, "192.168.1.1")
      # Returns verdict, confidence, and data from all available providers

      # Trigger manual refresh
      ThreatIntel.Feeds.refresh_all()

  ## Configuration

  Set API keys via environment variables:

      export VT_API_KEY=your-virustotal-key
      export OTX_API_KEY=your-alienvault-key
      export SHODAN_API_KEY=your-shodan-key
  """

  use GenServer
  require Logger

  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Detection.ThreatIntel.AbuseCh
  alias TamanduaServer.Detection.ThreatIntelCache

  @feeds [
    %{name: :malwarebazaar, url: "https://mb-api.abuse.ch/api/v1/", interval: :timer.hours(1)},
    %{name: :urlhaus, url: "https://urlhaus-api.abuse.ch/v1/", interval: :timer.minutes(30)},
    %{name: :threatfox, url: "https://threatfox-api.abuse.ch/api/v1/", interval: :timer.hours(1)}
  ]

  @ets_table :threat_intel_feeds_cache

  # ============================================================================
  # Client API
  # ============================================================================

  @doc """
  Starts the ThreatIntel.Feeds GenServer.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Refresh all configured feeds.

  This triggers an asynchronous refresh of all feeds. Use `get_feed_status/0`
  to check progress.
  """
  @spec refresh_all() :: :ok
  def refresh_all do
    GenServer.cast(__MODULE__, :refresh_all)
  end

  @doc """
  Refresh a specific feed by name.

  ## Parameters
    - `feed_name` - One of: :malwarebazaar, :urlhaus, :threatfox, :alienvault_otx
  """
  @spec refresh_feed(atom()) :: :ok
  def refresh_feed(feed_name) when is_atom(feed_name) do
    GenServer.cast(__MODULE__, {:refresh_feed, feed_name})
  end

  @doc """
  Check if a SHA256 hash is known malware.

  Returns enrichment data from threat intelligence feeds.

  ## Examples

      iex> check_hash("a1b2c3d4...")
      {:ok, %{
        found: true,
        source: "malwarebazaar",
        threat_type: "malware",
        malware_family: "Emotet",
        confidence: 0.95,
        first_seen: ~U[2024-01-15 10:00:00Z],
        tags: ["trojan", "banking"]
      }}

      iex> check_hash("cleanfile123...")
      {:ok, %{found: false}}
  """
  @spec check_hash(String.t()) :: {:ok, map()}
  def check_hash(sha256) when is_binary(sha256) do
    normalized = String.downcase(sha256)

    # Check ETS cache first
    case ets_lookup(:hash, normalized) do
      {:ok, cached} ->
        {:ok, Map.put(cached, :found, true)}

      :not_found ->
        # Check database cache
        case db_lookup(:hash, normalized) do
          {:ok, cached} ->
            # Populate ETS for faster subsequent lookups
            ets_insert(:hash, normalized, cached)
            {:ok, Map.put(cached, :found, true)}

          :not_found ->
            {:ok, %{found: false}}
        end
    end
  end

  @doc """
  Check if an IP address is associated with malicious activity.

  ## Examples

      iex> check_ip("192.168.1.1")
      {:ok, %{
        found: true,
        source: "threatfox",
        threat_type: "botnet_cc",
        malware_family: "Emotet",
        confidence: 0.85,
        first_seen: ~U[2024-01-15 10:00:00Z]
      }}
  """
  @spec check_ip(String.t()) :: {:ok, map()}
  def check_ip(ip) when is_binary(ip) do
    normalized = String.downcase(ip)

    case ets_lookup(:ip, normalized) do
      {:ok, cached} ->
        {:ok, Map.put(cached, :found, true)}

      :not_found ->
        case db_lookup(:ip, normalized) do
          {:ok, cached} ->
            ets_insert(:ip, normalized, cached)
            {:ok, Map.put(cached, :found, true)}

          :not_found ->
            {:ok, %{found: false}}
        end
    end
  end

  @doc """
  Check if a domain is associated with malicious activity.

  ## Examples

      iex> check_domain("evil.com")
      {:ok, %{
        found: true,
        source: "urlhaus",
        threat_type: "malware_distribution",
        confidence: 0.90
      }}
  """
  @spec check_domain(String.t()) :: {:ok, map()}
  def check_domain(domain) when is_binary(domain) do
    normalized = String.downcase(domain)

    case ets_lookup(:domain, normalized) do
      {:ok, cached} ->
        {:ok, Map.put(cached, :found, true)}

      :not_found ->
        case db_lookup(:domain, normalized) do
          {:ok, cached} ->
            ets_insert(:domain, normalized, cached)
            {:ok, Map.put(cached, :found, true)}

          :not_found ->
            {:ok, %{found: false}}
        end
    end
  end

  @doc """
  Check if a URL is known malicious.

  ## Examples

      iex> check_url("http://evil.com/malware.exe")
      {:ok, %{
        found: true,
        source: "urlhaus",
        threat_type: "malware_download",
        url_status: "online"
      }}
  """
  @spec check_url(String.t()) :: {:ok, map()}
  def check_url(url) when is_binary(url) do
    # URLs can have varying casing in path, so we normalize more carefully
    normalized = normalize_url(url)

    case ets_lookup(:url, normalized) do
      {:ok, cached} ->
        {:ok, Map.put(cached, :found, true)}

      :not_found ->
        case db_lookup(:url, normalized) do
          {:ok, cached} ->
            ets_insert(:url, normalized, cached)
            {:ok, Map.put(cached, :found, true)}

          :not_found ->
            {:ok, %{found: false}}
        end
    end
  end

  @doc """
  Enrich an IOC with threat intelligence data.

  Performs a lookup and returns detailed enrichment information.

  ## Parameters
    - `ioc_type` - One of: :hash, :ip, :domain, :url
    - `ioc_value` - The IOC value to enrich
  """
  @spec enrich_ioc(atom(), String.t()) :: {:ok, map()} | {:error, term()}
  def enrich_ioc(ioc_type, ioc_value) when ioc_type in [:hash, :ip, :domain, :url] do
    # First check our cache
    cache_result = case ioc_type do
      :hash -> check_hash(ioc_value)
      :ip -> check_ip(ioc_value)
      :domain -> check_domain(ioc_value)
      :url -> check_url(ioc_value)
    end

    case cache_result do
      {:ok, %{found: true} = enrichment} ->
        {:ok, enrichment}

      {:ok, %{found: false}} ->
        # Try live API query for enrichment
        live_enrich(ioc_type, ioc_value)

      error ->
        error
    end
  end

  @doc """
  Full enrichment using all available threat intelligence providers.

  This performs parallel lookups across VirusTotal, AlienVault OTX, Shodan,
  and local feed caches to provide comprehensive enrichment.

  ## Parameters
    - `indicator_type` - One of: :hash, :ip, :domain, :url
    - `indicator_value` - The indicator to enrich
    - `opts` - Options:
      - `:providers` - List of specific providers (default: all available)
      - `:timeout` - Timeout in milliseconds (default: 30000)

  ## Examples

      iex> enrich(:ip, "192.168.1.1")
      {:ok, %{
        indicator: "192.168.1.1",
        indicator_type: :ip,
        verdict: :malicious,
        confidence: 0.85,
        sources: [:virustotal, :alienvault, :shodan, :feeds],
        enrichments: %{
          virustotal: %{detection_stats: %{malicious: 5, ...}},
          alienvault: %{pulse_count: 3, ...},
          shodan: %{ports: [22, 80, 443], vulns: [...], ...},
          feeds: %{found: true, threat_type: "botnet_cc", ...}
        },
        threat_summary: %{
          malware_families: ["Emotet"],
          threat_types: ["botnet_cc"],
          tags: ["c2", "banking"],
          cves: ["CVE-2021-1234"],
          first_seen: ~U[2024-01-15 10:00:00Z]
        },
        enriched_at: ~U[2024-01-20 15:30:00Z]
      }}
  """
  @spec enrich(atom(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def enrich(indicator_type, indicator_value, opts \\ [])
      when indicator_type in [:hash, :ip, :domain, :url] and is_binary(indicator_value) do
    alias TamanduaServer.Detection.ThreatIntel.UnifiedEnrichment
    UnifiedEnrichment.enrich(indicator_type, indicator_value, opts)
  end

  @doc """
  Get the current status of all feeds.

  Returns sync status, last update times, and IOC counts per feed.
  """
  @spec get_feed_status() :: map()
  def get_feed_status do
    GenServer.call(__MODULE__, :get_feed_status)
  end

  @doc """
  Get statistics about cached threat intelligence.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    # Create ETS table for fast lookups
    :ets.new(@ets_table, [:named_table, :set, :public, read_concurrency: true])

    state = %{
      feeds: build_feeds_state(),
      api_keys: %{
        alienvault_otx: System.get_env("OTX_API_KEY")
      },
      enabled: Keyword.get(opts, :enabled, true),
      stats: %{
        lookups: 0,
        cache_hits: 0,
        cache_misses: 0,
        api_queries: 0
      }
    }

    # Schedule initial sync
    if state.enabled do
      Process.send_after(self(), :initial_sync, :timer.seconds(10))

      # Schedule periodic syncs for each feed
      Enum.each(@feeds, fn feed ->
        schedule_feed_sync(feed.name, feed.interval)
      end)
    end

    Logger.info("[ThreatIntel.Feeds] Initialized with #{length(@feeds)} feeds configured")

    {:ok, state}
  end

  @impl true
  def handle_cast(:refresh_all, state) do
    Logger.info("[ThreatIntel.Feeds] Refreshing all feeds...")

    # Spawn tasks for each feed
    Enum.each(state.feeds, fn {name, _status} ->
      Task.start(fn -> do_refresh_feed(name, state) end)
    end)

    {:noreply, state}
  end

  @impl true
  def handle_cast({:refresh_feed, feed_name}, state) do
    Logger.info("[ThreatIntel.Feeds] Refreshing feed: #{feed_name}")
    Task.start(fn -> do_refresh_feed(feed_name, state) end)
    {:noreply, state}
  end

  @impl true
  def handle_call(:get_feed_status, _from, state) do
    # Get counts from database
    db_counts = get_db_counts()

    status = %{
      enabled: state.enabled,
      feeds: Enum.map(state.feeds, fn {name, feed_status} ->
        %{
          name: name,
          status: feed_status.status,
          last_sync: feed_status.last_sync,
          last_error: feed_status.last_error,
          ioc_count: Map.get(db_counts, to_string(name), 0)
        }
      end),
      total_iocs: Enum.sum(Map.values(db_counts)),
      api_keys_configured: %{
        alienvault_otx: state.api_keys.alienvault_otx != nil
      }
    }

    {:reply, status, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    ets_size = :ets.info(@ets_table, :size)

    stats = %{
      ets_cache_size: ets_size,
      lookups: state.stats.lookups,
      cache_hits: state.stats.cache_hits,
      cache_misses: state.stats.cache_misses,
      api_queries: state.stats.api_queries
    }

    {:reply, stats, state}
  end

  @impl true
  def handle_info(:initial_sync, state) do
    Logger.info("[ThreatIntel.Feeds] Starting initial sync...")

    # Load existing cache from database into ETS
    load_cache_to_ets()

    # Trigger refresh for all feeds
    Enum.each(state.feeds, fn {name, _} ->
      Task.start(fn -> do_refresh_feed(name, state) end)
    end)

    {:noreply, state}
  end

  @impl true
  def handle_info({:sync_feed, feed_name}, state) do
    Task.start(fn -> do_refresh_feed(feed_name, state) end)
    schedule_feed_sync(feed_name, get_feed_interval(feed_name))
    {:noreply, state}
  end

  @impl true
  def handle_info({:feed_sync_complete, feed_name, result}, state) do
    new_feeds = Map.update!(state.feeds, feed_name, fn _old ->
      case result do
        {:ok, count} ->
          %{
            status: :ok,
            last_sync: DateTime.utc_now(),
            last_error: nil,
            last_count: count
          }

        {:error, reason} ->
          %{
            status: :error,
            last_sync: nil,
            last_error: inspect(reason),
            last_count: 0
          }
      end
    end)

    {:noreply, %{state | feeds: new_feeds}}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ============================================================================
  # Private Functions - Feed Synchronization
  # ============================================================================

  defp build_feeds_state do
    Enum.reduce(@feeds, %{}, fn feed, acc ->
      Map.put(acc, feed.name, %{
        status: :pending,
        last_sync: nil,
        last_error: nil,
        last_count: 0
      })
    end)
  end

  defp schedule_feed_sync(feed_name, interval) do
    Process.send_after(self(), {:sync_feed, feed_name}, interval)
  end

  defp get_feed_interval(feed_name) do
    Enum.find(@feeds, fn f -> f.name == feed_name end)
    |> Map.get(:interval, :timer.hours(1))
  end

  defp do_refresh_feed(:malwarebazaar, _state) do
    parent = self()

    result = try do
      case AbuseCh.get_recent_samples(500) do
        {:ok, samples} ->
          count = store_malwarebazaar_samples(samples)
          {:ok, count}

        {:error, reason} ->
          {:error, reason}
      end
    rescue
      e -> {:error, Exception.message(e)}
    end

    send(parent, {:feed_sync_complete, :malwarebazaar, result})
  end

  defp do_refresh_feed(:urlhaus, _state) do
    parent = self()

    result = try do
      case AbuseCh.get_recent_urls(500) do
        {:ok, urls} ->
          count = store_urlhaus_urls(urls)
          {:ok, count}

        {:error, reason} ->
          {:error, reason}
      end
    rescue
      e -> {:error, Exception.message(e)}
    end

    send(parent, {:feed_sync_complete, :urlhaus, result})
  end

  defp do_refresh_feed(:threatfox, _state) do
    parent = self()

    result = try do
      case AbuseCh.get_recent_iocs(7) do
        {:ok, iocs} ->
          count = store_threatfox_iocs(iocs)
          {:ok, count}

        {:error, reason} ->
          {:error, reason}
      end
    rescue
      e -> {:error, Exception.message(e)}
    end

    send(parent, {:feed_sync_complete, :threatfox, result})
  end

  defp do_refresh_feed(:alienvault_otx, state) do
    parent = self()

    result = if state.api_keys.alienvault_otx do
      try do
        # Would use OTX API here
        {:ok, 0}
      rescue
        e -> {:error, Exception.message(e)}
      end
    else
      {:error, :no_api_key}
    end

    send(parent, {:feed_sync_complete, :alienvault_otx, result})
  end

  defp do_refresh_feed(unknown, _state) do
    Logger.warning("[ThreatIntel.Feeds] Unknown feed: #{unknown}")
    send(self(), {:feed_sync_complete, unknown, {:error, :unknown_feed}})
  end

  # ============================================================================
  # Private Functions - Storage
  # ============================================================================

  defp store_malwarebazaar_samples(samples) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    entries = Enum.map(samples, fn sample ->
      %{
        ioc_type: "hash",
        ioc_value: String.downcase(sample.sha256 || ""),
        feed_source: "malwarebazaar",
        threat_type: "malware",
        malware_family: sample.signature,
        confidence: 0.95,
        tags: sample.tags || [],
        first_seen: parse_datetime(sample.first_seen),
        last_seen: parse_datetime(sample.last_seen) || now,
        raw_data: Map.drop(sample, [:sha256, :signature, :tags, :first_seen, :last_seen]),
        inserted_at: now,
        updated_at: now
      }
    end)
    |> Enum.filter(&(&1.ioc_value != ""))

    {count, _} = Repo.insert_all(
      ThreatIntelCache,
      entries,
      on_conflict: {:replace, [:last_seen, :raw_data, :updated_at]},
      conflict_target: [:ioc_type, :ioc_value, :feed_source]
    )

    # Update ETS cache
    Enum.each(entries, fn entry ->
      ets_insert(:hash, entry.ioc_value, entry_to_cache_map(entry))
    end)

    Logger.info("[ThreatIntel.Feeds] Stored #{count} samples from MalwareBazaar")
    count
  end

  defp store_urlhaus_urls(urls) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    entries = Enum.flat_map(urls, fn url_entry ->
      url_value = url_entry.url || ""
      host = url_entry.host

      url_entries = if url_value != "" do
        [%{
          ioc_type: "url",
          ioc_value: normalize_url(url_value),
          feed_source: "urlhaus",
          threat_type: url_entry.threat || "malware_distribution",
          malware_family: nil,
          confidence: url_status_to_confidence(url_entry.url_status),
          tags: url_entry.tags || [],
          first_seen: parse_datetime(url_entry.date_added),
          last_seen: now,
          raw_data: Map.drop(url_entry, [:url, :host, :tags, :date_added]),
          inserted_at: now,
          updated_at: now
        }]
      else
        []
      end

      domain_entries = if host && host != "" do
        [%{
          ioc_type: "domain",
          ioc_value: String.downcase(host),
          feed_source: "urlhaus",
          threat_type: url_entry.threat || "malware_distribution",
          malware_family: nil,
          confidence: url_status_to_confidence(url_entry.url_status),
          tags: url_entry.tags || [],
          first_seen: parse_datetime(url_entry.date_added),
          last_seen: now,
          raw_data: %{from_url: url_value},
          inserted_at: now,
          updated_at: now
        }]
      else
        []
      end

      url_entries ++ domain_entries
    end)

    {count, _} = Repo.insert_all(
      ThreatIntelCache,
      entries,
      on_conflict: {:replace, [:last_seen, :raw_data, :updated_at]},
      conflict_target: [:ioc_type, :ioc_value, :feed_source]
    )

    # Update ETS cache
    Enum.each(entries, fn entry ->
      type = String.to_atom(entry.ioc_type)
      ets_insert(type, entry.ioc_value, entry_to_cache_map(entry))
    end)

    Logger.info("[ThreatIntel.Feeds] Stored #{count} entries from URLhaus")
    count
  end

  defp store_threatfox_iocs(iocs) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    entries = Enum.map(iocs, fn ioc ->
      {ioc_type, ioc_value} = normalize_threatfox_ioc(ioc)

      %{
        ioc_type: ioc_type,
        ioc_value: ioc_value,
        feed_source: "threatfox",
        threat_type: ioc.threat_type || "unknown",
        malware_family: ioc.malware_printable || ioc.malware,
        confidence: (ioc.confidence_level || 50) / 100.0,
        tags: ioc.tags || [],
        first_seen: parse_datetime(ioc.first_seen),
        last_seen: parse_datetime(ioc.last_seen) || now,
        raw_data: Map.drop(ioc, [:ioc, :ioc_type, :threat_type, :malware, :confidence_level, :tags, :first_seen, :last_seen]),
        inserted_at: now,
        updated_at: now
      }
    end)
    |> Enum.filter(&(&1.ioc_value != ""))

    {count, _} = Repo.insert_all(
      ThreatIntelCache,
      entries,
      on_conflict: {:replace, [:last_seen, :raw_data, :updated_at]},
      conflict_target: [:ioc_type, :ioc_value, :feed_source]
    )

    # Update ETS cache
    Enum.each(entries, fn entry ->
      type = String.to_atom(entry.ioc_type)
      ets_insert(type, entry.ioc_value, entry_to_cache_map(entry))
    end)

    Logger.info("[ThreatIntel.Feeds] Stored #{count} IOCs from ThreatFox")
    count
  end

  defp normalize_threatfox_ioc(ioc) do
    case ioc.ioc_type do
      "ip:port" ->
        # Extract just the IP
        ip = ioc.ioc |> String.split(":") |> List.first() |> String.downcase()
        {"ip", ip}

      "domain" ->
        {"domain", String.downcase(ioc.ioc || "")}

      "url" ->
        {"url", normalize_url(ioc.ioc || "")}

      "md5_hash" ->
        {"hash", String.downcase(ioc.ioc || "")}

      "sha256_hash" ->
        {"hash", String.downcase(ioc.ioc || "")}

      _ ->
        {"unknown", String.downcase(ioc.ioc || "")}
    end
  end

  defp entry_to_cache_map(entry) do
    %{
      source: entry.feed_source,
      threat_type: entry.threat_type,
      malware_family: entry.malware_family,
      confidence: entry.confidence,
      tags: entry.tags,
      first_seen: entry.first_seen,
      last_seen: entry.last_seen
    }
  end

  # ============================================================================
  # Private Functions - Lookups
  # ============================================================================

  defp ets_lookup(type, value) do
    key = {type, value}

    case :ets.lookup(@ets_table, key) do
      [{^key, data}] -> {:ok, data}
      [] -> :not_found
    end
  end

  defp ets_insert(type, value, data) do
    key = {type, value}
    :ets.insert(@ets_table, {key, data})
  end

  defp db_lookup(type, value) do
    type_str = to_string(type)

    query = from(c in ThreatIntelCache,
      where: c.ioc_type == ^type_str and c.ioc_value == ^value,
      order_by: [desc: c.confidence],
      limit: 1
    )

    case Repo.one(query) do
      nil ->
        :not_found

      cache ->
        {:ok, %{
          source: cache.feed_source,
          threat_type: cache.threat_type,
          malware_family: cache.malware_family,
          confidence: cache.confidence,
          tags: cache.tags,
          first_seen: cache.first_seen,
          last_seen: cache.last_seen
        }}
    end
  end

  defp get_db_counts do
    query = from(c in ThreatIntelCache,
      group_by: c.feed_source,
      select: {c.feed_source, count(c.id)}
    )

    Repo.all(query)
    |> Map.new()
  end

  defp load_cache_to_ets do
    # Load high-confidence IOCs into ETS for fast lookups
    query = from(c in ThreatIntelCache,
      where: c.confidence >= 0.7,
      order_by: [desc: c.last_seen],
      limit: 50_000
    )

    Repo.all(query)
    |> Enum.each(fn cache ->
      type = String.to_atom(cache.ioc_type)
      data = %{
        source: cache.feed_source,
        threat_type: cache.threat_type,
        malware_family: cache.malware_family,
        confidence: cache.confidence,
        tags: cache.tags,
        first_seen: cache.first_seen,
        last_seen: cache.last_seen
      }
      ets_insert(type, cache.ioc_value, data)
    end)

    Logger.info("[ThreatIntel.Feeds] Loaded #{:ets.info(@ets_table, :size)} IOCs into ETS cache")
  end

  # ============================================================================
  # Private Functions - Live Enrichment
  # ============================================================================

  defp live_enrich(:hash, hash) do
    case AbuseCh.query_hash(hash) do
      {:ok, :not_found} ->
        {:ok, %{found: false}}

      {:ok, sample} ->
        enrichment = %{
          found: true,
          source: "malwarebazaar",
          threat_type: "malware",
          malware_family: sample.signature,
          confidence: 0.95,
          first_seen: parse_datetime(sample.first_seen),
          tags: sample.tags || [],
          file_type: sample.file_type,
          file_size: sample.file_size
        }
        {:ok, enrichment}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp live_enrich(:url, url) do
    case AbuseCh.query_url(url) do
      {:ok, :not_found} ->
        {:ok, %{found: false}}

      {:ok, url_info} ->
        enrichment = %{
          found: true,
          source: "urlhaus",
          threat_type: url_info.threat || "malware_distribution",
          confidence: url_status_to_confidence(url_info.url_status),
          url_status: url_info.url_status,
          first_seen: parse_datetime(url_info.date_added),
          tags: url_info.tags || []
        }
        {:ok, enrichment}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp live_enrich(:domain, domain) do
    case AbuseCh.query_host(domain) do
      {:ok, :not_found} ->
        {:ok, %{found: false}}

      {:ok, urls} when is_list(urls) ->
        # Domain was found with associated malicious URLs
        enrichment = %{
          found: true,
          source: "urlhaus",
          threat_type: "malware_distribution",
          confidence: 0.85,
          associated_urls: length(urls),
          tags: urls |> Enum.flat_map(& &1.tags || []) |> Enum.uniq() |> Enum.take(10)
        }
        {:ok, enrichment}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp live_enrich(:ip, ip) do
    # ThreatFox query for IP
    case AbuseCh.query_ioc("ip:port", "#{ip}:443") do
      {:ok, :not_found} ->
        # Try without port
        case AbuseCh.query_ioc("ip:port", ip) do
          {:ok, :not_found} -> {:ok, %{found: false}}
          {:ok, ioc} -> {:ok, threatfox_ioc_to_enrichment(ioc)}
          {:error, reason} -> {:error, reason}
        end

      {:ok, ioc} ->
        {:ok, threatfox_ioc_to_enrichment(ioc)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp threatfox_ioc_to_enrichment(ioc) do
    %{
      found: true,
      source: "threatfox",
      threat_type: ioc.threat_type,
      malware_family: ioc.malware_printable || ioc.malware,
      confidence: (ioc.confidence_level || 50) / 100.0,
      first_seen: parse_datetime(ioc.first_seen),
      tags: ioc.tags || []
    }
  end

  # ============================================================================
  # Helper Functions
  # ============================================================================

  defp normalize_url(url) when is_binary(url) do
    url
    |> String.trim()
    |> then(fn u ->
      # Lowercase the scheme and host, preserve path case
      case URI.parse(u) do
        %URI{scheme: scheme, host: host} = uri when is_binary(scheme) and is_binary(host) ->
          URI.to_string(%{uri | scheme: String.downcase(scheme), host: String.downcase(host)})
        _ ->
          String.downcase(u)
      end
    end)
  end

  defp normalize_url(nil), do: ""

  defp url_status_to_confidence("online"), do: 0.95
  defp url_status_to_confidence("offline"), do: 0.70
  defp url_status_to_confidence(_), do: 0.80

  defp parse_datetime(nil), do: nil
  defp parse_datetime(""), do: nil
  defp parse_datetime(%DateTime{} = dt), do: dt
  defp parse_datetime(str) when is_binary(str) do
    case DateTime.from_iso8601(str) do
      {:ok, dt, _} -> dt
      _ ->
        # Try other formats
        case NaiveDateTime.from_iso8601(str) do
          {:ok, ndt} -> DateTime.from_naive!(ndt, "Etc/UTC")
          _ ->
            # Try "YYYY-MM-DD HH:MM:SS" format
            case Regex.run(~r/^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})/, str) do
              [_, date, time] ->
                case NaiveDateTime.from_iso8601("#{date}T#{time}") do
                  {:ok, ndt} -> DateTime.from_naive!(ndt, "Etc/UTC")
                  _ -> nil
                end
              _ -> nil
            end
        end
    end
  end
end
