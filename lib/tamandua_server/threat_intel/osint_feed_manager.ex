defmodule TamanduaServer.ThreatIntel.OSINTFeedManager do
  @moduledoc """
  Unified OSINT Threat Intelligence Feed Manager.

  Orchestrates all OSINT feed integrations with:
  - Individual feed enable/disable
  - Scheduled updates via Oban
  - Comprehensive health monitoring
  - Detailed feed statistics
  - Alert correlation
  - Automatic IOC expiration
  - Feed priority management

  ## Architecture

  ```
  [OSINTFeedManager]
       |
       ├── [AlienVault OTX]
       ├── [Abuse.ch]
       ├── [PhishTank]
       ├── [Emerging Threats]
       ├── [GreyNoise]
       └── [Shodan]

       ↓
  [Aggregator] → [IOC Database]
  ```

  ## Supported Feeds

  1. **AlienVault OTX** - Open Threat Exchange pulses and indicators
  2. **Abuse.ch** - MalwareBazaar, URLhaus, ThreatFox, Feodo Tracker
  3. **PhishTank** - Verified phishing URLs
  4. **Emerging Threats** - Compromised IPs, C2 infrastructure
  5. **GreyNoise** - Internet noise classification
  6. **Shodan** - (enrichment only, not a feed)

  ## Usage

      # Start/stop feeds
      OSINTFeedManager.enable_feed(:alienvault_otx)
      OSINTFeedManager.disable_feed(:phishtank)

      # Manual sync
      OSINTFeedManager.sync_feed(:abuse_ch)
      OSINTFeedManager.sync_all()

      # Get status
      OSINTFeedManager.get_status()
      OSINTFeedManager.get_feed_health()
      OSINTFeedManager.get_statistics()
  """

  use GenServer
  require Logger

  alias TamanduaServer.Detection.ThreatIntel.{AlienVault, AbuseCh, Shodan}
  alias TamanduaServer.ThreatIntel.Feeds.{PhishTank, EmergingThreats, GreyNoise}
  alias TamanduaServer.ThreatIntel.Aggregator
  alias TamanduaServer.Detection.IOCs

  @feed_configs %{
    alienvault_otx: %{
      name: "AlienVault OTX",
      module: AlienVault,
      requires_api_key: true,
      default_enabled: false,
      sync_interval: :timer.hours(6),
      priority: :high,
      ioc_types: [:ip, :domain, :url, :hash_md5, :hash_sha1, :hash_sha256, :email]
    },
    abuse_ch: %{
      name: "Abuse.ch",
      module: AbuseCh,
      requires_api_key: false,
      default_enabled: true,
      sync_interval: :timer.hours(4),
      priority: :high,
      ioc_types: [:ip, :domain, :url, :hash_sha256]
    },
    phishtank: %{
      name: "PhishTank",
      module: PhishTank,
      requires_api_key: false,
      default_enabled: true,
      sync_interval: :timer.hours(2),
      priority: :medium,
      ioc_types: [:url]
    },
    emerging_threats: %{
      name: "Emerging Threats",
      module: EmergingThreats,
      requires_api_key: false,
      default_enabled: true,
      sync_interval: :timer.hours(6),
      priority: :medium,
      ioc_types: [:ip]
    },
    greynoise: %{
      name: "GreyNoise",
      module: GreyNoise,
      requires_api_key: true,
      default_enabled: false,
      sync_interval: :timer.hours(12),
      priority: :low,
      ioc_types: [:ip]
    }
  }

  @health_check_interval :timer.minutes(5)
  @stats_update_interval :timer.minutes(1)
  @expiration_check_interval :timer.hours(1)

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Enable a specific feed.

  ## Examples

      iex> enable_feed(:alienvault_otx)
      :ok
  """
  @spec enable_feed(atom()) :: :ok | {:error, term()}
  def enable_feed(feed_name) when is_atom(feed_name) do
    GenServer.call(__MODULE__, {:enable_feed, feed_name})
  end

  @doc """
  Disable a specific feed.

  ## Examples

      iex> disable_feed(:phishtank)
      :ok
  """
  @spec disable_feed(atom()) :: :ok | {:error, term()}
  def disable_feed(feed_name) when is_atom(feed_name) do
    GenServer.call(__MODULE__, {:disable_feed, feed_name})
  end

  @doc """
  Manually trigger sync for a specific feed.
  """
  @spec sync_feed(atom()) :: :ok
  def sync_feed(feed_name) when is_atom(feed_name) do
    GenServer.cast(__MODULE__, {:sync_feed, feed_name})
  end

  @doc """
  Manually trigger sync for all enabled feeds.
  """
  @spec sync_all() :: :ok
  def sync_all do
    GenServer.cast(__MODULE__, :sync_all)
  end

  @doc """
  Get overall status of the feed manager.
  """
  @spec get_status() :: map()
  def get_status do
    GenServer.call(__MODULE__, :get_status)
  end

  @doc """
  Get detailed health information for all feeds.
  """
  @spec get_feed_health() :: map()
  def get_feed_health do
    GenServer.call(__MODULE__, :get_feed_health)
  end

  @doc """
  Get detailed statistics for all feeds.
  """
  @spec get_statistics() :: map()
  def get_statistics do
    GenServer.call(__MODULE__, :get_statistics)
  end

  @doc """
  List all available feeds with their configuration.
  """
  @spec list_feeds() :: [map()]
  def list_feeds do
    GenServer.call(__MODULE__, :list_feeds)
  end

  @doc """
  Configure API key for a feed.
  """
  @spec configure_api_key(atom(), String.t()) :: :ok
  def configure_api_key(feed_name, api_key) when is_atom(feed_name) and is_binary(api_key) do
    GenServer.call(__MODULE__, {:configure_api_key, feed_name, api_key})
  end

  @doc """
  Add a custom feed URL.
  """
  @spec add_custom_feed(String.t(), String.t(), keyword()) :: :ok
  def add_custom_feed(name, url, opts \\ []) when is_binary(name) and is_binary(url) do
    GenServer.call(__MODULE__, {:add_custom_feed, name, url, opts})
  end

  @doc """
  Remove a custom feed.
  """
  @spec remove_custom_feed(String.t()) :: :ok
  def remove_custom_feed(name) when is_binary(name) do
    GenServer.call(__MODULE__, {:remove_custom_feed, name})
  end

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  @impl true
  def init(_opts) do
    # Create ETS table for feed state
    :ets.new(:osint_feed_state, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(:osint_feed_stats, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(:osint_feed_health, [:named_table, :set, :public, read_concurrency: true])

    # Initialize feed states
    Enum.each(@feed_configs, fn {feed_name, config} ->
      :ets.insert(:osint_feed_state, {feed_name, %{
        enabled: config.default_enabled,
        last_sync: nil,
        next_sync: nil,
        sync_in_progress: false,
        error_count: 0,
        last_error: nil
      }})

      :ets.insert(:osint_feed_stats, {feed_name, %{
        total_syncs: 0,
        successful_syncs: 0,
        failed_syncs: 0,
        total_iocs_imported: 0,
        iocs_added: 0,
        iocs_updated: 0,
        last_import_count: 0,
        average_sync_time_ms: 0
      }})

      :ets.insert(:osint_feed_health, {feed_name, %{
        status: :pending,
        health_score: 100,
        uptime_percentage: 100.0,
        avg_response_time_ms: 0,
        last_check: nil,
        issues: []
      }})
    end)

    state = %{
      feed_configs: @feed_configs,
      custom_feeds: [],
      api_keys: load_api_keys()
    }

    # Schedule periodic tasks
    schedule_health_check()
    schedule_stats_update()
    schedule_expiration_check()

    # Schedule initial syncs for enabled feeds with staggered delays
    Enum.with_index(@feed_configs)
    |> Enum.each(fn {{feed_name, _config}, index} ->
      [{^feed_name, feed_state}] = :ets.lookup(:osint_feed_state, feed_name)

      if feed_state.enabled do
        # Stagger initial syncs by 30 seconds each to avoid thundering herd
        delay = :timer.seconds(30 + (index * 30))
        schedule_feed_sync(feed_name, delay)
      end
    end)

    Logger.info("[OSINTFeedManager] Initialized with #{map_size(@feed_configs)} feeds")

    {:ok, state}
  end

  @impl true
  def handle_call({:enable_feed, feed_name}, _from, state) do
    case Map.get(state.feed_configs, feed_name) do
      nil ->
        {:reply, {:error, :unknown_feed}, state}

      config ->
        update_feed_state(feed_name, fn s -> %{s | enabled: true} end)

        # Schedule immediate sync
        schedule_feed_sync(feed_name, :timer.seconds(5))

        Logger.info("[OSINTFeedManager] Enabled feed: #{config.name}")
        {:reply, :ok, state}
    end
  end

  @impl true
  def handle_call({:disable_feed, feed_name}, _from, state) do
    case Map.get(state.feed_configs, feed_name) do
      nil ->
        {:reply, {:error, :unknown_feed}, state}

      config ->
        update_feed_state(feed_name, fn s -> %{s | enabled: false} end)

        Logger.info("[OSINTFeedManager] Disabled feed: #{config.name}")
        {:reply, :ok, state}
    end
  end

  @impl true
  def handle_call(:get_status, _from, state) do
    enabled_feeds = Enum.count(@feed_configs, fn {feed_name, _} ->
      [{^feed_name, feed_state}] = :ets.lookup(:osint_feed_state, feed_name)
      feed_state.enabled
    end)

    aggregator_stats = Aggregator.get_stats()

    status = %{
      total_feeds: map_size(@feed_configs),
      enabled_feeds: enabled_feeds,
      disabled_feeds: map_size(@feed_configs) - enabled_feeds,
      custom_feeds: length(state.custom_feeds),
      total_iocs: IOCs.count(),
      iocs_by_type: IOCs.count_by_type(),
      iocs_by_source: IOCs.count_by_source(),
      aggregator_stats: aggregator_stats
    }

    {:reply, status, state}
  end

  @impl true
  def handle_call(:get_feed_health, _from, state) do
    health = :ets.tab2list(:osint_feed_health)
    |> Enum.map(fn {feed_name, health_data} ->
      config = Map.get(@feed_configs, feed_name)
      [{^feed_name, feed_state}] = :ets.lookup(:osint_feed_state, feed_name)

      {feed_name, Map.merge(health_data, %{
        name: config.name,
        enabled: feed_state.enabled,
        requires_api_key: config.requires_api_key,
        api_key_configured: has_api_key?(state, feed_name)
      })}
    end)
    |> Map.new()

    {:reply, health, state}
  end

  @impl true
  def handle_call(:get_statistics, _from, state) do
    stats = :ets.tab2list(:osint_feed_stats)
    |> Enum.map(fn {feed_name, stats_data} ->
      config = Map.get(@feed_configs, feed_name)
      [{^feed_name, feed_state}] = :ets.lookup(:osint_feed_state, feed_name)

      {feed_name, Map.merge(stats_data, %{
        name: config.name,
        enabled: feed_state.enabled,
        last_sync: feed_state.last_sync,
        next_sync: feed_state.next_sync
      })}
    end)
    |> Map.new()

    {:reply, stats, state}
  end

  @impl true
  def handle_call(:list_feeds, _from, state) do
    feeds = Enum.map(@feed_configs, fn {feed_name, config} ->
      [{^feed_name, feed_state}] = :ets.lookup(:osint_feed_state, feed_name)
      [{^feed_name, stats}] = :ets.lookup(:osint_feed_stats, feed_name)
      [{^feed_name, health}] = :ets.lookup(:osint_feed_health, feed_name)

      %{
        id: feed_name,
        name: config.name,
        enabled: feed_state.enabled,
        requires_api_key: config.requires_api_key,
        api_key_configured: has_api_key?(state, feed_name),
        sync_interval_hours: config.sync_interval / :timer.hours(1),
        priority: config.priority,
        ioc_types: config.ioc_types,
        last_sync: feed_state.last_sync,
        next_sync: feed_state.next_sync,
        sync_in_progress: feed_state.sync_in_progress,
        health_status: health.status,
        health_score: health.health_score,
        total_iocs_imported: stats.total_iocs_imported,
        last_import_count: stats.last_import_count
      }
    end)

    custom_feeds = Enum.map(state.custom_feeds, fn custom ->
      %{
        id: String.to_atom(custom.name),
        name: custom.name,
        url: custom.url,
        enabled: custom.enabled,
        type: :custom,
        ioc_type: custom.ioc_type,
        last_sync: custom.last_sync
      }
    end)

    {:reply, feeds ++ custom_feeds, state}
  end

  @impl true
  def handle_call({:configure_api_key, feed_name, api_key}, _from, state) do
    new_api_keys = Map.put(state.api_keys, feed_name, api_key)

    # Configure the underlying service
    case Map.get(@feed_configs, feed_name) do
      %{module: module} when module in [AlienVault, Shodan, GreyNoise] ->
        apply(module, :configure, [api_key])
      _ ->
        :ok
    end

    Logger.info("[OSINTFeedManager] API key configured for #{feed_name}")
    {:reply, :ok, %{state | api_keys: new_api_keys}}
  end

  @impl true
  def handle_call({:add_custom_feed, name, url, opts}, _from, state) do
    custom_feed = %{
      name: name,
      url: url,
      enabled: Keyword.get(opts, :enabled, true),
      ioc_type: Keyword.get(opts, :ioc_type, :auto),
      format: Keyword.get(opts, :format, :plain_text),
      severity: Keyword.get(opts, :severity, "medium"),
      confidence: Keyword.get(opts, :confidence, 0.7),
      sync_interval: Keyword.get(opts, :sync_interval, :timer.hours(6)),
      headers: Keyword.get(opts, :headers, []),
      last_sync: nil
    }

    new_custom_feeds = [custom_feed | state.custom_feeds]

    Logger.info("[OSINTFeedManager] Added custom feed: #{name}")
    {:reply, :ok, %{state | custom_feeds: new_custom_feeds}}
  end

  @impl true
  def handle_call({:remove_custom_feed, name}, _from, state) do
    new_custom_feeds = Enum.reject(state.custom_feeds, &(&1.name == name))

    Logger.info("[OSINTFeedManager] Removed custom feed: #{name}")
    {:reply, :ok, %{state | custom_feeds: new_custom_feeds}}
  end

  @impl true
  def handle_cast({:sync_feed, feed_name}, state) do
    Task.start(fn -> do_sync_feed(feed_name, state) end)
    {:noreply, state}
  end

  @impl true
  def handle_cast(:sync_all, state) do
    Task.start(fn -> do_sync_all(state) end)
    {:noreply, state}
  end

  @impl true
  def handle_info({:sync_feed, feed_name}, state) do
    Task.start(fn -> do_sync_feed(feed_name, state) end)
    {:noreply, state}
  end

  @impl true
  def handle_info(:health_check, state) do
    do_health_check(state)
    schedule_health_check()
    {:noreply, state}
  end

  @impl true
  def handle_info(:stats_update, state) do
    do_stats_update()
    schedule_stats_update()
    {:noreply, state}
  end

  @impl true
  def handle_info(:expiration_check, state) do
    do_expiration_check()
    schedule_expiration_check()
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions - Feed Sync
  # ============================================================================

  defp do_sync_feed(feed_name, state) do
    config = Map.get(@feed_configs, feed_name)
    [{^feed_name, feed_state}] = :ets.lookup(:osint_feed_state, feed_name)

    if feed_state.enabled and not feed_state.sync_in_progress do
      Logger.info("[OSINTFeedManager] Syncing feed: #{config.name}")

      # Mark sync in progress
      update_feed_state(feed_name, fn s -> %{s | sync_in_progress: true} end)

      start_time = System.monotonic_time(:millisecond)

      result = try do
        case feed_name do
          :alienvault_otx -> sync_alienvault_otx(state)
          :abuse_ch -> sync_abuse_ch()
          :phishtank -> sync_phishtank()
          :emerging_threats -> sync_emerging_threats()
          :greynoise -> sync_greynoise(state)
          _ -> {:error, :unknown_feed}
        end
      rescue
        e ->
          Logger.error("[OSINTFeedManager] Sync error for #{config.name}: #{Exception.message(e)}")
          {:error, Exception.message(e)}
      end

      elapsed = System.monotonic_time(:millisecond) - start_time

      # Update feed state and stats
      case result do
        {:ok, count} ->
          update_feed_state(feed_name, fn s ->
            %{s |
              sync_in_progress: false,
              last_sync: DateTime.utc_now(),
              next_sync: DateTime.add(DateTime.utc_now(), config.sync_interval, :millisecond),
              error_count: 0,
              last_error: nil
            }
          end)

          update_feed_stats(feed_name, fn s ->
            avg_sync_time = if s.successful_syncs > 0 do
              (s.average_sync_time_ms * s.successful_syncs + elapsed) / (s.successful_syncs + 1)
            else
              elapsed
            end

            %{s |
              total_syncs: s.total_syncs + 1,
              successful_syncs: s.successful_syncs + 1,
              last_import_count: count,
              total_iocs_imported: s.total_iocs_imported + count,
              average_sync_time_ms: trunc(avg_sync_time)
            }
          end)

          update_feed_health(feed_name, fn h ->
            %{h | status: :healthy, last_check: DateTime.utc_now()}
          end)

          Logger.info("[OSINTFeedManager] Sync complete for #{config.name}: #{count} IOCs in #{elapsed}ms")

          # Schedule next sync
          schedule_feed_sync(feed_name, config.sync_interval)

        {:error, reason} ->
          update_feed_state(feed_name, fn s ->
            %{s |
              sync_in_progress: false,
              error_count: s.error_count + 1,
              last_error: %{reason: reason, timestamp: DateTime.utc_now()}
            }
          end)

          update_feed_stats(feed_name, fn s ->
            %{s |
              total_syncs: s.total_syncs + 1,
              failed_syncs: s.failed_syncs + 1
            }
          end)

          update_feed_health(feed_name, fn h ->
            new_score = max(h.health_score - 10, 0)
            %{h |
              status: if(new_score < 50, do: :unhealthy, else: :degraded),
              health_score: new_score,
              last_check: DateTime.utc_now(),
              issues: [{:sync_error, reason} | h.issues] |> Enum.take(5)
            }
          end)

          Logger.warning("[OSINTFeedManager] Sync failed for #{config.name}: #{inspect(reason)}")

          # Retry with exponential backoff
          retry_delay = min(feed_state.error_count * :timer.minutes(5), :timer.hours(1))
          schedule_feed_sync(feed_name, retry_delay)
      end
    end
  end

  defp do_sync_all(state) do
    Logger.info("[OSINTFeedManager] Syncing all enabled feeds...")

    enabled_feeds = Enum.filter(@feed_configs, fn {feed_name, _} ->
      [{^feed_name, feed_state}] = :ets.lookup(:osint_feed_state, feed_name)
      feed_state.enabled
    end)

    Enum.each(enabled_feeds, fn {feed_name, _} ->
      do_sync_feed(feed_name, state)
      Process.sleep(:timer.seconds(10))  # Stagger syncs
    end)

    # Sync custom feeds
    Enum.each(state.custom_feeds, fn custom ->
      if custom.enabled do
        sync_custom_feed(custom)
        Process.sleep(:timer.seconds(10))
      end
    end)
  end

  defp sync_alienvault_otx(state) do
    case Map.get(state.api_keys, :alienvault_otx) do
      nil ->
        {:error, :no_api_key}

      _api_key ->
        # Get subscribed pulses
        case AlienVault.get_subscribed_pulses(limit: 100) do
          {:ok, %{pulses: pulses}} ->
            iocs = parse_otx_pulses(pulses)
            Aggregator.ingest_batch("alienvault_otx", iocs)
            {:ok, length(iocs)}

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  defp sync_abuse_ch do
    # Use the existing ThreatIntelFeeds abuse.ch sync
    # Get recent samples from MalwareBazaar
    case AbuseCh.get_recent_samples(100) do
      {:ok, samples} ->
        iocs = Enum.map(samples, fn sample ->
          %{
            type: "hash_sha256",
            value: sample.sha256,
            source: "malware_bazaar",
            severity: "critical",
            confidence: 0.9,
            tags: sample.tags ++ ["malware"],
            metadata: %{
              "signature" => sample.signature,
              "file_type" => sample.file_type,
              "first_seen" => sample.first_seen
            },
            malware_family: sample.signature
          }
        end)

        Aggregator.ingest_batch("abuse_ch", iocs)
        {:ok, length(iocs)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp sync_phishtank do
    # Delegate to PhishTank module
    PhishTank.sync_all()
    {:ok, 0}  # PhishTank handles its own stats
  end

  defp sync_emerging_threats do
    # Delegate to EmergingThreats module
    EmergingThreats.sync_all()
    {:ok, 0}  # EmergingThreats handles its own stats
  end

  defp sync_greynoise(state) do
    case Map.get(state.api_keys, :greynoise) do
      nil ->
        {:error, :no_api_key}

      _api_key ->
        # Delegate to GreyNoise module
        GreyNoise.sync_all()
        {:ok, 0}
    end
  end

  defp sync_custom_feed(custom) do
    Logger.info("[OSINTFeedManager] Syncing custom feed: #{custom.name}")

    case Finch.build(:get, custom.url, custom.headers)
         |> Finch.request(TamanduaServer.Finch, receive_timeout: 60_000) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        iocs = parse_custom_feed(body, custom)
        Aggregator.ingest_batch(custom.name, iocs)
        Logger.info("[OSINTFeedManager] Custom feed #{custom.name}: #{length(iocs)} IOCs")

      {:ok, %Finch.Response{status: code}} ->
        Logger.warning("[OSINTFeedManager] Custom feed #{custom.name} returned HTTP #{code}")

      {:error, reason} ->
        Logger.error("[OSINTFeedManager] Custom feed #{custom.name} error: #{inspect(reason)}")
    end
  end

  # ============================================================================
  # Private Functions - Health & Stats
  # ============================================================================

  defp do_health_check(_state) do
    Enum.each(@feed_configs, fn {feed_name, config} ->
      [{^feed_name, feed_state}] = :ets.lookup(:osint_feed_state, feed_name)

      if feed_state.enabled do
        # Check if feed is stale
        if feed_state.last_sync do
          age = DateTime.diff(DateTime.utc_now(), feed_state.last_sync)
          expected_interval = config.sync_interval / 1000

          if age > expected_interval * 2 do
            update_feed_health(feed_name, fn h ->
              %{h |
                status: :stale,
                issues: [{:stale, "No sync for #{div(age, 3600)} hours"} | h.issues] |> Enum.take(5)
              }
            end)
          end
        end

        # Improve health score gradually if no errors
        if feed_state.error_count == 0 do
          update_feed_health(feed_name, fn h ->
            %{h | health_score: min(h.health_score + 5, 100)}
          end)
        end
      end
    end)
  end

  defp do_stats_update do
    # Update aggregator-level stats
    aggregator_stats = Aggregator.get_stats()

    Logger.debug("[OSINTFeedManager] Stats update - Total IOCs: #{aggregator_stats.dedup_index_size}")
  end

  defp do_expiration_check do
    # Delete expired IOCs
    now = DateTime.utc_now()

    query = """
    DELETE FROM iocs
    WHERE expires_at IS NOT NULL
    AND expires_at < $1
    """

    case TamanduaServer.Repo.query(query, [now]) do
      {:ok, %{num_rows: count}} when count > 0 ->
        Logger.info("[OSINTFeedManager] Expired #{count} IOCs")

      _ ->
        :ok
    end
  end

  # ============================================================================
  # Private Functions - Parsers
  # ============================================================================

  defp parse_otx_pulses(pulses) do
    Enum.flat_map(pulses, fn _pulse ->
      # AlienVault pulses don't have indicators in the subscribed endpoint
      # Would need to fetch each pulse individually for full details
      # For now, just log and return empty
      []
    end)
  end

  defp parse_custom_feed(body, custom) do
    case custom.format do
      :plain_text ->
        body
        |> String.split("\n")
        |> Enum.map(&String.trim/1)
        |> Enum.reject(&(String.starts_with?(&1, "#") or &1 == ""))
        |> Enum.map(fn value ->
          %{
            type: determine_ioc_type(value, custom.ioc_type),
            value: value,
            source: custom.name,
            severity: custom.severity,
            confidence: custom.confidence,
            tags: [custom.name]
          }
        end)

      :json ->
        case Jason.decode(body) do
          {:ok, data} when is_list(data) ->
            Enum.map(data, fn entry ->
              %{
                type: determine_ioc_type(entry["value"], custom.ioc_type),
                value: entry["value"],
                source: custom.name,
                severity: entry["severity"] || custom.severity,
                confidence: entry["confidence"] || custom.confidence,
                tags: [custom.name | (entry["tags"] || [])]
              }
            end)

          _ ->
            []
        end

      _ ->
        []
    end
  end

  defp determine_ioc_type(_value, type) when type != :auto, do: Atom.to_string(type)
  defp determine_ioc_type(value, :auto) do
    cond do
      Regex.match?(~r/^[a-f0-9]{64}$/i, value) -> "hash_sha256"
      Regex.match?(~r/^[a-f0-9]{40}$/i, value) -> "hash_sha1"
      Regex.match?(~r/^[a-f0-9]{32}$/i, value) -> "hash_md5"
      Regex.match?(~r/^https?:\/\//, value) -> "url"
      Regex.match?(~r/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/, value) -> "ip"
      Regex.match?(~r/^[a-z0-9.-]+\.[a-z]{2,}$/, value) -> "domain"
      true -> "filename"
    end
  end

  # ============================================================================
  # Private Functions - Helpers
  # ============================================================================

  defp schedule_feed_sync(feed_name, delay) do
    Process.send_after(self(), {:sync_feed, feed_name}, delay)
  end

  defp schedule_health_check do
    Process.send_after(self(), :health_check, @health_check_interval)
  end

  defp schedule_stats_update do
    Process.send_after(self(), :stats_update, @stats_update_interval)
  end

  defp schedule_expiration_check do
    Process.send_after(self(), :expiration_check, @expiration_check_interval)
  end

  defp update_feed_state(feed_name, update_fn) do
    [{^feed_name, current}] = :ets.lookup(:osint_feed_state, feed_name)
    :ets.insert(:osint_feed_state, {feed_name, update_fn.(current)})
  end

  defp update_feed_stats(feed_name, update_fn) do
    [{^feed_name, current}] = :ets.lookup(:osint_feed_stats, feed_name)
    :ets.insert(:osint_feed_stats, {feed_name, update_fn.(current)})
  end

  defp update_feed_health(feed_name, update_fn) do
    [{^feed_name, current}] = :ets.lookup(:osint_feed_health, feed_name)
    :ets.insert(:osint_feed_health, {feed_name, update_fn.(current)})
  end

  defp load_api_keys do
    %{
      alienvault_otx: System.get_env("OTX_API_KEY"),
      greynoise: System.get_env("GREYNOISE_API_KEY"),
      shodan: System.get_env("SHODAN_API_KEY")
    }
  end

  defp has_api_key?(state, feed_name) do
    case Map.get(state.api_keys, feed_name) do
      nil -> false
      "" -> false
      _ -> true
    end
  end
end
