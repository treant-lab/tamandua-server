defmodule TamanduaServer.Cache.Warmer do
  @moduledoc """
  Cache warming service for pre-populating caches on startup and periodic refresh.

  Implements intelligent cache warming strategies:
  - On-demand warming (manual triggers)
  - Scheduled warming (Oban jobs)
  - Predictive warming (ML-based, future enhancement)
  - Coordinated warming across distributed nodes

  ## Features

  - Async background warming (non-blocking)
  - Prioritized warming (critical data first)
  - Rate-limited warming (prevents DB overload)
  - Warm-on-deploy detection
  - Progress tracking and metrics

  ## Usage

      # Manual warming
      Warmer.warm_all()
      Warmer.warm_cache(:yara_rules)

      # Scheduled warming (via Oban)
      Warmer.schedule_warming(:threat_intel, interval: :timer.hours(1))
  """

  use GenServer
  require Logger

  alias TamanduaServer.Cache.{ETSCache, RedisCache}
  alias TamanduaServer.{Detection, ThreatIntel, Agents, Alerts}

  @warming_interval :timer.hours(12)
  @rate_limit_delay 10 # ms between batch fetches

  # Warming configuration: priority order and data sources
  # Note: Uses atoms as transform keys, resolved at runtime via get_transform/1
  @warming_configs [
    %{cache: :detection_config, priority: 1, source: {Detection, :list_config, []}, transform: :detection_config},
    %{cache: :yara_rules, priority: 2, source: {Detection, :list_yara_rules, []}, transform: :yara_rules},
    %{cache: :sigma_rules, priority: 3, source: {Detection, :list_sigma_rules, []}, transform: :sigma_rules},
    %{cache: :iocs, priority: 4, source: {ThreatIntel, :list_active_iocs, []}, transform: :iocs},
    %{cache: :threat_intel, priority: 5, source: {ThreatIntel, :list_enrichment_data, []}, transform: :threat_intel},
    %{cache: :agent_metadata, priority: 6, source: {Agents, :list_agents_with_metadata, []}, transform: :agent_metadata}
  ]

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Warms all caches in priority order.
  Returns `{:ok, stats}` with warming statistics.
  """
  def warm_all do
    GenServer.call(__MODULE__, :warm_all, :timer.minutes(5))
  end

  @doc """
  Warms a specific cache type.
  """
  def warm_cache(cache_type) do
    GenServer.call(__MODULE__, {:warm_cache, cache_type}, :timer.minutes(2))
  end

  @doc """
  Schedules periodic cache warming (non-blocking).
  """
  def schedule_warming(cache_type, opts \\ []) do
    GenServer.cast(__MODULE__, {:schedule_warming, cache_type, opts})
  end

  @doc """
  Returns warming statistics.
  """
  def stats do
    GenServer.call(__MODULE__, :stats)
  end

  @doc """
  Warms frequently accessed alert data into Redis.
  """
  def warm_hot_alerts(tenant_id, limit \\ 100) do
    GenServer.cast(__MODULE__, {:warm_hot_alerts, tenant_id, limit})
  end

  @doc """
  Warms frequently accessed agent data into Redis.
  """
  def warm_hot_agents(tenant_id, limit \\ 100) do
    GenServer.cast(__MODULE__, {:warm_hot_agents, tenant_id, limit})
  end

  # GenServer Callbacks

  @impl true
  def init(opts) do
    # Warm caches on startup if enabled
    warm_on_startup = Keyword.get(opts, :warm_on_startup, true)

    if warm_on_startup do
      Logger.info("[Warmer] Starting cache warming on startup")
      Task.start(fn -> perform_warm_all() end)
    end

    # Schedule periodic warming
    schedule_periodic_warming()

    state = %{
      warming_count: 0,
      last_warm: nil,
      stats: %{}
    }

    {:ok, state}
  end

  @impl true
  def handle_call(:warm_all, _from, state) do
    stats = perform_warm_all()

    new_state = %{
      state
      | warming_count: state.warming_count + 1,
        last_warm: DateTime.utc_now(),
        stats: stats
    }

    {:reply, {:ok, stats}, new_state}
  end

  def handle_call({:warm_cache, cache_type}, _from, state) do
    result = perform_warm_cache(cache_type)

    new_state = %{
      state
      | warming_count: state.warming_count + 1,
        last_warm: DateTime.utc_now()
    }

    {:reply, result, new_state}
  end

  def handle_call(:stats, _from, state) do
    stats = %{
      warming_count: state.warming_count,
      last_warm: state.last_warm,
      cache_stats: state.stats,
      ets_stats: ETSCache.stats_all()
    }

    {:reply, stats, state}
  end

  @impl true
  def handle_cast({:schedule_warming, cache_type, opts}, state) do
    interval = Keyword.get(opts, :interval, @warming_interval)

    # Schedule Oban job for periodic warming
    schedule_oban_warming(cache_type, interval)

    {:noreply, state}
  end

  def handle_cast({:warm_hot_alerts, tenant_id, limit}, state) do
    Task.start(fn -> perform_warm_hot_alerts(tenant_id, limit) end)
    {:noreply, state}
  end

  def handle_cast({:warm_hot_agents, tenant_id, limit}, state) do
    Task.start(fn -> perform_warm_hot_agents(tenant_id, limit) end)
    {:noreply, state}
  end

  @impl true
  def handle_info(:periodic_warm, state) do
    Logger.info("[Warmer] Starting periodic cache warming")
    Task.start(fn -> perform_warm_all() end)

    schedule_periodic_warming()
    {:noreply, state}
  end

  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # Private Functions

  defp perform_warm_all do
    Logger.info("[Warmer] Starting full cache warming")
    start_time = System.monotonic_time(:millisecond)

    stats =
      @warming_configs
      |> Enum.sort_by(& &1.priority)
      |> Enum.map(fn config ->
        result = perform_warm_cache(config.cache, config.source, config.transform)
        {config.cache, result}
      end)
      |> Map.new()

    duration = System.monotonic_time(:millisecond) - start_time
    Logger.info("[Warmer] Cache warming completed in #{duration}ms")

    Map.put(stats, :duration_ms, duration)
  end

  defp perform_warm_cache(cache_type) do
    config = Enum.find(@warming_configs, &(&1.cache == cache_type))

    if config do
      perform_warm_cache(config.cache, config.source, config.transform)
    else
      {:error, :unknown_cache_type}
    end
  end

  defp perform_warm_cache(cache_type, {mod, fun, args}, transform_key) do
    Logger.debug("[Warmer] Warming cache: #{cache_type}")
    start_time = System.monotonic_time(:millisecond)

    try do
      # Fetch data from source
      data = apply(mod, fun, args)

      # Transform into cache format
      entries = apply_transform(transform_key, data)

      # Warm ETS cache
      ETSCache.warm(cache_type, fn -> entries end)

      duration = System.monotonic_time(:millisecond) - start_time

      Logger.info("[Warmer] Warmed #{length(entries)} entries in #{cache_type} (#{duration}ms)")

      {:ok, %{count: length(entries), duration_ms: duration}}
    rescue
      error ->
        Logger.error("[Warmer] Failed to warm #{cache_type}: #{inspect(error)}")
        {:error, error}
    end
  end

  defp perform_warm_hot_alerts(tenant_id, limit) do
    Logger.debug("[Warmer] Warming hot alerts for tenant #{tenant_id}")

    # Fetch recent high-priority alerts
    alerts =
      Alerts.list_recent_alerts(tenant_id, limit: limit, priority: [:high, :critical])

    # Cache in Redis with short TTL
    Enum.each(alerts, fn alert ->
      RedisCache.put("tenant_#{tenant_id}", "alert:#{alert.id}", alert,
        ttl: RedisCache.ttl_5min()
      )

      # Rate limiting to prevent DB overload
      Process.sleep(@rate_limit_delay)
    end)

    Logger.info("[Warmer] Warmed #{length(alerts)} hot alerts for tenant #{tenant_id}")
  end

  defp perform_warm_hot_agents(tenant_id, limit) do
    Logger.debug("[Warmer] Warming hot agents for tenant #{tenant_id}")

    # Fetch online agents
    agents = Agents.list_online_agents(tenant_id, limit: limit)

    # Cache in Redis with short TTL
    Enum.each(agents, fn agent ->
      RedisCache.put("tenant_#{tenant_id}", "agent:#{agent.id}", agent,
        ttl: RedisCache.ttl_5min()
      )

      Process.sleep(@rate_limit_delay)
    end)

    Logger.info("[Warmer] Warmed #{length(agents)} hot agents for tenant #{tenant_id}")
  end

  defp schedule_periodic_warming do
    Process.send_after(self(), :periodic_warm, @warming_interval)
  end

  defp schedule_oban_warming(cache_type, interval) do
    # Schedule Oban job for background warming
    %{cache_type: cache_type}
    |> TamanduaServer.Workers.CacheWarmingWorker.new(schedule_in: interval)
    |> Oban.insert()
  end

  # Transform dispatcher - maps transform keys to functions
  defp apply_transform(:detection_config, data), do: transform_detection_config(data)
  defp apply_transform(:yara_rules, data), do: transform_yara_rules(data)
  defp apply_transform(:sigma_rules, data), do: transform_sigma_rules(data)
  defp apply_transform(:iocs, data), do: transform_iocs(data)
  defp apply_transform(:threat_intel, data), do: transform_threat_intel(data)
  defp apply_transform(:agent_metadata, data), do: transform_agent_metadata(data)

  # Transform functions

  defp transform_detection_config(config_items) do
    Enum.map(config_items, fn item ->
      {item.key, item.value}
    end)
  end

  defp transform_yara_rules(rules) do
    Enum.map(rules, fn rule ->
      {rule.id, %{
        name: rule.name,
        rule_text: rule.rule_text,
        enabled: rule.enabled,
        metadata: rule.metadata
      }}
    end)
  end

  defp transform_sigma_rules(rules) do
    Enum.map(rules, fn rule ->
      {rule.id, %{
        name: rule.name,
        detection: rule.detection,
        enabled: rule.enabled,
        level: rule.level
      }}
    end)
  end

  defp transform_iocs(iocs) do
    Enum.map(iocs, fn ioc ->
      {ioc.value, %{
        type: ioc.type,
        source: ioc.source,
        confidence: ioc.confidence,
        expires_at: ioc.expires_at
      }}
    end)
  end

  defp transform_threat_intel(intel_items) do
    Enum.map(intel_items, fn item ->
      {item.indicator, %{
        category: item.category,
        threat_type: item.threat_type,
        severity: item.severity
      }}
    end)
  end

  defp transform_agent_metadata(agents) do
    Enum.map(agents, fn agent ->
      {agent.id, %{
        hostname: agent.hostname,
        platform: agent.platform,
        status: agent.status,
        last_seen: agent.last_seen
      }}
    end)
  end
end
