defmodule TamanduaServer.Agents.HealthMonitor do
  @moduledoc """
  Agent Health Monitoring System

  ENTERPRISE FEATURE: Real-time health monitoring for all agents:
  - Heartbeat tracking with configurable intervals
  - Version management and upgrade tracking
  - Resource utilization monitoring (CPU, Memory, Disk)
  - Connectivity status and latency
  - Automatic stale agent detection
  - Health score calculation (0-100)

  This is critical for enterprise deployments to ensure
  complete endpoint coverage and agent health.
  """

  use GenServer
  require Logger

  alias TamanduaServer.{Repo, Agents}
  alias Phoenix.PubSub

  @heartbeat_timeout_seconds 300  # 5 minutes
  @health_check_interval 60_000   # 1 minute
  @stale_agent_threshold 900      # 15 minutes

  # Health thresholds
  @cpu_warning_threshold 80
  @cpu_critical_threshold 95
  @memory_warning_threshold 85
  @memory_critical_threshold 95
  @disk_warning_threshold 80
  @disk_critical_threshold 90

  # Agent health record
  defmodule AgentHealth do
    @moduledoc "Agent health status record"
    defstruct [
      :agent_id,
      :hostname,
      :status,              # :healthy, :warning, :critical, :offline, :stale
      :health_score,        # 0-100
      :last_heartbeat,
      :heartbeat_latency_ms,
      :version,
      :os_type,
      :os_version,
      :cpu_usage,
      :memory_usage,
      :disk_usage,
      :uptime_seconds,
      :event_rate,          # events per minute
      :detection_count_24h,
      :last_detection,
      :ip_addresses,
      :issues,              # List of current issues
      :tags
    ]
  end

  # Health issue
  defmodule HealthIssue do
    @moduledoc "Health issue record"
    defstruct [
      :type,                # :high_cpu, :high_memory, :high_disk, :outdated, :stale, :no_heartbeat
      :severity,            # :warning, :critical
      :message,
      :value,
      :threshold,
      :detected_at
    ]
  end

  # State
  defstruct [
    :agents,              # %{agent_id => AgentHealth}
    :version_info,        # Current agent versions
    :aggregated_stats,    # Overall statistics
    :last_check
  ]

  ## Client API

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Record a heartbeat from an agent
  """
  def record_heartbeat(agent_id, heartbeat_data) do
    GenServer.cast(__MODULE__, {:heartbeat, agent_id, heartbeat_data})
  end

  @doc """
  Get health status for an agent
  """
  def get_agent_health(agent_id) do
    GenServer.call(__MODULE__, {:get_health, agent_id})
  end

  @doc """
  Get simplified health status for alert tuning.

  Delegates to `TamanduaServer.Agents.Registry.get_agent_health_status/1`
  which provides a fast ETS-based lookup returning one of:
  `:healthy | :degraded | :critical | :unknown`

  This is the recommended entry point for detection-hot-path callers
  that need health status without a GenServer round-trip.
  """
  @spec get_agent_health_status(String.t()) :: :healthy | :degraded | :critical | :unknown
  defdelegate get_agent_health_status(agent_id), to: TamanduaServer.Agents.Registry

  @doc """
  Get health status for all agents
  """
  def get_all_health(filters \\ %{}) do
    GenServer.call(__MODULE__, {:get_all_health, filters})
  end

  @doc """
  Get aggregated health statistics
  """
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Get agents with issues
  """
  def get_unhealthy_agents do
    GenServer.call(__MODULE__, :get_unhealthy)
  end

  @doc """
  Get version distribution
  """
  def get_version_stats do
    GenServer.call(__MODULE__, :get_versions)
  end

  @doc """
  Get stale agents (no heartbeat for extended period)
  """
  def get_stale_agents do
    GenServer.call(__MODULE__, :get_stale)
  end

  @doc """
  Force health check for an agent
  """
  def check_agent_health(agent_id) do
    GenServer.call(__MODULE__, {:check_health, agent_id})
  end

  ## Server Callbacks

  @impl true
  def init(_opts) do
    Logger.info("Starting Agent Health Monitor")

    # Schedule periodic health checks
    schedule_health_check()

    state = %__MODULE__{
      agents: load_agents(),
      version_info: %{
        current: "1.0.0",
        minimum_supported: "0.9.0"
      },
      aggregated_stats: %{},
      last_check: DateTime.utc_now()
    }

    {:ok, state}
  end

  @impl true
  def handle_cast({:heartbeat, agent_id, data}, state) do
    now = DateTime.utc_now()

    health = case Map.get(state.agents, agent_id) do
      nil ->
        # New agent
        %AgentHealth{
          agent_id: agent_id,
          hostname: data[:hostname],
          status: :healthy,
          health_score: 100,
          last_heartbeat: now,
          version: data[:version],
          os_type: data[:os_type],
          os_version: data[:os_version],
          ip_addresses: data[:ip_addresses] || [],
          issues: [],
          tags: data[:tags] || []
        }
      existing ->
        existing
    end

    # Update with heartbeat data
    latency = calculate_latency(data[:client_timestamp], now)

    updated = %{health |
      last_heartbeat: now,
      heartbeat_latency_ms: latency,
      version: data[:version] || health.version,
      cpu_usage: data[:cpu_usage],
      memory_usage: data[:memory_usage],
      disk_usage: data[:disk_usage],
      uptime_seconds: data[:uptime_seconds],
      event_rate: data[:event_rate],
      ip_addresses: data[:ip_addresses] || health.ip_addresses
    }

    # Evaluate health
    {status, score, issues} = evaluate_health(updated, state.version_info)
    final = %{updated | status: status, health_score: score, issues: issues}

    # Broadcast health update
    PubSub.broadcast(
      TamanduaServer.PubSub,
      "agent_health",
      {:health_update, agent_id, final}
    )

    # Alert if status changed to critical
    if final.status == :critical and health.status != :critical do
      broadcast_alert(final)
    end

    new_agents = Map.put(state.agents, agent_id, final)
    {:noreply, %{state | agents: new_agents}}
  end

  @impl true
  def handle_call({:get_health, agent_id}, _from, state) do
    health = Map.get(state.agents, agent_id)
    {:reply, {:ok, health}, state}
  end

  @impl true
  def handle_call({:get_all_health, filters}, _from, state) do
    agents = state.agents
      |> Map.values()
      |> filter_agents(filters)
      |> Enum.sort_by(& &1.health_score)

    {:reply, {:ok, agents}, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    stats = calculate_aggregate_stats(state.agents)
    {:reply, {:ok, stats}, state}
  end

  @impl true
  def handle_call(:get_unhealthy, _from, state) do
    unhealthy = state.agents
      |> Map.values()
      |> Enum.filter(& &1.status in [:warning, :critical, :offline, :stale])
      |> Enum.sort_by(& &1.health_score)

    {:reply, {:ok, unhealthy}, state}
  end

  @impl true
  def handle_call(:get_versions, _from, state) do
    versions = state.agents
      |> Map.values()
      |> Enum.group_by(& &1.version)
      |> Enum.map(fn {version, agents} ->
        %{
          version: version,
          count: length(agents),
          is_current: version == state.version_info.current,
          is_outdated: version && Version.compare(version, state.version_info.minimum_supported) == :lt
        }
      end)
      |> Enum.sort_by(& &1.version, :desc)

    {:reply, {:ok, versions}, state}
  end

  @impl true
  def handle_call(:get_stale, _from, state) do
    now = DateTime.utc_now()

    stale = state.agents
      |> Map.values()
      |> Enum.filter(fn agent ->
        agent.last_heartbeat &&
        DateTime.diff(now, agent.last_heartbeat) > @stale_agent_threshold
      end)

    {:reply, {:ok, stale}, state}
  end

  @impl true
  def handle_call({:check_health, agent_id}, _from, state) do
    case Map.get(state.agents, agent_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      health ->
        {status, score, issues} = evaluate_health(health, state.version_info)
        updated = %{health | status: status, health_score: score, issues: issues}
        new_agents = Map.put(state.agents, agent_id, updated)
        {:reply, {:ok, updated}, %{state | agents: new_agents}}
    end
  end

  @impl true
  def handle_info(:health_check, state) do
    Logger.debug("Running periodic health check")
    now = DateTime.utc_now()

    # Update all agent health statuses
    updated_agents = state.agents
      |> Enum.map(fn {id, health} ->
        # Check for stale/offline
        seconds_since_heartbeat = if health.last_heartbeat do
          DateTime.diff(now, health.last_heartbeat)
        else
          @stale_agent_threshold + 1
        end

        health = cond do
          seconds_since_heartbeat > @stale_agent_threshold ->
            %{health | status: :stale, health_score: 0}

          seconds_since_heartbeat > @heartbeat_timeout_seconds ->
            %{health | status: :offline, health_score: 10}

          true ->
            {status, score, issues} = evaluate_health(health, state.version_info)
            %{health | status: status, health_score: score, issues: issues}
        end

        {id, health}
      end)
      |> Map.new()

    # Calculate and broadcast aggregate stats
    stats = calculate_aggregate_stats(updated_agents)
    PubSub.broadcast(
      TamanduaServer.PubSub,
      "agent_health",
      {:stats_update, stats}
    )

    schedule_health_check()

    {:noreply, %{state |
      agents: updated_agents,
      aggregated_stats: stats,
      last_check: now
    }}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  ## Private Functions

  defp load_agents do
    # Load known agents from database
    try do
      Agents.list_agents()
      |> Enum.map(fn agent ->
        {agent.id, %AgentHealth{
          agent_id: agent.id,
          hostname: agent.hostname,
          status: :offline,
          health_score: 0,
          last_heartbeat: agent.last_seen,
          version: agent.version,
          os_type: agent.os_type,
          os_version: agent.os_version,
          ip_addresses: agent.ip_addresses || [],
          issues: [],
          tags: agent.tags || []
        }}
      end)
      |> Map.new()
    rescue
      _ -> %{}
    end
  end

  defp calculate_latency(nil, _now), do: nil
  defp calculate_latency(client_ts, now) when is_integer(client_ts) do
    server_ts = DateTime.to_unix(now, :millisecond)
    max(0, server_ts - client_ts)
  end
  defp calculate_latency(_, _), do: nil

  defp evaluate_health(health, version_info) do
    issues = []
    score = 100

    # CPU check
    {score, issues} = if health.cpu_usage && health.cpu_usage >= @cpu_critical_threshold do
      issue = %HealthIssue{
        type: :high_cpu,
        severity: :critical,
        message: "CPU usage critical: #{health.cpu_usage}%",
        value: health.cpu_usage,
        threshold: @cpu_critical_threshold,
        detected_at: DateTime.utc_now()
      }
      {score - 30, [issue | issues]}
    else
      if health.cpu_usage && health.cpu_usage >= @cpu_warning_threshold do
        issue = %HealthIssue{
          type: :high_cpu,
          severity: :warning,
          message: "CPU usage high: #{health.cpu_usage}%",
          value: health.cpu_usage,
          threshold: @cpu_warning_threshold,
          detected_at: DateTime.utc_now()
        }
        {score - 15, [issue | issues]}
      else
        {score, issues}
      end
    end

    # Memory check
    {score, issues} = if health.memory_usage && health.memory_usage >= @memory_critical_threshold do
      issue = %HealthIssue{
        type: :high_memory,
        severity: :critical,
        message: "Memory usage critical: #{health.memory_usage}%",
        value: health.memory_usage,
        threshold: @memory_critical_threshold,
        detected_at: DateTime.utc_now()
      }
      {score - 25, [issue | issues]}
    else
      if health.memory_usage && health.memory_usage >= @memory_warning_threshold do
        issue = %HealthIssue{
          type: :high_memory,
          severity: :warning,
          message: "Memory usage high: #{health.memory_usage}%",
          value: health.memory_usage,
          threshold: @memory_warning_threshold,
          detected_at: DateTime.utc_now()
        }
        {score - 10, [issue | issues]}
      else
        {score, issues}
      end
    end

    # Disk check
    {score, issues} = if health.disk_usage && health.disk_usage >= @disk_critical_threshold do
      issue = %HealthIssue{
        type: :high_disk,
        severity: :critical,
        message: "Disk usage critical: #{health.disk_usage}%",
        value: health.disk_usage,
        threshold: @disk_critical_threshold,
        detected_at: DateTime.utc_now()
      }
      {score - 20, [issue | issues]}
    else
      if health.disk_usage && health.disk_usage >= @disk_warning_threshold do
        issue = %HealthIssue{
          type: :high_disk,
          severity: :warning,
          message: "Disk usage high: #{health.disk_usage}%",
          value: health.disk_usage,
          threshold: @disk_warning_threshold,
          detected_at: DateTime.utc_now()
        }
        {score - 10, [issue | issues]}
      else
        {score, issues}
      end
    end

    # Version check
    {score, issues} = if health.version do
      cond do
        Version.compare(health.version, version_info.minimum_supported) == :lt ->
          issue = %HealthIssue{
            type: :outdated,
            severity: :critical,
            message: "Agent version #{health.version} is below minimum supported #{version_info.minimum_supported}",
            value: health.version,
            threshold: version_info.minimum_supported,
            detected_at: DateTime.utc_now()
          }
          {score - 25, [issue | issues]}

        health.version != version_info.current ->
          issue = %HealthIssue{
            type: :outdated,
            severity: :warning,
            message: "Agent version #{health.version} is not current (#{version_info.current})",
            value: health.version,
            threshold: version_info.current,
            detected_at: DateTime.utc_now()
          }
          {score - 5, [issue | issues]}

        true ->
          {score, issues}
      end
    else
      {score, issues}
    end

    # Determine status
    score = max(0, score)
    status = cond do
      score >= 80 -> :healthy
      score >= 50 -> :warning
      true -> :critical
    end

    {status, score, issues}
  end

  defp filter_agents(agents, filters) do
    Enum.filter(agents, fn agent ->
      Enum.all?(filters, fn
        {:status, value} -> agent.status == value
        {:os_type, value} -> agent.os_type == value
        {:version, value} -> agent.version == value
        {:min_score, value} -> agent.health_score >= value
        {:max_score, value} -> agent.health_score <= value
        {:tag, value} -> value in (agent.tags || [])
        _ -> true
      end)
    end)
  end

  defp calculate_aggregate_stats(agents) do
    total = map_size(agents)
    agent_list = Map.values(agents)

    if total == 0 do
      %{
        total: 0,
        healthy: 0,
        warning: 0,
        critical: 0,
        offline: 0,
        stale: 0,
        average_health_score: 0,
        coverage_percentage: 0,
        version_distribution: %{},
        os_distribution: %{}
      }
    else
      status_counts = Enum.reduce(agent_list, %{healthy: 0, warning: 0, critical: 0, offline: 0, stale: 0}, fn agent, acc ->
        Map.update(acc, agent.status, 1, &(&1 + 1))
      end)

      avg_score = agent_list
        |> Enum.map(& &1.health_score)
        |> Enum.sum()
        |> Kernel./(total)
        |> round()

      coverage = (status_counts[:healthy] + status_counts[:warning]) / total * 100

      version_dist = agent_list
        |> Enum.group_by(& &1.version)
        |> Enum.map(fn {v, list} -> {v, length(list)} end)
        |> Map.new()

      os_dist = agent_list
        |> Enum.group_by(& &1.os_type)
        |> Enum.map(fn {os, list} -> {os, length(list)} end)
        |> Map.new()

      %{
        total: total,
        healthy: status_counts[:healthy] || 0,
        warning: status_counts[:warning] || 0,
        critical: status_counts[:critical] || 0,
        offline: status_counts[:offline] || 0,
        stale: status_counts[:stale] || 0,
        average_health_score: avg_score,
        coverage_percentage: Float.round(coverage, 1),
        version_distribution: version_dist,
        os_distribution: os_dist
      }
    end
  end

  defp broadcast_alert(health) do
    Logger.warning("Agent #{health.agent_id} (#{health.hostname}) is in critical state")

    PubSub.broadcast(
      TamanduaServer.PubSub,
      "alerts",
      {:agent_critical, health}
    )
  end

  defp schedule_health_check do
    Process.send_after(self(), :health_check, @health_check_interval)
  end
end
