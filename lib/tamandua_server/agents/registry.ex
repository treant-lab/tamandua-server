defmodule TamanduaServer.Agents.Registry do
  @moduledoc """
  ETS-based registry for tracking connected agents.

  Stores agent state including:
  - Connection status
  - Last seen timestamp
  - Configuration
  - Worker PID

  Uses ETS for fast reads and concurrent access.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Agents.HealthHistory

  @table_name :tamandua_agents
  @health_table :tamandua_agent_health
  @lock_table :tamandua_agent_locks
  @cleanup_interval :timer.minutes(1)
  @offline_threshold :timer.seconds(90)
  @lock_acquire_timeout 15_000
  @lock_spin_interval 25
  @lock_stale_after 30_000
  # Keep 24 data points of history (24 minutes at 60s intervals, or 24 hours at 1h intervals)
  @max_health_history 24

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Run a short critical section for one agent on the local server node.

  The live agent socket path can receive two near-simultaneous joins from the
  same endpoint during reconnects or duplicated local services. Serializing the
  worker swap here prevents both sockets from seeing an empty registry and
  starting competing workers.
  """
  @spec with_agent_lock(String.t(), (() -> term())) :: term()
  def with_agent_lock(agent_id, fun) when is_binary(agent_id) and is_function(fun, 0) do
    ensure_table(@lock_table)
    acquire_agent_lock(agent_id)

    try do
      fun.()
    after
      release_agent_lock(agent_id)
    end
  end

  # Per-agent mutual exclusion backed by an ETS lock row, executed in the
  # caller process so the critical section never blocks the registry GenServer
  # (and so independent agents never serialize against each other).
  defp acquire_agent_lock(agent_id, deadline \\ nil) do
    deadline = deadline || System.monotonic_time(:millisecond) + @lock_acquire_timeout
    now = System.monotonic_time(:millisecond)

    if :ets.insert_new(@lock_table, {agent_id, self(), now}) do
      :ok
    else
      case :ets.lookup(@lock_table, agent_id) do
        [{^agent_id, holder, acquired_at}] ->
          cond do
            # Reclaim a lock whose holder process has died.
            is_pid(holder) and not Process.alive?(holder) ->
              :ets.delete_object(@lock_table, {agent_id, holder, acquired_at})
              acquire_agent_lock(agent_id, deadline)

            # Reclaim a stale lock to avoid a permanently wedged critical section.
            now - acquired_at > @lock_stale_after ->
              :ets.delete_object(@lock_table, {agent_id, holder, acquired_at})
              acquire_agent_lock(agent_id, deadline)

            # Last resort after the acquire timeout: take over so the worker
            # swap still runs (the previous holder is almost certainly stuck).
            now >= deadline ->
              :ets.insert(@lock_table, {agent_id, self(), now})
              :ok

            true ->
              Process.sleep(@lock_spin_interval)
              acquire_agent_lock(agent_id, deadline)
          end

        [] ->
          acquire_agent_lock(agent_id, deadline)
      end
    end
  end

  defp release_agent_lock(agent_id) do
    self_pid = self()

    case :ets.lookup(@lock_table, agent_id) do
      [{^agent_id, ^self_pid, _acquired_at} = object] -> :ets.delete_object(@lock_table, object)
      _ -> :ok
    end
  end

  @doc """
  Register an agent in the registry.
  """
  @spec register(String.t(), map()) :: :ok
  def register(agent_id, agent_info) do
    ensure_tables()
    now = System.system_time(:millisecond)

    entry = %{
      agent_id: agent_id,
      hostname: agent_info[:hostname],
      ip_address: agent_info[:ip_address] || "unknown",
      os_type: agent_info[:os_type],
      os_version: agent_info[:os_version],
      agent_version: agent_info[:agent_version],
      machine_id: agent_info[:machine_id],
      organization_id: agent_info[:organization_id],
      status: :online,
      worker_pid: agent_info[:worker_pid],
      connected_at: now,
      last_seen_at: now,
      config: agent_info[:config] || %{},
      capabilities: agent_info[:capabilities] || []
    }

    :ets.insert(@table_name, {agent_id, entry})
    broadcast_status_change(agent_id, :online)
    Logger.info("Agent registered: #{agent_id} (#{entry.hostname})")

    # Process any pending actions queued while agent was offline
    spawn(fn ->
      Process.sleep(1000) # Small delay to ensure agent is fully connected
      TamanduaServer.Response.Executor.process_pending_actions(agent_id)
    end)

    :ok
  end

  @doc """
  Unregister an agent from the registry.
  """
  @spec unregister(String.t()) :: :ok
  def unregister(agent_id) do
    ensure_tables()
    :ets.delete(@table_name, agent_id)
    broadcast_status_change(agent_id, :offline)
    Logger.info("Agent unregistered: #{agent_id}")
    :ok
  end

  @doc """
  Update agent's last seen timestamp (heartbeat).
  """
  @spec heartbeat(String.t()) :: :ok | {:error, :not_found}
  def heartbeat(agent_id) do
    ensure_tables()
    now = System.system_time(:millisecond)

    case :ets.lookup(@table_name, agent_id) do
      [{^agent_id, entry}] ->
        updated = %{entry | last_seen_at: now, status: :online}
        :ets.insert(@table_name, {agent_id, updated})
        :ok

      [] ->
        {:error, :not_found}
    end
  end

  @doc """
  Get agent info by ID.
  """
  @spec get(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get(agent_id) do
    ensure_tables()
    case :ets.lookup(@table_name, agent_id) do
      [{^agent_id, entry}] -> {:ok, entry}
      [] -> {:error, :not_found}
    end
  end

  @doc """
  List all registered agents.
  """
  @spec list_all() :: [map()]
  def list_all do
    ensure_tables()
    :ets.tab2list(@table_name)
    |> Enum.map(fn {_id, entry} -> normalize_entry_presence(entry) end)
  end

  @doc """
  List agents by status.
  """
  @spec list_by_status(atom()) :: [map()]
  def list_by_status(status) do
    ensure_tables()
    :ets.tab2list(@table_name)
    |> Enum.map(fn {_id, entry} -> normalize_entry_presence(entry) end)
    |> Enum.filter(&(&1.status == status))
  end

  @doc """
  List agents for a specific organization.
  """
  @spec list_for_org(String.t()) :: [map()]
  def list_for_org(organization_id) do
    ensure_tables()
    :ets.tab2list(@table_name)
    |> Enum.map(fn {_id, entry} -> normalize_entry_presence(entry) end)
    |> Enum.filter(&(&1.organization_id == organization_id))
  end

  @doc """
  Count agents by status.
  """
  @spec count_by_status() :: map()
  def count_by_status do
    list_all()
    |> Enum.group_by(& &1.status)
    |> Enum.map(fn {status, agents} -> {status, length(agents)} end)
    |> Map.new()
  end

  @doc """
  Count live registry agents by status for a specific organization.

  This is intentionally registry-only: it answers "currently connected"
  state and is used by live dashboard channels. Inventory views that need
  offline database records should use `TamanduaServer.Agents.list_all_for_org/1`.
  """
  @spec count_by_status_for_org(String.t()) :: map()
  def count_by_status_for_org(organization_id) do
    organization_id
    |> list_for_org()
    |> Enum.group_by(& &1.status)
    |> Enum.map(fn {status, agents} -> {status, length(agents)} end)
    |> Map.new()
  end

  @doc """
  Get the worker PID for an agent.
  """
  @spec get_worker_pid(String.t()) :: {:ok, pid()} | {:error, :not_found}
  def get_worker_pid(agent_id) do
    case get(agent_id) do
      {:ok, %{worker_pid: pid}} when is_pid(pid) ->
        if Process.alive?(pid), do: {:ok, pid}, else: {:error, :not_found}

      _ -> {:error, :not_found}
    end
  end

  @doc """
  Look up an agent's worker PID by agent_id.

  Returns the worker PID if the agent is registered and has a worker,
  or `nil` if the agent is not found or has no worker.

  This is a convenience function used by WebSocket channels to dispatch
  messages to agent workers.
  """
  @spec lookup_agent(String.t()) :: pid() | nil
  def lookup_agent(agent_id) do
    case get_worker_pid(agent_id) do
      {:ok, pid} -> pid
      {:error, :not_found} -> nil
    end
  end

  @doc """
  Update agent configuration.
  """
  @spec update_config(String.t(), map()) :: :ok | {:error, :not_found}
  def update_config(agent_id, new_config) do
    ensure_tables()
    case :ets.lookup(@table_name, agent_id) do
      [{^agent_id, entry}] ->
        updated = %{entry | config: Map.merge(entry.config, new_config)}
        :ets.insert(@table_name, {agent_id, updated})
        :ok

      [] ->
        {:error, :not_found}
    end
  end

  @doc """
  Mark agent as isolated.
  """
  @spec set_isolated(String.t(), boolean()) :: :ok | {:error, :not_found}
  def set_isolated(agent_id, isolated) do
    ensure_tables()
    case :ets.lookup(@table_name, agent_id) do
      [{^agent_id, entry}] ->
        status = if isolated, do: :isolated, else: :online
        updated = %{entry | status: status}
        :ets.insert(@table_name, {agent_id, updated})
        broadcast_status_change(agent_id, status)
        :ok

      [] ->
        {:error, :not_found}
    end
  end

  @doc """
  Update health metrics for an agent.

  Stores the latest snapshot and appends CPU/memory values to a rolling
  history (up to @max_health_history entries).
  """
  @spec update_health(String.t(), map()) :: :ok
  def update_health(agent_id, health_data) do
    ensure_tables()
    now = System.system_time(:millisecond)

    case :ets.lookup(@health_table, agent_id) do
      [{^agent_id, existing}] ->
        cpu_history =
          (existing.cpu_history ++ [health_data[:cpu_usage] || health_data["cpu_usage"] || 0])
          |> Enum.take(-@max_health_history)

        memory_history =
          (existing.memory_history ++ [health_data[:memory_usage_percent] || health_data["memory_usage_percent"] || 0])
          |> Enum.take(-@max_health_history)

        entry = %{
          cpu_usage: health_data[:cpu_usage] || health_data["cpu_usage"] || 0,
          memory_usage: health_data[:memory_usage_percent] || health_data["memory_usage_percent"] || 0,
          disk_usage: health_data[:disk_usage_percent] || health_data["disk_usage_percent"] || 0,
          memory_total: health_data[:memory_total] || health_data["memory_total"] || 0,
          memory_used: health_data[:memory_used] || health_data["memory_used"] || 0,
          disk_total: health_data[:disk_total] || health_data["disk_total"] || 0,
          disk_used: health_data[:disk_used] || health_data["disk_used"] || 0,
          uptime_seconds: health_data[:uptime_seconds] || health_data["uptime_seconds"] || 0,
          collector_status: health_data[:collector_status] || health_data["collector_status"],
          platform_status: health_data[:platform_status] || health_data["platform_status"] || [],
          driver_status: health_data[:driver_status] || health_data["driver_status"],
          event_drop_rate: health_data[:event_drop_rate] || health_data["event_drop_rate"],
          cpu_history: cpu_history,
          memory_history: memory_history,
          updated_at: now
        }

        :ets.insert(@health_table, {agent_id, entry})

      [] ->
        cpu_val = health_data[:cpu_usage] || health_data["cpu_usage"] || 0
        mem_val = health_data[:memory_usage_percent] || health_data["memory_usage_percent"] || 0

        entry = %{
          cpu_usage: cpu_val,
          memory_usage: mem_val,
          disk_usage: health_data[:disk_usage_percent] || health_data["disk_usage_percent"] || 0,
          memory_total: health_data[:memory_total] || health_data["memory_total"] || 0,
          memory_used: health_data[:memory_used] || health_data["memory_used"] || 0,
          disk_total: health_data[:disk_total] || health_data["disk_total"] || 0,
          disk_used: health_data[:disk_used] || health_data["disk_used"] || 0,
          uptime_seconds: health_data[:uptime_seconds] || health_data["uptime_seconds"] || 0,
          collector_status: health_data[:collector_status] || health_data["collector_status"],
          platform_status: health_data[:platform_status] || health_data["platform_status"] || [],
          driver_status: health_data[:driver_status] || health_data["driver_status"],
          event_drop_rate: health_data[:event_drop_rate] || health_data["event_drop_rate"],
          cpu_history: [cpu_val],
          memory_history: [mem_val],
          updated_at: now
        }

        :ets.insert(@health_table, {agent_id, entry})
    end

    persist_health_snapshot(agent_id, health_data)

    # Also update the agent registry entry with current metrics
    case :ets.lookup(@table_name, agent_id) do
      [{^agent_id, agent_entry}] ->
        updated = agent_entry
          |> Map.put(:cpu_usage, health_data[:cpu_usage] || health_data["cpu_usage"] || 0)
          |> Map.put(:memory_usage, health_data[:memory_usage_percent] || health_data["memory_usage_percent"] || 0)
          |> Map.put(:disk_usage, health_data[:disk_usage_percent] || health_data["disk_usage_percent"] || 0)
          |> Map.put(:collector_status, health_data[:collector_status] || health_data["collector_status"])
          |> Map.put(:platform_status, health_data[:platform_status] || health_data["platform_status"] || [])
          |> Map.put(:driver_status, health_data[:driver_status] || health_data["driver_status"])

        :ets.insert(@table_name, {agent_id, updated})
      [] -> :ok
    end

    :ok
  end

  @doc """
  Get health metrics for an agent.
  Returns the latest snapshot plus CPU/memory history.
  """
  @spec get_health(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_health(agent_id) do
    ensure_tables()
    case :ets.lookup(@health_table, agent_id) do
      [{^agent_id, entry}] -> {:ok, entry}
      [] -> {:error, :not_found}
    end
  end

  @doc """
  Get the health status of an agent for alert tuning.

  Returns one of:
  - `:healthy`  - Agent is operating normally
  - `:degraded` - Agent has one degraded condition (stale heartbeat, high CPU/memory, or event drops)
  - `:critical` - Agent has multiple degraded conditions or a single extreme condition
  - `:unknown`  - Agent not found or no health data available

  ## Thresholds

  Degraded (any one of):
  - Heartbeat > 60s old
  - CPU > 90%
  - Memory > 95%
  - Event drop rate > 10%

  Critical:
  - Heartbeat > 120s old
  - Two or more degraded conditions simultaneously
  """
  @spec get_agent_health_status(String.t()) :: :healthy | :degraded | :critical | :unknown
  def get_agent_health_status(agent_id) when is_binary(agent_id) do
    ensure_tables()
    now = System.system_time(:millisecond)

    agent_entry = case :ets.lookup(@table_name, agent_id) do
      [{^agent_id, entry}] -> entry
      [] -> nil
    end

    health_entry = case :ets.lookup(@health_table, agent_id) do
      [{^agent_id, entry}] -> entry
      [] -> nil
    end

    if is_nil(agent_entry) do
      :unknown
    else
      agent_entry
      |> evaluate_health_status_detail(health_entry, now)
      |> Map.fetch!(:status)
    end
  end

  def get_agent_health_status(_), do: :unknown

  @doc """
  Get the agent health status plus machine-readable degraded reasons.
  """
  @spec get_agent_health_status_detail(String.t()) :: map()
  def get_agent_health_status_detail(agent_id) when is_binary(agent_id) do
    ensure_tables()
    now = System.system_time(:millisecond)

    agent_entry =
      case :ets.lookup(@table_name, agent_id) do
        [{^agent_id, entry}] -> entry
        [] -> nil
      end

    health_entry =
      case :ets.lookup(@health_table, agent_id) do
        [{^agent_id, entry}] -> entry
        [] -> nil
      end

    if is_nil(agent_entry) do
      %{
        status: :unknown,
        reasons: [:not_registered],
        metrics: %{}
      }
    else
      evaluate_health_status_detail(agent_entry, health_entry, now)
    end
  end

  def get_agent_health_status_detail(_), do: %{status: :unknown, reasons: [:invalid_agent_id], metrics: %{}}

  # Evaluate health status based on agent registry and health data.
  # Returns :healthy | :degraded | :critical | :unknown
  defp evaluate_health_status(agent_entry, health_entry, now) do
    agent_entry
    |> evaluate_health_status_detail(health_entry, now)
    |> Map.fetch!(:status)
  end

  defp evaluate_health_status_detail(agent_entry, health_entry, now) do
    degraded_conditions = []

    # 1. Check heartbeat recency
    last_seen = agent_entry[:last_seen_at] || 0
    heartbeat_age_ms = now - last_seen

    degraded_conditions =
      if heartbeat_age_ms > 120_000 do
        # Heartbeat > 120s is an immediate critical condition
        [:heartbeat_critical | degraded_conditions]
      else
        if heartbeat_age_ms > 60_000 do
          [:heartbeat_stale | degraded_conditions]
        else
          degraded_conditions
        end
      end

    # 2. Check CPU usage
    cpu = get_metric(agent_entry, health_entry, :cpu_usage)

    degraded_conditions =
      if cpu && cpu > 90.0 do
        [:high_cpu | degraded_conditions]
      else
        degraded_conditions
      end

    # 3. Check memory usage
    memory = get_metric(agent_entry, health_entry, :memory_usage)

    degraded_conditions =
      if memory && memory > 95.0 do
        [:high_memory | degraded_conditions]
      else
        degraded_conditions
      end

    # 4. Check event drop rate (from delivery stats if stored in health data)
    drop_rate = if health_entry, do: health_entry[:event_drop_rate] || health_entry["event_drop_rate"], else: nil

    degraded_conditions =
      if drop_rate && drop_rate > 10.0 do
        [:high_drop_rate | degraded_conditions]
      else
        degraded_conditions
      end

    platform_status =
      if health_entry, do: health_entry[:platform_status] || health_entry["platform_status"] || [], else: []

    degraded_platform_sensors = degraded_platform_sensors(platform_status)

    degraded_conditions =
      if degraded_platform_sensors == [] do
        degraded_conditions
      else
        [:platform_sensor_degraded | degraded_conditions]
      end

    driver_status = if health_entry, do: health_entry[:driver_status] || health_entry["driver_status"], else: nil

    degraded_conditions =
      if driver_degraded?(driver_status) do
        [:driver_or_endpoint_sensor_degraded | degraded_conditions]
      else
        degraded_conditions
      end

    # Determine final status
    status =
      cond do
        :heartbeat_critical in degraded_conditions ->
          :critical

        length(degraded_conditions) >= 2 ->
          :critical

        length(degraded_conditions) >= 1 ->
          :degraded

        true ->
          :healthy
      end

    %{
      status: status,
      reasons: Enum.reverse(degraded_conditions),
      metrics: %{
        heartbeat_age_ms: heartbeat_age_ms,
        cpu_usage: cpu,
        memory_usage: memory,
        event_drop_rate: drop_rate,
        platform_coverage: platform_coverage_score(%{platform_status: platform_status, driver_status: driver_status}),
        degraded_platform_sensors: degraded_platform_sensors,
        driver_state: map_get_any(driver_status, [:state, "state"]),
        driver_last_error: map_get_any(driver_status, [:last_error, "last_error"]),
        last_seen_at: last_seen
      }
    }
  end

  # Extract a metric from agent_entry or health_entry, preferring agent_entry
  defp get_metric(agent_entry, health_entry, key) do
    val = agent_entry[key]

    if is_nil(val) and not is_nil(health_entry) do
      health_entry[key]
    else
      val
    end
  end

  defp persist_health_snapshot(agent_id, health_data) do
    cpu = numeric_health_value(health_data, :cpu_usage, 0.0)
    memory = numeric_health_value(health_data, :memory_usage_percent, 0.0)
    disk = numeric_health_value(health_data, :disk_usage_percent, 0.0)
    drop_rate = numeric_health_value(health_data, :event_drop_rate, 0.0)

    cpu_score = inverse_score(cpu, 90.0)
    memory_score = inverse_score(memory, 95.0)
    throughput_score = inverse_score(drop_rate, 10.0)
    coverage_score = platform_coverage_score(health_data)
    uptime_score = if numeric_health_value(health_data, :uptime_seconds, 0.0) > 0, do: 100, else: 50
    compliance_score = 100
    error_rate_score = throughput_score

    health_score =
      [
        cpu_score,
        memory_score,
        throughput_score,
        error_rate_score,
        coverage_score,
        compliance_score,
        uptime_score,
        inverse_score(disk, 95.0)
      ]
      |> Enum.sum()
      |> div(8)

    category =
      cond do
        health_score >= 90 -> "excellent"
        health_score >= 75 -> "good"
        health_score >= 50 -> "fair"
        true -> "poor"
      end

    issues =
      health_data
      |> health_issues(cpu, memory, disk, drop_rate)
      |> Map.new(fn {key, value} -> {Atom.to_string(key), value} end)

    attrs = %{
      health_score: health_score,
      category: category,
      uptime_score: uptime_score,
      cpu_score: cpu_score,
      memory_score: memory_score,
      throughput_score: throughput_score,
      error_rate_score: error_rate_score,
      coverage_score: coverage_score,
      compliance_score: compliance_score,
      issues: issues
    }

    case HealthHistory.record_snapshot(agent_id, attrs) do
      {:ok, _snapshot} ->
        :ok

      {:error, changeset} ->
        Logger.debug(
          "Failed to persist agent health snapshot for #{agent_id}: #{inspect(changeset.errors)}"
        )
    end
  rescue
    e ->
      Logger.debug("Failed to persist agent health snapshot for #{agent_id}: #{Exception.message(e)}")
  end

  defp numeric_health_value(data, key, default) do
    case data[key] || data[Atom.to_string(key)] do
      value when is_integer(value) -> value * 1.0
      value when is_float(value) -> value
      value when is_binary(value) ->
        case Float.parse(value) do
          {parsed, _} -> parsed
          :error -> default
        end

      _ ->
        default
    end
  end

  defp inverse_score(value, threshold) do
    value
    |> Kernel./(threshold)
    |> Kernel.*(100)
    |> then(&(100 - round(&1)))
    |> max(0)
    |> min(100)
  end

  defp platform_coverage_score(health_data) do
    status = health_data[:platform_status] || health_data["platform_status"] || []
    driver_status = health_data[:driver_status] || health_data["driver_status"]

    case status do
      [_ | _] ->
        running = Enum.count(status, &(truthy?(&1[:running] || &1["running"])))
        configured = Enum.count(status, &(truthy?(&1[:configured] || &1["configured"])))
        denominator = max(configured, 1)
        min(100, round(running / denominator * 100))

      _ ->
        cond do
          is_nil(driver_status) -> 75
          driver_degraded?(driver_status) -> 50
          true -> 100
        end
    end
  end

  defp degraded_platform_sensors(status) when is_list(status) do
    status
    |> Enum.filter(&platform_sensor_degraded?/1)
    |> Enum.map(fn sensor ->
      %{
        name: map_get_any(sensor, [:name, "name"]) || "unknown",
        state: map_get_any(sensor, [:state, "state"]) || "unknown",
        reason: map_get_any(sensor, [:reason, "reason"])
      }
    end)
  end

  defp degraded_platform_sensors(_), do: []

  defp platform_sensor_degraded?(sensor) do
    configured? = truthy?(map_get_any(sensor, [:configured, "configured"]))
    compiled? = truthy?(map_get_any(sensor, [:compiled, "compiled"]))
    running? = truthy?(map_get_any(sensor, [:running, "running"]))
    state = sensor |> map_get_any([:state, "state"]) |> to_string() |> String.downcase()

    configured? and compiled? and not running? and state not in ["disabled", "unsupported", "not_compiled"]
  end

  defp driver_degraded?(nil), do: false

  defp driver_degraded?(driver_status) do
    supported? = truthy?(map_get_any(driver_status, [:supported, "supported"]))
    connected? = truthy?(map_get_any(driver_status, [:connected, "connected"]))
    state = driver_status |> map_get_any([:state, "state"]) |> to_string() |> String.downcase()

    supported? and not connected? and state not in ["unsupported", "disabled"]
  end

  defp map_get_any(nil, _keys), do: nil

  defp map_get_any(map, keys) when is_map(map) do
    Enum.find_value(keys, &Map.get(map, &1))
  end

  defp map_get_any(_, _keys), do: nil

  defp health_issues(health_data, cpu, memory, disk, drop_rate) do
    platform_status = health_data[:platform_status] || health_data["platform_status"] || []
    driver_status = health_data[:driver_status] || health_data["driver_status"]

    []
    |> maybe_issue(cpu > 90.0, :high_cpu, cpu)
    |> maybe_issue(memory > 95.0, :high_memory, memory)
    |> maybe_issue(disk > 95.0, :high_disk, disk)
    |> maybe_issue(drop_rate > 10.0, :high_drop_rate, drop_rate)
    |> maybe_issue(degraded_platform_sensors(platform_status) != [], :platform_sensor_degraded, degraded_platform_sensors(platform_status))
    |> maybe_issue(driver_degraded?(driver_status), :driver_or_endpoint_sensor_degraded, map_get_any(driver_status, [:state, "state"]))
  end

  defp maybe_issue(issues, true, key, value), do: [{key, value} | issues]
  defp maybe_issue(issues, false, _key, _value), do: issues

  defp truthy?(value) when value in [true, "true", 1, "1"], do: true
  defp truthy?(_), do: false

  # Server callbacks

  @impl true
  def init(_opts) do
    table = ensure_table(@table_name)
    health_table = ensure_table(@health_table)
    ensure_table(@lock_table)
    cleanup_stale_database_presence()
    schedule_cleanup()
    {:ok, %{table: table, health_table: health_table}}
  end

  @impl true
  def handle_info(:cleanup, state) do
    cleanup_stale_agents()
    cleanup_stale_database_presence()
    schedule_cleanup()
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # Private functions

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval)
  end

  defp cleanup_stale_agents do
    ensure_tables()
    now = System.system_time(:millisecond)
    threshold = now - @offline_threshold

    :ets.tab2list(@table_name)
    |> Enum.each(fn {agent_id, entry} ->
      worker_dead? = is_pid(entry[:worker_pid]) and not Process.alive?(entry[:worker_pid])

      if (entry.last_seen_at < threshold or worker_dead?) and entry.status == :online do
        updated = %{entry | status: :offline}
        :ets.insert(@table_name, {agent_id, updated})
        broadcast_status_change(agent_id, :offline)
        reason = if worker_dead?, do: "dead worker", else: "timeout"
        Logger.warning("Agent marked offline due to #{reason}: #{agent_id}")
      end
    end)
  end

  defp normalize_entry_presence(%{status: :online, worker_pid: pid} = entry)
       when is_pid(pid) do
    if Process.alive?(pid), do: entry, else: %{entry | status: :offline}
  end

  defp normalize_entry_presence(%{status: :online} = entry), do: %{entry | status: :offline}
  defp normalize_entry_presence(entry), do: entry

  defp cleanup_stale_database_presence do
    live_agent_ids =
      @table_name
      |> :ets.tab2list()
      |> Enum.filter(fn {_agent_id, entry} ->
        entry.status == :online and is_pid(entry[:worker_pid]) and Process.alive?(entry[:worker_pid])
      end)
      |> Enum.map(fn {agent_id, _entry} -> agent_id end)

    TamanduaServer.Agents.mark_stale_online_agents_offline(
      live_agent_ids,
      div(@offline_threshold, 1000)
    )
  rescue
    e ->
      Logger.debug("Stale DB presence cleanup skipped: #{Exception.message(e)}")
  end

  defp broadcast_status_change(agent_id, status) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "agents:status",
      {:agent_status_changed, agent_id, status}
    )
  end

  defp ensure_tables do
    ensure_table(@table_name)
    ensure_table(@health_table)
    :ok
  end

  defp ensure_table(table_name) do
    case :ets.whereis(table_name) do
      :undefined ->
        try do
          :ets.new(table_name, [:named_table, :set, :public, read_concurrency: true])
        rescue
          ArgumentError -> :ets.whereis(table_name)
        end

      table ->
        table
    end
  end
end
