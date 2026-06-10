defmodule TamanduaServer.Response.VssRollback do
  @moduledoc """
  VSS (Volume Shadow Copy) Rollback Orchestration

  Provides server-side orchestration for Windows VSS-based file rollback on
  managed agents. This GenServer tracks rollback state per agent, coordinates
  snapshot lifecycle, and provides the "1-click rollback" API that rivals
  SentinelOne's patented rollback capability.

  ## Capabilities

  - **Snapshot inventory**: Track available VSS snapshots per agent with
    periodic refresh.
  - **1-click rollback**: Initiate a full ransomware rollback with a single
    API call -- the server handles snapshot selection, file enumeration,
    restoration, and verification.
  - **Progress tracking**: Real-time rollback progress with PubSub broadcasts
    for dashboard updates.
  - **Rollback history**: Full audit trail of every rollback operation with
    success/failure statistics.
  - **Schedule management**: Configure per-agent snapshot scheduling from the
    server.

  ## Architecture

      [Dashboard/API] --> [VssRollback GenServer]
                                |                    |
                        [ETS: snapshots]     [ETS: operations]
                                |
                        [Executor] --> [WebSocket] --> [Agent]
                                                          |
                                                  [VssSnapshotManager]
                                                          |
                                            [result pushed back] --> [VssRollback]

  ## Integration

  This module delegates to `TamanduaServer.Response.Executor` for sending
  commands to agents.  It listens for rollback results via casts from the
  WebSocket channel handler.

  ## Usage

      # List snapshots for an agent
      {:ok, snapshots} = VssRollback.list_snapshots(agent_id)

      # Create a snapshot
      {:ok, snapshot} = VssRollback.create_snapshot(agent_id, %{volumes: ["C:"]})

      # 1-click rollback (uses latest clean snapshot)
      {:ok, op} = VssRollback.rollback_agent(agent_id, %{paths: [...]})

      # Ransomware rollback (auto-finds encrypted files + best snapshot)
      {:ok, op} = VssRollback.ransomware_rollback(agent_id, %{path: "C:\\\\Users"})

      # Check status
      {:ok, status} = VssRollback.get_rollback_status(operation_id)
  """

  use GenServer
  require Logger

  alias TamanduaServer.Response.Executor

  # ETS table names
  @snapshots_table :vss_snapshots
  @operations_table :vss_operations

  # Operation timeout (10 minutes for large rollbacks)
  @operation_timeout 600_000

  # Snapshot cache TTL (15 minutes)
  @cache_ttl_seconds 900

  # Periodic cleanup interval (30 minutes)
  @cleanup_interval_ms 1_800_000

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  List available VSS snapshots for an agent.

  Queries the agent if the cache is stale, otherwise returns cached data.
  Pass `force_refresh: true` to always query the agent.
  """
  @spec list_snapshots(String.t(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def list_snapshots(agent_id, opts \\ []) do
    GenServer.call(__MODULE__, {:list_snapshots, agent_id, opts}, @operation_timeout)
  end

  @doc """
  Create a new VSS snapshot on an agent.

  ## Options

  - `:volumes` - List of volume letters (default: ["C:"])
  - `:label` - Optional label for the snapshot
  """
  @spec create_snapshot(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def create_snapshot(agent_id, opts \\ %{}) do
    GenServer.call(__MODULE__, {:create_snapshot, agent_id, opts}, @operation_timeout)
  end

  @doc """
  Delete a VSS snapshot on an agent.
  """
  @spec delete_snapshot(String.t(), String.t()) :: :ok | {:error, term()}
  def delete_snapshot(agent_id, snapshot_id) do
    GenServer.call(__MODULE__, {:delete_snapshot, agent_id, snapshot_id}, @operation_timeout)
  end

  @doc """
  Initiate a 1-click VSS rollback on an agent.

  If no `snapshot_id` is given, the most recent clean snapshot is used.
  If `paths` is empty, the agent will determine affected files automatically.

  ## Options

  - `:snapshot_id` - Specific snapshot to roll back to
  - `:paths` - List of file paths to restore
  - `:verify` - Whether to hash-verify restored files (default: true)
  - `:volume` - Volume letter (default: "C:")
  - `:requested_by` - User ID for audit
  """
  @spec rollback_agent(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def rollback_agent(agent_id, opts \\ %{}) do
    GenServer.call(__MODULE__, {:rollback_agent, agent_id, opts}, @operation_timeout)
  end

  @doc """
  Initiate an automatic ransomware rollback.

  Scans for encrypted files, finds the best pre-attack snapshot, restores
  original files, and verifies the restoration.

  ## Options

  - `:path` - Root path to scan (default: "C:\\Users")
  - `:attack_time` - Unix epoch of attack detection (optional)
  - `:verify` - Whether to hash-verify (default: true)
  - `:requested_by` - User ID for audit
  """
  @spec ransomware_rollback(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def ransomware_rollback(agent_id, opts \\ %{}) do
    GenServer.call(__MODULE__, {:ransomware_rollback, agent_id, opts}, @operation_timeout)
  end

  @doc """
  Get the status of a rollback operation.
  """
  @spec get_rollback_status(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_rollback_status(operation_id) do
    GenServer.call(__MODULE__, {:get_rollback_status, operation_id})
  end

  @doc """
  List all rollback operations for an agent.
  """
  @spec list_operations(String.t(), atom() | nil) :: {:ok, [map()]}
  def list_operations(agent_id, status_filter \\ nil) do
    GenServer.call(__MODULE__, {:list_operations, agent_id, status_filter})
  end

  @doc """
  Handle a rollback result pushed from an agent.

  Called by the WebSocket channel handler when the agent sends back results.
  """
  @spec handle_result(String.t(), map()) :: :ok
  def handle_result(operation_id, result) do
    GenServer.cast(__MODULE__, {:operation_result, operation_id, result})
  end

  @doc """
  Register snapshot metadata reported by an agent.
  """
  @spec register_snapshots(String.t(), [map()]) :: :ok
  def register_snapshots(agent_id, snapshots) do
    GenServer.cast(__MODULE__, {:register_snapshots, agent_id, snapshots})
  end

  @doc """
  Get the VSS snapshot schedule for an agent.
  """
  @spec get_schedule(String.t()) :: {:ok, map()} | {:error, term()}
  def get_schedule(agent_id) do
    GenServer.call(__MODULE__, {:get_schedule, agent_id}, @operation_timeout)
  end

  @doc """
  Update the VSS snapshot schedule for an agent.
  """
  @spec set_schedule(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def set_schedule(agent_id, schedule) do
    GenServer.call(__MODULE__, {:set_schedule, agent_id, schedule}, @operation_timeout)
  end

  @doc """
  Get aggregate statistics across all agents.
  """
  @spec stats() :: map()
  def stats do
    GenServer.call(__MODULE__, :stats)
  end

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  @impl true
  def init(_opts) do
    Logger.info("[VssRollback] Starting VSS rollback orchestration service")

    # Create ETS tables
    :ets.new(@snapshots_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@operations_table, [:named_table, :set, :public, read_concurrency: true])

    schedule_cleanup()

    state = %{
      total_rollbacks: 0,
      total_successful: 0,
      total_failed: 0,
      total_files_restored: 0,
      total_bytes_restored: 0
    }

    Logger.info("[VssRollback] VSS rollback service ready")
    {:ok, state}
  end

  # --------------------------------------------------------------------------
  # Handle calls
  # --------------------------------------------------------------------------

  @impl true
  def handle_call({:list_snapshots, agent_id, opts}, _from, state) do
    force_refresh = Keyword.get(opts, :force_refresh, false)
    volume = Keyword.get(opts, :volume, "C:")

    # Check cache first
    cached = get_cached_snapshots(agent_id)

    if !force_refresh && cached != nil && !cache_expired?(cached) do
      {:reply, {:ok, cached.snapshots}, state}
    else
      # Query the agent
      case Executor.execute_action(agent_id, "list_snapshots", %{"volume" => volume}) do
        {:ok, %{"snapshots" => snapshots}} ->
          store_snapshots(agent_id, snapshots)
          {:reply, {:ok, snapshots}, state}

        {:ok, response} ->
          snapshots = Map.get(response, "result_data", %{}) |> Map.get("snapshots", [])
          store_snapshots(agent_id, snapshots)
          {:reply, {:ok, snapshots}, state}

        {:error, reason} = err ->
          Logger.error("[VssRollback] Failed to list snapshots for #{agent_id}: #{inspect(reason)}")
          {:reply, err, state}
      end
    end
  end

  def handle_call({:create_snapshot, agent_id, opts}, _from, state) do
    Logger.info("[VssRollback] Creating VSS snapshot on agent #{agent_id}")

    params = %{
      "volume" => Map.get(opts, :volume, "C:"),
      "label" => Map.get(opts, :label, "manual")
    }

    case Executor.execute_action(agent_id, "create_snapshot", params) do
      {:ok, result} ->
        # Update snapshot cache
        snapshot_data = Map.get(result, "snapshot", Map.get(result, "result_data", %{}))
        update_snapshot_cache(agent_id, snapshot_data)

        audit_log(agent_id, :snapshot_created, snapshot_data)
        broadcast_event("vss_snapshot_created", %{agent_id: agent_id, snapshot: snapshot_data})

        {:reply, {:ok, snapshot_data}, state}

      {:error, reason} = err ->
        Logger.error("[VssRollback] Snapshot creation failed on #{agent_id}: #{inspect(reason)}")
        {:reply, err, state}
    end
  end

  def handle_call({:delete_snapshot, agent_id, snapshot_id}, _from, state) do
    Logger.info("[VssRollback] Deleting snapshot #{snapshot_id} on agent #{agent_id}")

    case Executor.execute_action(agent_id, "delete_snapshot", %{"snapshot_id" => snapshot_id}) do
      {:ok, _} ->
        remove_snapshot_from_cache(agent_id, snapshot_id)
        audit_log(agent_id, :snapshot_deleted, %{snapshot_id: snapshot_id})
        {:reply, :ok, state}

      {:error, reason} = err ->
        Logger.error("[VssRollback] Snapshot deletion failed: #{inspect(reason)}")
        {:reply, err, state}
    end
  end

  def handle_call({:rollback_agent, agent_id, opts}, _from, state) do
    Logger.info("[VssRollback] 1-click rollback requested for agent #{agent_id}")

    operation = build_operation(agent_id, :rollback, opts)
    store_operation(operation)

    params = %{
      "snapshot_id" => Map.get(opts, :snapshot_id),
      "paths" => Map.get(opts, :paths, []),
      "verify" => Map.get(opts, :verify, true),
      "volume" => Map.get(opts, :volume, "C:")
    }

    # Execute asynchronously
    spawn_operation(operation, agent_id, "vss_rollback", params)

    audit_log(agent_id, :rollback_initiated, %{
      operation_id: operation.id,
      snapshot_id: Map.get(opts, :snapshot_id),
      path_count: length(Map.get(opts, :paths, []))
    })

    broadcast_event("vss_rollback_started", %{
      agent_id: agent_id,
      operation_id: operation.id
    })

    {:reply, {:ok, operation}, state}
  end

  def handle_call({:ransomware_rollback, agent_id, opts}, _from, state) do
    Logger.info("[VssRollback] Ransomware rollback requested for agent #{agent_id}")

    operation = build_operation(agent_id, :ransomware_rollback, opts)
    store_operation(operation)

    params = %{
      "path" => Map.get(opts, :path, "C:\\Users"),
      "attack_time" => Map.get(opts, :attack_time),
      "verify" => Map.get(opts, :verify, true)
    }

    spawn_operation(operation, agent_id, "vss_ransomware_rollback", params)

    audit_log(agent_id, :ransomware_rollback_initiated, %{
      operation_id: operation.id,
      root_path: Map.get(opts, :path, "C:\\Users"),
      attack_time: Map.get(opts, :attack_time)
    })

    broadcast_event("vss_ransomware_rollback_started", %{
      agent_id: agent_id,
      operation_id: operation.id
    })

    {:reply, {:ok, operation}, state}
  end

  def handle_call({:get_rollback_status, operation_id}, _from, state) do
    case find_operation(operation_id) do
      nil -> {:reply, {:error, :not_found}, state}
      op -> {:reply, {:ok, op}, state}
    end
  end

  def handle_call({:list_operations, agent_id, status_filter}, _from, state) do
    operations = get_agent_operations(agent_id)

    filtered =
      if status_filter do
        Enum.filter(operations, &(&1.status == status_filter))
      else
        operations
      end

    sorted = Enum.sort_by(filtered, & &1.created_at, {:desc, DateTime})
    {:reply, {:ok, sorted}, state}
  end

  def handle_call({:get_schedule, agent_id}, _from, state) do
    case Executor.execute_action(agent_id, "vss_get_schedule", %{}) do
      {:ok, result} ->
        schedule = Map.get(result, "result_data", result)
        {:reply, {:ok, schedule}, state}

      {:error, _} = err ->
        {:reply, err, state}
    end
  end

  def handle_call({:set_schedule, agent_id, schedule}, _from, state) do
    case Executor.execute_action(agent_id, "vss_set_schedule", schedule) do
      {:ok, result} ->
        updated = Map.get(result, "result_data", result)
        audit_log(agent_id, :schedule_updated, updated)
        {:reply, {:ok, updated}, state}

      {:error, _} = err ->
        {:reply, err, state}
    end
  end

  def handle_call(:stats, _from, state) do
    snapshot_count =
      :ets.foldl(fn {_key, _val}, acc -> acc + 1 end, 0, @snapshots_table)

    operation_count =
      :ets.foldl(fn {_key, _val}, acc -> acc + 1 end, 0, @operations_table)

    stats = %{
      total_agents_with_snapshots: snapshot_count,
      total_operations: operation_count,
      total_rollbacks: state.total_rollbacks,
      total_successful: state.total_successful,
      total_failed: state.total_failed,
      total_files_restored: state.total_files_restored,
      total_bytes_restored: state.total_bytes_restored,
      success_rate:
        if state.total_rollbacks > 0 do
          Float.round(state.total_successful / state.total_rollbacks * 100, 1)
        else
          0.0
        end
    }

    {:reply, stats, state}
  end

  # --------------------------------------------------------------------------
  # Handle casts
  # --------------------------------------------------------------------------

  @impl true
  def handle_cast({:operation_result, operation_id, result}, state) do
    case find_operation(operation_id) do
      nil ->
        Logger.warning("[VssRollback] Received result for unknown operation #{operation_id}")
        {:noreply, state}

      operation ->
        success = Map.get(result, "success", false)
        restored_count = Map.get(result, "restored_count", 0)
        bytes_restored = Map.get(result, "bytes_restored", 0)

        updated_op = %{operation |
          status: if(success, do: :completed, else: :failed),
          result: result,
          completed_at: DateTime.utc_now(),
          restored_count: restored_count,
          failed_count: Map.get(result, "failed_count", 0),
          skipped_count: Map.get(result, "skipped_count", 0),
          bytes_restored: bytes_restored,
          verification_passed: Map.get(result, "verification_passed", false),
          duration_ms: Map.get(result, "duration_ms", 0)
        }

        store_operation(updated_op)

        audit_log(operation.agent_id, :rollback_completed, %{
          operation_id: operation_id,
          success: success,
          restored_count: restored_count,
          bytes_restored: bytes_restored
        })

        broadcast_event("vss_rollback_completed", %{
          agent_id: operation.agent_id,
          operation_id: operation_id,
          success: success,
          restored_count: restored_count,
          bytes_restored: bytes_restored
        })

        new_state =
          state
          |> Map.update!(:total_rollbacks, &(&1 + 1))
          |> then(fn s ->
            if success do
              s
              |> Map.update!(:total_successful, &(&1 + 1))
              |> Map.update!(:total_files_restored, &(&1 + restored_count))
              |> Map.update!(:total_bytes_restored, &(&1 + bytes_restored))
            else
              Map.update!(s, :total_failed, &(&1 + 1))
            end
          end)

        {:noreply, new_state}
    end
  end

  def handle_cast({:register_snapshots, agent_id, snapshots}, state) do
    store_snapshots(agent_id, snapshots)
    Logger.debug("[VssRollback] Registered #{length(snapshots)} snapshots for agent #{agent_id}")
    {:noreply, state}
  end

  # --------------------------------------------------------------------------
  # Handle info
  # --------------------------------------------------------------------------

  @impl true
  def handle_info(:cleanup, state) do
    cleanup_old_operations()
    schedule_cleanup()
    {:noreply, state}
  end

  def handle_info({:operation_execution_result, operation_id, result}, state) do
    handle_cast({:operation_result, operation_id, result}, state)
  end

  def handle_info(msg, state) do
    Logger.debug("[VssRollback] Unexpected message: #{inspect(msg)}")
    {:noreply, state}
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  # -- Snapshot cache (ETS) --------------------------------------------------

  defp store_snapshots(agent_id, snapshots) when is_list(snapshots) do
    entry = %{
      agent_id: agent_id,
      snapshots: snapshots,
      cached_at: DateTime.utc_now()
    }
    :ets.insert(@snapshots_table, {agent_id, entry})
  end

  defp get_cached_snapshots(agent_id) do
    case :ets.lookup(@snapshots_table, agent_id) do
      [{^agent_id, entry}] -> entry
      [] -> nil
    end
  end

  defp cache_expired?(entry) do
    now = DateTime.utc_now()
    diff = DateTime.diff(now, entry.cached_at, :second)
    diff > @cache_ttl_seconds
  end

  defp update_snapshot_cache(agent_id, snapshot_data) when is_map(snapshot_data) do
    case get_cached_snapshots(agent_id) do
      nil ->
        store_snapshots(agent_id, [snapshot_data])

      entry ->
        updated = [snapshot_data | entry.snapshots]
        store_snapshots(agent_id, updated)
    end
  end

  defp remove_snapshot_from_cache(agent_id, snapshot_id) do
    case get_cached_snapshots(agent_id) do
      nil -> :ok
      entry ->
        updated = Enum.reject(entry.snapshots, fn s ->
          Map.get(s, "id", Map.get(s, :id)) == snapshot_id
        end)
        store_snapshots(agent_id, updated)
    end
  end

  # -- Operation storage (ETS) -----------------------------------------------

  defp store_operation(operation) do
    :ets.insert(@operations_table, {operation.id, operation})
  end

  defp find_operation(operation_id) do
    case :ets.lookup(@operations_table, operation_id) do
      [{^operation_id, op}] -> op
      [] -> nil
    end
  end

  defp get_agent_operations(agent_id) do
    :ets.foldl(
      fn {_key, op}, acc ->
        if op.agent_id == agent_id, do: [op | acc], else: acc
      end,
      [],
      @operations_table
    )
  end

  # -- Operation builder ------------------------------------------------------

  defp build_operation(agent_id, type, opts) do
    %{
      id: Ecto.UUID.generate(),
      agent_id: agent_id,
      type: type,
      status: :pending,
      requested_by: Map.get(opts, :requested_by, "system"),
      params: opts,
      result: nil,
      restored_count: 0,
      failed_count: 0,
      skipped_count: 0,
      bytes_restored: 0,
      verification_passed: false,
      duration_ms: 0,
      created_at: DateTime.utc_now(),
      started_at: nil,
      completed_at: nil
    }
  end

  # -- Async operation execution ----------------------------------------------

  defp spawn_operation(operation, agent_id, command_type, params) do
    manager_pid = self()

    Task.Supervisor.start_child(
      TamanduaServer.TaskSupervisor,
      fn -> execute_operation(manager_pid, operation, agent_id, command_type, params) end
    )
  end

  defp execute_operation(manager_pid, operation, agent_id, command_type, params) do
    Logger.info(
      "[VssRollback] Executing #{command_type} operation #{operation.id} on agent #{agent_id}"
    )

    # Update status to in_progress
    updated = %{operation | status: :in_progress, started_at: DateTime.utc_now()}
    store_operation(updated)

    result = Executor.execute_action(agent_id, command_type, params)

    case result do
      {:ok, agent_result} ->
        send(manager_pid, {:operation_execution_result, operation.id, agent_result})

      {:error, reason} ->
        error_result = %{
          "success" => false,
          "restored_count" => 0,
          "failed_count" => 0,
          "error" => inspect(reason)
        }
        send(manager_pid, {:operation_execution_result, operation.id, error_result})
    end
  end

  # -- Cleanup ----------------------------------------------------------------

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval_ms)
  end

  defp cleanup_old_operations do
    # Remove operations older than 7 days
    cutoff = DateTime.add(DateTime.utc_now(), -7 * 24 * 3600, :second)

    expired =
      :ets.foldl(
        fn {key, op}, acc ->
          if op.completed_at && DateTime.compare(op.completed_at, cutoff) == :lt do
            [key | acc]
          else
            acc
          end
        end,
        [],
        @operations_table
      )

    Enum.each(expired, fn key -> :ets.delete(@operations_table, key) end)

    if length(expired) > 0 do
      Logger.info("[VssRollback] Cleaned up #{length(expired)} old operations")
    end
  end

  # -- Audit logging ----------------------------------------------------------

  defp audit_log(agent_id, event_type, details) do
    Logger.info(
      "[VssRollback] AUDIT agent=#{agent_id} event=#{event_type} " <>
      "details=#{inspect(details, limit: 300)}"
    )

    try do
      TamanduaServer.Response.Audit.log_action(
        "vss_rollback.#{event_type}",
        details,
        agent_id,
        :system
      )
    rescue
      _ -> :ok
    end
  end

  # -- PubSub broadcast -------------------------------------------------------

  defp broadcast_event(event_name, payload) do
    try do
      TamanduaServerWeb.Endpoint.broadcast(
        "dashboard:alerts",
        event_name,
        Map.merge(payload, %{timestamp: DateTime.utc_now() |> DateTime.to_unix()})
      )
    rescue
      _ -> :ok
    end
  end
end
