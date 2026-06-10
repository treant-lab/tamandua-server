defmodule TamanduaServer.Response.RollbackManager do
  @moduledoc """
  System-State Rollback Manager

  Provides SentinelOne-class rollback orchestration across all managed agents.
  This GenServer tracks rollback snapshots per agent, coordinates rollback
  operations via WebSocket commands, and maintains a full audit trail.

  ## Capabilities

  - **Snapshot tracking**: ETS-backed per-agent snapshot metadata cache.
  - **Rollback orchestration**: Trigger full, selective, or dry-run rollbacks
    on remote agents via the existing WebSocket command channel.
  - **Status & progress**: Track in-flight rollback operations with status
    updates from agents.
  - **Diff API**: Request a diff between two snapshots to understand what
    changed (useful for incident investigation).
  - **Approval workflow**: Optional admin approval gate before executing
    destructive rollbacks.
  - **Audit logging**: Every rollback request, approval, execution, and
    result is logged to the audit trail and broadcast to the dashboard.

  ## Architecture

      [Dashboard/API] --> [RollbackManager GenServer]
                                  |                   |
                          [ETS: snapshots]    [ETS: requests]
                                  |
                          [Executor] --> [WebSocket] --> [Agent]
                                                            |
                                                     [RollbackEngine]
                                                            |
                                              [result pushed back] --> [RollbackManager]

  ## Snapshot Metadata Schema (per agent)

      %{
        id: uuid,
        agent_id: uuid,
        trigger: :automatic | :manual | :pre_remediation,
        trigger_context: %{alert_id: uuid, action: "kill_process"},
        categories: [:registry, :services, :tasks, :firewall, :files, :network],
        item_counts: %{registry_keys: 150, services: 45, tasks: 12, ...},
        size_bytes: 245_000,
        created_at: datetime,
        expires_at: datetime,
        status: :complete | :partial | :expired
      }

  ## Rollback Request Schema

      %{
        id: uuid,
        snapshot_id: uuid,
        agent_id: uuid,
        requested_by: user_id,
        categories: [:registry, :services],
        mode: :full | :selective | :dry_run,
        status: :pending_approval | :pending | :in_progress | :completed | :failed | :rolled_back,
        changes_applied: 45,
        changes_failed: 2,
        errors: [],
        started_at: datetime,
        completed_at: datetime
      }
  """

  use GenServer
  require Logger

  alias TamanduaServer.Response.Executor

  # ETS table names
  @snapshots_table :rollback_snapshots
  @requests_table :rollback_requests

  # Snapshot expiry (7 days by default)
  @default_snapshot_ttl_seconds 7 * 24 * 3600

  # Rollback command timeout
  @rollback_timeout 300_000  # 5 minutes

  # Periodic cleanup interval (every hour)
  @cleanup_interval_ms 3_600_000

  # Require approval for full rollbacks by default
  @require_approval_for_full true

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Register a snapshot reported by an agent.

  Called when an agent sends snapshot metadata (either from an automatic
  periodic snapshot or after a server-triggered snapshot).
  """
  @spec register_snapshot(String.t(), map()) :: :ok
  def register_snapshot(agent_id, snapshot_metadata) do
    GenServer.cast(__MODULE__, {:register_snapshot, agent_id, snapshot_metadata})
  end

  @doc """
  List all snapshots for a given agent.

  Returns a list of snapshot metadata maps, sorted newest first.
  """
  @spec list_snapshots(String.t()) :: {:ok, [map()]}
  def list_snapshots(agent_id) do
    GenServer.call(__MODULE__, {:list_snapshots, agent_id})
  end

  @doc """
  Get metadata for a specific snapshot.
  """
  @spec get_snapshot(String.t(), String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_snapshot(agent_id, snapshot_id) do
    GenServer.call(__MODULE__, {:get_snapshot, agent_id, snapshot_id})
  end

  @doc """
  Trigger creation of a new system-state snapshot on an agent.

  Sends a command to the agent to capture its current state. The agent will
  reply with snapshot metadata which is automatically registered.
  """
  @spec create_snapshot(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def create_snapshot(agent_id, opts \\ %{}) do
    GenServer.call(__MODULE__, {:create_snapshot, agent_id, opts}, @rollback_timeout)
  end

  @doc """
  Request a rollback to a specific snapshot.

  ## Modes

  - `:full` - Roll back all categories in the snapshot.
  - `:selective` - Roll back only the specified categories.
  - `:dry_run` - Generate a rollback plan without executing.

  ## Options

  - `:requested_by` - User ID requesting the rollback.
  - `:categories` - List of categories for selective mode.
  - `:skip_approval` - Boolean, skip approval workflow (requires admin).
  """
  @spec request_rollback(String.t(), String.t(), atom(), map()) ::
          {:ok, map()} | {:error, term()}
  def request_rollback(agent_id, snapshot_id, mode \\ :full, opts \\ %{}) do
    GenServer.call(__MODULE__, {:request_rollback, agent_id, snapshot_id, mode, opts}, @rollback_timeout)
  end

  @doc """
  Approve a pending rollback request.

  Only applies when the approval workflow is enabled. Approving a request
  will trigger immediate execution.
  """
  @spec approve_rollback(String.t(), String.t()) :: {:ok, map()} | {:error, term()}
  def approve_rollback(request_id, approved_by) do
    GenServer.call(__MODULE__, {:approve_rollback, request_id, approved_by}, @rollback_timeout)
  end

  @doc """
  Reject a pending rollback request.
  """
  @spec reject_rollback(String.t(), String.t(), String.t()) :: :ok | {:error, term()}
  def reject_rollback(request_id, rejected_by, reason \\ "") do
    GenServer.call(__MODULE__, {:reject_rollback, request_id, rejected_by, reason})
  end

  @doc """
  Get the status and details of a rollback request.
  """
  @spec get_rollback_status(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_rollback_status(request_id) do
    GenServer.call(__MODULE__, {:get_rollback_status, request_id})
  end

  @doc """
  List all rollback requests for an agent, optionally filtered by status.
  """
  @spec list_rollback_requests(String.t(), atom() | nil) :: {:ok, [map()]}
  def list_rollback_requests(agent_id, status_filter \\ nil) do
    GenServer.call(__MODULE__, {:list_rollback_requests, agent_id, status_filter})
  end

  @doc """
  Request a diff between two snapshots on an agent.

  The diff is computed agent-side since only the agent has the full snapshot
  data. Returns registry, service, task, firewall, file, and env changes.
  """
  @spec diff_snapshots(String.t(), String.t(), String.t()) :: {:ok, map()} | {:error, term()}
  def diff_snapshots(agent_id, base_snapshot_id, target_snapshot_id) do
    GenServer.call(__MODULE__, {:diff_snapshots, agent_id, base_snapshot_id, target_snapshot_id}, @rollback_timeout)
  end

  @doc """
  Delete a snapshot from the agent and remove tracking metadata.
  """
  @spec delete_snapshot(String.t(), String.t()) :: :ok | {:error, term()}
  def delete_snapshot(agent_id, snapshot_id) do
    GenServer.call(__MODULE__, {:delete_snapshot, agent_id, snapshot_id})
  end

  @doc """
  Handle a result callback from an agent after a rollback completes.

  This is called by the WebSocket channel handler when the agent pushes
  a rollback_result event.
  """
  @spec handle_rollback_result(String.t(), map()) :: :ok
  def handle_rollback_result(request_id, result) do
    GenServer.cast(__MODULE__, {:rollback_result, request_id, result})
  end

  @doc """
  Get rollback statistics across all agents.
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
    Logger.info("[RollbackManager] Starting system-state rollback manager")

    # Create ETS tables.
    :ets.new(@snapshots_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@requests_table, [:named_table, :set, :public, read_concurrency: true])

    # Schedule periodic cleanup.
    schedule_cleanup()

    state = %{
      snapshot_count: 0,
      request_count: 0,
      total_rollbacks_executed: 0,
      total_rollbacks_succeeded: 0,
      total_rollbacks_failed: 0,
      require_approval: @require_approval_for_full,
      snapshot_ttl_seconds: @default_snapshot_ttl_seconds
    }

    Logger.info("[RollbackManager] Rollback manager ready")
    {:ok, state}
  end

  # --------------------------------------------------------------------------
  # Handle calls
  # --------------------------------------------------------------------------

  @impl true
  def handle_call({:list_snapshots, agent_id}, _from, state) do
    snapshots = get_agent_snapshots(agent_id)
    sorted = Enum.sort_by(snapshots, & &1.created_at, {:desc, DateTime})
    {:reply, {:ok, sorted}, state}
  end

  def handle_call({:get_snapshot, agent_id, snapshot_id}, _from, state) do
    case find_snapshot(agent_id, snapshot_id) do
      nil -> {:reply, {:error, :not_found}, state}
      snapshot -> {:reply, {:ok, snapshot}, state}
    end
  end

  def handle_call({:create_snapshot, agent_id, opts}, _from, state) do
    Logger.info("[RollbackManager] Creating snapshot on agent #{agent_id}")

    params = %{
      "categories" => Map.get(opts, :categories),
      "alert_id" => Map.get(opts, :alert_id),
      "action" => Map.get(opts, :action, "manual")
    }

    case Executor.execute_response(nil, %{
      action_type: "create_system_snapshot",
      agent_id: agent_id,
      params: params
    }) do
      {:ok, result} ->
        # Agent returns snapshot metadata -- register it.
        snapshot_meta = build_snapshot_metadata(agent_id, result)
        store_snapshot(agent_id, snapshot_meta)

        audit_log(agent_id, :snapshot_created, %{
          snapshot_id: snapshot_meta.id,
          categories: snapshot_meta.categories,
          item_counts: snapshot_meta.item_counts
        })

        new_state = %{state | snapshot_count: state.snapshot_count + 1}
        {:reply, {:ok, snapshot_meta}, new_state}

      {:error, reason} = err ->
        Logger.error("[RollbackManager] Failed to create snapshot on #{agent_id}: #{inspect(reason)}")
        {:reply, err, state}
    end
  end

  def handle_call({:request_rollback, agent_id, snapshot_id, mode, opts}, _from, state) do
    Logger.info(
      "[RollbackManager] Rollback requested on agent #{agent_id}, " <>
      "snapshot=#{snapshot_id}, mode=#{mode}"
    )

    # Validate snapshot exists.
    case find_snapshot(agent_id, snapshot_id) do
      nil ->
        {:reply, {:error, :snapshot_not_found}, state}

      _snapshot ->
        request = build_rollback_request(agent_id, snapshot_id, mode, opts)

        # Check if approval is required.
        needs_approval =
          state.require_approval &&
          mode == :full &&
          !Map.get(opts, :skip_approval, false)

        if needs_approval do
          # Store as pending_approval.
          request = %{request | status: :pending_approval}
          store_request(request)

          audit_log(agent_id, :rollback_pending_approval, %{
            request_id: request.id,
            snapshot_id: snapshot_id,
            mode: mode
          })

          broadcast_rollback_event("rollback_pending_approval", request)

          new_state = %{state | request_count: state.request_count + 1}
          {:reply, {:ok, request}, new_state}
        else
          # Execute immediately.
          request = %{request | status: :pending}
          store_request(request)

          new_state = %{state | request_count: state.request_count + 1}

          # Execute rollback asynchronously.
          spawn_rollback_execution(request)

          {:reply, {:ok, request}, new_state}
        end
    end
  end

  def handle_call({:approve_rollback, request_id, approved_by}, _from, state) do
    case find_request(request_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      %{status: :pending_approval} = request ->
        Logger.info("[RollbackManager] Rollback #{request_id} approved by #{approved_by}")

        request = %{request |
          status: :pending,
          approved_by: approved_by,
          approved_at: DateTime.utc_now()
        }
        store_request(request)

        audit_log(request.agent_id, :rollback_approved, %{
          request_id: request_id,
          approved_by: approved_by
        })

        # Execute.
        spawn_rollback_execution(request)

        {:reply, {:ok, request}, state}

      %{status: status} ->
        {:reply, {:error, {:invalid_status, status}}, state}
    end
  end

  def handle_call({:reject_rollback, request_id, rejected_by, reason}, _from, state) do
    case find_request(request_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      %{status: :pending_approval} = request ->
        Logger.info("[RollbackManager] Rollback #{request_id} rejected by #{rejected_by}: #{reason}")

        request = %{request |
          status: :rejected,
          rejected_by: rejected_by,
          rejected_at: DateTime.utc_now(),
          rejection_reason: reason
        }
        store_request(request)

        audit_log(request.agent_id, :rollback_rejected, %{
          request_id: request_id,
          rejected_by: rejected_by,
          reason: reason
        })

        broadcast_rollback_event("rollback_rejected", request)

        {:reply, :ok, state}

      %{status: status} ->
        {:reply, {:error, {:invalid_status, status}}, state}
    end
  end

  def handle_call({:get_rollback_status, request_id}, _from, state) do
    case find_request(request_id) do
      nil -> {:reply, {:error, :not_found}, state}
      request -> {:reply, {:ok, request}, state}
    end
  end

  def handle_call({:list_rollback_requests, agent_id, status_filter}, _from, state) do
    requests = get_agent_requests(agent_id)

    filtered =
      if status_filter do
        Enum.filter(requests, &(&1.status == status_filter))
      else
        requests
      end

    sorted = Enum.sort_by(filtered, & &1.created_at, {:desc, DateTime})
    {:reply, {:ok, sorted}, state}
  end

  def handle_call({:diff_snapshots, agent_id, base_id, target_id}, _from, state) do
    Logger.info("[RollbackManager] Requesting diff on agent #{agent_id}: #{base_id} vs #{target_id}")

    params = %{
      "base_snapshot_id" => base_id,
      "target_snapshot_id" => target_id
    }

    case Executor.execute_response(nil, %{
      action_type: "snapshot_diff",
      agent_id: agent_id,
      params: params
    }) do
      {:ok, diff} ->
        {:reply, {:ok, diff}, state}

      {:error, reason} = err ->
        Logger.error("[RollbackManager] Diff failed on #{agent_id}: #{inspect(reason)}")
        {:reply, err, state}
    end
  end

  def handle_call({:delete_snapshot, agent_id, snapshot_id}, _from, state) do
    Logger.info("[RollbackManager] Deleting snapshot #{snapshot_id} on agent #{agent_id}")

    # Delete from agent.
    _ = Executor.execute_response(nil, %{
      action_type: "delete_system_snapshot",
      agent_id: agent_id,
      params: %{"snapshot_id" => snapshot_id}
    })

    # Remove from ETS.
    remove_snapshot(agent_id, snapshot_id)

    audit_log(agent_id, :snapshot_deleted, %{snapshot_id: snapshot_id})

    {:reply, :ok, state}
  end

  def handle_call(:stats, _from, state) do
    snapshot_count =
      :ets.foldl(fn {_key, _val}, acc -> acc + 1 end, 0, @snapshots_table)

    request_count =
      :ets.foldl(fn {_key, _val}, acc -> acc + 1 end, 0, @requests_table)

    stats = %{
      total_snapshots_tracked: snapshot_count,
      total_requests: request_count,
      total_rollbacks_executed: state.total_rollbacks_executed,
      total_rollbacks_succeeded: state.total_rollbacks_succeeded,
      total_rollbacks_failed: state.total_rollbacks_failed,
      require_approval: state.require_approval,
      snapshot_ttl_seconds: state.snapshot_ttl_seconds
    }

    {:reply, stats, state}
  end

  # --------------------------------------------------------------------------
  # Handle casts
  # --------------------------------------------------------------------------

  @impl true
  def handle_cast({:register_snapshot, agent_id, metadata}, state) do
    snapshot_meta = build_snapshot_metadata(agent_id, metadata)
    store_snapshot(agent_id, snapshot_meta)
    Logger.debug("[RollbackManager] Registered snapshot #{snapshot_meta.id} for agent #{agent_id}")
    {:noreply, %{state | snapshot_count: state.snapshot_count + 1}}
  end

  def handle_cast({:rollback_result, request_id, result}, state) do
    case find_request(request_id) do
      nil ->
        Logger.warning("[RollbackManager] Received result for unknown request #{request_id}")
        {:noreply, state}

      request ->
        completed_at = DateTime.utc_now()
        success = Map.get(result, "success", false)

        updated_request = %{request |
          status: if(success, do: :completed, else: :failed),
          changes_applied: Map.get(result, "changes_applied", 0),
          changes_failed: Map.get(result, "changes_failed", 0),
          changes_skipped: Map.get(result, "changes_skipped", 0),
          errors: Map.get(result, "errors", []),
          plan: Map.get(result, "plan", []),
          verification_passed: Map.get(result, "verification_passed", false),
          pre_rollback_snapshot_id: Map.get(result, "pre_rollback_snapshot_id"),
          completed_at: completed_at
        }

        store_request(updated_request)

        audit_log(request.agent_id, :rollback_completed, %{
          request_id: request_id,
          success: success,
          changes_applied: updated_request.changes_applied,
          changes_failed: updated_request.changes_failed,
          verification_passed: updated_request.verification_passed
        })

        broadcast_rollback_event("rollback_completed", updated_request)

        new_state =
          state
          |> Map.update!(:total_rollbacks_executed, &(&1 + 1))
          |> then(fn s ->
            if success do
              Map.update!(s, :total_rollbacks_succeeded, &(&1 + 1))
            else
              Map.update!(s, :total_rollbacks_failed, &(&1 + 1))
            end
          end)

        {:noreply, new_state}
    end
  end

  # --------------------------------------------------------------------------
  # Handle info (periodic cleanup, async rollback results)
  # --------------------------------------------------------------------------

  @impl true
  def handle_info(:cleanup_expired, state) do
    cleanup_expired_snapshots(state.snapshot_ttl_seconds)
    schedule_cleanup()
    {:noreply, state}
  end

  def handle_info({:rollback_execution_result, request_id, result}, state) do
    # This is the same as the cast path but via info (from the spawned task).
    handle_cast({:rollback_result, request_id, result}, state)
  end

  def handle_info(msg, state) do
    Logger.debug("[RollbackManager] Unexpected message: #{inspect(msg)}")
    {:noreply, state}
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  # -- Snapshot storage (ETS) -----------------------------------------------

  defp store_snapshot(agent_id, snapshot_meta) do
    key = {agent_id, snapshot_meta.id}
    :ets.insert(@snapshots_table, {key, snapshot_meta})
  end

  defp find_snapshot(agent_id, snapshot_id) do
    key = {agent_id, snapshot_id}
    case :ets.lookup(@snapshots_table, key) do
      [{^key, snapshot}] -> snapshot
      [] -> nil
    end
  end

  defp remove_snapshot(agent_id, snapshot_id) do
    key = {agent_id, snapshot_id}
    :ets.delete(@snapshots_table, key)
  end

  defp get_agent_snapshots(agent_id) do
    # Match all snapshots for this agent.
    match_spec = [{{{agent_id, :_}, :"$1"}, [], [:"$1"]}]
    :ets.select(@snapshots_table, match_spec)
  end

  # -- Request storage (ETS) ------------------------------------------------

  defp store_request(request) do
    :ets.insert(@requests_table, {request.id, request})
  end

  defp find_request(request_id) do
    case :ets.lookup(@requests_table, request_id) do
      [{^request_id, request}] -> request
      [] -> nil
    end
  end

  defp get_agent_requests(agent_id) do
    # Scan all requests for this agent.
    :ets.foldl(
      fn {_key, request}, acc ->
        if request.agent_id == agent_id, do: [request | acc], else: acc
      end,
      [],
      @requests_table
    )
  end

  # -- Snapshot metadata builder --------------------------------------------

  defp build_snapshot_metadata(agent_id, result) when is_map(result) do
    now = DateTime.utc_now()

    trigger =
      cond do
        is_map_key(result, "trigger") -> parse_trigger(result["trigger"])
        is_map_key(result, :trigger) -> parse_trigger(result[:trigger])
        true -> :manual
      end

    trigger_context =
      cond do
        is_map_key(result, "trigger_context") -> result["trigger_context"]
        is_map_key(result, :trigger_context) -> result[:trigger_context]
        true -> %{}
      end

    categories =
      cond do
        is_map_key(result, "categories") -> result["categories"] || []
        is_map_key(result, :categories) -> result[:categories] || []
        true -> []
      end

    item_counts =
      cond do
        is_map_key(result, "item_counts") -> result["item_counts"] || %{}
        is_map_key(result, :item_counts) -> result[:item_counts] || %{}
        true -> %{}
      end

    size_bytes =
      cond do
        is_map_key(result, "size_bytes") -> result["size_bytes"] || 0
        is_map_key(result, :size_bytes) -> result[:size_bytes] || 0
        true -> 0
      end

    snapshot_id =
      cond do
        is_map_key(result, "id") -> result["id"]
        is_map_key(result, :id) -> result[:id]
        true -> generate_id()
      end

    %{
      id: snapshot_id,
      agent_id: agent_id,
      trigger: trigger,
      trigger_context: trigger_context,
      categories: categories,
      item_counts: item_counts,
      size_bytes: size_bytes,
      created_at: now,
      expires_at: DateTime.add(now, @default_snapshot_ttl_seconds, :second),
      status: :complete
    }
  end

  defp parse_trigger(%{"type" => "pre_remediation"} = t) do
    {:pre_remediation, %{alert_id: t["alert_id"], action: t["action"]}}
  end
  defp parse_trigger(%{"type" => "automatic"}), do: :automatic
  defp parse_trigger(%{"type" => "manual"}), do: :manual
  defp parse_trigger(%{"type" => "pre_rollback"} = t) do
    {:pre_rollback, %{rollback_request_id: t["rollback_request_id"]}}
  end
  defp parse_trigger(:automatic), do: :automatic
  defp parse_trigger(:manual), do: :manual
  defp parse_trigger(_), do: :manual

  # -- Rollback request builder ---------------------------------------------

  defp build_rollback_request(agent_id, snapshot_id, mode, opts) do
    now = DateTime.utc_now()

    %{
      id: generate_id(),
      snapshot_id: snapshot_id,
      agent_id: agent_id,
      requested_by: Map.get(opts, :requested_by, "system"),
      categories: Map.get(opts, :categories, []),
      mode: mode,
      status: :pending,
      changes_applied: 0,
      changes_failed: 0,
      changes_skipped: 0,
      errors: [],
      plan: [],
      verification_passed: false,
      pre_rollback_snapshot_id: nil,
      approved_by: nil,
      approved_at: nil,
      rejected_by: nil,
      rejected_at: nil,
      rejection_reason: nil,
      created_at: now,
      started_at: nil,
      completed_at: nil
    }
  end

  # -- Rollback execution ---------------------------------------------------

  defp spawn_rollback_execution(request) do
    manager_pid = self()

    Task.Supervisor.start_child(
      TamanduaServer.TaskSupervisor,
      fn -> execute_rollback_on_agent(manager_pid, request) end
    )
  end

  defp execute_rollback_on_agent(manager_pid, request) do
    Logger.info(
      "[RollbackManager] Executing rollback #{request.id} on agent #{request.agent_id} " <>
      "(snapshot=#{request.snapshot_id}, mode=#{request.mode})"
    )

    # Update status to in_progress.
    updated = %{request | status: :in_progress, started_at: DateTime.utc_now()}
    store_request(updated)
    broadcast_rollback_event("rollback_started", updated)

    # Build agent command payload.
    mode_str = case request.mode do
      :full -> "full"
      :selective -> "selective"
      :dry_run -> "dry_run"
      other -> to_string(other)
    end

    params = %{
      "snapshot_id" => request.snapshot_id,
      "mode" => mode_str,
      "categories" => request.categories
    }

    result = Executor.execute_response(nil, %{
      action_type: "system_rollback",
      agent_id: request.agent_id,
      params: Map.put(params, "timeout", @rollback_timeout)
    })

    # Send result back to GenServer.
    case result do
      {:ok, agent_result} ->
        send(manager_pid, {:rollback_execution_result, request.id, agent_result})

      {:error, reason} ->
        error_result = %{
          "success" => false,
          "changes_applied" => 0,
          "changes_failed" => 0,
          "errors" => [inspect(reason)]
        }
        send(manager_pid, {:rollback_execution_result, request.id, error_result})
    end
  end

  # -- Cleanup --------------------------------------------------------------

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup_expired, @cleanup_interval_ms)
  end

  defp cleanup_expired_snapshots(ttl_seconds) do
    now = DateTime.utc_now()

    expired =
      :ets.foldl(
        fn {key, snapshot}, acc ->
          if snapshot.expires_at && DateTime.compare(snapshot.expires_at, now) == :lt do
            [key | acc]
          else
            acc
          end
        end,
        [],
        @snapshots_table
      )

    Enum.each(expired, fn key ->
      :ets.delete(@snapshots_table, key)
    end)

    if length(expired) > 0 do
      Logger.info("[RollbackManager] Cleaned up #{length(expired)} expired snapshots (TTL=#{ttl_seconds}s)")
    end
  end

  # -- Audit logging --------------------------------------------------------

  defp audit_log(agent_id, event_type, details) do
    Logger.info(
      "[RollbackManager] AUDIT agent=#{agent_id} event=#{event_type} " <>
      "details=#{inspect(details, limit: 300)}"
    )

    # Also persist via the Audit module if available.
    try do
      TamanduaServer.Response.Audit.log_action(
        "rollback.#{event_type}",
        details,
        agent_id,
        :system
      )
    rescue
      _ -> :ok
    end
  end

  # -- Dashboard broadcast --------------------------------------------------

  defp broadcast_rollback_event(event_name, payload) do
    try do
      TamanduaServerWeb.Endpoint.broadcast(
        "dashboard:alerts",
        event_name,
        %{
          request_id: Map.get(payload, :id),
          agent_id: Map.get(payload, :agent_id),
          snapshot_id: Map.get(payload, :snapshot_id),
          mode: Map.get(payload, :mode),
          status: Map.get(payload, :status),
          changes_applied: Map.get(payload, :changes_applied, 0),
          changes_failed: Map.get(payload, :changes_failed, 0),
          timestamp: DateTime.utc_now() |> DateTime.to_unix()
        }
      )
    rescue
      _ -> :ok
    end
  end

  # -- Utilities ------------------------------------------------------------

  defp generate_id do
    Ecto.UUID.generate()
  end
end
