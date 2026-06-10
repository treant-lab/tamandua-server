defmodule TamanduaServer.Response.ResponseHistory do
  @moduledoc """
  DETS-backed response action history.

  Tracks all response actions (kill process, quarantine file, isolate network, etc.)
  in an ETS table with periodic DETS persistence. This provides:

  1. **Audit trail** -- Every response action with timestamp, agent, alert, status, and result
     is recorded and survives process crashes and deployments.

  2. **Deduplication** -- Before executing a response action, callers can check whether
     the same action was recently taken (preventing duplicate isolations, kills, etc.).

  3. **Fast lookup** -- ETS provides sub-microsecond reads for the hot path. DETS provides
     durability across restarts.

  ## Data Lifecycle

  - On startup, the last 7 days of history are loaded from DETS into ETS.
  - Older records are pruned from DETS on load.
  - A periodic cleanup (every 6 hours) removes entries older than 7 days from ETS.
  - DETS is flushed every 60 seconds for batch durability.
  - On significant events (action recorded), a write-through to DETS is performed.

  ## ETS Record Format

      {action_key, action_record}

  Where:
  - `action_key` is `{agent_id, action_type, timestamp_unix}` for uniqueness
  - `action_record` is a map with full action details

  ## Deduplication

  `recently_executed?/3` checks if the same action type was executed on the same
  agent within a configurable window (default 5 minutes). This prevents automated
  playbooks from re-executing the same isolation or kill within a short window.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Persistence

  @ets_table :response_action_history
  @dets_flush_interval :timer.seconds(60)
  @cleanup_interval :timer.hours(6)
  @history_retention_days 7
  @default_dedup_window_seconds 300

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Record a response action in the history.

  This is called by the Executor after each action attempt (success or failure).
  The record is written through to both ETS and DETS immediately for durability.

  ## Parameters

    * `attrs` - A map with keys:
      - `:alert_id`     - Associated alert ID (may be nil for manual actions)
      - `:agent_id`     - Target agent ID (required)
      - `:action_type`  - Action type string (e.g. "kill_process", "isolate_network")
      - `:parameters`   - Action parameters map
      - `:status`       - Outcome: "success", "failed", "pending", "cancelled"
      - `:result`       - Result data map
      - `:executed_at`  - DateTime of execution (defaults to now)
  """
  @spec record(map()) :: :ok
  def record(attrs) when is_map(attrs) do
    GenServer.cast(__MODULE__, {:record, attrs})
  end

  @doc """
  Check if an action of the given type was recently executed on the given agent.

  Returns `true` if a matching action was found within the dedup window.
  Useful for preventing duplicate automated responses.

  ## Options

    * `:window_seconds` - Lookback window in seconds (default: #{@default_dedup_window_seconds})
    * `:status`         - Only consider actions with this status (default: "success")
  """
  @spec recently_executed?(String.t(), String.t(), keyword()) :: boolean()
  def recently_executed?(agent_id, action_type, opts \\ []) do
    window = Keyword.get(opts, :window_seconds, @default_dedup_window_seconds)
    status_filter = Keyword.get(opts, :status, "success")
    cutoff = System.system_time(:second) - window

    # Pattern match: look for entries for this agent + action_type within the window
    try do
      :ets.tab2list(@ets_table)
      |> Enum.any?(fn
        {{^agent_id, ^action_type, ts}, record} when ts >= cutoff ->
          record.status == status_filter

        _ ->
          false
      end)
    rescue
      ArgumentError -> false
    end
  end

  @doc """
  Get recent action history for a specific agent.

  Returns a list of action records sorted by timestamp (newest first).

  ## Options

    * `:limit`       - Maximum number of records (default: 50)
    * `:action_type` - Filter by action type
  """
  @spec get_history(String.t(), keyword()) :: [map()]
  def get_history(agent_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 50)
    action_type_filter = Keyword.get(opts, :action_type)

    try do
      :ets.tab2list(@ets_table)
      |> Enum.filter(fn
        {{^agent_id, action_type, _ts}, _record} ->
          if action_type_filter, do: action_type == action_type_filter, else: true

        _ ->
          false
      end)
      |> Enum.sort_by(fn {{_agent, _type, ts}, _record} -> ts end, :desc)
      |> Enum.take(limit)
      |> Enum.map(fn {_key, record} -> record end)
    rescue
      ArgumentError -> []
    end
  end

  @doc """
  Get overall response history statistics.
  """
  @spec stats() :: map()
  def stats do
    GenServer.call(__MODULE__, :stats)
  end

  # ---------------------------------------------------------------------------
  # GenServer Callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(_opts) do
    # Load last 7 days of history from DETS
    retention_cutoff = System.system_time(:second) - @history_retention_days * 86_400

    history_filter = fn
      {{_agent_id, _action_type, ts}, _record} when is_integer(ts) ->
        ts >= retention_cutoff

      _ ->
        false
    end

    {:ok, dets_ref} =
      Persistence.init_persistent_ets(@ets_table, "response_history",
        filter_fn: history_filter
      )

    restored = :ets.info(@ets_table, :size)

    schedule_dets_flush()
    schedule_cleanup()

    Logger.info(
      "[ResponseHistory] Initialized, restored #{restored} action records from DETS (last #{@history_retention_days} days)"
    )

    {:ok,
     %{
       dets_ref: dets_ref,
       total_recorded: 0
     }}
  end

  @impl true
  def handle_cast({:record, attrs}, state) do
    agent_id = attrs[:agent_id] || "unknown"
    action_type = to_string(attrs[:action_type] || "unknown")
    executed_at = attrs[:executed_at] || DateTime.utc_now()
    ts = DateTime.to_unix(executed_at)

    key = {agent_id, action_type, ts}

    record = %{
      alert_id: attrs[:alert_id],
      agent_id: agent_id,
      action_type: action_type,
      parameters: attrs[:parameters] || %{},
      status: to_string(attrs[:status] || "unknown"),
      result: attrs[:result],
      executed_at: executed_at,
      recorded_at: DateTime.utc_now()
    }

    # Write-through: each action is immediately persisted
    Persistence.write_through(@ets_table, state.dets_ref, key, record)

    {:noreply, %{state | total_recorded: state.total_recorded + 1}}
  end

  @impl true
  def handle_call(:stats, _from, state) do
    total_in_memory = :ets.info(@ets_table, :size)

    # Count by status
    status_counts =
      try do
        :ets.tab2list(@ets_table)
        |> Enum.reduce(%{}, fn {_key, record}, acc ->
          status = record[:status] || "unknown"
          Map.update(acc, status, 1, &(&1 + 1))
        end)
      rescue
        ArgumentError -> %{}
      end

    result = %{
      total_in_memory: total_in_memory,
      total_recorded_this_session: state.total_recorded,
      retention_days: @history_retention_days,
      by_status: status_counts
    }

    {:reply, result, state}
  end

  @impl true
  def handle_info(:dets_flush, state) do
    Persistence.flush(@ets_table, state.dets_ref)
    schedule_dets_flush()
    Logger.debug("[ResponseHistory] DETS flush completed")
    {:noreply, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    # Remove entries older than retention window
    cutoff = System.system_time(:second) - @history_retention_days * 86_400

    removed =
      try do
        :ets.tab2list(@ets_table)
        |> Enum.reduce(0, fn
          {{_agent, _type, ts} = key, _record}, count when ts < cutoff ->
            :ets.delete(@ets_table, key)
            count + 1

          _, count ->
            count
        end)
      rescue
        ArgumentError -> 0
      end

    if removed > 0 do
      Logger.info("[ResponseHistory] Cleaned up #{removed} expired action records")
    end

    schedule_cleanup()
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    if dets_ref = state[:dets_ref] do
      Logger.info("[ResponseHistory] Shutting down, flushing history to DETS")
      Persistence.flush(@ets_table, dets_ref)
      Persistence.close(dets_ref)
    end

    :ok
  end

  # ---------------------------------------------------------------------------
  # Private
  # ---------------------------------------------------------------------------

  defp schedule_dets_flush do
    Process.send_after(self(), :dets_flush, @dets_flush_interval)
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval)
  end
end
