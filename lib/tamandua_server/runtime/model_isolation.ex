defmodule TamanduaServer.Runtime.ModelIsolation do
  @moduledoc """
  GenServer that manages model isolation state with persistence.

  Tracks isolation status of AI/ML models running on agents, supporting
  multiple isolation modes and automatic release scheduling.

  ## Isolation Modes

  - `:none` - Model is active and operating normally
  - `:network` - Block model API calls (network isolation only)
  - `:process` - Suspend model process
  - `:memory` - Clear model context/cache
  - `:full` - All isolation measures applied

  ## State Transitions

  - `:active` -> `:isolated` (via isolate/3)
  - `:isolated` -> `:active` (via release/1)
  - `:active` | `:isolated` -> `:killed` (terminal state, via kill/2)

  ## Persistence

  State changes are persisted to the `model_isolation_history` table
  for audit trail and recovery after restarts.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Repo

  @ets_table :model_isolation_state
  @pubsub TamanduaServer.PubSub

  @type isolation_mode :: :none | :network | :process | :memory | :full
  @type model_status :: :active | :isolated | :killed

  @type model_state :: %{
          model_id: String.t(),
          agent_id: String.t(),
          status: model_status(),
          isolation_mode: isolation_mode(),
          isolated_at: DateTime.t() | nil,
          isolated_by: String.t() | nil,
          reason: String.t() | nil,
          auto_release_at: DateTime.t() | nil,
          metadata: map()
        }

  # ── Client API ─────────────────────────────────────────────────────

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Isolate a model, transitioning it from :active to :isolated state.

  ## Options

  - `:mode` - Isolation mode (`:network`, `:process`, `:memory`, `:full`). Default: `:full`
  - `:reason` - String describing why isolation was triggered
  - `:isolated_by` - User or system identifier that triggered isolation
  - `:duration_seconds` - Auto-release after duration (0 = indefinite). Default: 0
  - `:metadata` - Additional metadata to store with isolation state

  ## Returns

  - `{:ok, model_state}` - Model successfully isolated
  - `{:error, :already_isolated}` - Model is already isolated
  - `{:error, :already_killed}` - Model is in terminal killed state
  - `{:error, :model_not_found}` - Model not found (creates new entry)
  """
  @spec isolate(String.t(), String.t(), keyword()) :: {:ok, model_state()} | {:error, atom()}
  def isolate(model_id, agent_id, opts \\ []) do
    GenServer.call(__MODULE__, {:isolate, model_id, agent_id, opts})
  end

  @doc """
  Release an isolated model, transitioning it back to :active state.

  ## Returns

  - `{:ok, model_state}` - Model successfully released
  - `{:error, :not_isolated}` - Model is not currently isolated
  - `{:error, :already_killed}` - Model is in terminal killed state
  - `{:error, :model_not_found}` - Model not found
  """
  @spec release(String.t()) :: {:ok, model_state()} | {:error, atom()}
  def release(model_id) do
    GenServer.call(__MODULE__, {:release, model_id})
  end

  @doc """
  Kill a model process permanently (terminal state).

  This is a destructive operation - the model cannot be released after being killed.

  ## Returns

  - `{:ok, model_state}` - Model successfully killed
  - `{:error, :already_killed}` - Model is already killed
  - `{:error, :model_not_found}` - Model not found
  """
  @spec kill(String.t(), String.t()) :: {:ok, model_state()} | {:error, atom()}
  def kill(model_id, agent_id) do
    GenServer.call(__MODULE__, {:kill, model_id, agent_id})
  end

  @doc """
  Get the current isolation state for a model.

  ## Returns

  - `{:ok, model_state}` - Model state found
  - `{:error, :model_not_found}` - Model not tracked
  """
  @spec get_state(String.t()) :: {:ok, model_state()} | {:error, :model_not_found}
  def get_state(model_id) do
    case :ets.lookup(@ets_table, model_id) do
      [{^model_id, state}] -> {:ok, state}
      [] -> {:error, :model_not_found}
    end
  end

  @doc """
  List all currently isolated models.

  ## Returns

  List of model states where status is :isolated
  """
  @spec list_isolated() :: [model_state()]
  def list_isolated do
    :ets.tab2list(@ets_table)
    |> Enum.map(fn {_id, state} -> state end)
    |> Enum.filter(fn state -> state.status == :isolated end)
  end

  @doc """
  List all models on a specific agent.

  ## Returns

  List of model states for the given agent
  """
  @spec list_by_agent(String.t()) :: [model_state()]
  def list_by_agent(agent_id) do
    :ets.tab2list(@ets_table)
    |> Enum.map(fn {_id, state} -> state end)
    |> Enum.filter(fn state -> state.agent_id == agent_id end)
  end

  @doc """
  Check if a model exists in the isolation tracker.
  """
  @spec exists?(String.t()) :: boolean()
  def exists?(model_id) do
    case :ets.lookup(@ets_table, model_id) do
      [{^model_id, _}] -> true
      [] -> false
    end
  end

  @doc """
  Register a new model for tracking (starts in :active state).
  """
  @spec register(String.t(), String.t(), keyword()) :: {:ok, model_state()}
  def register(model_id, agent_id, opts \\ []) do
    GenServer.call(__MODULE__, {:register, model_id, agent_id, opts})
  end

  # ── Server Callbacks ───────────────────────────────────────────────

  @impl true
  def init(_opts) do
    # Create ETS table for fast lookups
    :ets.new(@ets_table, [:set, :named_table, :public, read_concurrency: true])

    # Load persisted state from database
    load_persisted_state()

    Logger.info("[ModelIsolation] Started with #{:ets.info(@ets_table, :size)} models loaded")

    {:ok, %{auto_release_timers: %{}}}
  end

  @impl true
  def handle_call({:isolate, model_id, agent_id, opts}, _from, state) do
    mode = Keyword.get(opts, :mode, :full)
    reason = Keyword.get(opts, :reason)
    isolated_by = Keyword.get(opts, :isolated_by, "system")
    duration_seconds = Keyword.get(opts, :duration_seconds, 0)
    metadata = Keyword.get(opts, :metadata, %{})

    now = DateTime.utc_now()

    auto_release_at =
      if duration_seconds > 0 do
        DateTime.add(now, duration_seconds, :second)
      else
        nil
      end

    current_state = get_current_state(model_id)

    case validate_isolation_transition(current_state) do
      :ok ->
        new_state = %{
          model_id: model_id,
          agent_id: agent_id,
          status: :isolated,
          isolation_mode: mode,
          isolated_at: now,
          isolated_by: isolated_by,
          reason: reason,
          auto_release_at: auto_release_at,
          metadata: metadata
        }

        :ets.insert(@ets_table, {model_id, new_state})
        persist_state_change(new_state, :isolated, current_state)
        broadcast_state_change(model_id, :isolated, new_state)
        emit_telemetry(:isolated, current_state, new_state, mode)

        # Schedule auto-release if duration specified
        state =
          if duration_seconds > 0 do
            schedule_auto_release(state, model_id, duration_seconds)
          else
            state
          end

        {:reply, {:ok, new_state}, state}

      {:error, _} = error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:release, model_id}, _from, state) do
    case :ets.lookup(@ets_table, model_id) do
      [{^model_id, current_state}] ->
        case validate_release_transition(current_state) do
          :ok ->
            new_state = %{
              current_state
              | status: :active,
                isolation_mode: :none,
                isolated_at: nil,
                isolated_by: nil,
                reason: nil,
                auto_release_at: nil
            }

            :ets.insert(@ets_table, {model_id, new_state})
            persist_state_change(new_state, :released, current_state)
            broadcast_state_change(model_id, :released, new_state)
            emit_telemetry(:released, current_state, new_state, :none)

            # Cancel any pending auto-release timer
            state = cancel_auto_release_timer(state, model_id)

            {:reply, {:ok, new_state}, state}

          {:error, _} = error ->
            {:reply, error, state}
        end

      [] ->
        {:reply, {:error, :model_not_found}, state}
    end
  end

  @impl true
  def handle_call({:kill, model_id, agent_id}, _from, state) do
    current_state = get_current_state(model_id)

    case validate_kill_transition(current_state) do
      :ok ->
        now = DateTime.utc_now()

        new_state = %{
          model_id: model_id,
          agent_id: agent_id,
          status: :killed,
          isolation_mode: :full,
          isolated_at: now,
          isolated_by: "kill_switch",
          reason: "Model process terminated",
          auto_release_at: nil,
          metadata: Map.get(current_state || %{}, :metadata, %{})
        }

        :ets.insert(@ets_table, {model_id, new_state})
        persist_state_change(new_state, :killed, current_state)
        broadcast_state_change(model_id, :killed, new_state)
        emit_telemetry(:killed, current_state, new_state, :full)

        # Cancel any pending auto-release timer
        state = cancel_auto_release_timer(state, model_id)

        {:reply, {:ok, new_state}, state}

      {:error, _} = error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:register, model_id, agent_id, opts}, _from, state) do
    metadata = Keyword.get(opts, :metadata, %{})

    new_state = %{
      model_id: model_id,
      agent_id: agent_id,
      status: :active,
      isolation_mode: :none,
      isolated_at: nil,
      isolated_by: nil,
      reason: nil,
      auto_release_at: nil,
      metadata: metadata
    }

    :ets.insert(@ets_table, {model_id, new_state})

    {:reply, {:ok, new_state}, state}
  end

  @impl true
  def handle_info({:auto_release, model_id}, state) do
    Logger.info("[ModelIsolation] Auto-releasing model #{model_id}")

    case :ets.lookup(@ets_table, model_id) do
      [{^model_id, current_state}] ->
        if current_state.status == :isolated do
          new_state = %{
            current_state
            | status: :active,
              isolation_mode: :none,
              isolated_at: nil,
              isolated_by: nil,
              reason: nil,
              auto_release_at: nil
          }

          :ets.insert(@ets_table, {model_id, new_state})
          persist_state_change(new_state, :auto_released, current_state)
          broadcast_state_change(model_id, :auto_released, new_state)
          emit_telemetry(:auto_released, current_state, new_state, :none)
        end

      [] ->
        :ok
    end

    # Remove timer from state
    state = update_in(state.auto_release_timers, &Map.delete(&1, model_id))

    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ── Private Functions ──────────────────────────────────────────────

  defp get_current_state(model_id) do
    case :ets.lookup(@ets_table, model_id) do
      [{^model_id, state}] -> state
      [] -> nil
    end
  end

  defp validate_isolation_transition(nil), do: :ok
  defp validate_isolation_transition(%{status: :active}), do: :ok
  defp validate_isolation_transition(%{status: :isolated}), do: {:error, :already_isolated}
  defp validate_isolation_transition(%{status: :killed}), do: {:error, :already_killed}

  defp validate_release_transition(%{status: :isolated}), do: :ok
  defp validate_release_transition(%{status: :active}), do: {:error, :not_isolated}
  defp validate_release_transition(%{status: :killed}), do: {:error, :already_killed}

  defp validate_kill_transition(nil), do: :ok
  defp validate_kill_transition(%{status: :active}), do: :ok
  defp validate_kill_transition(%{status: :isolated}), do: :ok
  defp validate_kill_transition(%{status: :killed}), do: {:error, :already_killed}

  defp schedule_auto_release(state, model_id, duration_seconds) do
    # Cancel existing timer if any
    state = cancel_auto_release_timer(state, model_id)

    # Schedule new timer
    timer_ref = Process.send_after(self(), {:auto_release, model_id}, duration_seconds * 1000)

    update_in(state.auto_release_timers, &Map.put(&1, model_id, timer_ref))
  end

  defp cancel_auto_release_timer(state, model_id) do
    case Map.get(state.auto_release_timers, model_id) do
      nil ->
        state

      timer_ref ->
        Process.cancel_timer(timer_ref)
        update_in(state.auto_release_timers, &Map.delete(&1, model_id))
    end
  end

  defp broadcast_state_change(model_id, event, state) do
    Phoenix.PubSub.broadcast(
      @pubsub,
      "model_isolation:#{model_id}",
      {:model_isolation, event, state}
    )

    Phoenix.PubSub.broadcast(
      @pubsub,
      "model_isolation:all",
      {:model_isolation, model_id, event, state}
    )
  end

  defp emit_telemetry(event, from_state, to_state, mode) do
    from_status = if from_state, do: from_state.status, else: :untracked

    :telemetry.execute(
      [:tamandua, :model_isolation, :transition],
      %{timestamp: System.system_time(:millisecond)},
      %{
        model_id: to_state.model_id,
        agent_id: to_state.agent_id,
        from_state: from_status,
        to_state: to_state.status,
        mode: mode,
        event: event
      }
    )
  end

  defp persist_state_change(state, event, previous_state) do
    # Persist to model_isolation_history table for audit trail
    Task.start(fn ->
      try do
        attrs = %{
          model_id: state.model_id,
          agent_id: state.agent_id,
          status: to_string(state.status),
          isolation_mode: to_string(state.isolation_mode),
          event: to_string(event),
          previous_status: if(previous_state, do: to_string(previous_state.status), else: nil),
          isolated_at: state.isolated_at,
          isolated_by: state.isolated_by,
          reason: state.reason,
          auto_release_at: state.auto_release_at,
          metadata: state.metadata,
          recorded_at: DateTime.utc_now()
        }

        # Use raw SQL insert if schema doesn't exist yet
        Repo.insert_all(
          "model_isolation_history",
          [attrs],
          on_conflict: :nothing
        )
      rescue
        e ->
          Logger.warning("[ModelIsolation] Failed to persist state change: #{Exception.message(e)}")
      end
    end)
  end

  defp load_persisted_state do
    # Load the most recent state for each model from history
    try do
      query = """
      SELECT DISTINCT ON (model_id)
        model_id, agent_id, status, isolation_mode,
        isolated_at, isolated_by, reason, auto_release_at, metadata
      FROM model_isolation_history
      WHERE status != 'killed'
      ORDER BY model_id, recorded_at DESC
      """

      case Repo.query(query) do
        {:ok, %{rows: rows, columns: columns}} ->
          Enum.each(rows, fn row ->
            record = Enum.zip(columns, row) |> Map.new()

            state = %{
              model_id: record["model_id"],
              agent_id: record["agent_id"],
              status: String.to_existing_atom(record["status"] || "active"),
              isolation_mode: String.to_existing_atom(record["isolation_mode"] || "none"),
              isolated_at: record["isolated_at"],
              isolated_by: record["isolated_by"],
              reason: record["reason"],
              auto_release_at: record["auto_release_at"],
              metadata: record["metadata"] || %{}
            }

            :ets.insert(@ets_table, {state.model_id, state})
          end)

        {:error, _} ->
          # Table might not exist yet
          :ok
      end
    rescue
      _ ->
        Logger.debug("[ModelIsolation] No persisted state to load")
    end
  end
end
