defmodule TamanduaServer.Updates.CanaryRollout do
  @moduledoc """
  Manages staged canary rollout for agent updates.

  Stages: canary (5%) -> early (25%) -> general (100%)

  Each stage has a minimum soak time and success threshold before
  automatically advancing. High failure rates trigger automatic rollback.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Updates.FailureDetector

  @stages [:canary, :early, :general, :paused, :rolled_back]
  @stage_percentages %{canary: 5.0, early: 25.0, general: 100.0, paused: 0.0, rolled_back: 0.0}
  @min_soak_times %{canary: 3600, early: 7200, general: 0}  # seconds
  @min_success_counts %{canary: 10, early: 50, general: 0}

  defstruct [
    :version,
    :previous_version,
    stage: :canary,
    stage_started_at: nil,
    success_count: 0,
    failure_count: 0,
    paused_reason: nil,
    agents_updated: MapSet.new()
  ]

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc "Get rollout percentage for a version."
  def get_rollout_percentage(version) do
    GenServer.call(__MODULE__, {:get_percentage, version})
  end

  @doc "Start a new rollout for a version."
  def start_rollout(version, previous_version) do
    GenServer.call(__MODULE__, {:start_rollout, version, previous_version})
  end

  @doc "Record an update report from an agent."
  def record_update_report(version, success, agent_id) do
    GenServer.cast(__MODULE__, {:record_report, version, success, agent_id})
  end

  @doc "Manually advance to next stage."
  def advance_stage(version) do
    GenServer.call(__MODULE__, {:advance_stage, version})
  end

  @doc "Pause rollout due to issues."
  def pause_rollout(version, reason) do
    GenServer.call(__MODULE__, {:pause, version, reason})
  end

  @doc "Resume a paused rollout."
  def resume_rollout(version) do
    GenServer.call(__MODULE__, {:resume, version})
  end

  @doc "Rollback to previous version."
  def rollback(version) do
    GenServer.call(__MODULE__, {:rollback, version})
  end

  @doc "Get current rollout state."
  def get_state(version) do
    GenServer.call(__MODULE__, {:get_state, version})
  end

  @doc "List all active rollouts."
  def list_rollouts do
    GenServer.call(__MODULE__, :list_rollouts)
  end

  @doc "Get available stages."
  def stages, do: @stages

  @doc "Get stage percentages map."
  def stage_percentages, do: @stage_percentages

  # Server callbacks

  @impl true
  def init(_opts) do
    # ETS table for rollout states
    :ets.new(:canary_rollouts, [:named_table, :set, :public, read_concurrency: true])
    Logger.info("CanaryRollout GenServer started")
    {:ok, %{}}
  end

  @impl true
  def handle_call({:get_percentage, version}, _from, state) do
    percentage = case :ets.lookup(:canary_rollouts, version) do
      [{^version, rollout}] -> Map.get(@stage_percentages, rollout.stage, 0.0)
      [] -> 0.0
    end
    {:reply, percentage, state}
  end

  @impl true
  def handle_call({:start_rollout, version, previous_version}, _from, state) do
    rollout = %__MODULE__{
      version: version,
      previous_version: previous_version,
      stage: :canary,
      stage_started_at: System.system_time(:second)
    }
    :ets.insert(:canary_rollouts, {version, rollout})
    Logger.info("Started canary rollout for #{version} (from #{previous_version})")
    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:advance_stage, version}, _from, state) do
    result = case :ets.lookup(:canary_rollouts, version) do
      [{^version, rollout}] ->
        case next_stage(rollout.stage) do
          nil -> {:error, :already_at_final_stage}
          next ->
            updated = %{rollout |
              stage: next,
              stage_started_at: System.system_time(:second),
              success_count: 0,
              failure_count: 0
            }
            :ets.insert(:canary_rollouts, {version, updated})
            Logger.info("Advanced #{version} to stage #{next}")
            {:ok, next}
        end
      [] -> {:error, :not_found}
    end
    {:reply, result, state}
  end

  @impl true
  def handle_call({:pause, version, reason}, _from, state) do
    case :ets.lookup(:canary_rollouts, version) do
      [{^version, rollout}] ->
        updated = %{rollout | stage: :paused, paused_reason: reason}
        :ets.insert(:canary_rollouts, {version, updated})
        Logger.warning("Paused rollout for #{version}: #{reason}")
        {:reply, :ok, state}
      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:resume, version}, _from, state) do
    case :ets.lookup(:canary_rollouts, version) do
      [{^version, %{stage: :paused} = rollout}] ->
        # Resume to early stage (or canary if that was the original stage)
        resume_stage = if rollout.success_count >= @min_success_counts[:canary], do: :early, else: :canary
        updated = %{rollout |
          stage: resume_stage,
          stage_started_at: System.system_time(:second),
          paused_reason: nil
        }
        :ets.insert(:canary_rollouts, {version, updated})
        Logger.info("Resumed rollout for #{version} at stage #{resume_stage}")
        {:reply, {:ok, resume_stage}, state}
      [{^version, _rollout}] ->
        {:reply, {:error, :not_paused}, state}
      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:rollback, version}, _from, state) do
    case :ets.lookup(:canary_rollouts, version) do
      [{^version, rollout}] ->
        updated = %{rollout | stage: :rolled_back}
        :ets.insert(:canary_rollouts, {version, updated})
        Logger.error("Rolled back version #{version} to #{rollout.previous_version}")
        {:reply, {:ok, rollout.previous_version}, state}
      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:get_state, version}, _from, state) do
    result = case :ets.lookup(:canary_rollouts, version) do
      [{^version, rollout}] -> {:ok, rollout}
      [] -> {:error, :not_found}
    end
    {:reply, result, state}
  end

  @impl true
  def handle_call(:list_rollouts, _from, state) do
    rollouts = :ets.tab2list(:canary_rollouts)
      |> Enum.map(fn {version, rollout} -> {version, rollout} end)
      |> Enum.into(%{})
    {:reply, rollouts, state}
  end

  @impl true
  def handle_cast({:record_report, version, success, agent_id}, state) do
    case :ets.lookup(:canary_rollouts, version) do
      [{^version, rollout}] ->
        updated = if success do
          %{rollout |
            success_count: rollout.success_count + 1,
            agents_updated: MapSet.put(rollout.agents_updated, agent_id)
          }
        else
          %{rollout | failure_count: rollout.failure_count + 1}
        end
        :ets.insert(:canary_rollouts, {version, updated})

        # Log the update
        Logger.debug(
          "Update report for #{version} from #{agent_id}: success=#{success}, " <>
          "total_success=#{updated.success_count}, total_failure=#{updated.failure_count}"
        )

        # Check for auto-advance or rollback
        check_stage_transition(version, updated)
      [] ->
        :ok
    end
    {:noreply, state}
  end

  # Private functions

  defp next_stage(:canary), do: :early
  defp next_stage(:early), do: :general
  defp next_stage(_), do: nil

  defp check_stage_transition(version, rollout) do
    failure_rate = FailureDetector.calculate_failure_rate(
      rollout.success_count,
      rollout.failure_count
    )

    # Auto-rollback on high failure rate (only if we have enough samples)
    if failure_rate > 0.05 and rollout.failure_count >= 3 do
      Logger.error("Auto-rollback triggered for #{version}: failure rate #{Float.round(failure_rate * 100, 2)}%")
      GenServer.call(__MODULE__, {:rollback, version})
      :rolled_back
    else
      # Auto-advance if conditions met
      min_soak = Map.get(@min_soak_times, rollout.stage, :infinity)
      min_success = Map.get(@min_success_counts, rollout.stage, :infinity)
      elapsed = System.system_time(:second) - (rollout.stage_started_at || 0)

      if elapsed >= min_soak and rollout.success_count >= min_success and failure_rate < 0.02 do
        case GenServer.call(__MODULE__, {:advance_stage, version}) do
          {:ok, new_stage} -> new_stage
          _ -> rollout.stage
        end
      else
        rollout.stage
      end
    end
  end
end
