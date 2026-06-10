defmodule TamanduaServer.Updates.RolloutSupervisor do
  @moduledoc """
  GenServer that monitors active rollouts and drives their lifecycle.

  Runs a periodic check (every 30 seconds) that:

  1. **Canary rollouts** -- Evaluates the failure rate of the canary group.
     If the canary group is healthy (failure rate < 5%) and enough agents
     have reported, promotes the canary to 100%. If the failure rate
     exceeds the threshold, triggers auto-rollback.

  2. **Staged rollouts** -- Checks whether the current stage's success
     criteria are met. If so, advances to the next stage. If failure rate
     is too high, pauses the rollout.

  3. **Immediate rollouts** -- Marks the rollout as completed once all
     agents have reported a terminal status (completed/failed/rolled_back).

  4. **Stale detection** -- If a rollout has been in `rolling_out` status
     for more than 24 hours with no progress, it is auto-paused.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Updates

  @check_interval :timer.seconds(30)
  # Minimum number of canary reports before auto-promoting
  @canary_min_reports_for_promotion 5
  # Failure rate threshold for auto-rollback
  @failure_threshold 5.0
  # Minimum success rate to advance staged rollouts
  @stage_min_success_rate 95.0
  # Stale rollout detection: 24 hours with no terminal reports
  @stale_hours 24

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Force an immediate check of all active rollouts.
  """
  def check_now do
    GenServer.cast(__MODULE__, :check_rollouts)
  end

  # ---------------------------------------------------------------------------
  # GenServer Callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(_opts) do
    Logger.info("[RolloutSupervisor] Starting rollout monitor (interval=#{@check_interval}ms)")
    schedule_check()
    {:ok, %{last_check_at: nil, check_count: 0}}
  end

  @impl true
  def handle_info(:check_rollouts, state) do
    new_state = do_check_rollouts(state)
    schedule_check()
    {:noreply, new_state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  @impl true
  def handle_cast(:check_rollouts, state) do
    new_state = do_check_rollouts(state)
    {:noreply, new_state}
  end

  # ---------------------------------------------------------------------------
  # Core Check Logic
  # ---------------------------------------------------------------------------

  defp do_check_rollouts(state) do
    rollouts = Updates.list_active_rollouts()

    if length(rollouts) > 0 do
      Logger.debug("[RolloutSupervisor] Checking #{length(rollouts)} active rollout(s)")
    end

    Enum.each(rollouts, &process_rollout/1)

    %{state | last_check_at: DateTime.utc_now(), check_count: state.check_count + 1}
  rescue
    e ->
      Logger.error(
        "[RolloutSupervisor] Error during rollout check: #{Exception.message(e)}"
      )

      state
  end

  defp process_rollout(rollout) do
    progress = Updates.get_rollout_progress(rollout.id)

    case rollout.strategy do
      "canary" -> process_canary(rollout, progress)
      "staged" -> process_staged(rollout, progress)
      "immediate" -> process_immediate(rollout, progress)
      "manual" -> :ok
    end
  rescue
    e ->
      Logger.error(
        "[RolloutSupervisor] Error processing rollout #{rollout.id}: #{Exception.message(e)}"
      )
  end

  # -- Canary Strategy -------------------------------------------------------

  defp process_canary(rollout, progress) do
    total_finished = progress.completed + progress.failed

    cond do
      # Not enough data yet
      total_finished < @canary_min_reports_for_promotion ->
        :ok

      # Failure rate too high -- auto-rollback
      progress.success_rate < (100 - @failure_threshold) ->
        Logger.warning(
          "[RolloutSupervisor] Canary rollout #{rollout.id} failing: " <>
            "success_rate=#{progress.success_rate}%, triggering rollback"
        )

        Updates.rollback_rollout(
          rollout.id,
          "auto-rollback: success rate #{progress.success_rate}% below threshold"
        )

      # All canary agents succeeded -- promote to 100%
      progress.pending == 0 and progress.in_progress == 0 and progress.failed == 0 ->
        Logger.info(
          "[RolloutSupervisor] Canary rollout #{rollout.id} healthy " <>
            "(#{progress.completed} agents OK), promoting to 100%"
        )

        Updates.promote_canary(rollout.id)

      # Canary healthy but still in progress
      true ->
        :ok
    end
  end

  # -- Staged Strategy -------------------------------------------------------

  defp process_staged(rollout, progress) do
    total_finished = progress.completed + progress.failed

    cond do
      total_finished == 0 ->
        :ok

      # Failure rate too high -- pause
      progress.success_rate < (100 - @failure_threshold) ->
        Logger.warning(
          "[RolloutSupervisor] Staged rollout #{rollout.id} paused at stage #{rollout.current_stage}: " <>
            "success_rate=#{progress.success_rate}%"
        )

        Updates.pause_rollout(rollout.id)

      # Current stage complete with sufficient success -- advance
      progress.pending == 0 and progress.in_progress == 0 and
          progress.success_rate >= @stage_min_success_rate ->
        Logger.info(
          "[RolloutSupervisor] Staged rollout #{rollout.id} advancing " <>
            "from stage #{rollout.current_stage} (success_rate=#{progress.success_rate}%)"
        )

        Updates.advance_rollout_stage(rollout.id)

      true ->
        :ok
    end
  end

  # -- Immediate Strategy ----------------------------------------------------

  defp process_immediate(rollout, progress) do
    if progress.pending == 0 and progress.in_progress == 0 and progress.total > 0 do
      Logger.info(
        "[RolloutSupervisor] Immediate rollout #{rollout.id} completed: " <>
          "#{progress.completed} success, #{progress.failed} failed"
      )

      Updates.complete_rollout(rollout.id)
    else
      check_stale(rollout)
    end
  end

  # -- Stale Detection -------------------------------------------------------

  defp check_stale(rollout) do
    case rollout.started_at do
      nil ->
        :ok

      started_at ->
        hours_elapsed = DateTime.diff(DateTime.utc_now(), started_at, :hour)

        if hours_elapsed > @stale_hours do
          Logger.warning(
            "[RolloutSupervisor] Rollout #{rollout.id} stale for #{hours_elapsed}h, auto-pausing"
          )

          Updates.pause_rollout(rollout.id)
        end
    end
  end

  # ---------------------------------------------------------------------------
  # Scheduling
  # ---------------------------------------------------------------------------

  defp schedule_check do
    Process.send_after(self(), :check_rollouts, @check_interval)
  end
end
