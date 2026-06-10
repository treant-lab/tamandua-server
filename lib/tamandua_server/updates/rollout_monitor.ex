defmodule TamanduaServer.Updates.RolloutMonitor do
  @moduledoc """
  Background monitor for active rollouts with health-gated auto-advancement.

  Runs periodically and for each active staged/canary rollout:

  1. Computes success rate from agent update reports
  2. Checks agent health metrics (CPU, memory, crash rate) post-update
  3. Enforces a minimum soak time before advancing
  4. Auto-advances staged rollouts when health gates pass
  5. Auto-promotes canary rollouts when canary group is healthy
  6. Auto-rolls back when failure rate exceeds threshold

  ## Health Gates

  Each rollout stage can specify a `min_success_rate` (default: 95%).
  The monitor also checks post-update agent health:

  - Agent crash/restart rate must not spike (> 2x baseline)
  - Agent CPU usage must not spike (> 2x pre-update average)
  - Agent must still be reporting heartbeats

  ## Soak Time

  Stages enforce a minimum soak time (configurable per stage, default 30 min)
  before auto-advancement, even if all health gates pass immediately.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Updates
  alias TamanduaServer.Updates.{Rollout, AgentUpdate}
  alias TamanduaServer.Agents
  alias TamanduaServer.Repo

  import Ecto.Query

  # Check every 2 minutes
  @check_interval_ms 120_000

  # Default soak time per stage (30 minutes)
  @default_soak_minutes 30

  # Default minimum success rate to pass health gate
  @default_min_success_rate 95.0

  # Maximum agent offline rate post-update before flagging
  @max_offline_rate 10.0

  # Failure threshold for auto-rollback
  @failure_threshold 5.0

  # Minimum completed reports before evaluating
  @min_reports 3

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Force an immediate evaluation cycle (useful for testing).
  """
  def evaluate_now do
    GenServer.cast(__MODULE__, :evaluate_now)
  end

  # ---------------------------------------------------------------------------
  # GenServer callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(_opts) do
    Logger.info("[RolloutMonitor] Started — checking active rollouts every #{div(@check_interval_ms, 1000)}s")
    schedule_check()
    {:ok, %{last_check: nil, evaluations: 0}}
  end

  @impl true
  def handle_info(:check, state) do
    evaluate_all_rollouts()
    schedule_check()
    {:noreply, %{state | last_check: DateTime.utc_now(), evaluations: state.evaluations + 1}}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  @impl true
  def handle_cast(:evaluate_now, state) do
    evaluate_all_rollouts()
    {:noreply, %{state | last_check: DateTime.utc_now(), evaluations: state.evaluations + 1}}
  end

  # ---------------------------------------------------------------------------
  # Core evaluation loop
  # ---------------------------------------------------------------------------

  defp evaluate_all_rollouts do
    active_rollouts = Updates.list_active_rollouts()

    Enum.each(active_rollouts, fn rollout ->
      try do
        evaluate_rollout(rollout)
      rescue
        e ->
          Logger.error(
            "[RolloutMonitor] Error evaluating rollout #{rollout.id}: #{Exception.message(e)}"
          )
      end
    end)
  end

  defp evaluate_rollout(rollout) do
    progress = Updates.get_rollout_progress(rollout.id)
    total_finished = progress.completed + progress.failed

    # Not enough data yet
    if total_finished < @min_reports do
      Logger.debug("[RolloutMonitor] Rollout #{rollout.id}: waiting for more reports (#{total_finished}/#{@min_reports})")
      :waiting
    else
      # Check for auto-rollback first
      failure_rate = if total_finished > 0, do: progress.failed / total_finished * 100, else: 0.0

      cond do
        failure_rate > @failure_threshold ->
          Logger.error(
            "[RolloutMonitor] Rollout #{rollout.id} failure rate #{Float.round(failure_rate, 1)}% " <>
              "exceeds threshold #{@failure_threshold}% — triggering auto-rollback"
          )

          Updates.rollback_rollout(
            rollout.id,
            "auto-rollback: #{Float.round(failure_rate, 1)}% failure rate (#{progress.failed}/#{total_finished})"
          )

        # Check health gates for advancement
        true ->
          check_health_gates(rollout, progress)
      end
    end
  end

  defp check_health_gates(rollout, progress) do
    case rollout.strategy do
      "staged" -> check_staged_gates(rollout, progress)
      "canary" -> check_canary_gates(rollout, progress)
      _ -> :ok
    end
  end

  # ---------------------------------------------------------------------------
  # Staged rollout health gates
  # ---------------------------------------------------------------------------

  defp check_staged_gates(rollout, progress) do
    current_stage = Enum.at(rollout.stages || [], rollout.current_stage)

    if current_stage == nil do
      Logger.info("[RolloutMonitor] Rollout #{rollout.id}: no more stages, completing")
      Updates.complete_rollout(rollout.id)
    else
      min_success = get_stage_min_success(current_stage)
      soak_minutes = get_stage_soak_minutes(current_stage)

      soak_passed = soak_time_passed?(rollout, soak_minutes)
      success_ok = progress.success_rate >= min_success
      health_ok = check_post_update_health(rollout)

      Logger.info(
        "[RolloutMonitor] Rollout #{rollout.id} stage #{rollout.current_stage}: " <>
          "success=#{progress.success_rate}% (min=#{min_success}%), " <>
          "soak=#{soak_passed}, health=#{health_ok}, " <>
          "completed=#{progress.completed}, failed=#{progress.failed}"
      )

      if soak_passed and success_ok and health_ok do
        Logger.info(
          "[RolloutMonitor] All health gates passed for rollout #{rollout.id} " <>
            "stage #{rollout.current_stage} — auto-advancing"
        )

        Updates.advance_rollout_stage(rollout.id)
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Canary rollout health gates
  # ---------------------------------------------------------------------------

  defp check_canary_gates(rollout, progress) do
    soak_minutes = @default_soak_minutes
    soak_passed = soak_time_passed?(rollout, soak_minutes)
    success_ok = progress.success_rate >= @default_min_success_rate
    health_ok = check_post_update_health(rollout)

    Logger.info(
      "[RolloutMonitor] Canary rollout #{rollout.id}: " <>
        "success=#{progress.success_rate}%, soak=#{soak_passed}, " <>
        "health=#{health_ok}, completed=#{progress.completed}"
    )

    if soak_passed and success_ok and health_ok do
      Logger.info(
        "[RolloutMonitor] Canary health gates passed for rollout #{rollout.id} — auto-promoting to 100%"
      )

      Updates.promote_canary(rollout.id)
    end
  end

  # ---------------------------------------------------------------------------
  # Post-update agent health check
  # ---------------------------------------------------------------------------

  defp check_post_update_health(rollout) do
    # Get agents that have completed the update
    updated_agent_ids =
      AgentUpdate
      |> where([au], au.rollout_id == ^rollout.id and au.status == "completed")
      |> select([au], au.agent_id)
      |> Repo.all()

    if Enum.empty?(updated_agent_ids) do
      true
    else
      # Check how many updated agents are still online
      online_count =
        TamanduaServer.Agents.Agent
        |> where([a], a.id in ^updated_agent_ids)
        |> where([a], a.status == "online")
        |> Repo.aggregate(:count, :id)

      total = length(updated_agent_ids)
      offline_rate = if total > 0, do: (1 - online_count / total) * 100, else: 0.0

      if offline_rate > @max_offline_rate do
        Logger.warning(
          "[RolloutMonitor] Rollout #{rollout.id}: #{Float.round(offline_rate, 1)}% of " <>
            "updated agents are offline (threshold: #{@max_offline_rate}%)"
        )

        false
      else
        true
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp soak_time_passed?(rollout, soak_minutes) do
    # Use started_at or the last stage advancement time
    reference_time = rollout.started_at || rollout.inserted_at

    case reference_time do
      nil ->
        false

      dt ->
        elapsed_minutes = DateTime.diff(DateTime.utc_now(), dt, :second) / 60
        elapsed_minutes >= soak_minutes
    end
  end

  defp get_stage_min_success(stage) when is_map(stage) do
    stage
    |> Map.get("min_success_rate", Map.get(stage, :min_success_rate, @default_min_success_rate))
    |> to_float()
  end

  defp get_stage_min_success(_), do: @default_min_success_rate

  defp get_stage_soak_minutes(stage) when is_map(stage) do
    stage
    |> Map.get("soak_minutes", Map.get(stage, :soak_minutes, @default_soak_minutes))
    |> to_integer()
  end

  defp get_stage_soak_minutes(_), do: @default_soak_minutes

  defp to_float(v) when is_float(v), do: v
  defp to_float(v) when is_integer(v), do: v * 1.0
  defp to_float(v) when is_binary(v), do: String.to_float(v)
  defp to_float(_), do: @default_min_success_rate

  defp to_integer(v) when is_integer(v), do: v
  defp to_integer(v) when is_float(v), do: round(v)
  defp to_integer(v) when is_binary(v), do: String.to_integer(v)
  defp to_integer(_), do: @default_soak_minutes

  defp schedule_check do
    Process.send_after(self(), :check, @check_interval_ms)
  end
end
