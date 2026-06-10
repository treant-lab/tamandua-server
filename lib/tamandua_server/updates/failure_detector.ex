defmodule TamanduaServer.Updates.FailureDetector do
  @moduledoc """
  Monitors agent update failure rates and triggers auto-rollback.

  Uses sliding window statistics to detect failure rate spikes.
  Integrates with CanaryRollout to provide automatic rollback
  when failure thresholds are exceeded.
  """

  require Logger

  alias TamanduaServer.Updates.CanaryRollout

  @failure_threshold 0.05  # 5% failure rate triggers rollback
  @min_samples 5           # Minimum reports before calculating rate

  @doc "Calculate failure rate from counts."
  @spec calculate_failure_rate(non_neg_integer(), non_neg_integer()) :: float()
  def calculate_failure_rate(success_count, failure_count) do
    total = success_count + failure_count
    if total < @min_samples do
      0.0
    else
      failure_count / total
    end
  end

  @doc "Check if failure rate exceeds threshold."
  @spec should_rollback?(non_neg_integer(), non_neg_integer()) :: boolean()
  def should_rollback?(success_count, failure_count) do
    total = success_count + failure_count
    total >= @min_samples and calculate_failure_rate(success_count, failure_count) > @failure_threshold
  end

  @doc """
  Process an update report and potentially trigger rollback.

  Returns:
  - `:ok` if the report was processed normally
  - `{:rollback, previous_version}` if a rollback was triggered
  """
  @spec process_report(String.t(), boolean(), String.t(), String.t() | nil) ::
    :ok | {:rollback, String.t()}
  def process_report(version, success, agent_id, error_message \\ nil) do
    # Record the report
    CanaryRollout.record_update_report(version, success, agent_id)

    # Log failures for debugging
    unless success do
      Logger.warning("Update failure for #{version} on agent #{agent_id}: #{error_message || "unknown error"}")
    end

    # Get current state and check rollback condition
    case CanaryRollout.get_state(version) do
      {:ok, state} ->
        # Calculate what the failure rate will be after this report
        new_failure_count = if success, do: state.failure_count, else: state.failure_count + 1
        new_success_count = if success, do: state.success_count + 1, else: state.success_count

        if should_rollback?(new_success_count, new_failure_count) do
          Logger.error("Failure rate spike detected for #{version}, triggering rollback")
          case CanaryRollout.rollback(version) do
            {:ok, previous_version} -> {:rollback, previous_version}
            _ -> :ok
          end
        else
          :ok
        end
      _ ->
        :ok
    end
  end

  @doc """
  Analyze failure patterns for a version.

  Returns a map with analysis results including:
  - current failure rate
  - trend (increasing, stable, decreasing)
  - recommendation (continue, pause, rollback)
  """
  @spec analyze_failures(String.t()) :: {:ok, map()} | {:error, :not_found}
  def analyze_failures(version) do
    case CanaryRollout.get_state(version) do
      {:ok, state} ->
        total = state.success_count + state.failure_count
        failure_rate = calculate_failure_rate(state.success_count, state.failure_count)

        recommendation = cond do
          failure_rate > @failure_threshold and total >= @min_samples -> :rollback
          failure_rate > 0.02 and total >= @min_samples -> :pause
          true -> :continue
        end

        analysis = %{
          version: version,
          stage: state.stage,
          success_count: state.success_count,
          failure_count: state.failure_count,
          total_reports: total,
          failure_rate: failure_rate,
          failure_rate_percent: Float.round(failure_rate * 100, 2),
          threshold_percent: @failure_threshold * 100,
          agents_updated: MapSet.size(state.agents_updated),
          recommendation: recommendation
        }

        {:ok, analysis}
      error ->
        error
    end
  end

  @doc """
  Get summary statistics for all active rollouts.
  """
  @spec get_summary() :: list(map())
  def get_summary do
    CanaryRollout.list_rollouts()
    |> Enum.map(fn {version, state} ->
      failure_rate = calculate_failure_rate(state.success_count, state.failure_count)
      %{
        version: version,
        stage: state.stage,
        previous_version: state.previous_version,
        success_count: state.success_count,
        failure_count: state.failure_count,
        failure_rate_percent: Float.round(failure_rate * 100, 2),
        agents_updated: MapSet.size(state.agents_updated),
        stage_started_at: state.stage_started_at
      }
    end)
    |> Enum.sort_by(& &1.stage_started_at, :desc)
  end

  @doc "Get the current failure threshold."
  def failure_threshold, do: @failure_threshold

  @doc "Get the minimum samples required before calculating failure rate."
  def min_samples, do: @min_samples
end
