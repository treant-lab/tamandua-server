defmodule TamanduaServer.Detection.TokenAnomalyDetector do
  @moduledoc """
  GenServer for detecting anomalies in token usage patterns per agent.

  Tracks rolling statistics using Welford's online algorithm and detects:
  - Spike anomalies (>3 stddev from mean)
  - Unusual ratio anomalies (input/output ratio outliers)
  - Sustained high usage (above 95th percentile for 5+ consecutive)

  Usage:
      {:ok, result} = TokenAnomalyDetector.detect("agent-123", %{input_tokens: 100, output_tokens: 500})
      result.is_anomaly  # => true
      result.anomaly_type  # => :spike
  """

  use GenServer
  require Logger
  alias Phoenix.PubSub

  @ets_table :token_baselines
  @learning_phase_samples 20
  @max_samples 1000
  @sustained_high_threshold 5

  # ============================================================================
  # Types
  # ============================================================================

  @type token_count :: %{
          input_tokens: non_neg_integer() | nil,
          output_tokens: non_neg_integer() | nil,
          total_tokens: non_neg_integer() | nil
        }

  @type baseline_state :: %{
          mean_input_tokens: float(),
          mean_output_tokens: float(),
          mean_total_tokens: float(),
          stddev_input: float(),
          stddev_output: float(),
          stddev_total: float(),
          mean_ratio: float(),
          stddev_ratio: float(),
          variance_input: float(),
          variance_output: float(),
          variance_total: float(),
          variance_ratio: float(),
          sample_count: non_neg_integer(),
          consecutive_high: non_neg_integer(),
          percentile_95_total: float(),
          last_updated: DateTime.t()
        }

  @type anomaly_type :: :spike | :unusual_ratio | :sustained_high

  @type detection_result :: %{
          is_anomaly: boolean(),
          anomaly_score: float(),
          anomaly_type: anomaly_type() | nil,
          details: map()
        }

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Detect anomalies in token usage for an agent.

  Returns {:ok, detection_result} where:
  - is_anomaly: Whether usage is anomalous
  - anomaly_score: 0.0-1.0 severity score
  - anomaly_type: :spike | :unusual_ratio | :sustained_high | nil
  - details: Additional context about the detection

  During learning phase (first #{@learning_phase_samples} samples), no anomalies are flagged.
  """
  @spec detect(String.t(), token_count()) :: {:ok, detection_result()}
  def detect(agent_id, token_count) do
    GenServer.call(__MODULE__, {:detect, agent_id, token_count})
  end

  @doc """
  Update baseline statistics for an agent without checking for anomalies.
  """
  @spec update_baseline(String.t(), token_count()) :: :ok
  def update_baseline(agent_id, token_count) do
    GenServer.cast(__MODULE__, {:update_baseline, agent_id, token_count})
  end

  @doc """
  Get current baseline statistics for an agent.
  """
  @spec get_baseline(String.t()) :: {:ok, baseline_state()} | {:error, :not_found}
  def get_baseline(agent_id) do
    GenServer.call(__MODULE__, {:get_baseline, agent_id})
  end

  @doc """
  Reset baseline for an agent.
  """
  @spec reset_baseline(String.t()) :: :ok
  def reset_baseline(agent_id) do
    GenServer.cast(__MODULE__, {:reset_baseline, agent_id})
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    table =
      :ets.new(@ets_table, [
        :set,
        :named_table,
        :public,
        read_concurrency: true,
        write_concurrency: true
      ])

    # Subscribe to inference events for automatic baseline updates
    PubSub.subscribe(TamanduaServer.PubSub, "inference:all")

    Logger.info("[TokenAnomalyDetector] Started")
    {:ok, %{table: table}}
  end

  @impl true
  def handle_call({:detect, agent_id, token_count}, _from, state) do
    start_time = System.monotonic_time(:millisecond)
    baseline = get_or_create_baseline(agent_id)

    result =
      if baseline.sample_count < @learning_phase_samples do
        # Learning phase: update baseline, don't flag anomalies
        new_baseline = update_baseline_stats(baseline, token_count)
        :ets.insert(@ets_table, {agent_id, new_baseline})

        %{
          is_anomaly: false,
          anomaly_score: 0.0,
          anomaly_type: nil,
          details: %{
            learning_phase: true,
            samples_remaining: @learning_phase_samples - baseline.sample_count
          }
        }
      else
        # Detection phase
        {is_anomaly, anomaly_score, anomaly_type, details} =
          detect_anomaly(baseline, token_count)

        # Update baseline with new sample
        new_baseline =
          baseline
          |> update_baseline_stats(token_count)
          |> update_consecutive_high(token_count, is_anomaly, anomaly_type)

        :ets.insert(@ets_table, {agent_id, new_baseline})

        %{
          is_anomaly: is_anomaly,
          anomaly_score: anomaly_score,
          anomaly_type: anomaly_type,
          details: details
        }
      end

    elapsed = System.monotonic_time(:millisecond) - start_time

    # Emit telemetry
    :telemetry.execute(
      [:tamandua, :token_anomaly, :detect],
      %{latency_ms: elapsed},
      %{
        agent_id: agent_id,
        anomaly_detected: result.is_anomaly,
        anomaly_type: result.anomaly_type,
        anomaly_score: result.anomaly_score
      }
    )

    {:reply, {:ok, result}, state}
  end

  @impl true
  def handle_call({:get_baseline, agent_id}, _from, state) do
    result =
      case :ets.lookup(@ets_table, agent_id) do
        [{^agent_id, baseline}] -> {:ok, baseline}
        [] -> {:error, :not_found}
      end

    {:reply, result, state}
  end

  @impl true
  def handle_cast({:update_baseline, agent_id, token_count}, state) do
    baseline = get_or_create_baseline(agent_id)
    new_baseline = update_baseline_stats(baseline, token_count)
    :ets.insert(@ets_table, {agent_id, new_baseline})
    {:noreply, state}
  end

  @impl true
  def handle_cast({:reset_baseline, agent_id}, state) do
    :ets.delete(@ets_table, agent_id)
    Logger.debug("[TokenAnomalyDetector] Reset baseline for agent #{agent_id}")
    {:noreply, state}
  end

  @impl true
  def handle_info({:inference_complete, session}, state) do
    # Auto-update baseline on inference completion
    if session.metrics && session.metrics.token_count do
      agent_id = session.agent_id
      token_count = session.metrics.token_count
      baseline = get_or_create_baseline(agent_id)
      new_baseline = update_baseline_stats(baseline, token_count)
      :ets.insert(@ets_table, {agent_id, new_baseline})
    end

    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp get_or_create_baseline(agent_id) do
    case :ets.lookup(@ets_table, agent_id) do
      [{^agent_id, baseline}] ->
        baseline

      [] ->
        %{
          mean_input_tokens: 0.0,
          mean_output_tokens: 0.0,
          mean_total_tokens: 0.0,
          stddev_input: 0.0,
          stddev_output: 0.0,
          stddev_total: 0.0,
          mean_ratio: 0.0,
          stddev_ratio: 0.0,
          variance_input: 0.0,
          variance_output: 0.0,
          variance_total: 0.0,
          variance_ratio: 0.0,
          sample_count: 0,
          consecutive_high: 0,
          percentile_95_total: 0.0,
          last_updated: DateTime.utc_now()
        }
    end
  end

  # Welford's online algorithm for incremental mean/variance calculation
  defp update_baseline_stats(baseline, token_count) do
    input = token_count[:input_tokens] || token_count["input_tokens"] || 0
    output = token_count[:output_tokens] || token_count["output_tokens"] || 0
    total = token_count[:total_tokens] || token_count["total_tokens"] || input + output

    # Calculate ratio (avoid division by zero)
    ratio = if input > 0, do: output / input, else: 0.0

    # Cap sample count at max_samples (rolling window approximation)
    new_count = min(baseline.sample_count + 1, @max_samples)

    # Welford's algorithm for each metric
    {new_mean_input, new_variance_input} =
      welford_update(baseline.mean_input_tokens, baseline.variance_input, input, new_count)

    {new_mean_output, new_variance_output} =
      welford_update(baseline.mean_output_tokens, baseline.variance_output, output, new_count)

    {new_mean_total, new_variance_total} =
      welford_update(baseline.mean_total_tokens, baseline.variance_total, total, new_count)

    {new_mean_ratio, new_variance_ratio} =
      welford_update(baseline.mean_ratio, baseline.variance_ratio, ratio, new_count)

    # Calculate stddev from variance
    stddev_input = safe_sqrt(new_variance_input)
    stddev_output = safe_sqrt(new_variance_output)
    stddev_total = safe_sqrt(new_variance_total)
    stddev_ratio = safe_sqrt(new_variance_ratio)

    # Estimate 95th percentile using mean + 1.645 * stddev (normal approximation)
    percentile_95 = new_mean_total + 1.645 * stddev_total

    %{
      baseline
      | mean_input_tokens: new_mean_input,
        mean_output_tokens: new_mean_output,
        mean_total_tokens: new_mean_total,
        stddev_input: stddev_input,
        stddev_output: stddev_output,
        stddev_total: stddev_total,
        mean_ratio: new_mean_ratio,
        stddev_ratio: stddev_ratio,
        variance_input: new_variance_input,
        variance_output: new_variance_output,
        variance_total: new_variance_total,
        variance_ratio: new_variance_ratio,
        sample_count: new_count,
        percentile_95_total: percentile_95,
        last_updated: DateTime.utc_now()
    }
  end

  # Welford's online algorithm for mean and variance
  defp welford_update(_mean, _variance, new_value, count) when count <= 1 do
    {new_value * 1.0, 0.0}
  end

  defp welford_update(mean, variance, new_value, count) do
    delta = new_value - mean
    new_mean = mean + delta / count
    delta2 = new_value - new_mean
    new_variance = variance + (delta * delta2 - variance) / count
    {new_mean, max(0.0, new_variance)}
  end

  defp safe_sqrt(value) when value <= 0, do: 0.0
  defp safe_sqrt(value), do: :math.sqrt(value)

  defp detect_anomaly(baseline, token_count) do
    input = token_count[:input_tokens] || token_count["input_tokens"] || 0
    output = token_count[:output_tokens] || token_count["output_tokens"] || 0
    total = token_count[:total_tokens] || token_count["total_tokens"] || input + output
    ratio = if input > 0, do: output / input, else: 0.0

    # Calculate z-scores
    z_input = z_score(input, baseline.mean_input_tokens, baseline.stddev_input)
    z_output = z_score(output, baseline.mean_output_tokens, baseline.stddev_output)
    z_total = z_score(total, baseline.mean_total_tokens, baseline.stddev_total)
    z_ratio = z_score(ratio, baseline.mean_ratio, baseline.stddev_ratio)

    max_z = Enum.max([abs(z_input), abs(z_output), abs(z_total)])

    details = %{
      input_tokens: input,
      output_tokens: output,
      total_tokens: total,
      ratio: ratio,
      z_scores: %{
        input: Float.round(z_input, 2),
        output: Float.round(z_output, 2),
        total: Float.round(z_total, 2),
        ratio: Float.round(z_ratio, 2)
      },
      baseline: %{
        mean_total: Float.round(baseline.mean_total_tokens, 2),
        stddev_total: Float.round(baseline.stddev_total, 2),
        mean_ratio: Float.round(baseline.mean_ratio, 2)
      }
    }

    cond do
      # Spike detection: >3 stddev from mean
      max_z > 3.0 ->
        anomaly_score = min((max_z - 3.0) / 3.0 + 0.5, 1.0)
        {true, anomaly_score, :spike, details}

      # Unusual ratio detection: ratio z-score >3
      abs(z_ratio) > 3.0 and baseline.stddev_ratio > 0.1 ->
        anomaly_score = min((abs(z_ratio) - 3.0) / 3.0 + 0.5, 1.0)
        {true, anomaly_score, :unusual_ratio, details}

      # Sustained high: check consecutive_high counter
      total > baseline.percentile_95_total and
          baseline.consecutive_high >= @sustained_high_threshold - 1 ->
        anomaly_score = 0.7 + min(baseline.consecutive_high * 0.05, 0.3)
        {true, anomaly_score, :sustained_high, details}

      true ->
        # Calculate score even for non-anomalous (for monitoring)
        score = min(max_z / 6.0, 0.49)
        {false, score, nil, details}
    end
  end

  defp z_score(_value, _mean, stddev) when stddev == 0 or stddev == 0.0, do: 0.0
  defp z_score(value, mean, stddev), do: (value - mean) / stddev

  defp update_consecutive_high(baseline, token_count, _is_anomaly, anomaly_type) do
    total =
      token_count[:total_tokens] || token_count["total_tokens"] ||
        (token_count[:input_tokens] || 0) + (token_count[:output_tokens] || 0)

    cond do
      anomaly_type == :sustained_high ->
        # Already anomalous, reset counter
        %{baseline | consecutive_high: 0}

      total > baseline.percentile_95_total ->
        # Above 95th percentile, increment counter
        %{baseline | consecutive_high: baseline.consecutive_high + 1}

      true ->
        # Below threshold, reset counter
        %{baseline | consecutive_high: 0}
    end
  end
end
