defmodule TamanduaServer.Detection.ConfidenceScorer do
  @moduledoc """
  Confidence scoring and adaptive threshold management for detections.

  This module addresses alert fatigue by:
  1. Adding multi-factor confidence scores to all detections
  2. Implementing adaptive thresholds based on historical baselines
  3. Providing suppression rules for known-good patterns
  4. Adjusting scores based on environmental context

  ## Confidence Scoring Factors

  Each detection receives a composite confidence score based on:
  - Rule confidence: Intrinsic reliability of the detection rule
  - Environmental context: User role, time of day, asset criticality
  - Historical baseline: How often this pattern occurs normally
  - Corroborating evidence: Other detections in the same session
  - Source quality: Reliability of the telemetry source

  ## Adaptive Thresholds

  Thresholds adapt over time based on:
  - Organization-specific baseline behavior
  - Feedback from analyst investigations
  - False positive/negative rates
  - Environmental changes (software deployments, etc.)

  ## Usage

      # Score a detection with context
      detection = %{type: :sigma, rule_name: "Mimikatz", confidence: 0.95}
      context = %{agent_id: "agent-1", user_role: :admin, asset_critical: true}
      scored = ConfidenceScorer.score(detection, context)
      # => %{confidence: 0.92, factors: [...], adjusted_threshold: 0.7}

      # Check if detection should be suppressed
      ConfidenceScorer.should_suppress?(detection, context)
      # => false

      # Record feedback for adaptive learning
      ConfidenceScorer.record_feedback(:false_positive, detection, context)
  """

  use GenServer
  require Logger

  alias TamanduaServer.Detection.ThresholdConfig

  @ets_baselines :confidence_baselines
  @ets_feedback :confidence_feedback
  @ets_suppressions :confidence_suppressions

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Calculate composite confidence score for a detection.

  Takes the raw detection and environmental context, returns the detection
  enriched with:
  - `adjusted_confidence`: Final confidence score (0.0-1.0)
  - `confidence_factors`: Breakdown of scoring factors
  - `adaptive_threshold`: Context-adjusted alert threshold
  - `recommendation`: :alert, :suppress, or :reduce_severity
  """
  @spec score(map(), map()) :: map()
  def score(detection, context \\ %{}) do
    # Base confidence from the detection rule
    base_confidence = detection[:confidence] || 0.5

    # Calculate confidence factors
    factors = %{
      rule_confidence: base_confidence,
      environmental: environmental_factor(context),
      baseline: baseline_factor(detection, context),
      corroboration: corroboration_factor(detection, context),
      source_quality: source_quality_factor(detection)
    }

    # Weighted composite score
    weights = %{
      rule_confidence: 0.40,
      environmental: 0.15,
      baseline: 0.25,
      corroboration: 0.10,
      source_quality: 0.10
    }

    adjusted_confidence =
      factors
      |> Enum.map(fn {factor, value} -> value * Map.get(weights, factor, 0) end)
      |> Enum.sum()
      |> min(1.0)
      |> max(0.0)

    # Get adaptive threshold for this detection type
    adaptive_threshold = get_adaptive_threshold(detection, context)

    # Determine recommendation
    recommendation =
      cond do
        should_suppress?(detection, context) -> :suppress
        adjusted_confidence < adaptive_threshold * 0.7 -> :reduce_severity
        adjusted_confidence >= adaptive_threshold -> :alert
        true -> :monitor
      end

    detection
    |> Map.put(:adjusted_confidence, Float.round(adjusted_confidence, 3))
    |> Map.put(:confidence_factors, factors)
    |> Map.put(:adaptive_threshold, adaptive_threshold)
    |> Map.put(:confidence_recommendation, recommendation)
  end

  @doc """
  Check if a detection should be suppressed based on known-good patterns.
  """
  @spec should_suppress?(map(), map()) :: boolean()
  def should_suppress?(detection, context) do
    # Check suppression rules
    suppression_key = build_suppression_key(detection, context)

    case :ets.lookup(@ets_suppressions, suppression_key) do
      [{^suppression_key, %{expires_at: expires_at}}] ->
        DateTime.compare(DateTime.utc_now(), expires_at) == :lt

      [] ->
        # Check baseline-based auto-suppression
        baseline_score = baseline_factor(detection, context)
        # If this pattern is extremely common (>95% baseline), suppress
        baseline_score > 0.95
    end
  rescue
    _ -> false
  end

  @doc """
  Add a suppression rule for a known-good pattern.
  """
  @spec add_suppression(map(), map(), keyword()) :: :ok
  def add_suppression(detection, context, opts \\ []) do
    GenServer.call(__MODULE__, {:add_suppression, detection, context, opts})
  end

  @doc """
  Record analyst feedback for adaptive threshold learning.

  Feedback types:
  - :true_positive - Detection was accurate
  - :false_positive - Detection was incorrect
  - :escalated - Detection was escalated to incident
  """
  @spec record_feedback(atom(), map(), map()) :: :ok
  def record_feedback(feedback_type, detection, context) do
    GenServer.cast(__MODULE__, {:record_feedback, feedback_type, detection, context})
  end

  @doc """
  Get adaptive threshold for a detection type and context.
  """
  @spec get_adaptive_threshold(map(), map()) :: float()
  def get_adaptive_threshold(detection, context) do
    # Get base threshold from config
    base_threshold = ThresholdConfig.get(:scores, :threat_alert_threshold, 0.75)

    # Adjust based on asset criticality
    criticality_adjustment =
      case context[:asset_criticality] do
        :critical -> -0.1  # Lower threshold for critical assets (more sensitive)
        :high -> -0.05
        :medium -> 0.0
        :low -> 0.05  # Higher threshold for low-value assets (less sensitive)
        _ -> 0.0
      end

    # Adjust based on user role
    role_adjustment =
      case context[:user_role] do
        :admin -> 0.05  # Admins have more legitimate high-risk activity
        :developer -> 0.03
        :service_account -> -0.05  # Service accounts should be more deterministic
        _ -> 0.0
      end

    # Adjust based on detection type feedback history
    feedback_adjustment = get_feedback_adjustment(detection)

    (base_threshold + criticality_adjustment + role_adjustment + feedback_adjustment)
    |> min(0.95)
    |> max(0.3)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    # Create ETS tables
    :ets.new(@ets_baselines, [:named_table, :set, :public, {:read_concurrency, true}])
    :ets.new(@ets_feedback, [:named_table, :set, :public, {:read_concurrency, true}])
    :ets.new(@ets_suppressions, [:named_table, :set, :public, {:read_concurrency, true}])

    # Schedule periodic baseline recalculation
    schedule_baseline_recalc()

    {:ok, %{}}
  end

  @impl true
  def handle_call({:add_suppression, detection, context, opts}, _from, state) do
    ttl_hours = Keyword.get(opts, :ttl_hours, 24)
    reason = Keyword.get(opts, :reason, "Manual suppression")

    expires_at = DateTime.add(DateTime.utc_now(), ttl_hours * 3600, :second)
    suppression_key = build_suppression_key(detection, context)

    suppression = %{
      detection_type: detection[:type],
      rule_name: detection[:rule_name],
      agent_id: context[:agent_id],
      reason: reason,
      created_at: DateTime.utc_now(),
      expires_at: expires_at,
      created_by: opts[:created_by]
    }

    :ets.insert(@ets_suppressions, {suppression_key, suppression})
    Logger.info("[ConfidenceScorer] Added suppression: #{suppression_key}, expires: #{expires_at}")

    {:reply, :ok, state}
  end

  @impl true
  def handle_cast({:record_feedback, feedback_type, detection, _context}, state) do
    feedback_key = build_feedback_key(detection)

    current = case :ets.lookup(@ets_feedback, feedback_key) do
      [{^feedback_key, data}] -> data
      [] -> %{true_positive: 0, false_positive: 0, escalated: 0}
    end

    updated = Map.update(current, feedback_type, 1, &(&1 + 1))
    :ets.insert(@ets_feedback, {feedback_key, updated})

    Logger.debug("[ConfidenceScorer] Recorded #{feedback_type} for #{detection[:rule_name]}")

    {:noreply, state}
  end

  @impl true
  def handle_info(:recalc_baselines, state) do
    recalculate_baselines()
    schedule_baseline_recalc()
    {:noreply, state}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions - Confidence Factors
  # ============================================================================

  defp environmental_factor(context) do
    factors = []

    # Time of day factor (unusual hours = higher confidence)
    hour = DateTime.utc_now().hour
    time_factor =
      cond do
        hour in 0..6 -> 1.1   # Very unusual hours
        hour in 7..8 -> 0.95  # Early morning
        hour in 9..17 -> 0.8  # Business hours
        hour in 18..21 -> 0.9 # Evening
        true -> 1.0           # Late evening
      end
    factors = [time_factor | factors]

    # Day of week factor
    day_factor =
      case Date.day_of_week(Date.utc_today()) do
        6 -> 1.1  # Saturday
        7 -> 1.1  # Sunday
        _ -> 1.0  # Weekday
      end
    factors = [day_factor | factors]

    # Asset criticality factor
    asset_factor =
      case context[:asset_criticality] do
        :critical -> 1.1
        :high -> 1.05
        :medium -> 1.0
        :low -> 0.9
        _ -> 1.0
      end
    factors = [asset_factor | factors]

    # Normalize to 0-1 range
    avg = Enum.sum(factors) / length(factors)
    normalize_factor(avg)
  end

  defp baseline_factor(detection, context) do
    # Check how common this detection is for this context
    baseline_key = build_baseline_key(detection, context)

    case :ets.lookup(@ets_baselines, baseline_key) do
      [{^baseline_key, %{frequency: freq, total: total}}] when total > 10 ->
        # If seen frequently, reduce confidence (it's normal)
        1.0 - min(freq / total, 0.95)

      _ ->
        # Unknown baseline, neutral factor
        0.5
    end
  end

  defp corroboration_factor(_detection, context) do
    # Check for corroborating detections
    # This would integrate with the Correlator module in a full implementation
    agent_id = context[:agent_id]

    if agent_id do
      # Placeholder: In production, query recent detections for this agent
      # correlated_count = Correlator.recent_detection_count(agent_id, :timer.minutes(5))
      correlated_count = Map.get(context, :correlated_detections, 0)

      cond do
        correlated_count >= 5 -> 1.0   # Strong corroboration
        correlated_count >= 3 -> 0.8
        correlated_count >= 1 -> 0.6
        true -> 0.4                     # No corroboration
      end
    else
      0.5
    end
  end

  defp source_quality_factor(detection) do
    # Assess reliability of the detection source
    case detection[:type] do
      :sigma -> 0.85              # Well-tested rules
      :yara -> 0.9                # Binary signatures are reliable
      :ioc -> 0.8                 # IOC quality varies
      :threat_intel_feed -> 0.75 # Feed quality varies
      :ml -> 0.7                  # ML can have false positives
      :behavioral -> 0.65        # Behavioral is context-dependent
      _ -> 0.5
    end
  end

  defp get_feedback_adjustment(detection) do
    feedback_key = build_feedback_key(detection)

    case :ets.lookup(@ets_feedback, feedback_key) do
      [{^feedback_key, %{true_positive: tp, false_positive: fp, escalated: esc}}] ->
        total = tp + fp + esc

        if total > 10 do
          # Calculate precision-based adjustment
          precision = tp / max(tp + fp, 1)

          cond do
            precision < 0.3 -> 0.1   # Many false positives, raise threshold
            precision < 0.5 -> 0.05
            precision > 0.9 -> -0.05 # Very accurate, can lower threshold
            true -> 0.0
          end
        else
          0.0
        end

      _ ->
        0.0
    end
  end

  # ============================================================================
  # Private Functions - Helpers
  # ============================================================================

  defp build_suppression_key(detection, context) do
    agent_id = context[:agent_id] || "global"
    rule_name = detection[:rule_name] || "unknown"
    type = detection[:type] || :unknown

    "#{type}:#{rule_name}:#{agent_id}"
  end

  defp build_feedback_key(detection) do
    rule_name = detection[:rule_name] || "unknown"
    type = detection[:type] || :unknown

    "#{type}:#{rule_name}"
  end

  defp build_baseline_key(detection, context) do
    org_id = context[:organization_id] || "default"
    rule_name = detection[:rule_name] || "unknown"

    "#{org_id}:#{rule_name}"
  end

  defp normalize_factor(value) do
    # Normalize factor to 0-1 range, centered around 0.5
    cond do
      value >= 1.2 -> 1.0
      value >= 1.0 -> 0.5 + (value - 1.0) * 2.5
      value >= 0.8 -> 0.5 - (1.0 - value) * 2.5
      true -> 0.0
    end
  end

  defp recalculate_baselines do
    # In production, this would query the database for detection frequency
    # For now, just clean up expired suppressions
    now = DateTime.utc_now()

    @ets_suppressions
    |> :ets.tab2list()
    |> Enum.each(fn {key, %{expires_at: expires_at}} ->
      if DateTime.compare(now, expires_at) == :gt do
        :ets.delete(@ets_suppressions, key)
      end
    end)

    Logger.debug("[ConfidenceScorer] Baseline recalculation completed")
  rescue
    _ -> :ok
  end

  defp schedule_baseline_recalc do
    Process.send_after(self(), :recalc_baselines, :timer.hours(1))
  end
end
