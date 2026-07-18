defmodule TamanduaServer.AISecurity.ModelAuditor do
  @moduledoc """
  AI Model Behavior Auditor.

  Tracks AI model behaviour over time and detects drift, manipulation,
  and compliance deviations.  Provides:

  - **Baseline establishment**: builds statistical profiles of model output
    distributions (confidence, sentiment, topic, latency, token count)
  - **Drift detection**: detects statistically significant changes in output
    distributions using CUSUM (cumulative sum) control charts and sliding-window
    z-score analysis
  - **Manipulation indicators**: detects sudden behaviour changes such as
    out-of-distribution outputs, repeated identical responses, or drastic
    sentiment shifts
  - **Compliance logging**: records every model invocation with enough metadata
    for EU AI Act transparency and auditability requirements
  - **Model lifecycle events**: tracks model version changes, retraining events,
    and configuration changes

  Uses ETS for fast access to baselines and running statistics.
  """

  use GenServer
  require Logger

  # ETS tables
  @baselines_table :model_auditor_baselines
  @events_table :model_auditor_events
  @alerts_table :model_auditor_alerts

  # Drift detection parameters
  @cusum_threshold 5.0
  @drift_z_threshold 2.5
  @baseline_min_samples 50

  # Sliding windows
  @recent_window_size 100
  @sentiment_bins [:very_negative, :negative, :neutral, :positive, :very_positive]

  # Intervals
  @drift_check_interval :timer.minutes(5)
  @events_trim_interval :timer.minutes(10)
  @max_events 100_000
  @max_alerts 10_000

  defstruct [
    :stats,
    :model_versions
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Record a model invocation for auditing and baseline tracking.

  Event map:
  - `:model_id` (required) - model identifier (e.g. "gpt-4", "claude-3-opus")
  - `:organization_id` - tenant ID
  - `:user_id` - who invoked the model
  - `:prompt_tokens` - number of prompt tokens
  - `:completion_tokens` - number of completion tokens
  - `:latency_ms` - end-to-end latency
  - `:confidence` - model confidence score (0.0-1.0) if available
  - `:sentiment` - output sentiment (:very_negative to :very_positive)
  - `:topics` - list of detected topic tags
  - `:output_hash` - hash of the output for dedup detection
  - `:model_version` - version string of the model
  - `:metadata` - arbitrary additional metadata
  """
  @spec record_invocation(map()) :: :ok
  def record_invocation(event) do
    GenServer.cast(__MODULE__, {:record_invocation, event})
  end

  @doc """
  Record a model lifecycle event (version change, retraining, config update).
  """
  @spec record_lifecycle_event(String.t(), atom(), map()) :: :ok
  def record_lifecycle_event(model_id, event_type, details \\ %{}) do
    GenServer.cast(__MODULE__, {:lifecycle_event, model_id, event_type, details})
  end

  @doc """
  Get the current baseline for a model.
  """
  @spec get_baseline(String.t()) :: {:ok, map()} | {:error, :not_found | :insufficient_data}
  def get_baseline(model_id) do
    GenServer.call(__MODULE__, {:get_baseline, model_id})
  end

  @doc """
  Get drift alerts for a model or all models.
  """
  @spec get_drift_alerts(keyword()) :: [map()]
  def get_drift_alerts(opts \\ []) do
    GenServer.call(__MODULE__, {:get_drift_alerts, opts})
  end

  @doc """
  Get the compliance event log for a model, suitable for regulatory reporting.
  """
  @spec get_compliance_log(String.t(), keyword()) :: [map()]
  def get_compliance_log(model_id, opts \\ []) do
    GenServer.call(__MODULE__, {:get_compliance_log, model_id, opts})
  end

  @doc """
  Get auditor statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Force a drift check for all models (normally runs on a timer).
  """
  @spec check_drift() :: :ok
  def check_drift do
    GenServer.call(__MODULE__, :check_drift)
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    :ets.new(@baselines_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@events_table, [:named_table, :ordered_set, :public, read_concurrency: true])
    :ets.new(@alerts_table, [:named_table, :ordered_set, :public, read_concurrency: true])

    state = %__MODULE__{
      stats: init_stats(),
      model_versions: %{}
    }

    schedule_drift_check()
    schedule_events_trim()

    Logger.info("[ModelAuditor] AI Model Behavior Auditor initialized")
    {:ok, state}
  end

  @impl true
  def handle_cast({:record_invocation, event}, state) do
    model_id = event[:model_id] || "unknown"
    now = DateTime.utc_now()

    # Store event in audit trail
    event_key = System.unique_integer([:positive, :monotonic])
    audit_event = %{
      id: event_key,
      type: :invocation,
      model_id: model_id,
      organization_id: event[:organization_id] || "default",
      user_id: event[:user_id] || "anonymous",
      prompt_tokens: event[:prompt_tokens] || 0,
      completion_tokens: event[:completion_tokens] || 0,
      latency_ms: event[:latency_ms] || 0.0,
      confidence: event[:confidence],
      sentiment: event[:sentiment],
      topics: event[:topics] || [],
      output_hash: event[:output_hash],
      model_version: event[:model_version],
      metadata: event[:metadata] || %{},
      timestamp: now
    }
    :ets.insert(@events_table, {event_key, audit_event})

    # Update baseline
    update_baseline(model_id, audit_event)

    # Track model versions
    new_versions = if event[:model_version] do
      Map.put(state.model_versions, model_id, event[:model_version])
    else
      state.model_versions
    end

    new_stats = increment_stat(state.stats, :invocations_recorded)
    {:noreply, %{state | stats: new_stats, model_versions: new_versions}}
  end

  @impl true
  def handle_cast({:lifecycle_event, model_id, event_type, details}, state) do
    event_key = System.unique_integer([:positive, :monotonic])

    lifecycle_event = %{
      id: event_key,
      type: :lifecycle,
      model_id: model_id,
      event_type: event_type,
      details: details,
      timestamp: DateTime.utc_now()
    }
    :ets.insert(@events_table, {event_key, lifecycle_event})

    # If model version changed, reset the drift CUSUM accumulators
    if event_type in [:version_change, :retrained] do
      reset_drift_accumulators(model_id)
    end

    new_stats = increment_stat(state.stats, :lifecycle_events_recorded)
    Logger.info("[ModelAuditor] Lifecycle event for #{model_id}: #{event_type}")
    {:noreply, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:get_baseline, model_id}, _from, state) do
    case :ets.lookup(@baselines_table, model_id) do
      [{^model_id, baseline}] ->
        if baseline.sample_count >= @baseline_min_samples do
          {:reply, {:ok, format_baseline(baseline)}, state}
        else
          {:reply, {:error, :insufficient_data}, state}
        end
      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:get_drift_alerts, opts}, _from, state) do
    model_id = opts[:model_id]
    limit = opts[:limit] || 100

    alerts = :ets.tab2list(@alerts_table)
    |> Enum.map(fn {_key, alert} -> alert end)
    |> then(fn alerts ->
      if model_id, do: Enum.filter(alerts, & &1.model_id == model_id), else: alerts
    end)
    |> Enum.sort_by(& &1.detected_at, {:desc, DateTime})
    |> Enum.take(limit)

    {:reply, alerts, state}
  end

  @impl true
  def handle_call({:get_compliance_log, model_id, opts}, _from, state) do
    limit = opts[:limit] || 500
    since = opts[:since]

    events = :ets.tab2list(@events_table)
    |> Enum.map(fn {_key, event} -> event end)
    |> Enum.filter(fn e -> e.model_id == model_id end)
    |> then(fn events ->
      if since do
        Enum.filter(events, fn e -> DateTime.compare(e.timestamp, since) in [:gt, :eq] end)
      else
        events
      end
    end)
    |> Enum.sort_by(& &1.timestamp, {:desc, DateTime})
    |> Enum.take(limit)
    |> Enum.map(&format_compliance_entry/1)

    {:reply, events, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    stats = Map.merge(state.stats, %{
      baselines_tracked: :ets.info(@baselines_table, :size),
      events_in_log: :ets.info(@events_table, :size),
      active_alerts: :ets.info(@alerts_table, :size),
      tracked_models: Map.keys(state.model_versions),
      model_versions: state.model_versions
    })
    {:reply, stats, state}
  end

  @impl true
  def handle_call(:check_drift, _from, state) do
    new_stats = perform_drift_check(state)
    {:reply, :ok, %{state | stats: new_stats}}
  end

  @impl true
  def handle_info(:drift_check, state) do
    new_stats = perform_drift_check(state)
    schedule_drift_check()
    {:noreply, %{state | stats: new_stats}}
  end

  @impl true
  def handle_info(:events_trim, state) do
    trim_events()
    trim_alerts()
    schedule_events_trim()
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Baseline Management
  # ============================================================================

  defp update_baseline(model_id, event) do
    baseline = case :ets.lookup(@baselines_table, model_id) do
      [{^model_id, b}] -> b
      [] -> new_baseline()
    end

    updated = baseline
    |> update_confidence_stats(event[:confidence])
    |> update_latency_stats(event[:latency_ms])
    |> update_token_stats(event[:completion_tokens])
    |> update_sentiment_distribution(event[:sentiment])
    |> update_topic_distribution(event[:topics])
    |> update_output_dedup(event[:output_hash])
    |> update_cusum(event)
    |> Map.update(:sample_count, 1, &(&1 + 1))
    |> Map.put(:last_updated, DateTime.utc_now())

    :ets.insert(@baselines_table, {model_id, updated})
  end

  defp new_baseline do
    %{
      sample_count: 0,

      # Running statistics (Welford's algorithm for online mean/variance)
      confidence_mean: 0.0,
      confidence_m2: 0.0,
      confidence_min: 1.0,
      confidence_max: 0.0,
      confidence_recent: [],

      latency_mean: 0.0,
      latency_m2: 0.0,
      latency_min: :infinity,
      latency_max: 0.0,
      latency_recent: [],

      tokens_mean: 0.0,
      tokens_m2: 0.0,
      tokens_recent: [],

      # Distribution tracking
      sentiment_counts: Map.new(@sentiment_bins, fn s -> {s, 0} end),
      topic_counts: %{},
      output_hash_counts: %{},

      # CUSUM accumulators for drift detection
      cusum_confidence_pos: 0.0,
      cusum_confidence_neg: 0.0,
      cusum_latency_pos: 0.0,
      cusum_latency_neg: 0.0,
      cusum_tokens_pos: 0.0,
      cusum_tokens_neg: 0.0,

      last_updated: nil,
      created_at: DateTime.utc_now()
    }
  end

  # Welford's online algorithm for running mean and variance
  defp welford_update(mean, m2, _n, nil), do: {mean, m2}
  defp welford_update(mean, m2, n, value) when is_number(value) do
    delta = value - mean
    new_mean = mean + delta / max(n, 1)
    delta2 = value - new_mean
    new_m2 = m2 + delta * delta2
    {new_mean, new_m2}
  end
  defp welford_update(mean, m2, _, _), do: {mean, m2}

  defp update_confidence_stats(baseline, nil), do: baseline
  defp update_confidence_stats(baseline, confidence) when is_number(confidence) do
    n = baseline.sample_count + 1
    {new_mean, new_m2} = welford_update(
      baseline.confidence_mean, baseline.confidence_m2, n, confidence
    )
    recent = [confidence | baseline.confidence_recent] |> Enum.take(@recent_window_size)

    %{baseline |
      confidence_mean: new_mean,
      confidence_m2: new_m2,
      confidence_min: min(baseline.confidence_min, confidence),
      confidence_max: max(baseline.confidence_max, confidence),
      confidence_recent: recent
    }
  end
  defp update_confidence_stats(baseline, _), do: baseline

  defp update_latency_stats(baseline, nil), do: baseline
  defp update_latency_stats(baseline, latency) when is_number(latency) do
    n = baseline.sample_count + 1
    {new_mean, new_m2} = welford_update(
      baseline.latency_mean, baseline.latency_m2, n, latency
    )
    recent = [latency | baseline.latency_recent] |> Enum.take(@recent_window_size)

    latency_min = if baseline.latency_min == :infinity, do: latency, else: min(baseline.latency_min, latency)

    %{baseline |
      latency_mean: new_mean,
      latency_m2: new_m2,
      latency_min: latency_min,
      latency_max: max(baseline.latency_max, latency),
      latency_recent: recent
    }
  end
  defp update_latency_stats(baseline, _), do: baseline

  defp update_token_stats(baseline, nil), do: baseline
  defp update_token_stats(baseline, tokens) when is_number(tokens) do
    n = baseline.sample_count + 1
    {new_mean, new_m2} = welford_update(
      baseline.tokens_mean, baseline.tokens_m2, n, tokens
    )
    recent = [tokens | baseline.tokens_recent] |> Enum.take(@recent_window_size)

    %{baseline |
      tokens_mean: new_mean,
      tokens_m2: new_m2,
      tokens_recent: recent
    }
  end
  defp update_token_stats(baseline, _), do: baseline

  defp update_sentiment_distribution(baseline, nil), do: baseline
  defp update_sentiment_distribution(baseline, sentiment) when sentiment in @sentiment_bins do
    new_counts = Map.update(baseline.sentiment_counts, sentiment, 1, &(&1 + 1))
    %{baseline | sentiment_counts: new_counts}
  end
  defp update_sentiment_distribution(baseline, _), do: baseline

  defp update_topic_distribution(baseline, nil), do: baseline
  defp update_topic_distribution(baseline, topics) when is_list(topics) do
    new_counts = Enum.reduce(topics, baseline.topic_counts, fn topic, acc ->
      Map.update(acc, topic, 1, &(&1 + 1))
    end)
    %{baseline | topic_counts: new_counts}
  end
  defp update_topic_distribution(baseline, _), do: baseline

  defp update_output_dedup(baseline, nil), do: baseline
  defp update_output_dedup(baseline, hash) do
    new_counts = Map.update(baseline.output_hash_counts, hash, 1, &(&1 + 1))
    # Keep only the top 1000 hashes
    trimmed = if map_size(new_counts) > 1000 do
      new_counts
      |> Enum.sort_by(fn {_, v} -> v end, :desc)
      |> Enum.take(1000)
      |> Map.new()
    else
      new_counts
    end
    %{baseline | output_hash_counts: trimmed}
  end

  # CUSUM (Cumulative Sum) control chart updates
  defp update_cusum(baseline, event) do
    n = baseline.sample_count + 1

    baseline
    |> cusum_update_metric(:confidence, event[:confidence], n)
    |> cusum_update_metric(:latency, event[:latency_ms], n)
    |> cusum_update_metric(:tokens, event[:completion_tokens], n)
  end

  defp cusum_update_metric(baseline, _metric, nil, _n), do: baseline
  defp cusum_update_metric(baseline, metric, value, n) when is_number(value) and n > @baseline_min_samples do
    mean_key = :"#{metric}_mean"
    m2_key = :"#{metric}_m2"
    pos_key = :"cusum_#{metric}_pos"
    neg_key = :"cusum_#{metric}_neg"

    mean = Map.get(baseline, mean_key, 0.0)
    m2 = Map.get(baseline, m2_key, 0.0)
    variance = if n > 1, do: m2 / (n - 1), else: 1.0
    stddev = :math.sqrt(max(variance, 0.0001))

    # Standardized deviation
    z = (value - mean) / stddev

    # Update CUSUM accumulators
    old_pos = Map.get(baseline, pos_key, 0.0)
    old_neg = Map.get(baseline, neg_key, 0.0)

    new_pos = max(0.0, old_pos + z - 0.5)  # slack parameter = 0.5
    new_neg = max(0.0, old_neg - z - 0.5)

    baseline
    |> Map.put(pos_key, new_pos)
    |> Map.put(neg_key, new_neg)
  end
  defp cusum_update_metric(baseline, _metric, _value, _n), do: baseline

  defp reset_drift_accumulators(model_id) do
    case :ets.lookup(@baselines_table, model_id) do
      [{^model_id, baseline}] ->
        updated = %{baseline |
          cusum_confidence_pos: 0.0,
          cusum_confidence_neg: 0.0,
          cusum_latency_pos: 0.0,
          cusum_latency_neg: 0.0,
          cusum_tokens_pos: 0.0,
          cusum_tokens_neg: 0.0
        }
        :ets.insert(@baselines_table, {model_id, updated})
      [] ->
        :ok
    end
  end

  # ============================================================================
  # Drift Detection
  # ============================================================================

  defp perform_drift_check(state) do
    baselines = :ets.tab2list(@baselines_table)

    Enum.each(baselines, fn {model_id, baseline} ->
      if baseline.sample_count >= @baseline_min_samples do
        alerts = []

        # CUSUM-based drift detection
        alerts = alerts ++ check_cusum_drift(model_id, baseline, :confidence)
        alerts = alerts ++ check_cusum_drift(model_id, baseline, :latency)
        alerts = alerts ++ check_cusum_drift(model_id, baseline, :tokens)

        # Sliding-window z-score on recent vs. baseline
        alerts = alerts ++ check_window_drift(model_id, baseline)

        # Output repetition detection
        alerts = alerts ++ check_output_repetition(model_id, baseline)

        # Sentiment shift detection
        alerts = alerts ++ check_sentiment_shift(model_id, baseline)

        # Store new alerts
        Enum.each(alerts, fn alert ->
          alert_key = System.unique_integer([:positive, :monotonic])
          :ets.insert(@alerts_table, {alert_key, alert})
        end)

        if length(alerts) > 0 do
          Logger.warning("[ModelAuditor] Drift detected for model #{model_id}: #{length(alerts)} alert(s)")
        end
      end
    end)

    increment_stat(state.stats, :drift_checks_performed)
  end

  defp check_cusum_drift(model_id, baseline, metric) do
    pos_key = :"cusum_#{metric}_pos"
    neg_key = :"cusum_#{metric}_neg"

    pos_val = Map.get(baseline, pos_key, 0.0)
    neg_val = Map.get(baseline, neg_key, 0.0)

    alerts = []

    alerts = if pos_val > @cusum_threshold do
      [%{
        model_id: model_id,
        type: :cusum_drift,
        metric: metric,
        direction: :increase,
        cusum_value: Float.round(pos_val, 3),
        threshold: @cusum_threshold,
        severity: severity_from_cusum(pos_val),
        description: "CUSUM drift detected: #{metric} showing sustained increase (CUSUM=#{Float.round(pos_val, 2)})",
        detected_at: DateTime.utc_now()
      } | alerts]
    else
      alerts
    end

    if neg_val > @cusum_threshold do
      [%{
        model_id: model_id,
        type: :cusum_drift,
        metric: metric,
        direction: :decrease,
        cusum_value: Float.round(neg_val, 3),
        threshold: @cusum_threshold,
        severity: severity_from_cusum(neg_val),
        description: "CUSUM drift detected: #{metric} showing sustained decrease (CUSUM=#{Float.round(neg_val, 2)})",
        detected_at: DateTime.utc_now()
      } | alerts]
    else
      alerts
    end
  end

  defp check_window_drift(model_id, baseline) do
    alerts = []

    # Check confidence drift
    alerts = if length(baseline.confidence_recent) >= 20 do
      recent_mean = Enum.sum(baseline.confidence_recent) / length(baseline.confidence_recent)
      n = baseline.sample_count
      variance = if n > 1, do: baseline.confidence_m2 / (n - 1), else: 0.0
      stddev = :math.sqrt(max(variance, 0.0001))
      z = abs(recent_mean - baseline.confidence_mean) / stddev

      if z > @drift_z_threshold do
        [%{
          model_id: model_id,
          type: :window_drift,
          metric: :confidence,
          baseline_mean: Float.round(baseline.confidence_mean, 4),
          recent_mean: Float.round(recent_mean, 4),
          z_score: Float.round(z, 3),
          severity: if(z > 4.0, do: :high, else: :medium),
          description: "Confidence distribution shifted (baseline=#{Float.round(baseline.confidence_mean, 3)}, recent=#{Float.round(recent_mean, 3)}, z=#{Float.round(z, 2)})",
          detected_at: DateTime.utc_now()
        } | alerts]
      else
        alerts
      end
    else
      alerts
    end

    # Check latency drift
    if length(baseline.latency_recent) >= 20 do
      recent_mean = Enum.sum(baseline.latency_recent) / length(baseline.latency_recent)
      n = baseline.sample_count
      variance = if n > 1, do: baseline.latency_m2 / (n - 1), else: 0.0
      stddev = :math.sqrt(max(variance, 0.0001))
      z = abs(recent_mean - baseline.latency_mean) / stddev

      if z > @drift_z_threshold do
        [%{
          model_id: model_id,
          type: :window_drift,
          metric: :latency,
          baseline_mean: Float.round(baseline.latency_mean, 2),
          recent_mean: Float.round(recent_mean, 2),
          z_score: Float.round(z, 3),
          severity: if(z > 4.0, do: :high, else: :medium),
          description: "Latency distribution shifted (baseline=#{Float.round(baseline.latency_mean, 1)}ms, recent=#{Float.round(recent_mean, 1)}ms, z=#{Float.round(z, 2)})",
          detected_at: DateTime.utc_now()
        } | alerts]
      else
        alerts
      end
    else
      alerts
    end
  end

  defp check_output_repetition(model_id, baseline) do
    hash_counts = baseline.output_hash_counts
    total = baseline.sample_count

    if total > 0 and map_size(hash_counts) > 0 do
      max_count = hash_counts |> Map.values() |> Enum.max()
      repetition_ratio = max_count / total

      if repetition_ratio > 0.3 and max_count > 10 do
        [%{
          model_id: model_id,
          type: :output_repetition,
          repetition_ratio: Float.round(repetition_ratio, 4),
          max_identical: max_count,
          severity: if(repetition_ratio > 0.5, do: :high, else: :medium),
          description: "Unusual output repetition detected (#{Float.round(repetition_ratio * 100, 1)}% identical outputs, max=#{max_count})",
          detected_at: DateTime.utc_now()
        }]
      else
        []
      end
    else
      []
    end
  end

  defp check_sentiment_shift(model_id, baseline) do
    counts = baseline.sentiment_counts
    total = Enum.sum(Map.values(counts))

    if total >= @baseline_min_samples do
      # Check if any single sentiment dominates excessively (>80%)
      dominant = counts |> Enum.max_by(fn {_, v} -> v end)
      {dominant_sentiment, dominant_count} = dominant
      ratio = dominant_count / total

      if ratio > 0.80 and dominant_sentiment in [:very_negative, :very_positive] do
        [%{
          model_id: model_id,
          type: :sentiment_shift,
          dominant_sentiment: dominant_sentiment,
          ratio: Float.round(ratio, 4),
          severity: :medium,
          description: "Sentiment skew detected: #{dominant_sentiment} at #{Float.round(ratio * 100, 1)}%",
          detected_at: DateTime.utc_now()
        }]
      else
        []
      end
    else
      []
    end
  end

  # ============================================================================
  # Formatting and Utilities
  # ============================================================================

  defp format_baseline(baseline) do
    n = baseline.sample_count

    confidence_var = if n > 1, do: baseline.confidence_m2 / (n - 1), else: 0.0
    latency_var = if n > 1, do: baseline.latency_m2 / (n - 1), else: 0.0
    tokens_var = if n > 1, do: baseline.tokens_m2 / (n - 1), else: 0.0

    %{
      sample_count: n,
      confidence: %{
        mean: Float.round(baseline.confidence_mean, 4),
        stddev: Float.round(:math.sqrt(max(confidence_var, 0.0)), 4),
        min: baseline.confidence_min,
        max: baseline.confidence_max,
        recent_mean: safe_mean(baseline.confidence_recent)
      },
      latency: %{
        mean: Float.round(baseline.latency_mean, 2),
        stddev: Float.round(:math.sqrt(max(latency_var, 0.0)), 2),
        min: if(baseline.latency_min == :infinity, do: 0.0, else: baseline.latency_min),
        max: baseline.latency_max,
        recent_mean: safe_mean(baseline.latency_recent)
      },
      tokens: %{
        mean: Float.round(baseline.tokens_mean, 2),
        stddev: Float.round(:math.sqrt(max(tokens_var, 0.0)), 2),
        recent_mean: safe_mean(baseline.tokens_recent)
      },
      sentiment_distribution: baseline.sentiment_counts,
      top_topics: baseline.topic_counts
      |> Enum.sort_by(fn {_, v} -> v end, :desc)
      |> Enum.take(20)
      |> Map.new(),
      unique_outputs: map_size(baseline.output_hash_counts),
      drift_indicators: %{
        cusum_confidence: %{pos: baseline.cusum_confidence_pos, neg: baseline.cusum_confidence_neg},
        cusum_latency: %{pos: baseline.cusum_latency_pos, neg: baseline.cusum_latency_neg},
        cusum_tokens: %{pos: baseline.cusum_tokens_pos, neg: baseline.cusum_tokens_neg}
      },
      created_at: baseline.created_at,
      last_updated: baseline.last_updated
    }
  end

  defp format_compliance_entry(event) do
    base = %{
      event_id: event.id,
      type: event.type,
      model_id: event.model_id,
      timestamp: event.timestamp
    }

    case event.type do
      :invocation ->
        Map.merge(base, %{
          user_id: event.user_id,
          organization_id: event.organization_id,
          prompt_tokens: event.prompt_tokens,
          completion_tokens: event.completion_tokens,
          latency_ms: event.latency_ms,
          model_version: event.model_version,
          # Do not include prompt/response content for compliance log
          # to minimize data exposure in audit reports
          topics: event.topics
        })

      :lifecycle ->
        Map.merge(base, %{
          lifecycle_event: event.event_type,
          details: event.details
        })

      _ ->
        base
    end
  end

  defp severity_from_cusum(val) when val > @cusum_threshold * 2, do: :critical
  defp severity_from_cusum(val) when val > @cusum_threshold * 1.5, do: :high
  defp severity_from_cusum(_), do: :medium

  defp safe_mean([]), do: 0.0
  defp safe_mean(list) do
    Float.round(Enum.sum(list) / length(list), 4)
  end

  defp init_stats do
    %{
      invocations_recorded: 0,
      lifecycle_events_recorded: 0,
      drift_checks_performed: 0,
      alerts_generated: 0,
      started_at: DateTime.utc_now()
    }
  end

  defp increment_stat(stats, key) do
    Map.update(stats, key, 1, &(&1 + 1))
  end

  defp trim_events do
    size = :ets.info(@events_table, :size)
    if size > @max_events do
      to_delete = size - @max_events
      :ets.tab2list(@events_table)
      |> Enum.sort_by(fn {key, _} -> key end)
      |> Enum.take(to_delete)
      |> Enum.each(fn {key, _} -> :ets.delete(@events_table, key) end)
    end
  end

  defp trim_alerts do
    size = :ets.info(@alerts_table, :size)
    if size > @max_alerts do
      to_delete = size - @max_alerts
      :ets.tab2list(@alerts_table)
      |> Enum.sort_by(fn {key, _} -> key end)
      |> Enum.take(to_delete)
      |> Enum.each(fn {key, _} -> :ets.delete(@alerts_table, key) end)
    end
  end

  defp schedule_drift_check do
    Process.send_after(self(), :drift_check, @drift_check_interval)
  end

  defp schedule_events_trim do
    Process.send_after(self(), :events_trim, @events_trim_interval)
  end
end
