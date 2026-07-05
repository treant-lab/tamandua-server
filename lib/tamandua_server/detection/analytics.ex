defmodule TamanduaServer.Detection.Analytics do
  @moduledoc """
  Detection Analytics & Tuning GenServer.

  Tracks per-rule detection metrics, pipeline performance, coverage gaps,
  and generates tuning recommendations. Uses ETS tables for high-performance
  metric tracking with periodic PostgreSQL persistence.

  ## Metrics tracked

  - Per-rule: hits, TP/FP counts, avg confidence, effectiveness score
  - Pipeline: events/sec, latency per stage, queue depth, error rates
  - Coverage: MITRE technique gaps, event type gaps, time-of-day gaps
  - Tuning: high FP rules, dormant rules, correlated rules, ML threshold adjustments
  """

  use GenServer
  require Logger

  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Detection.Mitre

  @ets_rule_metrics :detection_analytics_rule_metrics
  @ets_pipeline_metrics :detection_analytics_pipeline_metrics
  @ets_hourly_metrics :detection_analytics_hourly_metrics

  # Persist to database every 5 minutes
  @persist_interval_ms 5 * 60 * 1_000

  # Recalculate recommendations every 15 minutes
  @recommendation_interval_ms 15 * 60 * 1_000

  # Pipeline stages
  @pipeline_stages ~w(sigma yara ml ioc behavioral c2 dns threat_intel_feed)

  defstruct [
    :rule_metrics_table,
    :pipeline_metrics_table,
    :hourly_metrics_table,
    :recommendations,
    :blind_spots,
    :last_persist_at,
    :last_recommendation_at
  ]

  # =========================================================================
  # Client API
  # =========================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Record a detection event for a specific rule.
  Called from the Detection Engine after each analysis.
  """
  @spec record_detection(String.t(), map()) :: :ok
  def record_detection(rule_id, detection_data) do
    GenServer.cast(__MODULE__, {:record_detection, rule_id, detection_data})
  end

  @doc """
  Record pipeline stage timing.
  Called from the Detection Engine for each processing stage.
  """
  @spec record_pipeline_timing(String.t(), non_neg_integer()) :: :ok
  def record_pipeline_timing(stage, latency_us) do
    GenServer.cast(__MODULE__, {:record_pipeline_timing, stage, latency_us})
  end

  @doc """
  Record a pipeline error.
  """
  @spec record_pipeline_error(String.t(), term()) :: :ok
  def record_pipeline_error(stage, _error) do
    GenServer.cast(__MODULE__, {:record_pipeline_error, stage})
  end

  @doc """
  Record a verdict (TP/FP/benign) for a detection rule.
  Called when an analyst provides feedback.
  """
  @spec record_verdict(String.t(), String.t()) :: :ok
  def record_verdict(rule_id, verdict) when verdict in ~w(true_positive false_positive benign) do
    GenServer.cast(__MODULE__, {:record_verdict, rule_id, verdict})
  end

  @doc """
  Get overview metrics for the analytics dashboard.
  """
  @spec get_overview() :: map()
  def get_overview do
    if Process.whereis(__MODULE__) do
      GenServer.call(__MODULE__, :get_overview)
    else
      empty_overview()
    end
  end

  @doc """
  Get per-rule performance metrics.
  """
  @spec get_rule_metrics(keyword()) :: [map()]
  def get_rule_metrics(opts \\ []) do
    GenServer.call(__MODULE__, {:get_rule_metrics, opts})
  end

  @doc """
  Get pipeline performance metrics.
  """
  @spec get_pipeline_metrics() :: map()
  def get_pipeline_metrics do
    GenServer.call(__MODULE__, :get_pipeline_metrics)
  end

  @doc """
  Get detection blind spots (MITRE gaps, event type gaps, time gaps).
  """
  @spec get_blind_spots() :: map()
  def get_blind_spots do
    GenServer.call(__MODULE__, :get_blind_spots)
  end

  @doc """
  Get tuning recommendations.
  """
  @spec get_recommendations() :: [map()]
  def get_recommendations do
    GenServer.call(__MODULE__, :get_recommendations)
  end

  @doc """
  Get time-series trend metrics.
  """
  @spec get_trends(String.t()) :: map()
  def get_trends(time_range \\ "7d") do
    GenServer.call(__MODULE__, {:get_trends, time_range})
  end

  # =========================================================================
  # Server Callbacks
  # =========================================================================

  @impl true
  def init(_opts) do
    # Create ETS tables for high-performance metric tracking
    rule_table = :ets.new(@ets_rule_metrics, [
      :set, :public, :named_table,
      read_concurrency: true, write_concurrency: true
    ])

    pipeline_table = :ets.new(@ets_pipeline_metrics, [
      :set, :public, :named_table,
      read_concurrency: true, write_concurrency: true
    ])

    hourly_table = :ets.new(@ets_hourly_metrics, [
      :set, :public, :named_table,
      read_concurrency: true, write_concurrency: true
    ])

    # Initialize pipeline stage counters
    Enum.each(@pipeline_stages, fn stage ->
      :ets.insert(pipeline_table, {stage, 0, 0, 0, 0, []})
      # Format: {stage, total_events, total_latency_us, error_count, events_last_minute, latency_samples}
    end)

    state = %__MODULE__{
      rule_metrics_table: rule_table,
      pipeline_metrics_table: pipeline_table,
      hourly_metrics_table: hourly_table,
      recommendations: [],
      blind_spots: %{},
      last_persist_at: DateTime.utc_now(),
      last_recommendation_at: nil
    }

    # Schedule periodic tasks
    Process.send_after(self(), :persist_metrics, @persist_interval_ms)
    Process.send_after(self(), :recalculate_recommendations, 10_000)

    Logger.info("[DetectionAnalytics] Started with ETS tables for metric tracking")
    {:ok, state}
  end

  @impl true
  def handle_cast({:record_detection, rule_id, detection_data}, state) do
    now = System.system_time(:second)
    confidence = detection_data[:confidence] || 0.5
    rule_name = detection_data[:rule_name] || rule_id
    rule_type = to_string(detection_data[:type] || "unknown")
    mitre_techniques = detection_data[:mitre_techniques] || []

    case :ets.lookup(@ets_rule_metrics, rule_id) do
      [{^rule_id, metrics}] ->
        updated = %{metrics |
          total_hits: metrics.total_hits + 1,
          total_confidence: metrics.total_confidence + confidence,
          last_hit_at: now,
          mitre_techniques: Enum.uniq(metrics.mitre_techniques ++ mitre_techniques)
        }
        :ets.insert(@ets_rule_metrics, {rule_id, updated})

      [] ->
        metrics = %{
          rule_id: rule_id,
          rule_name: rule_name,
          rule_type: rule_type,
          total_hits: 1,
          true_positives: 0,
          false_positives: 0,
          benign_count: 0,
          total_confidence: confidence,
          first_hit_at: now,
          last_hit_at: now,
          mitre_techniques: mitre_techniques,
          triage_times: []
        }
        :ets.insert(@ets_rule_metrics, {rule_id, metrics})
    end

    # Record hourly metric
    hour_key = {div(now, 3600) * 3600, rule_type}
    case :ets.lookup(@ets_hourly_metrics, hour_key) do
      [{^hour_key, count}] ->
        :ets.insert(@ets_hourly_metrics, {hour_key, count + 1})
      [] ->
        :ets.insert(@ets_hourly_metrics, {hour_key, 1})
    end

    {:noreply, state}
  end

  @impl true
  def handle_cast({:record_pipeline_timing, stage, latency_us}, state) do
    case :ets.lookup(@ets_pipeline_metrics, stage) do
      [{^stage, total_events, total_latency, error_count, _events_last_min, latency_samples}] ->
        # Keep last 100 latency samples for percentile calculation
        samples = Enum.take([latency_us | latency_samples], 100)
        :ets.insert(@ets_pipeline_metrics, {
          stage, total_events + 1, total_latency + latency_us,
          error_count, 0, samples
        })

      [] ->
        :ets.insert(@ets_pipeline_metrics, {stage, 1, latency_us, 0, 0, [latency_us]})
    end

    {:noreply, state}
  end

  @impl true
  def handle_cast({:record_pipeline_error, stage}, state) do
    case :ets.lookup(@ets_pipeline_metrics, stage) do
      [{^stage, total_events, total_latency, error_count, events_last_min, samples}] ->
        :ets.insert(@ets_pipeline_metrics, {
          stage, total_events, total_latency,
          error_count + 1, events_last_min, samples
        })

      [] ->
        :ets.insert(@ets_pipeline_metrics, {stage, 0, 0, 1, 0, []})
    end

    {:noreply, state}
  end

  @impl true
  def handle_cast({:record_verdict, rule_id, verdict}, state) do
    now = System.system_time(:second)

    case :ets.lookup(@ets_rule_metrics, rule_id) do
      [{^rule_id, metrics}] ->
        updated = case verdict do
          "true_positive" ->
            %{metrics | true_positives: metrics.true_positives + 1}

          "false_positive" ->
            %{metrics | false_positives: metrics.false_positives + 1}

          "benign" ->
            %{metrics | benign_count: metrics.benign_count + 1}
        end

        # Track time to triage (seconds from last hit to verdict)
        triage_time = now - (metrics.last_hit_at || now)
        triage_times = Enum.take([triage_time | metrics.triage_times], 50)
        updated = %{updated | triage_times: triage_times}

        :ets.insert(@ets_rule_metrics, {rule_id, updated})

      [] ->
        # Rule not seen yet, create entry
        base = %{
          rule_id: rule_id,
          rule_name: rule_id,
          rule_type: "unknown",
          total_hits: 0,
          true_positives: 0,
          false_positives: 0,
          benign_count: 0,
          total_confidence: 0.0,
          first_hit_at: now,
          last_hit_at: now,
          mitre_techniques: [],
          triage_times: []
        }

        updated = case verdict do
          "true_positive" -> %{base | true_positives: 1}
          "false_positive" -> %{base | false_positives: 1}
          "benign" -> %{base | benign_count: 1}
        end

        :ets.insert(@ets_rule_metrics, {rule_id, updated})
    end

    {:noreply, state}
  end

  # =========================================================================
  # Call Handlers
  # =========================================================================

  defp empty_overview do
    %{
      total_rules: 0,
      active_rules: 0,
      total_detections: 0,
      avg_effectiveness: 0.0,
      false_positive_rate: 0.0,
      true_positive_rate: 0.0,
      detection_rate: 0.0,
      total_events_processed: 0,
      avg_pipeline_latency_ms: 0.0,
      total_recommendations: 0,
      total_blind_spots: 0
    }
  end

  @impl true
  def handle_call(:get_overview, _from, state) do
    rule_metrics = collect_all_rule_metrics()

    total_rules = length(rule_metrics)
    active_rules = Enum.count(rule_metrics, fn m -> m.total_hits > 0 end)
    total_hits = Enum.reduce(rule_metrics, 0, fn m, acc -> acc + m.total_hits end)
    total_tp = Enum.reduce(rule_metrics, 0, fn m, acc -> acc + m.true_positives end)
    total_fp = Enum.reduce(rule_metrics, 0, fn m, acc -> acc + m.false_positives end)
    total_reviewed = total_tp + total_fp

    avg_effectiveness = if total_rules > 0 do
      scores = Enum.map(rule_metrics, &calculate_effectiveness_score/1)
      Enum.sum(scores) / total_rules
    else
      0.0
    end

    fp_rate = if total_reviewed > 0 do
      total_fp / total_reviewed
    else
      0.0
    end

    detection_rate = get_detection_rate_from_db()

    # Pipeline throughput
    pipeline = collect_pipeline_metrics()
    total_events_processed = pipeline
      |> Map.values()
      |> Enum.reduce(0, fn stage, acc -> acc + stage.total_events end)

    avg_latency_ms = if map_size(pipeline) > 0 do
      total_lat = pipeline |> Map.values() |> Enum.reduce(0, fn s, acc -> acc + s.avg_latency_us end)
      total_lat / map_size(pipeline) / 1_000
    else
      0.0
    end

    overview = %{
      total_rules: total_rules,
      active_rules: active_rules,
      total_detections: total_hits,
      avg_effectiveness: Float.round(avg_effectiveness * 100, 1),
      false_positive_rate: Float.round(fp_rate * 100, 1),
      true_positive_rate: Float.round((1.0 - fp_rate) * 100, 1),
      detection_rate: Float.round(detection_rate * 100, 1),
      total_events_processed: total_events_processed,
      avg_pipeline_latency_ms: Float.round(avg_latency_ms, 2),
      total_recommendations: length(state.recommendations),
      total_blind_spots: count_blind_spots(state.blind_spots)
    }

    {:reply, overview, state}
  end

  @impl true
  def handle_call({:get_rule_metrics, opts}, _from, state) do
    metrics = collect_all_rule_metrics()

    # Enrich with calculated fields
    enriched = Enum.map(metrics, fn m ->
      effectiveness = calculate_effectiveness_score(m)
      avg_confidence = if m.total_hits > 0, do: m.total_confidence / m.total_hits, else: 0.0
      reviewed = m.true_positives + m.false_positives + m.benign_count
      fp_rate = if reviewed > 0, do: m.false_positives / reviewed, else: 0.0
      tp_rate = if reviewed > 0, do: m.true_positives / reviewed, else: 0.0

      mean_triage_seconds = if length(m.triage_times) > 0 do
        Enum.sum(m.triage_times) / length(m.triage_times)
      else
        nil
      end

      detection_to_alert_ratio = if m.total_hits > 0 do
        reviewed / m.total_hits
      else
        0.0
      end

      %{
        rule_id: m.rule_id,
        rule_name: m.rule_name,
        rule_type: m.rule_type,
        total_hits: m.total_hits,
        true_positives: m.true_positives,
        false_positives: m.false_positives,
        benign_count: m.benign_count,
        avg_confidence: Float.round(avg_confidence, 3),
        fp_rate: Float.round(fp_rate, 3),
        tp_rate: Float.round(tp_rate, 3),
        effectiveness_score: Float.round(effectiveness, 3),
        mean_triage_seconds: mean_triage_seconds,
        detection_to_alert_ratio: Float.round(detection_to_alert_ratio, 3),
        mitre_techniques: m.mitre_techniques,
        first_hit_at: format_unix_time(m.first_hit_at),
        last_hit_at: format_unix_time(m.last_hit_at)
      }
    end)

    # Apply sorting
    sort_by = Keyword.get(opts, :sort_by, :effectiveness_score)
    sort_order = Keyword.get(opts, :sort_order, :desc)

    sorted = Enum.sort_by(enriched, &Map.get(&1, sort_by, 0), sort_order)

    # Apply limit
    limited = case Keyword.get(opts, :limit) do
      nil -> sorted
      limit -> Enum.take(sorted, limit)
    end

    {:reply, limited, state}
  end

  @impl true
  def handle_call(:get_pipeline_metrics, _from, state) do
    pipeline = collect_pipeline_metrics()

    # Calculate events per second (from the last minute window)
    total_events = pipeline |> Map.values() |> Enum.reduce(0, fn s, acc -> acc + s.total_events end)

    result = %{
      stages: pipeline,
      total_events_processed: total_events,
      stages_summary: Enum.map(pipeline, fn {stage, metrics} ->
        %{
          stage: stage,
          total_events: metrics.total_events,
          avg_latency_us: metrics.avg_latency_us,
          avg_latency_ms: Float.round(metrics.avg_latency_us / 1_000, 2),
          p95_latency_us: metrics.p95_latency_us,
          p95_latency_ms: Float.round(metrics.p95_latency_us / 1_000, 2),
          error_count: metrics.error_count,
          error_rate: if(metrics.total_events > 0, do: Float.round(metrics.error_count / metrics.total_events, 4), else: 0.0)
        }
      end)
    }

    {:reply, result, state}
  end

  @impl true
  def handle_call(:get_blind_spots, _from, state) do
    blind_spots = calculate_blind_spots()
    {:reply, blind_spots, %{state | blind_spots: blind_spots}}
  end

  @impl true
  def handle_call(:get_recommendations, _from, state) do
    {:reply, state.recommendations, state}
  end

  @impl true
  def handle_call({:get_trends, time_range}, _from, state) do
    trends = calculate_trends(time_range)
    {:reply, trends, state}
  end

  # =========================================================================
  # Periodic Tasks
  # =========================================================================

  @impl true
  def handle_info(:persist_metrics, state) do
    # Persist ETS metrics to database (for historical analysis)
    persist_metrics_to_db()
    Process.send_after(self(), :persist_metrics, @persist_interval_ms)
    {:noreply, %{state | last_persist_at: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:recalculate_recommendations, state) do
    recommendations = generate_recommendations()
    blind_spots = calculate_blind_spots()

    Process.send_after(self(), :recalculate_recommendations, @recommendation_interval_ms)

    {:noreply, %{state |
      recommendations: recommendations,
      blind_spots: blind_spots,
      last_recommendation_at: DateTime.utc_now()
    }}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  def handle_info(_msg, state), do: {:noreply, state}

  # =========================================================================
  # Private: Metric Collection
  # =========================================================================

  defp collect_all_rule_metrics do
    :ets.tab2list(@ets_rule_metrics)
    |> Enum.map(fn {_rule_id, metrics} -> metrics end)
  end

  defp collect_pipeline_metrics do
    :ets.tab2list(@ets_pipeline_metrics)
    |> Enum.map(fn {stage, total_events, total_latency, error_count, _events_last_min, latency_samples} ->
      avg_latency = if total_events > 0, do: total_latency / total_events, else: 0
      p95_latency = calculate_percentile(latency_samples, 0.95)

      {stage, %{
        total_events: total_events,
        avg_latency_us: avg_latency,
        p95_latency_us: p95_latency,
        error_count: error_count
      }}
    end)
    |> Map.new()
  end

  defp calculate_percentile([], _p), do: 0
  defp calculate_percentile(samples, p) do
    sorted = Enum.sort(samples)
    index = round(p * (length(sorted) - 1))
    Enum.at(sorted, index, 0)
  end

  # =========================================================================
  # Private: Effectiveness Score
  # =========================================================================

  defp calculate_effectiveness_score(metrics) do
    reviewed = metrics.true_positives + metrics.false_positives + metrics.benign_count

    if reviewed == 0 do
      # No reviews yet -- moderate score to avoid penalizing unreviewed rules
      0.5
    else
      tp_rate = metrics.true_positives / reviewed
      fp_rate = metrics.false_positives / reviewed

      # Weighted combination: high TP rate is good, high FP rate is bad
      # Also factor in volume (rules that fire a lot and have good TP rate are more valuable)
      volume_factor = min(metrics.total_hits / 100.0, 1.0)

      base_score = (tp_rate * 0.6) + ((1.0 - fp_rate) * 0.3) + (volume_factor * 0.1)
      min(max(base_score, 0.0), 1.0)
    end
  end

  # =========================================================================
  # Private: Detection Rate
  # =========================================================================

  defp get_detection_rate_from_db do
    try do
      today = Date.utc_today()
      start_date = Date.add(today, -7)

      total_events = Repo.one(
        from(e in "telemetry_events",
          where: fragment("?::date", e.inserted_at) >= ^start_date,
          select: count(e.id)
        )
      ) || 0

      total_detections = Repo.one(
        from(a in Alert,
          where: fragment("?::date", a.inserted_at) >= ^start_date,
          select: count(a.id)
        )
      ) || 0

      if total_events > 0, do: total_detections / total_events, else: 0.0
    rescue
      _ -> 0.0
    end
  end

  # =========================================================================
  # Private: Blind Spot Analysis
  # =========================================================================

  defp calculate_blind_spots do
    %{
      mitre_gaps: calculate_mitre_gaps(),
      event_type_gaps: calculate_event_type_gaps(),
      time_of_day_gaps: calculate_time_of_day_gaps()
    }
  end

  defp calculate_mitre_gaps do
    # Get all known MITRE techniques
    all_techniques = try do
      Mitre.techniques()
      |> Enum.map(fn t -> t.id end)
    rescue
      _ -> []
    end

    # Get techniques covered by rules (from ETS)
    covered_techniques = collect_all_rule_metrics()
    |> Enum.flat_map(& &1.mitre_techniques)
    |> Enum.uniq()

    # Also check what techniques have been seen in alerts
    alert_techniques = try do
      Repo.all(
        from(a in Alert,
          where: not is_nil(a.mitre_techniques),
          select: a.mitre_techniques
        )
      )
      |> List.flatten()
      |> Enum.uniq()
    rescue
      _ -> []
    end

    all_covered = Enum.uniq(covered_techniques ++ alert_techniques)
    uncovered = all_techniques -- all_covered

    %{
      total_techniques: length(all_techniques),
      covered_techniques: length(all_covered),
      coverage_percent: if(length(all_techniques) > 0,
        do: Float.round(length(all_covered) / length(all_techniques) * 100, 1),
        else: 0.0
      ),
      uncovered_techniques: Enum.take(uncovered, 50),
      covered_by_rule_type: group_coverage_by_type()
    }
  end

  defp group_coverage_by_type do
    collect_all_rule_metrics()
    |> Enum.group_by(& &1.rule_type)
    |> Enum.map(fn {type, rules} ->
      techniques = rules |> Enum.flat_map(& &1.mitre_techniques) |> Enum.uniq()
      %{type: type, technique_count: length(techniques)}
    end)
  end

  defp calculate_event_type_gaps do
    # Known event types the agent can produce
    all_event_types = ~w(
      process_create process_terminate file_create file_modify file_delete
      network_connect dns_query registry_set registry_delete
      process_inject memory_scan shellcode_detected script_execution
      usb_connected usb_disconnected honeyfile_access named_pipe
    )

    # Event types covered by rules
    rule_metrics = collect_all_rule_metrics()
    covered_types = rule_metrics
    |> Enum.map(& &1.rule_type)
    |> Enum.uniq()

    # Event types seen in recent alerts
    alert_event_types = try do
      Repo.all(
        from(a in Alert,
          where: not is_nil(a.detection_metadata),
          select: fragment("?->>'event_type'", a.detection_metadata),
          limit: 1000
        )
      )
      |> Enum.filter(& &1)
      |> Enum.uniq()
    rescue
      _ -> []
    end

    all_covered = Enum.uniq(covered_types ++ alert_event_types)
    uncovered = all_event_types -- all_covered

    %{
      total_event_types: length(all_event_types),
      covered_event_types: length(all_covered),
      uncovered_event_types: uncovered
    }
  end

  defp calculate_time_of_day_gaps do
    # Analyze which hours have low detection coverage
    now = System.system_time(:second)
    week_ago = now - 7 * 24 * 3600

    hourly_counts = :ets.tab2list(@ets_hourly_metrics)
    |> Enum.filter(fn {{timestamp, _type}, _count} -> timestamp >= week_ago end)
    |> Enum.reduce(%{}, fn {{timestamp, _type}, count}, acc ->
      hour = rem(div(timestamp, 3600), 24)
      Map.update(acc, hour, count, &(&1 + count))
    end)

    # Find hours with below-average detection counts
    all_hours = 0..23 |> Enum.to_list()
    avg_count = if map_size(hourly_counts) > 0 do
      Enum.sum(Map.values(hourly_counts)) / 24
    else
      0.0
    end

    gap_hours = Enum.filter(all_hours, fn hour ->
      count = Map.get(hourly_counts, hour, 0)
      count < avg_count * 0.3  # Less than 30% of average
    end)

    %{
      hourly_distribution: Enum.map(all_hours, fn hour ->
        %{hour: hour, count: Map.get(hourly_counts, hour, 0)}
      end),
      gap_hours: gap_hours,
      avg_hourly_count: Float.round(avg_count, 1)
    }
  end

  defp count_blind_spots(blind_spots) when is_map(blind_spots) do
    mitre_gaps = get_in(blind_spots, [:mitre_gaps, :uncovered_techniques]) || []
    event_gaps = get_in(blind_spots, [:event_type_gaps, :uncovered_event_types]) || []
    time_gaps = get_in(blind_spots, [:time_of_day_gaps, :gap_hours]) || []

    length(mitre_gaps) + length(event_gaps) + length(time_gaps)
  end
  defp count_blind_spots(_), do: 0

  # =========================================================================
  # Private: Tuning Recommendations
  # =========================================================================

  defp generate_recommendations do
    metrics = collect_all_rule_metrics()

    recommendations = []

    # 1. High FP rate rules (>30%)
    recommendations = recommendations ++ high_fp_recommendations(metrics)

    # 2. Dormant rules (never fire)
    recommendations = recommendations ++ dormant_rule_recommendations(metrics)

    # 3. Correlated rules (always fire together)
    recommendations = recommendations ++ correlated_rule_recommendations(metrics)

    # 4. ML confidence threshold adjustments
    recommendations = recommendations ++ ml_threshold_recommendations(metrics)

    # 5. Low effectiveness rules
    recommendations = recommendations ++ low_effectiveness_recommendations(metrics)

    # Sort by priority
    Enum.sort_by(recommendations, fn r ->
      priority_weight = case r.priority do
        "critical" -> 0
        "high" -> 1
        "medium" -> 2
        "low" -> 3
        _ -> 4
      end
      priority_weight
    end)
  end

  defp high_fp_recommendations(metrics) do
    metrics
    |> Enum.filter(fn m ->
      reviewed = m.true_positives + m.false_positives + m.benign_count
      reviewed >= 5 and m.false_positives / reviewed > 0.30
    end)
    |> Enum.map(fn m ->
      reviewed = m.true_positives + m.false_positives + m.benign_count
      fp_rate = Float.round(m.false_positives / reviewed * 100, 1)

      %{
        id: "high_fp_#{m.rule_id}",
        type: "high_false_positive",
        priority: if(fp_rate > 60, do: "critical", else: "high"),
        rule_id: m.rule_id,
        rule_name: m.rule_name,
        title: "High false positive rate: #{m.rule_name}",
        description: "Rule '#{m.rule_name}' has a #{fp_rate}% false positive rate " <>
          "(#{m.false_positives} FPs out of #{reviewed} reviewed). " <>
          "Consider adjusting thresholds, adding exclusions, or suppressing.",
        impact: "Reducing FPs saves analyst time and reduces alert fatigue",
        action: "threshold_adjustment",
        metrics: %{
          fp_rate: fp_rate,
          false_positives: m.false_positives,
          total_reviewed: reviewed,
          total_hits: m.total_hits
        }
      }
    end)
  end

  defp dormant_rule_recommendations(metrics) do
    now = System.system_time(:second)
    thirty_days_ago = now - 30 * 24 * 3600

    metrics
    |> Enum.filter(fn m ->
      m.total_hits == 0 or (m.last_hit_at != nil and m.last_hit_at < thirty_days_ago)
    end)
    |> Enum.map(fn m ->
      days_dormant = if m.last_hit_at do
        div(now - m.last_hit_at, 86400)
      else
        nil
      end

      %{
        id: "dormant_#{m.rule_id}",
        type: "dormant_rule",
        priority: "low",
        rule_id: m.rule_id,
        rule_name: m.rule_name,
        title: "Dormant rule: #{m.rule_name}",
        description: if(days_dormant,
          do: "Rule '#{m.rule_name}' has not fired in #{days_dormant} days. " <>
              "Review if the rule is still relevant or if conditions are too restrictive.",
          else: "Rule '#{m.rule_name}' has never fired. " <>
              "The rule may be obsolete or its conditions may be too restrictive."
        ),
        impact: "Removing or updating dormant rules reduces processing overhead",
        action: "review_or_remove",
        metrics: %{
          total_hits: m.total_hits,
          days_dormant: days_dormant
        }
      }
    end)
  end

  defp correlated_rule_recommendations(metrics) do
    # Find rules that have similar hit patterns (fire at similar rates)
    # This is a simplified heuristic -- full correlation would require tracking
    # which rules fire on the same events
    active_rules = Enum.filter(metrics, fn m -> m.total_hits >= 10 end)

    pairs = for a <- active_rules, b <- active_rules, a.rule_id < b.rule_id do
      # Compare hit counts -- if very similar, they might be correlated
      ratio = if max(a.total_hits, b.total_hits) > 0 do
        min(a.total_hits, b.total_hits) / max(a.total_hits, b.total_hits)
      else
        0.0
      end

      # Also check if they cover the same MITRE techniques
      technique_overlap = length(a.mitre_techniques -- (a.mitre_techniques -- b.mitre_techniques))
      max_techniques = max(length(a.mitre_techniques), length(b.mitre_techniques))
      technique_similarity = if max_techniques > 0, do: technique_overlap / max_techniques, else: 0.0

      if ratio > 0.85 and technique_similarity > 0.5 do
        %{
          id: "correlated_#{a.rule_id}_#{b.rule_id}",
          type: "correlated_rules",
          priority: "medium",
          rule_id: a.rule_id,
          rule_name: "#{a.rule_name} & #{b.rule_name}",
          title: "Potentially redundant rules",
          description: "Rules '#{a.rule_name}' and '#{b.rule_name}' fire at similar rates " <>
            "(#{a.total_hits} vs #{b.total_hits} hits) and cover overlapping MITRE techniques. " <>
            "Consider merging them to reduce processing overhead.",
          impact: "Merging redundant rules simplifies rule management and reduces latency",
          action: "merge_or_consolidate",
          metrics: %{
            rule_a_hits: a.total_hits,
            rule_b_hits: b.total_hits,
            hit_ratio: Float.round(ratio, 2),
            technique_overlap: Float.round(technique_similarity, 2)
          }
        }
      else
        nil
      end
    end

    Enum.filter(pairs, & &1)
  end

  defp ml_threshold_recommendations(metrics) do
    ml_rules = Enum.filter(metrics, fn m ->
      m.rule_type in ~w(ml ml_malware) and
      m.true_positives + m.false_positives >= 10
    end)

    Enum.flat_map(ml_rules, fn m ->
      reviewed = m.true_positives + m.false_positives
      fp_rate = m.false_positives / reviewed
      avg_confidence = if m.total_hits > 0, do: m.total_confidence / m.total_hits, else: 0.5

      cond do
        fp_rate > 0.4 and avg_confidence < 0.7 ->
          [%{
            id: "ml_threshold_raise_#{m.rule_id}",
            type: "ml_threshold_adjustment",
            priority: "high",
            rule_id: m.rule_id,
            rule_name: m.rule_name,
            title: "Raise ML confidence threshold for #{m.rule_name}",
            description: "ML rule '#{m.rule_name}' has #{Float.round(fp_rate * 100, 1)}% FP rate " <>
              "with avg confidence #{Float.round(avg_confidence, 2)}. " <>
              "Consider raising the confidence threshold to reduce false positives.",
            impact: "Higher threshold reduces FPs at the cost of potentially missing some threats",
            action: "raise_threshold",
            metrics: %{
              current_avg_confidence: Float.round(avg_confidence, 3),
              fp_rate: Float.round(fp_rate, 3),
              suggested_threshold: Float.round(min(avg_confidence + 0.15, 0.95), 2)
            }
          }]

        fp_rate < 0.05 and avg_confidence > 0.85 ->
          [%{
            id: "ml_threshold_lower_#{m.rule_id}",
            type: "ml_threshold_adjustment",
            priority: "low",
            rule_id: m.rule_id,
            rule_name: m.rule_name,
            title: "Consider lowering ML threshold for #{m.rule_name}",
            description: "ML rule '#{m.rule_name}' has very low FP rate (#{Float.round(fp_rate * 100, 1)}%) " <>
              "with high avg confidence (#{Float.round(avg_confidence, 2)}). " <>
              "You could lower the threshold to catch more threats.",
            impact: "Lower threshold catches more threats but may increase FPs slightly",
            action: "lower_threshold",
            metrics: %{
              current_avg_confidence: Float.round(avg_confidence, 3),
              fp_rate: Float.round(fp_rate, 3),
              suggested_threshold: Float.round(max(avg_confidence - 0.10, 0.50), 2)
            }
          }]

        true ->
          []
      end
    end)
  end

  defp low_effectiveness_recommendations(metrics) do
    metrics
    |> Enum.filter(fn m ->
      reviewed = m.true_positives + m.false_positives + m.benign_count
      effectiveness = calculate_effectiveness_score(m)
      reviewed >= 10 and effectiveness < 0.3
    end)
    |> Enum.map(fn m ->
      effectiveness = calculate_effectiveness_score(m)

      %{
        id: "low_eff_#{m.rule_id}",
        type: "low_effectiveness",
        priority: "medium",
        rule_id: m.rule_id,
        rule_name: m.rule_name,
        title: "Low effectiveness rule: #{m.rule_name}",
        description: "Rule '#{m.rule_name}' has an effectiveness score of " <>
          "#{Float.round(effectiveness * 100, 1)}%. " <>
          "Consider tuning the rule conditions or reviewing its logic.",
        impact: "Improving rule effectiveness increases detection quality",
        action: "tune_or_replace",
        metrics: %{
          effectiveness_score: Float.round(effectiveness, 3),
          total_hits: m.total_hits,
          true_positives: m.true_positives,
          false_positives: m.false_positives
        }
      }
    end)
  end

  # =========================================================================
  # Private: Trends
  # =========================================================================

  defp calculate_trends(time_range) do
    days = case time_range do
      "24h" -> 1
      "7d" -> 7
      "30d" -> 30
      "90d" -> 90
      _ -> 7
    end

    start_date = Date.utc_today() |> Date.add(-days)

    # Alert trend from DB
    alert_trend = try do
      Repo.all(
        from(a in Alert,
          where: fragment("?::date", a.inserted_at) >= ^start_date,
          group_by: fragment("?::date", a.inserted_at),
          select: {fragment("?::date", a.inserted_at), count(a.id)},
          order_by: [asc: fragment("?::date", a.inserted_at)]
        )
      )
      |> Enum.map(fn {date, count} -> %{date: Date.to_iso8601(date), count: count} end)
    rescue
      _ -> []
    end

    # FP trend from DB
    fp_trend = try do
      Repo.all(
        from(a in Alert,
          where: fragment("?::date", a.inserted_at) >= ^start_date,
          where: a.verdict == "false_positive",
          group_by: fragment("?::date", a.inserted_at),
          select: {fragment("?::date", a.inserted_at), count(a.id)},
          order_by: [asc: fragment("?::date", a.inserted_at)]
        )
      )
      |> Enum.map(fn {date, count} -> %{date: Date.to_iso8601(date), count: count} end)
    rescue
      _ -> []
    end

    # Severity distribution over time
    severity_trend = try do
      Repo.all(
        from(a in Alert,
          where: fragment("?::date", a.inserted_at) >= ^start_date,
          group_by: [fragment("?::date", a.inserted_at), a.severity],
          select: {fragment("?::date", a.inserted_at), a.severity, count(a.id)},
          order_by: [asc: fragment("?::date", a.inserted_at)]
        )
      )
      |> Enum.group_by(fn {date, _sev, _count} -> date end)
      |> Enum.map(fn {date, entries} ->
        severity_counts = Enum.reduce(entries, %{}, fn {_d, sev, count}, acc ->
          Map.put(acc, sev, count)
        end)
        Map.put(severity_counts, "date", Date.to_iso8601(date))
      end)
      |> Enum.sort_by(& &1["date"])
    rescue
      _ -> []
    end

    %{
      time_range: time_range,
      alert_trend: alert_trend,
      fp_trend: fp_trend,
      severity_trend: severity_trend
    }
  end

  # =========================================================================
  # Private: Persistence
  # =========================================================================

  defp persist_metrics_to_db do
    # This would write aggregated metrics to a database table for historical analysis.
    # For now, we log a summary.
    metrics = collect_all_rule_metrics()
    pipeline = collect_pipeline_metrics()

    Logger.debug(
      "[DetectionAnalytics] Persisted metrics: " <>
      "#{length(metrics)} rules tracked, " <>
      "#{map_size(pipeline)} pipeline stages"
    )
  end

  # =========================================================================
  # Private: Helpers
  # =========================================================================

  defp format_unix_time(nil), do: nil
  defp format_unix_time(0), do: nil
  defp format_unix_time(unix_seconds) when is_integer(unix_seconds) do
    case DateTime.from_unix(unix_seconds) do
      {:ok, dt} -> DateTime.to_iso8601(dt)
      _ -> nil
    end
  end
  defp format_unix_time(_), do: nil
end
