defmodule TamanduaServer.MDR.Metrics do
  @moduledoc """
  MDR Metrics & Reporting Engine.

  Tracks and reports on all MDR service delivery metrics:

  - **SLA Compliance** - Per-customer, per-priority SLA tracking
  - **MTTD** - Mean Time to Detect (event to alert)
  - **MTTR** - Mean Time to Respond (alert to first action)
  - **MTTC** - Mean Time to Contain (alert to containment confirmed)
  - **Alert Volume** - Trends per customer, severity, source
  - **Detection Efficacy** - True/false positive rates, detection coverage
  - **Executive Reports** - Monthly/weekly per-customer summaries

  ## Integration

  - Consumes data from `MDR.Delivery` and `MDR.AnalystConsole`
  - Generates reports via `TamanduaServer.Reports.Scheduler`
  - Publishes metrics to PubSub for dashboarding
  - Multi-tenant: per-customer metrics isolation
  """

  use GenServer
  require Logger

  alias TamanduaServer.Repo

  import Ecto.Query

  # ETS tables
  @ets_customer_metrics :mdr_customer_metrics
  @ets_sla_tracking :mdr_sla_tracking
  @ets_time_series :mdr_time_series
  @ets_detection_efficacy :mdr_detection_efficacy

  # Aggregation intervals
  @hourly_aggregation :timer.hours(1)
  @daily_report_generation :timer.hours(24)

  # Rolling window sizes
  @max_time_series_points 8760  # 1 year of hourly data

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Record a detection event for MTTD calculation.
  """
  @spec record_detection(String.t(), DateTime.t(), DateTime.t()) :: :ok
  def record_detection(org_id, event_time, alert_time) do
    GenServer.cast(__MODULE__, {:record_detection, org_id, event_time, alert_time})
  end

  @doc """
  Record a response event for MTTR calculation.
  """
  @spec record_response(String.t(), DateTime.t(), DateTime.t()) :: :ok
  def record_response(org_id, alert_time, response_time) do
    GenServer.cast(__MODULE__, {:record_response, org_id, alert_time, response_time})
  end

  @doc """
  Record a containment event for MTTC calculation.
  """
  @spec record_containment(String.t(), DateTime.t(), DateTime.t()) :: :ok
  def record_containment(org_id, alert_time, containment_time) do
    GenServer.cast(__MODULE__, {:record_containment, org_id, alert_time, containment_time})
  end

  @doc """
  Record an alert for volume tracking.
  """
  @spec record_alert(String.t(), map()) :: :ok
  def record_alert(org_id, alert_info) do
    GenServer.cast(__MODULE__, {:record_alert, org_id, alert_info})
  end

  @doc """
  Record a triage verdict for detection efficacy.
  """
  @spec record_verdict(String.t(), String.t(), String.t()) :: :ok
  def record_verdict(org_id, alert_id, verdict) do
    GenServer.cast(__MODULE__, {:record_verdict, org_id, alert_id, verdict})
  end

  @doc """
  Record an SLA event (met or breached).
  """
  @spec record_sla_event(String.t(), atom(), boolean()) :: :ok
  def record_sla_event(org_id, priority, met?) do
    GenServer.cast(__MODULE__, {:record_sla, org_id, priority, met?})
  end

  @doc """
  Get comprehensive metrics for an organization.
  """
  @spec get_customer_metrics(String.t(), keyword()) :: map()
  def get_customer_metrics(org_id, opts \\ []) do
    GenServer.call(__MODULE__, {:get_metrics, org_id, opts})
  end

  @doc """
  Get SLA compliance report for an organization.
  """
  @spec get_sla_report(String.t(), keyword()) :: map()
  def get_sla_report(org_id, opts \\ []) do
    GenServer.call(__MODULE__, {:get_sla_report, org_id, opts})
  end

  @doc """
  Get alert volume trends for an organization.
  """
  @spec get_alert_trends(String.t(), keyword()) :: [map()]
  def get_alert_trends(org_id, opts \\ []) do
    GenServer.call(__MODULE__, {:get_alert_trends, org_id, opts})
  end

  @doc """
  Get detection efficacy report.
  """
  @spec get_detection_efficacy(String.t()) :: map()
  def get_detection_efficacy(org_id) do
    GenServer.call(__MODULE__, {:get_efficacy, org_id})
  end

  @doc """
  Generate an executive summary report for a customer.
  """
  @spec generate_executive_report(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def generate_executive_report(org_id, opts \\ []) do
    GenServer.call(__MODULE__, {:generate_executive_report, org_id, opts}, 60_000)
  end

  @doc """
  Get cross-customer aggregate metrics (anonymized).
  """
  @spec get_aggregate_metrics() :: map()
  def get_aggregate_metrics do
    GenServer.call(__MODULE__, :get_aggregate_metrics)
  end

  @doc """
  Get engine statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  @impl true
  def init(_opts) do
    :ets.new(@ets_customer_metrics, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@ets_sla_tracking, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@ets_time_series, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@ets_detection_efficacy, [:named_table, :set, :public, read_concurrency: true])

    state = %{
      stats: %{
        detections_recorded: 0,
        responses_recorded: 0,
        containments_recorded: 0,
        alerts_tracked: 0,
        verdicts_recorded: 0,
        reports_generated: 0
      }
    }

    # Schedule periodic aggregation
    schedule_hourly_aggregation()
    schedule_daily_reports()

    Logger.info("[MDR.Metrics] Initialized")
    {:ok, state}
  end

  # -- Event recording -----------------------------------------------------

  @impl true
  def handle_cast({:record_detection, org_id, event_time, alert_time}, state) do
    mttd_seconds = DateTime.diff(alert_time, event_time, :second)
    mttd_minutes = mttd_seconds / 60.0

    update_customer_metric(org_id, :mttd_samples, mttd_minutes)
    new_stats = %{state.stats | detections_recorded: state.stats.detections_recorded + 1}
    {:noreply, %{state | stats: new_stats}}
  end

  @impl true
  def handle_cast({:record_response, org_id, alert_time, response_time}, state) do
    mttr_seconds = DateTime.diff(response_time, alert_time, :second)
    mttr_minutes = mttr_seconds / 60.0

    update_customer_metric(org_id, :mttr_samples, mttr_minutes)
    new_stats = %{state.stats | responses_recorded: state.stats.responses_recorded + 1}
    {:noreply, %{state | stats: new_stats}}
  end

  @impl true
  def handle_cast({:record_containment, org_id, alert_time, containment_time}, state) do
    mttc_seconds = DateTime.diff(containment_time, alert_time, :second)
    mttc_minutes = mttc_seconds / 60.0

    update_customer_metric(org_id, :mttc_samples, mttc_minutes)
    new_stats = %{state.stats | containments_recorded: state.stats.containments_recorded + 1}
    {:noreply, %{state | stats: new_stats}}
  end

  @impl true
  def handle_cast({:record_alert, org_id, alert_info}, state) do
    severity = alert_info[:severity] || alert_info["severity"] || "medium"
    source = alert_info[:source] || alert_info["source"] || "unknown"

    # Update volume counters
    update_customer_counter(org_id, :total_alerts)
    update_customer_counter(org_id, :"alerts_#{severity}")
    update_customer_counter(org_id, :"alerts_source_#{source}")

    # Add to time series
    add_time_series_point(org_id, :alert_volume, %{
      severity: severity,
      source: source,
      timestamp: DateTime.utc_now()
    })

    new_stats = %{state.stats | alerts_tracked: state.stats.alerts_tracked + 1}
    {:noreply, %{state | stats: new_stats}}
  end

  @impl true
  def handle_cast({:record_verdict, org_id, _alert_id, verdict}, state) do
    # Update detection efficacy
    metrics = get_or_init_efficacy(org_id)

    updated = case verdict do
      "true_positive" ->
        %{metrics | true_positives: metrics.true_positives + 1}

      "false_positive" ->
        %{metrics | false_positives: metrics.false_positives + 1}

      "benign" ->
        %{metrics | benign: metrics.benign + 1}

      _ ->
        %{metrics | undetermined: metrics.undetermined + 1}
    end

    total = updated.true_positives + updated.false_positives + updated.benign + updated.undetermined
    updated = %{updated |
      total_verdicts: total,
      tp_rate: if(total > 0, do: Float.round(updated.true_positives / total * 100, 2), else: 0.0),
      fp_rate: if(total > 0, do: Float.round(updated.false_positives / total * 100, 2), else: 0.0)
    }

    :ets.insert(@ets_detection_efficacy, {org_id, updated})

    new_stats = %{state.stats | verdicts_recorded: state.stats.verdicts_recorded + 1}
    {:noreply, %{state | stats: new_stats}}
  end

  @impl true
  def handle_cast({:record_sla, org_id, priority, met?}, state) do
    sla = get_or_init_sla(org_id)

    priority_key = :"#{priority}"
    priority_data = Map.get(sla, priority_key, %{met: 0, breached: 0})

    updated_priority = if met? do
      %{priority_data | met: priority_data.met + 1}
    else
      %{priority_data | breached: priority_data.breached + 1}
    end

    updated = Map.put(sla, priority_key, updated_priority)
    :ets.insert(@ets_sla_tracking, {org_id, updated})

    {:noreply, state}
  end

  # -- Queries -------------------------------------------------------------

  @impl true
  def handle_call({:get_metrics, org_id, _opts}, _from, state) do
    metrics = get_or_init_customer_metrics(org_id)

    # Calculate averages
    mttd = calculate_average(metrics[:mttd_samples] || [])
    mttr = calculate_average(metrics[:mttr_samples] || [])
    mttc = calculate_average(metrics[:mttc_samples] || [])

    efficacy = get_or_init_efficacy(org_id)
    sla = get_or_init_sla(org_id)

    result = %{
      org_id: org_id,
      mttd_minutes: Float.round(mttd, 1),
      mttr_minutes: Float.round(mttr, 1),
      mttc_minutes: Float.round(mttc, 1),
      total_alerts: metrics[:total_alerts] || 0,
      alerts_by_severity: %{
        critical: metrics[:alerts_critical] || 0,
        high: metrics[:alerts_high] || 0,
        medium: metrics[:alerts_medium] || 0,
        low: metrics[:alerts_low] || 0
      },
      detection_efficacy: efficacy,
      sla_compliance: calculate_sla_compliance(sla),
      generated_at: DateTime.utc_now()
    }

    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_sla_report, org_id, _opts}, _from, state) do
    sla = get_or_init_sla(org_id)
    compliance = calculate_sla_compliance(sla)

    report = %{
      org_id: org_id,
      overall_compliance: compliance.overall_rate,
      by_priority: compliance.by_priority,
      total_alerts_tracked: compliance.total_tracked,
      total_breaches: compliance.total_breaches,
      generated_at: DateTime.utc_now()
    }

    {:reply, report, state}
  end

  @impl true
  def handle_call({:get_alert_trends, org_id, opts}, _from, state) do
    period = Keyword.get(opts, :period, :daily)
    limit = Keyword.get(opts, :limit, 30)

    points = get_time_series(org_id, :alert_volume)

    # Bucket by period
    bucketed = bucket_time_series(points, period)
      |> Enum.take(limit)

    {:reply, bucketed, state}
  end

  @impl true
  def handle_call({:get_efficacy, org_id}, _from, state) do
    efficacy = get_or_init_efficacy(org_id)
    {:reply, efficacy, state}
  end

  @impl true
  def handle_call({:generate_executive_report, org_id, opts}, _from, state) do
    period = Keyword.get(opts, :period, :monthly)

    report = do_generate_executive_report(org_id, period)
    new_stats = %{state.stats | reports_generated: state.stats.reports_generated + 1}
    {:reply, {:ok, report}, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call(:get_aggregate_metrics, _from, state) do
    all_orgs =
      :ets.tab2list(@ets_customer_metrics)
      |> Enum.map(fn {org_id, _} -> org_id end)

    total_metrics = Enum.map(all_orgs, fn org_id ->
      metrics = get_or_init_customer_metrics(org_id)
      %{
        mttd: calculate_average(metrics[:mttd_samples] || []),
        mttr: calculate_average(metrics[:mttr_samples] || []),
        mttc: calculate_average(metrics[:mttc_samples] || []),
        alerts: metrics[:total_alerts] || 0
      }
    end)

    aggregate = %{
      customer_count: length(all_orgs),
      avg_mttd_minutes: calculate_average(Enum.map(total_metrics, & &1.mttd)),
      avg_mttr_minutes: calculate_average(Enum.map(total_metrics, & &1.mttr)),
      avg_mttc_minutes: calculate_average(Enum.map(total_metrics, & &1.mttc)),
      total_alerts_across_customers: Enum.sum(Enum.map(total_metrics, & &1.alerts)),
      generated_at: DateTime.utc_now()
    }

    {:reply, aggregate, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  # -- Periodic tasks ------------------------------------------------------

  @impl true
  def handle_info(:hourly_aggregation, state) do
    # Publish current metrics to PubSub for dashboards
    all_orgs = :ets.tab2list(@ets_customer_metrics) |> Enum.map(fn {org_id, _} -> org_id end)

    Enum.each(all_orgs, fn org_id ->
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "mdr:metrics:#{org_id}",
        {:metrics_update, get_or_init_customer_metrics(org_id)}
      )
    end)

    schedule_hourly_aggregation()
    {:noreply, state}
  end

  @impl true
  def handle_info(:daily_reports, state) do
    # Generate daily reports for all MDR customers
    all_orgs = :ets.tab2list(@ets_customer_metrics) |> Enum.map(fn {org_id, _} -> org_id end)

    Enum.each(all_orgs, fn org_id ->
      try do
        do_generate_executive_report(org_id, :daily)
      rescue
        e -> Logger.error("[MDR.Metrics] Daily report failed for #{org_id}: #{Exception.message(e)}")
      end
    end)

    schedule_daily_reports()
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ============================================================================
  # Private - Metric Storage
  # ============================================================================

  defp get_or_init_customer_metrics(org_id) do
    case :ets.lookup(@ets_customer_metrics, org_id) do
      [{^org_id, metrics}] -> metrics
      [] -> %{}
    end
  end

  defp update_customer_metric(org_id, key, value) do
    metrics = get_or_init_customer_metrics(org_id)
    samples = Map.get(metrics, key, [])
    # Keep last 10000 samples
    updated_samples = Enum.take([value | samples], 10_000)
    updated = Map.put(metrics, key, updated_samples)
    :ets.insert(@ets_customer_metrics, {org_id, updated})
  end

  defp update_customer_counter(org_id, key) do
    metrics = get_or_init_customer_metrics(org_id)
    count = Map.get(metrics, key, 0)
    updated = Map.put(metrics, key, count + 1)
    :ets.insert(@ets_customer_metrics, {org_id, updated})
  end

  defp get_or_init_efficacy(org_id) do
    case :ets.lookup(@ets_detection_efficacy, org_id) do
      [{^org_id, efficacy}] -> efficacy
      [] -> %{
        true_positives: 0,
        false_positives: 0,
        benign: 0,
        undetermined: 0,
        total_verdicts: 0,
        tp_rate: 0.0,
        fp_rate: 0.0
      }
    end
  end

  defp get_or_init_sla(org_id) do
    case :ets.lookup(@ets_sla_tracking, org_id) do
      [{^org_id, sla}] -> sla
      [] -> %{p1: %{met: 0, breached: 0}, p2: %{met: 0, breached: 0}, p3: %{met: 0, breached: 0}, p4: %{met: 0, breached: 0}}
    end
  end

  # ============================================================================
  # Private - Time Series
  # ============================================================================

  defp add_time_series_point(org_id, series_name, point) do
    key = {org_id, series_name}

    points = case :ets.lookup(@ets_time_series, key) do
      [{^key, existing}] -> existing
      [] -> []
    end

    updated = Enum.take([point | points], @max_time_series_points)
    :ets.insert(@ets_time_series, {key, updated})
  end

  defp get_time_series(org_id, series_name) do
    key = {org_id, series_name}

    case :ets.lookup(@ets_time_series, key) do
      [{^key, points}] -> points
      [] -> []
    end
  end

  defp bucket_time_series(points, :hourly) do
    points
    |> Enum.group_by(fn p ->
      ts = p.timestamp
      %{year: ts.year, month: ts.month, day: ts.day, hour: ts.hour}
    end)
    |> Enum.map(fn {bucket, bucket_points} ->
      %{
        period: bucket,
        count: length(bucket_points),
        by_severity: bucket_points |> Enum.group_by(& &1.severity) |> Enum.map(fn {s, ps} -> {s, length(ps)} end) |> Map.new()
      }
    end)
    |> Enum.sort_by(& &1.period, :desc)
  end

  defp bucket_time_series(points, :daily) do
    points
    |> Enum.group_by(fn p ->
      ts = p.timestamp
      %{year: ts.year, month: ts.month, day: ts.day}
    end)
    |> Enum.map(fn {bucket, bucket_points} ->
      %{
        period: bucket,
        count: length(bucket_points),
        by_severity: bucket_points |> Enum.group_by(& &1.severity) |> Enum.map(fn {s, ps} -> {s, length(ps)} end) |> Map.new()
      }
    end)
    |> Enum.sort_by(& &1.period, :desc)
  end

  defp bucket_time_series(points, _monthly) do
    points
    |> Enum.group_by(fn p ->
      ts = p.timestamp
      %{year: ts.year, month: ts.month}
    end)
    |> Enum.map(fn {bucket, bucket_points} ->
      %{
        period: bucket,
        count: length(bucket_points),
        by_severity: bucket_points |> Enum.group_by(& &1.severity) |> Enum.map(fn {s, ps} -> {s, length(ps)} end) |> Map.new()
      }
    end)
    |> Enum.sort_by(& &1.period, :desc)
  end

  # ============================================================================
  # Private - SLA Compliance
  # ============================================================================

  defp calculate_sla_compliance(sla) do
    by_priority = Enum.map(sla, fn {priority, data} ->
      total = data.met + data.breached
      rate = if total > 0, do: Float.round(data.met / total * 100, 1), else: 100.0

      {priority, %{
        met: data.met,
        breached: data.breached,
        total: total,
        compliance_rate: rate
      }}
    end) |> Map.new()

    total_met = Enum.sum(Enum.map(by_priority, fn {_, d} -> d.met end))
    total_breached = Enum.sum(Enum.map(by_priority, fn {_, d} -> d.breached end))
    total = total_met + total_breached

    %{
      overall_rate: if(total > 0, do: Float.round(total_met / total * 100, 1), else: 100.0),
      by_priority: by_priority,
      total_tracked: total,
      total_breaches: total_breached
    }
  end

  # ============================================================================
  # Private - Executive Report
  # ============================================================================

  defp do_generate_executive_report(org_id, period) do
    metrics = get_or_init_customer_metrics(org_id)
    efficacy = get_or_init_efficacy(org_id)
    sla = get_or_init_sla(org_id)
    sla_compliance = calculate_sla_compliance(sla)

    mttd = calculate_average(metrics[:mttd_samples] || [])
    mttr = calculate_average(metrics[:mttr_samples] || [])
    mttc = calculate_average(metrics[:mttc_samples] || [])

    # Alert trends
    alert_trends = get_time_series(org_id, :alert_volume)
    period_trends = case period do
      :daily -> bucket_time_series(alert_trends, :hourly) |> Enum.take(24)
      :weekly -> bucket_time_series(alert_trends, :daily) |> Enum.take(7)
      :monthly -> bucket_time_series(alert_trends, :daily) |> Enum.take(30)
      _ -> bucket_time_series(alert_trends, :daily) |> Enum.take(30)
    end

    report = %{
      report_type: "mdr_executive_summary",
      org_id: org_id,
      period: period,
      generated_at: DateTime.utc_now(),

      executive_summary: %{
        total_alerts: metrics[:total_alerts] || 0,
        incidents_created: 0,
        incidents_resolved: 0,
        sla_compliance_rate: sla_compliance.overall_rate,
        mttd_minutes: Float.round(mttd, 1),
        mttr_minutes: Float.round(mttr, 1),
        mttc_minutes: Float.round(mttc, 1)
      },

      alert_breakdown: %{
        by_severity: %{
          critical: metrics[:alerts_critical] || 0,
          high: metrics[:alerts_high] || 0,
          medium: metrics[:alerts_medium] || 0,
          low: metrics[:alerts_low] || 0
        },
        trends: period_trends
      },

      detection_efficacy: %{
        true_positive_rate: efficacy.tp_rate,
        false_positive_rate: efficacy.fp_rate,
        total_verdicts: efficacy.total_verdicts,
        breakdown: %{
          true_positives: efficacy.true_positives,
          false_positives: efficacy.false_positives,
          benign: efficacy.benign,
          undetermined: efficacy.undetermined
        }
      },

      sla_compliance: sla_compliance,

      response_times: %{
        mttd: %{
          average_minutes: Float.round(mttd, 1),
          samples: length(metrics[:mttd_samples] || [])
        },
        mttr: %{
          average_minutes: Float.round(mttr, 1),
          samples: length(metrics[:mttr_samples] || [])
        },
        mttc: %{
          average_minutes: Float.round(mttc, 1),
          samples: length(metrics[:mttc_samples] || [])
        }
      },

      recommendations: generate_recommendations(metrics, efficacy, sla_compliance)
    }

    # Persist to reports table
    persist_executive_report(org_id, report)

    # Notify customer
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "mdr:reports:#{org_id}",
      {:executive_report, report}
    )

    report
  end

  defp generate_recommendations(metrics, efficacy, sla_compliance) do
    recommendations = []

    # High FP rate
    recommendations = if efficacy.fp_rate > 30.0 do
      ["Consider tuning detection rules to reduce false positive rate (currently #{efficacy.fp_rate}%)" | recommendations]
    else
      recommendations
    end

    # SLA issues
    recommendations = if sla_compliance.overall_rate < 95.0 do
      ["SLA compliance below target (#{sla_compliance.overall_rate}%). Review staffing and escalation procedures." | recommendations]
    else
      recommendations
    end

    # High alert volume
    total = metrics[:total_alerts] || 0
    recommendations = if total > 1000 do
      ["High alert volume detected (#{total}). Consider implementing additional alert suppression or tuning." | recommendations]
    else
      recommendations
    end

    if recommendations == [], do: ["Service delivery metrics within expected parameters."], else: recommendations
  end

  defp persist_executive_report(org_id, report) do
    Task.start(fn ->
      try do
        attrs = %{
          id: Ecto.UUID.generate(),
          org_id: org_id,
          report_type: "mdr_executive_summary",
          period: Atom.to_string(report.period),
          data: report,
          inserted_at: DateTime.utc_now(),
          updated_at: DateTime.utc_now()
        }

        Repo.insert_all("mdr_reports", [attrs], on_conflict: :nothing)
      rescue
        _ -> :ok
      end
    end)
  end

  # ============================================================================
  # Private - Helpers
  # ============================================================================

  defp calculate_average([]), do: 0.0
  defp calculate_average(samples) do
    Enum.sum(samples) / length(samples)
  end

  defp schedule_hourly_aggregation do
    Process.send_after(self(), :hourly_aggregation, @hourly_aggregation)
  end

  defp schedule_daily_reports do
    Process.send_after(self(), :daily_reports, @daily_report_generation)
  end
end
