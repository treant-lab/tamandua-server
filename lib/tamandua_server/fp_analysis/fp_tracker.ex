defmodule TamanduaServer.FPAnalysis.FPTracker do
  @moduledoc """
  False Positive Tracker - Handles FP report submissions and tracking.

  This module provides the primary interface for analysts to report false positives
  and tracks the feedback for use in improving detection accuracy.

  ## Features

  - Submit FP/TP reports from the alert view
  - Track classification history per alert
  - Aggregate statistics per rule, agent, and organization
  - Feed data to pattern detection and auto-tuning systems

  ## Usage

      # Report a false positive
      {:ok, report} = FPTracker.report_false_positive(alert_id, user_id, %{
        reason: "known_good_software",
        reason_detail: "Chrome auto-update is expected behavior"
      })

      # Report a true positive
      {:ok, report} = FPTracker.report_true_positive(alert_id, user_id, %{
        notes: "Confirmed malicious activity"
      })

      # Get FP statistics for a rule
      stats = FPTracker.get_rule_fp_stats(organization_id, "sigma", "rule_123")
  """

  use GenServer
  require Logger

  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.FPAnalysis.{FPReport, RuleQualityMetrics, FPPatterns, AutoTuner}

  # ETS table for caching rule stats
  @stats_cache :fp_tracker_stats_cache
  @cache_ttl :timer.minutes(5)

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Report an alert as a false positive.
  """
  @spec report_false_positive(String.t(), String.t() | nil, map()) ::
          {:ok, FPReport.t()} | {:error, term()}
  def report_false_positive(alert_id, user_id, opts \\ %{}) do
    report_classification(alert_id, user_id, "false_positive", opts)
  end

  @doc """
  Report an alert as a true positive.
  """
  @spec report_true_positive(String.t(), String.t() | nil, map()) ::
          {:ok, FPReport.t()} | {:error, term()}
  def report_true_positive(alert_id, user_id, opts \\ %{}) do
    report_classification(alert_id, user_id, "true_positive", opts)
  end

  @doc """
  Report an alert as benign (not malicious but also not a detection error).
  """
  @spec report_benign(String.t(), String.t() | nil, map()) ::
          {:ok, FPReport.t()} | {:error, term()}
  def report_benign(alert_id, user_id, opts \\ %{}) do
    report_classification(alert_id, user_id, "benign", opts)
  end

  @doc """
  Report an alert as suspicious (requires further investigation).
  """
  @spec report_suspicious(String.t(), String.t() | nil, map()) ::
          {:ok, FPReport.t()} | {:error, term()}
  def report_suspicious(alert_id, user_id, opts \\ %{}) do
    report_classification(alert_id, user_id, "suspicious", opts)
  end

  @doc """
  Generic classification report submission.
  """
  @spec report_classification(String.t(), String.t() | nil, String.t(), map()) ::
          {:ok, FPReport.t()} | {:error, term()}
  def report_classification(alert_id, user_id, classification, opts \\ %{}) do
    with {:ok, alert} <- get_alert(alert_id),
         changeset <- build_report_changeset(alert, user_id, classification, opts),
         {:ok, report} <- Repo.insert(changeset) do
      # Asynchronously update metrics and check for patterns
      GenServer.cast(__MODULE__, {:process_report, report})

      # Update alert verdict
      update_alert_verdict(alert, classification, user_id, report.id)

      {:ok, report}
    end
  end

  @doc """
  Get FP reports for an alert.
  """
  @spec get_alert_reports(String.t()) :: [FPReport.t()]
  def get_alert_reports(alert_id) do
    from(r in FPReport,
      where: r.alert_id == ^alert_id,
      order_by: [desc: r.inserted_at]
    )
    |> Repo.all()
  end

  @doc """
  Get FP statistics for a specific rule.
  """
  @spec get_rule_stats(String.t(), String.t(), String.t()) :: map()
  def get_rule_stats(organization_id, detection_source, rule_id) do
    cache_key = {organization_id, detection_source, rule_id}

    case get_cached_stats(cache_key) do
      {:ok, stats} -> stats
      :miss -> fetch_and_cache_stats(cache_key)
    end
  end

  @doc """
  Get FP statistics for an organization.
  """
  @spec get_organization_stats(String.t(), keyword()) :: map()
  def get_organization_stats(organization_id, opts \\ []) do
    days = Keyword.get(opts, :days, 30)
    start_time = DateTime.add(DateTime.utc_now(), -days * 24 * 3600, :second)

    # Get report counts by classification
    classification_counts =
      from(r in FPReport,
        where: r.organization_id == ^organization_id,
        where: r.inserted_at >= ^start_time,
        group_by: r.classification,
        select: {r.classification, count(r.id)}
      )
      |> Repo.all()
      |> Map.new()

    # Get report counts by detection source
    source_counts =
      from(r in FPReport,
        where: r.organization_id == ^organization_id,
        where: r.inserted_at >= ^start_time,
        where: not is_nil(r.detection_source),
        group_by: r.detection_source,
        select: {r.detection_source, count(r.id)}
      )
      |> Repo.all()
      |> Map.new()

    # Get FP counts by source
    fp_by_source =
      from(r in FPReport,
        where: r.organization_id == ^organization_id,
        where: r.inserted_at >= ^start_time,
        where: r.classification == "false_positive",
        where: not is_nil(r.detection_source),
        group_by: r.detection_source,
        select: {r.detection_source, count(r.id)}
      )
      |> Repo.all()
      |> Map.new()

    total_reports = Enum.sum(Map.values(classification_counts))
    fp_count = Map.get(classification_counts, "false_positive", 0)
    tp_count = Map.get(classification_counts, "true_positive", 0)

    fp_rate = if total_reports > 0, do: fp_count / total_reports, else: 0.0
    precision = if tp_count + fp_count > 0, do: tp_count / (tp_count + fp_count), else: nil

    %{
      total_reports: total_reports,
      classification_counts: classification_counts,
      source_counts: source_counts,
      fp_by_source: fp_by_source,
      fp_rate: Float.round(fp_rate, 4),
      precision: precision && Float.round(precision, 4),
      period_days: days,
      period_start: start_time
    }
  end

  @doc """
  Get top FP-generating rules for an organization.
  """
  @spec get_top_fp_rules(String.t(), keyword()) :: [map()]
  def get_top_fp_rules(organization_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 10)
    days = Keyword.get(opts, :days, 30)
    start_time = DateTime.add(DateTime.utc_now(), -days * 24 * 3600, :second)

    from(r in FPReport,
      where: r.organization_id == ^organization_id,
      where: r.inserted_at >= ^start_time,
      where: r.classification == "false_positive",
      where: not is_nil(r.rule_id),
      group_by: [r.detection_source, r.rule_id, r.rule_name],
      select: %{
        detection_source: r.detection_source,
        rule_id: r.rule_id,
        rule_name: r.rule_name,
        fp_count: count(r.id)
      },
      order_by: [desc: count(r.id)],
      limit: ^limit
    )
    |> Repo.all()
  end

  @doc """
  Get recent FP reports for review.
  """
  @spec get_pending_reviews(String.t(), keyword()) :: [FPReport.t()]
  def get_pending_reviews(organization_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 50)

    from(r in FPReport,
      where: r.organization_id == ^organization_id,
      where: r.reviewed == false,
      order_by: [desc: r.inserted_at],
      limit: ^limit,
      preload: [:reported_by, :alert]
    )
    |> Repo.all()
  end

  @doc """
  Mark an FP report as reviewed.
  """
  @spec review_report(String.t(), String.t(), map()) ::
          {:ok, FPReport.t()} | {:error, term()}
  def review_report(report_id, reviewer_id, opts \\ %{}) do
    case Repo.get(FPReport, report_id) do
      nil ->
        {:error, :not_found}

      report ->
        report
        |> FPReport.changeset(%{
          reviewed: true,
          reviewed_by_id: reviewer_id,
          reviewed_at: DateTime.utc_now(),
          review_notes: opts["notes"] || opts[:notes]
        })
        |> Repo.update()
    end
  end

  @doc """
  Bulk import FP reports (for migration or batch processing).
  """
  @spec bulk_import(String.t(), [map()]) :: {:ok, integer()} | {:error, term()}
  def bulk_import(organization_id, reports) when is_list(reports) do
    now = DateTime.utc_now()

    entries =
      Enum.map(reports, fn report ->
        %{
          id: Ecto.UUID.generate(),
          organization_id: organization_id,
          classification: report["classification"] || report[:classification],
          alert_id: report["alert_id"] || report[:alert_id],
          reported_by_id: report["reported_by_id"] || report[:reported_by_id],
          reason: report["reason"] || report[:reason],
          reason_detail: report["reason_detail"] || report[:reason_detail],
          detection_source: report["detection_source"] || report[:detection_source],
          rule_id: report["rule_id"] || report[:rule_id],
          rule_name: report["rule_name"] || report[:rule_name],
          inserted_at: now,
          updated_at: now
        }
      end)

    {count, _} = Repo.insert_all(FPReport, entries)

    # Trigger metrics update
    GenServer.cast(__MODULE__, {:bulk_update_metrics, organization_id})

    {:ok, count}
  rescue
    e -> {:error, Exception.message(e)}
  end

  # ---------------------------------------------------------------------------
  # GenServer Callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(_opts) do
    # Create ETS cache table
    :ets.new(@stats_cache, [:named_table, :set, :public, {:read_concurrency, true}])

    # Schedule periodic metrics recalculation
    schedule_metrics_refresh()

    Logger.info("[FPTracker] Initialized")
    {:ok, %{}}
  end

  @impl true
  def handle_cast({:process_report, report}, state) do
    # Update rule quality metrics
    update_rule_metrics(report)

    # Check for FP patterns
    if report.classification == "false_positive" do
      FPPatterns.analyze_report(report)
    end

    # Invalidate cache for this rule
    invalidate_cache({report.organization_id, report.detection_source, report.rule_id})

    {:noreply, state}
  end

  @impl true
  def handle_cast({:bulk_update_metrics, organization_id}, state) do
    recalculate_all_metrics(organization_id)
    {:noreply, state}
  end

  @impl true
  def handle_info(:refresh_metrics, state) do
    # Periodic full metrics refresh for all organizations
    recalculate_stale_metrics()
    schedule_metrics_refresh()
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ---------------------------------------------------------------------------
  # Private Functions
  # ---------------------------------------------------------------------------

  defp get_alert(alert_id) do
    case Alerts.get_alert(alert_id) do
      nil -> {:error, :alert_not_found}
      alert -> {:ok, alert}
    end
  rescue
    _ -> {:error, :alert_not_found}
  end

  defp build_report_changeset(alert, user_id, classification, opts) do
    evidence = alert.evidence || %{}
    process = evidence["process"] || evidence[:process] || %{}
    detection_meta = alert.detection_metadata || %{}

    attrs = %{
      alert_id: alert.id,
      organization_id: alert.organization_id,
      reported_by_id: user_id,
      classification: classification,
      confidence: opts[:confidence] || opts["confidence"] || 1.0,
      reason: opts[:reason] || opts["reason"],
      reason_detail: opts[:reason_detail] || opts["reason_detail"],
      tags: opts[:tags] || opts["tags"] || [],
      alert_snapshot: %{
        title: alert.title,
        severity: alert.severity,
        threat_score: alert.threat_score,
        mitre_tactics: alert.mitre_tactics,
        mitre_techniques: alert.mitre_techniques
      },
      detection_source: detection_meta["source"] || detection_meta[:source],
      rule_id: detection_meta["rule_id"] || detection_meta[:rule_id],
      rule_name: detection_meta["rule_name"] || detection_meta[:rule_name],
      agent_id: alert.agent_id,
      hostname: evidence["hostname"] || evidence[:hostname],
      process_name: process["name"] || process[:name],
      file_path: process["path"] || process[:path],
      file_hash: process["sha256"] || process[:sha256],
      command_line: process["command_line"] || process[:command_line],
      event_user: evidence["user"] || evidence[:user]
    }

    FPReport.changeset(%FPReport{}, attrs)
  end

  defp update_alert_verdict(alert, classification, user_id, report_id) do
    verdict = case classification do
      "true_positive" -> "true_positive"
      "false_positive" -> "false_positive"
      "benign" -> "benign"
      "suspicious" -> "suspicious"
      _ -> nil
    end

    if verdict do
      Alerts.update_alert(alert, %{
        verdict: verdict,
        verdict_by_id: user_id,
        verdict_at: DateTime.utc_now()
      })
    end
  rescue
    _ -> :ok
  end

  defp update_rule_metrics(%FPReport{} = report) do
    if report.detection_source && report.rule_id do
      # Get or create metrics record
      metrics = get_or_create_metrics(
        report.organization_id,
        report.detection_source,
        report.rule_id,
        report.rule_name
      )

      # Update counts based on classification
      updates = case report.classification do
        "true_positive" ->
          %{
            total_alerts: (metrics.total_alerts || 0) + 1,
            true_positives: (metrics.true_positives || 0) + 1
          }

        "false_positive" ->
          updates = %{
            total_alerts: (metrics.total_alerts || 0) + 1,
            false_positives: (metrics.false_positives || 0) + 1
          }

          # Update FP context tracking
          updates = update_fp_contexts(updates, metrics, report)
          updates

        "benign" ->
          %{
            total_alerts: (metrics.total_alerts || 0) + 1,
            benign_count: (metrics.benign_count || 0) + 1
          }

        "suspicious" ->
          %{
            total_alerts: (metrics.total_alerts || 0) + 1,
            suspicious_count: (metrics.suspicious_count || 0) + 1
          }

        _ ->
          %{total_alerts: (metrics.total_alerts || 0) + 1}
      end

      # Recalculate derived metrics
      updated_metrics = Map.merge(metrics, updates) |> struct(RuleQualityMetrics)
      calculated = RuleQualityMetrics.calculate_metrics(updated_metrics)
      updates = Map.merge(updates, calculated)

      # Update last alert timestamp
      updates = Map.put(updates, :last_alert_at, DateTime.utc_now())

      # Check if tuning recommendation needed
      {needs_tuning, rec_type, _reason} =
        struct(metrics, updates)
        |> RuleQualityMetrics.needs_tuning?()

      updates = if needs_tuning do
        Map.put(updates, :tuning_recommendation, to_string(rec_type))
        |> Map.put(:last_recommendation_at, DateTime.utc_now())
      else
        updates
      end

      metrics
      |> RuleQualityMetrics.changeset(updates)
      |> Repo.update()

      # Trigger auto-tuner if high FP rate
      if needs_tuning do
        AutoTuner.evaluate_rule(report.organization_id, report.detection_source, report.rule_id)
      end
    end
  rescue
    e ->
      Logger.warning("[FPTracker] Failed to update rule metrics: #{Exception.message(e)}")
  end

  defp get_or_create_metrics(organization_id, detection_source, rule_id, rule_name) do
    case Repo.get_by(RuleQualityMetrics,
           organization_id: organization_id,
           detection_source: detection_source,
           rule_id: rule_id
         ) do
      nil ->
        {:ok, metrics} =
          %RuleQualityMetrics{}
          |> RuleQualityMetrics.changeset(%{
            organization_id: organization_id,
            detection_source: detection_source,
            rule_id: rule_id,
            rule_name: rule_name,
            first_alert_at: DateTime.utc_now(),
            metrics_window_start: DateTime.utc_now()
          })
          |> Repo.insert()

        metrics

      metrics ->
        metrics
    end
  end

  defp update_fp_contexts(updates, metrics, report) do
    # Update time-based FP tracking
    hour = DateTime.utc_now().hour
    fp_by_hour = Map.update(metrics.fp_by_hour || %{}, to_string(hour), 1, &(&1 + 1))
    updates = Map.put(updates, :fp_by_hour, fp_by_hour)

    day = Date.day_of_week(Date.utc_today())
    fp_by_day = Map.update(metrics.fp_by_day_of_week || %{}, to_string(day), 1, &(&1 + 1))
    updates = Map.put(updates, :fp_by_day_of_week, fp_by_day)

    # Update OS-based tracking
    if report.os_type do
      fp_by_os = Map.update(metrics.fp_by_os || %{}, report.os_type, 1, &(&1 + 1))
      updates = Map.put(updates, :fp_by_os, fp_by_os)
    end

    # Update top FP processes
    if report.process_name do
      top_processes = update_top_list(
        metrics.top_fp_processes || [],
        report.process_name,
        10
      )
      updates = Map.put(updates, :top_fp_processes, top_processes)
    end

    # Update top FP paths
    if report.file_path do
      top_paths = update_top_list(
        metrics.top_fp_paths || [],
        report.file_path,
        10
      )
      updates = Map.put(updates, :top_fp_paths, top_paths)
    end

    updates
  end

  defp update_top_list(current_list, new_value, max_size) do
    # Find existing entry or create new one
    {updated, found} =
      Enum.reduce(current_list, {[], false}, fn entry, {acc, found} ->
        if entry["value"] == new_value do
          {[%{"value" => new_value, "count" => (entry["count"] || 0) + 1} | acc], true}
        else
          {[entry | acc], found}
        end
      end)

    updated = if found do
      updated
    else
      [%{"value" => new_value, "count" => 1} | updated]
    end

    # Sort by count and limit
    updated
    |> Enum.sort_by(fn e -> e["count"] end, :desc)
    |> Enum.take(max_size)
  end

  defp get_cached_stats(cache_key) do
    case :ets.lookup(@stats_cache, cache_key) do
      [{^cache_key, stats, cached_at}] ->
        if DateTime.diff(DateTime.utc_now(), cached_at, :millisecond) < @cache_ttl do
          {:ok, stats}
        else
          :miss
        end

      [] ->
        :miss
    end
  rescue
    _ -> :miss
  end

  defp fetch_and_cache_stats({organization_id, detection_source, rule_id} = cache_key) do
    stats =
      case Repo.get_by(RuleQualityMetrics,
             organization_id: organization_id,
             detection_source: detection_source,
             rule_id: rule_id
           ) do
        nil ->
          %{
            total_alerts: 0,
            true_positives: 0,
            false_positives: 0,
            precision: nil,
            fp_rate: nil,
            quality_score: nil
          }

        metrics ->
          %{
            total_alerts: metrics.total_alerts,
            true_positives: metrics.true_positives,
            false_positives: metrics.false_positives,
            precision: metrics.precision,
            fp_rate: metrics.fp_rate,
            quality_score: metrics.quality_score,
            fp_rate_trend: metrics.fp_rate_trend,
            tuning_recommendation: metrics.tuning_recommendation
          }
      end

    :ets.insert(@stats_cache, {cache_key, stats, DateTime.utc_now()})
    stats
  end

  defp invalidate_cache(cache_key) do
    :ets.delete(@stats_cache, cache_key)
  rescue
    _ -> :ok
  end

  defp recalculate_stale_metrics do
    # Find metrics that haven't been updated in 24 hours
    cutoff = DateTime.add(DateTime.utc_now(), -24 * 3600, :second)

    from(m in RuleQualityMetrics,
      where: m.updated_at < ^cutoff or is_nil(m.precision)
    )
    |> Repo.all()
    |> Enum.each(fn metrics ->
      calculated = RuleQualityMetrics.calculate_metrics(metrics)

      metrics
      |> RuleQualityMetrics.changeset(calculated)
      |> Repo.update()
    end)
  rescue
    e ->
      Logger.warning("[FPTracker] Failed to recalculate stale metrics: #{Exception.message(e)}")
  end

  defp recalculate_all_metrics(organization_id) do
    from(m in RuleQualityMetrics,
      where: m.organization_id == ^organization_id
    )
    |> Repo.all()
    |> Enum.each(fn metrics ->
      calculated = RuleQualityMetrics.calculate_metrics(metrics)

      metrics
      |> RuleQualityMetrics.changeset(calculated)
      |> Repo.update()
    end)
  rescue
    e ->
      Logger.warning("[FPTracker] Failed to recalculate metrics: #{Exception.message(e)}")
  end

  defp schedule_metrics_refresh do
    Process.send_after(self(), :refresh_metrics, :timer.hours(1))
  end
end
