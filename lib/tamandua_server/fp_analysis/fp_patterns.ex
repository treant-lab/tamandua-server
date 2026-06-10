defmodule TamanduaServer.FPAnalysis.FPPatterns do
  @moduledoc """
  False Positive Pattern Detection.

  Analyzes FP reports to identify recurring patterns that can be used for
  automatic suppression rule generation or tuning recommendations.

  ## Pattern Types

  - `:process` - Same process name generates FPs across alerts
  - `:path` - Same file path or path pattern generates FPs
  - `:time` - FPs occur at specific times (scheduled tasks, etc.)
  - `:user` - Specific users generate FPs (admins, service accounts)
  - `:rule` - Rule generates FPs regardless of context (too broad)
  - `:agent` - Specific agents generate FPs (test machines, etc.)
  - `:host` - Specific hostnames generate FPs
  - `:combined` - Combination of multiple factors

  ## Pattern Detection Algorithm

  1. Group FP reports by potential pattern dimensions
  2. Calculate frequency and confidence for each potential pattern
  3. Filter patterns that meet threshold (min 5 FPs, >80% FP rate)
  4. Rank by impact (number of FPs that would be suppressed)
  5. Generate suppression rule suggestions
  """

  use GenServer
  require Logger

  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.FPAnalysis.{FPReport, FPPattern, TuningRecommendation, AutoTuner}

  # Minimum FP count to consider a pattern valid
  @min_fp_count 5

  # Minimum FP confidence to consider a pattern valid
  @min_fp_confidence 0.8

  # Maximum patterns to track per organization
  @max_patterns_per_org 500

  # Pattern analysis interval
  @analysis_interval :timer.hours(4)

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Analyze a new FP report for pattern matching.
  """
  @spec analyze_report(FPReport.t()) :: :ok
  def analyze_report(%FPReport{} = report) do
    GenServer.cast(__MODULE__, {:analyze_report, report})
  end

  @doc """
  Run full pattern analysis for an organization.
  """
  @spec analyze_organization(String.t()) :: {:ok, [FPPattern.t()]}
  def analyze_organization(organization_id) do
    GenServer.call(__MODULE__, {:analyze_organization, organization_id}, :timer.minutes(5))
  end

  @doc """
  Get detected FP patterns for an organization.
  """
  @spec get_patterns(String.t(), keyword()) :: [FPPattern.t()]
  def get_patterns(organization_id, opts \\ []) do
    status = Keyword.get(opts, :status)
    pattern_type = Keyword.get(opts, :pattern_type)
    min_confidence = Keyword.get(opts, :min_confidence, 0.5)
    limit = Keyword.get(opts, :limit, 50)

    query = from(p in FPPattern,
      where: p.organization_id == ^organization_id,
      where: p.fp_confidence >= ^min_confidence,
      order_by: [desc: p.fp_confidence, desc: p.fp_count],
      limit: ^limit
    )

    query = if status, do: where(query, [p], p.status == ^status), else: query
    query = if pattern_type, do: where(query, [p], p.pattern_type == ^pattern_type), else: query

    Repo.all(query)
  end

  @doc """
  Get patterns ready for auto-tuning.
  """
  @spec get_tunable_patterns(String.t()) :: [FPPattern.t()]
  def get_tunable_patterns(organization_id) do
    from(p in FPPattern,
      where: p.organization_id == ^organization_id,
      where: p.status == "detected",
      where: p.suppression_created == false,
      where: p.fp_confidence >= ^@min_fp_confidence,
      where: p.fp_count >= ^@min_fp_count,
      where: p.tp_count <= 1,
      order_by: [desc: p.fp_count]
    )
    |> Repo.all()
  end

  @doc """
  Confirm a pattern (mark as valid for suppression).
  """
  @spec confirm_pattern(String.t(), String.t(), map()) ::
          {:ok, FPPattern.t()} | {:error, term()}
  def confirm_pattern(pattern_id, user_id, opts \\ %{}) do
    case Repo.get(FPPattern, pattern_id) do
      nil ->
        {:error, :not_found}

      pattern ->
        pattern
        |> FPPattern.changeset(%{
          status: "confirmed",
          reviewed: true,
          reviewed_by_id: user_id,
          reviewed_at: DateTime.utc_now(),
          review_action: "approve_suppression"
        })
        |> Repo.update()
        |> case do
          {:ok, updated} ->
            # Optionally create suppression rule
            if opts[:create_suppression] do
              AutoTuner.create_suppression_for_pattern(updated)
            end
            {:ok, updated}

          error ->
            error
        end
    end
  end

  @doc """
  Reject a pattern (mark as not suitable for suppression).
  """
  @spec reject_pattern(String.t(), String.t(), String.t() | nil) ::
          {:ok, FPPattern.t()} | {:error, term()}
  def reject_pattern(pattern_id, user_id, reason \\ nil) do
    case Repo.get(FPPattern, pattern_id) do
      nil ->
        {:error, :not_found}

      pattern ->
        pattern
        |> FPPattern.changeset(%{
          status: "rejected",
          reviewed: true,
          reviewed_by_id: user_id,
          reviewed_at: DateTime.utc_now(),
          review_action: "reject"
        })
        |> Repo.update()
    end
  end

  # ---------------------------------------------------------------------------
  # GenServer Callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(_opts) do
    schedule_periodic_analysis()
    Logger.info("[FPPatterns] Initialized")
    {:ok, %{}}
  end

  @impl true
  def handle_cast({:analyze_report, report}, state) do
    # Check if report matches existing patterns
    update_matching_patterns(report)

    # Check for potential new patterns
    check_new_patterns(report)

    {:noreply, state}
  end

  @impl true
  def handle_call({:analyze_organization, organization_id}, _from, state) do
    patterns = do_analyze_organization(organization_id)
    {:reply, {:ok, patterns}, state}
  end

  @impl true
  def handle_info(:periodic_analysis, state) do
    run_periodic_analysis()
    schedule_periodic_analysis()
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ---------------------------------------------------------------------------
  # Private - Pattern Analysis
  # ---------------------------------------------------------------------------

  defp do_analyze_organization(organization_id) do
    # Get recent FP reports (last 30 days)
    start_time = DateTime.add(DateTime.utc_now(), -30 * 24 * 3600, :second)

    fp_reports =
      from(r in FPReport,
        where: r.organization_id == ^organization_id,
        where: r.classification == "false_positive",
        where: r.inserted_at >= ^start_time
      )
      |> Repo.all()

    # Also get TP reports to check for overlap
    tp_reports =
      from(r in FPReport,
        where: r.organization_id == ^organization_id,
        where: r.classification == "true_positive",
        where: r.inserted_at >= ^start_time
      )
      |> Repo.all()

    # Analyze different pattern types
    patterns = []

    # Process patterns
    patterns = patterns ++ analyze_process_patterns(organization_id, fp_reports, tp_reports)

    # Path patterns
    patterns = patterns ++ analyze_path_patterns(organization_id, fp_reports, tp_reports)

    # Rule patterns
    patterns = patterns ++ analyze_rule_patterns(organization_id, fp_reports, tp_reports)

    # User patterns
    patterns = patterns ++ analyze_user_patterns(organization_id, fp_reports, tp_reports)

    # Host patterns
    patterns = patterns ++ analyze_host_patterns(organization_id, fp_reports, tp_reports)

    # Time patterns
    patterns = patterns ++ analyze_time_patterns(organization_id, fp_reports, tp_reports)

    # Combined patterns (process + path, etc.)
    patterns = patterns ++ analyze_combined_patterns(organization_id, fp_reports, tp_reports)

    # Save/update patterns in database
    saved_patterns = Enum.map(patterns, fn pattern_data ->
      upsert_pattern(organization_id, pattern_data)
    end)
    |> Enum.reject(&is_nil/1)

    # Clean up old patterns that no longer meet thresholds
    cleanup_stale_patterns(organization_id)

    saved_patterns
  end

  defp analyze_process_patterns(organization_id, fp_reports, tp_reports) do
    # Group FPs by process name
    fp_by_process =
      fp_reports
      |> Enum.filter(& &1.process_name)
      |> Enum.group_by(& String.downcase(&1.process_name))

    # Group TPs by process name
    tp_by_process =
      tp_reports
      |> Enum.filter(& &1.process_name)
      |> Enum.group_by(& String.downcase(&1.process_name))

    fp_by_process
    |> Enum.filter(fn {_process, reports} -> length(reports) >= @min_fp_count end)
    |> Enum.map(fn {process_name, fp_list} ->
      tp_count = length(Map.get(tp_by_process, process_name, []))
      fp_count = length(fp_list)
      total = fp_count + tp_count
      confidence = FPPattern.calculate_fp_confidence(fp_count, tp_count, total)

      if confidence >= @min_fp_confidence do
        %{
          pattern_type: "process",
          pattern_key: "process:#{process_name}",
          pattern_data: %{
            "process_name" => process_name,
            "associated_rules" => fp_list |> Enum.map(& &1.rule_name) |> Enum.uniq() |> Enum.take(10)
          },
          fp_count: fp_count,
          tp_count: tp_count,
          total_matches: total,
          fp_confidence: confidence,
          example_alert_ids: fp_list |> Enum.take(5) |> Enum.map(& &1.alert_id),
          detection_source: fp_list |> Enum.map(& &1.detection_source) |> Enum.uniq() |> List.first()
        }
      end
    end)
    |> Enum.reject(&is_nil/1)
  end

  defp analyze_path_patterns(organization_id, fp_reports, tp_reports) do
    # Group FPs by file path directory
    fp_by_path =
      fp_reports
      |> Enum.filter(& &1.file_path)
      |> Enum.map(fn report ->
        dir = Path.dirname(report.file_path) |> String.downcase()
        {dir, report}
      end)
      |> Enum.group_by(fn {dir, _} -> dir end, fn {_, report} -> report end)

    tp_by_path =
      tp_reports
      |> Enum.filter(& &1.file_path)
      |> Enum.map(fn report ->
        dir = Path.dirname(report.file_path) |> String.downcase()
        {dir, report}
      end)
      |> Enum.group_by(fn {dir, _} -> dir end, fn {_, report} -> report end)

    fp_by_path
    |> Enum.filter(fn {_path, reports} -> length(reports) >= @min_fp_count end)
    |> Enum.map(fn {path, fp_list} ->
      tp_count = length(Map.get(tp_by_path, path, []))
      fp_count = length(fp_list)
      total = fp_count + tp_count
      confidence = FPPattern.calculate_fp_confidence(fp_count, tp_count, total)

      if confidence >= @min_fp_confidence do
        %{
          pattern_type: "path",
          pattern_key: "path:#{:erlang.phash2(path)}",
          pattern_data: %{
            "path_pattern" => "#{path}/*",
            "path_directory" => path
          },
          fp_count: fp_count,
          tp_count: tp_count,
          total_matches: total,
          fp_confidence: confidence,
          example_alert_ids: fp_list |> Enum.take(5) |> Enum.map(& &1.alert_id)
        }
      end
    end)
    |> Enum.reject(&is_nil/1)
  end

  defp analyze_rule_patterns(organization_id, fp_reports, tp_reports) do
    # Group by rule_id - rules that always generate FPs
    fp_by_rule =
      fp_reports
      |> Enum.filter(& &1.rule_id)
      |> Enum.group_by(& &1.rule_id)

    tp_by_rule =
      tp_reports
      |> Enum.filter(& &1.rule_id)
      |> Enum.group_by(& &1.rule_id)

    fp_by_rule
    |> Enum.filter(fn {_rule, reports} -> length(reports) >= @min_fp_count end)
    |> Enum.map(fn {rule_id, fp_list} ->
      tp_count = length(Map.get(tp_by_rule, rule_id, []))
      fp_count = length(fp_list)
      total = fp_count + tp_count
      confidence = FPPattern.calculate_fp_confidence(fp_count, tp_count, total)

      # Only flag rules with very high FP rate (>90%)
      if confidence >= 0.9 do
        first_report = List.first(fp_list)
        %{
          pattern_type: "rule",
          pattern_key: "rule:#{rule_id}",
          pattern_data: %{
            "rule_id" => rule_id,
            "rule_name" => first_report.rule_name,
            "detection_source" => first_report.detection_source
          },
          fp_count: fp_count,
          tp_count: tp_count,
          total_matches: total,
          fp_confidence: confidence,
          example_alert_ids: fp_list |> Enum.take(5) |> Enum.map(& &1.alert_id),
          detection_source: first_report.detection_source,
          associated_rules: [rule_id]
        }
      end
    end)
    |> Enum.reject(&is_nil/1)
  end

  defp analyze_user_patterns(organization_id, fp_reports, tp_reports) do
    # Group by event user
    fp_by_user =
      fp_reports
      |> Enum.filter(& &1.event_user)
      |> Enum.group_by(& String.downcase(&1.event_user))

    tp_by_user =
      tp_reports
      |> Enum.filter(& &1.event_user)
      |> Enum.group_by(& String.downcase(&1.event_user))

    fp_by_user
    |> Enum.filter(fn {_user, reports} -> length(reports) >= @min_fp_count end)
    |> Enum.map(fn {user, fp_list} ->
      tp_count = length(Map.get(tp_by_user, user, []))
      fp_count = length(fp_list)
      total = fp_count + tp_count
      confidence = FPPattern.calculate_fp_confidence(fp_count, tp_count, total)

      if confidence >= @min_fp_confidence do
        %{
          pattern_type: "user",
          pattern_key: "user:#{user}",
          pattern_data: %{
            "user" => user,
            "user_role" => fp_list |> Enum.map(& &1.user_role) |> Enum.uniq() |> List.first()
          },
          fp_count: fp_count,
          tp_count: tp_count,
          total_matches: total,
          fp_confidence: confidence,
          example_alert_ids: fp_list |> Enum.take(5) |> Enum.map(& &1.alert_id)
        }
      end
    end)
    |> Enum.reject(&is_nil/1)
  end

  defp analyze_host_patterns(organization_id, fp_reports, tp_reports) do
    # Group by hostname
    fp_by_host =
      fp_reports
      |> Enum.filter(& &1.hostname)
      |> Enum.group_by(& String.downcase(&1.hostname))

    tp_by_host =
      tp_reports
      |> Enum.filter(& &1.hostname)
      |> Enum.group_by(& String.downcase(&1.hostname))

    fp_by_host
    |> Enum.filter(fn {_host, reports} -> length(reports) >= @min_fp_count end)
    |> Enum.map(fn {hostname, fp_list} ->
      tp_count = length(Map.get(tp_by_host, hostname, []))
      fp_count = length(fp_list)
      total = fp_count + tp_count
      confidence = FPPattern.calculate_fp_confidence(fp_count, tp_count, total)

      if confidence >= @min_fp_confidence do
        %{
          pattern_type: "host",
          pattern_key: "host:#{hostname}",
          pattern_data: %{
            "hostname" => hostname
          },
          fp_count: fp_count,
          tp_count: tp_count,
          total_matches: total,
          fp_confidence: confidence,
          example_alert_ids: fp_list |> Enum.take(5) |> Enum.map(& &1.alert_id)
        }
      end
    end)
    |> Enum.reject(&is_nil/1)
  end

  defp analyze_time_patterns(organization_id, fp_reports, _tp_reports) do
    # Group FPs by hour of day
    fp_by_hour =
      fp_reports
      |> Enum.group_by(& &1.inserted_at.hour)

    # Find hours with unusually high FP counts
    total_fps = length(fp_reports)
    avg_per_hour = total_fps / 24

    fp_by_hour
    |> Enum.filter(fn {_hour, reports} ->
      # Hour has 3x the average FP rate
      length(reports) >= max(@min_fp_count, avg_per_hour * 3)
    end)
    |> Enum.map(fn {hour, fp_list} ->
      fp_count = length(fp_list)

      %{
        pattern_type: "time",
        pattern_key: "time:hour:#{hour}",
        pattern_data: %{
          "hour" => hour,
          "description" => "High FP rate during hour #{hour}:00-#{hour}:59"
        },
        fp_count: fp_count,
        tp_count: 0,
        total_matches: fp_count,
        fp_confidence: 0.7,  # Lower confidence for time patterns
        example_alert_ids: fp_list |> Enum.take(5) |> Enum.map(& &1.alert_id)
      }
    end)
  end

  defp analyze_combined_patterns(organization_id, fp_reports, tp_reports) do
    # Analyze process + rule combinations
    fp_by_combo =
      fp_reports
      |> Enum.filter(& &1.process_name && &1.rule_id)
      |> Enum.group_by(fn r ->
        {String.downcase(r.process_name), r.rule_id}
      end)

    tp_by_combo =
      tp_reports
      |> Enum.filter(& &1.process_name && &1.rule_id)
      |> Enum.group_by(fn r ->
        {String.downcase(r.process_name), r.rule_id}
      end)

    fp_by_combo
    |> Enum.filter(fn {_combo, reports} -> length(reports) >= 3 end)  # Lower threshold for combined
    |> Enum.map(fn {{process_name, rule_id}, fp_list} ->
      tp_count = length(Map.get(tp_by_combo, {process_name, rule_id}, []))
      fp_count = length(fp_list)
      total = fp_count + tp_count
      confidence = FPPattern.calculate_fp_confidence(fp_count, tp_count, total)

      if confidence >= @min_fp_confidence do
        first_report = List.first(fp_list)
        %{
          pattern_type: "combined",
          pattern_key: "combo:#{process_name}:#{rule_id}",
          pattern_data: %{
            "process_name" => process_name,
            "rule_id" => rule_id,
            "rule_name" => first_report.rule_name
          },
          fp_count: fp_count,
          tp_count: tp_count,
          total_matches: total,
          fp_confidence: confidence,
          example_alert_ids: fp_list |> Enum.take(5) |> Enum.map(& &1.alert_id),
          detection_source: first_report.detection_source,
          associated_rules: [rule_id]
        }
      end
    end)
    |> Enum.reject(&is_nil/1)
  end

  # ---------------------------------------------------------------------------
  # Private - Pattern Management
  # ---------------------------------------------------------------------------

  defp update_matching_patterns(%FPReport{} = report) do
    # Find existing patterns that this report might match
    patterns =
      from(p in FPPattern,
        where: p.organization_id == ^report.organization_id,
        where: p.status in ["detected", "confirmed"]
      )
      |> Repo.all()

    Enum.each(patterns, fn pattern ->
      if report_matches_pattern?(report, pattern) do
        # Update pattern counts
        updates = case report.classification do
          "false_positive" ->
            %{
              fp_count: (pattern.fp_count || 0) + 1,
              total_matches: (pattern.total_matches || 0) + 1,
              last_seen_at: DateTime.utc_now()
            }

          "true_positive" ->
            %{
              tp_count: (pattern.tp_count || 0) + 1,
              total_matches: (pattern.total_matches || 0) + 1
            }

          _ ->
            %{total_matches: (pattern.total_matches || 0) + 1}
        end

        # Recalculate confidence
        updated = Map.merge(pattern, updates) |> struct(FPPattern)
        new_confidence = FPPattern.calculate_fp_confidence(
          updated.fp_count,
          updated.tp_count,
          updated.total_matches
        )
        updates = Map.put(updates, :fp_confidence, new_confidence)

        pattern
        |> FPPattern.changeset(updates)
        |> Repo.update()
      end
    end)
  rescue
    e ->
      Logger.warning("[FPPatterns] Failed to update matching patterns: #{Exception.message(e)}")
  end

  defp report_matches_pattern?(report, pattern) do
    case pattern.pattern_type do
      "process" ->
        report.process_name &&
          String.downcase(report.process_name) == pattern.pattern_data["process_name"]

      "path" ->
        report.file_path &&
          String.starts_with?(
            String.downcase(Path.dirname(report.file_path)),
            pattern.pattern_data["path_directory"]
          )

      "rule" ->
        report.rule_id == pattern.pattern_data["rule_id"]

      "user" ->
        report.event_user &&
          String.downcase(report.event_user) == pattern.pattern_data["user"]

      "host" ->
        report.hostname &&
          String.downcase(report.hostname) == pattern.pattern_data["hostname"]

      "combined" ->
        report.process_name &&
          report.rule_id &&
          String.downcase(report.process_name) == pattern.pattern_data["process_name"] &&
          report.rule_id == pattern.pattern_data["rule_id"]

      _ ->
        false
    end
  end

  defp check_new_patterns(%FPReport{} = report) do
    # This is called for each new FP report to check if we should
    # start tracking a new pattern. The full analysis runs periodically
    # to find patterns across all reports.

    # For immediate feedback, check if this report would create a high-confidence
    # pattern with existing FP reports

    # This is a lightweight check - full analysis happens in analyze_organization
    :ok
  end

  defp upsert_pattern(organization_id, pattern_data) do
    pattern_key = pattern_data[:pattern_key]

    case Repo.get_by(FPPattern,
           organization_id: organization_id,
           pattern_type: pattern_data[:pattern_type],
           pattern_key: pattern_key
         ) do
      nil ->
        # Create new pattern
        attrs = Map.merge(pattern_data, %{
          organization_id: organization_id,
          first_seen_at: DateTime.utc_now(),
          last_seen_at: DateTime.utc_now()
        })

        case %FPPattern{} |> FPPattern.changeset(attrs) |> Repo.insert() do
          {:ok, pattern} -> pattern
          {:error, _} -> nil
        end

      existing ->
        # Update existing pattern
        attrs = %{
          fp_count: pattern_data[:fp_count],
          tp_count: pattern_data[:tp_count],
          total_matches: pattern_data[:total_matches],
          fp_confidence: pattern_data[:fp_confidence],
          last_seen_at: DateTime.utc_now(),
          example_alert_ids: pattern_data[:example_alert_ids] || existing.example_alert_ids
        }

        case existing |> FPPattern.changeset(attrs) |> Repo.update() do
          {:ok, pattern} -> pattern
          {:error, _} -> existing
        end
    end
  rescue
    e ->
      Logger.warning("[FPPatterns] Failed to upsert pattern: #{Exception.message(e)}")
      nil
  end

  defp cleanup_stale_patterns(organization_id) do
    # Mark patterns as stale if they haven't been seen in 30 days
    # or if their confidence has dropped below threshold
    cutoff = DateTime.add(DateTime.utc_now(), -30 * 24 * 3600, :second)

    from(p in FPPattern,
      where: p.organization_id == ^organization_id,
      where: p.status == "detected",
      where: p.last_seen_at < ^cutoff or p.fp_confidence < 0.5
    )
    |> Repo.update_all(set: [status: "stale"])
  rescue
    _ -> :ok
  end

  defp run_periodic_analysis do
    # Get all organizations with recent FP reports
    cutoff = DateTime.add(DateTime.utc_now(), -7 * 24 * 3600, :second)

    org_ids =
      from(r in FPReport,
        where: r.inserted_at >= ^cutoff,
        distinct: true,
        select: r.organization_id
      )
      |> Repo.all()
      |> Enum.reject(&is_nil/1)

    Enum.each(org_ids, fn org_id ->
      try do
        do_analyze_organization(org_id)
      rescue
        e ->
          Logger.warning("[FPPatterns] Failed to analyze org #{org_id}: #{Exception.message(e)}")
      end
    end)

    Logger.info("[FPPatterns] Completed periodic analysis for #{length(org_ids)} organizations")
  end

  defp schedule_periodic_analysis do
    Process.send_after(self(), :periodic_analysis, @analysis_interval)
  end
end
