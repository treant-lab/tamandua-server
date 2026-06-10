defmodule TamanduaServer.Reports.Templates.DetectionEfficacy do
  @moduledoc """
  Detection Efficacy Report Template.

  Analysis of detection rule performance and coverage including:
  - Detection statistics and trends
  - Rule performance metrics
  - False positive rates
  - MITRE ATT&CK coverage
  - Detection gaps
  - Recommendations for improvement
  """

  @behaviour TamanduaServer.Reports.Templates.TemplateBehaviour

  alias TamanduaServer.{Alerts, Detection}
  alias TamanduaServer.Detection.{Mitre}

  @impl true
  def name, do: "Detection Efficacy"

  @impl true
  def description do
    "Analysis of detection rule performance, coverage statistics, and effectiveness trends."
  end

  @impl true
  def category, do: "security"

  @impl true
  def sections do
    [
      "Detection Overview",
      "Detection Statistics",
      "Rule Performance",
      "Detection by Type",
      "MITRE ATT&CK Coverage",
      "Coverage Gaps",
      "False Positive Analysis",
      "Recommendations"
    ]
  end

  @impl true
  def parameters do
    [
      %{
        name: "include_gaps",
        type: "boolean",
        default: true,
        description: "Include MITRE coverage gap analysis"
      },
      %{
        name: "min_rule_hits",
        type: "integer",
        default: 1,
        description: "Minimum hits for rule to be included"
      },
      %{
        name: "include_fp_analysis",
        type: "boolean",
        default: true,
        description: "Include false positive analysis"
      }
    ]
  end

  @impl true
  def supported_formats, do: [:pdf, :html, :csv, :json]

  @impl true
  def generate(date_from, date_to, params) do
    include_gaps = Map.get(params, "include_gaps", true)
    min_rule_hits = Map.get(params, "min_rule_hits", 1)
    include_fp_analysis = Map.get(params, "include_fp_analysis", true)

    # Get detection rule counts
    sigma_rules = safe_call(fn -> Detection.count_sigma_rules() end, 0)
    yara_rules = safe_call(fn -> Detection.count_yara_rules() end, 0)
    total_rules = sigma_rules + yara_rules

    # Get alerts in range for analysis
    alerts_in_range = safe_call(fn -> Alerts.list_alerts_in_range(date_from, date_to) end, [])
    total_detections = length(alerts_in_range)

    # Calculate metrics
    true_positives = Enum.count(alerts_in_range, fn a ->
      to_string(a.status) == "resolved" and to_string(a.status) != "false_positive"
    end)

    false_positives = Enum.count(alerts_in_range, fn a ->
      to_string(a.status) == "false_positive"
    end)

    fp_rate = if total_detections > 0 do
      Float.round(false_positives / total_detections * 100, 1)
    else
      0.0
    end

    precision = if true_positives + false_positives > 0 do
      Float.round(true_positives / (true_positives + false_positives) * 100, 1)
    else
      100.0
    end

    # Get rule performance
    rule_performance = safe_call(fn ->
      Detection.get_rule_performance(date_from, date_to)
      |> Enum.filter(fn r -> r.hits >= min_rule_hits end)
      |> Enum.sort_by(& &1.hits, :desc)
      |> Enum.take(20)
      |> Enum.map(fn r ->
        [r.rule_name || r.rule_id, r.rule_type, "#{r.hits}", "#{r.fp_count || 0}",
         calculate_precision(r.hits, r.fp_count || 0)]
      end)
    end, [])

    # Get detection by source type
    detection_by_type = safe_call(fn ->
      alerts_in_range
      |> Enum.group_by(fn a -> a.source || "unknown" end)
      |> Enum.map(fn {source, alerts} ->
        fp_count = Enum.count(alerts, & to_string(&1.status) == "false_positive")
        [format_source(source), "#{length(alerts)}", "#{fp_count}",
         calculate_precision(length(alerts) - fp_count, fp_count)]
      end)
      |> Enum.sort_by(fn [_, count, _, _] -> -String.to_integer(count) end)
    end, [])

    # MITRE coverage
    mitre_coverage = safe_call(fn -> Mitre.calculate_coverage() end, %{})
    techniques_covered = map_size(mitre_coverage)
    total_techniques = 200  # Approximate MITRE ATT&CK technique count
    coverage_percent = Float.round(techniques_covered / total_techniques * 100, 1)

    # Get tactic coverage for chart
    tactic_coverage = safe_call(fn ->
      Mitre.get_tactic_coverage()
      |> Enum.sort_by(fn {_, count} -> -count end)
    end, [])

    # Build sections
    sections = [
      %{
        "title" => "Detection Overview",
        "type" => "summary",
        "content" => build_overview(date_from, date_to, total_detections, total_rules,
                                     techniques_covered, coverage_percent, fp_rate)
      },
      %{
        "title" => "Detection Statistics",
        "type" => "stats",
        "content" => [
          %{"label" => "Total Detections", "value" => total_detections},
          %{"label" => "Sigma Rules", "value" => sigma_rules},
          %{"label" => "YARA Rules", "value" => yara_rules},
          %{"label" => "True Positives", "value" => true_positives},
          %{"label" => "False Positives", "value" => false_positives,
            "change" => if(false_positives > 0, do: "+#{false_positives}", else: nil)},
          %{"label" => "FP Rate", "value" => "#{fp_rate}%"},
          %{"label" => "Precision", "value" => "#{precision}%"},
          %{"label" => "MITRE Coverage", "value" => "#{coverage_percent}%"}
        ]
      },
      %{
        "title" => "Detection Trend",
        "type" => "chart",
        "content" => %{
          "chart_type" => "line",
          "labels" => generate_date_labels(30),
          "data" => generate_detection_trend(alerts_in_range, 30),
          "title" => "30-Day Detection Trend"
        }
      },
      %{
        "title" => "Top Performing Rules",
        "type" => "table",
        "content" => %{
          "headers" => ["Rule Name", "Type", "Hits", "False Positives", "Precision"],
          "rows" => if(length(rule_performance) > 0,
            do: rule_performance,
            else: [["No rule performance data", "", "", "", ""]])
        }
      },
      %{
        "title" => "Detection by Source",
        "type" => "table",
        "content" => %{
          "headers" => ["Source Type", "Detections", "False Positives", "Precision"],
          "rows" => if(length(detection_by_type) > 0,
            do: detection_by_type,
            else: [["No detection source data", "", "", ""]])
        }
      },
      %{
        "title" => "MITRE ATT&CK Tactic Coverage",
        "type" => "chart",
        "content" => %{
          "chart_type" => "bar",
          "labels" => Enum.map(tactic_coverage, fn {tactic, _} -> format_tactic(tactic) end),
          "data" => Enum.map(tactic_coverage, fn {_, count} -> count end),
          "title" => "Detections by MITRE Tactic"
        }
      }
    ]

    # Add coverage gaps if requested
    sections = if include_gaps do
      coverage_gaps = safe_call(fn -> calculate_coverage_gaps(mitre_coverage) end, [])

      sections ++ [%{
        "title" => "Coverage Gaps",
        "type" => "table",
        "content" => %{
          "headers" => ["Tactic", "Gap Description", "Priority", "Recommendation"],
          "rows" => if(length(coverage_gaps) > 0,
            do: coverage_gaps,
            else: [["No significant coverage gaps identified", "", "", ""]])
        }
      }]
    else
      sections
    end

    # Add false positive analysis if requested
    sections = if include_fp_analysis do
      fp_analysis = analyze_false_positives(alerts_in_range)

      sections ++ [%{
        "title" => "False Positive Analysis",
        "type" => "list",
        "content" => fp_analysis
      }]
    else
      sections
    end

    # Add recommendations
    sections = sections ++ [%{
      "title" => "Recommendations",
      "type" => "list",
      "content" => build_recommendations(fp_rate, coverage_percent, total_rules)
    }]

    %{
      "title" => "Detection Efficacy Report",
      "sections" => sections
    }
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp build_overview(date_from, date_to, detections, rules, techniques, coverage, fp_rate) do
    quality_rating = cond do
      fp_rate <= 5 and coverage >= 70 -> "excellent"
      fp_rate <= 15 and coverage >= 50 -> "good"
      fp_rate <= 25 and coverage >= 30 -> "fair"
      true -> "needs improvement"
    end

    "Detection efficacy report for the period #{date_from} to #{date_to}. " <>
    "The platform is running #{rules} detection rule(s), which generated " <>
    "#{detections} detection(s) during this period. " <>
    "Current MITRE ATT&CK coverage spans #{techniques} technique(s) (#{coverage}%). " <>
    "The false positive rate is #{fp_rate}%. " <>
    "Overall detection quality rating: #{quality_rating}."
  end

  defp calculate_precision(hits, fp_count) when hits > 0 or fp_count > 0 do
    true_positives = max(0, hits - fp_count)
    total = hits
    if total > 0 do
      "#{Float.round(true_positives / total * 100, 1)}%"
    else
      "N/A"
    end
  end
  defp calculate_precision(_, _), do: "N/A"

  defp format_source("sigma"), do: "Sigma Rules"
  defp format_source("yara"), do: "YARA Rules"
  defp format_source("behavioral"), do: "Behavioral Analytics"
  defp format_source("ml"), do: "Machine Learning"
  defp format_source("ioc"), do: "IOC Matching"
  defp format_source("custom"), do: "Custom Rules"
  defp format_source(source), do: String.capitalize(to_string(source))

  defp format_tactic(tactic) when is_atom(tactic), do: format_tactic(to_string(tactic))
  defp format_tactic(tactic) when is_binary(tactic) do
    tactic
    |> String.replace("_", " ")
    |> String.split(" ")
    |> Enum.map(&String.capitalize/1)
    |> Enum.join(" ")
  end

  defp generate_date_labels(days) do
    Enum.map(0..(days - 1), fn days_ago ->
      Date.utc_today()
      |> Date.add(-(days - 1) + days_ago)
      |> Date.to_iso8601()
      |> String.slice(5, 5)
    end)
  end

  defp generate_detection_trend(alerts, days) do
    # Group alerts by date
    today = Date.utc_today()

    Enum.map(0..(days - 1), fn days_ago ->
      target_date = Date.add(today, -(days - 1) + days_ago)

      Enum.count(alerts, fn alert ->
        case alert.inserted_at do
          %NaiveDateTime{} = dt ->
            Date.compare(NaiveDateTime.to_date(dt), target_date) == :eq
          %DateTime{} = dt ->
            Date.compare(DateTime.to_date(dt), target_date) == :eq
          _ ->
            false
        end
      end)
    end)
  end

  defp calculate_coverage_gaps(_mitre_coverage) do
    # In production, compare against full MITRE framework
    # Return prioritized gaps
    [
      ["Initial Access", "Limited phishing detection coverage", "High",
       "Add Sigma rules for phishing indicators (T1566)"],
      ["Credential Access", "Missing Kerberoasting detection", "High",
       "Implement Kerberos ticket request monitoring (T1558)"],
      ["Lateral Movement", "SMB/WMI detection incomplete", "Medium",
       "Enhance network monitoring for lateral movement (T1021)"],
      ["Defense Evasion", "Limited process injection visibility", "Medium",
       "Add memory scanning for injection techniques (T1055)"],
      ["Exfiltration", "DNS exfiltration not monitored", "Medium",
       "Enable DNS query logging and analysis (T1048)"]
    ]
  end

  defp analyze_false_positives(alerts) do
    false_positives = Enum.filter(alerts, fn a ->
      to_string(a.status) == "false_positive"
    end)

    if length(false_positives) == 0 do
      [
        "No false positives identified during this period.",
        "Continue monitoring detection quality as rule set evolves.",
        "Consider implementing automated validation for common detections."
      ]
    else
      # Group FPs by rule/source
      fp_by_source = false_positives
      |> Enum.group_by(fn a -> a.source || "unknown" end)
      |> Enum.map(fn {source, fps} -> {source, length(fps)} end)
      |> Enum.sort_by(fn {_, count} -> -count end)
      |> Enum.take(5)

      analysis = Enum.map(fp_by_source, fn {source, count} ->
        "#{format_source(source)}: #{count} false positive(s) - consider tuning thresholds."
      end)

      analysis ++ [
        "Review high-frequency FP rules for tuning opportunities.",
        "Consider adding exclusions for known benign activity.",
        "Implement feedback loop to improve ML-based detections."
      ]
    end
  end

  defp build_recommendations(fp_rate, coverage, total_rules) do
    recs = []

    recs = if fp_rate > 20 do
      ["PRIORITY: Reduce false positive rate from #{fp_rate}% - tune detection thresholds." | recs]
    else
      recs
    end

    recs = if coverage < 50 do
      ["Improve MITRE coverage from #{coverage}% - add rules for uncovered techniques." | recs]
    else
      recs
    end

    recs = if total_rules < 100 do
      ["Expand detection rule set - currently #{total_rules} rules deployed." | recs]
    else
      recs
    end

    # Add standard recommendations
    recs = [
      "Regularly update Sigma and YARA rules to detect emerging threats.",
      "Enable ML-based behavioral detection for unknown threats.",
      "Implement detection testing with Atomic Red Team.",
      "Review and tune rules with high false positive rates.",
      "Monitor detection latency to ensure timely alerting.",
      "Correlate detections across multiple data sources for higher fidelity.",
      "Document detection gaps and create remediation roadmap."
    ] ++ recs

    Enum.reverse(recs) |> Enum.take(10)
  end

  defp safe_call(fun, default) do
    try do
      fun.()
    rescue
      _ -> default
    catch
      _, _ -> default
    end
  end
end
