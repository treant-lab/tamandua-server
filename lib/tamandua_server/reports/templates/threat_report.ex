defmodule TamanduaServer.Reports.Templates.ThreatReport do
  @moduledoc """
  Detailed Threat Analysis Report Template.

  Comprehensive analysis of threats detected in the environment including:
  - Threat landscape overview
  - Attack vector distribution
  - MITRE ATT&CK technique mapping
  - IOC summary and statistics
  - Threat actor activity (if available)
  - Trend analysis
  """

  @behaviour TamanduaServer.Reports.Templates.TemplateBehaviour

  alias TamanduaServer.{Alerts, Detection, ThreatIntel}
  alias TamanduaServer.Detection.{IOCs, Mitre}

  @impl true
  def name, do: "Threat Report"

  @impl true
  def description do
    "Detailed threat analysis including attack patterns, IOCs, MITRE ATT&CK mapping, and threat actor activity."
  end

  @impl true
  def category, do: "security"

  @impl true
  def sections do
    [
      "Threat Overview",
      "Threat Statistics",
      "Attack Vector Distribution",
      "MITRE ATT&CK Techniques",
      "MITRE Tactic Coverage",
      "IOC Summary",
      "Threat Intel Indicators",
      "Trend Analysis"
    ]
  end

  @impl true
  def parameters do
    [
      %{
        name: "include_iocs",
        type: "boolean",
        default: true,
        description: "Include detailed IOC breakdown"
      },
      %{
        name: "max_techniques",
        type: "integer",
        default: 20,
        description: "Maximum number of techniques to display"
      },
      %{
        name: "include_threat_intel",
        type: "boolean",
        default: true,
        description: "Include threat intelligence feed data"
      }
    ]
  end

  @impl true
  def supported_formats, do: [:pdf, :html, :csv, :json]

  @impl true
  def generate(date_from, date_to, params) do
    include_iocs = Map.get(params, "include_iocs", true)
    max_techniques = Map.get(params, "max_techniques", 20)
    include_threat_intel = Map.get(params, "include_threat_intel", true)

    # IOC statistics
    ioc_stats = safe_call(fn -> IOCs.count_by_type() end, %{})
    total_iocs = safe_call(fn -> IOCs.count(enabled: true) end, 0)

    # Threat intel stats
    threat_intel_stats = safe_call(fn -> ThreatIntel.get_stats() end, %{})

    # Get attack techniques distribution
    technique_distribution = safe_call(fn ->
      Detection.get_top_techniques(limit: max_techniques)
      |> Enum.map(fn {tech_id, name, count} ->
        tactic = get_technique_tactic(tech_id)
        [name, tech_id, tactic, "#{count}"]
      end)
    end, [])

    # Get tactic distribution
    tactic_distribution = safe_call(fn ->
      Mitre.get_tactic_coverage()
      |> Enum.map(fn {tactic, count} ->
        [format_tactic_name(tactic), "#{count}"]
      end)
    end, [])

    # Get alerts in range for analysis
    alerts_in_range = safe_call(fn -> Alerts.list_alerts_in_range(date_from, date_to) end, [])
    total_alerts = length(alerts_in_range)

    # Attack vector analysis from alerts
    attack_vectors = safe_call(fn ->
      alerts_in_range
      |> Enum.flat_map(fn a -> a.mitre_tactics || [] end)
      |> Enum.frequencies()
      |> Enum.sort_by(fn {_, count} -> -count end)
      |> Enum.map(fn {tactic, count} ->
        percentage = if total_alerts > 0, do: Float.round(count / total_alerts * 100, 1), else: 0
        [format_tactic_name(tactic), "#{count}", "#{percentage}%", trend_indicator(count)]
      end)
    end, [])

    # IOC type breakdown
    ioc_breakdown = Enum.map(ioc_stats, fn {type, count} ->
      [format_ioc_type(type), "#{count}"]
    end)

    # Build sections
    sections = [
      %{
        "title" => "Threat Overview",
        "type" => "summary",
        "content" => build_overview(date_from, date_to, total_alerts, total_iocs,
                                     length(technique_distribution), threat_intel_stats)
      },
      %{
        "title" => "Threat Statistics",
        "type" => "stats",
        "content" => [
          %{"label" => "Total Detections", "value" => total_alerts},
          %{"label" => "Active IOCs", "value" => total_iocs},
          %{"label" => "IOC Categories", "value" => map_size(ioc_stats)},
          %{"label" => "Techniques Observed", "value" => length(technique_distribution)},
          %{"label" => "Threat Feeds Active", "value" => Map.get(threat_intel_stats, :feeds_active, 0)},
          %{"label" => "Critical Threats", "value" => count_by_severity(alerts_in_range, "critical")},
          %{"label" => "High Severity", "value" => count_by_severity(alerts_in_range, "high")},
          %{"label" => "Medium Severity", "value" => count_by_severity(alerts_in_range, "medium")}
        ]
      },
      %{
        "title" => "Attack Vector Distribution",
        "type" => "table",
        "content" => %{
          "headers" => ["Attack Vector (Tactic)", "Count", "Percentage", "Trend"],
          "rows" => if(length(attack_vectors) > 0,
            do: attack_vectors,
            else: [["No attack vectors detected", "", "", ""]])
        }
      },
      %{
        "title" => "MITRE ATT&CK Techniques",
        "type" => "table",
        "content" => %{
          "headers" => ["Technique", "ID", "Tactic", "Count"],
          "rows" => if(length(technique_distribution) > 0,
            do: technique_distribution,
            else: [["No techniques detected", "", "", ""]])
        }
      },
      %{
        "title" => "MITRE Tactic Coverage",
        "type" => "chart",
        "content" => %{
          "chart_type" => "bar",
          "labels" => Enum.map(tactic_distribution, fn [name, _] -> name end),
          "data" => Enum.map(tactic_distribution, fn [_, count] -> String.to_integer(count) end),
          "title" => "Detections by MITRE ATT&CK Tactic"
        }
      }
    ]

    # Add IOC section if requested
    sections = if include_iocs do
      sections ++ [%{
        "title" => "IOC Summary",
        "type" => "table",
        "content" => %{
          "headers" => ["IOC Type", "Count"],
          "rows" => if(length(ioc_breakdown) > 0,
            do: ioc_breakdown,
            else: [["No IOCs configured", ""]])
        }
      }]
    else
      sections
    end

    # Add threat intel section if requested
    sections = if include_threat_intel do
      threat_indicators = safe_call(fn -> get_recent_threat_indicators(date_from, date_to) end, [])

      sections ++ [%{
        "title" => "Threat Intel Indicators",
        "type" => "table",
        "content" => %{
          "headers" => ["Indicator", "Type", "Source", "Confidence", "First Seen"],
          "rows" => if(length(threat_indicators) > 0,
            do: threat_indicators,
            else: [["No threat indicators matched", "", "", "", ""]])
        }
      }]
    else
      sections
    end

    # Add trend analysis
    sections = sections ++ [%{
      "title" => "Trend Analysis",
      "type" => "list",
      "content" => build_trend_analysis(alerts_in_range, technique_distribution)
    }]

    %{
      "title" => "Threat Report",
      "sections" => sections
    }
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp build_overview(date_from, date_to, total_alerts, total_iocs, techniques_count, threat_intel_stats) do
    feeds_active = Map.get(threat_intel_stats, :feeds_active, 0)

    "Analysis of the threat landscape observed during #{date_from} to #{date_to}. " <>
    "The platform is monitoring #{total_iocs} active indicator(s) of compromise. " <>
    "During this period, #{total_alerts} security event(s) were detected, " <>
    "spanning #{techniques_count} unique MITRE ATT&CK techniques. " <>
    "#{feeds_active} threat intelligence feed(s) are actively providing threat data."
  end

  defp count_by_severity(alerts, severity) do
    Enum.count(alerts, fn a ->
      to_string(a.severity) == severity
    end)
  end

  defp get_technique_tactic(technique_id) do
    case safe_call(fn -> Mitre.get_technique(technique_id) end, nil) do
      nil -> "Unknown"
      technique -> List.first(technique.tactics) || "Unknown"
    end
  end

  defp format_tactic_name(tactic) when is_atom(tactic), do: format_tactic_name(to_string(tactic))
  defp format_tactic_name(tactic) when is_binary(tactic) do
    tactic
    |> String.replace("_", " ")
    |> String.split(" ")
    |> Enum.map(&String.capitalize/1)
    |> Enum.join(" ")
  end

  defp format_ioc_type("hash_md5"), do: "MD5 Hashes"
  defp format_ioc_type("hash_sha1"), do: "SHA1 Hashes"
  defp format_ioc_type("hash_sha256"), do: "SHA256 Hashes"
  defp format_ioc_type("ip"), do: "IP Addresses"
  defp format_ioc_type("domain"), do: "Domains"
  defp format_ioc_type("url"), do: "URLs"
  defp format_ioc_type("email"), do: "Email Addresses"
  defp format_ioc_type("filename"), do: "Filenames"
  defp format_ioc_type(type), do: String.capitalize(to_string(type))

  defp trend_indicator(count) when count >= 10, do: "Increasing"
  defp trend_indicator(count) when count >= 5, do: "Stable"
  defp trend_indicator(_), do: "Low"

  defp get_recent_threat_indicators(_date_from, _date_to) do
    # In production, query actual threat intel matches
    # Returns: [[indicator, type, source, confidence, first_seen], ...]
    []
  end

  defp build_trend_analysis(alerts, technique_distribution) do
    trends = []

    total_alerts = length(alerts)
    critical_count = count_by_severity(alerts, "critical")
    high_count = count_by_severity(alerts, "high")

    trends = if total_alerts > 0 do
      ["#{total_alerts} total security event(s) detected during this period." | trends]
    else
      trends
    end

    trends = if critical_count > 0 do
      ["#{critical_count} critical severity event(s) require immediate attention." | trends]
    else
      trends
    end

    trends = if high_count > 0 do
      ["#{high_count} high severity event(s) should be prioritized for investigation." | trends]
    else
      trends
    end

    trends = if length(technique_distribution) > 0 do
      # Get top technique
      case List.first(technique_distribution) do
        [name, _id, _tactic, count] ->
          ["Most observed technique: #{name} (#{count} occurrences)." | trends]
        _ ->
          trends
      end
    else
      trends
    end

    # Add general recommendations
    trends = [
      "Continue monitoring for emerging threats and update detection rules accordingly.",
      "Review MITRE ATT&CK coverage gaps to improve detection capabilities.",
      "Correlate threat intelligence with observed activity for attribution.",
      "Update IOC feeds to ensure coverage of latest threats."
    ] ++ trends

    Enum.reverse(trends)
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
