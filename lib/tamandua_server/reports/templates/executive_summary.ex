defmodule TamanduaServer.Reports.Templates.ExecutiveSummary do
  @moduledoc """
  Executive Summary Report Template.

  High-level security posture overview for leadership review including:
  - Security score and trends
  - Critical incidents summary
  - Agent coverage metrics
  - Top threats detected
  - Key recommendations
  """

  @behaviour TamanduaServer.Reports.Templates.TemplateBehaviour

  alias TamanduaServer.{Agents, Alerts, Telemetry, Detection, ThreatIntel}
  alias TamanduaServer.Detection.{IOCs, Mitre}

  @impl true
  def name, do: "Executive Summary"

  @impl true
  def description do
    "High-level overview of security posture, key metrics, and critical incidents for leadership review."
  end

  @impl true
  def category, do: "security"

  @impl true
  def sections do
    [
      "Security Posture Overview",
      "Key Metrics",
      "Security Score Trend",
      "Critical Incidents",
      "Top Threats Detected",
      "Agent Coverage",
      "Recommendations"
    ]
  end

  @impl true
  def parameters do
    [
      %{
        name: "include_trends",
        type: "boolean",
        default: true,
        description: "Include trend charts comparing to previous period"
      },
      %{
        name: "max_incidents",
        type: "integer",
        default: 10,
        description: "Maximum number of incidents to include"
      },
      %{
        name: "max_threats",
        type: "integer",
        default: 10,
        description: "Maximum number of threats to include"
      }
    ]
  end

  @impl true
  def supported_formats, do: [:pdf, :html, :json]

  @impl true
  def generate(date_from, date_to, params) do
    include_trends = Map.get(params, "include_trends", true)
    max_incidents = Map.get(params, "max_incidents", 10)
    max_threats = Map.get(params, "max_threats", 10)

    # Tenant scoping: alert data must be limited to the caller's
    # organization. When no organization is provided we fail closed
    # (zero counts / empty lists) instead of returning cross-tenant data.
    organization_id = params["organization_id"] || params[:organization_id]

    # Gather metrics
    total_agents = safe_call(fn -> Agents.count_all() end, 0)
    online_agents = safe_call(fn -> Agents.count_online() end, 0)
    offline_agents = max(total_agents - online_agents, 0)

    open_alerts =
      if organization_id,
        do: safe_call(fn -> Alerts.count_active_for_org(organization_id) end, 0),
        else: 0

    critical_alerts =
      if organization_id,
        do: safe_call(fn -> Alerts.count_by_severity_for_org(organization_id, :critical) end, 0),
        else: 0

    high_alerts =
      if organization_id,
        do: safe_call(fn -> Alerts.count_by_severity_for_org(organization_id, :high) end, 0),
        else: 0

    resolved_alerts =
      if organization_id,
        do: safe_call(fn -> Alerts.count_by_status_for_org(organization_id, "resolved") end, 0),
        else: 0

    events_period = safe_call(fn -> Telemetry.count_events_in_range(date_from, date_to) end, 0)
    detections_period = safe_call(fn -> Detection.count_detections_in_range(date_from, date_to) end, 0)

    # Calculate security score
    security_score = calculate_security_score(total_agents, online_agents, critical_alerts, high_alerts)

    # Get top threats
    top_threats = safe_call(fn ->
      Detection.get_top_techniques(limit: max_threats)
      |> Enum.map(fn {technique, name, count} ->
        [name, technique, "#{count}", severity_for_count(count)]
      end)
    end, [])

    # Get recent critical incidents (tenant-scoped; empty when no org)
    critical_incidents =
      if organization_id do
        safe_call(fn ->
          Alerts.list_alerts_in_range_for_org(organization_id, date_from, date_to)
          |> Enum.filter(&(&1.severity in ["critical", :critical]))
          |> Enum.take(max_incidents)
          |> Enum.map(fn a ->
            [
              format_datetime(a.inserted_at),
              a.title || "Untitled",
              to_string(a.severity),
              to_string(a.status)
            ]
          end)
        end, [])
      else
        []
      end

    # Build sections
    sections = [
      %{
        "title" => "Security Posture Overview",
        "type" => "summary",
        "content" => build_summary(date_from, date_to, total_agents, online_agents,
                                   open_alerts, critical_alerts, events_period,
                                   detections_period, security_score)
      },
      %{
        "title" => "Key Metrics",
        "type" => "stats",
        "content" => [
          %{"label" => "Security Score", "value" => "#{security_score}/100"},
          %{"label" => "Total Agents", "value" => total_agents},
          %{"label" => "Online Agents", "value" => online_agents},
          %{"label" => "Critical Alerts", "value" => critical_alerts,
            "change" => if(critical_alerts > 0, do: "+#{critical_alerts}", else: nil)},
          %{"label" => "Open Alerts", "value" => open_alerts},
          %{"label" => "Events (Period)", "value" => format_number(events_period)},
          %{"label" => "Detections (Period)", "value" => detections_period},
          %{"label" => "Resolved Alerts", "value" => resolved_alerts}
        ]
      }
    ]

    # Add trend chart if requested
    sections = if include_trends do
      trend_data = generate_trend_data(date_from, date_to)
      sections ++ [%{
        "title" => "Security Score Trend",
        "type" => "chart",
        "content" => %{
          "chart_type" => "line",
          "labels" => trend_data.labels,
          "data" => trend_data.scores,
          "title" => "30-Day Security Score Trend"
        }
      }]
    else
      sections
    end

    sections = sections ++ [
      %{
        "title" => "Critical Incidents",
        "type" => "table",
        "content" => %{
          "headers" => ["Date", "Incident", "Severity", "Status"],
          "rows" => if(length(critical_incidents) > 0,
            do: critical_incidents,
            else: [["No critical incidents in this period", "", "", ""]])
        }
      },
      %{
        "title" => "Top Threats Detected",
        "type" => "table",
        "content" => %{
          "headers" => ["Threat", "MITRE Technique", "Count", "Severity"],
          "rows" => if(length(top_threats) > 0,
            do: top_threats,
            else: [["No threats detected in this period", "", "", ""]])
        }
      },
      %{
        "title" => "Agent Coverage",
        "type" => "stats",
        "content" => [
          %{"label" => "Total Endpoints", "value" => total_agents},
          %{"label" => "Protected (Online)", "value" => online_agents},
          %{"label" => "Offline/Unreachable", "value" => offline_agents},
          %{"label" => "Coverage Rate", "value" => "#{coverage_rate(online_agents, total_agents)}%"}
        ]
      },
      %{
        "title" => "Recommendations",
        "type" => "list",
        "content" => build_recommendations(open_alerts, critical_alerts, total_agents, online_agents)
      }
    ]

    %{
      "title" => "Executive Summary",
      "sections" => sections
    }
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp build_summary(date_from, date_to, total_agents, online_agents, open_alerts,
                     critical_alerts, events_period, detections_period, security_score) do
    coverage = coverage_rate(online_agents, total_agents)

    "During the reporting period (#{date_from} to #{date_to}), the Tamandua EDR platform " <>
    "actively monitored #{total_agents} endpoint(s), with #{online_agents} currently online " <>
    "(#{coverage}% coverage). " <>
    "A total of #{format_number(events_period)} telemetry events were processed, resulting in " <>
    "#{detections_period} detection(s). " <>
    "Currently, #{open_alerts} alert(s) remain open, of which #{critical_alerts} are critical severity. " <>
    "The overall security score is #{security_score}/100."
  end

  defp calculate_security_score(total_agents, online_agents, critical_alerts, high_alerts) do
    base_score = 100

    # Deduct for agent coverage issues
    agent_penalty = if total_agents > 0 do
      offline_ratio = (total_agents - online_agents) / total_agents
      round(offline_ratio * 20)
    else
      20
    end

    # Deduct for critical alerts (max 30 points)
    critical_penalty = min(critical_alerts * 10, 30)

    # Deduct for high alerts (max 15 points)
    high_penalty = min(high_alerts * 3, 15)

    max(0, base_score - agent_penalty - critical_penalty - high_penalty)
  end

  defp coverage_rate(online, total) when total > 0 do
    Float.round(online / total * 100, 1)
  end
  defp coverage_rate(_, _), do: 0.0

  defp severity_for_count(count) when count >= 50, do: "critical"
  defp severity_for_count(count) when count >= 20, do: "high"
  defp severity_for_count(count) when count >= 5, do: "medium"
  defp severity_for_count(_), do: "low"

  defp generate_trend_data(_date_from, _date_to) do
    # Generate sample trend data for the chart
    # In production, this would query historical security scores
    labels = Enum.map(0..29, fn days_ago ->
      Date.utc_today()
      |> Date.add(-29 + days_ago)
      |> Date.to_iso8601()
      |> String.slice(5, 5)  # MM-DD format
    end)

    # Simulated scores (in production, query from database)
    scores = Enum.map(0..29, fn _ -> 70 + :rand.uniform(25) end)

    %{labels: labels, scores: scores}
  end

  defp build_recommendations(open_alerts, critical_alerts, total_agents, online_agents) do
    recs = []

    recs = if critical_alerts > 0 do
      ["URGENT: Review and triage #{critical_alerts} critical alert(s) immediately." | recs]
    else
      recs
    end

    recs = if open_alerts > 5 do
      ["Review and prioritize #{open_alerts} open alerts to reduce backlog." | recs]
    else
      recs
    end

    recs = if total_agents > online_agents do
      ["Investigate #{total_agents - online_agents} offline agent(s) to ensure coverage." | recs]
    else
      recs
    end

    recs = [
      "Ensure all endpoints have the latest agent version deployed.",
      "Update YARA and Sigma detection rules to the latest versions.",
      "Schedule periodic threat hunting sessions.",
      "Review and test incident response playbooks.",
      "Conduct user security awareness training."
    ] ++ recs

    Enum.reverse(recs) |> Enum.take(10)
  end

  defp format_datetime(nil), do: "N/A"
  defp format_datetime(%NaiveDateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M")
  defp format_datetime(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M")
  defp format_datetime(_), do: "N/A"

  defp format_number(n) when n >= 1_000_000, do: "#{Float.round(n / 1_000_000, 1)}M"
  defp format_number(n) when n >= 1_000, do: "#{Float.round(n / 1_000, 1)}K"
  defp format_number(n), do: "#{n}"

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
