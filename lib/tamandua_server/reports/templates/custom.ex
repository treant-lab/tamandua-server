defmodule TamanduaServer.Reports.Templates.Custom do
  @moduledoc """
  Custom Report Template for user-defined reports.

  Allows users to create reports by selecting sections from available
  data sources and configuring their layout. Supports dynamic section
  types including:

  - Executive Summary
  - Alert Statistics
  - Threat Overview
  - Agent Health
  - Detection Coverage
  - Compliance Status
  - Network Activity
  - User Activity
  - Custom Tables
  """

  @behaviour TamanduaServer.Reports.Templates.TemplateBehaviour

  alias TamanduaServer.{Agents, Alerts, Compliance, Detection}
  alias TamanduaServer.Detection.{IOCs, Timeline}

  @impl true
  def name, do: "Custom Report"

  @impl true
  def description do
    "Build a custom report by selecting from available data sections. " <>
    "Configure the layout and content to match your specific reporting needs."
  end

  @impl true
  def category, do: "custom"

  @impl true
  def sections do
    [
      "Executive Summary",
      "Alert Statistics",
      "Threat Overview",
      "Agent Health",
      "Detection Coverage",
      "Compliance Status",
      "Network Activity",
      "User Activity",
      "Timeline",
      "Custom Content"
    ]
  end

  @impl true
  def parameters do
    [
      %{
        name: "name",
        type: "string",
        required: true,
        description: "Report name"
      },
      %{
        name: "description",
        type: "string",
        required: false,
        description: "Report description"
      },
      %{
        name: "sections",
        type: "array",
        required: true,
        description: "Array of section configurations to include"
      },
      %{
        name: "branding",
        type: "object",
        required: false,
        description: "Custom branding options (logo_url, company_name, colors)"
      }
    ]
  end

  @impl true
  def supported_formats, do: [:pdf, :html, :csv, :json]

  @impl true
  def generate(date_from, date_to, params) do
    report_name = Map.get(params, "name", "Custom Report")
    description = Map.get(params, "description", "")
    section_configs = Map.get(params, "sections", [])

    # Build sections based on configuration
    sections = build_sections(section_configs, date_from, date_to, params)

    # Add description as first section if provided
    sections = if description != "" do
      [
        %{
          "title" => "Report Overview",
          "type" => "summary",
          "content" => description
        }
        | sections
      ]
    else
      sections
    end

    %{
      "title" => report_name,
      "sections" => sections
    }
  end

  # ============================================================================
  # Section Builders
  # ============================================================================

  defp build_sections(configs, date_from, date_to, params) do
    configs
    |> Enum.filter(& &1["enabled"] != false)
    |> Enum.map(fn config ->
      build_section(config, date_from, date_to, params)
    end)
    |> Enum.reject(&is_nil/1)
  end

  defp build_section(%{"type" => "executive_summary"} = config, date_from, date_to, _params) do
    title = Map.get(config, "title", "Executive Summary")

    # Gather metrics
    metrics = get_security_metrics()

    content = """
    Security overview for #{date_from} to #{date_to}. \
    The organization has #{metrics.total_agents} monitored endpoints with #{metrics.online_agents} currently online. \
    During this period, #{metrics.total_alerts} alerts were generated, including #{metrics.critical_alerts} critical severity. \
    Detection coverage includes #{metrics.sigma_rules} Sigma rules and #{metrics.yara_rules} YARA rules.
    """

    %{
      "title" => title,
      "type" => "summary",
      "content" => content
    }
  end

  defp build_section(%{"type" => "alert_stats"} = config, _date_from, _date_to, _params) do
    title = Map.get(config, "title", "Alert Statistics")

    stats = [
      %{"label" => "Total Alerts", "value" => safe_call(fn -> Alerts.count_open() end, 0)},
      %{"label" => "Critical", "value" => safe_call(fn -> Alerts.count_by_severity(:critical) end, 0)},
      %{"label" => "High", "value" => safe_call(fn -> Alerts.count_by_severity(:high) end, 0)},
      %{"label" => "Medium", "value" => safe_call(fn -> Alerts.count_by_severity(:medium) end, 0)},
      %{"label" => "Low", "value" => safe_call(fn -> Alerts.count_by_severity(:low) end, 0)},
      %{"label" => "Resolved", "value" => safe_call(fn -> Alerts.count_by_status("resolved") end, 0)}
    ]

    %{
      "title" => title,
      "type" => "stats",
      "content" => stats
    }
  end

  defp build_section(%{"type" => "threat_overview"} = config, _date_from, _date_to, _params) do
    title = Map.get(config, "title", "Threat Overview")

    # Get top threats
    threats = safe_call(fn ->
      Alerts.list_alerts(limit: 10, status: "open")
    end, [])

    rows = threats
    |> Enum.map(fn alert ->
      [
        alert.title || "Unknown",
        to_string(alert.severity),
        alert.mitre_tactic || "N/A",
        alert.status || "open"
      ]
    end)

    %{
      "title" => title,
      "type" => "table",
      "content" => %{
        "headers" => ["Threat", "Severity", "MITRE Tactic", "Status"],
        "rows" => if(length(rows) > 0, do: rows, else: [["No active threats", "", "", ""]])
      }
    }
  end

  defp build_section(%{"type" => "agent_health"} = config, _date_from, _date_to, _params) do
    title = Map.get(config, "title", "Agent Health")

    metrics = get_security_metrics()
    coverage = if metrics.total_agents > 0 do
      Float.round(metrics.online_agents / metrics.total_agents * 100, 1)
    else
      0.0
    end

    stats = [
      %{"label" => "Total Agents", "value" => metrics.total_agents},
      %{"label" => "Online", "value" => metrics.online_agents},
      %{"label" => "Offline", "value" => metrics.total_agents - metrics.online_agents},
      %{"label" => "Coverage", "value" => "#{coverage}%"}
    ]

    %{
      "title" => title,
      "type" => "stats",
      "content" => stats
    }
  end

  defp build_section(%{"type" => "detection_coverage"} = config, _date_from, _date_to, _params) do
    title = Map.get(config, "title", "Detection Coverage")

    metrics = get_security_metrics()

    %{
      "title" => title,
      "type" => "chart",
      "content" => %{
        "chart_type" => "bar",
        "labels" => ["Sigma Rules", "YARA Rules", "IOCs"],
        "data" => [metrics.sigma_rules, metrics.yara_rules, metrics.total_iocs],
        "title" => "Detection Rules by Type"
      }
    }
  end

  defp build_section(%{"type" => "compliance_status"} = config, _date_from, _date_to, _params) do
    title = Map.get(config, "title", "Compliance Status")

    rows =
      case safe_call(fn -> Compliance.get_overall_posture() end, nil) do
        %{frameworks: frameworks} when is_map(frameworks) ->
          frameworks
          |> Enum.map(fn {framework, posture} ->
            [
              to_string(framework),
              "#{Map.get(posture, :score, 0)}%",
              posture |> Map.get(:status, :unknown) |> to_string(),
              compliance_notes(posture)
            ]
          end)

        _ ->
          unavailable_rows("Compliance engine unavailable or not assessed")
      end

    %{
      "title" => title,
      "type" => "table",
      "content" => %{
        "headers" => ["Framework", "Score", "Status", "Notes"],
        "rows" => rows
      }
    }
  end

  defp build_section(%{"type" => "network_activity"} = config, date_from, date_to, _params) do
    title = Map.get(config, "title", "Network Activity")

    events = safe_call(fn -> Timeline.get_events(from: date_from, to: date_to, limit: 1000) end, [])

    network_events =
      Enum.filter(events, fn event ->
        event_type = to_string(event.event_type || "")
        String.contains?(event_type, "network") or event_type in ["dns_query", "dns"]
      end)

    stats =
      if Enum.empty?(network_events) do
        [
          %{"label" => "Status", "value" => "unavailable"},
          %{"label" => "Reason", "value" => "No network telemetry source returned data for the selected period"}
        ]
      else
        [
          %{"label" => "Network Events", "value" => length(network_events)},
          %{"label" => "DNS Events", "value" => Enum.count(network_events, &(to_string(&1.event_type || "") in ["dns_query", "dns"]))},
          %{"label" => "Source", "value" => "timeline_events"}
        ]
      end

    %{
      "title" => title,
      "type" => "stats",
      "content" => stats
    }
  end

  defp build_section(%{"type" => "user_activity"} = config, _date_from, _date_to, _params) do
    title = Map.get(config, "title", "User Activity")

    activities =
      Alerts.list_alerts(limit: 50)
      |> normalize_alert_list()
      |> Enum.map(fn alert ->
        metadata = alert_context(alert)

        [
          Map.get(metadata, "username") || Map.get(metadata, :username) || "unknown",
          alert.title || "Alert activity",
          Map.get(metadata, "source_ip") || Map.get(metadata, :source_ip) || "",
          format_datetime(alert.inserted_at)
        ]
      end)
      |> Enum.reject(fn [user | _] -> user == "unknown" end)

    %{
      "title" => title,
      "type" => "table",
      "content" => %{
        "headers" => ["User", "Action", "Source IP", "Time"],
        "rows" => if(length(activities) > 0, do: activities, else: unavailable_rows("No real user activity source returned data"))
      }
    }
  end

  defp build_section(%{"type" => "timeline"} = config, date_from, date_to, _params) do
    title = Map.get(config, "title", "Event Timeline")

    events = safe_call(fn ->
      Timeline.get_events(from: date_from, to: date_to, limit: 20)
    end, [])

    rows = events
    |> Enum.map(fn event ->
      [
        format_datetime(event.timestamp),
        event.event_type || "Unknown",
        event.description || "",
        event.severity || "info"
      ]
    end)

    %{
      "title" => title,
      "type" => "table",
      "content" => %{
        "headers" => ["Time", "Event Type", "Description", "Severity"],
        "rows" => if(length(rows) > 0, do: rows, else: [["No events in selected period", "", "", ""]])
      }
    }
  end

  defp build_section(%{"type" => "recommendations"} = config, _date_from, _date_to, _params) do
    title = Map.get(config, "title", "Recommendations")

    recommendations = [
      "Review and resolve critical alerts within 24 hours.",
      "Ensure all endpoints have the latest agent version.",
      "Update detection rules to address emerging threats.",
      "Conduct regular security awareness training.",
      "Review and update incident response procedures."
    ]

    %{
      "title" => title,
      "type" => "list",
      "content" => recommendations
    }
  end

  defp build_section(%{"type" => "custom_table"} = config, _date_from, _date_to, _params) do
    title = Map.get(config, "title", "Custom Data")
    headers = Map.get(config, "headers", ["Column 1", "Column 2"])
    rows = Map.get(config, "rows", [])

    %{
      "title" => title,
      "type" => "table",
      "content" => %{
        "headers" => headers,
        "rows" => rows
      }
    }
  end

  defp build_section(%{"type" => "custom_text"} = config, _date_from, _date_to, _params) do
    title = Map.get(config, "title", "Notes")
    content = Map.get(config, "content", "")

    %{
      "title" => title,
      "type" => "summary",
      "content" => content
    }
  end

  defp build_section(%{"type" => "custom_list"} = config, _date_from, _date_to, _params) do
    title = Map.get(config, "title", "Items")
    items = Map.get(config, "items", [])

    %{
      "title" => title,
      "type" => "list",
      "content" => items
    }
  end

  # Unknown section type - skip
  defp build_section(_config, _date_from, _date_to, _params), do: nil

  # ============================================================================
  # Helper Functions
  # ============================================================================

  defp get_security_metrics do
    %{
      total_agents: safe_call(fn -> Agents.count_all() end, 0),
      online_agents: safe_call(fn -> Agents.count_online() end, 0),
      total_alerts: safe_call(fn -> Alerts.count_open() end, 0),
      critical_alerts: safe_call(fn -> Alerts.count_by_severity(:critical) end, 0),
      sigma_rules: safe_call(fn -> Detection.count_sigma_rules() end, 0),
      yara_rules: safe_call(fn -> Detection.count_yara_rules() end, 0),
      total_iocs: safe_call(fn -> IOCs.count(enabled: true) end, 0)
    }
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

  defp normalize_alert_list({:ok, alerts}) when is_list(alerts), do: alerts
  defp normalize_alert_list(alerts) when is_list(alerts), do: alerts
  defp normalize_alert_list(_), do: []

  defp alert_context(alert) do
    %{}
    |> Map.merge(Map.get(alert, :enrichment) || %{})
    |> Map.merge(Map.get(alert, :raw_event) || %{})
    |> Map.merge(Map.get(alert, :evidence) || %{})
    |> Map.merge(Map.get(alert, :detection_metadata) || %{})
  end

  defp compliance_notes(posture) do
    not_assessed = Map.get(posture, :not_assessed, 0)
    non_compliant = Map.get(posture, :non_compliant, 0)

    cond do
      not_assessed > 0 -> "#{not_assessed} controls not assessed"
      non_compliant > 0 -> "#{non_compliant} controls non-compliant"
      true -> "Assessed from compliance engine"
    end
  end

  defp unavailable_rows(reason), do: [["unavailable", reason, "", ""]]

  defp format_datetime(nil), do: "N/A"
  defp format_datetime(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M")
  defp format_datetime(%NaiveDateTime{} = ndt), do: NaiveDateTime.to_string(ndt)
  defp format_datetime(str) when is_binary(str), do: str
  defp format_datetime(_), do: "N/A"
end
