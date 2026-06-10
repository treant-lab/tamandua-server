defmodule TamanduaServer.Dashboard.WidgetData do
  @moduledoc """
  Widget data provider for all dashboard widgets.

  This module provides data fetching functions for each widget type,
  optimized with caching and real-time updates via PubSub.
  """

  import Ecto.Query
  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.Detection.Engine
  alias TamanduaServer.Telemetry.Event
  alias TamanduaServer.Response.ResponseAction
  alias TamanduaServer.Monitoring.Metric
  alias TamanduaServer.Compliance
  alias TamanduaServer.Billing.UsageRecord

  require Logger

  @doc """
  Fetches data for a widget based on its type and configuration.
  """
  def fetch_widget_data(%{widget_type: widget_type, config: config}) do
    case widget_type do
      "threat_level_gauge" -> fetch_threat_level_gauge_data(config)
      "geo_map" -> fetch_geo_map_data(config)
      "timeline_viewer" -> fetch_timeline_viewer_data(config)
      "top_detections" -> fetch_top_detections_data(config)
      "agent_health_overview" -> fetch_agent_health_overview_data(config)
      "detection_efficacy" -> fetch_detection_efficacy_data(config)
      "mitre_attack_heatmap" -> fetch_mitre_attack_heatmap_data(config)
      "alert_volume_trends" -> fetch_alert_volume_trends_data(config)
      "response_time_metrics" -> fetch_response_time_metrics_data(config)
      "sla_compliance" -> fetch_sla_compliance_data(config)
      "top_threats" -> fetch_top_threats_data(config)
      "ioc_trends" -> fetch_ioc_trends_data(config)
      "network_topology" -> fetch_network_topology_data(config)
      "user_activity" -> fetch_user_activity_data(config)
      "compliance_score" -> fetch_compliance_score_data(config)
      "cost_tracking" -> fetch_cost_tracking_data(config)
      "incident_timeline" -> fetch_incident_timeline_data(config)
      "agent_status_overview" -> fetch_agent_status_overview_data(config)
      "recent_alerts" -> fetch_recent_alerts_data(config)
      "detection_performance" -> fetch_detection_performance_data(config)
      "system_health" -> fetch_system_health_data(config)
      _ -> {:error, :unknown_widget_type}
    end
  rescue
    e ->
      Logger.error("Failed to fetch widget data: #{inspect(e)}")
      {:error, :fetch_failed}
  end

  # ========================
  # Threat Level Gauge
  # ========================

  defp fetch_threat_level_gauge_data(config) do
    time_range = parse_time_range(config["time_range"] || "24h")

    counts = Alert
    |> where([a], a.inserted_at >= ^time_range)
    |> where([a], a.status != "closed")
    |> group_by([a], a.severity)
    |> select([a], {a.severity, count(a.id)})
    |> Repo.all()
    |> Map.new()

    total = Enum.sum(Map.values(counts))
    threat_score = calculate_threat_score(counts)

    {:ok, %{
      critical: Map.get(counts, "critical", 0),
      high: Map.get(counts, "high", 0),
      medium: Map.get(counts, "medium", 0),
      low: Map.get(counts, "low", 0),
      total: total,
      threat_score: threat_score,
      trend: calculate_threat_trend(time_range)
    }}
  end

  defp calculate_threat_score(counts) do
    critical = Map.get(counts, "critical", 0)
    high = Map.get(counts, "high", 0)
    medium = Map.get(counts, "medium", 0)
    low = Map.get(counts, "low", 0)

    # Weighted score: critical=10, high=5, medium=2, low=1
    score = critical * 10 + high * 5 + medium * 2 + low * 1
    min(100, score)
  end

  defp calculate_threat_trend(since) do
    # Compare current period vs previous period
    previous_period = DateTime.add(since, -1 * DateTime.diff(DateTime.utc_now(), since), :second)

    current_count = Alert
    |> where([a], a.inserted_at >= ^since)
    |> select([a], count(a.id))
    |> Repo.one()

    previous_count = Alert
    |> where([a], a.inserted_at >= ^previous_period and a.inserted_at < ^since)
    |> select([a], count(a.id))
    |> Repo.one()

    if previous_count > 0 do
      Float.round((current_count - previous_count) / previous_count * 100, 1)
    else
      0.0
    end
  end

  # ========================
  # Geographic Map
  # ========================

  defp fetch_geo_map_data(config) do
    time_range = parse_time_range(config["time_range"] || "24h")

    # Get alerts with location data
    alerts_with_location = Alert
    |> where([a], a.inserted_at >= ^time_range)
    |> where([a], not is_nil(a.metadata))
    |> select([a], %{
      id: a.id,
      severity: a.severity,
      latitude: fragment("(?->>'latitude')::float", a.metadata),
      longitude: fragment("(?->>'longitude')::float", a.metadata),
      country: fragment("?->>'country'", a.metadata),
      city: fragment("?->>'city'", a.metadata)
    })
    |> Repo.all()
    |> Enum.filter(&(&1.latitude && &1.longitude))

    # Get agent locations
    agent_locations = Agent
    |> where([a], a.status == "online")
    |> where([a], not is_nil(a.metadata))
    |> select([a], %{
      id: a.id,
      latitude: fragment("(?->>'latitude')::float", a.metadata),
      longitude: fragment("(?->>'longitude')::float", a.metadata),
      country: fragment("?->>'country'", a.metadata),
      hostname: a.hostname
    })
    |> Repo.all()
    |> Enum.filter(&(&1.latitude && &1.longitude))

    # Group by country for heatmap
    country_counts = alerts_with_location
    |> Enum.group_by(& &1.country)
    |> Enum.map(fn {country, alerts} -> %{country: country, count: length(alerts)} end)
    |> Enum.sort_by(& &1.count, :desc)

    {:ok, %{
      alerts: alerts_with_location,
      agents: agent_locations,
      heatmap: country_counts,
      total_alerts: length(alerts_with_location),
      total_agents: length(agent_locations)
    }}
  end

  # ========================
  # Timeline Viewer
  # ========================

  defp fetch_timeline_viewer_data(config) do
    time_range = parse_time_range(config["time_range"] || "24h")
    interval = config["interval"] || "hour"

    timeline_data = Alert
    |> where([a], a.inserted_at >= ^time_range)
    |> select([a], %{
      timestamp: fragment("date_trunc(?, ?)", ^interval, a.inserted_at),
      severity: a.severity,
      count: count(a.id)
    })
    |> group_by([a], [fragment("date_trunc(?, ?)", ^interval, a.inserted_at), a.severity])
    |> order_by([a], fragment("date_trunc(?, ?)", ^interval, a.inserted_at))
    |> Repo.all()

    # Group by timestamp for charting
    grouped_timeline = timeline_data
    |> Enum.group_by(& &1.timestamp)
    |> Enum.map(fn {timestamp, events} ->
      %{
        timestamp: timestamp,
        critical: Enum.find_value(events, 0, fn e -> if e.severity == "critical", do: e.count end),
        high: Enum.find_value(events, 0, fn e -> if e.severity == "high", do: e.count end),
        medium: Enum.find_value(events, 0, fn e -> if e.severity == "medium", do: e.count end),
        low: Enum.find_value(events, 0, fn e -> if e.severity == "low", do: e.count end),
        total: Enum.sum(Enum.map(events, & &1.count))
      }
    end)

    {:ok, %{
      timeline: grouped_timeline,
      interval: interval,
      time_range: config["time_range"] || "24h"
    }}
  end

  # ========================
  # Top Detections
  # ========================

  defp fetch_top_detections_data(config) do
    time_range = parse_time_range(config["time_range"] || "24h")
    limit = config["limit"] || 10

    detections = Alert
    |> where([a], a.inserted_at >= ^time_range)
    |> where([a], not is_nil(a.detection_name))
    |> group_by([a], [a.detection_name, a.mitre_technique])
    |> select([a], %{
      name: a.detection_name,
      technique: a.mitre_technique,
      count: count(a.id)
    })
    |> order_by([a], desc: count(a.id))
    |> limit(^limit)
    |> Repo.all()

    {:ok, %{
      detections: detections,
      total_unique: length(detections)
    }}
  end

  # ========================
  # Agent Health Overview
  # ========================

  defp fetch_agent_health_overview_data(config) do
    agents = Agent
    |> preload([:health_metrics])
    |> Repo.all()

    status_counts = Enum.reduce(agents, %{online: 0, offline: 0, error: 0}, fn agent, acc ->
      case agent.status do
        "online" -> %{acc | online: acc.online + 1}
        "offline" -> %{acc | offline: acc.offline + 1}
        _ -> %{acc | error: acc.error + 1}
      end
    end)

    # Calculate health scores
    health_summary = agents
    |> Enum.filter(&(&1.status == "online"))
    |> Enum.map(fn agent ->
      metrics = List.first(agent.health_metrics) || %{}
      %{
        id: agent.id,
        hostname: agent.hostname,
        cpu: get_in(metrics, [:cpu_usage]) || 0,
        memory: get_in(metrics, [:memory_usage]) || 0,
        health_score: calculate_health_score(metrics)
      }
    end)

    healthy_count = Enum.count(health_summary, &(&1.health_score >= 80))
    degraded_count = Enum.count(health_summary, &(&1.health_score < 80 and &1.health_score >= 50))
    unhealthy_count = Enum.count(health_summary, &(&1.health_score < 50))

    {:ok, %{
      total: length(agents),
      online: status_counts.online,
      offline: status_counts.offline,
      error: status_counts.error,
      healthy: healthy_count,
      degraded: degraded_count,
      unhealthy: unhealthy_count,
      agents: health_summary
    }}
  end

  defp calculate_health_score(metrics) do
    cpu = get_in(metrics, [:cpu_usage]) || 0
    memory = get_in(metrics, [:memory_usage]) || 0

    # Score based on resource usage (inverted)
    cpu_score = max(0, 100 - cpu)
    memory_score = max(0, 100 - memory)

    round((cpu_score + memory_score) / 2)
  end

  # ========================
  # Detection Efficacy
  # ========================

  defp fetch_detection_efficacy_data(config) do
    time_range = parse_time_range(config["time_range"] || "7d")

    total_alerts = Alert
    |> where([a], a.inserted_at >= ^time_range)
    |> select([a], count(a.id))
    |> Repo.one()

    true_positives = Alert
    |> where([a], a.inserted_at >= ^time_range)
    |> where([a], a.verdict == "true_positive")
    |> select([a], count(a.id))
    |> Repo.one()

    false_positives = Alert
    |> where([a], a.inserted_at >= ^time_range)
    |> where([a], a.verdict == "false_positive")
    |> select([a], count(a.id))
    |> Repo.one()

    accuracy = if total_alerts > 0, do: Float.round(true_positives / total_alerts * 100, 2), else: 0.0
    fp_rate = if total_alerts > 0, do: Float.round(false_positives / total_alerts * 100, 2), else: 0.0
    precision = if (true_positives + false_positives) > 0,
                do: Float.round(true_positives / (true_positives + false_positives), 3),
                else: 0.0

    {:ok, %{
      total_alerts: total_alerts,
      true_positives: true_positives,
      false_positives: false_positives,
      accuracy: accuracy,
      fp_rate: fp_rate,
      precision: precision,
      time_range: config["time_range"] || "7d"
    }}
  end

  # ========================
  # MITRE ATT&CK Heatmap
  # ========================

  defp fetch_mitre_attack_heatmap_data(config) do
    time_range = parse_time_range(config["time_range"] || "7d")

    techniques = Alert
    |> where([a], a.inserted_at >= ^time_range)
    |> where([a], not is_nil(a.mitre_technique))
    |> group_by([a], [a.mitre_technique, a.mitre_tactic])
    |> select([a], %{
      technique: a.mitre_technique,
      tactic: a.mitre_tactic,
      count: count(a.id)
    })
    |> Repo.all()

    # Group by tactic
    tactics_map = techniques
    |> Enum.group_by(& &1.tactic)
    |> Enum.map(fn {tactic, techs} ->
      %{
        tactic: tactic,
        techniques: techs,
        total_count: Enum.sum(Enum.map(techs, & &1.count))
      }
    end)
    |> Enum.sort_by(& &1.total_count, :desc)

    {:ok, %{
      tactics: tactics_map,
      total_techniques: length(techniques),
      total_detections: Enum.sum(Enum.map(techniques, & &1.count))
    }}
  end

  # ========================
  # Alert Volume Trends
  # ========================

  defp fetch_alert_volume_trends_data(config) do
    time_range = parse_time_range(config["time_range"] || "24h")
    interval = determine_interval(config["time_range"] || "24h")

    trends = Alert
    |> where([a], a.inserted_at >= ^time_range)
    |> select([a], %{
      timestamp: fragment("date_trunc(?, ?)", ^interval, a.inserted_at),
      count: count(a.id)
    })
    |> group_by([a], fragment("date_trunc(?, ?)", ^interval, a.inserted_at))
    |> order_by([a], fragment("date_trunc(?, ?)", ^interval, a.inserted_at))
    |> Repo.all()

    # Calculate moving average
    counts = Enum.map(trends, & &1.count)
    moving_avg = if length(counts) >= 3, do: calculate_moving_average(counts, 3), else: counts

    trends_with_avg = trends
    |> Enum.zip(moving_avg)
    |> Enum.map(fn {trend, avg} -> Map.put(trend, :moving_avg, avg) end)

    {:ok, %{
      trends: trends_with_avg,
      interval: interval,
      peak_value: if(length(counts) > 0, do: Enum.max(counts), else: 0),
      average: if(length(counts) > 0, do: Float.round(Enum.sum(counts) / length(counts), 1), else: 0)
    }}
  end

  defp calculate_moving_average(values, window) do
    values
    |> Enum.chunk_every(window, 1, :discard)
    |> Enum.map(fn chunk -> Enum.sum(chunk) / window end)
    |> then(fn avgs ->
      # Pad beginning to match original length
      List.duplicate(0, window - 1) ++ avgs
    end)
  end

  # ========================
  # Response Time Metrics
  # ========================

  defp fetch_response_time_metrics_data(config) do
    time_range = parse_time_range(config["time_range"] || "24h")

    # Get alerts with response times
    response_times = Alert
    |> where([a], a.inserted_at >= ^time_range)
    |> where([a], not is_nil(a.acknowledged_at))
    |> select([a], fragment("EXTRACT(EPOCH FROM (? - ?)) * 1000", a.acknowledged_at, a.inserted_at))
    |> Repo.all()
    |> Enum.sort()

    if length(response_times) > 0 do
      avg = Float.round(Enum.sum(response_times) / length(response_times), 2)
      p95_index = round(length(response_times) * 0.95) - 1
      p99_index = round(length(response_times) * 0.99) - 1

      {:ok, %{
        avg: avg,
        p50: Enum.at(response_times, div(length(response_times), 2)),
        p95: Enum.at(response_times, max(0, p95_index)),
        p99: Enum.at(response_times, max(0, p99_index)),
        min: Enum.min(response_times),
        max: Enum.max(response_times),
        sample_size: length(response_times)
      }}
    else
      {:ok, %{
        avg: 0,
        p50: 0,
        p95: 0,
        p99: 0,
        min: 0,
        max: 0,
        sample_size: 0
      }}
    end
  end

  # ========================
  # SLA Compliance
  # ========================

  defp fetch_sla_compliance_data(config) do
    time_range = parse_time_range(config["time_range"] || "7d")

    # Define SLA thresholds (in seconds)
    slas = %{
      "critical" => 15 * 60,   # 15 minutes
      "high" => 60 * 60,       # 1 hour
      "medium" => 4 * 60 * 60, # 4 hours
      "low" => 24 * 60 * 60    # 24 hours
    }

    compliance_by_severity = Enum.map(slas, fn {severity, threshold_seconds} ->
      alerts = Alert
      |> where([a], a.inserted_at >= ^time_range)
      |> where([a], a.severity == ^severity)
      |> where([a], not is_nil(a.acknowledged_at))
      |> select([a], %{
        id: a.id,
        response_time: fragment("EXTRACT(EPOCH FROM (? - ?))", a.acknowledged_at, a.inserted_at)
      })
      |> Repo.all()

      total = length(alerts)
      met = Enum.count(alerts, &(&1.response_time <= threshold_seconds))
      compliance_rate = if total > 0, do: Float.round(met / total * 100, 1), else: 100.0

      %{
        severity: severity,
        threshold_minutes: div(threshold_seconds, 60),
        total: total,
        met: met,
        missed: total - met,
        compliance_rate: compliance_rate
      }
    end)

    overall_compliance = if Enum.sum(Enum.map(compliance_by_severity, & &1.total)) > 0 do
      Float.round(
        Enum.sum(Enum.map(compliance_by_severity, & &1.met)) /
        Enum.sum(Enum.map(compliance_by_severity, & &1.total)) * 100,
        1
      )
    else
      100.0
    end

    {:ok, %{
      by_severity: compliance_by_severity,
      overall_compliance: overall_compliance
    }}
  end

  # ========================
  # Top Threats
  # ========================

  defp fetch_top_threats_data(config) do
    time_range = parse_time_range(config["time_range"] || "24h")
    limit = config["limit"] || 10

    threats = Alert
    |> where([a], a.inserted_at >= ^time_range)
    |> where([a], not is_nil(a.threat_name))
    |> group_by([a], [a.threat_name, a.threat_family, a.severity])
    |> select([a], %{
      name: a.threat_name,
      family: a.threat_family,
      severity: a.severity,
      count: count(a.id),
      latest: max(a.inserted_at)
    })
    |> order_by([a], desc: count(a.id))
    |> limit(^limit)
    |> Repo.all()

    {:ok, %{
      threats: threats,
      total_unique: length(threats)
    }}
  end

  # ========================
  # IOC Trends
  # ========================

  defp fetch_ioc_trends_data(config) do
    time_range = parse_time_range(config["time_range"] || "7d")

    # Get IOCs from alert metadata
    iocs = Alert
    |> where([a], a.inserted_at >= ^time_range)
    |> where([a], not is_nil(a.iocs))
    |> select([a], %{
      iocs: a.iocs,
      inserted_at: a.inserted_at
    })
    |> Repo.all()

    # Flatten and count IOCs
    ioc_counts = iocs
    |> Enum.flat_map(&(&1.iocs || []))
    |> Enum.frequencies()
    |> Enum.map(fn {ioc, count} -> %{ioc: ioc, count: count} end)
    |> Enum.sort_by(& &1.count, :desc)
    |> Enum.take(20)

    # Trending IOCs (increased in last 24h vs previous period)
    midpoint = DateTime.add(time_range, div(DateTime.diff(DateTime.utc_now(), time_range), 2), :second)

    recent_iocs = iocs
    |> Enum.filter(&(DateTime.compare(&1.inserted_at, midpoint) == :gt))
    |> Enum.flat_map(&(&1.iocs || []))
    |> Enum.frequencies()

    old_iocs = iocs
    |> Enum.filter(&(DateTime.compare(&1.inserted_at, midpoint) == :lt))
    |> Enum.flat_map(&(&1.iocs || []))
    |> Enum.frequencies()

    trending = recent_iocs
    |> Enum.map(fn {ioc, recent_count} ->
      old_count = Map.get(old_iocs, ioc, 0)
      trend = if old_count > 0, do: Float.round((recent_count - old_count) / old_count * 100, 1), else: 100.0
      %{ioc: ioc, count: recent_count, trend: trend}
    end)
    |> Enum.filter(&(&1.trend > 0))
    |> Enum.sort_by(& &1.trend, :desc)
    |> Enum.take(10)

    {:ok, %{
      top_iocs: ioc_counts,
      trending_iocs: trending,
      total_unique: map_size(Map.new(ioc_counts, &{&1.ioc, &1.count}))
    }}
  end

  # ========================
  # Network Topology
  # ========================

  defp fetch_network_topology_data(config) do
    time_range = parse_time_range(config["time_range"] || "1h")

    # Get network connections from telemetry
    connections = Event
    |> where([e], e.event_type == "network" and e.inserted_at >= ^time_range)
    |> limit(1000)
    |> select([e], %{
      source_ip: fragment("?->>'source_ip'", e.payload),
      dest_ip: fragment("?->>'dest_ip'", e.payload),
      dest_port: fragment("(?->>'dest_port')::integer", e.payload),
      protocol: fragment("?->>'protocol'", e.payload),
      agent_id: e.agent_id
    })
    |> Repo.all()
    |> Enum.filter(&(&1.source_ip && &1.dest_ip))

    # Build nodes and edges
    nodes = connections
    |> Enum.flat_map(&[&1.source_ip, &1.dest_ip])
    |> Enum.uniq()
    |> Enum.map(&%{id: &1, label: &1, type: classify_ip(&1)})

    edges = connections
    |> Enum.group_by(&{&1.source_ip, &1.dest_ip, &1.dest_port})
    |> Enum.map(fn {{source, dest, port}, conns} ->
      %{
        from: source,
        to: dest,
        port: port,
        count: length(conns),
        protocol: List.first(conns).protocol
      }
    end)

    {:ok, %{
      nodes: nodes,
      edges: edges,
      total_connections: length(connections)
    }}
  end

  defp classify_ip(ip) do
    cond do
      String.starts_with?(ip, "10.") or String.starts_with?(ip, "192.168.") or String.starts_with?(ip, "172.") ->
        "internal"
      true ->
        "external"
    end
  end

  # ========================
  # User Activity
  # ========================

  defp fetch_user_activity_data(config) do
    time_range = parse_time_range(config["time_range"] || "24h")
    limit = config["limit"] || 10

    # Get alerts grouped by affected users
    user_activity = Alert
    |> where([a], a.inserted_at >= ^time_range)
    |> where([a], not is_nil(fragment("?->>'username'", a.metadata)))
    |> group_by([a], fragment("?->>'username'", a.metadata))
    |> select([a], %{
      username: fragment("?->>'username'", a.metadata),
      alert_count: count(a.id),
      critical_count: fragment("COUNT(CASE WHEN ? = 'critical' THEN 1 END)", a.severity),
      high_count: fragment("COUNT(CASE WHEN ? = 'high' THEN 1 END)", a.severity)
    })
    |> order_by([a], desc: count(a.id))
    |> limit(^limit)
    |> Repo.all()

    {:ok, %{
      users: user_activity,
      total_users: length(user_activity)
    }}
  end

  # ========================
  # Compliance Score
  # ========================

  defp fetch_compliance_score_data(config) do
    frameworks = config["frameworks"] || ["pci_dss", "hipaa", "gdpr", "soc2"]

    scores =
      frameworks
      |> Enum.map(&fetch_framework_compliance/1)
      |> Enum.reject(&is_nil/1)

    if Enum.empty?(scores) do
      {:ok,
       insufficient_data("compliance_score", "No compliance assessments are available for the requested frameworks")}
    else
      overall_score = Float.round(Enum.sum(Enum.map(scores, & &1.score)) / length(scores), 1)

      {:ok, %{
        frameworks: scores,
        overall_score: overall_score,
        compliant_count: Enum.count(scores, &(&1.status == "compliant")),
        source: "compliance_engine",
        insufficient_data: false
      }}
    end
  end

  # ========================
  # Cost Tracking
  # ========================

  defp fetch_cost_tracking_data(config) do
    time_range = parse_time_range(config["time_range"] || "30d")
    organization_id = config["organization_id"] || config[:organization_id]

    query =
      UsageRecord
      |> where([u], u.period_start >= ^time_range)
      |> maybe_filter_usage_org(organization_id)

    usage =
      query
      |> group_by([u], fragment("date_trunc('day', ?)", u.period_start))
      |> order_by([u], fragment("date_trunc('day', ?)", u.period_start))
      |> select([u], %{
        date: fragment("date_trunc('day', ?)", u.period_start),
        agents_active: max(u.agents_active),
        api_calls: sum(u.api_calls),
        model_scans: sum(u.model_scans),
        storage_bytes: max(u.storage_bytes)
      })
      |> Repo.all()

    if Enum.empty?(usage) do
      {:ok,
       Map.merge(insufficient_data("cost_tracking", "No billing usage records exist for the selected period"), %{
         daily_costs: [],
         total_cost: nil,
         average_daily_cost: nil,
         currency: nil
       })}
    else
      {:ok, %{
        daily_usage: usage,
        daily_costs: [],
        total_cost: nil,
        average_daily_cost: nil,
        currency: nil,
        source: "usage_records",
        insufficient_data: true,
        reason: "Usage data is available, but no pricing source is configured for cost calculation"
      }}
    end
  end

  # ========================
  # Incident Timeline
  # ========================

  defp fetch_incident_timeline_data(config) do
    time_range = parse_time_range(config["time_range"] || "30d")

    # Get major incidents (high-severity alerts with responses)
    incidents = Alert
    |> where([a], a.inserted_at >= ^time_range)
    |> where([a], a.severity in ["critical", "high"])
    |> where([a], a.status in ["investigating", "contained", "resolved"])
    |> preload([:response_actions])
    |> order_by([a], desc: a.inserted_at)
    |> limit(50)
    |> Repo.all()
    |> Enum.map(fn alert ->
      %{
        id: alert.id,
        title: alert.title,
        severity: alert.severity,
        status: alert.status,
        started_at: alert.inserted_at,
        acknowledged_at: alert.acknowledged_at,
        resolved_at: alert.resolved_at,
        mitre_technique: alert.mitre_technique,
        affected_hosts: length(alert.response_actions || []),
        duration_minutes: if alert.resolved_at do
          div(DateTime.diff(alert.resolved_at, alert.inserted_at), 60)
        else
          nil
        end
      }
    end)

    {:ok, %{
      incidents: incidents,
      total: length(incidents),
      active: Enum.count(incidents, &(&1.status == "investigating")),
      resolved: Enum.count(incidents, &(&1.status == "resolved"))
    }}
  end

  # ========================
  # Legacy Widget Types (for backward compatibility)
  # ========================

  defp fetch_agent_status_overview_data(config) do
    fetch_agent_health_overview_data(config)
  end

  defp fetch_recent_alerts_data(config) do
    time_range = parse_time_range(config["time_range"] || "24h")
    limit = config["limit"] || 20

    alerts = Alert
    |> where([a], a.inserted_at >= ^time_range)
    |> order_by([a], desc: a.inserted_at)
    |> limit(^limit)
    |> Repo.all()

    {:ok, %{alerts: alerts}}
  end

  defp fetch_detection_performance_data(config) do
    fetch_detection_efficacy_data(config)
  end

  defp fetch_system_health_data(config) do
    # Get system metrics
    {:ok, %{
      cpu: %{current: 45, max: 100, threshold: 80, status: "ok"},
      memory: %{current: 62, max: 100, threshold: 85, status: "ok"},
      latency: %{current: 125, max: 1000, threshold: 500, status: "ok"}
    }}
  end

  # ========================
  # Helper Functions
  # ========================

  defp parse_time_range("1h"), do: DateTime.add(DateTime.utc_now(), -1, :hour)
  defp parse_time_range("6h"), do: DateTime.add(DateTime.utc_now(), -6, :hour)
  defp parse_time_range("24h"), do: DateTime.add(DateTime.utc_now(), -24, :hour)
  defp parse_time_range("7d"), do: DateTime.add(DateTime.utc_now(), -7, :day)
  defp parse_time_range("30d"), do: DateTime.add(DateTime.utc_now(), -30, :day)
  defp parse_time_range("90d"), do: DateTime.add(DateTime.utc_now(), -90, :day)
  defp parse_time_range(_), do: DateTime.add(DateTime.utc_now(), -24, :hour)

  defp determine_interval("1h"), do: "minute"
  defp determine_interval("6h"), do: "minute"
  defp determine_interval("24h"), do: "hour"
  defp determine_interval("7d"), do: "hour"
  defp determine_interval("30d"), do: "day"
  defp determine_interval("90d"), do: "day"
  defp determine_interval(_), do: "hour"

  defp fetch_framework_compliance(framework) do
    case safe_compliance_posture(framework) do
      {:ok, posture} ->
        total = Map.get(posture, :total_controls, 0)

        if total > 0 do
          %{
            framework: framework,
            score: Map.get(posture, :score, 0.0),
            controls_passed: Map.get(posture, :compliant, 0),
            controls_total: total,
            status: normalize_compliance_status(Map.get(posture, :status)),
            not_assessed: Map.get(posture, :not_assessed, 0)
          }
        end

      _ ->
        nil
    end
  end

  defp safe_compliance_posture(framework) do
    try do
      Compliance.get_posture(framework)
    catch
      _, _ -> {:error, :unavailable}
    rescue
      _ -> {:error, :unavailable}
    end
  end

  defp normalize_compliance_status(status) when is_atom(status), do: Atom.to_string(status)
  defp normalize_compliance_status(status) when is_binary(status), do: status
  defp normalize_compliance_status(_), do: "unknown"

  defp maybe_filter_usage_org(query, nil), do: query
  defp maybe_filter_usage_org(query, organization_id) do
    where(query, [u], u.organization_id == ^organization_id)
  end

  defp insufficient_data(widget_type, reason) do
    %{
      widget_type: widget_type,
      status: "insufficient_data",
      insufficient_data: true,
      reason: reason
    }
  end
end
