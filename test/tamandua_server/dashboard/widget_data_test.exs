defmodule TamanduaServer.Dashboard.WidgetDataTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Dashboard.WidgetData
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Agents.Agent

  describe "fetch_widget_data/1" do
    setup do
      # Create test agents
      {:ok, agent1} = create_agent(%{hostname: "test-agent-1", status: "online"})
      {:ok, agent2} = create_agent(%{hostname: "test-agent-2", status: "offline"})

      # Create test alerts
      {:ok, critical_alert} = create_alert(%{
        title: "Critical Threat",
        severity: "critical",
        detection_name: "Malware.Generic",
        mitre_technique: "T1059",
        mitre_tactic: "execution"
      })

      {:ok, high_alert} = create_alert(%{
        title: "High Threat",
        severity: "high",
        detection_name: "Suspicious Process",
        mitre_technique: "T1036",
        mitre_tactic: "defense_evasion"
      })

      %{
        agents: [agent1, agent2],
        alerts: [critical_alert, high_alert]
      }
    end

    test "fetches threat level gauge data", %{alerts: alerts} do
      widget = %{
        widget_type: "threat_level_gauge",
        config: %{"time_range" => "24h"}
      }

      assert {:ok, data} = WidgetData.fetch_widget_data(widget)
      assert data.critical >= 1
      assert data.high >= 1
      assert data.total >= 2
      assert data.threat_score > 0
      assert is_number(data.trend)
    end

    test "fetches geo map data" do
      widget = %{
        widget_type: "geo_map",
        config: %{"time_range" => "24h"}
      }

      assert {:ok, data} = WidgetData.fetch_widget_data(widget)
      assert is_list(data.alerts)
      assert is_list(data.agents)
      assert is_list(data.heatmap)
      assert is_integer(data.total_alerts)
      assert is_integer(data.total_agents)
    end

    test "fetches timeline viewer data", %{alerts: alerts} do
      widget = %{
        widget_type: "timeline_viewer",
        config: %{"time_range" => "24h", "interval" => "hour"}
      }

      assert {:ok, data} = WidgetData.fetch_widget_data(widget)
      assert is_list(data.timeline)
      assert data.interval == "hour"
    end

    test "fetches top detections data", %{alerts: alerts} do
      widget = %{
        widget_type: "top_detections",
        config: %{"time_range" => "24h", "limit" => 10}
      }

      assert {:ok, data} = WidgetData.fetch_widget_data(widget)
      assert is_list(data.detections)
      assert data.total_unique >= 0

      if length(data.detections) > 0 do
        detection = List.first(data.detections)
        assert Map.has_key?(detection, :name)
        assert Map.has_key?(detection, :count)
      end
    end

    test "fetches agent health overview data", %{agents: agents} do
      widget = %{
        widget_type: "agent_health_overview",
        config: %{}
      }

      assert {:ok, data} = WidgetData.fetch_widget_data(widget)
      assert data.total >= 2
      assert data.online >= 1
      assert data.offline >= 1
      assert is_list(data.agents)
    end

    test "fetches detection efficacy data", %{alerts: alerts} do
      widget = %{
        widget_type: "detection_efficacy",
        config: %{"time_range" => "7d"}
      }

      assert {:ok, data} = WidgetData.fetch_widget_data(widget)
      assert is_integer(data.total_alerts)
      assert is_integer(data.true_positives)
      assert is_integer(data.false_positives)
      assert is_float(data.accuracy)
      assert is_float(data.fp_rate)
      assert is_float(data.precision)
    end

    test "fetches MITRE ATT&CK heatmap data", %{alerts: alerts} do
      widget = %{
        widget_type: "mitre_attack_heatmap",
        config: %{"time_range" => "7d"}
      }

      assert {:ok, data} = WidgetData.fetch_widget_data(widget)
      assert is_list(data.tactics)
      assert is_integer(data.total_techniques)
      assert is_integer(data.total_detections)

      if length(data.tactics) > 0 do
        tactic = List.first(data.tactics)
        assert Map.has_key?(tactic, :tactic)
        assert Map.has_key?(tactic, :techniques)
        assert Map.has_key?(tactic, :total_count)
      end
    end

    test "fetches alert volume trends data" do
      widget = %{
        widget_type: "alert_volume_trends",
        config: %{"time_range" => "24h"}
      }

      assert {:ok, data} = WidgetData.fetch_widget_data(widget)
      assert is_list(data.trends)
      assert is_number(data.peak_value)
      assert is_number(data.average)
    end

    test "fetches response time metrics data" do
      widget = %{
        widget_type: "response_time_metrics",
        config: %{"time_range" => "24h"}
      }

      assert {:ok, data} = WidgetData.fetch_widget_data(widget)
      assert is_number(data.avg)
      assert is_number(data.p50)
      assert is_number(data.p95)
      assert is_number(data.p99)
      assert is_integer(data.sample_size)
    end

    test "fetches SLA compliance data" do
      widget = %{
        widget_type: "sla_compliance",
        config: %{"time_range" => "7d"}
      }

      assert {:ok, data} = WidgetData.fetch_widget_data(widget)
      assert is_list(data.by_severity)
      assert is_number(data.overall_compliance)
      assert length(data.by_severity) == 4  # critical, high, medium, low

      severity = List.first(data.by_severity)
      assert Map.has_key?(severity, :severity)
      assert Map.has_key?(severity, :compliance_rate)
      assert Map.has_key?(severity, :met)
      assert Map.has_key?(severity, :missed)
    end

    test "fetches top threats data" do
      widget = %{
        widget_type: "top_threats",
        config: %{"time_range" => "24h", "limit" => 10}
      }

      assert {:ok, data} = WidgetData.fetch_widget_data(widget)
      assert is_list(data.threats)
      assert is_integer(data.total_unique)
    end

    test "fetches IOC trends data" do
      widget = %{
        widget_type: "ioc_trends",
        config: %{"time_range" => "7d"}
      }

      assert {:ok, data} = WidgetData.fetch_widget_data(widget)
      assert is_list(data.top_iocs)
      assert is_list(data.trending_iocs)
      assert is_integer(data.total_unique)
    end

    test "fetches network topology data" do
      widget = %{
        widget_type: "network_topology",
        config: %{"time_range" => "1h"}
      }

      assert {:ok, data} = WidgetData.fetch_widget_data(widget)
      assert is_list(data.nodes)
      assert is_list(data.edges)
      assert is_integer(data.total_connections)
    end

    test "fetches user activity data" do
      widget = %{
        widget_type: "user_activity",
        config: %{"time_range" => "24h", "limit" => 10}
      }

      assert {:ok, data} = WidgetData.fetch_widget_data(widget)
      assert is_list(data.users)
      assert is_integer(data.total_users)
    end

    test "fetches compliance score data" do
      widget = %{
        widget_type: "compliance_score",
        config: %{"frameworks" => ["pci_dss", "hipaa", "gdpr"]}
      }

      assert {:ok, data} = WidgetData.fetch_widget_data(widget)
      assert is_list(data.frameworks)
      assert is_number(data.overall_score)
      assert length(data.frameworks) == 3

      framework = List.first(data.frameworks)
      assert Map.has_key?(framework, :framework)
      assert Map.has_key?(framework, :score)
      assert Map.has_key?(framework, :status)
    end

    test "fetches cost tracking data" do
      widget = %{
        widget_type: "cost_tracking",
        config: %{"time_range" => "30d"}
      }

      assert {:ok, data} = WidgetData.fetch_widget_data(widget)
      assert is_list(data.daily_costs)
      assert is_number(data.total_cost)
      assert is_number(data.average_daily_cost)
      assert data.currency == "USD"
    end

    test "fetches incident timeline data" do
      widget = %{
        widget_type: "incident_timeline",
        config: %{"time_range" => "30d"}
      }

      assert {:ok, data} = WidgetData.fetch_widget_data(widget)
      assert is_list(data.incidents)
      assert is_integer(data.total)
      assert is_integer(data.active)
      assert is_integer(data.resolved)
    end

    test "returns error for unknown widget type" do
      widget = %{
        widget_type: "unknown_widget",
        config: %{}
      }

      assert {:error, :unknown_widget_type} = WidgetData.fetch_widget_data(widget)
    end
  end

  # Helper functions

  defp create_agent(attrs) do
    default_attrs = %{
      hostname: "test-agent",
      agent_id: Ecto.UUID.generate(),
      status: "online",
      os: "linux",
      version: "1.0.0",
      metadata: %{}
    }

    attrs = Map.merge(default_attrs, attrs)
    Agent.changeset(%Agent{}, attrs)
    |> Repo.insert()
  end

  defp create_alert(attrs) do
    default_attrs = %{
      title: "Test Alert",
      severity: "medium",
      status: "open",
      agent_id: Ecto.UUID.generate(),
      detection_name: "Test Detection",
      metadata: %{}
    }

    attrs = Map.merge(default_attrs, attrs)
    Alert.changeset(%Alert{}, attrs)
    |> Repo.insert()
  end
end
