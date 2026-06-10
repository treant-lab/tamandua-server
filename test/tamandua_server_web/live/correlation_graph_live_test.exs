defmodule TamanduaServerWeb.CorrelationGraphLiveTest do
  use TamanduaServerWeb.ConnCase

  import Phoenix.LiveViewTest
  import TamanduaServer.Factory

  alias TamanduaServer.Alerts.{Alert, AttackCampaign, AlertCorrelation}
  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.Repo

  setup do
    user = insert(:user)
    organization = insert(:organization)

    {:ok, user: user, organization: organization}
  end

  describe "mount" do
    test "successfully mounts and loads initial graph", %{conn: conn, user: user, organization: organization} do
      conn = log_in_user(conn, user)

      # Create test data
      agent1 = insert(:agent, organization: organization, hostname: "host1", ip_address: "192.168.1.10")
      agent2 = insert(:agent, organization: organization, hostname: "host2", ip_address: "192.168.1.11")

      alert1 = insert(:alert,
        organization: organization,
        agent: agent1,
        title: "Suspicious Process",
        severity: "high",
        mitre_techniques: ["T1055"],
        evidence: %{
          "process" => %{
            "name" => "malware.exe",
            "pid" => 1234,
            "user" => "admin"
          }
        }
      )

      alert2 = insert(:alert,
        organization: organization,
        agent: agent2,
        title: "Lateral Movement",
        severity: "critical",
        mitre_techniques: ["T1055", "T1021"],
        evidence: %{
          "network" => %{
            "remote_ip" => "192.168.1.10"
          }
        }
      )

      {:ok, view, html} = live(conn, "/live/correlation-graph")

      assert html =~ "Attack Correlation Graph"
      assert has_element?(view, "#graph-container")
    end

    test "loads graph for specific campaign", %{conn: conn, user: user, organization: organization} do
      conn = log_in_user(conn, user)

      # Create campaign with alerts
      campaign = insert(:attack_campaign,
        organization: organization,
        name: "Test Campaign",
        status: "active"
      )

      agent = insert(:agent, organization: organization)
      alert = insert(:alert, organization: organization, agent: agent, campaign_id: campaign.id)

      {:ok, view, html} = live(conn, "/live/correlation-graph/campaign/#{campaign.id}")

      assert html =~ "Attack Correlation Graph"
      assert html =~ "Test Campaign"
    end
  end

  describe "graph data loading" do
    test "correctly builds nodes for agents, alerts, IOCs, users, and processes", %{
      conn: conn,
      user: user,
      organization: organization
    } do
      conn = log_in_user(conn, user)

      agent = insert(:agent, organization: organization, hostname: "test-host", ip_address: "10.0.0.1")

      alert = insert(:alert,
        organization: organization,
        agent: agent,
        title: "Test Alert",
        severity: "high",
        mitre_techniques: ["T1055"],
        evidence: %{
          "process" => %{
            "name" => "evil.exe",
            "pid" => 9999,
            "user" => "admin",
            "path" => "C:\\temp\\evil.exe"
          },
          "file_hashes" => %{
            "sha256" => "abc123def456"
          },
          "network" => %{
            "remote_ip" => "1.2.3.4"
          }
        }
      )

      {:ok, view, _html} = live(conn, "/live/correlation-graph")

      # Verify graph data includes all node types
      graph_data = :sys.get_state(view.pid).assigns.graph_data

      assert Enum.any?(graph_data.nodes, fn n -> n.type == "agent" end)
      assert Enum.any?(graph_data.nodes, fn n -> n.type == "alert" end)
      assert Enum.any?(graph_data.nodes, fn n -> n.type == "ioc" end)
      assert Enum.any?(graph_data.nodes, fn n -> n.type == "user" end)
      assert Enum.any?(graph_data.nodes, fn n -> n.type == "process" end)
    end

    test "creates correlation links between related alerts", %{
      conn: conn,
      user: user,
      organization: organization
    } do
      conn = log_in_user(conn, user)

      agent = insert(:agent, organization: organization)
      alert1 = insert(:alert, organization: organization, agent: agent)
      alert2 = insert(:alert, organization: organization, agent: agent)

      # Create correlation
      insert(:alert_correlation,
        alert: alert1,
        related_alert: alert2,
        correlation_type: "technique",
        confidence: 0.85
      )

      {:ok, view, _html} = live(conn, "/live/correlation-graph")

      graph_data = :sys.get_state(view.pid).assigns.graph_data

      # Verify link exists
      assert Enum.any?(graph_data.links, fn l ->
        l.source == "alert_#{alert1.id}" and
        l.target == "alert_#{alert2.id}" and
        l.type == "technique"
      end)
    end
  end

  describe "interactions" do
    test "handles node click event", %{conn: conn, user: user, organization: organization} do
      conn = log_in_user(conn, user)

      agent = insert(:agent, organization: organization, hostname: "test-host")
      alert = insert(:alert, organization: organization, agent: agent, title: "Test Alert")

      {:ok, view, _html} = live(conn, "/live/correlation-graph")

      # Simulate node click
      node_data = %{
        "id" => "alert_#{alert.id}",
        "type" => "alert",
        "title" => "Test Alert"
      }

      view
      |> element("#graph-container")
      |> render_hook("node_clicked", %{"node" => node_data})

      # Verify node is selected and details panel shows
      assert has_element?(view, "div", "Test Alert")
    end

    test "handles link click event", %{conn: conn, user: user, organization: organization} do
      conn = log_in_user(conn, user)

      agent = insert(:agent, organization: organization)
      alert1 = insert(:alert, organization: organization, agent: agent)
      alert2 = insert(:alert, organization: organization, agent: agent)

      {:ok, view, _html} = live(conn, "/live/correlation-graph")

      link_data = %{
        "source" => "alert_#{alert1.id}",
        "target" => "alert_#{alert2.id}",
        "type" => "technique"
      }

      view
      |> render_hook("link_clicked", %{"link" => link_data})

      # Verify link details are shown
      assert has_element?(view, "div", "Technique")
    end

    test "handles reset view", %{conn: conn, user: user} do
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/live/correlation-graph")

      view
      |> element("button", "Reset View")
      |> render_click()

      # Verify reset event was pushed
      assert_push_event(view, "reset-view", %{})
    end

    test "handles zoom to fit", %{conn: conn, user: user} do
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/live/correlation-graph")

      view
      |> element("button", "Fit to Screen")
      |> render_click()

      assert_push_event(view, "zoom-to-fit", %{})
    end

    test "toggles fullscreen mode", %{conn: conn, user: user} do
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/live/correlation-graph")

      refute :sys.get_state(view.pid).assigns.fullscreen

      view
      |> element("button", "Fullscreen")
      |> render_click()

      assert :sys.get_state(view.pid).assigns.fullscreen

      view
      |> element("button", "Exit Fullscreen")
      |> render_click()

      refute :sys.get_state(view.pid).assigns.fullscreen
    end
  end

  describe "filtering" do
    test "applies severity filter", %{conn: conn, user: user, organization: organization} do
      conn = log_in_user(conn, user)

      agent = insert(:agent, organization: organization)
      insert(:alert, organization: organization, agent: agent, severity: "critical")
      insert(:alert, organization: organization, agent: agent, severity: "low")

      {:ok, view, _html} = live(conn, "/live/correlation-graph")

      # Apply filter
      view
      |> form("form", filter: %{severity: ["critical"]})
      |> render_submit()

      filter = :sys.get_state(view.pid).assigns.filter
      assert "critical" in filter.severity
    end

    test "applies node type filter", %{conn: conn, user: user, organization: organization} do
      conn = log_in_user(conn, user)

      agent = insert(:agent, organization: organization)
      insert(:alert, organization: organization, agent: agent)

      {:ok, view, _html} = live(conn, "/live/correlation-graph")

      view
      |> form("form", filter: %{type: "alert"})
      |> render_submit()

      filter = :sys.get_state(view.pid).assigns.filter
      assert filter.type == "alert"
    end

    test "applies campaign filter", %{conn: conn, user: user, organization: organization} do
      conn = log_in_user(conn, user)

      campaign = insert(:attack_campaign, organization: organization)
      agent = insert(:agent, organization: organization)
      insert(:alert, organization: organization, agent: agent, campaign_id: campaign.id)

      {:ok, view, _html} = live(conn, "/live/correlation-graph")

      view
      |> form("form", filter: %{campaign: campaign.id})
      |> render_submit()

      filter = :sys.get_state(view.pid).assigns.filter
      assert filter.campaign == campaign.id
    end

    test "clears filter", %{conn: conn, user: user, organization: organization} do
      conn = log_in_user(conn, user)

      agent = insert(:agent, organization: organization)
      insert(:alert, organization: organization, agent: agent, severity: "critical")

      {:ok, view, _html} = live(conn, "/live/correlation-graph")

      # Apply filter
      view
      |> form("form", filter: %{severity: ["critical"]})
      |> render_submit()

      # Clear filter
      view
      |> element("button", "Clear")
      |> render_click()

      filter = :sys.get_state(view.pid).assigns.filter
      assert filter.severity == []
    end
  end

  describe "export" do
    test "handles SVG export", %{conn: conn, user: user} do
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/live/correlation-graph")

      view
      |> element("button", "Export as SVG")
      |> render_click()

      assert_push_event(view, "export-svg", %{})
    end

    test "handles PNG export", %{conn: conn, user: user} do
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/live/correlation-graph")

      view
      |> element("button", "Export as PNG")
      |> render_click()

      assert_push_event(view, "export-png", %{})
    end
  end

  describe "real-time updates" do
    test "updates graph when new alert is created", %{conn: conn, user: user, organization: organization} do
      conn = log_in_user(conn, user)

      campaign = insert(:attack_campaign, organization: organization)
      agent = insert(:agent, organization: organization)

      {:ok, view, _html} = live(conn, "/live/correlation-graph/campaign/#{campaign.id}")

      # Create new alert
      alert = insert(:alert, organization: organization, agent: agent, campaign_id: campaign.id)

      # Simulate PubSub broadcast
      send(view.pid, {:alert_created, alert})

      # Graph should update
      assert_push_event(view, "update-graph", %{graph_data: _})
    end

    test "updates graph when campaign is updated", %{conn: conn, user: user, organization: organization} do
      conn = log_in_user(conn, user)

      campaign = insert(:attack_campaign, organization: organization)

      {:ok, view, _html} = live(conn, "/live/correlation-graph/campaign/#{campaign.id}")

      # Update campaign
      campaign = Repo.update!(AttackCampaign.changeset(campaign, %{alert_count: 10}))

      # Simulate PubSub broadcast
      send(view.pid, {:campaign_updated, campaign})

      assert_push_event(view, "update-graph", %{graph_data: _})
    end
  end

  describe "statistics" do
    test "calculates correct node and link counts", %{conn: conn, user: user, organization: organization} do
      conn = log_in_user(conn, user)

      agent1 = insert(:agent, organization: organization)
      agent2 = insert(:agent, organization: organization)

      alert1 = insert(:alert, organization: organization, agent: agent1)
      alert2 = insert(:alert, organization: organization, agent: agent2)

      insert(:alert_correlation, alert: alert1, related_alert: alert2)

      {:ok, view, _html} = live(conn, "/live/correlation-graph")

      stats = :sys.get_state(view.pid).assigns.stats

      assert stats.total_nodes > 0
      assert stats.total_links > 0
      assert stats.node_counts["agent"] == 2
      assert stats.node_counts["alert"] == 2
    end
  end

  describe "performance" do
    test "handles large graphs efficiently", %{conn: conn, user: user, organization: organization} do
      conn = log_in_user(conn, user)

      # Create many agents and alerts
      agents = for i <- 1..50 do
        insert(:agent, organization: organization, hostname: "host-#{i}")
      end

      alerts = for agent <- agents do
        insert(:alert, organization: organization, agent: agent)
      end

      # Create correlations
      for i <- 0..(length(alerts) - 2) do
        alert1 = Enum.at(alerts, i)
        alert2 = Enum.at(alerts, i + 1)
        insert(:alert_correlation, alert: alert1, related_alert: alert2)
      end

      # Should load without timeout
      {:ok, view, _html} = live(conn, "/live/correlation-graph")

      graph_data = :sys.get_state(view.pid).assigns.graph_data

      # Verify all data loaded
      assert length(graph_data.nodes) >= 100  # 50 agents + 50 alerts
      assert length(graph_data.links) >= 49   # Correlations
    end
  end

  describe "edge cases" do
    test "handles empty graph", %{conn: conn, user: user} do
      conn = log_in_user(conn, user)

      {:ok, view, html} = live(conn, "/live/correlation-graph")

      assert html =~ "Attack Correlation Graph"
      graph_data = :sys.get_state(view.pid).assigns.graph_data
      assert graph_data.nodes == [] or length(graph_data.nodes) < 5
    end

    test "handles alerts without agents", %{conn: conn, user: user, organization: organization} do
      conn = log_in_user(conn, user)

      insert(:alert, organization: organization, agent: nil)

      {:ok, view, _html} = live(conn, "/live/correlation-graph")

      # Should not crash
      graph_data = :sys.get_state(view.pid).assigns.graph_data
      assert is_list(graph_data.nodes)
    end

    test "handles alerts without evidence", %{conn: conn, user: user, organization: organization} do
      conn = log_in_user(conn, user)

      agent = insert(:agent, organization: organization)
      insert(:alert, organization: organization, agent: agent, evidence: nil)

      {:ok, view, _html} = live(conn, "/live/correlation-graph")

      # Should not crash
      graph_data = :sys.get_state(view.pid).assigns.graph_data
      assert is_list(graph_data.nodes)
    end

    test "handles non-existent campaign", %{conn: conn, user: user} do
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/live/correlation-graph/campaign/00000000-0000-0000-0000-000000000000")

      # Should show empty graph
      graph_data = :sys.get_state(view.pid).assigns.graph_data
      assert graph_data.nodes == []
      assert graph_data.links == []
    end
  end

  # Helper to simulate login
  defp log_in_user(conn, user) do
    conn
    |> Phoenix.ConnTest.init_test_session(%{})
    |> Plug.Conn.assign(:current_user, user)
  end
end
