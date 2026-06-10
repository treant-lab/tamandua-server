defmodule TamanduaServerWeb.InvestigationGraphLiveTest do
  use TamanduaServerWeb.ConnCase, async: true

  import Phoenix.LiveViewTest

  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Telemetry.Event
  alias TamanduaServer.Agents.Agent

  setup %{conn: conn} do
    # Create test agent
    agent =
      %Agent{}
      |> Agent.changeset(%{
        agent_id: "test-graph-agent",
        hostname: "graph-test-host",
        ip_address: "192.168.1.150",
        os_type: "Windows"
      })
      |> Repo.insert!()

    # Create test events
    base_time = DateTime.utc_now()

    process_event =
      %Event{}
      |> Event.changeset(%{
        agent_id: agent.id,
        event_type: "process_start",
        timestamp: base_time,
        payload: %{
          "pid" => 2000,
          "name" => "test.exe",
          "user" => "testuser"
        },
        severity: "medium"
      })
      |> Repo.insert!()

    file_event =
      %Event{}
      |> Event.changeset(%{
        agent_id: agent.id,
        event_type: "file_write",
        timestamp: DateTime.add(base_time, 5, :second),
        payload: %{
          "path" => "C:\\test.txt",
          "action" => "write",
          "pid" => 2000
        },
        severity: "low"
      })
      |> Repo.insert!()

    # Create alert
    alert =
      %Alert{}
      |> Alert.changeset(%{
        agent_id: agent.id,
        severity: "medium",
        title: "Test Investigation Alert",
        description: "Test alert for graph visualization",
        event_ids: [process_event.id, file_event.id],
        mitre_techniques: ["T1055"]
      })
      |> Repo.insert!()

    %{
      conn: conn,
      agent: agent,
      alert: alert,
      process_event: process_event,
      file_event: file_event
    }
  end

  describe "mount" do
    test "renders investigation graph page with alert_id", %{conn: conn, alert: alert} do
      {:ok, view, html} = live(conn, "/investigation_graph?alert_id=#{alert.id}")

      assert html =~ "Investigation Graph"
      assert html =~ "Visualizing process, file, network, and registry relationships"
      assert has_element?(view, "#investigation-graph")
    end

    test "renders investigation graph page with alert_ids", %{conn: conn, alert: alert} do
      {:ok, view, html} = live(conn, "/investigation_graph?alert_ids[]=#{alert.id}")

      assert html =~ "Investigation Graph"
      assert has_element?(view, "#investigation-graph")
    end

    test "renders investigation graph page with agent and time range", %{conn: conn, agent: agent} do
      start_time = DateTime.utc_now() |> DateTime.add(-3600, :second) |> DateTime.to_iso8601()
      end_time = DateTime.utc_now() |> DateTime.to_iso8601()

      {:ok, view, html} =
        live(
          conn,
          "/investigation_graph?agent_id=#{agent.id}&start_time=#{start_time}&end_time=#{end_time}"
        )

      assert html =~ "Investigation Graph"
      assert has_element?(view, "#investigation-graph")
    end

    test "renders empty graph when no parameters provided", %{conn: conn} do
      {:ok, view, html} = live(conn, "/investigation_graph")

      assert html =~ "Investigation Graph"
      assert html =~ "0 nodes"
      assert html =~ "0 edges"
    end

    test "displays correct stats", %{conn: conn, alert: alert} do
      {:ok, view, html} = live(conn, "/investigation_graph?alert_id=#{alert.id}")

      # Should have at least process, file, user, and alert nodes
      refute html =~ "0 nodes"
      refute html =~ "0 edges"
    end
  end

  describe "node selection" do
    test "selecting a node updates details panel", %{conn: conn, alert: alert} do
      {:ok, view, _html} = live(conn, "/investigation_graph?alert_id=#{alert.id}")

      # Simulate node click
      view
      |> element("#investigation-graph")
      |> render_hook("select_node", %{"node_id" => "process_#{alert.agent_id}_2000"})

      html = render(view)
      assert html =~ "Details"
      assert html =~ "PROCESS"
    end

    test "clearing selection hides details panel", %{conn: conn, alert: alert} do
      {:ok, view, _html} = live(conn, "/investigation_graph?alert_id=#{alert.id}")

      # Select then clear
      view
      |> element("#investigation-graph")
      |> render_hook("select_node", %{"node_id" => "process_#{alert.agent_id}_2000"})

      view
      |> element("button", "clear_selection")
      |> render_click()

      html = render(view)
      refute html =~ "Details"
    end
  end

  describe "timeline controls" do
    test "changing timeline position filters graph", %{conn: conn, alert: alert} do
      {:ok, view, _html} = live(conn, "/investigation_graph?alert_id=#{alert.id}")

      # Change timeline position
      view
      |> element("input[name='position']")
      |> render_change(%{"position" => "50"})

      # Should trigger graph update
      assert_push_event(view, "update-graph", %{graph: _graph})
    end
  end

  describe "view controls" do
    test "reset view triggers event", %{conn: conn, alert: alert} do
      {:ok, view, _html} = live(conn, "/investigation_graph?alert_id=#{alert.id}")

      view
      |> element("button", "Reset View")
      |> render_click()

      assert_push_event(view, "reset-view", %{})
    end

    test "zoom in triggers event", %{conn: conn, alert: alert} do
      {:ok, view, _html} = live(conn, "/investigation_graph?alert_id=#{alert.id}")

      view
      |> element("button", "Zoom In")
      |> render_click()

      assert_push_event(view, "zoom-in", %{})
    end

    test "zoom out triggers event", %{conn: conn, alert: alert} do
      {:ok, view, _html} = live(conn, "/investigation_graph?alert_id=#{alert.id}")

      view
      |> element("button", "Zoom Out")
      |> render_click()

      assert_push_event(view, "zoom-out", %{})
    end

    test "fit to screen triggers event", %{conn: conn, alert: alert} do
      {:ok, view, _html} = live(conn, "/investigation_graph?alert_id=#{alert.id}")

      view
      |> element("button", "Fit")
      |> render_click()

      assert_push_event(view, "fit-to-screen", %{})
    end

    test "toggle fullscreen", %{conn: conn, alert: alert} do
      {:ok, view, _html} = live(conn, "/investigation_graph?alert_id=#{alert.id}")

      # Toggle fullscreen on
      view
      |> element("button", "Fullscreen")
      |> render_click()

      html = render(view)
      assert html =~ "Exit Fullscreen"

      # Toggle fullscreen off
      view
      |> element("button", "Exit Fullscreen")
      |> render_click()

      html = render(view)
      assert html =~ "Fullscreen"
      refute html =~ "Exit Fullscreen"
    end
  end

  describe "export" do
    test "export PNG triggers event", %{conn: conn, alert: alert} do
      {:ok, view, _html} = live(conn, "/investigation_graph?alert_id=#{alert.id}")

      view
      |> element("button", "Export as PNG")
      |> render_click()

      assert_push_event(view, "export-png", %{})
    end

    test "export SVG triggers event", %{conn: conn, alert: alert} do
      {:ok, view, _html} = live(conn, "/investigation_graph?alert_id=#{alert.id}")

      view
      |> element("button", "Export as SVG")
      |> render_click()

      assert_push_event(view, "export-svg", %{})
    end

    test "export GraphML triggers download", %{conn: conn, alert: alert} do
      {:ok, view, _html} = live(conn, "/investigation_graph?alert_id=#{alert.id}")

      view
      |> element("button", "Export as GraphML")
      |> render_click()

      assert_push_event(view, "download-file", %{
        filename: "investigation_graph.graphml",
        content: content,
        mime_type: "application/xml"
      })

      assert content =~ "<?xml version=\"1.0\""
      assert content =~ "<graphml"
    end
  end

  describe "filters" do
    test "applying node type filter", %{conn: conn, alert: alert} do
      {:ok, view, _html} = live(conn, "/investigation_graph?alert_id=#{alert.id}")

      # Apply filter for process nodes only
      view
      |> element("form")
      |> render_submit(%{"node_types" => ["process"]})

      # Should update graph
      assert_push_event(view, "update-graph", %{graph: _graph})
    end

    test "applying suspicious only filter", %{conn: conn, alert: alert} do
      {:ok, view, _html} = live(conn, "/investigation_graph?alert_id=#{alert.id}")

      view
      |> element("form")
      |> render_submit(%{"suspicious_only" => "true"})

      assert_push_event(view, "update-graph", %{graph: _graph})
    end

    test "clearing filters resets graph", %{conn: conn, alert: alert} do
      {:ok, view, _html} = live(conn, "/investigation_graph?alert_id=#{alert.id}")

      # Apply filter
      view
      |> element("form")
      |> render_submit(%{"node_types" => ["process"]})

      # Clear filters
      view
      |> element("button", "Clear")
      |> render_click()

      assert_push_event(view, "update-graph", %{graph: _graph})
    end
  end

  describe "refresh" do
    test "refresh reloads graph", %{conn: conn, alert: alert} do
      {:ok, view, _html} = live(conn, "/investigation_graph?alert_id=#{alert.id}")

      view
      |> element("button", "Refresh")
      |> render_click()

      assert_push_event(view, "update-graph", %{graph: _graph})
    end
  end

  describe "legend" do
    test "displays node type legend", %{conn: conn, alert: alert} do
      {:ok, view, html} = live(conn, "/investigation_graph?alert_id=#{alert.id}")

      assert html =~ "Legend"
      assert html =~ "Node Types:"
      assert html =~ "Process"
      assert html =~ "File"
      assert html =~ "Network"
      assert html =~ "DNS"
      assert html =~ "Registry"
      assert html =~ "User"
      assert html =~ "Module/DLL"
      assert html =~ "Alert"
    end
  end

  describe "details panel" do
    test "displays process node details", %{conn: conn, alert: alert} do
      {:ok, view, _html} = live(conn, "/investigation_graph?alert_id=#{alert.id}")

      # Build graph to get actual node
      graph = TamanduaServer.Investigations.GraphBuilder.build_from_alert(alert.id)
      process_node = Enum.find(graph.nodes, fn n -> n.type == :process end)

      if process_node do
        view = assign(view, :selected_node, process_node)
        html = render(view)

        assert html =~ "PROCESS"
        assert html =~ process_node.label
      end
    end

    test "displays file node details", %{conn: conn, alert: alert} do
      {:ok, view, _html} = live(conn, "/investigation_graph?alert_id=#{alert.id}")

      graph = TamanduaServer.Investigations.GraphBuilder.build_from_alert(alert.id)
      file_node = Enum.find(graph.nodes, fn n -> n.type == :file end)

      if file_node do
        view = assign(view, :selected_node, file_node)
        html = render(view)

        assert html =~ "FILE"
        assert html =~ "Path"
      end
    end

    test "displays alert node details", %{conn: conn, alert: alert} do
      {:ok, view, _html} = live(conn, "/investigation_graph?alert_id=#{alert.id}")

      graph = TamanduaServer.Investigations.GraphBuilder.build_from_alert(alert.id)
      alert_node = Enum.find(graph.nodes, fn n -> n.type == :alert end)

      if alert_node do
        view = assign(view, :selected_node, alert_node)
        html = render(view)

        assert html =~ "ALERT"
        assert html =~ "Severity"
        assert html =~ "View Alert Details"
      end
    end

    test "displays edge details", %{conn: conn, alert: alert} do
      {:ok, view, _html} = live(conn, "/investigation_graph?alert_id=#{alert.id}")

      graph = TamanduaServer.Investigations.GraphBuilder.build_from_alert(alert.id)

      if edge = List.first(graph.edges) do
        view = assign(view, :selected_edge, edge)
        html = render(view)

        assert html =~ "Relationship"
        assert html =~ "Source"
        assert html =~ "Target"
      end
    end
  end

  describe "real-time updates" do
    test "receives alert update notification", %{conn: conn, alert: alert} do
      {:ok, view, _html} = live(conn, "/investigation_graph?alert_id=#{alert.id}")

      # Simulate alert update via PubSub
      send(view.pid, {:alert_updated, alert.id})

      # Should trigger refresh
      assert_push_event(view, "update-graph", %{graph: _graph})
    end
  end

  describe "error handling" do
    test "handles invalid alert ID gracefully", %{conn: conn} do
      {:ok, view, html} = live(conn, "/investigation_graph?alert_id=invalid-uuid")

      assert html =~ "Investigation Graph"
      assert html =~ "0 nodes"
    end

    test "handles missing time range gracefully", %{conn: conn, agent: agent} do
      {:ok, view, html} = live(conn, "/investigation_graph?agent_id=#{agent.id}")

      # Should render without crashing
      assert html =~ "Investigation Graph"
    end
  end
end
