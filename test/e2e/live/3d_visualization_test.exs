defmodule TamanduaServerWeb.E2E.ThreeDVisualizationTest do
  use TamanduaServer.LiveViewCase, async: false
  alias TamanduaServer.Visualization

  describe "3D graph rendering" do
    test "loads 3D network graph", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      # Create network topology
      agent1 = insert(:agent, hostname: "web-server")
      agent2 = insert(:agent, hostname: "db-server")
      insert(:connection, source: agent1, target: agent2)

      {:ok, view, _html} = live(conn, "/visualization/3d")

      assert has_element?(view, "#three-canvas")
      assert has_element?(view, ".visualization-controls")
    end

    test "renders nodes for agents", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      agent1 = insert(:agent, hostname: "server1", status: :online)
      agent2 = insert(:agent, hostname: "server2", status: :offline)
      agent3 = insert(:agent, hostname: "server3", status: :isolated)

      {:ok, view, _html} = live(conn, "/visualization/3d")

      # Verify nodes are rendered
      assert render(view) =~ "server1"
      assert render(view) =~ "server2"
      assert render(view) =~ "server3"

      # Check node data attributes
      assert has_element?(view, "[data-node-id='#{agent1.id}']")
      assert has_element?(view, "[data-node-id='#{agent2.id}']")
      assert has_element?(view, "[data-node-id='#{agent3.id}']")
    end

    test "renders edges for connections", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      agent1 = insert(:agent)
      agent2 = insert(:agent)
      connection = insert(:connection, source: agent1, target: agent2, protocol: "tcp")

      {:ok, view, _html} = live(conn, "/visualization/3d")

      assert has_element?(view, "[data-edge-id='#{connection.id}']")
    end

    test "color codes nodes by status", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      online_agent = insert(:agent, status: :online)
      offline_agent = insert(:agent, status: :offline)
      isolated_agent = insert(:agent, status: :isolated)

      {:ok, view, _html} = live(conn, "/visualization/3d")

      assert has_element?(view, "[data-node-id='#{online_agent.id}'][data-color='green']")
      assert has_element?(view, "[data-node-id='#{offline_agent.id}'][data-color='red']")
      assert has_element?(view, "[data-node-id='#{isolated_agent.id}'][data-color='orange']")
    end

    test "node size reflects alert count", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      agent_with_alerts = insert(:agent)
      insert_list(5, :alert, agent: agent_with_alerts)

      agent_clean = insert(:agent)

      {:ok, view, _html} = live(conn, "/visualization/3d")

      # Agent with alerts should have larger size attribute
      assert has_element?(view, "[data-node-id='#{agent_with_alerts.id}'][data-size='large']")
      assert has_element?(view, "[data-node-id='#{agent_clean.id}'][data-size='normal']")
    end
  end

  describe "node interaction" do
    test "click node shows details panel", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      agent = insert(:agent, hostname: "test-server", os: "Windows 10")

      {:ok, view, _html} = live(conn, "/visualization/3d")

      # Click node
      view
      |> element("[data-node-id='#{agent.id}']")
      |> render_hook("node_click", %{node_id: agent.id})

      # Details panel should appear
      assert has_element?(view, ".node-details-panel")
      assert render(view) =~ "test-server"
      assert render(view) =~ "Windows 10"
    end

    test "hover node shows tooltip", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      agent = insert(:agent, hostname: "web-server-01")

      {:ok, view, _html} = live(conn, "/visualization/3d")

      # Hover node
      view
      |> element("[data-node-id='#{agent.id}']")
      |> render_hook("node_hover", %{node_id: agent.id})

      assert has_element?(view, ".node-tooltip")
      assert render(view) =~ "web-server-01"
    end

    test "double click node navigates to agent page", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      agent = insert(:agent)

      {:ok, view, _html} = live(conn, "/visualization/3d")

      # Double click
      view
      |> element("[data-node-id='#{agent.id}']")
      |> render_hook("node_dblclick", %{node_id: agent.id})

      assert_redirect(view, "/agents/#{agent.id}")
    end

    test "right click node shows context menu", %{conn: conn} do
      user = insert(:user, role: :admin)
      conn = log_in_user(conn, user)
      agent = insert(:agent)

      {:ok, view, _html} = live(conn, "/visualization/3d")

      # Right click
      view
      |> element("[data-node-id='#{agent.id}']")
      |> render_hook("node_contextmenu", %{node_id: agent.id})

      assert has_element?(view, ".context-menu")
      assert has_element?(view, ".menu-item-isolate")
      assert has_element?(view, ".menu-item-shell")
    end

    test "select multiple nodes", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      agent1 = insert(:agent)
      agent2 = insert(:agent)
      agent3 = insert(:agent)

      {:ok, view, _html} = live(conn, "/visualization/3d")

      # Select nodes with Ctrl+Click
      view
      |> element("[data-node-id='#{agent1.id}']")
      |> render_hook("node_click", %{node_id: agent1.id, ctrl: true})

      view
      |> element("[data-node-id='#{agent2.id}']")
      |> render_hook("node_click", %{node_id: agent2.id, ctrl: true})

      assert has_element?(view, "[data-node-id='#{agent1.id}'].selected")
      assert has_element?(view, "[data-node-id='#{agent2.id}'].selected")
      assert has_element?(view, ".selection-count", "2")
    end
  end

  describe "zoom and pan controls" do
    test "zoom in/out with mouse wheel", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/visualization/3d")

      # Zoom in
      view
      |> element("#three-canvas")
      |> render_hook("wheel", %{delta: -100})

      assert render(view) =~ "zoom-level"

      # Zoom out
      view
      |> element("#three-canvas")
      |> render_hook("wheel", %{delta: 100})

      assert render(view) =~ "zoom-level"
    end

    test "pan with mouse drag", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/visualization/3d")

      # Start drag
      view
      |> element("#three-canvas")
      |> render_hook("mousedown", %{x: 100, y: 100})

      # Move
      view
      |> element("#three-canvas")
      |> render_hook("mousemove", %{x: 200, y: 150})

      # End drag
      view
      |> element("#three-canvas")
      |> render_hook("mouseup", %{})

      assert render(view) =~ "camera-position"
    end

    test "reset camera view", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/visualization/3d")

      # Zoom and pan
      view |> element("#three-canvas") |> render_hook("wheel", %{delta: -500})

      # Reset
      view |> element("#reset-camera") |> render_click()

      assert has_element?(view, ".camera-reset")
    end

    test "fit view to content", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      insert_list(10, :agent)

      {:ok, view, _html} = live(conn, "/visualization/3d")

      # Fit to view
      view |> element("#fit-view") |> render_click()

      assert has_element?(view, ".view-fitted")
    end

    test "rotate camera with keyboard", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/visualization/3d")

      # Rotate with arrow keys
      view |> render_hook("keydown", %{key: "ArrowLeft"})

      assert render(view) =~ "camera-rotation"
    end
  end

  describe "VR mode" do
    test "toggle VR mode", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/visualization/3d")

      # Enable VR
      view |> element("#vr-toggle") |> render_click()

      assert has_element?(view, ".vr-active")
      assert has_element?(view, "#vr-overlay")
    end

    test "VR mode with WebXR", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/visualization/3d")

      # Check VR availability
      view |> render_hook("check_vr_support", %{})

      # Enable VR if supported
      view |> element("#enter-vr") |> render_click()

      assert has_element?(view, ".vr-session-active")
    end

    test "VR controller input", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      agent = insert(:agent)

      {:ok, view, _html} = live(conn, "/visualization/3d")

      view |> element("#vr-toggle") |> render_click()

      # Simulate VR controller select
      view
      |> render_hook("vr_select", %{node_id: agent.id})

      assert has_element?(view, ".node-details-panel")
    end
  end

  describe "graph layouts" do
    test "switch to force-directed layout", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/visualization/3d")

      view
      |> element("#layout-select")
      |> render_change(%{layout: "force_directed"})

      assert has_element?(view, ".layout-force-directed")
    end

    test "switch to hierarchical layout", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/visualization/3d")

      view
      |> element("#layout-select")
      |> render_change(%{layout: "hierarchical"})

      assert has_element?(view, ".layout-hierarchical")
    end

    test "switch to circular layout", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/visualization/3d")

      view
      |> element("#layout-select")
      |> render_change(%{layout: "circular"})

      assert has_element?(view, ".layout-circular")
    end

    test "custom grid layout", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/visualization/3d")

      view
      |> element("#layout-select")
      |> render_change(%{layout: "grid"})

      view
      |> element("#grid-config")
      |> render_change(%{grid: %{columns: 5, spacing: 10}})

      assert has_element?(view, ".layout-grid")
    end
  end

  describe "filtering and search" do
    test "filter nodes by status", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      online_agent = insert(:agent, status: :online)
      offline_agent = insert(:agent, status: :offline)

      {:ok, view, _html} = live(conn, "/visualization/3d")

      # Filter to online only
      view
      |> element("#status-filter")
      |> render_change(%{status: ["online"]})

      assert has_element?(view, "[data-node-id='#{online_agent.id}']")
      refute has_element?(view, "[data-node-id='#{offline_agent.id}']")
    end

    test "search for specific node", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      target_agent = insert(:agent, hostname: "web-server-01")
      other_agent = insert(:agent, hostname: "db-server-01")

      {:ok, view, _html} = live(conn, "/visualization/3d")

      # Search
      view
      |> element("#node-search")
      |> render_change(%{query: "web"})

      # Should highlight matching node
      assert has_element?(view, "[data-node-id='#{target_agent.id}'].highlighted")
      refute has_element?(view, "[data-node-id='#{other_agent.id}'].highlighted")
    end

    test "filter by alert severity", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      critical_agent = insert(:agent)
      insert(:alert, agent: critical_agent, severity: :critical)

      clean_agent = insert(:agent)

      {:ok, view, _html} = live(conn, "/visualization/3d")

      # Filter to agents with critical alerts
      view
      |> element("#alert-filter")
      |> render_change(%{severity: ["critical"]})

      assert has_element?(view, "[data-node-id='#{critical_agent.id}']")
      refute has_element?(view, "[data-node-id='#{clean_agent.id}']")
    end

    test "hide/show node labels", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/visualization/3d")

      # Hide labels
      view |> element("#toggle-labels") |> render_click()

      assert has_element?(view, ".labels-hidden")

      # Show labels
      view |> element("#toggle-labels") |> render_click()

      refute has_element?(view, ".labels-hidden")
    end
  end

  describe "real-time updates" do
    test "new agent appears in graph", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/visualization/3d")

      # Add new agent
      agent = insert(:agent, hostname: "new-server")

      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "visualization:nodes",
        {:node_added, agent}
      )

      :timer.sleep(100)

      assert has_element?(view, "[data-node-id='#{agent.id}']")
    end

    test "agent status change updates node color", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      agent = insert(:agent, status: :online)

      {:ok, view, _html} = live(conn, "/visualization/3d")

      # Agent goes offline
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "agents:status",
        {:status_changed, agent.id, :offline}
      )

      :timer.sleep(100)

      assert has_element?(view, "[data-node-id='#{agent.id}'][data-color='red']")
    end

    test "new connection appears as edge", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      agent1 = insert(:agent)
      agent2 = insert(:agent)

      {:ok, view, _html} = live(conn, "/visualization/3d")

      # Create connection
      connection = insert(:connection, source: agent1, target: agent2)

      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "visualization:edges",
        {:edge_added, connection}
      )

      :timer.sleep(100)

      assert has_element?(view, "[data-edge-id='#{connection.id}']")
    end

    test "alert increases node size", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      agent = insert(:agent)

      {:ok, view, _html} = live(conn, "/visualization/3d")

      # Create alert
      alert = insert(:alert, agent: agent, severity: :critical)

      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "alerts:new",
        {:new_alert, alert}
      )

      :timer.sleep(100)

      # Node should pulse or increase size
      assert has_element?(view, "[data-node-id='#{agent.id}'].has-alerts")
    end
  end

  describe "performance" do
    test "handles large graphs efficiently", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      # Create 100 agents
      agents = insert_list(100, :agent)

      {:ok, view, _html} = live(conn, "/visualization/3d")

      # Should render without timeout
      assert has_element?(view, "#three-canvas")
      assert render(view) =~ "node-count: 100"
    end

    test "LOD (Level of Detail) optimization", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      insert_list(50, :agent)

      {:ok, view, _html} = live(conn, "/visualization/3d")

      # Zoom out (should reduce detail)
      view
      |> element("#three-canvas")
      |> render_hook("wheel", %{delta: 1000})

      assert has_element?(view, ".lod-low-detail")
    end
  end

  describe "export visualization" do
    test "export as image", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/visualization/3d")

      view |> element("#export-image") |> render_click()

      assert_push_event(view, "download", %{format: "png"})
    end

    test "export as 3D model", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/visualization/3d")

      view |> element("#export-3d") |> render_click()

      assert_push_event(view, "download", %{format: "obj"})
    end
  end
end
