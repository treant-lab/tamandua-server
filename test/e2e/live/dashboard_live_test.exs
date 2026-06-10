defmodule TamanduaServerWeb.E2E.DashboardLiveTest do
  use TamanduaServer.LiveViewCase, async: false
  alias TamanduaServer.Dashboard

  describe "widget real-time updates" do
    test "metrics update every 5 seconds", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/dashboard")

      initial_html = render(view)

      # Simulate metrics update
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "dashboard:metrics",
        {:metrics_update, %{
          alerts_count: 42,
          agents_online: 15,
          events_per_second: 1250
        }}
      )

      :timer.sleep(100)

      updated_html = render(view)

      # Metrics should have updated
      refute initial_html == updated_html
      assert updated_html =~ "42"
      assert updated_html =~ "15"
    end

    test "alert widget updates with new alerts", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/dashboard")

      # Create new alert
      alert = insert(:alert, severity: :critical, title: "Ransomware Detected")

      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "alerts:new",
        {:new_alert, alert}
      )

      :timer.sleep(100)

      assert has_element?(view, ".widget-alerts [data-alert-id='#{alert.id}']")
      assert render(view) =~ "Ransomware Detected"
    end

    test "agent status widget updates", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      agent = insert(:agent, status: :offline)

      {:ok, view, _html} = live(conn, "/dashboard")

      initial_count = view
        |> element(".widget-agents .online-count")
        |> render()
        |> String.trim()
        |> String.to_integer()

      # Agent comes online
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "agents:status",
        {:status_changed, agent.id, :online}
      )

      :timer.sleep(100)

      updated_count = view
        |> element(".widget-agents .online-count")
        |> render()
        |> String.trim()
        |> String.to_integer()

      assert updated_count == initial_count + 1
    end

    test "events per second widget updates", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/dashboard")

      # Simulate telemetry spike
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "telemetry:metrics",
        {:throughput_update, %{events_per_second: 5000}}
      )

      :timer.sleep(100)

      assert render(view) =~ "5000"
      assert has_element?(view, ".throughput-high")
    end

    test "drag and drop widget reordering", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/dashboard")

      # Simulate drag start on alerts widget
      view
      |> element("[data-widget='alerts']")
      |> render_hook("drag_start", %{widget_id: "alerts"})

      # Simulate drop on new position
      view
      |> element(".grid-cell-1-1")
      |> render_hook("drop", %{widget_id: "alerts", position: %{row: 1, col: 1}})

      # Verify position saved
      assert has_element?(view, ".grid-cell-1-1 [data-widget='alerts']")
    end

    test "resize widget", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/dashboard")

      # Simulate resize
      view
      |> element("[data-widget='alerts'] .resize-handle")
      |> render_hook("resize", %{widget_id: "alerts", width: 600, height: 400})

      assert has_element?(view, "[data-widget='alerts'][data-width='600'][data-height='400']")
    end

    test "add new widget", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/dashboard")

      # Open widget selector
      view |> element("#add-widget") |> render_click()

      # Select widget type
      view
      |> element("#widget-selector")
      |> render_change(%{widget: %{type: "threat_map"}})

      view |> element("#confirm-add-widget") |> render_click()

      assert has_element?(view, "[data-widget='threat_map']")
    end

    test "remove widget", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/dashboard")

      # Remove alerts widget
      view
      |> element("[data-widget='alerts'] .remove-button")
      |> render_click()

      # Confirm removal
      view |> element("#confirm-remove") |> render_click()

      refute has_element?(view, "[data-widget='alerts']")
    end
  end

  describe "dashboard filters" do
    test "filter by time range", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/dashboard")

      # Change time range
      view
      |> element("#time-range-select")
      |> render_change(%{time_range: "last_24h"})

      assert has_element?(view, ".time-range-active", "Last 24 Hours")
    end

    test "filter by severity", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      insert(:alert, severity: :critical)
      insert(:alert, severity: :low)

      {:ok, view, _html} = live(conn, "/dashboard")

      # Filter to critical only
      view
      |> element("#severity-filter")
      |> render_change(%{severities: ["critical"]})

      assert has_element?(view, ".alert-critical")
      refute has_element?(view, ".alert-low")
    end

    test "filter by agent group", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      group1 = insert(:agent_group, name: "Production")
      group2 = insert(:agent_group, name: "Development")

      agent1 = insert(:agent, group: group1)
      agent2 = insert(:agent, group: group2)

      {:ok, view, _html} = live(conn, "/dashboard")

      # Filter to production group
      view
      |> element("#group-filter")
      |> render_change(%{group_id: group1.id})

      # Should only show production agents
      assert has_element?(view, "[data-agent-id='#{agent1.id}']")
      refute has_element?(view, "[data-agent-id='#{agent2.id}']")
    end
  end

  describe "collaboration" do
    test "shows other users viewing same page", %{conn: conn} do
      user1 = insert(:user, email: "analyst1@example.com")
      user2 = insert(:user, email: "analyst2@example.com")

      conn1 = log_in_user(conn, user1)
      conn2 = log_in_user(conn, user2)

      {:ok, view1, _html} = live(conn1, "/dashboard")
      {:ok, view2, _html} = live(conn2, "/dashboard")

      # User2 should see User1's presence
      assert has_element?(view2, "[data-presence='#{user1.id}']")
      assert render(view2) =~ "analyst1@example.com"

      # User1 should see User2's presence
      assert has_element?(view1, "[data-presence='#{user2.id}']")
      assert render(view1) =~ "analyst2@example.com"
    end

    test "cursor tracking between users", %{conn: conn} do
      user1 = insert(:user)
      user2 = insert(:user)

      conn1 = log_in_user(conn, user1)
      conn2 = log_in_user(conn, user2)

      {:ok, view1, _html} = live(conn1, "/dashboard")
      {:ok, view2, _html} = live(conn2, "/dashboard")

      # User1 moves cursor
      view1
      |> render_hook("cursor_move", %{x: 100, y: 200})

      :timer.sleep(100)

      # User2 should see User1's cursor
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "dashboard:presence",
        {:cursor_move, user1.id, %{x: 100, y: 200}}
      )

      assert render(view2) =~ "data-user-cursor=\"#{user1.id}\""
    end

    test "user leaves and presence is removed", %{conn: conn} do
      user1 = insert(:user)
      user2 = insert(:user)

      conn1 = log_in_user(conn, user1)
      conn2 = log_in_user(conn, user2)

      {:ok, view1, _html} = live(conn1, "/dashboard")
      {:ok, view2, _html} = live(conn2, "/dashboard")

      assert has_element?(view1, "[data-presence='#{user2.id}']")

      # User2 disconnects
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "dashboard:presence",
        {:user_left, user2.id}
      )

      :timer.sleep(100)

      refute has_element?(view1, "[data-presence='#{user2.id}']")
    end
  end

  describe "dashboard presets" do
    test "save custom dashboard layout", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/dashboard")

      # Customize layout
      view
      |> element("[data-widget='alerts']")
      |> render_hook("drag_start", %{widget_id: "alerts"})

      view
      |> element(".grid-cell-2-2")
      |> render_hook("drop", %{widget_id: "alerts", position: %{row: 2, col: 2}})

      # Save as preset
      view |> element("#save-preset") |> render_click()

      view
      |> element("#preset-form")
      |> render_submit(%{preset: %{name: "My Custom Dashboard"}})

      assert has_element?(view, ".preset-saved", "My Custom Dashboard")
    end

    test "load saved preset", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      preset = insert(:dashboard_preset,
        user: user,
        name: "Security Operations",
        layout: %{
          widgets: [
            %{type: "alerts", position: %{row: 1, col: 1}},
            %{type: "agents", position: %{row: 1, col: 2}}
          ]
        }
      )

      {:ok, view, _html} = live(conn, "/dashboard")

      # Load preset
      view
      |> element("#preset-select")
      |> render_change(%{preset_id: preset.id})

      assert has_element?(view, ".grid-cell-1-1 [data-widget='alerts']")
      assert has_element?(view, ".grid-cell-1-2 [data-widget='agents']")
    end

    test "share preset with team", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      preset = insert(:dashboard_preset, user: user, name: "SOC Dashboard", shared: false)

      {:ok, view, _html} = live(conn, "/dashboard/presets")

      # Share preset
      view
      |> element("[data-preset-id='#{preset.id}'] .share-button")
      |> render_click()

      assert has_element?(view, ".preset-shared-badge")
    end
  end

  describe "widget configurations" do
    test "configure alert widget", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/dashboard")

      # Open widget config
      view
      |> element("[data-widget='alerts'] .config-button")
      |> render_click()

      # Change settings
      view
      |> element("#widget-config-form")
      |> render_submit(%{
        config: %{
          max_items: 10,
          severity_filter: ["critical", "high"],
          auto_refresh: true
        }
      })

      assert has_element?(view, "[data-widget='alerts'][data-max-items='10']")
    end

    test "configure chart widget", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/dashboard")

      # Open chart config
      view
      |> element("[data-widget='events_chart'] .config-button")
      |> render_click()

      # Change chart type
      view
      |> element("#widget-config-form")
      |> render_submit(%{
        config: %{
          chart_type: "line",
          time_range: "24h",
          metric: "events_per_second"
        }
      })

      assert has_element?(view, "[data-widget='events_chart'][data-chart-type='line']")
    end
  end

  describe "dashboard charts" do
    test "events timeline chart updates in real-time", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/dashboard")

      # Simulate new data point
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "telemetry:metrics",
        {:chart_update, %{
          timestamp: DateTime.utc_now(),
          events_count: 1500
        }}
      )

      :timer.sleep(100)

      assert has_element?(view, ".chart-data-point")
    end

    test "threat distribution chart", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      insert(:alert, severity: :critical, category: "malware")
      insert(:alert, severity: :high, category: "malware")
      insert(:alert, severity: :medium, category: "phishing")

      {:ok, view, _html} = live(conn, "/dashboard")

      assert has_element?(view, ".threat-chart")
      assert render(view) =~ "malware"
      assert render(view) =~ "phishing"
    end

    test "agent health distribution", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      insert(:agent, health_score: 95)
      insert(:agent, health_score: 75)
      insert(:agent, health_score: 45)

      {:ok, view, _html} = live(conn, "/dashboard")

      assert has_element?(view, ".health-chart")
    end
  end

  describe "dashboard notifications" do
    test "toast notification for critical alert", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/dashboard")

      # Create critical alert
      alert = insert(:alert, severity: :critical, title: "Active Ransomware")

      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "alerts:critical",
        {:critical_alert, alert}
      )

      :timer.sleep(100)

      assert has_element?(view, ".toast-critical", "Active Ransomware")
    end

    test "notification for agent offline", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      agent = insert(:agent, hostname: "critical-server-01")

      {:ok, view, _html} = live(conn, "/dashboard")

      # Agent goes offline
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "agents:status",
        {:agent_offline, agent}
      )

      :timer.sleep(100)

      assert has_element?(view, ".toast-warning")
      assert render(view) =~ "critical-server-01"
    end

    test "dismiss notification", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/dashboard")

      # Show notification
      send(view.pid, {:toast, %{type: :info, message: "Test notification"}})

      :timer.sleep(100)

      assert has_element?(view, ".toast")

      # Dismiss
      view |> element(".toast .dismiss-button") |> render_click()

      refute has_element?(view, ".toast")
    end
  end

  describe "dashboard search" do
    test "global search from dashboard", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      alert = insert(:alert, title: "Suspicious PowerShell Activity")
      agent = insert(:agent, hostname: "web-server-01")

      {:ok, view, _html} = live(conn, "/dashboard")

      # Search
      view
      |> element("#global-search")
      |> render_change(%{query: "powershell"})

      assert has_element?(view, ".search-result-alert")
      assert render(view) =~ "Suspicious PowerShell Activity"
    end

    test "search navigation", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)
      alert = insert(:alert, title: "Test Alert")

      {:ok, view, _html} = live(conn, "/dashboard")

      # Search
      view
      |> element("#global-search")
      |> render_change(%{query: "test"})

      # Click result
      view
      |> element(".search-result[data-alert-id='#{alert.id}']")
      |> render_click()

      # Should navigate to alert
      assert_redirect(view, "/alerts/#{alert.id}")
    end
  end

  describe "dashboard export" do
    test "export dashboard as PDF", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/dashboard")

      # Export
      view |> element("#export-pdf") |> render_click()

      assert_push_event(view, "download", %{url: url})
      assert url =~ "/dashboard/export.pdf"
    end

    test "export dashboard as image", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/dashboard")

      # Export
      view |> element("#export-image") |> render_click()

      assert_push_event(view, "download", %{url: url})
      assert url =~ "/dashboard/export.png"
    end
  end

  describe "dark mode toggle" do
    test "toggle dark mode", %{conn: conn} do
      user = insert(:user, preferences: %{theme: "light"})
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/dashboard")

      # Toggle dark mode
      view |> element("#dark-mode-toggle") |> render_click()

      assert has_element?(view, ".theme-dark")
    end

    test "dark mode preference persists", %{conn: conn} do
      user = insert(:user, preferences: %{theme: "dark"})
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/dashboard")

      assert has_element?(view, ".theme-dark")
    end
  end

  describe "keyboard shortcuts" do
    test "keyboard shortcut opens search", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/dashboard")

      # Press Ctrl+K
      view |> render_hook("keydown", %{key: "k", ctrl: true})

      assert has_element?(view, "#global-search:focus")
    end

    test "keyboard shortcut navigates widgets", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/dashboard")

      # Press Tab
      view |> render_hook("keydown", %{key: "Tab"})

      assert has_element?(view, ".widget:focus")
    end
  end
end
