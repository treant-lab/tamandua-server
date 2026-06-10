defmodule TamanduaServer.E2E.DashboardTest do
  @moduledoc """
  E2E tests for dashboard functionality.

  Tests cover:
  - Dashboard widgets and visualization
  - Real-time updates
  - Customization and layout
  - Data refresh
  - Widget interactions
  - Performance metrics display
  """

  use TamanduaServer.E2ECase, async: false

  alias Wallaby.Query

  setup %{session: session} do
    org = insert(:organization)
    user = insert(:user, organization_id: org.id, role: "analyst")
    agents = insert_list(10, :agent, organization_id: org.id)
    alerts = insert_list(20, :alert, organization_id: org.id, agent: hd(agents))

    session = login_user(session, user)
    {:ok, session: session, user: user, org: org, agents: agents, alerts: alerts}
  end

  describe "dashboard landing page" do
    test "displays main dashboard after login", %{session: session} do
      session
      |> visit("/dashboard")
      |> assert_has(Query.css("[data-page='dashboard']"))
      |> assert_has(Query.css(".dashboard-header, [data-dashboard-header]"))
    end

    test "shows welcome message with user name", %{session: session, user: user} do
      session
      |> visit("/dashboard")
      |> assert_has(Query.text("Welcome, #{user.name}"))
    end

    test "displays current date and time", %{session: session} do
      session
      |> visit("/dashboard")
      |> assert_has(Query.css("[data-current-datetime]"))
    end

    test "shows organization name", %{session: session, org: org} do
      session
      |> visit("/dashboard")
      |> assert_has(Query.text(org.name))
    end
  end

  describe "agent status widget" do
    test "displays agent status counts", %{session: session, agents: agents} do
      # Update some agents to different statuses
      Enum.at(agents, 0) |> Ecto.Changeset.change(%{status: "online"}) |> Repo.update!()
      Enum.at(agents, 1) |> Ecto.Changeset.change(%{status: "offline"}) |> Repo.update!()
      Enum.at(agents, 2) |> Ecto.Changeset.change(%{status: "isolated"}) |> Repo.update!()

      session
      |> visit("/dashboard")
      |> assert_has(Query.css("[data-widget='agent-status']"))
      |> assert_has(Query.css("[data-status='online']"))
      |> assert_has(Query.css("[data-status='offline']"))
      |> assert_has(Query.css("[data-status='isolated']"))
    end

    test "agent status widget updates in real-time", %{session: session, agents: agents} do
      session
      |> visit("/dashboard")
      |> assert_has(Query.css("[data-widget='agent-status']"))

      # Simulate agent status change
      agent = Enum.at(agents, 0)
      agent |> Ecto.Changeset.change(%{status: "offline"}) |> Repo.update!()

      # Wait for LiveView to update
      session
      |> wait_for_live_view_event("agent_status_updated")
      |> assert_has(Query.css("[data-status='offline']"))
    end

    test "clicking agent status opens agent list filtered by status", %{session: session} do
      session
      |> visit("/dashboard")
      |> click(Query.css("[data-widget='agent-status'] [data-status='online']"))
      |> assert_current_path("/agents?status=online")
    end

    test "displays agent count by platform", %{session: session} do
      session
      |> visit("/dashboard")
      |> assert_has(Query.css("[data-platform-stats]"))
      |> assert_has(Query.css("[data-platform='windows']"))
      |> assert_has(Query.css("[data-platform='linux']"))
      |> assert_has(Query.css("[data-platform='macos']"))
    end
  end

  describe "alert summary widget" do
    test "displays alert counts by severity", %{session: session} do
      session
      |> visit("/dashboard")
      |> assert_has(Query.css("[data-widget='alert-summary']"))
      |> assert_has(Query.css("[data-severity='critical']"))
      |> assert_has(Query.css("[data-severity='high']"))
      |> assert_has(Query.css("[data-severity='medium']"))
      |> assert_has(Query.css("[data-severity='low']"))
    end

    test "displays new vs investigating vs resolved alerts", %{session: session} do
      session
      |> visit("/dashboard")
      |> assert_has(Query.css("[data-alert-status='new']"))
      |> assert_has(Query.css("[data-alert-status='investigating']"))
      |> assert_has(Query.css("[data-alert-status='resolved']"))
    end

    test "clicking severity opens alerts filtered by severity", %{session: session} do
      session
      |> visit("/dashboard")
      |> click(Query.css("[data-widget='alert-summary'] [data-severity='critical']"))
      |> assert_current_path("/alerts?severity=critical")
    end

    test "shows unassigned alerts count", %{session: session} do
      session
      |> visit("/dashboard")
      |> assert_has(Query.css("[data-unassigned-alerts]"))
    end
  end

  describe "alert trend chart" do
    test "renders alert trend chart canvas", %{session: session} do
      session
      |> visit("/dashboard")
      |> assert_has(Query.css("[data-widget='alert-trend']"))
      |> assert_has(Query.css("[data-widget='alert-trend'] canvas"))
    end

    test "chart shows last 7 days by default", %{session: session} do
      session
      |> visit("/dashboard")
      |> assert_has(Query.css("[data-chart-timerange='7d']", class: "active"))
    end

    test "can change chart timerange", %{session: session} do
      session
      |> visit("/dashboard")
      |> click(Query.css("[data-chart-timerange='24h']"))
      |> wait_for_ajax()
      |> assert_has(Query.css("[data-chart-timerange='24h']", class: "active"))
    end

    test "can toggle between line and bar chart", %{session: session} do
      session
      |> visit("/dashboard")
      |> click(Query.css("[data-chart-type='bar']"))
      |> assert_has(Query.css("[data-current-chart-type='bar']"))
    end

    test "chart legend is interactive", %{session: session} do
      session
      |> visit("/dashboard")
      |> click(Query.css("[data-legend-item='critical']"))
      # Legend item should toggle visibility
      |> assert_has(Query.css("[data-legend-item='critical'][data-hidden='true']"))
    end
  end

  describe "recent alerts widget" do
    test "displays list of recent alerts", %{session: session, alerts: alerts} do
      session
      |> visit("/dashboard")
      |> assert_has(Query.css("[data-widget='recent-alerts']"))
      |> assert_has(Query.css("[data-alert-item]", minimum: 5))
    end

    test "recent alerts show severity badges", %{session: session} do
      session
      |> visit("/dashboard")
      |> assert_has(Query.css("[data-alert-item] [data-severity-badge]"))
    end

    test "recent alerts show relative time", %{session: session} do
      session
      |> visit("/dashboard")
      |> assert_has(Query.css("[data-alert-item] [data-relative-time]"))
    end

    test "clicking alert opens alert detail page", %{session: session, alerts: alerts} do
      alert = hd(alerts)

      session
      |> visit("/dashboard")
      |> click(Query.css("[data-alert-id='#{alert.id}']"))
      |> assert_current_path("/alerts/#{alert.id}")
    end

    test "can quick-assign alert from widget", %{session: session, alerts: alerts} do
      alert = hd(alerts)

      session
      |> visit("/dashboard")
      |> hover(Query.css("[data-alert-id='#{alert.id}']"))
      |> click(Query.css("[data-alert-id='#{alert.id}'] [data-action='quick-assign']"))
      |> assert_success("Alert assigned to you")
    end
  end

  describe "MITRE ATT&CK coverage widget" do
    test "displays MITRE heatmap", %{session: session} do
      session
      |> visit("/dashboard")
      |> assert_has(Query.css("[data-widget='mitre-coverage']"))
      |> assert_has(Query.css("[data-mitre-heatmap]"))
    end

    test "heatmap shows tactics and techniques", %{session: session} do
      session
      |> visit("/dashboard")
      |> assert_has(Query.css("[data-tactic]", minimum: 1))
      |> assert_has(Query.css("[data-technique]", minimum: 1))
    end

    test "hovering technique shows alert count", %{session: session} do
      session
      |> visit("/dashboard")
      |> hover(Query.css("[data-technique='T1059']"))
      |> assert_has(Query.css("[data-tooltip]"))
    end

    test "clicking technique filters alerts by technique", %{session: session} do
      session
      |> visit("/dashboard")
      |> click(Query.css("[data-technique='T1059']"))
      |> assert_current_path("/alerts?technique=T1059")
    end
  end

  describe "threat score gauge" do
    test "displays organization threat score", %{session: session} do
      session
      |> visit("/dashboard")
      |> assert_has(Query.css("[data-widget='threat-score']"))
      |> assert_has(Query.css("[data-score-value]"))
    end

    test "threat score gauge changes color based on value", %{session: session} do
      session
      |> visit("/dashboard")
      |> assert_has(Query.css("[data-widget='threat-score'][data-score-level]"))
    end

    test "shows threat score trend", %{session: session} do
      session
      |> visit("/dashboard")
      |> assert_has(Query.css("[data-score-trend]"))
    end
  end

  describe "top targeted agents widget" do
    test "displays agents with most alerts", %{session: session} do
      session
      |> visit("/dashboard")
      |> assert_has(Query.css("[data-widget='top-agents']"))
      |> assert_has(Query.css("[data-agent-item]", minimum: 1))
    end

    test "shows alert count per agent", %{session: session} do
      session
      |> visit("/dashboard")
      |> assert_has(Query.css("[data-agent-item] [data-alert-count]"))
    end

    test "clicking agent opens agent detail page", %{session: session, agents: agents} do
      agent = hd(agents)

      session
      |> visit("/dashboard")
      |> click(Query.css("[data-agent-id='#{agent.id}']"))
      |> assert_current_path("/agents/#{agent.id}")
    end
  end

  describe "dashboard customization" do
    test "can enter customization mode", %{session: session} do
      session
      |> visit("/dashboard")
      |> click(Query.button("Customize Dashboard"))
      |> assert_has(Query.css("[data-mode='customize']"))
      |> assert_has(Query.css("[draggable='true']"))
    end

    test "can drag and drop widgets", %{session: session} do
      session
      |> visit("/dashboard")
      |> click(Query.button("Customize Dashboard"))
      |> drag_and_drop(
        Query.css("[data-widget='alert-summary']"),
        Query.css(".grid-cell-0-0")
      )
      |> assert_has(Query.css(".grid-cell-0-0 [data-widget='alert-summary']"))
    end

    test "can save custom layout", %{session: session} do
      session
      |> visit("/dashboard")
      |> click(Query.button("Customize Dashboard"))
      |> drag_and_drop(
        Query.css("[data-widget='alert-summary']"),
        Query.css(".grid-cell-0-0")
      )
      |> click(Query.button("Save Layout"))
      |> assert_success("Dashboard layout saved")
    end

    test "can reset to default layout", %{session: session} do
      session
      |> visit("/dashboard")
      |> click(Query.button("Customize Dashboard"))
      |> click(Query.button("Reset to Default"))
      |> assert_has(Query.css("[data-confirm-modal]"))
      |> click(Query.button("Confirm"))
      |> assert_success("Dashboard reset to default")
    end

    test "can hide widgets", %{session: session} do
      session
      |> visit("/dashboard")
      |> click(Query.button("Customize Dashboard"))
      |> click(Query.css("[data-widget='alert-summary'] [data-action='hide']"))
      |> refute_has(Query.css("[data-widget='alert-summary']", visible: true))
    end

    test "can show hidden widgets", %{session: session} do
      session
      |> visit("/dashboard")
      |> click(Query.button("Customize Dashboard"))
      |> click(Query.button("Add Widget"))
      |> click(Query.css("[data-widget-option='alert-summary']"))
      |> assert_has(Query.css("[data-widget='alert-summary']", visible: true))
    end

    test "layout persists across sessions", %{session: session, user: user} do
      # Customize layout
      session
      |> visit("/dashboard")
      |> click(Query.button("Customize Dashboard"))
      |> drag_and_drop(
        Query.css("[data-widget='alert-summary']"),
        Query.css(".grid-cell-0-0")
      )
      |> click(Query.button("Save Layout"))

      # Logout and login again
      session
      |> logout()
      |> login_user(user)
      |> visit("/dashboard")
      # Layout should be preserved
      |> assert_has(Query.css(".grid-cell-0-0 [data-widget='alert-summary']"))
    end
  end

  describe "real-time updates" do
    test "dashboard shows live update indicator", %{session: session} do
      session
      |> visit("/dashboard")
      |> assert_has(Query.css("[data-live-indicator]"))
    end

    test "new alerts appear automatically", %{session: session, org: org, agents: agents} do
      session
      |> visit("/dashboard")

      # Create new alert
      insert(:alert,
        organization_id: org.id,
        agent: hd(agents),
        severity: "critical",
        title: "New Real-time Alert"
      )

      # Should appear in dashboard
      session
      |> wait_for(Query.text("New Real-time Alert"))
      |> assert_has(Query.css("[data-alert-item]", text: "New Real-time Alert"))
    end

    test "agent status updates in real-time", %{session: session, agents: agents} do
      agent = hd(agents)

      session
      |> visit("/dashboard")

      # Update agent status
      agent |> Ecto.Changeset.change(%{status: "offline"}) |> Repo.update!()

      # Dashboard should reflect change
      session
      |> wait_for_live_view_event("agent_status_updated")
    end

    test "can pause real-time updates", %{session: session} do
      session
      |> visit("/dashboard")
      |> click(Query.css("[data-action='pause-updates']"))
      |> assert_has(Query.css("[data-live-status='paused']"))
    end

    test "can resume real-time updates", %{session: session} do
      session
      |> visit("/dashboard")
      |> click(Query.css("[data-action='pause-updates']"))
      |> click(Query.css("[data-action='resume-updates']"))
      |> assert_has(Query.css("[data-live-status='active']"))
    end
  end

  describe "data refresh" do
    test "can manually refresh dashboard data", %{session: session} do
      session
      |> visit("/dashboard")
      |> click(Query.button("Refresh"))
      |> wait_for_ajax()
      |> assert_success("Dashboard refreshed")
    end

    test "shows last updated timestamp", %{session: session} do
      session
      |> visit("/dashboard")
      |> assert_has(Query.css("[data-last-updated]"))
    end

    test "auto-refresh can be configured", %{session: session} do
      session
      |> visit("/dashboard")
      |> click(Query.css("[data-settings-toggle]"))
      |> select_by_label("Auto-refresh interval", "30 seconds")
      |> click(Query.button("Save Settings"))
      |> assert_success("Settings saved")
    end
  end

  describe "dashboard filters" do
    test "can filter dashboard by time range", %{session: session} do
      session
      |> visit("/dashboard")
      |> select_by_label("Time Range", "Last 24 hours")
      |> wait_for_ajax()
      |> assert_has(Query.css("[data-timerange='24h']"))
    end

    test "can filter by agent group", %{session: session} do
      session
      |> visit("/dashboard")
      |> select_by_label("Agent Group", "Production")
      |> wait_for_ajax()
    end

    test "filters apply to all widgets", %{session: session} do
      session
      |> visit("/dashboard")
      |> select_by_label("Time Range", "Last 24 hours")
      |> wait_for_ajax()
      # All widgets should update
      |> assert_has(Query.css("[data-widget][data-filtered='true']"))
    end
  end

  describe "dashboard export" do
    test "can export dashboard as PDF", %{session: session} do
      session
      |> visit("/dashboard")
      |> click(Query.css("[data-action='export']"))
      |> click(Query.css("[data-export-format='pdf']"))
      |> wait_for_notification("Export started")
    end

    test "can export dashboard as image", %{session: session} do
      session
      |> visit("/dashboard")
      |> click(Query.css("[data-action='export']"))
      |> click(Query.css("[data-export-format='png']"))
      |> wait_for_notification("Export started")
    end

    test "can schedule dashboard report", %{session: session} do
      session
      |> visit("/dashboard")
      |> click(Query.css("[data-action='schedule-report']"))
      |> select_by_label("Frequency", "Daily")
      |> fill_in(Query.text_field("Email"), with: "reports@example.com")
      |> click(Query.button("Schedule"))
      |> assert_success("Report scheduled successfully")
    end
  end
end
