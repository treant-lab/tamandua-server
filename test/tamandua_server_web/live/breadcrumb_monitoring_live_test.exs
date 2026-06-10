defmodule TamanduaServerWeb.BreadcrumbMonitoringLiveTest do
  use TamanduaServerWeb.ConnCase

  import Phoenix.LiveViewTest
  import TamanduaServer.DeceptionFixtures

  alias TamanduaServer.Repo
  alias TamanduaServer.Deception.{BreadcrumbDeployment, BreadcrumbAccessLog}

  describe "Monitoring Dashboard" do
    setup do
      # Create test breadcrumbs
      breadcrumb1 = breadcrumb_deployment_fixture(%{
        type: "credential",
        agent_id: "agent-1",
        path: "/home/user/.config/creds.txt",
        status: "active"
      })

      breadcrumb2 = breadcrumb_deployment_fixture(%{
        type: "ssh_key",
        agent_id: "agent-2",
        path: "/home/user/.ssh/id_rsa",
        status: "accessed",
        access_count: 3
      })

      # Create access log for breadcrumb2
      access_log = breadcrumb_access_log_fixture(%{
        breadcrumb_id: breadcrumb2.id,
        agent_id: "agent-2",
        process_name: "cat",
        pid: 1234,
        user: "attacker",
        access_type: "read"
      })

      %{breadcrumbs: [breadcrumb1, breadcrumb2], access_log: access_log}
    end

    test "displays monitoring dashboard", %{conn: conn} do
      {:ok, _view, html} = live(conn, ~p"/breadcrumbs/monitor")

      assert html =~ "Breadcrumb Monitor"
      assert html =~ "Total Deployed"
      assert html =~ "Active"
      assert html =~ "Accessed"
      assert html =~ "Effectiveness"
    end

    test "lists deployed breadcrumbs", %{conn: conn, breadcrumbs: breadcrumbs} do
      {:ok, _view, html} = live(conn, ~p"/breadcrumbs/monitor")

      assert html =~ "Deployed Breadcrumbs"
      assert html =~ "Credential"
      assert html =~ "Ssh Key"
    end

    test "switches between grid and list view", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/breadcrumbs/monitor")

      # Switch to list view
      html =
        view
        |> element("button[phx-click='set_view_mode'][phx-value-mode='list']")
        |> render_click()

      assert html =~ "<table"
      assert html =~ "Type"
      assert html =~ "Path"

      # Switch back to grid view
      html =
        view
        |> element("button[phx-click='set_view_mode'][phx-value-mode='grid']")
        |> render_click()

      refute html =~ "<table"
    end

    test "filters breadcrumbs by status", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/breadcrumbs/monitor")

      # Filter by accessed status
      html =
        view
        |> element("select[name='status']")
        |> render_change(%{"status" => "accessed"})

      assert html =~ "Ssh Key"
      refute html =~ "Credential"
    end

    test "filters breadcrumbs by type", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/breadcrumbs/monitor")

      # Filter by credential type
      html =
        view
        |> element("select[name='type']")
        |> render_change(%{"type" => "credential"})

      assert html =~ "Credential"
      refute html =~ "Ssh Key"
    end

    test "searches breadcrumbs", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/breadcrumbs/monitor")

      # Search for ssh
      html =
        view
        |> element("input[name='query']")
        |> render_change(%{"query" => "ssh"})

      assert html =~ "id_rsa"
    end

    test "displays breadcrumb detail modal", %{conn: conn, breadcrumbs: breadcrumbs} do
      breadcrumb = List.first(breadcrumbs)

      {:ok, _view, html} = live(conn, ~p"/breadcrumbs/monitor?id=#{breadcrumb.id}")

      assert html =~ "Breadcrumb Details"
      assert html =~ "Credential"
      assert html =~ breadcrumb.path
      assert html =~ breadcrumb.canary_token
    end

    test "closes detail modal", %{conn: conn, breadcrumbs: breadcrumbs} do
      breadcrumb = List.first(breadcrumbs)

      {:ok, view, _html} = live(conn, ~p"/breadcrumbs/monitor?id=#{breadcrumb.id}")

      {:ok, _view, html} =
        view
        |> element("button[phx-click='close_detail_modal']")
        |> render_click()
        |> follow_redirect(conn)

      refute html =~ "Breadcrumb Details"
    end

    test "displays access history in detail modal", %{conn: conn, breadcrumbs: breadcrumbs} do
      breadcrumb = Enum.find(breadcrumbs, &(&1.status == "accessed"))

      {:ok, _view, html} = live(conn, ~p"/breadcrumbs/monitor?id=#{breadcrumb.id}")

      assert html =~ "Access History"
      assert html =~ "cat"
      assert html =~ "attacker"
      assert html =~ "1234"
    end

    test "displays recent alerts", %{conn: conn} do
      # Create a breadcrumb alert
      alert_fixture(%{
        title: "Honeyfile Accessed: Credential",
        severity: "high",
        detection_metadata: %{
          "detection_type" => "honeypot",
          "breadcrumb_id" => "test-id"
        }
      })

      {:ok, _view, html} = live(conn, ~p"/breadcrumbs/monitor")

      assert html =~ "Recent Alerts"
      assert html =~ "Honeyfile Accessed: Credential"
    end

    test "displays access timeline", %{conn: conn, access_log: _access_log} do
      {:ok, _view, html} = live(conn, ~p"/breadcrumbs/monitor")

      assert html =~ "Access Timeline"
      assert html =~ "cat"
      assert html =~ "accessed breadcrumb"
    end

    test "changes access timeline time range", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/breadcrumbs/monitor")

      html =
        view
        |> element("select[name='range']")
        |> render_change(%{"range" => "last_7d"})

      assert html =~ "Access Timeline"
    end

    test "displays effectiveness by type", %{conn: conn} do
      {:ok, _view, html} = live(conn, ~p"/breadcrumbs/monitor")

      assert html =~ "Effectiveness by Type"
    end

    test "refreshes dashboard", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/breadcrumbs/monitor")

      html =
        view
        |> element("button[phx-click='refresh']")
        |> render_click()

      assert html =~ "Breadcrumb Monitor"
    end

    test "navigates to deploy new breadcrumb", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/breadcrumbs/monitor")

      {:ok, _deploy_view, html} =
        view
        |> element("a", "Deploy New")
        |> render_click()
        |> follow_redirect(conn)

      assert html =~ "Breadcrumb Gallery"
    end

    test "sorts breadcrumbs by column", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/breadcrumbs/monitor")

      # Switch to list view first
      view
      |> element("button[phx-click='set_view_mode'][phx-value-mode='list']")
      |> render_click()

      # Sort by type
      html =
        view
        |> element("th[phx-click='sort'][phx-value-by='type']")
        |> render_click()

      assert html =~ "Credential"
    end

    test "shows delete confirmation modal", %{conn: conn, breadcrumbs: breadcrumbs} do
      breadcrumb = List.first(breadcrumbs)

      {:ok, view, _html} = live(conn, ~p"/breadcrumbs/monitor?id=#{breadcrumb.id}")

      html =
        view
        |> element("button[phx-click='confirm_delete'][phx-value-id='#{breadcrumb.id}']")
        |> render_click()

      assert html =~ "Remove Breadcrumb"
      assert html =~ "Are you sure"
    end

    test "deletes breadcrumb", %{conn: conn, breadcrumbs: breadcrumbs} do
      breadcrumb = List.first(breadcrumbs)

      {:ok, view, _html} = live(conn, ~p"/breadcrumbs/monitor?id=#{breadcrumb.id}")

      # Open delete confirmation
      view
      |> element("button[phx-click='confirm_delete'][phx-value-id='#{breadcrumb.id}']")
      |> render_click()

      # Confirm deletion
      html =
        view
        |> element("button[phx-click='delete_breadcrumb']")
        |> render_click()

      assert html =~ "marked as removed"

      # Verify status changed
      updated = Repo.get(BreadcrumbDeployment, breadcrumb.id)
      assert updated.status == "removed"
    end

    test "cancels breadcrumb deletion", %{conn: conn, breadcrumbs: breadcrumbs} do
      breadcrumb = List.first(breadcrumbs)

      {:ok, view, _html} = live(conn, ~p"/breadcrumbs/monitor?id=#{breadcrumb.id}")

      # Open delete confirmation
      view
      |> element("button[phx-click='confirm_delete'][phx-value-id='#{breadcrumb.id}']")
      |> render_click()

      # Cancel deletion
      html =
        view
        |> element("button[phx-click='cancel_delete']")
        |> render_click()

      refute html =~ "Remove Breadcrumb"
    end

    test "receives real-time breadcrumb access notification", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/breadcrumbs/monitor")

      # Simulate breadcrumb access event
      send(
        view.pid,
        {:breadcrumb_access, "Breadcrumb accessed",
         %{breadcrumb_id: "test-id", agent_id: "agent-1"}}
      )

      html = render(view)
      assert html =~ "Breadcrumb Access Detected"
    end
  end

  describe "Empty State" do
    test "displays empty state when no breadcrumbs deployed", %{conn: conn} do
      # Clear all breadcrumbs
      Repo.delete_all(BreadcrumbDeployment)

      {:ok, _view, html} = live(conn, ~p"/breadcrumbs/monitor")

      assert html =~ "No breadcrumbs deployed"
      assert html =~ "Get started by deploying your first breadcrumb"
    end
  end
end
