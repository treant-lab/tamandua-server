defmodule TamanduaServerWeb.BreadcrumbDeploymentLiveTest do
  use TamanduaServerWeb.ConnCase

  import Phoenix.LiveViewTest
  import TamanduaServer.DeceptionFixtures
  import TamanduaServer.AgentsFixtures

  describe "Deployment Wizard" do
    setup do
      # Create test agents
      agent1 = agent_fixture(%{hostname: "test-agent-1", os_type: "linux", status: "online"})
      agent2 = agent_fixture(%{hostname: "test-agent-2", os_type: "windows", status: "online"})

      %{agents: [agent1, agent2]}
    end

    test "displays deployment wizard steps", %{conn: conn} do
      {:ok, _view, html} = live(conn, ~p"/breadcrumbs/deploy")

      assert html =~ "Deploy Breadcrumb"
      assert html =~ "Step 1: Select Breadcrumb Type"
      assert html =~ "Select Type"
      assert html =~ "Customize"
      assert html =~ "Target Agents"
      assert html =~ "Configuration"
      assert html =~ "Review & Deploy"
    end

    test "navigates through wizard steps", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/breadcrumbs/deploy")

      # Step 1: Select type
      assert render(view) =~ "Step 1: Select Breadcrumb Type"

      # Go to next step
      view
      |> element("button[phx-click='next_step']")
      |> render_click()

      assert render(view) =~ "Step 2: Customize Content"

      # Go to next step
      view
      |> element("button[phx-click='next_step']")
      |> render_click()

      assert render(view) =~ "Step 3: Select Target Agents"
    end

    test "selects breadcrumb type", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/breadcrumbs/deploy?type=ssh_key")

      assert render(view) =~ "SSH Private Key"

      # Change type
      html =
        view
        |> element("button[phx-click='select_type'][phx-value-type='api_token']")
        |> render_click()

      assert html =~ "API Tokens"
    end

    test "customizes breadcrumb content", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/breadcrumbs/deploy")

      # Go to customization step
      view
      |> element("button[phx-click='next_step']")
      |> render_click()

      # Update filename
      html =
        view
        |> element("input[name='filename']")
        |> render_change(%{"filename" => "custom_credentials"})

      assert html =~ "custom_credentials"
    end

    test "selects target agents", %{conn: conn, agents: agents} do
      {:ok, view, _html} = live(conn, ~p"/breadcrumbs/deploy")

      # Navigate to agent selection
      view |> element("button[phx-click='next_step']") |> render_click()
      view |> element("button[phx-click='next_step']") |> render_click()

      assert render(view) =~ "Step 3: Select Target Agents"
      assert render(view) =~ "test-agent-1"
      assert render(view) =~ "test-agent-2"

      # Select first agent
      view
      |> element("input[type='checkbox'][phx-value-agent_id='#{List.first(agents).id}']")
      |> render_click()

      assert render(view) =~ "1 of"
    end

    test "selects all agents", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/breadcrumbs/deploy")

      # Navigate to agent selection
      view |> element("button[phx-click='next_step']") |> render_click()
      view |> element("button[phx-click='next_step']") |> render_click()

      # Select all
      view
      |> element("button[phx-click='select_all_agents']")
      |> render_click()

      html = render(view)
      assert html =~ "of"
    end

    test "filters agents by status", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/breadcrumbs/deploy")

      # Navigate to agent selection
      view |> element("button[phx-click='next_step']") |> render_click()
      view |> element("button[phx-click='next_step']") |> render_click()

      # Filter by online status
      html =
        view
        |> element("select[name='status']")
        |> render_change(%{"status" => "online"})

      assert html =~ "test-agent-1"
      assert html =~ "test-agent-2"
    end

    test "searches agents", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/breadcrumbs/deploy")

      # Navigate to agent selection
      view |> element("button[phx-click='next_step']") |> render_click()
      view |> element("button[phx-click='next_step']") |> render_click()

      # Search for specific agent
      html =
        view
        |> element("input[name='query']")
        |> render_change(%{"query" => "agent-1"})

      assert html =~ "test-agent-1"
      refute html =~ "test-agent-2"
    end

    test "configures deployment density", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/breadcrumbs/deploy")

      # Navigate to configuration step
      view |> element("button[phx-click='next_step']") |> render_click()
      view |> element("button[phx-click='next_step']") |> render_click()
      view |> element("button[phx-click='next_step']") |> render_click()

      assert render(view) =~ "Step 4: Deployment Configuration"

      # Set high density
      html =
        view
        |> element("button[phx-click='set_density'][phx-value-density='high']")
        |> render_click()

      assert html =~ "12 variants"
    end

    test "enables rotation schedule", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/breadcrumbs/deploy")

      # Navigate to configuration step
      view |> element("button[phx-click='next_step']") |> render_click()
      view |> element("button[phx-click='next_step']") |> render_click()
      view |> element("button[phx-click='next_step']") |> render_click()

      # Enable rotation
      html =
        view
        |> element("input[type='checkbox'][name='enabled']")
        |> render_change(%{"enabled" => "true"})

      assert html =~ "Rotation Interval"
    end

    test "reviews deployment configuration", %{conn: conn, agents: agents} do
      {:ok, view, _html} = live(conn, ~p"/breadcrumbs/deploy")

      # Navigate through all steps
      view |> element("button[phx-click='next_step']") |> render_click()
      view |> element("button[phx-click='next_step']") |> render_click()

      # Select agent
      view
      |> element("input[type='checkbox'][phx-value-agent_id='#{List.first(agents).id}']")
      |> render_click()

      view |> element("button[phx-click='next_step']") |> render_click()
      view |> element("button[phx-click='next_step']") |> render_click()

      assert render(view) =~ "Step 5: Review & Deploy"
      assert render(view) =~ "Deployment Summary"
      assert render(view) =~ "Breadcrumb Type"
      assert render(view) =~ "Number of Agents"
    end

    test "cancels deployment", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/breadcrumbs/deploy")

      {:ok, _index_live, html} =
        view
        |> element("button[phx-click='cancel']")
        |> render_click()
        |> follow_redirect(conn)

      assert html =~ "Breadcrumb Gallery"
    end

    test "goes back to previous step", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/breadcrumbs/deploy")

      # Go to step 2
      view |> element("button[phx-click='next_step']") |> render_click()
      assert render(view) =~ "Step 2: Customize Content"

      # Go back to step 1
      view |> element("button[phx-click='prev_step']") |> render_click()
      assert render(view) =~ "Step 1: Select Breadcrumb Type"
    end

    test "jumps to specific step by clicking progress", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/breadcrumbs/deploy")

      # Go to step 2 first
      view |> element("button[phx-click='next_step']") |> render_click()

      # Jump to step 1 by clicking progress
      view
      |> element("button[phx-click='go_to_step'][phx-value-step='1']")
      |> render_click()

      assert render(view) =~ "Step 1: Select Breadcrumb Type"
    end
  end
end
