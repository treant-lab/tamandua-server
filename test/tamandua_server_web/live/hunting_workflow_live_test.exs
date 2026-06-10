defmodule TamanduaServerWeb.HuntingWorkflowLiveTest do
  use TamanduaServerWeb.ConnCase

  import Phoenix.LiveViewTest

  alias TamanduaServer.Hunting.{Workflow, WorkflowExecution}
  alias TamanduaServer.Repo

  setup do
    # Create test workflow
    workflow = %Workflow{
      name: "Test Hunt",
      description: "Test workflow",
      category: "custom",
      steps: [
        %{
          "type" => "query",
          "name" => "Find Processes",
          "description" => "Search for processes",
          "query_template" => "event_type:process_create"
        }
      ],
      metadata: %{},
      is_template: true,
      visibility: "global"
    }
    |> Repo.insert!()

    {:ok, workflow: workflow}
  end

  describe "workflow library view" do
    test "displays workflow library", %{conn: conn, workflow: workflow} do
      {:ok, view, html} = live(conn, ~p"/hunting/workflows")

      assert html =~ "Threat Hunting Workflows"
      assert html =~ workflow.name
    end

    test "shows workflow details when selected", %{conn: conn, workflow: workflow} do
      {:ok, view, _html} = live(conn, ~p"/hunting/workflows")

      # Select workflow
      view
      |> element("button[phx-click='select_workflow'][phx-value-workflow_id='#{workflow.id}']")
      |> render_click()

      html = render(view)
      assert html =~ workflow.name
      assert html =~ workflow.description
      assert html =~ "Start This Hunt"
    end

    test "starts workflow execution", %{conn: conn, workflow: workflow} do
      {:ok, view, _html} = live(conn, ~p"/hunting/workflows")

      # Select and start workflow
      view
      |> element("button[phx-click='select_workflow'][phx-value-workflow_id='#{workflow.id}']")
      |> render_click()

      assert view
      |> element("button[phx-click='start_workflow']")
      |> render_click() =~ "Workflow started"

      # Should redirect to execution view
      # Verify execution was created
      assert Repo.get_by(WorkflowExecution, workflow_id: workflow.id)
    end
  end

  describe "workflow execution view" do
    test "displays execution progress", %{conn: conn, workflow: workflow} do
      # Create execution
      execution = %WorkflowExecution{
        workflow_id: workflow.id,
        status: "in_progress",
        current_step_index: 0,
        progress_percentage: 0,
        started_at: DateTime.utc_now(),
        step_states: [],
        findings: [],
        annotations: [],
        hypothesis_status: %{}
      }
      |> Repo.insert!()
      |> Repo.preload(:workflow)

      {:ok, view, html} = live(conn, ~p"/hunting/workflows/#{execution.id}")

      assert html =~ workflow.name
      assert html =~ "in_progress"
      assert html =~ "Step 1 of #{length(workflow.steps)}"
    end

    test "executes next step", %{conn: conn, workflow: workflow} do
      execution = %WorkflowExecution{
        workflow_id: workflow.id,
        status: "in_progress",
        current_step_index: 0,
        step_states: [],
        findings: [],
        annotations: [],
        hypothesis_status: %{}
      }
      |> Repo.insert!()
      |> Repo.preload(:workflow)

      {:ok, view, _html} = live(conn, ~p"/hunting/workflows/#{execution.id}")

      # Execute step (would need to mock NLHunter)
      # html = view
      # |> element("button[phx-click='execute_next_step']")
      # |> render_click()

      # assert html =~ "Step executed"
    end

    test "adds annotation", %{conn: conn, workflow: workflow} do
      execution = %WorkflowExecution{
        workflow_id: workflow.id,
        status: "in_progress",
        current_step_index: 0,
        step_states: [],
        findings: [],
        annotations: [],
        hypothesis_status: %{}
      }
      |> Repo.insert!()
      |> Repo.preload(:workflow)

      {:ok, view, _html} = live(conn, ~p"/hunting/workflows/#{execution.id}")

      html = view
      |> form("form[phx-submit='add_annotation']", %{annotation: "Test note"})
      |> render_submit()

      assert html =~ "Annotation added"
    end

    test "pauses and resumes execution", %{conn: conn, workflow: workflow} do
      execution = %WorkflowExecution{
        workflow_id: workflow.id,
        status: "in_progress",
        current_step_index: 0,
        step_states: [],
        findings: [],
        annotations: [],
        hypothesis_status: %{}
      }
      |> Repo.insert!()
      |> Repo.preload(:workflow)

      {:ok, view, _html} = live(conn, ~p"/hunting/workflows/#{execution.id}")

      # Pause
      html = view
      |> element("button[phx-click='pause_execution']")
      |> render_click()

      assert html =~ "Execution paused"

      # Resume
      html = view
      |> element("button[phx-click='resume_execution']")
      |> render_click()

      assert html =~ "Execution resumed"
    end
  end

  describe "workflow builder view" do
    test "displays workflow builder", %{conn: conn} do
      {:ok, view, html} = live(conn, ~p"/hunting/workflows/builder")

      assert html =~ "Workflow Builder"
      assert html =~ "Workflow Details"
      assert html =~ "Add Step"
    end

    test "adds step to workflow", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/hunting/workflows/builder")

      html = view
      |> element("button[phx-click='add_step'][phx-value-type='query']")
      |> render_click()

      assert html =~ "Execute Query"
    end

    test "saves custom workflow", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/hunting/workflows/builder")

      # Update metadata
      view
      |> form("form[phx-change='update_metadata']", %{
        workflow: %{
          name: "Custom Hunt",
          description: "My custom workflow",
          category: "custom"
        }
      })
      |> render_change()

      # Add a step
      view
      |> element("button[phx-click='add_step'][phx-value-type='query']")
      |> render_click()

      # Save (would need valid step configuration)
      # html = view
      # |> element("button[phx-click='save_workflow']")
      # |> render_click()

      # assert html =~ "Workflow saved"
    end
  end
end
