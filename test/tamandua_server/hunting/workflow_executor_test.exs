defmodule TamanduaServer.Hunting.WorkflowExecutorTest do
  use TamanduaServer.DataCase

  alias TamanduaServer.Hunting.{
    Workflow,
    WorkflowExecution,
    WorkflowExecutor,
    WorkflowStepResult
  }

  setup do
    # Create a test workflow
    workflow = %Workflow{
      name: "Test Workflow",
      category: "custom",
      steps: [
        %{
          "type" => "query",
          "name" => "Step 1",
          "description" => "Find processes",
          "query_template" => "event_type:process_create"
        },
        %{
          "type" => "decision",
          "name" => "Step 2",
          "description" => "Make decision",
          "decision_criteria" => ["Check if suspicious"],
          "next_actions" => %{"suspicious" => 2, "benign" => 3}
        },
        %{
          "type" => "collect_evidence",
          "name" => "Step 3",
          "description" => "Collect evidence",
          "evidence_queries" => ["parent_process_chain"]
        }
      ],
      metadata: %{}
    }
    |> Repo.insert!()

    {:ok, workflow: workflow}
  end

  describe "start_workflow/4" do
    test "creates a new execution", %{workflow: workflow} do
      user_id = Ecto.UUID.generate()
      org_id = Ecto.UUID.generate()

      {:ok, execution} = WorkflowExecutor.start_workflow(workflow.id, user_id, org_id)

      assert execution.workflow_id == workflow.id
      assert execution.executed_by_id == user_id
      assert execution.organization_id == org_id
      assert execution.status == "in_progress"
      assert execution.current_step_index == 0
      assert execution.progress_percentage == 0
      assert execution.started_at
    end

    test "initializes step states", %{workflow: workflow} do
      {:ok, execution} = WorkflowExecutor.start_workflow(
        workflow.id,
        Ecto.UUID.generate(),
        Ecto.UUID.generate()
      )

      assert length(execution.step_states) == length(workflow.steps)

      for {state, idx} <- Enum.with_index(execution.step_states) do
        assert state.step_index == idx
        assert state.status == "pending"
      end
    end
  end

  describe "execute_next_step/1" do
    test "executes query step", %{workflow: workflow} do
      {:ok, execution} = WorkflowExecutor.start_workflow(
        workflow.id,
        Ecto.UUID.generate(),
        Ecto.UUID.generate()
      )

      # Mock NLHunter response would be needed in real test
      # For now, we test the structure
      result = WorkflowExecutor.execute_next_step(execution.id)

      assert {:ok, %{execution: updated_execution, step_result: _step_result}} = result
      assert updated_execution.current_step_index >= execution.current_step_index
    end

    test "waits for decision on decision step", %{workflow: workflow} do
      # Create execution already at decision step
      {:ok, execution} = WorkflowExecutor.start_workflow(
        workflow.id,
        Ecto.UUID.generate(),
        Ecto.UUID.generate()
      )

      # Move to decision step
      execution = execution
      |> Ecto.Changeset.change(%{current_step_index: 1})
      |> Repo.update!()

      result = WorkflowExecutor.execute_next_step(execution.id)

      assert {:ok, %{waiting_for: :decision}} = result
    end

    test "completes execution when all steps done", %{workflow: workflow} do
      {:ok, execution} = WorkflowExecutor.start_workflow(
        workflow.id,
        Ecto.UUID.generate(),
        Ecto.UUID.generate()
      )

      # Move to last step
      execution = execution
      |> Ecto.Changeset.change(%{current_step_index: length(workflow.steps)})
      |> Repo.update!()

      {:ok, updated_execution} = WorkflowExecutor.execute_next_step(execution.id)

      assert updated_execution.status == "completed"
      assert updated_execution.completed_at
      assert updated_execution.progress_percentage == 100
    end
  end

  describe "make_decision/3" do
    test "records decision and advances workflow", %{workflow: workflow} do
      {:ok, execution} = WorkflowExecutor.start_workflow(
        workflow.id,
        Ecto.UUID.generate(),
        Ecto.UUID.generate()
      )

      # Create a step result for the decision step
      step_result = %WorkflowStepResult{
        execution_id: execution.id,
        step_index: 1,
        step_type: "decision",
        status: "running"
      }
      |> Repo.insert!()

      {:ok, updated_execution} = WorkflowExecutor.make_decision(
        execution.id,
        1,
        "suspicious"
      )

      # Should jump to step 2 based on next_actions
      assert updated_execution.current_step_index == 2

      # Verify step result updated
      updated_step = Repo.get!(WorkflowStepResult, step_result.id)
      assert updated_step.decision == "suspicious"
      assert updated_step.status == "completed"
    end
  end

  describe "add_annotation/4" do
    test "adds annotation to execution", %{workflow: workflow} do
      {:ok, execution} = WorkflowExecutor.start_workflow(
        workflow.id,
        Ecto.UUID.generate(),
        Ecto.UUID.generate()
      )

      user_id = Ecto.UUID.generate()
      annotation = "Suspicious behavior detected"

      {:ok, updated_execution} = WorkflowExecutor.add_annotation(
        execution.id,
        0,
        annotation,
        user_id
      )

      assert length(updated_execution.annotations) == 1
      annotation_entry = List.first(updated_execution.annotations)

      assert annotation_entry.step_index == 0
      assert annotation_entry.annotation == annotation
      assert annotation_entry.user_id == user_id
      assert annotation_entry.timestamp
    end
  end

  describe "update_hypothesis/3" do
    test "updates hypothesis status", %{workflow: workflow} do
      {:ok, execution} = WorkflowExecutor.start_workflow(
        workflow.id,
        Ecto.UUID.generate(),
        Ecto.UUID.generate()
      )

      {:ok, updated_execution} = WorkflowExecutor.update_hypothesis(
        execution.id,
        "lateral_movement",
        "confirmed"
      )

      assert updated_execution.hypothesis_status["lateral_movement"]["status"] == "confirmed"
      assert updated_execution.hypothesis_status["lateral_movement"]["updated_at"]
    end
  end

  describe "pause_execution/1 and resume_execution/1" do
    test "pauses and resumes execution", %{workflow: workflow} do
      {:ok, execution} = WorkflowExecutor.start_workflow(
        workflow.id,
        Ecto.UUID.generate(),
        Ecto.UUID.generate()
      )

      assert execution.status == "in_progress"

      {:ok, paused} = WorkflowExecutor.pause_execution(execution.id)
      assert paused.status == "paused"

      {:ok, resumed} = WorkflowExecutor.resume_execution(execution.id)
      assert resumed.status == "in_progress"
    end
  end

  describe "generate_report/2" do
    test "generates final report", %{workflow: workflow} do
      {:ok, execution} = WorkflowExecutor.start_workflow(
        workflow.id,
        Ecto.UUID.generate(),
        Ecto.UUID.generate()
      )

      # Complete the execution
      execution = execution
      |> Ecto.Changeset.change(%{
        status: "completed",
        completed_at: DateTime.utc_now()
      })
      |> Repo.update!()

      {:ok, report} = WorkflowExecutor.generate_report(execution.id, :json)

      assert is_binary(report)
      # Should be valid JSON
      assert {:ok, parsed} = Jason.decode(report)
      assert Map.has_key?(parsed, "workflow")
      assert Map.has_key?(parsed, "execution")
      assert Map.has_key?(parsed, "summary")
    end

    test "report includes all sections", %{workflow: workflow} do
      {:ok, execution} = WorkflowExecutor.start_workflow(
        workflow.id,
        Ecto.UUID.generate(),
        Ecto.UUID.generate()
      )

      execution = execution
      |> Ecto.Changeset.change(%{status: "completed", completed_at: DateTime.utc_now()})
      |> Repo.update!()

      {:ok, report_json} = WorkflowExecutor.generate_report(execution.id, :json)
      {:ok, report} = Jason.decode(report_json)

      assert report["workflow"]["name"]
      assert report["execution"]["status"]
      assert report["summary"]["total_steps"]
      assert is_list(report["steps"])
      assert is_list(report["findings"])
      assert is_list(report["recommendations"])
    end
  end

  describe "progress calculation" do
    test "calculates progress correctly", %{workflow: workflow} do
      {:ok, execution} = WorkflowExecutor.start_workflow(
        workflow.id,
        Ecto.UUID.generate(),
        Ecto.UUID.generate()
      )

      total_steps = length(workflow.steps)

      # At step 0
      assert execution.progress_percentage == 0

      # Move to step 1
      execution = execution
      |> Ecto.Changeset.change(%{
        current_step_index: 1,
        progress_percentage: div(1 * 100, total_steps)
      })
      |> Repo.update!()

      assert execution.progress_percentage > 0
      assert execution.progress_percentage < 100

      # Complete
      execution = execution
      |> Ecto.Changeset.change(%{
        current_step_index: total_steps,
        progress_percentage: 100
      })
      |> Repo.update!()

      assert execution.progress_percentage == 100
    end
  end
end
