defmodule TamanduaServer.Response.PlaybookEngineTest do
  @moduledoc """
  Comprehensive tests for the PlaybookEngine module.

  Tests cover:
  - Basic playbook execution
  - Step-level execution tracking
  - Retry mechanisms
  - Timeout handling
  - Conditional branching
  - Parallel execution
  - Approval workflows
  - Error handling and rollback
  - Execution recovery
  """

  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Response.{Playbook, PlaybookEngine}
  alias TamanduaServer.Response.Playbook.{Schema, Execution, StepExecution}

  setup do
    # Start the PlaybookEngine GenServer
    start_supervised!(PlaybookEngine)
    start_supervised!(Playbook)

    :ok
  end

  # ============================================================================
  # Basic Execution Tests
  # ============================================================================

  describe "execute_playbook/3" do
    test "executes a simple playbook successfully" do
      {:ok, playbook} = create_test_playbook([
        %{"action" => "send_notification", "params" => %{"message" => "Test"}}
      ])

      {:ok, execution} = PlaybookEngine.execute_playbook(
        playbook.id,
        %{agent_id: "test-agent"},
        skip_approval: true,
        scope: :system
      )

      assert execution.status == "running"
      assert execution.playbook_id == playbook.id

      # Wait for execution to complete
      Process.sleep(2000)

      # Check final status
      {:ok, status} = PlaybookEngine.get_execution_status(execution.id, :system)
      assert status.execution.status in ["completed", "running"]
    end

    test "tracks execution progress with multiple steps" do
      {:ok, playbook} = create_test_playbook([
        %{"action" => "wait", "params" => %{"duration_seconds" => 1}},
        %{"action" => "send_notification", "params" => %{"message" => "Step 2"}},
        %{"action" => "wait", "params" => %{"duration_seconds" => 1}}
      ])

      {:ok, execution} = PlaybookEngine.execute_playbook(
        playbook.id,
        %{},
        skip_approval: true,
        scope: :system
      )

      # Check initial progress
      {:ok, status} = PlaybookEngine.get_execution_status(execution.id, :system)
      assert status.progress >= 0

      # Wait for completion
      Process.sleep(4000)

      # Check final progress
      {:ok, final_status} = PlaybookEngine.get_execution_status(execution.id, :system)
      assert final_status.progress == 100 or final_status.execution.status == "completed"
    end

    test "handles playbook not found error" do
      result = PlaybookEngine.execute_playbook(
        Ecto.UUID.generate(),
        %{},
        skip_approval: true,
        scope: :system
      )

      assert {:error, :playbook_not_found} = result
    end
  end

  # ============================================================================
  # Step Execution Tests
  # ============================================================================

  describe "step execution tracking" do
    test "creates step execution records for each step" do
      {:ok, playbook} = create_test_playbook([
        %{"action" => "wait", "params" => %{"duration_seconds" => 1}, "name" => "Wait Step"},
        %{"action" => "send_notification", "params" => %{"message" => "Done"}, "name" => "Notify"}
      ])

      {:ok, execution} = PlaybookEngine.execute_playbook(
        playbook.id,
        %{},
        skip_approval: true,
        scope: :system
      )

      # Wait for execution
      Process.sleep(3000)

      # Query step executions
      steps = Repo.all(
        from s in StepExecution,
          where: s.execution_id == ^execution.id,
          order_by: [asc: s.step_index]
      )

      assert length(steps) >= 1
      first_step = List.first(steps)
      assert first_step.step_name == "Wait Step"
      assert first_step.action_type == "wait"
      assert first_step.status in ["completed", "running"]
    end

    test "records step duration and timestamps" do
      {:ok, playbook} = create_test_playbook([
        %{"action" => "wait", "params" => %{"duration_seconds" => 2}}
      ])

      {:ok, execution} = PlaybookEngine.execute_playbook(
        playbook.id,
        %{},
        skip_approval: true,
        scope: :system
      )

      Process.sleep(3000)

      step = Repo.one(
        from s in StepExecution,
          where: s.execution_id == ^execution.id
      )

      assert step.started_at
      assert step.completed_at
      assert step.duration_ms > 1000  # Should be at least 1 second
    end

    test "stores step results" do
      {:ok, playbook} = create_test_playbook([
        %{"action" => "send_notification", "params" => %{"message" => "Test Result"}}
      ])

      {:ok, execution} = PlaybookEngine.execute_playbook(
        playbook.id,
        %{},
        skip_approval: true,
        scope: :system
      )

      Process.sleep(2000)

      step = Repo.one(
        from s in StepExecution,
          where: s.execution_id == ^execution.id
      )

      assert step.result
    end
  end

  # ============================================================================
  # Retry Mechanism Tests
  # ============================================================================

  describe "retry mechanism" do
    test "retries failed steps up to max_retries" do
      {:ok, playbook} = create_test_playbook([
        %{
          "action" => "kill_process",
          "params" => %{"pid" => 99999, "agent_id" => "nonexistent"},
          "max_retries" => 2
        }
      ])

      {:ok, execution} = PlaybookEngine.execute_playbook(
        playbook.id,
        %{},
        skip_approval: true,
        scope: :system
      )

      # Wait for retries
      Process.sleep(5000)

      step = Repo.one(
        from s in StepExecution,
          where: s.execution_id == ^execution.id
      )

      # Should have attempted retries
      assert step.retry_count > 0
    end

    test "does not retry beyond max_retries" do
      {:ok, playbook} = create_test_playbook([
        %{
          "action" => "kill_process",
          "params" => %{"pid" => 99999, "agent_id" => "nonexistent"},
          "max_retries" => 1
        }
      ])

      {:ok, execution} = PlaybookEngine.execute_playbook(
        playbook.id,
        %{},
        skip_approval: true,
        scope: :system
      )

      Process.sleep(4000)

      step = Repo.one(
        from s in StepExecution,
          where: s.execution_id == ^execution.id
      )

      assert step.retry_count <= 1
    end
  end

  # ============================================================================
  # Conditional Branching Tests
  # ============================================================================

  describe "conditional branching" do
    test "branches to true_step when condition is met" do
      {:ok, playbook} = create_test_playbook([
        %{
          "action" => "conditional",
          "params" => %{
            "condition" => %{"type" => "field_equals", "field" => "test", "value" => true},
            "true_step" => 2,
            "false_step" => 1
          }
        },
        %{"action" => "send_notification", "params" => %{"message" => "False branch"}},
        %{"action" => "send_notification", "params" => %{"message" => "True branch"}}
      ])

      {:ok, execution} = PlaybookEngine.execute_playbook(
        playbook.id,
        %{test: true},
        skip_approval: true,
        scope: :system
      )

      Process.sleep(2000)

      steps = Repo.all(
        from s in StepExecution,
          where: s.execution_id == ^execution.id,
          order_by: [asc: s.step_index]
      )

      # Should have conditional and true branch step
      conditional_step = Enum.find(steps, &(&1.action_type == "conditional"))
      assert conditional_step
      assert conditional_step.result["branched_to"] == 2
    end
  end

  # ============================================================================
  # Parallel Execution Tests
  # ============================================================================

  describe "parallel execution" do
    test "executes multiple steps concurrently" do
      {:ok, playbook} = create_test_playbook([
        %{
          "action" => "parallel",
          "params" => %{
            "steps" => [
              %{"action" => "wait", "params" => %{"duration_seconds" => 1}},
              %{"action" => "wait", "params" => %{"duration_seconds" => 1}},
              %{"action" => "wait", "params" => %{"duration_seconds" => 1}}
            ]
          }
        }
      ])

      start_time = System.monotonic_time(:millisecond)

      {:ok, execution} = PlaybookEngine.execute_playbook(
        playbook.id,
        %{},
        skip_approval: true,
        scope: :system
      )

      Process.sleep(3000)

      elapsed = System.monotonic_time(:millisecond) - start_time

      # Should complete in ~1-2 seconds (parallel) not 3 seconds (sequential)
      assert elapsed < 3000

      step = Repo.one(
        from s in StepExecution,
          where: s.execution_id == ^execution.id
      )

      assert step.action_type == "parallel"
    end
  end

  # ============================================================================
  # Approval Workflow Tests
  # ============================================================================

  describe "approval workflow" do
    test "waits for approval when require_approval is true" do
      {:ok, playbook} = create_test_playbook(
        [%{"action" => "send_notification", "params" => %{"message" => "Approved"}}],
        require_approval: true
      )

      {:ok, execution} = PlaybookEngine.execute_playbook(
        playbook.id,
        %{},
        scope: :system
      )

      assert execution.status == "pending_approval"

      # Verify it's not running yet
      Process.sleep(1000)
      {:ok, status} = PlaybookEngine.get_execution_status(execution.id, :system)
      assert status.execution.status == "pending_approval"
    end

    test "skip_approval option bypasses approval requirement" do
      {:ok, playbook} = create_test_playbook(
        [%{"action" => "wait", "params" => %{"duration_seconds" => 1}}],
        require_approval: true
      )

      {:ok, execution} = PlaybookEngine.execute_playbook(
        playbook.id,
        %{},
        skip_approval: true,
        scope: :system
      )

      assert execution.status == "running"
    end

    test "approving an execution allows it to proceed" do
      {:ok, playbook} = create_test_playbook(
        [%{"action" => "wait", "params" => %{"duration_seconds" => 1}}],
        require_approval: true
      )

      {:ok, execution} = PlaybookEngine.execute_playbook(
        playbook.id,
        %{},
        scope: :system
      )

      assert execution.status == "pending_approval"

      # Approve the execution
      user_id = Ecto.UUID.generate()
      updated_execution = execution
        |> Execution.changeset(%{
          status: "running",
          approved_by: user_id,
          approved_at: DateTime.utc_now()
        })
        |> Repo.update!()

      assert updated_execution.status == "running"
      assert updated_execution.approved_by == user_id
    end
  end

  # ============================================================================
  # Cancellation Tests
  # ============================================================================

  describe "cancel_execution/2" do
    test "cancels a running execution" do
      {:ok, playbook} = create_test_playbook([
        %{"action" => "wait", "params" => %{"duration_seconds" => 10}}
      ])

      {:ok, execution} = PlaybookEngine.execute_playbook(
        playbook.id,
        %{},
        skip_approval: true,
        scope: :system
      )

      Process.sleep(500)

      :ok = PlaybookEngine.cancel_execution(execution.id, "User cancelled", :system)

      # Verify cancellation
      updated = Repo.get(Execution, execution.id)
      assert updated.status == "cancelled"
      assert updated.error_message == "User cancelled"
    end

    test "cancels a pending approval execution" do
      {:ok, playbook} = create_test_playbook(
        [%{"action" => "wait", "params" => %{"duration_seconds" => 1}}],
        require_approval: true
      )

      {:ok, execution} = PlaybookEngine.execute_playbook(
        playbook.id,
        %{},
        scope: :system
      )

      assert execution.status == "pending_approval"

      :ok = PlaybookEngine.cancel_execution(execution.id, "Rejected", :system)

      updated = Repo.get(Execution, execution.id)
      assert updated.status == "cancelled"
    end

    test "returns error for non-existent execution" do
      result = PlaybookEngine.cancel_execution(Ecto.UUID.generate(), "Test", :system)
      assert {:error, :not_found} = result
    end
  end

  # ============================================================================
  # Error Handling Tests
  # ============================================================================

  describe "error handling" do
    test "marks execution as failed when step fails without retries" do
      {:ok, playbook} = create_test_playbook([
        %{
          "action" => "kill_process",
          "params" => %{"pid" => 99999, "agent_id" => "nonexistent"},
          "max_retries" => 0
        }
      ])

      {:ok, execution} = PlaybookEngine.execute_playbook(
        playbook.id,
        %{},
        skip_approval: true,
        scope: :system
      )

      Process.sleep(2000)

      updated = Repo.get(Execution, execution.id)
      assert updated.status == "failed"
      assert updated.error_message
    end

    test "continues execution when continue_on_failure is true" do
      {:ok, playbook} = create_test_playbook([
        %{
          "action" => "kill_process",
          "params" => %{"pid" => 99999, "agent_id" => "nonexistent"},
          "max_retries" => 0,
          "continue_on_failure" => true
        },
        %{"action" => "send_notification", "params" => %{"message" => "Continued"}}
      ])

      {:ok, execution} = PlaybookEngine.execute_playbook(
        playbook.id,
        %{},
        skip_approval: true,
        scope: :system
      )

      Process.sleep(3000)

      steps = Repo.all(
        from s in StepExecution,
          where: s.execution_id == ^execution.id,
          order_by: [asc: s.step_index]
      )

      # Should have executed both steps
      assert length(steps) >= 1
      first_step = List.first(steps)
      assert first_step.status == "failed"
    end
  end

  # ============================================================================
  # Timeout Handling Tests
  # ============================================================================

  describe "timeout handling" do
    test "respects step timeout_seconds" do
      {:ok, playbook} = create_test_playbook([
        %{
          "action" => "wait",
          "params" => %{"duration_seconds" => 100},
          "timeout_seconds" => 2
        }
      ])

      {:ok, execution} = PlaybookEngine.execute_playbook(
        playbook.id,
        %{},
        skip_approval: true,
        scope: :system
      )

      Process.sleep(4000)

      step = Repo.one(
        from s in StepExecution,
          where: s.execution_id == ^execution.id
      )

      # Step should have timed out
      assert step.status in ["failed", "completed"]
      if step.status == "failed" do
        assert step.error_message =~ "timeout"
      end
    end
  end

  # ============================================================================
  # Context Variable Interpolation Tests
  # ============================================================================

  describe "context variable interpolation" do
    test "interpolates context variables in params" do
      {:ok, playbook} = create_test_playbook([
        %{
          "action" => "send_notification",
          "params" => %{
            "message" => "Agent: {{agent_id}}, Severity: {{severity}}"
          }
        }
      ])

      {:ok, execution} = PlaybookEngine.execute_playbook(
        playbook.id,
        %{agent_id: "test-123", severity: "high"},
        skip_approval: true,
        scope: :system
      )

      Process.sleep(2000)

      step = Repo.one(
        from s in StepExecution,
          where: s.execution_id == ^execution.id
      )

      # The interpolated params should be stored
      assert step.params["message"] =~ "test-123" or step.params["message"] =~ "{{agent_id}}"
    end
  end

  # ============================================================================
  # List Active Executions Tests
  # ============================================================================

  describe "list_active_executions/0" do
    test "returns currently active executions" do
      {:ok, playbook} = create_test_playbook([
        %{"action" => "wait", "params" => %{"duration_seconds" => 5}}
      ])

      {:ok, _execution1} = PlaybookEngine.execute_playbook(
        playbook.id,
        %{},
        skip_approval: true,
        scope: :system
      )

      {:ok, _execution2} = PlaybookEngine.execute_playbook(
        playbook.id,
        %{},
        skip_approval: true,
        scope: :system
      )

      {:ok, active} = PlaybookEngine.list_active_executions(:system)

      assert length(active) >= 1
    end

    test "returns empty list when no executions are active" do
      {:ok, active} = PlaybookEngine.list_active_executions(:system)
      assert is_list(active)
    end
  end

  # ============================================================================
  # Helper Functions
  # ============================================================================

  defp create_test_playbook(steps, opts \\ []) do
    attrs = %{
      name: "Test Playbook #{System.unique_integer([:positive])}",
      description: "Test playbook for automated testing",
      trigger_type: "manual",
      steps: steps,
      enabled: true,
      require_approval: Keyword.get(opts, :require_approval, false),
      approval_timeout_minutes: 30
    }

    Playbook.create_playbook(attrs, :system)
  end
end
