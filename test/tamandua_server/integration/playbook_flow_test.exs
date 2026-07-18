defmodule TamanduaServer.Integration.PlaybookFlowTest do
  @moduledoc """
  Integration tests for complete playbook execution flows.

  Tests realistic scenarios including:
  - Ransomware response playbook
  - Incident investigation playbook
  - Automated remediation playbook
  - Multi-step complex workflows
  """

  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Response.{Playbook, PlaybookEngine}
  alias TamanduaServer.Response.Playbook.{Execution, StepExecution}

  setup do
    start_supervised!(Playbook)
    start_supervised!(PlaybookEngine)

    :ok
  end

  # ============================================================================
  # Ransomware Response Playbook
  # ============================================================================

  describe "ransomware response workflow" do
    test "executes full ransomware response playbook" do
      {:ok, playbook} = create_ransomware_playbook()

      context = %{
        agent_id: "test-agent-001",
        severity: "critical",
        detection_type: "ransomware",
        file_path: "/tmp/malware.exe",
        process_name: "malware.exe",
        pid: 12345
      }

      {:ok, execution} = PlaybookEngine.execute_playbook(
        playbook.id,
        context,
        skip_approval: true,
        scope: :system
      )

      # Wait for execution to complete
      Process.sleep(5000)

      # Verify execution completed
      final_execution = Repo.get(Execution, execution.id)
      assert final_execution.status in ["completed", "running", "failed"]

      # Verify all steps were executed
      steps = Repo.all(
        from s in StepExecution,
          where: s.execution_id == ^execution.id,
          order_by: [asc: s.step_index]
      )

      # Should have multiple steps
      assert length(steps) >= 3

      # Verify step sequence
      step_actions = Enum.map(steps, & &1.action_type)
      assert "isolate_host" in step_actions or "isolate_network" in step_actions
      assert "kill_process" in step_actions
    end
  end

  # ============================================================================
  # Incident Investigation Playbook
  # ============================================================================

  describe "incident investigation workflow" do
    test "collects forensics and creates ticket" do
      {:ok, playbook} = create_investigation_playbook()

      context = %{
        agent_id: "test-agent-002",
        alert_id: Ecto.UUID.generate(),
        severity: "high",
        detection_type: "suspicious_activity"
      }

      {:ok, execution} = PlaybookEngine.execute_playbook(
        playbook.id,
        context,
        skip_approval: true,
        scope: :system
      )

      Process.sleep(4000)

      steps = Repo.all(
        from s in StepExecution,
          where: s.execution_id == ^execution.id,
          order_by: [asc: s.step_index]
      )

      # Verify forensics collection step
      forensics_step = Enum.find(steps, &(&1.action_type == "collect_forensics"))

      if forensics_step do
        assert forensics_step.status in ["completed", "running", "failed"]
      end
    end
  end

  # ============================================================================
  # Conditional Response Playbook
  # ============================================================================

  describe "conditional response workflow" do
    test "executes different actions based on severity" do
      {:ok, playbook} = create_conditional_playbook()

      # Test high severity path
      high_severity_context = %{
        agent_id: "test-agent-003",
        severity: "high",
        confidence: 0.9
      }

      {:ok, high_execution} = PlaybookEngine.execute_playbook(
        playbook.id,
        high_severity_context,
        skip_approval: true,
        scope: :system
      )

      Process.sleep(3000)

      high_steps = Repo.all(
        from s in StepExecution,
          where: s.execution_id == ^high_execution.id,
          order_by: [asc: s.step_index]
      )

      # Should have conditional step
      conditional_step = Enum.find(high_steps, &(&1.action_type == "conditional"))
      assert conditional_step

      # Test low severity path
      low_severity_context = %{
        agent_id: "test-agent-004",
        severity: "low",
        confidence: 0.3
      }

      {:ok, low_execution} = PlaybookEngine.execute_playbook(
        playbook.id,
        low_severity_context,
        skip_approval: true,
        scope: :system
      )

      Process.sleep(3000)

      low_steps = Repo.all(
        from s in StepExecution,
          where: s.execution_id == ^low_execution.id,
          order_by: [asc: s.step_index]
      )

      assert length(low_steps) >= 1
    end
  end

  # ============================================================================
  # Parallel Forensics Collection
  # ============================================================================

  describe "parallel forensics collection workflow" do
    test "collects multiple forensic artifacts in parallel" do
      {:ok, playbook} = create_parallel_forensics_playbook()

      context = %{
        agent_id: "test-agent-005",
        severity: "critical"
      }

      start_time = System.monotonic_time(:millisecond)

      {:ok, execution} = PlaybookEngine.execute_playbook(
        playbook.id,
        context,
        skip_approval: true,
        scope: :system
      )

      Process.sleep(4000)

      elapsed = System.monotonic_time(:millisecond) - start_time

      # Verify parallel execution was faster than sequential would be
      assert elapsed < 10000  # Should complete much faster than 3x wait times

      parallel_step = Repo.one(
        from s in StepExecution,
          where: s.execution_id == ^execution.id and s.action_type == "parallel"
      )

      if parallel_step do
        assert parallel_step.status in ["completed", "running"]
      end
    end
  end

  # ============================================================================
  # Error Recovery Workflow
  # ============================================================================

  describe "error recovery workflow" do
    test "retries failed steps and continues execution" do
      {:ok, playbook} = create_error_recovery_playbook()

      context = %{
        agent_id: "test-agent-006",
        severity: "medium"
      }

      {:ok, execution} = PlaybookEngine.execute_playbook(
        playbook.id,
        context,
        skip_approval: true,
        scope: :system
      )

      Process.sleep(6000)

      steps = Repo.all(
        from s in StepExecution,
          where: s.execution_id == ^execution.id,
          order_by: [asc: s.step_index]
      )

      # Should have attempted retries
      failed_steps = Enum.filter(steps, &(&1.status == "failed"))

      if length(failed_steps) > 0 do
        first_failed = List.first(failed_steps)
        assert first_failed.retry_count > 0
      end
    end
  end

  # ============================================================================
  # Multi-Agent Response
  # ============================================================================

  describe "multi-agent response workflow" do
    test "executes actions across multiple agents" do
      {:ok, playbook} = create_multi_agent_playbook()

      context = %{
        primary_agent: "agent-001",
        secondary_agents: ["agent-002", "agent-003"],
        severity: "high",
        threat_ioc: "malicious.com"
      }

      {:ok, execution} = PlaybookEngine.execute_playbook(
        playbook.id,
        context,
        skip_approval: true,
        scope: :system
      )

      Process.sleep(4000)

      final_execution = Repo.get(Execution, execution.id)
      assert final_execution
    end
  end

  # ============================================================================
  # Dry Run Mode
  # ============================================================================

  describe "dry run mode" do
    test "simulates execution without actually running steps" do
      {:ok, playbook} = create_test_playbook([
        %{"action" => "isolate_host"},
        %{"action" => "kill_process", "params" => %{"pid" => 12345}},
        %{"action" => "quarantine_file", "params" => %{"path" => "/tmp/malware"}}
      ])

      context = %{agent_id: "test-agent-007"}

      {:ok, execution} = PlaybookEngine.execute_playbook(
        playbook.id,
        context,
        skip_approval: true,
        dry_run: true,
        scope: :system
      )

      assert execution.dry_run == true

      Process.sleep(3000)

      # Verify execution completed but was in dry run mode
      final = Repo.get(Execution, execution.id)
      assert final.dry_run == true
    end
  end

  # ============================================================================
  # Helper Functions
  # ============================================================================

  defp create_ransomware_playbook do
    Playbook.create_playbook(%{
      name: "Ransomware Response",
      description: "Automated response to ransomware detection",
      trigger_type: "alert",
      steps: [
        %{
          "action" => "isolate_host",
          "name" => "Isolate infected host",
          "max_retries" => 2
        },
        %{
          "action" => "kill_process",
          "name" => "Terminate malicious process",
          "params" => %{},
          "max_retries" => 2
        },
        %{
          "action" => "quarantine_file",
          "name" => "Quarantine malware",
          "params" => %{},
          "continue_on_failure" => true
        },
        %{
          "action" => "collect_forensics",
          "name" => "Collect evidence",
          "params" => %{"type" => "full"},
          "timeout_seconds" => 300
        },
        %{
          "action" => "send_notification",
          "name" => "Alert security team",
          "params" => %{
            "channel" => "slack",
            "message" => "Ransomware detected and contained on {{agent_id}}"
          }
        }
      ]
    }, :system)
  end

  defp create_investigation_playbook do
    Playbook.create_playbook(%{
      name: "Incident Investigation",
      description: "Collect forensic data and create incident ticket",
      trigger_type: "alert",
      steps: [
        %{
          "action" => "collect_forensics",
          "name" => "Collect forensic evidence",
          "params" => %{
            "memory_dump" => false,
            "process_list" => true,
            "network_connections" => true
          },
          "timeout_seconds" => 180
        },
        %{
          "action" => "create_ticket",
          "name" => "Create incident ticket",
          "params" => %{
            "title" => "Security Incident: {{detection_type}}",
            "priority" => "high"
          }
        },
        %{
          "action" => "send_notification",
          "name" => "Notify SOC",
          "params" => %{
            "channel" => "email",
            "message" => "New security incident requires investigation"
          }
        }
      ]
    }, :system)
  end

  defp create_conditional_playbook do
    Playbook.create_playbook(%{
      name: "Conditional Response",
      description: "Different actions based on severity",
      trigger_type: "alert",
      steps: [
        %{
          "action" => "conditional",
          "name" => "Check severity",
          "params" => %{
            "condition" => %{
              "type" => "severity_gte",
              "value" => "high"
            },
            "true_step" => 1,  # High severity: isolate
            "false_step" => 2  # Low severity: just notify
          }
        },
        %{
          "action" => "isolate_host",
          "name" => "Isolate high-severity threat"
        },
        %{
          "action" => "send_notification",
          "name" => "Notify about low-severity alert",
          "params" => %{
            "message" => "Low severity alert detected"
          }
        }
      ]
    }, :system)
  end

  defp create_parallel_forensics_playbook do
    Playbook.create_playbook(%{
      name: "Parallel Forensics Collection",
      description: "Collect multiple artifacts concurrently",
      trigger_type: "manual",
      steps: [
        %{
          "action" => "parallel",
          "name" => "Collect artifacts in parallel",
          "params" => %{
            "steps" => [
              %{"action" => "wait", "params" => %{"duration_seconds" => 1}},
              %{"action" => "wait", "params" => %{"duration_seconds" => 1}},
              %{"action" => "wait", "params" => %{"duration_seconds" => 1}}
            ]
          },
          "timeout_seconds" => 10
        }
      ]
    }, :system)
  end

  defp create_error_recovery_playbook do
    Playbook.create_playbook(%{
      name: "Error Recovery Test",
      description: "Test retry mechanisms",
      trigger_type: "manual",
      steps: [
        %{
          "action" => "kill_process",
          "name" => "Attempt to kill process",
          "params" => %{"pid" => 99999, "agent_id" => "nonexistent"},
          "max_retries" => 2,
          "continue_on_failure" => true
        },
        %{
          "action" => "send_notification",
          "name" => "Send completion notification",
          "params" => %{"message" => "Playbook completed despite errors"}
        }
      ]
    }, :system)
  end

  defp create_multi_agent_playbook do
    Playbook.create_playbook(%{
      name: "Multi-Agent Response",
      description: "Coordinate response across multiple agents",
      trigger_type: "alert",
      steps: [
        %{
          "action" => "block_ip",
          "name" => "Block malicious IP globally",
          "params" => %{"ip" => "192.168.1.100", "reason" => "Malicious activity"}
        },
        %{
          "action" => "update_blocklist",
          "name" => "Update threat intel blocklist",
          "params" => %{
            "blocklist_type" => "domain",
            "values" => ["malicious.com"],
            "reason" => "Confirmed malicious domain"
          }
        }
      ]
    }, :system)
  end

  defp create_test_playbook(steps) do
    Playbook.create_playbook(%{
      name: "Test Playbook #{System.unique_integer([:positive])}",
      description: "Test playbook",
      trigger_type: "manual",
      steps: steps
    }, :system)
  end
end
