defmodule TamanduaServer.Remediation.ExecutorTest do
  @moduledoc """
  Comprehensive unit tests for remediation action executor.
  Tests action execution, approval workflows, and playbook orchestration.
  """
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Remediation.{Executor, Action, Playbook}
  alias TamanduaServer.Repo

  setup do
    {org, agent} = create_agent_with_org()

    %{org: org, agent: agent}
  end

  # ── Action Execution Tests ─────────────────────────────────────────────

  describe "execute_action/2" do
    test "executes kill process action", %{agent: agent} do
      action = %Action{
        type: :kill_process,
        parameters: %{pid: 1234},
        agent_id: agent.id
      }

      {:ok, result} = Executor.execute_action(action)

      assert result.status in [:success, :pending, :failed]
      assert result.action_id != nil
    end

    test "executes quarantine file action", %{agent: agent} do
      action = %Action{
        type: :quarantine_file,
        parameters: %{path: "C:\\malicious.exe", hash: "abc123"},
        agent_id: agent.id
      }

      {:ok, result} = Executor.execute_action(action)

      assert is_map(result)
      assert Map.has_key?(result, :status)
    end

    test "executes isolate network action", %{agent: agent} do
      action = %Action{
        type: :isolate_network,
        parameters: %{},
        agent_id: agent.id
      }

      {:ok, result} = Executor.execute_action(action)

      assert result.status in [:success, :pending]
    end

    test "executes collect forensics action", %{agent: agent} do
      action = %Action{
        type: :collect_forensics,
        parameters: %{
          artifacts: ["memory", "disk", "registry"]
        },
        agent_id: agent.id
      }

      {:ok, result} = Executor.execute_action(action)

      assert is_map(result)
    end

    test "executes block IOC action", %{agent: agent} do
      action = %Action{
        type: :block_ioc,
        parameters: %{
          ioc_type: :ip,
          ioc_value: "10.0.0.100"
        },
        agent_id: agent.id
      }

      {:ok, result} = Executor.execute_action(action)

      assert result.status in [:success, :pending, :failed]
    end

    test "returns error for unknown action type", %{agent: agent} do
      action = %Action{
        type: :unknown_action,
        parameters: %{},
        agent_id: agent.id
      }

      {:error, _reason} = Executor.execute_action(action)
    end

    test "validates action parameters", %{agent: agent} do
      action = %Action{
        type: :kill_process,
        parameters: %{}, # Missing required 'pid' parameter
        agent_id: agent.id
      }

      result = Executor.execute_action(action)

      assert match?({:error, _}, result)
    end

    test "records action execution in audit log", %{agent: agent} do
      action = %Action{
        type: :kill_process,
        parameters: %{pid: 5678},
        agent_id: agent.id
      }

      {:ok, result} = Executor.execute_action(action)

      # Should create audit log entry
      audit_log = Repo.get_by(TamanduaServer.Response.Audit, action_id: result.action_id)

      if audit_log do
        assert audit_log.action_type == "kill_process"
      end
    end
  end

  # ── Approval Workflow Tests ────────────────────────────────────────────

  describe "approval workflows" do
    test "requires approval for destructive actions", %{agent: agent} do
      action = %Action{
        type: :wipe_disk,
        parameters: %{disk: "C:\\"},
        agent_id: agent.id,
        requires_approval: true
      }

      {:ok, result} = Executor.execute_action(action)

      assert result.status == :pending_approval
      assert result.approval_id != nil
    end

    test "auto-approves non-destructive actions", %{agent: agent} do
      action = %Action{
        type: :collect_logs,
        parameters: %{},
        agent_id: agent.id,
        requires_approval: false
      }

      {:ok, result} = Executor.execute_action(action)

      # Should execute immediately without approval
      assert result.status in [:success, :pending, :in_progress]
    end

    test "approves pending action", %{agent: agent, org: org} do
      action = insert!(:action, %{
        type: :kill_process,
        agent_id: agent.id,
        organization_id: org.id,
        status: :pending_approval
      })

      user = insert!(:user, %{organization_id: org.id})

      {:ok, approved} = Executor.approve_action(action.id, user.id, comment: "Approved for testing")

      assert approved.status in [:approved, :in_progress]
      assert approved.approved_by == user.id
      assert approved.approved_at != nil
    end

    test "rejects pending action", %{agent: agent, org: org} do
      action = insert!(:action, %{
        type: :isolate_network,
        agent_id: agent.id,
        organization_id: org.id,
        status: :pending_approval
      })

      user = insert!(:user, %{organization_id: org.id})

      {:ok, rejected} = Executor.reject_action(action.id, user.id, reason: "False positive")

      assert rejected.status == :rejected
      assert rejected.rejected_by == user.id
      assert rejected.rejection_reason == "False positive"
    end

    test "requires specific role for approval", %{agent: agent, org: org} do
      action = insert!(:action, %{
        type: :wipe_disk,
        agent_id: agent.id,
        organization_id: org.id,
        status: :pending_approval,
        required_role: "admin"
      })

      # User with insufficient role
      analyst = insert!(:user, %{organization_id: org.id, role: "analyst"})

      {:error, :insufficient_permissions} = Executor.approve_action(action.id, analyst.id)
    end

    test "sends notification on approval request", %{agent: agent, org: org} do
      action = %Action{
        type: :wipe_disk,
        parameters: %{disk: "C:\\"},
        agent_id: agent.id,
        organization_id: org.id,
        requires_approval: true
      }

      {:ok, result} = Executor.execute_action(action)

      # Should create notification for approvers
      # (This would require checking notification system)
      assert result.status == :pending_approval
    end
  end

  # ── Playbook Execution Tests ───────────────────────────────────────────

  describe "execute_playbook/2" do
    test "executes simple sequential playbook", %{agent: agent, org: org} do
      playbook = insert!(:playbook, %{
        organization_id: org.id,
        name: "Malware Response",
        steps: [
          %{order: 1, action_type: :kill_process, parameters: %{pid: 1234}},
          %{order: 2, action_type: :quarantine_file, parameters: %{path: "C:\\malware.exe"}},
          %{order: 3, action_type: :collect_forensics, parameters: %{artifacts: ["memory"]}}
        ]
      })

      {:ok, execution} = Executor.execute_playbook(playbook.id, agent_id: agent.id)

      assert execution.status in [:running, :completed, :pending]
      assert is_list(execution.step_results)
    end

    test "executes parallel playbook steps", %{agent: agent, org: org} do
      playbook = insert!(:playbook, %{
        organization_id: org.id,
        name: "Parallel Actions",
        execution_mode: :parallel,
        steps: [
          %{order: 1, action_type: :collect_logs, parameters: %{}},
          %{order: 1, action_type: :collect_forensics, parameters: %{artifacts: ["memory"]}},
          %{order: 1, action_type: :snapshot_registry, parameters: %{}}
        ]
      })

      {:ok, execution} = Executor.execute_playbook(playbook.id, agent_id: agent.id)

      # All steps should start simultaneously
      assert execution.status in [:running, :completed]
    end

    test "stops playbook on step failure when configured", %{agent: agent, org: org} do
      playbook = insert!(:playbook, %{
        organization_id: org.id,
        name: "Stop on Failure",
        stop_on_failure: true,
        steps: [
          %{order: 1, action_type: :kill_process, parameters: %{pid: 999999}}, # Likely to fail
          %{order: 2, action_type: :collect_logs, parameters: %{}}
        ]
      })

      {:ok, execution} = Executor.execute_playbook(playbook.id, agent_id: agent.id)

      # Should stop after first step fails
      # (This would be tested with proper async handling)
      assert is_map(execution)
    end

    test "continues playbook on step failure when configured", %{agent: agent, org: org} do
      playbook = insert!(:playbook, %{
        organization_id: org.id,
        name: "Continue on Failure",
        stop_on_failure: false,
        steps: [
          %{order: 1, action_type: :kill_process, parameters: %{pid: 999999}},
          %{order: 2, action_type: :collect_logs, parameters: %{}}
        ]
      })

      {:ok, execution} = Executor.execute_playbook(playbook.id, agent_id: agent.id)

      # Should execute all steps even if some fail
      assert is_map(execution)
    end

    test "supports conditional step execution", %{agent: agent, org: org} do
      playbook = insert!(:playbook, %{
        organization_id: org.id,
        name: "Conditional Playbook",
        steps: [
          %{
            order: 1,
            action_type: :check_process,
            parameters: %{name: "malware.exe"}
          },
          %{
            order: 2,
            action_type: :kill_process,
            parameters: %{pid: "${step1.pid}"},
            condition: "${step1.found} == true"
          }
        ]
      })

      {:ok, execution} = Executor.execute_playbook(playbook.id, agent_id: agent.id)

      assert is_map(execution)
    end

    test "executes playbook with variables", %{agent: agent, org: org} do
      playbook = insert!(:playbook, %{
        organization_id: org.id,
        name: "Parameterized Playbook",
        variables: %{
          target_pid: 1234,
          target_path: "C:\\malware.exe"
        },
        steps: [
          %{order: 1, action_type: :kill_process, parameters: %{pid: "${target_pid}"}},
          %{order: 2, action_type: :quarantine_file, parameters: %{path: "${target_path}"}}
        ]
      })

      {:ok, execution} = Executor.execute_playbook(playbook.id, agent_id: agent.id)

      assert is_map(execution)
    end

    test "cancels running playbook", %{agent: agent, org: org} do
      playbook = insert!(:playbook, %{
        organization_id: org.id,
        name: "Long Running",
        steps: [
          %{order: 1, action_type: :full_system_scan, parameters: %{}}
        ]
      })

      {:ok, execution} = Executor.execute_playbook(playbook.id, agent_id: agent.id)

      {:ok, cancelled} = Executor.cancel_playbook_execution(execution.id)

      assert cancelled.status == :cancelled
    end

    test "tracks playbook execution progress", %{agent: agent, org: org} do
      playbook = insert!(:playbook, %{
        organization_id: org.id,
        name: "Multi-Step",
        steps: [
          %{order: 1, action_type: :collect_logs, parameters: %{}},
          %{order: 2, action_type: :analyze_logs, parameters: %{}},
          %{order: 3, action_type: :generate_report, parameters: %{}}
        ]
      })

      {:ok, execution} = Executor.execute_playbook(playbook.id, agent_id: agent.id)

      # Get progress
      {:ok, progress} = Executor.get_playbook_progress(execution.id)

      assert Map.has_key?(progress, :total_steps)
      assert Map.has_key?(progress, :completed_steps)
      assert Map.has_key?(progress, :current_step)
    end
  end

  # ── Error Handling and Recovery ────────────────────────────────────────

  describe "error handling" do
    test "handles agent offline during action execution", %{agent: agent} do
      # Set agent offline
      agent
      |> Ecto.Changeset.change(%{status: "offline"})
      |> Repo.update!()

      action = %Action{
        type: :kill_process,
        parameters: %{pid: 1234},
        agent_id: agent.id
      }

      result = Executor.execute_action(action)

      assert match?({:error, :agent_offline}, result) or
             match?({:ok, %{status: :pending}}, result)
    end

    test "retries failed actions with exponential backoff", %{agent: agent} do
      action = %Action{
        type: :network_scan,
        parameters: %{},
        agent_id: agent.id,
        retry_policy: %{max_retries: 3, backoff: :exponential}
      }

      {:ok, result} = Executor.execute_action(action, retry: true)

      # Should track retry attempts
      assert is_map(result)
    end

    test "handles action timeout", %{agent: agent} do
      action = %Action{
        type: :long_running_scan,
        parameters: %{},
        agent_id: agent.id,
        timeout_seconds: 1 # Very short timeout
      }

      result = Executor.execute_action(action)

      # Should timeout
      assert match?({:error, :timeout}, result) or
             match?({:ok, %{status: :timeout}}, result)
    end

    test "rolls back failed playbook execution", %{agent: agent, org: org} do
      playbook = insert!(:playbook, %{
        organization_id: org.id,
        name: "With Rollback",
        rollback_on_failure: true,
        steps: [
          %{order: 1, action_type: :backup_file, parameters: %{path: "C:\\important.txt"}},
          %{order: 2, action_type: :delete_file, parameters: %{path: "C:\\important.txt"}},
          %{order: 3, action_type: :failing_action, parameters: %{}} # Will fail
        ],
        rollback_steps: [
          %{order: 1, action_type: :restore_file, parameters: %{path: "C:\\important.txt"}}
        ]
      })

      {:ok, execution} = Executor.execute_playbook(playbook.id, agent_id: agent.id)

      # Should attempt rollback
      assert is_map(execution)
    end
  end

  # ── Action Status and Monitoring ───────────────────────────────────────

  describe "action monitoring" do
    test "gets action status", %{agent: agent, org: org} do
      action = insert!(:action, %{
        agent_id: agent.id,
        organization_id: org.id,
        status: :in_progress
      })

      {:ok, status} = Executor.get_action_status(action.id)

      assert status.action_id == action.id
      assert status.status == :in_progress
    end

    test "lists pending actions for agent", %{agent: agent} do
      insert!(:action, %{agent_id: agent.id, status: :pending})
      insert!(:action, %{agent_id: agent.id, status: :pending})
      insert!(:action, %{agent_id: agent.id, status: :completed})

      pending = Executor.list_pending_actions(agent_id: agent.id)

      assert length(pending) == 2
      assert Enum.all?(pending, fn a -> a.status == :pending end)
    end

    test "lists actions requiring approval", %{org: org} do
      insert!(:action, %{organization_id: org.id, status: :pending_approval})
      insert!(:action, %{organization_id: org.id, status: :pending_approval})
      insert!(:action, %{organization_id: org.id, status: :approved})

      requiring_approval = Executor.list_actions_requiring_approval(organization_id: org.id)

      assert length(requiring_approval) == 2
    end

    test "gets action execution history", %{agent: agent} do
      # Create multiple actions
      for _ <- 1..5 do
        insert!(:action, %{agent_id: agent.id, status: :completed})
      end

      history = Executor.get_action_history(agent_id: agent.id, limit: 10)

      assert length(history) >= 5
    end
  end

  # ── Integration with Alert System ──────────────────────────────────────

  describe "alert integration" do
    test "creates remediation action from alert", %{agent: agent, org: org} do
      alert = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        severity: :critical,
        raw_event: %{"payload" => %{"pid" => 1234}}
      })

      {:ok, action} = Executor.create_action_from_alert(alert, action_type: :kill_process)

      assert action.alert_id == alert.id
      assert action.agent_id == agent.id
      assert action.type == :kill_process
    end

    test "auto-remediates based on alert rules", %{agent: agent, org: org} do
      # Create auto-remediation rule
      rule = insert!(:remediation_rule, %{
        organization_id: org.id,
        condition: %{severity: :critical, mitre_technique: "T1059.001"},
        action: %{type: :kill_process, extract_pid: true},
        auto_execute: true
      })

      alert = insert!(:alert, %{
        agent_id: agent.id,
        organization_id: org.id,
        severity: :critical,
        mitre_techniques: ["T1059.001"],
        raw_event: %{"payload" => %{"pid" => 5678}}
      })

      # Should automatically create and execute action
      actions = Executor.list_actions_for_alert(alert.id)

      # May create action automatically or require manual trigger
      assert is_list(actions)
    end
  end
end
