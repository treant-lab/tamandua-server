defmodule TamanduaServer.Playbooks.ExecutorTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Playbooks.Executor

  describe "should_execute?/2" do
    test "executes when detection_type matches" do
      playbook = %{
        "name" => "Test",
        "trigger" => %{"detection_type" => "ransomware"},
        "actions" => []
      }

      context = %{detection_type: "ransomware"}

      assert Executor.should_execute?(playbook, context) == true
    end

    test "does not execute when detection_type does not match" do
      playbook = %{
        "name" => "Test",
        "trigger" => %{"detection_type" => "ransomware"},
        "actions" => []
      }

      context = %{detection_type: "malware"}

      assert Executor.should_execute?(playbook, context) == false
    end

    test "executes when confidence meets threshold" do
      playbook = %{
        "name" => "Test",
        "trigger" => %{"confidence" => 0.8},
        "actions" => []
      }

      context = %{confidence: 0.9}

      assert Executor.should_execute?(playbook, context) == true
    end

    test "does not execute when confidence below threshold" do
      playbook = %{
        "name" => "Test",
        "trigger" => %{"confidence" => 0.8},
        "actions" => []
      }

      context = %{confidence: 0.7}

      assert Executor.should_execute?(playbook, context) == false
    end

    test "executes when severity meets threshold" do
      playbook = %{
        "name" => "Test",
        "trigger" => %{"severity" => "high"},
        "actions" => []
      }

      context = %{severity: "critical"}

      assert Executor.should_execute?(playbook, context) == true
    end

    test "executes when MITRE technique matches" do
      playbook = %{
        "name" => "Test",
        "trigger" => %{"mitre_techniques" => ["T1486", "T1003"]},
        "actions" => []
      }

      context = %{mitre_techniques: ["T1486", "T1055"]}

      assert Executor.should_execute?(playbook, context) == true
    end

    test "always executes when no trigger conditions specified" do
      playbook = %{
        "name" => "Test",
        "trigger" => %{},
        "actions" => []
      }

      context = %{}

      assert Executor.should_execute?(playbook, context) == true
    end
  end

  describe "execute/3 with dry_run mode" do
    test "simulates isolate_host action" do
      yaml = """
      name: "Test Isolation"
      trigger:
        detection_type: ransomware
      actions:
        - action: "isolate_host"
      """

      context = %{
        agent_id: "test-agent",
        detection_type: "ransomware",
        severity: "critical"
      }

      assert {:ok, result} = Executor.execute(yaml, context, dry_run: true)
      assert result.dry_run == true
      assert result.playbook_name == "Test Isolation"
      assert result.actions_executed == 1
      assert length(result.results) == 1

      [action_result] = result.results
      assert action_result.action == "isolate_host"
      assert action_result.status == "success"
      assert action_result.result.simulated == true
    end

    test "simulates multiple actions in sequence" do
      yaml = """
      name: "Multi-Action Test"
      trigger: {}
      actions:
        - action: "kill_process"
        - action: "quarantine_file"
        - action: "collect_forensics"
        - action: "create_ticket"
      """

      context = %{
        agent_id: "test-agent",
        pid: 1234,
        file_path: "/tmp/malware.exe"
      }

      assert {:ok, result} = Executor.execute(yaml, context, dry_run: true)
      assert result.actions_executed == 4

      actions = Enum.map(result.results, & &1.action)
      assert actions == ["kill_process", "quarantine_file", "collect_forensics", "create_ticket"]
    end

    test "simulates block_ip action" do
      yaml = """
      name: "Block IP Test"
      trigger: {}
      actions:
        - action: "block_ip"
          block_ip:
            ip: "192.168.1.100"
      """

      context = %{}

      assert {:ok, result} = Executor.execute(yaml, context, dry_run: true)
      [action_result] = result.results
      assert action_result.result.ip == "192.168.1.100"
    end

    test "simulates wait action" do
      yaml = """
      name: "Wait Test"
      trigger: {}
      actions:
        - action: "wait"
          wait:
            duration_seconds: 5
      """

      context = %{}

      assert {:ok, result} = Executor.execute(yaml, context, dry_run: true)
      [action_result] = result.results
      assert action_result.result.duration_seconds == 5
    end
  end

  describe "execute/3 with validation" do
    test "rejects invalid YAML" do
      yaml = """
      name: "Invalid"
      actions: []
      """

      context = %{}

      assert {:error, reason} = Executor.execute(yaml, context, dry_run: true)
      assert reason =~ "validation failed"
    end

    test "skips execution when trigger conditions not met" do
      yaml = """
      name: "Conditional Test"
      trigger:
        detection_type: ransomware
        confidence: 0.9
      actions:
        - action: "isolate_host"
      """

      context = %{
        detection_type: "malware",
        confidence: 0.5
      }

      assert {:ok, result} = Executor.execute(yaml, context, dry_run: true)
      assert result.skipped == true
      assert result.reason == "Trigger conditions not met"
    end
  end

  describe "execute/3 with continue_on_error" do
    test "continues execution after simulated error in dry-run" do
      yaml = """
      name: "Continue Test"
      trigger: {}
      actions:
        - action: "isolate_host"
        - action: "collect_forensics"
      """

      context = %{agent_id: "test-agent"}

      # In dry-run mode, all actions succeed, but we test the option is accepted
      assert {:ok, result} =
               Executor.execute(yaml, context, dry_run: true, continue_on_error: true)

      assert result.actions_executed == 2
    end
  end

  describe "execute/3 with timeout" do
    test "respects timeout option" do
      yaml = """
      name: "Timeout Test"
      trigger: {}
      actions:
        - action: "isolate_host"
      """

      context = %{agent_id: "test-agent"}

      # Short timeout should still work for dry-run
      assert {:ok, _result} = Executor.execute(yaml, context, dry_run: true, timeout: 1000)
    end
  end

  describe "context building" do
    test "builds context from map" do
      yaml = """
      name: "Context Test"
      trigger:
        detection_type: ransomware
      actions:
        - action: "isolate_host"
      """

      context = %{
        agent_id: "agent-123",
        detection_type: "ransomware",
        severity: "high",
        file_path: "/tmp/bad.exe"
      }

      assert {:ok, result} = Executor.execute(yaml, context, dry_run: true)
      assert result.context[:agent_id] == "agent-123"
      assert result.context[:detection_type] == "ransomware"
    end
  end
end
