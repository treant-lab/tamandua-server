defmodule TamanduaServer.Playbooks.ValidatorTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Playbooks.Validator

  describe "validate/1 with valid YAML" do
    test "accepts valid ransomware playbook" do
      yaml = """
      name: "Ransomware Response"
      trigger:
        detection_type: ransomware
        confidence: 0.9
      actions:
        - action: "isolate_host"
        - action: "kill_process"
        - action: "quarantine_file"
      """

      assert {:ok, playbook} = Validator.validate(yaml)
      assert playbook["name"] == "Ransomware Response"
      assert length(playbook["actions"]) == 3
    end

    test "accepts playbook with MITRE techniques" do
      yaml = """
      name: "Lateral Movement"
      trigger:
        mitre_techniques:
          - T1021
          - T1570.001
        confidence: 0.8
      actions:
        - action: "block_ip"
      """

      assert {:ok, playbook} = Validator.validate(yaml)
      assert playbook["trigger"]["mitre_techniques"] == ["T1021", "T1570.001"]
    end

    test "accepts playbook with severity threshold" do
      yaml = """
      name: "High Severity Response"
      trigger:
        severity: high
      actions:
        - action: "isolate_host"
      """

      assert {:ok, _playbook} = Validator.validate(yaml)
    end

    test "accepts all valid action types" do
      actions = [
        "isolate_host",
        "kill_process",
        "quarantine_file",
        "block_ip",
        "block_domain",
        "collect_forensics",
        "create_ticket",
        "send_notification",
        "wait",
        "trigger_scan"
      ]

      for action <- actions do
        yaml = """
        name: "Test #{action}"
        trigger: {}
        actions:
          - action: "#{action}"
        """

        assert {:ok, _playbook} = Validator.validate(yaml),
               "Action '#{action}' should be valid"
      end
    end
  end

  describe "validate/1 with invalid YAML" do
    test "rejects YAML with missing required fields" do
      yaml = """
      trigger: {}
      actions: []
      """

      assert {:error, errors} = Validator.validate(yaml)
      assert "Missing required fields: name" in errors
    end

    test "rejects empty actions list" do
      yaml = """
      name: "Empty Actions"
      trigger: {}
      actions: []
      """

      assert {:error, errors} = Validator.validate(yaml)
      assert "actions cannot be empty" in errors
    end

    test "rejects invalid detection type" do
      yaml = """
      name: "Invalid Detection"
      trigger:
        detection_type: invalid_type
      actions:
        - action: "isolate_host"
      """

      assert {:error, errors} = Validator.validate(yaml)
      assert Enum.any?(errors, &String.contains?(&1, "Invalid detection_type"))
    end

    test "rejects invalid confidence value" do
      yaml = """
      name: "Invalid Confidence"
      trigger:
        confidence: 1.5
      actions:
        - action: "isolate_host"
      """

      assert {:error, errors} = Validator.validate(yaml)
      assert Enum.any?(errors, &String.contains?(&1, "confidence must be between 0.0 and 1.0"))
    end

    test "rejects invalid MITRE technique format" do
      yaml = """
      name: "Invalid MITRE"
      trigger:
        mitre_techniques:
          - INVALID123
      actions:
        - action: "isolate_host"
      """

      assert {:error, errors} = Validator.validate(yaml)
      assert Enum.any?(errors, &String.contains?(&1, "Invalid MITRE technique"))
    end

    test "rejects invalid action type" do
      yaml = """
      name: "Invalid Action"
      trigger: {}
      actions:
        - action: "invalid_action"
      """

      assert {:error, errors} = Validator.validate(yaml)
      assert Enum.any?(errors, &String.contains?(&1, "invalid action type"))
    end

    test "rejects malformed YAML" do
      yaml = """
      name: "Bad YAML
      trigger: {
      actions:
        - broken
      """

      assert {:error, errors} = Validator.validate(yaml)
      assert Enum.any?(errors, &String.contains?(&1, "YAML parsing error"))
    end

    test "rejects wait action without duration" do
      yaml = """
      name: "Invalid Wait"
      trigger: {}
      actions:
        - action: "wait"
          wait: {}
      """

      assert {:error, errors} = Validator.validate(yaml)
      assert Enum.any?(errors, &String.contains?(&1, "duration_seconds"))
    end

    test "rejects invalid notification channel" do
      yaml = """
      name: "Invalid Notification"
      trigger: {}
      actions:
        - action: "send_notification"
          send_notification:
            channel: invalid_channel
      """

      assert {:error, errors} = Validator.validate(yaml)
      assert Enum.any?(errors, &String.contains?(&1, "invalid notification channel"))
    end
  end

  describe "validate_action_order/1" do
    test "warns when forensics collection happens before isolation" do
      actions = [
        %{"action" => "collect_forensics"},
        %{"action" => "isolate_host"}
      ]

      assert {:warning, warnings} = Validator.validate_action_order(actions)
      assert Enum.any?(warnings, &String.contains?(&1, "isolate"))
    end

    test "returns :valid for proper action order" do
      actions = [
        %{"action" => "isolate_host"},
        %{"action" => "kill_process"},
        %{"action" => "quarantine_file"},
        %{"action" => "collect_forensics"}
      ]

      assert {:ok, :valid} = Validator.validate_action_order(actions)
    end
  end

  describe "valid?/1" do
    test "returns true for valid YAML" do
      yaml = """
      name: "Test"
      trigger: {}
      actions:
        - action: "isolate_host"
      """

      assert Validator.valid?(yaml) == true
    end

    test "returns false for invalid YAML" do
      yaml = """
      name: "Test"
      actions: []
      """

      assert Validator.valid?(yaml) == false
    end
  end

  describe "helper functions" do
    test "valid_actions/0 returns list of valid actions" do
      actions = Validator.valid_actions()
      assert is_list(actions)
      assert "isolate_host" in actions
      assert "kill_process" in actions
      assert length(actions) > 10
    end

    test "valid_detection_types/0 returns list of valid detection types" do
      types = Validator.valid_detection_types()
      assert is_list(types)
      assert "ransomware" in types
      assert "lateral_movement" in types
    end

    test "valid_severities/0 returns list of valid severities" do
      severities = Validator.valid_severities()
      assert severities == ["low", "medium", "high", "critical"]
    end
  end
end
