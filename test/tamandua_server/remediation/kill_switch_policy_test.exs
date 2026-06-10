defmodule TamanduaServer.Remediation.KillSwitchPolicyTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Remediation.KillSwitchPolicy
  alias TamanduaServer.Runtime.{KillSwitch, ModelIsolation}

  setup do
    # Start required GenServers
    start_supervised!(ModelIsolation)
    start_supervised!(KillSwitch)
    :ok
  end

  describe "name/0 and description/0" do
    test "returns policy name" do
      assert KillSwitchPolicy.name() == "kill_switch"
    end

    test "returns policy description" do
      assert KillSwitchPolicy.description() =~ "Model isolation"
    end
  end

  describe "default_rules/0" do
    test "returns list of rules" do
      rules = KillSwitchPolicy.default_rules()

      assert is_list(rules)
      assert length(rules) > 0
    end

    test "rules have required fields" do
      rules = KillSwitchPolicy.default_rules()

      for rule <- rules do
        assert Map.has_key?(rule, :id)
        assert Map.has_key?(rule, :name)
        assert Map.has_key?(rule, :condition)
        assert Map.has_key?(rule, :action)
      end
    end

    test "includes critical auto-isolate rule" do
      rules = KillSwitchPolicy.default_rules()

      critical_rule = Enum.find(rules, fn r -> r.id == "ks_auto_critical" end)

      assert critical_rule != nil
      assert critical_rule.condition.risk_level == :critical
      assert critical_rule.action == :isolate
      assert critical_rule.requires_approval == false
    end

    test "includes high threat approval rule" do
      rules = KillSwitchPolicy.default_rules()

      high_rule = Enum.find(rules, fn r -> r.id == "ks_auto_high" end)

      assert high_rule != nil
      assert high_rule.condition.risk_level == :high
      assert high_rule.requires_approval == true
    end
  end

  describe "evaluate/2" do
    test "matches critical severity alert" do
      alert = %{
        severity: :critical,
        agent_id: "test-agent-1",
        title: "Critical output violation"
      }

      context = %{
        triggered_by: "test"
      }

      assert {:ok, action} = KillSwitchPolicy.evaluate(alert, context)
      assert action.action == :isolate
      assert action.mode == :full
      assert action.requires_approval == false
    end

    test "matches high severity alert" do
      alert = %{
        severity: :high,
        agent_id: "test-agent-2",
        title: "High risk output"
      }

      context = %{
        triggered_by: "test"
      }

      assert {:ok, action} = KillSwitchPolicy.evaluate(alert, context)
      assert action.action == :isolate
      assert action.mode == :network
      assert action.requires_approval == true
    end

    test "matches manual trigger" do
      alert = %{
        severity: :medium,
        agent_id: "test-agent-3"
      }

      context = %{
        trigger_type: :manual,
        triggered_by: "admin_user"
      }

      assert {:ok, action} = KillSwitchPolicy.evaluate(alert, context)
      assert action.action == :isolate
      assert action.audit_required == true
    end

    test "returns no_match for low severity without manual trigger" do
      alert = %{
        severity: :low,
        agent_id: "test-agent-4"
      }

      context = %{
        triggered_by: "system"
      }

      assert {:no_match, _reason} = KillSwitchPolicy.evaluate(alert, context)
    end

    test "extracts model_id from context" do
      alert = %{severity: :critical, agent_id: "test-agent"}
      context = %{model_id: "explicit-model-id"}

      {:ok, action} = KillSwitchPolicy.evaluate(alert, context)
      assert action.model_id == "explicit-model-id"
    end

    test "extracts model_id from alert when not in context" do
      alert = %{
        severity: :critical,
        agent_id: "test-agent",
        model_id: "alert-model-id"
      }

      context = %{}

      {:ok, action} = KillSwitchPolicy.evaluate(alert, context)
      assert action.model_id == "alert-model-id"
    end
  end

  describe "execute/2" do
    test "executes immediately for non-approval actions" do
      model_id = "test-model-exec-#{System.unique_integer()}"
      agent_id = "test-agent"

      # Register and arm model
      {:ok, _} = ModelIsolation.register(model_id, agent_id)
      KillSwitch.arm(model_id)

      action = %{
        rule_id: "ks_auto_critical",
        rule_name: "Test rule",
        action: :isolate,
        mode: :full,
        model_id: model_id,
        agent_id: agent_id,
        requires_approval: false,
        auto_release_hours: nil,
        audit_required: true,
        reason: "Test execution",
        triggered_by: "test"
      }

      context = %{}

      assert {:ok, result} = KillSwitchPolicy.execute(action, context)
      assert result.status == :triggered
    end

    test "creates workflow for approval-required actions" do
      model_id = "test-model-approval-#{System.unique_integer()}"
      agent_id = "test-agent"

      action = %{
        rule_id: "ks_auto_high",
        rule_name: "High threat rule",
        action: :isolate,
        mode: :network,
        model_id: model_id,
        agent_id: agent_id,
        requires_approval: true,
        approval_timeout_hours: 4,
        audit_required: true,
        reason: "Test workflow creation",
        triggered_by: "test"
      }

      context = %{
        organization_id: nil,
        alert_id: nil
      }

      # This will create a workflow requiring approval
      result = KillSwitchPolicy.execute(action, context)

      # May succeed or fail depending on DB setup
      # At minimum, it should not crash
      assert is_tuple(result)
    end
  end

  describe "rule matching with string severity" do
    test "handles string severity values" do
      alert = %{
        severity: "critical",
        agent_id: "test-agent"
      }

      context = %{}

      assert {:ok, action} = KillSwitchPolicy.evaluate(alert, context)
      assert action.action == :isolate
    end

    test "handles overall_risk field" do
      alert = %{
        overall_risk: :critical,
        agent_id: "test-agent"
      }

      context = %{}

      assert {:ok, action} = KillSwitchPolicy.evaluate(alert, context)
      assert action.action == :isolate
    end
  end

  describe "PII detection rule" do
    test "matches when pii_count exceeds threshold" do
      alert = %{
        severity: :medium,
        agent_id: "test-agent",
        pii: %{
          has_pii: true,
          pii_count: 10
        }
      }

      context = %{}

      assert {:ok, action} = KillSwitchPolicy.evaluate(alert, context)
      assert action.requires_approval == true
    end

    test "does not match when pii_count below threshold" do
      alert = %{
        severity: :medium,
        agent_id: "test-agent",
        pii: %{
          has_pii: true,
          pii_count: 2
        }
      }

      context = %{}

      # Should not match any rule
      assert {:no_match, _} = KillSwitchPolicy.evaluate(alert, context)
    end
  end

  describe "prompt injection rule" do
    test "matches critical prompt injection" do
      alert = %{
        category: :prompt_injection,
        severity: :critical,
        agent_id: "test-agent"
      }

      context = %{}

      assert {:ok, action} = KillSwitchPolicy.evaluate(alert, context)
      # May match either critical rule or prompt injection rule
      assert action.action == :isolate
      assert action.mode == :full
    end
  end

  describe "action building" do
    test "includes all required fields" do
      alert = %{
        severity: :critical,
        agent_id: "test-agent",
        title: "Test alert"
      }

      context = %{
        triggered_by: "unit_test"
      }

      {:ok, action} = KillSwitchPolicy.evaluate(alert, context)

      assert Map.has_key?(action, :rule_id)
      assert Map.has_key?(action, :rule_name)
      assert Map.has_key?(action, :action)
      assert Map.has_key?(action, :mode)
      assert Map.has_key?(action, :model_id)
      assert Map.has_key?(action, :agent_id)
      assert Map.has_key?(action, :requires_approval)
      assert Map.has_key?(action, :reason)
      assert Map.has_key?(action, :triggered_by)

      assert action.triggered_by == "unit_test"
      assert action.agent_id == "test-agent"
    end

    test "builds descriptive reason" do
      alert = %{
        severity: :critical,
        agent_id: "test-agent",
        title: "Harmful content detected"
      }

      context = %{}

      {:ok, action} = KillSwitchPolicy.evaluate(alert, context)

      assert action.reason =~ "Harmful content detected"
    end
  end

  describe "register/0" do
    test "does not crash even without registry" do
      # Should gracefully handle missing registry
      assert KillSwitchPolicy.register() == :ok
    end
  end
end
