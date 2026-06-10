defmodule TamanduaServer.Integrations.ChatRouterTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Integrations.ChatRouter

  @valid_alert %{
    id: "alert-123",
    organization_id: "org-456",
    title: "Suspicious process detected",
    severity: "high",
    description: "PowerShell executing encoded command",
    hostname: "workstation-01",
    agent_id: "agent-789",
    mitre_tactics: ["Execution"],
    mitre_techniques: ["T1059.001"],
    threat_score: 85
  }

  describe "route_alert/2" do
    test "returns empty results when no integrations are enabled" do
      # With no configs, should return empty
      assert {:ok, []} = ChatRouter.route_alert(@valid_alert)
    end

    test "skips alerts below min_severity threshold" do
      # Test with low severity alert
      low_severity_alert = Map.put(@valid_alert, :severity, "info")

      # Without any configs, should return empty
      assert {:ok, []} = ChatRouter.route_alert(low_severity_alert)
    end

    test "requires organization_id in alert" do
      alert_without_org = Map.delete(@valid_alert, :organization_id)
      assert {:ok, []} = ChatRouter.route_alert(alert_without_org)
    end
  end

  describe "should_notify?/2" do
    test "returns true when alert severity meets threshold" do
      config = %{min_severity: "high"}

      assert ChatRouter.should_notify?(%{severity: "critical"}, config)
      assert ChatRouter.should_notify?(%{severity: "high"}, config)
    end

    test "returns false when alert severity below threshold" do
      config = %{min_severity: "high"}

      refute ChatRouter.should_notify?(%{severity: "medium"}, config)
      refute ChatRouter.should_notify?(%{severity: "low"}, config)
      refute ChatRouter.should_notify?(%{severity: "info"}, config)
    end

    test "handles string keys in alert" do
      config = %{min_severity: "medium"}

      assert ChatRouter.should_notify?(%{"severity" => "critical"}, config)
      assert ChatRouter.should_notify?(%{"severity" => "high"}, config)
      assert ChatRouter.should_notify?(%{"severity" => "medium"}, config)
    end

    test "uses high as default min_severity" do
      config = %{min_severity: nil}

      assert ChatRouter.should_notify?(%{severity: "critical"}, config)
      assert ChatRouter.should_notify?(%{severity: "high"}, config)
      refute ChatRouter.should_notify?(%{severity: "medium"}, config)
    end
  end

  describe "get_enabled_integrations/1" do
    test "returns empty list when no configs exist" do
      assert [] = ChatRouter.get_enabled_integrations("nonexistent-org")
    end
  end

  describe "get_stats/0" do
    test "returns default stats when GenServer not started" do
      stats = ChatRouter.get_stats()

      assert stats.alerts_sent == 0
      assert stats.approvals_sent == 0
      assert stats.errors == 0
      assert stats.by_type == %{}
    end
  end

  describe "notify_approval_required/2" do
    test "returns error when GenServer not started" do
      execution = %{id: "exec-123", organization_id: "org-456"}
      approval_request = %{playbook_name: "Kill Process", action_type: "kill", target: "pid:1234"}

      assert {:error, :not_started} = ChatRouter.notify_approval_required(execution, approval_request)
    end
  end

  describe "severity ordering" do
    test "critical has highest priority" do
      config = %{min_severity: "info"}

      assert ChatRouter.should_notify?(%{severity: "critical"}, config)
    end

    test "info has lowest priority" do
      config = %{min_severity: "critical"}

      refute ChatRouter.should_notify?(%{severity: "info"}, config)
      refute ChatRouter.should_notify?(%{severity: "low"}, config)
      refute ChatRouter.should_notify?(%{severity: "medium"}, config)
      refute ChatRouter.should_notify?(%{severity: "high"}, config)
      assert ChatRouter.should_notify?(%{severity: "critical"}, config)
    end
  end
end
