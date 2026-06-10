defmodule TamanduaServer.Integrations.TicketingRouterTest do
  use TamanduaServer.DataCase, async: false

  import Mox

  alias TamanduaServer.Integrations.TicketingRouter
  alias TamanduaServer.Integrations.Ticketing.Config

  setup :verify_on_exit!

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
      assert {:ok, []} = TicketingRouter.route_alert(@valid_alert)
    end

    test "skips alerts below min_severity threshold" do
      # Test with low severity alert
      low_severity_alert = Map.put(@valid_alert, :severity, "info")

      # Without any configs, should return empty
      assert {:ok, []} = TicketingRouter.route_alert(low_severity_alert)
    end

    test "requires organization_id in alert" do
      alert_without_org = Map.delete(@valid_alert, :organization_id)
      assert {:ok, []} = TicketingRouter.route_alert(alert_without_org)
    end
  end

  describe "should_create_ticket?/2" do
    test "returns true when alert severity meets threshold" do
      config = %{min_severity: "high"}

      assert TicketingRouter.should_create_ticket?(%{severity: "critical"}, config)
      assert TicketingRouter.should_create_ticket?(%{severity: "high"}, config)
    end

    test "returns false when alert severity below threshold" do
      config = %{min_severity: "high"}

      refute TicketingRouter.should_create_ticket?(%{severity: "medium"}, config)
      refute TicketingRouter.should_create_ticket?(%{severity: "low"}, config)
      refute TicketingRouter.should_create_ticket?(%{severity: "info"}, config)
    end

    test "handles string keys in alert" do
      config = %{min_severity: "medium"}

      assert TicketingRouter.should_create_ticket?(%{"severity" => "critical"}, config)
      assert TicketingRouter.should_create_ticket?(%{"severity" => "high"}, config)
      assert TicketingRouter.should_create_ticket?(%{"severity" => "medium"}, config)
    end

    test "uses high as default min_severity" do
      config = %{min_severity: nil}

      assert TicketingRouter.should_create_ticket?(%{severity: "critical"}, config)
      assert TicketingRouter.should_create_ticket?(%{severity: "high"}, config)
      refute TicketingRouter.should_create_ticket?(%{severity: "medium"}, config)
    end
  end

  describe "get_enabled_integrations/1" do
    test "returns empty list when no configs exist" do
      assert [] = TicketingRouter.get_enabled_integrations("nonexistent-org")
    end
  end

  describe "get_stats/0" do
    test "returns default stats when GenServer not started" do
      stats = TicketingRouter.get_stats()

      assert stats.tickets_created == 0
      assert stats.errors == 0
      assert stats.dedup_hits == 0
      assert stats.by_type == %{}
    end
  end

  describe "route_batch/2" do
    test "processes multiple alerts" do
      alerts = [
        @valid_alert,
        Map.put(@valid_alert, :id, "alert-456"),
        Map.put(@valid_alert, :id, "alert-789")
      ]

      # Without configs, should return empty results
      assert {:ok, []} = TicketingRouter.route_batch(alerts)
    end
  end

  describe "severity ordering" do
    test "critical has highest priority" do
      config = %{min_severity: "info"}

      assert TicketingRouter.should_create_ticket?(%{severity: "critical"}, config)
    end

    test "info has lowest priority" do
      config = %{min_severity: "critical"}

      refute TicketingRouter.should_create_ticket?(%{severity: "info"}, config)
      refute TicketingRouter.should_create_ticket?(%{severity: "low"}, config)
      refute TicketingRouter.should_create_ticket?(%{severity: "medium"}, config)
      refute TicketingRouter.should_create_ticket?(%{severity: "high"}, config)
      assert TicketingRouter.should_create_ticket?(%{severity: "critical"}, config)
    end
  end
end
