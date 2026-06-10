defmodule TamanduaServer.Support.SLAConfigTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Support.SLAConfig

  @moduletag :enterprise

  describe "get_sla/2" do
    test "returns enterprise P1 SLA" do
      sla = SLAConfig.get_sla(:enterprise, :p1)

      assert sla.response == 15  # 15 minutes
      assert sla.resolution == 240  # 4 hours
    end

    test "returns enterprise P2 SLA" do
      sla = SLAConfig.get_sla(:enterprise, :p2)

      assert sla.response == 60  # 1 hour
      assert sla.resolution == 480  # 8 hours
    end

    test "returns enterprise P3 SLA" do
      sla = SLAConfig.get_sla(:enterprise, :p3)

      assert sla.response == 240  # 4 hours
      assert sla.resolution == 1440  # 24 hours
    end

    test "returns enterprise P4 SLA" do
      sla = SLAConfig.get_sla(:enterprise, :p4)

      assert sla.response == 480  # 8 hours
      assert sla.resolution == 2880  # 48 hours
    end

    test "returns pro tier SLAs with longer response times" do
      enterprise_p1 = SLAConfig.get_sla(:enterprise, :p1)
      pro_p1 = SLAConfig.get_sla(:pro, :p1)

      assert pro_p1.response > enterprise_p1.response
      assert pro_p1.resolution > enterprise_p1.resolution
    end

    test "returns trial tier SLAs as fallback" do
      trial_p1 = SLAConfig.get_sla(:trial, :p1)

      assert trial_p1.response == 240  # 4 hours (best effort)
      assert trial_p1.resolution == 1440  # 24 hours
    end

    test "handles string tier input" do
      sla = SLAConfig.get_sla("enterprise", :p1)
      assert sla.response == 15
    end

    test "handles string priority input" do
      sla = SLAConfig.get_sla(:enterprise, "p1")
      assert sla.response == 15
    end

    test "handles both string inputs" do
      sla = SLAConfig.get_sla("enterprise", "p1")
      assert sla.response == 15
    end

    test "unknown tier falls back to trial" do
      sla = SLAConfig.get_sla(:unknown, :p1)
      trial_sla = SLAConfig.get_sla(:trial, :p1)

      assert sla == trial_sla
    end

    test "unknown priority falls back to p3" do
      sla = SLAConfig.get_sla(:enterprise, :unknown)
      p3_sla = SLAConfig.get_sla(:enterprise, :p3)

      # Should fallback to default (1440/4320)
      assert sla.response == 1440
      assert sla.resolution == 4320
    end

    test "all enterprise SLAs are faster than pro" do
      for priority <- [:p1, :p2, :p3, :p4] do
        enterprise = SLAConfig.get_sla(:enterprise, priority)
        pro = SLAConfig.get_sla(:pro, priority)

        assert enterprise.response <= pro.response,
          "Enterprise #{priority} response should be faster than Pro"
        assert enterprise.resolution <= pro.resolution,
          "Enterprise #{priority} resolution should be faster than Pro"
      end
    end

    test "all pro SLAs are faster than trial" do
      for priority <- [:p1, :p2, :p3, :p4] do
        pro = SLAConfig.get_sla(:pro, priority)
        trial = SLAConfig.get_sla(:trial, priority)

        assert pro.response <= trial.response,
          "Pro #{priority} response should be faster than Trial"
        assert pro.resolution <= trial.resolution,
          "Pro #{priority} resolution should be faster than Trial"
      end
    end
  end

  describe "calculate_deadlines/3" do
    test "calculates deadlines based on SLA" do
      created_at = ~U[2026-04-15 10:00:00Z]

      {:ok, deadlines} = SLAConfig.calculate_deadlines(:enterprise, :p1, created_at)

      # P1 enterprise: 15 min response, 4h resolution
      assert deadlines.response_deadline == ~U[2026-04-15 10:15:00Z]
      assert deadlines.resolution_deadline == ~U[2026-04-15 14:00:00Z]
    end

    test "calculates pro tier deadlines" do
      created_at = ~U[2026-04-15 10:00:00Z]

      {:ok, deadlines} = SLAConfig.calculate_deadlines(:pro, :p1, created_at)

      # P1 pro: 30 min response, 8h resolution
      assert deadlines.response_deadline == ~U[2026-04-15 10:30:00Z]
      assert deadlines.resolution_deadline == ~U[2026-04-15 18:00:00Z]
    end

    test "uses current time when not provided" do
      {:ok, deadlines} = SLAConfig.calculate_deadlines(:enterprise, :p2)

      now = DateTime.utc_now()
      # P2 enterprise: 60 min response
      assert DateTime.diff(deadlines.response_deadline, now) <= 60 * 60  # ~1 hour
      assert DateTime.diff(deadlines.response_deadline, now) >= 59 * 60  # at least 59 min
    end

    test "handles string inputs" do
      created_at = ~U[2026-04-15 10:00:00Z]

      {:ok, deadlines} = SLAConfig.calculate_deadlines("enterprise", "p1", created_at)

      assert deadlines.response_deadline == ~U[2026-04-15 10:15:00Z]
    end
  end

  describe "get_escalation_config/1" do
    test "returns P1 escalation path with multiple levels" do
      config = SLAConfig.get_escalation_config(:p1)

      assert length(config) == 3

      [first, second, third] = config
      assert first.to == :engineering_manager
      assert first.after_minutes == 15
      assert :pagerduty in first.channels
      assert :slack in first.channels

      assert second.to == :vp_engineering
      assert second.after_minutes == 30

      assert third.to == :ceo
      assert third.after_minutes == 60
    end

    test "P2 has fewer escalation levels than P1" do
      p1_config = SLAConfig.get_escalation_config(:p1)
      p2_config = SLAConfig.get_escalation_config(:p2)

      assert length(p1_config) > length(p2_config)
      assert length(p2_config) == 2
    end

    test "P2 escalation config" do
      config = SLAConfig.get_escalation_config(:p2)

      [first, second] = config
      assert first.to == :engineering_manager
      assert first.after_minutes == 60

      assert second.to == :vp_engineering
      assert second.after_minutes == 240
    end

    test "P3 has single escalation level" do
      config = SLAConfig.get_escalation_config(:p3)

      assert length(config) == 1
      [first] = config
      assert first.to == :engineering_manager
      assert first.after_minutes == 480
    end

    test "P4 has no auto-escalation" do
      config = SLAConfig.get_escalation_config(:p4)
      assert config == []
    end

    test "handles string priority input" do
      config = SLAConfig.get_escalation_config("p1")
      assert length(config) == 3
    end

    test "unknown priority returns empty list" do
      config = SLAConfig.get_escalation_config(:unknown)
      assert config == []
    end
  end

  describe "helper functions" do
    test "tiers returns all supported tiers" do
      tiers = SLAConfig.tiers()

      assert :enterprise in tiers
      assert :pro in tiers
      assert :trial in tiers
      assert length(tiers) == 3
    end

    test "priorities returns all priorities" do
      priorities = SLAConfig.priorities()

      assert priorities == [:p1, :p2, :p3, :p4]
    end
  end

  describe "escalation timing" do
    test "P1 escalations are progressively spaced" do
      config = SLAConfig.get_escalation_config(:p1)

      [first, second, third] = config
      assert second.after_minutes > first.after_minutes
      assert third.after_minutes > second.after_minutes
    end

    test "P1 first escalation is within response SLA" do
      sla = SLAConfig.get_sla(:enterprise, :p1)
      escalation = SLAConfig.get_escalation_config(:p1) |> List.first()

      assert escalation.after_minutes == sla.response
    end
  end
end
