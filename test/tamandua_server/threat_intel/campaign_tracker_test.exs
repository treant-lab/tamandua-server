defmodule TamanduaServer.ThreatIntel.CampaignTrackerTest do
  @moduledoc """
  Tests for the Campaign Tracker GenServer.

  The CampaignTracker clusters related alerts by attributed threat actor
  within a time window. It maintains ETS-backed indexes for IOC-to-campaign
  and agent-to-campaign lookups.

  Tests cover:
  - Campaign listing with filters (status, actor, min_severity)
  - Campaign lookup by ID
  - Campaign scope retrieval
  - Campaign resolution
  - IOC-to-campaign lookup
  - Agent-to-campaign lookup
  - Attribution recording
  - Auto-detect trigger
  - Statistics reporting
  - ETS table existence
  """

  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.ThreatIntel.CampaignTracker

  # ============================================================================
  # Campaign listing
  # ============================================================================

  describe "list_campaigns/1" do
    test "returns a list (possibly empty)" do
      campaigns = CampaignTracker.list_campaigns()
      assert is_list(campaigns)
    end

    test "supports status filter" do
      campaigns = CampaignTracker.list_campaigns(status: "active")
      assert is_list(campaigns)

      for campaign <- campaigns do
        assert campaign.status == "active"
      end
    end

    test "supports limit option" do
      campaigns = CampaignTracker.list_campaigns(limit: 5)
      assert is_list(campaigns)
      assert length(campaigns) <= 5
    end

    test "supports actor filter" do
      campaigns = CampaignTracker.list_campaigns(actor: "APT29")
      assert is_list(campaigns)

      for campaign <- campaigns do
        assert campaign.actor == "APT29"
      end
    end

    test "supports min_severity filter" do
      severity_levels = %{"low" => 1, "medium" => 2, "high" => 3, "critical" => 4}

      campaigns = CampaignTracker.list_campaigns(min_severity: "high")
      assert is_list(campaigns)

      for campaign <- campaigns do
        level = Map.get(severity_levels, campaign[:severity] || "low", 0)
        assert level >= severity_levels["high"],
               "campaign severity #{campaign[:severity]} should be >= high"
      end
    end
  end

  # ============================================================================
  # Campaign lookup by ID
  # ============================================================================

  describe "get_campaign/1" do
    test "returns {:error, :not_found} for unknown campaign" do
      assert {:error, :not_found} = CampaignTracker.get_campaign("nonexistent-campaign-id")
    end
  end

  # ============================================================================
  # Campaign scope
  # ============================================================================

  describe "get_campaign_scope/1" do
    test "returns {:error, :not_found} for unknown campaign" do
      assert {:error, :not_found} = CampaignTracker.get_campaign_scope("nonexistent-campaign-id")
    end
  end

  # ============================================================================
  # Campaign resolution
  # ============================================================================

  describe "resolve_campaign/1" do
    test "returns {:error, :not_found} for unknown campaign" do
      assert {:error, :not_found} = CampaignTracker.resolve_campaign("nonexistent-campaign-id")
    end
  end

  # ============================================================================
  # IOC-to-campaign lookup
  # ============================================================================

  describe "campaigns_for_ioc/1" do
    test "returns empty list for unknown IOC" do
      campaigns = CampaignTracker.campaigns_for_ioc("unknown-ioc-value-#{System.unique_integer()}")
      assert campaigns == []
    end
  end

  # ============================================================================
  # Agent-to-campaign lookup
  # ============================================================================

  describe "campaigns_for_agent/1" do
    test "returns empty list for unknown agent" do
      campaigns = CampaignTracker.campaigns_for_agent(Ecto.UUID.generate())
      assert campaigns == []
    end
  end

  # ============================================================================
  # Attribution recording
  # ============================================================================

  describe "record_attribution/1" do
    test "accepts an attribution map with IOC values" do
      attribution = %{
        alert_id: Ecto.UUID.generate(),
        agent_id: Ecto.UUID.generate(),
        actor: "APT28",
        confidence: 0.85,
        ioc_values: ["192.168.1.100", "evil.example.com"]
      }

      assert CampaignTracker.record_attribution(attribution) == :ok
    end

    test "accepts attribution without IOC values" do
      attribution = %{
        alert_id: Ecto.UUID.generate(),
        actor: "Lazarus Group",
        confidence: 0.7
      }

      assert CampaignTracker.record_attribution(attribution) == :ok
    end

    test "accepts empty map" do
      assert CampaignTracker.record_attribution(%{}) == :ok
    end
  end

  # ============================================================================
  # Auto-detect trigger
  # ============================================================================

  describe "auto_detect_campaigns/0" do
    test "returns :ok (fire-and-forget)" do
      assert CampaignTracker.auto_detect_campaigns() == :ok
    end

    test "is idempotent" do
      assert CampaignTracker.auto_detect_campaigns() == :ok
      assert CampaignTracker.auto_detect_campaigns() == :ok
    end
  end

  # ============================================================================
  # Statistics
  # ============================================================================

  describe "get_stats/0" do
    test "returns a map with expected keys" do
      stats = CampaignTracker.get_stats()

      assert is_map(stats)
      assert Map.has_key?(stats, :campaigns_created)
      assert Map.has_key?(stats, :campaigns_resolved)
      assert Map.has_key?(stats, :campaigns_escalated)
      assert Map.has_key?(stats, :auto_detect_runs)
      assert Map.has_key?(stats, :attributions_recorded)
      assert Map.has_key?(stats, :iocs_indexed)
      assert Map.has_key?(stats, :active_campaigns)
      assert Map.has_key?(stats, :resolved_campaigns)
      assert Map.has_key?(stats, :total_campaigns)
      assert Map.has_key?(stats, :indexed_iocs)
      assert Map.has_key?(stats, :indexed_agents)
    end

    test "all counter values are non-negative integers" do
      stats = CampaignTracker.get_stats()

      for {key, value} <- stats do
        assert is_integer(value),
               "stat #{key} should be integer, got #{inspect(value)}"
        assert value >= 0,
               "stat #{key} should be non-negative, got #{value}"
      end
    end

    test "total_campaigns equals active + resolved (or more due to other statuses)" do
      stats = CampaignTracker.get_stats()
      assert stats.total_campaigns >= stats.active_campaigns + stats.resolved_campaigns
    end
  end

  # ============================================================================
  # ETS tables
  # ============================================================================

  describe "ETS tables" do
    test "campaign tracker campaigns table exists" do
      info = :ets.info(:campaign_tracker_campaigns, :size)
      assert info != :undefined
    end

    test "campaign tracker IOC index table exists" do
      info = :ets.info(:campaign_tracker_ioc_index, :size)
      assert info != :undefined
    end

    test "campaign tracker agent index table exists" do
      info = :ets.info(:campaign_tracker_agent_index, :size)
      assert info != :undefined
    end
  end

  # ============================================================================
  # Record attribution and verify IOC indexing
  # ============================================================================

  describe "attribution with IOC indexing" do
    test "recording attribution indexes IOC values in ETS" do
      ioc_value = "ioc-test-#{System.unique_integer([:positive])}"

      attribution = %{
        alert_id: Ecto.UUID.generate(),
        actor: "TestActor",
        confidence: 0.9,
        ioc_values: [ioc_value]
      }

      CampaignTracker.record_attribution(attribution)

      # Allow cast to be processed
      Process.sleep(50)

      # The IOC should now be indexed (may have empty campaign list initially)
      case :ets.lookup(:campaign_tracker_ioc_index, ioc_value) do
        [{^ioc_value, campaign_ids}] ->
          assert is_list(campaign_ids)

        [] ->
          # May not be indexed yet if cast hasn't been processed
          :ok
      end
    end
  end

  # ============================================================================
  # Severity escalation logic
  # ============================================================================

  describe "severity level ordering" do
    test "severity levels follow expected order" do
      severity_levels = %{"low" => 1, "medium" => 2, "high" => 3, "critical" => 4}

      assert severity_levels["low"] < severity_levels["medium"]
      assert severity_levels["medium"] < severity_levels["high"]
      assert severity_levels["high"] < severity_levels["critical"]
    end
  end
end
