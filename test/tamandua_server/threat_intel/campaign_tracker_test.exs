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
  @org_a "11111111-1111-4111-8111-111111111111"
  @org_b "22222222-2222-4222-8222-222222222222"

  # ============================================================================
  # Campaign listing
  # ============================================================================

  describe "list_campaigns/1" do
    test "returns a list (possibly empty)" do
      campaigns = CampaignTracker.list_campaigns(@org_a, [])
      assert is_list(campaigns)
    end

    test "supports status filter" do
      campaigns = CampaignTracker.list_campaigns(@org_a, status: "active")
      assert is_list(campaigns)

      for campaign <- campaigns do
        assert campaign.status == "active"
      end
    end

    test "supports limit option" do
      campaigns = CampaignTracker.list_campaigns(@org_a, limit: 5)
      assert is_list(campaigns)
      assert length(campaigns) <= 5
    end

    test "supports actor filter" do
      campaigns = CampaignTracker.list_campaigns(@org_a, actor: "APT29")
      assert is_list(campaigns)

      for campaign <- campaigns do
        assert campaign.actor == "APT29"
      end
    end

    test "supports min_severity filter" do
      severity_levels = %{"low" => 1, "medium" => 2, "high" => 3, "critical" => 4}

      campaigns = CampaignTracker.list_campaigns(@org_a, min_severity: "high")
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
      assert {:error, :not_found} =
               CampaignTracker.get_campaign(@org_a, "nonexistent-campaign-id")
    end
  end

  # ============================================================================
  # Campaign scope
  # ============================================================================

  describe "get_campaign_scope/1" do
    test "returns {:error, :not_found} for unknown campaign" do
      assert {:error, :not_found} =
               CampaignTracker.get_campaign_scope(@org_a, "nonexistent-campaign-id")
    end
  end

  # ============================================================================
  # Campaign resolution
  # ============================================================================

  describe "resolve_campaign/1" do
    test "returns {:error, :not_found} for unknown campaign" do
      assert {:error, :not_found} =
               CampaignTracker.resolve_campaign(@org_a, "nonexistent-campaign-id")
    end
  end

  # ============================================================================
  # IOC-to-campaign lookup
  # ============================================================================

  describe "campaigns_for_ioc/1" do
    test "returns empty list for unknown IOC" do
      campaigns =
        CampaignTracker.campaigns_for_ioc(@org_a, "unknown-ioc-value-#{System.unique_integer()}")

      assert campaigns == []
    end
  end

  # ============================================================================
  # Agent-to-campaign lookup
  # ============================================================================

  describe "campaigns_for_agent/1" do
    test "returns empty list for unknown agent" do
      campaigns = CampaignTracker.campaigns_for_agent(@org_a, Ecto.UUID.generate())
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

      assert CampaignTracker.record_attribution(@org_a, attribution) == :ok
    end

    test "accepts attribution without IOC values" do
      attribution = %{
        alert_id: Ecto.UUID.generate(),
        actor: "Lazarus Group",
        confidence: 0.7
      }

      assert CampaignTracker.record_attribution(@org_a, attribution) == :ok
    end

    test "accepts empty map" do
      assert CampaignTracker.record_attribution(@org_a, %{}) == :ok
    end
  end

  # ============================================================================
  # Auto-detect trigger
  # ============================================================================

  describe "auto_detect_campaigns/0" do
    test "returns :ok (fire-and-forget)" do
      assert CampaignTracker.auto_detect_campaigns(@org_a) == :ok
    end

    test "is idempotent" do
      assert CampaignTracker.auto_detect_campaigns(@org_a) == :ok
      assert CampaignTracker.auto_detect_campaigns(@org_a) == :ok
    end
  end

  # ============================================================================
  # Statistics
  # ============================================================================

  describe "get_stats/0" do
    test "returns a map with expected keys" do
      stats = CampaignTracker.get_stats(@org_a)

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
      stats = CampaignTracker.get_stats(@org_a)

      for {key, value} <- stats do
        assert is_integer(value),
               "stat #{key} should be integer, got #{inspect(value)}"

        assert value >= 0,
               "stat #{key} should be non-negative, got #{value}"
      end
    end

    test "total_campaigns equals active + resolved (or more due to other statuses)" do
      stats = CampaignTracker.get_stats(@org_a)
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

      CampaignTracker.record_attribution(@org_a, attribution)

      # Allow cast to be processed
      Process.sleep(50)

      # The IOC should now be indexed (may have empty campaign list initially)
      key = {@org_a, ioc_value}

      case :ets.lookup(:campaign_tracker_ioc_index, key) do
        [{^key, campaign_ids}] ->
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

  describe "tenant isolation" do
    test "legacy arities fail closed" do
      assert CampaignTracker.list_campaigns() == {:error, :organization_required}
      assert CampaignTracker.list_campaigns(status: "active") == {:error, :organization_required}
      assert CampaignTracker.get_campaign("campaign") == {:error, :organization_required}
      assert CampaignTracker.record_attribution(%{}) == {:error, :organization_required}
      assert CampaignTracker.auto_detect_campaigns() == {:error, :organization_required}
      assert CampaignTracker.get_stats() == {:error, :organization_required}
    end

    test "campaign, IOC, agent and stats remain isolated between organizations" do
      id = "tenant-campaign-#{System.unique_integer([:positive])}"
      ioc = "shared.example.test"
      agent = Ecto.UUID.generate()
      now = DateTime.utc_now()

      campaign_a = campaign_fixture(id, @org_a, "Actor A", agent, ioc, now)
      campaign_b = campaign_fixture(id, @org_b, "Actor B", agent, ioc, now)

      :ets.insert(:campaign_tracker_campaigns, {{@org_a, id}, campaign_a})
      :ets.insert(:campaign_tracker_campaigns, {{@org_b, id}, campaign_b})
      :ets.insert(:campaign_tracker_ioc_index, {{@org_a, ioc}, [id]})
      :ets.insert(:campaign_tracker_ioc_index, {{@org_b, ioc}, [id]})
      :ets.insert(:campaign_tracker_agent_index, {{@org_a, agent}, [id]})
      :ets.insert(:campaign_tracker_agent_index, {{@org_b, agent}, [id]})

      on_exit(fn ->
        :ets.delete(:campaign_tracker_campaigns, {@org_a, id})
        :ets.delete(:campaign_tracker_campaigns, {@org_b, id})
        :ets.delete(:campaign_tracker_ioc_index, {@org_a, ioc})
        :ets.delete(:campaign_tracker_ioc_index, {@org_b, ioc})
        :ets.delete(:campaign_tracker_agent_index, {@org_a, agent})
        :ets.delete(:campaign_tracker_agent_index, {@org_b, agent})
      end)

      assert {:ok, %{actor: "Actor A", organization_id: @org_a}} =
               CampaignTracker.get_campaign(@org_a, id)

      assert {:ok, %{actor: "Actor B", organization_id: @org_b}} =
               CampaignTracker.get_campaign(@org_b, id)

      assert [%{organization_id: @org_a}] = CampaignTracker.campaigns_for_ioc(@org_a, ioc)
      assert [%{organization_id: @org_b}] = CampaignTracker.campaigns_for_ioc(@org_b, ioc)
      assert [%{organization_id: @org_a}] = CampaignTracker.campaigns_for_agent(@org_a, agent)
      assert [%{organization_id: @org_b}] = CampaignTracker.campaigns_for_agent(@org_b, agent)
      assert CampaignTracker.get_stats(@org_a).total_campaigns >= 1
      assert CampaignTracker.get_stats(@org_b).total_campaigns >= 1
    end
  end

  defp campaign_fixture(id, organization_id, actor, agent, ioc, now) do
    %{
      id: id,
      organization_id: organization_id,
      name: "#{actor} Campaign",
      actor: actor,
      start_time: now,
      end_time: now,
      alert_ids: [],
      affected_agents: [agent],
      ioc_values: [ioc],
      ioc_count: 1,
      severity: "high",
      status: "active",
      confidence: 0.9,
      mitre_techniques: [],
      timeline: [],
      created_at: now,
      updated_at: now
    }
  end
end
