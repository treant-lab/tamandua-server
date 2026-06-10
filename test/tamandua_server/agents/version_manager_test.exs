defmodule TamanduaServer.Agents.VersionManagerTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Agents.VersionManager
  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.Accounts.Organization

  describe "get_version_inventory/1" do
    setup do
      org = insert(:organization)
      {:ok, org: org}
    end

    test "returns empty map when no agents", %{org: org} do
      assert VersionManager.get_version_inventory(org.id) == %{}
    end

    test "counts agents by version", %{org: org} do
      insert(:agent, organization: org, agent_version: "1.0.0")
      insert(:agent, organization: org, agent_version: "1.0.0")
      insert(:agent, organization: org, agent_version: "1.1.0")

      inventory = VersionManager.get_version_inventory(org.id)

      assert inventory["1.0.0"] == 2
      assert inventory["1.1.0"] == 1
    end

    test "handles nil versions", %{org: org} do
      insert(:agent, organization: org, agent_version: nil)
      insert(:agent, organization: org, agent_version: "1.0.0")

      inventory = VersionManager.get_version_inventory(org.id)

      assert inventory[nil] == 1
      assert inventory["1.0.0"] == 1
    end
  end

  describe "get_version_by_os/1" do
    test "breaks down versions by OS type" do
      org = insert(:organization)

      insert(:agent, organization: org, agent_version: "1.0.0", os_type: "windows")
      insert(:agent, organization: org, agent_version: "1.0.0", os_type: "linux")
      insert(:agent, organization: org, agent_version: "1.1.0", os_type: "windows")

      breakdown = VersionManager.get_version_by_os(org.id)

      assert length(breakdown) == 3
      assert Enum.find(breakdown, &(&1.version == "1.0.0" and &1.os_type == "windows"))
      assert Enum.find(breakdown, &(&1.version == "1.0.0" and &1.os_type == "linux"))
      assert Enum.find(breakdown, &(&1.version == "1.1.0" and &1.os_type == "windows"))
    end
  end

  describe "compare_versions/2" do
    test "compares major versions" do
      assert VersionManager.compare_versions("2.0.0", "1.0.0") == :gt
      assert VersionManager.compare_versions("1.0.0", "2.0.0") == :lt
      assert VersionManager.compare_versions("1.0.0", "1.0.0") == :eq
    end

    test "compares minor versions" do
      assert VersionManager.compare_versions("1.2.0", "1.1.0") == :gt
      assert VersionManager.compare_versions("1.1.0", "1.2.0") == :lt
    end

    test "compares patch versions" do
      assert VersionManager.compare_versions("1.0.2", "1.0.1") == :gt
      assert VersionManager.compare_versions("1.0.1", "1.0.2") == :lt
    end

    test "handles prerelease versions" do
      assert VersionManager.compare_versions("1.0.0", "1.0.0-beta") == :gt
      assert VersionManager.compare_versions("1.0.0-beta", "1.0.0") == :lt
      assert VersionManager.compare_versions("1.0.0-beta", "1.0.0-beta") == :eq
    end

    test "handles v prefix" do
      assert VersionManager.compare_versions("v1.0.0", "v1.0.0") == :eq
      assert VersionManager.compare_versions("v2.0.0", "v1.0.0") == :gt
    end

    test "returns error for invalid versions" do
      assert VersionManager.compare_versions("invalid", "1.0.0") == :error
      assert VersionManager.compare_versions("1.0.0", "invalid") == :error
    end
  end

  describe "parse_version/1" do
    test "parses standard semantic version" do
      assert {:ok, %{major: 1, minor: 2, patch: 3, prerelease: nil}} =
               VersionManager.parse_version("1.2.3")
    end

    test "parses version with prerelease" do
      assert {:ok, %{major: 1, minor: 2, patch: 3, prerelease: "beta"}} =
               VersionManager.parse_version("1.2.3-beta")

      assert {:ok, %{major: 1, minor: 2, patch: 3, prerelease: "beta.1"}} =
               VersionManager.parse_version("1.2.3-beta.1")
    end

    test "parses version with v prefix" do
      assert {:ok, %{major: 1, minor: 2, patch: 3}} =
               VersionManager.parse_version("v1.2.3")
    end

    test "returns error for invalid version" do
      assert {:error, :invalid_version} = VersionManager.parse_version("invalid")
      assert {:error, :invalid_version} = VersionManager.parse_version("1.2")
      assert {:error, :invalid_version} = VersionManager.parse_version("")
    end
  end

  describe "get_outdated_agents/2" do
    test "returns agents with versions older than target" do
      org = insert(:organization)

      agent1 = insert(:agent, organization: org, agent_version: "1.0.0")
      agent2 = insert(:agent, organization: org, agent_version: "1.1.0")
      agent3 = insert(:agent, organization: org, agent_version: "2.0.0")

      outdated = VersionManager.get_outdated_agents(org.id, "1.5.0")

      outdated_ids = Enum.map(outdated, & &1.id)
      assert agent1.id in outdated_ids
      assert agent2.id in outdated_ids
      refute agent3.id in outdated_ids
    end
  end

  describe "check_eol_status/1" do
    test "returns EOL status for old versions" do
      status = VersionManager.check_eol_status("0.1.0")
      assert status.status == :eol
      assert status.recommended_action =~ "Upgrade immediately"
    end

    test "returns approaching EOL for 0.4.x versions" do
      status = VersionManager.check_eol_status("0.4.5")
      assert status.status == :approaching_eol
      assert status.recommended_action =~ "Plan upgrade"
    end

    test "returns supported for recent versions" do
      status = VersionManager.check_eol_status("1.5.0")
      assert status.status == :supported
      assert status.recommended_action =~ "No action needed"
    end
  end

  describe "check_compatibility/1" do
    test "returns compatibility status for version" do
      compat = VersionManager.check_compatibility("1.5.0")

      assert compat.backend in [:compatible, :incompatible]
      assert compat.ml_service in [:compatible, :partial, :incompatible]
      assert compat.schema in [:compatible, :incompatible]
      assert is_list(compat.features)
    end

    test "newer versions have more features" do
      compat_old = VersionManager.check_compatibility("1.0.0")
      compat_new = VersionManager.check_compatibility("2.0.0")

      assert length(compat_new.features) >= length(compat_old.features)
    end
  end

  describe "get_version_stats/1" do
    test "calculates comprehensive version statistics" do
      org = insert(:organization)

      # Create agents with various versions
      insert(:agent, organization: org, agent_version: "2.0.0")
      insert(:agent, organization: org, agent_version: "2.0.0")
      insert(:agent, organization: org, agent_version: "1.5.0")
      insert(:agent, organization: org, agent_version: "0.1.0") # EOL

      stats = VersionManager.get_version_stats(org.id)

      assert stats.total_agents == 4
      assert stats.unique_versions == 3
      assert stats.latest_version == "2.0.0"
      assert stats.up_to_date_count == 2
      assert stats.outdated_count == 2
      assert stats.eol_count >= 1
      assert stats.outdated_percentage == 50.0
    end

    test "handles empty fleet" do
      org = insert(:organization)
      stats = VersionManager.get_version_stats(org.id)

      assert stats.total_agents == 0
      assert stats.unique_versions == 0
      assert stats.outdated_percentage == 0.0
    end
  end

  describe "get_eligible_agents/2" do
    test "returns agents eligible for upgrade" do
      org = insert(:organization)

      update_package = %{
        version: "2.0.0",
        platform: "linux",
        architecture: "x86_64",
        min_agent_version: "1.0.0"
      }

      agent1 = insert(:agent, organization: org, agent_version: "1.5.0", os_type: "linux")
      agent2 = insert(:agent, organization: org, agent_version: "2.0.0", os_type: "linux")
      agent3 = insert(:agent, organization: org, agent_version: "1.5.0", os_type: "windows")
      agent4 = insert(:agent, organization: org, agent_version: "0.5.0", os_type: "linux")

      eligible = VersionManager.get_eligible_agents(org.id, update_package)
      eligible_ids = Enum.map(eligible, & &1.id)

      # Should include agent1 (older version, correct OS, meets minimum)
      assert agent1.id in eligible_ids

      # Should exclude agent2 (already at target version)
      refute agent2.id in eligible_ids

      # Should exclude agent3 (wrong OS)
      refute agent3.id in eligible_ids

      # Should exclude agent4 (below minimum version)
      refute agent4.id in eligible_ids
    end
  end
end
