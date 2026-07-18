defmodule TamanduaServer.Agents.CollectorCatalogTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Agents.CollectorCatalog

  test "exposes endpoint collectors across supported operating systems" do
    collectors = CollectorCatalog.all_collectors()

    for collector <-
          ~w(process file network dns etw amsi ebpf auditd proxmox tcc_monitor xpc_monitor ai_discovery dlp network_dpi) do
      assert collector in collectors
    end
  end

  test "keeps runtime integrity default-off through the v1/v2 projection migration" do
    assert CollectorCatalog.valid_collector?("runtime-integrity")
    assert "runtime_integrity" in CollectorCatalog.common_collectors()

    for profile <- CollectorCatalog.profiles() do
      refute Map.has_key?(
               CollectorCatalog.default_template(profile)["collectors"],
               "runtime_integrity"
             )
    end
  end

  test "normalizes legacy collector aliases" do
    assert CollectorCatalog.normalize_collector("kernel-events") == "etw"
    assert CollectorCatalog.normalize_collector("edr_blinding") == "defense_evasion"
  end

  test "catalogues plugin and BOF work as lab or design dormant without policy enablement" do
    metadata = CollectorCatalog.collector_metadata()
    dormant = metadata.lab_design_dormant

    assert Enum.map(dormant, & &1.id) == ["plugin_runtime", "bof_loader", "dynamic_collector"]
    assert Enum.all?(dormant, &(&1.policy_enabled == false))
    assert Enum.all?(dormant, &(&1.maturity in ["lab", "design_dormant"]))

    refute CollectorCatalog.valid_collector?("plugin-runtime")
    refute CollectorCatalog.valid_collector?("bof_loader")
    refute CollectorCatalog.valid_collector?("dynamic_collector")
  end

  test "exposes capability gaps required before dynamic collector enablement" do
    gap_ids =
      CollectorCatalog.capability_gaps()
      |> Enum.map(& &1.id)

    for gap_id <-
          ~w(plugin_manifest_contract sandbox_enforcement runtime_telemetry_contract policy_rollout_gate) do
      assert gap_id in gap_ids
    end
  end

  test "templates include profile, collectors, resource limits, and rollout gates" do
    template = CollectorCatalog.default_template("high_value_asset")

    assert template["profile"] == "high_value_asset"
    assert template["collectors"]["credential_theft"]["enabled"] == true
    assert template["collectors"]["lateral_movement"]["interval_ms"] == 10_000
    assert template["resource_limits"]["max_cpu_percent"] == 20
    assert template["rollout"]["health_gates"]["min_success_rate_percent"] == 90
  end
end
