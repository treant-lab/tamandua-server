defmodule TamanduaServer.Agents.CollectorCatalogTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Agents.CollectorCatalog

  test "exposes endpoint collectors across supported operating systems" do
    collectors = CollectorCatalog.all_collectors()

    for collector <- ~w(process file network dns etw amsi ebpf auditd tcc_monitor xpc_monitor ai_discovery dlp network_dpi) do
      assert collector in collectors
    end
  end

  test "normalizes legacy collector aliases" do
    assert CollectorCatalog.normalize_collector("kernel-events") == "etw"
    assert CollectorCatalog.normalize_collector("edr_blinding") == "defense_evasion"
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
