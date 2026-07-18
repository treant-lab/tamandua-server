defmodule TamanduaServer.Agents.RegistryHealthTest do
  use TamanduaServer.DataCase, async: false

  @organization_id "22222222-2222-4222-8222-222222222222"

  alias TamanduaServer.Agents.Registry

  test "update_health preserves platform visibility in health and registry entries" do
    agent_id = "agent-platform-visibility-health-test"

    Registry.register(agent_id, %{
      hostname: "visibility-host",
      ip_address: "127.0.0.1",
      os_type: "linux",
      os_version: "6.8",
      agent_version: "test",
      machine_id: "machine-visibility",
      organization_id: @organization_id,
      worker_pid: self()
    })

    platform_visibility = %{
      "status" => "degraded",
      "evidence_source" => "platform_status",
      "active_sensors" => [],
      "degraded_sensors" => ["linux_ebpf"],
      "unavailable_sensors" => ["linux_auditd"],
      "reasons" => ["linux_ebpf: runtime attach status must be reported by the collector"],
      "claim_boundary" => "health event summary"
    }

    Registry.update_health(agent_id, %{
      "cpu_usage" => 1.0,
      "memory_usage_percent" => 2.0,
      "disk_usage_percent" => 3.0,
      "platform_visibility" => platform_visibility
    })

    assert {:ok, health} = Registry.get_health(agent_id)
    assert health.platform_visibility == platform_visibility

    assert {:ok, entry} = Registry.get(agent_id)
    assert entry.platform_visibility == platform_visibility
  after
    Registry.unregister("agent-platform-visibility-health-test")
  end
end
