defmodule TamanduaServer.Agents.RegistryRuntimeSnapshotTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.Agents.Registry

  @algorithm "screen_capture_policy_hash_sha256_lexical_v2"

  test "publishes only for the exact tenant, socket, worker and connection epoch" do
    agent_id = Ecto.UUID.generate()
    organization_id = Ecto.UUID.generate()
    epoch = "current-connection"
    other_pid = spawn(fn -> Process.sleep(:infinity) end)

    Registry.register(agent_id, %{
      hostname: "registry-runtime-test",
      os_type: "windows",
      organization_id: organization_id,
      worker_pid: self(),
      socket_pid: self(),
      connection_epoch: epoch,
      capabilities: ["screen_capture", @algorithm]
    })

    on_exit(fn ->
      Process.exit(other_pid, :kill)
      Registry.unregister(agent_id)
    end)

    runtime = %{capabilities: ["screen_capture", @algorithm], screen_session_broker: nil}

    assert {:error, :runtime_tenant_mismatch} =
             Registry.update_runtime_snapshot(
               agent_id,
               Ecto.UUID.generate(),
               self(),
               self(),
               epoch,
               runtime
             )

    assert {:error, :invalid_runtime_snapshot} =
             Registry.update_runtime_snapshot(
               agent_id,
               nil,
               self(),
               self(),
               epoch,
               runtime
             )

    assert {:error, :stale_runtime_connection} =
             Registry.update_runtime_snapshot(
               agent_id,
               organization_id,
               other_pid,
               self(),
               epoch,
               runtime
             )

    assert {:error, :stale_runtime_connection} =
             Registry.update_runtime_snapshot(
               agent_id,
               organization_id,
               self(),
               self(),
               "prior-connection",
               runtime
             )

    assert :ok =
             Registry.update_runtime_snapshot(
               agent_id,
               organization_id,
               self(),
               self(),
               epoch,
               runtime
             )

    assert {:ok, %{generation: 1, connection_epoch: ^epoch}} =
             Registry.get_runtime_snapshot(agent_id)
  end

  test "rejects malformed capabilities and unknown policy hash algorithms" do
    assert {:error, :invalid_runtime_capabilities} =
             Registry.normalize_runtime_capabilities([@algorithm, %{unexpected: true}])

    assert {:error, :invalid_runtime_capabilities} =
             Registry.normalize_runtime_capabilities([
               "screen_capture_policy_hash_sha256_enum_order_v1"
             ])

    assert {:error, :invalid_policy_hash_algorithm} =
             Registry.normalize_policy_hash_algorithms([
               "screen_capture_policy_hash_sha256_enum_order_v1"
             ])

    assert {:ok, [@algorithm]} =
             Registry.normalize_runtime_capabilities([@algorithm, @algorithm])
  end

  test "requires an exact canonical organization UUID for runtime publication" do
    agent_id = Ecto.UUID.generate()
    organization_id = Ecto.UUID.generate()
    epoch = "canonical-organization"

    Registry.register(agent_id, %{
      hostname: "registry-canonical-tenant-test",
      os_type: "windows",
      organization_id: organization_id,
      worker_pid: self(),
      socket_pid: self(),
      connection_epoch: epoch,
      capabilities: [@algorithm]
    })

    on_exit(fn -> Registry.unregister(agent_id) end)

    runtime = %{capabilities: [@algorithm], screen_session_broker: nil}

    assert Registry.canonical_organization_id?(organization_id)
    assert Registry.same_canonical_organization_id?(organization_id, organization_id)

    refute Registry.same_canonical_organization_id?(
             organization_id,
             String.upcase(organization_id)
           )

    refute Registry.same_canonical_organization_id?(organization_id, :organization_id)

    for invalid <- [
          nil,
          "",
          :organization_id,
          42,
          %{organization_id: organization_id},
          String.upcase(organization_id)
        ] do
      refute Registry.canonical_organization_id?(invalid)

      assert {:error, :invalid_runtime_snapshot} =
               Registry.update_runtime_snapshot(
                 agent_id,
                 invalid,
                 self(),
                 self(),
                 epoch,
                 runtime
               )
    end

    assert :ok =
             Registry.update_runtime_snapshot(
               agent_id,
               organization_id,
               self(),
               self(),
               epoch,
               runtime
             )
  end

  test "register rejects noncanonical tenants before storing agent or runtime state" do
    canonical = Ecto.UUID.generate()

    for invalid <- [nil, :organization_id, 42, %{id: canonical}, String.upcase(canonical)] do
      agent_id = Ecto.UUID.generate()

      assert {:error, :invalid_organization_id} =
               Registry.register(agent_id, %{
                 hostname: "invalid-registration",
                 os_type: "windows",
                 organization_id: invalid,
                 worker_pid: self(),
                 socket_pid: self(),
                 connection_epoch: "must-not-be-stored",
                 capabilities: [@algorithm]
               })

      assert [] == :ets.lookup(:tamandua_agents, agent_id)
      assert {:error, :not_found} = Registry.get_runtime_snapshot(agent_id)
    end
  end

  test "rejects malformed registered tenant types without string coercion or raising" do
    agent_id = Ecto.UUID.generate()
    organization_id = Ecto.UUID.generate()
    epoch = "poisoned-organization"

    Registry.register(agent_id, %{
      hostname: "registry-poisoned-tenant-test",
      os_type: "windows",
      organization_id: organization_id,
      worker_pid: self(),
      socket_pid: self(),
      connection_epoch: epoch,
      capabilities: [@algorithm]
    })

    on_exit(fn -> Registry.unregister(agent_id) end)

    runtime = %{capabilities: [@algorithm], screen_session_broker: nil}
    [{^agent_id, original}] = :ets.lookup(:tamandua_agents, agent_id)

    for poisoned <- [
          nil,
          :organization_id,
          42,
          %{organization_id: organization_id},
          String.upcase(organization_id)
        ] do
      :ets.insert(:tamandua_agents, {agent_id, %{original | organization_id: poisoned}})

      assert {:error, :runtime_tenant_mismatch} =
               Registry.update_runtime_snapshot(
                 agent_id,
                 organization_id,
                 self(),
                 self(),
                 epoch,
                 runtime
               )
    end
  end
end
