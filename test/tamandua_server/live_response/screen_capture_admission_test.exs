defmodule TamanduaServer.LiveResponse.ScreenCaptureAdmissionTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.Agents.Registry
  alias TamanduaServer.LiveResponse.ScreenCaptureAdmission

  @algorithm "screen_capture_policy_hash_sha256_lexical_v2"

  setup do
    agent_id = Ecto.UUID.generate()
    organization_id = Ecto.UUID.generate()
    epoch = Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false)

    Registry.register(agent_id, %{
      hostname: "policy-v2-test",
      os_type: "windows",
      organization_id: organization_id,
      worker_pid: self(),
      socket_pid: self(),
      connection_epoch: epoch,
      capabilities: ["screen_capture", @algorithm]
    })

    on_exit(fn -> Registry.unregister(agent_id) end)

    %{
      agent: %{id: agent_id, os_type: "windows"},
      organization_id: organization_id,
      epoch: epoch
    }
  end

  test "allows multi-scope only when the current agent and fresh broker negotiate the exact algorithm",
       context do
    assert :ok = publish(context, [@algorithm], broker(@algorithm))

    assert :ok =
             ScreenCaptureAdmission.authorize(
               context.agent,
               context.organization_id,
               %{kind: :desktop},
               multi_scope_policy()
             )
  end

  test "fails closed when either side is missing or advertises a wrong algorithm", context do
    assert :ok = publish(context, [], broker(@algorithm))
    assert_denied(context, :agent_policy_hash_algorithm_not_negotiated)

    assert :ok = publish(context, [@algorithm], broker(nil))
    assert_denied(context, :broker_policy_hash_algorithm_not_negotiated)

    assert {:error, :invalid_policy_hash_algorithm} =
             Registry.update_runtime_snapshot(
               context.agent.id,
               context.organization_id,
               self(),
               self(),
               context.epoch,
               %{
                 capabilities: [@algorithm],
                 screen_session_broker: broker("screen_capture_policy_hash_sha256_enum_v1")
               }
             )
  end

  test "rejects stale and future server receipt evidence", context do
    assert :ok = publish(context, [@algorithm], broker(@algorithm))

    mutate_received_at(context.agent.id, fn now ->
      now - ScreenCaptureAdmission.runtime_max_age_ms() - 1
    end)

    assert_denied(context, :runtime_snapshot_stale)

    assert :ok = publish(context, [@algorithm], broker(@algorithm))
    mutate_received_at(context.agent.id, &(&1 + 1_000))
    assert_denied(context, :runtime_snapshot_from_future)
  end

  test "legacy single-scope remains observable without negotiated evidence", context do
    assert :ok =
             ScreenCaptureAdmission.authorize(
               context.agent,
               context.organization_id,
               %{kind: :desktop},
               %{
                 allowed_scopes: ["virtual_desktop"],
                 policy: %{hash: String.duplicate("0", 64)}
               }
             )
  end

  test "legacy boundary rejects malformed, unknown, duplicate and reordered scopes", context do
    for scopes <- [
          [],
          ["unknown"],
          ["virtual_desktop", "virtual_desktop"],
          ["virtual_desktop", "active_window"]
        ] do
      assert {:error, {:screen_capture_admission_denied, :invalid_policy_scope_evidence}} =
               ScreenCaptureAdmission.authorize(
                 context.agent,
                 context.organization_id,
                 %{kind: :desktop},
                 %{allowed_scopes: scopes, policy: %{hash: String.duplicate("0", 64)}}
               )
    end
  end

  test "rejects a snapshot after its socket process has exited", context do
    dead_socket = spawn(fn -> :ok end)
    monitor = Process.monitor(dead_socket)
    assert_receive {:DOWN, ^monitor, :process, ^dead_socket, _reason}

    mutate_socket_pid(context.agent.id, dead_socket)
    assert_denied(context, :runtime_connection_mismatch)
  end

  test "rejects tenant mismatch and a prior connection epoch", context do
    assert :ok = publish(context, [@algorithm], broker(@algorithm))

    assert {:error, {:screen_capture_admission_denied, :runtime_tenant_mismatch}} =
             ScreenCaptureAdmission.authorize(
               context.agent,
               Ecto.UUID.generate(),
               %{kind: :desktop},
               multi_scope_policy()
             )

    assert {:error, :stale_runtime_connection} =
             Registry.update_runtime_snapshot(
               context.agent.id,
               context.organization_id,
               self(),
               self(),
               "prior-connection",
               %{capabilities: [@algorithm], screen_session_broker: broker(@algorithm)}
             )
  end

  test "rejects noncanonical caller tenants even on the legacy single-scope path", context do
    policy = %{
      allowed_scopes: ["virtual_desktop"],
      policy: %{hash: String.duplicate("0", 64)}
    }

    for invalid <- [
          nil,
          "",
          :organization_id,
          42,
          %{organization_id: context.organization_id},
          String.upcase(context.organization_id)
        ] do
      assert {:error, {:screen_capture_admission_denied, :runtime_tenant_mismatch}} =
               ScreenCaptureAdmission.authorize(
                 context.agent,
                 invalid,
                 %{kind: :desktop},
                 policy
               )
    end
  end

  test "rejects poisoned runtime and snapshot tenant types without raising", context do
    assert :ok = publish(context, [@algorithm], broker(@algorithm))
    [{agent_id, original}] = :ets.lookup(:tamandua_agents, context.agent.id)

    for {field, poisoned} <- [
          {:runtime, nil},
          {:runtime, :organization_id},
          {:runtime, %{organization_id: context.organization_id}},
          {:runtime, String.upcase(context.organization_id)},
          {:snapshot, nil},
          {:snapshot, 42},
          {:snapshot, %{organization_id: context.organization_id}},
          {:snapshot, String.upcase(context.organization_id)}
        ] do
      poisoned_runtime =
        case field do
          :runtime ->
            %{original | organization_id: poisoned}

          :snapshot ->
            %{
              original
              | runtime_snapshot: %{original.runtime_snapshot | organization_id: poisoned}
            }
        end

      :ets.insert(:tamandua_agents, {agent_id, poisoned_runtime})
      assert_denied(context, :runtime_tenant_mismatch)
    end
  end

  defp publish(context, capabilities, broker) do
    Registry.update_runtime_snapshot(
      context.agent.id,
      context.organization_id,
      self(),
      self(),
      context.epoch,
      %{capabilities: capabilities, screen_session_broker: broker}
    )
  end

  defp broker(algorithm) do
    %{
      "schema_version" => "tamandua.screen_session_broker/v1",
      "state" => "ready",
      "ready" => true,
      "capabilities" => ["screen_capture"],
      "policy_hash_algorithms" => if(algorithm, do: [algorithm], else: []),
      "observed_at" => DateTime.utc_now() |> DateTime.to_iso8601()
    }
  end

  defp multi_scope_policy do
    %{
      allowed_scopes: ["active_window", "virtual_desktop"],
      policy: %{hash_algorithm: @algorithm, hash: String.duplicate("0", 64)}
    }
  end

  defp assert_denied(context, reason) do
    assert {:error, {:screen_capture_admission_denied, ^reason}} =
             ScreenCaptureAdmission.authorize(
               context.agent,
               context.organization_id,
               %{kind: :desktop},
               multi_scope_policy()
             )
  end

  defp mutate_received_at(agent_id, fun) do
    [{^agent_id, runtime}] = :ets.lookup(:tamandua_agents, agent_id)
    snapshot = runtime.runtime_snapshot
    received = snapshot.server_received_monotonic_ms

    updated = %{
      runtime
      | runtime_snapshot: %{snapshot | server_received_monotonic_ms: fun.(received)}
    }

    :ets.insert(:tamandua_agents, {agent_id, updated})
  end

  defp mutate_socket_pid(agent_id, socket_pid) do
    [{^agent_id, runtime}] = :ets.lookup(:tamandua_agents, agent_id)

    updated = %{
      runtime
      | socket_pid: socket_pid,
        runtime_snapshot: %{runtime.runtime_snapshot | socket_pid: socket_pid}
    }

    :ets.insert(:tamandua_agents, {agent_id, updated})
  end
end
