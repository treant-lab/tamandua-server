defmodule TamanduaServer.Response.ExecutorAuthorizationTest do
  @moduledoc """
  Tests for organization-scope authorization in `TamanduaServer.Response.Executor`.

  These tests exercise the actor/tenancy checks that close the cross-org
  response bypass (Workstream A3): an org-scoped actor must not be able to
  execute response actions (kill/isolate/quarantine/forensics) against agents
  belonging to another organization.

  The tests are deliberately DB-free: agents are registered in the in-memory
  `TamanduaServer.Agents.Registry` (the authoritative source for online
  agents), and only code paths that do not require a successful database
  round-trip are asserted. The DB fallback path (`db_org_check/2`) is
  fail-closed, so it yields `{:error, :unauthorized}` both when the agent does
  not exist in the actor's org AND when the database is unreachable — making
  that assertion environment-independent.
  """

  use ExUnit.Case, async: false

  alias TamanduaServer.Agents.Registry
  alias TamanduaServer.Response.Executor

  @org_a "org-aaaaaaaa-0000-0000-0000-000000000001"
  @org_b "org-bbbbbbbb-0000-0000-0000-000000000002"

  defp register_agent(org_id, worker_pid) do
    agent_id = "authz-agent-" <> Integer.to_string(System.unique_integer([:positive]))

    :ok =
      Registry.register(agent_id, %{
        hostname: "authz-test-host",
        os_type: "linux",
        organization_id: org_id,
        worker_pid: worker_pid
      })

    on_exit(fn -> Registry.unregister(agent_id) end)
    agent_id
  end

  describe "cross-organization actors are blocked (fail closed)" do
    test "isolate_network with a cross-org actor returns {:error, :unauthorized}" do
      agent_id = register_agent(@org_a, self())

      assert {:error, :unauthorized} =
               Executor.isolate_network(agent_id,
                 allowed_ips: [],
                 actor: %{organization_id: @org_b, user_id: "user-1"}
               )
    end

    test "unisolate_network with a cross-org actor returns {:error, :unauthorized}" do
      agent_id = register_agent(@org_a, self())

      assert {:error, :unauthorized} =
               Executor.unisolate_network(agent_id,
                 actor: %{organization_id: @org_b, user_id: "user-1"}
               )
    end

    test "kill_process with a cross-org actor returns {:error, :unauthorized}" do
      agent_id = register_agent(@org_a, self())

      assert {:error, :unauthorized} =
               Executor.kill_process(agent_id, 4242,
                 actor: %{organization_id: @org_b, user_id: "user-1"}
               )
    end

    test "quarantine_file with a cross-org actor returns {:error, :unauthorized}" do
      agent_id = register_agent(@org_a, self())

      assert {:error, :unauthorized} =
               Executor.quarantine_file(agent_id, "/tmp/evil.bin",
                 actor: %{organization_id: @org_b, user_id: "user-1"}
               )
    end

    test "scan_path with a cross-org actor returns {:error, :unauthorized}" do
      agent_id = register_agent(@org_a, self())

      assert {:error, :unauthorized} =
               Executor.scan_path(agent_id, "/tmp",
                 recursive: false,
                 actor: %{organization_id: @org_b, user_id: "user-1"}
               )
    end

    test "collect_forensics with a cross-org actor is rejected synchronously" do
      agent_id = register_agent(@org_a, self())

      assert {:error, :unauthorized} =
               Executor.collect_forensics(agent_id, %{
                 type: "full",
                 actor: %{organization_id: @org_b, user_id: "user-1"}
               })
    end

    test "collect_forensics with a string-keyed actor option is rejected synchronously" do
      agent_id = register_agent(@org_a, self())

      assert {:error, :unauthorized} =
               Executor.collect_forensics(agent_id, %{
                 "actor" => %{"organization_id" => @org_b, "user_id" => "user-1"},
                 type: "quick"
               })
    end

    test "collect_artifact with a cross-org actor returns {:error, :unauthorized}" do
      agent_id = register_agent(@org_a, self())

      assert {:error, :unauthorized} =
               Executor.collect_artifact(agent_id, "/tmp/evidence.bin", "file",
                 actor: %{organization_id: @org_b, user_id: "user-1"}
               )
    end

    test "string-keyed actor maps are also enforced" do
      agent_id = register_agent(@org_a, self())

      assert {:error, :unauthorized} =
               Executor.execute_action(agent_id, "kill_process", %{pid: 1},
                 actor: %{"organization_id" => @org_b, "user_id" => "user-1"}
               )
    end
  end

  describe "malformed / incomplete actors fail closed" do
    test "an actor map without organization_id is rejected" do
      agent_id = register_agent(@org_a, self())

      assert {:error, :unauthorized} =
               Executor.execute_action(agent_id, "kill_process", %{pid: 1},
                 actor: %{user_id: "user-without-org"}
               )
    end

    test "a non-map, non-:system actor is rejected" do
      agent_id = register_agent(@org_a, self())

      action = %{
        action_type: "kill_process",
        agent_id: agent_id,
        params: %{pid: 1},
        actor: "bogus"
      }

      assert {:error, :unauthorized} = Executor.execute_response(nil, action)
    end

    test "an org-scoped actor targeting an unknown agent is rejected" do
      # Agent is NOT in the Registry, so the check falls back to the DB
      # (db_org_check/2). That path is fail-closed: not found, cast error,
      # or DB unavailable all deny the action.
      missing_agent_id = "authz-missing-" <> Integer.to_string(System.unique_integer([:positive]))

      assert {:error, :unauthorized} =
               Executor.execute_action(missing_agent_id, "kill_process", %{pid: 1},
                 actor: %{organization_id: @org_b, user_id: "user-1"}
               )
    end
  end

  describe "same-org and internal actors are allowed" do
    # The remote-target (dispatch_to_agent) path is used so the test does not
    # depend on a live Worker GenServer: authorization runs BEFORE dispatch,
    # and dispatch only requires a registered agent with a live worker_pid.

    test "a same-org actor passes authorization and the action dispatches" do
      agent_id = register_agent(@org_a, self())

      action = %{
        action_type: "isolate_network",
        agent_id: agent_id,
        params: %{allowed_ips: []},
        target_agent_id: agent_id,
        actor: %{organization_id: @org_a, user_id: "user-1"}
      }

      assert {:ok, %{dispatched: true, transport: :websocket}} =
               Executor.execute_response(nil, action)
    end

    test "a :system actor passes authorization" do
      agent_id = register_agent(@org_a, self())

      action = %{
        action_type: "isolate_network",
        agent_id: agent_id,
        params: %{allowed_ips: []},
        target_agent_id: agent_id,
        actor: :system
      }

      assert {:ok, %{dispatched: true, transport: :websocket}} =
               Executor.execute_response(nil, action)
    end

    test "legacy callers without an actor keep working" do
      agent_id = register_agent(@org_a, self())

      action = %{
        action_type: "kill_process",
        agent_id: agent_id,
        params: %{pid: 1},
        target_agent_id: agent_id
      }

      assert {:ok, %{dispatched: true, transport: :websocket}} =
               Executor.execute_response(nil, action)
    end

    test "same-org collect_forensics starts a collection" do
      # A dead worker pid keeps the async execute_action short-lived
      # (agent_offline) while authorization still resolves the org from the
      # Registry entry.
      dead_pid = spawn(fn -> :ok end)
      ref = Process.monitor(dead_pid)
      assert_receive {:DOWN, ^ref, :process, ^dead_pid, _}, 1_000

      agent_id = register_agent(@org_a, dead_pid)

      assert {:ok, collection_id} =
               Executor.collect_forensics(agent_id, %{
                 type: "quick",
                 requested_by: "user-1",
                 actor: %{organization_id: @org_a, user_id: "user-1"}
               })

      assert is_binary(collection_id)
      assert {:ok, record} = Executor.get_collection_status(collection_id)
      assert record.agent_id == agent_id
      assert record.requested_by == "user-1"
    end

    test "same-org collect_artifact passes authorization and dispatches" do
      agent_id = register_agent(@org_a, self())

      assert {:ok, %{dispatched: true, transport: :websocket}} =
               Executor.execute_response(nil, %{
                 action_type: "collect_artifact",
                 agent_id: agent_id,
                 params: %{path: "/tmp/evidence.bin", artifact_type: "file"},
                 target_agent_id: agent_id,
                 actor: %{organization_id: @org_a, user_id: "user-1"}
               })
    end
  end

  describe "alert/agent organization consistency (confused-deputy defense)" do
    test "an alert scoped to another org cannot drive actions on this agent" do
      agent_id = register_agent(@org_a, self())

      alert = %{id: Ecto.UUID.generate(), organization_id: @org_b}

      action = %{
        action_type: "kill_process",
        agent_id: agent_id,
        params: %{pid: 1},
        target_agent_id: agent_id
      }

      assert {:error, :unauthorized} = Executor.execute_response(alert, action)
    end

    test "an alert in the agent's own org is allowed" do
      agent_id = register_agent(@org_a, self())

      alert = %{id: Ecto.UUID.generate(), organization_id: @org_a}

      action = %{
        action_type: "kill_process",
        agent_id: agent_id,
        params: %{pid: 1},
        target_agent_id: agent_id
      }

      assert {:ok, %{dispatched: true, transport: :websocket}} =
               Executor.execute_response(alert, action)
    end
  end
end
