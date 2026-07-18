defmodule TamanduaServer.Agents.PresenceTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Agents
  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.Agents.{Registry, Worker}
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Repo

  import Ecto.Query

  setup do
    previous_lab_light = System.get_env("TAMANDUA_LAB_LIGHT")
    System.put_env("TAMANDUA_LAB_LIGHT", "true")

    on_exit(fn ->
      if previous_lab_light do
        System.put_env("TAMANDUA_LAB_LIGHT", previous_lab_light)
      else
        System.delete_env("TAMANDUA_LAB_LIGHT")
      end
    end)

    org = insert(:organization)
    agent = insert(:agent, organization_id: org.id, status: "offline")

    {:ok, org: org, agent: agent}
  end

  describe "agent presence persistence" do
    test "heartbeat persists online status after the DB throttle window", %{agent: agent, org: org} do
      pid = start_worker!(agent, org)
      old_seen_at = ~N[2024-01-01 00:00:00]
      force_agent_presence(agent.id, "offline", old_seen_at)

      :sys.replace_state(pid, fn state ->
        %{state | last_db_heartbeat: System.system_time(:millisecond) - :timer.seconds(31)}
      end)

      Worker.heartbeat(pid)
      eventually(fn ->
        updated = Repo.get!(Agent, agent.id)
        assert updated.status == "online"
        assert NaiveDateTime.compare(updated.last_seen_at, old_seen_at) == :gt
      end)
    end

    test "heartbeat does not write to DB inside the throttle window", %{agent: agent, org: org} do
      pid = start_worker!(agent, org)
      old_seen_at = ~N[2024-01-01 00:00:00]
      force_agent_presence(agent.id, "offline", old_seen_at)

      Worker.heartbeat(pid)
      Process.sleep(100)

      updated = Repo.get!(Agent, agent.id)
      assert updated.status == "offline"
      assert updated.last_seen_at == old_seen_at
    end

    test "heartbeat timeout unregisters current worker and marks agent offline", %{agent: agent, org: org} do
      pid = start_worker!(agent, org)
      last_seen_at = ~N[2026-05-22 07:21:41]
      force_agent_presence(agent.id, "online", last_seen_at)

      :sys.replace_state(pid, fn state ->
        %{state | last_heartbeat: System.system_time(:millisecond) - :timer.seconds(181)}
      end)

      ref = Process.monitor(pid)
      send(pid, :check_heartbeat)

      assert_receive {:DOWN, ^ref, :process, ^pid, _reason}, 1_000
      assert {:error, :not_found} = Registry.get(agent.id)
      updated = Repo.get!(Agent, agent.id)
      assert updated.status == "offline"
      assert updated.last_seen_at == last_seen_at
    end

    test "heartbeat timeout creates agent blinded alert", %{agent: agent, org: org} do
      pid = start_worker!(agent, org)

      :sys.replace_state(pid, fn state ->
        %{state | last_heartbeat: System.system_time(:millisecond) - :timer.seconds(181)}
      end)

      ref = Process.monitor(pid)
      send(pid, :check_heartbeat)

      assert_receive {:DOWN, ^ref, :process, ^pid, _reason}, 1_000

      alert =
        Repo.get_by!(Alert,
          agent_id: agent.id,
          dedup_key: "agent_blinded:#{agent.id}"
        )

      assert alert.organization_id == org.id
      assert alert.severity == "high"
      assert alert.detection_metadata["detection_type"] == "agent_blinded"
      assert alert.detection_metadata["clean_shutdown_observed"] == false
      assert alert.raw_event["event_type"] == "agent_blinded"
      assert alert.raw_event["heartbeat_timeout_ms"] == :timer.seconds(180)
    end

    test "socket disconnect does not create agent blinded alert", %{agent: agent, org: org} do
      pid = start_worker!(agent, org)
      ref = Process.monitor(pid)

      send(pid, {:DOWN, make_ref(), :process, self(), :normal})

      assert_receive {:DOWN, ^ref, :process, ^pid, _reason}, 1_000

      refute Repo.get_by(Alert,
               agent_id: agent.id,
               dedup_key: "agent_blinded:#{agent.id}"
             )
    end

    test "marking offline does not make a stale agent look recently seen", %{agent: agent, org: org} do
      old_seen_at = ~N[2024-01-01 00:00:00]
      force_agent_presence(agent.id, "online", old_seen_at)

      assert :ok = Agents.mark_agent_offline(agent.id, org.id)

      updated = Repo.get!(Agent, agent.id)
      assert updated.status == "offline"
      assert updated.last_seen_at == old_seen_at
    end

    test "tenant-scoped offline update does not modify another organization", %{agent: agent} do
      other_org = insert(:organization)

      assert {:error, :not_found} = Agents.mark_agent_offline(agent.id, other_org.id)
      assert Repo.get!(Agent, agent.id).status == "offline"
    end

    test "list_all_for_org keeps recent persisted online presence outside registry", %{agent: agent, org: org} do
      force_agent_presence(agent.id, "online", NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second))
      Registry.unregister(agent.id)

      listed_agent = Enum.find(Agents.list_all_for_org(org.id), &(&1.agent_id == agent.id))

      assert listed_agent.status == :online
    end

    test "list_all_for_org treats stale persisted online presence as offline", %{agent: agent, org: org} do
      stale_seen_at =
        NaiveDateTime.utc_now()
        |> NaiveDateTime.add(-180, :second)
        |> NaiveDateTime.truncate(:second)

      force_agent_presence(agent.id, "online", stale_seen_at)
      Registry.unregister(agent.id)

      listed_agent = Enum.find(Agents.list_all_for_org(org.id), &(&1.agent_id == agent.id))

      assert listed_agent.status == :offline
    end

    test "registry list does not report online when worker process is dead", %{agent: agent, org: org} do
      dead_worker =
        spawn(fn ->
          :ok
        end)

      ref = Process.monitor(dead_worker)
      assert_receive {:DOWN, ^ref, :process, ^dead_worker, _reason}, 1_000

      Registry.register(agent.id, %{
        hostname: agent.hostname,
        ip_address: agent.ip_address,
        os_type: agent.os_type,
        os_version: agent.os_version,
        agent_version: agent.agent_version,
        machine_id: agent.machine_id,
        organization_id: org.id,
        worker_pid: dead_worker
      })

      listed_agent = Enum.find(Registry.list_all(), &(&1.agent_id == agent.id))

      assert listed_agent.status == :offline
      assert Registry.lookup_agent(agent.id) == nil
    end
  end

  defp start_worker!(agent, org) do
    start_supervised!(
      {Worker,
       [
         agent_id: agent.id,
         socket_pid: self(),
         agent_info: %{
           hostname: agent.hostname,
           ip_address: agent.ip_address,
           os_type: agent.os_type,
           os_version: agent.os_version,
           agent_version: agent.agent_version,
           machine_id: agent.machine_id,
           organization_id: org.id
         }
       ]}
    )
  end

  defp force_agent_presence(agent_id, status, last_seen_at) do
    Repo.update_all(
      from(a in Agent, where: a.id == ^agent_id),
      set: [status: status, last_seen_at: last_seen_at]
    )
  end

  defp eventually(fun, attempts \\ 10)
  defp eventually(fun, 1), do: fun.()

  defp eventually(fun, attempts) do
    fun.()
  rescue
    ExUnit.AssertionError ->
      Process.sleep(50)
      eventually(fun, attempts - 1)
  end
end
