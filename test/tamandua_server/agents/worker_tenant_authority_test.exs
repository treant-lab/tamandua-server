defmodule TamanduaServer.Agents.WorkerTenantAuthorityTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Agents.{Agent, OrgLookup, Registry, Worker}
  alias TamanduaServer.Repo

  defp worker_opts(agent_id, organization_id, overrides \\ %{}, socket_pid \\ self()) do
    [
      agent_id: agent_id,
      socket_pid: socket_pid,
      agent_info:
        Map.merge(
          %{
            hostname: "tenant-authority-host",
            os_type: "linux",
            organization_id: organization_id
          },
          overrides
        )
    ]
  end

  test "rejects a non-canonical organization before mutating the agent table" do
    agent_id = Ecto.UUID.generate()

    assert {:error, :invalid_organization_id} =
             Worker.start_link(worker_opts(agent_id, "ORG-NOT-CANONICAL"))

    assert Repo.get(Agent, agent_id) == nil
    assert {:error, :not_found} = Registry.get(agent_id)
  end

  test "persists and caches the exact authenticated organization" do
    organization = insert(:organization)
    agent_id = Ecto.UUID.generate()

    assert {:ok, worker} = Worker.start_link(worker_opts(agent_id, organization.id))
    assert Worker.get_state(worker).organization_id === organization.id
    assert Repo.get!(Agent, agent_id).organization_id === organization.id
    assert OrgLookup.get_org_id(agent_id) === organization.id
    assert :ok = GenServer.stop(worker)
  end

  test "does not move an existing agent to a different authenticated tenant" do
    original_organization = insert(:organization)
    requested_organization = insert(:organization)
    agent = insert(:agent, organization: original_organization, hostname: "original-host")

    assert {:error, :agent_tenant_mismatch} =
             Worker.start_link(
               worker_opts(agent.id, requested_organization.id, %{hostname: "replacement-host"})
             )

    persisted = Repo.get!(Agent, agent.id)
    assert persisted.organization_id === original_organization.id
    assert persisted.hostname === "original-host"
    assert {:error, :not_found} = Registry.get(agent.id)
  end

  test "concurrent tenants cannot mutate the winning agent identity" do
    first_organization = insert(:organization)
    second_organization = insert(:organization)
    agent_id = Ecto.UUID.generate()
    socket_holder = self()

    attempts = [
      {first_organization.id, "first-tenant-host"},
      {second_organization.id, "second-tenant-host"}
    ]

    results =
      attempts
      |> Enum.map(fn {organization_id, hostname} ->
        task =
          Task.async(fn ->
            Worker.start_link(
              worker_opts(agent_id, organization_id, %{hostname: hostname}, socket_holder)
            )
          end)

        {organization_id, hostname, task}
      end)
      |> Enum.map(fn {organization_id, hostname, task} ->
        {organization_id, hostname, Task.await(task)}
      end)

    workers = for {_organization_id, _hostname, {:ok, worker}} <- results, do: worker

    on_exit(fn ->
      Enum.each(workers, fn worker ->
        if Process.alive?(worker), do: GenServer.stop(worker)
      end)

      Registry.unregister(agent_id)
      OrgLookup.invalidate(agent_id)
    end)

    assert [{winning_organization_id, winning_hostname, {:ok, worker}}] =
             Enum.filter(results, &match?({_, _, {:ok, _worker}}, &1))

    assert [{losing_organization_id, losing_hostname, {:error, :agent_tenant_mismatch}}] =
             Enum.reject(results, &match?({_, _, {:ok, _worker}}, &1))

    refute losing_organization_id === winning_organization_id
    persisted = Repo.get!(Agent, agent_id)
    assert persisted.organization_id === winning_organization_id
    assert persisted.hostname === winning_hostname
    refute persisted.hostname === losing_hostname
    assert Worker.get_state(worker).organization_id === winning_organization_id
    assert OrgLookup.get_org_id(agent_id) === winning_organization_id
    assert :ok = GenServer.stop(worker)
  end

  test "source contract has no tenant fallback and propagates registry failure" do
    source =
      __DIR__
      |> Path.join("../../../lib/tamandua_server/agents/worker.ex")
      |> File.read!()

    refute source =~ "OrgLookup.get_org_id"
    refute source =~ "organization_id ||"
    assert source =~ "Repo.transaction(fn ->"
    assert source =~ "pg_advisory_xact_lock(hashtextextended($1, 0))"
    assert source =~ ":ok <- Registry.register"
    assert source =~ "{:stop, reason}"

    transaction = :binary.match(source, "Repo.transaction(fn ->")
    insert = :binary.match(source, "Repo.insert_all(")
    cache = :binary.match(source, "OrgLookup.put(agent_id, organization_id)")

    assert elem(transaction, 0) < elem(insert, 0)
    assert elem(insert, 0) < elem(cache, 0)
  end
end
