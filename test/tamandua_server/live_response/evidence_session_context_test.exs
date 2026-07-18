defmodule TamanduaServer.LiveResponse.EvidenceSessionContextTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.LiveResponse.EvidenceSessionContext
  alias TamanduaServer.Repo
  alias TamanduaServer.Telemetry.Event

  @from ~U[2026-07-15 12:00:00.000000Z]
  @to ~U[2026-07-15 12:10:00.000000Z]
  @now ~U[2026-07-15 12:11:00.000000Z]

  test "queries the real event source by tenant, agent, and inclusive window" do
    organization = insert(:organization)
    agent = insert(:agent, organization: organization)
    other_agent = insert(:agent, organization: organization)

    process = event!(organization.id, agent.id, "process_create", @from, %{"pid" => 42})

    network =
      event!(organization.id, agent.id, "network_connect", @to, %{"dest_ip" => "203.0.113.7"})

    event!(organization.id, other_agent.id, "process_exec", DateTime.add(@from, 1), %{"pid" => 99})

    event!(organization.id, agent.id, "process_exec", DateTime.add(@from, -1), %{"pid" => 100})
    event!(organization.id, agent.id, "file_create", DateTime.add(@from, 2), %{})

    assert {:ok, context} =
             EvidenceSessionContext.build(organization.id, agent.id, @from, @to, now: @now)

    assert context.organization_id == organization.id
    assert context.agent_id == agent.id
    assert context.process.state == "observed"
    assert context.process.observed_count == 1
    assert [%{event_id: process_id, pid: 42}] = context.process.events
    assert process_id == process.id
    assert context.network.state == "observed"
    assert [%{event_id: network_id, destination_ip: "203.0.113.7"}] = context.network.events
    assert network_id == network.id
  end

  test "does not disclose whether an agent exists in another tenant" do
    owner = insert(:organization)
    attacker = insert(:organization)
    agent = insert(:agent, organization: owner)

    assert {:error, :not_found} =
             EvidenceSessionContext.build(attacker.id, agent.id, @from, @to, now: @now)
  end

  test "distinguishes successful absence from telemetry unavailability" do
    organization_id = Ecto.UUID.generate()
    agent_id = Ecto.UUID.generate()

    empty_loader = fn _, _, _, _, _ -> {:ok, []} end

    assert {:ok, absent} =
             EvidenceSessionContext.build(organization_id, agent_id, @from, @to,
               loader: empty_loader,
               now: @now
             )

    assert absent.process.state == "not_observed"
    assert absent.process.observed_count == 0
    assert absent.network.state == "not_observed"

    failing_loader = fn _, _, _, _, _ -> raise "database secret must not leak" end

    assert {:ok, unavailable} =
             EvidenceSessionContext.build(organization_id, agent_id, @from, @to,
               loader: failing_loader,
               now: @now
             )

    assert unavailable.process == %{
             state: "unavailable",
             reason: "telemetry_query_unavailable",
             observed_count: nil,
             events: [],
             truncated: false
           }

    refute inspect(unavailable) =~ "database secret"
  end

  test "enforces bounded windows and query limits" do
    organization_id = Ecto.UUID.generate()
    agent_id = Ecto.UUID.generate()

    assert {:error, :invalid_window} =
             EvidenceSessionContext.build(
               organization_id,
               agent_id,
               @from,
               DateTime.add(@from, 3_601),
               now: @now
             )

    assert {:error, :invalid_limit} =
             EvidenceSessionContext.build(organization_id, agent_id, @from, @to,
               limit: 0,
               now: @now
             )

    loader = fn _, _, _, _, limit ->
      send(self(), {:effective_limit, limit})
      {:ok, []}
    end

    assert {:ok, %{query_limit: 500}} =
             EvidenceSessionContext.build(organization_id, agent_id, @from, @to,
               limit: 50_000,
               loader: loader,
               now: @now
             )

    assert_received {:effective_limit, 500}
  end

  test "returns at most fifty summaries, marks truncation, and is idempotent" do
    organization_id = Ecto.UUID.generate()
    agent_id = Ecto.UUID.generate()

    events =
      for offset <- 0..59 do
        %Event{
          id: Ecto.UUID.generate(),
          organization_id: organization_id,
          agent_id: agent_id,
          event_type: "process_exec",
          timestamp: DateTime.add(@from, offset),
          payload: %{"pid" => offset, "command_line" => String.duplicate("x", 3_000)}
        }
      end

    loader = fn _, _, _, _, _ -> {:ok, events} end
    opts = [loader: loader, now: @now]

    assert {:ok, first} =
             EvidenceSessionContext.build(organization_id, agent_id, @from, @to, opts)

    assert {:ok, second} =
             EvidenceSessionContext.build(organization_id, agent_id, @from, @to, opts)

    assert first == second
    assert first.process.observed_count == 60
    assert length(first.process.events) == 50
    assert first.process.truncated
    assert String.length(hd(first.process.events).command_line) == 2_048
    assert first.network.state == "not_observed"
  end

  test "redacts common credential forms from exported summaries" do
    organization_id = Ecto.UUID.generate()
    agent_id = Ecto.UUID.generate()

    event = %Event{
      id: Ecto.UUID.generate(),
      event_type: "process_exec",
      timestamp: @from,
      payload: %{"command_line" => "curl -H 'Authorization: Bearer abc123' --token topsecret"}
    }

    loader = fn _, _, _, _, _ -> {:ok, [event]} end

    assert {:ok, context} =
             EvidenceSessionContext.build(organization_id, agent_id, @from, @to,
               loader: loader,
               now: @now
             )

    command = hd(context.process.events).command_line
    assert command =~ "[REDACTED]"
    refute command =~ "abc123"
    refute command =~ "topsecret"
  end

  defp event!(organization_id, agent_id, event_type, timestamp, payload) do
    Repo.insert!(%Event{
      organization_id: organization_id,
      agent_id: agent_id,
      event_type: event_type,
      timestamp: timestamp,
      payload: payload
    })
  end
end
