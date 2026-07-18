defmodule TamanduaServer.Telemetry.LatestAIDiscoveryEventTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Telemetry

  test "finds the newest AI discovery event independently of recent unrelated events" do
    organization = insert!(:organization)
    agent = insert!(:agent, organization: organization)
    now = DateTime.utc_now()

    expected =
      insert!(:event, %{
        agent: agent,
        organization_id: organization.id,
        event_type: "ai_discovery",
        timestamp: DateTime.add(now, -120, :second),
        payload: %{"ai_discovery" => true, "model_observations" => []}
      })

    for offset <- 1..25 do
      insert!(:event, %{
        agent: agent,
        organization_id: organization.id,
        event_type: "process_start",
        timestamp: DateTime.add(now, -offset, :second),
        payload: %{}
      })
    end

    insert!(:event, %{
      agent: agent,
      organization_id: organization.id,
      event_type: "process_start",
      timestamp: now,
      payload: %{"ai_discovery" => true}
    })

    assert Telemetry.latest_ai_discovery_event_for_agent(organization.id, agent.id).id ==
             expected.id
  end

  test "uses event id as a deterministic tie-break for equal timestamps" do
    organization = insert!(:organization)
    agent = insert!(:agent, organization: organization)
    timestamp = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    events =
      for score <- [0.1, 0.2] do
        insert!(:event, %{
          agent: agent,
          organization_id: organization.id,
          event_type: "ai_discovery",
          timestamp: timestamp,
          payload: %{"ai_discovery" => true, "score" => score}
        })
      end

    expected_id = events |> Enum.map(& &1.id) |> Enum.max()

    assert Telemetry.latest_ai_discovery_event_for_agent(organization.id, agent.id).id ==
             expected_id
  end
end
