defmodule TamanduaServer.Detection.CrossAgentCorrelatorTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Detection.CrossAgentCorrelator

  test "campaign linkage separates real event UUIDs from storyline references" do
    event_id = Ecto.UUID.generate()

    entries = [
      %{agent_id: "agent-b", event_id: event_id, storyline_id: "story-b"},
      %{agent_id: "agent-a", event_id: "not-a-uuid", storyline_id: "story-a"},
      %{agent_id: "agent-c", event_id: nil, storyline_id: "story-c"}
    ]

    assert CrossAgentCorrelator.campaign_event_ids(entries) == [event_id]

    assert CrossAgentCorrelator.campaign_contributing_events(entries) == [
             "not-a-uuid",
             "storyline:story-a",
             "storyline:story-b",
             "storyline:story-c",
             event_id
           ]

    correlation_data =
      CrossAgentCorrelator.campaign_correlation_data(:domain, "evil.example", entries, [
        "agent-b",
        "agent-a",
        "agent-c"
      ], [
        "story-b",
        "story-a",
        "story-c"
      ])

    assert correlation_data["event_ids"] == [event_id]
    assert correlation_data["event_refs"] == ["not-a-uuid", event_id]
    assert correlation_data["agent_ids"] == ["agent-a", "agent-b", "agent-c"]
    assert correlation_data["storyline_ids"] == ["story-a", "story-b", "story-c"]
  end

  test "campaign linkage does not invent event IDs for storyline-only entries" do
    entries = [
      %{agent_id: "agent-a", storyline_id: "story-a"},
      %{agent_id: "agent-b", storyline_id: "story-b"}
    ]

    assert CrossAgentCorrelator.campaign_event_ids(entries) == []
    assert CrossAgentCorrelator.campaign_contributing_events(entries) == [
             "storyline:story-a",
             "storyline:story-b"
           ]

    correlation_data =
      CrossAgentCorrelator.campaign_correlation_data(:ip, "203.0.113.10", entries, [
        "agent-a",
        "agent-b"
      ], [
        "story-a",
        "story-b"
      ])

    assert correlation_data["event_ids"] == []
    assert correlation_data["event_refs"] == []
  end
end
