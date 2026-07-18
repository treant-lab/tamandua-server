defmodule TamanduaServer.Investigations.StorylineTenantIsolationTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.Investigations.Storyline

  @org_a "00000000-0000-0000-0000-00000000000a"
  @org_b "00000000-0000-0000-0000-00000000000b"

  setup do
    for table <- [
          :investigation_story_events,
          :investigation_story_index,
          :investigation_stories
        ] do
      :ets.delete_all_objects(table)
    end

    :ok
  end

  test "requires organization context and stores it on every story" do
    assert {:error, :organization_required} = Storyline.create_story(event())

    assert {:error, :organization_required} =
             Storyline.add_event_to_story("unknown", event(organization_id: @org_a))

    assert {:error, :organization_required} =
             Storyline.auto_correlate(event(organization_id: @org_a))

    assert {:error, :organization_required} = Storyline.get_story("unknown")
    assert {:error, :organization_required} = Storyline.get_active_stories()
    assert {:error, :organization_required} = Storyline.stats()

    assert {:ok, story_id} = Storyline.create_story(@org_a, event())
    assert {:ok, %{organization_id: @org_a}} = Storyline.get_story(@org_a, story_id)
    assert {:error, :not_found} = Storyline.get_story(@org_b, story_id)
  end

  test "rejects conflicting organizations before mutation" do
    assert {:error, :organization_mismatch} =
             Storyline.create_story(@org_a, event(organization_id: @org_b))

    assert {:error, :organization_mismatch} =
             Storyline.create_story(@org_a, [
               event(organization_id: @org_a),
               event(organization_id: @org_b)
             ])

    assert {:error, :invalid_events} = Storyline.create_story(@org_a, [])
  end

  test "scopes reads, lists and mutations without disclosing cross-tenant existence" do
    assert {:ok, story_a} = Storyline.create_story(@org_a, event(id: "alert-a"))
    assert {:ok, story_b} = Storyline.create_story(@org_b, event(id: "alert-b"))

    assert {:ok, [%{id: ^story_a}]} = Storyline.get_active_stories(@org_a, [])
    assert {:ok, [%{id: ^story_b}]} = Storyline.get_active_stories(@org_b, [])

    assert {:error, :not_found} =
             Storyline.add_event_to_story(@org_b, story_a, event(id: "cross-add"))

    assert {:error, :not_found} =
             Storyline.resolve_story(@org_b, story_a, %{state: "resolved"})

    assert {:error, :not_found} = Storyline.merge_stories(@org_a, story_a, story_b)
    assert {:error, :not_found} = Storyline.get_story_timeline(@org_b, story_a)
    assert {:error, :not_found} = Storyline.get_story_graph(@org_b, story_a)
    assert {:error, :not_found} = Storyline.get_kill_chain_coverage(@org_b, story_a)

    assert {:ok, %{event_count: 1, state: "open"}} = Storyline.get_story(@org_a, story_a)
  end

  test "auto-correlation never joins stories across organizations" do
    shared = [agent_id: "shared-agent", pid: 4242, remote_ip: "203.0.113.10"]

    assert {:ok, story_a} = Storyline.auto_correlate(@org_a, event(shared))
    assert {:ok, story_b} = Storyline.auto_correlate(@org_b, event(shared))
    refute story_a == story_b

    assert {:ok, ^story_a} =
             Storyline.auto_correlate(@org_a, event(Keyword.put(shared, :id, "alert-a-2")))

    assert {:ok, %{event_count: 2}} = Storyline.get_story(@org_a, story_a)
    assert {:ok, %{event_count: 1}} = Storyline.get_story(@org_b, story_b)
  end

  test "same-tenant mutations and derived reads remain available" do
    assert {:ok, story_a} = Storyline.create_story(@org_a, event(id: "alert-a"))
    assert {:ok, story_b} = Storyline.create_story(@org_a, event(id: "alert-b"))

    assert {:ok, ^story_a} = Storyline.merge_stories(@org_a, story_a, story_b)
    assert {:error, :not_found} = Storyline.get_story(@org_a, story_b)
    assert {:ok, timeline} = Storyline.get_story_timeline(@org_a, story_a)
    assert length(timeline) == 2
    assert {:ok, %{story_id: ^story_a}} = Storyline.get_story_graph(@org_a, story_a)
    assert {:ok, %{total_stages: 14}} = Storyline.get_kill_chain_coverage(@org_a, story_a)

    assert :ok = Storyline.resolve_story(@org_a, story_a, %{state: "resolved"})
    assert {:ok, %{state: "resolved"}} = Storyline.get_story(@org_a, story_a)
  end

  test "tenant statistics do not include another organization's stories or events" do
    assert {:ok, story_a} = Storyline.create_story(@org_a, event(id: "alert-a"))
    assert {:ok, _story_b} = Storyline.create_story(@org_b, event(id: "alert-b"))
    assert :ok = Storyline.add_event_to_story(@org_a, story_a, event(id: "alert-a-2"))

    assert %{total_stories: 1, total_events: 2, active_stories: 1} = Storyline.stats(@org_a)
    assert %{total_stories: 1, total_events: 1, active_stories: 1} = Storyline.stats(@org_b)
  end

  defp event(overrides \\ []) do
    organization_id = Keyword.get(overrides, :organization_id)

    %{
      id: Keyword.get(overrides, :id, "alert-1"),
      organization_id: organization_id,
      agent_id: Keyword.get(overrides, :agent_id, "agent-1"),
      pid: Keyword.get(overrides, :pid, 100),
      severity: "high",
      timestamp: DateTime.utc_now(),
      raw_event: %{remote_ip: Keyword.get(overrides, :remote_ip)}
    }
  end
end
