defmodule TamanduaServer.Detection.StorylineTenantIsolationTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.Detection.Storyline

  setup do
    assert Process.whereis(Storyline)
    :ok
  end

  test "list, show, and agent APIs expose only the requested organization" do
    org_a = unique_id("org-a")
    org_b = unique_id("org-b")
    agent_a = unique_id("agent-a")
    agent_b = unique_id("agent-b")

    storyline_a = create_storyline(org_a, agent_a, 10_001)
    storyline_b = create_storyline(org_b, agent_b, 20_001)

    assert {:ok, [%{id: ^storyline_a, organization_id: ^org_a}]} =
             Storyline.list_storylines(org_a)

    assert {:ok, [%{id: ^storyline_b, organization_id: ^org_b}]} =
             Storyline.list_storylines(org_b)

    assert {:ok, %{id: ^storyline_a}} = Storyline.get_storyline(org_a, storyline_a)
    assert {:error, :not_found} = Storyline.get_storyline(org_b, storyline_a)

    assert {:ok, [%{id: ^storyline_a}]} =
             Storyline.get_agent_storylines(org_a, agent_a)

    assert {:ok, []} = Storyline.get_agent_storylines(org_b, agent_a)
  end

  test "merge is fail-closed across organizations" do
    org_a = unique_id("org-a")
    org_b = unique_id("org-b")

    first = create_storyline(org_a, unique_id("agent-a1"), 30_001)
    second = create_storyline(org_a, unique_id("agent-a2"), 30_002)
    foreign = create_storyline(org_b, unique_id("agent-b"), 40_001)

    assert {:error, :not_found} = Storyline.merge_storylines(org_a, first, foreign)
    assert {:ok, %{id: ^foreign}} = Storyline.get_storyline(org_b, foreign)

    assert :ok = Storyline.merge_storylines(org_a, first, second)

    assert {:ok, %{id: ^first, organization_id: ^org_a}} =
             Storyline.get_storyline(org_a, first)

    assert {:error, :not_found} = Storyline.get_storyline(org_a, second)
    assert {:error, :not_found} = Storyline.merge_storylines(org_b, first, first)
  end

  test "engine statistics and counters are tenant-scoped" do
    org_a = unique_id("org-a")
    org_b = unique_id("org-b")

    create_storyline(org_a, unique_id("agent-a1"), 50_001)
    create_storyline(org_a, unique_id("agent-a2"), 50_002)
    create_storyline(org_b, unique_id("agent-b"), 60_001)

    stats_a = Storyline.stats(org_a)
    stats_b = Storyline.stats(org_b)

    assert stats_a.process_tree_size == 2
    assert stats_a.storyline_count == 2
    assert stats_a.pid_mappings == 2
    assert stats_a.counters.process_events == 2
    assert stats_a.counters.detections_ingested == 2
    assert stats_a.counters.storylines_created == 2

    assert stats_b.process_tree_size == 1
    assert stats_b.storyline_count == 1
    assert stats_b.pid_mappings == 1
    assert stats_b.counters.process_events == 1
    assert stats_b.counters.detections_ingested == 1
    assert stats_b.counters.storylines_created == 1
  end

  test "same agent and pid can be reused across organizations without contamination" do
    org_a = unique_id("org-a")
    org_b = unique_id("org-b")
    shared_agent = unique_id("shared-agent")
    shared_pid = 65_001

    storyline_a = create_storyline(org_a, shared_agent, shared_pid, 0.1)
    storyline_b = create_storyline(org_b, shared_agent, shared_pid, 0.5)

    refute storyline_a == storyline_b

    assert {:ok, %{id: ^storyline_a, organization_id: ^org_a, total_score: score_a}} =
             Storyline.get_storyline(org_a, storyline_a)

    assert {:ok, %{id: ^storyline_b, organization_id: ^org_b, total_score: score_b}} =
             Storyline.get_storyline(org_b, storyline_b)

    assert_in_delta score_a, 10.0, 0.001
    assert_in_delta score_b, 50.0, 0.001
    assert {:error, :not_found} = Storyline.get_storyline(org_a, storyline_b)
    assert {:error, :not_found} = Storyline.get_storyline(org_b, storyline_a)

    assert %{process_tree_size: 1, pid_mappings: 1} = Storyline.stats(org_a)
    assert %{process_tree_size: 1, pid_mappings: 1} = Storyline.stats(org_b)
  end

  test "foreign pid mapping is rejected before storyline mutation" do
    org_a = unique_id("org-a")
    org_b = unique_id("org-b")
    agent_a = unique_id("agent-a")
    agent_b = unique_id("agent-b")
    pid = 66_001

    storyline_a = create_storyline(org_a, agent_a, pid, 0.1)
    TamanduaServer.Agents.OrgLookup.put(agent_b, org_b)

    Storyline.ingest_process_event(agent_b, %{
      event_type: "process_create",
      payload: %{"pid" => pid, "ppid" => 4, "name" => "foreign-map-test.exe"}
    })

    :ets.insert(:tamandua_pid_to_storyline, {{org_b, agent_b, pid}, storyline_a})

    Storyline.ingest_detection(agent_b, %{
      event_id: unique_id("event"),
      event_type: "behavioral_detection",
      payload: %{"pid" => pid},
      threat_score: 0.5,
      detections: []
    })

    assert %{storyline_count: 1, pid_mappings: 1} = Storyline.stats(org_b)

    assert {:ok, %{total_score: score_a}} = Storyline.get_storyline(org_a, storyline_a)
    assert_in_delta score_a, 10.0, 0.001

    assert {:ok, [%{id: storyline_b, total_score: score_b}]} =
             Storyline.get_agent_storylines(org_b, agent_b)

    refute storyline_b == storyline_a
    assert_in_delta score_b, 50.0, 0.001
  end

  test "organization broadcasts do not use the former global topic" do
    org_a = unique_id("org-a")
    org_b = unique_id("org-b")

    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "storylines:#{org_a}")
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "storylines:#{org_b}")
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "storylines")

    create_storyline(org_a, unique_id("agent-a"), 70_001, 0.5)

    assert_receive {:storyline_severity_changed, %{organization_id: ^org_a, severity: :medium}}

    refute_receive {:storyline_severity_changed, _}, 20
  end

  defp create_storyline(org_id, agent_id, pid, threat_score \\ 0.1) do
    TamanduaServer.Agents.OrgLookup.put(agent_id, org_id)

    Storyline.ingest_process_event(agent_id, %{
      event_type: "process_create",
      payload: %{"pid" => pid, "ppid" => 4, "name" => "tenant-test.exe"}
    })

    Storyline.ingest_detection(agent_id, %{
      event_id: unique_id("event"),
      event_type: "behavioral_detection",
      payload: %{"pid" => pid},
      threat_score: threat_score,
      detections: []
    })

    # A synchronous call after the casts is a mailbox barrier for the GenServer.
    assert %{storyline_count: count} = Storyline.stats(org_id)
    assert count > 0

    {:ok, storylines} = Storyline.get_agent_storylines(org_id, agent_id)
    storylines |> List.first() |> Map.fetch!(:id)
  end

  defp unique_id(prefix), do: "#{prefix}-#{System.unique_integer([:positive, :monotonic])}"
end
