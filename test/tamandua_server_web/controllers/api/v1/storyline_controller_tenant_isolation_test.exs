defmodule TamanduaServerWeb.API.V1.StorylineControllerTenantIsolationTest do
  use TamanduaServerWeb.ConnCase, async: false

  alias TamanduaServer.Detection.Storyline, as: AutonomousStoryline
  alias TamanduaServer.Investigations.Storyline, as: InvestigationStoryline

  setup %{conn: conn} do
    {org_a, agent_a} = create_agent_with_org()
    {org_b, agent_b} = create_agent_with_org()

    user_a = insert!(:user, %{organization: org_a, role: "analyst"})
    user_b = insert!(:user, %{organization: org_b, role: "analyst"})

    {:ok, token_a, _claims} = TamanduaServer.Guardian.encode_and_sign(user_a)
    {:ok, token_b, _claims} = TamanduaServer.Guardian.encode_and_sign(user_b)

    assert Process.whereis(AutonomousStoryline)
    assert Process.whereis(InvestigationStoryline)

    %{
      conn_a: put_req_header(conn, "authorization", "Bearer #{token_a}"),
      conn_b: put_req_header(conn, "authorization", "Bearer #{token_b}"),
      org_a: org_a,
      org_b: org_b,
      agent_a: agent_a,
      agent_b: agent_b
    }
  end

  describe "autonomous storyline HTTP tenant isolation" do
    test "show and list do not disclose another tenant's storyline", context do
      storyline_a = create_autonomous_storyline(context.org_a.id, context.agent_a.id)
      storyline_b = create_autonomous_storyline(context.org_b.id, context.agent_b.id)

      response =
        context.conn_b
        |> get("/api/v1/storylines/#{storyline_a}")
        |> json_response(404)

      assert response["error"] == "Storyline not found"

      response =
        context.conn_b
        |> get("/api/v1/storylines")
        |> json_response(200)

      ids = Enum.map(response["data"], & &1["id"])
      assert storyline_b in ids
      refute storyline_a in ids

      assert Enum.all?(response["data"], fn storyline ->
               storyline["organization_id"] == context.org_b.id
             end)
    end

    test "merge rejects storylines owned by another tenant without mutating them", context do
      storyline_a1 = create_autonomous_storyline(context.org_a.id, context.agent_a.id)
      storyline_a2 = create_autonomous_storyline(context.org_a.id, context.agent_a.id)
      refute storyline_a1 == storyline_a2

      response =
        context.conn_b
        |> post("/api/v1/storylines/#{storyline_a1}/merge/#{storyline_a2}")
        |> json_response(404)

      assert response["error"] == "One or both storylines not found"

      assert {:ok, %{id: ^storyline_a1}} =
               AutonomousStoryline.get_storyline(context.org_a.id, storyline_a1)

      assert {:ok, %{id: ^storyline_a2}} =
               AutonomousStoryline.get_storyline(context.org_a.id, storyline_a2)
    end

    test "engine stats count only the authenticated tenant", context do
      create_autonomous_storyline(context.org_a.id, context.agent_a.id)
      create_autonomous_storyline(context.org_a.id, context.agent_a.id)
      create_autonomous_storyline(context.org_b.id, context.agent_b.id)

      stats_a =
        context.conn_a
        |> get("/api/v1/storylines/engine-stats")
        |> json_response(200)
        |> Map.fetch!("data")

      stats_b =
        context.conn_b
        |> get("/api/v1/storylines/engine-stats")
        |> json_response(200)
        |> Map.fetch!("data")

      assert stats_a["storyline_count"] == 2
      assert stats_a["process_tree_size"] == 2
      assert stats_b["storyline_count"] == 1
      assert stats_b["process_tree_size"] == 1
    end
  end

  describe "investigation storyline HTTP tenant isolation" do
    test "graph and active list do not disclose another tenant's story", context do
      {:ok, story_a} = create_investigation_story(context.org_a.id, context.agent_a.id)
      {:ok, story_b} = create_investigation_story(context.org_b.id, context.agent_b.id)

      response =
        context.conn_b
        |> get("/api/v1/investigations/storylines/#{story_a}/graph")
        |> json_response(404)

      assert response["error"] == "Story not found"

      response =
        context.conn_b
        |> get("/api/v1/investigations/storylines/active")
        |> json_response(200)

      ids = Enum.map(response["data"], & &1["id"])
      assert story_b in ids
      refute story_a in ids

      assert Enum.all?(response["data"], fn story ->
               story["organization_id"] == context.org_b.id
             end)
    end

    test "merge rejects stories owned by another tenant without mutating them", context do
      {:ok, story_a1} = create_investigation_story(context.org_a.id, context.agent_a.id)
      {:ok, story_a2} = create_investigation_story(context.org_a.id, context.agent_a.id)

      response =
        context.conn_b
        |> post("/api/v1/investigations/storylines/merge", %{
          "story_id_1" => story_a1,
          "story_id_2" => story_a2
        })
        |> json_response(404)

      assert response["error"] == "One or both stories not found"

      assert {:ok, %{id: ^story_a1, event_count: 1}} =
               InvestigationStoryline.get_story(context.org_a.id, story_a1)

      assert {:ok, %{id: ^story_a2, event_count: 1}} =
               InvestigationStoryline.get_story(context.org_a.id, story_a2)
    end

    test "stats count only stories and events from the authenticated tenant", context do
      {:ok, story_a} = create_investigation_story(context.org_a.id, context.agent_a.id)
      {:ok, _story_b} = create_investigation_story(context.org_b.id, context.agent_b.id)

      :ok =
        InvestigationStoryline.add_event_to_story(
          context.org_a.id,
          story_a,
          investigation_event(context.org_a.id, context.agent_a.id)
        )

      stats_a =
        context.conn_a
        |> get("/api/v1/investigations/storylines/stats")
        |> json_response(200)
        |> Map.fetch!("data")

      stats_b =
        context.conn_b
        |> get("/api/v1/investigations/storylines/stats")
        |> json_response(200)
        |> Map.fetch!("data")

      assert stats_a["total_stories"] == 1
      assert stats_a["total_events"] == 2
      assert stats_b["total_stories"] == 1
      assert stats_b["total_events"] == 1
    end
  end

  describe "storyline analysis input contract" do
    test "rejects invalid nested elements with 422", context do
      payload = Map.put(analysis_storyline(), "nodes", ["not-a-node"])

      response =
        context.conn_a
        |> post("/api/v1/storyline/analyze", %{"storyline" => payload})
        |> json_response(422)

      assert response["error"] == "invalid_storyline"

      payload =
        Map.put(analysis_storyline(), "nodes", [
          %{"type" => "process", "process_name" => 123}
        ])

      response =
        context.conn_a
        |> post("/api/v1/storyline/analyze", %{"storyline" => payload})
        |> json_response(422)

      assert response["error"] == "invalid_storyline"
    end

    test "normalizes JSON values and treats string false as disabled AI", context do
      response =
        context.conn_a
        |> post("/api/v1/storyline/analyze", %{
          "storyline" => analysis_storyline(),
          "use_ai" => "false"
        })
        |> json_response(200)

      assert response["data"]["threat_assessment"]["severity"] == "high"

      assert Enum.any?(response["data"]["recommended_actions"], fn action ->
               action["action"] == "Investigate process chain"
             end)
    end
  end

  defp create_autonomous_storyline(organization_id, agent_id) do
    pid = System.unique_integer([:positive, :monotonic])
    TamanduaServer.Agents.OrgLookup.put(agent_id, organization_id)

    AutonomousStoryline.ingest_process_event(agent_id, %{
      event_type: "process_create",
      payload: %{"pid" => pid, "ppid" => 4, "name" => "tenant-http-test.exe"}
    })

    AutonomousStoryline.ingest_detection(agent_id, %{
      event_id: Ecto.UUID.generate(),
      event_type: "behavioral_detection",
      payload: %{"pid" => pid},
      threat_score: 0.2,
      detections: []
    })

    # The synchronous stats call is a mailbox barrier for both preceding casts.
    assert %{storyline_count: count} = AutonomousStoryline.stats(organization_id)
    assert count > 0

    {:ok, storylines} = AutonomousStoryline.get_agent_storylines(organization_id, agent_id)

    storylines
    |> Enum.find(&(&1.root_pid == pid))
    |> Map.fetch!(:id)
  end

  defp create_investigation_story(organization_id, agent_id) do
    InvestigationStoryline.create_story(
      organization_id,
      investigation_event(organization_id, agent_id)
    )
  end

  defp investigation_event(organization_id, agent_id) do
    %{
      id: Ecto.UUID.generate(),
      organization_id: organization_id,
      agent_id: agent_id,
      pid: System.unique_integer([:positive, :monotonic]),
      severity: "high",
      timestamp: DateTime.utc_now(),
      raw_event: %{remote_ip: "203.0.113.10"}
    }
  end

  defp analysis_storyline do
    %{
      "severity" => "high",
      "confidence_score" => 0.8,
      "attack_phase" => "execution",
      "root_cause" => nil,
      "nodes" => [%{"type" => "process", "process_name" => "powershell.exe"}],
      "edges" => [],
      "timeline" => [],
      "threat_indicators" => [],
      "mitre_techniques" => []
    }
  end
end
