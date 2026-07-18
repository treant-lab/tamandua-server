defmodule TamanduaServer.AI.QueryInterfaceInvestigatorTest do
  use TamanduaServer.DataCase

  alias TamanduaServer.AI.QueryInterface
  alias TamanduaServer.Telemetry.Event

  describe "focused investigation routing" do
    test "does not fall back to a generic event search without alert or entity scope" do
      queries = [
        {"Find all related activity for resolver 8.8.8.8:443", "activity_evidence"},
        {"Which process was responsible?", "process_responsible"},
        {"Show the full process tree", "process_tree"},
        {"Show network connections from this process", "process_network"},
        {"Show files accessed by this process", "process_files"},
        {"Show related MCP/AI exfil evidence", "ai_exfil_evidence"}
      ]

      for {query, expected_intent} <- queries do
        response = QueryInterface.process_query(query, organization_id: Ecto.UUID.generate())

        assert response.status == :needs_scope
        assert response.intent.type == expected_intent
        assert response.result_count == 0
        assert response.results == []
        assert [%{status: :not_run, result_count: 0}] = response.tool_results
        assert [%{type: "select_scope"}] = response.actions
        refute Map.has_key?(response, :query)
      end
    end

    test "requires a process id for process-bound pivots" do
      response =
        QueryInterface.process_query("Show network connections from this process",
          organization_id: Ecto.UUID.generate(),
          entity: %{agent_id: Ecto.UUID.generate(), type: "host"}
        )

      assert response.status == :needs_scope
      assert response.reason == :missing_process_id
      assert response.tool_results == [
               %{
                 tool: "process_network",
                 status: :not_run,
                 reason: :missing_process_id,
                 scope: response.scope,
                 result_count: 0,
                 results: []
               }
             ]
    end
  end

  describe "scoped tool results" do
    setup do
      organization = insert(:organization)
      agent = insert(:agent, organization: organization)
      other_agent = insert(:agent, organization: organization)

      %{organization: organization, agent: agent, other_agent: other_agent}
    end

    test "returns only network evidence for the selected process", context do
      matching =
        insert_event(context.agent, "network_connection", %{
          "pid" => "4242",
          "remote_ip" => "203.0.113.10"
        })

      _other_process =
        insert_event(context.agent, "network_connection", %{
          "pid" => "9999",
          "remote_ip" => "198.51.100.2"
        })

      _other_agent =
        insert_event(context.other_agent, "network_connection", %{
          "pid" => "4242",
          "remote_ip" => "192.0.2.5"
        })

      response =
        QueryInterface.process_query("Show network connections from this process",
          organization_id: context.organization.id,
          entity: %{agent_id: context.agent.id, pid: 4242}
        )

      assert response.status == :completed
      assert response.intent.type == "process_network"
      assert response.scope.entity_id == "4242"
      assert response.result_count == 1
      assert [%{id: id}] = response.results
      assert id == matching.id
      assert [%{tool: "process_network", status: :completed, result_count: 1}] = response.tool_results
      assert Enum.any?(response.actions, &(&1.intent == "ai_exfil_evidence"))
    end

    test "builds both ancestry and descendants for the scoped process", context do
      parent = insert_event(context.agent, "process_create", %{"pid" => "10", "ppid" => "1"})
      selected = insert_event(context.agent, "process_create", %{"pid" => "20", "ppid" => "10"})
      child = insert_event(context.agent, "process_create", %{"pid" => "30", "ppid" => "20"})
      _unrelated = insert_event(context.agent, "process_create", %{"pid" => "40", "ppid" => "1"})

      response =
        QueryInterface.process_query("Show the full process tree",
          organization_id: context.organization.id,
          entity: %{agent_id: context.agent.id, pid: 20}
        )

      assert response.status == :completed
      assert response.intent.type == "process_tree"
      assert MapSet.new(Enum.map(response.results, & &1.id)) ==
               MapSet.new([parent.id, selected.id, child.id])
    end

    test "derives process scope from the current alert", context do
      process = insert_event(context.agent, "process_create", %{"pid" => "5150", "name" => "runner"})

      alert =
        insert(:alert,
          organization: context.organization,
          agent: context.agent,
          evidence: %{"process" => %{"pid" => 5150}}
        )

      response =
        QueryInterface.process_query("Which process was responsible?",
          organization_id: context.organization.id,
          alert_id: alert.id
        )

      assert response.status == :completed
      assert response.scope.alert_id == alert.id
      assert response.scope.entity_id == "5150"
      assert Enum.map(response.results, & &1.id) == [process.id]
    end

    test "does not resolve an alert from another tenant", context do
      other_organization = insert(:organization)
      other_agent = insert(:agent, organization: other_organization)

      alert =
        insert(:alert,
          organization: other_organization,
          agent: other_agent,
          evidence: %{"process" => %{"pid" => 5150}}
        )

      response =
        QueryInterface.process_query("Which process was responsible?",
          organization_id: context.organization.id,
          alert_id: alert.id
        )

      assert response.status == :needs_scope
      assert response.reason == :alert_not_found
      assert response.results == []
      assert [%{status: :not_run}] = response.tool_results
    end

    test "degrades when the current alert has no process identity", context do
      alert =
        insert(:alert,
          organization: context.organization,
          agent: context.agent,
          evidence: %{}
        )

      response =
        QueryInterface.process_query("Which process was responsible?",
          organization_id: context.organization.id,
          alert_id: alert.id
        )

      assert response.status == :needs_scope
      assert response.reason == :missing_process_id
      assert response.results == []
    end

    test "redacts prompt, response, and credential fields from MCP/AI evidence", context do
      insert_event(context.agent, "mcp_tool_call", %{
        "operation" => "MCP upload exfil",
        "prompt" => "private analyst prompt",
        "response" => "private model response",
        "nested" => %{"api_key" => "key-value", "safe" => "kept"}
      })

      response =
        QueryInterface.process_query("Show related MCP/AI exfil evidence",
          organization_id: context.organization.id,
          entity: %{agent_id: context.agent.id, type: "host", id: context.agent.id}
        )

      assert response.status == :completed
      assert response.result_count == 1
      assert [result] = response.results
      assert result.payload["prompt"] == "[REDACTED]"
      assert result.payload["response"] == "[REDACTED]"
      assert result.payload["nested"]["api_key"] == "[REDACTED]"
      assert result.payload["nested"]["safe"] == "kept"
      refute Map.has_key?(response, :query)
    end
  end

  defp insert_event(agent, event_type, payload) do
    Repo.insert!(%Event{
      agent_id: agent.id,
      organization_id: agent.organization_id,
      event_type: event_type,
      timestamp: DateTime.utc_now(),
      payload: payload
    })
  end
end
