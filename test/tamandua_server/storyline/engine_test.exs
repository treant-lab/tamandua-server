defmodule TamanduaServer.Storyline.EngineTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Storyline.Engine

  describe "analyze_storyline/2 input contract" do
    test "requires explicit organization scope" do
      assert {:error, :organization_required} = Engine.analyze_storyline(analysis_storyline())
    end

    test "rejects incomplete maps instead of raising" do
      assert {:error, :invalid_storyline} =
               Engine.analyze_storyline(%{severity: "high"},
                 organization_id: Ecto.UUID.generate()
               )

      assert {:error, :invalid_storyline} =
               Engine.analyze_storyline(
                 Map.put(analysis_storyline(), :nodes, ["not-a-node"]),
                 organization_id: Ecto.UUID.generate()
               )

      assert {:error, :invalid_storyline} =
               Engine.analyze_storyline(
                 Map.put(analysis_storyline(), :nodes, [
                   %{type: "process", process_name: 123}
                 ]),
                 organization_id: Ecto.UUID.generate()
               )
    end

    test "normalizes JSON severity and node types" do
      assert {:ok, analysis} =
               Engine.analyze_storyline(analysis_storyline(),
                 organization_id: Ecto.UUID.generate()
               )

      assert analysis.threat_assessment.severity == :high
      assert Enum.any?(analysis.recommended_actions, &(&1.action == "Investigate process chain"))
    end
  end

  describe "generate_for_alert/2 network evidence" do
    test "fails closed when organization scope is absent" do
      assert {:error, :organization_required} = Engine.generate_for_alert(Ecto.UUID.generate())
    end

    test "rejects an alert outside the explicit organization scope" do
      owner = insert!(:organization)
      other = insert!(:organization)
      agent = insert!(:agent, organization: owner)

      alert =
        insert!(:alert, %{
          organization: owner,
          agent: agent,
          agent_id: agent.id,
          organization_id: owner.id,
          event_ids: [],
          process_chain: [],
          raw_event: %{},
          evidence: %{}
        })

      assert {:error, :alert_not_found} =
               Engine.generate_for_alert(alert.id, organization_id: other.id)
    end

    test "accepts App Guard network evidence as a map" do
      organization = insert!(:organization)
      agent = insert!(:agent, organization: organization)

      alert =
        insert!(:alert, %{
          organization: organization,
          agent: agent,
          agent_id: agent.id,
          organization_id: organization.id,
          event_ids: [],
          process_chain: [],
          raw_event: %{},
          evidence: %{
            "network" => %{
              "ip" => "203.0.113.42",
              "domain" => "risk.example",
              "port" => 443,
              "protocol" => "tcp"
            }
          }
        })

      assert {:ok, storyline} =
               Engine.generate_for_alert(alert.id, organization_id: organization.id)

      network_node = Enum.find(storyline.nodes, &(&1.type == "network"))

      assert network_node
      assert network_node.data["remote_addr"] == "203.0.113.42"
      assert network_node.data["remote_ip"] == "203.0.113.42"
      assert network_node.data["remote_port"] == 443
      assert network_node.data["protocol"] == "tcp"
      assert network_node.data["domain"] == "risk.example"
      refute Enum.any?(storyline.nodes, &(&1.type == "process"))
    end

    test "keeps traditional network evidence lists working" do
      organization = insert!(:organization)
      agent = insert!(:agent, organization: organization)

      alert =
        insert!(:alert, %{
          organization: organization,
          agent: agent,
          agent_id: agent.id,
          organization_id: organization.id,
          event_ids: [],
          process_chain: [],
          raw_event: %{},
          evidence: %{
            "network" => [
              %{
                "remote_addr" => "198.51.100.10",
                "remote_port" => 8443,
                "protocol" => "tcp"
              }
            ]
          }
        })

      assert {:ok, storyline} =
               Engine.generate_for_alert(alert.id, organization_id: organization.id)

      network_node = Enum.find(storyline.nodes, &(&1.type == "network"))

      assert network_node
      assert network_node.data["remote_addr"] == "198.51.100.10"
      assert network_node.data["remote_port"] == 8443
      assert network_node.data["protocol"] == "tcp"
    end

    test "accepts App Guard domain and URL as network evidence" do
      organization = insert!(:organization)
      agent = insert!(:agent, organization: organization)

      alert =
        insert!(:alert, %{
          organization: organization,
          agent: agent,
          agent_id: agent.id,
          organization_id: organization.id,
          event_ids: [],
          process_chain: [],
          raw_event: %{},
          evidence: %{
            "app_guard" => %{
              "domain" => "wallet.example",
              "url" => "https://wallet.example/login"
            }
          }
        })

      assert {:ok, storyline} =
               Engine.generate_for_alert(alert.id, organization_id: organization.id)

      network_node = Enum.find(storyline.nodes, &(&1.type == "network"))

      assert network_node
      assert network_node.data["remote_addr"] == "wallet.example"
      assert network_node.data["domain"] == "wallet.example"
    end

    test "falls back to App Guard URL when domain is empty" do
      organization = insert!(:organization)
      agent = insert!(:agent, organization: organization)

      alert =
        insert!(:alert, %{
          organization: organization,
          agent: agent,
          agent_id: agent.id,
          organization_id: organization.id,
          event_ids: [],
          process_chain: [],
          raw_event: %{},
          evidence: %{
            "app_guard" => %{
              "domain" => "",
              "url" => "https://wallet.example/login"
            }
          }
        })

      assert {:ok, storyline} =
               Engine.generate_for_alert(alert.id, organization_id: organization.id)

      network_node = Enum.find(storyline.nodes, &(&1.type == "network"))

      assert network_node
      assert network_node.data["remote_addr"] == "https://wallet.example/login"
    end

    test "accepts evidence snapshot network evidence" do
      organization = insert!(:organization)
      agent = insert!(:agent, organization: organization)

      alert =
        insert!(:alert, %{
          organization: organization,
          agent: agent,
          agent_id: agent.id,
          organization_id: organization.id,
          event_ids: [],
          process_chain: [],
          raw_event: %{},
          evidence: %{
            "evidence_snapshot" => %{
              "network" => %{
                "destination_ip" => "203.0.113.99",
                "destination_port" => 9443,
                "protocol" => "tcp"
              }
            }
          }
        })

      assert {:ok, storyline} =
               Engine.generate_for_alert(alert.id, organization_id: organization.id)

      network_node = Enum.find(storyline.nodes, &(&1.type == "network"))

      assert network_node
      assert network_node.data["remote_addr"] == "203.0.113.99"
      assert network_node.data["remote_ip"] == "203.0.113.99"
      assert network_node.data["remote_port"] == 9443
    end
  end

  defp analysis_storyline do
    %{
      alert_id: nil,
      severity: "high",
      confidence_score: 0.8,
      attack_phase: "execution",
      root_cause: nil,
      nodes: [%{type: "process", process_name: "powershell.exe"}],
      edges: [],
      timeline: [],
      threat_indicators: [],
      mitre_techniques: []
    }
  end
end
