defmodule TamanduaServer.Mitre.NavigatorTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Mitre.Navigator
  alias TamanduaServer.Mitre.TechniqueMapping
  alias TamanduaServer.Alerts.Alert

  describe "generate_coverage_layer/1" do
    test "generates Navigator layer JSON with coverage data" do
      org = insert(:organization)
      insert_list(3, :technique_mapping,
        technique_id: "T1059",
        organization_id: org.id,
        rule_type: "sigma"
      )
      insert_list(2, :technique_mapping,
        technique_id: "T1055",
        organization_id: org.id,
        rule_type: "yara"
      )

      layer = Navigator.generate_coverage_layer(organization_id: org.id)

      assert layer.name == "Tamandua EDR - Detection Coverage"
      assert layer.domain == "enterprise-attack"
      assert length(layer.techniques) == 2

      t1059 = Enum.find(layer.techniques, & &1.techniqueID == "T1059")
      assert t1059.score == 75  # 3 rules * 25
      assert t1059.comment == "3 detection rules"

      t1055 = Enum.find(layer.techniques, & &1.techniqueID == "T1055")
      assert t1055.score == 50  # 2 rules * 25
    end

    test "caps score at 100" do
      org = insert(:organization)
      insert_list(10, :technique_mapping,
        technique_id: "T1059",
        organization_id: org.id
      )

      layer = Navigator.generate_coverage_layer(organization_id: org.id)

      technique = Enum.find(layer.techniques, & &1.techniqueID == "T1059")
      assert technique.score == 100  # Capped
    end
  end

  describe "generate_frequency_layer/1" do
    test "generates layer with alert frequency data" do
      org = insert(:organization)
      agent = insert(:agent, organization_id: org.id)

      # Create alerts with techniques
      insert_list(5, :alert,
        organization_id: org.id,
        agent_id: agent.id,
        mitre_techniques: ["T1059"],
        severity: "high"
      )
      insert_list(2, :alert,
        organization_id: org.id,
        agent_id: agent.id,
        mitre_techniques: ["T1055"],
        severity: "medium"
      )

      layer = Navigator.generate_frequency_layer(
        organization_id: org.id,
        time_range: 30,
        severity_weight: true
      )

      assert layer.name =~ "Alert Frequency"
      assert length(layer.techniques) == 2

      t1059 = Enum.find(layer.techniques, & &1.techniqueID == "T1059")
      assert t1059.metadata.alert_count == 5

      t1055 = Enum.find(layer.techniques, & &1.techniqueID == "T1055")
      assert t1055.metadata.alert_count == 2
    end

    test "filters by time range" do
      org = insert(:organization)
      agent = insert(:agent, organization_id: org.id)

      # Old alert (outside range)
      insert(:alert,
        organization_id: org.id,
        agent_id: agent.id,
        mitre_techniques: ["T1059"],
        inserted_at: DateTime.add(DateTime.utc_now(), -60 * 24 * 60 * 60, :second)
      )

      # Recent alert
      insert(:alert,
        organization_id: org.id,
        agent_id: agent.id,
        mitre_techniques: ["T1055"]
      )

      layer = Navigator.generate_frequency_layer(
        organization_id: org.id,
        time_range: 30
      )

      # Should only include T1055 (recent)
      assert length(layer.techniques) == 1
      assert hd(layer.techniques).techniqueID == "T1055"
    end
  end

  describe "generate_gap_layer/1" do
    test "identifies techniques with no coverage" do
      org = insert(:organization)

      # Insert some techniques in the database
      insert(:technique, technique_id: "T1059")
      insert(:technique, technique_id: "T1055")
      insert(:technique, technique_id: "T1003")

      # Only map one technique
      insert(:technique_mapping,
        technique_id: "T1059",
        organization_id: org.id
      )

      layer = Navigator.generate_gap_layer(organization_id: org.id)

      assert layer.name == "Tamandua EDR - Coverage Gaps"
      # Should show T1055 and T1003 as gaps
      assert length(layer.techniques) == 2

      technique_ids = Enum.map(layer.techniques, & &1.techniqueID)
      assert "T1055" in technique_ids
      assert "T1003" in technique_ids
      refute "T1059" in technique_ids  # This one is covered
    end
  end

  describe "save_layer/3" do
    test "saves a navigator layer" do
      org = insert(:organization)
      user = insert(:user, organization_id: org.id)

      layer_data = %{
        name: "Test Layer",
        techniques: []
      }

      assert {:ok, saved_layer} = Navigator.save_layer(
        layer_data,
        "Test Layer",
        layer_type: "custom",
        organization_id: org.id,
        created_by_id: user.id
      )

      assert saved_layer.name == "Test Layer"
      assert saved_layer.layer_data == layer_data
      assert saved_layer.organization_id == org.id
    end
  end

  describe "export_layer_json/1" do
    test "exports layer as pretty JSON" do
      layer = %{
        name: "Test",
        techniques: [%{techniqueID: "T1059"}]
      }

      json = Navigator.export_layer_json(layer)

      assert is_binary(json)
      assert json =~ "\"name\""
      assert json =~ "\"Test\""
      assert json =~ "T1059"
    end
  end
end
