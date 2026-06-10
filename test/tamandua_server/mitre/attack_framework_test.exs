defmodule TamanduaServer.Mitre.AttackFrameworkTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Mitre.AttackFramework
  alias TamanduaServer.Mitre.Technique

  describe "import_attack_data/1" do
    test "imports techniques from STIX data" do
      # This would require a test STIX file
      # For now, we'll test the basic structure
      assert {:ok, _} = AttackFramework.import_attack_data(force: true, source: "test/fixtures/mitre/test-attack.json")
    end

    test "skips import if data already exists" do
      # Insert a test technique
      %Technique{}
      |> Technique.changeset(%{technique_id: "T1059", name: "Test Technique"})
      |> Repo.insert!()

      assert {:ok, :already_imported} = AttackFramework.import_attack_data()
    end
  end

  describe "get_technique/1" do
    test "returns technique by ID" do
      technique = insert(:technique, technique_id: "T1059.001", name: "PowerShell")

      assert found = AttackFramework.get_technique("T1059.001")
      assert found.id == technique.id
      assert found.name == "PowerShell"
    end

    test "returns nil for non-existent technique" do
      assert is_nil(AttackFramework.get_technique("T9999"))
    end
  end

  describe "list_techniques/0" do
    test "returns all techniques ordered by ID" do
      insert(:technique, technique_id: "T1059")
      insert(:technique, technique_id: "T1055")
      insert(:technique, technique_id: "T1003")

      techniques = AttackFramework.list_techniques()

      assert length(techniques) == 3
      assert [t1, t2, t3] = techniques
      assert t1.technique_id == "T1003"
      assert t2.technique_id == "T1055"
      assert t3.technique_id == "T1059"
    end
  end

  describe "get_techniques_for_tactic/1" do
    test "returns techniques for a specific tactic" do
      insert(:technique, technique_id: "T1059", tactics: ["TA0002"])
      insert(:technique, technique_id: "T1055", tactics: ["TA0004", "TA0005"])
      insert(:technique, technique_id: "T1003", tactics: ["TA0006"])

      techniques = AttackFramework.get_techniques_for_tactic("TA0002")

      assert length(techniques) == 1
      assert hd(techniques).technique_id == "T1059"
    end
  end

  describe "get_subtechniques/1" do
    test "returns sub-techniques for a parent" do
      insert(:technique, technique_id: "T1059", is_subtechnique: false)
      insert(:technique, technique_id: "T1059.001", parent_technique_id: "T1059", is_subtechnique: true)
      insert(:technique, technique_id: "T1059.003", parent_technique_id: "T1059", is_subtechnique: true)

      subtechniques = AttackFramework.get_subtechniques("T1059")

      assert length(subtechniques) == 2
      assert Enum.all?(subtechniques, & &1.is_subtechnique)
    end
  end

  describe "search_techniques/1" do
    test "finds techniques by name" do
      insert(:technique, technique_id: "T1059", name: "Command and Scripting Interpreter")
      insert(:technique, technique_id: "T1055", name: "Process Injection")

      results = AttackFramework.search_techniques("scripting")

      assert length(results) == 1
      assert hd(results).technique_id == "T1059"
    end

    test "finds techniques by description" do
      insert(:technique, technique_id: "T1059", description: "Adversaries may abuse command interpreters")

      results = AttackFramework.search_techniques("interpreter")

      assert length(results) == 1
      assert hd(results).technique_id == "T1059"
    end
  end
end
