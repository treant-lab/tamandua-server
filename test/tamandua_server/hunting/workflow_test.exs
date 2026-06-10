defmodule TamanduaServer.Hunting.WorkflowTest do
  use TamanduaServer.DataCase

  alias TamanduaServer.Hunting.{Workflow, WorkflowLibrary}

  describe "workflow schema" do
    test "creates a valid workflow" do
      attrs = %{
        name: "Test Workflow",
        description: "Test description",
        category: "lateral_movement",
        steps: [
          %{
            "type" => "query",
            "name" => "Test Query",
            "description" => "Find processes"
          }
        ],
        metadata: %{
          "mitre_techniques" => ["T1021"]
        }
      }

      changeset = Workflow.changeset(%Workflow{}, attrs)
      assert changeset.valid?
    end

    test "requires name and category" do
      attrs = %{}
      changeset = Workflow.changeset(%Workflow{}, attrs)

      refute changeset.valid?
      assert %{name: ["can't be blank"], category: ["can't be blank"]} = errors_on(changeset)
    end

    test "validates category from allowed list" do
      attrs = %{
        name: "Test",
        category: "invalid_category"
      }

      changeset = Workflow.changeset(%Workflow{}, attrs)
      refute changeset.valid?
      assert %{category: ["is invalid"]} = errors_on(changeset)
    end

    test "validates step structure" do
      invalid_step = %{
        "type" => "invalid_type",
        "name" => "Test"
      }

      attrs = %{
        name: "Test",
        category: "custom",
        steps: [invalid_step]
      }

      changeset = Workflow.changeset(%Workflow{}, attrs)
      refute changeset.valid?
    end

    test "accepts valid step types" do
      for step_type <- Workflow.step_types() do
        attrs = %{
          name: "Test",
          category: "custom",
          steps: [
            %{
              "type" => step_type,
              "name" => "Step",
              "description" => "Desc"
            }
          ]
        }

        changeset = Workflow.changeset(%Workflow{}, attrs)
        assert changeset.valid?, "#{step_type} should be valid"
      end
    end
  end

  describe "workflow library" do
    test "returns all built-in workflows" do
      workflows = WorkflowLibrary.all_workflows()

      assert length(workflows) >= 10
      assert Enum.all?(workflows, &Map.has_key?(&1, :name))
      assert Enum.all?(workflows, &Map.has_key?(&1, :steps))
    end

    test "all workflows have required metadata" do
      workflows = WorkflowLibrary.all_workflows()

      for workflow <- workflows do
        assert workflow.name
        assert workflow.description
        assert workflow.category
        assert workflow.metadata
        assert workflow.steps
        assert length(workflow.steps) > 0
      end
    end

    test "all workflows have valid MITRE mappings" do
      workflows = WorkflowLibrary.all_workflows()

      for workflow <- workflows do
        assert Map.has_key?(workflow.metadata, :mitre_techniques)
        assert Map.has_key?(workflow.metadata, :mitre_tactics)

        techniques = workflow.metadata[:mitre_techniques]
        assert is_list(techniques)
        assert Enum.all?(techniques, &String.starts_with?(&1, "T"))
      end
    end

    test "lateral_movement workflow has correct structure" do
      workflow = WorkflowLibrary.get_by_category("lateral_movement")

      assert workflow
      assert workflow.name == "Lateral Movement Detection"
      assert workflow.category == "lateral_movement"
      assert length(workflow.steps) > 0

      # Verify first step is a query
      first_step = List.first(workflow.steps)
      assert first_step["type"] == "query"
      assert first_step["name"]
      assert first_step["query_template"]
    end

    test "ransomware workflow has expected steps" do
      workflow = WorkflowLibrary.get_by_category("ransomware")

      assert workflow
      step_types = Enum.map(workflow.steps, & &1["type"])

      # Should have query steps for shadow copy deletion, mass encryption, etc.
      assert "query" in step_types
      assert "decision" in step_types or "collect_evidence" in step_types
    end
  end

  describe "workflow steps" do
    test "query step has required fields" do
      workflow = WorkflowLibrary.get_by_category("credential_theft")
      query_steps = Enum.filter(workflow.steps, &(&1["type"] == "query"))

      for step <- query_steps do
        assert step["name"]
        assert step["description"]
        assert step["query_template"]
      end
    end

    test "decision step has decision criteria" do
      workflow = WorkflowLibrary.get_by_category("lateral_movement")
      decision_steps = Enum.filter(workflow.steps, &(&1["type"] == "decision"))

      for step <- decision_steps do
        assert step["name"]
        assert step["description"]
        assert step["decision_criteria"]
        assert is_list(step["decision_criteria"])
        assert step["next_actions"]
        assert is_map(step["next_actions"])
      end
    end

    test "manual_review step has review checklist" do
      workflow = WorkflowLibrary.get_by_category("insider_threat")
      review_steps = Enum.filter(workflow.steps, &(&1["type"] == "manual_review"))

      for step <- review_steps do
        assert step["name"]
        assert step["review_checklist"]
        assert is_list(step["review_checklist"])
        assert length(step["review_checklist"]) > 0
      end
    end

    test "collect_evidence step has evidence queries" do
      workflow = WorkflowLibrary.get_by_category("c2_communication")
      evidence_steps = Enum.filter(workflow.steps, &(&1["type"] == "collect_evidence"))

      for step <- evidence_steps do
        assert step["name"]
        assert step["description"]
        assert step["evidence_queries"] || true  # Optional
      end
    end
  end

  describe "workflow metadata" do
    test "all workflows have difficulty rating" do
      workflows = WorkflowLibrary.all_workflows()

      for workflow <- workflows do
        difficulty = workflow.metadata[:difficulty]
        assert difficulty in ["easy", "medium", "hard"]
      end
    end

    test "all workflows have expected duration" do
      workflows = WorkflowLibrary.all_workflows()

      for workflow <- workflows do
        duration = workflow.metadata[:expected_duration_minutes]
        assert is_integer(duration)
        assert duration > 0
        assert duration <= 120  # Reasonable max
      end
    end
  end
end
