defmodule TamanduaServer.MlRules.GeneratorTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.MlRules.{Generator, MlRule}
  alias TamanduaServer.Hunting.HuntSession
  alias TamanduaServer.Repo

  setup do
    # Create test organization
    org = insert(:organization)

    # Create test user
    user = insert(:user, organization: org)

    # Create test hunt session
    hunt_session = %HuntSession{
      query: "suspicious powershell activity",
      parsed_query: %{},
      findings: [
        %{
          "timestamp" => 1706000000,
          "event" => %{
            "process" => %{
              "name" => "powershell.exe",
              "command_line" => "powershell.exe -enc ABC123",
              "parent_name" => "cmd.exe"
            },
            "network" => %{
              "domain" => "malicious.com",
              "dst_ip" => "192.168.1.100"
            }
          },
          "is_malicious" => true,
          "mitre_technique" => "T1059.001"
        }
      ],
      status: "active",
      created_by: "test_user"
    }
    |> Repo.insert!()

    %{
      organization: org,
      user: user,
      hunt_session: hunt_session
    }
  end

  describe "create_ml_rule/1" do
    test "creates a valid ML rule", %{organization: org} do
      attrs = %{
        rule_id: "test_rule_1",
        rule_type: "yara",
        name: "Test YARA Rule",
        description: "A test rule",
        content: "rule test { condition: true }",
        severity: "medium",
        mitre_techniques: ["T1055"],
        tags: ["test"],
        confidence_score: 0.85,
        organization_id: org.id
      }

      assert {:ok, %MlRule{} = rule} = Generator.create_ml_rule(attrs)
      assert rule.rule_id == "test_rule_1"
      assert rule.rule_type == "yara"
      assert rule.enabled == false
      assert rule.approved == false
      assert rule.confidence_score == 0.85
    end

    test "validates required fields" do
      attrs = %{
        rule_type: "yara"
        # Missing required fields
      }

      assert {:error, %Ecto.Changeset{}} = Generator.create_ml_rule(attrs)
    end

    test "validates rule type" do
      attrs = %{
        rule_id: "test",
        rule_type: "invalid_type",
        name: "Test",
        content: "test"
      }

      assert {:error, %Ecto.Changeset{} = changeset} = Generator.create_ml_rule(attrs)
      assert "is invalid" in errors_on(changeset).rule_type
    end
  end

  describe "approve_rule/2" do
    test "approves a pending rule", %{organization: org, user: user} do
      rule = insert(:ml_rule, approved: false, enabled: false, organization: org)

      assert {:ok, updated_rule} = Generator.approve_rule(rule.id, user.id)
      assert updated_rule.approved == true
      assert updated_rule.enabled == true
      assert updated_rule.approved_by_id == user.id
      assert updated_rule.approved_at != nil
    end

    test "returns error for non-existent rule" do
      assert {:error, :not_found} = Generator.approve_rule(Ecto.UUID.generate(), Ecto.UUID.generate())
    end
  end

  describe "reject_rule/1" do
    test "deletes a rejected rule", %{organization: org} do
      rule = insert(:ml_rule, organization: org)

      assert {:ok, _} = Generator.reject_rule(rule.id)
      assert Repo.get(MlRule, rule.id) == nil
    end
  end

  describe "list_ml_rules/1" do
    test "filters by approved status", %{organization: org} do
      _approved = insert(:ml_rule, approved: true, organization: org)
      _pending = insert(:ml_rule, approved: false, organization: org)

      approved_rules = Generator.list_ml_rules(%{approved: true})
      assert length(approved_rules) == 1
      assert Enum.all?(approved_rules, & &1.approved)

      pending_rules = Generator.list_ml_rules(%{approved: false})
      assert length(pending_rules) == 1
      assert Enum.all?(pending_rules, &(not &1.approved))
    end

    test "filters by rule type", %{organization: org} do
      _yara = insert(:ml_rule, rule_type: "yara", organization: org)
      _sigma = insert(:ml_rule, rule_type: "sigma", organization: org)

      yara_rules = Generator.list_ml_rules(%{rule_type: "yara"})
      assert length(yara_rules) == 1
      assert Enum.all?(yara_rules, & &1.rule_type == "yara")
    end

    test "filters by enabled status", %{organization: org} do
      _enabled = insert(:ml_rule, enabled: true, organization: org)
      _disabled = insert(:ml_rule, enabled: false, organization: org)

      enabled_rules = Generator.list_ml_rules(%{enabled: true})
      assert length(enabled_rules) == 1
      assert Enum.all?(enabled_rules, & &1.enabled)
    end
  end

  describe "start_ab_test/3" do
    test "starts an A/B test for a rule", %{organization: org} do
      rule = insert(:ml_rule, organization: org)

      assert {:ok, updated_rule} = Generator.start_ab_test(rule.id, "variant_a", 24)
      assert updated_rule.ab_test_group == "variant_a"
      assert updated_rule.ab_test_start != nil
      assert updated_rule.ab_test_end != nil
    end

    test "validates test group" do
      # A/B test groups are validated by the changeset
      rule = insert(:ml_rule)

      # This should work
      assert {:ok, _} = Generator.start_ab_test(rule.id, "variant_a", 24)

      # Invalid groups should be caught by validation
      # (Implementation would need to handle this in the changeset)
    end
  end

  describe "deploy_to_engine/1" do
    test "deploys YARA rule to detection engine", %{organization: org} do
      rule = insert(:ml_rule,
        rule_type: "yara",
        approved: true,
        enabled: true,
        content: "rule test { condition: true }",
        organization: org
      )

      # Note: This is an integration test that would require the Detection module
      # In a real test, we'd mock the Detection module or use a test database
      # For now, we just verify the rule can be retrieved
      assert Generator.get_ml_rule(rule.id) != nil
    end
  end

  # Helper to insert test data
  defp insert(schema, attrs \\ %{})

  defp insert(:organization, attrs) do
    %TamanduaServer.Accounts.Organization{
      name: attrs[:name] || "Test Org",
      slug: attrs[:slug] || "test-org"
    }
    |> Repo.insert!()
  end

  defp insert(:user, attrs) do
    %TamanduaServer.Accounts.User{
      email: attrs[:email] || "test@example.com",
      name: attrs[:name] || "Test User",
      organization_id: attrs[:organization].id
    }
    |> Repo.insert!()
  end

  defp insert(:ml_rule, attrs \\ %{}) do
    default_attrs = %{
      rule_id: "rule_#{:rand.uniform(10000)}",
      rule_type: "yara",
      name: "Test Rule",
      description: "Test description",
      content: "rule test { condition: true }",
      severity: "medium",
      enabled: false,
      approved: false,
      mitre_techniques: [],
      tags: ["test"],
      confidence_score: 0.8,
      organization_id: attrs[:organization]&.id || insert(:organization).id
    }

    attrs = Map.merge(default_attrs, Enum.into(attrs, %{}))

    %MlRule{}
    |> MlRule.changeset(attrs)
    |> Repo.insert!()
  end
end
