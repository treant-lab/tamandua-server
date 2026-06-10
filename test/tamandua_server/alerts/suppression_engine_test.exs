defmodule TamanduaServer.Alerts.SuppressionEngineTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Alerts.{
    SuppressionRule,
    SuppressionEngine,
    SuppressedAlert
  }

  setup do
    {:ok, _pid} = start_supervised(SuppressionEngine)

    organization = insert(:organization)
    user = insert(:user, organization: organization)
    agent = insert(:agent, organization: organization)

    {:ok, organization: organization, user: user, agent: agent}
  end

  describe "evaluate_rules/2" do
    test "returns :allow when no rules match", %{organization: organization} do
      alert_data = %{
        title: "Test Alert",
        severity: "high",
        organization_id: organization.id
      }

      assert :allow == SuppressionEngine.evaluate_rules(alert_data)
    end

    test "suppresses alert when rule matches", %{organization: organization, user: user} do
      # Create suppression rule
      {:ok, rule} = %SuppressionRule{}
      |> SuppressionRule.changeset(%{
        name: "Suppress test alerts",
        action: "suppress",
        title_pattern: "Test Alert",
        organization_id: organization.id,
        created_by_id: user.id
      })
      |> Repo.insert()

      # Refresh cache
      SuppressionEngine.refresh_priority_cache()

      alert_data = %{
        title: "Test Alert",
        severity: "high",
        organization_id: organization.id
      }

      assert {:suppress, rule_id, reason} = SuppressionEngine.evaluate_rules(alert_data)
      assert rule_id == rule.id
      assert reason =~ "Suppress test alerts"
    end

    test "reduces severity when rule matches", %{organization: organization, user: user} do
      {:ok, rule} = %SuppressionRule{}
      |> SuppressionRule.changeset(%{
        name: "Reduce severity",
        action: "reduce_severity",
        reduce_to_severity: "low",
        title_pattern: "Noisy Alert",
        organization_id: organization.id,
        created_by_id: user.id
      })
      |> Repo.insert()

      SuppressionEngine.refresh_priority_cache()

      alert_data = %{
        title: "Noisy Alert",
        severity: "critical",
        organization_id: organization.id
      }

      assert {:reduce_severity, "low", rule_id, _reason} = SuppressionEngine.evaluate_rules(alert_data)
      assert rule_id == rule.id
    end

    test "respects rule priority - higher priority evaluated first", %{organization: organization, user: user} do
      # Create low priority rule
      {:ok, _low_rule} = %SuppressionRule{}
      |> SuppressionRule.changeset(%{
        name: "Low priority",
        action: "suppress",
        priority: 1,
        severity: "high",
        organization_id: organization.id,
        created_by_id: user.id
      })
      |> Repo.insert()

      # Create high priority rule
      {:ok, high_rule} = %SuppressionRule{}
      |> SuppressionRule.changeset(%{
        name: "High priority",
        action: "reduce_severity",
        reduce_to_severity: "medium",
        priority: 10,
        severity: "high",
        organization_id: organization.id,
        created_by_id: user.id
      })
      |> Repo.insert()

      SuppressionEngine.refresh_priority_cache()

      alert_data = %{
        title: "Test",
        severity: "high",
        organization_id: organization.id
      }

      # High priority rule should match first
      assert {:reduce_severity, "medium", rule_id, _} = SuppressionEngine.evaluate_rules(alert_data)
      assert rule_id == high_rule.id
    end

    test "respects exemptions - exempted agent not suppressed", %{organization: organization, user: user, agent: agent} do
      {:ok, _rule} = %SuppressionRule{}
      |> SuppressionRule.changeset(%{
        name: "Suppress with exemption",
        action: "suppress",
        title_pattern: "Test",
        exempted_agent_ids: [agent.id],
        organization_id: organization.id,
        created_by_id: user.id
      })
      |> Repo.insert()

      SuppressionEngine.refresh_priority_cache()

      alert_data = %{
        title: "Test Alert",
        severity: "high",
        organization_id: organization.id,
        agent_id: agent.id
      }

      # Should not suppress because agent is exempted
      assert :allow == SuppressionEngine.evaluate_rules(alert_data)
    end

    test "respects time window - expired rule not applied", %{organization: organization, user: user} do
      past_time = DateTime.add(DateTime.utc_now(), -3600, :second)

      {:ok, _rule} = %SuppressionRule{}
      |> SuppressionRule.changeset(%{
        name: "Expired rule",
        action: "suppress",
        title_pattern: "Test",
        expires_at: past_time,
        organization_id: organization.id,
        created_by_id: user.id
      })
      |> Repo.insert()

      SuppressionEngine.refresh_priority_cache()

      alert_data = %{
        title: "Test Alert",
        severity: "high",
        organization_id: organization.id
      }

      # Expired rule should not match
      assert :allow == SuppressionEngine.evaluate_rules(alert_data)
    end

    test "respects max_matches limit", %{organization: organization, user: user} do
      {:ok, rule} = %SuppressionRule{}
      |> SuppressionRule.changeset(%{
        name: "Limited rule",
        action: "suppress",
        title_pattern: "Test",
        max_matches: 2,
        match_count: 2,  # Already hit limit
        organization_id: organization.id,
        created_by_id: user.id
      })
      |> Repo.insert()

      SuppressionEngine.refresh_priority_cache()

      alert_data = %{
        title: "Test Alert",
        severity: "high",
        organization_id: organization.id
      }

      # Should not suppress because max_matches reached
      assert :allow == SuppressionEngine.evaluate_rules(alert_data)
    end
  end

  describe "store_suppressed_alert/2" do
    test "stores suppressed alert with all details", %{organization: organization, agent: agent} do
      alert_data = %{
        title: "Suppressed Test Alert",
        description: "Test description",
        severity: "high",
        mitre_techniques: ["T1055"],
        evidence: %{process: %{name: "test.exe"}},
        organization_id: organization.id,
        agent_id: agent.id
      }

      suppression_details = %{
        reason: "Test suppression",
        type: "rule",
        rule_id: Ecto.UUID.generate()
      }

      assert {:ok, suppressed} = SuppressionEngine.store_suppressed_alert(alert_data, suppression_details)
      assert suppressed.title == "Suppressed Test Alert"
      assert suppressed.suppression_type == "rule"
      assert suppressed.suppression_reason == "Test suppression"
      assert suppressed.organization_id == organization.id
    end
  end

  describe "unsuppress_alert/3" do
    test "unsuppresses alert and marks as unsuppressed", %{organization: organization, user: user, agent: agent} do
      # Create suppressed alert
      {:ok, suppressed} = %SuppressedAlert{}
      |> SuppressedAlert.changeset(%{
        title: "Test Alert",
        severity: "high",
        suppression_reason: "Test",
        suppression_type: "manual",
        suppressed_at: DateTime.utc_now(),
        organization_id: organization.id,
        agent_id: agent.id
      })
      |> Repo.insert()

      # Unsuppress it
      assert {:ok, result} = SuppressionEngine.unsuppress_alert(suppressed.id, user.id, %{})

      # Verify unsuppression
      updated = Repo.get(SuppressedAlert, suppressed.id)
      assert updated.unsuppressed == true
      assert updated.unsuppressed_by_id == user.id
      assert updated.unsuppressed_at != nil
    end

    test "creates new alert when unsuppressed with create_alert option", %{organization: organization, user: user, agent: agent} do
      {:ok, suppressed} = %SuppressedAlert{}
      |> SuppressedAlert.changeset(%{
        title: "Test Alert",
        severity: "high",
        suppression_reason: "Test",
        suppression_type: "manual",
        suppressed_at: DateTime.utc_now(),
        organization_id: organization.id,
        agent_id: agent.id
      })
      |> Repo.insert()

      assert {:ok, result} = SuppressionEngine.unsuppress_alert(suppressed.id, user.id, %{create_alert: true})

      # Verify alert was created
      assert Map.has_key?(result, :create_alert)
    end
  end

  describe "template management" do
    test "lists templates for organization", %{organization: organization, user: user} do
      # Create template
      {:ok, _template} = %SuppressionRule{}
      |> SuppressionRule.changeset(%{
        name: "Template Rule",
        action: "suppress",
        is_template: true,
        template_name: "Common FP Template",
        template_description: "Suppress common false positives",
        title_pattern: "Known FP",
        organization_id: organization.id,
        created_by_id: user.id
      })
      |> Repo.insert()

      templates = SuppressionEngine.list_templates(organization.id)
      assert length(templates) == 1
      assert hd(templates).template_name == "Common FP Template"
    end

    test "creates rule from template", %{organization: organization, user: user} do
      # Create template
      {:ok, template} = %SuppressionRule{}
      |> SuppressionRule.changeset(%{
        name: "Template Rule",
        action: "suppress",
        is_template: true,
        template_name: "Test Template",
        title_pattern: "Pattern",
        priority: 5,
        organization_id: organization.id,
        created_by_id: user.id
      })
      |> Repo.insert()

      # Create from template with overrides
      assert {:ok, rule} = SuppressionEngine.create_from_template(
        template.id,
        %{name: "Custom Rule", priority: 10},
        organization.id
      )

      assert rule.name == "Custom Rule"
      assert rule.priority == 10
      assert rule.title_pattern == "Pattern"  # Inherited from template
      assert rule.is_template == false
    end
  end
end
