defmodule TamanduaServer.Integrations.SOAR.AlertTriggerTest do
  use TamanduaServer.DataCase, async: true

  import Mox

  alias TamanduaServer.Integrations.SOAR.{AlertTrigger, TriggerRule}

  setup :verify_on_exit!

  @critical_alert %{
    id: "alert-123",
    title: "Critical Malware Detected",
    severity: "critical",
    threat_score: 0.92,
    mitre_tactics: ["execution", "impact"],
    mitre_techniques: ["T1204", "T1486"],
    hostname: "workstation-1"
  }

  @credential_alert %{
    id: "alert-456",
    title: "Credential Dumping Detected",
    severity: "high",
    threat_score: 0.78,
    mitre_tactics: ["credential_access"],
    mitre_techniques: ["T1003"],
    hostname: "server-1"
  }

  @model_alert %{
    id: "alert-789",
    title: "Malicious Pickle Model Detected",
    severity: "high",
    threat_score: 0.85,
    mitre_tactics: ["execution"],
    mitre_techniques: ["T1059"],
    hostname: "ml-workstation"
  }

  @low_alert %{
    id: "alert-low",
    title: "Policy Violation",
    severity: "low",
    threat_score: 0.2,
    mitre_tactics: [],
    mitre_techniques: [],
    hostname: "laptop-1"
  }

  describe "trigger_for_alert/1" do
    test "matches alert against all enabled rules" do
      # Create test rules
      {:ok, rule} = TriggerRule.create(%{
        name: "Test Critical Rule",
        match_criteria: %{"severity" => ["critical"]},
        soar_platform: "xsoar",
        playbook_name: "test_playbook"
      })

      # Mock the PlaybookRouter
      TamanduaServer.HTTPMock
      |> expect(:request, fn _request, _finch, _opts ->
        {:ok, %Finch.Response{status: 200, body: Jason.encode!(%{"id" => "run-123"})}}
      end)

      assert {:ok, results} = AlertTrigger.trigger_for_alert(@critical_alert)
      assert length(results) >= 1

      # Cleanup
      TriggerRule.delete(rule)
    end

    test "critical alerts with threat_score > 0.8 trigger high_priority_incident playbook" do
      {:ok, rule} = TriggerRule.create(%{
        name: "High Priority Critical",
        match_criteria: %{
          "severity" => ["critical"],
          "threat_score_gte" => 0.8
        },
        soar_platform: "both",
        playbook_name: "high_priority_incident"
      })

      # Alert matches (severity=critical, threat_score=0.92)
      assert AlertTrigger.evaluate_rule(rule, @critical_alert) == true

      # Low alert does not match
      assert AlertTrigger.evaluate_rule(rule, @low_alert) == false

      TriggerRule.delete(rule)
    end

    test "alerts with MITRE T1003 (Credential Dumping) trigger credential_theft_response playbook" do
      {:ok, rule} = TriggerRule.create(%{
        name: "Credential Theft Response",
        match_criteria: %{
          "mitre_techniques" => ["T1003"]
        },
        soar_platform: "xsoar",
        playbook_name: "credential_theft_response"
      })

      # Credential alert has T1003
      assert AlertTrigger.evaluate_rule(rule, @credential_alert) == true

      # Critical alert does not have T1003
      assert AlertTrigger.evaluate_rule(rule, @critical_alert) == false

      TriggerRule.delete(rule)
    end

    test "rules can specify which SOAR platform (xsoar, tines, or both)" do
      {:ok, xsoar_rule} = TriggerRule.create(%{
        name: "XSOAR Only",
        match_criteria: %{"severity" => ["high"]},
        soar_platform: "xsoar",
        playbook_name: "xsoar_playbook"
      })

      {:ok, tines_rule} = TriggerRule.create(%{
        name: "Tines Only",
        match_criteria: %{"severity" => ["high"]},
        soar_platform: "tines",
        playbook_name: "tines_playbook"
      })

      {:ok, both_rule} = TriggerRule.create(%{
        name: "Both Platforms",
        match_criteria: %{"severity" => ["critical"]},
        soar_platform: "both",
        playbook_name: "critical_playbook"
      })

      assert xsoar_rule.soar_platform == "xsoar"
      assert tines_rule.soar_platform == "tines"
      assert both_rule.soar_platform == "both"

      TriggerRule.delete(xsoar_rule)
      TriggerRule.delete(tines_rule)
      TriggerRule.delete(both_rule)
    end
  end

  describe "get_trigger_rules/0" do
    test "returns all active rules" do
      {:ok, rule1} = TriggerRule.create(%{
        name: "Active Rule",
        enabled: true,
        match_criteria: %{},
        soar_platform: "xsoar",
        playbook_name: "test1"
      })

      {:ok, rule2} = TriggerRule.create(%{
        name: "Disabled Rule",
        enabled: false,
        match_criteria: %{},
        soar_platform: "xsoar",
        playbook_name: "test2"
      })

      active_rules = AlertTrigger.get_trigger_rules()
      active_names = Enum.map(active_rules, & &1.name)

      assert "Active Rule" in active_names
      refute "Disabled Rule" in active_names

      TriggerRule.delete(rule1)
      TriggerRule.delete(rule2)
    end
  end

  describe "add_trigger_rule/1" do
    test "creates new rule" do
      attrs = %{
        name: "New Rule",
        description: "Test description",
        priority: 75,
        match_criteria: %{"severity" => ["high", "critical"]},
        soar_platform: "both",
        playbook_name: "new_playbook"
      }

      assert {:ok, rule} = AlertTrigger.add_trigger_rule(attrs)
      assert rule.name == "New Rule"
      assert rule.priority == 75
      assert rule.soar_platform == "both"

      TriggerRule.delete(rule)
    end

    test "validates soar_platform" do
      attrs = %{
        name: "Invalid Platform",
        soar_platform: "invalid",
        playbook_name: "test"
      }

      assert {:error, changeset} = AlertTrigger.add_trigger_rule(attrs)
      assert "is invalid" in errors_on(changeset).soar_platform
    end
  end

  describe "evaluate_rule/2" do
    test "matches severity criteria" do
      rule = %TriggerRule{
        match_criteria: %{"severity" => ["critical", "high"]}
      }

      assert AlertTrigger.evaluate_rule(rule, %{severity: "critical"}) == true
      assert AlertTrigger.evaluate_rule(rule, %{severity: "high"}) == true
      assert AlertTrigger.evaluate_rule(rule, %{severity: "medium"}) == false
    end

    test "matches MITRE tactics" do
      rule = %TriggerRule{
        match_criteria: %{"mitre_tactics" => ["credential_access", "persistence"]}
      }

      assert AlertTrigger.evaluate_rule(rule, %{mitre_tactics: ["credential_access"]}) == true
      assert AlertTrigger.evaluate_rule(rule, %{mitre_tactics: ["persistence"]}) == true
      assert AlertTrigger.evaluate_rule(rule, %{mitre_tactics: ["execution"]}) == false
    end

    test "matches MITRE techniques" do
      rule = %TriggerRule{
        match_criteria: %{"mitre_techniques" => ["T1003", "T1059"]}
      }

      assert AlertTrigger.evaluate_rule(rule, %{mitre_techniques: ["T1003"]}) == true
      assert AlertTrigger.evaluate_rule(rule, %{mitre_techniques: ["T1059", "T1204"]}) == true
      assert AlertTrigger.evaluate_rule(rule, %{mitre_techniques: ["T1204"]}) == false
    end

    test "matches threat score threshold" do
      rule = %TriggerRule{
        match_criteria: %{"threat_score_gte" => 0.7}
      }

      assert AlertTrigger.evaluate_rule(rule, %{threat_score: 0.8}) == true
      assert AlertTrigger.evaluate_rule(rule, %{threat_score: 0.7}) == true
      assert AlertTrigger.evaluate_rule(rule, %{threat_score: 0.5}) == false
    end

    test "matches title keywords (case-insensitive)" do
      rule = %TriggerRule{
        match_criteria: %{"title_contains" => ["malware", "ransomware"]}
      }

      assert AlertTrigger.evaluate_rule(rule, %{title: "Critical Malware Detected"}) == true
      assert AlertTrigger.evaluate_rule(rule, %{title: "RANSOMWARE ALERT"}) == true
      assert AlertTrigger.evaluate_rule(rule, %{title: "Policy Violation"}) == false
    end

    test "empty criteria matches all alerts" do
      rule = %TriggerRule{match_criteria: %{}}

      assert AlertTrigger.evaluate_rule(rule, @critical_alert) == true
      assert AlertTrigger.evaluate_rule(rule, @low_alert) == true
    end

    test "multiple criteria use AND logic" do
      rule = %TriggerRule{
        match_criteria: %{
          "severity" => ["critical"],
          "threat_score_gte" => 0.8
        }
      }

      # Critical + high score = match
      assert AlertTrigger.evaluate_rule(rule, @critical_alert) == true

      # Critical but low score = no match
      low_score_critical = %{@critical_alert | threat_score: 0.5}
      assert AlertTrigger.evaluate_rule(rule, low_score_critical) == false

      # High score but not critical = no match
      high_score_high = %{@credential_alert | threat_score: 0.9}
      assert AlertTrigger.evaluate_rule(rule, high_score_high) == false
    end
  end

  describe "get_default_rules/0" do
    test "returns predefined default rules" do
      rules = AlertTrigger.get_default_rules()

      assert is_list(rules)
      assert length(rules) >= 3

      names = Enum.map(rules, & &1.name)
      assert Enum.any?(names, &String.contains?(&1, "Critical"))
      assert Enum.any?(names, &String.contains?(&1, "Credential"))
      assert Enum.any?(names, &String.contains?(&1, "AI Model"))
    end
  end

  # Helper function for changeset errors
  defp errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
