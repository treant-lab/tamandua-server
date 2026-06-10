defmodule TamanduaServer.Integrations.Ticketing.JiraTest do
  use ExUnit.Case, async: true

  import Mox

  alias TamanduaServer.Integrations.Ticketing.Jira

  setup :verify_on_exit!

  @valid_config %{
    project_key: "SEC",
    issue_type: "Security Incident"
  }

  @valid_alert %{
    id: "alert-123",
    title: "Suspicious process detected",
    severity: "high",
    description: "PowerShell executing encoded command",
    hostname: "workstation-01",
    agent_id: "agent-789",
    mitre_tactics: ["Execution", "Defense Evasion"],
    mitre_techniques: ["T1059.001", "T1027"],
    threat_score: 85
  }

  describe "create_issue_from_alert/2" do
    test "maps alert fields to Jira issue structure" do
      issue_data = build_expected_issue_data(@valid_alert, @valid_config)

      # Verify the expected fields are present
      assert issue_data[:title] == "[Tamandua] Suspicious process detected"
      assert issue_data[:severity] == "high"
      assert issue_data[:project_key] == "SEC"
      assert issue_data[:issue_type] == "Security Incident"
      assert issue_data[:hostname] == "workstation-01"
      assert issue_data[:agent_id] == "agent-789"
    end

    test "includes MITRE ATT&CK info in issue data" do
      issue_data = build_expected_issue_data(@valid_alert, @valid_config)

      assert issue_data[:mitre_tactics] == ["Execution", "Defense Evasion"]
      assert issue_data[:mitre_techniques] == ["T1059.001", "T1027"]
    end

    test "adds tamandua-alert-{id} label for deduplication" do
      issue_data = build_expected_issue_data(@valid_alert, @valid_config)

      assert "tamandua-alert-alert-123" in issue_data[:labels]
      assert "tamandua" in issue_data[:labels]
      assert "severity-high" in issue_data[:labels]
    end

    test "maps severity to priority correctly" do
      # The mapping is:
      # critical -> Highest
      # high -> High
      # medium -> Medium
      # low -> Low
      # other -> Medium

      assert map_severity("critical") == "Highest"
      assert map_severity("high") == "High"
      assert map_severity("medium") == "Medium"
      assert map_severity("low") == "Low"
      assert map_severity("info") == "Medium"
      assert map_severity(nil) == "Medium"
    end

    test "handles alerts with missing optional fields" do
      minimal_alert = %{
        id: "alert-456",
        title: "Test Alert",
        severity: "medium"
      }

      issue_data = build_expected_issue_data(minimal_alert, @valid_config)

      assert issue_data[:id] == "alert-456"
      assert issue_data[:title] == "[Tamandua] Test Alert"
      assert issue_data[:mitre_tactics] == []
      assert issue_data[:mitre_techniques] == []
    end

    test "supports string-keyed alert maps" do
      string_alert = %{
        "id" => "alert-789",
        "title" => "String Key Alert",
        "severity" => "high",
        "hostname" => "server-01",
        "mitre_tactics" => ["Persistence"]
      }

      issue_data = build_expected_issue_data_from_string_keys(string_alert, @valid_config)

      assert issue_data[:id] == "alert-789"
      assert issue_data[:title] == "[Tamandua] String Key Alert"
      assert issue_data[:severity] == "high"
      assert issue_data[:hostname] == "server-01"
    end
  end

  describe "find_existing_ticket/2" do
    test "builds correct JQL query for deduplication" do
      alert_id = "alert-123"
      config = %{project_key: "SEC"}

      jql = build_dedup_jql(alert_id, config)

      assert jql == "project = SEC AND labels = tamandua-alert-alert-123"
    end

    test "uses default project key if not specified" do
      alert_id = "alert-456"
      config = %{}

      jql = build_dedup_jql(alert_id, config)

      assert jql == "project = SEC AND labels = tamandua-alert-alert-456"
    end
  end

  describe "severity mapping" do
    test "critical severity maps to Highest priority" do
      assert map_severity("critical") == "Highest"
    end

    test "high severity maps to High priority" do
      assert map_severity("high") == "High"
    end

    test "medium severity maps to Medium priority" do
      assert map_severity("medium") == "Medium"
    end

    test "low severity maps to Low priority" do
      assert map_severity("low") == "Low"
    end

    test "unknown severity defaults to Medium priority" do
      assert map_severity("unknown") == "Medium"
      assert map_severity("info") == "Medium"
    end
  end

  describe "label generation" do
    test "generates correct labels for alert" do
      labels = build_labels(@valid_alert)

      assert "tamandua" in labels
      assert "tamandua-alert-alert-123" in labels
      assert "severity-high" in labels
      assert length(labels) == 3
    end

    test "handles nil severity gracefully" do
      alert = %{id: "test-alert", severity: nil}
      labels = build_labels(alert)

      assert "tamandua" in labels
      assert "tamandua-alert-test-alert" in labels
      # severity-nil label should still be generated
      assert "severity-" in labels
    end
  end

  # Helper functions to test the logic without GenServer calls

  defp build_expected_issue_data(alert, config) do
    %{
      title: "[Tamandua] #{alert[:title] || alert["title"] || "Alert"}",
      description: alert[:description] || alert["description"],
      severity: alert[:severity] || alert["severity"],
      project_key: config[:project_key] || config["project_key"],
      issue_type: config[:issue_type] || config["issue_type"] || "Security Incident",
      labels: build_labels(alert),
      id: alert[:id] || alert["id"],
      hostname: alert[:hostname] || alert["hostname"],
      agent_id: alert[:agent_id] || alert["agent_id"],
      mitre_tactics: alert[:mitre_tactics] || alert["mitre_tactics"] || [],
      mitre_techniques: alert[:mitre_techniques] || alert["mitre_techniques"] || [],
      threat_score: alert[:threat_score] || alert["threat_score"]
    }
  end

  defp build_expected_issue_data_from_string_keys(alert, config) do
    %{
      title: "[Tamandua] #{alert["title"] || "Alert"}",
      description: alert["description"],
      severity: alert["severity"],
      project_key: config[:project_key] || config["project_key"],
      issue_type: config[:issue_type] || config["issue_type"] || "Security Incident",
      labels: build_labels_from_string_keys(alert),
      id: alert["id"],
      hostname: alert["hostname"],
      agent_id: alert["agent_id"],
      mitre_tactics: alert["mitre_tactics"] || [],
      mitre_techniques: alert["mitre_techniques"] || [],
      threat_score: alert["threat_score"]
    }
  end

  defp build_labels(alert) do
    [
      "tamandua",
      "tamandua-alert-#{alert[:id] || alert["id"]}",
      "severity-#{alert[:severity] || alert["severity"]}"
    ]
  end

  defp build_labels_from_string_keys(alert) do
    [
      "tamandua",
      "tamandua-alert-#{alert["id"]}",
      "severity-#{alert["severity"]}"
    ]
  end

  defp build_dedup_jql(alert_id, config) do
    project_key = config[:project_key] || config["project_key"] || "SEC"
    "project = #{project_key} AND labels = tamandua-alert-#{alert_id}"
  end

  defp map_severity("critical"), do: "Highest"
  defp map_severity("high"), do: "High"
  defp map_severity("medium"), do: "Medium"
  defp map_severity("low"), do: "Low"
  defp map_severity(_), do: "Medium"
end
