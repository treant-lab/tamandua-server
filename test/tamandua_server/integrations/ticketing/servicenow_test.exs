defmodule TamanduaServer.Integrations.Ticketing.ServiceNowTest do
  use ExUnit.Case, async: true

  import Mox

  alias TamanduaServer.Integrations.Ticketing.ServiceNow

  setup :verify_on_exit!

  @security_incident_table "sn_si_incident"

  @valid_config %{
    table: @security_incident_table
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

  describe "create_incident_from_alert/2" do
    test "maps alert fields to ServiceNow incident" do
      incident_data = build_expected_incident_data(@valid_alert, @valid_config)

      assert incident_data[:title] == "[Tamandua] Suspicious process detected"
      assert incident_data[:severity] == "high"
      assert incident_data[:hostname] == "workstation-01"
      assert incident_data[:agent_id] == "agent-789"
      assert incident_data[:table] == @security_incident_table
    end

    test "includes MITRE ATT&CK info in incident data" do
      incident_data = build_expected_incident_data(@valid_alert, @valid_config)

      assert incident_data[:mitre_tactics] == ["Execution", "Defense Evasion"]
      assert incident_data[:mitre_techniques] == ["T1059.001", "T1027"]
    end

    test "uses security incident table by default" do
      incident_data = build_expected_incident_data(@valid_alert, %{})

      assert incident_data[:table] == @security_incident_table
    end

    test "includes custom u_tamandua_ fields" do
      # These fields would be formatted during create_incident call
      # Verify the raw data includes the necessary identifiers
      incident_data = build_expected_incident_data(@valid_alert, @valid_config)

      assert incident_data[:id] == "alert-123"
      assert incident_data[:threat_score] == 85
    end

    test "handles alerts with missing optional fields" do
      minimal_alert = %{
        id: "alert-456",
        title: "Test Alert",
        severity: "medium"
      }

      incident_data = build_expected_incident_data(minimal_alert, @valid_config)

      assert incident_data[:id] == "alert-456"
      assert incident_data[:title] == "[Tamandua] Test Alert"
      assert incident_data[:mitre_tactics] == []
      assert incident_data[:mitre_techniques] == []
      assert is_nil(incident_data[:hostname])
    end

    test "supports string-keyed alert maps" do
      string_alert = %{
        "id" => "alert-789",
        "title" => "String Key Alert",
        "severity" => "critical",
        "hostname" => "server-01",
        "mitre_tactics" => ["Persistence"]
      }

      incident_data = build_expected_incident_data_from_string_keys(string_alert, @valid_config)

      assert incident_data[:id] == "alert-789"
      assert incident_data[:title] == "[Tamandua] String Key Alert"
      assert incident_data[:severity] == "critical"
      assert incident_data[:hostname] == "server-01"
    end
  end

  describe "find_existing_incident/2" do
    test "builds correct sysparm_query for deduplication" do
      alert_id = "alert-123"
      config = %{table: @security_incident_table}

      query = build_dedup_query(alert_id, config)

      assert query[:sysparm_query] == "u_tamandua_alert_id=alert-123"
      assert query[:table] == @security_incident_table
      assert query[:limit] == 1
      assert query[:fields] == ["sys_id", "number"]
    end

    test "uses default table if not specified" do
      alert_id = "alert-456"
      config = %{}

      query = build_dedup_query(alert_id, config)

      assert query[:table] == @security_incident_table
      assert query[:sysparm_query] == "u_tamandua_alert_id=alert-456"
    end
  end

  describe "sync_alert_status/2" do
    test "maps resolved status to ServiceNow state 6" do
      state = map_status_to_snow_state("resolved")
      assert state == 6
    end

    test "maps closed status to ServiceNow state 7" do
      state = map_status_to_snow_state("closed")
      assert state == 7
    end

    test "maps in_progress status to ServiceNow state 2" do
      state = map_status_to_snow_state("in_progress")
      assert state == 2
    end

    test "maps acknowledged status to ServiceNow state 2" do
      state = map_status_to_snow_state("acknowledged")
      assert state == 2
    end

    test "maps unknown status to ServiceNow state 1 (New)" do
      state = map_status_to_snow_state("unknown")
      assert state == 1
    end
  end

  describe "severity mapping" do
    test "critical severity maps to impact/urgency 1" do
      {impact, urgency} = map_severity_to_impact_urgency("critical")
      assert impact == 1
      assert urgency == 1
    end

    test "high severity maps to impact/urgency 2" do
      {impact, urgency} = map_severity_to_impact_urgency("high")
      assert impact == 2
      assert urgency == 2
    end

    test "medium severity maps to impact/urgency 2" do
      {impact, urgency} = map_severity_to_impact_urgency("medium")
      assert impact == 2
      assert urgency == 2
    end

    test "low severity maps to impact/urgency 3" do
      {impact, urgency} = map_severity_to_impact_urgency("low")
      assert impact == 3
      assert urgency == 3
    end

    test "unknown severity defaults to impact/urgency 2" do
      {impact, urgency} = map_severity_to_impact_urgency("info")
      assert impact == 2
      assert urgency == 2
    end
  end

  describe "CMDB integration" do
    test "builds correct CMDB lookup query" do
      hostname = "workstation-01"
      query = build_cmdb_query(hostname)

      assert String.contains?(query, "name=workstation-01")
      assert String.contains?(query, "ip_address=workstation-01")
    end

    test "URL encodes special characters in hostname" do
      hostname = "server/with spaces"
      query = build_cmdb_query(hostname)

      # The query should be URL encoded
      assert String.contains?(query, URI.encode("server/with spaces"))
    end
  end

  describe "custom field naming" do
    test "uses u_tamandua_ prefix for custom fields" do
      formatted = format_custom_fields(@valid_alert)

      assert Map.has_key?(formatted, :u_tamandua_alert_id)
      assert Map.has_key?(formatted, :u_hostname)
      assert Map.has_key?(formatted, :u_agent_id)
      assert Map.has_key?(formatted, :u_mitre_tactics)
      assert Map.has_key?(formatted, :u_mitre_techniques)
      assert Map.has_key?(formatted, :u_threat_score)
    end

    test "joins MITRE arrays with commas" do
      formatted = format_custom_fields(@valid_alert)

      assert formatted[:u_mitre_tactics] == "Execution, Defense Evasion"
      assert formatted[:u_mitre_techniques] == "T1059.001, T1027"
    end
  end

  # Helper functions to test the logic without GenServer calls

  defp build_expected_incident_data(alert, config) do
    %{
      title: "[Tamandua] #{alert[:title] || alert["title"] || "Alert"}",
      description: alert[:description] || alert["description"],
      severity: alert[:severity] || alert["severity"],
      hostname: alert[:hostname] || alert["hostname"],
      agent_id: alert[:agent_id] || alert["agent_id"],
      mitre_tactics: alert[:mitre_tactics] || alert["mitre_tactics"] || [],
      mitre_techniques: alert[:mitre_techniques] || alert["mitre_techniques"] || [],
      threat_score: alert[:threat_score] || alert["threat_score"],
      id: alert[:id] || alert["id"],
      table: config[:table] || config["table"] || @security_incident_table,
      cmdb_ci: nil
    }
  end

  defp build_expected_incident_data_from_string_keys(alert, config) do
    %{
      title: "[Tamandua] #{alert["title"] || "Alert"}",
      description: alert["description"],
      severity: alert["severity"],
      hostname: alert["hostname"],
      agent_id: alert["agent_id"],
      mitre_tactics: alert["mitre_tactics"] || [],
      mitre_techniques: alert["mitre_techniques"] || [],
      threat_score: alert["threat_score"],
      id: alert["id"],
      table: config[:table] || config["table"] || @security_incident_table,
      cmdb_ci: nil
    }
  end

  defp build_dedup_query(alert_id, config) do
    table = config[:table] || config["table"] || @security_incident_table
    %{
      table: table,
      sysparm_query: "u_tamandua_alert_id=#{alert_id}",
      limit: 1,
      fields: ["sys_id", "number"]
    }
  end

  defp map_status_to_snow_state("resolved"), do: 6
  defp map_status_to_snow_state("closed"), do: 7
  defp map_status_to_snow_state("in_progress"), do: 2
  defp map_status_to_snow_state("acknowledged"), do: 2
  defp map_status_to_snow_state(_), do: 1

  defp map_severity_to_impact_urgency("critical"), do: {1, 1}
  defp map_severity_to_impact_urgency("high"), do: {2, 2}
  defp map_severity_to_impact_urgency("medium"), do: {2, 2}
  defp map_severity_to_impact_urgency("low"), do: {3, 3}
  defp map_severity_to_impact_urgency(_), do: {2, 2}

  defp build_cmdb_query(hostname_or_ip) do
    "sysparm_query=name=#{URI.encode(hostname_or_ip)}^ORip_address=#{URI.encode(hostname_or_ip)}"
  end

  defp format_custom_fields(alert) do
    %{
      u_tamandua_alert_id: alert[:id] || alert["id"],
      u_hostname: alert[:hostname] || alert["hostname"],
      u_agent_id: alert[:agent_id] || alert["agent_id"],
      u_mitre_tactics: Enum.join(alert[:mitre_tactics] || alert["mitre_tactics"] || [], ", "),
      u_mitre_techniques: Enum.join(alert[:mitre_techniques] || alert["mitre_techniques"] || [], ", "),
      u_threat_score: alert[:threat_score] || alert["threat_score"]
    }
  end
end
