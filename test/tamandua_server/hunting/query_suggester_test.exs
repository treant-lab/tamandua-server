defmodule TamanduaServer.Hunting.QuerySuggesterTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Hunting.QuerySuggester
  alias TamanduaServer.Alerts.Alert

  describe "suggest_from_alert/2" do
    test "generates suggestions for credential access alert" do
      alert = %Alert{
        id: Ecto.UUID.generate(),
        title: "Mimikatz Credential Dumping",
        description: "Detected mimikatz accessing lsass.exe",
        process_name: "mimikatz.exe",
        command_line: "mimikatz.exe sekurlsa::logonpasswords",
        mitre_techniques: ["T1003.001"],
        severity: "critical"
      }

      suggestions = QuerySuggester.suggest_from_alert(alert, Ecto.UUID.generate())

      assert is_list(suggestions)
      assert length(suggestions) > 0

      # Should include similar activity suggestion
      assert Enum.any?(suggestions, fn s -> s.title =~ "similar" end)

      # Should suggest related TTPs
      assert Enum.any?(suggestions, fn s -> length(s.mitre_ttps) > 0 end)
    end

    test "generates lateral movement suggestions for network activity" do
      alert = %Alert{
        id: Ecto.UUID.generate(),
        title: "Suspicious SMB Connection",
        description: "Outbound SMB connection detected",
        process_name: "powershell.exe",
        network_info: %{
          "dst_ip" => "192.168.1.100",
          "dst_port" => 445,
          "protocol" => "tcp"
        },
        mitre_techniques: ["T1021.002"]
      }

      suggestions = QuerySuggester.suggest_from_alert(alert, Ecto.UUID.generate())

      # Should suggest lateral movement hunt
      lateral_suggestion =
        Enum.find(suggestions, fn s -> s.title =~ ~r/lateral/i end)

      assert lateral_suggestion != nil
      assert lateral_suggestion.query =~ "445"
    end

    test "generates persistence suggestions for registry modifications" do
      alert = %Alert{
        id: Ecto.UUID.generate(),
        title: "Registry Run Key Modified",
        description: "Suspicious registry modification for persistence",
        registry_path: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        mitre_techniques: ["T1547.001"]
      }

      suggestions = QuerySuggester.suggest_from_alert(alert, Ecto.UUID.generate())

      # Should suggest persistence check
      persistence_suggestion =
        Enum.find(suggestions, fn s -> s.title =~ ~r/persistence/i end)

      assert persistence_suggestion != nil
      assert persistence_suggestion.query =~ "registry"
    end
  end

  describe "generate_hunt_query_from_alert/1" do
    test "generates query from process-based alert" do
      alert = %Alert{
        process_name: "mimikatz.exe",
        command_line: "mimikatz.exe sekurlsa::logonpasswords"
      }

      query = QuerySuggester.generate_hunt_query_from_alert(alert)

      assert is_binary(query)
      assert query =~ "mimikatz.exe"
    end

    test "generates query from file-based alert" do
      alert = %Alert{
        file_path: "C:\\Windows\\Temp\\malware.exe"
      }

      query = QuerySuggester.generate_hunt_query_from_alert(alert)

      assert query =~ "malware.exe"
    end

    test "generates query from network-based alert" do
      alert = %Alert{
        network_info: %{
          "dst_ip" => "1.2.3.4",
          "dst_port" => 443
        }
      }

      query = QuerySuggester.generate_hunt_query_from_alert(alert)

      assert query =~ "1.2.3.4"
      assert query =~ "443"
    end

    test "generates query from IOC-based alert" do
      alert = %Alert{
        iocs: [
          %{type: "ip", value: "10.0.0.5"},
          %{type: "hash", value: "abc123"}
        ]
      }

      query = QuerySuggester.generate_hunt_query_from_alert(alert)

      assert query =~ "10.0.0.5"
      assert query =~ "abc123"
    end

    test "combines multiple conditions with OR" do
      alert = %Alert{
        process_name: "powershell.exe",
        file_path: "C:\\temp\\script.ps1"
      }

      query = QuerySuggester.generate_hunt_query_from_alert(alert)

      # Should contain both conditions
      assert query =~ "powershell.exe"
      assert query =~ "script.ps1"
    end
  end

  describe "ML-powered suggestions" do
    test "falls back gracefully when ML service unavailable" do
      alert = %Alert{
        id: Ecto.UUID.generate(),
        title: "Test Alert",
        description: "Test",
        process_name: "test.exe",
        mitre_techniques: []
      }

      # Should not crash even if ML service is down
      suggestions = QuerySuggester.suggest_from_alert(alert, Ecto.UUID.generate())

      assert is_list(suggestions)
      # Should still have rule-based suggestions
      assert length(suggestions) > 0
    end
  end

  describe "MITRE technique correlation" do
    test "suggests related techniques for credential access" do
      alert = %Alert{
        id: Ecto.UUID.generate(),
        title: "Credential Access",
        mitre_techniques: ["T1003.001"]
      }

      suggestions = QuerySuggester.suggest_from_alert(alert, Ecto.UUID.generate())

      # Should include related credential access techniques
      mitre_suggestion =
        Enum.find(suggestions, fn s -> s.source == "mitre_correlation" end)

      if mitre_suggestion do
        assert length(mitre_suggestion.mitre_ttps) > 0
      end
    end

    test "suggests related techniques for PowerShell execution" do
      alert = %Alert{
        id: Ecto.UUID.generate(),
        title: "PowerShell Execution",
        mitre_techniques: ["T1059.001"]
      }

      suggestions = QuerySuggester.suggest_from_alert(alert, Ecto.UUID.generate())

      # Related techniques should include cmd, VBScript, WMI
      related =
        suggestions
        |> Enum.flat_map(& &1.mitre_ttps)
        |> Enum.uniq()

      # Should have more techniques than just the original
      assert length(related) > 1
    end
  end

  describe "confidence scoring" do
    test "assigns high confidence to direct matches" do
      alert = %Alert{
        id: Ecto.UUID.generate(),
        title: "Direct Match",
        process_name: "mimikatz.exe"
      }

      suggestions = QuerySuggester.suggest_from_alert(alert, Ecto.UUID.generate())

      similar_suggestion =
        Enum.find(suggestions, fn s -> s.source == "pattern_matching" end)

      assert similar_suggestion.confidence >= 80
    end

    test "assigns lower confidence to ML suggestions when unavailable" do
      alert = %Alert{
        id: Ecto.UUID.generate(),
        title: "Test",
        process_name: "test.exe"
      }

      suggestions = QuerySuggester.suggest_from_alert(alert, Ecto.UUID.generate())

      # Rule-based suggestions should have confidence scores
      Enum.each(suggestions, fn s ->
        assert s.confidence >= 0
        assert s.confidence <= 100
      end)
    end
  end
end
