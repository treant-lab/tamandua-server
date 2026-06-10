defmodule TamanduaServer.Alerts.SupplyChainEnricherTest do
  use TamanduaServer.DataCase

  alias TamanduaServer.Alerts.SupplyChainEnricher
  alias TamanduaServer.Alerts.Alert

  describe "enrich/1" do
    test "enriches known_malicious type with Socket.dev data" do
      alert = %Alert{
        enrichment: %{
          "ecosystem" => "npm",
          "package_name" => "malicious-package",
          "package_version" => "1.0.0",
          "risk_type" => "known_malicious",
          "socket_dev_score" => 95
        }
      }

      enriched = SupplyChainEnricher.enrich(alert)

      assert enriched.enrichment["ecosystem_display"] == "npm"
      assert enriched.enrichment["severity_reason"] != nil
      assert enriched.enrichment["recommended_action"] != nil
      assert enriched.enrichment["socket_dev_score"] == 95
    end

    test "enriches typosquatting type with similar_to packages" do
      alert = %Alert{
        enrichment: %{
          "ecosystem" => "pypi",
          "package_name" => "requsts",
          "package_version" => "2.0.0",
          "risk_type" => "typosquatting",
          "similar_to" => ["requests"],
          "detection_method" => "levenshtein",
          "levenshtein_distance" => 1
        }
      }

      enriched = SupplyChainEnricher.enrich(alert)

      assert enriched.enrichment["similar_packages"] == ["requests"]
      assert enriched.enrichment["detection_method"] == "levenshtein"
      assert enriched.enrichment["distance"] == 1
      assert enriched.enrichment["ecosystem_display"] == "PyPI"
    end

    test "enriches malicious_script type with pattern details" do
      alert = %Alert{
        enrichment: %{
          "ecosystem" => "npm",
          "package_name" => "evil-package",
          "package_version" => "1.0.0",
          "risk_type" => "malicious_script",
          "suspicious_patterns" => ["base64_decode", "network_download"],
          "risk_score" => 0.85,
          "script_content" => "eval(atob('base64data'))"
        }
      }

      enriched = SupplyChainEnricher.enrich(alert)

      assert enriched.enrichment["patterns_detected"] == ["base64_decode", "network_download"]
      assert enriched.enrichment["risk_score"] == 0.85
      assert enriched.enrichment["script_hash"] != nil
    end

    test "enriches anomalous_behavior type with behavior details" do
      alert = %Alert{
        enrichment: %{
          "ecosystem" => "cargo",
          "package_name" => "suspicious-crate",
          "package_version" => "0.1.0",
          "risk_type" => "anomalous_behavior",
          "network_destinations" => ["evil.com", "malicious.net"],
          "sensitive_files" => [".ssh/id_rsa", ".aws/credentials"]
        }
      }

      enriched = SupplyChainEnricher.enrich(alert)

      assert enriched.enrichment["anomaly_types"] != nil
      assert enriched.enrichment["network_count"] == 2
      assert enriched.enrichment["files_count"] == 2
      assert enriched.enrichment["ecosystem_display"] == "Cargo"
    end

    test "preserves existing enrichment fields" do
      alert = %Alert{
        enrichment: %{
          "ecosystem" => "npm",
          "package_name" => "test-package",
          "package_version" => "1.0.0",
          "risk_type" => "known_malicious",
          "custom_field" => "custom_value"
        }
      }

      enriched = SupplyChainEnricher.enrich(alert)

      assert enriched.enrichment["custom_field"] == "custom_value"
      assert enriched.enrichment["ecosystem"] == "npm"
    end

    test "handles gem ecosystem with correct display name" do
      alert = %Alert{
        enrichment: %{
          "ecosystem" => "gem",
          "package_name" => "test-gem",
          "package_version" => "1.0.0",
          "risk_type" => "known_malicious"
        }
      }

      enriched = SupplyChainEnricher.enrich(alert)

      assert enriched.enrichment["ecosystem_display"] == "RubyGems"
    end

    test "handles go ecosystem with correct display name" do
      alert = %Alert{
        enrichment: %{
          "ecosystem" => "go",
          "package_name" => "github.com/evil/package",
          "package_version" => "v1.0.0",
          "risk_type" => "known_malicious"
        }
      }

      enriched = SupplyChainEnricher.enrich(alert)

      assert enriched.enrichment["ecosystem_display"] == "Go Modules"
    end
  end

  describe "create_supply_chain_alert/2" do
    test "builds alert with correct schema fields" do
      agent_id = Ecto.UUID.generate()

      details = %{
        ecosystem: :npm,
        package_name: "test-package",
        version: "1.0.0",
        risk_type: :known_malicious
      }

      alert = SupplyChainEnricher.create_supply_chain_alert(agent_id, details)

      assert alert.agent_id == agent_id
      assert alert.severity in ["critical", "high", "medium", "low"]
      assert alert.title != nil
      assert alert.description != nil
      assert "initial_access" in alert.mitre_tactics
      assert "T1195.001" in alert.mitre_techniques
      assert alert.enrichment["ecosystem"] == "npm"
      assert alert.enrichment["package_name"] == "test-package"
      assert alert.enrichment["package_version"] == "1.0.0"
      assert alert.enrichment["risk_type"] == "known_malicious"
    end

    test "maps known_malicious to critical severity" do
      alert =
        SupplyChainEnricher.create_supply_chain_alert(Ecto.UUID.generate(), %{
          ecosystem: :npm,
          package_name: "evil",
          version: "1.0.0",
          risk_type: :known_malicious
        })

      assert alert.severity == "critical"
    end

    test "maps typosquatting to high severity" do
      alert =
        SupplyChainEnricher.create_supply_chain_alert(Ecto.UUID.generate(), %{
          ecosystem: :npm,
          package_name: "lodas",
          version: "1.0.0",
          risk_type: :typosquatting
        })

      assert alert.severity == "high"
    end

    test "maps malicious_script to high severity" do
      alert =
        SupplyChainEnricher.create_supply_chain_alert(Ecto.UUID.generate(), %{
          ecosystem: :npm,
          package_name: "suspicious",
          version: "1.0.0",
          risk_type: :malicious_script
        })

      assert alert.severity == "high"
    end

    test "maps anomalous_behavior to medium severity" do
      alert =
        SupplyChainEnricher.create_supply_chain_alert(Ecto.UUID.generate(), %{
          ecosystem: :npm,
          package_name: "strange",
          version: "1.0.0",
          risk_type: :anomalous_behavior
        })

      assert alert.severity == "medium"
    end

    test "merges extra fields into enrichment" do
      alert =
        SupplyChainEnricher.create_supply_chain_alert(Ecto.UUID.generate(), %{
          ecosystem: :npm,
          package_name: "test",
          version: "1.0.0",
          risk_type: :known_malicious,
          extra: %{"socket_dev_score" => 95, "custom_field" => "value"}
        })

      assert alert.enrichment["socket_dev_score"] == 95
      assert alert.enrichment["custom_field"] == "value"
    end
  end

  describe "broadcast_alert/1" do
    test "publishes to alerts:supply_chain topic" do
      alert = %Alert{
        id: Ecto.UUID.generate(),
        severity: "critical",
        title: "Malicious package detected",
        enrichment: %{
          "ecosystem" => "npm",
          "package_name" => "evil",
          "risk_type" => "known_malicious"
        }
      }

      # Subscribe to the topic to verify broadcast
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "alerts:supply_chain")

      :ok = SupplyChainEnricher.broadcast_alert(alert)

      assert_receive %{event: "new_alert", payload: ^alert}, 500
    end
  end
end
