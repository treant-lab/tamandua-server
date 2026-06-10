defmodule TamanduaServer.Agents.DriftDetectorTest do
  use TamanduaServer.DataCase

  alias TamanduaServer.Agents.{
    Agent,
    ConfigurationBaseline,
    ConfigurationDrift,
    DriftDetector,
    ComplianceStatus
  }

  describe "scan_agent/2" do
    setup do
      org = insert(:organization)
      agent = insert(:agent, organization: org, config: build_config())

      baseline = insert(:configuration_baseline,
        agent: agent,
        organization: org,
        collector_settings: %{
          "process" => %{"enabled" => true, "interval_ms" => 1000},
          "file" => %{"enabled" => true, "interval_ms" => 5000}
        },
        response_permissions: %{
          "allowed_actions" => ["kill_process", "quarantine"],
          "auto_response_enabled" => false
        },
        network_settings: %{
          "server_url" => "wss://server.test:4000",
          "tls_verify" => true
        },
        resource_limits: %{
          "max_cpu_percent" => 20,
          "max_memory_mb" => 512
        },
        enabled_features: %{
          "yara_enabled" => true,
          "sigma_enabled" => true,
          "ml_enabled" => false
        }
      )

      %{agent: agent, baseline: baseline, org: org}
    end

    test "detects no drift when configuration matches baseline", %{agent: agent} do
      {:ok, result} = DriftDetector.scan_agent(agent.id)

      assert result.scan.drifts_detected == 0
      assert Enum.empty?(result.drifts)
      assert result.compliance_score == 100.0
    end

    test "detects collector disabled drift", %{agent: agent} do
      # Disable process collector in agent config
      config = put_in(agent.config, ["collectors", "process", "enabled"], false)
      Repo.update!(Agent.changeset(agent, %{config: config}))

      {:ok, result} = DriftDetector.scan_agent(agent.id)

      assert result.scan.drifts_detected > 0
      assert Enum.any?(result.drifts, &(&1.drift_type == "collector_disabled"))
      assert result.compliance_score < 100.0
    end

    test "detects response permission changes", %{agent: agent} do
      # Enable auto-response (critical change)
      config = put_in(agent.config, ["response", "auto_response_enabled"], true)
      Repo.update!(Agent.changeset(agent, %{config: config}))

      {:ok, result} = DriftDetector.scan_agent(agent.id)

      drift = Enum.find(result.drifts, &(&1.drift_type == "response_permission_changed"))
      assert drift
      assert drift.severity == "critical"
    end

    test "detects network configuration changes", %{agent: agent} do
      # Change server URL (critical change)
      config = put_in(agent.config, ["network", "server_url"], "wss://malicious.test:4000")
      Repo.update!(Agent.changeset(agent, %{config: config}))

      {:ok, result} = DriftDetector.scan_agent(agent.id)

      drift = Enum.find(result.drifts, &(&1.category == "network"))
      assert drift
      assert drift.severity == "critical"
    end

    test "detects feature toggle changes", %{agent: agent} do
      # Disable YARA (critical security feature)
      config = put_in(agent.config, ["detection", "yara_enabled"], false)
      Repo.update!(Agent.changeset(agent, %{config: config}))

      {:ok, result} = DriftDetector.scan_agent(agent.id)

      drift = Enum.find(result.drifts, &(&1.drift_type == "feature_toggled"))
      assert drift
      assert drift.severity == "critical"
    end

    test "creates compliance status record", %{agent: agent} do
      {:ok, _result} = DriftDetector.scan_agent(agent.id)

      compliance = Repo.get_by(ComplianceStatus, agent_id: agent.id)
      assert compliance
      assert compliance.is_compliant == true
      assert compliance.compliance_score == 100.0
    end

    test "updates compliance status on subsequent scans", %{agent: agent} do
      # First scan - compliant
      {:ok, _} = DriftDetector.scan_agent(agent.id)

      # Introduce drift
      config = put_in(agent.config, ["collectors", "process", "enabled"], false)
      Repo.update!(Agent.changeset(agent, %{config: config}))

      # Second scan - non-compliant
      {:ok, _} = DriftDetector.scan_agent(agent.id)

      compliance = Repo.get_by(ComplianceStatus, agent_id: agent.id)
      assert compliance.is_compliant == false
      assert compliance.drift_count > 0
    end
  end

  describe "scan_organization/2" do
    test "scans all agents in organization" do
      org = insert(:organization)
      agent1 = insert(:agent, organization: org, config: build_config())
      agent2 = insert(:agent, organization: org, config: build_config())

      insert(:configuration_baseline, agent: agent1, organization: org)
      insert(:configuration_baseline, agent: agent2, organization: org)

      {:ok, result} = DriftDetector.scan_organization(org.id)

      assert result.total == 2
      assert result.scanned == 2
      assert result.failed == 0
    end
  end

  describe "get_compliance_summary/1" do
    test "returns compliance summary for organization" do
      org = insert(:organization)
      agent1 = insert(:agent, organization: org)
      agent2 = insert(:agent, organization: org)

      insert(:compliance_status,
        agent: agent1,
        organization: org,
        is_compliant: true,
        compliance_score: 100.0,
        critical_drifts: 0
      )

      insert(:compliance_status,
        agent: agent2,
        organization: org,
        is_compliant: false,
        compliance_score: 75.0,
        critical_drifts: 1,
        high_drifts: 2
      )

      summary = DriftDetector.get_compliance_summary(org.id)

      assert summary.total_agents == 2
      assert summary.compliant == 1
      assert summary.non_compliant == 1
      assert summary.avg_compliance_score == 87.5
      assert summary.total_critical_drifts == 1
      assert summary.total_high_drifts == 2
    end
  end

  describe "detect_drifts/3" do
    test "detects multiple drift types simultaneously" do
      org = insert(:organization)
      agent = insert(:agent, organization: org)

      baseline = %ConfigurationBaseline{
        collector_settings: %{
          "process" => %{"enabled" => true, "interval_ms" => 1000}
        },
        response_permissions: %{
          "allowed_actions" => ["kill_process"]
        },
        network_settings: %{
          "server_url" => "wss://server.test:4000"
        },
        resource_limits: %{
          "max_cpu_percent" => 20
        },
        enabled_features: %{
          "yara_enabled" => true
        }
      }

      current_config = %{
        "collectors" => %{
          "process" => %{"enabled" => false, "interval_ms" => 1000}
        },
        "response" => %{
          "allowed_actions" => ["kill_process", "delete_file"]
        },
        "network" => %{
          "server_url" => "wss://other.test:4000"
        },
        "resource_limits" => %{
          "max_cpu_percent" => 10
        },
        "detection" => %{
          "yara_enabled" => false
        }
      }

      drifts = DriftDetector.detect_drifts(baseline, current_config, agent)

      assert length(drifts) >= 4
      assert Enum.any?(drifts, &(&1.drift_type == "collector_disabled"))
      assert Enum.any?(drifts, &(&1.category == "response"))
      assert Enum.any?(drifts, &(&1.category == "network"))
      assert Enum.any?(drifts, &(&1.drift_type == "feature_toggled"))
    end
  end

  # Helper functions

  defp build_config do
    %{
      "collectors" => %{
        "process" => %{"enabled" => true, "interval_ms" => 1000},
        "file" => %{"enabled" => true, "interval_ms" => 5000}
      },
      "response" => %{
        "allowed_actions" => ["kill_process", "quarantine"],
        "auto_response_enabled" => false
      },
      "network" => %{
        "server_url" => "wss://server.test:4000",
        "tls_verify" => true
      },
      "resource_limits" => %{
        "max_cpu_percent" => 20,
        "max_memory_mb" => 512
      },
      "detection" => %{
        "yara_enabled" => true,
        "sigma_enabled" => true,
        "ml_enabled" => false
      }
    }
  end
end
