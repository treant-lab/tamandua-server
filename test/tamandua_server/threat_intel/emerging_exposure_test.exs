defmodule TamanduaServer.ThreatIntel.EmergingExposureTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.ThreatIntel.EmergingExposure

  describe "assess/2" do
    test "returns unknown with coverage gaps when local context is missing" do
      result =
        EmergingExposure.assess(%{
          "cves" => ["CVE-2024-12345"],
          "indicators" => [%{"type" => "ip", "value" => "203.0.113.10"}]
        })

      assert result.exposure_status == :unknown
      assert result.matched_assets == []
      assert result.matched_products == []
      assert result.matched_cves == []
      assert result.telemetry_matches == []
      assert :software_inventory_missing in result.coverage_gaps
      assert :vulnerability_inventory_missing in result.coverage_gaps
      assert :asset_inventory_missing in result.coverage_gaps
      assert :telemetry_missing in result.coverage_gaps
      assert :software_inventory in result.recommended_collection
      assert :vulnerability_scan in result.recommended_collection
      assert :network_telemetry in result.recommended_collection
    end

    test "matches explicit CVEs, affected products, telemetry IOCs, and assets" do
      threat = %{
        affected_products: [%{vendor: "Apache", product: "Apache HTTP Server"}],
        cves: ["CVE-2021-41773"],
        iocs: [%{type: "ip", value: "198.51.100.25"}]
      }

      context = %{
        software_inventory: [
          %{id: "sw-1", agent_id: "agent-1", vendor: "Apache", name: "Apache HTTP Server", version: "2.4.49"}
        ],
        vulnerabilities: [
          %{
            id: "vuln-1",
            agent_id: "agent-1",
            software_id: "sw-1",
            cve_id: "CVE-2021-41773",
            severity: "critical",
            status: "open"
          }
        ],
        agents: [
          %{id: "agent-1", hostname: "web-01", os_type: "linux", status: "online"}
        ],
        telemetry: [
          %{id: "event-1", agent_id: "agent-1", event_type: "network_connect", dst_ip: "198.51.100.25"}
        ]
      }

      result = EmergingExposure.assess(threat, context)

      assert result.exposure_status == :exposed
      assert [%{asset_id: "agent-1", hostname: "web-01"}] = result.matched_assets
      assert [%{product: "Apache HTTP Server", vendor: "Apache", version: "2.4.49", asset_id: "agent-1"}] =
               result.matched_products

      assert [%{cve_id: "CVE-2021-41773", asset_id: "agent-1", product: "Apache HTTP Server"}] =
               result.matched_cves

      assert [%{type: "ip", value: "198.51.100.25", asset_id: "agent-1"}] = result.telemetry_matches
      assert result.coverage_gaps == []
      assert result.recommended_collection == []
    end

    test "does not invent matches when context is present but unrelated" do
      threat = %{
        affected_products: ["OpenSSL"],
        cves: ["CVE-2024-99999"],
        iocs: [%{type: "domain", value: "malicious.example"}]
      }

      context = %{
        software_inventory: [%{agent_id: "agent-1", vendor: "curl", name: "curl", version: "8.0.0"}],
        vulnerabilities: [%{agent_id: "agent-1", cve_id: "CVE-2023-0001"}],
        assets: [%{id: "agent-1", hostname: "workstation-01"}],
        browser_telemetry: [%{agent_id: "agent-1", event_type: "dns_query", domain: "benign.example"}]
      }

      result = EmergingExposure.assess(threat, context)

      assert result.exposure_status == :not_detected
      assert result.matched_assets == []
      assert result.matched_products == []
      assert result.matched_cves == []
      assert result.telemetry_matches == []
      assert result.coverage_gaps == []
      assert result.recommended_collection == []
    end
  end
end
