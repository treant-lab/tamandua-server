defmodule TamanduaServer.Inventory.LicenseAnalyzerTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Inventory.LicenseAnalyzer

  describe "analyze_software/1" do
    test "defaults missing license metadata to unknown" do
      result = LicenseAnalyzer.analyze_software(%{"name" => "Mystery App", "version" => "1.0"})

      assert result.license == ""
      assert result.license_source == "default"
      assert result.license_risk == "unknown"
    end

    test "reads license metadata from nested metadata payloads" do
      result =
        LicenseAnalyzer.analyze_software(%{
          "name" => "Nested Package",
          "version" => "2.0",
          "metadata" => %{"license_expression" => "Apache-2.0"}
        })

      assert result.license == "Apache-2.0"
      assert result.license_source == "metadata"
      assert result.license_risk == "permissive"
    end

    test "classifies conservative license risk buckets" do
      assert LicenseAnalyzer.classify_license("MIT") == "permissive"
      assert LicenseAnalyzer.classify_license("GPL-3.0-only") == "copyleft"
      assert LicenseAnalyzer.classify_license("SSPL-1.0") == "restricted"
      assert LicenseAnalyzer.classify_license("Commercial EULA") == "commercial"
      assert LicenseAnalyzer.classify_license("unlicensed") == "unlicensed"
      assert LicenseAnalyzer.classify_license("custom internal terms") == "unknown"
    end
  end

  describe "analyze_asset/1" do
    test "returns summary and findings for asset software inventory" do
      analysis =
        LicenseAnalyzer.analyze_asset(%{
          id: "asset-1",
          hostname: "host-1",
          installed_software: [
            %{"name" => "Phoenix", "version" => "1.7", "license" => "MIT"},
            %{"name" => "Database", "version" => "8", "metadata" => %{"license" => "SSPL"}},
            %{"name" => "Unknown Tool", "version" => "0.1"}
          ]
        })

      assert analysis.asset_id == "asset-1"
      assert analysis.hostname == "host-1"
      assert analysis.summary.total_software == 3
      assert analysis.summary.with_license_metadata == 2
      assert analysis.summary.without_license_metadata == 1
      assert analysis.summary.by_license_risk["permissive"] == 1
      assert analysis.summary.by_license_risk["restricted"] == 1
      assert analysis.summary.by_license_risk["unknown"] == 1

      assert Enum.map(analysis.findings, & &1.license_risk) == ["restricted", "unknown"]
    end
  end
end
