defmodule TamanduaServer.InsiderThreat.IndicatorTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.InsiderThreat.Indicator

  describe "new/2" do
    test "creates off-hours activity indicator" do
      indicator = Indicator.new(:off_hours_activity, %{hour: 2, user: "user123"})

      assert indicator.type == :off_hours_activity
      assert indicator.severity == :medium
      assert indicator.weight == 20.0
      assert indicator.description =~ "off-hours"
    end

    test "creates data exfiltration indicator" do
      indicator =
        Indicator.new(:data_exfiltration, %{bytes: 5_000_000_000, destination: "external.com"})

      assert indicator.type == :data_exfiltration
      assert indicator.severity == :critical
      assert indicator.weight == 40.0
      assert indicator.description =~ "5.0 GB"
    end

    test "creates privilege escalation indicator" do
      indicator = Indicator.new(:privilege_escalation, %{method: "sudo", count: 3})

      assert indicator.type == :privilege_escalation
      assert indicator.severity == :high
      assert indicator.weight == 30.0
    end
  end

  describe "get_weight/1" do
    test "returns correct weights for different indicator types" do
      assert Indicator.get_weight(:data_exfiltration) == 40.0
      assert Indicator.get_weight(:privilege_escalation) == 30.0
      assert Indicator.get_weight(:off_hours_activity) == 20.0
      assert Indicator.get_weight(:peer_group_outlier) == 10.0
    end
  end

  describe "get_severity/1" do
    test "returns correct severity for different indicator types" do
      assert Indicator.get_severity(:data_exfiltration) == :critical
      assert Indicator.get_severity(:privilege_escalation) == :high
      assert Indicator.get_severity(:off_hours_activity) == :medium
      assert Indicator.get_severity(:peer_group_outlier) == :low
    end
  end

  describe "high_severity?/1" do
    test "returns true for critical and high severity indicators" do
      critical_indicator = Indicator.new(:data_exfiltration, %{bytes: 1_000_000, destination: "test"})
      high_indicator = Indicator.new(:privilege_escalation, %{method: "sudo", count: 1})
      medium_indicator = Indicator.new(:off_hours_activity, %{hour: 2, user: "user"})

      assert Indicator.high_severity?(critical_indicator)
      assert Indicator.high_severity?(high_indicator)
      refute Indicator.high_severity?(medium_indicator)
    end
  end

  describe "format_bytes/1" do
    test "formats bytes correctly" do
      assert Indicator.format_bytes(500) == "500 B"
      assert Indicator.format_bytes(1024) == "1.0 KB"
      assert Indicator.format_bytes(1_048_576) == "1.0 MB"
      assert Indicator.format_bytes(1_073_741_824) == "1.0 GB"
      assert Indicator.format_bytes(5_368_709_120) == "5.0 GB"
    end
  end

  describe "all_types/0" do
    test "returns all indicator types" do
      types = Indicator.all_types()

      assert :off_hours_activity in types
      assert :data_exfiltration in types
      assert :privilege_escalation in types
      assert :peer_group_outlier in types
      assert length(types) == 16
    end
  end
end
