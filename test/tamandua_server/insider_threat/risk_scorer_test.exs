defmodule TamanduaServer.InsiderThreat.RiskScorerTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.InsiderThreat.{RiskScorer, Indicator}

  describe "calculate_indicator_score/1" do
    test "sums indicator weights" do
      indicators = [
        Indicator.new(:data_exfiltration, %{bytes: 1_000_000, destination: "test"}),
        Indicator.new(:privilege_escalation, %{method: "sudo", count: 1}),
        Indicator.new(:off_hours_activity, %{hour: 2, user: "user"})
      ]

      score = RiskScorer.calculate_indicator_score(indicators)

      # 40 + 30 + 20 = 90
      assert score == 90.0
    end

    test "caps score at max (100.0)" do
      indicators = [
        Indicator.new(:data_exfiltration, %{bytes: 1_000_000, destination: "test"}),
        Indicator.new(:privilege_escalation, %{method: "sudo", count: 1}),
        Indicator.new(:bulk_download, %{bytes: 1_000_000, files: 100}),
        Indicator.new(:credential_misuse, %{credential_type: "shared"})
      ]

      score = RiskScorer.calculate_indicator_score(indicators)

      # Would be 40 + 30 + 35 + 35 = 140, but capped at 100
      assert score == 100.0
    end

    test "returns 0 for empty indicators" do
      assert RiskScorer.calculate_indicator_score([]) == 0.0
    end
  end

  describe "get_severity/1" do
    test "returns critical for scores >= 70" do
      assert RiskScorer.get_severity(70.0) == :critical
      assert RiskScorer.get_severity(85.0) == :critical
      assert RiskScorer.get_severity(100.0) == :critical
    end

    test "returns high for scores >= 40 and < 70" do
      assert RiskScorer.get_severity(40.0) == :high
      assert RiskScorer.get_severity(55.0) == :high
      assert RiskScorer.get_severity(69.0) == :high
    end

    test "returns medium for scores >= 20 and < 40" do
      assert RiskScorer.get_severity(20.0) == :medium
      assert RiskScorer.get_severity(30.0) == :medium
      assert RiskScorer.get_severity(39.0) == :medium
    end

    test "returns low for scores < 20" do
      assert RiskScorer.get_severity(0.0) == :low
      assert RiskScorer.get_severity(10.0) == :low
      assert RiskScorer.get_severity(19.0) == :low
    end
  end

  describe "exceeds_threshold?/2" do
    test "checks high threshold (70)" do
      assert RiskScorer.exceeds_threshold?(75.0, :high)
      refute RiskScorer.exceeds_threshold?(65.0, :high)
    end

    test "checks medium threshold (40)" do
      assert RiskScorer.exceeds_threshold?(45.0, :medium)
      refute RiskScorer.exceeds_threshold?(35.0, :medium)
    end
  end

  describe "breakdown/1" do
    test "groups indicators by type and calculates totals" do
      indicators = [
        Indicator.new(:data_exfiltration, %{bytes: 1_000_000, destination: "test"}),
        Indicator.new(:data_exfiltration, %{bytes: 2_000_000, destination: "test2"}),
        Indicator.new(:privilege_escalation, %{method: "sudo", count: 1})
      ]

      breakdown = RiskScorer.breakdown(indicators)

      assert breakdown[:data_exfiltration].count == 2
      assert breakdown[:data_exfiltration].total_weight == 80.0
      assert breakdown[:data_exfiltration].severity == :critical

      assert breakdown[:privilege_escalation].count == 1
      assert breakdown[:privilege_escalation].total_weight == 30.0
      assert breakdown[:privilege_escalation].severity == :high
    end
  end

  describe "high_risk_threshold/0 and medium_risk_threshold/0" do
    test "returns correct thresholds" do
      assert RiskScorer.high_risk_threshold() == 70.0
      assert RiskScorer.medium_risk_threshold() == 40.0
    end
  end
end
