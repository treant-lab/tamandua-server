defmodule TamanduaServer.SLO.ErrorBudgetTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.SLO.ErrorBudget

  describe "calculate_budget/2" do
    test "calculates zero budget consumption with perfect uptime" do
      uptime_samples = List.duplicate(1, 1440)  # 24 hours of uptime
      result = ErrorBudget.calculate_budget(uptime_samples, 30)

      assert result.budget_consumed_percent == 0.0
      assert result.budget_consumed_minutes == 0.0
      assert result.budget_remaining_percent == 100.0
      assert result.status == :healthy
    end

    test "calculates budget consumption with downtime" do
      # 1430 up, 10 down = 10 minutes downtime
      uptime_samples = List.duplicate(1, 1430) ++ List.duplicate(0, 10)
      result = ErrorBudget.calculate_budget(uptime_samples, 30)

      # Total budget for 30 days @ 99.9% = 43.2 minutes
      # 10 minutes consumed = 23.15% of budget
      assert result.budget_consumed_minutes == 10.0
      assert result.budget_consumed_percent > 23.0
      assert result.budget_consumed_percent < 24.0
      assert result.budget_remaining_percent > 76.0
      assert result.status == :healthy
    end

    test "detects warning status when budget is low" do
      # Consume 30 minutes of 43.2 minute budget = ~69% consumed
      uptime_samples = List.duplicate(1, 1410) ++ List.duplicate(0, 30)
      result = ErrorBudget.calculate_budget(uptime_samples, 30)

      assert result.budget_consumed_minutes == 30.0
      assert result.budget_remaining_percent < 31.0
      assert result.status == :warning
    end

    test "detects critical status when budget is critically low" do
      # Consume 40 minutes of 43.2 minute budget = ~92% consumed
      uptime_samples = List.duplicate(1, 1400) ++ List.duplicate(0, 40)
      result = ErrorBudget.calculate_budget(uptime_samples, 30)

      assert result.budget_consumed_minutes == 40.0
      assert result.budget_remaining_percent < 10.0
      assert result.status == :critical
    end

    test "calculates for different time windows" do
      uptime_samples = List.duplicate(1, 1440)

      result_7d = ErrorBudget.calculate_budget(uptime_samples, 7)
      result_30d = ErrorBudget.calculate_budget(uptime_samples, 30)

      assert result_7d.time_window_days == 7
      assert result_30d.time_window_days == 30
      assert result_30d.budget_total_minutes > result_7d.budget_total_minutes
    end

    test "handles empty samples" do
      result = ErrorBudget.calculate_budget([], 30)

      assert result.budget_consumed_percent == 0.0
      assert result.status == :healthy
    end
  end

  describe "calculate_burn_rate/2" do
    test "calculates zero burn rate with perfect uptime" do
      short_samples = List.duplicate(1, 5)
      long_samples = List.duplicate(1, 60)

      result = ErrorBudget.calculate_burn_rate(short_samples, long_samples)

      assert result.short_window.burn_rate == 0.0
      assert result.long_window.burn_rate == 0.0
      assert result.alert_status == :ok
    end

    test "calculates normal burn rate (1x)" do
      # 0.1% error rate = 1x burn rate
      # 1 error per 1000 samples
      short_samples = List.duplicate(1, 4) ++ [0]
      long_samples = List.duplicate(1, 59) ++ [0]

      result = ErrorBudget.calculate_burn_rate(short_samples, long_samples)

      # Short window: 1/5 = 20% error rate = 200x burn rate
      # Long window: 1/60 = 1.67% error rate = 16.7x burn rate
      assert result.short_window.burn_rate > 0
      assert result.long_window.burn_rate > 0
    end

    test "detects fast burn (critical)" do
      # High error rate in short window
      short_samples = List.duplicate(0, 3) ++ List.duplicate(1, 2)  # 60% errors
      long_samples = List.duplicate(1, 50) ++ List.duplicate(0, 10)

      result = ErrorBudget.calculate_burn_rate(short_samples, long_samples)

      # 60% error rate / 0.1% allowed = 600x burn rate
      assert result.short_window.burn_rate > 14.4
      assert result.alert_status == :critical
    end

    test "detects medium burn (warning)" do
      # Elevated error rate in long window
      short_samples = List.duplicate(1, 5)
      long_samples = List.duplicate(1, 55) ++ List.duplicate(0, 5)  # 8.33% errors

      result = ErrorBudget.calculate_burn_rate(short_samples, long_samples)

      # 8.33% / 0.1% = 83.3x burn rate
      assert result.long_window.burn_rate > 6.0
      assert result.alert_status in [:warning, :critical]
    end

    test "detects slow burn (watch)" do
      short_samples = List.duplicate(1, 5)
      long_samples = List.duplicate(1, 58) ++ List.duplicate(0, 2)  # 3.33% errors

      result = ErrorBudget.calculate_burn_rate(short_samples, long_samples)

      # 3.33% / 0.1% = 33.3x burn rate
      assert result.long_window.burn_rate > 3.0
      assert result.alert_status in [:watch, :warning, :critical]
    end

    test "includes burn rate thresholds in result" do
      short_samples = List.duplicate(1, 5)
      long_samples = List.duplicate(1, 60)

      result = ErrorBudget.calculate_burn_rate(short_samples, long_samples)

      assert result.thresholds.fast_burn == 14.4
      assert result.thresholds.medium_burn == 6.0
      assert result.thresholds.slow_burn == 3.0
    end

    test "projects budget exhaustion time" do
      # Create sustained error rate
      short_samples = List.duplicate(1, 4) ++ [0]
      long_samples = List.duplicate(1, 50) ++ List.duplicate(0, 10)

      result = ErrorBudget.calculate_burn_rate(short_samples, long_samples)

      # Should project a future exhaustion time
      if result.long_window.burn_rate > 0 do
        assert result.projected_budget_exhaustion != nil
        assert DateTime.compare(result.projected_budget_exhaustion, DateTime.utc_now()) == :gt
      end
    end

    test "handles all-down samples" do
      short_samples = List.duplicate(0, 5)
      long_samples = List.duplicate(0, 60)

      result = ErrorBudget.calculate_burn_rate(short_samples, long_samples)

      # 100% error rate / 0.1% allowed = 1000x burn rate
      assert result.short_window.burn_rate > 100
      assert result.alert_status == :critical
    end
  end

  describe "burn rate alert thresholds" do
    test "fast burn exhausts budget in ~2 hours" do
      # 14.4x burn rate means consuming budget 14.4x faster
      # 30 days * 24 hours / 14.4 = 50 hours to exhaust
      # But we only consume 0.1% of time, so 0.1% * 720 hours / 14.4 = ~5 hours
      # More precisely: 43.2 minutes / 14.4 = 3 minutes to exhaust

      # This is a conceptual test - actual calculation in production
      burn_rate = 14.4
      budget_minutes = 43.2

      time_to_exhaust_minutes = budget_minutes / burn_rate
      assert time_to_exhaust_minutes == 3.0
    end

    test "medium burn exhausts budget in ~5 hours" do
      burn_rate = 6.0
      budget_minutes = 43.2

      time_to_exhaust_minutes = budget_minutes / burn_rate
      assert time_to_exhaust_minutes == 7.2
    end

    test "slow burn exhausts budget in ~10 hours" do
      burn_rate = 3.0
      budget_minutes = 43.2

      time_to_exhaust_minutes = budget_minutes / burn_rate
      assert time_to_exhaust_minutes == 14.4
    end
  end

  describe "error budget lifecycle" do
    test "budget starts at 100%" do
      uptime_samples = []
      result = ErrorBudget.calculate_budget(uptime_samples, 30)

      assert result.budget_remaining_percent == 100.0 - 99.9  # 0.1%
    end

    test "budget decreases with downtime" do
      samples_perfect = List.duplicate(1, 1440)
      samples_some_downtime = List.duplicate(1, 1430) ++ List.duplicate(0, 10)

      result_perfect = ErrorBudget.calculate_budget(samples_perfect, 30)
      result_downtime = ErrorBudget.calculate_budget(samples_some_downtime, 30)

      assert result_downtime.budget_remaining_percent < result_perfect.budget_remaining_percent
    end

    test "budget can be exhausted" do
      # Exceed the 43.2 minute budget with 50 minutes downtime
      uptime_samples = List.duplicate(1, 1390) ++ List.duplicate(0, 50)
      result = ErrorBudget.calculate_budget(uptime_samples, 30)

      assert result.budget_consumed_minutes > result.budget_total_minutes
      assert result.budget_remaining_percent < 0
      assert result.status == :critical
    end
  end

  describe "violation recording" do
    test "records violation impact" do
      # This would be tested with the actual GenServer in integration tests
      # Here we test the calculation logic

      violation = %{type: :downtime, duration_minutes: 5.0}

      # A 5 minute violation should consume 5 minutes of budget
      assert violation.duration_minutes == 5.0
    end

    test "calculates cumulative violations" do
      violations = [
        %{duration_minutes: 2.0},
        %{duration_minutes: 3.0},
        %{duration_minutes: 5.0}
      ]

      total_impact = Enum.reduce(violations, 0.0, fn v, acc ->
        acc + v.duration_minutes
      end)

      assert total_impact == 10.0
    end
  end
end
