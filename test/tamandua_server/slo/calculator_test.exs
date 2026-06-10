defmodule TamanduaServer.SLO.CalculatorTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.SLO.Calculator

  describe "calculate_availability/2" do
    test "calculates 100% availability with all up samples" do
      uptime_samples = List.duplicate(1, 100)
      result = Calculator.calculate_availability(uptime_samples, :hour)

      assert result.value == 100.0
      assert result.compliant == true
      assert result.uptime_count == 100
      assert result.total_count == 100
      assert result.downtime_minutes == 0.0
    end

    test "calculates availability with some downtime" do
      # 99 up, 1 down = 99% availability
      uptime_samples = List.duplicate(1, 99) ++ [0]
      result = Calculator.calculate_availability(uptime_samples, :hour)

      assert result.value == 99.0
      assert result.compliant == true  # Above 99.9% threshold
      assert result.uptime_count == 99
      assert result.total_count == 100
      assert result.downtime_minutes == 1.0
    end

    test "detects SLO breach with excessive downtime" do
      # 98 up, 2 down = 98% availability (below 99.9% SLO)
      uptime_samples = List.duplicate(1, 98) ++ [0, 0]
      result = Calculator.calculate_availability(uptime_samples, :hour)

      assert result.value == 98.0
      assert result.compliant == false
      assert result.downtime_minutes == 2.0
    end

    test "handles empty samples" do
      result = Calculator.calculate_availability([], :hour)

      assert result.value == 100.0
      assert result.compliant == true
      assert result.total_count == 0
    end

    test "calculates for different time windows" do
      uptime_samples = List.duplicate(1, 1000)

      result_hour = Calculator.calculate_availability(uptime_samples, :hour)
      result_day = Calculator.calculate_availability(uptime_samples, :day)

      assert result_hour.time_window == :hour
      assert result_day.time_window == :day
    end
  end

  describe "calculate_latency/2" do
    test "calculates latency percentiles correctly" do
      # Create latency samples: 1ms to 100ms
      latencies = Enum.to_list(1..100)
      result = Calculator.calculate_latency(latencies, :api)

      assert result.p50 >= 49.0 and result.p50 <= 51.0
      assert result.p95 >= 94.0 and result.p95 <= 96.0
      assert result.p99 >= 98.0 and result.p99 <= 100.0
      assert result.min == 1.0
      assert result.max == 100.0
      assert result.avg == 50.5
      assert result.sample_count == 100
    end

    test "detects SLO compliance" do
      # All latencies below 500ms threshold
      latencies = List.duplicate(100, 100)
      result = Calculator.calculate_latency(latencies, :api)

      assert result.compliant == true
      assert result.p95 == 100.0
      assert result.target_p95 == 500
    end

    test "detects SLO breach" do
      # p95 above 500ms threshold
      latencies = List.duplicate(100, 95) ++ List.duplicate(600, 5)
      result = Calculator.calculate_latency(latencies, :api)

      assert result.compliant == false
      assert result.p95 > 500
    end

    test "handles empty latencies" do
      result = Calculator.calculate_latency([], :api)

      assert result.p50 == 0.0
      assert result.p95 == 0.0
      assert result.p99 == 0.0
      assert result.compliant == true
      assert result.sample_count == 0
    end

    test "handles single sample" do
      result = Calculator.calculate_latency([250.5], :api)

      assert result.p50 == 250.5
      assert result.p95 == 250.5
      assert result.p99 == 250.5
      assert result.compliant == true
    end
  end

  describe "calculate_error_rate/2" do
    test "calculates 0% error rate with no errors" do
      result = Calculator.calculate_error_rate(1000, 0)

      assert result.value == 0.0
      assert result.compliant == true
      assert result.total_requests == 1000
      assert result.error_requests == 0
      assert result.success_requests == 1000
    end

    test "calculates error rate correctly" do
      # 1 error in 1000 requests = 0.1%
      result = Calculator.calculate_error_rate(1000, 1)

      assert result.value == 0.1
      assert result.compliant == true  # At threshold
      assert result.error_requests == 1
    end

    test "detects SLO breach" do
      # 2 errors in 1000 requests = 0.2% (above 0.1% threshold)
      result = Calculator.calculate_error_rate(1000, 2)

      assert result.value == 0.2
      assert result.compliant == false
    end

    test "handles 100% error rate" do
      result = Calculator.calculate_error_rate(100, 100)

      assert result.value == 100.0
      assert result.compliant == false
      assert result.success_requests == 0
    end

    test "handles zero requests" do
      result = Calculator.calculate_error_rate(0, 0)

      assert result.value == 0.0
      assert result.compliant == true
      assert result.total_requests == 0
    end
  end

  describe "calculate_throughput/3" do
    test "calculates throughput correctly" do
      # 3600 events in 1 hour = 1 event/sec
      result = Calculator.calculate_throughput(3600, :hour, :telemetry)

      assert result.value == 1.0
      assert result.total_events == 3600
      assert result.time_window == :hour
      assert result.time_window_seconds == 3600
    end

    test "detects SLO compliance" do
      # 3,600,000 events in 1 hour = 1000 events/sec (at threshold)
      result = Calculator.calculate_throughput(3_600_000, :hour, :telemetry)

      assert result.value == 1000.0
      assert result.compliant == true
      assert result.target == 1000
    end

    test "detects SLO breach" do
      # 100 events in 1 hour = 0.027 events/sec (below threshold)
      result = Calculator.calculate_throughput(100, :hour, :telemetry)

      assert result.value < 1000
      assert result.compliant == false
    end

    test "handles different time windows" do
      result_minute = Calculator.calculate_throughput(60, :minute, :api)
      result_day = Calculator.calculate_throughput(86400, :day, :api)

      assert result_minute.value == 1.0
      assert result_day.value == 1.0
      assert result_minute.time_window_seconds == 60
      assert result_day.time_window_seconds == 86400
    end
  end

  describe "calculate_composite_sli/1" do
    test "calculates perfect composite score" do
      slis = %{
        availability: %{compliant: true},
        latency: %{compliant: true},
        error_rate: %{compliant: true},
        throughput: %{compliant: true}
      }

      result = Calculator.calculate_composite_sli(slis)

      assert result.score == 100.0
      assert result.compliant == true
      assert result.breakdown.availability == true
      assert result.breakdown.latency == true
      assert result.breakdown.error_rate == true
      assert result.breakdown.throughput == true
    end

    test "calculates partial compliance score" do
      slis = %{
        availability: %{compliant: true},
        latency: %{compliant: false},
        error_rate: %{compliant: true},
        throughput: %{compliant: true}
      }

      result = Calculator.calculate_composite_sli(slis)

      # 30% + 0% + 25% + 20% = 75%
      assert result.score == 75.0
      assert result.compliant == false
      assert result.breakdown.latency == false
    end

    test "calculates zero compliance score" do
      slis = %{
        availability: %{compliant: false},
        latency: %{compliant: false},
        error_rate: %{compliant: false},
        throughput: %{compliant: false}
      }

      result = Calculator.calculate_composite_sli(slis)

      assert result.score == 0.0
      assert result.compliant == false
    end

    test "handles missing SLIs" do
      slis = %{
        availability: %{compliant: true}
      }

      result = Calculator.calculate_composite_sli(slis)

      # Only availability (30% weight) is present
      assert result.score == 30.0
    end
  end

  describe "all_slos_met?/1" do
    test "returns true when all SLOs are met" do
      slis = %{
        availability: %{compliant: true},
        latency: %{compliant: true},
        error_rate: %{compliant: true}
      }

      assert Calculator.all_slos_met?(slis) == true
    end

    test "returns false when any SLO is breached" do
      slis = %{
        availability: %{compliant: true},
        latency: %{compliant: false},
        error_rate: %{compliant: true}
      }

      assert Calculator.all_slos_met?(slis) == false
    end

    test "returns false when all SLOs are breached" do
      slis = %{
        availability: %{compliant: false},
        latency: %{compliant: false}
      }

      assert Calculator.all_slos_met?(slis) == false
    end

    test "handles empty SLIs" do
      assert Calculator.all_slos_met?(%{}) == true
    end
  end

  describe "calculate_trend/2" do
    test "detects improving trend for availability" do
      current = %{value: 99.95, target: 99.9}
      historical = [
        %{value: 99.90},
        %{value: 99.85},
        %{value: 99.80}
      ]

      result = Calculator.calculate_trend(current, historical)
      assert result == :improving
    end

    test "detects degrading trend for latency" do
      current = %{value: 550.0, target: 500}
      historical = [
        %{value: 400.0},
        %{value: 420.0},
        %{value: 450.0}
      ]

      result = Calculator.calculate_trend(current, historical)
      assert result == :degrading
    end

    test "detects stable trend" do
      current = %{value: 99.9, target: 99.9}
      historical = [
        %{value: 99.9},
        %{value: 99.91},
        %{value: 99.89}
      ]

      result = Calculator.calculate_trend(current, historical)
      assert result == :stable
    end

    test "handles insufficient historical data" do
      current = %{value: 99.9}
      historical = [%{value: 99.8}]

      result = Calculator.calculate_trend(current, historical)
      assert result == :stable
    end
  end

  describe "targets/0" do
    test "returns configured SLO targets" do
      targets = Calculator.targets()

      assert targets.availability_percent == 99.9
      assert targets.latency_p95_ms == 500
      assert targets.latency_p99_ms == 1000
      assert targets.error_rate_percent == 0.1
      assert targets.throughput_events_per_sec == 1000
    end
  end
end
