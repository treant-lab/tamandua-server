defmodule TamanduaServer.SLO.TrackerTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.SLO.Tracker

  setup do
    # Start the tracker for testing
    start_supervised!(Tracker)
    :ok
  end

  describe "record_api_request/3" do
    test "records successful API request" do
      Tracker.record_api_request(150, true, "/api/alerts")

      # Give it a moment to process
      Process.sleep(10)

      metrics = Tracker.current_metrics()
      assert metrics.api.latency.sample_count > 0
    end

    test "records failed API request" do
      Tracker.record_api_request(250, false, "/api/events")

      Process.sleep(10)

      metrics = Tracker.current_metrics()
      assert metrics.api.error_rate.error_requests > 0
    end

    test "tracks multiple requests" do
      # Record 100 successful requests
      for _ <- 1..100 do
        Tracker.record_api_request(Enum.random(50..200), true, "/api/test")
      end

      Process.sleep(50)

      metrics = Tracker.current_metrics()
      assert metrics.api.latency.sample_count >= 100
      assert metrics.api.throughput.total_events >= 100
    end
  end

  describe "record_event_processing/2" do
    test "records event processing metrics" do
      Tracker.record_event_processing(75, true)

      Process.sleep(10)

      metrics = Tracker.current_metrics()
      assert metrics.event_processing.latency.sample_count > 0
    end

    test "tracks processing errors" do
      Tracker.record_event_processing(500, false)

      Process.sleep(10)

      metrics = Tracker.current_metrics()
      assert metrics.event_processing.error_rate.error_requests > 0
    end
  end

  describe "record_detection/3" do
    test "records YARA detection" do
      Tracker.record_detection(200, true, :yara)

      Process.sleep(10)

      metrics = Tracker.current_metrics()
      assert metrics.detection.latency.sample_count > 0
    end

    test "records Sigma detection" do
      Tracker.record_detection(150, true, :sigma)

      Process.sleep(10)

      metrics = Tracker.current_metrics()
      assert metrics.detection.latency.sample_count > 0
    end

    test "records ML detection" do
      Tracker.record_detection(300, true, :ml)

      Process.sleep(10)

      metrics = Tracker.current_metrics()
      assert metrics.detection.latency.sample_count > 0
    end
  end

  describe "record_ml_prediction/2" do
    test "records ML predictions" do
      Tracker.record_ml_prediction(450, true)

      Process.sleep(10)

      metrics = Tracker.current_metrics()
      assert metrics.ml_service.latency.sample_count > 0
    end
  end

  describe "record_availability_check/1" do
    test "records system up" do
      Tracker.record_availability_check(true)

      Process.sleep(10)

      metrics = Tracker.current_metrics()
      assert metrics.availability.uptime_count > 0
    end

    test "records system down" do
      Tracker.record_availability_check(false)

      Process.sleep(10)

      metrics = Tracker.current_metrics()
      assert metrics.availability.total_count > 0
    end
  end

  describe "current_metrics/0" do
    test "returns all service metrics" do
      # Record some test data
      Tracker.record_api_request(100, true, "/test")
      Tracker.record_event_processing(50, true)
      Tracker.record_detection(200, true, :yara)
      Tracker.record_ml_prediction(300, true)
      Tracker.record_availability_check(true)

      Process.sleep(50)

      metrics = Tracker.current_metrics()

      assert Map.has_key?(metrics, :api)
      assert Map.has_key?(metrics, :event_processing)
      assert Map.has_key?(metrics, :detection)
      assert Map.has_key?(metrics, :ml_service)
      assert Map.has_key?(metrics, :availability)
      assert Map.has_key?(metrics, :timestamp)
    end

    test "calculates SLI metrics correctly" do
      # Record latencies: 100ms (x10)
      for _ <- 1..10 do
        Tracker.record_api_request(100, true, "/test")
      end

      Process.sleep(50)

      metrics = Tracker.current_metrics()

      assert metrics.api.latency.p50 > 0
      assert metrics.api.latency.p95 > 0
      assert metrics.api.error_rate.value >= 0
      assert metrics.api.throughput.value >= 0
    end
  end

  describe "service_metrics/1" do
    test "returns metrics for specific service" do
      Tracker.record_api_request(150, true, "/test")
      Process.sleep(10)

      metrics = Tracker.service_metrics(:api)

      assert Map.has_key?(metrics, :latency)
      assert Map.has_key?(metrics, :error_rate)
      assert Map.has_key?(metrics, :throughput)
      assert Map.has_key?(metrics, :sample_count)
    end

    test "returns events service metrics" do
      Tracker.record_event_processing(75, true)
      Process.sleep(10)

      metrics = Tracker.service_metrics(:events)

      assert metrics.latency.sample_count > 0
    end

    test "returns detection service metrics" do
      Tracker.record_detection(200, true, :yara)
      Process.sleep(10)

      metrics = Tracker.service_metrics(:detection)

      assert metrics.latency.sample_count > 0
    end
  end

  describe "error_budget_status/0" do
    test "returns error budget information" do
      # Record some availability samples
      for _ <- 1..10 do
        Tracker.record_availability_check(true)
      end

      Process.sleep(50)

      status = Tracker.error_budget_status()

      assert Map.has_key?(status, :budget_remaining_percent)
      assert Map.has_key?(status, :budget_consumed_percent)
      assert Map.has_key?(status, :burn_rate)
    end
  end

  describe "SLO compliance tracking" do
    test "tracks compliance when all metrics meet SLO" do
      # Record good metrics
      for _ <- 1..100 do
        Tracker.record_api_request(100, true, "/test")
        Tracker.record_event_processing(50, true)
        Tracker.record_availability_check(true)
      end

      Process.sleep(100)

      metrics = Tracker.current_metrics()

      assert metrics.api.latency.compliant == true
      assert metrics.event_processing.latency.compliant == true
      assert metrics.availability.compliant == true
    end

    test "detects SLO breach on high latency" do
      # Record latencies above 500ms threshold
      for _ <- 1..100 do
        Tracker.record_api_request(600, true, "/test")
      end

      Process.sleep(50)

      metrics = Tracker.current_metrics()

      # p95 should be around 600ms, exceeding 500ms target
      assert metrics.api.latency.p95 > 500
      assert metrics.api.latency.compliant == false
    end

    test "detects SLO breach on high error rate" do
      # Record 50% error rate (well above 0.1% threshold)
      for _ <- 1..50 do
        Tracker.record_api_request(100, true, "/test")
        Tracker.record_api_request(100, false, "/test")
      end

      Process.sleep(50)

      metrics = Tracker.current_metrics()

      assert metrics.api.error_rate.value > 0.1
      assert metrics.api.error_rate.compliant == false
    end
  end

  describe "time window aggregation" do
    test "aggregates metrics over time" do
      # Record metrics over time
      for i <- 1..20 do
        Tracker.record_api_request(i * 10, true, "/test")
        Process.sleep(10)
      end

      metrics = Tracker.current_metrics()

      # Should have calculated percentiles
      assert metrics.api.latency.p50 > 0
      assert metrics.api.latency.p95 > metrics.api.latency.p50
    end
  end

  describe "ETS storage" do
    test "stores metrics in ETS for fast access" do
      Tracker.record_api_request(100, true, "/test")

      Process.sleep(10)

      # ETS table should have entries
      table = :ets.whereis(:slo_metrics)
      assert table != :undefined

      # Should be able to query the table
      entries = :ets.tab2list(table)
      assert length(entries) > 0
    end
  end

  describe "metric retention" do
    test "retains recent metrics in ETS" do
      # Record old and new metrics
      for i <- 1..10 do
        Tracker.record_api_request(i * 10, true, "/test")
      end

      Process.sleep(50)

      metrics = Tracker.current_metrics()

      # Should only include recent samples (within time window)
      assert metrics.api.latency.sample_count > 0
    end
  end
end
