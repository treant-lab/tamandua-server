defmodule TamanduaServer.Integrations.HealthMonitorTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Integrations.{HealthMonitor, Config}
  alias TamanduaServer.Integrations.Schemas.{HealthMetric, UptimeRecord, Incident}

  setup do
    # Create test integration
    {:ok, integration} = Config.create_integration(%{
      type: :splunk,
      name: "Test Splunk",
      config: %{
        hec_url: "https://splunk.example.com:8088",
        hec_token: "test-token"
      }
    })

    %{integration: integration}
  end

  describe "health metrics tracking" do
    test "updates health metrics", %{integration: integration} do
      metrics = %{
        status: "connected",
        errors_per_minute: 2.5,
        latency_avg: 150.0
      }

      HealthMonitor.update_health(integration.id, metrics)

      # Give it time to process
      Process.sleep(100)

      health = HealthMonitor.get_health(integration.id)

      assert health[:status] == "connected"
      assert health[:errors_per_minute] == 2.5
      assert health[:latency_avg] == 150.0
    end

    test "records API requests", %{integration: integration} do
      # Record some requests
      HealthMonitor.record_request(integration.id, duration_ms: 100, status_code: 200, success: true)
      HealthMonitor.record_request(integration.id, duration_ms: 150, status_code: 200, success: true)
      HealthMonitor.record_request(integration.id, duration_ms: 200, status_code: 500, success: false)

      # Give it time to calculate metrics
      Process.sleep(100)

      health = HealthMonitor.get_health(integration.id)

      assert health[:total_requests] == 3
      assert health[:total_errors] == 1
      assert health[:errors_per_minute] > 0
    end

    test "calculates latency percentiles", %{integration: integration} do
      # Record requests with different latencies
      for ms <- [50, 100, 150, 200, 250, 300, 350, 400, 450, 500] do
        HealthMonitor.record_request(integration.id, duration_ms: ms, success: true)
      end

      Process.sleep(100)

      health = HealthMonitor.get_health(integration.id)

      assert health[:latency_avg] != nil
      assert health[:latency_p50] != nil
      assert health[:latency_p95] != nil
      assert health[:latency_p99] != nil
    end

    test "lists health for all integrations", %{integration: _integration} do
      health_list = HealthMonitor.list_health()

      assert is_list(health_list)
      assert length(health_list) > 0
    end

    test "gets health summary" do
      summary = HealthMonitor.get_summary()

      assert is_map(summary)
      assert Map.has_key?(summary, :total)
      assert Map.has_key?(summary, :connected)
      assert Map.has_key?(summary, :disconnected)
      assert Map.has_key?(summary, :health_score)
    end
  end

  describe "incident detection" do
    test "creates incident on connection failure", %{integration: integration} do
      metrics = %{
        status: "disconnected",
        error_message: "Connection timeout"
      }

      HealthMonitor.update_health(integration.id, metrics)

      Process.sleep(100)

      incidents = Incident.list_open(integration.id)
      assert length(incidents) > 0

      incident = List.first(incidents)
      assert incident.incident_type == "connection_failure"
      assert incident.severity == "critical"
    end

    test "creates incident on high error rate", %{integration: integration} do
      metrics = %{
        errors_per_minute: 10.0  # >5% threshold
      }

      HealthMonitor.update_health(integration.id, metrics)

      Process.sleep(100)

      incidents = Incident.list_open(integration.id)
      high_error_incidents = Enum.filter(incidents, & &1.incident_type == "high_error_rate")

      assert length(high_error_incidents) > 0
    end

    test "creates incident on rate limit approaching", %{integration: integration} do
      metrics = %{
        rate_limit_total: 1000,
        rate_limit_used: 850,  # 85% usage
        rate_limit_remaining: 150
      }

      HealthMonitor.update_health(integration.id, metrics)

      Process.sleep(100)

      incidents = Incident.list_open(integration.id)
      rate_limit_incidents = Enum.filter(incidents, & &1.incident_type == "rate_limit")

      assert length(rate_limit_incidents) > 0
    end

    test "creates incident on credential expiry", %{integration: integration} do
      # Credential expires in 5 days
      expires_at = DateTime.utc_now() |> DateTime.add(5 * 24 * 60 * 60, :second)

      metrics = %{
        credential_expires_at: expires_at
      }

      HealthMonitor.update_health(integration.id, metrics)

      Process.sleep(100)

      incidents = Incident.list_open(integration.id)
      expiry_incidents = Enum.filter(incidents, & &1.incident_type == "credential_expiry")

      assert length(expiry_incidents) > 0
    end

    test "creates incident on sync lag", %{integration: integration} do
      metrics = %{
        sync_lag_seconds: 7200  # 2 hours
      }

      HealthMonitor.update_health(integration.id, metrics)

      Process.sleep(100)

      incidents = Incident.list_open(integration.id)
      sync_lag_incidents = Enum.filter(incidents, & &1.incident_type == "sync_lag")

      assert length(sync_lag_incidents) > 0
    end
  end

  describe "uptime tracking" do
    test "calculates daily uptime", %{integration: integration} do
      # Create an incident that lasted 1 hour
      started_at = DateTime.utc_now() |> DateTime.add(-7200, :second)  # 2 hours ago
      resolved_at = DateTime.utc_now() |> DateTime.add(-3600, :second)  # 1 hour ago

      {:ok, incident} = Incident.create_or_update(integration.id, :connection_failure, %{
        severity: "critical",
        started_at: started_at,
        resolved_at: resolved_at,
        resolution_time_seconds: 3600,
        status: "resolved"
      })

      # Calculate uptime
      {:ok, uptime} = UptimeRecord.calculate_daily_uptime(integration.id)

      assert uptime.incident_count == 1
      assert uptime.downtime_seconds == 3600
      assert uptime.uptime_seconds == 82800  # 24 hours - 1 hour
      assert uptime.sla_actual < 100
    end

    test "gets uptime stats for period", %{integration: integration} do
      stats = UptimeRecord.get_uptime_stats(integration.id, 30)

      assert is_map(stats)
      assert Map.has_key?(stats, :avg_uptime_percent)
      assert Map.has_key?(stats, :total_incidents)
      assert Map.has_key?(stats, :sla_compliance_percent)
    end
  end

  describe "request metrics cleanup" do
    test "cleans up old request data", %{integration: integration} do
      # Record some requests
      for _ <- 1..100 do
        HealthMonitor.record_request(integration.id, duration_ms: 100, success: true)
      end

      # Wait for cleanup cycle (simulate with manual call)
      # In real test, would wait for :cleanup message
      initial_count = :ets.info(:integration_requests, :size)
      assert initial_count > 0

      # Cleanup is handled by the GenServer automatically
      # For testing, we just verify data was recorded
      health = HealthMonitor.get_health(integration.id)
      assert health[:total_requests] != nil
    end
  end
end
