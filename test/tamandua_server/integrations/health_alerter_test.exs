defmodule TamanduaServer.Integrations.HealthAlerterTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Integrations.{HealthAlerter, Config, HealthMonitor}
  alias TamanduaServer.Integrations.Schemas.Incident

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

  describe "alert configuration" do
    test "configures alert settings", %{integration: integration} do
      config = %{
        error_rate: 10.0,
        rate_limit: 90.0,
        credential_expiry_days: 14,
        sync_lag_hours: 2
      }

      result = HealthAlerter.configure_alerts(integration.id, config)

      assert result == :ok

      # Verify config was stored
      retrieved_config = HealthAlerter.get_alert_config(integration.id)
      assert retrieved_config[:error_rate] == 10.0
      assert retrieved_config[:rate_limit] == 90.0
    end

    test "returns default thresholds when not configured" do
      config = HealthAlerter.get_alert_config(Ecto.UUID.generate())

      assert is_map(config)
      assert config[:error_rate] == 5.0
      assert config[:rate_limit] == 80.0
      assert config[:credential_expiry_days] == 7
      assert config[:sync_lag_hours] == 1
    end
  end

  describe "alert triggering" do
    test "sends alert for connection failure", %{integration: integration} do
      # Create an incident
      {:ok, incident} = Incident.create_or_update(integration.id, :connection_failure, %{
        severity: "critical",
        error_message: "Connection lost"
      })

      # Trigger alert
      HealthAlerter.send_alert(incident.id)

      # Wait for async processing
      Process.sleep(100)

      # Verify incident was marked as alerted
      updated_incident = Repo.get(Incident, incident.id)
      assert updated_incident.alert_sent == true
      assert updated_incident.alert_sent_at != nil
    end

    test "sends alert for high error rate", %{integration: integration} do
      {:ok, incident} = Incident.create_or_update(integration.id, :high_error_rate, %{
        severity: "high",
        error_message: "Error rate: 10.5%"
      })

      HealthAlerter.send_alert(incident.id)

      Process.sleep(100)

      updated_incident = Repo.get(Incident, incident.id)
      assert updated_incident.alert_sent == true
    end
  end

  describe "alert throttling" do
    test "does not re-send alert for already alerted incident", %{integration: integration} do
      # Create incident and mark as alerted
      {:ok, incident} = Incident.create_or_update(integration.id, :connection_failure, %{
        severity: "critical",
        error_message: "Connection lost",
        alert_sent: true,
        alert_sent_at: DateTime.utc_now()
      })

      # Try to send alert again
      initial_alert_time = incident.alert_sent_at
      HealthAlerter.send_alert(incident.id)

      Process.sleep(100)

      # Verify alert time didn't change
      updated_incident = Repo.get(Incident, incident.id)
      assert DateTime.compare(updated_incident.alert_sent_at, initial_alert_time) == :eq
    end
  end

  describe "metric monitoring" do
    test "detects connection failures from metrics", %{integration: integration} do
      metrics = %{
        status: "disconnected",
        error_message: "Connection timeout"
      }

      HealthMonitor.update_health(integration.id, metrics)

      # Wait for incident creation and alert processing
      Process.sleep(200)

      incidents = Incident.list_open(integration.id)
      connection_incidents = Enum.filter(incidents, & &1.incident_type == "connection_failure")

      assert length(connection_incidents) > 0
    end

    test "detects high error rates from metrics", %{integration: integration} do
      metrics = %{
        errors_per_minute: 12.0,
        total_requests: 100,
        total_errors: 12
      }

      HealthMonitor.update_health(integration.id, metrics)

      Process.sleep(200)

      incidents = Incident.list_open(integration.id)
      error_rate_incidents = Enum.filter(incidents, & &1.incident_type == "high_error_rate")

      assert length(error_rate_incidents) > 0
    end

    test "auto-resolves incidents when health improves", %{integration: integration} do
      # Create incident
      {:ok, incident} = Incident.create_or_update(integration.id, :connection_failure, %{
        severity: "critical",
        error_message: "Connection lost"
      })

      # Update metrics to show connection restored
      metrics = %{
        status: "connected",
        last_health_check_success: true
      }

      HealthMonitor.update_health(integration.id, metrics)

      Process.sleep(200)

      # Verify incident was auto-resolved
      updated_incident = Repo.get(Incident, incident.id)
      assert updated_incident.status == "resolved"
      assert updated_incident.resolved_at != nil
    end
  end

  describe "alert message formatting" do
    test "builds comprehensive alert messages", %{integration: integration} do
      {:ok, incident} = Incident.create_or_update(integration.id, :connection_failure, %{
        severity: "critical",
        error_message: "Connection timeout after 30s"
      })

      # The alert message is built internally
      # We can verify the incident has all necessary data
      assert incident.integration_id == integration.id
      assert incident.incident_type == "connection_failure"
      assert incident.severity == "critical"
      assert incident.error_message == "Connection timeout after 30s"
      assert incident.started_at != nil
    end
  end

  describe "PubSub broadcasting" do
    test "broadcasts health alerts", %{integration: integration} do
      # Subscribe to health alerts
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "integration_health")

      {:ok, incident} = Incident.create_or_update(integration.id, :connection_failure, %{
        severity: "critical",
        error_message: "Connection lost"
      })

      HealthAlerter.send_alert(incident.id)

      # Should receive broadcast
      assert_receive {:health_alert, _, _}, 500
    end

    test "broadcasts to integration-specific channel", %{integration: integration} do
      # Subscribe to integration-specific channel
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "integration_health:#{integration.id}")

      {:ok, incident} = Incident.create_or_update(integration.id, :connection_failure, %{
        severity: "critical",
        error_message: "Connection lost"
      })

      HealthAlerter.send_alert(incident.id)

      # Should receive broadcast
      assert_receive {:health_alert, _}, 500
    end
  end
end
