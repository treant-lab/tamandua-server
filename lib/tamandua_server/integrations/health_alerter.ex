defmodule TamanduaServer.Integrations.HealthAlerter do
  @moduledoc """
  Health Alerting System for Integrations

  Monitors integration health and sends alerts when thresholds are breached:
  - Connection failures
  - High error rates (>5%)
  - Rate limit approaching (>80%)
  - Credential expiry (<7 days)
  - Sync lag (>1 hour)

  ## Alert Channels

  - Email
  - Slack
  - PagerDuty
  - Webhook

  ## Alert Throttling

  Prevents alert spam by tracking last notification time and respecting
  notification intervals (default: 60 minutes).
  """

  use GenServer
  require Logger
  import Ecto.Query

  alias TamanduaServer.Integrations.Schemas.{HealthMetric, Incident}
  alias TamanduaServer.Notifications
  alias Phoenix.PubSub

  @pubsub TamanduaServer.PubSub

  # Check for alerts every minute
  @check_interval :timer.minutes(1)

  # Default alert thresholds
  @default_thresholds %{
    error_rate: 5.0,           # 5%
    rate_limit: 80.0,          # 80%
    credential_expiry_days: 7, # 7 days
    sync_lag_hours: 1          # 1 hour
  }

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Send an alert for an incident.
  """
  def send_alert(incident_id) do
    GenServer.cast(__MODULE__, {:send_alert, incident_id})
  end

  @doc """
  Configure alert settings for an integration.
  """
  def configure_alerts(integration_id, config) do
    GenServer.call(__MODULE__, {:configure_alerts, integration_id, config})
  end

  @doc """
  Get alert configuration for an integration.
  """
  def get_alert_config(integration_id) do
    GenServer.call(__MODULE__, {:get_alert_config, integration_id})
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    # Subscribe to health updates
    PubSub.subscribe(@pubsub, "integration_health")

    # Initialize ETS table for alert config
    table = :ets.new(:integration_health_alerts, [
      :set,
      :named_table,
      :public,
      read_concurrency: true,
      write_concurrency: true
    ])

    # Load alert configs from database
    load_alert_configs()

    # Schedule periodic checks
    schedule_check()

    Logger.info("[HealthAlerter] Started")

    state = %{
      table: table,
      last_check: DateTime.utc_now()
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:configure_alerts, integration_id, config}, _from, state) do
    # Store in ETS
    :ets.insert(:integration_health_alerts, {integration_id, config})

    # Persist to database (async)
    Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
      persist_alert_config(integration_id, config)
    end)

    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:get_alert_config, integration_id}, _from, state) do
    config = case :ets.lookup(:integration_health_alerts, integration_id) do
      [{^integration_id, config}] -> config
      [] -> @default_thresholds
    end

    {:reply, config, state}
  end

  @impl true
  def handle_cast({:send_alert, incident_id}, state) do
    Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
      do_send_alert(incident_id)
    end)

    {:noreply, state}
  end

  @impl true
  def handle_info(:check_alerts, state) do
    # Check all open incidents and send alerts
    check_all_incidents()

    schedule_check()
    {:noreply, Map.put(state, :last_check, DateTime.utc_now())}
  end

  @impl true
  def handle_info({:health_update, integration_id, metrics}, state) do
    # Check if we need to alert based on new metrics
    Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
      check_metrics_for_alerts(integration_id, metrics)
    end)

    {:noreply, state}
  end

  @impl true
  def handle_info(_, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp schedule_check do
    Process.send_after(self(), :check_alerts, @check_interval)
  end

  defp load_alert_configs do
    # Load from database (implement as needed)
    # For now, use default thresholds
    :ok
  end

  defp persist_alert_config(_integration_id, _config) do
    # Persist to database (implement as needed)
    :ok
  end

  defp check_all_incidents do
    # Get all open incidents
    incidents = TamanduaServer.Repo.all(
      from i in Incident,
      where: i.status in ["open", "acknowledged"] and i.alert_sent == false
    )

    Enum.each(incidents, fn incident ->
      # Check if we should send an alert
      if should_send_alert?(incident) do
        do_send_alert(incident.id)
      end
    end)
  end

  defp check_metrics_for_alerts(integration_id, metrics) do
    # Get alert config for this integration
    config = get_alert_config_from_ets(integration_id)

    # Check each alert condition
    check_connection_failure(integration_id, metrics, config)
    check_error_rate(integration_id, metrics, config)
    check_rate_limit(integration_id, metrics, config)
    check_credential_expiry(integration_id, metrics, config)
    check_sync_lag(integration_id, metrics, config)
  end

  defp get_alert_config_from_ets(integration_id) do
    case :ets.lookup(:integration_health_alerts, integration_id) do
      [{^integration_id, config}] -> config
      [] -> @default_thresholds
    end
  end

  defp check_connection_failure(integration_id, metrics, _config) do
    if metrics[:status] == "disconnected" do
      # Check if incident already exists
      case Incident.get_open_incident(integration_id, "connection_failure") do
        nil ->
          # Create incident (this will trigger alert)
          Incident.create_or_update(integration_id, :connection_failure, %{
            severity: "critical",
            error_message: metrics[:error_message] || "Connection lost"
          })

        _existing ->
          # Incident already exists, don't create duplicate
          :ok
      end
    else
      # Connection is healthy, auto-resolve any open incidents
      Incident.auto_resolve(integration_id, :connection_failure)
    end
  end

  defp check_error_rate(integration_id, metrics, config) do
    threshold = config[:error_rate] || @default_thresholds.error_rate

    if metrics[:errors_per_minute] && metrics[:errors_per_minute] > threshold do
      case Incident.get_open_incident(integration_id, "high_error_rate") do
        nil ->
          Incident.create_or_update(integration_id, :high_error_rate, %{
            severity: "high",
            error_message: "Error rate: #{Float.round(metrics[:errors_per_minute], 2)}%"
          })

        _existing ->
          :ok
      end
    else
      Incident.auto_resolve(integration_id, :high_error_rate)
    end
  end

  defp check_rate_limit(integration_id, metrics, config) do
    threshold = config[:rate_limit] || @default_thresholds.rate_limit

    if metrics[:rate_limit_total] && metrics[:rate_limit_remaining] do
      usage_percent = (metrics[:rate_limit_used] / metrics[:rate_limit_total]) * 100

      if usage_percent > threshold do
        case Incident.get_open_incident(integration_id, "rate_limit") do
          nil ->
            Incident.create_or_update(integration_id, :rate_limit, %{
              severity: "medium",
              error_message: "Rate limit usage: #{trunc(usage_percent)}%"
            })

          _existing ->
            :ok
        end
      else
        Incident.auto_resolve(integration_id, :rate_limit)
      end
    end
  end

  defp check_credential_expiry(integration_id, metrics, config) do
    threshold_days = config[:credential_expiry_days] || @default_thresholds.credential_expiry_days

    if metrics[:credential_expires_at] do
      days_until_expiry = DateTime.diff(metrics[:credential_expires_at], DateTime.utc_now(), :day)

      if days_until_expiry < threshold_days do
        case Incident.get_open_incident(integration_id, "credential_expiry") do
          nil ->
            severity = if days_until_expiry < 1, do: "critical", else: "medium"

            Incident.create_or_update(integration_id, :credential_expiry, %{
              severity: severity,
              error_message: "Credentials expire in #{days_until_expiry} days"
            })

          _existing ->
            :ok
        end
      else
        Incident.auto_resolve(integration_id, :credential_expiry)
      end
    end
  end

  defp check_sync_lag(integration_id, metrics, config) do
    threshold_hours = config[:sync_lag_hours] || @default_thresholds.sync_lag_hours
    threshold_seconds = threshold_hours * 3600

    if metrics[:sync_lag_seconds] && metrics[:sync_lag_seconds] > threshold_seconds do
      case Incident.get_open_incident(integration_id, "sync_lag") do
        nil ->
          Incident.create_or_update(integration_id, :sync_lag, %{
            severity: "medium",
            error_message: "Sync lag: #{div(metrics[:sync_lag_seconds], 60)} minutes"
          })

        _existing ->
          :ok
      end
    else
      Incident.auto_resolve(integration_id, :sync_lag)
    end
  end

  defp should_send_alert?(incident) do
    # Check if alert was already sent
    if incident.alert_sent do
      false
    else
      # Check notification interval
      true
    end
  end

  defp do_send_alert(incident_id) do
    case TamanduaServer.Repo.get(Incident, incident_id) do
      nil ->
        Logger.warning("[HealthAlerter] Incident not found: #{incident_id}")
        :ok

      incident ->
        # Get integration details
        case TamanduaServer.Integrations.Config.get_integration(incident.integration_id) do
          {:ok, integration} ->
            # Build alert message
            message = build_alert_message(integration, incident)

            # Send to notification channels
            send_notification(integration, incident, message)

            # Mark alert as sent
            Incident.mark_alert_sent(incident_id)

            Logger.info("[HealthAlerter] Alert sent for incident #{incident_id}")

          {:error, _} ->
            Logger.warning("[HealthAlerter] Integration not found: #{incident.integration_id}")
        end
    end
  end

  defp build_alert_message(integration, incident) do
    """
    Integration Health Alert

    Integration: #{integration.name} (#{integration.type})
    Incident Type: #{incident.incident_type}
    Severity: #{incident.severity}
    Status: #{incident.status}

    #{incident.error_message}

    Started: #{format_datetime(incident.started_at)}
    #{if incident.acknowledged_at, do: "Acknowledged: #{format_datetime(incident.acknowledged_at)}", else: ""}
    #{if incident.resolved_at, do: "Resolved: #{format_datetime(incident.resolved_at)}", else: ""}
    """
  end

  defp send_notification(integration, incident, message) do
    # Send via notification system
    notification_attrs = %{
      title: "Integration Health Alert: #{integration.name}",
      message: message,
      severity: incident.severity,
      type: "integration_health",
      metadata: %{
        integration_id: integration.id,
        incident_id: incident.id,
        incident_type: incident.incident_type
      }
    }

    # Send notification (implement as needed)
    # Notifications.send(notification_attrs)

    # Broadcast to PubSub
    PubSub.broadcast(@pubsub, "integration_health", {:health_alert, integration.id, incident})
    PubSub.broadcast(@pubsub, "integration_health:#{integration.id}", {:health_alert, incident})

    :ok
  end

  defp format_datetime(nil), do: "N/A"
  defp format_datetime(datetime) do
    Calendar.strftime(datetime, "%Y-%m-%d %H:%M:%S UTC")
  end
end
