defmodule TamanduaServer.ThreatIntel.FeedHealthMonitor do
  @moduledoc """
  Feed Health Monitoring System.

  Monitors health and performance of all threat intelligence feeds:
  - Connectivity checks (every 5 minutes)
  - Data freshness tracking
  - Error rate monitoring
  - API quota usage tracking
  - Automatic alerting on feed degradation
  - Historical health metrics

  ## Health Metrics

  - **status**: :healthy, :degraded, :failed, :disabled
  - **connectivity**: Last successful API call timestamp
  - **freshness**: Age of most recent IOC import
  - **error_rate**: Errors per hour
  - **response_time**: Average API response time
  - **quota_usage**: API calls vs quota limits

  ## Usage

      # Get overall feed health
      FeedHealthMonitor.get_overall_health()

      # Get specific feed health
      FeedHealthMonitor.get_feed_health("recorded_future")

      # Force health check
      FeedHealthMonitor.check_all_feeds()
  """

  use GenServer
  require Logger

  alias TamanduaServer.Alerts

  @check_interval :timer.minutes(5)
  @freshness_warning_threshold :timer.hours(24)
  @freshness_critical_threshold :timer.hours(48)
  @error_rate_warning_threshold 10  # errors per hour
  @error_rate_critical_threshold 30

  # Feed modules to monitor
  @feeds [
    {"recorded_future", TamanduaServer.ThreatIntel.Feeds.RecordedFuture},
    {"crowdstrike", TamanduaServer.ThreatIntel.Feeds.CrowdStrikeIntel},
    {"palo_alto_autofocus", TamanduaServer.ThreatIntel.Feeds.PaloAltoAutoFocus},
    {"cisco_talos", TamanduaServer.ThreatIntel.Feeds.CiscoTalos},
    {"ibm_xforce", TamanduaServer.ThreatIntel.Feeds.IBMXForce},
    {"anomali", TamanduaServer.ThreatIntel.Feeds.Anomali},
    {"mandiant", TamanduaServer.ThreatIntel.Feeds.Mandiant},
    {"proofpoint", TamanduaServer.ThreatIntel.Feeds.Proofpoint},
    {"emerging_threats", TamanduaServer.ThreatIntel.Feeds.EmergingThreats},
    {"greynoise", TamanduaServer.ThreatIntel.Feeds.GreyNoise}
  ]

  @ets_table :feed_health_metrics

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Get overall feed health summary.
  """
  @spec get_overall_health() :: map()
  def get_overall_health do
    GenServer.call(__MODULE__, :get_overall_health)
  end

  @doc """
  Get health status for specific feed.
  """
  @spec get_feed_health(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_feed_health(feed_name) do
    GenServer.call(__MODULE__, {:get_feed_health, feed_name})
  end

  @doc """
  Get historical health metrics for feed.
  """
  @spec get_feed_history(String.t(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def get_feed_history(feed_name, opts \\ []) do
    GenServer.call(__MODULE__, {:get_feed_history, feed_name, opts})
  end

  @doc """
  Record an API call for a feed.
  """
  @spec record_api_call(String.t(), atom(), integer()) :: :ok
  def record_api_call(feed_name, status, response_time_ms) do
    GenServer.cast(__MODULE__, {:record_api_call, feed_name, status, response_time_ms})
  end

  @doc """
  Record an error for a feed.
  """
  @spec record_error(String.t(), term()) :: :ok
  def record_error(feed_name, error) do
    GenServer.cast(__MODULE__, {:record_error, feed_name, error})
  end

  @doc """
  Record successful IOC import.
  """
  @spec record_ioc_import(String.t(), integer()) :: :ok
  def record_ioc_import(feed_name, count) do
    GenServer.cast(__MODULE__, {:record_ioc_import, feed_name, count})
  end

  @doc """
  Force health check for all feeds.
  """
  @spec check_all_feeds() :: :ok
  def check_all_feeds do
    GenServer.cast(__MODULE__, :check_all_feeds)
  end

  @doc """
  Get feed degradation alerts.
  """
  @spec get_active_alerts() :: [map()]
  def get_active_alerts do
    GenServer.call(__MODULE__, :get_active_alerts)
  end

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  @impl true
  def init(_opts) do
    # Create ETS table for metrics
    :ets.new(@ets_table, [:named_table, :set, :public, read_concurrency: true])

    # Initialize health state for each feed
    Enum.each(@feeds, fn {feed_name, _module} ->
      :ets.insert(@ets_table, {feed_name, initial_health_state()})
    end)

    # Schedule periodic health checks
    schedule_health_check()

    Logger.info("[FeedHealthMonitor] Initialized monitoring for #{length(@feeds)} feeds")

    state = %{
      active_alerts: %{},
      last_check: nil,
      check_count: 0
    }

    {:ok, state}
  end

  @impl true
  def handle_call(:get_overall_health, _from, state) do
    health_summary = build_overall_health_summary()
    {:reply, health_summary, state}
  end

  @impl true
  def handle_call({:get_feed_health, feed_name}, _from, state) do
    case :ets.lookup(@ets_table, feed_name) do
      [{^feed_name, health}] ->
        {:reply, {:ok, health}, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:get_feed_history, feed_name, _opts}, _from, state) do
    # In production, fetch from TimescaleDB or similar time-series database
    # For now, return current state
    case :ets.lookup(@ets_table, feed_name) do
      [{^feed_name, health}] ->
        {:reply, {:ok, [health]}, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call(:get_active_alerts, _from, state) do
    alerts = Map.values(state.active_alerts)
    {:reply, alerts, state}
  end

  @impl true
  def handle_cast({:record_api_call, feed_name, status, response_time_ms}, state) do
    case :ets.lookup(@ets_table, feed_name) do
      [{^feed_name, health}] ->
        updated_health = %{health |
          last_api_call: DateTime.utc_now(),
          total_api_calls: health.total_api_calls + 1,
          successful_api_calls: health.successful_api_calls + (if status == :ok, do: 1, else: 0),
          avg_response_time_ms: calculate_avg_response_time(health, response_time_ms)
        }

        :ets.insert(@ets_table, {feed_name, updated_health})

      [] ->
        :ok
    end

    {:noreply, state}
  end

  @impl true
  def handle_cast({:record_error, feed_name, error}, state) do
    case :ets.lookup(@ets_table, feed_name) do
      [{^feed_name, health}] ->
        updated_health = %{health |
          last_error: DateTime.utc_now(),
          last_error_message: inspect(error),
          total_errors: health.total_errors + 1,
          errors_last_hour: health.errors_last_hour + 1
        }

        :ets.insert(@ets_table, {feed_name, updated_health})

        # Check if error rate exceeds thresholds
        new_state = check_error_rate_alert(feed_name, updated_health, state)
        {:noreply, new_state}

      [] ->
        {:noreply, state}
    end
  end

  @impl true
  def handle_cast({:record_ioc_import, feed_name, count}, state) do
    case :ets.lookup(@ets_table, feed_name) do
      [{^feed_name, health}] ->
        updated_health = %{health |
          last_ioc_import: DateTime.utc_now(),
          total_iocs_imported: health.total_iocs_imported + count
        }

        :ets.insert(@ets_table, {feed_name, updated_health})

      [] ->
        :ok
    end

    {:noreply, state}
  end

  @impl true
  def handle_cast(:check_all_feeds, state) do
    new_state = perform_health_checks(state)
    {:noreply, new_state}
  end

  @impl true
  def handle_info(:health_check, state) do
    new_state = perform_health_checks(state)
    schedule_health_check()
    {:noreply, %{new_state | last_check: DateTime.utc_now(), check_count: state.check_count + 1}}
  end

  @impl true
  def handle_info(:reset_hourly_errors, state) do
    # Reset hourly error counters
    Enum.each(@feeds, fn {feed_name, _module} ->
      case :ets.lookup(@ets_table, feed_name) do
        [{^feed_name, health}] ->
          :ets.insert(@ets_table, {feed_name, %{health | errors_last_hour: 0}})

        [] ->
          :ok
      end
    end)

    schedule_hourly_reset()
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions - Health Checks
  # ============================================================================

  defp perform_health_checks(state) do
    Logger.debug("[FeedHealthMonitor] Running health checks for all feeds...")

    new_state = Enum.reduce(@feeds, state, fn {feed_name, module}, acc_state ->
      health = check_feed_health(feed_name, module)
      :ets.insert(@ets_table, {feed_name, health})

      # Update alerts based on health status
      update_alerts(feed_name, health, acc_state)
    end)

    new_state
  end

  defp check_feed_health(feed_name, module) do
    # Get current health state
    [{^feed_name, current_health}] = :ets.lookup(@ets_table, feed_name)

    # Check connectivity
    connectivity_status = check_connectivity(module)

    # Determine overall status
    status = determine_overall_status(current_health, connectivity_status)

    %{current_health |
      status: status,
      connectivity: connectivity_status,
      last_health_check: DateTime.utc_now()
    }
  end

  defp check_connectivity(module) do
    try do
      case apply(module, :get_status, []) do
        %{configured: true, enabled: true} ->
          :healthy

        %{configured: false} ->
          :not_configured

        %{enabled: false} ->
          :disabled

        _ ->
          :unknown
      end
    rescue
      _ -> :failed
    catch
      _ -> :failed
    end
  end

  defp determine_overall_status(health, connectivity) do
    cond do
      connectivity in [:failed, :not_configured] ->
        :failed

      connectivity == :disabled ->
        :disabled

      health.errors_last_hour >= @error_rate_critical_threshold ->
        :critical

      is_feed_stale?(health, @freshness_critical_threshold) ->
        :critical

      health.errors_last_hour >= @error_rate_warning_threshold ->
        :degraded

      is_feed_stale?(health, @freshness_warning_threshold) ->
        :degraded

      true ->
        :healthy
    end
  end

  defp is_feed_stale?(health, threshold) do
    if health.last_ioc_import do
      age_ms = DateTime.diff(DateTime.utc_now(), health.last_ioc_import, :millisecond)
      age_ms > threshold
    else
      # No imports yet
      false
    end
  end

  # ============================================================================
  # Private Functions - Alerting
  # ============================================================================

  defp update_alerts(feed_name, health, state) do
    alert_key = "feed_health_#{feed_name}"

    case health.status do
      status when status in [:critical, :degraded] ->
        # Create or update alert
        if Map.has_key?(state.active_alerts, alert_key) do
          state
        else
          alert = create_feed_alert(feed_name, health)
          %{state | active_alerts: Map.put(state.active_alerts, alert_key, alert)}
        end

      :healthy ->
        # Clear alert if exists
        if Map.has_key?(state.active_alerts, alert_key) do
          clear_feed_alert(alert_key)
          %{state | active_alerts: Map.delete(state.active_alerts, alert_key)}
        else
          state
        end

      _ ->
        state
    end
  end

  defp create_feed_alert(feed_name, health) do
    severity = if health.status == :critical, do: "critical", else: "high"

    description = build_alert_description(feed_name, health)

    alert_data = %{
      alert_type: "feed_health_degradation",
      severity: severity,
      title: "Threat Feed Health Degradation: #{feed_name}",
      description: description,
      metadata: %{
        feed_name: feed_name,
        status: health.status,
        errors_last_hour: health.errors_last_hour,
        last_error: health.last_error_message,
        data_freshness_hours: calculate_freshness_hours(health)
      }
    }

    # Create alert in system. create_alert/1 can return {:error, {:suppressed, _}}
    # (operators often suppress repetitive feed-health alerts) or {:error, changeset};
    # degrade to nil instead of crashing the periodic health-check GenServer.
    case Alerts.create_alert(alert_data) do
      {:ok, alert} ->
        Logger.warning("[FeedHealthMonitor] Alert created for #{feed_name}: #{health.status}")
        alert

      {:error, reason} ->
        Logger.warning(
          "[FeedHealthMonitor] Feed alert for #{feed_name} not created: #{inspect(reason)}"
        )
        nil
    end
  end

  defp clear_feed_alert(alert_key) do
    Logger.info("[FeedHealthMonitor] Clearing alert: #{alert_key}")
    # Mark alert as resolved
    # In production, call Alerts.resolve_alert/1
  end

  defp build_alert_description(feed_name, health) do
    reasons = []

    reasons = if health.errors_last_hour >= @error_rate_critical_threshold do
      ["Critical error rate: #{health.errors_last_hour} errors/hour" | reasons]
    else
      reasons
    end

    reasons = if health.errors_last_hour >= @error_rate_warning_threshold do
      ["Elevated error rate: #{health.errors_last_hour} errors/hour" | reasons]
    else
      reasons
    end

    reasons = if is_feed_stale?(health, @freshness_critical_threshold) do
      hours = calculate_freshness_hours(health)
      ["Data critically stale: #{hours} hours since last import" | reasons]
    else
      reasons
    end

    reasons = if is_feed_stale?(health, @freshness_warning_threshold) do
      hours = calculate_freshness_hours(health)
      ["Data freshness warning: #{hours} hours since last import" | reasons]
    else
      reasons
    end

    if health.last_error_message do
      reasons = ["Last error: #{health.last_error_message}" | reasons]
    end

    """
    Threat intelligence feed '#{feed_name}' is experiencing issues:

    #{Enum.join(reasons, "\n")}

    This may impact detection capabilities. Review feed configuration and connectivity.
    """
  end

  defp check_error_rate_alert(feed_name, health, state) do
    if health.errors_last_hour >= @error_rate_warning_threshold do
      update_alerts(feed_name, health, state)
    else
      state
    end
  end

  # ============================================================================
  # Private Functions - Metrics
  # ============================================================================

  defp build_overall_health_summary do
    all_feeds = Enum.map(@feeds, fn {feed_name, _module} ->
      [{^feed_name, health}] = :ets.lookup(@ets_table, feed_name)
      {feed_name, health}
    end)

    status_counts = Enum.reduce(all_feeds, %{}, fn {_name, health}, acc ->
      Map.update(acc, health.status, 1, &(&1 + 1))
    end)

    total_feeds = length(all_feeds)
    healthy_feeds = Map.get(status_counts, :healthy, 0)
    degraded_feeds = Map.get(status_counts, :degraded, 0)
    critical_feeds = Map.get(status_counts, :critical, 0)
    failed_feeds = Map.get(status_counts, :failed, 0)

    overall_status = cond do
      critical_feeds > 0 or failed_feeds > 0 -> :critical
      degraded_feeds > 0 -> :degraded
      healthy_feeds == total_feeds -> :healthy
      true -> :unknown
    end

    %{
      overall_status: overall_status,
      total_feeds: total_feeds,
      healthy: healthy_feeds,
      degraded: degraded_feeds,
      critical: critical_feeds,
      failed: failed_feeds,
      feeds: Map.new(all_feeds)
    }
  end

  defp calculate_avg_response_time(health, new_response_time) do
    if health.total_api_calls == 0 do
      new_response_time
    else
      # Running average
      current_avg = health.avg_response_time_ms || 0
      total = health.total_api_calls
      (current_avg * total + new_response_time) / (total + 1)
    end
  end

  defp calculate_freshness_hours(health) do
    if health.last_ioc_import do
      DateTime.diff(DateTime.utc_now(), health.last_ioc_import, :second) / 3600
      |> Float.round(1)
    else
      nil
    end
  end

  defp initial_health_state do
    %{
      status: :unknown,
      connectivity: :unknown,
      last_health_check: nil,
      last_api_call: nil,
      last_ioc_import: nil,
      last_error: nil,
      last_error_message: nil,
      total_api_calls: 0,
      successful_api_calls: 0,
      total_errors: 0,
      errors_last_hour: 0,
      total_iocs_imported: 0,
      avg_response_time_ms: 0
    }
  end

  defp schedule_health_check do
    Process.send_after(self(), :health_check, @check_interval)
  end

  defp schedule_hourly_reset do
    Process.send_after(self(), :reset_hourly_errors, :timer.hours(1))
  end
end
