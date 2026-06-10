defmodule TamanduaServer.Integrations.HealthMonitor do
  @moduledoc """
  Integration Health Monitoring System

  Tracks health metrics for all integrations:
  - Connection status (connected, disconnected, degraded)
  - API rate limits and usage
  - Error rates and latency
  - Sync status and lag
  - Credential expiry
  - Uptime and SLA compliance

  ## Metrics Tracked

  - **Connection Status**: Current connection state and last connected/disconnected times
  - **Rate Limits**: API rate limit tracking (used/remaining/reset time)
  - **Error Rates**: 4xx/5xx errors per minute, total errors
  - **Latency**: Average, P50, P95, P99 response times
  - **Sync Status**: Last sync time, sync lag, pending items
  - **Credentials**: Expiry tracking and warning thresholds
  - **Uptime**: Daily uptime percentage and SLA compliance
  """

  use GenServer
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Integrations.{Config, HealthCheck}
  alias TamanduaServer.Integrations.Schemas.{HealthMetric, UptimeRecord, Incident}
  alias Phoenix.PubSub

  @pubsub TamanduaServer.PubSub

  # Refresh metrics every 30 seconds
  @refresh_interval :timer.seconds(30)

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Get current health metrics for an integration.
  """
  def get_health(integration_id) do
    GenServer.call(__MODULE__, {:get_health, integration_id})
  end

  @doc """
  Get health metrics for all integrations.
  """
  def list_health do
    GenServer.call(__MODULE__, :list_health)
  end

  @doc """
  Update health metrics for an integration.
  """
  def update_health(integration_id, metrics) do
    GenServer.cast(__MODULE__, {:update_health, integration_id, metrics})
  end

  @doc """
  Record an API request for metrics tracking.
  """
  def record_request(integration_id, opts \\ []) do
    GenServer.cast(__MODULE__, {:record_request, integration_id, opts})
  end

  @doc """
  Get uptime statistics for an integration.
  """
  def get_uptime_stats(integration_id, opts \\ []) do
    GenServer.call(__MODULE__, {:get_uptime_stats, integration_id, opts})
  end

  @doc """
  Get recent incidents for an integration.
  """
  def get_incidents(integration_id, opts \\ []) do
    GenServer.call(__MODULE__, {:get_incidents, integration_id, opts})
  end

  @doc """
  Get health summary for dashboard.
  """
  def get_summary do
    GenServer.call(__MODULE__, :get_summary)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    # Initialize ETS table for fast in-memory metrics access
    table = :ets.new(:integration_health_metrics, [
      :set,
      :named_table,
      :public,
      read_concurrency: true,
      write_concurrency: true
    ])

    # Initialize request tracking table (for rate calculation)
    request_table = :ets.new(:integration_requests, [
      :bag,
      :named_table,
      :public,
      read_concurrency: true,
      write_concurrency: true
    ])

    # Schedule periodic tasks
    schedule_refresh()
    schedule_uptime_calculation()
    schedule_cleanup()

    Logger.info("[HealthMonitor] Started")

    state = %{
      table: table,
      request_table: request_table,
      last_refresh: DateTime.utc_now()
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:get_health, integration_id}, _from, state) do
    metrics = case :ets.lookup(:integration_health_metrics, integration_id) do
      [{^integration_id, metrics}] -> metrics
      [] -> load_health_from_db(integration_id)
    end

    {:reply, metrics, state}
  end

  @impl true
  def handle_call(:list_health, _from, state) do
    metrics = :ets.tab2list(:integration_health_metrics)
    |> Enum.map(fn {_id, metrics} -> metrics end)

    {:reply, metrics, state}
  end

  @impl true
  def handle_call({:get_uptime_stats, integration_id, opts}, _from, state) do
    days = Keyword.get(opts, :days, 30)
    stats = UptimeRecord.get_uptime_stats(integration_id, days)
    {:reply, stats, state}
  end

  @impl true
  def handle_call({:get_incidents, integration_id, opts}, _from, state) do
    limit = Keyword.get(opts, :limit, 50)
    incidents = Incident.list_recent(integration_id, limit)
    {:reply, incidents, state}
  end

  @impl true
  def handle_call(:get_summary, _from, state) do
    summary = calculate_summary()
    {:reply, summary, state}
  end

  @impl true
  def handle_cast({:update_health, integration_id, metrics}, state) do
    # Load existing metrics
    existing = case :ets.lookup(:integration_health_metrics, integration_id) do
      [{^integration_id, m}] -> m
      [] -> %{}
    end

    # Merge metrics
    updated = Map.merge(existing, metrics)
    |> Map.put(:integration_id, integration_id)
    |> Map.put(:updated_at, DateTime.utc_now())

    # Update ETS
    :ets.insert(:integration_health_metrics, {integration_id, updated})

    # Check for incidents
    check_for_incidents(integration_id, updated)

    # Persist to database (async)
    Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
      persist_metrics(integration_id, updated)
    end)

    # Broadcast update
    PubSub.broadcast(@pubsub, "integration_health", {:health_update, integration_id, updated})
    PubSub.broadcast(@pubsub, "integration_health:#{integration_id}", {:health_update, updated})

    {:noreply, state}
  end

  @impl true
  def handle_cast({:record_request, integration_id, opts}, state) do
    timestamp = System.monotonic_time(:millisecond)

    request_data = %{
      timestamp: timestamp,
      duration_ms: Keyword.get(opts, :duration_ms),
      status_code: Keyword.get(opts, :status_code),
      success: Keyword.get(opts, :success, true),
      error_type: Keyword.get(opts, :error_type)
    }

    # Store in request tracking table (with TTL via cleanup)
    :ets.insert(:integration_requests, {integration_id, request_data})

    # Update metrics
    update_request_metrics(integration_id)

    {:noreply, state}
  end

  @impl true
  def handle_info(:refresh, state) do
    # Refresh all integration health metrics
    refresh_all_metrics()

    schedule_refresh()
    {:noreply, Map.put(state, :last_refresh, DateTime.utc_now())}
  end

  @impl true
  def handle_info(:calculate_uptime, state) do
    # Calculate daily uptime for all integrations
    calculate_daily_uptime()

    schedule_uptime_calculation()
    {:noreply, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    # Clean up old request data (keep last 5 minutes)
    cleanup_old_requests()

    schedule_cleanup()
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp schedule_refresh do
    Process.send_after(self(), :refresh, @refresh_interval)
  end

  defp schedule_uptime_calculation do
    # Calculate uptime every 5 minutes
    Process.send_after(self(), :calculate_uptime, :timer.minutes(5))
  end

  defp schedule_cleanup do
    # Cleanup old requests every minute
    Process.send_after(self(), :cleanup, :timer.minutes(1))
  end

  defp refresh_all_metrics do
    integrations = Config.list_integrations(enabled: true)

    Enum.each(integrations, fn integration ->
      # Trigger health check
      Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
        HealthCheck.perform_health_check(integration.id)
      end)
    end)
  end

  defp calculate_daily_uptime do
    integrations = Config.list_integrations()

    Enum.each(integrations, fn integration ->
      Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
        UptimeRecord.calculate_daily_uptime(integration.id)
      end)
    end)
  end

  defp cleanup_old_requests do
    cutoff = System.monotonic_time(:millisecond) - :timer.minutes(5)

    # Get all entries and filter old ones
    all_entries = :ets.tab2list(:integration_requests)

    old_entries = Enum.filter(all_entries, fn {_id, data} ->
      data.timestamp < cutoff
    end)

    # Delete old entries
    Enum.each(old_entries, fn {id, data} ->
      :ets.delete_object(:integration_requests, {id, data})
    end)
  end

  defp load_health_from_db(integration_id) do
    case HealthMetric.get_latest(integration_id) do
      nil -> %{integration_id: integration_id, status: "unknown"}
      metric -> metric
    end
  end

  defp persist_metrics(integration_id, metrics) do
    HealthMetric.create_or_update(integration_id, metrics)
  end

  defp update_request_metrics(integration_id) do
    # Get requests from last 1 minute
    now = System.monotonic_time(:millisecond)
    one_minute_ago = now - :timer.minutes(1)

    requests = :ets.lookup(:integration_requests, integration_id)
    |> Enum.map(fn {_id, data} -> data end)
    |> Enum.filter(fn data -> data.timestamp >= one_minute_ago end)

    if length(requests) > 0 do
      # Calculate metrics
      total_requests = length(requests)
      errors = Enum.count(requests, & !&1.success)
      errors_4xx = Enum.count(requests, fn r -> r.status_code in 400..499 end)
      errors_5xx = Enum.count(requests, fn r -> r.status_code in 500..599 end)

      error_rate = if total_requests > 0, do: errors / total_requests * 100, else: 0.0

      # Calculate latency percentiles
      durations = Enum.map(requests, & &1.duration_ms) |> Enum.reject(&is_nil/1) |> Enum.sort()

      latency_metrics = if length(durations) > 0 do
        %{
          latency_avg: Enum.sum(durations) / length(durations),
          latency_p50: percentile(durations, 50),
          latency_p95: percentile(durations, 95),
          latency_p99: percentile(durations, 99)
        }
      else
        %{}
      end

      # Update health metrics
      metrics = Map.merge(%{
        errors_per_minute: error_rate,
        errors_4xx_count: errors_4xx,
        errors_5xx_count: errors_5xx,
        total_errors: errors,
        total_requests: total_requests
      }, latency_metrics)

      update_health(integration_id, metrics)
    end
  end

  defp percentile(sorted_list, p) when p >= 0 and p <= 100 do
    k = (length(sorted_list) - 1) * p / 100
    f = floor(k)
    c = ceil(k)

    if f == c do
      Enum.at(sorted_list, trunc(k))
    else
      d0 = Enum.at(sorted_list, trunc(f)) * (c - k)
      d1 = Enum.at(sorted_list, trunc(c)) * (k - f)
      d0 + d1
    end
  end

  defp check_for_incidents(integration_id, metrics) do
    # Check for connection failures
    if metrics[:status] == "disconnected" do
      Incident.create_or_update(integration_id, :connection_failure, %{
        severity: "critical",
        error_message: metrics[:error_message] || "Connection lost"
      })
    end

    # Check for high error rate (>5%)
    if metrics[:errors_per_minute] && metrics[:errors_per_minute] > 5.0 do
      Incident.create_or_update(integration_id, :high_error_rate, %{
        severity: "high",
        error_message: "Error rate: #{metrics[:errors_per_minute]}%"
      })
    end

    # Check for rate limit approaching (>80%)
    if metrics[:rate_limit_total] && metrics[:rate_limit_remaining] do
      usage_percent = (metrics[:rate_limit_used] / metrics[:rate_limit_total]) * 100
      if usage_percent > 80 do
        Incident.create_or_update(integration_id, :rate_limit, %{
          severity: "medium",
          error_message: "Rate limit usage: #{trunc(usage_percent)}%"
        })
      end
    end

    # Check for credential expiry (<7 days)
    if metrics[:credential_expires_at] do
      days_until_expiry = DateTime.diff(metrics[:credential_expires_at], DateTime.utc_now(), :day)
      if days_until_expiry < 7 do
        Incident.create_or_update(integration_id, :credential_expiry, %{
          severity: if(days_until_expiry < 1, do: "critical", else: "medium"),
          error_message: "Credentials expire in #{days_until_expiry} days"
        })
      end
    end

    # Check for sync lag (>1 hour)
    if metrics[:sync_lag_seconds] && metrics[:sync_lag_seconds] > 3600 do
      Incident.create_or_update(integration_id, :sync_lag, %{
        severity: "medium",
        error_message: "Sync lag: #{div(metrics[:sync_lag_seconds], 60)} minutes"
      })
    end
  end

  defp calculate_summary do
    metrics = :ets.tab2list(:integration_health_metrics)
    |> Enum.map(fn {_id, m} -> m end)

    total = length(metrics)
    connected = Enum.count(metrics, fn m -> m[:status] == "connected" end)
    degraded = Enum.count(metrics, fn m -> m[:status] == "degraded" end)
    disconnected = Enum.count(metrics, fn m -> m[:status] == "disconnected" end)

    avg_error_rate = if total > 0 do
      Enum.map(metrics, & &1[:errors_per_minute] || 0.0)
      |> Enum.sum()
      |> Kernel./(total)
    else
      0.0
    end

    %{
      total: total,
      connected: connected,
      degraded: degraded,
      disconnected: disconnected,
      avg_error_rate: avg_error_rate,
      health_score: calculate_overall_health_score(metrics)
    }
  end

  defp calculate_overall_health_score(metrics) do
    if length(metrics) == 0, do: 100, else:
      Enum.map(metrics, fn m ->
        score = 100

        # Penalize for disconnected status
        score = if m[:status] == "disconnected", do: score - 50, else: score
        score = if m[:status] == "degraded", do: score - 20, else: score

        # Penalize for high error rate
        error_rate = m[:errors_per_minute] || 0.0
        score = score - min(error_rate * 2, 30)

        # Penalize for high latency
        if m[:latency_avg] && m[:latency_avg] > 1000 do
          score = score - 10
        end

        max(score, 0)
      end)
      |> Enum.sum()
      |> Kernel./(length(metrics))
      |> trunc()
  end
end
