defmodule TamanduaServer.Webhooks.HealthMonitor do
  @moduledoc """
  Webhook health monitoring and alerting.

  Features:
  - Real-time health status tracking
  - Automatic health alerts when error rate exceeds threshold
  - Circuit breaker pattern
  - Performance metrics (response time, success rate)
  - Health dashboard data aggregation
  """

  use GenServer
  require Logger

  alias TamanduaServer.{Repo, Webhooks}
  alias TamanduaServer.Webhooks.Webhook

  @health_check_interval :timer.minutes(5)

  ## Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Records a webhook delivery result for health tracking.
  """
  def record_delivery(webhook_id, success?, response_time_ms, status_code) do
    GenServer.cast(__MODULE__, {:record_delivery, webhook_id, success?, response_time_ms, status_code})
  end

  @doc """
  Gets health metrics for a webhook.
  """
  def get_health_metrics(webhook_id) do
    GenServer.call(__MODULE__, {:get_health_metrics, webhook_id})
  end

  @doc """
  Gets health status for all webhooks in an organization.
  """
  def get_organization_health(organization_id) do
    GenServer.call(__MODULE__, {:get_organization_health, organization_id})
  end

  ## Server Callbacks

  @impl true
  def init(_opts) do
    schedule_health_check()

    state = %{
      metrics_buffer: %{},  # webhook_id => [delivery_results]
      last_check: DateTime.utc_now()
    }

    {:ok, state}
  end

  @impl true
  def handle_cast({:record_delivery, webhook_id, success?, response_time_ms, status_code}, state) do
    delivery_result = %{
      success: success?,
      response_time_ms: response_time_ms,
      status_code: status_code,
      timestamp: DateTime.utc_now()
    }

    metrics_buffer =
      Map.update(
        state.metrics_buffer,
        webhook_id,
        [delivery_result],
        fn results -> [delivery_result | Enum.take(results, 99)] end
      )

    {:noreply, %{state | metrics_buffer: metrics_buffer}}
  end

  @impl true
  def handle_call({:get_health_metrics, webhook_id}, _from, state) do
    metrics = calculate_metrics(Map.get(state.metrics_buffer, webhook_id, []))
    {:reply, metrics, state}
  end

  @impl true
  def handle_call({:get_organization_health, organization_id}, _from, state) do
    webhooks = Webhooks.list_webhooks(organization_id)

    health_data =
      Enum.map(webhooks, fn webhook ->
        metrics = calculate_metrics(Map.get(state.metrics_buffer, webhook.id, []))

        %{
          webhook_id: webhook.id,
          webhook_name: webhook.name,
          health_status: webhook.health_status,
          metrics: metrics,
          last_delivery: webhook.last_delivery_at,
          consecutive_failures: webhook.consecutive_failures
        }
      end)

    {:reply, health_data, state}
  end

  @impl true
  def handle_info(:health_check, state) do
    Logger.info("[WebhookHealthMonitor] Running periodic health check")

    # Flush buffered metrics to database
    flush_metrics_to_database(state.metrics_buffer)

    # Check webhook health and update status
    check_all_webhooks_health()

    # Send health alerts if needed
    send_health_alerts()

    schedule_health_check()

    {:noreply, %{state | metrics_buffer: %{}, last_check: DateTime.utc_now()}}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  ## Private Functions

  defp schedule_health_check do
    Process.send_after(self(), :health_check, @health_check_interval)
  end

  defp calculate_metrics([]), do: default_metrics()

  defp calculate_metrics(results) do
    total = length(results)
    successes = Enum.count(results, & &1.success)
    failures = total - successes

    response_times = Enum.map(results, & &1.response_time_ms)
    avg_response_time = Enum.sum(response_times) / max(total, 1)

    sorted_times = Enum.sort(response_times)
    p95_index = trunc(total * 0.95)
    p99_index = trunc(total * 0.99)
    p95_response_time = Enum.at(sorted_times, p95_index, 0)
    p99_response_time = Enum.at(sorted_times, p99_index, 0)

    error_rate = if total > 0, do: failures / total, else: 0.0
    success_rate = if total > 0, do: successes / total, else: 0.0

    status_codes =
      results
      |> Enum.filter(& &1.status_code)
      |> Enum.frequencies_by(& &1.status_code)

    %{
      total_deliveries: total,
      successful_deliveries: successes,
      failed_deliveries: failures,
      error_rate: Float.round(error_rate * 100, 2),
      success_rate: Float.round(success_rate * 100, 2),
      avg_response_time_ms: Float.round(avg_response_time, 2),
      p95_response_time_ms: p95_response_time,
      p99_response_time_ms: p99_response_time,
      status_codes: status_codes
    }
  end

  defp default_metrics do
    %{
      total_deliveries: 0,
      successful_deliveries: 0,
      failed_deliveries: 0,
      error_rate: 0.0,
      success_rate: 0.0,
      avg_response_time_ms: 0.0,
      p95_response_time_ms: 0,
      p99_response_time_ms: 0,
      status_codes: %{}
    }
  end

  defp flush_metrics_to_database(metrics_buffer) do
    timestamp = DateTime.utc_now()

    Enum.each(metrics_buffer, fn {webhook_id, results} ->
      metrics = calculate_metrics(results)

      # Insert metrics into webhook_health_metrics table
      %{
        id: Ecto.UUID.generate(),
        webhook_id: webhook_id,
        timestamp: timestamp,
        success_count: metrics.successful_deliveries,
        failure_count: metrics.failed_deliveries,
        avg_response_time_ms: metrics.avg_response_time_ms,
        p95_response_time_ms: metrics.p95_response_time_ms,
        p99_response_time_ms: metrics.p99_response_time_ms,
        error_rate_percent: metrics.error_rate,
        status_codes: metrics.status_codes,
        inserted_at: timestamp,
        updated_at: timestamp
      }
      |> then(fn attrs ->
        Repo.insert_all("webhook_health_metrics", [attrs])
      end)
    end)
  end

  defp check_all_webhooks_health do
    import Ecto.Query

    # Get all enabled webhooks
    webhooks =
      Webhook
      |> where([w], w.enabled == true)
      |> Repo.all()

    Enum.each(webhooks, &check_webhook_health/1)
  end

  defp check_webhook_health(webhook) do
    # Get recent delivery logs
    recent_logs = get_recent_delivery_logs(webhook.id, limit: 20)

    if length(recent_logs) < 5 do
      # Not enough data, keep current status
      :ok
    else
      failure_count = Enum.count(recent_logs, &(&1.status == "failure"))
      error_rate = failure_count / length(recent_logs)

      new_health_status = determine_health_status(error_rate, webhook.consecutive_failures)

      if new_health_status != webhook.health_status do
        update_webhook_health(webhook, new_health_status, failure_count)
      end
    end
  end

  defp determine_health_status(error_rate, consecutive_failures) do
    cond do
      consecutive_failures >= 5 || error_rate > 0.50 ->
        "unhealthy"

      error_rate > 0.20 ->
        "degraded"

      true ->
        "healthy"
    end
  end

  defp update_webhook_health(webhook, new_status, failure_count) do
    Logger.warning(
      "[WebhookHealthMonitor] Webhook #{webhook.id} (#{webhook.name}) health changed: " <>
        "#{webhook.health_status} -> #{new_status}"
    )

    webhook
    |> Ecto.Changeset.change(%{
      health_status: new_status,
      consecutive_failures: if(new_status == "healthy", do: 0, else: failure_count),
      last_health_check_at: DateTime.utc_now()
    })
    |> Repo.update()

    # Broadcast health status change
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "webhooks:#{webhook.organization_id}",
      {:webhook_health_changed, webhook.id, new_status}
    )
  end

  defp send_health_alerts do
    import Ecto.Query

    # Get all unhealthy webhooks
    unhealthy_webhooks =
      Webhook
      |> where([w], w.health_status in ["unhealthy", "circuit_open"])
      |> where([w], w.enabled == true)
      |> Repo.all()

    Enum.each(unhealthy_webhooks, fn webhook ->
      send_health_alert(webhook)
    end)
  end

  defp send_health_alert(webhook) do
    Logger.warning(
      "[WebhookHealthMonitor] Health alert for webhook #{webhook.id} (#{webhook.name}): " <>
        "Status is #{webhook.health_status}"
    )

    # In production, send notification via:
    # - Email to administrators
    # - Slack/Teams notification
    # - In-app notification
    # - PagerDuty incident

    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "webhooks:health_alerts",
      {:webhook_health_alert, webhook.id, webhook.name, webhook.health_status}
    )
  end

  defp get_recent_delivery_logs(webhook_id, opts) do
    limit = Keyword.get(opts, :limit, 20)

    import Ecto.Query
    alias TamanduaServer.Webhooks.DeliveryLog

    DeliveryLog
    |> where([d], d.webhook_id == ^webhook_id)
    |> order_by([d], desc: d.inserted_at)
    |> limit(^limit)
    |> Repo.all()
  end
end
