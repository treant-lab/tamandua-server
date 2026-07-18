defmodule TamanduaServer.Webhooks.RetryHandler do
  @moduledoc """
  Advanced retry handler for webhook deliveries.

  Features:
  - Exponential and linear backoff strategies
  - Circuit breaker pattern
  - Dead letter queue for failed webhooks
  - Retry budget tracking
  - Adaptive retry delays based on error type
  """

  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Webhooks.{DeliveryLog}

  @doc """
  Calculates the next retry delay based on backoff strategy and error context.

  Implements:
  - Exponential backoff: 2^retry * base_delay
  - Linear backoff: retry * base_delay
  - Adaptive delays based on HTTP status codes
  - Jitter to prevent thundering herd
  """
  def calculate_retry_delay(webhook, retry_count, error_context \\ %{}) do
    base_delay = base_delay_for_error(error_context)

    delay =
      case webhook.backoff_strategy do
        "exponential" ->
          calculate_exponential_backoff(retry_count, base_delay)

        "linear" ->
          calculate_linear_backoff(retry_count, base_delay)

        _ ->
          base_delay
      end

    # Add jitter (±20%) to prevent thundering herd
    add_jitter(delay)
  end

  defp calculate_exponential_backoff(retry_count, base_delay) do
    # 2^retry * base_delay, with cap at 1 hour
    delay = trunc(:math.pow(2, retry_count - 1) * base_delay)
    min(delay, 3600)
  end

  defp calculate_linear_backoff(retry_count, base_delay) do
    # retry * base_delay, with cap at 30 minutes
    delay = retry_count * base_delay
    min(delay, 1800)
  end

  defp base_delay_for_error(%{status: status}) when status in 429..429 do
    # Rate limit - longer delay
    300
  end

  defp base_delay_for_error(%{status: status}) when status in 500..599 do
    # Server error - medium delay
    120
  end

  defp base_delay_for_error(%{status: status}) when status in 400..499 do
    # Client error - shorter delay (unlikely to recover)
    60
  end

  defp base_delay_for_error(_) do
    # Network errors, timeouts - standard delay
    60
  end

  defp add_jitter(delay) do
    jitter_range = trunc(delay * 0.2)
    jitter = :rand.uniform(jitter_range * 2) - jitter_range
    max(delay + jitter, 1)
  end

  @doc """
  Determines if a webhook should be retried based on error type and context.
  """
  def should_retry?(webhook, retry_count, error_context) do
    cond do
      retry_count >= webhook.max_retries ->
        Logger.info("[RetryHandler] Max retries reached for webhook #{webhook.id}")
        false

      is_permanent_error?(error_context) ->
        Logger.info("[RetryHandler] Permanent error detected, skipping retry")
        false

      is_circuit_open?(webhook) ->
        Logger.warning("[RetryHandler] Circuit breaker open for webhook #{webhook.id}")
        false

      true ->
        true
    end
  end

  @doc """
  Checks if an error is permanent (should not retry).

  Permanent errors:
  - 4xx errors (except 408, 429)
  - Invalid URL/DNS resolution failures
  - SSL certificate verification failures
  """
  def is_permanent_error?(%{status: status}) when status in [401, 403, 404, 410] do
    true
  end

  def is_permanent_error?(%{message: message}) when is_binary(message) do
    permanent_patterns = [
      "nxdomain",
      "ssl_error",
      "certificate verify failed",
      "invalid_url"
    ]

    Enum.any?(permanent_patterns, fn pattern ->
      String.contains?(String.downcase(message), pattern)
    end)
  end

  def is_permanent_error?(_), do: false

  @doc """
  Implements circuit breaker pattern.

  Circuit opens when error rate exceeds threshold (e.g., >50% failures in last 10 attempts).
  Circuit automatically closes after cooldown period.
  """
  def is_circuit_open?(webhook) do
    recent_logs = get_recent_delivery_logs(webhook.id, limit: 10)

    if length(recent_logs) < 5 do
      # Not enough data, allow delivery
      false
    else
      failure_count = Enum.count(recent_logs, &(&1.status == "failure"))
      failure_rate = failure_count / length(recent_logs)

      if failure_rate > 0.5 do
        check_circuit_cooldown(webhook)
      else
        false
      end
    end
  end

  defp check_circuit_cooldown(webhook) do
    # Check if last successful delivery was within cooldown period (5 minutes)
    case webhook.last_delivery_at do
      nil ->
        true

      last_delivery ->
        cooldown_seconds = 300
        cutoff = DateTime.add(DateTime.utc_now(), -cooldown_seconds, :second)
        DateTime.compare(last_delivery, cutoff) == :lt
    end
  end

  defp get_recent_delivery_logs(webhook_id, opts) do
    limit = Keyword.get(opts, :limit, 10)

    import Ecto.Query

    DeliveryLog
    |> where([d], d.webhook_id == ^webhook_id)
    |> order_by([d], desc: d.inserted_at)
    |> limit(^limit)
    |> Repo.all()
  end

  @doc """
  Moves a permanently failed webhook delivery to the dead letter queue.
  """
  def move_to_dead_letter_queue(webhook, delivery_log, error_reason) do
    Logger.warning(
      "[RetryHandler] Moving webhook #{webhook.id} delivery to DLQ: #{error_reason}"
    )

    # Create DLQ entry
    attrs = %{
      webhook_id: webhook.id,
      delivery_log_id: delivery_log.id,
      event_type: delivery_log.event_type,
      event_id: delivery_log.event_id,
      payload: delivery_log.request_body,
      error_reason: error_reason,
      failure_count: delivery_log.retry_count + 1,
      inserted_at: DateTime.utc_now()
    }

    # In production, you might want to:
    # 1. Store in a separate DLQ table
    # 2. Send to a message queue (RabbitMQ, SQS)
    # 3. Trigger alerts for engineering team
    # 4. Provide manual retry UI

    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "webhooks:dlq",
      {:webhook_delivery_failed, attrs}
    )

    {:ok, :moved_to_dlq}
  end

  @doc """
  Calculates retry budget for rate limiting.

  Prevents excessive retries from overwhelming the system.
  Budget: max 100 retries per webhook per hour.
  """
  def has_retry_budget?(webhook_id) do
    one_hour_ago = DateTime.add(DateTime.utc_now(), -3600, :second)

    import Ecto.Query

    retry_count =
      DeliveryLog
      |> where([d], d.webhook_id == ^webhook_id)
      |> where([d], d.retry_count > 0)
      |> where([d], d.inserted_at > ^one_hour_ago)
      |> Repo.aggregate(:count)

    retry_count < 100
  end

  @doc """
  Returns retry statistics for a webhook.
  """
  def get_retry_stats(webhook_id) do
    import Ecto.Query

    one_hour_ago = DateTime.add(DateTime.utc_now(), -3600, :second)

    stats =
      DeliveryLog
      |> where([d], d.webhook_id == ^webhook_id)
      |> where([d], d.inserted_at > ^one_hour_ago)
      |> select([d], %{
        total: count(d.id),
        retries: sum(d.retry_count),
        failures: count(fragment("CASE WHEN ? = 'failure' THEN 1 END", d.status))
      })
      |> Repo.one()

    %{
      total_deliveries: stats.total || 0,
      total_retries: stats.retries || 0,
      total_failures: stats.failures || 0,
      failure_rate: calculate_failure_rate(stats)
    }
  end

  defp calculate_failure_rate(%{total: total, failures: failures})
       when is_integer(total) and total > 0 do
    Float.round(failures / total * 100, 2)
  end

  defp calculate_failure_rate(_), do: 0.0

  @doc """
  Implements smart retry scheduling based on webhook health.

  Healthy webhooks: normal retry schedule
  Degraded webhooks: extended retry delays
  Unhealthy webhooks: circuit breaker activation
  """
  def smart_retry_schedule(webhook, retry_count, error_context) do
    health_status = calculate_health_status(webhook)

    case health_status do
      :healthy ->
        calculate_retry_delay(webhook, retry_count, error_context)

      :degraded ->
        delay = calculate_retry_delay(webhook, retry_count, error_context)
        delay * 2  # Double the delay for degraded webhooks

      :unhealthy ->
        :circuit_open
    end
  end

  defp calculate_health_status(webhook) do
    stats = get_retry_stats(webhook.id)

    cond do
      stats.failure_rate > 50 ->
        :unhealthy

      stats.failure_rate > 20 ->
        :degraded

      true ->
        :healthy
    end
  end
end
