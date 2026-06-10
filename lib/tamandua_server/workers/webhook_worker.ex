defmodule TamanduaServer.Workers.WebhookWorker do
  @moduledoc """
  Oban worker for reliable webhook delivery with retry logic.

  Handles:
  - Delivering webhook payloads via HTTP
  - Recording delivery attempts in delivery logs
  - Implementing retry logic with exponential/linear backoff
  - Updating webhook statistics
  """

  use Oban.Worker,
    queue: :webhooks,
    max_attempts: 1  # We handle retries manually for better control

  require Logger

  alias TamanduaServer.Webhooks
  alias TamanduaServer.Webhooks.{Dispatcher, DeliveryLog}

  @impl Oban.Worker
  def perform(%Oban.Job{args: args}) do
    webhook_id = args["webhook_id"]
    event_type = args["event_type"]
    event_id = args["event_id"]
    payload = args["payload"]
    retry_count = Map.get(args, "retry_count", 0)

    case Webhooks.get_webhook(webhook_id) do
      {:ok, webhook} ->
        deliver_webhook(webhook, event_type, event_id, payload, retry_count)

      {:error, :not_found} ->
        Logger.warning("[WebhookWorker] Webhook #{webhook_id} not found, skipping delivery")
        :ok
    end
  end

  defp deliver_webhook(webhook, event_type, event_id, payload, retry_count) do
    # Create initial delivery log entry
    full_payload = Dispatcher.build_payload(event_type, event_id, payload)

    {:ok, log} =
      Webhooks.create_delivery_log(%{
        webhook_id: webhook.id,
        event_type: event_type,
        event_id: event_id,
        request_url: webhook.url,
        request_method: "POST",
        request_headers: %{"content-type" => "application/json"},
        request_body: full_payload,
        status: "pending",
        retry_count: retry_count
      })

    # Attempt delivery
    case Dispatcher.deliver_webhook(webhook, event_type, full_payload) do
      {:ok, response_data} ->
        handle_success(webhook, log, response_data)

      {:error, error_data} ->
        handle_failure(webhook, log, error_data, retry_count, event_type, event_id, payload)
    end
  end

  defp handle_success(webhook, log, response_data) do
    Logger.info(
      "[WebhookWorker] Successfully delivered to #{webhook.name} " <>
        "(#{response_data.status}, #{response_data.duration_ms}ms)"
    )

    # Update delivery log
    log
    |> DeliveryLog.success_changeset(response_data)
    |> TamanduaServer.Repo.update!()

    # Update webhook stats
    Webhooks.update_webhook_stats(webhook.id, success: true)

    :ok
  end

  defp handle_failure(webhook, log, error_data, retry_count, event_type, event_id, payload) do
    Logger.warning(
      "[WebhookWorker] Failed to deliver to #{webhook.name}: #{error_data[:message]}"
    )

    # Update delivery log with error details
    log
    |> DeliveryLog.failure_changeset(error_data)
    |> TamanduaServer.Repo.update!()

    # Determine if we should retry
    if retry_count < webhook.max_retries do
      schedule_retry(webhook, log, retry_count, event_type, event_id, payload)
    else
      Logger.error(
        "[WebhookWorker] Max retries (#{webhook.max_retries}) reached for #{webhook.name}"
      )

      # Update webhook stats
      Webhooks.update_webhook_stats(webhook.id, success: false)

      :ok
    end
  end

  defp schedule_retry(webhook, log, retry_count, event_type, event_id, payload) do
    next_retry_count = retry_count + 1
    backoff_seconds = calculate_backoff(webhook.backoff_strategy, next_retry_count)
    next_retry_at = DateTime.utc_now() |> DateTime.add(backoff_seconds, :second)

    Logger.info(
      "[WebhookWorker] Scheduling retry #{next_retry_count}/#{webhook.max_retries} " <>
        "for #{webhook.name} in #{backoff_seconds}s"
    )

    # Update delivery log to mark as retrying
    log
    |> DeliveryLog.retry_changeset(next_retry_at)
    |> TamanduaServer.Repo.update!()

    # Enqueue retry job
    %{
      webhook_id: webhook.id,
      event_type: event_type,
      event_id: event_id,
      payload: payload,
      retry_count: next_retry_count
    }
    |> new(scheduled_at: next_retry_at)
    |> Oban.insert()

    :ok
  end

  defp calculate_backoff("exponential", retry_count) do
    # Exponential backoff: 2^retry * 60 seconds (base delay)
    base_delay = 60
    trunc(:math.pow(2, retry_count - 1) * base_delay)
  end

  defp calculate_backoff("linear", retry_count) do
    # Linear backoff: retry * 120 seconds
    retry_count * 120
  end
end
