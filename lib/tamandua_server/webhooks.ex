defmodule TamanduaServer.Webhooks do
  @moduledoc """
  Context module for webhook management.

  Provides functions for CRUD operations on webhooks and querying delivery logs.
  """

  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Webhooks.{Webhook, DeliveryLog, Dispatcher}

  ## Webhook CRUD

  @doc """
  Lists all webhooks for an organization.
  """
  def list_webhooks(organization_id) do
    Webhook
    |> where([w], w.organization_id == ^organization_id)
    |> order_by([w], desc: w.inserted_at)
    |> Repo.all()
  end

  @doc """
  Gets a single webhook by ID.
  """
  def get_webhook(id) do
    case Repo.get(Webhook, id) do
      nil -> {:error, :not_found}
      webhook -> {:ok, webhook}
    end
  end

  @doc """
  Gets a webhook by ID, raising if not found.
  """
  def get_webhook!(id), do: Repo.get!(Webhook, id)

  @doc """
  Creates a webhook.
  """
  def create_webhook(attrs) do
    %Webhook{}
    |> Webhook.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a webhook.
  """
  def update_webhook(webhook, attrs) do
    webhook
    |> Webhook.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes a webhook.
  """
  def delete_webhook(webhook) do
    Repo.delete(webhook)
  end

  @doc """
  Toggles webhook enabled status.
  """
  def toggle_enabled(webhook) do
    webhook
    |> Webhook.changeset(%{enabled: !webhook.enabled})
    |> Repo.update()
  end

  @doc """
  Returns an empty webhook changeset for form rendering.
  """
  def change_webhook(webhook \\ %Webhook{}, attrs \\ %{}) do
    Webhook.changeset(webhook, attrs)
  end

  ## Delivery Logs

  @doc """
  Lists delivery logs for a webhook.
  """
  def list_delivery_logs(webhook_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)
    offset = Keyword.get(opts, :offset, 0)

    DeliveryLog
    |> where([d], d.webhook_id == ^webhook_id)
    |> order_by([d], desc: d.inserted_at)
    |> limit(^limit)
    |> offset(^offset)
    |> Repo.all()
  end

  @doc """
  Counts delivery logs for a webhook.
  """
  def count_delivery_logs(webhook_id) do
    DeliveryLog
    |> where([d], d.webhook_id == ^webhook_id)
    |> Repo.aggregate(:count)
  end

  @doc """
  Gets a single delivery log by ID.
  """
  def get_delivery_log(id) do
    case Repo.get(DeliveryLog, id) do
      nil -> {:error, :not_found}
      log -> {:ok, log}
    end
  end

  @doc """
  Creates a delivery log entry.
  """
  def create_delivery_log(attrs) do
    %DeliveryLog{}
    |> DeliveryLog.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a delivery log entry.
  """
  def update_delivery_log(log, attrs) do
    log
    |> DeliveryLog.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Updates webhook delivery statistics.
  """
  def update_webhook_stats(webhook_id, success: success?) do
    case get_webhook(webhook_id) do
      {:ok, webhook} ->
        webhook
        |> Webhook.increment_delivery_stats(success: success?)
        |> Repo.update()

      error ->
        error
    end
  end

  ## Event Dispatch

  @doc """
  Dispatches an event to all matching webhooks.

  ## Examples

      iex> dispatch_event("alert.created", alert.id, %{alert: alert_data}, organization_id: org_id)
      {:ok, 3}

  """
  defdelegate dispatch_event(event_type, event_id, payload, opts \\ []), to: Dispatcher

  @doc """
  Sends a test event to a webhook.
  """
  defdelegate send_test_event(webhook), to: Dispatcher

  ## Metadata

  @doc """
  Returns all supported event types.
  """
  defdelegate event_types, to: Webhook

  @doc """
  Returns all supported authentication types.
  """
  defdelegate auth_types, to: Webhook

  @doc """
  Returns all supported backoff strategies.
  """
  defdelegate backoff_strategies, to: Webhook

  ## Statistics

  @doc """
  Gets webhook statistics for an organization.
  """
  def get_webhook_stats(organization_id) do
    webhooks = list_webhooks(organization_id)

    total_webhooks = length(webhooks)
    enabled_webhooks = Enum.count(webhooks, & &1.enabled)

    total_deliveries = Enum.sum(Enum.map(webhooks, & &1.total_deliveries))
    successful_deliveries = Enum.sum(Enum.map(webhooks, & &1.successful_deliveries))
    failed_deliveries = Enum.sum(Enum.map(webhooks, & &1.failed_deliveries))

    success_rate =
      if total_deliveries > 0 do
        Float.round(successful_deliveries / total_deliveries * 100, 2)
      else
        0.0
      end

    %{
      total_webhooks: total_webhooks,
      enabled_webhooks: enabled_webhooks,
      total_deliveries: total_deliveries,
      successful_deliveries: successful_deliveries,
      failed_deliveries: failed_deliveries,
      success_rate: success_rate
    }
  end

  ## Cleanup

  @doc """
  Deletes old delivery logs older than the specified number of days.
  """
  def cleanup_old_logs(days_to_keep \\ 30) do
    cutoff = DateTime.utc_now() |> DateTime.add(-days_to_keep * 24 * 3600, :second)

    {count, _} =
      DeliveryLog
      |> where([d], d.inserted_at < ^cutoff)
      |> Repo.delete_all()

    {:ok, count}
  end
end
