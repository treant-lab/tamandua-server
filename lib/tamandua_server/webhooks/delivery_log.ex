defmodule TamanduaServer.Webhooks.DeliveryLog do
  @moduledoc """
  Schema for webhook delivery logs.

  Records every attempt to deliver a webhook, including request/response details,
  status, latency, and retry information.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Webhooks.Webhook

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "webhook_deliveries" do
    field :event_type, :string
    field :event_id, :binary_id

    # Request details
    field :request_url, :string
    field :request_method, :string, default: "POST"
    field :request_headers, :map
    field :request_body, :map

    # Response details
    field :response_status, :integer
    field :response_headers, :map
    field :response_body, :string
    field :response_time_ms, :integer

    # Delivery status
    field :status, :string
    field :error_message, :string
    field :retry_count, :integer, default: 0
    field :next_retry_at, :utc_datetime

    belongs_to :webhook, Webhook

    timestamps(updated_at: false)
  end

  @doc false
  def changeset(delivery_log, attrs) do
    delivery_log
    |> cast(attrs, [
      :event_type,
      :event_id,
      :request_url,
      :request_method,
      :request_headers,
      :request_body,
      :response_status,
      :response_headers,
      :response_body,
      :response_time_ms,
      :status,
      :error_message,
      :retry_count,
      :next_retry_at,
      :webhook_id
    ])
    |> validate_required([:event_type, :webhook_id, :request_url, :status])
    |> validate_inclusion(:status, ~w(pending success failure retrying))
    |> foreign_key_constraint(:webhook_id)
  end

  @doc """
  Creates a changeset for a successful delivery.
  """
  def success_changeset(delivery_log, response_data) do
    delivery_log
    |> change(%{
      status: "success",
      response_status: response_data.status,
      response_headers: response_data.headers,
      response_body: truncate_body(response_data.body),
      response_time_ms: response_data.duration_ms
    })
  end

  @doc """
  Creates a changeset for a failed delivery.
  """
  def failure_changeset(delivery_log, error_data) do
    delivery_log
    |> change(%{
      status: "failure",
      response_status: error_data[:status],
      response_headers: error_data[:headers],
      response_body: truncate_body(error_data[:body]),
      response_time_ms: error_data[:duration_ms],
      error_message: error_data[:message]
    })
  end

  @doc """
  Creates a changeset for a retry attempt.
  """
  def retry_changeset(delivery_log, next_retry_at) do
    delivery_log
    |> change(%{
      status: "retrying",
      retry_count: delivery_log.retry_count + 1,
      next_retry_at: next_retry_at
    })
  end

  # Truncate response body to avoid storing huge payloads
  defp truncate_body(nil), do: nil
  defp truncate_body(body) when is_binary(body) do
    max_length = 10_000
    if String.length(body) > max_length do
      String.slice(body, 0, max_length) <> "... (truncated)"
    else
      body
    end
  end
  defp truncate_body(body), do: inspect(body)
end
