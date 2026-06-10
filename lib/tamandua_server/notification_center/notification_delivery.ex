defmodule TamanduaServer.NotificationCenter.NotificationDelivery do
  @moduledoc """
  Schema for tracking multi-channel notification delivery.
  """
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @channels ["in_app", "email", "sms", "slack", "teams", "pagerduty", "webhook", "discord"]
  @statuses ["pending", "sent", "failed", "throttled"]

  schema "notification_deliveries" do
    field :channel, :string
    field :status, :string, default: "pending"

    field :sent_at, :utc_datetime
    field :failed_at, :utc_datetime
    field :error_message, :string

    field :provider_response, :map
    field :retry_count, :integer, default: 0

    belongs_to :notification, TamanduaServer.NotificationCenter.Notification
    belongs_to :organization, TamanduaServer.Accounts.Organization

    timestamps(type: :utc_datetime)
  end

  def changeset(delivery, attrs) do
    delivery
    |> cast(attrs, [
      :notification_id,
      :organization_id,
      :channel,
      :status,
      :sent_at,
      :failed_at,
      :error_message,
      :provider_response,
      :retry_count
    ])
    |> validate_required([:notification_id, :organization_id, :channel, :status])
    |> validate_inclusion(:channel, @channels)
    |> validate_inclusion(:status, @statuses)
    |> foreign_key_constraint(:notification_id)
    |> foreign_key_constraint(:organization_id)
  end

  def sent_changeset(delivery, response) do
    delivery
    |> change(%{
      status: "sent",
      sent_at: DateTime.utc_now(),
      provider_response: response
    })
  end

  def failed_changeset(delivery, error) do
    delivery
    |> change(%{
      status: "failed",
      failed_at: DateTime.utc_now(),
      error_message: to_string(error),
      retry_count: delivery.retry_count + 1
    })
  end

  def throttled_changeset(delivery) do
    delivery
    |> change(%{
      status: "throttled",
      failed_at: DateTime.utc_now()
    })
  end

  def channels, do: @channels
  def statuses, do: @statuses
end
