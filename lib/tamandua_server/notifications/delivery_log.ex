defmodule TamanduaServer.Notifications.DeliveryLog do
  @moduledoc """
  Schema for notification delivery logs.

  Tracks sent, failed, and retry notifications for auditing and debugging.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  @statuses ~w(sent failed retry throttled)

  schema "notification_delivery_logs" do
    field :status, :string
    field :provider, :string
    field :recipient, :string

    # Request/Response
    field :rendered_title, :string
    field :rendered_body, :string
    field :error_message, :string
    field :response_code, :integer
    field :response_body, :string

    # Metadata
    field :delivered_at, :utc_datetime_usec
    field :retry_count, :integer, default: 0
    field :next_retry_at, :utc_datetime_usec

    belongs_to :integration, TamanduaServer.Notifications.Integration
    belongs_to :organization, TamanduaServer.Accounts.Organization
    belongs_to :alert, TamanduaServer.Alerts.Alert

    timestamps()
  end

  @doc """
  Changeset for creating delivery logs.
  """
  def changeset(log, attrs) do
    log
    |> cast(attrs, [
      :status,
      :provider,
      :recipient,
      :rendered_title,
      :rendered_body,
      :error_message,
      :response_code,
      :response_body,
      :delivered_at,
      :retry_count,
      :next_retry_at,
      :integration_id,
      :organization_id,
      :alert_id
    ])
    |> validate_required([:status, :provider, :integration_id, :organization_id])
    |> validate_inclusion(:status, @statuses)
    |> foreign_key_constraint(:integration_id)
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:alert_id)
  end

  @doc """
  Create a success log entry.
  """
  def success(integration_id, organization_id, alert_id, attrs) do
    %__MODULE__{}
    |> changeset(
      Map.merge(attrs, %{
        integration_id: integration_id,
        organization_id: organization_id,
        alert_id: alert_id,
        status: "sent",
        delivered_at: DateTime.utc_now()
      })
    )
  end

  @doc """
  Create a failure log entry.
  """
  def failure(integration_id, organization_id, alert_id, attrs) do
    %__MODULE__{}
    |> changeset(
      Map.merge(attrs, %{
        integration_id: integration_id,
        organization_id: organization_id,
        alert_id: alert_id,
        status: "failed"
      })
    )
  end

  @doc """
  Create a throttled log entry.
  """
  def throttled(integration_id, organization_id, alert_id, attrs) do
    %__MODULE__{}
    |> changeset(
      Map.merge(attrs, %{
        integration_id: integration_id,
        organization_id: organization_id,
        alert_id: alert_id,
        status: "throttled"
      })
    )
  end

  @doc """
  Get list of valid statuses.
  """
  def statuses, do: @statuses
end
