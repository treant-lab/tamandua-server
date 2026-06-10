defmodule TamanduaServer.Integrations.WebhookDelivery do
  @moduledoc """
  Schema for tracking webhook deliveries (both inbound and outbound).

  Used for audit logging, debugging, and retry logic.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Integrations.Config
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Accounts.Organization

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  schema "webhook_deliveries" do
    belongs_to :integration, Config
    belongs_to :alert, Alert
    belongs_to :organization, Organization

    field :integration_type, :string
    field :direction, :string # inbound or outbound
    field :source, :string
    field :destination_url, :string
    field :event_type, :string
    field :status, :string
    field :payload_size, :integer
    field :request_headers, :map
    field :response_status, :integer
    field :response_body, :string
    field :error_message, :string
    field :duration_ms, :integer
    field :retry_count, :integer, default: 0
    field :next_retry_at, :utc_datetime
    field :webhook_id, :string
    field :signature_verified, :boolean
    field :raw_payload, :map
    field :metadata, :map, default: %{}

    timestamps()
  end

  @required_fields [:integration_type, :direction, :status]
  @optional_fields [
    :integration_id,
    :alert_id,
    :organization_id,
    :source,
    :destination_url,
    :event_type,
    :payload_size,
    :request_headers,
    :response_status,
    :response_body,
    :error_message,
    :duration_ms,
    :retry_count,
    :next_retry_at,
    :webhook_id,
    :signature_verified,
    :raw_payload,
    :metadata
  ]

  def changeset(delivery, attrs) do
    delivery
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:direction, ~w(inbound outbound))
    |> validate_inclusion(:status, ~w(pending delivered failed rate_limited duplicate))
    |> foreign_key_constraint(:integration_id)
    |> foreign_key_constraint(:alert_id)
    |> foreign_key_constraint(:organization_id)
  end
end
