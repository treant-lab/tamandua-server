defmodule TamanduaServer.Integrations.IntegrationSyncState do
  @moduledoc """
  Schema for tracking synchronization state between Tamandua alerts and external system tickets/incidents.

  Maintains the relationship between a Tamandua alert and its corresponding
  external ticket in Jira, ServiceNow, Splunk, etc.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Integrations.Config
  alias TamanduaServer.Alerts.Alert

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  schema "integration_sync_states" do
    belongs_to :integration, Config
    belongs_to :alert, Alert

    field :external_id, :string
    field :external_url, :string
    field :external_status, :string
    field :last_synced_at, :utc_datetime
    field :sync_direction, :string
    field :metadata, :map, default: %{}

    timestamps()
  end

  @required_fields [:integration_id, :alert_id, :external_id]
  @optional_fields [
    :external_url,
    :external_status,
    :last_synced_at,
    :sync_direction,
    :metadata
  ]

  def changeset(sync_state, attrs) do
    sync_state
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:sync_direction, ~w(push pull bidirectional))
    |> unique_constraint([:integration_id, :alert_id])
    |> unique_constraint([:integration_id, :external_id])
    |> foreign_key_constraint(:integration_id)
    |> foreign_key_constraint(:alert_id)
  end
end
