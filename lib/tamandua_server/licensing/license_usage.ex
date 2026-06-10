defmodule TamanduaServer.Licensing.LicenseUsage do
  @moduledoc """
  Schema for tracking license usage metrics.

  Used for:
  - Usage-based billing
  - Quota enforcement
  - Usage analytics
  - Capacity planning
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @metric_types ~w(
    agent_checkin
    event_ingested
    alert_generated
    query_executed
    api_call
    storage_bytes
    bandwidth_bytes
  )

  schema "license_usage" do
    belongs_to :organization, Organization

    field :metric_type, :string
    field :value, :integer
    field :metadata, :map, default: %{}
    field :recorded_at, :utc_datetime_usec

    timestamps(type: :utc_datetime_usec, updated_at: false)
  end

  @required_fields ~w(organization_id metric_type value recorded_at)a
  @optional_fields ~w(metadata)a

  def changeset(usage, attrs) do
    usage
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:metric_type, @metric_types)
    |> validate_number(:value, greater_than_or_equal_to: 0)
    |> foreign_key_constraint(:organization_id)
  end

  @doc """
  Returns the list of valid metric types.
  """
  def metric_types, do: @metric_types
end
