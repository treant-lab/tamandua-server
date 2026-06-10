defmodule TamanduaServer.Agents.GeoTravelRequest do
  @moduledoc """
  Travel request for temporary geofencing exceptions.
  Allows users to request approval for accessing from new locations.
  """
  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Organization, User}
  alias TamanduaServer.Agents.{Agent, GeoRegion}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]
  schema "geo_travel_requests" do
    field :destination_country, :string
    field :destination_city, :string
    field :reason, :string
    field :start_date, :date
    field :end_date, :date
    field :status, :string, default: "pending"
    field :approved_at, :utc_datetime_usec
    field :denied_at, :utc_datetime_usec
    field :denial_reason, :string
    field :auto_approved, :boolean, default: false

    belongs_to :organization, Organization
    belongs_to :agent, Agent
    belongs_to :destination_region, GeoRegion
    belongs_to :requested_by, User
    belongs_to :approved_by, User
    belongs_to :denied_by, User

    timestamps()
  end

  @doc false
  def changeset(request, attrs) do
    request
    |> cast(attrs, [
      :organization_id,
      :agent_id,
      :requested_by_id,
      :destination_region_id,
      :destination_country,
      :destination_city,
      :reason,
      :start_date,
      :end_date,
      :status,
      :approved_by_id,
      :approved_at,
      :denied_by_id,
      :denied_at,
      :denial_reason,
      :auto_approved
    ])
    |> validate_required([:organization_id, :agent_id, :start_date, :end_date])
    |> validate_inclusion(:status, ~w(pending approved denied expired))
    |> validate_date_range()
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:agent_id)
    |> foreign_key_constraint(:requested_by_id)
  end

  defp validate_date_range(changeset) do
    start_date = get_change(changeset, :start_date)
    end_date = get_change(changeset, :end_date)

    if start_date && end_date && Date.compare(start_date, end_date) == :gt do
      add_error(changeset, :end_date, "must be after start date")
    else
      changeset
    end
  end
end
