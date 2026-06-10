defmodule TamanduaServer.Agents.AgentLocation do
  @moduledoc """
  Tracks agent location history with GeoIP data, VPN detection,
  and region matching.
  """
  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Agents.Agent

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]
  schema "agent_locations" do
    field :ip_address, :string
    field :country_code, :string
    field :country_name, :string
    field :city, :string
    field :region, :string
    field :latitude, :float
    field :longitude, :float
    field :accuracy_km, :float
    field :source, :string, default: "geoip"
    field :is_vpn, :boolean, default: false
    field :vpn_provider, :string
    field :is_proxy, :boolean, default: false
    field :is_tor, :boolean, default: false
    field :true_location, :map
    field :matched_region_ids, {:array, :binary_id}, default: []
    field :is_expected, :boolean
    field :is_restricted, :boolean
    field :metadata, :map, default: %{}
    field :detected_at, :utc_datetime_usec

    belongs_to :organization, Organization
    belongs_to :agent, Agent

    timestamps()
  end

  @doc false
  def changeset(location, attrs) do
    location
    |> cast(attrs, [
      :organization_id,
      :agent_id,
      :ip_address,
      :country_code,
      :country_name,
      :city,
      :region,
      :latitude,
      :longitude,
      :accuracy_km,
      :source,
      :is_vpn,
      :vpn_provider,
      :is_proxy,
      :is_tor,
      :true_location,
      :matched_region_ids,
      :is_expected,
      :is_restricted,
      :metadata,
      :detected_at
    ])
    |> validate_required([:organization_id, :agent_id, :detected_at])
    |> validate_inclusion(:source, ~w(geoip gps wifi manual))
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:agent_id)
  end
end
