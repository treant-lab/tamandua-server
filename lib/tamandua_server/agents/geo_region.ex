defmodule TamanduaServer.Agents.GeoRegion do
  @moduledoc """
  Geographic region definition for geofencing.

  Supports multiple region types:
  - Country: ISO country code
  - City: Country + city + state
  - Polygon: Custom drawn region (list of lat/lon coordinates)
  - Radius: Center point + radius in kilometers
  """
  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "geo_regions" do
    field :name, :string
    field :description, :string
    field :region_type, :string
    field :definition, :map
    field :color, :string, default: "#3B82F6"
    field :is_active, :boolean, default: true

    belongs_to :organization, Organization

    timestamps()
  end

  @doc false
  def changeset(region, attrs) do
    region
    |> cast(attrs, [
      :organization_id,
      :name,
      :description,
      :region_type,
      :definition,
      :color,
      :is_active
    ])
    |> validate_required([:organization_id, :name, :region_type, :definition])
    |> validate_inclusion(:region_type, ~w(country city polygon radius))
    |> validate_definition()
    |> foreign_key_constraint(:organization_id)
  end

  defp validate_definition(changeset) do
    case get_change(changeset, :region_type) do
      "country" -> validate_country_definition(changeset)
      "city" -> validate_city_definition(changeset)
      "polygon" -> validate_polygon_definition(changeset)
      "radius" -> validate_radius_definition(changeset)
      _ -> changeset
    end
  end

  defp validate_country_definition(changeset) do
    definition = get_change(changeset, :definition)

    if definition && is_map(definition) && Map.has_key?(definition, "country_code") do
      changeset
    else
      add_error(changeset, :definition, "must include country_code for country type")
    end
  end

  defp validate_city_definition(changeset) do
    definition = get_change(changeset, :definition)

    required_keys = ["country", "city"]

    if definition && is_map(definition) && Enum.all?(required_keys, &Map.has_key?(definition, &1)) do
      changeset
    else
      add_error(changeset, :definition, "must include country and city for city type")
    end
  end

  defp validate_polygon_definition(changeset) do
    definition = get_change(changeset, :definition)

    if definition && is_map(definition) && Map.has_key?(definition, "coordinates") do
      coords = definition["coordinates"]

      if is_list(coords) && length(coords) >= 3 do
        changeset
      else
        add_error(changeset, :definition, "polygon must have at least 3 coordinates")
      end
    else
      add_error(changeset, :definition, "must include coordinates for polygon type")
    end
  end

  defp validate_radius_definition(changeset) do
    definition = get_change(changeset, :definition)

    if definition && is_map(definition) &&
         Map.has_key?(definition, "center") &&
         Map.has_key?(definition, "radius_km") do
      center = definition["center"]

      if is_map(center) && Map.has_key?(center, "lat") && Map.has_key?(center, "lon") do
        changeset
      else
        add_error(changeset, :definition, "center must have lat and lon")
      end
    else
      add_error(changeset, :definition, "must include center and radius_km for radius type")
    end
  end
end
