defmodule TamanduaServer.Mitre.NavigatorLayer do
  @moduledoc """
  Schema for saved MITRE ATT&CK Navigator layers.

  Navigator layers are JSON-based heatmap visualizations that can be
  exported and viewed in the official MITRE ATT&CK Navigator tool.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Organization, User}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "mitre_navigator_layers" do
    field :name, :string
    field :description, :string
    field :layer_data, :map
    field :layer_type, :string
    field :is_public, :boolean, default: false
    field :time_range_start, :utc_datetime_usec
    field :time_range_end, :utc_datetime_usec

    belongs_to :organization, Organization
    belongs_to :created_by, User, foreign_key: :created_by_id

    timestamps()
  end

  @doc false
  def changeset(layer, attrs) do
    layer
    |> cast(attrs, [
      :name,
      :description,
      :layer_data,
      :layer_type,
      :is_public,
      :time_range_start,
      :time_range_end,
      :organization_id,
      :created_by_id
    ])
    |> validate_required([:name, :layer_data])
    |> validate_inclusion(:layer_type, ~w(coverage frequency custom severity timeline))
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:created_by_id)
  end
end
