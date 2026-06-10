defmodule TamanduaServer.Investigations.PivotChain do
  @moduledoc """
  Schema for storing investigation pivot chains.

  A pivot chain represents a sequence of investigation pivots that an analyst
  performed while investigating an incident. Each chain can be saved, shared,
  and replayed.
  """
  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Organization, User}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  schema "pivot_chains" do
    field :name, :string
    field :description, :string
    field :chain_data, :map, default: %{}
    field :pivot_count, :integer, default: 0
    field :is_template, :boolean, default: false
    field :template_name, :string
    field :shared, :boolean, default: false
    field :tags, {:array, :string}, default: []
    field :metadata, :map, default: %{}

    belongs_to :organization, Organization
    belongs_to :created_by, User, foreign_key: :created_by_id

    timestamps()
  end

  @doc false
  def changeset(pivot_chain, attrs) do
    pivot_chain
    |> cast(attrs, [
      :name,
      :description,
      :chain_data,
      :pivot_count,
      :is_template,
      :template_name,
      :shared,
      :tags,
      :metadata,
      :organization_id,
      :created_by_id
    ])
    |> validate_required([:name, :organization_id, :created_by_id])
    |> validate_length(:name, min: 1, max: 255)
    |> validate_chain_data()
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:created_by_id)
  end

  defp validate_chain_data(changeset) do
    case get_change(changeset, :chain_data) do
      nil ->
        changeset

      chain_data when is_map(chain_data) ->
        pivots = chain_data["pivots"] || []
        put_change(changeset, :pivot_count, length(pivots))

      _ ->
        add_error(changeset, :chain_data, "must be a valid map")
    end
  end
end
