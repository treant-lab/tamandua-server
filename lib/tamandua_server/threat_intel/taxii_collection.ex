defmodule TamanduaServer.ThreatIntel.TaxiiCollection do
  @moduledoc """
  Schema for TAXII 2.1 collection configuration.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "taxii_collections" do
    field :collection_id, :string
    field :api_root, :string

    field :title, :string
    field :description, :string
    field :can_read, :boolean, default: false
    field :can_write, :boolean, default: false
    field :media_types, {:array, :string}, default: []

    # Sync config
    field :poll_enabled, :boolean, default: true
    field :filter_types, {:array, :string}, default: []
    field :last_added_after, :utc_datetime

    # Status
    field :last_poll_at, :utc_datetime
    field :objects_imported, :integer, default: 0
    field :status, :string, default: "pending"
    field :last_error, :string

    field :enabled, :boolean, default: true

    belongs_to :taxii_server, TamanduaServer.ThreatIntel.TaxiiServer

    timestamps()
  end

  @doc false
  def changeset(collection, attrs) do
    collection
    |> cast(attrs, [
      :taxii_server_id, :collection_id, :api_root,
      :title, :description, :can_read, :can_write, :media_types,
      :poll_enabled, :filter_types, :enabled
    ])
    |> validate_required([:taxii_server_id, :collection_id, :api_root])
    |> foreign_key_constraint(:taxii_server_id)
    |> unique_constraint([:taxii_server_id, :collection_id])
  end
end
