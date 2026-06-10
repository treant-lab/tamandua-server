defmodule TamanduaServer.Mitre.ThreatActor do
  @moduledoc """
  Schema for MITRE ATT&CK threat actors (APT groups).

  Represents adversary groups tracked by MITRE ATT&CK.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "mitre_threat_actors" do
    field :actor_id, :string
    field :name, :string
    field :aliases, {:array, :string}, default: []
    field :description, :string
    field :techniques, {:array, :string}, default: []
    field :country, :string
    field :first_seen, :date
    field :last_activity, :date
    field :sophistication, :string
    field :objectives, {:array, :string}, default: []
    field :sectors, {:array, :string}, default: []
    field :external_references, {:array, :map}, default: []
    field :metadata, :map, default: %{}

    timestamps()
  end

  @doc false
  def changeset(actor, attrs) do
    actor
    |> cast(attrs, [
      :actor_id,
      :name,
      :aliases,
      :description,
      :techniques,
      :country,
      :first_seen,
      :last_activity,
      :sophistication,
      :objectives,
      :sectors,
      :external_references,
      :metadata
    ])
    |> validate_required([:actor_id, :name])
    |> validate_inclusion(:sophistication, ~w(low medium high expert))
    |> unique_constraint(:actor_id)
  end
end
