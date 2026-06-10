defmodule TamanduaServer.Mitre.Technique do
  @moduledoc """
  Schema for MITRE ATT&CK techniques.

  Represents a technique or sub-technique from the MITRE ATT&CK framework.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "mitre_techniques" do
    field :technique_id, :string
    field :name, :string
    field :description, :string
    field :platforms, {:array, :string}, default: []
    field :data_sources, {:array, :string}, default: []
    field :tactics, {:array, :string}, default: []
    field :is_subtechnique, :boolean, default: false
    field :parent_technique_id, :string
    field :mitigations, :map, default: %{}
    field :detection_guidance, :string
    field :external_references, {:array, :map}, default: []
    field :metadata, :map, default: %{}

    timestamps()
  end

  @doc false
  def changeset(technique, attrs) do
    technique
    |> cast(attrs, [
      :technique_id,
      :name,
      :description,
      :platforms,
      :data_sources,
      :tactics,
      :is_subtechnique,
      :parent_technique_id,
      :mitigations,
      :detection_guidance,
      :external_references,
      :metadata
    ])
    |> validate_required([:technique_id, :name])
    |> validate_format(:technique_id, ~r/^T\d{4}(\.\d{3})?$/, message: "must be valid technique ID")
    |> unique_constraint(:technique_id)
  end
end
