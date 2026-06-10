defmodule TamanduaServer.Mitre.TechniqueMapping do
  @moduledoc """
  Schema for mapping detection rules to MITRE techniques.

  Tracks which detection rules (Sigma, YARA, behavioral, ML) cover which techniques.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "mitre_technique_mappings" do
    field :technique_id, :string
    field :rule_type, :string
    field :rule_id, :binary_id
    field :rule_name, :string
    field :confidence, :float, default: 1.0
    field :auto_mapped, :boolean, default: false
    field :notes, :string

    belongs_to :organization, Organization

    timestamps()
  end

  @doc false
  def changeset(mapping, attrs) do
    mapping
    |> cast(attrs, [
      :technique_id,
      :rule_type,
      :rule_id,
      :rule_name,
      :confidence,
      :auto_mapped,
      :notes,
      :organization_id
    ])
    |> validate_required([:technique_id, :rule_type, :rule_name])
    |> validate_inclusion(:rule_type, ~w(sigma yara behavioral ml custom))
    |> validate_number(:confidence, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0)
    |> unique_constraint([:technique_id, :rule_type, :rule_id])
    |> foreign_key_constraint(:organization_id)
  end
end
