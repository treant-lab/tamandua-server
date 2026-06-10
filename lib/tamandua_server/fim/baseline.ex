defmodule TamanduaServer.Fim.Baseline do
  @moduledoc """
  Schema for FIM baselines.

  Stores the known-good state of files for integrity monitoring.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "fim_baselines" do
    field :agent_id, :string
    field :path, :string
    field :hash, :string
    field :size, :integer
    field :permissions, :string
    field :owner, :string
    field :group, :string
    field :mtime, :integer
    field :ctime, :integer
    field :attributes, {:array, :string}, default: []
    field :category, :string, default: "custom"
    field :known_good, :boolean, default: false
    field :baseline_version, :integer, default: 1
    field :compliance_frameworks, {:array, :string}, default: []

    timestamps()
  end

  @doc false
  def changeset(baseline, attrs) do
    baseline
    |> cast(attrs, [
      :agent_id,
      :path,
      :hash,
      :size,
      :permissions,
      :owner,
      :group,
      :mtime,
      :ctime,
      :attributes,
      :category,
      :known_good,
      :baseline_version,
      :compliance_frameworks
    ])
    |> validate_required([:agent_id, :path, :hash, :size])
    |> unique_constraint([:agent_id, :path])
  end
end
