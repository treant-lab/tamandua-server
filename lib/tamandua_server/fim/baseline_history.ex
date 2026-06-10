defmodule TamanduaServer.Fim.BaselineHistory do
  @moduledoc """
  Schema for FIM baseline history.

  Tracks changes to baselines over time for audit trail.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "fim_baseline_history" do
    belongs_to :baseline, TamanduaServer.Fim.Baseline

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
    field :baseline_version, :integer
    field :archived_at, :utc_datetime

    timestamps()
  end

  @doc false
  def changeset(history, attrs) do
    history
    |> cast(attrs, [
      :baseline_id,
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
      :baseline_version,
      :archived_at
    ])
    |> validate_required([:baseline_id, :agent_id, :path, :hash])
  end
end
