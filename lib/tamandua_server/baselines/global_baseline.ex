defmodule TamanduaServer.Baselines.GlobalBaseline do
  @moduledoc """
  Schema for global baselines aggregated from all agents.

  Global baselines represent normal behavior across the entire fleet.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "global_baselines" do
    field :baseline_type, :string
    field :baseline_key, :string
    field :baseline_data, :map
    field :agent_count, :integer
    field :total_samples, :integer
    field :confidence_score, :float

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(global_baseline, attrs) do
    global_baseline
    |> cast(attrs, [
      :baseline_type,
      :baseline_key,
      :baseline_data,
      :agent_count,
      :total_samples,
      :confidence_score
    ])
    |> validate_required([
      :baseline_type,
      :baseline_key,
      :baseline_data
    ])
    |> validate_inclusion(:baseline_type, [
      "process",
      "user",
      "network",
      "file_access",
      "registry"
    ])
    |> unique_constraint([:baseline_type, :baseline_key])
  end
end
