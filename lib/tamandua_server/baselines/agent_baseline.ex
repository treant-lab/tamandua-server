defmodule TamanduaServer.Baselines.AgentBaseline do
  @moduledoc """
  Schema for agent-specific baselines.

  Stores baseline data uploaded from individual agents.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "agent_baselines" do
    field :agent_id, :binary_id
    field :baseline_type, :string
    field :baseline_key, :string
    field :baseline_data, :map
    field :learning_samples, :integer
    field :first_seen, :utc_datetime
    field :last_updated, :utc_datetime
    field :version, :integer

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(agent_baseline, attrs) do
    agent_baseline
    |> cast(attrs, [
      :agent_id,
      :baseline_type,
      :baseline_key,
      :baseline_data,
      :learning_samples,
      :first_seen,
      :last_updated,
      :version
    ])
    |> validate_required([
      :agent_id,
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
    |> unique_constraint([:agent_id, :baseline_type, :baseline_key])
  end
end
