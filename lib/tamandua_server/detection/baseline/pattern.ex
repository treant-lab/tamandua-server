defmodule TamanduaServer.Detection.Baseline.Pattern do
  @moduledoc """
  Ecto schema for baseline patterns stored in the database.

  Patterns represent learned normal behavior for agents or organizations.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "baselines" do
    field :baseline_type, :string  # "process", "network", "file", "schedule"
    field :pattern, :map, default: %{}
    field :occurrence_count, :integer, default: 1
    field :first_seen, :utc_datetime_usec
    field :last_seen, :utc_datetime_usec
    field :confidence_weight, :float, default: 1.0

    belongs_to :agent, TamanduaServer.Agents.Agent
    belongs_to :organization, TamanduaServer.Accounts.Organization

    timestamps(type: :utc_datetime_usec)
  end

  @doc false
  def changeset(pattern, attrs) do
    pattern
    |> cast(attrs, [
      :agent_id,
      :organization_id,
      :baseline_type,
      :pattern,
      :occurrence_count,
      :first_seen,
      :last_seen,
      :confidence_weight
    ])
    |> validate_required([:baseline_type, :pattern])
    |> validate_inclusion(:baseline_type, ~w(process network file schedule user))
  end

  @doc """
  Compute a hash of the pattern for uniqueness checking.
  Uses MD5 of the JSON-encoded pattern.
  """
  def pattern_hash(%__MODULE__{pattern: pattern}) do
    pattern_hash(pattern)
  end

  def pattern_hash(pattern) when is_map(pattern) do
    pattern
    |> Jason.encode!()
    |> then(&:crypto.hash(:md5, &1))
    |> Base.encode16(case: :lower)
  end
end
