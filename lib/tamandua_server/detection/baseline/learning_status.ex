defmodule TamanduaServer.Detection.Baseline.LearningStatus do
  @moduledoc """
  Ecto schema for tracking baseline learning status per agent.

  Each agent goes through a learning period (default 7 days) during which
  patterns are recorded but not used for false positive reduction.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "baseline_learning_status" do
    field :started_at, :utc_datetime_usec
    field :completed_at, :utc_datetime_usec
    field :learning_days, :integer, default: 7
    field :status, :string, default: "learning"  # "learning", "completed", "paused"
    field :events_processed, :integer, default: 0
    field :patterns_learned, :integer, default: 0

    belongs_to :agent, TamanduaServer.Agents.Agent
    belongs_to :organization, TamanduaServer.Accounts.Organization

    timestamps(type: :utc_datetime_usec)
  end

  @doc false
  def changeset(status, attrs) do
    status
    |> cast(attrs, [
      :agent_id,
      :organization_id,
      :started_at,
      :completed_at,
      :learning_days,
      :status,
      :events_processed,
      :patterns_learned
    ])
    |> validate_required([:agent_id, :started_at, :status])
    |> validate_inclusion(:status, ~w(learning completed paused))
    |> validate_number(:learning_days, greater_than: 0)
    |> unique_constraint(:agent_id)
  end

  @doc """
  Check if the learning period has expired based on started_at and learning_days.
  """
  def learning_expired?(%__MODULE__{started_at: started_at, learning_days: days}) do
    cutoff = DateTime.add(started_at, days * 24 * 60 * 60, :second)
    DateTime.compare(DateTime.utc_now(), cutoff) == :gt
  end
end
