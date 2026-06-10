defmodule TamanduaServer.Hunting.WorkflowStepResult do
  @moduledoc """
  Schema for individual workflow step results.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "workflow_step_results" do
    field :step_index, :integer
    field :step_type, :string
    field :query, :string
    field :results, {:array, :map}, default: []
    field :result_count, :integer, default: 0
    field :decision, :string
    field :annotations, :string
    field :status, :string
    field :started_at, :utc_datetime
    field :completed_at, :utc_datetime
    field :duration_ms, :integer

    belongs_to :execution, TamanduaServer.Hunting.WorkflowExecution

    timestamps()
  end

  @doc false
  def changeset(step_result, attrs) do
    step_result
    |> cast(attrs, [
      :execution_id,
      :step_index,
      :step_type,
      :query,
      :results,
      :result_count,
      :decision,
      :annotations,
      :status,
      :started_at,
      :completed_at,
      :duration_ms
    ])
    |> validate_required([:execution_id, :step_index, :step_type])
    |> validate_inclusion(:status, ["pending", "running", "completed", "skipped", "failed"])
  end
end
