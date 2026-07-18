defmodule TamanduaServer.Hunting.WorkflowExecution do
  @moduledoc """
  Schema for workflow execution instances.

  Tracks the state of a running/completed workflow hunt including:
  - Progress through steps
  - Findings and evidence collected
  - Analyst annotations
  - Hypothesis tracking
  - Final report generation
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "workflow_executions" do
    field :status, :string, default: "pending"
    field :current_step_index, :integer, default: 0
    field :step_states, {:array, :map}, default: []
    field :findings, {:array, :map}, default: []
    field :annotations, {:array, :map}, default: []
    field :hypothesis_status, :map, default: %{}
    field :progress_percentage, :integer, default: 0
    field :started_at, :utc_datetime
    field :completed_at, :utc_datetime
    field :error_message, :string
    field :final_report, :map

    belongs_to :workflow, TamanduaServer.Hunting.Workflow

    # The migration column is `executed_by` (NOT `executed_by_id` — see
    # 20260220600004_create_hunting_workflows.exs). Ecto forbids an association
    # sharing its FK column name, so the association is `:executed_by_user`
    # while the persisted field stays `:executed_by`.
    belongs_to :executed_by_user, TamanduaServer.Accounts.User,
      foreign_key: :executed_by

    # The organizations schema lives under Accounts (there is no
    # TamanduaServer.Organizations.Organization module).
    belongs_to :organization, TamanduaServer.Accounts.Organization

    # Child schemas declare `belongs_to :execution` and the migration column is
    # `execution_id` (see 20260220600004_create_hunting_workflows.exs), so the
    # default FK guess (`workflow_execution_id`) must be overridden.
    has_many :step_results, TamanduaServer.Hunting.WorkflowStepResult,
      foreign_key: :execution_id

    has_many :workflow_findings, TamanduaServer.Hunting.WorkflowFinding,
      foreign_key: :execution_id

    timestamps()
  end

  @doc false
  def changeset(execution, attrs) do
    execution
    |> cast(attrs, [
      :workflow_id,
      :status,
      :current_step_index,
      :step_states,
      :findings,
      :annotations,
      :hypothesis_status,
      :progress_percentage,
      :started_at,
      :completed_at,
      :error_message,
      :final_report,
      :executed_by,
      :organization_id
    ])
    |> validate_required([:workflow_id])
    |> validate_inclusion(:status, ["pending", "in_progress", "paused", "completed", "failed"])
    |> validate_number(:progress_percentage, greater_than_or_equal_to: 0, less_than_or_equal_to: 100)
  end

  @doc """
  Create a new execution from a workflow.
  """
  def new_from_workflow(workflow, user_id, organization_id) do
    %__MODULE__{}
    |> changeset(%{
      workflow_id: workflow.id,
      executed_by: user_id,
      organization_id: organization_id,
      status: "pending",
      step_states: initialize_step_states(workflow.steps)
    })
  end

  defp initialize_step_states(steps) do
    Enum.with_index(steps, fn _step, idx ->
      %{
        step_index: idx,
        status: "pending",
        results: [],
        decision: nil
      }
    end)
  end
end
