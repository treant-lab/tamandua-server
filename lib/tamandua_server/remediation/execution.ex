defmodule TamanduaServer.Remediation.Execution do
  @moduledoc """
  Remediation Playbook Execution Record Schema

  Tracks the execution of remediation playbooks including:
  - Execution status and progress
  - Approval workflow state
  - Step-by-step execution history
  - Rollback state
  - Dry-run simulation results
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Repo

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "remediation_executions" do
    field :playbook_id, :binary_id
    field :playbook_name, :string
    field :playbook_version, :integer
    field :trigger_event, :map
    field :status, :string
    field :execution_mode, :string, default: "live"
    field :steps_completed, :integer, default: 0
    field :steps_total, :integer, default: 0
    field :current_step_index, :integer, default: 0
    field :error_message, :string
    field :started_at, :utc_datetime
    field :completed_at, :utc_datetime
    field :execution_context, :map, default: %{}
    field :execution_results, {:array, :map}, default: []

    # Approval workflow fields
    field :require_approval, :boolean, default: false
    field :approval_tier, :string
    field :approval_status, :string
    field :approved_by, :binary_id
    field :approved_at, :utc_datetime
    field :approval_comments, :string

    # Rollback fields
    field :rollback_available, :boolean, default: false
    field :rollback_data, :map
    field :rolled_back, :boolean, default: false
    field :rolled_back_at, :utc_datetime
    field :rolled_back_by, :binary_id

    # Metadata
    field :triggered_by, :binary_id
    field :agent_id, :binary_id
    field :alert_id, :binary_id
    field :impact_assessment, :map

    timestamps()
  end

  @execution_statuses [
    "pending_approval",
    "approved",
    "running",
    "paused",
    "completed",
    "failed",
    "cancelled",
    "rolled_back"
  ]

  @execution_modes ["live", "dry_run", "simulation"]
  @approval_statuses ["pending", "approved", "rejected", "expired"]

  def changeset(execution, attrs) do
    execution
    |> cast(attrs, [
      :playbook_id,
      :playbook_name,
      :playbook_version,
      :trigger_event,
      :status,
      :execution_mode,
      :steps_completed,
      :steps_total,
      :current_step_index,
      :error_message,
      :started_at,
      :completed_at,
      :execution_context,
      :execution_results,
      :require_approval,
      :approval_tier,
      :approval_status,
      :approved_by,
      :approved_at,
      :approval_comments,
      :rollback_available,
      :rollback_data,
      :rolled_back,
      :rolled_back_at,
      :rolled_back_by,
      :triggered_by,
      :agent_id,
      :alert_id,
      :impact_assessment
    ])
    |> validate_required([:playbook_id, :status])
    |> validate_inclusion(:status, @execution_statuses)
    |> validate_inclusion(:execution_mode, @execution_modes)
    |> validate_inclusion(:approval_status, [nil] ++ @approval_statuses)
  end

  @doc """
  List executions with optional filters
  """
  def list_executions(filters \\ %{}) do
    query = from(e in __MODULE__, order_by: [desc: e.inserted_at])

    query
    |> apply_filters(filters)
    |> Repo.all()
  end

  @doc """
  Get an execution by ID
  """
  def get_execution(id) do
    Repo.get(__MODULE__, id)
  end

  @doc """
  Create a new execution record
  """
  def create_execution(attrs) do
    %__MODULE__{}
    |> changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Update an execution record
  """
  def update_execution(%__MODULE__{} = execution, attrs) do
    execution
    |> changeset(attrs)
    |> Repo.update()
  end

  @doc """
  List pending approvals
  """
  def list_pending_approvals do
    from(e in __MODULE__,
      where: e.status == "pending_approval" and e.approval_status == "pending",
      order_by: [asc: e.inserted_at]
    )
    |> Repo.all()
  end

  @doc """
  List active executions
  """
  def list_active_executions do
    from(e in __MODULE__,
      where: e.status in ["running", "paused"],
      order_by: [desc: e.started_at]
    )
    |> Repo.all()
  end

  @doc """
  Calculate execution progress percentage
  """
  def calculate_progress(%__MODULE__{} = execution) do
    if execution.steps_total > 0 do
      (execution.steps_completed / execution.steps_total * 100)
      |> Float.round(1)
    else
      0.0
    end
  end

  @doc """
  Calculate execution duration in seconds
  """
  def calculate_duration(%__MODULE__{} = execution) do
    cond do
      execution.completed_at && execution.started_at ->
        DateTime.diff(execution.completed_at, execution.started_at, :second)

      execution.started_at ->
        DateTime.diff(DateTime.utc_now(), execution.started_at, :second)

      true ->
        0
    end
  end

  # Private Functions

  defp apply_filters(query, filters) do
    Enum.reduce(filters, query, fn
      {:playbook_id, value}, q ->
        from(e in q, where: e.playbook_id == ^value)

      {:status, value}, q ->
        from(e in q, where: e.status == ^value)

      {:execution_mode, value}, q ->
        from(e in q, where: e.execution_mode == ^value)

      {:agent_id, value}, q ->
        from(e in q, where: e.agent_id == ^value)

      {:alert_id, value}, q ->
        from(e in q, where: e.alert_id == ^value)

      {:triggered_by, value}, q ->
        from(e in q, where: e.triggered_by == ^value)

      {:date_from, value}, q ->
        from(e in q, where: e.inserted_at >= ^value)

      {:date_to, value}, q ->
        from(e in q, where: e.inserted_at <= ^value)

      _, q ->
        q
    end)
  end
end
