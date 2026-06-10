defmodule TamanduaServer.Remediation.Workflow do
  @moduledoc """
  Remediation workflow schema - tracks the state and execution of remediation actions.

  ## States

  - `pending` - Workflow created, waiting to start (or waiting for approval)
  - `in_progress` - Action is being executed
  - `completed` - Action completed successfully
  - `failed` - Action failed after all retries
  - `cancelled` - Workflow was manually cancelled

  ## Execution Modes

  - `auto` - Execute immediately without approval
  - `queued` - Queue for execution, auto-approve after timeout
  - `pending_approval` - Require explicit human approval
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Remediation.{WorkflowMachine, Notifier, AuditTrail}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  @states ~w(pending in_progress completed failed cancelled)
  @execution_modes ~w(auto queued pending_approval)

  schema "remediation_workflows" do
    field :state, :string, default: "pending"
    field :previous_state, :string
    field :execution_mode, :string

    field :action_type, :string
    field :action_config, :map, default: %{}

    field :started_at, :utc_datetime_usec
    field :completed_at, :utc_datetime_usec
    field :failed_at, :utc_datetime_usec
    field :cancelled_at, :utc_datetime_usec

    field :result, :map, default: %{}
    field :error_message, :string
    field :retry_count, :integer, default: 0

    field :approved_at, :utc_datetime_usec
    field :approval_notes, :string

    field :oban_job_id, :integer

    # Escalation fields
    field :escalation_level, :integer, default: 0
    field :escalation_timeout_minutes, :integer, default: 60
    field :last_escalated_at, :utc_datetime_usec

    belongs_to :alert, TamanduaServer.Alerts.Alert
    belongs_to :policy, TamanduaServer.Remediation.Policy
    belongs_to :organization, TamanduaServer.Accounts.Organization
    belongs_to :approved_by, TamanduaServer.Accounts.User

    timestamps()
  end

  @doc false
  def changeset(workflow, attrs) do
    workflow
    |> cast(attrs, [
      :state, :previous_state, :execution_mode, :action_type, :action_config,
      :started_at, :completed_at, :failed_at, :cancelled_at,
      :result, :error_message, :retry_count,
      :approved_at, :approved_by_id, :approval_notes, :oban_job_id,
      :escalation_level, :escalation_timeout_minutes, :last_escalated_at,
      :alert_id, :policy_id, :organization_id
    ])
    |> validate_required([:execution_mode, :action_type])
    |> validate_inclusion(:state, @states)
    |> validate_inclusion(:execution_mode, @execution_modes)
    |> foreign_key_constraint(:alert_id)
    |> foreign_key_constraint(:policy_id)
    |> foreign_key_constraint(:organization_id)
  end

  @doc "Changeset for state transitions"
  def transition_changeset(workflow, new_state, attrs \\ %{}) do
    now = DateTime.utc_now()

    timestamp_field = case new_state do
      "in_progress" -> :started_at
      "completed" -> :completed_at
      "failed" -> :failed_at
      "cancelled" -> :cancelled_at
      _ -> nil
    end

    attrs = attrs
      |> Map.put(:previous_state, workflow.state)
      |> Map.put(:state, new_state)
      |> then(fn a -> if timestamp_field, do: Map.put(a, timestamp_field, now), else: a end)

    changeset(workflow, attrs)
  end

  # === Context Functions ===

  @doc "Create a new workflow"
  def create_workflow(attrs) do
    case %__MODULE__{}
         |> changeset(attrs)
         |> Repo.insert() do
      {:ok, workflow} = result ->
        # Log audit event for creation
        Task.start(fn ->
          try do
            AuditTrail.log_event(workflow, :created, :system, %{
              execution_mode: workflow.execution_mode,
              action_type: workflow.action_type
            })
          rescue
            _ -> :ok
          end
        end)

        # Notify on creation (async)
        Task.start(fn ->
          try do
            Notifier.notify_workflow_created(workflow)

            # If pending approval, send approval request
            if workflow.execution_mode == "pending_approval" do
              Notifier.notify_approval_requested(workflow)
            end
          rescue
            e ->
              require Logger
              Logger.error("[Workflow] Failed to send workflow notification: #{inspect(e)}")
          end
        end)

        result

      error ->
        error
    end
  end

  @doc "Get a workflow by ID"
  def get_workflow!(id), do: Repo.get!(__MODULE__, id)

  @doc "Get a workflow by ID, returns {:ok, workflow} or {:error, :not_found}"
  def get_workflow(id) do
    case Repo.get(__MODULE__, id) do
      nil -> {:error, :not_found}
      workflow -> {:ok, workflow}
    end
  end

  @doc "List workflows with filters"
  def list_workflows(opts \\ []) do
    organization_id = Keyword.get(opts, :organization_id)
    state = Keyword.get(opts, :state)
    alert_id = Keyword.get(opts, :alert_id)
    limit = Keyword.get(opts, :limit, 100)

    from(w in __MODULE__, order_by: [desc: w.inserted_at], limit: ^limit)
    |> maybe_filter(:organization_id, organization_id)
    |> maybe_filter(:state, state)
    |> maybe_filter(:alert_id, alert_id)
    |> Repo.all()
  end

  @doc "Get workflows pending approval"
  def list_pending_approval(opts \\ []) do
    organization_id = Keyword.get(opts, :organization_id)

    from(w in __MODULE__,
      where: w.state == "pending" and w.execution_mode == "pending_approval",
      order_by: [asc: w.inserted_at]
    )
    |> maybe_filter(:organization_id, organization_id)
    |> Repo.all()
  end

  @doc "Transition workflow to a new state"
  def transition_state(%__MODULE__{} = workflow, new_state, attrs \\ %{}) do
    with :ok <- WorkflowMachine.can_transition?(workflow.state, new_state) do
      case workflow
           |> transition_changeset(new_state, attrs)
           |> Repo.update() do
        {:ok, updated_workflow} ->
          # Log audit event for state transition
          actor = Map.get(attrs, :actor, :system)
          event_type = state_to_event_type(new_state)
          audit_details = Map.drop(attrs, [:actor])

          Task.start(fn ->
            try do
              AuditTrail.log_event(updated_workflow, event_type, actor, audit_details)
            rescue
              _ -> :ok
            end
          end)

          # Trigger notification based on new state (async)
          notify_state_change(updated_workflow, new_state)
          {:ok, updated_workflow}

        {:error, changeset} = error ->
          error
      end
    end
  end

  # Map state transitions to audit event types
  defp state_to_event_type("in_progress"), do: :started
  defp state_to_event_type("completed"), do: :completed
  defp state_to_event_type("failed"), do: :failed
  defp state_to_event_type("cancelled"), do: :cancelled
  defp state_to_event_type(_), do: :started

  # Async notification dispatch for state transitions
  defp notify_state_change(workflow, new_state) do
    Task.start(fn ->
      try do
        case new_state do
          "in_progress" -> Notifier.notify_workflow_started(workflow)
          "completed" -> Notifier.notify_workflow_completed(workflow)
          "failed" -> Notifier.notify_workflow_failed(workflow)
          _ -> :ok
        end
      rescue
        e ->
          require Logger
          Logger.error("[Workflow] Failed to send workflow notification: #{inspect(e)}")
      end
    end)

    :ok
  end

  @doc "Update workflow with Oban job ID"
  def set_oban_job_id(%__MODULE__{} = workflow, job_id) do
    workflow
    |> changeset(%{oban_job_id: job_id})
    |> Repo.update()
  end

  @doc "Increment retry count"
  def increment_retry(%__MODULE__{} = workflow) do
    workflow
    |> changeset(%{retry_count: workflow.retry_count + 1})
    |> Repo.update()
  end

  @doc "Get valid states"
  def states, do: @states

  @doc "Get valid execution modes"
  def execution_modes, do: @execution_modes

  # === Aggregate Query Functions (for Dashboard) ===

  @doc """
  Count workflows by state for an organization.

  Returns a map of state => count.

  ## Examples

      Workflow.count_by_state(org_id)
      # => %{"pending" => 5, "in_progress" => 2, "completed" => 45, "failed" => 3}
  """
  def count_by_state(organization_id) do
    from(w in __MODULE__,
      where: w.organization_id == ^organization_id,
      group_by: w.state,
      select: {w.state, count(w.id)}
    )
    |> Repo.all()
    |> Map.new()
  end

  @doc """
  Count pending approval workflows for an organization.

  ## Examples

      Workflow.count_pending_approvals(org_id)
      # => 5
  """
  def count_pending_approvals(organization_id) do
    from(w in __MODULE__,
      where: w.organization_id == ^organization_id,
      where: w.state == "pending",
      where: w.execution_mode == "pending_approval",
      select: count(w.id)
    )
    |> Repo.one()
  end

  @doc """
  List recent workflows with preloaded associations.

  ## Options

  - `:limit` - Maximum number of workflows (default: 20)

  ## Examples

      Workflow.list_recent(org_id, limit: 10)
  """
  def list_recent(organization_id, limit \\ 20) do
    from(w in __MODULE__,
      where: w.organization_id == ^organization_id,
      order_by: [desc: w.updated_at],
      limit: ^limit,
      preload: [:alert, :policy]
    )
    |> Repo.all()
  end

  @doc """
  Reject a pending approval workflow.

  Transitions workflow to cancelled state with rejection reason.

  ## Examples

      Workflow.reject_workflow(workflow_id, user_id, "False positive - not a real threat")
  """
  def reject_workflow(workflow_id, user_id, reason) do
    with {:ok, workflow} <- get_workflow(workflow_id),
         :ok <- validate_pending_approval(workflow) do
      workflow
      |> transition_changeset("cancelled", %{
        approval_notes: reason,
        approved_by_id: user_id,
        actor: user_id
      })
      |> Repo.update()
      |> case do
        {:ok, updated} = result ->
          # Log rejection audit event
          Task.start(fn ->
            try do
              AuditTrail.log_event(updated, :rejected, user_id, %{reason: reason})
            rescue
              _ -> :ok
            end
          end)

          # Send rejection notification
          Task.start(fn ->
            try do
              preloaded = Repo.preload(updated, [:alert, :policy, :organization, :approved_by])
              Notifier.notify_workflow_rejected(preloaded)
            rescue
              _ -> :ok
            end
          end)

          result

        error ->
          error
      end
    end
  end

  defp validate_pending_approval(%__MODULE__{state: "pending", execution_mode: "pending_approval"}), do: :ok
  defp validate_pending_approval(_), do: {:error, :not_pending_approval}

  defp maybe_filter(query, _field, nil), do: query
  defp maybe_filter(query, field, value), do: where(query, [w], field(w, ^field) == ^value)
end
