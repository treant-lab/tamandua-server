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
  alias TamanduaServer.Repo.MultiTenant
  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.Accounts.User
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Remediation.Playbook

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "remediation_executions" do
    field(:playbook_id, :binary_id)
    field(:playbook_name, :string)
    field(:playbook_version, :integer)
    field(:trigger_event, :map)
    field(:status, :string)
    field(:execution_mode, :string, default: "live")
    field(:steps_completed, :integer, default: 0)
    field(:steps_total, :integer, default: 0)
    field(:current_step_index, :integer, default: 0)
    field(:error_message, :string)
    field(:started_at, :utc_datetime)
    field(:completed_at, :utc_datetime)
    field(:execution_context, :map, default: %{})
    field(:execution_results, {:array, :map}, default: [])

    # Approval workflow fields
    field(:require_approval, :boolean, default: false)
    field(:approval_tier, :string)
    field(:approval_status, :string)
    field(:approved_by, :binary_id)
    field(:approved_at, :utc_datetime)
    field(:approval_comments, :string)
    field(:approval_timeout_minutes, :integer, default: 30)

    # Rollback fields
    field(:rollback_available, :boolean, default: false)
    field(:rollback_data, :map)
    field(:rolled_back, :boolean, default: false)
    field(:rolled_back_at, :utc_datetime)
    field(:rolled_back_by, :binary_id)

    # Metadata
    field(:triggered_by, :binary_id)
    field(:agent_id, :binary_id)
    field(:alert_id, :binary_id)
    field(:impact_assessment, :map)
    field(:organization_id, :binary_id)

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
      :approval_timeout_minutes,
      :rollback_available,
      :rollback_data,
      :rolled_back,
      :rolled_back_at,
      :rolled_back_by,
      :triggered_by,
      :agent_id,
      :alert_id,
      :impact_assessment,
      :organization_id
    ])
    |> validate_required([:playbook_id, :status])
    |> validate_inclusion(:status, @execution_statuses)
    |> validate_inclusion(:execution_mode, @execution_modes)
    |> validate_inclusion(:approval_status, [nil] ++ @approval_statuses)
  end

  @doc """
  List executions with optional filters
  """
  def list_executions(filters \\ %{}, scope \\ nil) do
    with_scope(scope, fn ->
      with {:ok, query} <- scoped_query(scope) do
        executions =
          query
          |> order_by([e], desc: e.inserted_at)
          |> apply_filters(filters)
          |> Repo.all()

        {:ok, executions}
      end
    end)
  end

  @doc """
  Get an execution by ID
  """
  def get_execution(id, scope \\ nil) do
    with_scope(scope, fn ->
      with {:ok, query} <- scoped_query(scope) do
        case Repo.one(from(e in query, where: e.id == ^id)) do
          nil -> {:error, :not_found}
          execution -> {:ok, execution}
        end
      end
    end)
  end

  @doc """
  Create a new execution record
  """
  def create_execution(attrs, scope \\ nil) do
    with_scope(scope, fn ->
      with {:ok, scoped_attrs} <- scope_create_attrs(attrs, scope),
           :ok <- validate_tenant_references(scoped_attrs, scope) do
        %__MODULE__{}
        |> changeset(scoped_attrs)
        |> Repo.insert()
      end
    end)
  end

  @doc """
  Update an execution record
  """
  def update_execution(%__MODULE__{} = execution, attrs, scope \\ nil) do
    with_scope(scope, fn ->
      with :ok <- authorize_resource(execution, scope),
           scoped_attrs <- preserve_resource_references(attrs, execution) do
        execution
        |> changeset(scoped_attrs)
        |> Repo.update()
      end
    end)
  end

  @doc """
  List pending approvals
  """
  def list_pending_approvals(scope \\ nil) do
    with_scope(scope, fn ->
      with {:ok, query} <- scoped_query(scope) do
        approvals =
          query
          |> where([e], e.status == "pending_approval" and e.approval_status == "pending")
          |> order_by([e], asc: e.inserted_at)
          |> Repo.all()

        {:ok, approvals}
      end
    end)
  end

  @doc """
  List active executions
  """
  def list_active_executions(scope \\ nil) do
    with_scope(scope, fn ->
      with {:ok, query} <- scoped_query(scope) do
        executions =
          query
          |> where([e], e.status in ["running", "paused"])
          |> order_by([e], desc: e.started_at)
          |> Repo.all()

        {:ok, executions}
      end
    end)
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

  defp scoped_query({:organization, organization_id})
       when is_binary(organization_id) and organization_id != "" do
    {:ok, from(e in __MODULE__, where: e.organization_id == ^organization_id)}
  end

  defp scoped_query(_scope), do: {:error, :tenant_required}

  defp with_scope({:organization, organization_id}, fun)
       when is_binary(organization_id) and organization_id != "",
       do: MultiTenant.with_organization(organization_id, fun)

  defp with_scope(_scope, _fun), do: {:error, :tenant_required}

  defp scope_create_attrs(attrs, {:organization, organization_id})
       when is_map(attrs) and is_binary(organization_id) and organization_id != "" do
    {:ok, put_attr(attrs, :organization_id, organization_id)}
  end

  defp scope_create_attrs(_attrs, _scope), do: {:error, :tenant_required}

  defp validate_tenant_references(attrs, {:organization, organization_id}) do
    playbook_id = value_from(attrs, :playbook_id)
    agent_id = value_from(attrs, :agent_id)
    alert_id = value_from(attrs, :alert_id)
    triggered_by = value_from(attrs, :triggered_by)

    cond do
      not scoped_resource_exists?(Playbook, playbook_id, organization_id) ->
        {:error, :not_found}

      agent_id && not scoped_resource_exists?(Agent, agent_id, organization_id) ->
        {:error, :unauthorized_agent}

      alert_id && not scoped_resource_exists?(Alert, alert_id, organization_id) ->
        {:error, :unauthorized_alert}

      triggered_by && not scoped_resource_exists?(User, triggered_by, organization_id) ->
        {:error, :unauthorized_actor}

      true ->
        :ok
    end
  end

  defp scoped_resource_exists?(_schema, nil, _organization_id), do: false

  defp scoped_resource_exists?(schema, id, organization_id) do
    Repo.exists?(
      from(resource in schema,
        where: resource.id == ^id and resource.organization_id == ^organization_id
      )
    )
  rescue
    _ -> false
  end

  defp authorize_resource(%{organization_id: organization_id}, {:organization, organization_id})
       when is_binary(organization_id) and organization_id != "",
       do: :ok

  defp authorize_resource(_resource, {:organization, organization_id})
       when is_binary(organization_id) and organization_id != "",
       do: {:error, :not_found}

  defp authorize_resource(_resource, _scope), do: {:error, :tenant_required}

  defp put_attr(attrs, key, value) when is_map(attrs) do
    attrs
    |> Map.delete(key)
    |> Map.delete(Atom.to_string(key))
    |> Map.put(key, value)
  end

  defp value_from(attrs, key), do: Map.get(attrs, key) || Map.get(attrs, Atom.to_string(key))

  defp preserve_resource_references(attrs, execution) when is_map(attrs) do
    attrs
    |> put_attr(:organization_id, execution.organization_id)
    |> put_attr(:playbook_id, execution.playbook_id)
    |> put_attr(:agent_id, execution.agent_id)
    |> put_attr(:alert_id, execution.alert_id)
    |> put_attr(:triggered_by, execution.triggered_by)
  end

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
