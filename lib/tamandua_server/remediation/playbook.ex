defmodule TamanduaServer.Remediation.Playbook do
  @moduledoc """
  Enhanced Remediation Playbook Schema and Management

  Provides comprehensive automated remediation playbooks with:
  - 15+ action types
  - Approval workflows with tiers
  - Dry-run mode
  - Rollback capabilities
  - Conditional logic and parallel execution
  - Retry logic with exponential backoff
  - Comprehensive audit trails
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "remediation_playbooks" do
    field(:name, :string)
    field(:description, :string)
    field(:category, :string)
    field(:trigger_type, :string)
    field(:trigger_conditions, :map)
    field(:steps, {:array, :map})
    field(:enabled, :boolean, default: true)
    field(:require_approval, :boolean, default: false)
    field(:approval_tier, :string, default: "analyst")
    field(:approval_timeout_minutes, :integer, default: 30)
    field(:auto_rollback_on_failure, :boolean, default: false)
    field(:tags, {:array, :string}, default: [])
    field(:severity_threshold, :string)
    field(:risk_level, :string, default: "medium")
    field(:execution_count, :integer, default: 0)
    field(:success_count, :integer, default: 0)
    field(:failure_count, :integer, default: 0)
    field(:last_executed_at, :utc_datetime)
    field(:created_by, :binary_id)
    field(:version, :integer, default: 1)
    field(:is_template, :boolean, default: false)
    field(:organization_id, :binary_id)

    timestamps()
  end

  @doc """
  List of all supported remediation actions
  """
  @action_types [
    "isolate_network",
    "kill_process",
    "quarantine_file",
    "disable_user",
    "force_password_reset",
    "block_ip",
    "block_domain",
    "stop_service",
    "disable_service",
    "delete_registry_key",
    "delete_file",
    "reboot_agent",
    "deploy_patch",
    "revoke_certificate",
    "enforce_mfa",
    "terminate_session",
    "collect_forensics",
    "create_ticket",
    "send_notification",
    "run_script",
    "restore_file",
    "enable_user",
    "enable_service"
  ]

  @approval_tiers ["analyst", "senior_analyst", "manager", "security_director"]
  @risk_levels ["low", "medium", "high", "critical"]
  @severity_levels ["low", "medium", "high", "critical"]
  @trigger_types ["manual", "alert", "detection", "schedule", "api"]

  def changeset(playbook, attrs) do
    playbook
    |> cast(attrs, [
      :name,
      :description,
      :category,
      :trigger_type,
      :trigger_conditions,
      :steps,
      :enabled,
      :require_approval,
      :approval_tier,
      :approval_timeout_minutes,
      :auto_rollback_on_failure,
      :tags,
      :severity_threshold,
      :risk_level,
      :created_by,
      :version,
      :is_template,
      :organization_id
    ])
    |> validate_required([:name, :steps])
    |> validate_inclusion(:trigger_type, @trigger_types)
    |> validate_inclusion(:severity_threshold, [nil] ++ @severity_levels)
    |> validate_inclusion(:risk_level, @risk_levels)
    |> validate_inclusion(:approval_tier, @approval_tiers)
    |> validate_number(:approval_timeout_minutes, greater_than: 0, less_than: 1440)
    |> validate_steps()
  end

  defp validate_steps(changeset) do
    case get_change(changeset, :steps) do
      nil ->
        changeset

      steps when is_list(steps) ->
        if valid_steps?(steps) do
          changeset
        else
          add_error(changeset, :steps, "invalid step configuration")
        end

      _ ->
        add_error(changeset, :steps, "steps must be a list")
    end
  end

  defp valid_steps?(steps) do
    Enum.all?(steps, &valid_step?/1)
  end

  defp valid_step?(%{"action" => action} = _step) when is_binary(action) do
    # Validate action type
    action in @action_types or action in ["conditional", "parallel", "wait", "approval"]
  end

  defp valid_step?(_), do: false

  @doc """
  List all playbooks with optional filters
  """
  def list_playbooks(filters \\ %{}, scope \\ nil) do
    with_scope(scope, fn ->
      with {:ok, query} <- scoped_query(scope) do
        playbooks =
          query
          |> order_by([p], desc: p.inserted_at)
          |> apply_filters(filters)
          |> Repo.all()

        {:ok, playbooks}
      end
    end)
  end

  @doc """
  Get a playbook by ID
  """
  def get_playbook(id, scope \\ nil) do
    with_scope(scope, fn ->
      with {:ok, query} <- scoped_query(scope) do
        case Repo.one(from(p in query, where: p.id == ^id)) do
          nil -> {:error, :not_found}
          playbook -> {:ok, playbook}
        end
      end
    end)
  end

  @doc """
  Create a new playbook
  """
  def create_playbook(attrs, scope \\ nil) do
    with_scope(scope, fn ->
      with {:ok, scoped_attrs} <- scope_create_attrs(attrs, scope) do
        %__MODULE__{}
        |> changeset(scoped_attrs)
        |> Repo.insert()
      end
    end)
  end

  @doc """
  Update a playbook
  """
  def update_playbook(%__MODULE__{} = playbook, attrs, scope \\ nil) do
    with_scope(scope, fn ->
      with :ok <- authorize_resource(playbook, scope),
           {:ok, scoped_attrs} <- preserve_organization(attrs, playbook.organization_id) do
        playbook
        |> changeset(scoped_attrs)
        |> Repo.update()
      end
    end)
  end

  @doc """
  Delete a playbook
  """
  def delete_playbook(%__MODULE__{} = playbook, scope \\ nil) do
    with_scope(scope, fn ->
      with :ok <- authorize_resource(playbook, scope), do: Repo.delete(playbook)
    end)
  end

  @doc """
  Clone a playbook with a new name
  """
  def clone_playbook(%__MODULE__{} = playbook, new_name, user_id, scope \\ nil) do
    attrs = %{
      name: new_name,
      description: playbook.description,
      category: playbook.category,
      trigger_type: playbook.trigger_type,
      trigger_conditions: playbook.trigger_conditions,
      steps: playbook.steps,
      enabled: false,
      require_approval: playbook.require_approval,
      approval_tier: playbook.approval_tier,
      approval_timeout_minutes: playbook.approval_timeout_minutes,
      auto_rollback_on_failure: playbook.auto_rollback_on_failure,
      tags: playbook.tags,
      severity_threshold: playbook.severity_threshold,
      risk_level: playbook.risk_level,
      created_by: user_id,
      version: 1,
      is_template: false
    }

    with :ok <- authorize_resource(playbook, scope) do
      create_playbook(attrs, scope)
    end
  end

  @doc """
  List all supported action types
  """
  def list_action_types, do: @action_types

  @doc """
  List all approval tiers
  """
  def list_approval_tiers, do: @approval_tiers

  @doc """
  List all risk levels
  """
  def list_risk_levels, do: @risk_levels

  # Private Functions

  defp scoped_query({:organization, organization_id})
       when is_binary(organization_id) and organization_id != "" do
    {:ok, from(p in __MODULE__, where: p.organization_id == ^organization_id)}
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

  defp authorize_resource(%{organization_id: organization_id}, {:organization, organization_id})
       when is_binary(organization_id) and organization_id != "",
       do: :ok

  defp authorize_resource(_resource, {:organization, organization_id})
       when is_binary(organization_id) and organization_id != "",
       do: {:error, :not_found}

  defp authorize_resource(_resource, _scope), do: {:error, :tenant_required}

  defp preserve_organization(attrs, organization_id) when is_map(attrs),
    do: {:ok, put_attr(attrs, :organization_id, organization_id)}

  defp put_attr(attrs, key, value) do
    attrs
    |> Map.delete(key)
    |> Map.delete(Atom.to_string(key))
    |> Map.put(key, value)
  end

  defp apply_filters(query, filters) do
    Enum.reduce(filters, query, fn
      {:enabled, value}, q ->
        from(p in q, where: p.enabled == ^value)

      {:category, value}, q ->
        from(p in q, where: p.category == ^value)

      {:trigger_type, value}, q ->
        from(p in q, where: p.trigger_type == ^value)

      {:tag, value}, q ->
        from(p in q, where: ^value in p.tags)

      {:is_template, value}, q ->
        from(p in q, where: p.is_template == ^value)

      {:risk_level, value}, q ->
        from(p in q, where: p.risk_level == ^value)

      _, q ->
        q
    end)
  end
end
