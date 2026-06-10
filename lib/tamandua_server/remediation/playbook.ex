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

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "remediation_playbooks" do
    field :name, :string
    field :description, :string
    field :category, :string
    field :trigger_type, :string
    field :trigger_conditions, :map
    field :steps, {:array, :map}
    field :enabled, :boolean, default: true
    field :require_approval, :boolean, default: false
    field :approval_tier, :string, default: "analyst"
    field :approval_timeout_minutes, :integer, default: 30
    field :auto_rollback_on_failure, :boolean, default: false
    field :tags, {:array, :string}, default: []
    field :severity_threshold, :string
    field :risk_level, :string, default: "medium"
    field :execution_count, :integer, default: 0
    field :success_count, :integer, default: 0
    field :failure_count, :integer, default: 0
    field :last_executed_at, :utc_datetime
    field :created_by, :binary_id
    field :version, :integer, default: 1
    field :is_template, :boolean, default: false

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
      :is_template
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

  defp valid_step?(%{"action" => action} = step) when is_binary(action) do
    # Validate action type
    action in @action_types or action in ["conditional", "parallel", "wait", "approval"]
  end

  defp valid_step?(_), do: false

  @doc """
  List all playbooks with optional filters
  """
  def list_playbooks(filters \\ %{}) do
    query = from(p in __MODULE__, order_by: [desc: p.inserted_at])

    query
    |> apply_filters(filters)
    |> Repo.all()
  end

  @doc """
  Get a playbook by ID
  """
  def get_playbook(id) do
    Repo.get(__MODULE__, id)
  end

  @doc """
  Create a new playbook
  """
  def create_playbook(attrs) do
    %__MODULE__{}
    |> changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Update a playbook
  """
  def update_playbook(%__MODULE__{} = playbook, attrs) do
    playbook
    |> changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Delete a playbook
  """
  def delete_playbook(%__MODULE__{} = playbook) do
    Repo.delete(playbook)
  end

  @doc """
  Clone a playbook with a new name
  """
  def clone_playbook(%__MODULE__{} = playbook, new_name, user_id) do
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

    create_playbook(attrs)
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
