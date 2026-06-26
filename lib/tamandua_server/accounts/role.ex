defmodule TamanduaServer.Accounts.Role do
  @moduledoc """
  Schema for roles with fine-grained permissions.

  Roles are organization-scoped and define what actions
  users can perform on specific resources.

  ## Role Hierarchy

  Roles have a priority-based hierarchy where higher priority roles
  inherit permissions from lower priority roles if configured:

  - admin (100) - Full system access
  - manager (90) - Team management + analyst permissions
  - hunter (80) - Threat hunting + analyst permissions
  - responder (70) - Incident response + analyst permissions
  - analyst (50) - Security analysis + viewer permissions
  - compliance_officer (40) - Compliance focus + viewer permissions
  - viewer (10) - Read-only access
  - api_only (5) - Programmatic access only

  ## Permission Inheritance

  Roles can optionally inherit from a parent role, allowing for
  hierarchical permission structures without duplication.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Permission, RolePermission, UserRole}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @builtin_roles ~w(admin manager analyst viewer responder hunter compliance_officer api_only)

  # Role hierarchy levels (higher = more permissions)
  @role_hierarchy %{
    "admin" => 100,
    "manager" => 90,
    "hunter" => 80,
    "responder" => 70,
    "analyst" => 50,
    "compliance_officer" => 40,
    "viewer" => 10,
    "api_only" => 5
  }

  # Role templates for quick creation
  @role_templates %{
    "security_analyst" => %{
      name: "Security Analyst",
      description: "Security analyst with investigation capabilities",
      permissions: [:alerts_read, :alerts_update, :alerts_assign, :alerts_comment,
                    :events_read, :events_search, :agents_read, :agents_list,
                    :hunting_read, :hunting_execute, :hunting_save,
                    :detection_read, :detection_test, :forensics_read,
                    :forensics_collect, :behavioral_read, :behavioral_analyze,
                    :reports_read, :reports_create, :dashboard_read]
    },
    "incident_responder" => %{
      name: "Incident Responder",
      description: "Incident response specialist with containment capabilities",
      permissions: [:alerts_read, :alerts_update, :alerts_assign, :alerts_respond,
                    :events_read, :events_search, :agents_read, :agents_command,
                    :response_execute, :response_isolate, :response_contain,
                    :live_response_access, :live_response_file, :live_response_process,
                    :forensics_read, :forensics_collect, :forensics_advanced,
                    :dashboard_read]
    },
    "threat_hunter" => %{
      name: "Threat Hunter",
      description: "Proactive threat hunter with advanced query capabilities",
      permissions: [:alerts_read, :events_read, :events_search, :events_export,
                    :agents_read, :hunting_read, :hunting_create, :hunting_execute,
                    :hunting_save, :hunting_schedule, :hunting_advanced,
                    :detection_read, :detection_create, :detection_update,
                    :detection_test, :behavioral_read, :behavioral_analyze,
                    :threat_intel_read, :dashboard_read]
    },
    "soc_manager" => %{
      name: "SOC Manager",
      description: "Security operations center manager",
      permissions: [:alerts_read, :alerts_update, :alerts_assign, :alerts_bulk,
                    :events_read, :events_search, :agents_read, :agents_list,
                    :agents_policy, :agents_group, :response_approve,
                    :detection_read, :detection_deploy, :users_read,
                    :users_role_assign, :roles_read, :reports_read,
                    :reports_create, :reports_schedule, :dashboard_read,
                    :dashboard_create, :dashboard_share]
    },
    "compliance_auditor" => %{
      name: "Compliance Auditor",
      description: "Compliance-focused read-only with reporting",
      permissions: [:alerts_read, :events_read, :agents_read, :compliance_read,
                    :compliance_assess, :compliance_evidence, :compliance_report,
                    :compliance_export, :reports_read, :reports_create,
                    :reports_export, :system_audit, :dashboard_read]
    },
    "read_only" => %{
      name: "Read Only",
      description: "View-only access to dashboards and reports",
      permissions: [:alerts_read, :events_read, :agents_read, :detection_read,
                    :compliance_read, :reports_read, :dashboard_read]
    }
  }

  schema "roles" do
    field :name, :string
    field :slug, :string
    field :description, :string
    field :builtin, :boolean, default: false
    field :priority, :integer, default: 0
    field :api_only, :boolean, default: false
    field :inherit_from_id, :binary_id
    field :color, :string, default: "#6366f1"  # For UI display

    belongs_to :organization, TamanduaServer.Accounts.Organization
    belongs_to :inherit_from, __MODULE__, foreign_key: :inherit_from_id, define_field: false

    has_many :role_permissions, RolePermission, on_delete: :delete_all
    has_many :permissions, through: [:role_permissions, :permission]
    has_many :user_roles, UserRole, on_delete: :delete_all
    has_many :users, through: [:user_roles, :user]

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(name slug)a
  @optional_fields ~w(description builtin priority organization_id api_only inherit_from_id color)a

  def changeset(role, attrs) do
    role
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_format(:slug, ~r/^[a-z0-9_-]+$/)
    |> validate_format(:color, ~r/^#[0-9a-fA-F]{6}$/)
    |> unique_constraint([:organization_id, :slug])
    |> validate_not_modifying_builtin()
    |> validate_no_circular_inheritance()
  end

  defp validate_not_modifying_builtin(changeset) do
    if get_field(changeset, :builtin) && changed?(changeset, :slug) do
      add_error(changeset, :slug, "cannot modify slug of builtin role")
    else
      changeset
    end
  end

  defp validate_no_circular_inheritance(changeset) do
    # Prevent circular inheritance chains
    inherit_from_id = get_field(changeset, :inherit_from_id)
    role_id = get_field(changeset, :id)

    if inherit_from_id && inherit_from_id == role_id do
      add_error(changeset, :inherit_from_id, "role cannot inherit from itself")
    else
      changeset
    end
  end

  def builtin_roles, do: @builtin_roles
  def role_hierarchy, do: @role_hierarchy
  def role_templates, do: @role_templates

  @doc """
  Get the hierarchy level for a role slug.
  """
  def hierarchy_level(slug) when is_binary(slug) do
    Map.get(@role_hierarchy, slug, 0)
  end

  @doc """
  Check if role_a outranks role_b based on hierarchy.
  """
  def outranks?(role_a, role_b) when is_binary(role_a) and is_binary(role_b) do
    hierarchy_level(role_a) > hierarchy_level(role_b)
  end

  @doc """
  Get a role template by name.
  """
  def get_template(name) when is_binary(name) do
    Map.get(@role_templates, name)
  end

  @doc """
  List all available role templates.
  """
  def list_templates do
    @role_templates
    |> Enum.map(fn {key, value} ->
      Map.merge(value, %{key: key})
    end)
  end

  @doc """
  Default permission sets for builtin roles.
  """
  def default_permissions(:admin) do
    # Admin has all permissions
    Permission.all_permissions()
  end

  def default_permissions(:analyst) do
    [
      # Alerts
      :alerts_read, :alerts_update, :alerts_assign, :alerts_comment,
      # Events
      :events_read, :events_search,
      # Agents
      :agents_read, :agents_list,
      # Hunting
      :hunting_read, :hunting_execute, :hunting_save,
      # Detection
      :detection_read, :detection_test,
      # Forensics
      :forensics_read, :forensics_collect,
      # Behavioral
      :behavioral_read, :behavioral_analyze,
      # Compliance
      :compliance_read,
      # Reports
      :reports_read, :reports_create,
      # Dashboard
      :dashboard_read,
      # App Guard / research review
      :app_guard_apps_read, :app_guard_builds_read, :app_guard_events_read,
      :research_programs_read, :research_submissions_read, :research_submissions_validate
    ]
  end

  def default_permissions(:viewer) do
    [
      :alerts_read,
      :events_read,
      :agents_read,
      :detection_read,
      :compliance_read,
      :reports_read,
      :app_guard_apps_read,
      :app_guard_events_read,
      :research_programs_read,
      :dashboard_read
    ]
  end

  def default_permissions(:responder) do
    default_permissions(:analyst) ++ [
      :alerts_respond,
      :response_execute,
      :response_isolate,
      :response_contain,
      :live_response_access,
      :agents_command
    ]
  end

  def default_permissions(:hunter) do
    default_permissions(:analyst) ++ [
      :hunting_create,
      :hunting_advanced,
      :detection_create,
      :detection_update,
      :detection_deploy,
      :forensics_advanced
    ]
  end

  def default_permissions(:compliance_officer) do
    [
      :compliance_read, :compliance_assess, :compliance_report,
      :compliance_evidence, :compliance_export,
      :reports_read, :reports_create, :reports_export,
      :alerts_read,
      :dashboard_read
    ]
  end

  def default_permissions(:manager) do
    # Manager has analyst permissions plus team management
    default_permissions(:analyst) ++ [
      # User management
      :users_read, :users_create, :users_update, :users_role_assign,
      # Role management (read only)
      :roles_read,
      # Response approval
      :response_approve,
      # Detection deployment
      :detection_deploy,
      # Reports
      :reports_create, :reports_schedule, :reports_share,
      # Dashboard management
      :dashboard_create, :dashboard_share,
      # Playbooks
      :playbooks_read, :playbooks_execute, :playbooks_approve,
      # App Guard / research program ownership
      :app_guard_apps_read, :app_guard_apps_create, :app_guard_apps_update,
      :app_guard_builds_read, :app_guard_events_read,
      :app_guard_policy_read, :app_guard_policy_update,
      :research_programs_read, :research_programs_create, :research_programs_update,
      :research_submissions_read, :research_submissions_validate,
      :research_rewards_manage
    ]
  end

  def default_permissions(:api_only) do
    [
      # API-only role has programmatic access for integrations
      :alerts_read, :alerts_update,
      :events_read, :events_search,
      :agents_read, :agents_list,
      :detection_read,
      :threat_intel_read,
      :reports_read,
      :app_guard_events_ingest,
      :research_submissions_create,
      # System API access
      :system_api_keys
    ]
  end

  def default_permissions(_), do: []
end
