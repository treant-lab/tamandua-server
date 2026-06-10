defmodule TamanduaServer.Accounts.Permission do
  @moduledoc """
  Schema for permissions.

  Permissions follow a resource:action pattern and are
  grouped into categories for easy management.

  ## Permission Categories

  Permissions are organized into the following categories:
  - Alerts: Alert management and response
  - Events: Telemetry and event access
  - Agents: Endpoint agent management
  - Investigations: Case and investigation management
  - Response: Incident response actions
  - Live Response: Interactive remote sessions
  - Hunting: Threat hunting capabilities
  - Detection: Rule management
  - Forensics: Evidence collection
  - Behavioral: UEBA features
  - Compliance: Compliance monitoring
  - Reports: Reporting capabilities
  - Dashboard: UI customization
  - Users: User account management
  - Roles: RBAC configuration
  - Organization: Tenant settings
  - System: Administrative functions
  - Threat Intel: IOC and feed management
  - Device Control: USB/device policies

  ## Permission Naming Convention

  Permissions use the pattern: `{category}_{action}`

  Common actions:
  - read: View/list resources
  - create: Create new resources
  - update: Modify existing resources
  - delete: Remove resources
  - manage: Full CRUD access
  - execute: Perform actions
  - approve: Authorize changes
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  # Permission definitions organized by resource
  @permission_definitions %{
    # Alert Management
    alerts: [
      {:alerts_read, "View alerts and alert details", :alerts},
      {:alerts_create, "Create manual alerts", :alerts},
      {:alerts_update, "Update alert status and fields", :alerts},
      {:alerts_delete, "Delete alerts", :alerts},
      {:alerts_assign, "Assign alerts to analysts", :alerts},
      {:alerts_comment, "Add comments to alerts", :alerts},
      {:alerts_acknowledge, "Acknowledge alerts", :alerts},
      {:alerts_resolve, "Resolve and close alerts", :alerts},
      {:alerts_respond, "Execute response actions on alerts", :alerts},
      {:alerts_bulk, "Perform bulk operations on alerts", :alerts},
      {:alerts_escalate, "Escalate alerts to higher tiers", :alerts},
      {:alerts_suppress, "Suppress false positive alerts", :alerts}
    ],

    # Event/Telemetry
    events: [
      {:events_read, "View security events", :events},
      {:events_search, "Search and query events", :events},
      {:events_export, "Export event data", :events},
      {:events_delete, "Delete events (data retention)", :events},
      {:events_correlate, "Create event correlations", :events}
    ],

    # Agent Management
    agents: [
      {:agents_read, "View agent status and details", :agents},
      {:agents_list, "List all agents", :agents},
      {:agents_create, "Register new agents", :agents},
      {:agents_update, "Update agent configuration", :agents},
      {:agents_delete, "Remove agents", :agents},
      {:agents_command, "Send commands to agents", :agents},
      {:agents_policy, "Manage agent policies", :agents},
      {:agents_group, "Manage agent groups", :agents},
      {:agents_isolate, "Network isolate agents", :agents},
      {:agents_unisolate, "Restore agent network access", :agents},
      {:agents_uninstall, "Remotely uninstall agents", :agents},
      {:agents_restart, "Restart agent service", :agents}
    ],

    # Investigation Management
    investigations: [
      {:investigations_read, "View investigations", :investigations},
      {:investigations_create, "Create new investigations", :investigations},
      {:investigations_update, "Update investigation details", :investigations},
      {:investigations_delete, "Delete investigations", :investigations},
      {:investigations_close, "Close investigations", :investigations},
      {:investigations_assign, "Assign investigations", :investigations},
      {:investigations_evidence, "Manage investigation evidence", :investigations},
      {:investigations_timeline, "Manage investigation timeline", :investigations}
    ],

    # Response Actions
    response: [
      {:response_view, "View response actions", :response},
      {:response_execute, "Execute response actions", :response},
      {:response_isolate, "Network isolate endpoints", :response},
      {:response_contain, "Contain threats (kill, quarantine)", :response},
      {:response_remediate, "Execute remediation playbooks", :response},
      {:response_approve, "Approve pending response actions", :response},
      {:response_rollback, "Rollback response actions", :response}
    ],

    # Live Response
    live_response: [
      {:live_response_access, "Access live response sessions", :live_response},
      {:live_response_file, "File operations in live response", :live_response},
      {:live_response_process, "Process operations in live response", :live_response},
      {:live_response_memory, "Memory operations in live response", :live_response},
      {:live_response_shell, "Execute shell commands (restricted)", :live_response},
      {:live_response_admin, "Full shell access (privileged)", :live_response}
    ],

    # Threat Hunting
    hunting: [
      {:hunting_read, "View saved hunts and results", :hunting},
      {:hunting_create, "Create new hunt queries", :hunting},
      {:hunting_execute, "Execute hunt queries", :hunting},
      {:hunting_save, "Save hunt queries", :hunting},
      {:hunting_schedule, "Schedule recurring hunts", :hunting},
      {:hunting_advanced, "Advanced hunting (custom queries)", :hunting},
      {:hunting_share, "Share hunt queries with team", :hunting}
    ],

    # Detection Rules
    detection: [
      {:detection_read, "View detection rules", :detection},
      {:detection_create, "Create detection rules", :detection},
      {:detection_update, "Modify detection rules", :detection},
      {:detection_delete, "Delete detection rules", :detection},
      {:detection_deploy, "Deploy rules to production", :detection},
      {:detection_test, "Test rules in sandbox", :detection},
      {:detection_import, "Import detection rules", :detection},
      {:detection_export, "Export detection rules", :detection}
    ],

    # Forensics
    forensics: [
      {:forensics_read, "View forensic data", :forensics},
      {:forensics_collect, "Collect forensic evidence", :forensics},
      {:forensics_advanced, "Advanced forensics (memory, disk)", :forensics},
      {:forensics_export, "Export forensic packages", :forensics},
      {:forensics_delete, "Delete forensic collections", :forensics}
    ],

    # Behavioral Analytics
    behavioral: [
      {:behavioral_read, "View behavioral profiles", :behavioral},
      {:behavioral_analyze, "Analyze entity behavior", :behavioral},
      {:behavioral_tune, "Tune behavioral baselines", :behavioral},
      {:behavioral_manage, "Manage behavioral rules", :behavioral}
    ],

    # Compliance
    compliance: [
      {:compliance_read, "View compliance posture", :compliance},
      {:compliance_assess, "Perform control assessments", :compliance},
      {:compliance_evidence, "Collect compliance evidence", :compliance},
      {:compliance_report, "Generate compliance reports", :compliance},
      {:compliance_export, "Export audit data", :compliance},
      {:compliance_configure, "Configure compliance frameworks", :compliance}
    ],

    # Reports
    reports: [
      {:reports_read, "View reports", :reports},
      {:reports_create, "Create reports", :reports},
      {:reports_schedule, "Schedule report generation", :reports},
      {:reports_export, "Export reports", :reports},
      {:reports_delete, "Delete reports", :reports},
      {:reports_share, "Share reports with others", :reports}
    ],

    # Dashboard
    dashboard: [
      {:dashboard_read, "View dashboards", :dashboard},
      {:dashboard_create, "Create custom dashboards", :dashboard},
      {:dashboard_update, "Modify dashboards", :dashboard},
      {:dashboard_delete, "Delete dashboards", :dashboard},
      {:dashboard_share, "Share dashboards", :dashboard}
    ],

    # User Management
    users: [
      {:users_read, "View user accounts", :users},
      {:users_create, "Create user accounts", :users},
      {:users_update, "Modify user accounts", :users},
      {:users_delete, "Delete user accounts", :users},
      {:users_role_assign, "Assign roles to users", :users},
      {:users_mfa_manage, "Manage user MFA settings", :users},
      {:users_password_reset, "Reset user passwords", :users},
      {:users_activate, "Activate/deactivate users", :users}
    ],

    # Role Management
    roles: [
      {:roles_read, "View roles", :roles},
      {:roles_create, "Create custom roles", :roles},
      {:roles_update, "Modify roles", :roles},
      {:roles_delete, "Delete custom roles", :roles},
      {:roles_clone, "Clone existing roles", :roles},
      {:roles_permissions, "Manage role permissions", :roles}
    ],

    # Organization/Tenant Management
    organization: [
      {:organization_read, "View organization settings", :organization},
      {:organization_update, "Update organization settings", :organization},
      {:organization_billing, "Manage billing and subscription", :organization},
      {:organization_integrations, "Manage integrations", :organization},
      {:organization_sso, "Configure SSO settings", :organization}
    ],

    # System Administration
    system: [
      {:system_settings, "Manage system settings", :system},
      {:system_audit, "View audit logs", :system},
      {:system_maintenance, "Perform maintenance operations", :system},
      {:system_api_keys, "Manage API keys", :system},
      {:system_backup, "Manage system backups", :system},
      {:system_all, "Super admin - all permissions", :system}
    ],

    # Threat Intelligence
    threat_intel: [
      {:threat_intel_read, "View threat intelligence", :threat_intel},
      {:threat_intel_add, "Add threat indicators", :threat_intel},
      {:threat_intel_manage, "Manage threat feeds", :threat_intel},
      {:threat_intel_export, "Export threat data", :threat_intel},
      {:threat_intel_integrate, "Configure TI integrations", :threat_intel}
    ],

    # Device Control
    device_control: [
      {:device_control_read, "View device policies", :device_control},
      {:device_control_manage, "Manage device policies", :device_control},
      {:device_control_approve, "Approve device exceptions", :device_control}
    ],

    # Inventory/Assets
    inventory: [
      {:inventory_read, "View asset inventory", :inventory},
      {:inventory_manage, "Manage assets", :inventory},
      {:inventory_scan, "Trigger asset scans", :inventory},
      {:inventory_delete, "Delete assets", :inventory}
    ],

    # Playbooks & Automation
    playbooks: [
      {:playbooks_read, "View playbooks", :playbooks},
      {:playbooks_create, "Create playbooks", :playbooks},
      {:playbooks_update, "Modify playbooks", :playbooks},
      {:playbooks_delete, "Delete playbooks", :playbooks},
      {:playbooks_execute, "Execute playbooks", :playbooks},
      {:playbooks_approve, "Approve playbook execution", :playbooks}
    ],

    # AI Features
    ai: [
      {:ai_query, "Use AI assistant", :ai},
      {:ai_investigate, "Use AI for investigations", :ai},
      {:ai_configure, "Configure AI settings", :ai}
    ]
  }

  schema "permissions" do
    field :name, :string
    field :slug, :string
    field :description, :string
    field :category, :string

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(name slug)a
  @optional_fields ~w(description category)a

  def changeset(permission, attrs) do
    permission
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> unique_constraint(:slug)
  end

  @doc """
  Returns all permission definitions grouped by category.
  """
  def definitions, do: @permission_definitions

  @doc """
  Returns a flat list of all permission atoms.
  """
  def all_permissions do
    @permission_definitions
    |> Enum.flat_map(fn {_category, perms} ->
      Enum.map(perms, fn {slug, _desc, _cat} -> slug end)
    end)
  end

  @doc """
  Get permissions by category.
  """
  def permissions_for_category(category) when is_atom(category) do
    Map.get(@permission_definitions, category, [])
    |> Enum.map(fn {slug, _desc, _cat} -> slug end)
  end

  @doc """
  Check if a permission slug is valid.
  """
  def valid_permission?(slug) when is_atom(slug) do
    slug in all_permissions()
  end

  def valid_permission?(_), do: false

  @doc """
  Get permission description.
  """
  def description(slug) when is_atom(slug) do
    @permission_definitions
    |> Enum.find_value(fn {_category, perms} ->
      Enum.find_value(perms, fn
        {^slug, desc, _cat} -> desc
        _ -> nil
      end)
    end)
  end

  @doc """
  Get all categories.
  """
  def categories do
    Map.keys(@permission_definitions)
  end
end
