defmodule TamanduaServer.Audit.AuditLog do
  @moduledoc """
  Schema for audit logs tracking all system activities.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Organization, User}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec, updated_at: false]

  schema "audit_logs" do
    field :action, :string
    field :action_type, :string
    field :user_email, :string
    field :resource_type, :string
    field :resource_id, :string

    field :metadata, :map
    field :details, :map
    field :changes, :map

    field :ip_address, :string
    field :user_agent, :string
    field :request_id, :string

    field :success, :boolean
    field :error_message, :string

    field :severity, :string
    field :category, :string
    field :sequence_number, :integer
    field :entry_hash, :string
    field :previous_hash, :string

    field :suspicious, :boolean
    field :suspicious_reason, :string
    field :risk_score, :integer

    field :search_vector, :string, virtual: true

    belongs_to :user, User
    belongs_to :organization, Organization

    timestamps(type: :utc_datetime_usec, updated_at: false)
  end

  @required_fields ~w(action action_type resource_type organization_id)a
  @optional_fields ~w(
    user_id user_email resource_id metadata details changes ip_address user_agent request_id
    success error_message severity category sequence_number entry_hash previous_hash
    suspicious suspicious_reason risk_score
  )a

  @severities ~w(critical high medium low info)
  @categories ~w(
    authentication authorization data_access configuration
    alert_management agent_management user_management detection
    response investigation compliance security
  )

  def changeset(audit_log, attrs) do
    audit_log
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:severity, @severities)
    |> validate_inclusion(:category, @categories)
    |> validate_number(:risk_score, greater_than_or_equal_to: 0, less_than_or_equal_to: 100)
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:organization_id)
  end

  @doc """
  Returns all available action types.
  """
  def action_types do
    [
      # Authentication
      "auth.login_success",
      "auth.login_failed",
      "auth.logout",
      "auth.mfa_enabled",
      "auth.mfa_disabled",
      "auth.password_changed",
      "auth.password_reset_requested",
      "auth.token_created",
      "auth.token_revoked",
      # Authorization
      "authz.permission_granted",
      "authz.permission_denied",
      "authz.role_assigned",
      "authz.role_removed",
      # Alerts
      "alert.created",
      "alert.status_changed",
      "alert.assigned",
      "alert.escalated",
      "alert.commented",
      "alert.exported",
      "alert.deleted",
      # Agents
      "agent.registered",
      "agent.disconnected",
      "agent.config_updated",
      "agent.command_sent",
      "agent.isolation_enabled",
      "agent.isolation_disabled",
      "agent.uninstalled",
      # Users
      "user.created",
      "user.updated",
      "user.deleted",
      "user.activated",
      "user.deactivated",
      # Configuration
      "config.yara_rule_added",
      "config.yara_rule_updated",
      "config.yara_rule_deleted",
      "config.sigma_rule_added",
      "config.sigma_rule_updated",
      "config.sigma_rule_deleted",
      "config.setting_changed",
      # Detection
      "detection.rule_triggered",
      "detection.ml_prediction",
      "detection.ioc_matched",
      # Response
      "response.process_killed",
      "response.file_quarantined",
      "response.network_isolated",
      "response.script_executed",
      # Investigation
      "investigation.created",
      "investigation.updated",
      "investigation.closed",
      "investigation.evidence_added",
      # Data Access
      "data.logs_exported",
      "data.report_generated",
      "data.search_performed",
      "data.bulk_download",
      # Compliance
      "compliance.report_generated",
      "compliance.audit_requested",
      "compliance.retention_policy_applied",
      # Security
      "security.privilege_escalation_attempt",
      "security.suspicious_activity_detected",
      "security.brute_force_detected",
      "security.anomalous_access",
      # Dashboard WebSocket
      "dashboard.socket_connect",
      "dashboard.socket_disconnect",
      "dashboard.socket_auth_failed",
      "dashboard.channel_join",
      "dashboard.channel_leave",
      "dashboard.alert_acknowledged",
      "dashboard.alert_viewed",
      "dashboard.agent_viewed",
      "dashboard.events_streamed",
      "dashboard.geo_map_viewed"
    ]
  end

  def categories, do: @categories
  def severities, do: @severities
end
