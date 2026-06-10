defmodule TamanduaServer.Branding.EmailTemplate do
  @moduledoc """
  Schema for custom email templates.

  Organizations can customize email templates for:
  - Welcome emails
  - Alert notifications
  - Password reset
  - MFA setup
  - Report delivery
  - Weekly/monthly digests

  Templates support variable interpolation using {{variable}} syntax.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @template_types [
    :welcome,
    :alert_notification,
    :alert_digest,
    :password_reset,
    :mfa_setup,
    :report_delivery,
    :weekly_digest,
    :monthly_digest,
    :incident_report,
    :compliance_report,
    :user_invitation,
    :account_locked,
    :suspicious_login
  ]

  @derive {Jason.Encoder, only: [
    :id, :organization_id, :template_type, :name, :subject,
    :body_html, :body_text, :is_active, :inserted_at, :updated_at
  ]}

  schema "email_templates" do
    belongs_to :organization, Organization

    field :template_type, Ecto.Enum, values: @template_types
    field :name, :string
    field :subject, :string
    field :body_html, :string
    field :body_text, :string
    field :is_active, :boolean, default: true

    # Template metadata
    field :description, :string
    field :available_variables, {:array, :string}, default: []

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(organization_id template_type subject body_html)a
  @optional_fields ~w(name body_text is_active description available_variables)a

  @doc """
  Changeset for creating or updating an email template.
  """
  def changeset(template, attrs) do
    template
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:template_type, @template_types)
    |> validate_length(:subject, max: 500)
    |> validate_template_syntax(:subject)
    |> validate_template_syntax(:body_html)
    |> validate_template_syntax(:body_text)
    |> unique_constraint([:organization_id, :template_type])
    |> foreign_key_constraint(:organization_id)
    |> set_available_variables()
  end

  defp validate_template_syntax(changeset, field) do
    case get_change(changeset, field) do
      nil ->
        changeset

      value when is_binary(value) ->
        # Check for unclosed template tags
        open_count = length(Regex.scan(~r/\{\{/, value))
        close_count = length(Regex.scan(~r/\}\}/, value))

        if open_count == close_count do
          changeset
        else
          add_error(changeset, field, "has unclosed template tags")
        end

      _ ->
        changeset
    end
  end

  defp set_available_variables(changeset) do
    # Extract variables from template fields
    subject = get_field(changeset, :subject) || ""
    body_html = get_field(changeset, :body_html) || ""
    body_text = get_field(changeset, :body_text) || ""

    all_content = subject <> body_html <> body_text

    variables = Regex.scan(~r/\{\{([a-zA-Z_][a-zA-Z0-9_]*)\}\}/, all_content)
    |> Enum.map(fn [_, var] -> var end)
    |> Enum.uniq()
    |> Enum.sort()

    put_change(changeset, :available_variables, variables)
  end

  @doc """
  Returns the list of valid template types.
  """
  def template_types, do: @template_types

  @doc """
  Returns the default variables available for each template type.
  """
  def default_variables(:welcome) do
    ["user_name", "user_email", "company_name", "logo_url", "login_url",
     "primary_color", "support_email"]
  end

  def default_variables(:alert_notification) do
    ["user_name", "company_name", "logo_url", "primary_color", "support_email",
     "alert_id", "alert_title", "alert_description", "severity", "severity_color",
     "agent_hostname", "agent_id", "alert_time", "alert_url", "mitre_technique"]
  end

  def default_variables(:alert_digest) do
    ["user_name", "company_name", "logo_url", "primary_color",
     "digest_period", "total_alerts", "critical_count", "high_count",
     "medium_count", "low_count", "top_alerts", "dashboard_url"]
  end

  def default_variables(:password_reset) do
    ["user_name", "user_email", "company_name", "logo_url",
     "reset_url", "expiry_hours", "primary_color", "support_email"]
  end

  def default_variables(:mfa_setup) do
    ["user_name", "company_name", "logo_url", "setup_url",
     "primary_color", "support_email"]
  end

  def default_variables(:report_delivery) do
    ["user_name", "company_name", "logo_url", "report_name",
     "report_type", "report_period", "download_url", "primary_color"]
  end

  def default_variables(:incident_report) do
    ["user_name", "company_name", "logo_url", "incident_id",
     "incident_title", "incident_summary", "affected_assets",
     "timeline_summary", "report_url", "primary_color"]
  end

  def default_variables(_), do: ["user_name", "company_name", "logo_url", "primary_color", "support_email"]

  @doc """
  Returns a description for each template type.
  """
  def template_description(:welcome), do: "Sent to new users when their account is created"
  def template_description(:alert_notification), do: "Real-time alert notifications"
  def template_description(:alert_digest), do: "Periodic summary of alerts"
  def template_description(:password_reset), do: "Password reset request emails"
  def template_description(:mfa_setup), do: "Two-factor authentication setup instructions"
  def template_description(:report_delivery), do: "Automated report delivery emails"
  def template_description(:weekly_digest), do: "Weekly security summary"
  def template_description(:monthly_digest), do: "Monthly security summary"
  def template_description(:incident_report), do: "Incident investigation reports"
  def template_description(:compliance_report), do: "Compliance assessment reports"
  def template_description(:user_invitation), do: "Invitations for new users"
  def template_description(:account_locked), do: "Account lockout notifications"
  def template_description(:suspicious_login), do: "Suspicious login activity alerts"
  def template_description(_), do: "Custom email template"
end
