defmodule TamanduaServer.Licensing.FeatureLicense do
  @moduledoc """
  Schema for individual feature licensing.

  Allows granular control over which features are enabled
  beyond the base tier. Useful for:
  - Add-on features
  - Beta features
  - Custom enterprise packages
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @features ~w(
    detection
    dashboards
    alerts
    basic_response
    hunting
    behavioral_analytics
    playbooks
    api_access
    custom_integrations
    sso
    advanced_forensics
    live_response
    compliance
    mssp_portal
    white_labeling
    sub_licensing
    ai_assistant
    threat_intel_premium
    cloud_security
    container_security
    deception
    xdr
  )

  schema "feature_licenses" do
    belongs_to :organization, Organization

    field :feature, :string
    field :enabled, :boolean, default: true
    field :expires_at, :utc_datetime_usec
    field :quota, :integer  # Optional usage quota for the feature
    field :metadata, :map, default: %{}

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(organization_id feature)a
  @optional_fields ~w(enabled expires_at quota metadata)a

  def changeset(license, attrs) do
    license
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:feature, @features)
    |> unique_constraint([:organization_id, :feature])
    |> foreign_key_constraint(:organization_id)
  end

  @doc """
  Returns the list of available features.
  """
  def features, do: @features

  @doc """
  Returns feature descriptions.
  """
  def feature_description(feature) do
    descriptions = %{
      "detection" => "Real-time threat detection with YARA and Sigma rules",
      "dashboards" => "Security dashboards and visualizations",
      "alerts" => "Alert management and notifications",
      "basic_response" => "Basic response actions (kill, quarantine)",
      "hunting" => "Threat hunting with custom queries",
      "behavioral_analytics" => "User and entity behavior analytics (UEBA)",
      "playbooks" => "Automated response playbooks",
      "api_access" => "REST API access for integrations",
      "custom_integrations" => "Custom SIEM/SOAR integrations",
      "sso" => "Single Sign-On (SAML, OIDC, Azure AD, Okta)",
      "advanced_forensics" => "Memory and disk forensics collection",
      "live_response" => "Interactive remote response sessions",
      "compliance" => "Compliance reporting and audit trails",
      "mssp_portal" => "Multi-tenant MSSP management portal",
      "white_labeling" => "Custom branding and white-labeling",
      "sub_licensing" => "Sub-licensing for managed clients",
      "ai_assistant" => "AI-powered security assistant",
      "threat_intel_premium" => "Premium threat intelligence feeds",
      "cloud_security" => "Cloud workload protection",
      "container_security" => "Container and Kubernetes security",
      "deception" => "Honeypots and deception technology",
      "xdr" => "Extended detection and response"
    }

    Map.get(descriptions, feature, feature)
  end

  @doc """
  Returns features by category.
  """
  def features_by_category do
    %{
      core: ["detection", "dashboards", "alerts", "basic_response"],
      advanced: ["hunting", "behavioral_analytics", "playbooks", "api_access"],
      enterprise: ["custom_integrations", "sso", "advanced_forensics", "live_response", "compliance"],
      mssp: ["mssp_portal", "white_labeling", "sub_licensing"],
      addons: ["ai_assistant", "threat_intel_premium", "cloud_security", "container_security", "deception", "xdr"]
    }
  end
end
