defmodule TamanduaServer.Auth.SSO.SSOConfig do
  @moduledoc """
  Schema for SSO configuration per organization.

  Stores the IdP settings for various SSO providers:
  - SAML 2.0
  - OIDC
  - Azure AD
  - Okta
  - Google Workspace
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @providers [:saml, :oidc, :azure_ad, :okta, :google_workspace, :onelogin, :ping_identity]

  @derive {Jason.Encoder, only: [
    :id, :organization_id, :provider, :enabled,
    :jit_provisioning, :default_role, :group_attribute,
    :group_role_mappings, :inserted_at, :updated_at
  ]}

  schema "sso_configs" do
    belongs_to :organization, Organization

    field :provider, Ecto.Enum, values: @providers
    field :enabled, :boolean, default: false

    # Provider-specific settings (encrypted in production)
    field :settings, :map, default: %{}

    # Just-in-time provisioning
    field :jit_provisioning, :boolean, default: true
    field :default_role, :string, default: "analyst"

    # Group/role mapping
    field :group_attribute, :string
    field :group_role_mappings, :map, default: %{}

    # Domain restrictions
    field :allowed_domains, {:array, :string}, default: []

    # Session settings
    field :session_duration_hours, :integer, default: 8
    field :force_reauth, :boolean, default: false

    # Audit
    field :last_used_at, :utc_datetime_usec
    field :last_error, :string

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(organization_id)a
  @optional_fields ~w(
    provider enabled settings jit_provisioning default_role
    group_attribute group_role_mappings allowed_domains
    session_duration_hours force_reauth last_used_at last_error
  )a

  @doc """
  Changeset for SSO configuration.
  """
  def changeset(config, attrs) do
    config
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:provider, @providers)
    |> validate_number(:session_duration_hours, greater_than: 0, less_than_or_equal_to: 72)
    |> validate_settings()
    |> unique_constraint(:organization_id)
    |> foreign_key_constraint(:organization_id)
  end

  defp validate_settings(changeset) do
    provider = get_field(changeset, :provider)
    settings = get_field(changeset, :settings) || %{}
    enabled = get_field(changeset, :enabled)

    if enabled && provider do
      required = required_settings_for_provider(provider)
      missing = Enum.filter(required, fn key -> !settings[key] end)

      if Enum.empty?(missing) do
        changeset
      else
        add_error(changeset, :settings, "missing required settings for #{provider}: #{Enum.join(missing, ", ")}")
      end
    else
      changeset
    end
  end

  defp required_settings_for_provider(:saml) do
    ["idp_entity_id", "idp_sso_url", "idp_certificate"]
  end

  defp required_settings_for_provider(:oidc) do
    ["issuer", "client_id", "client_secret", "authorization_endpoint", "token_endpoint"]
  end

  defp required_settings_for_provider(:azure_ad) do
    ["tenant_id", "client_id", "client_secret"]
  end

  defp required_settings_for_provider(:okta) do
    ["domain", "client_id", "client_secret"]
  end

  defp required_settings_for_provider(:google_workspace) do
    ["client_id", "client_secret"]
  end

  defp required_settings_for_provider(_), do: []

  @doc """
  Returns the list of supported providers.
  """
  def providers, do: @providers

  @doc """
  Returns default settings template for a provider.
  """
  def default_settings(:saml) do
    %{
      "idp_entity_id" => "",
      "idp_sso_url" => "",
      "idp_slo_url" => "",
      "idp_certificate" => "",
      "sp_entity_id" => "",
      "acs_url" => "",
      "slo_url" => "",
      "sign_requests" => false,
      "sign_assertions" => true,
      "encrypt_assertions" => false
    }
  end

  def default_settings(:oidc) do
    %{
      "issuer" => "",
      "client_id" => "",
      "client_secret" => "",
      "authorization_endpoint" => "",
      "token_endpoint" => "",
      "userinfo_endpoint" => "",
      "jwks_uri" => "",
      "scope" => "openid email profile",
      "redirect_uri" => ""
    }
  end

  def default_settings(:azure_ad) do
    %{
      "tenant_id" => "",
      "client_id" => "",
      "client_secret" => "",
      "redirect_uri" => ""
    }
  end

  def default_settings(:okta) do
    %{
      "domain" => "",
      "client_id" => "",
      "client_secret" => "",
      "redirect_uri" => ""
    }
  end

  def default_settings(:google_workspace) do
    %{
      "client_id" => "",
      "client_secret" => "",
      "hosted_domain" => "",
      "redirect_uri" => ""
    }
  end

  def default_settings(_), do: %{}
end
