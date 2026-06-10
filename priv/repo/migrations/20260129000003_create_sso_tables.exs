defmodule TamanduaServer.Repo.Migrations.CreateSSOTables do
  use Ecto.Migration

  def change do
    # SSO configuration table
    create_if_not_exists table(:sso_configs, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      add :provider, :string  # saml, oidc, azure_ad, okta, google_workspace
      add :enabled, :boolean, default: false, null: false

      # Provider-specific settings (JSON)
      add :settings, :map, default: %{}

      # Just-in-time provisioning
      add :jit_provisioning, :boolean, default: true
      add :default_role, :string, default: "analyst"

      # Group/role mapping
      add :group_attribute, :string
      add :group_role_mappings, :map, default: %{}

      # Domain restrictions
      add :allowed_domains, {:array, :string}, default: []

      # Session settings
      add :session_duration_hours, :integer, default: 8
      add :force_reauth, :boolean, default: false

      # Audit
      add :last_used_at, :utc_datetime_usec
      add :last_error, :string

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists unique_index(:sso_configs, [:organization_id])
    create_if_not_exists index(:sso_configs, [:provider])
    create_if_not_exists index(:sso_configs, [:enabled])

    # SSO sessions table
    create_if_not_exists table(:sso_sessions, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      add :provider, :string, null: false
      add :provider_user_id, :string
      add :session_index, :string  # SAML SessionIndex for SLO

      add :expires_at, :utc_datetime_usec
      add :last_activity_at, :utc_datetime_usec
      add :ip_address, :string
      add :user_agent, :string

      add :is_active, :boolean, default: true, null: false
      add :terminated_at, :utc_datetime_usec
      add :termination_reason, :string

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists index(:sso_sessions, [:user_id])
    create_if_not_exists index(:sso_sessions, [:organization_id])
    create_if_not_exists index(:sso_sessions, [:provider])
    create_if_not_exists index(:sso_sessions, [:provider_user_id])
    create_if_not_exists index(:sso_sessions, [:session_index])
    create_if_not_exists index(:sso_sessions, [:is_active])
    create_if_not_exists index(:sso_sessions, [:expires_at])
  end
end
