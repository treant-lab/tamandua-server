defmodule TamanduaServer.Repo.Migrations.EnhanceOrganizationsForMultitenancy do
  @moduledoc """
  Enhances organizations table with license tier, agent limits, and
  adds audit trail table for RBAC changes.
  """

  use Ecto.Migration

  def change do
    # Add license and limits to organizations
    # Use raw SQL with IF NOT EXISTS to be idempotent
    execute """
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='organizations' AND column_name='license_tier') THEN
        ALTER TABLE organizations ADD COLUMN license_tier varchar(255) DEFAULT 'trial' NOT NULL;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='organizations' AND column_name='max_agents') THEN
        ALTER TABLE organizations ADD COLUMN max_agents integer DEFAULT 10 NOT NULL;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='organizations' AND column_name='features') THEN
        ALTER TABLE organizations ADD COLUMN features jsonb DEFAULT '{}'::jsonb;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='organizations' AND column_name='subscription_expires_at') THEN
        ALTER TABLE organizations ADD COLUMN subscription_expires_at timestamp;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='organizations' AND column_name='is_active') THEN
        ALTER TABLE organizations ADD COLUMN is_active boolean DEFAULT true NOT NULL;
      END IF;
    END $$;
    """, ""

    create_if_not_exists index(:organizations, [:license_tier])
    create_if_not_exists index(:organizations, [:is_active])

    # Create audit trail table for RBAC changes
    create_if_not_exists table(:rbac_audit_log, primary_key: false) do
      add :id, :binary_id, primary_key: true, default: fragment("gen_random_uuid()")
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false
      add :actor_id, references(:users, type: :binary_id, on_delete: :nilify_all)

      # Action details
      add :action, :string, null: false  # role_assigned, role_revoked, role_created, role_updated, role_deleted, permission_changed
      add :target_type, :string, null: false  # user, role
      add :target_id, :binary_id, null: false
      add :target_name, :string

      # Change details
      add :changes, :map, default: %{}
      add :metadata, :map, default: %{}

      # Request context
      add :ip_address, :string
      add :user_agent, :string

      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create_if_not_exists index(:rbac_audit_log, [:organization_id])
    create_if_not_exists index(:rbac_audit_log, [:actor_id])
    create_if_not_exists index(:rbac_audit_log, [:action])
    create_if_not_exists index(:rbac_audit_log, [:target_type, :target_id])
    create_if_not_exists index(:rbac_audit_log, [:inserted_at])

    # Add API-only flag to roles (may already exist from later migrations)
    execute """
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='roles' AND column_name='api_only') THEN
        ALTER TABLE roles ADD COLUMN api_only boolean DEFAULT false NOT NULL;
      END IF;
    END $$;
    """, ""
  end
end
