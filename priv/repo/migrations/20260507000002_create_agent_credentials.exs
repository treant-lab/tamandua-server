defmodule TamanduaServer.Repo.Migrations.CreateAgentCredentials do
  use Ecto.Migration

  @doc """
  Creates the agent_credentials table for DB-backed socket identity validation.

  This implements the security requirements from ACCOUNT_INTEGRITY_THREAT_MODEL.md:
  1. Validate token against DB-backed agent credential record
  2. Check active/not-revoked status, org binding, token jti
  3. Require finite expiry (no infinite tokens)
  4. Track last_used_at for auditing
  """

  def change do
    create table(:agent_credentials, primary_key: false) do
      add :id, :binary_id, primary_key: true

      # Link to agent - cascade delete when agent is removed
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all), null: false

      # Organization binding - ensures agents only connect to their org
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      # JWT ID (jti) claim - unique identifier for this credential
      add :jti, :string, null: false

      # Token metadata
      add :issued_at, :utc_datetime_usec, null: false
      add :expires_at, :utc_datetime_usec, null: false

      # Revocation tracking
      add :revoked_at, :utc_datetime_usec
      add :revocation_reason, :string

      # Usage tracking for auditing and anomaly detection
      add :last_used_at, :utc_datetime_usec
      add :last_used_ip, :string
      add :use_count, :integer, default: 0

      # Connection metadata for forensics
      add :issued_from_ip, :string
      add :issued_by_user_id, references(:users, type: :binary_id, on_delete: :nilify_all)

      timestamps()
    end

    # Unique constraint on jti - each token ID must be unique
    create unique_index(:agent_credentials, [:jti])

    # Find credentials by agent
    create index(:agent_credentials, [:agent_id])

    # Find credentials by organization
    create index(:agent_credentials, [:organization_id])

    # Find active (non-revoked, non-expired) credentials
    create index(:agent_credentials, [:expires_at])
    create index(:agent_credentials, [:revoked_at])

    # Composite index for the common lookup pattern
    create index(:agent_credentials, [:agent_id, :organization_id, :jti])
  end
end
