defmodule TamanduaServer.Repo.Migrations.CreateHealthAttestations do
  use Ecto.Migration

  def change do
    create table(:health_attestations, primary_key: false) do
      add :id, :binary_id, primary_key: true

      # Pseudonymized agent identifier: SHA256(agent_id)[:12]
      add :agent_pseudonym, :string, null: false

      # Time window for the attestation (default 24 hours)
      add :window_hours, :integer, default: 24, null: false

      # Alert counts by severity in the window
      add :critical_alerts, :integer, default: 0, null: false
      add :high_alerts, :integer, default: 0, null: false
      add :medium_alerts, :integer, default: 0, null: false
      add :low_alerts, :integer, default: 0, null: false

      # Last time the agent was seen online
      add :last_seen, :utc_datetime

      # Policy profile: "aggressive" | "balanced" | "lightweight" | "default"
      add :policy_profile, :string, default: "balanced"

      # SHA256 hash of all fields for verification
      add :health_hash, :string, null: false

      # Solana transaction signature
      add :solana_signature, :string

      # When the attestation was recorded on-chain
      add :attested_at, :utc_datetime

      # Reference to the actual agent (for internal queries)
      add :agent_id, references(:agents, type: :binary_id, on_delete: :nilify_all)

      # Organization for multi-tenancy
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps()
    end

    # Index for querying by pseudonym (for public verification)
    create index(:health_attestations, [:agent_pseudonym])

    # Index for querying by agent (for internal dashboards)
    create index(:health_attestations, [:agent_id])

    # Index for querying by organization
    create index(:health_attestations, [:organization_id])

    # Index for querying by Solana signature
    create unique_index(:health_attestations, [:solana_signature], where: "solana_signature IS NOT NULL")

    # Index for recent attestations
    create index(:health_attestations, [:inserted_at])

    # Composite index for efficient queries
    create index(:health_attestations, [:organization_id, :inserted_at])
  end
end
