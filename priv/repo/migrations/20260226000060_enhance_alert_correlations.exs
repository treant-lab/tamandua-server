defmodule TamanduaServer.Repo.Migrations.EnhanceAlertCorrelations do
  use Ecto.Migration

  def change do
    # Ensure alert_correlations table has all necessary fields
    # (table should already exist from previous migrations)

    # Add index for faster correlation queries
    create_if_not_exists index(:alert_correlations, [:alert_id, :correlation_type])
    create_if_not_exists index(:alert_correlations, [:related_alert_id, :correlation_type])
    create_if_not_exists index(:alert_correlations, [:confidence])
    create_if_not_exists index(:alert_correlations, [:organization_id])

    # Add index for temporal queries on alerts
    create_if_not_exists index(:alerts, [:organization_id, :inserted_at])
    create_if_not_exists index(:alerts, [:agent_id, :inserted_at])

    # Add GIN index for MITRE technique searches (PostgreSQL)
    execute(
      "CREATE INDEX IF NOT EXISTS alerts_mitre_techniques_gin_idx ON alerts USING GIN (mitre_techniques)",
      "DROP INDEX IF EXISTS alerts_mitre_techniques_gin_idx"
    )

    execute(
      "CREATE INDEX IF NOT EXISTS alerts_mitre_tactics_gin_idx ON alerts USING GIN (mitre_tactics)",
      "DROP INDEX IF EXISTS alerts_mitre_tactics_gin_idx"
    )

    # Add GIN index for evidence JSONB searches
    execute(
      "CREATE INDEX IF NOT EXISTS alerts_evidence_gin_idx ON alerts USING GIN (evidence)",
      "DROP INDEX IF EXISTS alerts_evidence_gin_idx"
    )
  end
end
