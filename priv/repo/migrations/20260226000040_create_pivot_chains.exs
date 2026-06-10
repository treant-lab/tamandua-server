defmodule TamanduaServer.Repo.Migrations.CreatePivotChains do
  use Ecto.Migration

  def up do
    create_if_not_exists table(:pivot_chains, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text
      add :chain_data, :map, default: %{}, null: false
      add :pivot_count, :integer, default: 0, null: false
      add :is_template, :boolean, default: false, null: false
      add :template_name, :string
      add :shared, :boolean, default: false, null: false
      add :tags, {:array, :string}, default: [], null: false
      add :metadata, :map, default: %{}, null: false

      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false

      add :created_by_id, references(:users, type: :binary_id, on_delete: :nilify_all), null: false

      timestamps(type: :utc_datetime_usec)
    end

    # Indexes for efficient queries
    execute "CREATE INDEX IF NOT EXISTS pivot_chains_organization_id_index ON pivot_chains(organization_id)", ""
    execute "CREATE INDEX IF NOT EXISTS pivot_chains_created_by_id_index ON pivot_chains(created_by_id)", ""
    execute "CREATE INDEX IF NOT EXISTS pivot_chains_is_template_index ON pivot_chains(is_template)", ""
    execute "CREATE INDEX IF NOT EXISTS pivot_chains_shared_index ON pivot_chains(shared)", ""
    execute "CREATE INDEX IF NOT EXISTS pivot_chains_tags_index ON pivot_chains USING gin(tags)", ""
    execute "CREATE INDEX IF NOT EXISTS pivot_chains_updated_at_index ON pivot_chains(updated_at)", ""

    # Index for searching by name
    execute "CREATE INDEX IF NOT EXISTS pivot_chains_organization_id_name_index ON pivot_chains(organization_id, name)", ""

    # Add indexes to existing tables for pivot queries
    # These indexes optimize the pivot engine queries

    # Events table indexes for pivot operations
    execute """
    CREATE INDEX IF NOT EXISTS events_payload_remote_ip_idx
    ON events ((payload->>'remote_ip'))
    WHERE payload->>'remote_ip' IS NOT NULL
    """

    execute """
    CREATE INDEX IF NOT EXISTS events_payload_sha256_idx
    ON events ((payload->>'sha256'))
    WHERE payload->>'sha256' IS NOT NULL
    """

    execute """
    CREATE INDEX IF NOT EXISTS events_payload_user_idx
    ON events ((payload->>'user'))
    WHERE payload->>'user' IS NOT NULL
    """

    execute """
    CREATE INDEX IF NOT EXISTS events_payload_domain_idx
    ON events ((payload->>'domain'))
    WHERE payload->>'domain' IS NOT NULL
    """

    execute """
    CREATE INDEX IF NOT EXISTS events_payload_file_path_lower_idx
    ON events (LOWER(payload->>'file_path'))
    WHERE payload->>'file_path' IS NOT NULL
    """

    # Alerts table indexes for pivot operations
    execute """
    CREATE INDEX IF NOT EXISTS alerts_evidence_sha256_idx
    ON alerts ((evidence->>'sha256'))
    WHERE evidence->>'sha256' IS NOT NULL
    """

    execute """
    CREATE INDEX IF NOT EXISTS alerts_evidence_remote_ip_idx
    ON alerts ((evidence->'network'->>'remote_ip'))
    WHERE evidence->'network'->>'remote_ip' IS NOT NULL
    """

    execute """
    CREATE INDEX IF NOT EXISTS alerts_evidence_user_idx
    ON alerts ((evidence->'process'->>'user'))
    WHERE evidence->'process'->>'user' IS NOT NULL
    """

    execute """
    CREATE INDEX IF NOT EXISTS alerts_evidence_domain_idx
    ON alerts ((evidence->'network'->>'domain'))
    WHERE evidence->'network'->>'domain' IS NOT NULL
    """

    execute """
    CREATE INDEX IF NOT EXISTS alerts_evidence_file_path_lower_idx
    ON alerts (LOWER(evidence->'file'->>'path'))
    WHERE evidence->'file'->>'path' IS NOT NULL
    """
  end

  def down do
    # Drop pivot-specific indexes
    execute "DROP INDEX IF EXISTS events_payload_remote_ip_idx"
    execute "DROP INDEX IF EXISTS events_payload_sha256_idx"
    execute "DROP INDEX IF EXISTS events_payload_user_idx"
    execute "DROP INDEX IF EXISTS events_payload_domain_idx"
    execute "DROP INDEX IF EXISTS events_payload_file_path_lower_idx"
    execute "DROP INDEX IF EXISTS alerts_evidence_sha256_idx"
    execute "DROP INDEX IF EXISTS alerts_evidence_remote_ip_idx"
    execute "DROP INDEX IF EXISTS alerts_evidence_user_idx"
    execute "DROP INDEX IF EXISTS alerts_evidence_domain_idx"
    execute "DROP INDEX IF EXISTS alerts_evidence_file_path_lower_idx"

    drop table(:pivot_chains)
  end
end
