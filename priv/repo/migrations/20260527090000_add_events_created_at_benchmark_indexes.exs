defmodule TamanduaServer.Repo.Migrations.AddEventsCreatedAtBenchmarkIndexes do
  use Ecto.Migration

  @disable_ddl_transaction true
  @disable_migration_lock true

  def up do
    execute """
    CREATE INDEX IF NOT EXISTS events_agent_created_at_idx
    ON events (agent_id, created_at DESC)
    """

    execute """
    CREATE INDEX IF NOT EXISTS events_agent_type_created_at_idx
    ON events (agent_id, event_type, created_at DESC)
    """
  end

  def down do
    execute "DROP INDEX IF EXISTS events_agent_type_created_at_idx"
    execute "DROP INDEX IF EXISTS events_agent_created_at_idx"
  end
end
