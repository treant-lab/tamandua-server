defmodule TamanduaServer.Repo.Migrations.AddEventsOrgTimelineIndexes do
  use Ecto.Migration

  @disable_ddl_transaction true

  def up do
    execute """
    CREATE INDEX CONCURRENTLY IF NOT EXISTS events_org_timestamp_idx
    ON events (organization_id, timestamp DESC)
    """

    execute """
    CREATE INDEX CONCURRENTLY IF NOT EXISTS events_org_type_timestamp_idx
    ON events (organization_id, event_type, timestamp DESC)
    """
  end

  def down do
    execute "DROP INDEX CONCURRENTLY IF EXISTS events_org_type_timestamp_idx"
    execute "DROP INDEX CONCURRENTLY IF EXISTS events_org_timestamp_idx"
  end
end
