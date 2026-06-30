defmodule TamanduaServer.Repo.Migrations.AddDnsFeedIndexes do
  use Ecto.Migration

  @disable_ddl_transaction true
  @disable_migration_lock true

  def up do
    execute """
    CREATE INDEX CONCURRENTLY IF NOT EXISTS events_org_dns_type_time_idx
    ON events (organization_id, event_type, timestamp DESC)
    WHERE event_type IN ('dns_query', 'dns', 'dns_response', 'name_resolution', 'domain_lookup')
       OR event_type LIKE 'dns%'
    """

    execute """
    CREATE INDEX CONCURRENTLY IF NOT EXISTS events_org_dns_recent_time_idx
    ON events (organization_id, timestamp DESC)
    WHERE event_type IN ('dns_query', 'dns', 'dns_response', 'name_resolution', 'domain_lookup')
       OR event_type LIKE 'dns%'
       OR payload ? 'dns'
       OR payload ? 'dns_query'
       OR payload ? 'query_name'
       OR payload ? 'dns.domain'
    """
  end

  def down do
    execute "DROP INDEX CONCURRENTLY IF EXISTS events_org_dns_recent_time_idx"
    execute "DROP INDEX CONCURRENTLY IF EXISTS events_org_dns_type_time_idx"
  end
end
