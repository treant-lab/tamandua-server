defmodule TamanduaServer.Repo.Migrations.AddDnsFeedIndexes do
  use Ecto.Migration

  @disable_ddl_transaction true

  def up do
    concurrently = concurrently_clause("events")

    execute("""
    CREATE INDEX#{concurrently} IF NOT EXISTS events_org_dns_type_time_idx
    ON events (organization_id, event_type, timestamp DESC)
    WHERE event_type IN ('dns_query', 'dns', 'dns_response', 'name_resolution', 'domain_lookup')
       OR event_type LIKE 'dns%'
    """)

    execute("""
    CREATE INDEX#{concurrently} IF NOT EXISTS events_org_dns_recent_time_idx
    ON events (organization_id, timestamp DESC)
    WHERE event_type IN ('dns_query', 'dns', 'dns_response', 'name_resolution', 'domain_lookup')
       OR event_type LIKE 'dns%'
       OR payload ? 'dns'
       OR payload ? 'dns_query'
       OR payload ? 'query_name'
       OR payload ? 'dns.domain'
    """)
  end

  def down do
    concurrently = concurrently_clause("events")

    execute("DROP INDEX#{concurrently} IF EXISTS events_org_dns_recent_time_idx")
    execute("DROP INDEX#{concurrently} IF EXISTS events_org_dns_type_time_idx")
  end

  # TimescaleDB does not support concurrent index creation on hypertables. The
  # non-concurrent form is therefore unavoidable there; regular PostgreSQL
  # tables retain the less disruptive concurrent path.
  defp concurrently_clause(table_name) do
    if timescale_hypertable?(table_name), do: "", else: " CONCURRENTLY"
  end

  defp timescale_hypertable?(table_name) do
    extension_installed? =
      case Ecto.Adapters.SQL.query!(
             repo(),
             "SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb')",
             []
           ).rows do
        [[true]] -> true
        _ -> false
      end

    extension_installed? and
      case Ecto.Adapters.SQL.query!(
             repo(),
             """
             SELECT EXISTS (
               SELECT 1
               FROM timescaledb_information.hypertables
               WHERE hypertable_schema = current_schema()
                 AND hypertable_name = $1
             )
             """,
             [table_name]
           ).rows do
        [[true]] -> true
        _ -> false
      end
  end
end
