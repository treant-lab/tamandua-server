defmodule TamanduaServer.Repo.Migrations.AddEventsOrgTimelineIndexes do
  use Ecto.Migration

  @disable_ddl_transaction true

  def up do
    concurrently = concurrently_clause("events")

    drop_invalid_index("events", "events_org_timestamp_idx", concurrently)
    drop_invalid_index("events", "events_org_type_timestamp_idx", concurrently)

    execute("""
    CREATE INDEX#{concurrently} IF NOT EXISTS events_org_timestamp_idx
    ON events (organization_id, timestamp DESC)
    """)

    execute("""
    CREATE INDEX#{concurrently} IF NOT EXISTS events_org_type_timestamp_idx
    ON events (organization_id, event_type, timestamp DESC)
    """)
  end

  def down do
    concurrently = concurrently_clause("events")

    execute("DROP INDEX#{concurrently} IF EXISTS events_org_type_timestamp_idx")
    execute("DROP INDEX#{concurrently} IF EXISTS events_org_timestamp_idx")
  end

  # TimescaleDB does not support concurrent index creation on hypertables. The
  # non-concurrent form is therefore unavoidable there; regular PostgreSQL
  # tables retain the less disruptive concurrent path.
  defp concurrently_clause(table_name) do
    if timescale_hypertable?(table_name), do: "", else: " CONCURRENTLY"
  end

  # IF NOT EXISTS accepts an index left invalid by an interrupted concurrent
  # build. Remove only that failed artifact so a retry actually rebuilds it.
  defp drop_invalid_index(table_name, index_name, concurrently) do
    invalid_index =
      case Ecto.Adapters.SQL.query!(
             repo(),
             """
             SELECT pg_catalog.quote_ident(index_namespace.nspname) || '.' ||
                    pg_catalog.quote_ident(index_relation.relname)
             FROM pg_catalog.pg_index AS index
             JOIN pg_catalog.pg_class AS index_relation
               ON index_relation.oid = index.indexrelid
             JOIN pg_catalog.pg_namespace AS index_namespace
               ON index_namespace.oid = index_relation.relnamespace
             JOIN pg_catalog.pg_class AS table_relation
               ON table_relation.oid = index.indrelid
             JOIN pg_catalog.pg_namespace AS table_namespace
               ON table_namespace.oid = table_relation.relnamespace
             WHERE index_relation.relname = $1
               AND index_namespace.nspname = current_schema()
               AND table_relation.relname = $2
               AND table_namespace.nspname = current_schema()
               AND NOT index.indisvalid
             """,
             [index_name, table_name]
           ).rows do
        [[qualified_name]] -> qualified_name
        _ -> nil
      end

    if invalid_index do
      execute("DROP INDEX#{concurrently} IF EXISTS #{invalid_index}")
    end
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
