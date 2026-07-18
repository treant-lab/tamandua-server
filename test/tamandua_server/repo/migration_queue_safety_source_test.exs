defmodule TamanduaServer.Repo.MigrationQueueSafetySourceTest do
  use ExUnit.Case, async: true

  @timeline_index_migration "priv/repo/migrations/20260626020000_add_events_org_timeline_indexes.exs"

  test "timeline indexes retain the migration lock and repair invalid builds" do
    source = File.read!(@timeline_index_migration)

    assert source =~ "@disable_ddl_transaction true"
    refute source =~ "@disable_migration_lock true"
    assert source =~ "CREATE INDEX\#{concurrently} IF NOT EXISTS"
    assert source =~ "AND NOT index.indisvalid"
    assert source =~ "DROP INDEX\#{concurrently} IF EXISTS \#{invalid_index}"
    assert source =~ "index_namespace.nspname = current_schema()"
    assert source =~ "table_namespace.nspname = current_schema()"
    assert source =~ "table_relation.relname = $2"
    assert source =~ "pg_catalog.quote_ident(index_namespace.nspname)"
  end
end
