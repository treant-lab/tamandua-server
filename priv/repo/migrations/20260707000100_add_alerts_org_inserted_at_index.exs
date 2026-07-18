defmodule TamanduaServer.Repo.Migrations.AddAlertsOrgInsertedAtIndex do
  use Ecto.Migration

  @disable_ddl_transaction true

  def up do
    drop_invalid_index("alerts_org_inserted_at_idx")

    execute("""
    CREATE INDEX CONCURRENTLY IF NOT EXISTS alerts_org_inserted_at_idx
    ON alerts (organization_id, inserted_at DESC)
    """)
  end

  def down do
    execute("DROP INDEX CONCURRENTLY IF EXISTS alerts_org_inserted_at_idx")
  end

  # An interrupted concurrent build leaves an invalid index behind, and
  # IF NOT EXISTS would otherwise skip rebuilding it on the next deploy.
  defp drop_invalid_index(index_name) do
    invalid? =
      case Ecto.Adapters.SQL.query!(
             repo(),
             """
             SELECT NOT i.indisvalid
             FROM pg_index AS i
             JOIN pg_class AS c ON c.oid = i.indexrelid
             WHERE c.relname = $1
               AND pg_table_is_visible(c.oid)
             """,
             [index_name]
           ).rows do
        [[true]] -> true
        _ -> false
      end

    if invalid? do
      execute("DROP INDEX CONCURRENTLY IF EXISTS #{index_name}")
    end
  end
end
