defmodule TamanduaServer.Repo.Migrations.CreateIocAuthorityEpoch do
  use Ecto.Migration

  def up do
    execute("""
    CREATE TABLE public.ioc_authority_epochs (
      singleton boolean PRIMARY KEY DEFAULT TRUE CHECK (singleton),
      epoch bigint NOT NULL DEFAULT 0 CHECK (epoch >= 0),
      updated_at timestamptz NOT NULL DEFAULT NOW()
    )
    """)

    execute("INSERT INTO public.ioc_authority_epochs (singleton, epoch) VALUES (TRUE, 0)")

    execute("""
    CREATE FUNCTION public.bump_ioc_authority_epoch() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    DECLARE
      next_epoch bigint;
    BEGIN
      UPDATE public.ioc_authority_epochs
      SET epoch = epoch + 1, updated_at = NOW()
      WHERE singleton = TRUE
      RETURNING epoch INTO next_epoch;

      PERFORM pg_catalog.pg_notify('tamandua_ioc_authority_epoch', next_epoch::text);
      RETURN NULL;
    END;
    $$
    """)

    execute("REVOKE ALL ON FUNCTION public.bump_ioc_authority_epoch() FROM PUBLIC")

    for operation <- ["INSERT", "UPDATE", "DELETE", "TRUNCATE"] do
      trigger = "iocs_authority_epoch_after_#{String.downcase(operation)}"

      execute("""
      CREATE TRIGGER #{trigger}
      AFTER #{operation} ON iocs
      FOR EACH STATEMENT EXECUTE FUNCTION public.bump_ioc_authority_epoch()
      """)

      # ALWAYS prevents a privileged replication session from silently
      # bypassing the authority clock. ALTER TABLE remains privileged and is
      # therefore also verified by the runtime preflight below.
      execute("ALTER TABLE iocs ENABLE ALWAYS TRIGGER #{trigger}")
    end
  end

  def down do
    for operation <- ["INSERT", "UPDATE", "DELETE", "TRUNCATE"] do
      execute(
        "DROP TRIGGER IF EXISTS iocs_authority_epoch_after_#{String.downcase(operation)} ON iocs"
      )
    end

    execute("DROP FUNCTION IF EXISTS public.bump_ioc_authority_epoch()")
    execute("DROP TABLE IF EXISTS public.ioc_authority_epochs")
  end
end
