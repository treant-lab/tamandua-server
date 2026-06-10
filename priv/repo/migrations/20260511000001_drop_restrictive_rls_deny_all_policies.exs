defmodule TamanduaServer.Repo.Migrations.DropRestrictiveRlsDenyAllPolicies do
  use Ecto.Migration

  def up do
    execute """
    DO $$
    DECLARE
      policy_record RECORD;
    BEGIN
      FOR policy_record IN
        SELECT schemaname, tablename, policyname
        FROM pg_policies
        WHERE policyname = tablename || '_deny_all'
      LOOP
        EXECUTE format(
          'DROP POLICY IF EXISTS %I ON %I.%I',
          policy_record.policyname,
          policy_record.schemaname,
          policy_record.tablename
        );
      END LOOP;
    END $$;
    """
  end

  def down do
    :ok
  end
end
