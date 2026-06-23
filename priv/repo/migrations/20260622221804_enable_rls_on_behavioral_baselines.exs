defmodule TamanduaServer.Repo.Migrations.EnableRlsOnBehavioralBaselines do
  use Ecto.Migration

  @moduledoc """
  Closes the RLS gap left by 20260220500002_enable_row_level_security.exs:70.

  The upstream RLS migration excluded `behavioral_baselines` with the comment
  "doesn't have organization_id column". The prerequisite column was added
  in 20260622203457_add_organization_id_to_persisted_baselines.exs (nullable
  binary_id FK to organizations, on_delete: :nilify_all, indexed). This
  migration enables RLS on the table using the same conventions as the
  upstream migration: helper-function bypass via `rls_bypass_enabled()`,
  policy name `<table>_organization_isolation`, PERMISSIVE FOR ALL TO PUBLIC,
  FORCE ROW LEVEL SECURITY, and a guarded DO $$ ... $$ block that no-ops if
  the table or column is missing.

  ## NULL-permissive policy (critical)

  The `organization_id` column is intentionally nullable. Pre-migration rows
  (including legacy `__noorg__::` prefixed rows and any pre-Phase-2 rows)
  have NULL there because backfill is a separate concern. A strict
  `organization_id = current_setting('app.current_organization_id')` policy
  would lock the application out of those legacy rows on the next deploy.
  To preserve read/write access to legacy data while still enforcing tenant
  isolation on rows that DO carry an org id, the USING / WITH CHECK clauses
  include an `organization_id IS NULL` disjunct alongside
  `organization_id = current_setting('app.current_organization_id', TRUE)::uuid`.

  Once backfill lands (separate migration with its own risk review), the
  IS NULL disjunct can be tightened or removed in a follow-up migration.

  Reverse: drops the policy and disables/un-forces RLS on the table only.
  The shared helper functions (`current_organization_id`, `rls_bypass_enabled`)
  are NOT dropped here — they remain owned by the upstream migration.
  """

  def change do
    execute(
      """
      DO $$
      BEGIN
        IF EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_name = 'behavioral_baselines'
          AND column_name = 'organization_id'
        ) THEN
          EXECUTE 'ALTER TABLE behavioral_baselines ENABLE ROW LEVEL SECURITY';
          EXECUTE 'ALTER TABLE behavioral_baselines FORCE ROW LEVEL SECURITY';

          IF NOT EXISTS (
            SELECT 1 FROM pg_policies
            WHERE tablename = 'behavioral_baselines'
            AND policyname = 'behavioral_baselines_organization_isolation'
          ) THEN
            EXECUTE 'CREATE POLICY behavioral_baselines_organization_isolation ON behavioral_baselines AS PERMISSIVE FOR ALL TO PUBLIC USING (rls_bypass_enabled() = TRUE OR organization_id IS NULL OR organization_id = NULLIF(current_setting(''app.current_organization_id'', TRUE), '''')::uuid) WITH CHECK (rls_bypass_enabled() = TRUE OR organization_id IS NULL OR organization_id = NULLIF(current_setting(''app.current_organization_id'', TRUE), '''')::uuid)';
          END IF;
        END IF;
      END
      $$;
      """,
      """
      DO $$
      BEGIN
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'behavioral_baselines') THEN
          EXECUTE 'DROP POLICY IF EXISTS behavioral_baselines_organization_isolation ON behavioral_baselines';
          EXECUTE 'ALTER TABLE behavioral_baselines NO FORCE ROW LEVEL SECURITY';
          EXECUTE 'ALTER TABLE behavioral_baselines DISABLE ROW LEVEL SECURITY';
        END IF;
      END $$;
      """
    )

    # The behavioral_baselines(organization_id) index was created by
    # 20260622203457_add_organization_id_to_persisted_baselines.exs. The
    # guarded create-if-missing below mirrors the upstream RLS migration's
    # belt-and-suspenders index creation; the down side is a no-op because
    # ownership of the index belongs to the column migration.
    execute(
      """
      DO $$
      BEGIN
        IF EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_name = 'behavioral_baselines'
          AND column_name = 'organization_id'
        ) THEN
          IF NOT EXISTS (
            SELECT 1 FROM pg_indexes
            WHERE tablename = 'behavioral_baselines'
            AND indexdef LIKE '%organization_id%'
          ) THEN
            EXECUTE 'CREATE INDEX behavioral_baselines_organization_id_idx ON behavioral_baselines(organization_id)';
          END IF;
        END IF;
      END $$;
      """,
      "SELECT 1"
    )
  end
end
