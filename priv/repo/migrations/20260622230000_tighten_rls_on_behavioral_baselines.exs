defmodule TamanduaServer.Repo.Migrations.TightenRlsOnBehavioralBaselines do
  use Ecto.Migration

  @moduledoc """
  Tightens the `behavioral_baselines_organization_isolation` policy created
  by 20260622221804_enable_rls_on_behavioral_baselines.exs.

  ## What changed and why

  The original policy admitted ANY NULL `organization_id` row to ANY tenant:

      USING (rls_bypass_enabled() = TRUE
             OR organization_id IS NULL
             OR organization_id = NULLIF(current_setting('app.current_organization_id', TRUE), '')::uuid)

  That blanket `IS NULL` disjunct was a temporary safety belt while
  pre-Phase-5 rows still existed with NULL org_id (legacy `__noorg__::`
  prefix and pre-backfill rows). The 20260622225000 backfill migration
  and the 20260622225500 CHECK constraint together guarantee that the
  ONLY remaining NULL-org_id rows are the singleton
  `entity_type='historical_stats'` global aggregates written by
  `persist_historical_stats/1` in behavioral.ex:3252.

  This migration replaces the broad `IS NULL` disjunct with a narrow
  one that admits only that singleton:

      USING (rls_bypass_enabled() = TRUE
             OR (entity_type = 'historical_stats' AND organization_id IS NULL)
             OR organization_id = NULLIF(current_setting('app.current_organization_id', TRUE), '')::uuid)

  Effect: any future regression that writes a non-historical_stats row
  with NULL org_id will be invisible to every tenant (rather than
  visible to all tenants), and the CHECK constraint will reject the
  write up front anyway. Defense in depth.

  ## Ordering

  Must run after both 20260622225000 (backfill) and 20260622225500
  (CHECK). If a legacy non-historical_stats NULL row still exists when
  this policy applies, it becomes invisible to every tenant — which is
  the SAFE outcome (no cross-tenant leak), and the CHECK migration
  before this one would have failed first anyway.

  ## Reverse

  Restores the broader policy with the IS NULL disjunct. Symmetric to
  the original migration's reverse path.
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
          EXECUTE 'DROP POLICY IF EXISTS behavioral_baselines_organization_isolation ON behavioral_baselines';

          EXECUTE 'CREATE POLICY behavioral_baselines_organization_isolation
                   ON behavioral_baselines
                   AS PERMISSIVE FOR ALL TO PUBLIC
                   USING (
                     rls_bypass_enabled() = TRUE
                     OR (entity_type = ''historical_stats'' AND organization_id IS NULL)
                     OR organization_id = NULLIF(current_setting(''app.current_organization_id'', TRUE), '''')::uuid
                   )
                   WITH CHECK (
                     rls_bypass_enabled() = TRUE
                     OR (entity_type = ''historical_stats'' AND organization_id IS NULL)
                     OR organization_id = NULLIF(current_setting(''app.current_organization_id'', TRUE), '''')::uuid
                   )';
        END IF;
      END
      $$;
      """,
      """
      DO $$
      BEGIN
        IF EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_name = 'behavioral_baselines'
          AND column_name = 'organization_id'
        ) THEN
          EXECUTE 'DROP POLICY IF EXISTS behavioral_baselines_organization_isolation ON behavioral_baselines';

          EXECUTE 'CREATE POLICY behavioral_baselines_organization_isolation
                   ON behavioral_baselines
                   AS PERMISSIVE FOR ALL TO PUBLIC
                   USING (
                     rls_bypass_enabled() = TRUE
                     OR organization_id IS NULL
                     OR organization_id = NULLIF(current_setting(''app.current_organization_id'', TRUE), '''')::uuid
                   )
                   WITH CHECK (
                     rls_bypass_enabled() = TRUE
                     OR organization_id IS NULL
                     OR organization_id = NULLIF(current_setting(''app.current_organization_id'', TRUE), '''')::uuid
                   )';
        END IF;
      END
      $$;
      """
    )
  end
end
