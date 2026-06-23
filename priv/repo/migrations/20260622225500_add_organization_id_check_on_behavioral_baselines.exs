defmodule TamanduaServer.Repo.Migrations.AddOrganizationIdCheckOnBehavioralBaselines do
  use Ecto.Migration

  @moduledoc """
  Adds a CHECK constraint on `behavioral_baselines` enforcing that
  `organization_id` is populated for every row EXCEPT the singleton
  `entity_type='historical_stats'` row written by `persist_historical_stats/1`
  in `apps/tamandua_server/lib/tamandua_server/detection/behavioral.ex:3252`.

  ## Why CHECK instead of NOT NULL

  A strict `NOT NULL` cannot ship because `persist_historical_stats/1`
  upserts a deliberately cross-tenant row:

      upsert_baseline(:historical_stats, "global", stats)

  That row aggregates platform-wide statistics and has no owning tenant
  by design. The CHECK constraint admits exactly this case and rejects
  every other NULL.

  ## Ordering

  This migration MUST run after the backfill
  (20260622225000_backfill_organization_id_on_behavioral_baselines.exs).
  Adding the CHECK before backfill would reject the legacy NULL rows that
  the backfill is responsible for populating.

  ## Operator override

  If pre-existing NULL rows survive the backfill (e.g. `__noorg__::`
  prefixed rows with no JSON blob org_id), the constraint creation will
  fail. The recovery is either: (a) hand-map the survivors in an ops
  migration, or (b) decide they are abandoned and DELETE them. We
  deliberately do not auto-delete: silent data loss is worse than a
  loud migration failure.

  ## Reversibility

  The reverse path drops the constraint. Guarded by `pg_constraint` so
  rollback is idempotent.
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
          IF NOT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conname = 'behavioral_baselines_organization_id_required'
          ) THEN
            EXECUTE 'ALTER TABLE behavioral_baselines
                     ADD CONSTRAINT behavioral_baselines_organization_id_required
                     CHECK (entity_type = ''historical_stats'' OR organization_id IS NOT NULL)';
          END IF;
        END IF;
      END
      $$;
      """,
      """
      DO $$
      BEGIN
        IF EXISTS (
          SELECT 1 FROM pg_constraint
          WHERE conname = 'behavioral_baselines_organization_id_required'
        ) THEN
          EXECUTE 'ALTER TABLE behavioral_baselines
                   DROP CONSTRAINT behavioral_baselines_organization_id_required';
        END IF;
      END
      $$;
      """
    )
  end
end
