defmodule TamanduaServer.Repo.Migrations.BackfillOrganizationIdOnBehavioralBaselines do
  use Ecto.Migration

  @moduledoc """
  Backfills `behavioral_baselines.organization_id` for rows written before the
  Phase 5 follow-up that started populating the column directly (see
  20260622203457_add_organization_id_to_persisted_baselines.exs and the
  matching `upsert_baseline/3` change in
  `apps/tamandua_server/lib/tamandua_server/detection/behavioral.ex`).

  Two recovery paths, applied in order, both `WHERE organization_id IS NULL`:

    1. **JSON blob path** — the legacy `data` JSONB blob serialized by
       `serialize_baseline_for_persistence/2` includes `"organization_id"`
       when it was available at write time. Parse it back into the column
       when it is a syntactically valid UUID.

    2. **Entity-id prefix path** — `Behavioral` prefixed historical entity_id
       values with `"<UUID>::"` for org-scoped baselines and with
       `"__noorg__::"` when no org context was available. Extract the UUID
       prefix when present; ignore `__noorg__` rows (no org context to
       recover from disk).

  ## Rows that intentionally remain NULL after this migration

    * `entity_type = 'historical_stats'` — `persist_historical_stats/1` in
      `behavioral.ex:3252` writes a single platform-wide row
      `(entity_type='historical_stats', entity_id='global', organization_id=NULL)`.
      This is genuinely cross-tenant aggregate stats, not a missing label.
      The follow-up CHECK constraint will permit exactly this case.

    * Pre-historic `__noorg__::` prefixed rows with no JSON blob org_id —
      these were written when the agent had no org context at all. There is
      no recoverable label on disk; an operator would need to either accept
      the loss or hand-map them in a separate ops migration.

  ## Reversibility

  Backfill is not reversibly invertible (we cannot tell which rows were
  populated by this migration vs. by the application after deploy). The
  reverse path is a deliberate no-op (`SELECT 1`).

  ## Idempotence

  All UPDATEs are guarded by `organization_id IS NULL`, so re-running this
  migration is a no-op once it has succeeded. The outer DO block also gates
  on `information_schema.columns` so the migration is safe on schemas where
  the column has not yet been added.
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
          -- Pass 1: recover from the JSON blob.
          -- `data->>'organization_id'` returns NULL when the key is absent.
          -- The regex guard avoids feeding malformed strings to ::uuid (which
          -- would abort the whole migration). UUID v4 canonical form only.
          EXECUTE $sql$
            UPDATE behavioral_baselines
            SET organization_id = (data->>'organization_id')::uuid
            WHERE organization_id IS NULL
              AND entity_type <> 'historical_stats'
              AND data ? 'organization_id'
              AND data->>'organization_id' ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
          $sql$;

          -- Pass 2: recover from the entity_id prefix.
          -- Matches `"<uuid>::<rest>"` but explicitly excludes `"__noorg__::"`.
          EXECUTE $sql$
            UPDATE behavioral_baselines
            SET organization_id = substring(entity_id from '^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})::')::uuid
            WHERE organization_id IS NULL
              AND entity_type <> 'historical_stats'
              AND entity_id ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}::'
          $sql$;
        END IF;
      END
      $$;
      """,
      "SELECT 1"
    )
  end
end
