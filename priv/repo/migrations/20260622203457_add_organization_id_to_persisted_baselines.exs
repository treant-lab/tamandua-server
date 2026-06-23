defmodule TamanduaServer.Repo.Migrations.AddOrganizationIdToPersistedBaselines do
  use Ecto.Migration

  @moduledoc """
  Phase 5 of .planning/BEHAVIORAL_TENANT_SCOPING_DESIGN.md.

  The behavioral_baselines table was created in 20260131300001 with only
  (entity_type, entity_id, data) — no organization_id column. Phase 2 of the
  behavioral tenant-scoping work (commit cd6a69f3) worked around the missing
  column by smuggling org_id into entity_id via a "org_id::entity" string
  prefix (with "__noorg__::" for legacy nil-org rows) AND by stamping
  "organization_id" into the JSON data blob.

  This migration adds the proper column. It is nullable so existing rows
  (including legacy "__noorg__::" prefixed rows) pass without backfill.
  Backfill is intentionally NOT part of this migration — it is a separate
  concern with its own risk profile. The prefix-fallback parser in
  `load_persisted_baselines/0` continues to handle pre-migration rows.

  The behavioral_baselines table is also referenced by
  `TamanduaServer.Repo.RlsAdmin` (`@tenant_scoped_tables`) and was
  explicitly excluded from the RLS migration (20260220500002:70) with the
  comment "doesn't have organization_id column" — this migration closes
  that prerequisite gap.

  Reverse: drops the index and the column. No data is touched.
  """

  def change do
    alter table(:behavioral_baselines) do
      add :organization_id,
          references(:organizations, type: :binary_id, on_delete: :nilify_all),
          null: true
    end

    create index(:behavioral_baselines, [:organization_id])
  end
end
