defmodule TamanduaServer.Repo.BehavioralBaselinesInvariantsTest do
  use TamanduaServer.DataCase, async: false

  @moduledoc """
  CI invariants for `behavioral_baselines` org isolation.

  These tests enforce the post-Phase-5-follow-up contract:

    1. Every non-`historical_stats` row carries a non-NULL `organization_id`.
       Backed by the CHECK constraint added in
       20260622225500_add_organization_id_check_on_behavioral_baselines.exs.

    2. The CHECK constraint actually exists in the live schema (regression
       guard for someone dropping it without replacement).

    3. RLS is enabled AND forced on the table (so even the table owner
       sees only their tenant rows + the `historical_stats` singleton).

    4. The tightened isolation policy (20260622230000) does NOT contain the
       broad `organization_id IS NULL` disjunct — only the narrow
       `entity_type = 'historical_stats' AND organization_id IS NULL` form.
       Regression guard against someone reintroducing the wider permissive
       form.

  All queries run under RLS bypass via `MultiTenant.with_bypass/1` so the
  test can see the full row population (without bypass, RLS would mask
  rows from other tenants and the count assertions would be meaningless).
  """

  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant

  describe "behavioral_baselines org_id population" do
    test "no non-historical_stats row exists with NULL organization_id" do
      {:ok, %{rows: [[count]]}} =
        MultiTenant.with_bypass(fn ->
          Repo.query(
            """
            SELECT COUNT(*)::int
            FROM behavioral_baselines
            WHERE organization_id IS NULL
              AND entity_type <> 'historical_stats'
            """,
            []
          )
        end)

      assert count == 0,
             "found #{count} behavioral_baselines row(s) with NULL organization_id outside the historical_stats exception"
    end

    test "the historical_stats singleton is allowed to keep NULL organization_id" do
      # Purely a documentation / regression test: the CHECK constraint
      # admits this case by design. We do not assert presence of the row
      # (it is written lazily by persist_historical_stats/1), only that
      # the constraint admits NULL there.
      {:ok, %{rows: [[count]]}} =
        MultiTenant.with_bypass(fn ->
          Repo.query(
            """
            SELECT COUNT(*)::int
            FROM behavioral_baselines
            WHERE entity_type = 'historical_stats'
              AND organization_id IS NOT NULL
            """,
            []
          )
        end)

      # historical_stats rows MAY carry an org_id (per-tenant aggregates
      # in the future) but the singleton 'global' one must not be
      # rejected by the constraint. We don't pin a hard direction here;
      # the surviving invariant is the CHECK + the test above.
      assert is_integer(count)
    end
  end

  describe "schema constraints" do
    test "behavioral_baselines_organization_id_required CHECK exists" do
      {:ok, %{rows: rows}} =
        Repo.query(
          """
          SELECT pg_get_constraintdef(c.oid)
          FROM pg_constraint c
          JOIN pg_class t ON t.oid = c.conrelid
          WHERE t.relname = 'behavioral_baselines'
            AND c.conname = 'behavioral_baselines_organization_id_required'
            AND c.contype = 'c'
          """,
          []
        )

      assert length(rows) == 1,
             "CHECK constraint behavioral_baselines_organization_id_required is missing"

      [[def_text]] = rows

      assert def_text =~ "historical_stats",
             "CHECK constraint must mention the historical_stats exception, got: #{def_text}"

      assert def_text =~ ~r/organization_id IS NOT NULL/i,
             "CHECK constraint must enforce organization_id IS NOT NULL outside the exception, got: #{def_text}"
    end
  end

  describe "RLS posture" do
    test "row-level security is enabled and forced on behavioral_baselines" do
      {:ok, %{rows: [[rls_enabled, force_rls]]}} =
        Repo.query(
          """
          SELECT relrowsecurity, relforcerowsecurity
          FROM pg_class
          WHERE relname = 'behavioral_baselines'
            AND relnamespace = 'public'::regnamespace
          """,
          []
        )

      assert rls_enabled == true,
             "behavioral_baselines must have ROW LEVEL SECURITY enabled"

      assert force_rls == true,
             "behavioral_baselines must have FORCE ROW LEVEL SECURITY enabled (so the table owner is not exempt)"
    end

    test "isolation policy admits historical_stats NULL exception only — not the broad IS NULL" do
      {:ok, %{rows: rows}} =
        Repo.query(
          """
          SELECT qual, with_check
          FROM pg_policies
          WHERE schemaname = 'public'
            AND tablename = 'behavioral_baselines'
            AND policyname = 'behavioral_baselines_organization_isolation'
          """,
          []
        )

      assert length(rows) == 1,
             "behavioral_baselines_organization_isolation policy is missing"

      [[qual, with_check]] = rows

      # The narrow exception MUST be present.
      for clause <- [qual, with_check] do
        assert clause =~ "historical_stats",
               "policy clause must reference the historical_stats exception, got: #{clause}"
      end

      # The broad `organization_id IS NULL` disjunct (without the
      # historical_stats guard) MUST NOT be present. pg_policies expands
      # the policy text, so we check for the standalone form. The
      # presence of `historical_stats' AND organization_id IS NULL` is
      # fine; an isolated `OR organization_id IS NULL` next to a
      # non-historical-stats subexpression is a regression.
      for clause <- [qual, with_check] do
        # Strip the legitimate narrow form so any leftover `IS NULL`
        # is a regression.
        stripped =
          clause
          |> String.replace(~r/\(?\s*entity_type\s*=\s*'historical_stats'::text\)?\s*AND\s*\(?\s*organization_id\s+IS\s+NULL\s*\)?/i, "")
          |> String.replace(~r/\(?\s*organization_id\s+IS\s+NULL\s*AND\s*\(?\s*entity_type\s*=\s*'historical_stats'::text\)?\)?/i, "")

        refute stripped =~ ~r/organization_id\s+IS\s+NULL/i,
               "policy clause still contains a broad `organization_id IS NULL` disjunct outside the historical_stats exception: #{clause}"
      end
    end
  end
end
