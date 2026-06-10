defmodule TamanduaServerWeb.Controllers.API.V1.IDORRegressionTest do
  @moduledoc """
  IDOR regression tests for the 11 cross-tenant fixes from commit 25ca0500.

  These tests verify that org-scoped getters correctly reject cross-tenant access:
  - Soft getters (get_rule_for_org/2, get_suppression_rule_for_org/2) return {:error, :not_found}
  - Bang getters (get_submission_for_org!/2) raise Ecto.NoResultsError

  Green run: DEFERRED until an Elixir-capable host runs `mix test`.
  """
  use TamanduaServerWeb.ConnCase, async: true

  alias TamanduaServer.Detection.Exclusions
  alias TamanduaServer.Alerts
  alias TamanduaServer.Bounties

  # ── Setup ────────────────────────────────────────────────────────────────────

  setup %{conn: conn} do
    # Org A: the "owner" org
    {org_a, agent_a} = create_agent_with_org()
    user_a = insert!(:user, %{organization_id: org_a.id, role: "admin"})
    {:ok, token_a, _} = TamanduaServer.Guardian.encode_and_sign(user_a)
    conn_a = put_req_header(conn, "authorization", "Bearer #{token_a}")

    # Org B: the "attacker" org trying cross-tenant access
    {org_b, agent_b} = create_agent_with_org()
    user_b = insert!(:user, %{organization_id: org_b.id, role: "admin"})
    {:ok, token_b, _} = TamanduaServer.Guardian.encode_and_sign(user_b)
    conn_b = put_req_header(conn, "authorization", "Bearer #{token_b}")

    %{
      org_a: org_a,
      org_b: org_b,
      user_a: user_a,
      user_b: user_b,
      agent_a: agent_a,
      agent_b: agent_b,
      conn_a: conn_a,
      conn_b: conn_b
    }
  end

  # ── Exclusions.get_rule_for_org/2 (SOFT getter) ──────────────────────────────
  # Gaps 1-3: alert_controller.ex:574 (PUT), :611 (DELETE), :636 (toggle)

  describe "Exclusions.get_rule_for_org/2 - IDOR prevention" do
    test "returns {:ok, rule} for same-org access", %{org_a: org_a, user_a: user_a} do
      rule = insert!(:exclusion_rule, %{organization_id: org_a.id, created_by_id: user_a.id})

      assert {:ok, fetched} = Exclusions.get_rule_for_org(org_a.id, rule.id)
      assert fetched.id == rule.id
    end

    test "returns {:error, :not_found} for cross-tenant access (Gap 1-3)", %{org_a: org_a, org_b: org_b, user_a: user_a} do
      # Rule belongs to Org A
      rule = insert!(:exclusion_rule, %{organization_id: org_a.id, created_by_id: user_a.id})

      # Org B tries to access it
      assert {:error, :not_found} = Exclusions.get_rule_for_org(org_b.id, rule.id)
    end

    test "returns {:error, :not_found} for non-existent rule", %{org_a: org_a} do
      fake_id = Ecto.UUID.generate()
      assert {:error, :not_found} = Exclusions.get_rule_for_org(org_a.id, fake_id)
    end
  end

  # ── Alerts.get_suppression_rule_for_org/2 (SOFT getter) ──────────────────────
  # Gaps 4-6: alert_controller.ex:857 (PUT), :893 (DELETE), :917 (toggle)

  describe "Alerts.get_suppression_rule_for_org/2 - IDOR prevention" do
    test "returns {:ok, rule} for same-org access", %{org_a: org_a, user_a: user_a} do
      rule = insert!(:suppression_rule, %{organization_id: org_a.id, created_by_id: user_a.id})

      assert {:ok, fetched} = Alerts.get_suppression_rule_for_org(org_a.id, rule.id)
      assert fetched.id == rule.id
    end

    test "returns {:error, :not_found} for cross-tenant access (Gap 4-6)", %{org_a: org_a, org_b: org_b, user_a: user_a} do
      # Rule belongs to Org A
      rule = insert!(:suppression_rule, %{organization_id: org_a.id, created_by_id: user_a.id})

      # Org B tries to access it
      assert {:error, :not_found} = Alerts.get_suppression_rule_for_org(org_b.id, rule.id)
    end

    test "returns {:error, :not_found} for non-existent rule", %{org_a: org_a} do
      fake_id = Ecto.UUID.generate()
      assert {:error, :not_found} = Alerts.get_suppression_rule_for_org(org_a.id, fake_id)
    end
  end

  # ── Bounties.get_submission_for_org!/2 (BANG getter) ─────────────────────────
  # Gap 7: bounty_controller.ex:23 (GET show)

  describe "Bounties.get_submission_for_org!/2 - IDOR prevention" do
    test "returns submission for same-org access", %{org_a: org_a, user_a: user_a} do
      submission = insert!(:submission, %{organization_id: org_a.id, submitted_by_id: user_a.id})

      fetched = Bounties.get_submission_for_org!(org_a.id, submission.id)
      assert fetched.id == submission.id
    end

    test "raises Ecto.NoResultsError for cross-tenant access (Gap 7)", %{org_a: org_a, org_b: org_b, user_a: user_a} do
      # Submission belongs to Org A
      submission = insert!(:submission, %{organization_id: org_a.id, submitted_by_id: user_a.id})

      # Org B tries to access it - should raise
      assert_raise Ecto.NoResultsError, fn ->
        Bounties.get_submission_for_org!(org_b.id, submission.id)
      end
    end

    test "raises Ecto.NoResultsError for non-existent submission", %{org_a: org_a} do
      fake_id = Ecto.UUID.generate()

      assert_raise Ecto.NoResultsError, fn ->
        Bounties.get_submission_for_org!(org_a.id, fake_id)
      end
    end
  end

  # ── Bounties.validate_submission_for_org/3 (calls bang getter internally) ────
  # Gap 8: bounty_controller.ex:40 (POST validate)

  describe "Bounties.validate_submission_for_org/3 - IDOR prevention" do
    test "validates submission for same-org access", %{org_a: org_a, user_a: user_a} do
      submission = insert!(:submission, %{organization_id: org_a.id, submitted_by_id: user_a.id})

      assert {:ok, validated} = Bounties.validate_submission_for_org(org_a.id, submission.id, user_a.id)
      assert validated.status == "validated"
    end

    test "raises Ecto.NoResultsError for cross-tenant access (Gap 8)", %{org_a: org_a, org_b: org_b, user_a: user_a, user_b: user_b} do
      # Submission belongs to Org A
      submission = insert!(:submission, %{organization_id: org_a.id, submitted_by_id: user_a.id})

      # Org B admin tries to validate it
      assert_raise Ecto.NoResultsError, fn ->
        Bounties.validate_submission_for_org(org_b.id, submission.id, user_b.id)
      end
    end
  end

  # ── Bounties.reject_submission_for_org/4 (calls bang getter internally) ──────
  # Gap 9: bounty_controller.ex:108 (POST reject)

  describe "Bounties.reject_submission_for_org/4 - IDOR prevention" do
    test "rejects submission for same-org access", %{org_a: org_a, user_a: user_a} do
      submission = insert!(:submission, %{organization_id: org_a.id, submitted_by_id: user_a.id})

      assert {:ok, rejected} = Bounties.reject_submission_for_org(org_a.id, submission.id, user_a.id, "Duplicate")
      assert rejected.status == "rejected"
      assert rejected.rejection_reason == "Duplicate"
    end

    test "raises Ecto.NoResultsError for cross-tenant access (Gap 9)", %{org_a: org_a, org_b: org_b, user_a: user_a, user_b: user_b} do
      # Submission belongs to Org A
      submission = insert!(:submission, %{organization_id: org_a.id, submitted_by_id: user_a.id})

      # Org B admin tries to reject it
      assert_raise Ecto.NoResultsError, fn ->
        Bounties.reject_submission_for_org(org_b.id, submission.id, user_b.id, "Unauthorized rejection attempt")
      end
    end
  end

  # ── Bounties.pay_bounty_for_org/3 (calls bang getter internally) ─────────────
  # Gap 10: bounty_controller.ex:148 (POST pay)

  describe "Bounties.pay_bounty_for_org/3 - IDOR prevention" do
    test "raises Ecto.NoResultsError for cross-tenant access (Gap 10)", %{org_a: org_a, org_b: org_b, user_a: user_a} do
      # Create and validate submission for Org A
      submission = insert!(:submission, %{
        organization_id: org_a.id,
        submitted_by_id: user_a.id,
        status: "validated"
      })

      # Org B tries to pay bounty for Org A's submission
      assert_raise Ecto.NoResultsError, fn ->
        Bounties.pay_bounty_for_org(org_b.id, submission.id, 1_000_000)
      end
    end

    # Note: Same-org pay test would require Solana mock/stub; cross-tenant denial is the IDOR test.
  end

  # ── org_id source fix: conn.assigns[:current_organization_id] ────────────────
  # Gap 11: alert_controller.ex:175 (bulk), :279 (search)
  # These are tested via HTTP requests to ensure the controller uses the correct conn.assigns key.

  describe "Alert controller org_id source (Gap 11)" do
    setup %{conn_a: conn_a, conn_b: conn_b, org_a: org_a, org_b: org_b, agent_a: agent_a, agent_b: agent_b} do
      # Create alerts for each org
      alert_a = insert!(:alert, %{organization_id: org_a.id, agent_id: agent_a.id, title: "Org A Alert"})
      alert_b = insert!(:alert, %{organization_id: org_b.id, agent_id: agent_b.id, title: "Org B Alert"})

      %{alert_a: alert_a, alert_b: alert_b, conn_a: conn_a, conn_b: conn_b}
    end

    test "list alerts returns only same-org alerts", %{conn_a: conn_a, alert_a: alert_a, alert_b: alert_b} do
      conn = get(conn_a, "/api/v1/alerts")
      data = json_response(conn, 200)["data"]

      alert_ids = Enum.map(data, & &1["id"])

      assert alert_a.id in alert_ids
      refute alert_b.id in alert_ids
    end

    test "search alerts excludes cross-org results", %{conn_a: conn_a, alert_a: alert_a, alert_b: alert_b} do
      # Search for alerts (keyword matches both)
      conn = get(conn_a, "/api/v1/alerts?q=Alert")
      data = json_response(conn, 200)["data"]

      alert_ids = Enum.map(data, & &1["id"])

      # Org A's alert should be visible
      assert alert_a.id in alert_ids
      # Org B's alert should NOT be visible
      refute alert_b.id in alert_ids
    end
  end
end
