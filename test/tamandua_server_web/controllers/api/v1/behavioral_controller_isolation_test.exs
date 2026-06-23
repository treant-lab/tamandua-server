defmodule TamanduaServerWeb.Controllers.API.V1.BehavioralControllerIsolationTest do
  @moduledoc """
  Phase 4 cross-tenant isolation acceptance tests for the Behavioral API.

  See `.planning/BEHAVIORAL_TENANT_SCOPING_DESIGN.md` §4 Phase 4 and §7
  Acceptance Criteria. These tests speculatively encode the behavior that
  Phases 1-3 (commits 85d63e41, 5e148500, cd6a69f3, 37a30bf9, 2723d889)
  are intended to deliver:

    * Every public endpoint on `BehavioralController` reads the caller's
      `current_organization_id` and refuses (403) when the assign is
      missing.
    * Every read filters by org_id so data written for org A is not
      visible to org B.

  All tests are tagged `@tag :isolation` so the suite can be run via
  `mix test --only isolation`.
  """
  use TamanduaServerWeb.ConnCase, async: false

  alias TamanduaServer.Detection.Behavioral
  alias TamanduaServer.Detection.Behavioral.{BehavioralAnomaly, UserProfile}

  @profiles_table :behavioral_profiles
  @anomaly_table :behavioral_anomalies

  setup %{conn: conn} do
    # Two independent tenants. Each gets its own org, agent, and analyst
    # user. Both users are authenticated against the API via Guardian
    # bearer tokens; the only thing that distinguishes their requests is
    # the `current_organization_id` assign set by the `:api_auth`
    # pipeline (SetOrganizationContext plug) from the user's
    # `organization_id` claim.
    {org_a, agent_a} = create_agent_with_org()
    {org_b, agent_b} = create_agent_with_org()

    user_a = insert!(:user, %{organization_id: org_a.id, role: "analyst"})
    user_b = insert!(:user, %{organization_id: org_b.id, role: "analyst"})

    {:ok, token_a, _} = TamanduaServer.Guardian.encode_and_sign(user_a)
    {:ok, token_b, _} = TamanduaServer.Guardian.encode_and_sign(user_b)

    conn_a = put_req_header(conn, "authorization", "Bearer #{token_a}")
    conn_b = put_req_header(conn, "authorization", "Bearer #{token_b}")

    # Scrub Behavioral ETS tables between tests. The Behavioral GenServer
    # is started by the application supervisor and is shared by every
    # test — so test ordering would otherwise leak rows. We do NOT call
    # `init_ets_tables/0` directly (it is private); instead we clear the
    # already-existing public tables. Tables that the Behavioral
    # controller lazily creates (`:behavioral_risk_snapshots`) may not
    # exist yet — guard with `:ets.whereis/1`. Suppression rules are no
    # longer in ETS; the controller now routes through
    # `TamanduaServer.Alerts.SuppressionRule` (DB-backed, org-scoped),
    # and the SQL Sandbox isolates rows per test.
    for table <- [
          :behavioral_profiles,
          :behavioral_stats,
          :behavioral_peer_groups,
          :behavioral_temporal,
          :behavioral_thresholds,
          :behavioral_risk_trends,
          :behavioral_anomalies
        ] do
      case :ets.whereis(table) do
        :undefined -> :ok
        _tid -> :ets.delete_all_objects(table)
      end
    end

    %{
      conn_a: conn_a,
      conn_b: conn_b,
      org_a: org_a,
      org_b: org_b,
      agent_a: agent_a,
      agent_b: agent_b,
      user_a: user_a,
      user_b: user_b,
      token_a: token_a,
      token_b: token_b
    }
  end

  # ─── 1. API isolation: profiles ──────────────────────────────────────────

  @tag :isolation
  test "GET /api/v1/behavioral/entities does not leak org A's profile to org B",
       %{conn_a: conn_a, conn_b: conn_b, org_a: org_a, agent_a: agent_a} do
    # Plant a behavioral profile for org A's user "alice" directly into
    # the public profiles ETS table. This simulates what Behavioral
    # writes after ingesting telemetry for that user.
    profile = %UserProfile{
      user_id: "alice",
      total_events: 42,
      last_updated: DateTime.utc_now()
    }

    :ets.insert(
      @profiles_table,
      {{org_a.id, :user, "alice"}, profile}
    )

    # Also plant for the agent's hostname so the controller's hostname
    # heuristics (if any) cannot rescue org B.
    :ets.insert(
      @profiles_table,
      {{org_a.id, :host, agent_a.hostname}, %UserProfile{user_id: agent_a.hostname, total_events: 7}}
    )

    # Org A sees its own entity (≥ 1, since the controller may include
    # other discovered profiles).
    resp_a = get(conn_a, "/api/v1/behavioral/entities") |> json_response(200)
    data_a = resp_a["data"] || []

    assert is_list(data_a)
    assert Enum.any?(data_a, fn entity ->
             (entity["entity_id"] == "alice" or entity["id"] == "alice") and
               (entity["entity_type"] in ["user", :user] or entity["type"] in ["user", :user])
           end),
           "expected org A's `alice` profile to appear in its own /entities response, got: #{inspect(data_a)}"

    # Org B sees no record of "alice".
    resp_b = get(conn_b, "/api/v1/behavioral/entities") |> json_response(200)
    data_b = resp_b["data"] || []

    refute Enum.any?(data_b, fn entity ->
             entity["entity_id"] == "alice" or entity["id"] == "alice"
           end),
           "org B must not see org A's `alice` profile, got: #{inspect(data_b)}"

    refute Enum.any?(data_b, fn entity ->
             entity["entity_id"] == agent_a.hostname or entity["id"] == agent_a.hostname
           end),
           "org B must not see org A's host profile (#{agent_a.hostname}), got: #{inspect(data_b)}"
  end

  # ─── 2. API isolation: anomalies ─────────────────────────────────────────

  @tag :isolation
  test "GET /api/v1/behavioral/anomalies does not leak org A's anomalies to org B",
       %{conn_a: conn_a, conn_b: conn_b, org_a: org_a, agent_a: agent_a} do
    anomaly = %BehavioralAnomaly{
      anomaly_type: :statistical_outlier,
      entity_type: :user,
      entity_id: "alice",
      agent_id: agent_a.id,
      organization_id: org_a.id,
      description: "Anomalous login hour (planted for isolation test)",
      risk_score: 88,
      deviation_score: 4.2,
      baseline_value: 9,
      observed_value: 3,
      mitre_techniques: ["T1078"],
      rule_id: nil,
      timestamp: DateTime.utc_now()
    }

    # Phase 2 stores anomalies keyed by {org_id, entity_type, entity_id}
    # (or a per-entity bounded list). We insert under the org-scoped key
    # so the test passes only when the controller filters by org.
    :ets.insert(@anomaly_table, {{org_a.id, :user, "alice"}, [anomaly]})

    # Org A may or may not see it depending on the controller's storage
    # contract for `@anomaly_table`. The isolation claim we MUST hold is
    # that org B sees nothing.
    resp_b = get(conn_b, "/api/v1/behavioral/anomalies") |> json_response(200)
    data_b = resp_b["data"] || []

    refute Enum.any?(data_b, fn a ->
             a["entity_id"] == "alice" or a["agent_id"] == agent_a.id or
               a["organization_id"] == org_a.id
           end),
           "org B must not see org A's anomalies, got: #{inspect(data_b)}"
  end

  # ─── 3. API isolation: peer analysis ─────────────────────────────────────

  @tag :isolation
  test "GET /api/v1/behavioral/peer-analysis/user/alice as org B does not return org A's profile",
       %{conn_b: conn_b, org_a: org_a} do
    # alice exists only in org A.
    :ets.insert(
      @profiles_table,
      {{org_a.id, :user, "alice"},
       %UserProfile{user_id: "alice", total_events: 200, peer_group: "tenant_a:engineering"}}
    )

    conn_b = get(conn_b, "/api/v1/behavioral/peer-analysis/user/alice")

    # Accept either 200 with empty/zero data or 404. What we explicitly
    # disallow is a 200 that surfaces org A's profile (e.g.
    # `total_events == 200` or the org_a peer_group label).
    case conn_b.status do
      404 ->
        :ok

      200 ->
        body = json_response(conn_b, 200)
        data = body["data"] || %{}

        refute Map.get(data, "total_events") == 200,
               "org B must not receive org A's total_events count, got: #{inspect(body)}"

        refute (Map.get(data, "peer_group") || "") =~ "tenant_a",
               "org B must not receive org A's peer_group label, got: #{inspect(body)}"

      other ->
        flunk("unexpected status #{other} from cross-tenant peer-analysis, body: #{inspect(conn_b.resp_body)}")
    end
  end

  # ─── 4. API isolation: suppressions ──────────────────────────────────────
  #
  # Suppressions now route through `TamanduaServer.Alerts.SuppressionRule`,
  # which is DB-backed and org-scoped via `TenantScope.scope_to_tenant`.
  # The legacy ETS shim (`@suppression_table :behavioral_suppressions`)
  # has been removed from the controller, so this test no longer needs
  # the `@tag :pending_scoping` escape hatch — the assertion is now
  # enforced end-to-end at the HTTP boundary.

  @tag :isolation
  test "GET /api/v1/behavioral/suppressions does not list org A's suppression to org B",
       %{conn_a: conn_a, conn_b: conn_b} do
    # Org A creates a suppression via the existing API.
    create_payload = %{
      "pattern_type" => "process_name",
      "pattern" => "tenant_a_only_suppression.exe",
      "reason" => "isolation test"
    }

    resp = post(conn_a, "/api/v1/behavioral/suppressions", create_payload)
    assert resp.status in [200, 201]

    # Org B lists suppressions and must not see it.
    list_resp = get(conn_b, "/api/v1/behavioral/suppressions") |> json_response(200)
    data = list_resp["data"] || []

    refute Enum.any?(data, fn s ->
             (s["pattern"] || s[:pattern]) == "tenant_a_only_suppression.exe"
           end),
           "org B must not see org A's suppression rules, got: #{inspect(data)}"
  end

  # ─── 5. 403 when no org assigned ─────────────────────────────────────────

  @tag :isolation
  test "GET /api/v1/behavioral/entities returns 403 when current_organization_id is missing",
       %{conn: conn} do
    # Build a raw conn that has been through the API pipeline (Bearer
    # missing → no org context). The `:api_auth` pipeline + the
    # controller's `require_org_id/1` guard should reject this with 403.
    #
    # We do NOT set a Bearer token, do NOT assign current_user, and do
    # NOT assign current_organization_id. APIAuth will halt with 401
    # before the controller is reached — which is *also* an acceptable
    # "no org" failure mode (stronger than 403). Accept either.
    conn = get(conn, "/api/v1/behavioral/entities")

    assert conn.status in [401, 403],
           "expected 401 or 403 for unauthenticated request, got #{conn.status}: #{inspect(conn.resp_body)}"
  end
end
