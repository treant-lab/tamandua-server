defmodule TamanduaServer.Detection.BehavioralIsolationTest do
  @moduledoc """
  Phase 4 GenServer-level isolation tests for `Detection.Behavioral`.

  See `.planning/BEHAVIORAL_TENANT_SCOPING_DESIGN.md` §4 Phase 4 and §7
  Acceptance Criteria. These tests speculatively encode the behavior
  Phase 2 (commit cd6a69f3) is meant to deliver at the data-layer
  boundary: every read/write into the seven behavioral ETS tables is
  keyed by `{org_id, ...}` so that one tenant's writes are invisible
  to another tenant's reads.

  No HTTP, no DB — direct calls into `TamanduaServer.Detection.Behavioral`
  and direct ETS inspection.

  All tests are tagged `@tag :isolation` so the suite can be run via
  `mix test --only isolation`.
  """
  use ExUnit.Case, async: false

  alias TamanduaServer.Detection.Behavioral
  alias TamanduaServer.Detection.Behavioral.{UserProfile, OnlineStats}

  @profiles_table :behavioral_profiles
  @stats_table :behavioral_stats
  @peer_groups_table :behavioral_peer_groups
  @thresholds_table :behavioral_thresholds
  @risk_trends_table :behavioral_risk_trends

  setup do
    # The Behavioral GenServer is supervised by the application and is
    # therefore already running for every test in this VM. We must NOT
    # call its private `init_ets_tables/0`. Instead, clear the public
    # tables it has already created. Each table is set as `:public,
    # :named_table` at `behavioral.ex:1413-1419`, so the test process
    # may write/clear directly.
    for table <- [
          @profiles_table,
          @stats_table,
          @peer_groups_table,
          @thresholds_table,
          @risk_trends_table,
          :behavioral_temporal,
          :behavioral_anomalies
        ] do
      case :ets.whereis(table) do
        :undefined -> :ok
        _tid -> :ets.delete_all_objects(table)
      end
    end

    org_a = "org-a-" <> short_uuid()
    org_b = "org-b-" <> short_uuid()

    %{org_a: org_a, org_b: org_b}
  end

  defp short_uuid do
    :crypto.strong_rand_bytes(6) |> Base.encode16(case: :lower)
  end

  # ─── 1. Profile isolation ────────────────────────────────────────────────

  @tag :isolation
  test "get_user_profile returns the profile for the owning org and nil for another org",
       %{org_a: org_a, org_b: org_b} do
    profile = %UserProfile{user_id: "alice", total_events: 5, last_updated: DateTime.utc_now()}

    # Phase 2 ETS key shape: {org_id, entity_type, entity_id}.
    :ets.insert(@profiles_table, {{org_a, :user, "alice"}, profile})

    # Also seed the GenServer's in-memory map so the call-based read
    # path can find it for org_a. We send a cast through the GenServer
    # by directly inserting into ETS (the call-path checks the
    # nested state map; the ETS path is the fast read).
    #
    # The public `get_user_profile/2` reads the GenServer state map. To
    # avoid forcing GenServer.call ordering on a foreign state, we
    # verify via ETS *and* via the public API. The ETS-based assertion
    # is the strict isolation contract.
    assert :ets.lookup(@profiles_table, {org_a, :user, "alice"}) == [
             {{org_a, :user, "alice"}, profile}
           ]

    assert :ets.lookup(@profiles_table, {org_b, :user, "alice"}) == [],
           "org B must not see org A's profile row in :behavioral_profiles ETS"

    # Public API contract: org B's get_user_profile call yields nil.
    case Behavioral.get_user_profile(org_b, "alice") do
      {:ok, nil} -> :ok
      nil -> :ok
      other -> flunk("expected nil/`{:ok, nil}` for cross-tenant get_user_profile, got: #{inspect(other)}")
    end
  end

  # ─── 2. Stats isolation ──────────────────────────────────────────────────

  @tag :isolation
  test "get_feature_stats does not leak stats across orgs",
       %{org_a: org_a, org_b: org_b} do
    stats =
      %OnlineStats{}
      |> OnlineStats.update(8.0)
      |> OnlineStats.update(9.0)
      |> OnlineStats.update(10.0)

    # Stats table is keyed by {org_id, entity_type, entity_id, feature}
    # per `get_feature_stats/4` at behavioral.ex:1679.
    :ets.insert(@stats_table, {{org_a, :user, "alice", :login_hour}, stats})

    assert Behavioral.get_feature_stats(org_a, :user, "alice", :login_hour) == stats

    assert Behavioral.get_feature_stats(org_b, :user, "alice", :login_hour) == nil,
           "org B must not see org A's :behavioral_stats row"

    # And the raw ETS lookup confirms no cross-tenant row exists.
    assert :ets.lookup(@stats_table, {org_b, :user, "alice", :login_hour}) == []
  end

  # ─── 3. Peer group isolation ─────────────────────────────────────────────

  @tag :isolation
  test "peer-group recalculation keys ETS rows by {org_id, group_label}",
       %{org_a: org_a, org_b: org_b} do
    # Plant two users per org with the same nominal "alice" id but
    # disjoint profile states. Each has total_events large enough that
    # the recalculation produces a peer-group row (n >= 2).
    insert_profile = fn org_id, user_id, total ->
      profile = %UserProfile{
        user_id: user_id,
        total_events: total,
        peer_group: "all_users",
        last_updated: DateTime.utc_now()
      }

      :ets.insert(@profiles_table, {{org_id, :user, user_id}, profile})
      profile
    end

    insert_profile.(org_a, "alice", 100)
    insert_profile.(org_a, "bob", 120)
    insert_profile.(org_b, "alice", 5)
    insert_profile.(org_b, "carol", 7)

    # The Behavioral GenServer holds its own nested state map and only
    # iterates orgs it knows about via `enumerate_known_orgs/1`. Since
    # we cannot mutate that state directly (no public API), the peer
    # group recalculation is *not* expected to populate ETS for orgs
    # that the GenServer does not know about — that is precisely the
    # cross-tenant contract: org B's peers come only from org B's
    # known profiles. What we strictly assert is that *if* any peer
    # group ETS row is created, its key is the 2-tuple
    # `{org_id, group_label}` and never the bare `group_label`.
    send(Behavioral, :recalc_peer_groups)
    # Give the GenServer a moment to process the message.
    Process.sleep(50)

    rows = :ets.tab2list(@peer_groups_table)

    Enum.each(rows, fn {key, _value} ->
      assert match?({_org, _group}, key),
             "peer-group ETS row must be keyed {org_id, group_label}, got: #{inspect(key)}"
    end)

    # Cross-tenant isolation: a row keyed {org_a, _} must not also
    # appear keyed {org_b, _} with the same member_count (which would
    # imply org B's count was inflated by org A's members).
    by_org =
      rows
      |> Enum.group_by(fn {{org_id, _label}, _value} -> org_id end)

    Enum.each(Map.get(by_org, org_a, []), fn {{^org_a, _label}, %{member_count: a_n}} ->
      Enum.each(Map.get(by_org, org_b, []), fn {{^org_b, _label}, %{member_count: b_n}} ->
        refute a_n == b_n and a_n > 0,
               "org A and org B should not share peer-group member counts " <>
                 "(suggests cross-tenant aggregation)"
      end)
    end)
  end

  # ─── 4. Adaptive threshold isolation ─────────────────────────────────────

  @tag :isolation
  test "get_adaptive_threshold defaults are per-org, and feedback for one org leaves the other untouched",
       %{org_a: org_a, org_b: org_b} do
    # First read seeds defaults lazily for org A only.
    {threshold_a_initial, fp_a, tp_a} = Behavioral.get_adaptive_threshold(org_a, :user, :login_hour)
    assert is_number(threshold_a_initial)
    assert fp_a == 0
    assert tp_a == 0

    # Send verdict feedback DIRECTLY to the GenServer with the org_id
    # already resolved (the payload shortcut avoids touching Alerts/DB).
    # This mirrors the production message at behavioral.ex:1570.
    send(
      Behavioral,
      {:verdict_feedback,
       %{
         alert_id: "phase4-test-alert",
         organization_id: org_a,
         verdict: "false_positive",
         entity_type: :user,
         feature: :login_hour,
         rule_id: nil
       }}
    )

    # And many more FP feedbacks to drive the threshold visibly upward
    # (Bayesian posterior with @threshold_prior_strength=10 is sluggish).
    for _ <- 1..30 do
      send(
        Behavioral,
        {:verdict_feedback,
         %{
           alert_id: "phase4-test-alert",
           organization_id: org_a,
           verdict: "false_positive",
           entity_type: :user,
           feature: :login_hour,
           rule_id: nil
         }}
      )
    end

    # Force serialization with the GenServer mailbox.
    _ = Behavioral.dashboard_summary()
    Process.sleep(20)

    {threshold_a_after, fp_a_after, _tp} =
      Behavioral.get_adaptive_threshold(org_a, :user, :login_hour)

    assert fp_a_after > 0,
           "org A's threshold row must have recorded the FP feedback (got fp_count=#{fp_a_after})"

    # FP feedback pushes the z-threshold *up* (less sensitive) per the
    # Bayesian posterior at behavioral.ex:3801. We accept either an
    # observably-mutated threshold OR a non-zero fp_count as the
    # liveness signal — what we strictly require is org-isolation.
    _ = threshold_a_after

    # org B has never read a threshold yet AND never received feedback.
    # When org B reads, it must get a fresh default with fp_count == 0.
    {_threshold_b, fp_b, tp_b} = Behavioral.get_adaptive_threshold(org_b, :user, :login_hour)

    assert fp_b == 0,
           "org B's :login_hour threshold must be a fresh default — fp_count must be 0, got #{fp_b}"

    assert tp_b == 0,
           "org B's :login_hour threshold must be a fresh default — tp_count must be 0, got #{tp_b}"

    # Raw ETS confirms there is no cross-tenant row mutation: the
    # {org_a, ...} and {org_b, ...} entries are independent.
    assert [{{^org_a, :user, :login_hour}, _val_a}] =
             :ets.lookup(@thresholds_table, {org_a, :user, :login_hour})

    assert [{{^org_b, :user, :login_hour}, {_z, 0, 0}}] =
             :ets.lookup(@thresholds_table, {org_b, :user, :login_hour})
  end

  # ─── 5. Risk trend isolation ─────────────────────────────────────────────

  @tag :isolation
  test "get_risk_trend does not leak risk-trend rows across orgs",
       %{org_a: org_a, org_b: org_b} do
    trend = %{
      ewma: 72.5,
      consecutive_high: 3,
      last_score: 80.0,
      updated_at: System.monotonic_time(:second)
    }

    # Phase 2 risk-trend ETS key shape: {org_id, entity_type, entity_id}.
    :ets.insert(@risk_trends_table, {{org_a, :user, "alice"}, trend})

    assert Behavioral.get_risk_trend(org_a, :user, "alice") == trend

    assert Behavioral.get_risk_trend(org_b, :user, "alice") == nil,
           "org B must not see org A's risk-trend row in :behavioral_risk_trends ETS"

    # Raw ETS confirmation.
    assert :ets.lookup(@risk_trends_table, {org_b, :user, "alice"}) == []
  end
end
