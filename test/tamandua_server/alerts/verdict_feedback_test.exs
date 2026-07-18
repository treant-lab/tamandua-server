defmodule TamanduaServer.Alerts.VerdictFeedbackTest do
  @moduledoc """
  Tests for the analyst verdict / FP review feedback loop.

  Covers the data layer that the FP Review UI (alert detail verdict modal +
  analyst dashboard FP metric card) was wired to on 2026-06-15:

  - `Alerts.set_verdict/4` (alert update + VerdictFeedbackLog audit entry)
  - Auto-generation of suppression rules with TTL from an FP verdict
  - TTL expiry behavior for suppression rules
  - `Alerts.get_verdict_stats/1` aggregation (FP rate, reviewed/unreviewed,
    top FP rules, active suppression rules)
  - `Alerts.bulk_set_verdict/4`
  - `Alerts.get_feedback_log/1`

  Uses async: false because `set_verdict` interacts with the globally
  registered Suppression and Baseline GenServers (shared sandbox mode).
  """

  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Alerts
  alias TamanduaServer.Alerts.{Alert, SuppressionRule, VerdictFeedbackLog}

  import TamanduaServer.AccountsFixtures
  import TamanduaServer.AlertsFixtures

  @day_seconds 24 * 60 * 60

  setup do
    org = organization_fixture()
    user = user_fixture(organization_id: org.id)
    %{org: org, user: user}
  end

  defp detection_alert(org, attrs \\ []) do
    defaults = [
      organization_id: org.id,
      agent_id: Ecto.UUID.generate(),
      title: "Suspicious process #{System.unique_integer([:positive])}",
      severity: "high",
      status: "new",
      detection_metadata: %{"rule_name" => "test_rule_#{System.unique_integer([:positive])}"},
      evidence: %{
        "process" => %{
          "name" => "noisy_tool.exe",
          "path" => "C:\\Tools\\noisy_tool.exe",
          "pid" => 1234
        }
      }
    ]

    alert_fixture(Keyword.merge(defaults, attrs))
  end

  # ===========================================================================
  # set_verdict/4 -- validation
  # ===========================================================================

  describe "set_verdict/4 validation" do
    test "rejects an invalid verdict value", %{org: org, user: user} do
      alert = detection_alert(org)

      assert {:error, :invalid_verdict} =
               Alerts.set_verdict(alert.id, "not_a_verdict", user.id)
    end

    test "returns not_found for an unknown alert id", %{user: user} do
      assert {:error, :not_found} =
               Alerts.set_verdict(Ecto.UUID.generate(), "false_positive", user.id)
    end
  end

  # ===========================================================================
  # set_verdict/4 -- false positive path
  # ===========================================================================

  describe "set_verdict/4 false positive" do
    test "marks the alert FP with notes and analyst attribution", %{org: org, user: user} do
      alert = detection_alert(org)

      assert {:ok, %{alert: updated, suppression_rule: nil, feedback_log: log}} =
               Alerts.set_verdict(alert.id, "false_positive", user.id,
                 notes: "Known admin tool, scheduled job"
               )

      assert updated.verdict == "false_positive"
      # FP verdict also flips workflow status
      assert updated.status == "false_positive"
      assert updated.verdict_notes == "Known admin tool, scheduled job"
      assert updated.verdict_by_id == user.id
      assert updated.verdict_at != nil
      # No suppression rule requested -> none linked
      assert updated.suppression_rule_id == nil

      # Audit log entry persisted with previous/new verdict and metadata
      assert %VerdictFeedbackLog{} = log
      assert log.alert_id == alert.id
      assert log.user_id == user.id
      assert log.previous_verdict == "unconfirmed"
      assert log.new_verdict == "false_positive"
      assert log.notes == "Known admin tool, scheduled job"
      assert log.metadata["agent_id"] == alert.agent_id
      assert log.metadata["title"] == alert.title
      assert log.metadata["severity"] == alert.severity

      persisted = Repo.get!(VerdictFeedbackLog, log.id)
      assert persisted.suppression_rule_created == false
    end

    test "records previous_verdict when the verdict is changed", %{org: org, user: user} do
      alert = detection_alert(org)

      assert {:ok, _} = Alerts.set_verdict(alert.id, "true_positive", user.id)

      assert {:ok, %{feedback_log: second_log}} =
               Alerts.set_verdict(alert.id, "false_positive", user.id,
                 notes: "Re-triaged: benign tooling"
               )

      assert second_log.previous_verdict == "true_positive"
      assert second_log.new_verdict == "false_positive"
    end

    test "broadcasts alert_updated on the org and alert topics", %{org: org, user: user} do
      alert = detection_alert(org)

      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "alerts:#{org.id}")
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "alert:#{alert.id}")

      assert {:ok, _} = Alerts.set_verdict(alert.id, "false_positive", user.id)

      alert_id = alert.id
      assert_receive {:alert_updated, %Alert{id: ^alert_id, verdict: "false_positive"}}
      assert_receive {:alert_updated, %Alert{id: ^alert_id, verdict: "false_positive"}}
    end

    test "accepts a nil user id (system verdict)", %{org: org} do
      alert = detection_alert(org)

      assert {:ok, %{alert: updated, feedback_log: log}} =
               Alerts.set_verdict(alert.id, "false_positive", nil)

      assert updated.verdict == "false_positive"
      assert updated.verdict_by_id == nil
      assert log.user_id == nil
    end
  end

  # ===========================================================================
  # set_verdict/4 -- other verdicts
  # ===========================================================================

  describe "set_verdict/4 true positive and benign" do
    test "true_positive moves the alert to investigating and never creates a suppression rule",
         %{org: org, user: user} do
      alert = detection_alert(org)

      # Even when the caller explicitly asks for a suppression rule, a TP must
      # never generate one (it would mute future real detections).
      assert {:ok, %{alert: updated, suppression_rule: nil}} =
               Alerts.set_verdict(alert.id, "true_positive", user.id,
                 create_suppression_rule: true
               )

      assert updated.verdict == "true_positive"
      assert updated.status == "investigating"
      assert updated.suppression_rule_id == nil
      assert Repo.aggregate(SuppressionRule, :count, :id) == 0
    end

    test "benign resolves the alert and may create a suppression rule", %{org: org, user: user} do
      alert = detection_alert(org)

      assert {:ok, %{alert: updated, suppression_rule: rule}} =
               Alerts.set_verdict(alert.id, "benign", user.id,
                 create_suppression_rule: true,
                 suppression_ttl_days: 14
               )

      assert updated.verdict == "benign"
      assert updated.status == "resolved"
      assert %SuppressionRule{} = rule
      assert updated.suppression_rule_id == rule.id
    end
  end

  # ===========================================================================
  # Suppression rule auto-generation with TTL
  # ===========================================================================

  describe "suppression rule auto-generation" do
    test "FP verdict with create_suppression_rule generates a linked rule with TTL",
         %{org: org, user: user} do
      alert =
        detection_alert(org,
          detection_metadata: %{"rule_name" => "sigma_noisy_rule"},
          evidence: %{
            "process" => %{"name" => "backup_agent.exe", "path" => "C:\\Backup\\backup_agent.exe"}
          }
        )

      assert {:ok, %{alert: updated, suppression_rule: rule, feedback_log: log}} =
               Alerts.set_verdict(alert.id, "false_positive", user.id,
                 notes: "Backup agent, recurring",
                 create_suppression_rule: true,
                 suppression_ttl_days: 7
               )

      assert %SuppressionRule{} = rule
      assert rule.enabled
      assert rule.action == "suppress"
      assert rule.source_alert_id == alert.id
      assert rule.organization_id == org.id
      assert rule.created_by_id == user.id
      assert rule.agent_id == alert.agent_id

      # Matching criteria extracted from the alert
      assert rule.title_pattern == alert.title
      assert rule.rule_name_pattern == "sigma_noisy_rule"
      assert rule.process_name_pattern == "backup_agent.exe"
      assert rule.file_path_pattern == "C:\\Backup\\backup_agent.exe"

      # TTL: expires ~7 days from now
      assert rule.expires_at != nil
      ttl_seconds = DateTime.diff(rule.expires_at, DateTime.utc_now())
      assert_in_delta ttl_seconds, 7 * @day_seconds, 120

      # Rule is linked back to the alert
      assert updated.suppression_rule_id == rule.id

      # Feedback log flag updated post-insert
      assert Repo.get!(VerdictFeedbackLog, log.id).suppression_rule_created == true
    end

    test "defaults to a 30-day TTL when none is specified", %{org: org, user: user} do
      alert = detection_alert(org)

      assert {:ok, %{suppression_rule: rule}} =
               Alerts.set_verdict(alert.id, "false_positive", user.id,
                 create_suppression_rule: true
               )

      ttl_seconds = DateTime.diff(rule.expires_at, DateTime.utc_now())
      assert_in_delta ttl_seconds, 30 * @day_seconds, 120
    end

    test "does not create a rule when create_suppression_rule is false (default)",
         %{org: org, user: user} do
      alert = detection_alert(org)

      assert {:ok, %{suppression_rule: nil, feedback_log: log}} =
               Alerts.set_verdict(alert.id, "false_positive", user.id)

      assert Repo.aggregate(SuppressionRule, :count, :id) == 0
      assert Repo.get!(VerdictFeedbackLog, log.id).suppression_rule_created == false
    end

    test "supports the reduce_severity suppression action", %{org: org, user: user} do
      alert = detection_alert(org)

      assert {:ok, %{suppression_rule: rule}} =
               Alerts.set_verdict(alert.id, "false_positive", user.id,
                 create_suppression_rule: true,
                 suppression_action: "reduce_severity"
               )

      assert rule.action == "reduce_severity"
    end
  end

  # ===========================================================================
  # TTL expiry behavior
  # ===========================================================================

  describe "suppression rule TTL expiry" do
    test "expired rules are excluded from active rule queries", %{org: org, user: user} do
      alert = detection_alert(org)
      agent_id = alert.agent_id

      assert {:ok, %{suppression_rule: rule}} =
               Alerts.set_verdict(alert.id, "false_positive", user.id,
                 create_suppression_rule: true,
                 suppression_ttl_days: 7
               )

      # Rule is active while unexpired
      active_ids = Alerts.get_suppression_rules(agent_id) |> Enum.map(& &1.id)
      assert rule.id in active_ids

      # Force-expire the rule (simulate TTL elapsing)
      expired_at = DateTime.add(DateTime.utc_now(), -60, :second)
      {:ok, expired_rule} = Alerts.update_suppression_rule(rule, %{expires_at: expired_at})
      assert DateTime.compare(expired_rule.expires_at, DateTime.utc_now()) == :lt

      # Excluded from agent-scoped active rules
      active_ids = Alerts.get_suppression_rules(agent_id) |> Enum.map(& &1.id)
      refute rule.id in active_ids

      # Excluded from enabled_only listing, but still present in the full list
      enabled_ids =
        Alerts.list_suppression_rules(enabled_only: true) |> Enum.map(& &1.id)

      refute rule.id in enabled_ids

      all_ids = Alerts.list_suppression_rules() |> Enum.map(& &1.id)
      assert rule.id in all_ids
    end

    test "disabled rules are excluded from active rule queries", %{org: org, user: user} do
      alert = detection_alert(org)

      assert {:ok, %{suppression_rule: rule}} =
               Alerts.set_verdict(alert.id, "false_positive", user.id,
                 create_suppression_rule: true
               )

      {:ok, _disabled} = Alerts.toggle_suppression_rule(rule)

      active_ids = Alerts.get_suppression_rules(alert.agent_id) |> Enum.map(& &1.id)
      refute rule.id in active_ids
    end

    test "expired rules are not counted in verdict stats", %{org: org, user: user} do
      alert = detection_alert(org)

      assert {:ok, %{suppression_rule: rule}} =
               Alerts.set_verdict(alert.id, "false_positive", user.id,
                 create_suppression_rule: true
               )

      assert Alerts.get_verdict_stats(organization_id: org.id).active_suppression_rules == 1

      expired_at = DateTime.add(DateTime.utc_now(), -60, :second)
      {:ok, _} = Alerts.update_suppression_rule(rule, %{expires_at: expired_at})

      assert Alerts.get_verdict_stats(organization_id: org.id).active_suppression_rules == 0
    end
  end

  # ===========================================================================
  # get_verdict_stats/1
  # ===========================================================================

  describe "get_verdict_stats/1" do
    test "aggregates FP rate, reviewed/unreviewed counts, and top FP rules",
         %{org: org, user: user} do
      # 2 FPs from "Noisy Rule A", 1 FP from "Noisy Rule B"
      fp_a1 = detection_alert(org, detection_metadata: %{"rule_name" => "Noisy Rule A"})
      fp_a2 = detection_alert(org, detection_metadata: %{"rule_name" => "Noisy Rule A"})
      fp_b = detection_alert(org, detection_metadata: %{"rule_name" => "Noisy Rule B"})
      tp = detection_alert(org)
      benign = detection_alert(org)
      _unreviewed1 = detection_alert(org)
      _unreviewed2 = detection_alert(org)

      for a <- [fp_a1, fp_a2, fp_b] do
        assert {:ok, _} = Alerts.set_verdict(a.id, "false_positive", user.id)
      end

      assert {:ok, _} = Alerts.set_verdict(tp.id, "true_positive", user.id)
      assert {:ok, _} = Alerts.set_verdict(benign.id, "benign", user.id)

      stats = Alerts.get_verdict_stats(organization_id: org.id, days: 30)

      assert stats.total_alerts == 7
      assert stats.by_verdict["false_positive"] == 3
      assert stats.by_verdict["true_positive"] == 1
      assert stats.by_verdict["benign"] == 1
      assert stats.by_verdict["unconfirmed"] == 2

      # reviewed = FP + TP + benign = 5; fp_rate = 3/5 = 60.0%
      assert stats.reviewed_count == 5
      assert stats.unreviewed_count == 2
      assert stats.false_positive_rate == 60.0

      # Top FP rules ordered by FP count
      assert [%{rule_name: "Noisy Rule A", fp_count: 2}, %{rule_name: "Noisy Rule B", fp_count: 1}] =
               stats.top_fp_rules

      assert stats.days == 30
    end

    test "scopes counts to the given organization", %{org: org, user: user} do
      other_org = organization_fixture()

      alert = detection_alert(org)
      other_alert = detection_alert(other_org)

      assert {:ok, _} = Alerts.set_verdict(alert.id, "false_positive", user.id)
      assert {:ok, _} = Alerts.set_verdict(other_alert.id, "false_positive", user.id)

      stats = Alerts.get_verdict_stats(organization_id: org.id)

      assert stats.total_alerts == 1
      assert stats.by_verdict["false_positive"] == 1
    end

    test "excludes alerts older than the days window", %{org: org, user: user} do
      recent = detection_alert(org)
      old = detection_alert(org)

      assert {:ok, _} = Alerts.set_verdict(recent.id, "false_positive", user.id)
      assert {:ok, _} = Alerts.set_verdict(old.id, "false_positive", user.id)

      # Backdate the old alert beyond the 30-day window
      backdated = DateTime.add(DateTime.utc_now(), -40 * @day_seconds, :second)

      Repo.update_all(
        from(a in Alert, where: a.id == ^old.id),
        set: [inserted_at: backdated]
      )

      stats = Alerts.get_verdict_stats(organization_id: org.id, days: 30)

      assert stats.total_alerts == 1
      assert stats.by_verdict["false_positive"] == 1
    end

    test "returns a zero FP rate when nothing has been reviewed", %{org: org} do
      _unreviewed = detection_alert(org)

      stats = Alerts.get_verdict_stats(organization_id: org.id)

      assert stats.false_positive_rate == 0.0
      assert stats.reviewed_count == 0
      assert stats.unreviewed_count == 1
    end
  end

  # ===========================================================================
  # bulk_set_verdict/4
  # ===========================================================================

  describe "bulk_set_verdict/4" do
    test "applies the verdict to all alerts and reports counts", %{org: org, user: user} do
      alerts = for _ <- 1..3, do: detection_alert(org)
      ids = Enum.map(alerts, & &1.id)

      assert {:ok, %{updated: 3, errors: 0, suppression_rules_created: 3}} =
               Alerts.bulk_set_verdict(ids, "false_positive", user.id,
                 create_suppression_rule: true,
                 suppression_ttl_days: 7
               )

      for id <- ids do
        assert Repo.get!(Alert, id).verdict == "false_positive"
      end

      assert Repo.aggregate(SuppressionRule, :count, :id) == 3
    end

    test "counts unknown alert ids as errors", %{org: org, user: user} do
      alert = detection_alert(org)

      assert {:ok, %{updated: 1, errors: 1}} =
               Alerts.bulk_set_verdict(
                 [alert.id, Ecto.UUID.generate()],
                 "false_positive",
                 user.id
               )
    end

    test "rejects invalid verdicts up front", %{user: user} do
      assert {:error, :invalid_verdict} =
               Alerts.bulk_set_verdict([Ecto.UUID.generate()], "bogus", user.id)
    end
  end

  # ===========================================================================
  # get_feedback_log/1
  # ===========================================================================

  describe "get_feedback_log/1" do
    test "returns entries for an alert, newest first", %{org: org, user: user} do
      alert = detection_alert(org)
      other = detection_alert(org)

      assert {:ok, _} = Alerts.set_verdict(alert.id, "true_positive", user.id)
      assert {:ok, _} = Alerts.set_verdict(alert.id, "false_positive", user.id, notes: "re-triaged")
      assert {:ok, _} = Alerts.set_verdict(other.id, "benign", user.id)

      log = Alerts.get_feedback_log(alert.id)

      assert length(log) == 2
      assert [newest, oldest] = log
      assert newest.new_verdict == "false_positive"
      assert newest.previous_verdict == "true_positive"
      assert oldest.new_verdict == "true_positive"
      assert oldest.previous_verdict == "unconfirmed"

      # User preloaded for the audit trail UI
      assert newest.user.id == user.id
    end

    test "returns an empty list for an alert with no verdicts", %{org: org} do
      alert = detection_alert(org)
      assert Alerts.get_feedback_log(alert.id) == []
    end
  end
end
