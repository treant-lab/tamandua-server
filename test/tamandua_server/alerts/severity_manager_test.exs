defmodule TamanduaServer.Alerts.SeverityManagerTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Alerts.SeverityManager
  alias TamanduaServer.Alerts.SeverityAdjustment
  alias TamanduaServer.Repo

  import TamanduaServer.AccountsFixtures
  import TamanduaServer.AlertsFixtures

  describe "severity adjustment" do
    setup do
      org = organization_fixture()
      user = user_fixture(%{organization_id: org.id})
      alert = alert_fixture(%{organization_id: org.id, severity: "high"})

      %{organization: org, user: user, alert: alert}
    end

    test "adjust_severity/5 creates adjustment and updates alert for non-critical changes", %{
      alert: alert,
      user: user,
      organization: org
    } do
      reason = "This alert was triggered by legitimate admin activity"

      assert {:ok, {adjustment, updated_alert}} =
               SeverityManager.adjust_severity(
                 alert.id,
                 "medium",
                 reason,
                 user,
                 organization_id: org.id
               )

      assert adjustment.alert_id == alert.id
      assert adjustment.old_severity == "high"
      assert adjustment.new_severity == "medium"
      assert adjustment.reason == reason
      assert adjustment.adjusted_by_id == user.id
      assert adjustment.requires_approval == false

      assert updated_alert.severity == "medium"
      assert updated_alert.original_severity == "high"
      assert updated_alert.severity_adjusted == true
      assert updated_alert.severity_adjusted_by_id == user.id
    end

    test "adjust_severity/5 requires approval for critical downgrades", %{
      user: user,
      organization: org
    } do
      # Create a critical alert
      alert = alert_fixture(%{organization_id: org.id, severity: "critical"})
      reason = "False positive - testing tool detected"

      assert {:ok, {adjustment, :pending_approval}} =
               SeverityManager.adjust_severity(
                 alert.id,
                 "medium",
                 reason,
                 user,
                 organization_id: org.id
               )

      assert adjustment.requires_approval == true
      assert is_nil(adjustment.approved)

      # Alert severity should NOT be changed yet
      updated_alert = Repo.get(TamanduaServer.Alerts.Alert, alert.id)
      assert updated_alert.severity == "critical"
    end

    test "adjust_severity/5 validates reason length", %{alert: alert, user: user, organization: org} do
      short_reason = "too short"

      assert {:error, {changeset, _}} =
               catch_error(
                 SeverityManager.adjust_severity(
                   alert.id,
                   "medium",
                   short_reason,
                   user,
                   organization_id: org.id
                 )
               )
    end

    test "adjust_severity/5 rejects same severity", %{alert: alert, user: user, organization: org} do
      assert {:error, :same_severity} =
               SeverityManager.adjust_severity(
                 alert.id,
                 "high",
                 "This should fail",
                 user,
                 organization_id: org.id
               )
    end

    test "adjust_severity/5 includes optional notes", %{alert: alert, user: user, organization: org} do
      reason = "This alert was triggered by legitimate admin activity"
      notes = "Confirmed with IT team - scheduled maintenance"

      assert {:ok, {adjustment, _updated_alert}} =
               SeverityManager.adjust_severity(
                 alert.id,
                 "medium",
                 reason,
                 user,
                 organization_id: org.id,
                 notes: notes
               )

      assert adjustment.notes == notes
    end
  end

  describe "adjustment approval" do
    setup do
      org = organization_fixture()
      adjuster = user_fixture(%{organization_id: org.id, email: "adjuster@test.com"})
      approver = user_fixture(%{organization_id: org.id, email: "approver@test.com"})
      alert = alert_fixture(%{organization_id: org.id, severity: "critical"})

      # Create adjustment requiring approval
      {:ok, {adjustment, :pending_approval}} =
        SeverityManager.adjust_severity(
          alert.id,
          "low",
          "False positive detection",
          adjuster,
          organization_id: org.id
        )

      %{
        organization: org,
        adjuster: adjuster,
        approver: approver,
        alert: alert,
        adjustment: adjustment
      }
    end

    test "approve_adjustment/3 approves and applies severity change", %{
      adjustment: adjustment,
      approver: approver,
      organization: org,
      alert: alert
    } do
      assert {:ok, {updated_adjustment, updated_alert}} =
               SeverityManager.approve_adjustment(adjustment.id, approver, org.id)

      assert updated_adjustment.approved == true
      assert updated_adjustment.approved_by_id == approver.id
      assert updated_adjustment.approved_at != nil

      assert updated_alert.severity == "low"
      assert updated_alert.severity_adjusted == true
    end

    test "approve_adjustment/3 prevents self-approval", %{
      adjustment: adjustment,
      adjuster: adjuster,
      organization: org
    } do
      assert {:error, :cannot_approve_own_adjustment} =
               SeverityManager.approve_adjustment(adjustment.id, adjuster, org.id)
    end

    test "approve_adjustment/3 prevents duplicate approval", %{
      adjustment: adjustment,
      approver: approver,
      organization: org
    } do
      {:ok, _} = SeverityManager.approve_adjustment(adjustment.id, approver, org.id)

      # Try to approve again
      assert {:error, :already_processed} =
               SeverityManager.approve_adjustment(adjustment.id, approver, org.id)
    end

    test "reject_adjustment/4 rejects with reason", %{
      adjustment: adjustment,
      approver: approver,
      organization: org,
      alert: alert
    } do
      rejection_reason = "Insufficient justification provided"

      assert {:ok, updated_adjustment} =
               SeverityManager.reject_adjustment(adjustment.id, rejection_reason, approver, org.id)

      assert updated_adjustment.approved == false
      assert updated_adjustment.rejection_reason == rejection_reason

      # Alert severity should remain unchanged
      unchanged_alert = Repo.get(TamanduaServer.Alerts.Alert, alert.id)
      assert unchanged_alert.severity == "critical"
    end
  end

  describe "adjustment history" do
    setup do
      org = organization_fixture()
      user = user_fixture(%{organization_id: org.id})
      alert = alert_fixture(%{organization_id: org.id, severity: "high"})

      %{organization: org, user: user, alert: alert}
    end

    test "list_alert_adjustments/2 returns adjustment history", %{
      alert: alert,
      user: user,
      organization: org
    } do
      # Make multiple adjustments
      {:ok, {_adj1, _}} =
        SeverityManager.adjust_severity(
          alert.id,
          "medium",
          "First adjustment",
          user,
          organization_id: org.id
        )

      # Update alert to medium for next adjustment
      updated_alert = Repo.get(TamanduaServer.Alerts.Alert, alert.id)

      {:ok, {_adj2, _}} =
        SeverityManager.adjust_severity(
          updated_alert.id,
          "low",
          "Second adjustment",
          user,
          organization_id: org.id
        )

      history = SeverityManager.list_alert_adjustments(alert.id)

      assert length(history) == 2
      # Should be ordered by most recent first
      assert hd(history).reason == "Second adjustment"
    end

    test "list_pending_adjustments/2 returns only pending approvals", %{organization: org} do
      user = user_fixture(%{organization_id: org.id})

      # Create critical alert requiring approval
      alert1 = alert_fixture(%{organization_id: org.id, severity: "critical"})
      alert2 = alert_fixture(%{organization_id: org.id, severity: "critical"})

      {:ok, {_adj1, :pending_approval}} =
        SeverityManager.adjust_severity(
          alert1.id,
          "low",
          "Pending adjustment 1",
          user,
          organization_id: org.id
        )

      {:ok, {_adj2, :pending_approval}} =
        SeverityManager.adjust_severity(
          alert2.id,
          "medium",
          "Pending adjustment 2",
          user,
          organization_id: org.id
        )

      pending = SeverityManager.list_pending_adjustments(org.id)

      assert length(pending) == 2
      assert Enum.all?(pending, &(&1.requires_approval == true))
      assert Enum.all?(pending, &is_nil(&1.approved))
    end
  end

  describe "bulk operations" do
    setup do
      org = organization_fixture()
      user = user_fixture(%{organization_id: org.id})

      alert1 = alert_fixture(%{organization_id: org.id, severity: "high"})
      alert2 = alert_fixture(%{organization_id: org.id, severity: "medium"})
      alert3 = alert_fixture(%{organization_id: org.id, severity: "high"})

      %{organization: org, user: user, alerts: [alert1, alert2, alert3]}
    end

    test "bulk_adjust_severity/5 adjusts multiple alerts", %{
      organization: org,
      user: user,
      alerts: alerts
    } do
      alert_ids = Enum.map(alerts, & &1.id)

      result =
        SeverityManager.bulk_adjust_severity(
          alert_ids,
          "low",
          "Bulk adjustment test",
          user,
          organization_id: org.id
        )

      assert result.succeeded == 3
      assert result.errors == []

      # Verify all alerts were adjusted
      for alert <- alerts do
        updated_alert = Repo.get(TamanduaServer.Alerts.Alert, alert.id)
        assert updated_alert.severity == "low"
      end
    end

    test "bulk_adjust_severity/5 separates pending approvals", %{organization: org, user: user} do
      # Create critical alerts
      alert1 = alert_fixture(%{organization_id: org.id, severity: "critical"})
      alert2 = alert_fixture(%{organization_id: org.id, severity: "critical"})

      alert_ids = [alert1.id, alert2.id]

      result =
        SeverityManager.bulk_adjust_severity(
          alert_ids,
          "low",
          "Bulk critical downgrade",
          user,
          organization_id: org.id
        )

      assert length(result.pending) == 2
      assert result.succeeded == 0
    end
  end

  describe "statistics" do
    setup do
      org = organization_fixture()
      user = user_fixture(%{organization_id: org.id})

      %{organization: org, user: user}
    end

    test "adjustment_statistics/2 returns adjustment breakdown", %{
      organization: org,
      user: user
    } do
      # Create various adjustments
      for _ <- 1..3 do
        alert = alert_fixture(%{organization_id: org.id, severity: "high"})

        SeverityManager.adjust_severity(
          alert.id,
          "medium",
          "Test adjustment",
          user,
          organization_id: org.id
        )
      end

      for _ <- 1..2 do
        alert = alert_fixture(%{organization_id: org.id, severity: "medium"})

        SeverityManager.adjust_severity(
          alert.id,
          "low",
          "Test adjustment",
          user,
          organization_id: org.id
        )
      end

      stats = SeverityManager.adjustment_statistics(org.id)

      assert length(stats.adjustments) == 2

      high_to_medium = Enum.find(stats.adjustments, &(&1.old_severity == "high" && &1.new_severity == "medium"))
      assert high_to_medium.count == 3

      medium_to_low = Enum.find(stats.adjustments, &(&1.old_severity == "medium" && &1.new_severity == "low"))
      assert medium_to_low.count == 2
    end

    test "adjustment_statistics/2 includes pending approval count", %{
      organization: org,
      user: user
    } do
      alert = alert_fixture(%{organization_id: org.id, severity: "critical"})

      {:ok, {_adj, :pending_approval}} =
        SeverityManager.adjust_severity(
          alert.id,
          "low",
          "Pending test",
          user,
          organization_id: org.id
        )

      stats = SeverityManager.adjustment_statistics(org.id)

      assert stats.pending_approvals == 1
    end
  end

  describe "validation" do
    test "requires_approval?/2 identifies critical downgrades" do
      assert SeverityAdjustment.requires_approval?("critical", "high") == true
      assert SeverityAdjustment.requires_approval?("critical", "medium") == true
      assert SeverityAdjustment.requires_approval?("critical", "low") == true
      assert SeverityAdjustment.requires_approval?("critical", "info") == true
      assert SeverityAdjustment.requires_approval?("high", "medium") == true
      assert SeverityAdjustment.requires_approval?("high", "low") == true

      # These should not require approval
      assert SeverityAdjustment.requires_approval?("low", "high") == false
      assert SeverityAdjustment.requires_approval?("medium", "high") == false
      assert SeverityAdjustment.requires_approval?("medium", "low") == false
    end
  end
end
