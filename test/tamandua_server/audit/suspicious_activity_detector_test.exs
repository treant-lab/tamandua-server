defmodule TamanduaServer.Audit.SuspiciousActivityDetectorTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Audit.{SuspiciousActivityDetector, ActivityLogger, AuditLog}
  alias TamanduaServer.Accounts.{User, Organization}

  setup do
    org = insert(:organization)
    user = insert(:user, organization: org)
    {:ok, organization: org, user: user}
  end

  describe "check_failed_logins/1" do
    test "detects multiple failed login attempts", %{organization: org} do
      # Create 5 failed login attempts
      for _ <- 1..5 do
        ActivityLogger.log_login_failure(
          "test@example.com",
          org.id,
          "192.168.1.1",
          "Invalid password"
        )
      end

      # The 6th attempt should be flagged as suspicious
      {:ok, log} = ActivityLogger.log_login_failure(
        "test@example.com",
        org.id,
        "192.168.1.1",
        "Invalid password"
      )

      assert log.suspicious == true
      assert log.suspicious_reason =~ "Multiple failed login attempts"
      assert log.risk_score == 80
    end

    test "does not flag failed logins from different IPs", %{organization: org} do
      for i <- 1..3 do
        ActivityLogger.log_login_failure(
          "test@example.com",
          org.id,
          "192.168.1.#{i}",
          "Invalid password"
        )
      end

      {:ok, log} = ActivityLogger.log_login_failure(
        "test@example.com",
        org.id,
        "192.168.1.100",
        "Invalid password"
      )

      assert log.suspicious == false
    end
  end

  describe "check_new_ip/1" do
    test "flags login from new IP address", %{organization: org, user: user} do
      # First login from known IP
      ActivityLogger.log_login(user.id, org.id, "192.168.1.1", "Mozilla/5.0")

      # Wait a moment
      Process.sleep(100)

      # Login from new IP
      {:ok, log} = ActivityLogger.log_login(
        user.id,
        org.id,
        "10.0.0.1",
        "Mozilla/5.0"
      )

      assert log.suspicious == true
      assert log.suspicious_reason =~ "new IP address"
      assert log.risk_score == 50
    end
  end

  describe "check_privilege_escalation/1" do
    test "flags admin role assignment", %{organization: org, user: user} do
      {:ok, log} = ActivityLogger.log(%{
        action: "authz.role_assigned",
        resource_type: "user",
        resource_id: user.id,
        user_id: user.id,
        organization_id: org.id,
        metadata: %{"new_role" => "admin"}
      })

      assert log.suspicious == true
      assert log.suspicious_reason =~ "Admin role assigned"
      assert log.risk_score == 70
    end

    test "flags explicit privilege escalation attempts", %{organization: org, user: user} do
      {:ok, log} = ActivityLogger.log(%{
        action: "security.privilege_escalation_attempt",
        resource_type: "user",
        user_id: user.id,
        organization_id: org.id
      })

      assert log.suspicious == true
      assert log.risk_score == 90
    end
  end

  describe "check_bulk_access/1" do
    test "detects bulk data access", %{organization: org, user: user} do
      # Create 100+ data access events in short time
      for _ <- 1..100 do
        ActivityLogger.log(%{
          action: "data.logs_exported",
          resource_type: "logs",
          user_id: user.id,
          organization_id: org.id,
          category: "data_access"
        })
      end

      # The next access should be flagged
      {:ok, log} = ActivityLogger.log(%{
        action: "data.logs_exported",
        resource_type: "logs",
        user_id: user.id,
        organization_id: org.id,
        category: "data_access"
      })

      assert log.suspicious == true
      assert log.suspicious_reason =~ "Bulk data access"
      assert log.risk_score == 75
    end
  end

  describe "check_off_hours/1" do
    test "flags activity during off-hours", %{organization: org, user: user} do
      # Mock timestamp for 3 AM
      off_hours_time = DateTime.utc_now() |> Map.put(:hour, 3)

      {:ok, log} = ActivityLogger.log(%{
        action: "config.setting_changed",
        resource_type: "config",
        user_id: user.id,
        organization_id: org.id,
        category: "configuration"
      })

      # Manually update timestamp for testing
      log = Repo.update!(Ecto.Changeset.change(log, inserted_at: off_hours_time))

      result = SuspiciousActivityDetector.analyze(log)

      assert {:suspicious, reason, risk_score} = result
      assert reason =~ "off-hours"
      assert risk_score == 40
    end
  end

  describe "check_impossible_travel/1" do
    test "detects impossible travel", %{organization: org, user: user} do
      # Login from first location
      ActivityLogger.log_login(user.id, org.id, "192.168.1.1", "Mozilla/5.0")

      # Wait briefly (less than physically possible to travel)
      Process.sleep(100)

      # Login from different location
      {:ok, log} = ActivityLogger.log_login(
        user.id,
        org.id,
        "10.0.0.1",
        "Mozilla/5.0"
      )

      # Should be flagged if within 30 minutes from different IP
      # (This is a simplified check - real implementation would use GeoIP)
      assert log.risk_score >= 50
    end
  end

  describe "get_suspicious_summary/2" do
    test "returns summary of suspicious activities", %{organization: org, user: user} do
      # Create some suspicious activities
      for _ <- 1..5 do
        ActivityLogger.log_login_failure(
          "test@example.com",
          org.id,
          "192.168.1.1",
          "Invalid password"
        )
      end

      summary = SuspiciousActivityDetector.get_suspicious_summary(org.id, 7)

      assert summary.total_count > 0
      assert is_list(summary.by_reason)
      assert is_list(summary.by_user)
      assert is_list(summary.high_risk)
    end
  end
end
