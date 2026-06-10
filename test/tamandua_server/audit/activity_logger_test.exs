defmodule TamanduaServer.Audit.ActivityLoggerTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Audit.{ActivityLogger, AuditLog}
  alias TamanduaServer.Accounts.{User, Organization}

  setup do
    org = insert(:organization)
    user = insert(:user, organization: org)
    {:ok, organization: org, user: user}
  end

  describe "log/1" do
    test "creates audit log entry", %{organization: org, user: user} do
      {:ok, log} = ActivityLogger.log(%{
        action: "alert.created",
        resource_type: "alert",
        resource_id: Ecto.UUID.generate(),
        user_id: user.id,
        organization_id: org.id,
        ip_address: "192.168.1.100",
        metadata: %{alert_title: "Test Alert"}
      })

      assert log.action == "alert.created"
      assert log.resource_type == "alert"
      assert log.user_id == user.id
      assert log.success == true
    end

    test "sets default values", %{organization: org} do
      {:ok, log} = ActivityLogger.log(%{
        action: "test.action",
        resource_type: "test",
        organization_id: org.id
      })

      assert log.success == true
      assert log.severity == "info"
      assert log.metadata == %{}
    end
  end

  describe "log_login/4" do
    test "logs successful login", %{organization: org, user: user} do
      {:ok, log} = ActivityLogger.log_login(
        user.id,
        org.id,
        "192.168.1.1",
        "Mozilla/5.0"
      )

      assert log.action == "auth.login_success"
      assert log.resource_type == "user"
      assert log.ip_address == "192.168.1.1"
      assert log.category == "authentication"
    end
  end

  describe "log_login_failure/4" do
    test "logs failed login attempt", %{organization: org} do
      {:ok, log} = ActivityLogger.log_login_failure(
        "test@example.com",
        org.id,
        "192.168.1.1",
        "Invalid password"
      )

      assert log.action == "auth.login_failed"
      assert log.success == false
      assert log.severity == "medium"
      assert log.metadata["email"] == "test@example.com"
    end
  end

  describe "search_paginated/4" do
    test "returns paginated results", %{organization: org, user: user} do
      # Create multiple log entries
      for i <- 1..25 do
        ActivityLogger.log(%{
          action: "test.action_#{i}",
          resource_type: "test",
          user_id: user.id,
          organization_id: org.id
        })
      end

      result = ActivityLogger.search_paginated(org.id, %{}, 1, 10)

      assert length(result.entries) == 10
      assert result.page == 1
      assert result.per_page == 10
      assert result.total == 25
      assert result.total_pages == 3
    end

    test "filters by user_id", %{organization: org} do
      user1 = insert(:user, organization: org)
      user2 = insert(:user, organization: org)

      ActivityLogger.log(%{
        action: "test.action",
        resource_type: "test",
        user_id: user1.id,
        organization_id: org.id
      })

      ActivityLogger.log(%{
        action: "test.action",
        resource_type: "test",
        user_id: user2.id,
        organization_id: org.id
      })

      result = ActivityLogger.search_paginated(org.id, %{user_id: user1.id})

      assert length(result.entries) == 1
      assert hd(result.entries).user_id == user1.id
    end

    test "filters by action", %{organization: org} do
      ActivityLogger.log(%{
        action: "alert.created",
        resource_type: "alert",
        organization_id: org.id
      })

      ActivityLogger.log(%{
        action: "alert.status_changed",
        resource_type: "alert",
        organization_id: org.id
      })

      result = ActivityLogger.search_paginated(org.id, %{action: "alert.created"})

      assert length(result.entries) == 1
      assert hd(result.entries).action == "alert.created"
    end

    test "filters by date range", %{organization: org} do
      yesterday = DateTime.add(DateTime.utc_now(), -86400, :second)
      tomorrow = DateTime.add(DateTime.utc_now(), 86400, :second)

      ActivityLogger.log(%{
        action: "test.action",
        resource_type: "test",
        organization_id: org.id
      })

      result = ActivityLogger.search_paginated(org.id, %{
        from_date: yesterday,
        to_date: tomorrow
      })

      assert length(result.entries) == 1
    end

    test "filters by suspicious flag", %{organization: org} do
      {:ok, log} = ActivityLogger.log(%{
        action: "test.action",
        resource_type: "test",
        organization_id: org.id
      })

      # Mark as suspicious
      log
      |> Ecto.Changeset.change(%{suspicious: true, suspicious_reason: "Test"})
      |> Repo.update!()

      result = ActivityLogger.search_paginated(org.id, %{suspicious: true})

      assert length(result.entries) == 1
      assert hd(result.entries).suspicious == true
    end
  end

  describe "activity broadcasting" do
    test "broadcasts new activity to PubSub", %{organization: org, user: user} do
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "activity:org:#{org.id}")

      {:ok, log} = ActivityLogger.log(%{
        action: "alert.created",
        resource_type: "alert",
        user_id: user.id,
        organization_id: org.id
      })

      assert_receive {:new_activity, ^log}
    end

    test "broadcasts suspicious activity separately", %{organization: org} do
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "suspicious_activity:org:#{org.id}")

      # This would trigger suspicious activity detection
      for _ <- 1..6 do
        ActivityLogger.log_login_failure(
          "test@example.com",
          org.id,
          "192.168.1.1",
          "Invalid password"
        )
      end

      # Should receive suspicious activity broadcast
      assert_receive {:suspicious_activity, _log}, 1000
    end
  end
end
