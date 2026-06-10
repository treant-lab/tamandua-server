defmodule TamanduaServer.NotificationCenterTest do
  use TamanduaServer.DataCase

  alias TamanduaServer.NotificationCenter
  alias TamanduaServer.NotificationCenter.{
    Notification,
    UserPreference,
    EscalationPolicy
  }

  describe "notifications" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      %{organization: org, user: user}
    end

    test "list_notifications/2 returns notifications for user", %{user: user} do
      notification = insert(:notification, user: user)
      notifications = NotificationCenter.list_notifications(user.id)

      assert length(notifications) == 1
      assert List.first(notifications).id == notification.id
    end

    test "unread_count/1 returns count of unread notifications", %{user: user} do
      insert(:notification, user: user)
      insert(:notification, user: user, read_at: DateTime.utc_now())

      assert NotificationCenter.unread_count(user.id) == 1
    end

    test "mark_as_read/1 marks notification as read", %{user: user} do
      notification = insert(:notification, user: user)

      assert is_nil(notification.read_at)

      {:ok, updated} = NotificationCenter.mark_as_read(notification)

      refute is_nil(updated.read_at)
    end

    test "mark_all_as_read/1 marks all notifications as read", %{user: user} do
      insert(:notification, user: user)
      insert(:notification, user: user)

      {count, _} = NotificationCenter.mark_all_as_read(user.id)

      assert count == 2
      assert NotificationCenter.unread_count(user.id) == 0
    end

    test "cleanup_expired_notifications/0 removes expired notifications", %{user: user} do
      # Create expired notification
      yesterday = DateTime.utc_now() |> DateTime.add(-86400, :second)
      insert(:notification, user: user, expires_at: yesterday)

      # Create valid notification
      tomorrow = DateTime.utc_now() |> DateTime.add(86400, :second)
      insert(:notification, user: user, expires_at: tomorrow)

      {:ok, count} = NotificationCenter.cleanup_expired_notifications()

      assert count == 1
      assert length(NotificationCenter.list_notifications(user.id)) == 1
    end
  end

  describe "user preferences" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      %{organization: org, user: user}
    end

    test "get_user_preferences/2 creates default if not exists", %{user: user, organization: org} do
      {:ok, pref} = NotificationCenter.get_user_preferences(user.id, org.id)

      assert pref.user_id == user.id
      assert pref.organization_id == org.id
      assert pref.enabled == true
      assert pref.frequency == "immediate"
    end

    test "update_user_preferences/2 updates preferences", %{user: user, organization: org} do
      {:ok, pref} = NotificationCenter.get_user_preferences(user.id, org.id)

      {:ok, updated} =
        NotificationCenter.update_user_preferences(pref, %{
          frequency: "digest_hourly",
          min_severity: "high"
        })

      assert updated.frequency == "digest_hourly"
      assert updated.min_severity == "high"
    end

    test "update_user_preferences/2 validates channel preferences", %{
      user: user,
      organization: org
    } do
      {:ok, pref} = NotificationCenter.get_user_preferences(user.id, org.id)

      {:ok, updated} =
        NotificationCenter.update_user_preferences(pref, %{
          channel_preferences: %{
            "alert_new" => ["in_app", "email"],
            "comment_mention" => ["in_app"]
          }
        })

      assert updated.channel_preferences["alert_new"] == ["in_app", "email"]
    end
  end

  describe "escalation policies" do
    setup do
      org = insert(:organization)
      user1 = insert(:user, organization: org)
      user2 = insert(:user, organization: org)
      %{organization: org, user1: user1, user2: user2}
    end

    test "create_escalation_policy/1 creates policy", %{organization: org, user1: user1, user2: user2} do
      attrs = %{
        organization_id: org.id,
        name: "Tier 1 Escalation",
        escalation_chain: [
          %{"user_id" => user1.id, "delay_minutes" => 15},
          %{"user_id" => user2.id, "delay_minutes" => 30}
        ]
      }

      {:ok, policy} = NotificationCenter.create_escalation_policy(attrs)

      assert policy.name == "Tier 1 Escalation"
      assert length(policy.escalation_chain) == 2
    end

    test "list_escalation_policies/1 returns policies for org", %{organization: org, user1: user1} do
      insert(:escalation_policy, organization: org, escalation_chain: [
        %{"user_id" => user1.id, "delay_minutes" => 15}
      ])

      policies = NotificationCenter.list_escalation_policies(org.id)

      assert length(policies) == 1
    end

    test "validate escalation chain format", %{organization: org} do
      # Invalid - missing delay_minutes
      attrs = %{
        organization_id: org.id,
        name: "Invalid",
        escalation_chain: [
          %{"user_id" => Ecto.UUID.generate()}
        ]
      }

      {:error, changeset} = NotificationCenter.create_escalation_policy(attrs)

      assert changeset.errors[:escalation_chain]
    end
  end

  describe "dispatcher" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      alert = insert(:alert, organization: org, assigned_to: user)
      %{organization: org, user: user, alert: alert}
    end

    test "dispatch/4 creates notification", %{organization: org, user: user, alert: alert} do
      {:ok, notifications} =
        NotificationCenter.dispatch(
          "alert_new",
          "New Alert: #{alert.title}",
          "A new alert was created",
          %{
            organization_id: org.id,
            users: [user.id],
            related_resource_type: "alert",
            related_resource_id: alert.id
          }
        )

      assert length(notifications) == 1
      notification = List.first(notifications)
      assert notification.type == "alert_new"
      assert notification.user_id == user.id
    end

    test "dispatch/4 groups similar notifications", %{organization: org, user: user} do
      group_key = "test_group"

      # First notification
      {:ok, [notification1]} =
        NotificationCenter.dispatch(
          "alert_new",
          "Alert 1",
          "Body 1",
          %{
            organization_id: org.id,
            users: [user.id],
            group_key: group_key
          }
        )

      # Second notification with same group key (should update first)
      {:ok, [notification2]} =
        NotificationCenter.dispatch(
          "alert_new",
          "Alert 2",
          "Body 2",
          %{
            organization_id: org.id,
            users: [user.id],
            group_key: group_key
          }
        )

      # Should be the same notification with incremented count
      assert notification1.id == notification2.id
      assert notification2.group_count == 2
    end
  end
end
