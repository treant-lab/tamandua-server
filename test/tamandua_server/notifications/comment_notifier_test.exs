defmodule TamanduaServer.Notifications.CommentNotifierTest do
  use TamanduaServer.DataCase, async: true
  use Swoosh.TestAssertions

  alias TamanduaServer.Notifications.{CommentNotifier, NotificationPreference}
  alias TamanduaServer.Alerts.{Alert, Comment, CommentManager}
  alias TamanduaServer.Accounts.{Organization, User}

  describe "notify_mention/3" do
    setup do
      org = insert(:organization)
      author = insert(:user, organization: org, name: "Alice")
      mentioned = insert(:user, organization: org, name: "Bob", email: "bob@example.com")
      alert = insert(:alert, organization: org)

      {:ok, comment} =
        CommentManager.create_comment(
          %{"content" => "Hey @Bob, check this out!"},
          author,
          alert
        )

      %{org: org, author: author, mentioned: mentioned, comment: comment}
    end

    test "sends mention notification email when enabled", %{
      author: author,
      mentioned: mentioned,
      comment: comment
    } do
      # Enable mention notifications
      CommentNotifier.update_preference(mentioned, "mention", true, "email")

      CommentNotifier.notify_mention(comment, mentioned, author)

      assert_email_sent(
        subject: "Alice mentioned you in a comment",
        to: [{"Bob", "bob@example.com"}]
      )
    end

    test "does not send email when notifications are disabled", %{
      author: author,
      mentioned: mentioned,
      comment: comment
    } do
      # Disable mention notifications
      CommentNotifier.update_preference(mentioned, "mention", false, "none")

      CommentNotifier.notify_mention(comment, mentioned, author)

      refute_email_sent()
    end

    test "email contains comment content", %{author: author, mentioned: mentioned, comment: comment} do
      CommentNotifier.update_preference(mentioned, "mention", true, "email")

      CommentNotifier.notify_mention(comment, mentioned, author)

      assert_email_sent(fn email ->
        email.html_body =~ "check this out"
      end)
    end

    test "email contains alert title", %{author: author, mentioned: mentioned, comment: comment} do
      CommentNotifier.update_preference(mentioned, "mention", true, "email")

      CommentNotifier.notify_mention(comment, mentioned, author)

      assert_email_sent(fn email ->
        email.html_body =~ comment.alert.title
      end)
    end
  end

  describe "notify_reply/3" do
    setup do
      org = insert(:organization)
      parent_author = insert(:user, organization: org, name: "Alice", email: "alice@example.com")
      reply_author = insert(:user, organization: org, name: "Bob")
      alert = insert(:alert, organization: org)

      {:ok, parent_comment} =
        CommentManager.create_comment(
          %{"content" => "This looks suspicious"},
          parent_author,
          alert
        )

      {:ok, reply} =
        CommentManager.create_comment(
          %{"content" => "I agree, investigating now", "parent_id" => parent_comment.id},
          reply_author,
          alert
        )

      %{parent_author: parent_author, reply_author: reply_author, reply: reply}
    end

    test "sends reply notification email when enabled", %{
      parent_author: parent_author,
      reply_author: reply_author,
      reply: reply
    } do
      CommentNotifier.update_preference(parent_author, "reply", true, "email")

      CommentNotifier.notify_reply(reply, parent_author, reply_author)

      assert_email_sent(
        subject: "Bob replied to your comment",
        to: [{"Alice", "alice@example.com"}]
      )
    end

    test "email contains both parent and reply content", %{
      parent_author: parent_author,
      reply_author: reply_author,
      reply: reply
    } do
      CommentNotifier.update_preference(parent_author, "reply", true, "email")

      CommentNotifier.notify_reply(reply, parent_author, reply_author)

      assert_email_sent(fn email ->
        email.html_body =~ "This looks suspicious" &&
          email.html_body =~ "I agree, investigating now"
      end)
    end
  end

  describe "notify_reaction/4" do
    setup do
      org = insert(:organization)
      comment_author = insert(:user, organization: org, email: "author@example.com")
      reactor = insert(:user, organization: org, name: "Bob")
      alert = insert(:alert, organization: org)

      {:ok, comment} =
        CommentManager.create_comment(
          %{"content" => "Great analysis!"},
          comment_author,
          alert
        )

      %{comment_author: comment_author, reactor: reactor, comment: comment}
    end

    test "sends reaction notification when enabled", %{
      comment_author: comment_author,
      reactor: reactor,
      comment: comment
    } do
      CommentNotifier.update_preference(comment_author, "reaction", true, "email")

      CommentNotifier.notify_reaction(comment, "thumbs_up", reactor, comment_author)

      assert_email_sent(
        subject: "Bob reacted 👍 to your comment",
        to: [{"author@example.com", "author@example.com"}]
      )
    end

    test "includes emoji in email", %{
      comment_author: comment_author,
      reactor: reactor,
      comment: comment
    } do
      CommentNotifier.update_preference(comment_author, "reaction", true, "email")

      CommentNotifier.notify_reaction(comment, "heart", reactor, comment_author)

      assert_email_sent(fn email ->
        email.html_body =~ "❤️"
      end)
    end

    test "does not send when reactions disabled (default)", %{
      comment_author: comment_author,
      reactor: reactor,
      comment: comment
    } do
      CommentNotifier.notify_reaction(comment, "thumbs_up", reactor, comment_author)

      refute_email_sent()
    end
  end

  describe "send_daily_digest/0" do
    setup do
      org = insert(:organization)
      user1 = insert(:user, organization: org, email: "user1@example.com")
      user2 = insert(:user, organization: org, email: "user2@example.com")
      alert = insert(:alert, organization: org)

      # Create some unread notifications for user1
      {:ok, comment1} =
        CommentManager.create_comment(%{"content" => "Comment 1"}, user2, alert)

      {:ok, comment2} =
        CommentManager.create_comment(%{"content" => "Comment 2"}, user2, alert)

      # Create notifications manually (normally done by CommentManager)
      insert(:comment_notification, user: user1, comment: comment1, alert: alert, is_read: false)
      insert(:comment_notification, user: user1, comment: comment2, alert: alert, is_read: false)

      %{user1: user1, user2: user2}
    end

    test "sends digest to users with unread notifications", %{user1: user1} do
      CommentNotifier.update_preference(user1, "digest", true, "email")

      CommentNotifier.send_daily_digest()

      assert_email_sent(
        subject: "Your daily Tamandua comment digest (2 updates)",
        to: [{"user1@example.com", "user1@example.com"}]
      )
    end

    test "marks notifications as read after digest", %{user1: user1} do
      CommentNotifier.update_preference(user1, "digest", true, "email")

      unread_before = CommentManager.list_unread_notifications(user1)
      assert length(unread_before) == 2

      CommentNotifier.send_daily_digest()

      unread_after = CommentManager.list_unread_notifications(user1)
      assert length(unread_after) == 0
    end

    test "does not send to users with digest disabled", %{user1: user1, user2: user2} do
      CommentNotifier.update_preference(user1, "digest", false, "none")

      CommentNotifier.send_daily_digest()

      refute_email_sent()
    end
  end

  describe "notification preferences" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      %{user: user}
    end

    test "creates new preference", %{user: user} do
      {:ok, pref} = CommentNotifier.update_preference(user, "mention", true, "email")

      assert pref.notification_type == "mention"
      assert pref.enabled == true
      assert pref.delivery_method == "email"
    end

    test "updates existing preference", %{user: user} do
      {:ok, _} = CommentNotifier.update_preference(user, "mention", true, "email")
      {:ok, updated} = CommentNotifier.update_preference(user, "mention", false, "none")

      assert updated.enabled == false
      assert updated.delivery_method == "none"
    end

    test "returns default preferences when not set", %{user: user} do
      pref = CommentNotifier.get_preference(user, "mention")

      assert pref.enabled == true
      assert pref.delivery_method == "email"
    end

    test "reactions are disabled by default", %{user: user} do
      pref = CommentNotifier.get_preference(user, "reaction")

      assert pref.enabled == false
    end
  end

  # Factory helpers
  defp insert(:organization) do
    Repo.insert!(%Organization{
      name: "Test Org",
      slug: "test-org-#{System.unique_integer([:positive])}"
    })
  end

  defp insert(:user, attrs) do
    defaults = %{
      email: "user#{System.unique_integer([:positive])}@example.com",
      password_hash: Bcrypt.hash_pwd_salt("password123"),
      role: "analyst"
    }

    attrs = Enum.into(attrs, defaults)

    Repo.insert!(%User{
      email: attrs.email,
      password_hash: attrs.password_hash,
      role: attrs.role,
      name: attrs[:name],
      organization_id: attrs.organization_id || attrs[:organization].id
    })
  end

  defp insert(:alert, attrs) do
    defaults = %{
      title: "Test Alert #{System.unique_integer([:positive])}",
      severity: "medium",
      status: "new"
    }

    attrs = Enum.into(attrs, defaults)
    agent = insert(:agent, organization: attrs[:organization])

    Repo.insert!(%Alert{
      title: attrs.title,
      severity: attrs.severity,
      status: attrs[:status],
      organization_id: attrs.organization_id || attrs[:organization].id,
      agent_id: agent.id
    })
  end

  defp insert(:agent, attrs) do
    Repo.insert!(%TamanduaServer.Agents.Agent{
      hostname: "test-host-#{System.unique_integer([:positive])}",
      os_type: "windows",
      os_version: "10.0.19042",
      organization_id: attrs.organization_id || attrs[:organization].id
    })
  end

  defp insert(:comment_notification, attrs) do
    defaults = %{
      notification_type: "mention",
      is_read: false
    }

    attrs = Enum.into(attrs, defaults)

    Repo.insert!(%TamanduaServer.Alerts.CommentNotification{
      notification_type: attrs.notification_type,
      is_read: attrs.is_read,
      user_id: attrs.user.id,
      comment_id: attrs.comment.id,
      alert_id: attrs.alert.id,
      organization_id: attrs.user.organization_id
    })
  end
end
