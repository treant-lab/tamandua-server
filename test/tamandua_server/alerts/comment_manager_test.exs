defmodule TamanduaServer.Alerts.CommentManagerTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Alerts.{
    Alert,
    Comment,
    CommentManager,
    CommentReaction,
    CommentAttachment
  }

  alias TamanduaServer.Accounts.{Organization, User}

  describe "create_comment/3" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      agent = insert(:agent, organization: org)

      alert =
        insert(:alert,
          organization: org,
          agent: agent,
          title: "Test Alert",
          severity: "high"
        )

      %{org: org, user: user, alert: alert}
    end

    test "creates a comment successfully", %{user: user, alert: alert} do
      attrs = %{
        "content" => "This looks like a false positive based on the process chain."
      }

      assert {:ok, comment} = CommentManager.create_comment(attrs, user, alert)
      assert comment.content == attrs["content"]
      assert comment.user_id == user.id
      assert comment.alert_id == alert.id
      assert comment.organization_id == alert.organization_id
      assert comment.content_type == "markdown"
      assert comment.is_deleted == false
      assert comment.is_pinned == false
    end

    test "creates a nested reply", %{user: user, alert: alert} do
      # Create parent comment
      {:ok, parent} =
        CommentManager.create_comment(
          %{"content" => "Parent comment"},
          user,
          alert
        )

      # Create reply
      attrs = %{
        "content" => "Reply to parent",
        "parent_id" => parent.id
      }

      assert {:ok, reply} = CommentManager.create_comment(attrs, user, alert)
      assert reply.parent_id == parent.id
      assert reply.content == "Reply to parent"
    end

    test "extracts @mentions from content", %{user: user, alert: alert} do
      other_user = insert(:user, organization: alert.organization_id, name: "John Doe")

      attrs = %{
        "content" => "Hey @#{other_user.name}, what do you think about this?"
      }

      assert {:ok, comment} = CommentManager.create_comment(attrs, user, alert)
      assert comment.metadata["mentions"] == [other_user.name]
    end

    test "validates required fields", %{user: user, alert: alert} do
      attrs = %{"content" => ""}

      assert {:error, changeset} = CommentManager.create_comment(attrs, user, alert)
      assert changeset.errors[:content]
    end

    test "broadcasts comment creation to PubSub", %{user: user, alert: alert} do
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "alert:#{alert.id}")

      attrs = %{"content" => "Test comment"}
      {:ok, comment} = CommentManager.create_comment(attrs, user, alert)

      assert_received {:comment_created, ^comment}
    end
  end

  describe "edit_comment/3" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      alert = insert(:alert, organization: org)

      {:ok, comment} =
        CommentManager.create_comment(
          %{"content" => "Original content"},
          user,
          alert
        )

      %{user: user, alert: alert, comment: comment}
    end

    test "edits own comment successfully", %{user: user, comment: comment} do
      attrs = %{"content" => "Updated content"}

      assert {:ok, updated} = CommentManager.edit_comment(comment, attrs, user)
      assert updated.content == "Updated content"
      assert updated.edit_count == 1
      assert updated.edited_at != nil
    end

    test "increments edit count on multiple edits", %{user: user, comment: comment} do
      {:ok, updated1} =
        CommentManager.edit_comment(comment, %{"content" => "Edit 1"}, user)

      assert updated1.edit_count == 1

      {:ok, updated2} =
        CommentManager.edit_comment(updated1, %{"content" => "Edit 2"}, user)

      assert updated2.edit_count == 2
    end

    test "stores edit history", %{user: user, comment: comment} do
      original_content = comment.content

      {:ok, updated} =
        CommentManager.edit_comment(
          comment,
          %{"content" => "New content"},
          user
        )

      history = Repo.preload(updated, :edit_history).edit_history
      assert length(history) == 1
      assert hd(history).previous_content == original_content
      assert hd(history).new_content == "New content"
    end

    test "prevents editing other user's comments", %{alert: alert, comment: comment} do
      other_user = insert(:user, organization: alert.organization_id)

      assert {:error, :unauthorized} =
               CommentManager.edit_comment(
                 comment,
                 %{"content" => "Hacked"},
                 other_user
               )
    end

    test "broadcasts comment update to PubSub", %{user: user, alert: alert, comment: comment} do
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "alert:#{alert.id}")

      {:ok, updated} =
        CommentManager.edit_comment(comment, %{"content" => "Updated"}, user)

      assert_received {:comment_updated, ^updated}
    end
  end

  describe "delete_comment/2" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      alert = insert(:alert, organization: org)

      {:ok, comment} =
        CommentManager.create_comment(
          %{"content" => "Test comment"},
          user,
          alert
        )

      %{user: user, alert: alert, comment: comment}
    end

    test "soft deletes own comment", %{user: user, comment: comment} do
      assert {:ok, deleted} = CommentManager.delete_comment(comment, user)
      assert deleted.is_deleted == true
      assert deleted.deleted_at != nil
      assert deleted.deleted_by_id == user.id
    end

    test "admin can delete any comment", %{alert: alert, comment: comment} do
      admin = insert(:user, organization: alert.organization_id, role: "admin")

      assert {:ok, deleted} = CommentManager.delete_comment(comment, admin)
      assert deleted.is_deleted == true
      assert deleted.deleted_by_id == admin.id
    end

    test "non-admin cannot delete other user's comments", %{alert: alert, comment: comment} do
      other_user = insert(:user, organization: alert.organization_id, role: "analyst")

      assert {:error, :unauthorized} =
               CommentManager.delete_comment(comment, other_user)
    end

    test "broadcasts comment deletion", %{user: user, alert: alert, comment: comment} do
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "alert:#{alert.id}")

      {:ok, deleted} = CommentManager.delete_comment(comment, user)

      assert_received {:comment_deleted, ^deleted}
    end
  end

  describe "toggle_pin/2" do
    setup do
      org = insert(:organization)
      admin = insert(:user, organization: org, role: "admin")
      alert = insert(:alert, organization: org)

      {:ok, comment} =
        CommentManager.create_comment(
          %{"content" => "Important comment"},
          admin,
          alert
        )

      %{admin: admin, alert: alert, comment: comment}
    end

    test "admin can pin comment", %{admin: admin, comment: comment} do
      assert comment.is_pinned == false

      assert {:ok, pinned} = CommentManager.toggle_pin(comment, admin)
      assert pinned.is_pinned == true

      # Toggle again to unpin
      assert {:ok, unpinned} = CommentManager.toggle_pin(pinned, admin)
      assert unpinned.is_pinned == false
    end

    test "non-admin cannot pin comments", %{alert: alert, comment: comment} do
      analyst = insert(:user, organization: alert.organization_id, role: "analyst")

      assert {:error, :unauthorized} = CommentManager.toggle_pin(comment, analyst)
    end
  end

  describe "toggle_reaction/3" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      alert = insert(:alert, organization: org)

      {:ok, comment} =
        CommentManager.create_comment(
          %{"content" => "Great analysis!"},
          user,
          alert
        )

      %{user: user, alert: alert, comment: comment}
    end

    test "adds a reaction to comment", %{user: user, comment: comment} do
      assert {:ok, reaction} =
               CommentManager.toggle_reaction(comment, "thumbs_up", user)

      assert reaction.reaction_type == "thumbs_up"
      assert reaction.user_id == user.id
      assert reaction.comment_id == comment.id
    end

    test "removes reaction if already exists (toggle)", %{user: user, comment: comment} do
      # Add reaction
      {:ok, _} = CommentManager.toggle_reaction(comment, "heart", user)

      # Toggle to remove
      assert {:ok, nil} = CommentManager.toggle_reaction(comment, "heart", user)

      # Verify removed
      reactions = CommentManager.list_reactions(comment)
      assert reactions["heart"] == nil
    end

    test "different users can add same reaction type", %{alert: alert, comment: comment} do
      user1 = insert(:user, organization: alert.organization_id)
      user2 = insert(:user, organization: alert.organization_id)

      {:ok, _} = CommentManager.toggle_reaction(comment, "thumbs_up", user1)
      {:ok, _} = CommentManager.toggle_reaction(comment, "thumbs_up", user2)

      reactions = CommentManager.list_reactions(comment)
      assert length(reactions["thumbs_up"]) == 2
    end

    test "broadcasts reaction events", %{user: user, alert: alert, comment: comment} do
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "alert:#{alert.id}")

      {:ok, reaction} = CommentManager.toggle_reaction(comment, "rocket", user)

      assert_received {:reaction_added, ^comment, ^reaction}
    end
  end

  describe "list_comments/2" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      alert = insert(:alert, organization: org)

      # Create multiple comments
      {:ok, comment1} =
        CommentManager.create_comment(
          %{"content" => "First comment"},
          user,
          alert
        )

      Process.sleep(10)

      {:ok, comment2} =
        CommentManager.create_comment(
          %{"content" => "Second comment"},
          user,
          alert
        )

      # Pin the second comment
      admin = insert(:user, organization: org, role: "admin")
      {:ok, _} = CommentManager.toggle_pin(comment2, admin)

      %{user: user, alert: alert, comment1: comment1, comment2: comment2}
    end

    test "lists comments with default sort (newest first)", %{alert: alert} do
      comments = CommentManager.list_comments(alert, sort: :newest_first)

      assert length(comments) == 2
      assert hd(comments).content == "Second comment"
    end

    test "lists comments sorted by oldest first", %{alert: alert} do
      comments = CommentManager.list_comments(alert, sort: :oldest_first)

      assert length(comments) == 2
      assert hd(comments).content == "First comment"
    end

    test "lists comments with pinned first", %{alert: alert} do
      comments = CommentManager.list_comments(alert, sort: :pinned_first)

      assert length(comments) == 2
      assert hd(comments).is_pinned == true
      assert hd(comments).content == "Second comment"
    end

    test "excludes deleted comments by default", %{user: user, alert: alert, comment1: comment1} do
      {:ok, _} = CommentManager.delete_comment(comment1, user)

      comments = CommentManager.list_comments(alert)
      assert length(comments) == 1
      assert hd(comments).content == "Second comment"
    end

    test "includes deleted comments when requested", %{user: user, alert: alert, comment1: comment1} do
      {:ok, _} = CommentManager.delete_comment(comment1, user)

      comments = CommentManager.list_comments(alert, include_deleted: true)
      assert length(comments) == 2
    end

    test "preloads associations", %{alert: alert} do
      comments = CommentManager.list_comments(alert)
      comment = hd(comments)

      assert Ecto.assoc_loaded?(comment.user)
      assert Ecto.assoc_loaded?(comment.attachments)
      assert Ecto.assoc_loaded?(comment.reactions)
    end
  end

  describe "search_comments/3" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      alert1 = insert(:alert, organization: org, title: "Alert 1")
      alert2 = insert(:alert, organization: org, title: "Alert 2")

      {:ok, _} =
        CommentManager.create_comment(
          %{"content" => "Malware detected in C:\\Windows\\Temp"},
          user,
          alert1
        )

      {:ok, _} =
        CommentManager.create_comment(
          %{"content" => "Investigating suspicious PowerShell activity"},
          user,
          alert2
        )

      {:ok, _} =
        CommentManager.create_comment(
          %{"content" => "False positive, benign process"},
          user,
          alert1
        )

      %{org: org, user: user}
    end

    test "searches comments by content", %{org: org} do
      results = CommentManager.search_comments(org.id, "malware")

      assert length(results) == 1
      assert hd(results).content =~ "Malware"
    end

    test "search is case-insensitive", %{org: org} do
      results = CommentManager.search_comments(org.id, "POWERSHELL")

      assert length(results) == 1
      assert hd(results).content =~ "PowerShell"
    end

    test "returns multiple matching comments", %{org: org} do
      results = CommentManager.search_comments(org.id, "alert")
      # Should match comments from both alerts via preloaded association
      assert length(results) >= 2
    end

    test "respects limit option", %{org: org} do
      results = CommentManager.search_comments(org.id, "", limit: 2)

      assert length(results) == 2
    end
  end

  describe "list_activity/2" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org)
      alert = insert(:alert, organization: org)

      # Create some activity
      {:ok, comment} =
        CommentManager.create_comment(
          %{"content" => "Test comment"},
          user,
          alert
        )

      {:ok, _} = CommentManager.edit_comment(comment, %{"content" => "Edited"}, user)

      %{alert: alert}
    end

    test "lists all activity for alert", %{alert: alert} do
      activity = CommentManager.list_activity(alert)

      assert length(activity) >= 2
      assert Enum.any?(activity, &(&1.activity_type == "comment_added"))
      assert Enum.any?(activity, &(&1.activity_type == "comment_edited"))
    end

    test "filters by activity type", %{alert: alert} do
      activity = CommentManager.list_activity(alert, types: ["comment_added"])

      assert length(activity) >= 1
      assert Enum.all?(activity, &(&1.activity_type == "comment_added"))
    end

    test "respects limit option", %{alert: alert} do
      activity = CommentManager.list_activity(alert, limit: 1)

      assert length(activity) == 1
    end
  end

  describe "export_activity_log/1" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org, email: "analyst@example.com")
      alert = insert(:alert, organization: org)

      {:ok, _} =
        CommentManager.create_comment(
          %{"content" => "Test comment"},
          user,
          alert
        )

      %{alert: alert, user: user}
    end

    test "exports activity log as structured data", %{alert: alert, user: user} do
      log = CommentManager.export_activity_log(alert)

      assert is_list(log)
      assert length(log) >= 1

      entry = hd(log)
      assert entry.timestamp
      assert entry.user == user.email
      assert entry.activity_type
      assert entry.summary
    end
  end

  describe "broadcast_typing/2 and broadcast_stop_typing/2" do
    setup do
      org = insert(:organization)
      user = insert(:user, organization: org, name: "John Analyst")
      alert = insert(:alert, organization: org)

      %{user: user, alert: alert}
    end

    test "broadcasts typing indicator", %{user: user, alert: alert} do
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "alert:#{alert.id}")

      CommentManager.broadcast_typing(alert, user)

      assert_received {:user_typing, ^user}
    end

    test "broadcasts stop typing indicator", %{user: user, alert: alert} do
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "alert:#{alert.id}")

      CommentManager.broadcast_stop_typing(alert, user)

      assert_received {:user_stop_typing, ^user}
    end
  end

  # Factory helpers (would normally be in test/support/factory.ex)
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

  defp insert(:agent, attrs) do
    defaults = %{
      hostname: "test-host-#{System.unique_integer([:positive])}",
      os_type: "windows",
      os_version: "10.0.19042"
    }

    attrs = Enum.into(attrs, defaults)

    Repo.insert!(%TamanduaServer.Agents.Agent{
      hostname: attrs.hostname,
      os_type: attrs.os_type,
      os_version: attrs.os_version,
      organization_id: attrs.organization_id || attrs[:organization].id
    })
  end

  defp insert(:alert, attrs) do
    defaults = %{
      title: "Test Alert",
      severity: "medium",
      status: "new"
    }

    attrs = Enum.into(attrs, defaults)

    Repo.insert!(%Alert{
      title: attrs.title,
      severity: attrs.severity,
      status: attrs[:status],
      organization_id: attrs.organization_id || attrs[:organization].id,
      agent_id: attrs[:agent_id] || attrs[:agent].id
    })
  end
end
