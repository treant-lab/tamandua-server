defmodule TamanduaServer.Alerts.CommentManager do
  @moduledoc """
  Context module for managing alert comments, reactions, attachments, and activity feed.
  Provides functions for creating, editing, deleting comments with real-time collaboration.
  """

  import Ecto.Query, warn: false
  alias TamanduaServer.Repo

  alias TamanduaServer.Accounts.User
  alias TamanduaServer.Alerts.{
    Alert,
    Comment,
    CommentAttachment,
    CommentReaction,
    CommentEditHistory,
    AlertActivity,
    CommentNotification
  }

  require Logger

  ## Comments

  @doc """
  Lists all comments for an alert with preloaded associations.
  Returns comments in threaded format (parent comments with their replies).
  """
  def list_comments(%Alert{id: alert_id}, opts \\ []) do
    sort_order = Keyword.get(opts, :sort, :newest_first)
    include_deleted = Keyword.get(opts, :include_deleted, false)

    query =
      from c in Comment,
        where: c.alert_id == ^alert_id,
        preload: [
          :user,
          :deleted_by,
          :attachments,
          reactions: [:user],
          replies: [
            :user,
            :deleted_by,
            :attachments,
            reactions: [:user]
          ]
        ]

    query =
      if include_deleted do
        query
      else
        where(query, [c], c.is_deleted == false)
      end

    query =
      case sort_order do
        :newest_first -> order_by(query, [c], desc: c.inserted_at)
        :oldest_first -> order_by(query, [c], asc: c.inserted_at)
        :pinned_first -> order_by(query, [c], [desc: c.is_pinned, desc: c.inserted_at])
      end

    # Only get top-level comments (no parent)
    query
    |> where([c], is_nil(c.parent_id))
    |> Repo.all()
  end

  @doc """
  Gets a single comment with preloaded associations.
  """
  def get_comment(id) do
    Comment
    |> where([c], c.id == ^id)
    |> preload([
      :user,
      :alert,
      :parent,
      :deleted_by,
      :attachments,
      :reactions,
      :replies,
      :edit_history
    ])
    |> Repo.one()
  end

  @doc """
  Creates a comment on an alert.
  Broadcasts to PubSub, creates activity feed entry, and sends notifications for @mentions.
  """
  def create_comment(attrs, %User{} = user, %Alert{} = alert) do
    attrs = Map.put_new(attrs, "content_type", "markdown")

    changeset = Comment.create_changeset(attrs, user, alert)

    Repo.transaction(fn ->
      with {:ok, comment} <- Repo.insert(changeset),
           {:ok, comment} <- {:ok, Repo.preload(comment, [:user, :attachments, :reactions])},
           :ok <- create_activity_entry(comment, "comment_added", user),
           :ok <- send_mention_notifications(comment, user),
           :ok <- broadcast_comment_created(comment) do
        comment
      else
        {:error, reason} ->
          Repo.rollback(reason)
      end
    end)
  end

  @doc """
  Edits a comment. Only the comment author can edit.
  Stores edit history and broadcasts update.
  """
  def edit_comment(%Comment{} = comment, attrs, %User{id: user_id}) do
    if comment.user_id == user_id do
      changeset = Comment.edit_changeset(comment, attrs)

      Repo.transaction(fn ->
        with {:ok, updated_comment} <- Repo.update(changeset),
             :ok <- store_edit_history(comment, updated_comment, user_id),
             :ok <- create_activity_entry(updated_comment, "comment_edited", %User{id: user_id}),
             :ok <- broadcast_comment_updated(updated_comment) do
          Repo.preload(updated_comment, [:user, :attachments, :reactions, :edit_history])
        else
          {:error, reason} ->
            Repo.rollback(reason)
        end
      end)
    else
      {:error, :unauthorized}
    end
  end

  @doc """
  Soft-deletes a comment. User can delete their own comments; admins can delete any.
  """
  def delete_comment(%Comment{} = comment, %User{} = user) do
    if can_delete_comment?(comment, user) do
      changeset = Comment.delete_changeset(comment, user.id)

      Repo.transaction(fn ->
        with {:ok, deleted_comment} <- Repo.update(changeset),
             :ok <- create_activity_entry(deleted_comment, "comment_deleted", user),
             :ok <- broadcast_comment_deleted(deleted_comment) do
          deleted_comment
        else
          {:error, reason} ->
            Repo.rollback(reason)
        end
      end)
    else
      {:error, :unauthorized}
    end
  end

  @doc """
  Pins or unpins a comment. Only admins can pin.
  """
  def toggle_pin(%Comment{} = comment, %User{} = user) do
    if is_admin?(user) do
      is_pinned = !comment.is_pinned
      changeset = Comment.pin_changeset(comment, is_pinned)

      Repo.transaction(fn ->
        with {:ok, updated_comment} <- Repo.update(changeset),
             :ok <- create_activity_entry(updated_comment, "comment_pinned", user),
             :ok <- broadcast_comment_updated(updated_comment) do
          Repo.preload(updated_comment, [:user, :attachments, :reactions])
        else
          {:error, reason} ->
            Repo.rollback(reason)
        end
      end)
    else
      {:error, :unauthorized}
    end
  end

  ## Reactions

  @doc """
  Adds a reaction to a comment. If user already reacted with same type, removes it (toggle).
  """
  def toggle_reaction(%Comment{} = comment, reaction_type, %User{} = user) do
    # Check if reaction already exists
    existing =
      Repo.get_by(CommentReaction,
        comment_id: comment.id,
        user_id: user.id,
        reaction_type: reaction_type
      )

    Repo.transaction(fn ->
      case existing do
        nil ->
          # Create new reaction
          attrs = %{reaction_type: reaction_type}
          changeset = CommentReaction.create_changeset(attrs, user, comment)

          with {:ok, reaction} <- Repo.insert(changeset),
               :ok <- create_activity_entry(comment, "reaction_added", user),
               :ok <- broadcast_reaction_added(comment, reaction) do
            reaction
          else
            {:error, reason} -> Repo.rollback(reason)
          end

        reaction ->
          # Remove existing reaction
          with {:ok, _} <- Repo.delete(reaction),
               :ok <- broadcast_reaction_removed(comment, reaction) do
            nil
          else
            {:error, reason} -> Repo.rollback(reason)
          end
      end
    end)
  end

  @doc """
  Lists all reactions for a comment, grouped by reaction type.
  """
  def list_reactions(%Comment{id: comment_id}) do
    from(r in CommentReaction,
      where: r.comment_id == ^comment_id,
      preload: [:user],
      order_by: [asc: r.inserted_at]
    )
    |> Repo.all()
    |> Enum.group_by(& &1.reaction_type)
  end

  ## Attachments

  @doc """
  Creates an attachment for a comment.
  """
  def create_attachment(attrs, %User{} = user, %Comment{} = comment) do
    changeset = CommentAttachment.create_changeset(attrs, user, comment)

    Repo.transaction(fn ->
      with {:ok, attachment} <- Repo.insert(changeset),
           :ok <- create_activity_entry(comment, "attachment_added", user),
           :ok <- broadcast_attachment_added(comment, attachment) do
        attachment
      else
        {:error, reason} ->
          Repo.rollback(reason)
      end
    end)
  end

  @doc """
  Updates attachment scan results.
  """
  def update_attachment_scan(%CommentAttachment{} = attachment, scan_status, scan_result) do
    changeset = CommentAttachment.scan_result_changeset(attachment, scan_status, scan_result)
    Repo.update(changeset)
  end

  @doc """
  Gets an attachment by ID.
  """
  def get_attachment(id) do
    Repo.get(CommentAttachment, id)
  end

  ## Activity Feed

  @doc """
  Lists all activity for an alert.
  """
  def list_activity(%Alert{id: alert_id}, opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)
    activity_types = Keyword.get(opts, :types, nil)

    query =
      from a in AlertActivity,
        where: a.alert_id == ^alert_id,
        preload: [:user],
        order_by: [desc: a.inserted_at],
        limit: ^limit

    query =
      if activity_types do
        where(query, [a], a.activity_type in ^activity_types)
      else
        query
      end

    Repo.all(query)
  end

  @doc """
  Searches comments across all alerts in an organization.
  """
  def search_comments(organization_id, search_term, opts \\ []) do
    limit = Keyword.get(opts, :limit, 50)

    from(c in Comment,
      where: c.organization_id == ^organization_id,
      where: c.is_deleted == false,
      where: ilike(c.content, ^"%#{search_term}%"),
      preload: [:user, :alert],
      order_by: [desc: c.inserted_at],
      limit: ^limit
    )
    |> Repo.all()
  end

  @doc """
  Exports activity log for an alert.
  """
  def export_activity_log(%Alert{} = alert) do
    activities = list_activity(alert, limit: 10_000)

    activities
    |> Enum.map(fn activity ->
      %{
        timestamp: activity.inserted_at,
        user: activity.user && activity.user.email,
        activity_type: activity.activity_type,
        summary: activity.summary,
        details: activity.details
      }
    end)
  end

  ## Notifications

  @doc """
  Lists unread notifications for a user.
  """
  def list_unread_notifications(%User{id: user_id}) do
    from(n in CommentNotification,
      where: n.user_id == ^user_id,
      where: n.is_read == false,
      preload: [:comment, :alert, :triggered_by],
      order_by: [desc: n.inserted_at]
    )
    |> Repo.all()
  end

  @doc """
  Marks a notification as read.
  """
  def mark_notification_read(%CommentNotification{} = notification) do
    notification
    |> CommentNotification.mark_read_changeset()
    |> Repo.update()
  end

  @doc """
  Marks all notifications as read for a user.
  """
  def mark_all_notifications_read(%User{id: user_id}) do
    from(n in CommentNotification,
      where: n.user_id == ^user_id,
      where: n.is_read == false
    )
    |> Repo.update_all(set: [is_read: true, read_at: DateTime.utc_now()])
  end

  ## Private Helpers

  defp create_activity_entry(%Comment{} = comment, activity_type, %User{} = user) do
    summary = generate_activity_summary(comment, activity_type, user)

    attrs = %{
      activity_type: activity_type,
      related_id: comment.id,
      related_type: "comment",
      summary: summary,
      details: %{
        comment_id: comment.id,
        content_preview: String.slice(comment.content || "", 0..100)
      }
    }

    comment
    |> Repo.preload(:alert)
    |> Map.get(:alert)
    |> AlertActivity.create_changeset(attrs, user)
    |> Repo.insert()
    |> case do
      {:ok, _} -> :ok
      {:error, _} -> :ok # Don't fail the main operation if activity logging fails
    end
  end

  defp generate_activity_summary(%Comment{} = comment, activity_type, %User{} = user) do
    comment = Repo.preload(comment, :user)
    user_name = user.name || user.email

    case activity_type do
      "comment_added" -> "#{user_name} added a comment"
      "comment_edited" -> "#{user_name} edited a comment"
      "comment_deleted" -> "#{user_name} deleted a comment"
      "comment_pinned" -> "#{user_name} pinned a comment"
      "attachment_added" -> "#{user_name} added an attachment"
      "reaction_added" -> "#{user_name} reacted to a comment"
      _ -> "Activity on comment"
    end
  end

  defp store_edit_history(%Comment{} = old_comment, %Comment{} = new_comment, user_id) do
    attrs = %{
      previous_content: old_comment.content,
      new_content: new_comment.content,
      user_id: user_id,
      comment_id: old_comment.id,
      organization_id: old_comment.organization_id
    }

    %CommentEditHistory{}
    |> CommentEditHistory.changeset(attrs)
    |> Repo.insert()
    |> case do
      {:ok, _} -> :ok
      {:error, _} -> :ok # Don't fail if history storage fails
    end
  end

  defp send_mention_notifications(%Comment{} = comment, %User{} = triggering_user) do
    # Extract mentioned usernames from content
    mentions = extract_mentions(comment.content)

    if Enum.empty?(mentions) do
      :ok
    else
      # Find users by email/name matching mentions
      users =
        from(u in User,
          where: u.organization_id == ^comment.organization_id,
          where: u.email in ^mentions or u.name in ^mentions,
          where: u.id != ^triggering_user.id
        )
        |> Repo.all()

      # Create notifications
      Enum.each(users, fn user ->
        attrs = %{
          notification_type: "mention",
          triggered_by_id: triggering_user.id
        }

        CommentNotification.create_changeset(attrs, user, comment)
        |> Repo.insert()

        # Broadcast notification
        broadcast_notification(user, comment)
      end)

      :ok
    end
  end

  defp extract_mentions(content) do
    Regex.scan(~r/@([a-zA-Z0-9_@.-]+)/, content)
    |> Enum.map(fn [_, username] -> username end)
    |> Enum.uniq()
  end

  defp can_delete_comment?(%Comment{user_id: user_id}, %User{id: user_id}), do: true
  defp can_delete_comment?(_comment, %User{} = user), do: is_admin?(user)

  defp is_admin?(%User{role: "admin"}), do: true
  defp is_admin?(_), do: false

  ## PubSub Broadcasting

  defp broadcast_comment_created(%Comment{} = comment) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "alert:#{comment.alert_id}",
      {:comment_created, comment}
    )

    :ok
  end

  defp broadcast_comment_updated(%Comment{} = comment) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "alert:#{comment.alert_id}",
      {:comment_updated, comment}
    )

    :ok
  end

  defp broadcast_comment_deleted(%Comment{} = comment) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "alert:#{comment.alert_id}",
      {:comment_deleted, comment}
    )

    :ok
  end

  defp broadcast_reaction_added(%Comment{} = comment, %CommentReaction{} = reaction) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "alert:#{comment.alert_id}",
      {:reaction_added, comment, reaction}
    )

    :ok
  end

  defp broadcast_reaction_removed(%Comment{} = comment, %CommentReaction{} = reaction) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "alert:#{comment.alert_id}",
      {:reaction_removed, comment, reaction}
    )

    :ok
  end

  defp broadcast_attachment_added(%Comment{} = comment, %CommentAttachment{} = attachment) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "alert:#{comment.alert_id}",
      {:attachment_added, comment, attachment}
    )

    :ok
  end

  defp broadcast_notification(%User{} = user, %Comment{} = comment) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "user:#{user.id}",
      {:comment_notification, comment}
    )

    :ok
  end

  @doc """
  Broadcasts typing indicator for real-time collaboration.
  """
  def broadcast_typing(%Alert{id: alert_id}, %User{} = user) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "alert:#{alert_id}",
      {:user_typing, user}
    )

    :ok
  end

  @doc """
  Broadcasts stop typing indicator.
  """
  def broadcast_stop_typing(%Alert{id: alert_id}, %User{} = user) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "alert:#{alert_id}",
      {:user_stop_typing, user}
    )

    :ok
  end
end
