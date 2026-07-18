defmodule TamanduaServer.Notifications.CommentNotifier do
  @moduledoc """
  Handles email notifications for comment mentions, replies, and reactions.
  Supports notification preferences and digest emails.
  """

  import Ecto.Query
  alias TamanduaServer.Repo
  alias TamanduaServer.Accounts.User
  alias TamanduaServer.Alerts.{CommentNotification}
  alias TamanduaServer.Notifications.NotificationPreference
  alias TamanduaServer.Mailer

  require Logger

  @doc """
  Sends notification email for a comment mention.
  """
  def notify_mention(comment, mentioned_user, author)
      when is_map(comment) and is_map(mentioned_user) and is_map(author) do
    if should_notify?(mentioned_user, "mention") do
      email = build_mention_email(comment, mentioned_user, author)
      deliver_email(email, mentioned_user)
    end

    :ok
  end

  @doc """
  Sends notification email for a comment reply.
  """
  def notify_reply(reply, parent_author, reply_author)
      when is_map(reply) and is_map(parent_author) and is_map(reply_author) do
    if should_notify?(parent_author, "reply") do
      email = build_reply_email(reply, parent_author, reply_author)
      deliver_email(email, parent_author)
    end

    :ok
  end

  @doc """
  Sends notification email for a comment reaction.
  """
  def notify_reaction(
        comment,
        reaction_type,
        reactor,
        comment_author
      )
      when is_map(comment) and is_map(reactor) and is_map(comment_author) do
    if should_notify?(comment_author, "reaction") do
      email = build_reaction_email(comment, reaction_type, reactor, comment_author)
      deliver_email(email, comment_author)
    end

    :ok
  end

  @doc """
  Sends daily digest of unread comments to users.
  Should be called by a scheduled job (e.g., Oban worker).
  """
  def send_daily_digest do
    users_with_unread = get_users_with_unread_notifications()

    Enum.each(users_with_unread, fn user ->
      if should_notify?(user, "digest") do
        notifications = get_unread_notifications(user)
        email = build_digest_email(user, notifications)
        deliver_email(email, user)

        # Mark notifications as included in digest
        mark_notifications_digested(notifications)
      end
    end)

    :ok
  end

  @doc """
  Gets notification preference for a user and notification type.
  """
  def get_preference(%{id: user_id}, notification_type) do
    case Repo.get_by(NotificationPreference,
           user_id: user_id,
           notification_type: notification_type
         ) do
      nil -> get_default_preference(notification_type)
      preference -> preference
    end
  end

  @doc """
  Updates notification preference for a user.
  """
  def update_preference(user, notification_type, enabled, delivery_method \\ "email")
      when is_map(user) do
    attrs = %{
      user_id: user.id,
      notification_type: notification_type,
      enabled: enabled,
      delivery_method: delivery_method
    }

    case Repo.get_by(NotificationPreference,
           user_id: user.id,
           notification_type: notification_type
         ) do
      nil ->
        %NotificationPreference{}
        |> NotificationPreference.changeset(attrs)
        |> Repo.insert()

      preference ->
        preference
        |> NotificationPreference.changeset(attrs)
        |> Repo.update()
    end
  end

  ## Private Functions

  defp should_notify?(user, notification_type) when is_map(user) do
    preference = get_preference(user, notification_type)
    preference.enabled && preference.delivery_method in ["email", "both"]
  end

  defp build_mention_email(comment, mentioned_user, author)
       when is_map(comment) and is_map(mentioned_user) and is_map(author) do
    comment = Repo.preload(comment, :alert)

    Swoosh.Email.new()
    |> Swoosh.Email.to({mentioned_user.name || mentioned_user.email, mentioned_user.email})
    |> Swoosh.Email.from({"Tamandua EDR", "noreply@treantlab.org"})
    |> Swoosh.Email.subject("#{author.name || author.email} mentioned you in a comment")
    |> Swoosh.Email.html_body("""
    <html>
      <body style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #4F46E5;">You were mentioned in a comment</h2>

        <p>
          <strong>#{escape_html(display_name(author))}</strong> mentioned you in a comment on alert:
          <strong>#{escape_html(comment.alert.title)}</strong>
        </p>

        <div style="background: #F3F4F6; padding: 15px; border-left: 4px solid #4F46E5; margin: 20px 0;">
          #{render_comment_html(comment.content)}
        </div>

        <p>
          <a href="#{escape_html(alert_url(comment.alert))}"
             style="display: inline-block; padding: 10px 20px; background: #4F46E5; color: white; text-decoration: none; border-radius: 5px;">
            View Alert &rarr;
          </a>
        </p>

        <hr style="margin: 30px 0; border: none; border-top: 1px solid #E5E7EB;" />

        <p style="color: #6B7280; font-size: 12px;">
          You received this email because you were mentioned in a comment.
          <a href="#{preferences_url()}" style="color: #4F46E5;">Manage notification preferences</a>
        </p>
      </body>
    </html>
    """)
    |> Swoosh.Email.text_body("""
    You were mentioned in a comment

    #{author.name || author.email} mentioned you in a comment on alert: #{comment.alert.title}

    Comment:
    #{comment_text(comment.content)}

    View alert: #{alert_url(comment.alert)}

    ---
    Manage notification preferences: #{preferences_url()}
    """)
  end

  defp build_reply_email(reply, parent_author, reply_author)
       when is_map(reply) and is_map(parent_author) and is_map(reply_author) do
    reply = Repo.preload(reply, [:alert, :parent])

    Swoosh.Email.new()
    |> Swoosh.Email.to({parent_author.name || parent_author.email, parent_author.email})
    |> Swoosh.Email.from({"Tamandua EDR", "noreply@treantlab.org"})
    |> Swoosh.Email.subject("#{reply_author.name || reply_author.email} replied to your comment")
    |> Swoosh.Email.html_body("""
    <html>
      <body style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #4F46E5;">New reply to your comment</h2>

        <p>
          <strong>#{escape_html(display_name(reply_author))}</strong> replied to your comment on alert:
          <strong>#{escape_html(reply.alert.title)}</strong>
        </p>

        <div style="background: #F9FAFB; padding: 15px; border-left: 2px solid #D1D5DB; margin: 20px 0;">
          <p style="color: #6B7280; font-size: 12px; margin: 0 0 10px 0;">Your comment:</p>
          #{render_comment_html(reply.parent.content)}
        </div>

        <div style="background: #F3F4F6; padding: 15px; border-left: 4px solid #4F46E5; margin: 20px 0;">
          <p style="color: #6B7280; font-size: 12px; margin: 0 0 10px 0;">Reply:</p>
          #{render_comment_html(reply.content)}
        </div>

        <p>
          <a href="#{escape_html(alert_url(reply.alert))}"
             style="display: inline-block; padding: 10px 20px; background: #4F46E5; color: white; text-decoration: none; border-radius: 5px;">
            View Conversation &rarr;
          </a>
        </p>

        <hr style="margin: 30px 0; border: none; border-top: 1px solid #E5E7EB;" />

        <p style="color: #6B7280; font-size: 12px;">
          You received this email because someone replied to your comment.
          <a href="#{preferences_url()}" style="color: #4F46E5;">Manage notification preferences</a>
        </p>
      </body>
    </html>
    """)
    |> Swoosh.Email.text_body("""
    New reply to your comment

    #{reply_author.name || reply_author.email} replied to your comment on alert: #{reply.alert.title}

    Your comment:
    #{comment_text(reply.parent.content)}

    Reply:
    #{comment_text(reply.content)}

    View conversation: #{alert_url(reply.alert)}

    ---
    Manage notification preferences: #{preferences_url()}
    """)
  end

  defp build_reaction_email(
         comment,
         reaction_type,
         reactor,
         comment_author
       )
       when is_map(comment) and is_map(reactor) and is_map(comment_author) do
    comment = Repo.preload(comment, :alert)
    emoji = reaction_emoji(reaction_type)

    Swoosh.Email.new()
    |> Swoosh.Email.to({comment_author.name || comment_author.email, comment_author.email})
    |> Swoosh.Email.from({"Tamandua EDR", "noreply@treantlab.org"})
    |> Swoosh.Email.subject("#{reactor.name || reactor.email} reacted #{emoji} to your comment")
    |> Swoosh.Email.html_body("""
    <html>
      <body style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #4F46E5;">#{emoji} New reaction to your comment</h2>

        <p>
          <strong>#{escape_html(display_name(reactor))}</strong> reacted with #{emoji} to your comment on alert:
          <strong>#{escape_html(comment.alert.title)}</strong>
        </p>

        <div style="background: #F3F4F6; padding: 15px; border-left: 4px solid #4F46E5; margin: 20px 0;">
          #{render_comment_html(comment.content)}
        </div>

        <p>
          <a href="#{escape_html(alert_url(comment.alert))}"
             style="display: inline-block; padding: 10px 20px; background: #4F46E5; color: white; text-decoration: none; border-radius: 5px;">
            View Alert &rarr;
          </a>
        </p>

        <hr style="margin: 30px 0; border: none; border-top: 1px solid #E5E7EB;" />

        <p style="color: #6B7280; font-size: 12px;">
          You received this email because someone reacted to your comment.
          <a href="#{preferences_url()}" style="color: #4F46E5;">Manage notification preferences</a>
        </p>
      </body>
    </html>
    """)
    |> Swoosh.Email.text_body("""
    #{emoji} New reaction to your comment

    #{reactor.name || reactor.email} reacted with #{emoji} to your comment on alert: #{comment.alert.title}

    Comment:
    #{comment_text(comment.content)}

    View alert: #{alert_url(comment.alert)}

    ---
    Manage notification preferences: #{preferences_url()}
    """)
  end

  defp build_digest_email(user, notifications) when is_map(user) do
    grouped = group_notifications_by_alert(notifications)
    comment_count = length(notifications)

    Swoosh.Email.new()
    |> Swoosh.Email.to({user.name || user.email, user.email})
    |> Swoosh.Email.from({"Tamandua EDR", "noreply@treantlab.org"})
    |> Swoosh.Email.subject("Your daily Tamandua comment digest (#{comment_count} updates)")
    |> Swoosh.Email.html_body("""
    <html>
      <body style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #4F46E5;">Your Daily Comment Digest</h2>

        <p>You have <strong>#{comment_count}</strong> unread comment notifications across #{map_size(grouped)} alerts.</p>

        #{render_digest_alerts(grouped)}

        <p style="margin-top: 30px;">
          <a href="#{dashboard_url()}"
             style="display: inline-block; padding: 10px 20px; background: #4F46E5; color: white; text-decoration: none; border-radius: 5px;">
            View Dashboard &rarr;
          </a>
        </p>

        <hr style="margin: 30px 0; border: none; border-top: 1px solid #E5E7EB;" />

        <p style="color: #6B7280; font-size: 12px;">
          You received this digest because you have unread comment notifications.
          <a href="#{preferences_url()}" style="color: #4F46E5;">Manage notification preferences</a>
        </p>
      </body>
    </html>
    """)
    |> Swoosh.Email.text_body("""
    Your Daily Comment Digest

    You have #{comment_count} unread comment notifications across #{map_size(grouped)} alerts.

    #{render_digest_text(grouped)}

    View dashboard: #{dashboard_url()}

    ---
    Manage notification preferences: #{preferences_url()}
    """)
  end

  defp deliver_email(email, user) when is_map(user) do
    case Mailer.deliver(email) do
      {:ok, _} ->
        Logger.info("Sent notification email to #{user.email}")
        :ok

      {:error, reason} ->
        Logger.error("Failed to send notification email to #{user.email}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp get_users_with_unread_notifications do
    from(n in CommentNotification,
      where: n.is_read == false,
      join: u in User,
      on: n.user_id == u.id,
      group_by: u.id,
      select: u
    )
    |> Repo.all()
  end

  defp get_unread_notifications(%{id: user_id}) do
    from(n in CommentNotification,
      where: n.user_id == ^user_id,
      where: n.is_read == false,
      preload: [:comment, :alert, :triggered_by],
      order_by: [desc: n.inserted_at]
    )
    |> Repo.all()
  end

  defp mark_notifications_digested(notifications) do
    notification_ids = Enum.map(notifications, & &1.id)

    from(n in CommentNotification,
      where: n.id in ^notification_ids
    )
    |> Repo.update_all(set: [is_read: true, read_at: DateTime.utc_now()])
  end

  defp group_notifications_by_alert(notifications) do
    Enum.group_by(notifications, & &1.alert_id)
  end

  defp render_comment_html(content) do
    content =
      if is_binary(content) and String.valid?(content) do
        String.slice(content, 0, 501)
      else
        "[comment unavailable]"
      end

    ~s(<div style="white-space: pre-wrap; overflow-wrap: anywhere;">#{escape_html(content)}</div>)
  end

  defp render_digest_alerts(grouped) do
    grouped
    |> Enum.map(fn {_alert_id, notifications} ->
      alert = hd(notifications).alert
      count = length(notifications)

      """
      <div style="margin: 20px 0; padding: 15px; background: #F9FAFB; border-left: 3px solid #4F46E5;">
        <h3 style="margin: 0 0 10px 0; font-size: 16px;">
          <a href="#{escape_html(alert_url(alert))}" style="color: #1F2937; text-decoration: none;">
            #{escape_html(alert.title)}
          </a>
        </h3>
        <p style="margin: 0; color: #6B7280; font-size: 14px;">
          #{count} new #{if count == 1, do: "comment", else: "comments"}
        </p>
      </div>
      """
    end)
    |> Enum.join("\n")
  end

  defp render_digest_text(grouped) do
    grouped
    |> Enum.map(fn {_alert_id, notifications} ->
      alert = hd(notifications).alert
      count = length(notifications)

      """
      - #{alert.title}
        #{count} new #{if count == 1, do: "comment", else: "comments"}
        #{alert_url(alert)}
      """
    end)
    |> Enum.join("\n")
  end

  defp get_default_preference("mention"), do: %{enabled: true, delivery_method: "email"}
  defp get_default_preference("reply"), do: %{enabled: true, delivery_method: "email"}
  defp get_default_preference("reaction"), do: %{enabled: false, delivery_method: "none"}
  defp get_default_preference("digest"), do: %{enabled: true, delivery_method: "email"}
  defp get_default_preference(_), do: %{enabled: false, delivery_method: "none"}

  defp reaction_emoji("thumbs_up"), do: "👍"
  defp reaction_emoji("thumbs_down"), do: "👎"
  defp reaction_emoji("eyes"), do: "👀"
  defp reaction_emoji("heart"), do: "❤️"
  defp reaction_emoji("check"), do: "✅"
  defp reaction_emoji("rocket"), do: "🚀"
  defp reaction_emoji("confused"), do: "😕"
  defp reaction_emoji(_), do: "❓"

  defp display_name(user), do: user.name || user.email

  defp comment_text(content) when is_binary(content) do
    if String.valid?(content), do: content, else: "[comment unavailable]"
  end

  defp comment_text(_content), do: "[comment unavailable]"

  defp escape_html(value) when is_binary(value) do
    if String.valid?(value) do
      value
      |> Phoenix.HTML.html_escape()
      |> Phoenix.HTML.safe_to_string()
    else
      escape_html("[unavailable]")
    end
  end

  defp escape_html(_value), do: escape_html("[unavailable]")

  # URL helpers - in production these would use proper router helpers
  defp alert_url(%{id: id}) do
    normalized_id =
      case Ecto.UUID.cast(id) do
        {:ok, uuid} -> uuid
        :error -> "unavailable"
      end

    "https://treantlab.org/alerts/#{normalized_id}"
  end

  defp preferences_url, do: "https://treantlab.org/settings/notifications"
  defp dashboard_url, do: "https://treantlab.org/dashboard"
end
