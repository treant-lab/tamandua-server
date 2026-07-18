defmodule TamanduaServer.NotificationCenter do
  @moduledoc """
  Context module for notification center functionality.
  """

  import Ecto.Query
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.NotificationCenter.{
    Notification,
    UserPreference,
    EscalationPolicy,
    NotificationTemplate,
    NotificationWebhook,
    NotificationDelivery,
    Dispatcher,
    EscalationManager
  }

  # Notifications

  @doc """
  List notifications for a user.
  """
  def list_notifications(user_id, opts \\ []) do
    query = from n in Notification, where: n.user_id == ^user_id

    query =
      if opts[:unread_only] do
        where(query, [n], is_nil(n.read_at))
      else
        query
      end

    query =
      if opts[:include_archived] do
        query
      else
        where(query, [n], is_nil(n.archived_at))
      end

    query =
      case opts[:type] do
        nil -> query
        type -> where(query, [n], n.type == ^type)
      end

    limit = opts[:limit] || 50
    offset = opts[:offset] || 0

    query
    |> order_by([n], desc: n.inserted_at)
    |> limit(^limit)
    |> offset(^offset)
    |> Repo.all()
  end

  @doc """
  Get unread notification count for a user.
  """
  def unread_count(user_id) do
    Notification
    |> where([n], n.user_id == ^user_id)
    |> where([n], is_nil(n.read_at))
    |> where([n], is_nil(n.archived_at))
    |> select([n], count(n.id))
    |> Repo.one()
  end

  @doc """
  Get a single notification.
  """
  def get_notification(id, user_id) do
    Notification
    |> where([n], n.id == ^id and n.user_id == ^user_id)
    |> Repo.one()
  end

  @doc """
  Mark notification as read.
  """
  def mark_as_read(%Notification{} = notification) do
    notification
    |> Notification.mark_read_changeset()
    |> Repo.update()
  end

  @doc """
  Mark all notifications as read for a user.
  """
  def mark_all_as_read(user_id) do
    now = DateTime.utc_now()

    Notification
    |> where([n], n.user_id == ^user_id)
    |> where([n], is_nil(n.read_at))
    |> Repo.update_all(set: [read_at: now])
  end

  @doc """
  Archive a notification.
  """
  def archive_notification(%Notification{} = notification) do
    notification
    |> Notification.archive_changeset()
    |> Repo.update()
  end

  @doc """
  Clean up expired notifications.
  """
  def cleanup_expired_notifications do
    now = DateTime.utc_now()

    {count, _} =
      Notification
      |> where([n], n.expires_at < ^now)
      |> Repo.delete_all()

    Logger.info("[NotificationCenter] Cleaned up #{count} expired notifications")
    {:ok, count}
  end

  # User Preferences

  @doc """
  Get user notification preferences.
  """
  def get_user_preferences(user_id, organization_id) do
    case Repo.get_by(UserPreference, user_id: user_id, organization_id: organization_id) do
      nil ->
        # Create default preferences
        create_user_preferences(%{
          user_id: user_id,
          organization_id: organization_id
        })

      pref ->
        {:ok, pref}
    end
  end

  @doc """
  Create user notification preferences.
  """
  def create_user_preferences(attrs) do
    %UserPreference{}
    |> UserPreference.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Update user notification preferences.
  """
  def update_user_preferences(%UserPreference{} = preference, attrs) do
    preference
    |> UserPreference.changeset(attrs)
    |> Repo.update()
  end

  # Escalation Policies

  @doc """
  List escalation policies for an organization.
  """
  def list_escalation_policies(organization_id) do
    EscalationPolicy
    |> where([p], p.organization_id == ^organization_id)
    |> order_by([p], [desc: p.enabled, asc: p.name])
    |> Repo.all()
  end

  @doc """
  Get an escalation policy.
  """
  def get_escalation_policy(id) do
    Repo.get(EscalationPolicy, id)
  end

  @doc """
  Create an escalation policy.
  """
  def create_escalation_policy(attrs) do
    %EscalationPolicy{}
    |> EscalationPolicy.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Update an escalation policy.
  """
  def update_escalation_policy(%EscalationPolicy{} = policy, attrs) do
    policy
    |> EscalationPolicy.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Delete an escalation policy.
  """
  def delete_escalation_policy(%EscalationPolicy{} = policy) do
    Repo.delete(policy)
  end

  @doc """
  Start escalation for an alert.
  """
  def start_escalation(alert_id, policy_id) do
    EscalationManager.start_escalation(alert_id, policy_id)
  end

  @doc """
  Acknowledge an escalation.
  """
  def acknowledge_escalation(instance_id, user_id) do
    EscalationManager.acknowledge_escalation(instance_id, user_id)
  end

  # Templates

  @doc """
  List notification templates.
  """
  def list_templates(organization_id, opts \\ []) do
    query = NotificationTemplate

    query =
      if organization_id do
        where(query, [t], t.organization_id == ^organization_id or is_nil(t.organization_id))
      else
        where(query, [t], is_nil(t.organization_id))
      end

    query =
      case opts[:type] do
        nil -> query
        type -> where(query, [t], t.type == ^type)
      end

    query =
      case opts[:channel] do
        nil -> query
        channel -> where(query, [t], t.channel == ^channel)
      end

    Repo.all(query)
  end

  @doc """
  Create a notification template.
  """
  def create_template(attrs) do
    %NotificationTemplate{}
    |> NotificationTemplate.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Update a notification template.
  """
  def update_template(%NotificationTemplate{} = template, attrs) do
    template
    |> NotificationTemplate.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Delete a notification template.
  """
  def delete_template(%NotificationTemplate{} = template) do
    Repo.delete(template)
  end

  # Webhooks

  @doc """
  List notification webhooks.
  """
  def list_webhooks(organization_id) do
    NotificationWebhook
    |> where([w], w.organization_id == ^organization_id)
    |> order_by([w], [desc: w.enabled, asc: w.name])
    |> Repo.all()
  end

  @doc """
  Get a webhook.
  """
  def get_webhook(id) do
    Repo.get(NotificationWebhook, id)
  end

  @doc """
  Create a webhook.
  """
  def create_webhook(attrs) do
    %NotificationWebhook{}
    |> NotificationWebhook.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Update a webhook.
  """
  def update_webhook(%NotificationWebhook{} = webhook, attrs) do
    webhook
    |> NotificationWebhook.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Delete a webhook.
  """
  def delete_webhook(%NotificationWebhook{} = webhook) do
    Repo.delete(webhook)
  end

  # Delivery logs

  @doc """
  Get delivery logs for a notification.
  """
  def get_delivery_logs(notification_id) do
    NotificationDelivery
    |> where([d], d.notification_id == ^notification_id)
    |> order_by([d], desc: d.inserted_at)
    |> Repo.all()
  end

  # Dispatch

  @doc """
  Dispatch a notification.
  """
  defdelegate dispatch(type, title, body, attrs \\ %{}), to: Dispatcher
end
