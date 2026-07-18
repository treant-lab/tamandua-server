defmodule TamanduaServer.NotificationCenter.Dispatcher do
  @moduledoc """
  Dispatches notifications to users based on their preferences and escalation policies.
  Handles grouping, filtering, and channel routing.
  """

  require Logger
  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.NotificationCenter.{
    Notification,
    UserPreference,
    NotificationDelivery,
    EscalationPolicy
  }

  @doc """
  Create and dispatch a notification.

  ## Options
  - `:users` - List of user IDs to notify (if not provided, use escalation policy or alert assignment)
  - `:escalation_policy_id` - ID of escalation policy to use
  - `:group_key` - Key for grouping similar notifications
  """
  def dispatch(type, title, body, attrs \\ %{}) do
    organization_id = attrs[:organization_id]
    users = attrs[:users] || []
    escalation_policy_id = attrs[:escalation_policy_id]

    # Determine who to notify
    user_ids =
      cond do
        # Explicit user list
        Enum.any?(users) ->
          users

        # Use escalation policy
        escalation_policy_id ->
          get_escalation_recipients(escalation_policy_id, organization_id)

        # Use alert assignment
        attrs[:related_resource_type] == "alert" and attrs[:related_resource_id] ->
          get_alert_recipients(attrs[:related_resource_id])

        # Fallback: notify org admins
        true ->
          get_org_admins(organization_id)
      end

    # Create notifications for each user
    notifications =
      Enum.flat_map(user_ids, fn user_id ->
        case create_notification(type, title, body, user_id, attrs) do
          {:ok, notification} ->
            [notification]

          {:error, reason} ->
            Logger.error(
              "[NotificationCenter] Failed to create notification for user #{user_id}: #{inspect(reason)}"
            )

            []
        end
      end)

    # Dispatch to channels
    Enum.each(notifications, &dispatch_to_channels/1)

    {:ok, notifications}
  end

  @doc """
  Create a notification record.
  """
  def create_notification(type, title, body, user_id, attrs) do
    # Check if should group with existing notification
    grouping_result =
      case attrs[:group_key] do
        nil ->
          {:new, build_notification_attrs(type, title, body, user_id, attrs)}

        group_key ->
          case find_groupable_notification(user_id, group_key) do
            nil ->
              new_attrs =
                build_notification_attrs(type, title, body, user_id, attrs)
                |> Map.put(:group_key, group_key)

              {:new, new_attrs}

            existing ->
              # Update existing notification group count
              existing
              |> Ecto.Changeset.change(%{
                group_count: existing.group_count + 1,
                updated_at: DateTime.utc_now()
              })
              |> Repo.update()

              {:existing, existing}
          end
      end

    case grouping_result do
      {:existing, existing} ->
        {:ok, existing}

      {:new, notification_attrs} ->
        %Notification{}
        |> Notification.changeset(notification_attrs)
        |> Repo.insert()
    end
  end

  @doc """
  Dispatch notification to appropriate channels based on user preferences.
  """
  def dispatch_to_channels(%Notification{} = notification) do
    preference = get_or_create_preference(notification.user_id, notification.organization_id)

    cond do
      not preference.enabled ->
        Logger.debug(
          "[NotificationCenter] Notifications disabled for user #{notification.user_id}"
        )

        :ok

      in_quiet_hours?(preference) and not is_critical?(notification, preference) ->
        Logger.debug("[NotificationCenter] In quiet hours, deferring notification")
        :ok

      not meets_severity_threshold?(notification, preference) ->
        Logger.debug("[NotificationCenter] Notification below severity threshold")
        :ok

      true ->
        channels = get_channels_for_type(notification.type, preference)
        Enum.each(channels, fn channel -> dispatch_to_channel(notification, channel) end)
        :ok
    end
  end

  @doc """
  Dispatch to a specific channel.
  """
  def dispatch_to_channel(%Notification{} = notification, channel) do
    # Create delivery record
    {:ok, delivery} =
      %NotificationDelivery{}
      |> NotificationDelivery.changeset(%{
        notification_id: notification.id,
        organization_id: notification.organization_id,
        channel: channel,
        status: "pending"
      })
      |> Repo.insert()

    # Enqueue delivery job
    case channel do
      "in_app" ->
        # In-app notifications are already created
        delivery
        |> NotificationDelivery.sent_changeset(%{})
        |> Repo.update()

        # Broadcast to user's channel
        Phoenix.PubSub.broadcast(
          TamanduaServer.PubSub,
          "notifications:#{notification.user_id}",
          {:new_notification, notification}
        )

      "email" ->
        TamanduaServer.NotificationCenter.Channels.EmailWorker.new(%{
          delivery_id: delivery.id
        })
        |> Oban.insert()

      "sms" ->
        TamanduaServer.NotificationCenter.Channels.SmsWorker.new(%{
          delivery_id: delivery.id
        })
        |> Oban.insert()

      "slack" ->
        TamanduaServer.NotificationCenter.Channels.SlackWorker.new(%{
          delivery_id: delivery.id
        })
        |> Oban.insert()

      "teams" ->
        TamanduaServer.NotificationCenter.Channels.TeamsWorker.new(%{
          delivery_id: delivery.id
        })
        |> Oban.insert()

      "pagerduty" ->
        TamanduaServer.NotificationCenter.Channels.PagerDutyWorker.new(%{
          delivery_id: delivery.id
        })
        |> Oban.insert()

      "webhook" ->
        TamanduaServer.NotificationCenter.Channels.WebhookWorker.new(%{
          delivery_id: delivery.id
        })
        |> Oban.insert()

      "discord" ->
        TamanduaServer.NotificationCenter.Channels.DiscordWorker.new(%{
          delivery_id: delivery.id
        })
        |> Oban.insert()
    end
  end

  # Private helpers

  defp build_notification_attrs(type, title, body, user_id, attrs) do
    %{
      type: type,
      title: title,
      body: body,
      user_id: user_id,
      organization_id: attrs[:organization_id],
      priority: attrs[:priority] || "normal",
      metadata: attrs[:metadata] || %{},
      related_resource_type: attrs[:related_resource_type],
      related_resource_id: attrs[:related_resource_id],
      expires_at: attrs[:expires_at] || default_expiry()
    }
  end

  defp find_groupable_notification(user_id, group_key) do
    # Find unread notification with same group key created in last hour
    one_hour_ago = DateTime.utc_now() |> DateTime.add(-3600, :second)

    Notification
    |> where([n], n.user_id == ^user_id)
    |> where([n], n.group_key == ^group_key)
    |> where([n], is_nil(n.read_at))
    |> where([n], n.inserted_at > ^one_hour_ago)
    |> order_by([n], desc: n.inserted_at)
    |> limit(1)
    |> Repo.one()
  end

  defp get_or_create_preference(user_id, organization_id) do
    case Repo.get_by(UserPreference, user_id: user_id, organization_id: organization_id) do
      nil ->
        {:ok, pref} =
          %UserPreference{}
          |> UserPreference.changeset(%{
            user_id: user_id,
            organization_id: organization_id
          })
          |> Repo.insert()

        pref

      pref ->
        pref
    end
  end

  defp in_quiet_hours?(%UserPreference{quiet_hours_enabled: false}), do: false

  defp in_quiet_hours?(%UserPreference{} = pref) do
    now = DateTime.utc_now() |> DateTime.shift_zone!(pref.quiet_hours_timezone)
    current_time = Time.new!(now.hour, now.minute, now.second)

    Time.compare(current_time, pref.quiet_hours_start) == :gt and
      Time.compare(current_time, pref.quiet_hours_end) == :lt
  rescue
    _ -> false
  end

  defp is_critical?(%Notification{priority: "critical"}, %UserPreference{
         critical_override: true
       }),
       do: true

  defp is_critical?(_, _), do: false

  defp meets_severity_threshold?(%Notification{priority: priority}, %UserPreference{
         min_severity: min_severity
       }) do
    severity_level(priority) >= severity_level(min_severity)
  end

  defp severity_level("low"), do: 1
  defp severity_level("normal"), do: 2
  defp severity_level("high"), do: 3
  defp severity_level("critical"), do: 4

  defp get_channels_for_type(type, %UserPreference{channel_preferences: prefs}) do
    # Get user's channel preferences for this type
    channels = Map.get(prefs, type, default_channels_for_type(type))

    # Always include in_app
    channels
    |> List.wrap()
    |> Enum.uniq()
  end

  defp default_channels_for_type(type) do
    case type do
      type when type in ["alert_new", "alert_escalated", "sla_breach"] ->
        ["in_app", "email"]

      type when type in ["comment_mention", "comment_reply"] ->
        ["in_app"]

      type when type in ["agent_offline", "integration_failure"] ->
        ["in_app", "email"]

      _ ->
        ["in_app"]
    end
  end

  defp default_expiry do
    # Default 7 days
    DateTime.utc_now() |> DateTime.add(7 * 24 * 3600, :second)
  end

  defp get_escalation_recipients(policy_id, _organization_id) do
    case Repo.get(EscalationPolicy, policy_id) do
      nil ->
        []

      policy ->
        policy.escalation_chain
        |> Enum.map(& &1["user_id"])
    end
  end

  defp get_alert_recipients(alert_id) do
    alert = Repo.get(TamanduaServer.Alerts.Alert, alert_id)

    case alert do
      %{assigned_to_id: user_id} when not is_nil(user_id) -> [user_id]
      _ -> []
    end
  end

  defp get_org_admins(organization_id) do
    TamanduaServer.Accounts.User
    |> where([u], u.organization_id == ^organization_id)
    |> where([u], u.role == "admin")
    |> select([u], u.id)
    |> Repo.all()
  end
end
