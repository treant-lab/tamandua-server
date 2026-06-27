defmodule TamanduaServer.Alerts.Notifier do
  @moduledoc """
  Central alert notification dispatcher.

  Coordinates notification delivery across multiple channels (email, SMS, Slack)
  based on user preferences and alert severity. Handles deduplication,
  batching, and escalation.

  ## Channels

  - Email (via Swoosh)
  - SMS (via Twilio)
  - Slack (via webhooks)

  ## Features

  - Multi-channel delivery
  - User preference filtering
  - Quiet hours enforcement
  - Notification deduplication
  - Escalation rules
  - Digest/batching for low-priority alerts
  """

  require Logger

  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Alerts.Notifier.{Email, SMS, Slack, Preferences}
  alias TamanduaServer.Alerts.NotificationDedup
  alias TamanduaServer.Repo

  @doc """
  Send notifications for a new alert to all configured channels.

  This is the main entry point called by the Alerts context when a new alert is created.
  It triggers both the new notification integrations system and the legacy user preference system.

  ## Options
  - `:force` - Bypass deduplication and quiet hours (default: false)
  - `:channels` - List of channels to use (default: all enabled)
  """
  def notify_alert(%Alert{} = alert, opts \\ []) do
    force = Keyword.get(opts, :force, false)
    requested_channels = Keyword.get(opts, :channels, [:email, :sms, :slack])

    # Trigger new notification integrations system
    spawn(fn ->
      try do
        case TamanduaServer.Notifications.notify_alert(alert, alert.organization_id) do
          {:ok, integrations} when length(integrations) > 0 ->
            Logger.info("[Notifier] Enqueued #{length(integrations)} notification integrations for alert #{alert.id}")

          {:ok, []} ->
            Logger.debug("[Notifier] No notification integrations matched for alert #{alert.id}")

          {:error, reason} ->
            Logger.error("[Notifier] Failed to enqueue notification integrations: #{inspect(reason)}")
        end
      rescue
        e ->
          Logger.error("[Notifier] Error triggering notification integrations: #{inspect(e)}")
      end
    end)

    # Trigger SOAR playbooks (async, non-blocking)
    if Application.get_env(:tamandua_server, :soar_enabled, false) do
      Task.start(fn ->
        try do
          alert_map = alert_to_map(alert)
          case TamanduaServer.Integrations.SOAR.AlertTrigger.trigger_for_alert(alert_map) do
            {:ok, triggered} when length(triggered) > 0 ->
              Logger.info("[Notifier] Triggered #{length(triggered)} SOAR playbooks for alert #{alert.id}")

            {:ok, []} ->
              Logger.debug("[Notifier] No SOAR rules matched for alert #{alert.id}")

            {:error, reason} ->
              Logger.warning("[Notifier] SOAR trigger failed for alert #{alert.id}: #{inspect(reason)}")
          end
        rescue
          e ->
            Logger.error("[Notifier] SOAR trigger error for alert #{alert.id}: #{inspect(e)}")
        end
      end)
    end

    # Trigger ticketing integrations (async, non-blocking)
    if Application.get_env(:tamandua_server, :ticketing_enabled, false) do
      Task.start(fn ->
        try do
          alert_map = alert_to_map(alert)
          case TamanduaServer.Integrations.TicketingRouter.route_alert(alert_map) do
            {:ok, results} when length(results) > 0 ->
              successes = Enum.filter(results, fn {_, r} -> match?({:ok, _}, r) end)
              Logger.info("[Notifier] Created #{length(successes)} tickets for alert #{alert.id}")

            {:ok, []} ->
              Logger.debug("[Notifier] No ticketing integrations enabled for alert #{alert.id}")

            {:error, reason} ->
              Logger.warning("[Notifier] Ticketing dispatch failed for alert #{alert.id}: #{inspect(reason)}")
          end
        rescue
          e ->
            Logger.error("[Notifier] Ticketing trigger error for alert #{alert.id}: #{inspect(e)}")
        end
      end)
    end

    # Trigger chat integrations (async, non-blocking)
    if Application.get_env(:tamandua_server, :chat_notifications_enabled, false) do
      Task.start(fn ->
        try do
          alert_map = alert_to_map(alert)
          case TamanduaServer.Integrations.ChatRouter.route_alert(alert_map) do
            {:ok, results} when length(results) > 0 ->
              successes = Enum.filter(results, fn {_, r} -> match?(:ok, r) or match?({:ok, _}, r) end)
              Logger.info("[Notifier] Sent alert to #{length(successes)} chat platforms for alert #{alert.id}")

            {:ok, []} ->
              Logger.debug("[Notifier] No chat integrations enabled for alert #{alert.id}")

            {:error, reason} ->
              Logger.warning("[Notifier] Chat dispatch failed for alert #{alert.id}: #{inspect(reason)}")
          end
        rescue
          e ->
            Logger.error("[Notifier] Chat trigger error for alert #{alert.id}: #{inspect(e)}")
        end
      end)
    end

    # Continue with legacy user preferences system
    # Check deduplication - skip if we notified about this recently
    dedup_status =
      if force do
        :not_duplicate
      else
        NotificationDedup.check_recent(alert)
      end

    case dedup_status do
      {:duplicate, last_notified_at} ->
        Logger.debug(
          "[Notifier] Skipping duplicate notification for alert #{alert.id} " <>
          "(last notified: #{last_notified_at})"
        )
        {:ok, :deduplicated}

      :not_duplicate ->
        dispatch_legacy_notifications(alert, requested_channels, force)
    end
  end

  # Legacy user-preference based dispatch path, executed only when the alert
  # is not a deduplication hit (or when `force: true` was passed).
  defp dispatch_legacy_notifications(alert, requested_channels, force) do
    # Get users to notify for this alert's organization
    users = get_users_to_notify(alert)

    # Filter users by preferences and quiet hours
    users =
      if force do
        users
      else
        users
        |> Enum.filter(&should_notify_user?(&1, alert))
        |> Enum.reject(&in_quiet_hours?/1)
      end

    if Enum.empty?(users) do
      Logger.debug("[Notifier] No users to notify for alert #{alert.id}")
      {:ok, :no_recipients}
    else
      # Send to all enabled channels
      results = send_to_channels(alert, users, requested_channels)

      # Record notification in dedup tracker
      NotificationDedup.record_notification(alert)

      # Schedule escalation if configured
      maybe_schedule_escalation(alert)

      {:ok, results}
    end
  end

  @doc """
  Send a batch digest notification.

  Groups alerts by severity and sends a summary email/notification.
  """
  def send_digest(alerts, users, opts \\ []) when is_list(alerts) do
    if Enum.empty?(alerts) do
      {:ok, :no_alerts}
    else
      channels = Keyword.get(opts, :channels, [:email])

      results = Enum.map(channels, fn channel ->
        case channel do
          :email -> Email.send_digest(alerts, users)
          :slack -> Slack.send_digest(alerts, get_slack_webhooks(users))
          _ -> {:error, :unsupported_channel}
        end
      end)

      {:ok, results}
    end
  end

  @doc """
  Send an escalation notification.

  Notifies escalation contacts (managers, on-call) about unresolved alerts.
  """
  def send_escalation(alert, escalation_rule) do
    Logger.info(
      "[Notifier] Escalating alert #{alert.id} via rule #{escalation_rule.id}"
    )

    # Get escalation contacts
    contacts = get_escalation_contacts(alert, escalation_rule)

    # Send via all channels (escalations bypass quiet hours and dedup)
    results = send_to_channels(alert, contacts, [:email, :sms, :slack], force: true)

    {:ok, results}
  end

  @doc """
  Send a test notification to verify channel configuration.
  """
  def send_test_notification(user, channel) do
    test_alert = %{
      id: "test",
      title: "Test Notification from Tamandua EDR",
      severity: "info",
      description: "This is a test notification to verify your notification settings.",
      agent_id: "test-agent",
      inserted_at: DateTime.utc_now()
    }

    case channel do
      :email ->
        Email.send_alert_email(test_alert, [user.email])

      :sms ->
        phone = Preferences.get_phone_number(user)
        if phone, do: SMS.send_alert_sms(test_alert, [phone]), else: {:error, :no_phone}

      :slack ->
        webhook = Preferences.get_slack_webhook(user)
        if webhook, do: Slack.send_alert_slack(test_alert, webhook), else: {:error, :no_webhook}

      _ ->
        {:error, :invalid_channel}
    end
  end

  # ===========================================================================
  # Private Helpers
  # ===========================================================================

  defp send_to_channels(alert, users, channels, opts \\ []) do
    Enum.map(channels, fn channel ->
      try do
        result = case channel do
          :email -> send_email_notifications(alert, users)
          :sms -> send_sms_notifications(alert, users)
          :slack -> send_slack_notifications(alert, users)
          _ -> {:error, :unknown_channel}
        end

        {channel, result}
      rescue
        e ->
          Logger.error("[Notifier] Failed to send #{channel} notification: #{inspect(e)}")
          {channel, {:error, e}}
      end
    end)
  end

  defp send_email_notifications(alert, users) do
    if email_enabled?() do
      recipients = Enum.map(users, & &1.email)
      Email.send_alert_email(alert, recipients)
    else
      {:ok, :disabled}
    end
  end

  defp send_sms_notifications(alert, users) do
    if sms_enabled?() do
      phones = users
        |> Enum.map(&Preferences.get_phone_number/1)
        |> Enum.reject(&is_nil/1)

      if Enum.empty?(phones) do
        {:ok, :no_recipients}
      else
        SMS.send_alert_sms(alert, phones)
      end
    else
      {:ok, :disabled}
    end
  end

  defp send_slack_notifications(alert, users) do
    if slack_enabled?() do
      webhooks = get_slack_webhooks(users)

      if Enum.empty?(webhooks) do
        {:ok, :no_recipients}
      else
        # Send to each unique webhook
        results = Enum.map(webhooks, fn webhook ->
          Slack.send_alert_slack(alert, webhook)
        end)

        {:ok, results}
      end
    else
      {:ok, :disabled}
    end
  end

  defp get_users_to_notify(%Alert{organization_id: org_id, severity: severity}) do
    # Get all active users in the organization with notification preferences
    query = """
    SELECT u.* FROM users u
    LEFT JOIN notification_preferences np ON np.user_id = u.id
    WHERE u.organization_id = $1
      AND u.is_active = true
      AND (
        np.enabled IS NULL OR np.enabled = true
      )
      AND (
        np.severity_filter IS NULL OR
        $2 = ANY(np.severity_filter) OR
        array_length(np.severity_filter, 1) = 0
      )
    """

    case Repo.query(query, [org_id, severity]) do
      {:ok, %{rows: rows, columns: columns}} ->
        Enum.map(rows, fn row ->
          columns
          |> Enum.zip(row)
          |> Map.new()
          |> atomize_keys()
        end)

      {:error, _} ->
        []
    end
  end

  defp should_notify_user?(user, alert) do
    prefs = Preferences.get_preferences(user.id)

    cond do
      # No preferences = notify (default enabled)
      is_nil(prefs) -> true

      # Explicitly disabled
      !prefs.enabled -> false

      # Check severity filter
      prefs.severity_filter != [] and alert.severity not in prefs.severity_filter ->
        false

      # Check channel-specific settings
      true -> true
    end
  end

  defp in_quiet_hours?(user) do
    prefs = Preferences.get_preferences(user.id)

    if prefs && prefs.quiet_hours_start && prefs.quiet_hours_end do
      now = Time.utc_now()
      start_time = prefs.quiet_hours_start
      end_time = prefs.quiet_hours_end

      # Handle overnight quiet hours (e.g., 22:00 - 06:00)
      if Time.compare(start_time, end_time) == :gt do
        Time.compare(now, start_time) in [:gt, :eq] or Time.compare(now, end_time) == :lt
      else
        Time.compare(now, start_time) in [:gt, :eq] and Time.compare(now, end_time) == :lt
      end
    else
      false
    end
  end

  defp get_escalation_contacts(_alert, escalation_rule) do
    # Get users from escalation rule's contact list
    # This would typically query a separate escalation_contacts table
    # For now, return the rule creator
    case Repo.get(TamanduaServer.Accounts.User, escalation_rule.created_by_id) do
      nil -> []
      user -> [user]
    end
  end

  defp get_slack_webhooks(users) do
    users
    |> Enum.map(&Preferences.get_slack_webhook/1)
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
  end

  defp maybe_schedule_escalation(alert) do
    # Check if there are active escalation rules for this alert
    # Schedule escalation job via Oban if configured
    case TamanduaServer.Alerts.EscalationRules.get_matching_rules(alert) do
      [] ->
        :ok

      rules ->
        Enum.each(rules, fn rule ->
          TamanduaServer.Alerts.EscalationRules.schedule_escalation(alert, rule)
        end)
    end
  end

  defp email_enabled? do
    Application.get_env(:tamandua_server, :email_enabled, false)
  end

  defp sms_enabled? do
    Application.get_env(:tamandua_server, :twilio_enabled, false)
  end

  defp slack_enabled? do
    Application.get_env(:tamandua_server, :slack_enabled, false)
  end

  defp atomize_keys(map) when is_map(map) do
    Map.new(map, fn
      {k, v} when is_binary(k) -> {safe_existing_atom(k), v}
      {k, v} -> {k, v}
    end)
  end

  # Resolve DB column-name strings to existing atoms without growing the global
  # atom table. Known User schema fields already exist as compile-time literal
  # atoms; any column not declared in the schema (e.g. added by migration only)
  # keeps its string key rather than minting a new atom.
  defp safe_existing_atom(k) do
    String.to_existing_atom(k)
  rescue
    ArgumentError -> k
  end

  # Convert Alert struct to map for SOAR trigger
  defp alert_to_map(%Alert{} = alert) do
    %{
      id: alert.id,
      title: alert.title,
      description: alert.description,
      severity: alert.severity,
      status: alert.status,
      hostname: alert_hostname(alert),
      agent_id: alert.agent_id,
      organization_id: alert.organization_id,
      mitre_tactics: alert.mitre_tactics || [],
      mitre_techniques: alert.mitre_techniques || [],
      threat_score: alert.threat_score,
      evidence: alert.evidence,
      inserted_at: alert.inserted_at
    }
  end

  defp alert_hostname(%Alert{} = alert) do
    [
      loaded_agent_hostname(alert),
      nested_value(alert.raw_event, ["hostname", :hostname]),
      nested_value(alert.raw_event, ["agent_hostname", :agent_hostname]),
      nested_value(alert.raw_event, ["payload", :payload, "hostname", :hostname]),
      nested_value(alert.raw_event, ["payload", :payload, "agent_hostname", :agent_hostname]),
      nested_value(alert.evidence, ["hostname", :hostname]),
      nested_value(alert.evidence, ["agent_hostname", :agent_hostname]),
      nested_value(alert.detection_metadata, ["hostname", :hostname]),
      nested_value(alert.detection_metadata, ["agent_hostname", :agent_hostname])
    ]
    |> Enum.find(&present_string?/1)
  end

  defp loaded_agent_hostname(%Alert{agent: %Ecto.Association.NotLoaded{}}), do: nil
  defp loaded_agent_hostname(%Alert{agent: nil}), do: nil
  defp loaded_agent_hostname(%Alert{agent: agent}), do: Map.get(agent, :hostname)

  defp nested_value(map, path) when is_map(map) and is_list(path) do
    path
    |> Enum.chunk_every(2)
    |> Enum.reduce_while(map, fn keys, current ->
      case first_present(current, keys) do
        nil -> {:halt, nil}
        value -> {:cont, value}
      end
    end)
  end

  defp nested_value(_, _), do: nil

  defp first_present(map, keys) when is_map(map) do
    Enum.find_value(keys, fn key ->
      value = Map.get(map, key)
      if present_value?(value), do: value, else: nil
    end)
  end

  defp first_present(_, _), do: nil

  defp present_string?(value), do: is_binary(value) and String.trim(value) != ""
  defp present_value?(value), do: value not in [nil, ""]
end
