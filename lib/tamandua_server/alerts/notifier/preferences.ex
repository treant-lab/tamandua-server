defmodule TamanduaServer.Alerts.Notifier.Preferences do
  @moduledoc """
  User notification preferences management.

  Manages per-user settings for notification channels, severity filters,
  quiet hours, and digest preferences.
  """

  import Ecto.Query
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts.NotificationPreference

  @doc """
  Get notification preferences for a user.

  Returns the preference struct or nil if not set.
  """
  def get_preferences(user_id) do
    from(p in NotificationPreference, where: p.user_id == ^user_id)
    |> Repo.one()
  end

  @doc """
  Get or create default preferences for a user.
  """
  def get_or_create_preferences(user_id) do
    case get_preferences(user_id) do
      nil ->
        {:ok, prefs} = create_default_preferences(user_id)
        prefs

      prefs ->
        prefs
    end
  end

  @doc """
  Create default notification preferences for a user.
  """
  def create_default_preferences(user_id) do
    %NotificationPreference{}
    |> NotificationPreference.changeset(%{
      user_id: user_id,
      enabled: true,
      email_enabled: true,
      sms_enabled: false,
      slack_enabled: false,
      severity_filter: ["critical", "high"],
      digest_enabled: false
    })
    |> Repo.insert()
  end

  @doc """
  Update notification preferences for a user.
  """
  def update_preferences(user_id, attrs) do
    prefs = get_or_create_preferences(user_id)

    prefs
    |> NotificationPreference.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Enable or disable all notifications for a user.
  """
  def set_enabled(user_id, enabled) when is_boolean(enabled) do
    update_preferences(user_id, %{enabled: enabled})
  end

  @doc """
  Set quiet hours for a user.

  ## Examples

      iex> set_quiet_hours(user_id, ~T[22:00:00], ~T[06:00:00])
      {:ok, %NotificationPreference{}}
  """
  def set_quiet_hours(user_id, start_time, end_time) do
    update_preferences(user_id, %{
      quiet_hours_start: start_time,
      quiet_hours_end: end_time
    })
  end

  @doc """
  Clear quiet hours for a user.
  """
  def clear_quiet_hours(user_id) do
    update_preferences(user_id, %{
      quiet_hours_start: nil,
      quiet_hours_end: nil
    })
  end

  @doc """
  Set severity filter for a user.

  Only alerts matching these severities will trigger notifications.

  ## Examples

      iex> set_severity_filter(user_id, ["critical", "high"])
      {:ok, %NotificationPreference{}}
  """
  def set_severity_filter(user_id, severities) when is_list(severities) do
    update_preferences(user_id, %{severity_filter: severities})
  end

  @doc """
  Enable digest mode for a user.

  When enabled, alerts are batched and sent periodically instead of immediately.
  """
  def enable_digest(user_id) do
    update_preferences(user_id, %{digest_enabled: true})
  end

  @doc """
  Disable digest mode for a user.
  """
  def disable_digest(user_id) do
    update_preferences(user_id, %{digest_enabled: false})
  end

  @doc """
  Get phone number for SMS notifications.

  Returns nil if not configured.
  """
  def get_phone_number(user) when is_map(user) do
    case get_preferences(user.id) do
      nil -> nil
      prefs -> if prefs.sms_enabled, do: prefs.phone_number, else: nil
    end
  end

  @doc """
  Set phone number for SMS notifications.
  """
  def set_phone_number(user_id, phone_number) do
    update_preferences(user_id, %{
      phone_number: phone_number,
      sms_enabled: true
    })
  end

  @doc """
  Get Slack webhook URL for a user.

  Returns nil if not configured.
  """
  def get_slack_webhook(user) when is_map(user) do
    case get_preferences(user.id) do
      nil -> nil
      prefs -> if prefs.slack_enabled, do: prefs.slack_webhook_url, else: nil
    end
  end

  @doc """
  Set Slack webhook URL for a user.
  """
  def set_slack_webhook(user_id, webhook_url) do
    update_preferences(user_id, %{
      slack_webhook_url: webhook_url,
      slack_enabled: true
    })
  end

  @doc """
  Enable a specific notification channel for a user.
  """
  def enable_channel(user_id, channel) when channel in [:email, :sms, :slack] do
    field = String.to_atom("#{channel}_enabled")
    update_preferences(user_id, %{field => true})
  end

  @doc """
  Disable a specific notification channel for a user.
  """
  def disable_channel(user_id, channel) when channel in [:email, :sms, :slack] do
    field = String.to_atom("#{channel}_enabled")
    update_preferences(user_id, %{field => false})
  end

  @doc """
  Get all users with digest enabled.

  Used by the digest worker to determine who should receive digests.
  """
  def get_digest_users do
    from(p in NotificationPreference,
      where: p.enabled == true,
      where: p.digest_enabled == true,
      preload: [:user]
    )
    |> Repo.all()
    |> Enum.map(& &1.user)
  end

  @doc """
  Check if a user should receive notifications during current time.

  Returns false if currently in user's quiet hours.
  """
  def can_notify_now?(user_id) do
    case get_preferences(user_id) do
      nil ->
        true

      prefs ->
        if prefs.quiet_hours_start && prefs.quiet_hours_end do
          now = Time.utc_now()
          start_time = prefs.quiet_hours_start
          end_time = prefs.quiet_hours_end

          # Handle overnight quiet hours (e.g., 22:00 - 06:00)
          in_quiet_hours? = if Time.compare(start_time, end_time) == :gt do
            Time.compare(now, start_time) in [:gt, :eq] or Time.compare(now, end_time) == :lt
          else
            Time.compare(now, start_time) in [:gt, :eq] and Time.compare(now, end_time) == :lt
          end

          not in_quiet_hours?
        else
          true
        end
    end
  end

  @doc """
  Get notification summary stats for a user.
  """
  def get_stats(user_id) do
    prefs = get_preferences(user_id)

    %{
      enabled: prefs && prefs.enabled,
      channels: %{
        email: prefs && prefs.email_enabled,
        sms: prefs && prefs.sms_enabled,
        slack: prefs && prefs.slack_enabled
      },
      severity_filter: (prefs && prefs.severity_filter) || [],
      digest_enabled: prefs && prefs.digest_enabled,
      quiet_hours: if prefs && prefs.quiet_hours_start do
        %{
          start: Time.to_string(prefs.quiet_hours_start),
          end: Time.to_string(prefs.quiet_hours_end)
        }
      else
        nil
      end
    }
  end
end
