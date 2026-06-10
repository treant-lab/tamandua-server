defmodule TamanduaServer.NotificationCenter.UserPreference do
  @moduledoc """
  Schema for user notification preferences.
  """
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @frequencies ["immediate", "digest_15min", "digest_hourly", "digest_daily"]
  @severities ["low", "medium", "high", "critical"]
  @channels ["in_app", "email", "sms", "slack", "teams", "pagerduty", "webhook"]

  schema "user_notification_preferences" do
    field :enabled, :boolean, default: true
    field :frequency, :string, default: "immediate"

    field :quiet_hours_enabled, :boolean, default: false
    field :quiet_hours_start, :time
    field :quiet_hours_end, :time
    field :quiet_hours_timezone, :string, default: "UTC"

    field :min_severity, :string, default: "low"

    # %{"alert_new" => ["in_app", "email"], ...}
    field :channel_preferences, :map, default: %{}

    field :critical_override, :boolean, default: true

    belongs_to :user, TamanduaServer.Accounts.User
    belongs_to :organization, TamanduaServer.Accounts.Organization

    timestamps(type: :utc_datetime)
  end

  def changeset(preference, attrs) do
    preference
    |> cast(attrs, [
      :user_id,
      :organization_id,
      :enabled,
      :frequency,
      :quiet_hours_enabled,
      :quiet_hours_start,
      :quiet_hours_end,
      :quiet_hours_timezone,
      :min_severity,
      :channel_preferences,
      :critical_override
    ])
    |> validate_required([:user_id, :organization_id])
    |> validate_inclusion(:frequency, @frequencies)
    |> validate_inclusion(:min_severity, @severities)
    |> validate_channel_preferences()
    |> unique_constraint([:user_id, :organization_id])
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:organization_id)
  end

  defp validate_channel_preferences(changeset) do
    case get_field(changeset, :channel_preferences) do
      nil ->
        changeset

      prefs when is_map(prefs) ->
        valid? =
          Enum.all?(prefs, fn {_type, channels} ->
            is_list(channels) and Enum.all?(channels, &(&1 in @channels))
          end)

        if valid? do
          changeset
        else
          add_error(changeset, :channel_preferences, "contains invalid channels")
        end

      _ ->
        add_error(changeset, :channel_preferences, "must be a map")
    end
  end

  def frequencies, do: @frequencies
  def channels, do: @channels
  def severities, do: @severities
end
