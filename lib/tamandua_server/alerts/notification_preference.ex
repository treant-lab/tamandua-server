defmodule TamanduaServer.Alerts.NotificationPreference do
  @moduledoc """
  Schema for user notification preferences.

  Stores per-user settings for notification channels, filters, and scheduling.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  schema "notification_preferences" do
    # Global notification toggle
    field :enabled, :boolean, default: true

    # Channel-specific toggles
    field :email_enabled, :boolean, default: true
    field :sms_enabled, :boolean, default: false
    field :slack_enabled, :boolean, default: false

    # Contact details
    field :phone_number, :string
    field :slack_webhook_url, :string

    # Filtering
    field :severity_filter, {:array, :string}, default: []  # Empty = all severities

    # Quiet hours
    field :quiet_hours_start, :time
    field :quiet_hours_end, :time

    # Digest mode
    field :digest_enabled, :boolean, default: false

    belongs_to :user, TamanduaServer.Accounts.User

    timestamps()
  end

  @doc false
  def changeset(preference, attrs) do
    preference
    |> cast(attrs, [
      :enabled,
      :email_enabled,
      :sms_enabled,
      :slack_enabled,
      :phone_number,
      :slack_webhook_url,
      :severity_filter,
      :quiet_hours_start,
      :quiet_hours_end,
      :digest_enabled,
      :user_id
    ])
    |> validate_required([:user_id])
    |> validate_subset(:severity_filter, ["critical", "high", "medium", "low", "info"])
    |> validate_phone_number()
    |> validate_slack_webhook()
    |> unique_constraint(:user_id)
    |> foreign_key_constraint(:user_id)
  end

  defp validate_phone_number(changeset) do
    if get_change(changeset, :sms_enabled) == true do
      validate_required(changeset, [:phone_number])
    else
      changeset
    end
  end

  defp validate_slack_webhook(changeset) do
    if get_change(changeset, :slack_enabled) == true do
      changeset
      |> validate_required([:slack_webhook_url])
      |> validate_format(:slack_webhook_url, ~r/^https:\/\/hooks\.slack\.com\//)
    else
      changeset
    end
  end
end
