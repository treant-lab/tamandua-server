defmodule TamanduaServer.Notifications.NotificationPreference do
  @moduledoc """
  Schema for user notification preferences.
  Allows users to configure how they receive different types of notifications.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Organization, User}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  @notification_types ~w(mention reply reaction digest all_comments)
  @delivery_methods ~w(email push both none)

  schema "notification_preferences" do
    field :notification_type, :string
    field :enabled, :boolean, default: true
    field :delivery_method, :string, default: "email"
    field :frequency, :string, default: "immediate" # immediate, hourly, daily
    field :quiet_hours_start, :time
    field :quiet_hours_end, :time

    belongs_to :user, User
    belongs_to :organization, Organization

    timestamps()
  end

  @doc false
  def changeset(preference, attrs) do
    preference
    |> cast(attrs, [
      :notification_type,
      :enabled,
      :delivery_method,
      :frequency,
      :quiet_hours_start,
      :quiet_hours_end,
      :user_id,
      :organization_id
    ])
    |> validate_required([:notification_type, :enabled, :delivery_method, :user_id])
    |> validate_inclusion(:notification_type, @notification_types)
    |> validate_inclusion(:delivery_method, @delivery_methods)
    |> validate_inclusion(:frequency, ~w(immediate hourly daily))
    |> unique_constraint([:user_id, :notification_type])
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:organization_id)
  end

  @doc """
  Returns the list of notification types.
  """
  def notification_types, do: @notification_types

  @doc """
  Returns the list of delivery methods.
  """
  def delivery_methods, do: @delivery_methods
end
