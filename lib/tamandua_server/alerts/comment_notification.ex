defmodule TamanduaServer.Alerts.CommentNotification do
  @moduledoc """
  Schema for comment notifications (@mentions, replies, reactions).
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Organization, User}
  alias TamanduaServer.Alerts.{Alert, Comment}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  @notification_types ~w(mention reply reaction)

  schema "comment_notifications" do
    field :notification_type, :string
    field :is_read, :boolean, default: false
    field :read_at, :utc_datetime_usec

    belongs_to :user, User
    belongs_to :comment, Comment
    belongs_to :alert, Alert
    belongs_to :organization, Organization
    belongs_to :triggered_by, User, foreign_key: :triggered_by_id

    timestamps(updated_at: false)
  end

  @doc false
  def changeset(notification, attrs) do
    notification
    |> cast(attrs, [
      :notification_type,
      :is_read,
      :read_at,
      :user_id,
      :comment_id,
      :alert_id,
      :organization_id,
      :triggered_by_id
    ])
    |> validate_required([
      :notification_type,
      :user_id,
      :comment_id,
      :alert_id,
      :organization_id
    ])
    |> validate_inclusion(:notification_type, @notification_types)
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:comment_id)
    |> foreign_key_constraint(:alert_id)
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:triggered_by_id)
  end

  @doc """
  Changeset for creating a new notification.
  """
  def create_changeset(attrs, %User{} = user, %Comment{} = comment) do
    %__MODULE__{}
    |> changeset(attrs)
    |> put_change(:user_id, user.id)
    |> put_change(:comment_id, comment.id)
    |> put_change(:alert_id, comment.alert_id)
    |> put_change(:organization_id, comment.organization_id)
  end

  @doc """
  Changeset for marking a notification as read.
  """
  def mark_read_changeset(notification) do
    notification
    |> change()
    |> put_change(:is_read, true)
    |> put_change(:read_at, DateTime.utc_now())
  end

  @doc """
  Returns the list of notification types.
  """
  def notification_types, do: @notification_types
end
