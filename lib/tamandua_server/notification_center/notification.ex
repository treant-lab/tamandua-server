defmodule TamanduaServer.NotificationCenter.Notification do
  @moduledoc """
  Schema for in-app notifications.
  """
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @notification_types [
    "alert_new",
    "alert_status_change",
    "alert_assigned",
    "alert_unassigned",
    "alert_escalated",
    "comment_mention",
    "comment_reply",
    "agent_offline",
    "agent_reconnected",
    "integration_failure",
    "integration_recovered",
    "policy_violation",
    "system_event",
    "sla_breach",
    "sla_warning"
  ]

  @priorities ["low", "normal", "high", "critical"]

  schema "notifications" do
    field :type, :string
    field :title, :string
    field :body, :string
    field :priority, :string, default: "normal"

    field :metadata, :map, default: %{}
    field :related_resource_type, :string
    field :related_resource_id, :binary_id

    field :read_at, :utc_datetime
    field :acknowledged_at, :utc_datetime
    field :archived_at, :utc_datetime
    field :expires_at, :utc_datetime

    field :group_key, :string
    field :group_count, :integer, default: 1

    belongs_to :organization, TamanduaServer.Accounts.Organization
    belongs_to :user, TamanduaServer.Accounts.User

    has_many :deliveries, TamanduaServer.NotificationCenter.NotificationDelivery

    timestamps(type: :utc_datetime)
  end

  def changeset(notification, attrs) do
    notification
    |> cast(attrs, [
      :organization_id,
      :user_id,
      :type,
      :title,
      :body,
      :priority,
      :metadata,
      :related_resource_type,
      :related_resource_id,
      :group_key,
      :group_count,
      :expires_at
    ])
    |> validate_required([:organization_id, :user_id, :type, :title])
    |> validate_inclusion(:type, @notification_types)
    |> validate_inclusion(:priority, @priorities)
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:user_id)
  end

  def mark_read_changeset(notification) do
    notification
    |> change(%{read_at: DateTime.utc_now()})
  end

  def mark_acknowledged_changeset(notification) do
    notification
    |> change(%{acknowledged_at: DateTime.utc_now()})
  end

  def archive_changeset(notification) do
    notification
    |> change(%{archived_at: DateTime.utc_now()})
  end

  def notification_types, do: @notification_types
  def priorities, do: @priorities
end
