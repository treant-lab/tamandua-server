defmodule TamanduaServer.Alerts.AlertActivity do
  @moduledoc """
  Schema for alert activity feed (comments, state changes, assignments, etc.).
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Organization, User}
  alias TamanduaServer.Alerts.Alert

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  @activity_types ~w(
    comment_added comment_edited comment_deleted comment_pinned
    status_changed assignment_changed verdict_changed
    attachment_added reaction_added
    alert_created alert_updated
  )

  schema "alert_activity_feed" do
    field :activity_type, :string
    field :related_id, :binary_id
    field :related_type, :string
    field :details, :map, default: %{}
    field :summary, :string

    belongs_to :alert, Alert
    belongs_to :user, User
    belongs_to :organization, Organization

    timestamps(updated_at: false)
  end

  @doc false
  def changeset(activity, attrs) do
    activity
    |> cast(attrs, [
      :activity_type,
      :related_id,
      :related_type,
      :details,
      :summary,
      :alert_id,
      :user_id,
      :organization_id
    ])
    |> validate_required([:activity_type, :alert_id, :organization_id])
    |> validate_inclusion(:activity_type, @activity_types)
    |> foreign_key_constraint(:alert_id)
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:organization_id)
  end

  @doc """
  Changeset for creating a new activity entry.
  """
  def create_changeset(attrs, %Alert{} = alert, user \\ nil) do
    %__MODULE__{}
    |> changeset(attrs)
    |> put_change(:alert_id, alert.id)
    |> put_change(:organization_id, alert.organization_id)
    |> maybe_put_user_id(user)
  end

  defp maybe_put_user_id(changeset, nil), do: changeset
  defp maybe_put_user_id(changeset, %User{} = user), do: put_change(changeset, :user_id, user.id)

  @doc """
  Returns the list of activity types.
  """
  def activity_types, do: @activity_types
end
