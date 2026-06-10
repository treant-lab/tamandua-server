defmodule TamanduaServer.Alerts.TagAssignment do
  @moduledoc """
  Schema for alert-tag assignments (join table).

  Tracks which tags are assigned to which alerts, along with
  audit information about who assigned the tag and when.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Alerts.Tag
  alias TamanduaServer.Accounts.User

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  schema "alert_tag_assignments" do
    belongs_to :alert, Alert
    belongs_to :tag, Tag
    belongs_to :assigned_by, User, foreign_key: :assigned_by_id

    timestamps(updated_at: false)
  end

  @doc false
  def changeset(assignment, attrs) do
    assignment
    |> cast(attrs, [:alert_id, :tag_id, :assigned_by_id])
    |> validate_required([:alert_id, :tag_id])
    |> unique_constraint([:alert_id, :tag_id], name: :alert_tag_assignments_unique)
    |> foreign_key_constraint(:alert_id)
    |> foreign_key_constraint(:tag_id)
    |> foreign_key_constraint(:assigned_by_id)
  end
end
