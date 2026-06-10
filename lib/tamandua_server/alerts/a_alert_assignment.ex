defmodule TamanduaServer.Alerts.AlertAssignment do
  @moduledoc """
  Schema for tracking alert assignment history.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Accounts.User

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec, updated_at: false]

  schema "alert_assignments" do
    field :assignment_type, :string
    field :handoff_notes, :string
    field :unassigned_at, :utc_datetime_usec
    field :unassignment_reason, :string

    belongs_to :alert, Alert
    belongs_to :assigned_to, User, foreign_key: :assigned_to_id
    belongs_to :assigned_by, User, foreign_key: :assigned_by_id
    belongs_to :unassigned_by, User, foreign_key: :unassigned_by_id

    timestamps(updated_at: false)
  end

  def changeset(assignment, attrs) do
    assignment
    |> cast(attrs, [
      :alert_id,
      :assigned_to_id,
      :assigned_by_id,
      :assignment_type,
      :handoff_notes,
      :unassigned_at,
      :unassigned_by_id,
      :unassignment_reason
    ])
    |> validate_required([:alert_id, :assigned_to_id])
    |> validate_inclusion(:assignment_type, ["manual", "auto", "escalation", "round_robin"])
    |> foreign_key_constraint(:alert_id)
    |> foreign_key_constraint(:assigned_to_id)
  end
end
