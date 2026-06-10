defmodule TamanduaServer.Alerts.StateTransition do
  @moduledoc """
  Schema for tracking alert state transitions (audit log).
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Accounts.User

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec, updated_at: false]

  schema "alert_state_transitions" do
    field :from_state, :string
    field :to_state, :string
    field :transition_reason, :string
    field :transition_notes, :string
    field :metadata, :map, default: %{}

    belongs_to :alert, Alert
    belongs_to :transitioned_by, User, foreign_key: :transitioned_by_id

    timestamps(updated_at: false)
  end

  def changeset(transition, attrs) do
    transition
    |> cast(attrs, [
      :alert_id,
      :from_state,
      :to_state,
      :transition_reason,
      :transition_notes,
      :transitioned_by_id,
      :metadata
    ])
    |> validate_required([:alert_id, :from_state, :to_state])
    |> foreign_key_constraint(:alert_id)
    |> foreign_key_constraint(:transitioned_by_id)
  end
end
