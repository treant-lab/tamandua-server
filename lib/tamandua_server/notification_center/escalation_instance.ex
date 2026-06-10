defmodule TamanduaServer.NotificationCenter.EscalationInstance do
  @moduledoc """
  Schema for active escalation instances.
  """
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @states ["pending", "in_progress", "acknowledged", "completed", "cancelled"]

  schema "escalation_instances" do
    field :current_level, :integer, default: 0
    field :max_level, :integer

    field :started_at, :utc_datetime
    field :completed_at, :utc_datetime
    field :acknowledged_at, :utc_datetime

    field :state, :string, default: "pending"

    belongs_to :organization, TamanduaServer.Accounts.Organization
    belongs_to :escalation_policy, TamanduaServer.NotificationCenter.EscalationPolicy
    belongs_to :alert, TamanduaServer.Alerts.Alert
    belongs_to :acknowledged_by, TamanduaServer.Accounts.User

    timestamps(type: :utc_datetime)
  end

  def changeset(instance, attrs) do
    instance
    |> cast(attrs, [
      :organization_id,
      :escalation_policy_id,
      :alert_id,
      :current_level,
      :max_level,
      :started_at,
      :state
    ])
    |> validate_required([
      :organization_id,
      :escalation_policy_id,
      :alert_id,
      :max_level,
      :started_at
    ])
    |> validate_inclusion(:state, @states)
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:escalation_policy_id)
    |> foreign_key_constraint(:alert_id)
  end

  def escalate_changeset(instance) do
    instance
    |> change(%{
      current_level: instance.current_level + 1,
      state: "in_progress"
    })
  end

  def acknowledge_changeset(instance, user_id) do
    instance
    |> change(%{
      state: "acknowledged",
      acknowledged_at: DateTime.utc_now(),
      acknowledged_by_id: user_id
    })
  end

  def complete_changeset(instance) do
    instance
    |> change(%{
      state: "completed",
      completed_at: DateTime.utc_now()
    })
  end

  def cancel_changeset(instance) do
    instance
    |> change(%{
      state: "cancelled",
      completed_at: DateTime.utc_now()
    })
  end

  def states, do: @states
end
