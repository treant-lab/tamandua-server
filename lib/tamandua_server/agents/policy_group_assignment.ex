defmodule TamanduaServer.Agents.PolicyGroupAssignment do
  @moduledoc """
  Schema for assigning policies to agent groups.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.User
  alias TamanduaServer.Agents.{Policy, Group}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "agent_policy_group_assignments" do
    field :overrides, :map, default: %{}
    field :priority, :integer, default: 0
    field :assigned_at, :utc_datetime

    belongs_to :policy, Policy
    belongs_to :group, Group
    belongs_to :assigned_by, User, foreign_key: :assigned_by_id

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(assignment, attrs) do
    assignment
    |> cast(attrs, [:policy_id, :group_id, :overrides, :priority, :assigned_at, :assigned_by_id])
    |> validate_required([:policy_id, :group_id])
    |> put_assigned_at()
    |> foreign_key_constraint(:policy_id)
    |> foreign_key_constraint(:group_id)
    |> foreign_key_constraint(:assigned_by_id)
    |> unique_constraint([:policy_id, :group_id])
  end

  defp put_assigned_at(changeset) do
    case get_field(changeset, :assigned_at) do
      nil -> put_change(changeset, :assigned_at, DateTime.utc_now())
      _ -> changeset
    end
  end
end
