defmodule TamanduaServer.Agents.PolicyAssignment do
  @moduledoc """
  Schema for assigning policies to individual agents (overrides).
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.User
  alias TamanduaServer.Agents.{Policy, Agent}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "agent_policy_assignments" do
    field :overrides, :map, default: %{}
    field :priority, :integer, default: 100
    field :assigned_at, :utc_datetime

    belongs_to :policy, Policy
    belongs_to :agent, Agent
    belongs_to :assigned_by, User, foreign_key: :assigned_by_id

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(assignment, attrs) do
    assignment
    |> cast(attrs, [:policy_id, :agent_id, :overrides, :priority, :assigned_at, :assigned_by_id])
    |> validate_required([:policy_id, :agent_id])
    |> put_assigned_at()
    |> foreign_key_constraint(:policy_id)
    |> foreign_key_constraint(:agent_id)
    |> foreign_key_constraint(:assigned_by_id)
    |> unique_constraint([:policy_id, :agent_id])
  end

  defp put_assigned_at(changeset) do
    case get_field(changeset, :assigned_at) do
      nil -> put_change(changeset, :assigned_at, DateTime.utc_now())
      _ -> changeset
    end
  end
end
