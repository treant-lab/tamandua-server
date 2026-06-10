defmodule TamanduaServer.Agents.PolicyHistory do
  @moduledoc """
  Schema for tracking policy change history and versions.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.User
  alias TamanduaServer.Agents.Policy

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @change_types ~w(created updated activated deactivated deployed rolled_back deleted)

  schema "agent_policy_history" do
    field :version, :integer
    field :previous_version, :integer
    field :change_type, :string
    field :changes, :map, default: %{}
    field :diff, :map, default: %{}
    field :change_reason, :string

    belongs_to :policy, Policy
    belongs_to :changed_by, User, foreign_key: :changed_by_id

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(history, attrs) do
    history
    |> cast(attrs, [
      :policy_id,
      :version,
      :previous_version,
      :change_type,
      :changes,
      :diff,
      :change_reason,
      :changed_by_id
    ])
    |> validate_required([:policy_id, :version, :change_type])
    |> validate_inclusion(:change_type, @change_types)
    |> foreign_key_constraint(:policy_id)
    |> foreign_key_constraint(:changed_by_id)
  end
end
