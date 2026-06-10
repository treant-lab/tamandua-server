defmodule TamanduaServer.Agents.GroupMember do
  @moduledoc """
  Join table for agent group membership.

  Tracks which agents belong to which groups with optional metadata.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Agents.{Agent, Group}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "agent_group_members" do
    field :added_by, :string
    field :metadata, :map, default: %{}

    belongs_to :agent, Agent, type: :binary_id
    belongs_to :group, Group

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(member, attrs) do
    member
    |> cast(attrs, [:agent_id, :group_id, :added_by, :metadata])
    |> validate_required([:agent_id, :group_id])
    |> foreign_key_constraint(:agent_id)
    |> foreign_key_constraint(:group_id)
    |> unique_constraint([:agent_id, :group_id],
      name: :agent_group_members_agent_id_group_id_index,
      message: "Agent is already a member of this group"
    )
  end
end
