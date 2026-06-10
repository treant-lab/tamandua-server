defmodule TamanduaServer.InsiderThreat.PeerGroupMember do
  @moduledoc """
  Association schema for peer group membership.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.User
  alias TamanduaServer.InsiderThreat.PeerGroup

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  schema "insider_threat_peer_group_members" do
    belongs_to :peer_group, PeerGroup
    belongs_to :user, User

    timestamps()
  end

  @doc false
  def changeset(member, attrs) do
    member
    |> cast(attrs, [:peer_group_id, :user_id])
    |> validate_required([:peer_group_id, :user_id])
    |> unique_constraint([:peer_group_id, :user_id])
    |> foreign_key_constraint(:peer_group_id)
    |> foreign_key_constraint(:user_id)
  end
end
