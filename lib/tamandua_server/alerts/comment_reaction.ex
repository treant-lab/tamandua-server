defmodule TamanduaServer.Alerts.CommentReaction do
  @moduledoc """
  Schema for comment reactions (thumbs up, heart, etc.).
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Organization, User}
  alias TamanduaServer.Alerts.Comment

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  @reaction_types ~w(thumbs_up thumbs_down eyes heart check rocket confused)

  schema "comment_reactions" do
    field :reaction_type, :string

    belongs_to :comment, Comment
    belongs_to :user, User
    belongs_to :organization, Organization

    timestamps(updated_at: false)
  end

  @doc false
  def changeset(reaction, attrs) do
    reaction
    |> cast(attrs, [:reaction_type, :comment_id, :user_id, :organization_id])
    |> validate_required([:reaction_type, :comment_id, :user_id, :organization_id])
    |> validate_inclusion(:reaction_type, @reaction_types)
    |> unique_constraint([:comment_id, :user_id, :reaction_type])
    |> foreign_key_constraint(:comment_id)
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:organization_id)
  end

  @doc """
  Changeset for creating a new reaction.
  """
  def create_changeset(attrs, %User{} = user, %Comment{} = comment) do
    %__MODULE__{}
    |> changeset(attrs)
    |> put_change(:user_id, user.id)
    |> put_change(:comment_id, comment.id)
    |> put_change(:organization_id, comment.organization_id)
  end

  @doc """
  Returns the list of allowed reaction types.
  """
  def reaction_types, do: @reaction_types
end
