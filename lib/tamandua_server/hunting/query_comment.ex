defmodule TamanduaServer.Hunting.QueryComment do
  @moduledoc """
  Schema for query comments and discussions.
  """
  use Ecto.Schema
  import Ecto.Changeset

  schema "query_comments" do
    belongs_to :saved_query, TamanduaServer.Hunting.SavedQuery
    belongs_to :user, TamanduaServer.Accounts.User
    belongs_to :parent, TamanduaServer.Hunting.QueryComment

    field :comment, :string

    has_many :replies, TamanduaServer.Hunting.QueryComment, foreign_key: :parent_id

    timestamps()
  end

  @doc false
  def changeset(comment, attrs) do
    comment
    |> cast(attrs, [:saved_query_id, :user_id, :parent_id, :comment])
    |> validate_required([:saved_query_id, :user_id, :comment])
    |> validate_length(:comment, min: 1, max: 5000)
  end
end
