defmodule TamanduaServer.Hunting.QueryRating do
  @moduledoc """
  Schema for query ratings, votes, and reviews.
  """
  use Ecto.Schema
  import Ecto.Changeset

  schema "query_ratings" do
    belongs_to :saved_query, TamanduaServer.Hunting.SavedQuery
    belongs_to :user, TamanduaServer.Accounts.User

    field :vote, :integer
    field :rating, :integer
    field :comment, :string

    timestamps()
  end

  @doc false
  def changeset(rating, attrs) do
    rating
    |> cast(attrs, [:saved_query_id, :user_id, :vote, :rating, :comment])
    |> validate_required([:saved_query_id, :user_id])
    |> validate_inclusion(:vote, [-1, 1])
    |> validate_inclusion(:rating, 1..5)
    |> unique_constraint([:saved_query_id, :user_id], name: :query_ratings_unique_user_query)
  end
end
