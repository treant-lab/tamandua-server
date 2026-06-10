defmodule TamanduaServer.AI.Conversation do
  @moduledoc """
  Persistent AI Assistant conversation history.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  schema "ai_conversations" do
    field :user_id, :string
    field :title, :string
    field :messages, {:array, :map}, default: []

    timestamps()
  end

  def changeset(conversation, attrs) do
    conversation
    |> cast(attrs, [:id, :user_id, :title, :messages])
    |> validate_required([:user_id, :title, :messages])
  end
end
