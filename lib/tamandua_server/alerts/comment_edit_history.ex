defmodule TamanduaServer.Alerts.CommentEditHistory do
  @moduledoc """
  Schema for tracking comment edit history.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Organization, User}
  alias TamanduaServer.Alerts.Comment

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  schema "comment_edit_history" do
    field :previous_content, :string
    field :new_content, :string
    field :edit_reason, :string

    belongs_to :comment, Comment
    belongs_to :user, User
    belongs_to :organization, Organization

    timestamps(updated_at: false)
  end

  @doc false
  def changeset(history, attrs) do
    history
    |> cast(attrs, [
      :previous_content,
      :new_content,
      :edit_reason,
      :comment_id,
      :user_id,
      :organization_id
    ])
    |> validate_required([
      :previous_content,
      :new_content,
      :comment_id,
      :user_id,
      :organization_id
    ])
    |> foreign_key_constraint(:comment_id)
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:organization_id)
  end

  @doc """
  Changeset for creating a new edit history entry.
  """
  def create_changeset(attrs, %User{} = user, %Comment{} = comment) do
    %__MODULE__{}
    |> changeset(attrs)
    |> put_change(:user_id, user.id)
    |> put_change(:comment_id, comment.id)
    |> put_change(:organization_id, comment.organization_id)
  end
end
