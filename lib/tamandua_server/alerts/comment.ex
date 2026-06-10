defmodule TamanduaServer.Alerts.Comment do
  @moduledoc """
  Schema for alert comments with threading, reactions, and attachments.
  Supports markdown formatting, @mentions, and collaborative editing.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Organization, User}
  alias TamanduaServer.Alerts.Alert

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  schema "alert_comments" do
    field :content, :string
    field :content_type, :string, default: "markdown"
    field :is_pinned, :boolean, default: false
    field :is_deleted, :boolean, default: false
    field :deleted_at, :utc_datetime_usec
    field :edited_at, :utc_datetime_usec
    field :edit_count, :integer, default: 0
    field :mentioned_user_ids, {:array, :binary_id}, default: []
    field :metadata, :map, default: %{}

    belongs_to :alert, Alert
    belongs_to :user, User
    belongs_to :parent, __MODULE__
    belongs_to :organization, Organization
    belongs_to :deleted_by, User, foreign_key: :deleted_by_id

    has_many :replies, __MODULE__, foreign_key: :parent_id
    has_many :attachments, TamanduaServer.Alerts.CommentAttachment, foreign_key: :comment_id
    has_many :reactions, TamanduaServer.Alerts.CommentReaction, foreign_key: :comment_id
    has_many :edit_history, TamanduaServer.Alerts.CommentEditHistory, foreign_key: :comment_id

    timestamps()
  end

  @doc false
  def changeset(comment, attrs) do
    comment
    |> cast(attrs, [
      :content,
      :content_type,
      :is_pinned,
      :is_deleted,
      :deleted_at,
      :deleted_by_id,
      :edited_at,
      :edit_count,
      :mentioned_user_ids,
      :metadata,
      :alert_id,
      :user_id,
      :parent_id,
      :organization_id
    ])
    |> validate_required([:content, :alert_id, :user_id, :organization_id])
    |> validate_length(:content, min: 1, max: 50_000)
    |> validate_inclusion(:content_type, ~w(markdown plain))
    |> extract_mentions()
    |> foreign_key_constraint(:alert_id)
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:parent_id)
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:deleted_by_id)
  end

  @doc """
  Changeset for creating a new comment.
  """
  def create_changeset(attrs, %User{} = user, %Alert{} = alert) do
    %__MODULE__{}
    |> changeset(attrs)
    |> put_change(:user_id, user.id)
    |> put_change(:alert_id, alert.id)
    |> put_change(:organization_id, alert.organization_id)
  end

  @doc """
  Changeset for editing a comment.
  """
  def edit_changeset(comment, attrs) do
    comment
    |> cast(attrs, [:content])
    |> validate_required([:content])
    |> validate_length(:content, min: 1, max: 50_000)
    |> extract_mentions()
    |> put_change(:edited_at, DateTime.utc_now())
    |> put_change(:edit_count, (comment.edit_count || 0) + 1)
  end

  @doc """
  Changeset for soft-deleting a comment.
  """
  def delete_changeset(comment, deleted_by_user_id) do
    comment
    |> change()
    |> put_change(:is_deleted, true)
    |> put_change(:deleted_at, DateTime.utc_now())
    |> put_change(:deleted_by_id, deleted_by_user_id)
  end

  @doc """
  Changeset for pinning/unpinning a comment.
  """
  def pin_changeset(comment, is_pinned) do
    comment
    |> change()
    |> put_change(:is_pinned, is_pinned)
  end

  # Extract @mentions from content and store user IDs
  defp extract_mentions(changeset) do
    case get_change(changeset, :content) do
      nil ->
        changeset

      content ->
        # Extract @username mentions (simplified - in production you'd validate against actual users)
        mentions = Regex.scan(~r/@([a-zA-Z0-9_-]+)/, content)
        |> Enum.map(fn [_, username] -> username end)
        |> Enum.uniq()

        put_change(changeset, :metadata, Map.put(changeset.data.metadata || %{}, "mentions", mentions))
    end
  end
end
