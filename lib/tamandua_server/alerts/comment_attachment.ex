defmodule TamanduaServer.Alerts.CommentAttachment do
  @moduledoc """
  Schema for comment attachments (screenshots, PCAP files, logs, etc.).
  Supports file uploads up to 10MB with virus scanning.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Organization, User}
  alias TamanduaServer.Alerts.Comment

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  @max_file_size 10_485_760 # 10MB in bytes
  @allowed_types ~w(screenshot pcap log other)
  @scan_statuses ~w(pending clean infected error)

  schema "comment_attachments" do
    field :filename, :string
    field :content_type, :string
    field :size_bytes, :integer
    field :storage_path, :string
    field :checksum_sha256, :string
    field :attachment_type, :string
    field :thumbnail_path, :string
    field :scan_status, :string, default: "pending"
    field :scan_result, :string
    field :scanned_at, :utc_datetime_usec
    field :metadata, :map, default: %{}

    belongs_to :comment, Comment
    belongs_to :user, User
    belongs_to :organization, Organization

    timestamps()
  end

  @doc false
  def changeset(attachment, attrs) do
    attachment
    |> cast(attrs, [
      :filename,
      :content_type,
      :size_bytes,
      :storage_path,
      :checksum_sha256,
      :attachment_type,
      :thumbnail_path,
      :scan_status,
      :scan_result,
      :scanned_at,
      :metadata,
      :comment_id,
      :user_id,
      :organization_id
    ])
    |> validate_required([
      :filename,
      :content_type,
      :size_bytes,
      :storage_path,
      :checksum_sha256,
      :attachment_type,
      :comment_id,
      :user_id,
      :organization_id
    ])
    |> validate_inclusion(:attachment_type, @allowed_types)
    |> validate_inclusion(:scan_status, @scan_statuses)
    |> validate_number(:size_bytes, greater_than: 0, less_than_or_equal_to: @max_file_size)
    |> foreign_key_constraint(:comment_id)
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:organization_id)
  end

  @doc """
  Changeset for creating a new attachment.
  """
  def create_changeset(attrs, %User{} = user, %Comment{} = comment) do
    %__MODULE__{}
    |> changeset(attrs)
    |> put_change(:user_id, user.id)
    |> put_change(:comment_id, comment.id)
    |> put_change(:organization_id, comment.organization_id)
  end

  @doc """
  Changeset for updating scan results.
  """
  def scan_result_changeset(attachment, scan_status, scan_result) do
    attachment
    |> change()
    |> put_change(:scan_status, scan_status)
    |> put_change(:scan_result, scan_result)
    |> put_change(:scanned_at, DateTime.utc_now())
  end

  @doc """
  Returns the maximum allowed file size in bytes.
  """
  def max_file_size, do: @max_file_size

  @doc """
  Returns the list of allowed attachment types.
  """
  def allowed_types, do: @allowed_types
end
