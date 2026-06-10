defmodule TamanduaServer.Repo.Migrations.CreateCommentAttachments do
  use Ecto.Migration

  def change do
    create table(:comment_attachments, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :comment_id, references(:alert_comments, type: :binary_id, on_delete: :delete_all), null: false
      add :user_id, references(:users, type: :binary_id, on_delete: :nilify_all), null: false
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      add :filename, :string, null: false
      add :content_type, :string, null: false
      add :size_bytes, :bigint, null: false
      add :storage_path, :string, null: false
      add :checksum_sha256, :string, null: false

      # Attachment type: screenshot, pcap, log, other
      add :attachment_type, :string, null: false

      # Preview/thumbnail for images
      add :thumbnail_path, :string

      # Virus scan results
      add :scan_status, :string, default: "pending"
      add :scan_result, :string
      add :scanned_at, :utc_datetime_usec

      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime_usec)
    end

    create index(:comment_attachments, [:comment_id])
    create index(:comment_attachments, [:user_id])
    create index(:comment_attachments, [:organization_id])
    create index(:comment_attachments, [:checksum_sha256])
    create index(:comment_attachments, [:scan_status])
  end
end
