defmodule TamanduaServer.Repo.Migrations.CreateAuditExports do
  use Ecto.Migration

  def change do
    create table(:audit_exports, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      add :export_type, :string, null: false # csv, json, pdf
      add :filters, :map, default: %{}

      # Status
      add :status, :string, default: "pending" # pending, processing, completed, failed
      add :progress, :integer, default: 0
      add :total_records, :integer

      # File info
      add :file_path, :string
      add :file_size, :bigint
      add :download_url, :string
      add :expires_at, :utc_datetime_usec

      # Error handling
      add :error_message, :string

      # Scheduled exports
      add :schedule, :string # daily, weekly, monthly
      add :next_run_at, :utc_datetime_usec
      add :is_recurring, :boolean, default: false

      timestamps(type: :utc_datetime_usec)
    end

    create index(:audit_exports, [:organization_id])
    create index(:audit_exports, [:user_id])
    create index(:audit_exports, [:status])
    create index(:audit_exports, [:is_recurring, :next_run_at])
    create index(:audit_exports, [:expires_at])
  end
end
