defmodule TamanduaServer.Repo.Migrations.CreateBackupCodes do
  use Ecto.Migration

  def change do
    create table(:mfa_backup_codes, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, on_delete: :delete_all, type: :binary_id), null: false
      add :code_hash, :string, null: false  # bcrypt hash of the code
      add :used_at, :utc_datetime_usec
      add :used_ip, :string

      timestamps(type: :utc_datetime_usec)
    end

    create index(:mfa_backup_codes, [:user_id])
    create index(:mfa_backup_codes, [:user_id, :used_at])
  end
end
