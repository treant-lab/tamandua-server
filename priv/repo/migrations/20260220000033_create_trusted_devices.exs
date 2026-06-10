defmodule TamanduaServer.Repo.Migrations.CreateTrustedDevices do
  use Ecto.Migration

  def change do
    create table(:mfa_trusted_devices, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, on_delete: :delete_all, type: :binary_id), null: false
      add :token_hash, :string, null: false  # bcrypt hash of device token
      add :name, :string  # User-friendly device name
      add :fingerprint, :string  # Browser fingerprint (user agent + IP hash)
      add :ip_address, :string
      add :user_agent, :string
      add :expires_at, :utc_datetime_usec  # 30 days from creation
      add :last_used_at, :utc_datetime_usec
      add :revoked_at, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec)
    end

    create index(:mfa_trusted_devices, [:user_id])
    create index(:mfa_trusted_devices, [:user_id, :revoked_at])
    create index(:mfa_trusted_devices, [:token_hash])
  end
end
