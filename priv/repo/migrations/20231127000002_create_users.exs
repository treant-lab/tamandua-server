defmodule TamanduaServer.Repo.Migrations.CreateUsers do
  use Ecto.Migration

  def change do
    create table(:users, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :email, :string, null: false
      add :password_hash, :string, null: false
      add :role, :string, default: "analyst"
      add :name, :string
      add :mfa_secret, :string
      add :mfa_enabled, :boolean, default: false
      add :last_login_at, :utc_datetime_usec

      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:users, [:email])
    create index(:users, [:organization_id])
    create index(:users, [:role])
  end
end
