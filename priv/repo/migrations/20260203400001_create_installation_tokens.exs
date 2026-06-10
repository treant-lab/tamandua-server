defmodule TamanduaServer.Repo.Migrations.CreateInstallationTokens do
  use Ecto.Migration

  def change do
    create table(:installation_tokens, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :token_hash, :string, null: false
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)
      add :name, :string
      add :created_by, :string
      add :expires_at, :utc_datetime_usec
      add :max_uses, :integer
      add :use_count, :integer, default: 0
      add :revoked, :boolean, default: false
      add :last_used_at, :utc_datetime_usec

      timestamps()
    end

    create unique_index(:installation_tokens, [:token_hash])
    create index(:installation_tokens, [:organization_id])
    create index(:installation_tokens, [:revoked])
  end
end
