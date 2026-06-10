defmodule TamanduaServer.Repo.Migrations.CreateWalletAuthTables do
  use Ecto.Migration

  def change do
    create table(:wallet_identities, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :chain, :string, null: false, default: "solana"
      add :wallet_address, :string, null: false
      add :provider, :string
      add :verified_at, :utc_datetime_usec, null: false
      add :last_used_at, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:wallet_identities, [:chain, :wallet_address])
    create index(:wallet_identities, [:user_id])

    create table(:wallet_auth_events, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :chain, :string, null: false, default: "solana"
      add :wallet_address, :string, null: false
      add :provider, :string
      add :event_type, :string, null: false
      add :ip_address, :string
      add :user_agent, :text
      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime_usec)
    end

    create index(:wallet_auth_events, [:wallet_address])
    create index(:wallet_auth_events, [:user_id])
    create index(:wallet_auth_events, [:event_type])
  end
end
