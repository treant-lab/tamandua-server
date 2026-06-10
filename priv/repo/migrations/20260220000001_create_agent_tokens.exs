defmodule TamanduaServer.Repo.Migrations.CreateAgentTokens do
  use Ecto.Migration

  def change do
    create table(:agent_tokens, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all), null: false
      add :token_generation, :integer, null: false, default: 1
      add :token_hash, :string, null: false
      add :issued_at, :utc_datetime_usec, null: false
      add :expires_at, :utc_datetime_usec, null: false
      add :last_refreshed_at, :utc_datetime_usec
      add :revoked_at, :utc_datetime_usec
      add :revocation_reason, :string
      add :refresh_count, :integer, default: 0
      add :ip_address, :string
      add :user_agent, :string

      timestamps()
    end

    create index(:agent_tokens, [:agent_id])
    create index(:agent_tokens, [:token_hash])
    create index(:agent_tokens, [:expires_at])
    create index(:agent_tokens, [:revoked_at])
    create unique_index(:agent_tokens, [:agent_id, :token_generation])

    # Add token rotation configuration to agents table
    alter table(:agents) do
      add :token_rotation_enabled, :boolean, default: true
      add :token_ttl_hours, :integer, default: 24
      add :token_refresh_window_percent, :integer, default: 80
      add :current_token_generation, :integer, default: 1
    end

    create index(:agents, [:token_rotation_enabled])
  end
end
