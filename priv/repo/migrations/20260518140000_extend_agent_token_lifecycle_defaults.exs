defmodule TamanduaServer.Repo.Migrations.ExtendAgentTokenLifecycleDefaults do
  use Ecto.Migration

  def up do
    alter table(:agents) do
      modify :token_ttl_hours, :integer, default: 720
      modify :token_refresh_window_percent, :integer, default: 60
    end

    execute("""
    UPDATE agents
    SET token_ttl_hours = 720
    WHERE token_ttl_hours IS NULL OR token_ttl_hours < 720
    """)

    execute("""
    UPDATE agents
    SET token_refresh_window_percent = 60
    WHERE token_refresh_window_percent IS NULL OR token_refresh_window_percent > 60
    """)

    execute("""
    UPDATE agent_tokens
    SET expires_at = NOW() + INTERVAL '30 days'
    WHERE revoked_at IS NULL
      AND expires_at < NOW() + INTERVAL '30 days'
      AND expires_at > NOW() - INTERVAL '30 days'
    """)

    execute("""
    UPDATE agent_credentials
    SET expires_at = NOW() + INTERVAL '30 days'
    WHERE revoked_at IS NULL
      AND expires_at < NOW() + INTERVAL '30 days'
      AND expires_at > NOW() - INTERVAL '30 days'
    """)
  end

  def down do
    alter table(:agents) do
      modify :token_ttl_hours, :integer, default: 24
      modify :token_refresh_window_percent, :integer, default: 80
    end
  end
end
