defmodule TamanduaServer.Repo.Migrations.AddIsolationStatusToAgents do
  use Ecto.Migration

  def change do
    execute(
      "ALTER TABLE agents ADD COLUMN IF NOT EXISTS isolation_status jsonb",
      "ALTER TABLE agents DROP COLUMN IF EXISTS isolation_status"
    )
  end
end
