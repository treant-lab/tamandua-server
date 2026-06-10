defmodule TamanduaServer.Repo.Migrations.AddIpAddressToAgents do
  use Ecto.Migration

  def change do
    # Column already exists if migration runs after manual addition
    execute(
      "ALTER TABLE agents ADD COLUMN IF NOT EXISTS ip_address VARCHAR",
      "ALTER TABLE agents DROP COLUMN IF EXISTS ip_address"
    )
  end
end
