defmodule TamanduaServer.Repo.Migrations.AddIsActiveToUsers do
  use Ecto.Migration

  def change do
    execute(
      "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active boolean DEFAULT true NOT NULL",
      "ALTER TABLE users DROP COLUMN IF EXISTS is_active"
    )

    create_if_not_exists index(:users, [:is_active])
  end
end
