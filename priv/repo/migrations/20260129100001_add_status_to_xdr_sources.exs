defmodule TamanduaServer.Repo.Migrations.AddStatusToXdrSources do
  use Ecto.Migration

  def change do
    execute(
      "ALTER TABLE xdr_sources ADD COLUMN IF NOT EXISTS status varchar(255) DEFAULT 'unknown' NOT NULL",
      "ALTER TABLE xdr_sources DROP COLUMN IF EXISTS status"
    )

    create_if_not_exists index(:xdr_sources, [:status])
  end
end
