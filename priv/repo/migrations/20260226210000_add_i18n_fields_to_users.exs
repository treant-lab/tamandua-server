defmodule TamanduaServer.Repo.Migrations.AddI18nFieldsToUsers do
  use Ecto.Migration

  def change do
    alter table(:users) do
      add :locale, :string, default: "en", null: false
      add :timezone, :string, default: "UTC", null: false
    end

    create index(:users, [:locale])
  end
end
