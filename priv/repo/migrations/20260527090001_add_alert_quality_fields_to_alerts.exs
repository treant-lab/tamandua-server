defmodule TamanduaServer.Repo.Migrations.AddAlertQualityFieldsToAlerts do
  use Ecto.Migration

  def change do
    alter table(:alerts) do
      add :rule_version, :string, null: true
      add :recommended_response, :text, null: true
      add :false_positive_notes, :text, null: true
    end
  end
end
