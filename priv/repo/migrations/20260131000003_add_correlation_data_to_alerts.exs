defmodule TamanduaServer.Repo.Migrations.AddCorrelationDataToAlerts do
  use Ecto.Migration

  def change do
    alter table(:alerts) do
      add :correlation_data, :map, default: %{}
    end
  end
end
