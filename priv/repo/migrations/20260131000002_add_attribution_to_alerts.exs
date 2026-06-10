defmodule TamanduaServer.Repo.Migrations.AddAttributionToAlerts do
  use Ecto.Migration

  def change do
    alter table(:alerts) do
      add :attributed_actors, {:array, :string}, default: []
      add :campaign_id, :string
      add :attribution_confidence, :float
      add :attribution_details, :map, default: %{}
    end

    create_if_not_exists index(:alerts, [:campaign_id], where: "campaign_id IS NOT NULL")
    create_if_not_exists index(:alerts, [:attribution_confidence], where: "attribution_confidence IS NOT NULL")
  end
end
