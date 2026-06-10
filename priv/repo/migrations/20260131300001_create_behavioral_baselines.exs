defmodule TamanduaServer.Repo.Migrations.CreateBehavioralBaselines do
  use Ecto.Migration

  def change do
    create_if_not_exists table(:behavioral_baselines, primary_key: false) do
      add :id, :binary_id, primary_key: true, default: fragment("gen_random_uuid()")
      add :entity_type, :string, null: false
      add :entity_id, :string, null: false
      add :data, :jsonb, null: false, default: "{}"
      add :updated_at, :utc_datetime_usec, null: false, default: fragment("now()")
    end

    create_if_not_exists unique_index(:behavioral_baselines, [:entity_type, :entity_id])
    create_if_not_exists index(:behavioral_baselines, [:entity_type])
  end
end
