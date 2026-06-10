defmodule TamanduaServer.Repo.Migrations.CreateDslDetections do
  use Ecto.Migration

  def change do
    create table(:dsl_detections, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :source, :text, null: false
      add :description, :text
      add :severity, :string, null: false
      add :enabled, :boolean, default: true, null: false
      add :mitre_techniques, {:array, :string}, default: []
      add :tags, {:array, :string}, default: []
      add :created_by, :string
      add :version, :integer, default: 1, null: false
      add :compiled_ast, :map
      add :last_triggered_at, :utc_datetime
      add :trigger_count, :integer, default: 0, null: false

      timestamps(type: :utc_datetime)
    end

    create unique_index(:dsl_detections, [:name])
    create index(:dsl_detections, [:enabled])
    create index(:dsl_detections, [:severity])
    create index(:dsl_detections, [:created_by])
    create index(:dsl_detections, [:last_triggered_at])
  end
end
