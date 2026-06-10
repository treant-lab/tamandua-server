defmodule TamanduaServer.Repo.Migrations.CreateAlerts do
  use Ecto.Migration

  def change do
    create table(:alerts, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :title, :string, null: false
      add :description, :text
      add :severity, :string, default: "medium", null: false
      add :status, :string, default: "new", null: false
      add :source, :string  # detection_engine, sigma, yara, ml, honeyfile
      add :event_ids, {:array, :binary_id}, default: []
      add :mitre_tactics, {:array, :string}, default: []
      add :mitre_techniques, {:array, :string}, default: []
      add :threat_score, :float, default: 0.0
      add :enrichment, :map, default: %{}
      add :resolution_notes, :text
      add :resolved_at, :utc_datetime_usec

      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all), null: false
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)
      add :assigned_to_id, references(:users, type: :binary_id, on_delete: :nilify_all)

      timestamps(type: :utc_datetime_usec)
    end

    create index(:alerts, [:agent_id])
    create index(:alerts, [:organization_id])
    create index(:alerts, [:assigned_to_id])
    create index(:alerts, [:severity])
    create index(:alerts, [:status])
    create index(:alerts, [:source])
    create index(:alerts, [:inserted_at])

    # Composite index for common dashboard queries
    create index(:alerts, [:organization_id, :status, :severity])

    # GIN index for MITRE technique searches
    execute "CREATE INDEX alerts_mitre_tactics_idx ON alerts USING GIN (mitre_tactics)"
    execute "CREATE INDEX alerts_mitre_techniques_idx ON alerts USING GIN (mitre_techniques)"
  end
end
