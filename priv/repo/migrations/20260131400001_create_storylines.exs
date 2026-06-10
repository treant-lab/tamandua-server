defmodule TamanduaServer.Repo.Migrations.CreateStorylines do
  use Ecto.Migration

  def change do
    create_if_not_exists table(:storylines, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all), null: false
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)
      add :alert_id, references(:alerts, type: :binary_id, on_delete: :nilify_all)

      add :root_pid, :integer
      add :status, :string, null: false, default: "active"
      add :severity, :string, null: false, default: "low"
      add :total_score, :float, null: false, default: 0.0

      # Process PIDs involved in this storyline (array of integers)
      add :process_pids, {:array, :integer}, default: []

      # MITRE ATT&CK coverage
      add :mitre_tactics, {:array, :string}, default: []
      add :mitre_techniques, {:array, :string}, default: []

      # Detections embedded as JSONB (array of detection records)
      add :detections, {:array, :map}, default: []

      # Summary metadata for fast querying
      add :detection_count, :integer, null: false, default: 0
      add :process_count, :integer, null: false, default: 0
      add :tactic_count, :integer, null: false, default: 0

      # Timestamps with microsecond precision
      add :first_seen_at, :utc_datetime_usec
      add :last_seen_at, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec)
    end

    # Indexes for common query patterns
    create_if_not_exists index(:storylines, [:agent_id])
    create_if_not_exists index(:storylines, [:organization_id])
    create_if_not_exists index(:storylines, [:alert_id])
    create_if_not_exists index(:storylines, [:status])
    create_if_not_exists index(:storylines, [:severity])
    create_if_not_exists index(:storylines, [:inserted_at])

    # Composite indexes for dashboard queries
    create_if_not_exists index(:storylines, [:organization_id, :status, :severity])
    create_if_not_exists index(:storylines, [:agent_id, :status])
    create_if_not_exists index(:storylines, [:status, :total_score])

    # GIN indexes for array containment queries (e.g. "find storylines with T1059")
    create_if_not_exists index(:storylines, [:mitre_tactics], using: "GIN")
    create_if_not_exists index(:storylines, [:mitre_techniques], using: "GIN")
  end
end
