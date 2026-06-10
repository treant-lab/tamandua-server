defmodule TamanduaServer.Repo.Migrations.CreateCaseInvestigations do
  use Ecto.Migration

  def change do
    create_if_not_exists table(:case_investigations, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :title, :string, null: false
      add :description, :text
      add :status, :string, null: false, default: "open"
      add :severity, :string, null: false, default: "medium"

      # Assignment
      add :assigned_to, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :created_by, references(:users, type: :binary_id, on_delete: :nilify_all), null: false

      # Linked entities (arrays of UUIDs stored as text arrays for flexibility)
      add :alert_ids, {:array, :binary_id}, default: []
      add :event_ids, {:array, :binary_id}, default: []

      # Investigation content
      add :notes, :text
      add :findings, :text
      add :timeline, :map, default: %{}

      # Tags for categorization
      add :tags, {:array, :string}, default: []

      # MITRE ATT&CK mapping
      add :mitre_tactics, {:array, :string}, default: []
      add :mitre_techniques, {:array, :string}, default: []

      # Multi-tenancy
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps()
    end

    create_if_not_exists index(:case_investigations, [:status])
    create_if_not_exists index(:case_investigations, [:severity])
    create_if_not_exists index(:case_investigations, [:assigned_to])
    create_if_not_exists index(:case_investigations, [:created_by])
    create_if_not_exists index(:case_investigations, [:organization_id])
    create_if_not_exists index(:case_investigations, [:inserted_at])
  end
end
