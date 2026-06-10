defmodule TamanduaServer.Repo.Migrations.CreateAttackChains do
  use Ecto.Migration

  def change do
    # Attack chain definitions table
    create_if_not_exists table(:attack_chains, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      add :name, :string, null: false
      add :description, :text
      add :severity, :string, null: false, default: "high"
      add :enabled, :boolean, null: false, default: true

      # Chain definition stored as JSONB for flexibility
      add :definition, :map, null: false

      # Metadata
      add :author, :string
      add :version, :string, default: "1.0"
      add :tags, {:array, :string}, default: []

      # Testing mode (dry run)
      add :test_mode, :boolean, null: false, default: false

      # Statistics
      add :trigger_count, :integer, null: false, default: 0
      add :false_positive_count, :integer, null: false, default: 0
      add :last_triggered_at, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec)
    end

    # Indexes for attack_chains
    create_if_not_exists index(:attack_chains, [:organization_id])
    create_if_not_exists index(:attack_chains, [:enabled])
    create_if_not_exists index(:attack_chains, [:severity])
    create_if_not_exists index(:attack_chains, [:tags], using: "GIN")

    # Unique constraint on name per organization
    create_if_not_exists unique_index(:attack_chains, [:organization_id, :name],
                          name: :attack_chains_organization_id_name_index
                        )

    # Chain detection results table
    create_if_not_exists table(:chain_detections, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :chain_id, references(:attack_chains, type: :binary_id, on_delete: :delete_all),
        null: false
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all), null: false
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)
      add :alert_id, references(:alerts, type: :binary_id, on_delete: :nilify_all)

      # Detection details
      add :status, :string, null: false, default: "in_progress"
      add :current_step, :integer, null: false, default: 0
      add :total_steps, :integer, null: false
      add :completed, :boolean, null: false, default: false

      # Matched event IDs
      add :event_ids, {:array, :binary_id}, default: []

      # Correlation data
      add :correlation_data, :map, default: %{}

      # MITRE techniques detected across all steps
      add :mitre_techniques, {:array, :string}, default: []
      add :mitre_tactics, {:array, :string}, default: []

      # Timestamps
      add :started_at, :utc_datetime_usec, null: false
      add :last_updated_at, :utc_datetime_usec, null: false
      add :completed_at, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec)
    end

    # Indexes for chain_detections
    create_if_not_exists index(:chain_detections, [:chain_id])
    create_if_not_exists index(:chain_detections, [:agent_id])
    create_if_not_exists index(:chain_detections, [:organization_id])
    create_if_not_exists index(:chain_detections, [:alert_id])
    create_if_not_exists index(:chain_detections, [:status])
    create_if_not_exists index(:chain_detections, [:completed])
    create_if_not_exists index(:chain_detections, [:started_at])

    # Composite indexes for queries
    create_if_not_exists index(:chain_detections, [:organization_id, :status, :completed])
    create_if_not_exists index(:chain_detections, [:agent_id, :status])
    create_if_not_exists index(:chain_detections, [:chain_id, :completed])

    # GIN indexes for array queries
    create_if_not_exists index(:chain_detections, [:mitre_techniques], using: "GIN")
    create_if_not_exists index(:chain_detections, [:mitre_tactics], using: "GIN")
  end
end
