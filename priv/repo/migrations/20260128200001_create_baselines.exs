defmodule TamanduaServer.Repo.Migrations.CreateBaselines do
  use Ecto.Migration

  def change do
    create_if_not_exists table(:baselines, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all)
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)
      add :baseline_type, :string, null: false  # process, network, file, schedule
      add :pattern, :map, null: false, default: %{}
      add :occurrence_count, :integer, default: 1
      add :first_seen, :utc_datetime_usec
      add :last_seen, :utc_datetime_usec
      add :confidence_weight, :float, default: 1.0

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists index(:baselines, [:agent_id])
    create_if_not_exists index(:baselines, [:organization_id])
    create_if_not_exists index(:baselines, [:baseline_type])
    create_if_not_exists index(:baselines, [:agent_id, :baseline_type])

    # Unique constraint on agent + type + pattern hash
    # We use a generated column for pattern hash to enable uniqueness
    execute """
    CREATE UNIQUE INDEX baselines_agent_type_pattern_idx
    ON baselines (agent_id, baseline_type, md5(pattern::text))
    WHERE agent_id IS NOT NULL
    """, """
    DROP INDEX baselines_agent_type_pattern_idx
    """

    execute """
    CREATE UNIQUE INDEX baselines_org_type_pattern_idx
    ON baselines (organization_id, baseline_type, md5(pattern::text))
    WHERE organization_id IS NOT NULL AND agent_id IS NULL
    """, """
    DROP INDEX baselines_org_type_pattern_idx
    """

    # Learning status table
    create_if_not_exists table(:baseline_learning_status, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all), null: false
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)
      add :started_at, :utc_datetime_usec, null: false
      add :completed_at, :utc_datetime_usec
      add :learning_days, :integer, default: 7
      add :status, :string, default: "learning"  # learning, completed, paused
      add :events_processed, :integer, default: 0
      add :patterns_learned, :integer, default: 0

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists unique_index(:baseline_learning_status, [:agent_id])
    create_if_not_exists index(:baseline_learning_status, [:organization_id])
    create_if_not_exists index(:baseline_learning_status, [:status])
  end
end
