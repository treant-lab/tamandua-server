defmodule TamanduaServer.Repo.Migrations.CreateGlobalBaselines do
  use Ecto.Migration

  def change do
    # Agent baselines table - stores baselines from individual agents
    create table(:agent_baselines, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all), null: false
      add :baseline_type, :string, null: false
      add :baseline_key, :string, null: false
      add :baseline_data, :map, null: false
      add :learning_samples, :integer, default: 0
      add :first_seen, :utc_datetime
      add :last_updated, :utc_datetime
      add :version, :integer, default: 1

      timestamps(type: :utc_datetime)
    end

    create index(:agent_baselines, [:agent_id])
    create index(:agent_baselines, [:baseline_type])
    create index(:agent_baselines, [:baseline_key])
    create index(:agent_baselines, [:last_updated])
    create unique_index(:agent_baselines, [:agent_id, :baseline_type, :baseline_key])

    # Global baselines table - aggregated baselines from all agents
    create table(:global_baselines, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :baseline_type, :string, null: false
      add :baseline_key, :string, null: false
      add :baseline_data, :map, null: false
      add :agent_count, :integer, default: 0
      add :total_samples, :integer, default: 0
      add :confidence_score, :float

      timestamps(type: :utc_datetime)
    end

    create index(:global_baselines, [:baseline_type])
    create index(:global_baselines, [:baseline_key])
    create index(:global_baselines, [:updated_at])
    create unique_index(:global_baselines, [:baseline_type, :baseline_key])

    # Baseline drift tracking table
    create table(:baseline_drifts, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :baseline_type, :string, null: false
      add :baseline_key, :string, null: false
      add :drift_percent, :float, null: false
      add :direction, :string
      add :previous_value, :map
      add :current_value, :map
      add :detected_at, :utc_datetime, null: false

      timestamps(type: :utc_datetime)
    end

    create index(:baseline_drifts, [:baseline_type])
    create index(:baseline_drifts, [:baseline_key])
    create index(:baseline_drifts, [:detected_at])
    create index(:baseline_drifts, [:drift_percent])
  end
end
