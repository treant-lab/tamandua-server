defmodule TamanduaServer.Repo.Migrations.CreateMitreAttackTables do
  use Ecto.Migration

  def change do
    # MITRE Techniques table
    create table(:mitre_techniques, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :technique_id, :string, null: false  # e.g., "T1059" or "T1059.001"
      add :name, :string, null: false
      add :description, :text
      add :platforms, {:array, :string}, default: []
      add :data_sources, {:array, :string}, default: []
      add :tactics, {:array, :string}, default: []  # tactic IDs like "TA0002"
      add :is_subtechnique, :boolean, default: false
      add :parent_technique_id, :string  # For sub-techniques, reference to parent
      add :mitigations, :map, default: %{}  # Mitigation strategies
      add :detection_guidance, :text
      add :external_references, {:array, :map}, default: []
      add :metadata, :map, default: %{}

      timestamps()
    end

    create unique_index(:mitre_techniques, [:technique_id])
    create index(:mitre_techniques, [:is_subtechnique])
    create index(:mitre_techniques, [:parent_technique_id])
    execute "CREATE INDEX mitre_techniques_tactics_idx ON mitre_techniques USING GIN (tactics)"
    execute "CREATE INDEX mitre_techniques_platforms_idx ON mitre_techniques USING GIN (platforms)"

    # Technique mappings table (maps detection rules to techniques)
    create table(:mitre_technique_mappings, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :technique_id, :string, null: false
      add :rule_type, :string, null: false  # "sigma", "yara", "behavioral", "ml"
      add :rule_id, :binary_id  # Reference to sigma_rules, yara_rules, etc.
      add :rule_name, :string, null: false
      add :confidence, :float, default: 1.0  # How confident is this mapping (0.0-1.0)
      add :auto_mapped, :boolean, default: false  # Was this auto-discovered or manual
      add :notes, :text
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps()
    end

    create index(:mitre_technique_mappings, [:technique_id])
    create index(:mitre_technique_mappings, [:rule_type])
    create index(:mitre_technique_mappings, [:rule_id])
    create index(:mitre_technique_mappings, [:organization_id])
    create unique_index(:mitre_technique_mappings, [:technique_id, :rule_type, :rule_id])

    # Threat actors (APT groups) table
    create table(:mitre_threat_actors, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :actor_id, :string, null: false  # e.g., "G0016" (APT29)
      add :name, :string, null: false
      add :aliases, {:array, :string}, default: []
      add :description, :text
      add :techniques, {:array, :string}, default: []  # Associated technique IDs
      add :country, :string
      add :first_seen, :date
      add :last_activity, :date
      add :sophistication, :string  # "low", "medium", "high", "expert"
      add :objectives, {:array, :string}, default: []
      add :sectors, {:array, :string}, default: []  # Targeted sectors
      add :external_references, {:array, :map}, default: []
      add :metadata, :map, default: %{}

      timestamps()
    end

    create unique_index(:mitre_threat_actors, [:actor_id])
    create index(:mitre_threat_actors, [:country])
    execute "CREATE INDEX mitre_threat_actors_techniques_idx ON mitre_threat_actors USING GIN (techniques)"
    execute "CREATE INDEX mitre_threat_actors_aliases_idx ON mitre_threat_actors USING GIN (aliases)"

    # Coverage snapshots (historical coverage tracking)
    create table(:mitre_coverage_snapshots, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)
      add :snapshot_date, :date, null: false
      add :coverage_data, :map, null: false  # Full coverage heatmap data
      add :total_techniques, :integer
      add :covered_techniques, :integer
      add :coverage_percentage, :float
      add :notes, :text

      timestamps()
    end

    create index(:mitre_coverage_snapshots, [:organization_id, :snapshot_date])
    create index(:mitre_coverage_snapshots, [:snapshot_date])

    # Navigator layers (saved heatmaps/views)
    create table(:mitre_navigator_layers, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text
      add :layer_data, :map, null: false  # ATT&CK Navigator JSON format
      add :layer_type, :string  # "coverage", "frequency", "custom"
      add :is_public, :boolean, default: false
      add :time_range_start, :utc_datetime_usec
      add :time_range_end, :utc_datetime_usec
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)
      add :created_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)

      timestamps()
    end

    create index(:mitre_navigator_layers, [:organization_id])
    create index(:mitre_navigator_layers, [:created_by_id])
    create index(:mitre_navigator_layers, [:layer_type])
    create index(:mitre_navigator_layers, [:is_public])
  end
end
