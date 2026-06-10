defmodule TamanduaServer.Repo.Migrations.CreateMlRules do
  use Ecto.Migration

  def change do
    create table(:ml_rules, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :rule_id, :string, null: false
      add :rule_type, :string, null: false  # yara, sigma, ml_custom
      add :name, :string, null: false
      add :description, :text
      add :content, :text, null: false  # Rule definition (YARA/Sigma/JSON)
      add :severity, :string, default: "medium"  # low, medium, high, critical
      add :enabled, :boolean, default: false  # Disabled by default until approved
      add :approved, :boolean, default: false
      add :approved_at, :utc_datetime_usec
      add :approved_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)

      # Generation metadata
      add :hunt_campaign, :string  # Name of the hunt campaign
      add :hunt_session_id, references(:hunt_sessions, type: :binary_id, on_delete: :nilify_all)
      add :finding_count, :integer  # Number of findings used to generate rule
      add :confidence_score, :float  # 0-1 confidence in the rule

      # MITRE ATT&CK
      add :mitre_techniques, {:array, :string}, default: []
      add :tags, {:array, :string}, default: []

      # Optimization metrics
      add :precision, :float  # Precision score from optimization
      add :recall, :float  # Recall score from optimization
      add :f1_score, :float  # F1 score
      add :true_positives, :integer
      add :false_positives, :integer
      add :true_negatives, :integer
      add :false_negatives, :integer

      # Optimization parameters
      add :optimized_params, :map, default: %{}
      add :optimization_trials, :integer  # Number of Optuna trials
      add :validation_passed, :boolean, default: false

      # A/B testing
      add :ab_test_group, :string  # "control", "variant_a", "variant_b", etc.
      add :ab_test_start, :utc_datetime_usec
      add :ab_test_end, :utc_datetime_usec
      add :ab_test_metrics, :map, default: %{}

      # Version control
      add :version, :integer, default: 1
      add :parent_rule_id, references(:ml_rules, type: :binary_id, on_delete: :nilify_all)

      # Metadata
      add :metadata, :map, default: %{}

      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:ml_rules, [:rule_id, :organization_id])
    create index(:ml_rules, [:organization_id])
    create index(:ml_rules, [:hunt_session_id])
    create index(:ml_rules, [:rule_type])
    create index(:ml_rules, [:enabled])
    create index(:ml_rules, [:approved])
    create index(:ml_rules, [:severity])
    create index(:ml_rules, [:hunt_campaign])
    create index(:ml_rules, [:ab_test_group])
    create index(:ml_rules, [:validation_passed])

    # GIN indexes for array fields
    execute "CREATE INDEX ml_rules_mitre_techniques_idx ON ml_rules USING GIN (mitre_techniques)"
    execute "CREATE INDEX ml_rules_tags_idx ON ml_rules USING GIN (tags)"

    # Index for finding latest version of a rule
    create index(:ml_rules, [:parent_rule_id, :version])
  end
end
