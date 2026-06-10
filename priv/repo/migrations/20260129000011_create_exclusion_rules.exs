defmodule TamanduaServer.Repo.Migrations.CreateExclusionRules do
  use Ecto.Migration

  def change do
    create_if_not_exists table(:exclusion_rules, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text
      add :enabled, :boolean, default: true, null: false

      # Rule type: whitelist, suppress, tune
      add :rule_type, :string, null: false

      # Match criteria (JSONB for flexible matching)
      add :criteria, :map, default: %{}

      # Specific pattern matchers
      add :hash_patterns, {:array, :string}, default: []
      add :path_patterns, {:array, :string}, default: []
      add :cmdline_patterns, {:array, :string}, default: []
      add :ip_patterns, {:array, :string}, default: []
      add :domain_patterns, {:array, :string}, default: []
      add :rule_name_patterns, {:array, :string}, default: []

      # Source filters
      add :source_agent_ids, {:array, :binary_id}, default: []
      add :source_hostnames, {:array, :string}, default: []

      # Time-based suppression
      add :time_based, :boolean, default: false
      add :active_start, :time
      add :active_end, :time
      add :active_days, {:array, :integer}, default: []

      # Expiration
      add :expires_at, :utc_datetime

      # Severity adjustment (for tune rules)
      add :adjust_severity, :string

      # Statistics
      add :match_count, :integer, default: 0
      add :last_matched_at, :utc_datetime

      # Relations
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)
      add :created_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)

      timestamps()
    end

    create_if_not_exists index(:exclusion_rules, [:organization_id])
    create_if_not_exists index(:exclusion_rules, [:rule_type])
    create_if_not_exists index(:exclusion_rules, [:enabled])
    create_if_not_exists index(:exclusion_rules, [:expires_at])
  end
end
