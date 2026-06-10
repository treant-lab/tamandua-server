defmodule TamanduaServer.Repo.Migrations.CreateFimTables do
  use Ecto.Migration

  def change do
    # FIM Baselines table
    create table(:fim_baselines, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :agent_id, :string, null: false
      add :path, :string, null: false
      add :hash, :string, null: false
      add :size, :bigint, null: false
      add :permissions, :string
      add :owner, :string
      add :group, :string
      add :mtime, :bigint
      add :ctime, :bigint
      add :attributes, {:array, :string}, default: []
      add :category, :string, default: "custom"
      add :known_good, :boolean, default: false
      add :baseline_version, :integer, default: 1
      add :compliance_frameworks, {:array, :string}, default: []

      timestamps()
    end

    create unique_index(:fim_baselines, [:agent_id, :path])
    create index(:fim_baselines, [:agent_id])
    create index(:fim_baselines, [:category])
    create index(:fim_baselines, [:known_good])

    # FIM Baseline History table
    create table(:fim_baseline_history, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :baseline_id, references(:fim_baselines, type: :binary_id, on_delete: :delete_all)
      add :agent_id, :string, null: false
      add :path, :string, null: false
      add :hash, :string, null: false
      add :size, :bigint
      add :permissions, :string
      add :owner, :string
      add :group, :string
      add :mtime, :bigint
      add :ctime, :bigint
      add :attributes, {:array, :string}, default: []
      add :baseline_version, :integer
      add :archived_at, :utc_datetime

      timestamps()
    end

    create index(:fim_baseline_history, [:baseline_id])
    create index(:fim_baseline_history, [:agent_id])
    create index(:fim_baseline_history, [:archived_at])

    # FIM Changes table
    create table(:fim_changes, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :agent_id, :string, null: false
      add :path, :string, null: false
      add :change_type, :string, null: false
      add :previous_hash, :string
      add :current_hash, :string
      add :previous_size, :bigint
      add :current_size, :bigint
      add :previous_permissions, :string
      add :current_permissions, :string
      add :previous_owner, :string
      add :current_owner, :string
      add :category, :string
      add :compliance_impact, {:array, :string}, default: []
      add :whitelisted, :boolean, default: false
      add :whitelist_reason, :string
      add :modifier_pid, :integer
      add :modifier_process, :string
      add :entropy, :float
      add :severity, :string, null: false
      add :detected_at, :utc_datetime, null: false
      add :reviewed, :boolean, default: false
      add :reviewed_by, :string
      add :reviewed_at, :utc_datetime
      add :remediated, :boolean, default: false
      add :remediation_action, :string
      add :remediated_at, :utc_datetime

      timestamps()
    end

    create index(:fim_changes, [:agent_id])
    create index(:fim_changes, [:path])
    create index(:fim_changes, [:change_type])
    create index(:fim_changes, [:severity])
    create index(:fim_changes, [:detected_at])
    create index(:fim_changes, [:whitelisted])
    create index(:fim_changes, [:reviewed])
    create index(:fim_changes, [:remediated])
    create index(:fim_changes, [:category])

    # FIM Whitelist Rules table
    create table(:fim_whitelist_rules, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :agent_id, :string, null: false
      add :pattern, :string, null: false
      add :allowed_changes, {:array, :string}, default: []
      add :reason, :string, null: false
      add :expires, :bigint, default: 0
      add :added_by, :string, null: false
      add :enabled, :boolean, default: true

      timestamps()
    end

    create index(:fim_whitelist_rules, [:agent_id])
    create index(:fim_whitelist_rules, [:pattern])
    create index(:fim_whitelist_rules, [:enabled])
    create index(:fim_whitelist_rules, [:expires])
  end
end
