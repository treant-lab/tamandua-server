defmodule TamanduaServer.Repo.Migrations.CreateYaraRules do
  use Ecto.Migration

  def change do
    create table(:yara_rules, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text
      add :author, :string
      add :source, :text, null: false  # The actual YARA rule content
      add :enabled, :boolean, default: true

      # Classification
      add :category, :string  # e.g., "malware", "ransomware", "miner", "rat"
      add :severity, :string, default: "medium"
      add :tags, {:array, :string}, default: []

      # MITRE ATT&CK
      add :mitre_tactics, {:array, :string}, default: []
      add :mitre_techniques, {:array, :string}, default: []

      # Context
      add :malware_family, :string
      add :threat_actor, :string

      # References
      add :references, {:array, :string}, default: []

      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:yara_rules, [:name, :organization_id])
    create index(:yara_rules, [:organization_id])
    create index(:yara_rules, [:enabled])
    create index(:yara_rules, [:category])
    create index(:yara_rules, [:malware_family])

    # GIN indexes for array fields
    execute "CREATE INDEX yara_rules_tags_idx ON yara_rules USING GIN (tags)"
    execute "CREATE INDEX yara_rules_mitre_tactics_idx ON yara_rules USING GIN (mitre_tactics)"
    execute "CREATE INDEX yara_rules_mitre_techniques_idx ON yara_rules USING GIN (mitre_techniques)"
  end
end
