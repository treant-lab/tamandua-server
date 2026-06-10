defmodule TamanduaServer.Repo.Migrations.CreateSigmaRules do
  use Ecto.Migration

  def change do
    create table(:sigma_rules, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :title, :string
      add :description, :text
      add :author, :string
      add :level, :string, default: "medium"
      add :status, :string, default: "experimental"
      add :enabled, :boolean, default: true
      add :source, :text
      add :detection, :map, default: %{}
      add :logsource_category, :string
      add :logsource_product, :string
      add :logsource_service, :string
      add :mitre_tactics, {:array, :string}, default: []
      add :mitre_techniques, {:array, :string}, default: []
      add :references, {:array, :string}, default: []
      add :tags, {:array, :string}, default: []

      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps(type: :utc_datetime_usec)
    end

    create index(:sigma_rules, [:organization_id])
    create index(:sigma_rules, [:enabled])
    create index(:sigma_rules, [:level])
    create index(:sigma_rules, [:logsource_category])

    # GIN indexes for array searches
    execute "CREATE INDEX sigma_rules_mitre_tactics_idx ON sigma_rules USING GIN (mitre_tactics)"
    execute "CREATE INDEX sigma_rules_mitre_techniques_idx ON sigma_rules USING GIN (mitre_techniques)"
    execute "CREATE INDEX sigma_rules_tags_idx ON sigma_rules USING GIN (tags)"
  end
end
