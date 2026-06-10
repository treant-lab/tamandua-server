defmodule TamanduaServer.Repo.Migrations.CreateIocs do
  use Ecto.Migration

  def change do
    create table(:iocs, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :type, :string, null: false
      add :value, :string, null: false
      add :description, :text
      add :confidence, :integer, default: 50
      add :severity, :string, default: "medium"
      add :source, :string
      add :source_ref, :string
      add :tags, {:array, :string}, default: []
      add :enabled, :boolean, default: true
      add :expires_at, :utc_datetime_usec

      # Context fields
      add :malware_family, :string
      add :threat_actor, :string
      add :campaign, :string

      # MITRE ATT&CK
      add :mitre_tactics, {:array, :string}, default: []
      add :mitre_techniques, {:array, :string}, default: []

      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:iocs, [:type, :value, :organization_id])
    create index(:iocs, [:organization_id])
    create index(:iocs, [:type])
    create index(:iocs, [:enabled])
    create index(:iocs, [:expires_at])
    create index(:iocs, [:malware_family])
    create index(:iocs, [:threat_actor])

    # Index for value lookups (hash, IP, domain searches)
    create index(:iocs, [:value])

    # GIN indexes
    execute "CREATE INDEX iocs_tags_idx ON iocs USING GIN (tags)"
    execute "CREATE INDEX iocs_mitre_tactics_idx ON iocs USING GIN (mitre_tactics)"
    execute "CREATE INDEX iocs_mitre_techniques_idx ON iocs USING GIN (mitre_techniques)"
  end
end
