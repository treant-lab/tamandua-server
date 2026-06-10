defmodule TamanduaServer.Repo.Migrations.CreateThreatIntelCache do
  use Ecto.Migration

  def change do
    create_if_not_exists table(:threat_intel_cache, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :ioc_type, :string, null: false  # hash, ip, domain, url
      add :ioc_value, :string, null: false
      add :feed_source, :string, null: false  # malwarebazaar, urlhaus, threatfox, alienvault_otx
      add :threat_type, :string  # malware, botnet_cc, phishing, c2, ransomware
      add :malware_family, :string
      add :confidence, :float, default: 0.5
      add :tags, {:array, :string}, default: []
      add :first_seen, :utc_datetime
      add :last_seen, :utc_datetime
      add :raw_data, :map, default: %{}

      timestamps()
    end

    # Unique constraint on (ioc_type, ioc_value, feed_source) to allow same IOC from different feeds
    create_if_not_exists unique_index(:threat_intel_cache, [:ioc_type, :ioc_value, :feed_source])

    # Fast lookup by ioc_value
    create_if_not_exists index(:threat_intel_cache, [:ioc_value])

    # Index for feed-specific queries
    create_if_not_exists index(:threat_intel_cache, [:feed_source])

    # Index for finding high-confidence IOCs
    create_if_not_exists index(:threat_intel_cache, [:confidence])

    # Index for time-based queries
    create_if_not_exists index(:threat_intel_cache, [:last_seen])

    # Composite index for type + value lookups (most common query pattern)
    create_if_not_exists index(:threat_intel_cache, [:ioc_type, :ioc_value])

    # Index for malware family queries
    create_if_not_exists index(:threat_intel_cache, [:malware_family])
  end
end
