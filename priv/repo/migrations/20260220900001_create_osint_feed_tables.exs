defmodule TamanduaServer.Repo.Migrations.CreateOsintFeedTables do
  use Ecto.Migration

  def change do
    # Table for storing OSINT feed configurations
    create table(:osint_feeds, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :feed_type, :string, null: false  # alienvault_otx, abuse_ch, phishtank, etc.
      add :url, :text
      add :enabled, :boolean, default: true
      add :requires_api_key, :boolean, default: false
      add :api_key_configured, :boolean, default: false

      # Configuration
      add :sync_interval_seconds, :integer, default: 21600  # 6 hours
      add :priority, :string, default: "medium"  # low, medium, high, critical
      add :format, :string, default: "plain_text"  # plain_text, json, csv, xml
      add :ioc_types, {:array, :string}, default: []
      add :severity, :string, default: "medium"
      add :confidence, :float, default: 0.7

      # Custom feed options
      add :headers, :map, default: %{}
      add :parser_options, :map, default: %{}

      # State tracking
      add :last_sync, :utc_datetime_usec
      add :next_sync, :utc_datetime_usec
      add :sync_in_progress, :boolean, default: false
      add :last_error, :text
      add :error_count, :integer, default: 0

      # Statistics
      add :total_syncs, :integer, default: 0
      add :successful_syncs, :integer, default: 0
      add :failed_syncs, :integer, default: 0
      add :total_iocs_imported, :integer, default: 0
      add :last_import_count, :integer, default: 0
      add :average_sync_time_ms, :integer, default: 0

      # Health
      add :health_status, :string, default: "pending"  # pending, healthy, degraded, unhealthy, stale
      add :health_score, :integer, default: 100
      add :uptime_percentage, :float, default: 100.0
      add :last_health_check, :utc_datetime_usec

      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:osint_feeds, [:name, :organization_id])
    create index(:osint_feeds, [:organization_id])
    create index(:osint_feeds, [:feed_type])
    create index(:osint_feeds, [:enabled])
    create index(:osint_feeds, [:health_status])
    create index(:osint_feeds, [:next_sync])

    # Table for enriched IOC data
    create table(:enriched_iocs, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :ioc_id, references(:iocs, type: :binary_id, on_delete: :delete_all), null: false

      # Enrichment sources
      add :enriched_by, {:array, :string}, default: []
      add :enrichment_data, :map, default: %{}

      # AlienVault OTX enrichment
      add :otx_pulse_count, :integer
      add :otx_pulses, {:array, :map}, default: []
      add :otx_related_samples, {:array, :map}, default: []

      # GreyNoise enrichment
      add :greynoise_classification, :string  # noise, benign, malicious, unknown
      add :greynoise_actor, :string
      add :greynoise_tags, {:array, :string}, default: []
      add :greynoise_first_seen, :utc_datetime_usec
      add :greynoise_last_seen, :utc_datetime_usec
      add :greynoise_riot, :boolean, default: false

      # Shodan enrichment
      add :shodan_ports, {:array, :integer}, default: []
      add :shodan_services, {:array, :map}, default: []
      add :shodan_vulns, {:array, :string}, default: []
      add :shodan_org, :string
      add :shodan_asn, :string
      add :shodan_country, :string

      # Abuse.ch enrichment
      add :abusech_malware_family, :string
      add :abusech_confidence, :integer
      add :abusech_tags, {:array, :string}, default: []

      # VirusTotal enrichment
      add :vt_positives, :integer
      add :vt_total, :integer
      add :vt_permalink, :string
      add :vt_scan_date, :utc_datetime_usec

      # GeoIP enrichment
      add :geo_country, :string
      add :geo_country_code, :string
      add :geo_city, :string
      add :geo_latitude, :float
      add :geo_longitude, :float
      add :geo_asn, :string
      add :geo_organization, :string

      # WHOIS enrichment (for domains/IPs)
      add :whois_registrar, :string
      add :whois_creation_date, :utc_datetime_usec
      add :whois_expiration_date, :utc_datetime_usec
      add :whois_nameservers, {:array, :string}, default: []

      # DNS enrichment
      add :dns_a_records, {:array, :string}, default: []
      add :dns_mx_records, {:array, :string}, default: []
      add :dns_ns_records, {:array, :string}, default: []
      add :passive_dns, {:array, :map}, default: []

      # Timestamps
      add :last_enriched, :utc_datetime_usec
      add :enrichment_ttl, :utc_datetime_usec  # When to re-enrich

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:enriched_iocs, [:ioc_id])
    create index(:enriched_iocs, [:greynoise_classification])
    create index(:enriched_iocs, [:greynoise_riot])
    create index(:enriched_iocs, [:abusech_malware_family])
    create index(:enriched_iocs, [:geo_country_code])

    # GIN indexes for array fields
    execute "CREATE INDEX enriched_iocs_enriched_by_idx ON enriched_iocs USING GIN (enriched_by)"
    execute "CREATE INDEX enriched_iocs_greynoise_tags_idx ON enriched_iocs USING GIN (greynoise_tags)"
    execute "CREATE INDEX enriched_iocs_abusech_tags_idx ON enriched_iocs USING GIN (abusech_tags)"
    execute "CREATE INDEX enriched_iocs_shodan_ports_idx ON enriched_iocs USING GIN (shodan_ports)"
    execute "CREATE INDEX enriched_iocs_shodan_vulns_idx ON enriched_iocs USING GIN (shodan_vulns)"

    # Table for feed sync history (for audit and debugging)
    create table(:osint_feed_sync_history, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :feed_id, references(:osint_feeds, type: :binary_id, on_delete: :delete_all), null: false

      add :started_at, :utc_datetime_usec, null: false
      add :completed_at, :utc_datetime_usec
      add :duration_ms, :integer
      add :status, :string, null: false  # success, failure, partial
      add :error_message, :text

      add :iocs_fetched, :integer, default: 0
      add :iocs_added, :integer, default: 0
      add :iocs_updated, :integer, default: 0
      add :iocs_skipped, :integer, default: 0

      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create index(:osint_feed_sync_history, [:feed_id])
    create index(:osint_feed_sync_history, [:started_at])
    create index(:osint_feed_sync_history, [:status])

    # Index for failed syncs (partial index with NOW() not supported in PostgreSQL)
    execute """
    CREATE INDEX IF NOT EXISTS osint_feed_sync_history_failures_idx
    ON osint_feed_sync_history (feed_id, started_at)
    WHERE status = 'failure'
    """, ""
  end
end
