defmodule TamanduaServer.Repo.Migrations.CreateMispIntegrationTables do
  @moduledoc """
  Creates tables for MISP (Malware Information Sharing Platform) integration.

  Tables:
  - misp_instances: MISP server configurations
  - misp_events: Synced events from MISP
  - threat_actors: Known threat actors from MISP galaxies
  - ioc_scores: IOC scoring history
  - ioc_sightings: Sighting records for IOCs
  """

  use Ecto.Migration

  def change do
    # =========================================================================
    # MISP Instances
    # =========================================================================
    create_if_not_exists table(:misp_instances, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :url, :string, null: false
      add :api_key, :string, null: false
      add :verify_ssl, :boolean, default: true
      add :enabled, :boolean, default: true

      # MISP organization config
      add :misp_org_id, :string
      add :misp_org_name, :string

      # Sharing configuration
      add :sharing_group_ids, {:array, :integer}, default: []
      add :pull_enabled, :boolean, default: true
      add :push_enabled, :boolean, default: false

      # Trust and priority
      add :trust_level, :integer, default: 50  # 0-100, higher = more trusted
      add :priority, :integer, default: 0      # Sync order priority

      # Sync configuration
      add :sync_interval_hours, :integer, default: 4
      add :last_sync, :utc_datetime
      add :last_sync_status, :string
      add :last_sync_error, :text
      add :events_synced, :integer, default: 0
      add :iocs_imported, :integer, default: 0

      # Filter configuration
      add :tags_filter, {:array, :string}, default: []
      add :threat_level_filter, {:array, :integer}, default: []
      add :published_only, :boolean, default: true

      # Capabilities (detected from server)
      add :server_version, :string
      add :can_publish, :boolean, default: false
      add :can_sighting, :boolean, default: false

      # Tenant
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps()
    end

    create_if_not_exists unique_index(:misp_instances, [:url, :organization_id], name: :misp_instances_url_org_index)
    create_if_not_exists unique_index(:misp_instances, [:name, :organization_id], name: :misp_instances_name_org_index)
    create_if_not_exists index(:misp_instances, [:organization_id])
    create_if_not_exists index(:misp_instances, [:enabled])

    # =========================================================================
    # MISP Events
    # =========================================================================
    create_if_not_exists table(:misp_events, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :misp_event_id, :string, null: false
      add :uuid, :string
      add :info, :text
      add :threat_level_id, :integer
      add :analysis, :integer
      add :date, :string
      add :published, :boolean, default: false

      # Organization info
      add :org_name, :string
      add :orgc_name, :string

      # Metadata
      add :tags, {:array, :string}, default: []
      add :galaxies, {:array, :map}, default: []
      add :attribute_count, :integer, default: 0
      add :tlp, :string, default: "AMBER"

      # Attribution
      add :threat_actor_name, :string
      add :campaign_name, :string
      add :malware_family, :string

      # Relationships
      add :misp_instance_id, references(:misp_instances, type: :binary_id, on_delete: :delete_all), null: false

      timestamps()
    end

    create_if_not_exists unique_index(:misp_events, [:misp_instance_id, :misp_event_id])
    create_if_not_exists index(:misp_events, [:misp_instance_id])
    create_if_not_exists index(:misp_events, [:uuid])
    create_if_not_exists index(:misp_events, [:threat_level_id])
    create_if_not_exists index(:misp_events, [:published])
    create_if_not_exists index(:misp_events, [:tlp])
    create_if_not_exists index(:misp_events, [:threat_actor_name])
    create_if_not_exists index(:misp_events, [:campaign_name])
    create_if_not_exists index(:misp_events, [:inserted_at])

    # GIN index for array search on tags
    execute "CREATE INDEX IF NOT EXISTS misp_events_tags_gin ON misp_events USING GIN (tags)",
            "DROP INDEX IF EXISTS misp_events_tags_gin"

    # =========================================================================
    # Threat Actors
    # =========================================================================
    create_if_not_exists table(:threat_actors, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text
      add :aliases, {:array, :string}, default: []

      # Classification
      add :motivation, :string  # financial, espionage, hacktivism, sabotage, unknown
      add :sophistication, :string  # novice, intermediate, advanced, expert
      add :resource_level, :string  # individual, small-group, organization, government

      # Attribution
      add :origin_country, :string
      add :target_countries, {:array, :string}, default: []
      add :target_sectors, {:array, :string}, default: []
      add :target_regions, {:array, :string}, default: []

      # MITRE ATT&CK
      add :ttps, {:array, :string}, default: []
      add :primary_tactics, {:array, :string}, default: []

      # Malware and tools
      add :known_malware, {:array, :string}, default: []
      add :known_tools, {:array, :string}, default: []

      # Activity timeline
      add :first_seen, :utc_datetime
      add :last_seen, :utc_datetime
      add :active, :boolean, default: true

      # Source tracking
      add :source, :string, default: "manual"
      add :misp_cluster_uuid, :string
      add :galaxy_type, :string
      add :confidence, :float, default: 0.7

      # External references
      add :external_refs, {:array, :map}, default: []
      add :metadata, :map, default: %{}

      # IOC count (denormalized for performance)
      add :ioc_count, :integer, default: 0

      # Relationships
      add :misp_instance_id, references(:misp_instances, type: :binary_id, on_delete: :nilify_all)
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps()
    end

    create_if_not_exists unique_index(:threat_actors, [:misp_cluster_uuid], where: "misp_cluster_uuid IS NOT NULL")
    create_if_not_exists index(:threat_actors, [:name])
    create_if_not_exists index(:threat_actors, [:motivation])
    create_if_not_exists index(:threat_actors, [:origin_country])
    create_if_not_exists index(:threat_actors, [:active])
    create_if_not_exists index(:threat_actors, [:misp_instance_id])
    create_if_not_exists index(:threat_actors, [:organization_id])
    create_if_not_exists index(:threat_actors, [:last_seen])

    # GIN indexes for array search
    execute "CREATE INDEX IF NOT EXISTS threat_actors_aliases_gin ON threat_actors USING GIN (aliases)",
            "DROP INDEX IF EXISTS threat_actors_aliases_gin"
    execute "CREATE INDEX IF NOT EXISTS threat_actors_ttps_gin ON threat_actors USING GIN (ttps)",
            "DROP INDEX IF EXISTS threat_actors_ttps_gin"
    execute "CREATE INDEX IF NOT EXISTS threat_actors_target_sectors_gin ON threat_actors USING GIN (target_sectors)",
            "DROP INDEX IF EXISTS threat_actors_target_sectors_gin"

    # =========================================================================
    # Campaigns
    # =========================================================================
    create_if_not_exists table(:threat_campaigns, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text
      add :aliases, {:array, :string}, default: []

      # Status
      add :status, :string, default: "active"  # active, dormant, concluded

      # Timeline
      add :first_seen, :utc_datetime
      add :last_seen, :utc_datetime
      add :start_date, :date
      add :end_date, :date

      # Targeting
      add :target_countries, {:array, :string}, default: []
      add :target_sectors, {:array, :string}, default: []
      add :target_regions, {:array, :string}, default: []

      # MITRE ATT&CK
      add :ttps, {:array, :string}, default: []

      # Attribution
      add :confidence, :float, default: 0.5

      # Source tracking
      add :source, :string, default: "manual"
      add :misp_cluster_uuid, :string
      add :external_refs, {:array, :map}, default: []
      add :metadata, :map, default: %{}

      # IOC count
      add :ioc_count, :integer, default: 0

      # Relationships
      add :threat_actor_id, references(:threat_actors, type: :binary_id, on_delete: :nilify_all)
      add :misp_instance_id, references(:misp_instances, type: :binary_id, on_delete: :nilify_all)
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps()
    end

    create_if_not_exists unique_index(:threat_campaigns, [:misp_cluster_uuid], where: "misp_cluster_uuid IS NOT NULL")
    create_if_not_exists index(:threat_campaigns, [:name])
    create_if_not_exists index(:threat_campaigns, [:status])
    create_if_not_exists index(:threat_campaigns, [:threat_actor_id])
    create_if_not_exists index(:threat_campaigns, [:misp_instance_id])
    create_if_not_exists index(:threat_campaigns, [:organization_id])
    create_if_not_exists index(:threat_campaigns, [:last_seen])

    # =========================================================================
    # IOC Sightings
    # =========================================================================
    create_if_not_exists table(:ioc_sightings, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :ioc_id, references(:iocs, type: :binary_id, on_delete: :delete_all), null: false

      # Sighting info
      add :sighting_type, :integer, default: 0  # 0=sighting, 1=false_positive, 2=expiration
      add :source, :string, null: false
      add :timestamp, :utc_datetime, null: false

      # Optional details
      add :agent_id, references(:agents, type: :binary_id, on_delete: :nilify_all)
      add :alert_id, references(:alerts, type: :binary_id, on_delete: :nilify_all)
      add :analyst_id, references(:users, type: :binary_id, on_delete: :nilify_all)

      # Metadata
      add :reason, :text
      add :confidence, :float, default: 1.0
      add :metadata, :map, default: %{}

      # MISP sync
      add :misp_synced, :boolean, default: false
      add :misp_sighting_id, :string

      timestamps()
    end

    create_if_not_exists index(:ioc_sightings, [:ioc_id])
    create_if_not_exists index(:ioc_sightings, [:sighting_type])
    create_if_not_exists index(:ioc_sightings, [:source])
    create_if_not_exists index(:ioc_sightings, [:timestamp])
    create_if_not_exists index(:ioc_sightings, [:agent_id])
    create_if_not_exists index(:ioc_sightings, [:alert_id])
    create_if_not_exists index(:ioc_sightings, [:analyst_id])
    create_if_not_exists index(:ioc_sightings, [:misp_synced])

    # =========================================================================
    # IOC Scores History
    # =========================================================================
    create_if_not_exists table(:ioc_score_history, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :ioc_id, references(:iocs, type: :binary_id, on_delete: :delete_all), null: false

      # Score at this point in time
      add :score, :integer, null: false
      add :base_score, :integer
      add :age_factor, :float
      add :sighting_boost, :integer
      add :fp_penalty, :integer
      add :correlation_boost, :integer
      add :misp_boost, :integer

      # Stats at this point
      add :sighting_count, :integer, default: 0
      add :fp_count, :integer, default: 0

      # Reason for score change
      add :reason, :string  # recalculation, sighting, false_positive, manual

      add :calculated_at, :utc_datetime, null: false

      timestamps()
    end

    create_if_not_exists index(:ioc_score_history, [:ioc_id])
    create_if_not_exists index(:ioc_score_history, [:score])
    create_if_not_exists index(:ioc_score_history, [:calculated_at])

    # =========================================================================
    # Add MISP fields to IOCs table
    # Use raw SQL with IF NOT EXISTS to avoid duplicate column errors
    # =========================================================================
    execute """
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='iocs' AND column_name='misp_uuid') THEN
        ALTER TABLE iocs ADD COLUMN misp_uuid varchar(255);
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='iocs' AND column_name='misp_event_id') THEN
        ALTER TABLE iocs ADD COLUMN misp_event_id varchar(255);
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='iocs' AND column_name='misp_instance_id') THEN
        ALTER TABLE iocs ADD COLUMN misp_instance_id uuid REFERENCES misp_instances(id) ON DELETE SET NULL;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='iocs' AND column_name='score') THEN
        ALTER TABLE iocs ADD COLUMN score integer DEFAULT 50;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='iocs' AND column_name='sighting_count') THEN
        ALTER TABLE iocs ADD COLUMN sighting_count integer DEFAULT 0;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='iocs' AND column_name='fp_count') THEN
        ALTER TABLE iocs ADD COLUMN fp_count integer DEFAULT 0;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='iocs' AND column_name='threat_actor_id') THEN
        ALTER TABLE iocs ADD COLUMN threat_actor_id uuid REFERENCES threat_actors(id) ON DELETE SET NULL;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='iocs' AND column_name='campaign_id') THEN
        ALTER TABLE iocs ADD COLUMN campaign_id uuid REFERENCES threat_campaigns(id) ON DELETE SET NULL;
      END IF;
    END $$;
    """, ""

    create_if_not_exists index(:iocs, [:misp_uuid])
    create_if_not_exists index(:iocs, [:misp_event_id])
    create_if_not_exists index(:iocs, [:misp_instance_id])
    create_if_not_exists index(:iocs, [:score])
    create_if_not_exists index(:iocs, [:threat_actor_id])
    create_if_not_exists index(:iocs, [:campaign_id])

    # =========================================================================
    # Published Alerts (alerts that were published to MISP)
    # =========================================================================
    create_if_not_exists table(:misp_published_alerts, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :alert_id, references(:alerts, type: :binary_id, on_delete: :delete_all), null: false
      add :misp_instance_id, references(:misp_instances, type: :binary_id, on_delete: :delete_all), null: false
      add :misp_event_id, :string, null: false
      add :misp_event_uuid, :string

      # Publication details
      add :published_at, :utc_datetime, null: false
      add :published_by, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :tlp, :string, default: "AMBER"
      add :sharing_group_id, :integer
      add :auto_publish, :boolean, default: false

      # Attributes published
      add :attributes_count, :integer, default: 0
      add :tags, {:array, :string}, default: []

      timestamps()
    end

    create_if_not_exists unique_index(:misp_published_alerts, [:alert_id, :misp_instance_id])
    create_if_not_exists index(:misp_published_alerts, [:alert_id])
    create_if_not_exists index(:misp_published_alerts, [:misp_instance_id])
    create_if_not_exists index(:misp_published_alerts, [:misp_event_id])
    create_if_not_exists index(:misp_published_alerts, [:published_at])
    create_if_not_exists index(:misp_published_alerts, [:published_by])
  end
end
