defmodule TamanduaServer.Repo.Migrations.CreateStixObjectsAndTaxiiServers do
  use Ecto.Migration

  def change do
    # ── STIX Objects Table ───────────────────────────────────────────────
    create_if_not_exists table(:stix_objects, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :stix_id, :string, null: false  # STIX object ID (e.g., indicator--uuid)
      add :stix_type, :string, null: false  # indicator, malware, threat-actor, etc.
      add :spec_version, :string, default: "2.1"

      add :name, :string
      add :description, :text
      add :created, :utc_datetime
      add :modified, :utc_datetime

      # Indicator-specific fields
      add :pattern, :text  # STIX pattern
      add :pattern_type, :string  # stix, pcre, sigma, etc.
      add :indicator_types, {:array, :string}, default: []
      add :valid_from, :utc_datetime
      add :valid_until, :utc_datetime

      # Confidence and labels
      add :confidence, :integer, default: 50  # 0-100
      add :labels, {:array, :string}, default: []

      # Source tracking
      add :source_collection_id, :binary_id  # FK to taxii_collections
      add :source_server_id, :binary_id  # FK to taxii_servers
      add :created_by_ref, :string  # STIX identity reference

      # Full STIX object as JSON
      add :raw_data, :map, default: %{}

      # Tamandua-specific
      add :ioc_id, :binary_id  # FK to iocs table if converted
      add :enabled, :boolean, default: true
      add :last_seen_at, :utc_datetime

      timestamps()
    end

    # Unique constraint on STIX ID
    create_if_not_exists unique_index(:stix_objects, [:stix_id])

    # Index for type lookups
    create_if_not_exists index(:stix_objects, [:stix_type])

    # Index for pattern searches
    create_if_not_exists index(:stix_objects, [:pattern_type])

    # Index for source tracking
    create_if_not_exists index(:stix_objects, [:source_collection_id])
    create_if_not_exists index(:stix_objects, [:source_server_id])

    # Index for IOC correlation
    create_if_not_exists index(:stix_objects, [:ioc_id])

    # Index for time-based queries
    create_if_not_exists index(:stix_objects, [:created])
    create_if_not_exists index(:stix_objects, [:modified])

    # Composite index for type + enabled queries
    create_if_not_exists index(:stix_objects, [:stix_type, :enabled])

    # ── STIX Relationships Table ─────────────────────────────────────────
    create_if_not_exists table(:stix_relationships, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :stix_id, :string, null: false

      add :source_ref, :string, null: false  # STIX ID of source object
      add :target_ref, :string, null: false  # STIX ID of target object
      add :relationship_type, :string, null: false  # indicates, uses, etc.

      add :description, :text
      add :created, :utc_datetime
      add :modified, :utc_datetime

      # Source tracking
      add :source_collection_id, :binary_id
      add :source_server_id, :binary_id

      # Full STIX relationship as JSON
      add :raw_data, :map, default: %{}

      timestamps()
    end

    create_if_not_exists unique_index(:stix_relationships, [:stix_id])
    create_if_not_exists index(:stix_relationships, [:source_ref])
    create_if_not_exists index(:stix_relationships, [:target_ref])
    create_if_not_exists index(:stix_relationships, [:relationship_type])

    # Composite index for finding relationships
    create_if_not_exists index(:stix_relationships, [:source_ref, :relationship_type])
    create_if_not_exists index(:stix_relationships, [:target_ref, :relationship_type])

    # ── TAXII Servers Table ──────────────────────────────────────────────
    create_if_not_exists table(:taxii_servers, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :url, :string, null: false
      add :description, :text

      # Authentication (encrypted in production)
      add :auth_type, :string  # basic, api_key, bearer
      add :auth_config, :map, default: %{}  # encrypted credentials

      # Discovery info
      add :api_roots, {:array, :string}, default: []
      add :default_api_root, :string

      # Sync configuration
      add :poll_enabled, :boolean, default: true
      add :poll_interval_minutes, :integer, default: 60
      add :auto_import, :boolean, default: true

      # Status tracking
      add :last_poll_at, :utc_datetime
      add :last_success_at, :utc_datetime
      add :last_error, :text
      add :status, :string, default: "pending"  # pending, ok, error

      # Stats
      add :total_polls, :integer, default: 0
      add :total_objects_imported, :integer, default: 0
      add :total_errors, :integer, default: 0

      add :enabled, :boolean, default: true

      timestamps()
    end

    create_if_not_exists unique_index(:taxii_servers, [:url])
    create_if_not_exists index(:taxii_servers, [:enabled])
    create_if_not_exists index(:taxii_servers, [:status])

    # ── TAXII Collections Table ──────────────────────────────────────────
    create_if_not_exists table(:taxii_collections, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :taxii_server_id, :binary_id, null: false  # FK to taxii_servers
      add :collection_id, :string, null: false  # TAXII collection UUID
      add :api_root, :string, null: false

      add :title, :string
      add :description, :text
      add :can_read, :boolean, default: false
      add :can_write, :boolean, default: false
      add :media_types, {:array, :string}, default: []

      # Sync configuration
      add :poll_enabled, :boolean, default: true
      add :filter_types, {:array, :string}, default: []  # STIX types to import
      add :last_added_after, :utc_datetime  # For incremental polling

      # Status
      add :last_poll_at, :utc_datetime
      add :objects_imported, :integer, default: 0
      add :status, :string, default: "pending"
      add :last_error, :text

      add :enabled, :boolean, default: true

      timestamps()
    end

    # Unique constraint on server + collection
    create_if_not_exists unique_index(:taxii_collections, [:taxii_server_id, :collection_id])
    create_if_not_exists index(:taxii_collections, [:taxii_server_id])
    create_if_not_exists index(:taxii_collections, [:enabled])

    # Add foreign key constraints
    alter table(:taxii_collections) do
      modify :taxii_server_id, references(:taxii_servers, type: :binary_id, on_delete: :delete_all)
    end

    alter table(:stix_objects) do
      modify :source_collection_id, references(:taxii_collections, type: :binary_id, on_delete: :nilify_all)
      modify :source_server_id, references(:taxii_servers, type: :binary_id, on_delete: :nilify_all)
    end

    alter table(:stix_relationships) do
      modify :source_collection_id, references(:taxii_collections, type: :binary_id, on_delete: :nilify_all)
      modify :source_server_id, references(:taxii_servers, type: :binary_id, on_delete: :nilify_all)
    end
  end
end
