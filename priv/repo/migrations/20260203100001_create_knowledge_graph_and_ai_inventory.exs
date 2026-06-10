defmodule TamanduaServer.Repo.Migrations.CreateKnowledgeGraphAndAIInventory do
  use Ecto.Migration

  def change do
    # ================================================================
    # Knowledge Graph Snapshots
    # Periodic snapshots of the in-memory graph for durability.
    # ================================================================
    create_if_not_exists table(:knowledge_graph_snapshots, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :node_count, :integer, null: false, default: 0
      add :edge_count, :integer, null: false, default: 0
      add :snapshot_data, :map, null: false, default: %{}

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists index(:knowledge_graph_snapshots, [:inserted_at])

    # ================================================================
    # AI Inventory - persisted AI component inventory
    # ================================================================
    create_if_not_exists table(:ai_inventory, primary_key: false) do
      add :id, :string, primary_key: true, size: 64
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all)
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      add :name, :string, null: false
      add :component_type, :string, null: false
      add :version, :string
      add :install_path, :text
      add :risk_score, :integer, null: false, default: 0
      add :risk_level, :string, null: false, default: "low"
      add :policy_status, :string, null: false, default: "unknown"
      add :is_shadow, :boolean, null: false, default: false

      # Full component data as JSONB
      add :data, :map, default: %{}

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists index(:ai_inventory, [:agent_id])
    create_if_not_exists index(:ai_inventory, [:organization_id])
    create_if_not_exists index(:ai_inventory, [:component_type])
    create_if_not_exists index(:ai_inventory, [:is_shadow])
    create_if_not_exists index(:ai_inventory, [:risk_level])
    create_if_not_exists index(:ai_inventory, [:policy_status])
    create_if_not_exists index(:ai_inventory, [:name])

    # Composite index for dashboard queries
    create_if_not_exists index(:ai_inventory, [:organization_id, :component_type])
    create_if_not_exists index(:ai_inventory, [:organization_id, :is_shadow])

    # ================================================================
    # XDR Events Warm Tier (for retention promotion)
    # Same schema as xdr_events but for older data.
    # ================================================================
    create_if_not_exists table(:xdr_events_warm, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :agent_id, :binary_id
      add :organization_id, :binary_id
      add :event_type, :string, null: false
      add :severity, :string
      add :payload, :map, default: %{}
      add :timestamp, :utc_datetime_usec, null: false

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists index(:xdr_events_warm, [:agent_id])
    create_if_not_exists index(:xdr_events_warm, [:event_type])
    create_if_not_exists index(:xdr_events_warm, [:timestamp])
    create_if_not_exists index(:xdr_events_warm, [:severity])

    # ================================================================
    # XDR Events Cold Tier (archive data)
    # ================================================================
    create_if_not_exists table(:xdr_events_cold, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :agent_id, :binary_id
      add :organization_id, :binary_id
      add :event_type, :string, null: false
      add :severity, :string
      add :payload, :map, default: %{}
      add :timestamp, :utc_datetime_usec, null: false

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists index(:xdr_events_cold, [:timestamp])
    create_if_not_exists index(:xdr_events_cold, [:agent_id])

    # ================================================================
    # Partial indexes on xdr_events for optimized common queries
    # ================================================================
    execute """
    DO $$
    BEGIN
      -- Partial index for high severity events (most queried)
      IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'xdr_events_severity_high_critical_idx') THEN
        BEGIN
          CREATE INDEX xdr_events_severity_high_critical_idx ON xdr_events (timestamp DESC)
            WHERE severity IN ('high', 'critical');
        EXCEPTION WHEN others THEN
          NULL;
        END;
      END IF;

      -- Partial index for process events (most common type)
      IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'xdr_events_process_events_idx') THEN
        BEGIN
          CREATE INDEX xdr_events_process_events_idx ON xdr_events (organization_id, timestamp DESC)
            WHERE event_type IN ('process_create', 'process_terminate');
        EXCEPTION WHEN others THEN
          NULL;
        END;
      END IF;

      -- Partial index for network events
      IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'xdr_events_network_events_idx') THEN
        BEGIN
          CREATE INDEX xdr_events_network_events_idx ON xdr_events (organization_id, timestamp DESC)
            WHERE event_type IN ('network_connect', 'network_listen', 'network_close');
        EXCEPTION WHEN others THEN
          NULL;
        END;
      END IF;

      -- BRIN index for timestamp-based range scans (very efficient for time-series)
      IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'xdr_events_timestamp_brin_idx') THEN
        BEGIN
          CREATE INDEX xdr_events_timestamp_brin_idx ON xdr_events USING BRIN (timestamp)
            WITH (pages_per_range = 32);
        EXCEPTION WHEN others THEN
          NULL;
        END;
      END IF;
    END $$;
    """, """
    DO $$ BEGIN
      DROP INDEX IF EXISTS xdr_events_severity_high_critical_idx;
      DROP INDEX IF EXISTS xdr_events_process_events_idx;
      DROP INDEX IF EXISTS xdr_events_network_events_idx;
      DROP INDEX IF EXISTS xdr_events_timestamp_brin_idx;
    EXCEPTION WHEN others THEN
      NULL;
    END $$;
    """
  end
end
