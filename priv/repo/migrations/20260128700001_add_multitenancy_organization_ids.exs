defmodule TamanduaServer.Repo.Migrations.AddMultitenancyOrganizationIds do
  @moduledoc """
  Add organization_id to all tables that need tenant scoping for full multi-tenancy support.

  Tables being updated:
  - playbooks - Add organization_id for tenant-scoped playbooks
  - playbook_executions - Add organization_id for tenant-scoped execution history
  - events - Add organization_id for direct tenant filtering (in addition to via agent)
  - saved_queries - Add organization_id if not present
  - hunt_sessions - Add organization_id if not present
  - investigations - Add organization_id if not present

  Also creates:
  - api_keys table for programmatic access
  - tenant_rate_limits table for per-tenant rate limiting configuration
  """

  use Ecto.Migration

  def change do
    # =========================================================================
    # API Keys Table
    # =========================================================================
    create_if_not_exists table(:api_keys, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      # Key identification
      add :name, :string, null: false
      add :description, :string
      add :key_prefix, :string, null: false  # First 8 chars of key for identification (e.g., "tam_live_")
      add :key_hash, :string, null: false    # bcrypt hash of the full key

      # Permissions and scoping
      add :permissions, {:array, :string}, default: []  # List of permission slugs
      add :scope, :string, default: "full"  # "full", "read_only", "custom"

      # Rate limiting specific to this key
      add :rate_limit_per_minute, :integer, default: 1000
      add :rate_limit_per_hour, :integer, default: 50000

      # Lifecycle
      add :expires_at, :utc_datetime_usec
      add :last_used_at, :utc_datetime_usec
      add :is_active, :boolean, default: true, null: false

      # Audit
      add :created_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)

      # IP restrictions (optional)
      add :allowed_ips, {:array, :string}, default: []

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists index(:api_keys, [:organization_id])
    create_if_not_exists index(:api_keys, [:key_prefix])
    create_if_not_exists index(:api_keys, [:is_active])
    create_if_not_exists unique_index(:api_keys, [:key_hash])

    # =========================================================================
    # Tenant Rate Limits Table
    # =========================================================================
    create_if_not_exists table(:tenant_rate_limits, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      # Rate limit configuration based on license tier
      add :api_requests_per_minute, :integer, default: 1000
      add :api_requests_per_hour, :integer, default: 50000
      add :api_requests_per_day, :integer, default: 500000

      add :events_per_minute, :integer, default: 10000
      add :events_per_hour, :integer, default: 500000

      add :alert_webhooks_per_hour, :integer, default: 1000

      # Storage limits
      add :max_events_retained_days, :integer, default: 90
      add :max_storage_gb, :integer, default: 100

      # Feature limits
      add :max_concurrent_hunts, :integer, default: 5
      add :max_playbooks, :integer, default: 50
      add :max_sigma_rules, :integer, default: 500
      add :max_yara_rules, :integer, default: 200
      add :max_api_keys, :integer, default: 10

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists unique_index(:tenant_rate_limits, [:organization_id])

    # =========================================================================
    # Add organization_id to playbooks (columns added conditionally to avoid duplicates)
    # =========================================================================
    execute """
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='playbooks' AND column_name='organization_id') THEN
        ALTER TABLE playbooks ADD COLUMN organization_id uuid REFERENCES organizations(id) ON DELETE CASCADE;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='playbooks' AND column_name='require_approval') THEN
        ALTER TABLE playbooks ADD COLUMN require_approval boolean DEFAULT false;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='playbooks' AND column_name='approval_timeout_minutes') THEN
        ALTER TABLE playbooks ADD COLUMN approval_timeout_minutes integer DEFAULT 30;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='playbooks' AND column_name='tags') THEN
        ALTER TABLE playbooks ADD COLUMN tags varchar(255)[] DEFAULT '{}';
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='playbooks' AND column_name='severity_threshold') THEN
        ALTER TABLE playbooks ADD COLUMN severity_threshold varchar(255);
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='playbooks' AND column_name='execution_count') THEN
        ALTER TABLE playbooks ADD COLUMN execution_count integer DEFAULT 0;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='playbooks' AND column_name='success_count') THEN
        ALTER TABLE playbooks ADD COLUMN success_count integer DEFAULT 0;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='playbooks' AND column_name='last_executed_at') THEN
        ALTER TABLE playbooks ADD COLUMN last_executed_at timestamp;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='playbooks' AND column_name='created_by') THEN
        ALTER TABLE playbooks ADD COLUMN created_by uuid;
      END IF;
    END $$;
    """, ""

    execute """
    CREATE INDEX IF NOT EXISTS playbooks_organization_id_index ON playbooks(organization_id);
    """, ""

    # =========================================================================
    # Add organization_id to playbook_executions
    # =========================================================================
    execute """
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'playbook_executions' AND column_name = 'organization_id'
      ) THEN
        ALTER TABLE playbook_executions ADD COLUMN organization_id uuid REFERENCES organizations(id) ON DELETE CASCADE;
      END IF;
    END $$;
    """, """
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'playbook_executions' AND column_name = 'organization_id'
      ) THEN
        ALTER TABLE playbook_executions DROP COLUMN organization_id;
      END IF;
    END $$;
    """

    create_if_not_exists index(:playbook_executions, [:organization_id])

    # =========================================================================
    # Add organization_id to events (denormalized for direct tenant filtering)
    # This is in addition to the agent_id -> organization_id relationship
    # =========================================================================
    # Note: For TimescaleDB hypertables, we need to handle this carefully
    # We'll add the column but skip the FK constraint due to hypertable limitations
    execute """
    DO $$
    BEGIN
      -- Check if column already exists
      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'events' AND column_name = 'organization_id'
      ) THEN
        ALTER TABLE events ADD COLUMN organization_id UUID;
      END IF;
    END $$;
    """, """
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'events' AND column_name = 'organization_id'
      ) THEN
        ALTER TABLE events DROP COLUMN organization_id;
      END IF;
    END $$;
    """

    # Create index on events.organization_id
    execute """
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE tablename = 'events' AND indexname = 'events_organization_id_index'
      ) THEN
        CREATE INDEX events_organization_id_index ON events (organization_id);
      END IF;
    END $$;
    """, """
    DROP INDEX IF EXISTS events_organization_id_index;
    """

    # =========================================================================
    # Add organization_id to saved_queries if not present
    # =========================================================================
    execute """
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'saved_queries' AND column_name = 'organization_id'
      ) THEN
        ALTER TABLE saved_queries ADD COLUMN organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
        CREATE INDEX IF NOT EXISTS saved_queries_organization_id_index ON saved_queries (organization_id);
      END IF;
    END $$;
    """, """
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'saved_queries' AND column_name = 'organization_id'
      ) THEN
        DROP INDEX IF EXISTS saved_queries_organization_id_index;
        ALTER TABLE saved_queries DROP COLUMN organization_id;
      END IF;
    END $$;
    """

    # =========================================================================
    # Add organization_id to hunt_sessions if not present
    # =========================================================================
    execute """
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'hunt_sessions' AND column_name = 'organization_id'
      ) THEN
        ALTER TABLE hunt_sessions ADD COLUMN organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
        CREATE INDEX IF NOT EXISTS hunt_sessions_organization_id_index ON hunt_sessions (organization_id);
      END IF;
    END $$;
    """, """
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'hunt_sessions' AND column_name = 'organization_id'
      ) THEN
        DROP INDEX IF EXISTS hunt_sessions_organization_id_index;
        ALTER TABLE hunt_sessions DROP COLUMN organization_id;
      END IF;
    END $$;
    """

    # =========================================================================
    # Add organization_id to investigations if not present
    # =========================================================================
    execute """
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'investigations' AND column_name = 'organization_id'
      ) THEN
        ALTER TABLE investigations ADD COLUMN organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
        CREATE INDEX IF NOT EXISTS investigations_organization_id_index ON investigations (organization_id);
      END IF;
    END $$;
    """, """
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'investigations' AND column_name = 'organization_id'
      ) THEN
        DROP INDEX IF EXISTS investigations_organization_id_index;
        ALTER TABLE investigations DROP COLUMN organization_id;
      END IF;
    END $$;
    """

    # =========================================================================
    # Add organization_id to workflows if not present
    # =========================================================================
    execute """
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'workflows' AND column_name = 'organization_id'
      ) THEN
        ALTER TABLE workflows ADD COLUMN organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
        CREATE INDEX IF NOT EXISTS workflows_organization_id_index ON workflows (organization_id);
      END IF;
    END $$;
    """, """
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'workflows' AND column_name = 'organization_id'
      ) THEN
        DROP INDEX IF EXISTS workflows_organization_id_index;
        ALTER TABLE workflows DROP COLUMN organization_id;
      END IF;
    END $$;
    """

    # =========================================================================
    # Add organization_id to assets if not present
    # =========================================================================
    execute """
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'assets' AND column_name = 'organization_id'
      ) THEN
        ALTER TABLE assets ADD COLUMN organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
        CREATE INDEX IF NOT EXISTS assets_organization_id_index ON assets (organization_id);
      END IF;
    END $$;
    """, """
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'assets' AND column_name = 'organization_id'
      ) THEN
        DROP INDEX IF EXISTS assets_organization_id_index;
        ALTER TABLE assets DROP COLUMN organization_id;
      END IF;
    END $$;
    """

    # =========================================================================
    # Add organization_id to baselines if not present
    # =========================================================================
    execute """
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'baselines' AND column_name = 'organization_id'
      ) THEN
        ALTER TABLE baselines ADD COLUMN organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
        CREATE INDEX IF NOT EXISTS baselines_organization_id_index ON baselines (organization_id);
      END IF;
    END $$;
    """, """
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'baselines' AND column_name = 'organization_id'
      ) THEN
        DROP INDEX IF EXISTS baselines_organization_id_index;
        ALTER TABLE baselines DROP COLUMN organization_id;
      END IF;
    END $$;
    """

    # =========================================================================
    # Add organization_id to samples if not present
    # =========================================================================
    execute """
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'samples' AND column_name = 'organization_id'
      ) THEN
        ALTER TABLE samples ADD COLUMN organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
        CREATE INDEX IF NOT EXISTS samples_organization_id_index ON samples (organization_id);
      END IF;
    END $$;
    """, """
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'samples' AND column_name = 'organization_id'
      ) THEN
        DROP INDEX IF EXISTS samples_organization_id_index;
        ALTER TABLE samples DROP COLUMN organization_id;
      END IF;
    END $$;
    """

    # =========================================================================
    # Add organization_id to reports if not present
    # =========================================================================
    execute """
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'reports' AND column_name = 'organization_id'
      ) THEN
        ALTER TABLE reports ADD COLUMN organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
        CREATE INDEX IF NOT EXISTS reports_organization_id_index ON reports (organization_id);
      END IF;
    END $$;
    """, """
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'reports' AND column_name = 'organization_id'
      ) THEN
        DROP INDEX IF EXISTS reports_organization_id_index;
        ALTER TABLE reports DROP COLUMN organization_id;
      END IF;
    END $$;
    """

    # =========================================================================
    # Add organization_id to threat_intel_cache if not present
    # =========================================================================
    execute """
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'threat_intel_cache' AND column_name = 'organization_id'
      ) THEN
        ALTER TABLE threat_intel_cache ADD COLUMN organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
        CREATE INDEX IF NOT EXISTS threat_intel_cache_organization_id_index ON threat_intel_cache (organization_id);
      END IF;
    END $$;
    """, """
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'threat_intel_cache' AND column_name = 'organization_id'
      ) THEN
        DROP INDEX IF EXISTS threat_intel_cache_organization_id_index;
        ALTER TABLE threat_intel_cache DROP COLUMN organization_id;
      END IF;
    END $$;
    """

    # =========================================================================
    # Add organization_id to prevention_policies if not present
    # =========================================================================
    execute """
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'prevention_policies' AND column_name = 'organization_id'
      ) THEN
        ALTER TABLE prevention_policies ADD COLUMN organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
        CREATE INDEX IF NOT EXISTS prevention_policies_organization_id_index ON prevention_policies (organization_id);
      END IF;
    END $$;
    """, """
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'prevention_policies' AND column_name = 'organization_id'
      ) THEN
        DROP INDEX IF EXISTS prevention_policies_organization_id_index;
        ALTER TABLE prevention_policies DROP COLUMN organization_id;
      END IF;
    END $$;
    """

    # =========================================================================
    # Add organization_id to case_investigations if not present
    # =========================================================================
    execute """
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'case_investigations' AND column_name = 'organization_id'
      ) THEN
        ALTER TABLE case_investigations ADD COLUMN organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
        CREATE INDEX IF NOT EXISTS case_investigations_organization_id_index ON case_investigations (organization_id);
      END IF;
    END $$;
    """, """
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'case_investigations' AND column_name = 'organization_id'
      ) THEN
        DROP INDEX IF EXISTS case_investigations_organization_id_index;
        ALTER TABLE case_investigations DROP COLUMN organization_id;
      END IF;
    END $$;
    """
  end
end
