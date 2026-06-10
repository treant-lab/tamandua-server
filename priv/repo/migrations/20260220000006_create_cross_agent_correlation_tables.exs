defmodule TamanduaServer.Repo.Migrations.CreateCrossAgentCorrelationTables do
  use Ecto.Migration

  def change do
    # Alert correlations: store relationships between alerts
    create table(:alert_correlations, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :alert_id, references(:alerts, on_delete: :delete_all, type: :binary_id), null: false
      add :related_alert_id, references(:alerts, on_delete: :delete_all, type: :binary_id), null: false

      add :correlation_type, :string, null: false  # temporal, ioc, technique, network, user, pattern
      add :confidence, :float, default: 0.0        # 0.0 - 1.0
      add :similarity_score, :float, default: 0.0  # 0.0 - 1.0

      # Detailed correlation metadata
      add :metadata, :jsonb, default: fragment("'{}'::jsonb")
      # Example metadata:
      # {
      #   "shared_techniques": ["T1055", "T1059"],
      #   "shared_iocs": ["192.168.1.1", "malware.exe"],
      #   "time_delta_seconds": 120,
      #   "network_proximity": "same_subnet",
      #   "user_overlap": ["admin", "user1"]
      # }

      add :organization_id, references(:organizations, type: :binary_id), null: false

      timestamps()
    end

    create index(:alert_correlations, [:alert_id])
    create index(:alert_correlations, [:related_alert_id])
    create index(:alert_correlations, [:correlation_type])
    create index(:alert_correlations, [:confidence])
    create index(:alert_correlations, [:organization_id])
    create unique_index(:alert_correlations, [:alert_id, :related_alert_id, :correlation_type],
                        name: :unique_alert_correlation)

    # Attack campaigns: group correlated alerts into campaigns
    create table(:attack_campaigns, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text
      add :severity, :string, default: "medium"     # critical, high, medium, low
      add :status, :string, default: "active"       # active, contained, resolved

      add :agent_count, :integer, default: 0
      add :alert_count, :integer, default: 0
      add :affected_users, {:array, :string}, default: []
      add :affected_hosts, {:array, :string}, default: []

      add :start_time, :utc_datetime_usec
      add :end_time, :utc_datetime_usec
      add :last_activity, :utc_datetime_usec

      add :mitre_tactics, {:array, :string}, default: []
      add :mitre_techniques, {:array, :string}, default: []

      # Campaign pattern metadata
      add :attack_pattern, :string  # lateral_movement, ransomware, exfiltration, etc.
      add :confidence_score, :float, default: 0.0

      # Network topology data
      add :network_graph, :jsonb, default: fragment("'{}'::jsonb")
      # {
      #   "nodes": [{"id": "agent-1", "ip": "192.168.1.10", "type": "endpoint"}],
      #   "edges": [{"source": "agent-1", "target": "agent-2", "type": "network"}]
      # }

      # Detailed campaign metadata
      add :metadata, :jsonb, default: fragment("'{}'::jsonb")

      add :organization_id, references(:organizations, type: :binary_id), null: false
      add :created_by_id, references(:users, type: :binary_id)
      add :assigned_to_id, references(:users, type: :binary_id)

      timestamps()
    end

    create index(:attack_campaigns, [:organization_id])
    create index(:attack_campaigns, [:status])
    create index(:attack_campaigns, [:severity])
    create index(:attack_campaigns, [:start_time])
    create index(:attack_campaigns, [:attack_pattern])
    create index(:attack_campaigns, [:assigned_to_id])

    # Campaign alerts: many-to-many relationship
    create table(:campaign_alerts, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :campaign_id, references(:attack_campaigns, on_delete: :delete_all, type: :binary_id), null: false
      add :alert_id, references(:alerts, on_delete: :delete_all, type: :binary_id), null: false

      add :role, :string  # initial, pivot, lateral, impact, etc.
      add :sequence_order, :integer
      add :added_at, :utc_datetime_usec

      timestamps()
    end

    create index(:campaign_alerts, [:campaign_id])
    create index(:campaign_alerts, [:alert_id])
    create unique_index(:campaign_alerts, [:campaign_id, :alert_id])

    # Add campaign_id to alerts for quick lookup (if not already present)
    execute "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS campaign_id uuid REFERENCES attack_campaigns(id)", ""
    execute "CREATE INDEX IF NOT EXISTS alerts_campaign_id_index ON alerts(campaign_id)", ""

    # Correlation cache: ETS-backed cache for fast lookups
    # This table stores pre-computed correlation patterns
    create table(:correlation_cache, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :cache_key, :string, null: false
      add :cache_data, :jsonb, null: false
      add :expires_at, :utc_datetime_usec
      add :organization_id, references(:organizations, type: :binary_id)

      timestamps()
    end

    create unique_index(:correlation_cache, [:cache_key, :organization_id])
    create index(:correlation_cache, [:expires_at])

    # Deduplication window config per technique
    create table(:dedup_windows, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :mitre_technique, :string, null: false
      add :window_seconds, :integer, default: 300
      add :noise_level, :string, default: "normal"  # low, normal, high
      add :organization_id, references(:organizations, type: :binary_id)

      timestamps()
    end

    create unique_index(:dedup_windows, [:mitre_technique, :organization_id])
    create index(:dedup_windows, [:organization_id])
  end
end
