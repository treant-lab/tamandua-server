defmodule TamanduaServer.Repo.Migrations.CreateInsiderThreatTables do
  use Ecto.Migration

  def up do
    # Peer groups table
    create table(:insider_threat_peer_groups, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text
      add :group_type, :string, null: false
      add :baseline, :jsonb, default: "{}"
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false

      timestamps(type: :utc_datetime_usec)
    end

    create index(:insider_threat_peer_groups, [:organization_id])
    create unique_index(:insider_threat_peer_groups, [:name, :organization_id])

    # Peer group members table
    create table(:insider_threat_peer_group_members, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :peer_group_id,
          references(:insider_threat_peer_groups, type: :binary_id, on_delete: :delete_all),
          null: false

      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false

      timestamps(type: :utc_datetime_usec)
    end

    create index(:insider_threat_peer_group_members, [:peer_group_id])
    create index(:insider_threat_peer_group_members, [:user_id])
    create unique_index(:insider_threat_peer_group_members, [:peer_group_id, :user_id])

    # Insider threat alerts table
    create table(:insider_threat_alerts, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false

      add :organization_id,
          references(:organizations, type: :binary_id, on_delete: :delete_all),
          null: false

      add :risk_score, :float, null: false
      add :severity, :string, null: false
      add :indicators, {:array, :jsonb}, default: []
      add :risk_breakdown, :jsonb, default: "{}"
      add :user_metrics, :jsonb, default: "{}"
      add :trend, :string
      add :status, :string, default: "open"
      add :requires_investigation, :boolean, default: false
      add :investigation_notes, :text
      add :resolution_notes, :text
      add :resolved_at, :utc_datetime_usec
      add :false_positive, :boolean, default: false
      add :suppressed, :boolean, default: false
      add :investigation_id, :binary_id

      add :investigated_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :resolved_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)

      timestamps(type: :utc_datetime_usec)
    end

    create index(:insider_threat_alerts, [:user_id])
    create index(:insider_threat_alerts, [:organization_id])
    create index(:insider_threat_alerts, [:status])
    create index(:insider_threat_alerts, [:severity])
    create index(:insider_threat_alerts, [:risk_score])
    create index(:insider_threat_alerts, [:inserted_at])
    create index(:insider_threat_alerts, [:requires_investigation])
    create index(:insider_threat_alerts, [:investigation_id])

    # Composite index for common queries
    create index(:insider_threat_alerts, [:organization_id, :status, :inserted_at])
    create index(:insider_threat_alerts, [:user_id, :status])

    # Insider threat investigations table
    create table(:insider_threat_investigations, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :title, :string, null: false
      add :description, :text

      add :subject_user_id, references(:users, type: :binary_id, on_delete: :delete_all),
        null: false

      add :organization_id,
          references(:organizations, type: :binary_id, on_delete: :delete_all),
          null: false

      add :status, :string, default: "open"
      add :priority, :string, default: "medium"
      add :findings, :text
      add :evidence, {:array, :jsonb}, default: []
      add :timeline, {:array, :jsonb}, default: []
      add :investigation_started_at, :utc_datetime_usec
      add :investigation_completed_at, :utc_datetime_usec
      add :outcome, :text
      add :action_taken, :text

      add :lead_investigator_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :assigned_to_id, references(:users, type: :binary_id, on_delete: :nilify_all)

      timestamps(type: :utc_datetime_usec)
    end

    create index(:insider_threat_investigations, [:subject_user_id])
    create index(:insider_threat_investigations, [:organization_id])
    create index(:insider_threat_investigations, [:status])
    create index(:insider_threat_investigations, [:priority])
    create index(:insider_threat_investigations, [:lead_investigator_id])
    create index(:insider_threat_investigations, [:assigned_to_id])
    create index(:insider_threat_investigations, [:inserted_at])

    # Composite indexes
    create index(:insider_threat_investigations, [:organization_id, :status])
    create index(:insider_threat_investigations, [:subject_user_id, :status])

    # Note: investigation_id index was already created above

    # Add user_id to events table if not exists (for insider threat detection)
    # This is a soft check - if the column exists, this will be a no-op in most migrations
    execute("""
      ALTER TABLE events
      ADD COLUMN IF NOT EXISTS user_id uuid
      REFERENCES users(id) ON DELETE SET NULL
    """)

    execute "CREATE INDEX IF NOT EXISTS events_user_id_index ON events(user_id)", ""
    execute "CREATE INDEX IF NOT EXISTS events_user_id_event_type_index ON events(user_id, event_type)", ""

    # Only create index if inserted_at column exists
    execute """
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'events' AND column_name = 'inserted_at') THEN
        CREATE INDEX IF NOT EXISTS events_user_id_inserted_at_index ON events(user_id, inserted_at);
      END IF;
    END $$;
    """, ""
  end

  def down do
    drop_if_exists index(:events, [:user_id, :inserted_at])
    drop_if_exists index(:events, [:user_id, :event_type])
    drop_if_exists index(:events, [:user_id])

    execute("""
      ALTER TABLE events
      DROP COLUMN IF EXISTS user_id
    """)

    drop table(:insider_threat_investigations)
    drop table(:insider_threat_alerts)
    drop table(:insider_threat_peer_group_members)
    drop table(:insider_threat_peer_groups)
  end
end
