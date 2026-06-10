defmodule TamanduaServer.Repo.Migrations.CreateXdrEvents do
  use Ecto.Migration

  def change do
    # Create XDR sources table first (for foreign key reference)
    create_if_not_exists table(:xdr_sources, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :source_type, :string, null: false  # firewall, proxy, email, cloud, network, etc.
      add :vendor, :string  # Palo Alto, Fortinet, Zscaler, AWS, etc.
      add :enabled, :boolean, default: true, null: false
      add :config, :map, default: %{}  # Connection settings, credentials reference, etc.
      add :last_event_at, :utc_datetime_usec
      add :event_count, :bigint, default: 0
      add :error_count, :integer, default: 0
      add :last_error, :text
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps()
    end

    create_if_not_exists index(:xdr_sources, [:organization_id])
    create_if_not_exists index(:xdr_sources, [:source_type])
    create_if_not_exists index(:xdr_sources, [:enabled])
    create_if_not_exists unique_index(:xdr_sources, [:organization_id, :name])

    # Create XDR events table with normalized schema
    create_if_not_exists table(:xdr_events, primary_key: false) do
      add :id, :binary_id, primary_key: true

      # Timestamp fields
      add :timestamp, :utc_datetime_usec, null: false  # When the event occurred
      add :received_at, :utc_datetime_usec, null: false  # When Tamandua received it
      add :ingested_at, :utc_datetime_usec  # When it was processed

      # Source identification
      add :source_type, :string, null: false  # firewall, proxy, email, cloud, network
      add :source_name, :string  # Specific source name (e.g., "paloalto-fw-01")
      add :source_id, references(:xdr_sources, type: :binary_id, on_delete: :nilify_all)
      add :log_format, :string  # CEF, LEEF, JSON, Syslog, etc.

      # Normalized network fields (ECS-inspired)
      add :source_ip, :string
      add :source_port, :integer
      add :dest_ip, :string
      add :dest_port, :integer
      add :source_hostname, :string
      add :dest_hostname, :string
      add :network_direction, :string  # inbound, outbound, internal, external
      add :network_protocol, :string  # TCP, UDP, ICMP, etc.
      add :network_transport, :string  # HTTP, HTTPS, DNS, etc.

      # User/identity fields
      add :user_name, :string
      add :user_domain, :string
      add :user_email, :string
      add :source_user, :string  # For lateral movement tracking
      add :dest_user, :string

      # Action/outcome fields
      add :action, :string  # allow, deny, block, alert, quarantine, etc.
      add :outcome, :string  # success, failure, unknown
      add :event_category, :string  # network, authentication, file, process, etc.
      add :event_type, :string  # connection, login, download, etc.

      # Severity and risk
      add :severity, :string, default: "info"  # critical, high, medium, low, info
      add :risk_score, :float  # 0.0 to 1.0

      # URL/domain fields
      add :url, :text
      add :url_domain, :string
      add :url_path, :string
      add :dns_query, :string

      # File fields
      add :file_name, :string
      add :file_path, :text
      add :file_hash_sha256, :string
      add :file_hash_md5, :string
      add :file_size, :bigint

      # Email fields (for email security sources)
      add :email_subject, :string
      add :email_from, :string
      add :email_to, :text  # JSON array of recipients
      add :email_direction, :string  # inbound, outbound

      # Cloud-specific fields
      add :cloud_provider, :string  # aws, azure, gcp
      add :cloud_region, :string
      add :cloud_account_id, :string
      add :cloud_resource_id, :string
      add :cloud_service, :string  # S3, EC2, Lambda, etc.

      # Rule/signature fields
      add :rule_name, :string
      add :rule_id, :string
      add :signature_id, :string
      add :threat_name, :string
      add :threat_category, :string

      # MITRE ATT&CK mapping
      add :mitre_tactics, {:array, :string}, default: []
      add :mitre_techniques, {:array, :string}, default: []

      # Raw and enriched data
      add :raw_event, :text  # Original log line/event
      add :parsed_fields, :map, default: %{}  # Additional parsed fields
      add :enrichment, :map, default: %{}  # GeoIP, threat intel, etc.

      # Correlation fields
      add :correlation_id, :binary_id  # Groups related events
      # Note: No FK to events table - it's a TimescaleDB hypertable without unique constraints
      add :correlated_endpoint_event_id, :binary_id
      add :correlated_alert_id, references(:alerts, type: :binary_id, on_delete: :nilify_all)

      # Multi-tenancy
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)
    end

    # Performance indexes
    create_if_not_exists index(:xdr_events, [:timestamp])
    create_if_not_exists index(:xdr_events, [:organization_id, :timestamp])
    create_if_not_exists index(:xdr_events, [:source_type])
    create_if_not_exists index(:xdr_events, [:source_id])
    create_if_not_exists index(:xdr_events, [:source_ip])
    create_if_not_exists index(:xdr_events, [:dest_ip])
    create_if_not_exists index(:xdr_events, [:user_name])
    create_if_not_exists index(:xdr_events, [:severity])
    create_if_not_exists index(:xdr_events, [:action])
    create_if_not_exists index(:xdr_events, [:correlation_id])
    create_if_not_exists index(:xdr_events, [:correlated_endpoint_event_id])

    # Composite indexes for common queries
    create_if_not_exists index(:xdr_events, [:organization_id, :source_type, :timestamp])
    create_if_not_exists index(:xdr_events, [:organization_id, :severity, :timestamp])
    create_if_not_exists index(:xdr_events, [:source_ip, :dest_ip, :timestamp])

    # Create XDR correlation rules table
    create_if_not_exists table(:xdr_correlation_rules, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text
      add :enabled, :boolean, default: true, null: false
      add :priority, :integer, default: 50

      # Rule definition
      add :source_types, {:array, :string}, default: []  # Which sources this rule applies to
      add :conditions, :map, null: false  # JSON conditions for matching
      add :time_window_seconds, :integer, default: 300  # Time window for correlation
      add :threshold, :integer, default: 1  # Minimum matches to trigger

      # Alert generation
      add :alert_severity, :string, default: "medium"
      add :alert_title_template, :string
      add :mitre_tactics, {:array, :string}, default: []
      add :mitre_techniques, {:array, :string}, default: []

      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps()
    end

    create_if_not_exists index(:xdr_correlation_rules, [:organization_id])
    create_if_not_exists index(:xdr_correlation_rules, [:enabled])
  end
end
