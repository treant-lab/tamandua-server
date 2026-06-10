defmodule TamanduaServer.Repo.Migrations.CreateGeofencing do
  use Ecto.Migration

  def change do
    # Geographic regions definition
    create table(:geo_regions, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false

      add :name, :string, null: false
      add :description, :text
      add :region_type, :string, null: false
      # country, city, polygon, radius

      # Region definition (varies by type)
      # For country: {"country_code": "US"}
      # For city: {"country": "US", "city": "New York", "state": "NY"}
      # For polygon: {"coordinates": [[lat, lon], [lat, lon], ...]}
      # For radius: {"center": {"lat": 40.7, "lon": -74.0}, "radius_km": 50}
      add :definition, :map, null: false

      # Color for map display
      add :color, :string, default: "#3B82F6"

      # Whether this region is active
      add :is_active, :boolean, default: true

      timestamps()
    end

    create index(:geo_regions, [:organization_id])
    create index(:geo_regions, [:region_type])
    create index(:geo_regions, [:is_active])

    # Geofencing rules - define expected and restricted regions for agents
    create table(:geofencing_rules, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false

      add :name, :string, null: false
      add :description, :text

      # Scope - which agents does this apply to?
      # "all", "group", "agent", "tag"
      add :scope_type, :string, null: false
      add :scope_ids, {:array, :binary_id}, default: []
      # For tag-based: store tag names
      add :scope_tags, {:array, :string}, default: []

      # Expected regions (agent should normally be in these)
      add :expected_region_ids, {:array, :binary_id}, default: []

      # Allowed regions (agent can travel to these without alert)
      add :allowed_region_ids, {:array, :binary_id}, default: []

      # Restricted regions (block access from these)
      add :restricted_region_ids, {:array, :binary_id}, default: []

      # Alert on unexpected location?
      add :alert_on_unexpected, :boolean, default: true
      add :alert_severity, :string, default: "medium"

      # Auto-isolate from restricted regions?
      add :auto_isolate_restricted, :boolean, default: false

      # Priority (higher priority rules override lower)
      add :priority, :integer, default: 0

      add :is_enabled, :boolean, default: true

      timestamps()
    end

    create index(:geofencing_rules, [:organization_id])
    create index(:geofencing_rules, [:scope_type])
    create index(:geofencing_rules, [:is_enabled])
    create index(:geofencing_rules, [:priority])

    # Agent location history
    create table(:agent_locations, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all), null: false

      # IP-based location
      add :ip_address, :string
      add :country_code, :string
      add :country_name, :string
      add :city, :string
      add :region, :string
      # State/province
      add :latitude, :float
      add :longitude, :float
      add :accuracy_km, :float

      # Location source: geoip, gps, wifi, manual
      add :source, :string, default: "geoip"

      # VPN detection
      add :is_vpn, :boolean, default: false
      add :vpn_provider, :string
      add :is_proxy, :boolean, default: false
      add :is_tor, :boolean, default: false

      # True location if VPN detected (best guess)
      add :true_location, :map

      # Matched regions
      add :matched_region_ids, {:array, :binary_id}, default: []

      # Was this location expected?
      add :is_expected, :boolean
      add :is_restricted, :boolean

      # Additional metadata from GeoIP provider
      add :metadata, :map, default: %{}

      # When this location was detected
      add :detected_at, :utc_datetime_usec, null: false

      timestamps()
    end

    create index(:agent_locations, [:organization_id])
    create index(:agent_locations, [:agent_id])
    create index(:agent_locations, [:detected_at])
    create index(:agent_locations, [:country_code])
    create index(:agent_locations, [:is_expected])
    create index(:agent_locations, [:is_restricted])
    create index(:agent_locations, [:is_vpn])

    # Composite index for time-based queries
    create index(:agent_locations, [:agent_id, :detected_at])

    # Travel notifications and approvals
    create table(:geo_travel_requests, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all), null: false

      # Requested by (user traveling with laptop)
      add :requested_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)

      # Travel details
      add :destination_region_id, references(:geo_regions, type: :binary_id, on_delete: :nilify_all)
      add :destination_country, :string
      add :destination_city, :string
      add :reason, :text

      # Time window
      add :start_date, :date, null: false
      add :end_date, :date, null: false

      # Approval workflow
      # pending, approved, denied, expired
      add :status, :string, default: "pending"
      add :approved_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :approved_at, :utc_datetime_usec
      add :denied_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :denied_at, :utc_datetime_usec
      add :denial_reason, :text

      # Auto-approved by policy?
      add :auto_approved, :boolean, default: false

      timestamps()
    end

    create index(:geo_travel_requests, [:organization_id])
    create index(:geo_travel_requests, [:agent_id])
    create index(:geo_travel_requests, [:status])
    create index(:geo_travel_requests, [:start_date, :end_date])

    # Geo-based policy enforcement
    create table(:geo_policies, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false

      add :name, :string, null: false
      add :description, :text

      # Which regions does this apply to?
      add :region_ids, {:array, :binary_id}, default: []
      # Apply to unexpected locations?
      add :apply_to_unexpected, :boolean, default: false
      # Apply to restricted locations?
      add :apply_to_restricted, :boolean, default: true

      # Policy actions
      # Require MFA for access from this region?
      add :require_mfa, :boolean, default: false

      # Disable sensitive features?
      add :disable_features, {:array, :string}, default: []
      # Example: ["file_download", "screen_capture", "remote_shell"]

      # Restrict file operations?
      add :restrict_file_downloads, :boolean, default: false
      add :restrict_file_uploads, :boolean, default: false

      # Enhanced monitoring?
      add :enhanced_monitoring, :boolean, default: false
      # Increase telemetry frequency, capture more events

      # Auto-isolate?
      add :auto_isolate, :boolean, default: false

      # Alert security team?
      add :send_alert, :boolean, default: true
      add :alert_severity, :string, default: "high"

      # Priority (higher overrides lower)
      add :priority, :integer, default: 0

      add :is_enabled, :boolean, default: true

      timestamps()
    end

    create index(:geo_policies, [:organization_id])
    create index(:geo_policies, [:is_enabled])
    create index(:geo_policies, [:priority])

    # Policy enforcement log
    create table(:geo_policy_enforcements, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false
      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all), null: false
      add :policy_id, references(:geo_policies, type: :binary_id, on_delete: :nilify_all)
      add :location_id,
        references(:agent_locations, type: :binary_id, on_delete: :nilify_all)

      # What was enforced?
      add :enforcement_type, :string, null: false
      # mfa_required, feature_disabled, file_restricted, isolated, alert_sent

      add :enforcement_details, :map, default: %{}

      # Result
      add :success, :boolean, default: true
      add :error_message, :text

      add :enforced_at, :utc_datetime_usec, null: false

      timestamps()
    end

    create index(:geo_policy_enforcements, [:organization_id])
    create index(:geo_policy_enforcements, [:agent_id])
    create index(:geo_policy_enforcements, [:policy_id])
    create index(:geo_policy_enforcements, [:enforced_at])

    # VPN whitelist
    create table(:vpn_whitelist, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false

      add :name, :string, null: false
      # Corporate VPN, AWS VPN, etc.
      add :vpn_provider, :string

      # IP ranges (CIDR notation)
      add :ip_ranges, {:array, :string}, default: []

      # ASN numbers
      add :asn_numbers, {:array, :integer}, default: []

      # Domains
      add :domains, {:array, :string}, default: []

      # Trust level: trusted (don't flag), monitored (flag but allow), blocked
      add :trust_level, :string, default: "trusted"

      add :notes, :text

      add :is_active, :boolean, default: true

      timestamps()
    end

    create index(:vpn_whitelist, [:organization_id])
    create index(:vpn_whitelist, [:trust_level])
    create index(:vpn_whitelist, [:is_active])

    # Add geofencing fields to agents table
    alter table(:agents) do
      add :current_location_id, references(:agent_locations, type: :binary_id, on_delete: :nilify_all)
      add :geofencing_enabled, :boolean, default: true
      # Geo-based policy restrictions currently active
      add :geo_restrictions, :map, default: %{}
    end

    create index(:agents, [:current_location_id])
  end
end
