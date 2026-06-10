defmodule TamanduaServer.Repo.Migrations.CreateNetworkDevices do
  @moduledoc """
  Creates the network_devices table for the distributed network discovery system.

  Stores all discovered network devices with classification, fingerprinting data,
  vulnerability findings, and management status. Supports the SentinelOne Ranger-style
  device inventory with multi-agent sighting merging.
  """

  use Ecto.Migration

  def change do
    # ------------------------------------------------------------------
    # network_devices: discovered network devices from agent scanning
    # ------------------------------------------------------------------
    create_if_not_exists table(:network_devices, primary_key: false) do
      add :id, :binary_id, primary_key: true

      # Device identity
      add :mac_address, :string
      add :ip_addresses, {:array, :string}, default: []
      add :hostnames, {:array, :string}, default: []

      # OS fingerprinting
      add :os_family, :string
      add :os_version, :string
      add :os_confidence, :float, default: 0.0
      add :os_evidence, {:array, :string}, default: []

      # Classification
      add :device_type, :string, default: "unknown"
      add :device_category, :string, default: "unknown"
      add :device_state, :string, default: "new"

      # Network information
      add :open_ports, {:array, :map}, default: []
      add :services, {:array, :map}, default: []
      add :vendor, :string
      add :subnet, :string

      # Discovery metadata
      add :first_seen, :utc_datetime_usec
      add :last_seen, :utc_datetime_usec
      add :discovery_method, :string
      add :discovered_by_agents, {:array, :string}, default: []

      # Management status
      add :managed, :boolean, default: false
      add :agent_id, references(:agents, type: :binary_id, on_delete: :nilify_all), null: true
      add :whitelisted, :boolean, default: false
      add :whitelist_reason, :string

      # Fingerprint data
      add :ttl, :integer
      add :tcp_window_size, :integer

      # Risk assessment
      add :risk_score, :integer, default: 0
      add :risk_factors, {:array, :string}, default: []

      # State transition history (JSONB array)
      add :state_history, {:array, :map}, default: []

      # Multi-tenancy
      add :organization_id,
          references(:organizations, type: :binary_id, on_delete: :delete_all),
          null: true

      timestamps()
    end

    # Indexes for efficient querying
    create_if_not_exists index(:network_devices, [:mac_address])
    create_if_not_exists index(:network_devices, [:subnet])
    create_if_not_exists index(:network_devices, [:device_type])
    create_if_not_exists index(:network_devices, [:device_category])
    create_if_not_exists index(:network_devices, [:device_state])
    create_if_not_exists index(:network_devices, [:managed])
    create_if_not_exists index(:network_devices, [:organization_id])
    create_if_not_exists index(:network_devices, [:last_seen])
    create_if_not_exists index(:network_devices, [:risk_score])
    create_if_not_exists index(:network_devices, [:vendor])
    create_if_not_exists index(:network_devices, [:agent_id])

    # GIN index for IP address array searching
    execute(
      "CREATE INDEX IF NOT EXISTS network_devices_ip_addresses_idx ON network_devices USING GIN (ip_addresses)",
      "DROP INDEX IF EXISTS network_devices_ip_addresses_idx"
    )

    # GIN index for hostname array searching
    execute(
      "CREATE INDEX IF NOT EXISTS network_devices_hostnames_idx ON network_devices USING GIN (hostnames)",
      "DROP INDEX IF EXISTS network_devices_hostnames_idx"
    )

    # ------------------------------------------------------------------
    # network_device_vuln_findings: vulnerability findings for devices
    # ------------------------------------------------------------------
    create_if_not_exists table(:network_device_vuln_findings, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :device_id, references(:network_devices, type: :binary_id, on_delete: :delete_all),
          null: false

      add :device_ip, :string
      add :device_mac, :string
      add :device_type, :string

      # Finding details
      add :protocol, :string, null: false
      add :port, :integer
      add :check_type, :string, null: false
      add :title, :string, null: false
      add :description, :text
      add :severity, :string, null: false
      add :cvss_score, :float
      add :cve_ids, {:array, :string}, default: []
      add :evidence, :text
      add :remediation, :text
      add :service_version, :string

      # Scan metadata
      add :scan_id, :binary_id
      add :status, :string, default: "open"

      # Multi-tenancy
      add :organization_id,
          references(:organizations, type: :binary_id, on_delete: :delete_all),
          null: true

      timestamps()
    end

    create_if_not_exists index(:network_device_vuln_findings, [:device_id])
    create_if_not_exists index(:network_device_vuln_findings, [:severity])
    create_if_not_exists index(:network_device_vuln_findings, [:protocol])
    create_if_not_exists index(:network_device_vuln_findings, [:status])
    create_if_not_exists index(:network_device_vuln_findings, [:scan_id])
    create_if_not_exists index(:network_device_vuln_findings, [:check_type])
    create_if_not_exists index(:network_device_vuln_findings, [:organization_id])

    # ------------------------------------------------------------------
    # network_scan_policies: per-subnet scan configuration
    # ------------------------------------------------------------------
    create_if_not_exists table(:network_scan_policies, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :subnet, :string, null: false
      add :name, :string
      add :description, :text

      add :scan_enabled, :boolean, default: true
      add :scan_type, :string, default: "passive_only"
      add :scan_interval_secs, :integer, default: 300
      add :excluded_ips, {:array, :string}, default: []
      add :excluded_ports, {:array, :integer}, default: []
      add :min_agent_count, :integer, default: 1
      add :scan_window_start, :integer
      add :scan_window_end, :integer
      add :max_scan_rate_pps, :integer, default: 50
      add :active_scan_ports, {:array, :integer}, default: []
      add :snmp_communities, {:array, :string}, default: []
      add :priority, :integer, default: 0

      # Multi-tenancy
      add :organization_id,
          references(:organizations, type: :binary_id, on_delete: :delete_all),
          null: true

      timestamps()
    end

    create_if_not_exists unique_index(:network_scan_policies, [:subnet, :organization_id],
             name: :network_scan_policies_subnet_org_idx)
    create_if_not_exists index(:network_scan_policies, [:organization_id])

    # ------------------------------------------------------------------
    # network_rogue_detections: rogue device detection records
    # ------------------------------------------------------------------
    create_if_not_exists table(:network_rogue_detections, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :device_id, references(:network_devices, type: :binary_id, on_delete: :nilify_all),
          null: true

      add :mac_address, :string
      add :ip_addresses, {:array, :string}, default: []
      add :device_type, :string
      add :vendor, :string
      add :subnet, :string

      add :violation_type, :string, null: false
      add :violation_details, :text
      add :policy_name, :string
      add :risk_score, :integer, default: 0
      add :action_taken, :string, default: "alert"
      add :isolated_by_agents, {:array, :string}, default: []

      add :detected_at, :utc_datetime_usec
      add :resolved_at, :utc_datetime_usec
      add :resolved_by, :string
      add :status, :string, default: "active"

      # Multi-tenancy
      add :organization_id,
          references(:organizations, type: :binary_id, on_delete: :delete_all),
          null: true

      timestamps()
    end

    create_if_not_exists index(:network_rogue_detections, [:status])
    create_if_not_exists index(:network_rogue_detections, [:subnet])
    create_if_not_exists index(:network_rogue_detections, [:violation_type])
    create_if_not_exists index(:network_rogue_detections, [:detected_at])
    create_if_not_exists index(:network_rogue_detections, [:device_id])
    create_if_not_exists index(:network_rogue_detections, [:organization_id])
  end
end
