defmodule TamanduaServer.Repo.Migrations.CreateMobileDevices do
  use Ecto.Migration

  def change do
    # Mobile Devices table
    create_if_not_exists table(:mobile_devices, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      # Device identification
      add :device_id, :string, null: false
      add :platform, :string, null: false  # ios, android
      add :model, :string
      add :manufacturer, :string
      add :os_version, :string
      add :agent_version, :string
      add :serial_number, :string

      # MDM Integration
      add :mdm_enrolled, :boolean, default: false
      add :mdm_provider, :string, default: "none"
      add :mdm_device_id, :string
      add :mdm_compliance_status, :string
      add :mdm_last_sync, :naive_datetime

      # Security Posture
      add :is_jailbroken, :boolean, default: false
      add :is_rooted, :boolean, default: false
      add :passcode_enabled, :boolean
      add :passcode_compliant, :boolean
      add :encryption_enabled, :boolean
      add :biometric_enabled, :boolean
      add :developer_mode_enabled, :boolean, default: false
      add :usb_debugging_enabled, :boolean, default: false

      # Network
      add :ip_address, :string
      add :mac_address, :string
      add :wifi_mac_address, :string
      add :bluetooth_mac_address, :string
      add :imei, :string
      add :phone_number, :string

      # User assignment
      add :user_email, :string
      add :user_name, :string
      add :department, :string

      # Status
      add :status, :string, default: "active"
      add :last_seen_at, :naive_datetime
      add :enrolled_at, :naive_datetime
      add :last_location, :map

      # Risk scoring
      add :risk_score, :integer, default: 0
      add :risk_factors, {:array, :string}, default: []

      # Metadata
      add :tags, {:array, :string}, default: []
      add :custom_attributes, :map, default: %{}

      timestamps()
    end

    create_if_not_exists unique_index(:mobile_devices, [:organization_id, :device_id])
    create_if_not_exists index(:mobile_devices, [:organization_id])
    create_if_not_exists index(:mobile_devices, [:status])
    create_if_not_exists index(:mobile_devices, [:platform])
    create_if_not_exists index(:mobile_devices, [:risk_score])
    create_if_not_exists index(:mobile_devices, [:mdm_enrolled])
    create_if_not_exists index(:mobile_devices, [:last_seen_at])

    # Mobile App Inventory table
    create_if_not_exists table(:mobile_app_inventory, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :device_id, references(:mobile_devices, type: :binary_id, on_delete: :delete_all), null: false

      # App identification
      add :bundle_id, :string, null: false
      add :app_name, :string
      add :version, :string
      add :version_code, :integer

      # Security info
      add :signature_hash, :string
      add :installer, :string, default: "unknown"
      add :permissions, {:array, :string}, default: []
      add :dangerous_permissions, {:array, :string}, default: []

      # Risk assessment
      add :risk_level, :string, default: "low"
      add :risk_reasons, {:array, :string}, default: []
      add :is_system_app, :boolean, default: false
      add :is_debuggable, :boolean, default: false

      # Metadata
      add :developer, :string
      add :category, :string
      add :size_bytes, :bigint
      add :installed_at, :naive_datetime
      add :last_updated_at, :naive_datetime
      add :first_seen_at, :naive_datetime

      timestamps()
    end

    create_if_not_exists unique_index(:mobile_app_inventory, [:device_id, :bundle_id])
    create_if_not_exists index(:mobile_app_inventory, [:device_id])
    create_if_not_exists index(:mobile_app_inventory, [:risk_level])
    create_if_not_exists index(:mobile_app_inventory, [:installer])
    create_if_not_exists index(:mobile_app_inventory, [:bundle_id])

    # Mobile Events table
    create_if_not_exists table(:mobile_events, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :device_id, references(:mobile_devices, type: :binary_id, on_delete: :delete_all), null: false
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      add :event_type, :string, null: false
      add :severity, :string, null: false
      add :timestamp, :naive_datetime, null: false

      # Event details
      add :title, :string
      add :description, :text
      add :payload, :map, default: %{}

      # Detection info
      add :mitre_technique, :string
      add :mitre_tactic, :string
      add :rule_id, :string
      add :rule_name, :string

      # App context
      add :app_bundle_id, :string
      add :app_name, :string

      # Network context
      add :remote_address, :string
      add :remote_port, :integer
      add :domain, :string

      # Location context
      add :latitude, :float
      add :longitude, :float

      # Processing status
      add :processed, :boolean, default: false
      add :alerted, :boolean, default: false
      add :alert_id, :binary_id

      timestamps(updated_at: false)
    end

    create_if_not_exists index(:mobile_events, [:device_id])
    create_if_not_exists index(:mobile_events, [:organization_id])
    create_if_not_exists index(:mobile_events, [:event_type])
    create_if_not_exists index(:mobile_events, [:severity])
    create_if_not_exists index(:mobile_events, [:timestamp])
    create_if_not_exists index(:mobile_events, [:mitre_technique])
    create_if_not_exists index(:mobile_events, [:processed])
  end
end
