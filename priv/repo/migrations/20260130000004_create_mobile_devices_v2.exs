defmodule TamanduaServer.Repo.Migrations.CreateMobileDevicesV2 do
  use Ecto.Migration

  def change do
    # =====================================================================
    # mobile_devices table
    # =====================================================================
    create table(:mobile_devices_v2, primary_key: false) do
      add :id, :binary_id, primary_key: true

      # Device identification
      add :device_id, :string, null: false
      add :device_name, :string
      add :platform, :string
      add :os_version, :string
      add :model, :string
      add :serial_number, :string

      # Owner
      add :owner_email, :string

      # MDM
      add :mdm_enrolled, :boolean, default: false
      add :mdm_provider, :string

      # Compliance
      add :compliance_status, :string, default: "unknown"

      # Security posture booleans
      add :encryption_enabled, :boolean, default: false
      add :jailbroken, :boolean, default: false
      add :passcode_set, :boolean, default: true

      # Timestamps
      add :last_seen_at, :utc_datetime_usec
      add :enrolled_at, :utc_datetime_usec

      # Organization reference
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:mobile_devices_v2, [:device_id])
    create index(:mobile_devices_v2, [:organization_id])
    create index(:mobile_devices_v2, [:platform])
    create index(:mobile_devices_v2, [:compliance_status])

    # =====================================================================
    # mdm_commands table
    # =====================================================================
    create table(:mdm_commands, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :device_id, references(:mobile_devices_v2, type: :binary_id, on_delete: :delete_all)

      add :command_type, :string
      add :status, :string, default: "pending"
      add :payload, :map, default: %{}
      add :result, :map, default: %{}

      add :sent_at, :utc_datetime_usec
      add :completed_at, :utc_datetime_usec
      add :requested_by, :string

      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps(type: :utc_datetime_usec)
    end

    create index(:mdm_commands, [:device_id])
    create index(:mdm_commands, [:organization_id])
    create index(:mdm_commands, [:status])
    create index(:mdm_commands, [:command_type])
  end
end
