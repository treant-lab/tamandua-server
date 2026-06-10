defmodule TamanduaServer.Repo.Migrations.CreateAssets do
  use Ecto.Migration

  def change do
    create_if_not_exists table(:assets, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :agent_id, :binary_id
      add :hostname, :string
      add :fqdn, :string
      add :os_type, :string
      add :os_version, :string
      add :os_build, :string
      add :architecture, :string

      # Network info
      add :ip_addresses, {:array, :string}, default: []
      add :mac_addresses, {:array, :string}, default: []
      add :domain, :string

      # Timestamps for tracking
      add :last_seen, :utc_datetime
      add :first_seen, :utc_datetime

      # Hardware info
      add :cpu_model, :string
      add :cpu_cores, :integer
      add :memory_gb, :float
      add :disk_gb, :float
      add :is_virtual, :boolean
      add :hypervisor, :string

      # Risk & security
      add :risk_score, :integer, default: 0
      add :criticality, :string, default: "medium"
      add :security_posture, :map, default: %{}
      add :compliance_status, :map, default: %{}

      # Software inventory
      add :installed_software, {:array, :map}, default: []
      add :running_services, {:array, :map}, default: []
      add :open_ports, {:array, :map}, default: []

      # Vulnerabilities
      add :vulnerabilities, {:array, :map}, default: []
      add :vulnerability_count, :integer, default: 0
      add :critical_vuln_count, :integer, default: 0

      # Tags and classification
      add :tags, {:array, :string}, default: []
      add :business_unit, :string
      add :owner, :string
      add :environment, :string
      add :asset_type, :string

      # Cloud metadata
      add :cloud_provider, :string
      add :cloud_region, :string
      add :cloud_instance_type, :string
      add :cloud_tags, :map, default: %{}
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists index(:assets, [:hostname])
    create_if_not_exists index(:assets, [:agent_id])
    create_if_not_exists index(:assets, [:risk_score])
    create_if_not_exists index(:assets, [:criticality])
    create_if_not_exists index(:assets, [:environment])
    create_if_not_exists index(:assets, [:organization_id])
  end
end
