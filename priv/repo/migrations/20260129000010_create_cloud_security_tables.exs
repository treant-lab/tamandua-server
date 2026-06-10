defmodule TamanduaServer.Repo.Migrations.CreateCloudSecurityTables do
  use Ecto.Migration

  def change do
    # Cloud Accounts table
    create_if_not_exists table(:cloud_accounts, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :provider, :string, null: false  # aws, azure, gcp
      add :account_id, :string, null: false  # AWS Account ID, Azure Subscription, GCP Project
      add :external_id, :string  # For AWS STS AssumeRole
      add :alias, :string
      add :description, :text

      add :status, :string, default: "active"
      add :connection_status, :string, default: "pending"
      add :last_connection_error, :text

      add :credentials, :map, default: %{}

      add :regions, {:array, :string}, default: []

      add :scan_enabled, :boolean, default: true
      add :scan_schedule, :string, default: "0 */4 * * *"
      add :last_scan_at, :utc_datetime
      add :next_scan_at, :utc_datetime
      add :last_scan_status, :string
      add :last_scan_duration_seconds, :integer
      add :last_scan_resources_count, :integer
      add :last_scan_findings_count, :integer

      add :resources_count, :integer, default: 0
      add :findings_count, :integer, default: 0
      add :critical_findings_count, :integer, default: 0
      add :compliance_score, :float, default: 100.0

      add :organization_id, :binary_id
      add :created_by, :string
      add :tags, {:array, :string}, default: []

      timestamps()
    end

    create_if_not_exists unique_index(:cloud_accounts, [:provider, :account_id])
    create_if_not_exists index(:cloud_accounts, [:organization_id])
    create_if_not_exists index(:cloud_accounts, [:status])
    create_if_not_exists index(:cloud_accounts, [:connection_status])
    create_if_not_exists index(:cloud_accounts, [:provider])

    # Cloud Findings table
    create_if_not_exists table(:cloud_findings, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :provider, :string, null: false
      add :account_id, :string, null: false
      add :resource_id, :string, null: false
      add :resource_arn, :string
      add :resource_name, :string, null: false
      add :resource_type, :string, null: false
      add :region, :string

      add :category, :string, null: false
      add :severity, :string, null: false
      add :title, :string, null: false
      add :description, :text, null: false
      add :recommendation, :text

      add :compliance, {:array, :string}, default: []
      add :remediation_terraform, :text
      add :remediation_cloudformation, :text
      add :remediation_arm, :text

      add :status, :string, default: "open"
      add :status_reason, :text
      add :status_updated_at, :utc_datetime
      add :status_updated_by, :string

      add :exception_expiry, :utc_datetime
      add :exception_justification, :text

      add :first_seen_at, :utc_datetime
      add :last_seen_at, :utc_datetime
      add :resolved_at, :utc_datetime

      add :fingerprint, :string, null: false

      add :organization_id, :binary_id
      add :assigned_to, :string

      timestamps()
    end

    create_if_not_exists unique_index(:cloud_findings, [:fingerprint])
    create_if_not_exists index(:cloud_findings, [:provider, :account_id])
    create_if_not_exists index(:cloud_findings, [:status])
    create_if_not_exists index(:cloud_findings, [:severity])
    create_if_not_exists index(:cloud_findings, [:category])
    create_if_not_exists index(:cloud_findings, [:resource_type])
    create_if_not_exists index(:cloud_findings, [:organization_id])
    create_if_not_exists index(:cloud_findings, [:first_seen_at])
    create_if_not_exists index(:cloud_findings, [:last_seen_at])

    # Cloud Scans table (audit log of scans)
    create_if_not_exists table(:cloud_scans, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :account_id, references(:cloud_accounts, type: :binary_id, on_delete: :delete_all)
      add :provider, :string, null: false
      add :cloud_account_id, :string, null: false

      add :status, :string, null: false  # running, completed, failed, cancelled
      add :started_at, :utc_datetime, null: false
      add :completed_at, :utc_datetime
      add :duration_seconds, :integer

      add :resources_scanned, :integer, default: 0
      add :evaluations_run, :integer, default: 0
      add :passed, :integer, default: 0
      add :failed, :integer, default: 0

      add :error_message, :text
      add :triggered_by, :string  # "schedule", "manual", "api"
      add :triggered_by_user, :string

      add :scan_config, :map, default: %{}
      add :summary, :map, default: %{}

      timestamps()
    end

    create_if_not_exists index(:cloud_scans, [:account_id])
    create_if_not_exists index(:cloud_scans, [:provider])
    create_if_not_exists index(:cloud_scans, [:status])
    create_if_not_exists index(:cloud_scans, [:started_at])

    # Cloud Resources table (inventory)
    create_if_not_exists table(:cloud_resources, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :provider, :string, null: false
      add :account_id, :string, null: false
      add :resource_id, :string, null: false
      add :resource_arn, :string
      add :name, :string
      add :resource_type, :string, null: false
      add :region, :string

      add :status, :string
      add :tags, :map, default: %{}
      add :metadata, :map, default: %{}

      add :publicly_accessible, :boolean, default: false
      add :internet_facing, :boolean, default: false
      add :encrypted, :boolean

      add :findings_count, :integer, default: 0
      add :critical_findings, :integer, default: 0

      add :first_seen_at, :utc_datetime
      add :last_seen_at, :utc_datetime

      add :organization_id, :binary_id

      timestamps()
    end

    create_if_not_exists unique_index(:cloud_resources, [:provider, :account_id, :resource_id])
    create_if_not_exists index(:cloud_resources, [:provider, :account_id])
    create_if_not_exists index(:cloud_resources, [:resource_type])
    create_if_not_exists index(:cloud_resources, [:region])
    create_if_not_exists index(:cloud_resources, [:publicly_accessible])
    create_if_not_exists index(:cloud_resources, [:organization_id])

    # Custom cloud policies table
    create_if_not_exists table(:cloud_custom_policies, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :policy_id, :string, null: false
      add :name, :string, null: false
      add :description, :text
      add :provider, :string, null: false
      add :resource_type, :string

      add :severity, :string, null: false
      add :category, :string, null: false
      add :enabled, :boolean, default: true

      add :compliance, {:array, :string}, default: []
      add :condition, :map, null: false
      add :recommendation, :text

      add :remediation_terraform, :text
      add :remediation_cloudformation, :text
      add :remediation_arm, :text
      add :remediation_cli, :text

      add :organization_id, :binary_id
      add :created_by, :string

      timestamps()
    end

    create_if_not_exists unique_index(:cloud_custom_policies, [:policy_id])
    create_if_not_exists index(:cloud_custom_policies, [:provider])
    create_if_not_exists index(:cloud_custom_policies, [:severity])
    create_if_not_exists index(:cloud_custom_policies, [:enabled])
    create_if_not_exists index(:cloud_custom_policies, [:organization_id])
  end
end
