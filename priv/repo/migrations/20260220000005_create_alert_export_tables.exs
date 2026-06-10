defmodule TamanduaServer.Repo.Migrations.CreateAlertExportTables do
  use Ecto.Migration

  def change do
    # Alert Export Templates
    create table(:alert_export_templates, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text

      # Export configuration
      add :format, :string, null: false
      add :columns, {:array, :string}, default: []
      add :filter_json, :map, default: %{}
      add :include_evidence, :boolean, default: false
      add :include_process_chain, :boolean, default: false

      # Schedule configuration
      add :scheduled, :boolean, default: false
      add :schedule_type, :string
      add :schedule_cron, :string
      add :schedule_timezone, :string, default: "UTC"
      add :max_records, :integer

      # Delivery configuration
      add :delivery_method, :string
      add :delivery_config, :map, default: %{}

      # Retention
      add :retention_days, :integer, default: 7

      # Sharing
      add :is_shared, :boolean, default: false
      add :last_run_at, :utc_datetime_usec

      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false

      add :created_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)

      timestamps(type: :utc_datetime_usec)
    end

    create index(:alert_export_templates, [:organization_id])
    create index(:alert_export_templates, [:created_by_id])
    create index(:alert_export_templates, [:scheduled])
    create index(:alert_export_templates, [:last_run_at])

    # Alert Export Jobs
    create table(:alert_export_jobs, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :status, :string, default: "pending", null: false
      add :format, :string, null: false
      add :filter_json, :map, default: %{}
      add :columns, {:array, :string}, default: []

      # Progress tracking
      add :progress, :integer, default: 0
      add :total_records, :integer
      add :processed_records, :integer, default: 0
      add :message, :string

      # Output
      add :file_path, :string
      add :file_size, :bigint
      add :download_url, :string
      add :url_expires_at, :utc_datetime_usec

      # Metadata
      add :triggered_by, :string
      add :delivery_method, :string
      add :delivery_status, :string
      add :delivery_error, :text

      # Error handling
      add :error_message, :text
      add :error_details, :map

      # Completion
      add :started_at, :utc_datetime_usec
      add :completed_at, :utc_datetime_usec

      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false

      add :user_id, references(:users, type: :binary_id, on_delete: :nilify_all)

      add :template_id,
          references(:alert_export_templates, type: :binary_id, on_delete: :nilify_all)

      timestamps(type: :utc_datetime_usec)
    end

    create index(:alert_export_jobs, [:organization_id])
    create index(:alert_export_jobs, [:user_id])
    create index(:alert_export_jobs, [:template_id])
    create index(:alert_export_jobs, [:status])
    create index(:alert_export_jobs, [:triggered_by])
    create index(:alert_export_jobs, [:url_expires_at])
    create index(:alert_export_jobs, [:inserted_at])
    create index(:alert_export_jobs, [:completed_at])
  end
end
