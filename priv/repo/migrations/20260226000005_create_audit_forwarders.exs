defmodule TamanduaServer.Repo.Migrations.CreateAuditForwarders do
  use Ecto.Migration

  def change do
    create table(:audit_forwarders, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      add :name, :string, null: false
      add :forwarder_type, :string, null: false # splunk, s3, syslog, siem

      # Configuration (encrypted in production)
      add :config, :map, null: false

      # Filters (what to forward)
      add :filter_actions, {:array, :string}, default: []
      add :filter_categories, {:array, :string}, default: []
      add :filter_severity, {:array, :string}, default: []
      add :forward_all, :boolean, default: true

      # Status & health
      add :is_active, :boolean, default: true
      add :health_status, :string, default: "healthy" # healthy, degraded, down
      add :last_success_at, :utc_datetime_usec
      add :last_error_at, :utc_datetime_usec
      add :last_error_message, :string
      add :consecutive_failures, :integer, default: 0

      # Statistics
      add :total_forwarded, :bigint, default: 0
      add :total_failed, :bigint, default: 0

      # Batching settings
      add :batch_size, :integer, default: 100
      add :batch_timeout_ms, :integer, default: 5000

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:audit_forwarders, [:organization_id, :name])
    create index(:audit_forwarders, [:is_active])
    create index(:audit_forwarders, [:health_status])
  end
end
