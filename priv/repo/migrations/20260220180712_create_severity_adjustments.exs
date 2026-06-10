defmodule TamanduaServer.Repo.Migrations.CreateSeverityAdjustments do
  use Ecto.Migration

  def change do
    # Severity adjustments audit log
    create table(:severity_adjustments, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :alert_id, references(:alerts, type: :binary_id, on_delete: :delete_all), null: false
      add :old_severity, :string, null: false
      add :new_severity, :string, null: false
      add :reason, :text, null: false  # Required justification
      add :notes, :text
      add :requires_approval, :boolean, default: false
      add :approved, :boolean
      add :approved_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :approved_at, :utc_datetime_usec
      add :rejection_reason, :text
      add :metadata, :map, default: %{}

      add :adjusted_by_id, references(:users, type: :binary_id, on_delete: :nilify_all), null: false
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create index(:severity_adjustments, [:alert_id])
    create index(:severity_adjustments, [:adjusted_by_id])
    create index(:severity_adjustments, [:organization_id])
    create index(:severity_adjustments, [:requires_approval])
    create index(:severity_adjustments, [:approved])
    create index(:severity_adjustments, [:inserted_at])

    # Add current_severity to alerts to track manual overrides
    alter table(:alerts) do
      add :original_severity, :string  # Store original ML/rule-detected severity
      add :severity_adjusted, :boolean, default: false
      add :severity_adjusted_at, :utc_datetime_usec
      add :severity_adjusted_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
    end

    # Backfill original_severity with current severity for existing alerts
    execute "UPDATE alerts SET original_severity = severity WHERE original_severity IS NULL", ""
  end
end
