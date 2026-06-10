defmodule TamanduaServer.Repo.Migrations.CreateSoarExecutionLogs do
  use Ecto.Migration

  def change do
    create table(:soar_execution_logs, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :alert_id, :binary_id
      add :trigger_rule_id, :binary_id
      add :soar_platform, :string, null: false  # "xsoar", "tines"
      add :playbook_name, :string, null: false
      add :execution_id, :string  # ID from SOAR platform
      add :status, :string, default: "pending", null: false  # pending, running, completed, failed, timeout
      add :result, :map
      add :error_message, :text
      add :started_at, :utc_datetime_usec
      add :completed_at, :utc_datetime_usec

      # Callback tracking
      add :callback_received_at, :utc_datetime_usec
      add :callback_payload, :map

      timestamps(type: :utc_datetime_usec)
    end

    create index(:soar_execution_logs, [:alert_id])
    create index(:soar_execution_logs, [:trigger_rule_id])
    create index(:soar_execution_logs, [:execution_id])
    create index(:soar_execution_logs, [:status])
    create index(:soar_execution_logs, [:soar_platform])
    create index(:soar_execution_logs, [:started_at])
  end
end
