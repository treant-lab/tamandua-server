defmodule TamanduaServer.Repo.Migrations.CreateShellAuditLogs do
  use Ecto.Migration

  def change do
    create_if_not_exists table(:shell_audit_logs, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(
        :session_id,
        references(:shell_sessions, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:user_id, references(:users, type: :binary_id, on_delete: :nilify_all))

      add(:event_type, :string, null: false)
      add(:timestamp, :utc_datetime, null: false)

      add(:command, :text)
      add(:exit_code, :integer)
      add(:blocked, :boolean, default: false, null: false)
      add(:block_reason, :string)

      add(:output, :text)
      add(:output_size, :integer)

      add(:client_ip, :string)

      timestamps(updated_at: false)
    end

    create_if_not_exists(index(:shell_audit_logs, [:session_id]))
    create_if_not_exists(index(:shell_audit_logs, [:user_id]))
    create_if_not_exists(index(:shell_audit_logs, [:event_type]))
    create_if_not_exists(index(:shell_audit_logs, [:timestamp]))
  end
end
