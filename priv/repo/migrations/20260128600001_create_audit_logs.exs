defmodule TamanduaServer.Repo.Migrations.CreateAuditLogs do
  use Ecto.Migration

  def change do
    create_if_not_exists table(:audit_logs, primary_key: false) do
      add :id, :binary_id, primary_key: true, default: fragment("gen_random_uuid()")

      # Who performed the action
      add :user_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :user_email, :string  # Denormalized for quick display

      # What action was performed
      add :action, :string, null: false  # e.g., "login", "logout", "kill_process", "config_change"
      add :action_type, :string, null: false  # Category: login, logout, config_change, response_action, etc.

      # What resource was affected
      add :resource_type, :string  # e.g., "agent", "alert", "playbook", "config", "user"
      add :resource_id, :string  # ID of the affected resource

      # Additional details as JSON
      add :details, :map, default: %{}

      # Request metadata
      add :ip_address, :string
      add :user_agent, :string

      # Organization for multi-tenancy
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    # Indexes for common query patterns
    create_if_not_exists index(:audit_logs, [:user_id])
    create_if_not_exists index(:audit_logs, [:user_email])
    create_if_not_exists index(:audit_logs, [:action])
    create_if_not_exists index(:audit_logs, [:action_type])
    create_if_not_exists index(:audit_logs, [:resource_type])
    create_if_not_exists index(:audit_logs, [:resource_id])
    create_if_not_exists index(:audit_logs, [:organization_id])
    create_if_not_exists index(:audit_logs, [:inserted_at])

    # Composite indexes for filtered queries
    create_if_not_exists index(:audit_logs, [:organization_id, :inserted_at])
    create_if_not_exists index(:audit_logs, [:action_type, :inserted_at])
    create_if_not_exists index(:audit_logs, [:user_id, :inserted_at])
  end
end
