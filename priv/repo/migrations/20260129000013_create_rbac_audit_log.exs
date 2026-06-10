defmodule TamanduaServer.Repo.Migrations.CreateRbacAuditLog do
  use Ecto.Migration

  def change do
    create_if_not_exists table(:rbac_audit_log, primary_key: false) do
      add :id, :binary_id, primary_key: true, default: fragment("gen_random_uuid()")

      # Organization for multi-tenancy
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      # Who performed the action
      add :actor_id, references(:users, type: :binary_id, on_delete: :nilify_all)

      # What action was performed
      add :action, :string, null: false

      # Target of the action
      add :target_type, :string, null: false
      add :target_id, :binary_id, null: false
      add :target_name, :string

      # Changes made
      add :changes, :map, default: %{}
      add :metadata, :map, default: %{}

      # Request context
      add :ip_address, :string
      add :user_agent, :string

      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create_if_not_exists index(:rbac_audit_log, [:organization_id])
    create_if_not_exists index(:rbac_audit_log, [:actor_id])
    create_if_not_exists index(:rbac_audit_log, [:action])
    create_if_not_exists index(:rbac_audit_log, [:target_type])
    create_if_not_exists index(:rbac_audit_log, [:target_id])
    create_if_not_exists index(:rbac_audit_log, [:inserted_at])
    create_if_not_exists index(:rbac_audit_log, [:organization_id, :inserted_at])
    create_if_not_exists index(:rbac_audit_log, [:target_type, :target_id])
  end
end
