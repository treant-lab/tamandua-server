defmodule TamanduaServer.Repo.Migrations.CreateResponseAuditTrail do
  use Ecto.Migration

  def change do
    create_if_not_exists table(:response_audit_trail, primary_key: false) do
      add :id, :binary_id, primary_key: true, default: fragment("gen_random_uuid()")
      add :action_type, :string, null: false
      add :details, :map, default: %{}
      add :agent_id, :binary_id, null: false
      add :organization_id, :binary_id
      add :actor_type, :string, null: false  # "system" or "user"
      add :actor_id, :binary_id  # user_id if actor_type is "user"
      add :performed_at, :utc_datetime_usec, null: false

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists index(:response_audit_trail, [:agent_id])
    create_if_not_exists index(:response_audit_trail, [:organization_id])
    create_if_not_exists index(:response_audit_trail, [:action_type])
    create_if_not_exists index(:response_audit_trail, [:actor_type])
    create_if_not_exists index(:response_audit_trail, [:performed_at])
    create_if_not_exists index(:response_audit_trail, [:agent_id, :performed_at])
  end
end
