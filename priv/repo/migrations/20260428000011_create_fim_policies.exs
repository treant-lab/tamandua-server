defmodule TamanduaServer.Repo.Migrations.CreateFimPolicies do
  use Ecto.Migration

  def change do
    create table(:fim_policies, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :agent_id, :string, null: false  # "*" for global
      add :pattern, :string, null: false
      add :action, :string, null: false, default: "alert"
      add :severity_threshold, :string  # nullable
      add :auto_response, :string, null: false, default: "notify"
      add :priority, :integer, null: false, default: 100
      add :expires, :bigint, null: false, default: 0
      add :reason, :string, null: false
      add :added_by, :string, null: false
      add :enabled, :boolean, null: false, default: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps()
    end

    create index(:fim_policies, [:agent_id])
    create index(:fim_policies, [:organization_id])
    create index(:fim_policies, [:enabled, :priority])
    create index(:fim_policies, [:pattern], using: :btree)
  end
end
