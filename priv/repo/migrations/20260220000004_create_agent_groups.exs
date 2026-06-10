defmodule TamanduaServer.Repo.Migrations.CreateAgentGroups do
  use Ecto.Migration

  def change do
    # Agent groups table
    create table(:agent_groups, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text
      add :color, :string
      add :tags, {:array, :string}, default: []
      add :metadata, :map, default: %{}
      add :visible_to_roles, {:array, :string}, default: []
      add :manageable_by_roles, {:array, :string}, default: []

      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false

      add :parent_id, references(:agent_groups, type: :binary_id, on_delete: :nilify_all)

      timestamps(type: :utc_datetime)
    end

    create index(:agent_groups, [:organization_id])
    create index(:agent_groups, [:parent_id])
    create unique_index(:agent_groups, [:name, :organization_id])

    # Agent group members (join table)
    create table(:agent_group_members, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :added_by, :string
      add :metadata, :map, default: %{}

      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all), null: false
      add :group_id, references(:agent_groups, type: :binary_id, on_delete: :delete_all), null: false

      timestamps(type: :utc_datetime)
    end

    create index(:agent_group_members, [:agent_id])
    create index(:agent_group_members, [:group_id])
    create unique_index(:agent_group_members, [:agent_id, :group_id])

    # Batch commands table
    create table(:batch_commands, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :command_type, :string, null: false
      add :command_params, :map, default: %{}
      add :status, :string, default: "pending", null: false
      add :total_count, :integer, default: 0
      add :completed_count, :integer, default: 0
      add :success_count, :integer, default: 0
      add :failed_count, :integer, default: 0
      add :initiated_by, :string
      add :expires_at, :utc_datetime
      add :started_at, :utc_datetime
      add :completed_at, :utc_datetime
      add :timeout_seconds, :integer, default: 3600

      add :target_type, :string, null: false
      add :target_ids, {:array, :string}, default: []

      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false

      add :group_id, references(:agent_groups, type: :binary_id, on_delete: :nilify_all)

      timestamps(type: :utc_datetime)
    end

    create index(:batch_commands, [:organization_id])
    create index(:batch_commands, [:group_id])
    create index(:batch_commands, [:status])
    create index(:batch_commands, [:inserted_at])

    # Batch command results table
    create table(:batch_command_results, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :agent_id, :string, null: false
      add :status, :string, default: "pending", null: false
      add :result, :map
      add :error, :text
      add :started_at, :utc_datetime
      add :completed_at, :utc_datetime

      add :batch_command_id,
        references(:batch_commands, type: :binary_id, on_delete: :delete_all),
        null: false

      timestamps(type: :utc_datetime)
    end

    create index(:batch_command_results, [:batch_command_id])
    create index(:batch_command_results, [:agent_id])
    create index(:batch_command_results, [:status])
  end
end
