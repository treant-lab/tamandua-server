defmodule TamanduaServer.Repo.Migrations.CreateFleetQueryRuns do
  use Ecto.Migration

  def change do
    create table(:fleet_query_runs, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false
      add :created_by_user_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :query, :text, null: false
      add :query_hash, :string, null: false
      add :status, :string, null: false, default: "queued"
      add :requested_agent_ids, {:array, :binary_id}, null: false, default: []
      add :filters, :jsonb, null: false, default: fragment("'{}'::jsonb")
      add :options, :jsonb, null: false, default: fragment("'{}'::jsonb")
      add :target_count, :integer, null: false, default: 0
      add :queued_count, :integer, null: false, default: 0
      add :skipped_count, :integer, null: false, default: 0
      add :completed_count, :integer, null: false, default: 0
      add :failed_count, :integer, null: false, default: 0
      add :started_at, :utc_datetime
      add :completed_at, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    create index(:fleet_query_runs, [:organization_id, :inserted_at])
    create index(:fleet_query_runs, [:organization_id, :status])
    create index(:fleet_query_runs, [:query_hash])

    create table(:fleet_query_targets, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :fleet_query_run_id,
          references(:fleet_query_runs, type: :binary_id, on_delete: :delete_all),
          null: false

      add :agent_id, references(:agents, type: :binary_id, on_delete: :nilify_all)
      add :hostname, :string
      add :os_type, :string
      add :status, :string, null: false, default: "queued"
      add :agent_command_id, references(:agent_commands, type: :binary_id, on_delete: :nilify_all)
      add :skip_reason, :string
      add :result_summary, :jsonb
      add :error, :text
      add :completed_at, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    create index(:fleet_query_targets, [:fleet_query_run_id, :status])
    create index(:fleet_query_targets, [:agent_command_id])
    create unique_index(:fleet_query_targets, [:fleet_query_run_id, :agent_id])
  end
end
