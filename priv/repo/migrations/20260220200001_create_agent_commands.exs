defmodule TamanduaServer.Repo.Migrations.CreateAgentCommands do
  use Ecto.Migration

  def change do
    create table(:agent_commands, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :agent_id, :string, null: false
      add :command_type, :string, null: false
      add :command_params, :jsonb, default: fragment("'{}'::jsonb")
      add :status, :string, default: "pending"
      add :priority, :integer, default: 0
      add :sent_at, :utc_datetime
      add :acknowledged_at, :utc_datetime
      add :completed_at, :utc_datetime
      add :error, :text
      add :result, :jsonb
      add :expires_at, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    create index(:agent_commands, [:agent_id, :status])
    create index(:agent_commands, [:status, :inserted_at])
    create index(:agent_commands, [:expires_at])
  end
end
