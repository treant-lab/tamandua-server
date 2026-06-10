defmodule TamanduaServer.Repo.Migrations.CreateResponseActions do
  use Ecto.Migration

  def change do
    create table(:response_actions, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :action_type, :string, null: false
      add :parameters, :map, default: %{}
      add :status, :string, default: "pending", null: false
      add :result, :map
      add :error_message, :text
      add :executed_at, :utc_datetime_usec

      add :agent_id, references(:agents, type: :binary_id, on_delete: :delete_all), null: false
      add :alert_id, references(:alerts, type: :binary_id, on_delete: :nilify_all)
      add :executed_by_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all)

      timestamps(type: :utc_datetime_usec)
    end

    create index(:response_actions, [:agent_id])
    create index(:response_actions, [:alert_id])
    create index(:response_actions, [:executed_by_id])
    create index(:response_actions, [:organization_id])
    create index(:response_actions, [:status])
    create index(:response_actions, [:action_type])
    create index(:response_actions, [:inserted_at])
  end
end
