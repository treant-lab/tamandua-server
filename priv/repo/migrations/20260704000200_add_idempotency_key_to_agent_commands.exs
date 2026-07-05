defmodule TamanduaServer.Repo.Migrations.AddIdempotencyKeyToAgentCommands do
  use Ecto.Migration

  @moduledoc """
  Adds an optional idempotency_key to agent_commands so UI/API retries of
  send_command do not insert and dispatch duplicate commands. Uniqueness is
  scoped per agent and only enforced when a key is provided (partial index).
  """

  def change do
    alter table(:agent_commands) do
      add :idempotency_key, :string
    end

    create unique_index(:agent_commands, [:agent_id, :idempotency_key],
             where: "idempotency_key IS NOT NULL",
             name: :agent_commands_agent_id_idempotency_key_index
           )
  end
end
