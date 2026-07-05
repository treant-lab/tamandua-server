defmodule TamanduaServer.Repo.Migrations.AddDispatchTrackingToAgentCommands do
  use Ecto.Migration

  @moduledoc """
  Adds dispatch bookkeeping to agent_commands so commands stuck in "sent"
  (worker/channel died between mark_sent and actual delivery) can be safely
  re-delivered on agent reconnect without tight redelivery loops:

  - dispatch_count: how many times the command was pushed towards the agent
  - last_dispatched_at: last push timestamp (used for a redelivery cooldown)
  """

  def change do
    alter table(:agent_commands) do
      add :dispatch_count, :integer, default: 0, null: false
      add :last_dispatched_at, :utc_datetime
    end
  end
end
