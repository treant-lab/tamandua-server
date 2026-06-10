defmodule TamanduaServer.Repo.Migrations.RollbackAgentGroups do
  @moduledoc """
  Rollback script for agent groups feature.

  This is a safety rollback migration in case you need to remove the agent groups feature.

  WARNING: This will delete all group data, memberships, and batch command history.

  To use this rollback:
  1. Rename this file with a newer timestamp than the original migration
  2. Run: mix ecto.migrate

  Example:
  mv ROLLBACK_agent_groups.exs 20260221000001_rollback_agent_groups.exs
  mix ecto.migrate
  """

  use Ecto.Migration

  def up do
    # Drop tables in reverse order of dependencies
    drop_if_exists table(:batch_command_results)
    drop_if_exists table(:batch_commands)
    drop_if_exists table(:agent_group_members)
    drop_if_exists table(:agent_groups)
  end

  def down do
    # This would recreate the tables - copy from the original migration if needed
    raise "Cannot undo rollback - restore from backup instead"
  end
end
