defmodule TamanduaServer.Repo.Migrations.ReconcileAlertSuppressionRuleColumns do
  use Ecto.Migration

  def change do
    execute """
    ALTER TABLE alert_suppression_rules
      ADD COLUMN IF NOT EXISTS tags varchar[] DEFAULT '{}',
      ADD COLUMN IF NOT EXISTS time_window_type varchar,
      ADD COLUMN IF NOT EXISTS time_window_value integer,
      ADD COLUMN IF NOT EXISTS exempted_agent_ids uuid[] DEFAULT '{}',
      ADD COLUMN IF NOT EXISTS exempted_users varchar[] DEFAULT '{}',
      ADD COLUMN IF NOT EXISTS add_tags varchar[] DEFAULT '{}';
    """, """
    ALTER TABLE alert_suppression_rules
      DROP COLUMN IF EXISTS add_tags,
      DROP COLUMN IF EXISTS exempted_users,
      DROP COLUMN IF EXISTS exempted_agent_ids,
      DROP COLUMN IF EXISTS time_window_value,
      DROP COLUMN IF EXISTS time_window_type,
      DROP COLUMN IF EXISTS tags;
    """
  end
end
