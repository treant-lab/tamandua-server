defmodule TamanduaServer.Repo.Migrations.AddK8sContextToAlerts do
  use Ecto.Migration

  def up do
    execute("""
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'alerts' AND column_name = 'k8s_context'
      ) THEN
        ALTER TABLE alerts ADD COLUMN k8s_context jsonb;
      END IF;
    END $$;
    """)
  end

  def down do
    execute("ALTER TABLE alerts DROP COLUMN IF EXISTS k8s_context")
  end
end
