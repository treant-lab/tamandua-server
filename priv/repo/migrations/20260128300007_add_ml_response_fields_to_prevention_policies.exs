defmodule TamanduaServer.Repo.Migrations.AddMlResponseFieldsToPreventionPolicies do
  use Ecto.Migration

  def change do
    # Use raw SQL with IF NOT EXISTS to avoid duplicate column errors
    execute """
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='prevention_policies' AND column_name='auto_quarantine_threshold') THEN
        ALTER TABLE prevention_policies ADD COLUMN auto_quarantine_threshold float DEFAULT 0.90;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='prevention_policies' AND column_name='auto_kill_process') THEN
        ALTER TABLE prevention_policies ADD COLUMN auto_kill_process boolean DEFAULT false;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='prevention_policies' AND column_name='ml_response_enabled') THEN
        ALTER TABLE prevention_policies ADD COLUMN ml_response_enabled boolean DEFAULT true;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='prevention_policies' AND column_name='alert_threshold') THEN
        ALTER TABLE prevention_policies ADD COLUMN alert_threshold float DEFAULT 0.75;
      END IF;
    END $$;
    """, ""
  end
end
