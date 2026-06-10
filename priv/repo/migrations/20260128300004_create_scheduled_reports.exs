defmodule TamanduaServer.Repo.Migrations.CreateScheduledReports do
  use Ecto.Migration

  def change do
    create_if_not_exists table(:scheduled_reports, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :template_id, :string, null: false
      add :schedule, :string, null: false  # Cron expression
      add :recipients, {:array, :string}, default: []
      add :format, :string, default: "pdf"
      add :params, :map, default: %{}
      add :enabled, :boolean, default: true

      add :last_run_at, :utc_datetime
      add :next_run_at, :utc_datetime
      add :created_by, :string
      add :organization_id, references(:organizations, on_delete: :delete_all, type: :binary_id)

      timestamps()
    end

    create_if_not_exists index(:scheduled_reports, [:organization_id])
    create_if_not_exists index(:scheduled_reports, [:enabled])
    create_if_not_exists index(:scheduled_reports, [:next_run_at])
    create_if_not_exists index(:scheduled_reports, [:template_id])

    # Add schedule_id to reports table for linking
    execute """
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='reports' AND column_name='schedule_id') THEN
        ALTER TABLE reports ADD COLUMN schedule_id uuid REFERENCES scheduled_reports(id) ON DELETE SET NULL;
      END IF;
    END $$;
    """, """
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='reports' AND column_name='schedule_id') THEN
        ALTER TABLE reports DROP COLUMN schedule_id;
      END IF;
    END $$;
    """

    create_if_not_exists index(:reports, [:schedule_id])
  end
end
