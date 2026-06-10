defmodule TamanduaServer.Repo.Migrations.AddWidgetExportSettings do
  use Ecto.Migration

  def change do
    execute """
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'dashboard_widgets') THEN
        ALTER TABLE dashboard_widgets ADD COLUMN IF NOT EXISTS export_enabled BOOLEAN DEFAULT TRUE;
        ALTER TABLE dashboard_widgets ADD COLUMN IF NOT EXISTS drill_down_enabled BOOLEAN DEFAULT TRUE;
        ALTER TABLE dashboard_widgets ADD COLUMN IF NOT EXISTS settings_schema JSONB DEFAULT '{}';
      END IF;
    END $$;
    """, ""

    execute "CREATE INDEX IF NOT EXISTS dashboard_widgets_widget_type_index ON dashboard_widgets(widget_type)", ""
    execute "CREATE INDEX IF NOT EXISTS dashboard_widgets_dashboard_layout_id_is_visible_index ON dashboard_widgets(dashboard_layout_id, is_visible)", ""
  end
end
