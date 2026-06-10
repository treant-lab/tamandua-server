defmodule TamanduaServer.Repo.Migrations.CreateDashboardWidgets do
  use Ecto.Migration

  def change do
    # Dashboard layouts table
    create table(:dashboard_layouts, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, on_delete: :delete_all, type: :binary_id), null: false
      add :name, :string, null: false
      add :description, :text
      add :is_default, :boolean, default: false
      add :is_template, :boolean, default: false
      add :template_type, :string # "soc_analyst", "executive", "incident_responder", etc.
      add :layout_config, :map, default: %{} # Grid layout configuration
      add :shared_with_users, {:array, :binary_id}, default: []
      add :organization_id, references(:organizations, on_delete: :delete_all, type: :binary_id)

      timestamps(type: :utc_datetime_usec)
    end

    create index(:dashboard_layouts, [:user_id])
    create index(:dashboard_layouts, [:organization_id])
    create index(:dashboard_layouts, [:template_type])
    create index(:dashboard_layouts, [:is_template])

    # Dashboard widgets table
    create table(:dashboard_widgets, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :dashboard_layout_id, references(:dashboard_layouts, on_delete: :delete_all, type: :binary_id), null: false
      add :widget_type, :string, null: false # "threat_level_gauge", "top_detections", "geo_map", etc.
      add :title, :string, null: false
      add :position_x, :integer, null: false, default: 0
      add :position_y, :integer, null: false, default: 0
      add :width, :integer, null: false, default: 4
      add :height, :integer, null: false, default: 4
      add :config, :map, default: %{} # Widget-specific configuration
      add :refresh_interval, :integer, default: 30000 # milliseconds
      add :is_visible, :boolean, default: true
      add :order, :integer, default: 0

      timestamps(type: :utc_datetime_usec)
    end

    create index(:dashboard_widgets, [:dashboard_layout_id])
    create index(:dashboard_widgets, [:widget_type])

    # Widget data cache table (optional, for heavy queries)
    create table(:widget_data_cache, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :widget_id, references(:dashboard_widgets, on_delete: :delete_all, type: :binary_id), null: false
      add :cache_key, :string, null: false
      add :data, :map
      add :expires_at, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec)
    end

    create index(:widget_data_cache, [:widget_id])
    create index(:widget_data_cache, [:cache_key])
    create index(:widget_data_cache, [:expires_at])
    create unique_index(:widget_data_cache, [:widget_id, :cache_key])
  end
end
