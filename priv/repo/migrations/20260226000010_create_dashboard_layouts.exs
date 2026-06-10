defmodule TamanduaServer.Repo.Migrations.CreateDashboardLayouts do
  use Ecto.Migration

  def change do
    create_if_not_exists table(:dashboard_layouts, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :description, :text
      add :widgets, :jsonb, default: "[]", null: false
      add :settings, :jsonb, default: "{}", null: false
      add :is_template, :boolean, default: false
      add :is_default, :boolean, default: false
      add :is_public, :boolean, default: false
      add :template_category, :string
      add :tags, {:array, :string}, default: []
      add :thumbnail_url, :string
      add :version, :integer, default: 1
      add :author_name, :string
      add :view_count, :integer, default: 0
      add :clone_count, :integer, default: 0

      # User-specific layout (if nil, it's a role-based or public template)
      add :user_id, references(:users, on_delete: :delete_all, type: :binary_id)
      # Role-based default layout (if nil and user_id is nil, it's a public template)
      add :role, :string
      # Organization scoping
      add :organization_id, references(:organizations, on_delete: :delete_all, type: :binary_id), null: false

      # Cloning support
      add :cloned_from_id, references(:dashboard_layouts, on_delete: :nilify_all, type: :binary_id)

      timestamps(type: :utc_datetime_usec)
    end

    # Add any missing columns to existing table
    execute """
    DO $$
    BEGIN
      ALTER TABLE dashboard_layouts ADD COLUMN IF NOT EXISTS role VARCHAR;
      ALTER TABLE dashboard_layouts ADD COLUMN IF NOT EXISTS is_template BOOLEAN DEFAULT FALSE;
      ALTER TABLE dashboard_layouts ADD COLUMN IF NOT EXISTS is_default BOOLEAN DEFAULT FALSE;
      ALTER TABLE dashboard_layouts ADD COLUMN IF NOT EXISTS is_public BOOLEAN DEFAULT FALSE;
      ALTER TABLE dashboard_layouts ADD COLUMN IF NOT EXISTS template_category VARCHAR;
      ALTER TABLE dashboard_layouts ADD COLUMN IF NOT EXISTS tags TEXT[] DEFAULT '{}';
      ALTER TABLE dashboard_layouts ADD COLUMN IF NOT EXISTS thumbnail_url VARCHAR;
      ALTER TABLE dashboard_layouts ADD COLUMN IF NOT EXISTS version INTEGER DEFAULT 1;
      ALTER TABLE dashboard_layouts ADD COLUMN IF NOT EXISTS author_name VARCHAR;
      ALTER TABLE dashboard_layouts ADD COLUMN IF NOT EXISTS view_count INTEGER DEFAULT 0;
      ALTER TABLE dashboard_layouts ADD COLUMN IF NOT EXISTS clone_count INTEGER DEFAULT 0;
      ALTER TABLE dashboard_layouts ADD COLUMN IF NOT EXISTS cloned_from_id UUID;
    END $$;
    """, ""

    execute "CREATE INDEX IF NOT EXISTS dashboard_layouts_organization_id_index ON dashboard_layouts(organization_id)", ""
    execute "CREATE INDEX IF NOT EXISTS dashboard_layouts_user_id_index ON dashboard_layouts(user_id)", ""
    execute "CREATE INDEX IF NOT EXISTS dashboard_layouts_role_index ON dashboard_layouts(role)", ""
    execute "CREATE INDEX IF NOT EXISTS dashboard_layouts_is_template_index ON dashboard_layouts(is_template)", ""
    execute "CREATE INDEX IF NOT EXISTS dashboard_layouts_is_public_index ON dashboard_layouts(is_public)", ""
    execute "CREATE INDEX IF NOT EXISTS dashboard_layouts_template_category_index ON dashboard_layouts(template_category)", ""
    execute "CREATE INDEX IF NOT EXISTS dashboard_layouts_tags_index ON dashboard_layouts USING gin(tags)", ""
    execute "CREATE INDEX IF NOT EXISTS dashboard_layouts_cloned_from_id_index ON dashboard_layouts(cloned_from_id)", ""

    # Ensure only one default layout per user OR per role within an organization
    execute """
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'dashboard_layouts_user_default_idx') THEN
        CREATE UNIQUE INDEX dashboard_layouts_user_default_idx ON dashboard_layouts(user_id, is_default) WHERE is_default = true AND user_id IS NOT NULL;
      END IF;
    END $$;
    """, ""

    execute """
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'dashboard_layouts_role_default_idx') THEN
        CREATE UNIQUE INDEX dashboard_layouts_role_default_idx ON dashboard_layouts(organization_id, role, is_default) WHERE is_default = true AND role IS NOT NULL AND user_id IS NULL;
      END IF;
    END $$;
    """, ""

    # Layout versions table for history
    create_if_not_exists table(:dashboard_layout_versions, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :layout_id, references(:dashboard_layouts, on_delete: :delete_all, type: :binary_id), null: false
      add :version, :integer, null: false
      add :widgets, :jsonb, null: false
      add :settings, :jsonb, null: false
      add :created_by_id, references(:users, on_delete: :nilify_all, type: :binary_id)
      add :change_description, :text

      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    execute "CREATE INDEX IF NOT EXISTS dashboard_layout_versions_layout_id_index ON dashboard_layout_versions(layout_id)", ""
    execute "CREATE UNIQUE INDEX IF NOT EXISTS dashboard_layout_versions_layout_id_version_index ON dashboard_layout_versions(layout_id, version)", ""
  end
end
