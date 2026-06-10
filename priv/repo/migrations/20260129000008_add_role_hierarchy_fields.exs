defmodule TamanduaServer.Repo.Migrations.AddRoleHierarchyFields do
  use Ecto.Migration

  def change do
    # Use conditional SQL to avoid duplicate column errors
    execute """
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='roles' AND column_name='api_only') THEN
        ALTER TABLE roles ADD COLUMN api_only boolean DEFAULT false NOT NULL;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='roles' AND column_name='inherit_from_id') THEN
        ALTER TABLE roles ADD COLUMN inherit_from_id uuid REFERENCES roles(id) ON DELETE SET NULL;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='roles' AND column_name='color') THEN
        ALTER TABLE roles ADD COLUMN color varchar(255) DEFAULT '#6366f1';
      END IF;
    END $$;
    """, ""

    execute """
    CREATE INDEX IF NOT EXISTS roles_inherit_from_id_index ON roles(inherit_from_id);
    """, ""

    execute """
    CREATE INDEX IF NOT EXISTS roles_api_only_index ON roles(api_only);
    """, ""
  end
end
