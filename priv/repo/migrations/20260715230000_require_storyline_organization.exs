defmodule TamanduaServer.Repo.Migrations.RequireStorylineOrganization do
  use Ecto.Migration

  def up do
    # Fail closed if legacy orphan rows exist. Operators must attribute them
    # from governed provenance before this invariant can be enabled.
    execute("ALTER TABLE storylines ALTER COLUMN organization_id SET NOT NULL")
  end

  def down do
    execute("ALTER TABLE storylines ALTER COLUMN organization_id DROP NOT NULL")
  end
end
