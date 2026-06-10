defmodule TamanduaServer.Repo.Migrations.CreateDNSBlocklistEntries do
  use Ecto.Migration

  def up do
    create table(:dns_blocklist_entries, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :organization_id,
          references(:organizations, type: :binary_id, on_delete: :delete_all),
          null: false

      add :domain, :string, null: false
      add :normalized_domain, :string, null: false
      add :reason, :text
      add :blocked_by, :string
      add :source, :string, null: false, default: "manual"
      add :active, :boolean, null: false, default: true

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:dns_blocklist_entries, [:organization_id, :normalized_domain],
             name: :dns_blocklist_entries_org_domain_index
           )

    create index(:dns_blocklist_entries, [:organization_id, :active])
    create index(:dns_blocklist_entries, [:normalized_domain])

    execute """
    ALTER TABLE dns_blocklist_entries ENABLE ROW LEVEL SECURITY;
    """

    execute """
    CREATE POLICY dns_blocklist_entries_deny_all
      ON dns_blocklist_entries
      AS RESTRICTIVE
      FOR ALL
      TO PUBLIC
      USING (FALSE);
    """

    execute """
    CREATE POLICY dns_blocklist_entries_organization_isolation
      ON dns_blocklist_entries
      AS PERMISSIVE
      FOR ALL
      TO PUBLIC
      USING (rls_bypass_enabled() = TRUE OR organization_id = current_organization_id())
      WITH CHECK (rls_bypass_enabled() = TRUE OR organization_id = current_organization_id());
    """
  end

  def down do
    execute "DROP POLICY IF EXISTS dns_blocklist_entries_organization_isolation ON dns_blocklist_entries;"
    execute "DROP POLICY IF EXISTS dns_blocklist_entries_deny_all ON dns_blocklist_entries;"
    drop table(:dns_blocklist_entries)
  end
end
