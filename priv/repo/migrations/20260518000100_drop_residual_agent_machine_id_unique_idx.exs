defmodule TamanduaServer.Repo.Migrations.DropResidualAgentMachineIdUniqueIdx do
  use Ecto.Migration

  def up do
    execute("DROP INDEX IF EXISTS agents_machine_id_unique_idx")
    drop_if_exists unique_index(:agents, [:machine_id], name: :agents_machine_id_index)

    create_if_not_exists index(:agents, [:organization_id, :machine_id],
                           name: :agents_org_machine_id_index,
                           where: "machine_id IS NOT NULL"
                         )
  end

  def down do
    drop_if_exists index(:agents, [:organization_id, :machine_id],
                     name: :agents_org_machine_id_index
                   )

    create_if_not_exists unique_index(:agents, [:machine_id],
                           name: :agents_machine_id_index,
                           where: "machine_id IS NOT NULL"
                         )
  end
end
