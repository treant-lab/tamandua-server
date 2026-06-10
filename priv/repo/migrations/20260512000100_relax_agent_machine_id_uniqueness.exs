defmodule TamanduaServer.Repo.Migrations.RelaxAgentMachineIdUniqueness do
  use Ecto.Migration

  def change do
    drop_if_exists unique_index(:agents, [:machine_id], name: :agents_machine_id_index)

    create_if_not_exists index(:agents, [:organization_id, :machine_id],
                           name: :agents_org_machine_id_index,
                           where: "machine_id IS NOT NULL"
                         )
  end
end
