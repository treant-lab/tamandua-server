defmodule TamanduaServer.Repo.Migrations.SplitGlobalAndTenantIocUniqueness do
  use Ecto.Migration

  def up do
    drop_if_exists(
      index(:iocs, [:type, :value], name: :iocs_type_value_unique_index)
    )

    create_if_not_exists(
      unique_index(:iocs, [:type, :value, :organization_id],
        name: :iocs_type_value_organization_id_index
      )
    )

    create_if_not_exists(
      unique_index(:iocs, [:type, :value],
        where: "organization_id IS NULL",
        name: :iocs_global_type_value_unique_index
      )
    )
  end

  def down do
    drop_if_exists(
      index(:iocs, [:type, :value], name: :iocs_global_type_value_unique_index)
    )

    # If global and tenant-private overrides with the same key were created,
    # this statement fails transactionally instead of discarding either row.
    create_if_not_exists(
      unique_index(:iocs, [:type, :value], name: :iocs_type_value_unique_index)
    )
  end
end
