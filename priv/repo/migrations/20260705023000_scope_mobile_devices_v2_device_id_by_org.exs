defmodule TamanduaServer.Repo.Migrations.ScopeMobileDevicesV2DeviceIdByOrg do
  use Ecto.Migration

  def up do
    drop_if_exists index(:mobile_devices_v2, [:device_id],
                     name: :mobile_devices_v2_device_id_index
                   )

    create unique_index(:mobile_devices_v2, [:organization_id, :device_id],
             name: :mobile_devices_v2_organization_id_device_id_index
           )
  end

  def down do
    drop_if_exists index(:mobile_devices_v2, [:organization_id, :device_id],
                     name: :mobile_devices_v2_organization_id_device_id_index
                   )

    create unique_index(:mobile_devices_v2, [:device_id],
             name: :mobile_devices_v2_device_id_index
           )
  end
end
