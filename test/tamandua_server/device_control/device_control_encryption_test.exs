defmodule TamanduaServer.DeviceControlEncryptionTest do
  @moduledoc """
  Tests for the real encryption-posture counts in DeviceControl
  (previously hardcoded to 0, which presented an unknown state as
  "zero encrypted devices").
  """

  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.DeviceControl
  alias TamanduaServer.Mobile.Device

  defp insert_device!(org, device_id, encryption_enabled) do
    %Device{}
    |> Device.changeset(%{
      organization_id: org.id,
      device_id: device_id,
      platform: "android",
      encryption_enabled: encryption_enabled
    })
    |> Repo.insert!()
  end

  test "count_agents_with_encryption/0 counts only devices reporting encryption enabled" do
    org = insert!(:organization)

    insert_device!(org, "enc-1", true)
    insert_device!(org, "enc-2", true)
    insert_device!(org, "unenc-1", false)
    insert_device!(org, "unknown-1", nil)

    assert DeviceControl.count_agents_with_encryption() == 2
  end

  test "count_unencrypted_devices/0 counts only devices explicitly reporting no encryption" do
    org = insert!(:organization)

    insert_device!(org, "enc-1", true)
    insert_device!(org, "unenc-1", false)
    insert_device!(org, "unenc-2", false)
    # Never-reported state must not be assumed unencrypted
    insert_device!(org, "unknown-1", nil)

    assert DeviceControl.count_unencrypted_devices() == 2
  end

  test "returns 0 (a real measurement) when there are no devices" do
    assert DeviceControl.count_agents_with_encryption() == 0
    assert DeviceControl.count_unencrypted_devices() == 0
  end
end
