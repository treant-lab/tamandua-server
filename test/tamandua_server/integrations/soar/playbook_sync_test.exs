defmodule TamanduaServer.Integrations.SOAR.PlaybookSyncTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.Integrations.SOAR.PlaybookSync

  setup do
    start_supervised!(PlaybookSync)
    :ok
  end

  test "tenant-sensitive metadata APIs fail closed without scope" do
    assert {:error, :tenant_required} = PlaybookSync.get_conflicts()

    assert {:error, :tenant_required} =
             PlaybookSync.get_version_info(Ecto.UUID.generate())

    assert {:error, :tenant_required} =
             PlaybookSync.resolve_conflict("missing", :keep_local)
  end

  test "conflict listing is partitioned by explicit organization scope" do
    scope = {:organization, Ecto.UUID.generate()}
    assert {:ok, []} = PlaybookSync.get_conflicts(scope)
  end
end
