defmodule TamanduaServer.Mobile.AppGuardReplayGuardTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Mobile.AppGuardReplayGuard

  @fallback_table :tamandua_app_guard_replay_reservations

  setup do
    previous_store = Application.get_env(:tamandua_server, :app_guard_replay_reservation_store)

    Application.put_env(:tamandua_server, :app_guard_replay_reservation_store, :ets)
    delete_fallback_table()

    on_exit(fn ->
      delete_fallback_table()
      stop_fallback_owner()

      if is_nil(previous_store) do
        Application.delete_env(:tamandua_server, :app_guard_replay_reservation_store)
      else
        Application.put_env(:tamandua_server, :app_guard_replay_reservation_store, previous_store)
      end
    end)

    :ok
  end

  test "ETS fallback reserves signed App Guard values once per organization and key" do
    organization_id = Ecto.UUID.generate()

    assert AppGuardReplayGuard.reserve_signed_value(
             organization_id,
             "test-key",
             "payload_sha256",
             String.duplicate("a", 64),
             300
           ) == :reserved

    assert AppGuardReplayGuard.reserve_signed_value(
             organization_id,
             "test-key",
             "payload_sha256",
             String.duplicate("a", 64),
             300
           ) == :duplicate

    assert AppGuardReplayGuard.reserve_signed_value(
             organization_id,
             "test-key",
             "nonce",
             "nonce-1",
             300
           ) == :reserved
  end

  test "ETS fallback reserves App Guard event IDs once" do
    organization_id = Ecto.UUID.generate()

    assert AppGuardReplayGuard.reserve_event_id(organization_id, "evt-ets-replay-1") == :reserved
    assert AppGuardReplayGuard.reserve_event_id(organization_id, "evt-ets-replay-1") == :duplicate
  end

  test "persistent store reserves signed values by organization, key, type, and value" do
    Application.put_env(:tamandua_server, :app_guard_replay_reservation_store, :db)

    organization = insert(:organization)
    other_organization = insert(:organization)
    value = String.duplicate("b", 64)

    assert AppGuardReplayGuard.reserve_signed_value(
             organization.id,
             "signing-key-1",
             "payload_sha256",
             value,
             300
           ) == :reserved

    assert AppGuardReplayGuard.reserve_signed_value(
             organization.id,
             "signing-key-1",
             "payload_sha256",
             value,
             300
           ) == :duplicate

    assert AppGuardReplayGuard.reserve_signed_value(
             other_organization.id,
             "signing-key-1",
             "payload_sha256",
             value,
             300
           ) == :reserved

    assert AppGuardReplayGuard.reserve_signed_value(
             organization.id,
             "signing-key-2",
             "payload_sha256",
             value,
             300
           ) == :reserved

    assert AppGuardReplayGuard.reserve_signed_value(
             organization.id,
             "signing-key-1",
             "nonce",
             value,
             300
           ) == :reserved

    assert replay_reservation_count(value) == 4
  end

  test "persistent store prunes expired reservations before reserving" do
    Application.put_env(:tamandua_server, :app_guard_replay_reservation_store, :db)

    organization = insert(:organization)

    assert AppGuardReplayGuard.reserve_signed_value(
             organization.id,
             "signing-key-expired",
             "payload_sha256",
             String.duplicate("c", 64),
             -1
           ) == :reserved

    assert AppGuardReplayGuard.reserve_signed_value(
             organization.id,
             "signing-key-expired",
             "payload_sha256",
             String.duplicate("c", 64),
             300
           ) == :reserved

    assert replay_reservation_count(String.duplicate("c", 64)) == 1
  end

  defp delete_fallback_table do
    case :ets.whereis(@fallback_table) do
      :undefined -> :ok
      _table -> :ets.delete(@fallback_table)
    end
  end

  defp stop_fallback_owner do
    case Process.whereis(AppGuardReplayGuard) do
      nil -> :ok
      pid -> GenServer.stop(pid)
    end
  end

  defp replay_reservation_count(value) do
    %{rows: [[count]]} =
      Repo.query!(
        """
        SELECT count(*)
        FROM app_guard_replay_reservations
        WHERE reservation_value = $1
        """,
        [value]
      )

    count
  end
end
