defmodule TamanduaServer.Mobile.MobileRecoveryExpiryBarrierTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Mobile.MobileDeviceIdentityRecovery
  alias TamanduaServer.Repo

  @now ~U[2026-07-16 12:00:00.000000Z]

  test "persists expiry at the exact server-time boundary before allowing posture" do
    organization = insert(:organization)
    installation_id = installation_id("boundary")
    intent = insert_pending(organization.id, installation_id, @now)

    assert :ok =
             Repo.transaction(fn ->
               lock_installation(organization.id, installation_id)

               MobileDeviceIdentityRecovery.enforce_signed_posture_barrier(
                 organization.id,
                 installation_id,
                 @now
               )
             end)
             |> unwrap_transaction()

    expired = Repo.get!(MobileDeviceIdentityRecovery, intent.id)
    assert expired.state == "expired"
    assert expired.expired_at == @now
    assert expired.last_checked_at == @now
  end

  test "rolls stale expiry back when the enclosing posture decision fails" do
    organization = insert(:organization)
    installation_id = installation_id("rollback")
    stale = insert_pending(organization.id, installation_id, DateTime.add(@now, -1, :second))

    assert {:error, :posture_failed_after_expiry} =
             Repo.transaction(fn ->
               lock_installation(organization.id, installation_id)

               assert :ok =
                        MobileDeviceIdentityRecovery.enforce_signed_posture_barrier(
                          organization.id,
                          installation_id,
                          @now
                        )

               Repo.rollback(:posture_failed_after_expiry)
             end)

    assert Repo.get!(MobileDeviceIdentityRecovery, stale.id).state == "pending"
  end

  test "rolls an expired lease back when later posture work fails" do
    organization = insert(:organization)
    installation_id = installation_id("posture-rollback")
    stale = insert_pending(organization.id, installation_id, @now)

    assert {:error, :posture_failed} =
             Repo.transaction(fn ->
               lock_installation(organization.id, installation_id)

               assert :ok =
                        MobileDeviceIdentityRecovery.enforce_signed_posture_barrier(
                          organization.id,
                          installation_id,
                          @now
                        )

               Repo.rollback(:posture_failed)
             end)

    persisted = Repo.get!(MobileDeviceIdentityRecovery, stale.id)
    assert persisted.state == "pending"
    assert is_nil(persisted.expired_at)
    assert is_nil(persisted.last_checked_at)
  end

  test "blocks before expiry and rejects a missing server time" do
    organization = insert(:organization)
    installation_id = installation_id("live")
    insert_pending(organization.id, installation_id, DateTime.add(@now, 1, :microsecond))

    assert {:error, :identity_recovery_in_progress} =
             Repo.transaction(fn ->
               lock_installation(organization.id, installation_id)

               case MobileDeviceIdentityRecovery.enforce_signed_posture_barrier(
                      organization.id,
                      installation_id,
                      @now
                    ) do
                 :ok -> :ok
                 {:error, reason} -> Repo.rollback(reason)
               end
             end)

    assert {:error, :invalid_server_time} =
             MobileDeviceIdentityRecovery.enforce_signed_posture_barrier(
               organization.id,
               installation_id,
               nil
             )
  end

  test "reconciliation resolves in canonical installation-lock then row-lock order" do
    source = File.read!("lib/tamandua_server/mobile/mobile_device_identity_recovery.ex")

    resolve =
      source
      |> String.split("def resolve(", parts: 2)
      |> List.last()
      |> String.split("defp resolve_intent", parts: 2)
      |> List.first()

    locator_position = position!(resolve, "intent_locator(organization_id, intent_id)")

    installation_lock_position =
      position!(resolve, "lock_installation(organization_id, installation_id)")

    row_lock_position = position!(resolve, "locked_intent(organization_id, intent_id)")

    assert locator_position < installation_lock_position
    assert installation_lock_position < row_lock_position
  end

  defp insert_pending(organization_id, installation_id, expires_at) do
    suffix = System.unique_integer([:positive]) |> Integer.to_string()

    Repo.insert!(%MobileDeviceIdentityRecovery{
      organization_id: organization_id,
      installation_id: installation_id,
      purpose: "reconcile_rotation",
      state: "pending",
      old_device_key_id: "tmdk_v1_" <> String.duplicate("o", 43),
      candidate_device_key_id: "tmdk_v1_" <> String.duplicate("c", 43),
      reason: "expiry_barrier_test",
      token_digest: :crypto.hash(:sha256, installation_id <> suffix),
      step_up_required: false,
      authorization_state: "not_required",
      authorization_provenance: %{},
      issued_at: DateTime.add(expires_at, -60, :second),
      expires_at: expires_at
    })
  end

  defp lock_installation(organization_id, installation_id) do
    <<first::signed-32, second::signed-32, _::binary>> =
      :crypto.hash(
        :sha256,
        "tamandua.mobile.installation-lock/v1" <>
          <<0>> <> organization_id <> <<0>> <> installation_id
      )

    Repo.query!("SELECT pg_advisory_xact_lock($1, $2)", [first, second])
    :ok
  end

  defp unwrap_transaction({:ok, value}), do: value
  defp position!(source, needle), do: source |> :binary.match(needle) |> elem(0)

  defp installation_id(label),
    do: "tmnd-recovery-expiry-#{label}-#{System.unique_integer([:positive])}"
end
