defmodule TamanduaServer.Mobile.MobileDeviceIdentityRecoveryTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Mobile.{
    MobileDeviceIdentityChallenge,
    MobileDeviceIdentityKey,
    MobileDeviceIdentityRecovery
  }

  alias TamanduaServer.Repo

  @old_key_id "tmdk_v1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  @candidate_key_id "tmdk_v1_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

  setup do
    organization = insert(:organization)
    user = insert(:user, organization_id: organization.id)
    {:ok, organization: organization, user: user}
  end

  test "stores only a digest and binds server-owned authorization policy", %{
    organization: organization,
    user: user
  } do
    insert_identity_key(organization.id, "recover-install-1", @old_key_id, "active")

    assert {:ok, %{intent: intent, recovery_token: token}} =
             MobileDeviceIdentityRecovery.issue(
               organization.id,
               %{
                 installation_id: "recover-install-1",
                 purpose: "rebind",
                 old_device_key_id: @old_key_id,
                 candidate_device_key_id: @candidate_key_id,
                 reason: "local_key_lost",
                 state: "consumed",
                 authorization_state: "authorized",
                 step_up_required: false
               },
               requested_by_id: user.id,
               authorization_provenance: %{
                 "actor_user_id" => Ecto.UUID.generate(),
                 "authentication_source" => "test_session",
                 "requested_via" => "recovery_test",
                 "step_up_evidence" => "verified",
                 "client_authorized" => true
               }
             )

    assert byte_size(Base.url_decode64!(token, padding: false)) == 32
    assert intent.token_digest ==
             :crypto.hash(
               :sha256,
               "tamandua.mobile.identity-recovery-token/v1" <> <<0>> <> token
             )
    refute intent.token_digest == token
    assert intent.state == "pending"
    assert intent.authorization_state == "pending_authorization"
    assert intent.step_up_required
    assert intent.authorization_provenance["actor_user_id"] == user.id
    assert intent.authorization_provenance["step_up_evidence"] == "not_verified"
    refute Map.has_key?(intent.authorization_provenance, "client_authorized")
  end

  test "reconciliation consumes once when the old key remains active and never mutates keys", %{
    organization: organization
  } do
    key = insert_identity_key(organization.id, "recover-install-2", @old_key_id, "active")
    key_snapshot = identity_key_snapshot(key)

    assert {:ok, %{intent: intent, recovery_token: token}} =
             issue_reconciliation(organization.id, "recover-install-2")

    assert {:ok, resolved} =
             MobileDeviceIdentityRecovery.resolve(organization.id, intent.id, token)

    assert resolved.state == "consumed"
    assert resolved.resolution == "previous_key_confirmed"
    assert resolved.token_consumed_at
    assert identity_key_snapshot(Repo.get!(MobileDeviceIdentityKey, key.id)) == key_snapshot

    assert {:error, :intent_unavailable} =
             MobileDeviceIdentityRecovery.resolve(organization.id, intent.id, token)
  end

  test "reconciliation confirms a committed replacement without changing either key", %{
    organization: organization
  } do
    old = insert_identity_key(organization.id, "recover-install-3", @old_key_id, "rotated")

    candidate =
      insert_identity_key(
        organization.id,
        "recover-install-3",
        @candidate_key_id,
        "active"
      )

    snapshots = Enum.map([old, candidate], &identity_key_snapshot/1)

    assert {:ok, %{intent: intent, recovery_token: token}} =
             issue_reconciliation(organization.id, "recover-install-3")

    assert {:ok, resolved} =
             MobileDeviceIdentityRecovery.resolve(organization.id, intent.id, token)

    assert resolved.state == "consumed"
    assert resolved.resolution == "replacement_key_confirmed"

    assert Enum.map([old, candidate], fn key ->
             MobileDeviceIdentityKey |> Repo.get!(key.id) |> identity_key_snapshot()
           end) == snapshots
  end

  test "unknown active state is denied and cannot activate or delete a key", %{
    organization: organization
  } do
    old = insert_identity_key(organization.id, "recover-install-4", @old_key_id, "revoked")

    assert {:ok, %{intent: intent, recovery_token: token}} =
             issue_reconciliation(organization.id, "recover-install-4")

    assert {:ok, denied} =
             MobileDeviceIdentityRecovery.resolve(organization.id, intent.id, token)

    assert denied.state == "denied"
    assert denied.resolution == "active_key_unknown"
    assert Repo.get!(MobileDeviceIdentityKey, old.id).lifecycle_state == "revoked"
    assert Repo.aggregate(MobileDeviceIdentityKey, :count) == 1
  end

  test "rebind consumes the bearer token but remains pending authorization", %{
    organization: organization
  } do
    insert_identity_key(organization.id, "recover-install-5", @old_key_id, "active")

    assert {:ok, %{intent: intent, recovery_token: token}} =
             MobileDeviceIdentityRecovery.issue(organization.id, %{
               installation_id: "recover-install-5",
               purpose: "rebind",
               old_device_key_id: @old_key_id,
               candidate_device_key_id: @candidate_key_id,
               reason: "key_store_reset"
             })

    assert {:ok, pending} =
             MobileDeviceIdentityRecovery.resolve(organization.id, intent.id, token)

    assert pending.state == "pending"
    assert pending.authorization_state == "pending_authorization"
    assert pending.step_up_required
    assert pending.token_consumed_at

    assert {:error, :intent_unavailable} =
             MobileDeviceIdentityRecovery.resolve(organization.id, intent.id, token)

    assert Repo.one!(from key in MobileDeviceIdentityKey, select: key.device_key_id) == @old_key_id
  end

  test "invalid token is non-destructive and expiry is persisted", %{organization: organization} do
    now = ~U[2026-07-15 20:00:00.000000Z]
    insert_identity_key(organization.id, "recover-install-6", @old_key_id, "active")

    assert {:ok, %{intent: intent, recovery_token: token}} =
             MobileDeviceIdentityRecovery.issue(
               organization.id,
               %{
                 installation_id: "recover-install-6",
                 purpose: "reconcile_rotation",
                 old_device_key_id: @old_key_id,
                 candidate_device_key_id: @candidate_key_id,
                 reason: "response_lost"
               },
               now: now,
               ttl_seconds: 60
             )

    assert {:error, :invalid_recovery_token} =
             MobileDeviceIdentityRecovery.resolve(organization.id, intent.id, token <> "x",
               now: DateTime.add(now, 30, :second)
             )

    assert Repo.get!(MobileDeviceIdentityRecovery, intent.id).token_consumed_at == nil

    assert {:error, :intent_expired} =
             MobileDeviceIdentityRecovery.status(organization.id, intent.id,
               now: DateTime.add(now, 60, :second)
             )

    expired = Repo.get!(MobileDeviceIdentityRecovery, intent.id)
    assert expired.state == "expired"
    assert expired.expired_at
  end

  test "reconciliation source uses the same installation lock domain as the identity protocol" do
    recovery_source = File.read!("lib/tamandua_server/mobile/mobile_device_identity_recovery.ex")
    identity_source = File.read!("lib/tamandua_server/mobile/mobile_device_identity.ex")

    assert recovery_source =~
             ~s(@installation_lock_domain "tamandua.mobile.installation-lock/v1")

    assert identity_source =~
             ~s(@installation_lock_domain "tamandua.mobile.installation-lock/v1")

    assert recovery_source =~ "SELECT pg_advisory_xact_lock($1, $2)"
    assert recovery_source =~
             ":ok = lock_installation(intent.organization_id, intent.installation_id)"
  end

  defp issue_reconciliation(organization_id, installation_id) do
    MobileDeviceIdentityRecovery.issue(organization_id, %{
      installation_id: installation_id,
      purpose: "reconcile_rotation",
      old_device_key_id: @old_key_id,
      candidate_device_key_id: @candidate_key_id,
      reason: "rotation_response_lost"
    })
  end

  defp insert_identity_key(organization_id, installation_id, device_key_id, lifecycle_state) do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    challenge =
      %MobileDeviceIdentityChallenge{}
      |> MobileDeviceIdentityChallenge.changeset(%{
        organization_id: organization_id,
        installation_id: installation_id,
        platform: "android",
        purpose: "enroll",
        key_scope_id: "tmdks_v1_recovery_test_scope",
        challenge_digest: :crypto.strong_rand_bytes(32),
        state: "consumed",
        issued_at: now,
        expires_at: DateTime.add(now, 300, :second),
        consumed_at: now
      })
      |> Repo.insert!()

    %MobileDeviceIdentityKey{}
    |> MobileDeviceIdentityKey.changeset(%{
      organization_id: organization_id,
      proof_challenge_id: challenge.id,
      installation_id: installation_id,
      platform: "android",
      key_scope_id: "tmdks_v1_recovery_test_scope",
      device_key_id: device_key_id,
      public_key_spki: :crypto.strong_rand_bytes(91),
      algorithm: "ecdsa-p256-sha256",
      proof_state: "verified",
      attestation_state: "present_unverified",
      lifecycle_state: lifecycle_state,
      activated_at: now,
      last_proof_at: now,
      revoked_at: if(lifecycle_state == "revoked", do: now),
      rotated_at: if(lifecycle_state == "rotated", do: now)
    })
    |> Repo.insert!()
  end

  defp identity_key_snapshot(key) do
    Map.take(key, [
      :id,
      :device_key_id,
      :lifecycle_state,
      :public_key_spki,
      :activated_at,
      :revoked_at,
      :rotated_at
    ])
  end
end
