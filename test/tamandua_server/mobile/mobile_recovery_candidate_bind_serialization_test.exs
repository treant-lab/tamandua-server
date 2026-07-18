defmodule TamanduaServer.Mobile.MobileRecoveryCandidateBindSerializationTest do
  use TamanduaServer.DataCase, async: false

  import Ecto.Query

  alias Ecto.Adapters.SQL.Sandbox

  alias TamanduaServer.Mobile.{
    MobileDeviceIdentity,
    MobileDeviceIdentityCandidateLock,
    MobileDeviceIdentityChallenge,
    MobileDeviceIdentityKey,
    MobileDeviceIdentityRecovery
  }

  alias TamanduaServer.Repo

  @public_key_1 "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC5iM0/c6FZmhIJ1pO/PIsyQ2HqESS7LO/VAgEUL/ZFHugMKNzBWyeCKU+UMqW2ubv2/1WF/AU7vIbj+a8aw/BA=="
  @private_key_1 "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZ1B1d3lTMW90U2JsSkREczAKdGVCM2cvK3V5aWJsS3pFeWJxaGVrS3VRTktlaFJBTkNBQVFMbUl6VDl6b1ZtYUVnbldrNzg4aXpKRFllb1JKTApzczc5VUNBUlF2OWtVZTZBd28zTUZiSjRJcFQ1UXlwYmE1dS9iL1ZZWDhCVHU4aHVQNXJ4ckQ4RQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg=="

  @public_key_2 "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVQOY+nd4+5AdDbap2BrNRy1R69xuVWGeVYDEWqYER0sD/dNPX57/V08lJ38a/9FgIXWk7rXcpmLIPi5bH6NEpg=="
  @private_key_2 "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZ0pvU21MNU5xTFlUenJvd28KRXVmdy9qVVpoSDlSb2swMCtYUFA3aXFhZkN1aFJBTkNBQVJWQTVqNmQzajdrQjBOdHFuWUdzMUhMVkhyM0c1VgpZWjVWZ01SYXBnUkhTd1A5MDA5Zm52OVhUeVVuZnhyLzBXQWhkYVR1dGR5bVlzZytMbHNmbzBTbQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg=="

  @algorithm "ecdsa-p256-sha256"

  test "candidate locks deduplicate and sort keys before acquiring PostgreSQL locks" do
    organization = unboxed(fn -> insert(:organization) end)
    first = "tmdk_v1_" <> String.duplicate("a", 43)
    second = "tmdk_v1_" <> String.duplicate("b", 43)
    cleanup_organizations([organization.id])

    assert :ok =
             unboxed(fn ->
               Repo.transaction(fn ->
                 MobileDeviceIdentityCandidateLock.lock_keys(organization.id, [
                   second,
                   first,
                   second
                 ])
               end)
             end)
             |> unwrap_transaction()
  end

  test "the same candidate remains independently lockable in another tenant" do
    first_organization = unboxed(fn -> insert(:organization) end)
    second_organization = unboxed(fn -> insert(:organization) end)
    candidate = "tmdk_v1_" <> String.duplicate("t", 43)
    parent = self()
    cleanup_organizations([first_organization.id, second_organization.id])

    first =
      Task.async(fn ->
        unboxed(fn ->
          Repo.transaction(fn ->
            :ok = MobileDeviceIdentityCandidateLock.lock_keys(first_organization.id, candidate)
            send(parent, {:tenant_candidate_locked, self()})

            receive do
              :release_tenant_candidate -> :ok
            after
              2_000 -> Repo.rollback(:barrier_timeout)
            end
          end)
        end)
      end)

    assert_receive {:tenant_candidate_locked, first_pid}, 2_000

    assert :ok =
             unboxed(fn ->
               Repo.transaction(fn ->
                 MobileDeviceIdentityCandidateLock.lock_keys(second_organization.id, candidate)
               end)
             end)
             |> unwrap_transaction()

    send(first_pid, :release_tenant_candidate)
    assert Task.await(first, 2_000) == {:ok, :ok}
  end

  test "recovery-first reservation makes another installation bind lose after blocking" do
    fixture = committed_fixture(:other_installation)
    parent = self()

    recovery =
      held_public_call(parent, :recovery_committed, fn ->
        issue_recovery(fixture)
      end)

    assert_receive {:recovery_committed, recovery_pid, {:ok, %{intent: intent}}}, 2_000

    bind =
      public_call(parent, :bind_attempting, fn ->
        MobileDeviceIdentity.verify_and_bind(
          fixture.organization_id,
          fixture.candidate_proof,
          now: fixture.now
        )
      end)

    assert_receive :bind_attempting, 2_000
    assert Task.yield(bind, 100) == nil
    send(recovery_pid, :release_public_call)

    assert {:ok, {:ok, %{intent: ^intent}}} = Task.await(recovery, 2_000)
    assert Task.await(bind, 2_000) == {:error, :candidate_key_reserved}

    state = persisted_state(fixture)
    assert state.challenge.state == "pending"
    assert Enum.map(state.intents, &{&1.id, &1.state}) == [{intent.id, "pending"}]

    assert Enum.map(state.keys, &{&1.installation_id, &1.device_key_id, &1.lifecycle_state}) == [
             {fixture.recovery_installation_id, fixture.old_key_id, "active"}
           ]
  end

  test "bind-first commit makes another installation recovery lose after blocking" do
    fixture = committed_fixture(:other_installation)
    parent = self()

    bind =
      held_public_call(parent, :bind_committed, fn ->
        MobileDeviceIdentity.verify_and_bind(
          fixture.organization_id,
          fixture.candidate_proof,
          now: fixture.now
        )
      end)

    assert_receive {:bind_committed, bind_pid, {:ok, candidate_key}}, 2_000

    recovery = public_call(parent, :recovery_attempting, fn -> issue_recovery(fixture) end)
    assert_receive :recovery_attempting, 2_000
    assert Task.yield(recovery, 100) == nil
    send(bind_pid, :release_public_call)

    assert {:ok, {:ok, ^candidate_key}} = Task.await(bind, 2_000)
    assert Task.await(recovery, 2_000) == {:error, :candidate_key_binding_invalid}

    state = persisted_state(fixture)
    assert state.challenge.state == "consumed"
    assert state.intents == []

    assert MapSet.new(
             Enum.map(state.keys, &{&1.installation_id, &1.device_key_id, &1.lifecycle_state})
           ) ==
             MapSet.new([
               {fixture.recovery_installation_id, fixture.old_key_id, "active"},
               {fixture.bind_installation_id, fixture.candidate_key_id, "active"}
             ])
  end

  test "a reservation owned by the same installation permits the public rotation bind" do
    fixture = committed_fixture(:same_installation)
    parent = self()

    recovery =
      held_public_call(parent, :same_install_recovery_committed, fn ->
        issue_recovery(fixture)
      end)

    assert_receive {:same_install_recovery_committed, recovery_pid, {:ok, %{intent: intent}}},
                   2_000

    bind =
      public_call(parent, :same_install_bind_attempting, fn ->
        MobileDeviceIdentity.verify_and_bind(
          fixture.organization_id,
          fixture.candidate_proof,
          now: fixture.now
        )
      end)

    assert_receive :same_install_bind_attempting, 2_000
    assert Task.yield(bind, 100) == nil
    send(recovery_pid, :release_public_call)

    assert {:ok, {:ok, %{intent: ^intent}}} = Task.await(recovery, 2_000)
    assert {:ok, replacement} = Task.await(bind, 2_000)
    assert replacement.device_key_id == fixture.candidate_key_id

    state = persisted_state(fixture)
    assert state.challenge.state == "consumed"
    assert Enum.map(state.intents, &{&1.id, &1.state}) == [{intent.id, "pending"}]

    assert MapSet.new(Enum.map(state.keys, &{&1.device_key_id, &1.lifecycle_state})) ==
             MapSet.new([
               {fixture.old_key_id, "rotated"},
               {fixture.candidate_key_id, "active"}
             ])
  end

  test "an uncommitted recovery in one tenant does not block a public bind in another" do
    recovery_fixture = committed_fixture(:other_installation)
    bind_fixture = committed_enrollment_candidate()
    parent = self()

    recovery =
      held_public_call(parent, :tenant_recovery_committed, fn ->
        issue_recovery(recovery_fixture)
      end)

    assert_receive {:tenant_recovery_committed, recovery_pid, {:ok, %{intent: intent}}}, 2_000

    bind =
      public_call(parent, :other_tenant_bind_attempting, fn ->
        MobileDeviceIdentity.verify_and_bind(
          bind_fixture.organization_id,
          bind_fixture.candidate_proof,
          now: bind_fixture.now
        )
      end)

    assert_receive :other_tenant_bind_attempting, 2_000
    assert {:ok, key} = Task.await(bind, 2_000)
    assert key.device_key_id == bind_fixture.candidate_key_id
    refute key.device_key_id == recovery_fixture.candidate_key_id

    send(recovery_pid, :release_public_call)
    assert {:ok, {:ok, %{intent: ^intent}}} = Task.await(recovery, 2_000)

    recovery_state = persisted_state(recovery_fixture)
    bind_state = persisted_state(bind_fixture)
    assert Enum.map(recovery_state.intents, & &1.id) == [intent.id]
    assert bind_state.challenge.state == "consumed"
    assert Enum.map(bind_state.keys, & &1.device_key_id) == [bind_fixture.candidate_key_id]
  end

  test "identity validates proof before installation and candidate locks, then binds" do
    identity =
      File.read!(
        Path.expand("../../../lib/tamandua_server/mobile/mobile_device_identity.ex", __DIR__)
      )
      |> source_section("defp verify_and_bind_transaction", "defp bind_for_purpose")

    assert source_position(identity, "verify_p256_signature") <
             source_position(identity, "lock_installations")

    assert source_position(identity, "lock_installations") <
             source_position(identity, "MobileDeviceIdentityCandidateLock.lock_keys")

    assert source_position(identity, "MobileDeviceIdentityCandidateLock.lock_keys") <
             source_position(identity, "ensure_candidate_not_reserved_elsewhere")
  end

  test "recovery locks installation then candidate before barriers and insertion" do
    recovery =
      File.read!(
        Path.expand(
          "../../../lib/tamandua_server/mobile/mobile_device_identity_recovery.ex",
          __DIR__
        )
      )
      |> source_section("def issue(", "def issue(_organization_id")

    assert source_position(recovery, "lock_installation") <
             source_position(recovery, "MobileDeviceIdentityCandidateLock.lock_keys")

    assert source_position(recovery, "MobileDeviceIdentityCandidateLock.lock_keys") <
             source_position(recovery, "ensure_no_live_pending_recovery")
  end

  defp held_public_call(parent, ready_tag, callback) do
    Task.async(fn ->
      unboxed(fn ->
        Repo.transaction(fn ->
          result = callback.()
          send(parent, {ready_tag, self(), result})

          receive do
            :release_public_call -> result
          after
            2_000 -> Repo.rollback(:barrier_timeout)
          end
        end)
      end)
    end)
  end

  defp public_call(parent, attempting_tag, callback) do
    Task.async(fn ->
      unboxed(fn ->
        send(parent, attempting_tag)
        callback.()
      end)
    end)
  end

  defp issue_recovery(fixture) do
    MobileDeviceIdentityRecovery.issue(
      fixture.organization_id,
      %{
        installation_id: fixture.recovery_installation_id,
        purpose: "reconcile_rotation",
        old_device_key_id: fixture.old_key_id,
        candidate_device_key_id: fixture.candidate_key_id,
        reason: "candidate_bind_serialization_test"
      },
      now: fixture.now
    )
  end

  defp committed_fixture(relationship) do
    fixture =
      unboxed(fn ->
        organization = insert(:organization)
        suffix = System.unique_integer([:positive])
        recovery_installation_id = "tmnd-candidate-recovery-#{suffix}"
        now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

        old_issued = issue!(organization.id, recovery_installation_id, "enroll", now)

        old_proof =
          signed_proof(
            organization.id,
            old_issued,
            recovery_installation_id,
            @public_key_1,
            @private_key_1
          )

        {:ok, old_key} =
          MobileDeviceIdentity.verify_and_bind(organization.id, old_proof, now: now)

        bind_installation_id =
          if relationship == :same_installation,
            do: recovery_installation_id,
            else: "tmnd-candidate-bind-#{suffix}"

        purpose = if relationship == :same_installation, do: "rotate", else: "enroll"
        candidate_issued = issue!(organization.id, bind_installation_id, purpose, now)

        candidate_proof =
          signed_proof(
            organization.id,
            candidate_issued,
            bind_installation_id,
            @public_key_2,
            @private_key_2,
            previous_private_key:
              if(relationship == :same_installation, do: @private_key_1, else: nil)
          )

        candidate_proof =
          if relationship == :same_installation,
            do: Map.put(candidate_proof, :previous_device_key_id, old_key.device_key_id),
            else: candidate_proof

        %{
          organization_id: organization.id,
          recovery_installation_id: recovery_installation_id,
          bind_installation_id: bind_installation_id,
          old_key_id: old_key.device_key_id,
          candidate_key_id: candidate_proof.device_key_id,
          candidate_challenge_id: candidate_issued.challenge_id,
          candidate_proof: candidate_proof,
          now: now
        }
      end)

    cleanup_organizations([fixture.organization_id])
    fixture
  end

  defp committed_enrollment_candidate do
    fixture =
      unboxed(fn ->
        organization = insert(:organization)
        suffix = System.unique_integer([:positive])
        installation_id = "tmnd-candidate-tenant-bind-#{suffix}"
        now = DateTime.utc_now() |> DateTime.truncate(:microsecond)
        issued = issue!(organization.id, installation_id, "enroll", now)

        proof =
          signed_proof(
            organization.id,
            issued,
            installation_id,
            @public_key_2,
            @private_key_2
          )

        %{
          organization_id: organization.id,
          recovery_installation_id: installation_id,
          bind_installation_id: installation_id,
          candidate_key_id: proof.device_key_id,
          candidate_challenge_id: issued.challenge_id,
          candidate_proof: proof,
          now: now
        }
      end)

    cleanup_organizations([fixture.organization_id])
    fixture
  end

  defp issue!(organization_id, installation_id, purpose, now) do
    {:ok, issued} =
      MobileDeviceIdentity.issue_challenge(
        organization_id,
        %{installation_id: installation_id, platform: "android", purpose: purpose},
        now: now
      )

    issued
  end

  defp signed_proof(
         organization_id,
         issued,
         installation_id,
         public_key_base64,
         private_key_base64,
         opts \\ []
       ) do
    challenge = Repo.get!(MobileDeviceIdentityChallenge, issued.challenge_id)
    spki = Base.decode64!(public_key_base64)
    device_key_id = MobileDeviceIdentity.derive_device_key_id(organization_id, spki)

    payload =
      MobileDeviceIdentity.canonical_payload(
        challenge,
        issued.challenge,
        device_key_id,
        @algorithm
      )

    proof = %{
      challenge_id: issued.challenge_id,
      challenge: issued.challenge,
      installation_id: installation_id,
      platform: "android",
      purpose: challenge.purpose,
      key_scope_id: issued.key_scope_id,
      algorithm: @algorithm,
      public_key_spki: base64url(spki),
      device_key_id: device_key_id,
      signature:
        base64url(:public_key.sign(payload, :sha256, decode_private_key(private_key_base64)))
    }

    case Keyword.get(opts, :previous_private_key) do
      nil ->
        proof

      previous_private_key ->
        Map.put(
          proof,
          :previous_signature,
          base64url(:public_key.sign(payload, :sha256, decode_private_key(previous_private_key)))
        )
    end
  end

  defp persisted_state(fixture) do
    unboxed(fn ->
      %{
        challenge: Repo.get!(MobileDeviceIdentityChallenge, fixture.candidate_challenge_id),
        intents:
          MobileDeviceIdentityRecovery
          |> where([intent], intent.organization_id == ^fixture.organization_id)
          |> order_by([intent], asc: intent.inserted_at, asc: intent.id)
          |> Repo.all(),
        keys:
          MobileDeviceIdentityKey
          |> where([key], key.organization_id == ^fixture.organization_id)
          |> order_by([key], asc: key.activated_at, asc: key.id)
          |> Repo.all()
      }
    end)
  end

  defp cleanup_organizations(organization_ids) do
    on_exit(fn ->
      unboxed(fn ->
        Repo.delete_all(
          from(organization in TamanduaServer.Accounts.Organization,
            where: organization.id in ^organization_ids
          )
        )
      end)
    end)
  end

  defp decode_private_key(encoded) do
    encoded
    |> Base.decode64!()
    |> :public_key.pem_decode()
    |> hd()
    |> :public_key.pem_entry_decode()
  end

  defp base64url(value), do: Base.url_encode64(value, padding: false)
  defp unwrap_transaction({:ok, value}), do: value
  defp unboxed(callback), do: Sandbox.unboxed_run(Repo, callback)

  defp source_section(source, start_marker, end_marker) do
    [_before, after_start] = String.split(source, start_marker, parts: 2)
    [section, _after] = String.split(after_start, end_marker, parts: 2)
    section
  end

  defp source_position(source, marker) do
    {position, _length} = :binary.match(source, marker)
    position
  end
end
