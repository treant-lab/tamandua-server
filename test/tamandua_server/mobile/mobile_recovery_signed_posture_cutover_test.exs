defmodule TamanduaServer.Mobile.MobileRecoverySignedPostureCutoverTest do
  use TamanduaServer.DataCase, async: false

  alias Ecto.Adapters.SQL.Sandbox

  alias TamanduaServer.Mobile.{
    MobileDeviceIdentityChallenge,
    MobileDeviceIdentityKey,
    MobileDeviceIdentityRecovery,
    MobileSignedPostureIngestion
  }

  alias TamanduaServer.Repo

  @lock_domain "tamandua.mobile.installation-lock/v1"
  @old_key_id "tmdk_v1_" <> String.duplicate("o", 43)
  @candidate_key_id "tmdk_v1_" <> String.duplicate("c", 43)

  setup do
    fixture = committed_identity_fixture()

    on_exit(fn ->
      unboxed(fn ->
        Repo.delete_all(
          from(o in TamanduaServer.Accounts.Organization,
            where: o.id == ^fixture.organization_id
          )
        )
      end)
    end)

    %{fixture: fixture}
  end

  test "recovery issue waits for the canonical installation transaction lock", %{
    fixture: fixture
  } do
    parent = self()

    locker =
      Task.async(fn ->
        unboxed(fn ->
          Repo.transaction(fn ->
            lock_installation(fixture.organization_id, fixture.installation_id)
            send(parent, {:installation_locked, self()})

            receive do
              :release_installation -> :ok
            after
              2_000 -> Repo.rollback(:barrier_timeout)
            end
          end)
        end)
      end)

    assert_receive {:installation_locked, locker_pid}, 2_000

    issuer =
      Task.async(fn ->
        unboxed(fn -> issue_recovery(fixture) end)
      end)

    assert Task.yield(issuer, 100) == nil
    send(locker_pid, :release_installation)

    assert Task.await(locker, 2_000) == {:ok, :ok}
    assert {:ok, %{intent: intent, recovery_token: token}} = Task.await(issuer, 2_000)
    assert intent.organization_id == fixture.organization_id
    assert is_binary(token)
  end

  test "committed recovery cutover makes signed posture issuance fail closed", %{
    fixture: fixture
  } do
    parent = self()

    recovery =
      Task.async(fn ->
        unboxed(fn ->
          Repo.transaction(fn ->
            result = issue_recovery(fixture)
            send(parent, {:recovery_issued_uncommitted, self(), result})

            receive do
              :commit_recovery -> result
            after
              2_000 -> Repo.rollback(:barrier_timeout)
            end
          end)
        end)
      end)

    assert_receive {:recovery_issued_uncommitted, recovery_pid, {:ok, %{}}}, 2_000

    posture_issue =
      Task.async(fn ->
        unboxed(fn ->
          MobileSignedPostureIngestion.issue(
            fixture.organization_id,
            fixture.installation_id
          )
        end)
      end)

    assert Task.yield(posture_issue, 100) == nil
    send(recovery_pid, :commit_recovery)

    assert {:ok, {:ok, %{intent: _intent, recovery_token: _token}}} =
             Task.await(recovery, 2_000)

    assert Task.await(posture_issue, 2_000) == {:error, :identity_recovery_in_progress}
  end

  defp issue_recovery(fixture) do
    MobileDeviceIdentityRecovery.issue(fixture.organization_id, %{
      installation_id: fixture.installation_id,
      purpose: "reconcile_rotation",
      old_device_key_id: @old_key_id,
      candidate_device_key_id: @candidate_key_id,
      reason: "signed_posture_cutover_test"
    })
  end

  defp committed_identity_fixture do
    unboxed(fn ->
      organization = insert(:organization)
      installation_id = "tmnd-recovery-cutover-#{System.unique_integer([:positive])}"
      now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

      challenge =
        Repo.insert!(%MobileDeviceIdentityChallenge{
          organization_id: organization.id,
          installation_id: installation_id,
          platform: "android",
          purpose: "enroll",
          key_scope_id: "tmdks_v1_" <> String.duplicate("s", 43),
          challenge_digest: :crypto.hash(:sha256, installation_id),
          state: "consumed",
          issued_at: now,
          expires_at: DateTime.add(now, 300, :second),
          consumed_at: now
        })

      Repo.insert!(%MobileDeviceIdentityKey{
        organization_id: organization.id,
        proof_challenge_id: challenge.id,
        installation_id: installation_id,
        platform: "android",
        key_scope_id: "tmdks_v1_" <> String.duplicate("s", 43),
        device_key_id: @old_key_id,
        public_key_spki: <<1>>,
        algorithm: "ecdsa-p256-sha256",
        proof_state: "verified",
        attestation_state: "not_requested",
        lifecycle_state: "active",
        activated_at: now,
        last_proof_at: now
      })

      %{organization_id: organization.id, installation_id: installation_id}
    end)
  end

  defp lock_installation(organization_id, installation_id) do
    <<first::signed-32, second::signed-32, _::binary>> =
      :crypto.hash(
        :sha256,
        @lock_domain <> <<0>> <> organization_id <> <<0>> <> installation_id
      )

    Repo.query!("SELECT pg_advisory_xact_lock($1, $2)", [first, second])
  end

  defp unboxed(callback), do: Sandbox.unboxed_run(Repo, callback)
end
