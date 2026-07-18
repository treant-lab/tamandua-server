defmodule TamanduaServer.Mobile.MobileSignedPostureIngestionTest do
  use TamanduaServer.DataCase, async: false

  alias Ecto.Adapters.SQL.Sandbox

  alias TamanduaServer.Mobile.{
    MobileDeviceIdentity,
    MobileDeviceIdentityChallenge,
    MobileDeviceIdentityKey,
    MobileDeviceIdentityRecovery,
    MobileSignedPostureIngestion,
    MobileSignedPostureProjection,
    MobileSignedPostureReceipt,
    MobileSignedPostureRequest,
    SignedPosture
  }

  alias TamanduaServer.Repo

  @now ~U[2026-07-16 12:00:00.000000Z]

  test "persists only domain-separated binding digests and redacts unavailable status" do
    %{organization: organization} = identity_fixture("tmnd-signed-posture-hash")

    assert {:ok, issued} =
             MobileSignedPostureIngestion.issue(organization.id, "tmnd-signed-posture-hash",
               now: @now
             )

    request = Repo.one!(MobileSignedPostureRequest)

    refute inspect(request) =~ issued.request_id
    refute inspect(request) =~ issued.challenge_id
    refute inspect(request) =~ issued.nonce
    assert byte_size(request.request_id_digest) == 32
    assert byte_size(request.challenge_id_digest) == 32
    assert byte_size(request.nonce_digest) == 32

    assert {:ok, %{state: "pending"} = status} =
             MobileSignedPostureIngestion.request_status(organization.id, issued.request_id,
               now: @now
             )

    assert status == %{state: "pending"}

    assert {:ok, %{state: "unavailable"}} =
             MobileSignedPostureIngestion.request_status(organization.id, issued.request_id,
               now: DateTime.add(@now, 300, :second)
             )

    assert {:ok, %{state: "unavailable"}} =
             MobileSignedPostureIngestion.request_status(organization.id, Ecto.UUID.generate())
  end

  test "verifies once and atomically creates receipt and projection" do
    fixture = identity_fixture("tmnd-signed-posture-once")

    {:ok, issued} =
      MobileSignedPostureIngestion.issue(fixture.organization.id, fixture.installation_id,
        now: @now
      )

    {envelope, posture} = signed_submission(fixture, issued)

    assert {:ok, %{receipt: receipt, projection: projection}} =
             MobileSignedPostureIngestion.verify(fixture.organization.id, envelope, posture,
               now: DateTime.add(@now, 1, :second)
             )

    assert receipt.id == projection.receipt_id
    assert Repo.aggregate(MobileSignedPostureReceipt, :count) == 1
    assert Repo.aggregate(MobileSignedPostureProjection, :count) == 1
    assert Repo.one!(MobileSignedPostureRequest).state == "consumed"

    assert {:error, :request_unavailable} =
             MobileSignedPostureIngestion.verify(fixture.organization.id, envelope, posture,
               now: DateTime.add(@now, 2, :second)
             )

    assert {:ok, %{state: "unavailable"}} =
             MobileSignedPostureIngestion.request_status(
               fixture.organization.id,
               issued.request_id,
               now: DateTime.add(@now, 2, :second)
             )
  end

  test "fails closed for tenant, expiry, key changes, recovery, and signature while rolling back" do
    fixture = identity_fixture("tmnd-signed-posture-negative")
    other = insert(:organization)

    {:ok, issued} =
      MobileSignedPostureIngestion.issue(fixture.organization.id, fixture.installation_id,
        now: @now
      )

    {envelope, posture} = signed_submission(fixture, issued)

    assert {:error, :request_unavailable} =
             MobileSignedPostureIngestion.verify(other.id, envelope, posture, now: @now)

    assert {:error, :request_expired} =
             MobileSignedPostureIngestion.verify(fixture.organization.id, envelope, posture,
               now: DateTime.add(@now, 301, :second)
             )

    bad_signature =
      put_in(
        envelope["signature"],
        Base.url_encode64(<<48, 6, 2, 1, 0, 2, 1, 1>>, padding: false)
      )

    assert {:error, :invalid_signature} =
             MobileSignedPostureIngestion.verify(fixture.organization.id, bad_signature, posture,
               now: DateTime.add(@now, 1, :second)
             )

    assert Repo.one!(MobileSignedPostureRequest).state == "pending"
    assert Repo.aggregate(MobileSignedPostureReceipt, :count) == 0

    changed_key = "tmdk_v1_" <> String.duplicate("z", 43)
    fixture.key |> Ecto.Changeset.change(device_key_id: changed_key) |> Repo.update!()

    assert {:error, :active_identity_changed} =
             MobileSignedPostureIngestion.verify(fixture.organization.id, envelope, posture,
               now: DateTime.add(@now, 1, :second)
             )

    fixture.key |> Ecto.Changeset.change(device_key_id: fixture.device_key_id) |> Repo.update!()
    insert_pending_recovery(fixture)

    assert {:error, :identity_recovery_in_progress} =
             MobileSignedPostureIngestion.verify(fixture.organization.id, envelope, posture,
               now: DateTime.add(@now, 1, :second)
             )
  end

  test "twenty concurrent verifies commit exactly once" do
    Sandbox.mode(Repo, {:shared, self()})
    fixture = identity_fixture("tmnd-signed-posture-race")

    {:ok, issued} =
      MobileSignedPostureIngestion.issue(fixture.organization.id, fixture.installation_id,
        now: @now
      )

    {envelope, posture} = signed_submission(fixture, issued)

    results =
      1..20
      |> Task.async_stream(
        fn _ ->
          MobileSignedPostureIngestion.verify(fixture.organization.id, envelope, posture,
            now: DateTime.add(@now, 1, :second)
          )
        end,
        max_concurrency: 20,
        ordered: false,
        timeout: 30_000,
        on_timeout: :kill_task
      )
      |> Enum.map(fn
        {:ok, result} -> result
        {:exit, reason} -> flunk("concurrent verify task exited: #{inspect(reason)}")
      end)

    assert Enum.count(results, &match?({:ok, _}, &1)) == 1
    assert Enum.all?(results, &(match?({:ok, _}, &1) or &1 == {:error, :request_unavailable}))
    assert Repo.aggregate(MobileSignedPostureReceipt, :count) == 1
    assert Repo.aggregate(MobileSignedPostureProjection, :count) == 1
  end

  defp identity_fixture(installation_id) do
    organization = insert(:organization)
    {private_key, spki} = p256_keypair()
    device_key_id = MobileDeviceIdentity.derive_device_key_id(organization.id, spki)
    key_scope_id = "tmdks_v1_" <> String.duplicate("s", 43)

    challenge =
      Repo.insert!(%MobileDeviceIdentityChallenge{
        organization_id: organization.id,
        installation_id: installation_id,
        platform: "android",
        purpose: "enroll",
        key_scope_id: key_scope_id,
        challenge_digest: :crypto.hash(:sha256, "fixture"),
        state: "consumed",
        issued_at: @now,
        expires_at: DateTime.add(@now, 300, :second),
        consumed_at: @now
      })

    key =
      Repo.insert!(%MobileDeviceIdentityKey{
        organization_id: organization.id,
        proof_challenge_id: challenge.id,
        installation_id: installation_id,
        platform: "android",
        key_scope_id: key_scope_id,
        device_key_id: device_key_id,
        public_key_spki: spki,
        algorithm: "ecdsa-p256-sha256",
        proof_state: "verified",
        attestation_state: "not_requested",
        lifecycle_state: "active",
        activated_at: @now,
        last_proof_at: @now
      })

    %{
      organization: organization,
      installation_id: installation_id,
      private_key: private_key,
      key: key,
      device_key_id: device_key_id,
      key_scope_id: key_scope_id
    }
  end

  defp signed_submission(fixture, issued) do
    posture = %{
      "schema" => "tamandua.mobile.endpoint-posture/v1",
      "observed_at" => "2026-07-16T12:00:01.000Z",
      "source" => "android_foreground_online",
      "risk_score" => 42,
      "security_checks" =>
        Map.new(
          ~w(app_integrity_violation debugger_detected emulator_detected frida_detected hook_framework_detected root_detected),
          &{&1, false}
        )
    }

    {:ok, posture_sha256} = SignedPosture.posture_digest(posture)

    envelope = %{
      "protocol" => "tamandua.mobile.endpoint-telemetry/v1",
      "message_type" => "endpoint_posture",
      "message_version" => "1",
      "organization_id" => fixture.organization.id,
      "installation_id" => fixture.installation_id,
      "platform" => "android",
      "device_key_id" => fixture.device_key_id,
      "key_scope_id" => fixture.key_scope_id,
      "request_id" => issued.request_id,
      "challenge_id" => issued.challenge_id,
      "nonce" => issued.nonce,
      "posture_sha256" => posture_sha256,
      "algorithm" => "ecdsa-p256-sha256",
      "issued_at" => issued.issued_at,
      "expires_at" => issued.expires_at,
      "external_claim_allowed" => false,
      "hardware_attestation_verified" => false,
      "verification_state" => "locally_signed_server_verification_required"
    }

    {:ok, payload} = SignedPosture.canonical_payload(envelope)

    envelope =
      envelope
      |> Map.put(
        "signed_payload_sha256",
        :crypto.hash(:sha256, payload) |> Base.url_encode64(padding: false)
      )
      |> Map.put(
        "signature",
        :public_key.sign(payload, :sha256, fixture.private_key)
        |> Base.url_encode64(padding: false)
      )

    {envelope, posture}
  end

  defp insert_pending_recovery(fixture) do
    Repo.insert!(%MobileDeviceIdentityRecovery{
      organization_id: fixture.organization.id,
      installation_id: fixture.installation_id,
      purpose: "reconcile_rotation",
      state: "pending",
      old_device_key_id: fixture.device_key_id,
      candidate_device_key_id: "tmdk_v1_" <> String.duplicate("c", 43),
      reason: "test",
      token_digest: :crypto.hash(:sha256, "recovery"),
      step_up_required: false,
      authorization_state: "not_required",
      authorization_provenance: %{},
      issued_at: @now,
      expires_at: DateTime.add(@now, 300, :second)
    })
  end

  defp p256_keypair do
    {:ECPrivateKey, _version, _private, params, public, _attrs} =
      private_key = :public_key.generate_key({:namedCurve, :secp256r1})

    spki =
      :public_key.der_encode(
        :SubjectPublicKeyInfo,
        {:SubjectPublicKeyInfo, {:AlgorithmIdentifier, {1, 2, 840, 10045, 2, 1}, params}, public}
      )

    {private_key, spki}
  end
end
