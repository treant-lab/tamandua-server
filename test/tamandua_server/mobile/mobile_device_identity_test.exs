defmodule TamanduaServer.Mobile.MobileDeviceIdentityTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Mobile.{
    MobileDeviceIdentity,
    MobileDeviceIdentityAndroidAttestation,
    MobileDeviceIdentityChallenge,
    MobileDeviceIdentityKey
  }

  alias TamanduaServer.AndroidAttestationFixture
  alias Ecto.Adapters.SQL.Sandbox

  @public_key_1 "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC5iM0/c6FZmhIJ1pO/PIsyQ2HqESS7LO/VAgEUL/ZFHugMKNzBWyeCKU+UMqW2ubv2/1WF/AU7vIbj+a8aw/BA=="
  @private_key_1 "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZ1B1d3lTMW90U2JsSkREczAKdGVCM2cvK3V5aWJsS3pFeWJxaGVrS3VRTktlaFJBTkNBQVFMbUl6VDl6b1ZtYUVnbldrNzg4aXpKRFllb1JKTApzczc5VUNBUlF2OWtVZTZBd28zTUZiSjRJcFQ1UXlwYmE1dS9iL1ZZWDhCVHU4aHVQNXJ4ckQ4RQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg=="

  @public_key_2 "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVQOY+nd4+5AdDbap2BrNRy1R69xuVWGeVYDEWqYER0sD/dNPX57/V08lJ38a/9FgIXWk7rXcpmLIPi5bH6NEpg=="
  @private_key_2 "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZ0pvU21MNU5xTFlUenJvd28KRXVmdy9qVVpoSDlSb2swMCtYUFA3aXFhZkN1aFJBTkNBQVJWQTVqNmQzajdrQjBOdHFuWUdzMUhMVkhyM0c1VgpZWjVWZ01SYXBnUkhTd1A5MDA5Zm52OVhUeVVuZnhyLzBXQWhkYVR1dGR5bVlzZytMbHNmbzBTbQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg=="

  @algorithm "ecdsa-p256-sha256"

  test "issues a tenant-bound 256-bit challenge while persisting only its digest" do
    organization = insert(:organization)
    now = ~U[2026-07-15 20:00:00.000000Z]

    assert {:ok, issued} =
             MobileDeviceIdentity.issue_challenge(
               organization.id,
               %{installation_id: "tmnd-install-1", platform: "android", purpose: "enroll"},
               now: now
             )

    challenge = Repo.get!(MobileDeviceIdentityChallenge, issued.challenge_id)

    assert byte_size(Base.url_decode64!(issued.challenge, padding: false)) == 32
    assert challenge.challenge_digest == :crypto.hash(:sha256, issued.challenge)
    refute challenge.challenge_digest == issued.challenge
    assert challenge.organization_id == organization.id
    assert challenge.installation_id == "tmnd-install-1"
    assert challenge.expires_at == DateTime.add(now, 300, :second)
    assert issued.algorithm == @algorithm
    assert issued.installation_id == challenge.installation_id
    assert issued.platform == challenge.platform
    assert issued.key_scope_id == challenge.key_scope_id
    refute inspect(challenge) =~ issued.challenge
  end

  test "verifies P-256 proof, ignores client verified-attestation claims, and consumes once" do
    organization = insert(:organization)
    installation_id = "tmnd-install-proof-1"
    now = ~U[2026-07-15 20:00:00.000000Z]

    issued = issue!(organization.id, installation_id, "enroll", now)

    proof =
      signed_proof(organization.id, issued, installation_id, @public_key_1, @private_key_1,
        attestation_evidence: ["certificate-chain-present"],
        attestation_state: "verified_strongbox"
      )

    assert {:ok, key} = MobileDeviceIdentity.verify_and_bind(organization.id, proof, now: now)
    assert key.proof_state == "verified"
    assert key.attestation_state == "present_unverified"
    assert key.lifecycle_state == "active"
    assert key.metadata["client_attestation_claim_ignored"] == true

    assert key.metadata["attestation_verification"] ==
             "android_attestation_trust_roots_unconfigured"

    assert key.public_key_spki == Base.decode64!(@public_key_1)

    challenge = Repo.get!(MobileDeviceIdentityChallenge, issued.challenge_id)
    assert challenge.state == "consumed"
    assert challenge.consumed_at == now

    assert {:error, :challenge_unavailable} =
             MobileDeviceIdentity.verify_and_bind(organization.id, proof, now: now)
  end

  test "binds, revalidates, upgrades metadata, and rotates with governed Android attestation" do
    organization = insert(:organization)
    installation_id = "tmnd-install-attested-lifecycle-1"
    now = ~U[2026-07-16 10:00:00.000000Z]
    root = AndroidAttestationFixture.root()
    key_1 = decode_private_key(@private_key_1)
    key_2 = decode_private_key(@private_key_2)
    enrollment = issue!(organization.id, installation_id, "enroll", now)

    fixture_1 =
      AndroidAttestationFixture.build(
        Base.url_decode64!(enrollment.challenge, padding: false),
        key: key_1,
        root: root
      )

    config = AndroidAttestationFixture.verifier_config(fixture_1, now: now, policy: :reject)

    with_attestation_config(config, fn ->
      enrollment_proof =
        signed_proof(
          organization.id,
          enrollment,
          installation_id,
          @public_key_1,
          @private_key_1,
          attestation_evidence: fixture_1.chain,
          attestation_state: "verified_strongbox"
        )

      assert {:ok, first_key} =
               MobileDeviceIdentity.verify_and_bind(organization.id, enrollment_proof, now: now)

      assert first_key.attestation_state == "verified_tee"
      assert first_key.metadata["attestation_governance_source"] == "test-governance"
      assert first_key.metadata["client_attestation_claim_ignored"] == true

      no_evidence_now = DateTime.add(now, 15, :second)
      no_evidence_refresh = issue!(organization.id, installation_id, "enroll", no_evidence_now)

      assert {:error, :attestation_revalidation_required} =
               MobileDeviceIdentity.verify_and_bind(
                 organization.id,
                 signed_proof(
                   organization.id,
                   no_evidence_refresh,
                   installation_id,
                   @public_key_1,
                   @private_key_1
                 ),
                 now: no_evidence_now
               )

      assert Repo.get!(MobileDeviceIdentityChallenge, no_evidence_refresh.challenge_id).state ==
               "pending"

      refresh_now = DateTime.add(now, 30, :second)
      refresh = issue!(organization.id, installation_id, "enroll", refresh_now)

      refresh_proof =
        signed_proof(
          organization.id,
          refresh,
          installation_id,
          @public_key_1,
          @private_key_1,
          attestation_evidence: fixture_1.chain
        )

      assert {:ok, refreshed} =
               MobileDeviceIdentity.verify_and_bind(
                 organization.id,
                 refresh_proof,
                 now: refresh_now
               )

      assert refreshed.attestation_state == "verified_tee"

      assert refreshed.metadata["attestation_verification"] ==
               "server_verified_android_key_attestation"

      rotation_now = DateTime.add(now, 60, :second)
      rotation = issue!(organization.id, installation_id, "rotate", rotation_now)

      fixture_2 =
        AndroidAttestationFixture.build(
          Base.url_decode64!(rotation.challenge, padding: false),
          key: key_2,
          root: root,
          security_level: 2
        )

      Application.put_env(
        :tamandua_server,
        MobileDeviceIdentityAndroidAttestation,
        AndroidAttestationFixture.verifier_config([fixture_1, fixture_2],
          now: rotation_now,
          policy: :reject
        )
      )

      rotation_proof =
        signed_proof(
          organization.id,
          rotation,
          installation_id,
          @public_key_2,
          @private_key_2,
          previous_device_key_id: first_key.device_key_id,
          previous_private_key: @private_key_1,
          attestation_evidence: fixture_2.chain
        )

      assert {:ok, replacement} =
               MobileDeviceIdentity.verify_and_bind(
                 organization.id,
                 rotation_proof,
                 now: rotation_now
               )

      assert replacement.attestation_state == "verified_strongbox"
      assert replacement.rotated_from_id == first_key.id
      assert Repo.get!(MobileDeviceIdentityKey, first_key.id).lifecycle_state == "rotated"
    end)
  end

  test "reject policy rolls back a failed attestation without consuming its challenge" do
    organization = insert(:organization)
    installation_id = "tmnd-install-attestation-reject-1"
    now = ~U[2026-07-16 11:00:00.000000Z]
    issued = issue!(organization.id, installation_id, "enroll", now)

    proof =
      signed_proof(
        organization.id,
        issued,
        installation_id,
        @public_key_1,
        @private_key_1,
        attestation_evidence: ["malformed-chain"]
      )

    with_attestation_config(
      [
        trust_roots_pem: [],
        revoked_certificate_sha256: [],
        freshness_receipt: nil,
        unverified_evidence_policy: :reject
      ],
      fn ->
        assert {:error, :android_key_attestation_invalid} =
                 MobileDeviceIdentity.verify_and_bind(organization.id, proof, now: now)

        assert Repo.get!(MobileDeviceIdentityChallenge, issued.challenge_id).state == "pending"

        refute Repo.exists?(
                 MobileDeviceIdentityKey.active_for_installation(
                   organization.id,
                   installation_id
                 )
               )
      end
    )
  end

  test "presented revoked evidence makes verified same-key refresh fail atomically" do
    organization = insert(:organization)
    installation_id = "tmnd-install-attestation-revoked-refresh-1"
    now = ~U[2026-07-16 12:00:00.000000Z]
    root = AndroidAttestationFixture.root()
    enrollment = issue!(organization.id, installation_id, "enroll", now)

    fixture =
      AndroidAttestationFixture.build(
        Base.url_decode64!(enrollment.challenge, padding: false),
        key: decode_private_key(@private_key_1),
        root: root
      )

    with_attestation_config(
      AndroidAttestationFixture.verifier_config(fixture, now: now, policy: :reject),
      fn ->
        enrollment_proof =
          signed_proof(
            organization.id,
            enrollment,
            installation_id,
            @public_key_1,
            @private_key_1,
            attestation_evidence: fixture.chain
          )

        assert {:ok, first_key} =
                 MobileDeviceIdentity.verify_and_bind(
                   organization.id,
                   enrollment_proof,
                   now: now
                 )

        refresh_now = DateTime.add(now, 30, :second)
        refresh = issue!(organization.id, installation_id, "enroll", refresh_now)
        [leaf | _] = fixture.chain_der
        revoked = Base.encode16(:crypto.hash(:sha256, leaf), case: :lower)

        Application.put_env(
          :tamandua_server,
          MobileDeviceIdentityAndroidAttestation,
          AndroidAttestationFixture.verifier_config(fixture,
            now: refresh_now,
            policy: :preserve,
            revoked: [revoked]
          )
        )

        refresh_proof =
          signed_proof(
            organization.id,
            refresh,
            installation_id,
            @public_key_1,
            @private_key_1,
            attestation_evidence: fixture.chain
          )

        assert {:error, :android_key_attestation_revalidation_failed} =
                 MobileDeviceIdentity.verify_and_bind(
                   organization.id,
                   refresh_proof,
                   now: refresh_now
                 )

        assert Repo.get!(MobileDeviceIdentityChallenge, refresh.challenge_id).state == "pending"
        unchanged = Repo.get!(MobileDeviceIdentityKey, first_key.id)
        assert unchanged.lifecycle_state == "active"
        assert unchanged.last_proof_at == now
      end
    )
  end

  test "rotation denies a valid but weaker hardware attestation and keeps the old key active" do
    organization = insert(:organization)
    installation_id = "tmnd-install-attestation-monotonic-1"
    now = ~U[2026-07-16 13:00:00.000000Z]
    root = AndroidAttestationFixture.root()
    enrollment = issue!(organization.id, installation_id, "enroll", now)

    strongbox =
      AndroidAttestationFixture.build(
        Base.url_decode64!(enrollment.challenge, padding: false),
        key: decode_private_key(@private_key_1),
        root: root,
        security_level: 2
      )

    with_attestation_config(
      AndroidAttestationFixture.verifier_config(strongbox, now: now, policy: :reject),
      fn ->
        assert {:ok, first_key} =
                 MobileDeviceIdentity.verify_and_bind(
                   organization.id,
                   signed_proof(
                     organization.id,
                     enrollment,
                     installation_id,
                     @public_key_1,
                     @private_key_1,
                     attestation_evidence: strongbox.chain
                   ),
                   now: now
                 )

        assert first_key.attestation_state == "verified_strongbox"

        rotation_now = DateTime.add(now, 30, :second)
        rotation = issue!(organization.id, installation_id, "rotate", rotation_now)

        tee =
          AndroidAttestationFixture.build(
            Base.url_decode64!(rotation.challenge, padding: false),
            key: decode_private_key(@private_key_2),
            root: root,
            security_level: 1
          )

        rotation_proof =
          signed_proof(
            organization.id,
            rotation,
            installation_id,
            @public_key_2,
            @private_key_2,
            previous_device_key_id: first_key.device_key_id,
            previous_private_key: @private_key_1,
            attestation_evidence: tee.chain
          )

        assert {:error, :attestation_downgrade_forbidden} =
                 MobileDeviceIdentity.verify_and_bind(
                   organization.id,
                   rotation_proof,
                   now: rotation_now
                 )

        assert Repo.get!(MobileDeviceIdentityChallenge, rotation.challenge_id).state == "pending"
        assert Repo.get!(MobileDeviceIdentityKey, first_key.id).lifecycle_state == "active"
      end
    )
  end

  test "same-key refresh upgrades preserved evidence after governance becomes available" do
    organization = insert(:organization)
    installation_id = "tmnd-install-attestation-upgrade-1"
    now = ~U[2026-07-16 14:00:00.000000Z]
    enrollment = issue!(organization.id, installation_id, "enroll", now)

    fixture =
      AndroidAttestationFixture.build(
        Base.url_decode64!(enrollment.challenge, padding: false),
        key: decode_private_key(@private_key_1)
      )

    with_attestation_config(
      [
        trust_roots_pem: [],
        revoked_certificate_sha256: [],
        freshness_receipt: nil,
        unverified_evidence_policy: :preserve
      ],
      fn ->
        assert {:ok, preserved} =
                 MobileDeviceIdentity.verify_and_bind(
                   organization.id,
                   signed_proof(
                     organization.id,
                     enrollment,
                     installation_id,
                     @public_key_1,
                     @private_key_1,
                     attestation_evidence: fixture.chain
                   ),
                   now: now
                 )

        assert preserved.attestation_state == "present_unverified"
        assert byte_size(preserved.metadata["attestation_challenge_sha256"]) == 64

        refresh_now = DateTime.add(now, 30, :second)
        refresh = issue!(organization.id, installation_id, "enroll", refresh_now)

        Application.put_env(
          :tamandua_server,
          MobileDeviceIdentityAndroidAttestation,
          AndroidAttestationFixture.verifier_config(fixture,
            now: refresh_now,
            policy: :reject
          )
        )

        assert {:ok, upgraded} =
                 MobileDeviceIdentity.verify_and_bind(
                   organization.id,
                   signed_proof(
                     organization.id,
                     refresh,
                     installation_id,
                     @public_key_1,
                     @private_key_1,
                     attestation_evidence: fixture.chain
                   ),
                   now: refresh_now
                 )

        assert upgraded.attestation_state == "verified_tee"
        assert upgraded.metadata["attestation_governance_source"] == "test-governance"
      end
    )
  end

  test "rejects wrong tenant, expired challenges, tampering, and a non-P-256 SPKI" do
    organization = insert(:organization)
    other_organization = insert(:organization)
    now = ~U[2026-07-15 20:00:00.000000Z]
    installation_id = "tmnd-install-negative-1"
    issued = issue!(organization.id, installation_id, "enroll", now)
    proof = signed_proof(organization.id, issued, installation_id, @public_key_1, @private_key_1)

    assert {:error, :challenge_unavailable} =
             MobileDeviceIdentity.verify_and_bind(other_organization.id, proof, now: now)

    assert {:error, :invalid_signature} =
             MobileDeviceIdentity.verify_and_bind(
               organization.id,
               Map.put(proof, :signature, base64url(<<48, 6, 2, 1, 1, 2, 1, 1>>)),
               now: now
             )

    rsa_like_spki = Base.url_encode64(:binary.copy(<<1>>, 91), padding: false)

    assert {:error, :invalid_p256_public_key} =
             MobileDeviceIdentity.verify_and_bind(
               organization.id,
               proof
               |> Map.put(:public_key_spki, rsa_like_spki)
               |> Map.put(:device_key_id, "tmdk_v1_" <> String.duplicate("a", 43)),
               now: now
             )

    assert {:error, :challenge_expired} =
             MobileDeviceIdentity.verify_and_bind(
               organization.id,
               proof,
               now: DateTime.add(now, 300, :second)
             )
  end

  test "tenant-scopes key identifiers and blocks legacy downgrade after binding" do
    organization = insert(:organization)
    other_organization = insert(:organization)
    installation_id = "tmnd-install-bound-1"
    spki = Base.decode64!(@public_key_1)

    refute MobileDeviceIdentity.derive_device_key_id(organization.id, spki) ==
             MobileDeviceIdentity.derive_device_key_id(other_organization.id, spki)

    assert MobileDeviceIdentity.registration_decision(organization.id, installation_id) ==
             {:allow, :legacy_unbound}

    now = ~U[2026-07-15 20:00:00.000000Z]
    issued = issue!(organization.id, installation_id, "enroll", now)
    proof = signed_proof(organization.id, issued, installation_id, @public_key_1, @private_key_1)
    assert {:ok, key} = MobileDeviceIdentity.verify_and_bind(organization.id, proof, now: now)

    assert MobileDeviceIdentity.proof_required?(organization.id, installation_id)

    assert MobileDeviceIdentity.registration_decision(organization.id, installation_id) ==
             {:deny, :device_identity_proof_required}

    assert MobileDeviceIdentity.registration_decision(organization.id, installation_id, key) ==
             {:allow, :verified_device_proof}

    assert MobileDeviceIdentity.registration_decision(organization.id, installation_id, %{
             "installation_id" => installation_id,
             "device_key_id" => key.device_key_id,
             "proof_state" => "verified",
             "proof_required" => true,
             "key_scope_id" => key.key_scope_id
           }) == {:allow, :verified_device_proof}

    forged_context = %{key | device_key_id: "tmdk_v1_" <> String.duplicate("a", 43)}

    assert MobileDeviceIdentity.registration_decision(
             organization.id,
             installation_id,
             forged_context
           ) == {:deny, :device_identity_proof_required}

    assert MobileDeviceIdentity.registration_decision(organization.id, installation_id, %{
             "installation_id" => installation_id,
             "device_key_id" => key.device_key_id,
             "proof_state" => "verified",
             "proof_required" => true,
             "key_scope_id" => "wrong-scope"
           }) == {:deny, :device_identity_proof_required}
  end

  test "re-proving the same key is idempotent and consumes the fresh challenge" do
    organization = insert(:organization)
    installation_id = "tmnd-install-idempotent-1"
    now = ~U[2026-07-15 20:00:00.000000Z]
    first_challenge = issue!(organization.id, installation_id, "enroll", now)

    assert {:ok, first_key} =
             MobileDeviceIdentity.verify_and_bind(
               organization.id,
               signed_proof(
                 organization.id,
                 first_challenge,
                 installation_id,
                 @public_key_1,
                 @private_key_1
               ),
               now: now
             )

    second_now = DateTime.add(now, 15, :second)
    second_challenge = issue!(organization.id, installation_id, "enroll", second_now)

    assert {:ok, refreshed_key} =
             MobileDeviceIdentity.verify_and_bind(
               organization.id,
               signed_proof(
                 organization.id,
                 second_challenge,
                 installation_id,
                 @public_key_1,
                 @private_key_1
               ),
               now: second_now
             )

    assert refreshed_key.id == first_key.id
    assert refreshed_key.last_proof_at == second_now
    assert refreshed_key.proof_challenge_id == second_challenge.challenge_id

    assert Repo.get!(MobileDeviceIdentityChallenge, second_challenge.challenge_id).state ==
             "consumed"

    assert Repo.aggregate(
             MobileDeviceIdentityKey.active_for_installation(organization.id, installation_id),
             :count
           ) == 1
  end

  test "rotates only with proof from both the active and replacement key" do
    organization = insert(:organization)
    installation_id = "tmnd-install-rotate-1"
    now = ~U[2026-07-15 20:00:00.000000Z]

    enrollment = issue!(organization.id, installation_id, "enroll", now)

    assert {:ok, first_key} =
             MobileDeviceIdentity.verify_and_bind(
               organization.id,
               signed_proof(
                 organization.id,
                 enrollment,
                 installation_id,
                 @public_key_1,
                 @private_key_1
               ),
               now: now
             )

    rotation_now = DateTime.add(now, 10, :second)
    rotation = issue!(organization.id, installation_id, "rotate", rotation_now)

    rotation_proof =
      signed_proof(
        organization.id,
        rotation,
        installation_id,
        @public_key_2,
        @private_key_2,
        previous_device_key_id: first_key.device_key_id,
        previous_private_key: @private_key_1
      )

    assert {:ok, replacement} =
             MobileDeviceIdentity.verify_and_bind(
               organization.id,
               rotation_proof,
               now: rotation_now
             )

    assert replacement.lifecycle_state == "active"
    assert replacement.rotated_from_id == first_key.id

    rotated = Repo.get!(MobileDeviceIdentityKey, first_key.id)
    assert rotated.lifecycle_state == "rotated"
    assert rotated.rotated_at == rotation_now
    assert rotated.revoked_at == rotation_now

    assert Repo.aggregate(
             MobileDeviceIdentityKey.active_for_installation(organization.id, installation_id),
             :count
           ) == 1
  end

  test "requires explicit rotation when a different key tries to enroll a bound install" do
    organization = insert(:organization)
    installation_id = "tmnd-install-no-silent-rebind-1"
    now = ~U[2026-07-15 20:00:00.000000Z]

    first = issue!(organization.id, installation_id, "enroll", now)

    assert {:ok, _key} =
             MobileDeviceIdentity.verify_and_bind(
               organization.id,
               signed_proof(
                 organization.id,
                 first,
                 installation_id,
                 @public_key_1,
                 @private_key_1
               ),
               now: now
             )

    second_now = DateTime.add(now, 10, :second)
    second = issue!(organization.id, installation_id, "enroll", second_now)

    assert {:error, :rotation_required} =
             MobileDeviceIdentity.verify_and_bind(
               organization.id,
               signed_proof(
                 organization.id,
                 second,
                 installation_id,
                 @public_key_2,
                 @private_key_2
               ),
               now: second_now
             )

    assert Repo.get!(MobileDeviceIdentityChallenge, second.challenge_id).state == "pending"
  end

  test "revokes an active key without reopening the legacy downgrade path" do
    organization = insert(:organization)
    installation_id = "tmnd-install-revoke-1"
    now = ~U[2026-07-15 20:00:00.000000Z]
    issued = issue!(organization.id, installation_id, "enroll", now)

    assert {:ok, key} =
             MobileDeviceIdentity.verify_and_bind(
               organization.id,
               signed_proof(
                 organization.id,
                 issued,
                 installation_id,
                 @public_key_1,
                 @private_key_1
               ),
               now: now
             )

    revoked_at = DateTime.add(now, 20, :second)

    assert {:ok, revoked} =
             MobileDeviceIdentity.revoke_active(organization.id, installation_id, now: revoked_at)

    assert revoked.id == key.id
    assert revoked.lifecycle_state == "revoked"
    assert revoked.revoked_at == revoked_at
    assert MobileDeviceIdentity.proof_required?(organization.id, installation_id)

    assert MobileDeviceIdentity.registration_decision(organization.id, installation_id) ==
             {:deny, :device_identity_proof_required}

    assert {:error, :active_key_not_found} =
             MobileDeviceIdentity.revoke_active(organization.id, installation_id, now: revoked_at)

    assert {:error, :device_identity_proof_required} =
             MobileDeviceIdentity.with_legacy_unbound(
               organization.id,
               [installation_id, installation_id],
               fn ->
                 send(self(), :legacy_callback_ran)
                 {:ok, :mutated}
               end
             )

    refute_received :legacy_callback_ran

    replacement_time = DateTime.add(now, 30, :second)
    replacement = issue!(organization.id, installation_id, "enroll", replacement_time)

    assert {:error, :re_enrollment_authorization_required} =
             MobileDeviceIdentity.verify_and_bind(
               organization.id,
               signed_proof(
                 organization.id,
                 replacement,
                 installation_id,
                 @public_key_2,
                 @private_key_2
               ),
               now: replacement_time
             )
  end

  test "rolls back a failed legacy callback and rejects invalid installation sets" do
    organization = insert(:organization)
    installation_id = "tmnd-install-legacy-rollback-1"

    assert {:error, :legacy_mutation_failed} =
             MobileDeviceIdentity.with_legacy_unbound(organization.id, installation_id, fn ->
               assert {:ok, _issued} =
                        MobileDeviceIdentity.issue_challenge(
                          organization.id,
                          %{
                            installation_id: installation_id,
                            platform: "android",
                            purpose: "enroll"
                          }
                        )

               {:error, :legacy_mutation_failed}
             end)

    refute Repo.exists?(
             from(challenge in MobileDeviceIdentityChallenge,
               where:
                 challenge.organization_id == ^organization.id and
                   challenge.installation_id == ^installation_id
             )
           )

    assert {:error, :invalid_installation_ids} =
             MobileDeviceIdentity.with_legacy_unbound(organization.id, [], fn ->
               {:ok, :unused}
             end)

    assert {:error, :invalid_installation_ids} =
             MobileDeviceIdentity.with_legacy_unbound(organization.id, " padded-id ", fn ->
               {:ok, :unused}
             end)

    assert {:error, :invalid_callback_result} =
             MobileDeviceIdentity.with_legacy_unbound(
               organization.id,
               "tmnd-install-invalid-callback-1",
               fn -> :not_a_transaction_result end
             )

    exception_installation_id = "tmnd-install-legacy-exception-1"

    assert_raise RuntimeError, "legacy callback failed", fn ->
      MobileDeviceIdentity.with_legacy_unbound(
        organization.id,
        exception_installation_id,
        fn ->
          assert {:ok, _issued} =
                   MobileDeviceIdentity.issue_challenge(
                     organization.id,
                     %{
                       installation_id: exception_installation_id,
                       platform: "android",
                       purpose: "enroll"
                     }
                   )

          raise "legacy callback failed"
        end
      )
    end

    refute Repo.exists?(
             from(challenge in MobileDeviceIdentityChallenge,
               where:
                 challenge.organization_id == ^organization.id and
                   challenge.installation_id == ^exception_installation_id
             )
           )
  end

  test "orders installation locks so reverse-order callers serialize without deadlock" do
    organization_id = Ecto.UUID.generate()
    first_id = "tmnd-install-lock-a"
    second_id = "tmnd-install-lock-b"
    parent = self()

    first =
      Task.async(fn ->
        Sandbox.unboxed_run(Repo, fn ->
          MobileDeviceIdentity.with_legacy_unbound(
            organization_id,
            [second_id, first_id, second_id],
            fn ->
              send(parent, {:inside_legacy_lock, :first, self()})

              receive do
                :release_legacy_lock -> {:ok, :first}
              after
                2_000 -> {:error, :barrier_timeout}
              end
            end
          )
        end)
      end)

    assert_receive {:inside_legacy_lock, :first, first_pid}, 2_000

    second =
      Task.async(fn ->
        Sandbox.unboxed_run(Repo, fn ->
          send(parent, {:attempting_legacy_lock, :second})

          MobileDeviceIdentity.with_legacy_unbound(
            organization_id,
            [first_id, second_id],
            fn ->
              send(parent, {:inside_legacy_lock, :second, self()})

              receive do
                :release_legacy_lock -> {:ok, :second}
              after
                2_000 -> {:error, :barrier_timeout}
              end
            end
          )
        end)
      end)

    assert_receive {:attempting_legacy_lock, :second}, 2_000
    refute_receive {:inside_legacy_lock, :second, _pid}, 100
    send(first_pid, :release_legacy_lock)
    assert Task.await(first, 2_000) == {:ok, :first}

    assert_receive {:inside_legacy_lock, :second, second_pid}, 2_000
    send(second_pid, :release_legacy_lock)
    assert Task.await(second, 2_000) == {:ok, :second}
  end

  test "registration decision and callback share the identity lock and transaction" do
    organization = insert(:organization)
    installation_id = "tmnd-install-registration-transaction-1"
    now = ~U[2026-07-15 20:00:00.000000Z]
    issued = issue!(organization.id, installation_id, "enroll", now)
    proof = signed_proof(organization.id, issued, installation_id, @public_key_1, @private_key_1)
    parent = self()

    mutation =
      Task.async(fn ->
        Sandbox.unboxed_run(Repo, fn ->
          MobileDeviceIdentity.with_registration_mutation(
            organization.id,
            [{installation_id, nil}],
            fn ->
              send(parent, {:inside_registration_mutation, self()})

              receive do
                :release_registration_mutation -> {:ok, :mutated}
              after
                2_000 -> {:error, :barrier_timeout}
              end
            end
          )
        end)
      end)

    assert_receive {:inside_registration_mutation, mutation_pid}, 2_000

    binder =
      Task.async(fn ->
        Sandbox.unboxed_run(Repo, fn ->
          send(parent, :attempting_identity_bind)
          result = MobileDeviceIdentity.verify_and_bind(organization.id, proof, now: now)
          send(parent, :identity_bind_finished)
          result
        end)
      end)

    assert_receive :attempting_identity_bind, 2_000
    refute_receive :identity_bind_finished, 100
    send(mutation_pid, :release_registration_mutation)
    assert Task.await(mutation, 2_000) == {:ok, :mutated}
    assert {:ok, %MobileDeviceIdentityKey{}} = Task.await(binder, 2_000)
    assert_receive :identity_bind_finished, 2_000
  end

  test "registration mutation rolls back callback writes and rejects conflicting bindings" do
    organization = insert(:organization)
    installation_id = "tmnd-install-registration-rollback-1"

    assert {:error, :registration_mutation_failed} =
             MobileDeviceIdentity.with_registration_mutation(
               organization.id,
               [{installation_id, nil}],
               fn ->
                 assert {:ok, _issued} =
                          MobileDeviceIdentity.issue_challenge(
                            organization.id,
                            %{
                              installation_id: installation_id,
                              platform: "android",
                              purpose: "enroll"
                            }
                          )

                 {:error, :registration_mutation_failed}
               end
             )

    refute Repo.exists?(
             from(challenge in MobileDeviceIdentityChallenge,
               where:
                 challenge.organization_id == ^organization.id and
                   challenge.installation_id == ^installation_id
             )
           )

    assert {:error, :invalid_installation_ids} =
             MobileDeviceIdentity.with_registration_mutation(
               organization.id,
               [{installation_id, nil}, {installation_id, %{proof_state: "verified"}}],
               fn -> {:ok, :unused} end
             )
  end

  defp issue!(organization_id, installation_id, purpose, now) do
    assert {:ok, issued} =
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

    signature = :public_key.sign(payload, :sha256, decode_private_key(private_key_base64))

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
      signature: base64url(signature)
    }

    proof =
      if previous_private_key = Keyword.get(opts, :previous_private_key) do
        previous_signature =
          :public_key.sign(payload, :sha256, decode_private_key(previous_private_key))

        Map.put(proof, :previous_signature, base64url(previous_signature))
      else
        proof
      end

    opts
    |> Keyword.drop([:previous_private_key])
    |> Enum.into(proof)
  end

  defp decode_private_key(encoded) do
    encoded
    |> Base.decode64!()
    |> :public_key.pem_decode()
    |> hd()
    |> :public_key.pem_entry_decode()
  end

  defp with_attestation_config(config, callback) do
    previous =
      Application.get_env(:tamandua_server, MobileDeviceIdentityAndroidAttestation, :missing)

    Application.put_env(:tamandua_server, MobileDeviceIdentityAndroidAttestation, config)

    try do
      callback.()
    after
      case previous do
        :missing ->
          Application.delete_env(:tamandua_server, MobileDeviceIdentityAndroidAttestation)

        value ->
          Application.put_env(:tamandua_server, MobileDeviceIdentityAndroidAttestation, value)
      end
    end
  end

  defp base64url(value), do: Base.url_encode64(value, padding: false)
end
