ExUnit.start()

defmodule TamanduaServer.Mobile.MobileDeviceIdentityAppleAppAttestTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.AppleAppAttestFixture
  alias TamanduaServer.Mobile.MobileDeviceIdentityAppleAppAttest, as: AppAttest

  test "binds a configured app, nonce, credential, key and first monotonic assertion" do
    challenge = :crypto.strong_rand_bytes(32)
    client_data = "tamandua canonical device proof"
    fixture = AppleAppAttestFixture.build(challenge, client_data)

    assert {:ok, result} =
             AppAttest.verify_bind(
               fixture.evidence,
               challenge,
               client_data,
               fixture.spki,
               app_profiles: fixture.profile
             )

    assert result.state == "verified_app_attest"
    assert result.provider_binding.credential_id == fixture.key_id
    assert result.provider_binding.sign_count == 1
    assert byte_size(result.provider_binding.public_key_spki) == 91
  end

  test "fails closed without an explicitly configured profile and roots" do
    challenge = :crypto.strong_rand_bytes(32)
    fixture = AppleAppAttestFixture.build(challenge, "client-data")

    assert {:error, :apple_app_attest_profile_unconfigured} =
             AppAttest.verify_bind(
               fixture.evidence,
               challenge,
               "client-data",
               fixture.spki,
               app_profiles: %{}
             )
  end

  test "rejects challenge nonce replay and client-data substitution" do
    challenge = :crypto.strong_rand_bytes(32)
    fixture = AppleAppAttestFixture.build(challenge, "bound-client-data")
    opts = [app_profiles: fixture.profile]

    assert {:error, _} =
             AppAttest.verify_bind(
               fixture.evidence,
               :crypto.strong_rand_bytes(32),
               "bound-client-data",
               fixture.spki,
               opts
             )

    assert {:error, :apple_app_attest_binding_invalid} =
             AppAttest.verify_bind(fixture.evidence, challenge, "substituted", fixture.spki, opts)
  end

  test "rejects a zero assertion counter" do
    challenge = :crypto.strong_rand_bytes(32)
    fixture = AppleAppAttestFixture.build(challenge, "client-data", sign_count: 0)

    assert {:error, :apple_app_attest_assertion_invalid} =
             AppAttest.verify_bind(
               fixture.evidence,
               challenge,
               "client-data",
               fixture.spki,
               app_profiles: fixture.profile
             )
  end

  test "rejects an untyped provider and malformed canonical CBOR" do
    challenge = :crypto.strong_rand_bytes(32)
    fixture = AppleAppAttestFixture.build(challenge, "client-data")

    assert {:error, :apple_app_attest_invalid} =
             AppAttest.verify_bind(
               Map.put(fixture.evidence, "provider", "generic"),
               challenge,
               "client-data",
               fixture.spki,
               app_profiles: fixture.profile
             )

    malformed =
      Map.put(
        fixture.evidence,
        "assertion_base64url",
        Base.url_encode64(<<0xBF, 0xFF>>, padding: false)
      )

    assert {:error, :apple_app_attest_assertion_invalid} =
             AppAttest.verify_bind(
               malformed,
               challenge,
               "client-data",
               fixture.spki,
               app_profiles: fixture.profile
             )
  end

  test "rejects an unrelated identity proof SPKI" do
    challenge = :crypto.strong_rand_bytes(32)
    fixture = AppleAppAttestFixture.build(challenge, "client-data")
    unrelated = AppleAppAttestFixture.build(:crypto.strong_rand_bytes(32), "other")

    assert {:error, :apple_app_attest_binding_invalid} =
             AppAttest.verify_bind(
               fixture.evidence,
               challenge,
               "client-data",
               unrelated.spki,
               app_profiles: fixture.profile
             )
  end

  test "requires governed Apple extensions in both attestation and assertion" do
    challenge = :crypto.strong_rand_bytes(32)

    for opts <- [
          [attestation_extensions: :absent],
          [assertion_extensions: :absent],
          [attestation_extensions: {:raw, <<0xBF, 0xFF>>}],
          [assertion_extensions: {:raw, <<0xBF, 0xFF>>}],
          [assertion_validation_category: 4],
          [assertion_bundle_version: "2.0"]
        ] do
      fixture = AppleAppAttestFixture.build(challenge, "client-data", opts)

      assert {:error, _reason} =
               AppAttest.verify_bind(
                 fixture.evidence,
                 challenge,
                 "client-data",
                 fixture.spki,
                 app_profiles: fixture.profile
               )
    end
  end

  test "rejects extension values outside the governed profile" do
    challenge = :crypto.strong_rand_bytes(32)

    category =
      AppleAppAttestFixture.build(challenge, "client-data", allowed_validation_categories: [4])

    assert {:error, _} =
             AppAttest.verify_bind(
               category.evidence,
               challenge,
               "client-data",
               category.spki,
               app_profiles: category.profile
             )

    version =
      AppleAppAttestFixture.build(challenge, "client-data", allowed_bundle_versions: ["2.0"])

    assert {:error, _} =
             AppAttest.verify_bind(
               version.evidence,
               challenge,
               "client-data",
               version.spki,
               app_profiles: version.profile
             )
  end
end
