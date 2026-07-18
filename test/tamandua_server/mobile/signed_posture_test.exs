defmodule TamanduaServer.Mobile.SignedPostureTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Mobile.SignedPosture

  @fixture_path Path.expand(
                  "../../../../../tools/detection_validation/fixtures/mobile_signed_posture_v1.json",
                  __DIR__
                )
  @fixture_sha256 "83eed8c8c3aa93d8da50fe70ac5ed4cfd250926d2024f705d9df9cc5b1974983"
  @now ~U[2026-07-16 12:03:00Z]
  @context_fields ~w(
    organization_id installation_id device_key_id key_scope_id request_id challenge_id nonce
  )

  setup_all do
    raw = File.read!(@fixture_path)
    assert Base.encode16(:crypto.hash(:sha256, raw), case: :lower) == @fixture_sha256
    fixture = decode_pinned_fixture!(raw)

    {:ok,
     fixture: fixture,
     envelope: fixture["envelope"],
     posture: fixture["posture"],
     public_key_spki: decode64(fixture["public_key"]["value"]),
     expected_context: Map.take(fixture["envelope"], @context_fields)}
  end

  test "verifies the pinned local-contract vector with server-owned context", context do
    assert {:ok, verified} = verify_fixture(context)
    assert verified.request_id == context.envelope["request_id"]
    assert verified.challenge_id == context.envelope["challenge_id"]
    assert verified.posture_sha256 == context.envelope["posture_sha256"]
    assert verified.signed_payload_sha256 == context.envelope["signed_payload_sha256"]
  end

  test "canonical payloads exactly match the pinned vector", context do
    expected_posture_payload = context.fixture["canonical_posture_payload"]
    expected_payload = context.fixture["canonical_payload"]

    assert {:ok, ^expected_posture_payload} =
             SignedPosture.canonical_posture_payload(context.posture)

    assert {:ok, ^expected_payload} = SignedPosture.canonical_payload(context.envelope)
  end

  test "requires complete server-owned context and rejects mismatches", context do
    assert SignedPosture.verify(context.envelope, context.posture, context.public_key_spki,
             now: @now
           ) == {:error, :expected_context_required}

    mismatched =
      Map.put(
        context.expected_context,
        "nonce",
        Base.url_encode64(:binary.copy(<<9>>, 32), padding: false)
      )

    assert verify_fixture(context, expected_context: mismatched) ==
             {:error, :expected_context_mismatch}

    incomplete = Map.delete(context.expected_context, "challenge_id")

    assert verify_fixture(context, expected_context: incomplete) ==
             {:error, :invalid_expected_context}
  end

  test "enforces canonical identifiers and distinct request binding", context do
    bad_key = Map.put(context.envelope, "device_key_id", "tmdk_v1_short")
    assert verify_fixture(context, envelope: bad_key) == {:error, :invalid_identifier}

    bad_scope = Map.put(context.envelope, "key_scope_id", "tmdks_v1_short")
    assert verify_fixture(context, envelope: bad_scope) == {:error, :invalid_identifier}

    equal_binding = Map.put(context.envelope, "request_id", context.envelope["challenge_id"])
    assert verify_fixture(context, envelope: equal_binding) == {:error, :invalid_request_binding}
  end

  test "rejects future envelopes, expired envelopes, and observations outside TTL", context do
    assert verify_fixture(context, now: ~U[2026-07-16 11:59:59Z]) ==
             {:error, :envelope_not_yet_valid}

    assert verify_fixture(context, now: ~U[2026-07-16 12:05:00Z]) ==
             {:error, :envelope_expired}

    posture = Map.put(context.posture, "observed_at", "2026-07-16T12:05:00.001Z")
    assert verify_fixture(context, posture: posture) == {:error, :invalid_observation_window}

    overlong_ttl = Map.put(context.envelope, "expires_at", "2026-07-16T12:05:00.001Z")
    assert verify_fixture(context, envelope: overlong_ttl) == {:error, :invalid_ttl}
  end

  test "requires millisecond UTC and binary string keys", context do
    bad_time = Map.put(context.envelope, "issued_at", "2026-07-16T12:00:00Z")
    assert verify_fixture(context, envelope: bad_time) == {:error, :invalid_time}

    atom_keyed =
      context.envelope
      |> Map.delete("protocol")
      |> Map.put(:protocol, context.envelope["protocol"])

    assert SignedPosture.canonical_payload(atom_keyed) == {:error, :invalid_fields}
  end

  test "rejects non-minimal DER and signature mutation before cryptographic acceptance",
       context do
    zero_r =
      Base.url_encode64(<<0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01>>,
        padding: false
      )

    malformed = Map.put(context.envelope, "signature", zero_r)
    assert verify_fixture(context, envelope: malformed) == {:error, :invalid_signature}

    signature = decode64(context.envelope["signature"])
    <<head, tail::binary>> = signature

    mutated_signature =
      Base.url_encode64(<<Bitwise.bxor(head, 1), tail::binary>>, padding: false)

    mutated = Map.put(context.envelope, "signature", mutated_signature)
    assert verify_fixture(context, envelope: mutated) == {:error, :invalid_signature}
  end

  test "binds device key to organization and SPKI", context do
    other_spki = :binary.copy(<<1>>, byte_size(context.public_key_spki))
    assert verify_fixture(context, public_key_spki: other_spki) == {:error, :invalid_public_key}
  end

  test "rejects private material, unsupported fields, and elevated claims", context do
    assert SignedPosture.canonical_payload(Map.put(context.envelope, "private_key", "secret")) ==
             {:error, :private_material_in_posture}

    assert SignedPosture.canonical_payload(Map.put(context.envelope, "network", %{})) ==
             {:error, :invalid_fields}

    elevated = Map.put(context.envelope, "external_claim_allowed", true)
    assert verify_fixture(context, envelope: elevated) == {:error, :external_claim_not_allowed}
  end

  defp verify_fixture(context, overrides \\ []) do
    envelope = Keyword.get(overrides, :envelope, context.envelope)
    posture = Keyword.get(overrides, :posture, context.posture)
    public_key_spki = Keyword.get(overrides, :public_key_spki, context.public_key_spki)
    expected_context = Keyword.get(overrides, :expected_context, context.expected_context)
    now = Keyword.get(overrides, :now, @now)

    SignedPosture.verify(envelope, posture, public_key_spki,
      now: now,
      expected_context: expected_context
    )
  end

  defp decode64(value), do: Base.url_decode64!(value, padding: false)

  # The fixture hash is checked before evaluation. This keeps the pure runner
  # usable on OTP 26, where the OTP 27 `:json` module is unavailable, without
  # adding an application dependency to this isolated contract test.
  defp decode_pinned_fixture!(raw) do
    {fixture, []} =
      raw
      |> String.replace("{", "%{")
      |> String.replace(~r/"([^"]+)"\s*:/, "\"\\1\" =>")
      |> Code.eval_string()

    fixture
  end
end
