defmodule TamanduaServer.Mobile.MobileDeviceIdentityAndroidAttestationTest do
  use ExUnit.Case, async: true

  import Bitwise

  alias TamanduaServer.Mobile.MobileDeviceIdentityAndroidAttestation, as: Attestation
  alias TamanduaServer.AndroidAttestationFixture

  @extension_oid {1, 3, 6, 1, 4, 1, 11_129, 2, 1, 17}

  test "verifies a TEE-generated P-256 signing key against an explicit root" do
    fixture = fixture(<<1, 2, 3, 4>>)

    assert {:ok, result} =
             Attestation.verify(
               fixture.chain,
               fixture.challenge,
               fixture.spki,
               verify_opts(fixture)
             )

    assert result.state == "verified_tee"
    assert result.metadata["android_security_level"] == "tee"
    assert result.metadata["android_verified_boot"] == true
    assert byte_size(result.metadata["attestation_leaf_sha256"]) == 64
    refute inspect(result) =~ fixture.challenge
  end

  test "recognizes StrongBox only from signed attestation fields" do
    fixture = fixture(<<4, 3, 2, 1>>, security_level: 2)

    assert {:ok, %{state: "verified_strongbox"}} =
             Attestation.verify(
               fixture.chain,
               fixture.challenge,
               fixture.spki,
               verify_opts(fixture)
             )
  end

  test "requires hardware-enforced NO_AUTH_REQUIRED with the provider's exact NULL encoding" do
    provider_shaped = fixture(<<5, 4, 3, 2>>)

    assert {:ok, %{state: "verified_tee"}} =
             Attestation.verify(
               provider_shaped.chain,
               provider_shaped.challenge,
               provider_shaped.spki,
               verify_opts(provider_shaped)
             )

    missing = fixture(<<6, 4, 3, 2>>, include_no_auth_required: false)

    assert {:error, :android_attestation_authorization_invalid} =
             Attestation.verify(
               missing.chain,
               missing.challenge,
               missing.spki,
               verify_opts(missing)
             )

    software_only =
      fixture(<<7, 4, 3, 2>>,
        include_no_auth_required: false,
        software_extra: der_context(503, der_null())
      )

    assert {:error, :android_attestation_authorization_conflict} =
             Attestation.verify(
               software_only.chain,
               software_only.challenge,
               software_only.spki,
               verify_opts(software_only)
             )

    malformed = fixture(<<8, 4, 3, 2>>, no_auth_required_value: der_integer(0))

    assert {:error, :android_attestation_authorization_invalid} =
             Attestation.verify(
               malformed.chain,
               malformed.challenge,
               malformed.spki,
               verify_opts(malformed)
             )

    conflicting = fixture(<<9, 4, 3, 2>>, software_extra: der_context(503, der_null()))

    assert {:error, :android_attestation_authorization_conflict} =
             Attestation.verify(
               conflicting.chain,
               conflicting.challenge,
               conflicting.spki,
               verify_opts(conflicting)
             )

    duplicate = fixture(<<10, 4, 3, 2>>, hardware_extra: der_context(503, der_null()))

    assert {:error, :android_attestation_extension_invalid} =
             Attestation.verify(
               duplicate.chain,
               duplicate.challenge,
               duplicate.spki,
               verify_opts(duplicate)
             )
  end

  test "shared DataCase fixture mirrors the provider NO_AUTH_REQUIRED profile" do
    fixture = AndroidAttestationFixture.build(<<11, 4, 3, 2>>)
    opts = AndroidAttestationFixture.verifier_config(fixture, policy: :reject)

    assert {:ok, %{state: "verified_tee"}} =
             Attestation.verify(fixture.chain, fixture.challenge, fixture.spki, opts)
  end

  test "fails closed when no governed trust root is configured" do
    fixture = fixture(<<9, 8, 7, 6>>)

    assert {:error, :android_attestation_trust_roots_unconfigured} =
             Attestation.verify(fixture.chain, fixture.challenge, fixture.spki,
               trust_roots_der: []
             )
  end

  test "rejects an untrusted certificate chain" do
    fixture = fixture(<<10, 11, 12>>)
    other = fixture(<<10, 11, 12>>)

    assert {:error, :android_attestation_untrusted_chain} =
             Attestation.verify(
               fixture.chain,
               fixture.challenge,
               fixture.spki,
               verify_opts(other)
             )
  end

  test "binds both the server challenge and leaf SPKI" do
    fixture = fixture(<<21, 22, 23>>)

    assert {:error, :android_attestation_challenge_mismatch} =
             Attestation.verify(fixture.chain, <<0, 1>>, fixture.spki, verify_opts(fixture))

    other = fixture(<<21, 22, 23>>)

    assert {:error, :android_attestation_spki_mismatch} =
             Attestation.verify(
               fixture.chain,
               fixture.challenge,
               other.spki,
               verify_opts(fixture)
             )
  end

  test "rejects malformed extensions and software-only security levels" do
    malformed = fixture(<<31, 32>>, extension: der_sequence(der_integer(1)))

    assert {:error, :android_attestation_extension_invalid} =
             Attestation.verify(
               malformed.chain,
               malformed.challenge,
               malformed.spki,
               verify_opts(malformed)
             )

    software = fixture(<<33, 34>>, security_level: 0)

    assert {:error, :android_attestation_software_security_level} =
             Attestation.verify(
               software.chain,
               software.challenge,
               software.spki,
               verify_opts(software)
             )
  end

  test "rejects an unlocked device and revoked certificates" do
    unlocked = fixture(<<41, 42>>, device_locked: false)

    assert {:error, :android_attestation_root_of_trust_invalid} =
             Attestation.verify(
               unlocked.chain,
               unlocked.challenge,
               unlocked.spki,
               verify_opts(unlocked)
             )

    fixture = fixture(<<43, 44>>)
    [leaf | _] = fixture.chain_der
    revoked = Base.encode16(:crypto.hash(:sha256, leaf), case: :lower)

    assert {:error, :android_attestation_certificate_revoked} =
             Attestation.verify(
               fixture.chain,
               fixture.challenge,
               fixture.spki,
               verify_opts(fixture, [revoked])
             )
  end

  test "requires a fresh receipt bound to roots and the complete revocation set" do
    fixture = fixture(<<51, 52>>)
    now = DateTime.utc_now()
    valid = verify_opts(fixture)
    {public_key, private_key} = :crypto.generate_key(:eddsa, :ed25519)

    assert {:error, :android_attestation_governance_receipt_invalid} =
             Attestation.verify(fixture.chain, fixture.challenge, fixture.spki,
               trust_roots_der: [fixture.root],
               revoked_certificate_sha256: [],
               freshness_receipt: nil,
               now: now
             )

    stale_receipt =
      Attestation.freshness_receipt_template(
        [fixture.root],
        [],
        "test-governance",
        DateTime.add(now, -7_200, :second),
        DateTime.add(now, -3_600, :second)
      )
      |> Attestation.sign_freshness_receipt("stale-key", private_key)

    stale_opts =
      Keyword.merge(valid,
        governance_public_keys: %{"stale-key" => public_key},
        freshness_receipt: stale_receipt,
        now: now
      )

    assert {:error, :android_attestation_governance_receipt_invalid} =
             Attestation.verify(
               fixture.chain,
               fixture.challenge,
               fixture.spki,
               stale_opts
             )

    mismatched =
      put_in(valid, [:freshness_receipt, :revocation_set_sha256], String.duplicate("0", 64))

    assert {:error, :android_attestation_governance_receipt_invalid} =
             Attestation.verify(fixture.chain, fixture.challenge, fixture.spki, mismatched)

    {wrong_public_key, _wrong_private_key} = :crypto.generate_key(:eddsa, :ed25519)

    wrong_key =
      Keyword.put(valid, :governance_public_keys, %{"test-governance-key" => wrong_public_key})

    assert {:error, :android_attestation_governance_receipt_invalid} =
             Attestation.verify(fixture.chain, fixture.challenge, fixture.spki, wrong_key)

    tampered = put_in(valid, [:freshness_receipt, :source], "tampered-governance")

    assert {:error, :android_attestation_governance_receipt_invalid} =
             Attestation.verify(fixture.chain, fixture.challenge, fixture.spki, tampered)
  end

  test "fails closed on malformed or duplicate governed configuration" do
    fixture = fixture(<<53, 54>>)

    assert {:error, :android_attestation_revocation_config_invalid} =
             Attestation.verify(fixture.chain, fixture.challenge, fixture.spki,
               trust_roots_der: [fixture.root],
               revoked_certificate_sha256: ["not-a-digest"]
             )

    assert {:error, :android_attestation_trust_roots_invalid} =
             Attestation.verify(fixture.chain, fixture.challenge, fixture.spki,
               trust_roots_der: [fixture.root, fixture.root]
             )

    assert {:error, :android_attestation_trust_roots_invalid} =
             Attestation.verify(fixture.chain, fixture.challenge, fixture.spki,
               trust_roots_der: [<<1, 2, 3>>]
             )
  end

  test "pre-bounds encoded and aggregate chain input and requires canonical base64url" do
    fixture = fixture(<<55, 56>>)
    [leaf | rest] = fixture.chain
    noncanonical = [leaf <> "=" | rest]

    assert {:error, :android_attestation_chain_invalid} =
             Attestation.verify(
               noncanonical,
               fixture.challenge,
               fixture.spki,
               verify_opts(fixture)
             )

    oversized = List.duplicate(String.duplicate("A", 21_846), 7)

    assert {:error, :android_attestation_chain_invalid} =
             Attestation.verify(oversized, fixture.challenge, fixture.spki, verify_opts(fixture))
  end

  test "rejects authorization conflicts, extra purpose members, and malformed boot identity" do
    conflicting = fixture(<<61>>, software_conflict: true)

    assert {:error, :android_attestation_authorization_conflict} =
             Attestation.verify(
               conflicting.chain,
               conflicting.challenge,
               conflicting.spki,
               verify_opts(conflicting)
             )

    extra_purpose = fixture(<<62>>, purpose_values: [2, 3])

    assert {:error, :android_attestation_authorization_invalid} =
             Attestation.verify(
               extra_purpose.chain,
               extra_purpose.challenge,
               extra_purpose.spki,
               verify_opts(extra_purpose)
             )

    empty_boot = fixture(<<63>>, boot_key: <<>>, boot_hash: <<>>)

    assert {:error, :android_attestation_root_of_trust_invalid} =
             Attestation.verify(
               empty_boot.chain,
               empty_boot.challenge,
               empty_boot.spki,
               verify_opts(empty_boot)
             )

    for {challenge, sentinel} <- [{<<64>>, 0}, {<<65>>, 255}] do
      fixture =
        fixture(challenge,
          boot_key: :binary.copy(<<sentinel>>, 32),
          boot_hash: :binary.copy(<<sentinel>>, 32)
        )

      assert {:error, :android_attestation_root_of_trust_invalid} =
               Attestation.verify(
                 fixture.chain,
                 fixture.challenge,
                 fixture.spki,
                 verify_opts(fixture)
               )
    end
  end

  test "rejects forbidden and unsupported authorization tags but allows bounded patch metadata" do
    all_applications =
      fixture(<<66>>, hardware_extra: der_context(600, der_tlv(0, false, 5, <<>>)))

    assert {:error, :android_attestation_authorization_forbidden} =
             Attestation.verify(
               all_applications.chain,
               all_applications.challenge,
               all_applications.spki,
               verify_opts(all_applications)
             )

    unsupported = fixture(<<67>>, hardware_extra: der_context(999, der_integer(1)))

    assert {:error, :android_attestation_authorization_unsupported} =
             Attestation.verify(
               unsupported.chain,
               unsupported.challenge,
               unsupported.spki,
               verify_opts(unsupported)
             )

    informational =
      fixture(<<68>>,
        hardware_extra:
          der_context(705, der_integer(120_000)) <>
            der_context(706, der_integer(202_607)) <>
            der_context(718, der_integer(202_607)) <>
            der_context(719, der_integer(202_607))
      )

    assert {:ok, %{state: "verified_tee"}} =
             Attestation.verify(
               informational.chain,
               informational.challenge,
               informational.spki,
               verify_opts(informational)
             )
  end

  test "validates intermediate paths with the configured root included or omitted" do
    full = fixture(<<71, 72>>, intermediates: [[digest: :sha256]])
    omitted = fixture(<<73, 74>>, intermediates: [[digest: :sha256]], chain_shape: :omit_root)

    assert length(full.chain) == 3

    assert {:ok, %{state: "verified_tee"}} =
             Attestation.verify(full.chain, full.challenge, full.spki, verify_opts(full))

    assert length(omitted.chain) == 2

    assert {:ok, %{state: "verified_tee"}} =
             Attestation.verify(
               omitted.chain,
               omitted.challenge,
               omitted.spki,
               verify_opts(omitted)
             )
  end

  test "rejects reverse, duplicate, and unrelated path material" do
    reversed = fixture(<<75>>, intermediates: [[digest: :sha256]], chain_shape: :reverse)
    duplicated = fixture(<<76>>, intermediates: [[digest: :sha256]], chain_shape: :duplicate_leaf)
    valid = fixture(<<77>>, intermediates: [[digest: :sha256]])
    unrelated = fixture(<<78>>)

    for {fixture, chain} <- [
          {reversed, reversed.chain},
          {duplicated, duplicated.chain},
          {valid, valid.chain ++ [unrelated.root |> Base.url_encode64(padding: false)]}
        ] do
      assert {:error, :android_attestation_untrusted_chain} =
               Attestation.verify(chain, fixture.challenge, fixture.spki, verify_opts(fixture))
    end
  end

  test "rejects expired and not-yet-valid leaf certificates" do
    expired =
      fixture(<<81>>,
        peer_options: [validity: {certificate_date(-2), certificate_date(-1)}]
      )

    future =
      fixture(<<82>>,
        peer_options: [validity: {certificate_date(1), certificate_date(2)}]
      )

    expired_root =
      fixture(<<89>>,
        root_options: [
          digest: :sha256,
          validity: {certificate_date(-2), certificate_date(-1)}
        ]
      )

    future_root =
      fixture(<<90>>,
        root_options: [
          digest: :sha256,
          validity: {certificate_date(1), certificate_date(2)}
        ]
      )

    for fixture <- [expired, future] do
      assert {:error, :android_attestation_certificate_not_current} =
               Attestation.verify(
                 fixture.chain,
                 fixture.challenge,
                 fixture.spki,
                 verify_opts(fixture)
               )
    end

    for fixture <- [expired_root, future_root] do
      assert {:error, :android_attestation_certificate_not_current} =
               Attestation.verify(
                 fixture.chain,
                 fixture.challenge,
                 fixture.spki,
                 verify_opts(fixture)
               )
    end
  end

  test "uses the same injected time at certificate validity boundaries" do
    today = Date.utc_today()
    boundary_now = DateTime.new!(today, ~T[13:00:00], "Etc/UTC")

    at_not_before =
      fixture(<<92>>,
        peer_options: [validity: {Date.to_erl(today), certificate_date(1)}]
      )

    at_not_after =
      fixture(<<93>>,
        peer_options: [validity: {certificate_date(-1), Date.to_erl(today)}]
      )

    for {boundary, fixture} <- [not_before: at_not_before, not_after: at_not_after] do
      opts = verify_opts(fixture, [], boundary_now)

      assert {:ok, %{state: "verified_tee"}} =
               Attestation.verify(fixture.chain, fixture.challenge, fixture.spki, opts),
             "expected #{boundary} to be inclusive"
    end

    assert {:error, :android_attestation_certificate_not_current} =
             Attestation.verify(
               at_not_after.chain,
               at_not_after.challenge,
               at_not_after.spki,
               verify_opts(at_not_after, [], DateTime.add(boundary_now, 1, :second))
             )
  end

  test "rejects invalid leaf CA/key usage and a leaf used as its own anchor" do
    ca_leaf = fixture(<<83>>, leaf_ca: true)
    wrong_usage = fixture(<<84>>, leaf_key_usage: [:keyAgreement])
    leaf_anchor = fixture(<<85>>)
    [leaf | _] = leaf_anchor.chain_der
    leaf_chain = [Base.url_encode64(leaf, padding: false)]
    leaf_anchor_opts = governance_opts([leaf])

    assert {:error, _reason} =
             Attestation.verify(
               ca_leaf.chain,
               ca_leaf.challenge,
               ca_leaf.spki,
               verify_opts(ca_leaf)
             )

    assert {:error, _reason} =
             Attestation.verify(
               wrong_usage.chain,
               wrong_usage.challenge,
               wrong_usage.spki,
               verify_opts(wrong_usage)
             )

    assert {:error, :android_attestation_trust_roots_invalid} =
             Attestation.verify(
               leaf_chain,
               leaf_anchor.challenge,
               leaf_anchor.spki,
               leaf_anchor_opts
             )
  end

  test "rejects intermediate CA, key usage, and path-length violations" do
    invalid_ca =
      [
        digest: :sha256,
        extensions: [
          {:Extension, {2, 5, 29, 19}, true, {:BasicConstraints, false, :asn1_NOVALUE}},
          {:Extension, {2, 5, 29, 15}, true, [:keyCertSign]}
        ]
      ]

    invalid_usage =
      [
        digest: :sha256,
        extensions: [
          {:Extension, {2, 5, 29, 19}, true, {:BasicConstraints, true, :asn1_NOVALUE}},
          {:Extension, {2, 5, 29, 15}, true, [:digitalSignature]}
        ]
      ]

    path_len_zero =
      [
        digest: :sha256,
        extensions: [
          {:Extension, {2, 5, 29, 19}, true, {:BasicConstraints, true, 0}},
          {:Extension, {2, 5, 29, 15}, true, [:keyCertSign]}
        ]
      ]

    fixtures = [
      fixture(<<86>>, intermediates: [invalid_ca]),
      fixture(<<87>>, intermediates: [invalid_usage]),
      fixture(<<88>>, intermediates: [path_len_zero, [digest: :sha256]])
    ]

    for fixture <- fixtures do
      assert {:error, :android_attestation_untrusted_chain} =
               Attestation.verify(
                 fixture.chain,
                 fixture.challenge,
                 fixture.spki,
                 verify_opts(fixture)
               )
    end

    invalid_root =
      fixture(<<91>>,
        root_options: [
          digest: :sha256,
          extensions: [
            {:Extension, {2, 5, 29, 19}, true, {:BasicConstraints, false, :asn1_NOVALUE}},
            {:Extension, {2, 5, 29, 15}, true, [:digitalSignature]}
          ]
        ]
      )

    assert {:error, :android_attestation_trust_roots_invalid} =
             Attestation.verify(
               invalid_root.chain,
               invalid_root.challenge,
               invalid_root.spki,
               verify_opts(invalid_root)
             )
  end

  defp verify_opts(fixture, revoked \\ [], now \\ DateTime.utc_now()) do
    {public_key, private_key} = :crypto.generate_key(:eddsa, :ed25519)

    receipt =
      Attestation.freshness_receipt_template(
        [fixture.root],
        revoked,
        "test-governance",
        DateTime.add(now, -60, :second),
        DateTime.add(now, 3_600, :second)
      )
      |> Attestation.sign_freshness_receipt("test-governance-key", private_key)

    [
      trust_roots_der: [fixture.root],
      revoked_certificate_sha256: revoked,
      governance_public_keys: %{"test-governance-key" => public_key},
      freshness_receipt: receipt,
      now: now
    ]
  end

  defp governance_opts(roots) do
    now = DateTime.utc_now()
    {public_key, private_key} = :crypto.generate_key(:eddsa, :ed25519)

    receipt =
      Attestation.freshness_receipt_template(
        roots,
        [],
        "test-governance",
        DateTime.add(now, -60, :second),
        DateTime.add(now, 3_600, :second)
      )
      |> Attestation.sign_freshness_receipt("test-governance-key", private_key)

    [
      trust_roots_der: roots,
      revoked_certificate_sha256: [],
      governance_public_keys: %{"test-governance-key" => public_key},
      freshness_receipt: receipt,
      now: now
    ]
  end

  defp certificate_date(offset), do: Date.utc_today() |> Date.add(offset) |> Date.to_erl()

  defp fixture(challenge, opts \\ []) do
    key = :public_key.generate_key({:namedCurve, :secp256r1})
    extension = Keyword.get_lazy(opts, :extension, fn -> key_description(challenge, opts) end)
    leaf_key_usage = Keyword.get(opts, :leaf_key_usage, [:digitalSignature])
    leaf_ca = Keyword.get(opts, :leaf_ca, false)

    generated =
      :public_key.pkix_test_data(%{
        root: Keyword.get(opts, :root_options, [{:digest, :sha256}]),
        intermediates: Keyword.get(opts, :intermediates, []),
        peer:
          [
            {:digest, :sha256},
            {:key, key},
            {:extensions,
             [
               {:Extension, @extension_oid, false, extension},
               {:Extension, {2, 5, 29, 15}, true, leaf_key_usage},
               {:Extension, {2, 5, 29, 19}, true, {:BasicConstraints, leaf_ca, :asn1_NOVALUE}}
             ]}
          ] ++ Keyword.get(opts, :peer_options, [])
      })

    leaf = Keyword.fetch!(generated, :cert)
    root = generated |> Keyword.fetch!(:cacerts) |> hd()
    {:Certificate, tbs, _, _} = :public_key.pkix_decode_cert(leaf, :plain)
    spki = tbs |> elem(7) |> then(&:public_key.der_encode(:SubjectPublicKeyInfo, &1))
    chain_der = build_chain(leaf, root, Keyword.fetch!(generated, :cacerts))

    chain_der =
      case Keyword.get(opts, :chain_shape, :full) do
        :omit_root -> Enum.drop(chain_der, -1)
        :reverse -> Enum.reverse(chain_der)
        :duplicate_leaf -> [leaf | chain_der]
        _ -> chain_der
      end

    %{
      challenge: challenge,
      root: root,
      spki: spki,
      chain_der: chain_der,
      chain: Enum.map(chain_der, &Base.url_encode64(&1, padding: false))
    }
  end

  defp build_chain(leaf, root, candidates),
    do: build_chain([leaf], leaf, root, Enum.uniq(candidates))

  defp build_chain(acc, root, root, _candidates), do: acc

  defp build_chain(acc, current, root, candidates) do
    issuer = Enum.find(candidates, &:public_key.pkix_is_issuer(current, &1))

    if is_nil(issuer) or issuer in acc,
      do: acc,
      else: build_chain(acc ++ [issuer], issuer, root, candidates)
  end

  defp key_description(challenge, opts) do
    security_level = Keyword.get(opts, :security_level, 1)
    attestation_level = Keyword.get(opts, :attestation_security_level, security_level)
    keymint_level = Keyword.get(opts, :keymint_security_level, security_level)
    device_locked = Keyword.get(opts, :device_locked, true)
    boot_key = Keyword.get(opts, :boot_key, :binary.copy(<<7>>, 32))
    boot_hash = Keyword.get(opts, :boot_hash, :binary.copy(<<8>>, 32))
    purpose_values = Keyword.get(opts, :purpose_values, [2])
    digest_values = Keyword.get(opts, :digest_values, [4])

    root_of_trust =
      der_sequence(
        der_octet_string(boot_key) <>
          der_boolean(device_locked) <>
          der_enumerated(0) <>
          der_octet_string(boot_hash)
      )

    software_payload =
      if Keyword.get(opts, :software_conflict, false),
        do: der_context(2, der_integer(3)),
        else: <<>>

    software_authorizations =
      der_sequence(software_payload <> Keyword.get(opts, :software_extra, <<>>))

    hardware_authorizations =
      der_sequence(
        der_context(1, der_set(Enum.map_join(purpose_values, &der_integer/1))) <>
          der_context(2, der_integer(3)) <>
          der_context(3, der_integer(256)) <>
          der_context(5, der_set(Enum.map_join(digest_values, &der_integer/1))) <>
          der_context(10, der_integer(1)) <>
          no_auth_required(opts) <>
          der_context(702, der_integer(0)) <>
          der_context(704, root_of_trust) <>
          Keyword.get(opts, :hardware_extra, <<>>)
      )

    der_sequence(
      der_integer(3) <>
        der_enumerated(attestation_level) <>
        der_integer(4) <>
        der_enumerated(keymint_level) <>
        der_octet_string(challenge) <>
        der_octet_string(<<>>) <>
        software_authorizations <>
        hardware_authorizations
    )
  end

  defp der_sequence(value), do: der_tlv(0, true, 16, value)
  defp der_set(value), do: der_tlv(0, true, 17, value)
  defp der_octet_string(value), do: der_tlv(0, false, 4, value)
  defp der_null, do: der_tlv(0, false, 5, <<>>)
  defp der_boolean(true), do: der_tlv(0, false, 1, <<255>>)
  defp der_boolean(false), do: der_tlv(0, false, 1, <<0>>)
  defp der_integer(value), do: der_tlv(0, false, 2, der_integer_bytes(value))
  defp der_enumerated(value), do: der_tlv(0, false, 10, der_integer_bytes(value))
  defp der_context(tag, value), do: der_tlv(2, true, tag, value)

  defp no_auth_required(opts) do
    if Keyword.get(opts, :include_no_auth_required, true) do
      der_context(503, Keyword.get(opts, :no_auth_required_value, der_null()))
    else
      <<>>
    end
  end

  defp der_tlv(class, constructed, tag, value) do
    identifier = der_identifier(class, constructed, tag)
    identifier <> der_length(byte_size(value)) <> value
  end

  defp der_identifier(class, constructed, tag) when tag < 31 do
    <<class <<< 6 ||| if(constructed, do: 0x20, else: 0) ||| tag>>
  end

  defp der_identifier(class, constructed, tag) do
    prefix = <<class <<< 6 ||| if(constructed, do: 0x20, else: 0) ||| 0x1F>>
    prefix <> der_high_tag(tag)
  end

  defp der_high_tag(tag) do
    digits = high_tag_digits(tag, [])

    digits
    |> Enum.with_index()
    |> Enum.map(fn {digit, index} ->
      if index < length(digits) - 1, do: digit ||| 0x80, else: digit
    end)
    |> :erlang.list_to_binary()
  end

  defp high_tag_digits(tag, acc) when tag < 128, do: [tag | acc]
  defp high_tag_digits(tag, acc), do: high_tag_digits(tag >>> 7, [tag &&& 0x7F | acc])

  defp der_length(length) when length < 128, do: <<length>>

  defp der_length(length) do
    bytes = :binary.encode_unsigned(length)
    <<0x80 ||| byte_size(bytes)>> <> bytes
  end

  defp der_integer_bytes(0), do: <<0>>

  defp der_integer_bytes(value) do
    bytes = :binary.encode_unsigned(value)
    if :binary.first(bytes) >= 128, do: <<0>> <> bytes, else: bytes
  end
end
