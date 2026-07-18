defmodule TamanduaServer.AndroidAttestationFixture do
  @moduledoc false

  import Bitwise

  alias TamanduaServer.Mobile.MobileDeviceIdentityAndroidAttestation, as: Attestation

  @extension_oid {1, 3, 6, 1, 4, 1, 11_129, 2, 1, 17}

  def root do
    :public_key.pkix_test_root_cert(~c"Tamandua Android Attestation Test Root", digest: :sha256)
  end

  def build(challenge, opts \\ []) when is_binary(challenge) do
    key =
      Keyword.get_lazy(opts, :key, fn -> :public_key.generate_key({:namedCurve, :secp256r1}) end)

    root = Keyword.get(opts, :root, [{:digest, :sha256}])
    extension = Keyword.get_lazy(opts, :extension, fn -> key_description(challenge, opts) end)

    generated =
      :public_key.pkix_test_data(%{
        root: root,
        peer: [
          {:digest, :sha256},
          {:key, key},
          {:extensions,
           [
             {:Extension, @extension_oid, false, extension},
             {:Extension, {2, 5, 29, 15}, true, [:digitalSignature]},
             {:Extension, {2, 5, 29, 19}, true, {:BasicConstraints, false, :asn1_NOVALUE}}
           ]}
        ]
      })

    leaf = Keyword.fetch!(generated, :cert)

    root_der =
      case root do
        %{cert: certificate} -> certificate
        _ -> generated |> Keyword.fetch!(:cacerts) |> hd()
      end

    {:Certificate, tbs, _, _} = :public_key.pkix_decode_cert(leaf, :plain)
    spki = tbs |> elem(7) |> then(&:public_key.der_encode(:SubjectPublicKeyInfo, &1))
    chain_der = [leaf, root_der]

    %{
      challenge: challenge,
      root: root_der,
      spki: spki,
      key: key,
      chain_der: chain_der,
      chain: Enum.map(chain_der, &Base.url_encode64(&1, padding: false))
    }
  end

  def verifier_config(fixtures, opts \\ []) do
    fixtures = List.wrap(fixtures)
    roots = fixtures |> Enum.map(& &1.root) |> Enum.uniq()
    revoked = Keyword.get(opts, :revoked, [])
    now = Keyword.get(opts, :now, DateTime.utc_now())

    {public_key, private_key} =
      Keyword.get_lazy(opts, :governance_key_pair, fn ->
        :crypto.generate_key(:eddsa, :ed25519)
      end)

    key_id = Keyword.get(opts, :key_id, "test-governance-key")

    receipt =
      Attestation.freshness_receipt_template(
        roots,
        revoked,
        Keyword.get(opts, :source, "test-governance"),
        Keyword.get(opts, :issued_at, DateTime.add(now, -60, :second)),
        Keyword.get(opts, :expires_at, DateTime.add(now, 3_600, :second))
      )
      |> Attestation.sign_freshness_receipt(key_id, private_key)

    [
      trust_roots_der: roots,
      revoked_certificate_sha256: revoked,
      governance_public_keys: %{key_id => public_key},
      freshness_receipt: receipt,
      unverified_evidence_policy: Keyword.get(opts, :policy, :reject)
    ]
  end

  defp key_description(challenge, opts) do
    security_level = Keyword.get(opts, :security_level, 1)
    device_locked = Keyword.get(opts, :device_locked, true)

    root_of_trust =
      der_sequence(
        der_octet_string(:binary.copy(<<7>>, 32)) <>
          der_boolean(device_locked) <>
          der_enumerated(0) <>
          der_octet_string(:binary.copy(<<8>>, 32))
      )

    hardware_authorizations =
      der_sequence(
        der_context(1, der_set(der_integer(2))) <>
          der_context(2, der_integer(3)) <>
          der_context(3, der_integer(256)) <>
          der_context(5, der_set(der_integer(4))) <>
          der_context(10, der_integer(1)) <>
          der_context(503, der_null()) <>
          der_context(702, der_integer(0)) <>
          der_context(704, root_of_trust)
      )

    der_sequence(
      der_integer(3) <>
        der_enumerated(security_level) <>
        der_integer(4) <>
        der_enumerated(security_level) <>
        der_octet_string(challenge) <>
        der_octet_string(<<>>) <>
        der_sequence(<<>>) <>
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

  defp der_tlv(class, constructed, tag, value) do
    der_identifier(class, constructed, tag) <> der_length(byte_size(value)) <> value
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
