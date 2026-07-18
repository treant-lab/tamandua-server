defmodule TamanduaServer.AppleAppAttestFixture do
  @moduledoc false

  import Bitwise

  @nonce_oid {1, 2, 840, 113_635, 100, 8, 2}
  @team_id "A1B2C3D4E5"
  @bundle_id "io.tamandua.test"
  @profile_id "ios-test-development"

  def root do
    :public_key.pkix_test_root_cert(~c"Tamandua App Attest Test Root", digest: :sha256)
  end

  def public_key_spki({:ECPrivateKey, _, _, _, <<4, _::binary-size(64)>> = point, _}),
    do: spki(point)

  def build(challenge, client_data, opts \\ [])
      when byte_size(challenge) == 32 and is_binary(client_data) do
    key =
      Keyword.get_lazy(opts, :key, fn -> :public_key.generate_key({:namedCurve, :secp256r1}) end)

    root = Keyword.get_lazy(opts, :root, &root/0)
    environment = Keyword.get(opts, :environment, "development")
    validation_category = Keyword.get(opts, :validation_category, 3)
    bundle_version = Keyword.get(opts, :bundle_version, "1.0")
    point = elem(key, 4)
    <<4, x::binary-size(32), y::binary-size(32)>> = point
    key_id = :crypto.hash(:sha256, point)

    cose = cbor_map([{1, 2}, {3, -7}, {-1, 1}, {-2, x}, {-3, y}])
    aaguid = if environment == "production", do: <<"appattest", 0::56>>, else: "appattestdevelop"
    rp_hash = :crypto.hash(:sha256, @team_id <> "." <> @bundle_id)

    attestation_extension =
      app_extensions(
        Keyword.get(opts, :attestation_extensions, :present),
        validation_category,
        bundle_version
      )

    {attestation_flags, attestation_extension_bytes} =
      extension_auth_data(attestation_extension, 0x40)

    auth_data =
      rp_hash <>
        <<attestation_flags, 0::32, aaguid::binary, 32::16, key_id::binary, cose::binary,
          attestation_extension_bytes::binary>>

    nonce = :crypto.hash(:sha256, auth_data <> :crypto.hash(:sha256, challenge))

    generated =
      :public_key.pkix_test_data(%{
        root: root,
        peer: [
          {:digest, :sha256},
          {:key, key},
          {:extensions,
           [
             {:Extension, @nonce_oid, false, der_sequence(der_octet_string(nonce))},
             {:Extension, {2, 5, 29, 15}, true, [:digitalSignature]},
             {:Extension, {2, 5, 29, 19}, true, {:BasicConstraints, false, :asn1_NOVALUE}}
           ]}
        ]
      })

    leaf = Keyword.fetch!(generated, :cert)
    root_der = root.cert
    receipt = Keyword.get(opts, :receipt, "test-app-attest-receipt")

    attestation =
      cbor_map([
        {"fmt", {:text, "apple-appattest"}},
        {"attStmt",
         {:encoded,
          cbor_map([{"x5c", {:encoded, cbor_array([leaf, root_der])}}, {"receipt", receipt}])}},
        {"authData", auth_data}
      ])

    sign_count = Keyword.get(opts, :sign_count, 1)

    assertion_extension =
      app_extensions(
        Keyword.get(opts, :assertion_extensions, :present),
        Keyword.get(opts, :assertion_validation_category, validation_category),
        Keyword.get(opts, :assertion_bundle_version, bundle_version)
      )

    {assertion_flags, assertion_extension_bytes} = extension_auth_data(assertion_extension, 0)

    assertion_auth_data =
      rp_hash <> <<assertion_flags, sign_count::32, assertion_extension_bytes::binary>>

    assertion_nonce =
      :crypto.hash(:sha256, assertion_auth_data <> :crypto.hash(:sha256, client_data))

    signature = :public_key.sign(assertion_nonce, :sha256, key)

    assertion =
      cbor_map([{"signature", signature}, {"authenticatorData", assertion_auth_data}])

    %{
      evidence: %{
        "provider" => "apple_app_attest",
        "profile_id" => @profile_id,
        "key_id_base64url" => b64(key_id),
        "attestation_object_base64url" => b64(attestation),
        "assertion_base64url" => b64(assertion),
        "assertion_client_data_base64url" => b64(client_data)
      },
      profile: %{
        @profile_id => %{
          "team_id" => @team_id,
          "bundle_id" => @bundle_id,
          "environment" => environment,
          "trust_roots_der" => [root_der],
          "allowed_validation_categories" =>
            Keyword.get(opts, :allowed_validation_categories, [validation_category]),
          "allowed_bundle_versions" =>
            Keyword.get(opts, :allowed_bundle_versions, [bundle_version])
        }
      },
      root: root,
      key: key,
      key_id: key_id,
      public_point: point,
      spki: spki(point),
      sign_count: sign_count
    }
  end

  defp b64(value), do: Base.url_encode64(value, padding: false)

  defp cbor(value) when is_integer(value) and value >= 0, do: cbor_head(0, value)
  defp cbor(value) when is_integer(value), do: cbor_head(1, -1 - value)
  defp cbor(value) when is_binary(value), do: cbor_head(2, byte_size(value)) <> value

  defp cbor_array(values) do
    cbor_head(4, length(values)) <> Enum.map_join(values, &cbor/1)
  end

  defp cbor_map(entries) do
    encoded =
      entries
      |> Enum.map(fn {key, value} -> {cbor_key(key), cbor_value(value)} end)
      |> Enum.sort_by(fn {key, _value} -> {byte_size(key), key} end)

    cbor_head(5, length(encoded)) <> Enum.map_join(encoded, fn {key, value} -> key <> value end)
  end

  defp cbor_key(value), do: if(is_binary(value), do: cbor_text(value), else: cbor(value))
  defp cbor_value({:encoded, value}) when is_binary(value), do: value
  defp cbor_value({:text, value}) when is_binary(value), do: cbor_text(value)
  defp cbor_value(value) when is_binary(value), do: cbor(value)
  defp cbor_value(value) when is_integer(value), do: cbor(value)

  defp cbor_value(value) when is_list(value), do: cbor_array(value)

  defp cbor_value(value) when is_map(value) do
    raise ArgumentError,
          "maps must be pre-encoded to preserve deterministic ordering: #{inspect(value)}"
  end

  # Nested arrays/maps are already encoded by the fixture helpers.
  defp cbor_value(value), do: value

  defp cbor_text(value), do: cbor_head(3, byte_size(value)) <> value
  defp cbor_head(major, value) when value < 24, do: <<major <<< 5 ||| value>>
  defp cbor_head(major, value) when value <= 0xFF, do: <<major <<< 5 ||| 24, value>>
  defp cbor_head(major, value) when value <= 0xFFFF, do: <<major <<< 5 ||| 25, value::16>>
  defp cbor_head(major, value), do: <<major <<< 5 ||| 26, value::32>>

  defp der_sequence(value), do: <<0x30>> <> der_length(byte_size(value)) <> value
  defp der_octet_string(value), do: <<0x04>> <> der_length(byte_size(value)) <> value
  defp der_length(length) when length < 128, do: <<length>>

  defp der_length(length) do
    encoded = :binary.encode_unsigned(length)
    <<0x80 ||| byte_size(encoded)>> <> encoded
  end

  defp app_extensions(:present, validation_category, bundle_version) do
    {:encoded,
     cbor_map([
       {"apple_validation_category_01", validation_category},
       {"apple_bundle_version_01", {:text, bundle_version}}
     ])}
  end

  defp app_extensions(:absent, _validation_category, _bundle_version), do: :absent

  defp app_extensions({:raw, encoded}, _validation_category, _bundle_version),
    do: {:encoded, encoded}

  defp extension_auth_data(:absent, base_flags), do: {base_flags, <<>>}
  defp extension_auth_data({:encoded, encoded}, base_flags), do: {base_flags ||| 0x80, encoded}

  defp spki(<<4, coordinates::binary-size(64)>>) do
    <<
      0x30,
      0x59,
      0x30,
      0x13,
      0x06,
      0x07,
      0x2A,
      0x86,
      0x48,
      0xCE,
      0x3D,
      0x02,
      0x01,
      0x06,
      0x08,
      0x2A,
      0x86,
      0x48,
      0xCE,
      0x3D,
      0x03,
      0x01,
      0x07,
      0x03,
      0x42,
      0x00,
      0x04,
      coordinates::binary
    >>
  end
end
