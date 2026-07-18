defmodule TamanduaServer.Mobile.MobileDeviceIdentityAppleAppAttest do
  @moduledoc false

  import Bitwise

  @nonce_oid {1, 2, 840, 113_635, 100, 8, 2}
  @max_object_bytes 32_768
  @max_certificate_bytes 8_192
  @max_chain_length 5
  @max_receipt_bytes 16_384
  @max_cbor_depth 8
  @max_cbor_items 48
  @max_text_bytes 128
  @max_byte_string_bytes 16_384

  @production_aaguid <<"appattest", 0, 0, 0, 0, 0, 0, 0>>
  @development_aaguid "appattestdevelop"

  @p256_spki_prefix <<
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
    0x04
  >>

  @type verified :: %{
          state: String.t(),
          metadata: map(),
          provider_binding: map()
        }

  @validation_categories [1, 2, 3, 4, 5, 6, 10]

  @spec verify_bind(map(), binary(), binary(), binary(), keyword()) ::
          {:ok, verified()} | {:error, atom()}
  def verify_bind(
        evidence,
        challenge,
        assertion_client_data,
        identity_public_key_spki,
        opts \\ []
      )

  def verify_bind(evidence, challenge, assertion_client_data, identity_public_key_spki, opts)
      when is_map(evidence) and is_binary(challenge) and is_binary(assertion_client_data) and
             is_binary(identity_public_key_spki) do
    with "apple_app_attest" <- field(evidence, "provider"),
         {:ok, profile} <- profile(evidence, opts),
         {:ok, key_id} <- canonical_base64url(field(evidence, "key_id_base64url"), 32, 32),
         {:ok, attestation_object} <-
           canonical_base64url(
             field(evidence, "attestation_object_base64url"),
             1,
             @max_object_bytes
           ),
         {:ok, assertion_object} <-
           canonical_base64url(field(evidence, "assertion_base64url"), 1, @max_object_bytes),
         {:ok, asserted_client_data} <-
           canonical_base64url(
             field(evidence, "assertion_client_data_base64url"),
             1,
             @max_object_bytes
           ),
         true <- asserted_client_data == assertion_client_data,
         {:ok, attestation} <- decode_attestation(attestation_object),
         {:ok, chain} <- decode_chain(attestation.x5c),
         {:ok, root} <- validate_path(chain, profile.trust_roots_der),
         {:ok, leaf} <- decode_certificate(hd(chain)),
         {:ok, public_key_spki, public_point} <- leaf_public_key(hd(chain)),
         true <- public_key_spki == identity_public_key_spki,
         true <- :crypto.hash(:sha256, public_point) == key_id,
         {:ok, app_extensions} <-
           verify_attestation_auth_data(attestation.auth_data, key_id, profile),
         :ok <- verify_nonce(leaf, attestation.auth_data, challenge),
         {:ok, assertion} <- decode_assertion(assertion_object),
         {:ok, sign_count} <-
           verify_assertion(
             assertion,
             asserted_client_data,
             public_key_spki,
             profile,
             app_extensions
           ) do
      {:ok,
       %{
         state: "verified_app_attest",
         metadata: %{
           "attestation_evidence_present" => true,
           "attestation_verification" => "server_verified_apple_app_attest",
           "apple_app_attest_profile_id" => profile.id,
           "apple_app_attest_environment" => profile.environment,
           "apple_app_attest_key_id_sha256" => sha256_hex(key_id),
           "apple_app_attest_receipt_sha256" => sha256_hex(attestation.receipt),
           "apple_app_attest_trust_root_sha256" => sha256_hex(root),
           "apple_app_attest_sign_count" => sign_count,
           "apple_validation_category_01" => app_extensions.validation_category,
           "apple_bundle_version_01" => app_extensions.bundle_version
         },
         provider_binding: %{
           provider: "apple_app_attest",
           profile_id: profile.id,
           environment: profile.environment,
           team_id: profile.team_id,
           bundle_id: profile.bundle_id,
           credential_id: key_id,
           public_key_spki: public_key_spki,
           receipt_sha256: :crypto.hash(:sha256, attestation.receipt),
           sign_count: sign_count
         }
       }}
    else
      false -> {:error, :apple_app_attest_binding_invalid}
      {:error, _reason} = error -> error
      _ -> {:error, :apple_app_attest_invalid}
    end
  rescue
    _ -> {:error, :apple_app_attest_invalid}
  catch
    _, _ -> {:error, :apple_app_attest_invalid}
  end

  def verify_bind(_evidence, _challenge, _client_data, _identity_public_key_spki, _opts),
    do: {:error, :apple_app_attest_invalid}

  @spec unverified_evidence_policy() :: :preserve | :reject
  def unverified_evidence_policy do
    case config()[:unverified_evidence_policy] do
      :preserve -> :preserve
      _ -> :reject
    end
  end

  @spec configured_profile(String.t() | nil, keyword()) :: {:ok, map()} | {:error, atom()}
  def configured_profile(profile_id \\ nil, opts \\ []) do
    selected = profile_id || Keyword.get(opts, :default_profile_id, config()[:default_profile_id])
    profile(%{"profile_id" => selected}, opts)
  end

  @spec verify_attestation(map(), binary(), keyword()) :: {:ok, map()} | {:error, atom()}
  def verify_attestation(evidence, client_data, opts \\ [])

  def verify_attestation(evidence, client_data, opts)
      when is_map(evidence) and is_binary(client_data) do
    with "apple_app_attest" <- field(evidence, "provider"),
         {:ok, profile} <- profile(evidence, opts),
         {:ok, key_id} <- canonical_base64url(field(evidence, "key_id_base64url"), 32, 32),
         {:ok, attestation_object} <-
           canonical_base64url(
             field(evidence, "attestation_object_base64url"),
             1,
             @max_object_bytes
           ),
         {:ok, attestation} <- decode_attestation(attestation_object),
         {:ok, chain} <- decode_chain(attestation.x5c),
         {:ok, root} <- validate_path(chain, profile.trust_roots_der),
         {:ok, leaf} <- decode_certificate(hd(chain)),
         {:ok, public_key_spki, public_point} <- leaf_public_key(hd(chain)),
         true <- :crypto.hash(:sha256, public_point) == key_id,
         {:ok, app_extensions} <-
           verify_attestation_auth_data(attestation.auth_data, key_id, profile),
         :ok <- verify_nonce(leaf, attestation.auth_data, client_data) do
      {:ok,
       %{
         profile_id: profile.id,
         environment: profile.environment,
         team_id: profile.team_id,
         bundle_id: profile.bundle_id,
         credential_id: key_id,
         public_key_spki: public_key_spki,
         receipt_sha256: :crypto.hash(:sha256, attestation.receipt),
         validation_category: app_extensions.validation_category,
         bundle_version: app_extensions.bundle_version,
         metadata: %{
           "attestation_evidence_present" => true,
           "attestation_verification" => "server_verified_apple_app_attest",
           "apple_app_attest_profile_id" => profile.id,
           "apple_app_attest_environment" => profile.environment,
           "apple_app_attest_key_id_sha256" => sha256_hex(key_id),
           "apple_app_attest_receipt_sha256" => sha256_hex(attestation.receipt),
           "apple_app_attest_trust_root_sha256" => sha256_hex(root),
           "apple_validation_category_01" => app_extensions.validation_category,
           "apple_bundle_version_01" => app_extensions.bundle_version
         }
       }}
    else
      false -> {:error, :apple_app_attest_binding_invalid}
      {:error, _reason} = error -> error
      _ -> {:error, :apple_app_attest_invalid}
    end
  rescue
    _ -> {:error, :apple_app_attest_invalid}
  catch
    _, _ -> {:error, :apple_app_attest_invalid}
  end

  def verify_attestation(_evidence, _client_data, _opts),
    do: {:error, :apple_app_attest_invalid}

  @spec verify_first_assertion(map(), binary(), map(), keyword()) ::
          {:ok, map()} | {:error, atom()}
  def verify_first_assertion(evidence, client_data, stored, opts \\ [])

  def verify_first_assertion(evidence, client_data, stored, opts)
      when is_map(evidence) and is_binary(client_data) and is_map(stored) do
    with "apple_app_attest" <- field(evidence, "provider"),
         {:ok, profile} <- configured_profile(Map.get(stored, :profile_id), opts),
         true <- profile.environment == Map.get(stored, :environment),
         true <- profile.team_id == Map.get(stored, :team_id),
         true <- profile.bundle_id == Map.get(stored, :bundle_id),
         {:ok, key_id} <- canonical_base64url(field(evidence, "key_id_base64url"), 32, 32),
         true <- key_id == Map.get(stored, :credential_id),
         {:ok, assertion_object} <-
           canonical_base64url(field(evidence, "assertion_base64url"), 1, @max_object_bytes),
         {:ok, assertion} <- decode_assertion(assertion_object),
         expected_extensions <- %{
           validation_category: Map.get(stored, :validation_category),
           bundle_version: Map.get(stored, :bundle_version)
         },
         public_key_spki when is_binary(public_key_spki) <- Map.get(stored, :public_key_spki),
         {:ok, sign_count} <-
           verify_assertion(
             assertion,
             client_data,
             public_key_spki,
             profile,
             expected_extensions
           ) do
      {:ok,
       %{
         sign_count: sign_count,
         metadata:
           Map.merge(Map.get(stored, :metadata, %{}), %{
             "apple_app_attest_sign_count" => sign_count
           }),
         provider_binding: %{
           provider: "apple_app_attest",
           profile_id: Map.fetch!(stored, :profile_id),
           environment: Map.fetch!(stored, :environment),
           team_id: Map.fetch!(stored, :team_id),
           bundle_id: Map.fetch!(stored, :bundle_id),
           credential_id: key_id,
           public_key_spki: public_key_spki,
           receipt_sha256: Map.fetch!(stored, :receipt_sha256),
           sign_count: sign_count
         }
       }}
    else
      false -> {:error, :apple_app_attest_binding_invalid}
      {:error, _reason} = error -> error
      _ -> {:error, :apple_app_attest_invalid}
    end
  rescue
    _ -> {:error, :apple_app_attest_invalid}
  catch
    _, _ -> {:error, :apple_app_attest_invalid}
  end

  def verify_first_assertion(_evidence, _client_data, _stored, _opts),
    do: {:error, :apple_app_attest_invalid}

  defp profile(evidence, opts) do
    profile_id = field(evidence, "profile_id")
    profiles = Keyword.get(opts, :app_profiles, config()[:app_profiles] || %{})
    configured = if is_map(profiles) and is_binary(profile_id), do: Map.get(profiles, profile_id)

    with true <- is_map(configured),
         team_id when is_binary(team_id) <- field(configured, "team_id"),
         true <- team_id =~ ~r/\A[A-Z0-9]{10}\z/,
         bundle_id when is_binary(bundle_id) <- field(configured, "bundle_id"),
         true <- bundle_id =~ ~r/\A[A-Za-z0-9][A-Za-z0-9.-]{2,254}\z/,
         environment when environment in ["development", "production"] <-
           field(configured, "environment"),
         roots when is_list(roots) <- field(configured, "trust_roots_der"),
         true <- roots != [] and length(roots) <= 4,
         true <- Enum.all?(roots, &valid_certificate_der?/1),
         categories when is_list(categories) <-
           field(configured, "allowed_validation_categories"),
         true <-
           categories != [] and length(categories) <= length(@validation_categories) and
             Enum.all?(categories, &(&1 in @validation_categories)),
         bundle_versions when is_list(bundle_versions) <-
           field(configured, "allowed_bundle_versions"),
         true <-
           bundle_versions != [] and length(bundle_versions) <= 32 and
             Enum.all?(bundle_versions, &valid_bundle_version?/1) do
      {:ok,
       %{
         id: profile_id,
         team_id: team_id,
         bundle_id: bundle_id,
         environment: environment,
         trust_roots_der: roots,
         allowed_validation_categories: MapSet.new(categories),
         allowed_bundle_versions: MapSet.new(bundle_versions),
         rp_id_hash: :crypto.hash(:sha256, team_id <> "." <> bundle_id)
       }}
    else
      _ -> {:error, :apple_app_attest_profile_unconfigured}
    end
  end

  defp config, do: Application.get_env(:tamandua_server, __MODULE__, [])

  defp decode_attestation(encoded) do
    with {:ok, value} <- decode_cbor(encoded),
         %{} = object <- value,
         {:text, "apple-appattest"} <- cbor_field(object, "fmt"),
         auth_data when is_binary(auth_data) <- cbor_field(object, "authData"),
         true <- byte_size(auth_data) in 55..@max_object_bytes,
         %{} = statement <- cbor_field(object, "attStmt"),
         x5c when is_list(x5c) <- cbor_field(statement, "x5c"),
         true <- x5c != [] and length(x5c) <= @max_chain_length,
         true <- Enum.all?(x5c, &is_binary/1),
         receipt when is_binary(receipt) <- cbor_field(statement, "receipt"),
         true <- byte_size(receipt) in 1..@max_receipt_bytes,
         true <- map_size(object) == 3 and map_size(statement) == 2 do
      {:ok, %{auth_data: auth_data, x5c: x5c, receipt: receipt}}
    else
      _ -> {:error, :apple_app_attest_attestation_invalid}
    end
  end

  defp decode_assertion(encoded) do
    with {:ok, value} <- decode_cbor(encoded),
         %{} = object <- value,
         signature when is_binary(signature) <- cbor_field(object, "signature"),
         true <- byte_size(signature) in 8..128,
         auth_data when is_binary(auth_data) <- cbor_field(object, "authenticatorData"),
         true <- byte_size(auth_data) in 37..@max_object_bytes,
         true <- map_size(object) == 2 do
      {:ok, %{signature: signature, auth_data: auth_data}}
    else
      _ -> {:error, :apple_app_attest_assertion_invalid}
    end
  end

  defp verify_attestation_auth_data(auth_data, key_id, profile) do
    with <<rp_id_hash::binary-size(32), flags, 0::unsigned-32, aaguid::binary-size(16),
           credential_length::unsigned-16, rest::binary>> <- auth_data,
         true <- rp_id_hash == profile.rp_id_hash,
         true <- (flags &&& 0x40) == 0x40,
         true <- aaguid == expected_aaguid(profile.environment),
         true <- credential_length == 32,
         <<credential_id::binary-size(32), cose_and_extensions::binary>> <- rest,
         true <- credential_id == key_id,
         {:ok, cose_key, extension_bytes} <- decode_cbor_prefix(cose_and_extensions),
         :ok <- verify_cose_key(cose_key, key_id),
         {:ok, extensions} <- verify_app_extensions(flags, extension_bytes, profile) do
      {:ok, extensions}
    else
      _ -> {:error, :apple_app_attest_auth_data_invalid}
    end
  end

  defp expected_aaguid("development"), do: @development_aaguid
  defp expected_aaguid("production"), do: @production_aaguid

  defp verify_cose_key(cose, key_id) when is_map(cose) and map_size(cose) == 5 do
    with 2 <- Map.get(cose, 1),
         -7 <- Map.get(cose, 3),
         1 <- Map.get(cose, -1),
         x when is_binary(x) and byte_size(x) == 32 <- Map.get(cose, -2),
         y when is_binary(y) and byte_size(y) == 32 <- Map.get(cose, -3),
         true <- :crypto.hash(:sha256, <<4, x::binary, y::binary>>) == key_id do
      :ok
    else
      _ -> {:error, :apple_app_attest_cose_key_invalid}
    end
  end

  defp verify_cose_key(_cose, _key_id), do: {:error, :apple_app_attest_cose_key_invalid}

  defp verify_app_extensions(flags, encoded, profile) when (flags &&& 0x80) == 0x80 do
    with {:ok, extensions} <- decode_cbor(encoded),
         true <- is_map(extensions),
         true <- map_size(extensions) == 2,
         validation_category when is_integer(validation_category) <-
           cbor_field(extensions, "apple_validation_category_01"),
         true <- MapSet.member?(profile.allowed_validation_categories, validation_category),
         {:text, bundle_version} when is_binary(bundle_version) <-
           cbor_field(extensions, "apple_bundle_version_01"),
         true <- MapSet.member?(profile.allowed_bundle_versions, bundle_version) do
      {:ok, %{validation_category: validation_category, bundle_version: bundle_version}}
    else
      _ -> {:error, :apple_app_attest_extensions_invalid}
    end
  end

  defp verify_app_extensions(_flags, _encoded, _profile),
    do: {:error, :apple_app_attest_extensions_invalid}

  defp verify_nonce(leaf, auth_data, challenge) do
    client_data_hash = :crypto.hash(:sha256, challenge)
    expected = :crypto.hash(:sha256, auth_data <> client_data_hash)

    with {:ok, extension} <- certificate_extension(leaf, @nonce_oid),
         {:ok, nonce} <- decode_nonce_extension(extension),
         true <- nonce == expected do
      :ok
    else
      _ -> {:error, :apple_app_attest_nonce_invalid}
    end
  end

  defp verify_assertion(assertion, client_data, public_key_spki, profile, attested_extensions) do
    with <<rp_id_hash::binary-size(32), flags, sign_count::unsigned-32, rest::binary>> <-
           assertion.auth_data,
         true <- rp_id_hash == profile.rp_id_hash,
         true <- sign_count > 0,
         {:ok, asserted_extensions} <- verify_app_extensions(flags, rest, profile),
         true <- asserted_extensions == attested_extensions,
         nonce <-
           :crypto.hash(
             :sha256,
             assertion.auth_data <> :crypto.hash(:sha256, client_data)
           ),
         public_key <-
           :public_key.pem_entry_decode({:SubjectPublicKeyInfo, public_key_spki, :not_encrypted}),
         true <- :public_key.verify(nonce, :sha256, assertion.signature, public_key) do
      {:ok, sign_count}
    else
      _ -> {:error, :apple_app_attest_assertion_invalid}
    end
  rescue
    _ -> {:error, :apple_app_attest_assertion_invalid}
  end

  defp canonical_base64url(value, minimum, maximum) when is_binary(value) do
    with true <- byte_size(value) <= div(maximum * 4 + 2, 3),
         {:ok, decoded} <- Base.url_decode64(value, padding: false),
         true <- byte_size(decoded) in minimum..maximum,
         true <- Base.url_encode64(decoded, padding: false) == value do
      {:ok, decoded}
    else
      _ -> {:error, :apple_app_attest_encoding_invalid}
    end
  end

  defp canonical_base64url(_value, _minimum, _maximum),
    do: {:error, :apple_app_attest_encoding_invalid}

  defp decode_chain(chain) when chain != [] and length(chain) <= @max_chain_length do
    if Enum.all?(chain, &(byte_size(&1) in 1..@max_certificate_bytes)) do
      {:ok, chain}
    else
      {:error, :apple_app_attest_chain_invalid}
    end
  end

  defp decode_chain(_chain), do: {:error, :apple_app_attest_chain_invalid}

  defp validate_path(chain, roots) do
    last = List.last(chain)

    case Enum.find(roots, &(&1 == last)) do
      nil ->
        case Enum.find(roots, &safe_issuer?(last, &1)) do
          nil -> {:error, :apple_app_attest_untrusted_chain}
          root -> validate_path_with_root(root, Enum.reverse(chain))
        end

      root ->
        validate_path_with_root(root, chain |> Enum.drop(-1) |> Enum.reverse())
    end
  end

  defp validate_path_with_root(_root, []), do: {:error, :apple_app_attest_leaf_missing}

  defp validate_path_with_root(root, path) do
    case :public_key.pkix_path_validation(root, path, []) do
      {:ok, _} -> {:ok, root}
      _ -> {:error, :apple_app_attest_untrusted_chain}
    end
  rescue
    _ -> {:error, :apple_app_attest_untrusted_chain}
  end

  defp safe_issuer?(certificate, issuer) do
    :public_key.pkix_is_issuer(certificate, issuer)
  rescue
    _ -> false
  end

  defp valid_certificate_der?(der)
       when is_binary(der) and byte_size(der) in 1..@max_certificate_bytes,
       do: match?({:ok, _}, decode_certificate(der))

  defp valid_certificate_der?(_der), do: false

  defp decode_certificate(der) do
    case :public_key.pkix_decode_cert(der, :otp) do
      {:OTPCertificate, _, _, _} = certificate -> {:ok, certificate}
      _ -> {:error, :apple_app_attest_certificate_invalid}
    end
  rescue
    _ -> {:error, :apple_app_attest_certificate_invalid}
  end

  defp leaf_public_key(der) do
    {:Certificate, tbs, _, _} = :public_key.pkix_decode_cert(der, :plain)
    spki = :public_key.der_encode(:SubjectPublicKeyInfo, elem(tbs, 7))

    case spki do
      <<prefix::binary-size(27), coordinates::binary-size(64)>>
      when prefix == @p256_spki_prefix ->
        {:ok, spki, <<4, coordinates::binary>>}

      _ ->
        {:error, :apple_app_attest_public_key_invalid}
    end
  rescue
    _ -> {:error, :apple_app_attest_public_key_invalid}
  end

  defp certificate_extension({:OTPCertificate, tbs, _, _}, oid) do
    case Enum.find(elem(tbs, 10), fn
           {:Extension, ^oid, _critical, value} when is_binary(value) -> true
           _ -> false
         end) do
      {:Extension, ^oid, _critical, value} -> {:ok, value}
      _ -> {:error, :missing}
    end
  rescue
    _ -> {:error, :missing}
  end

  defp decode_nonce_extension(<<0x30, sequence_length, 0x04, nonce_length, nonce::binary>>)
       when sequence_length == nonce_length + 2 and nonce_length == 32,
       do: {:ok, nonce}

  defp decode_nonce_extension(_value), do: {:error, :invalid}

  defp decode_cbor(encoded) when is_binary(encoded) and byte_size(encoded) <= @max_object_bytes do
    with {:ok, value, <<>>, _count} <- decode_cbor_value(encoded, 0, 0), do: {:ok, value}
  end

  defp decode_cbor(_encoded), do: {:error, :apple_app_attest_cbor_invalid}

  defp decode_cbor_prefix(encoded) do
    with {:ok, value, rest, _count} <- decode_cbor_value(encoded, 0, 0),
         do: {:ok, value, rest}
  end

  defp decode_cbor_value(_encoded, depth, _count) when depth > @max_cbor_depth,
    do: {:error, :apple_app_attest_cbor_invalid}

  defp decode_cbor_value(_encoded, _depth, count) when count >= @max_cbor_items,
    do: {:error, :apple_app_attest_cbor_invalid}

  defp decode_cbor_value(<<initial, rest::binary>>, depth, count) do
    major = initial >>> 5
    additional = initial &&& 0x1F

    with {:ok, argument, remaining} <- decode_cbor_argument(additional, rest) do
      decode_cbor_major(major, argument, remaining, depth, count + 1)
    end
  end

  defp decode_cbor_value(_encoded, _depth, _count),
    do: {:error, :apple_app_attest_cbor_invalid}

  defp decode_cbor_argument(value, rest) when value < 24, do: {:ok, value, rest}
  defp decode_cbor_argument(24, <<value, rest::binary>>) when value >= 24, do: {:ok, value, rest}

  defp decode_cbor_argument(25, <<value::unsigned-16, rest::binary>>) when value > 255,
    do: {:ok, value, rest}

  defp decode_cbor_argument(26, <<value::unsigned-32, rest::binary>>) when value > 65_535,
    do: {:ok, value, rest}

  defp decode_cbor_argument(_additional, _rest),
    do: {:error, :apple_app_attest_cbor_invalid}

  defp decode_cbor_major(0, value, rest, _depth, count), do: {:ok, value, rest, count}
  defp decode_cbor_major(1, value, rest, _depth, count), do: {:ok, -1 - value, rest, count}

  defp decode_cbor_major(2, length, rest, _depth, count)
       when length <= @max_byte_string_bytes and byte_size(rest) >= length do
    <<value::binary-size(length), remaining::binary>> = rest
    {:ok, value, remaining, count}
  end

  defp decode_cbor_major(3, length, rest, _depth, count)
       when length <= @max_text_bytes and byte_size(rest) >= length do
    <<value::binary-size(length), remaining::binary>> = rest

    if String.valid?(value),
      do: {:ok, {:text, value}, remaining, count},
      else: {:error, :apple_app_attest_cbor_invalid}
  end

  defp decode_cbor_major(4, length, rest, depth, count) when length <= @max_cbor_items,
    do: decode_cbor_array(length, rest, depth + 1, count, [])

  defp decode_cbor_major(5, length, rest, depth, count) when length <= @max_cbor_items,
    do: decode_cbor_map(length, rest, depth + 1, count, %{}, nil)

  defp decode_cbor_major(_major, _value, _rest, _depth, _count),
    do: {:error, :apple_app_attest_cbor_invalid}

  defp decode_cbor_array(0, rest, _depth, count, acc),
    do: {:ok, Enum.reverse(acc), rest, count}

  defp decode_cbor_array(length, encoded, depth, count, acc) do
    with {:ok, value, rest, next_count} <- decode_cbor_value(encoded, depth, count) do
      decode_cbor_array(length - 1, rest, depth, next_count, [value | acc])
    end
  end

  defp decode_cbor_map(0, rest, _depth, count, acc, _previous), do: {:ok, acc, rest, count}

  defp decode_cbor_map(length, encoded, depth, count, acc, previous) do
    before = byte_size(encoded)

    with {:ok, key, after_key, key_count} <- decode_cbor_value(encoded, depth, count),
         key_size <- before - byte_size(after_key),
         key_encoding <- binary_part(encoded, 0, key_size),
         true <- is_nil(previous) or canonical_key_after?(key_encoding, previous),
         false <- Map.has_key?(acc, key),
         {:ok, value, rest, next_count} <- decode_cbor_value(after_key, depth, key_count) do
      decode_cbor_map(length - 1, rest, depth, next_count, Map.put(acc, key, value), key_encoding)
    else
      _ -> {:error, :apple_app_attest_cbor_invalid}
    end
  end

  defp canonical_key_after?(current, previous) do
    byte_size(current) > byte_size(previous) or
      (byte_size(current) == byte_size(previous) and current > previous)
  end

  defp field(map, key) when is_map(map) do
    case Map.fetch(map, key) do
      {:ok, value} ->
        value

      :error ->
        Enum.find_value(map, fn
          {candidate, value} when is_atom(candidate) ->
            if Atom.to_string(candidate) == key, do: {:found, value}

          _ ->
            nil
        end)
        |> case do
          {:found, value} -> value
          nil -> nil
        end
    end
  end

  defp field(_map, _key), do: nil

  defp cbor_field(map, key), do: Map.get(map, {:text, key})

  defp valid_bundle_version?(value) when is_binary(value) do
    byte_size(value) in 1..64 and value == String.trim(value) and
      value =~ ~r/\A[0-9A-Za-z][0-9A-Za-z._+-]*\z/
  end

  defp valid_bundle_version?(_value), do: false

  defp sha256_hex(value), do: :crypto.hash(:sha256, value) |> Base.encode16(case: :lower)
end
