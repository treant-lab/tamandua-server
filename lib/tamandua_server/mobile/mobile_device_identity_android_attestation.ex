defmodule TamanduaServer.Mobile.MobileDeviceIdentityAndroidAttestation do
  @moduledoc false

  import Bitwise

  @extension_oid {1, 3, 6, 1, 4, 1, 11_129, 2, 1, 17}
  @max_chain_length 8
  @max_certificate_bytes 16_384
  @max_encoded_certificate_bytes 21_846
  @max_encoded_chain_bytes 131_072
  @max_extension_bytes 16_384
  @max_der_children 96
  @max_trust_roots 16

  @ec_algorithm 3
  @p256_curve 1
  @sha256_digest 4
  @sign_purpose 2
  @generated_origin 0
  @verified_boot 0
  @hardware_authorization_tags [1, 2, 3, 5, 10, 503, 702, 704, 705, 706, 718, 719]
  @software_authorization_tags [1, 2, 3, 5, 10, 503, 701, 702, 704, 705, 706, 709, 718, 719]
  @forbidden_authorization_tags [600]
  @freshness_receipt_version 1
  @freshness_receipt_protocol "tamandua.android-attestation-governance/v1"
  @max_receipt_lifetime_seconds 604_800
  @max_receipt_future_skew_seconds 300

  @type expected_challenge :: binary() | {:sha256, binary()}

  @spec verify([String.t()], expected_challenge(), binary(), keyword()) ::
          {:ok, %{state: String.t(), metadata: map()}} | {:error, atom()}
  def verify(chain_base64url, expected_challenge, expected_spki, opts \\ [])

  def verify(chain_base64url, expected_challenge, expected_spki, opts)
      when is_list(chain_base64url) and
             (is_binary(expected_challenge) or
                (is_tuple(expected_challenge) and tuple_size(expected_challenge) == 2)) and
             is_binary(expected_spki) do
    with {:ok, trust_roots} <- trust_roots(opts),
         {:ok, revoked} <- revoked_certificates(opts),
         {:ok, receipt} <- validate_freshness_receipt(trust_roots, revoked, opts),
         {:ok, chain} <- decode_chain(chain_base64url),
         :ok <- validate_certificate_times(chain ++ trust_roots, receipt.now),
         :ok <- reject_revoked(chain, revoked),
         {:ok, trust_root} <- validate_path(chain, trust_roots),
         {:ok, leaf} <- decode_certificate(hd(chain)),
         :ok <- verify_leaf_constraints(leaf),
         :ok <- verify_leaf_spki(hd(chain), expected_spki),
         {:ok, extension} <- attestation_extension(leaf),
         {:ok, description} <- parse_key_description(extension),
         :ok <- verify_description(description, expected_challenge) do
      state =
        if description.keymint_security_level == 2,
          do: "verified_strongbox",
          else: "verified_tee"

      {:ok,
       %{
         state: state,
         metadata: %{
           "attestation_evidence_present" => true,
           "attestation_verification" => "server_verified_android_key_attestation",
           "attestation_revalidation" => "verified",
           "attestation_freshness" => "fresh",
           "android_attestation_version" => description.attestation_version,
           "android_keymint_version" => description.keymint_version,
           "android_security_level" => security_level(description.keymint_security_level),
           "android_verified_boot" => true,
           "android_device_locked" => true,
           "android_unique_id_present" => false,
           "attestation_leaf_sha256" => sha256_hex(hd(chain)),
           "attestation_chain_sha256" => chain_sha256(chain),
           "attestation_trust_root_sha256" => sha256_hex(trust_root),
           "attestation_governance_version" => receipt.version,
           "attestation_governance_key_id" => receipt.key_id,
           "attestation_governance_source" => receipt.source,
           "attestation_governance_issued_at" => DateTime.to_iso8601(receipt.issued_at),
           "attestation_governance_expires_at" => DateTime.to_iso8601(receipt.expires_at),
           "attestation_challenge_sha256" => challenge_sha256_hex(expected_challenge)
         }
       }}
    end
  rescue
    _error -> {:error, :android_attestation_invalid}
  catch
    _kind, _reason -> {:error, :android_attestation_invalid}
  end

  def verify(_chain, _challenge, _spki, _opts), do: {:error, :android_attestation_invalid}

  @spec freshness_receipt_template(
          [binary()],
          [String.t()],
          String.t(),
          DateTime.t(),
          DateTime.t()
        ) ::
          map()
  def freshness_receipt_template(trust_roots, revoked, source, issued_at, expires_at) do
    %{
      version: @freshness_receipt_version,
      source: source,
      issued_at: DateTime.to_iso8601(issued_at),
      expires_at: DateTime.to_iso8601(expires_at),
      trust_roots_sha256: trust_roots_digest(trust_roots),
      revocation_set_sha256: revocation_digest(revoked)
    }
  end

  @spec sign_freshness_receipt(map(), String.t(), binary()) :: map()
  def sign_freshness_receipt(receipt, key_id, private_key) do
    signed = Map.put(receipt, :key_id, key_id)

    signature =
      :crypto.sign(:eddsa, :none, freshness_receipt_payload(signed), [private_key, :ed25519])

    Map.put(signed, :signature, Base.url_encode64(signature, padding: false))
  end

  @spec unverified_evidence_policy() :: :preserve | :reject
  def unverified_evidence_policy do
    config()
    |> Keyword.get(:unverified_evidence_policy, :reject)
    |> case do
      :preserve -> :preserve
      _ -> :reject
    end
  end

  defp trust_roots(opts) do
    result =
      if Keyword.has_key?(opts, :trust_roots_der) do
        validate_trust_roots(Keyword.get(opts, :trust_roots_der))
      else
        configured_trust_roots()
      end

    case result do
      {:ok, []} -> {:error, :android_attestation_trust_roots_unconfigured}
      {:ok, roots} -> {:ok, roots}
      {:error, _reason} -> {:error, :android_attestation_trust_roots_invalid}
    end
  end

  defp configured_trust_roots do
    direct = Keyword.get(config(), :trust_roots_der, [])
    pem_entries = Keyword.get(config(), :trust_roots_pem, [])

    with {:ok, direct} <- validate_trust_roots(direct),
         {:ok, decoded_pem} <- decode_pem_roots(pem_entries),
         {:ok, roots} <- validate_trust_roots(direct ++ decoded_pem) do
      {:ok, roots}
    end
  rescue
    _ -> {:error, :invalid}
  end

  defp validate_trust_roots(roots)
       when is_list(roots) and length(roots) <= @max_trust_roots do
    fingerprints = Enum.map(roots, &sha256_hex/1)

    if Enum.all?(roots, &valid_trust_anchor?/1) and
         length(fingerprints) == length(Enum.uniq(fingerprints)) do
      {:ok, roots}
    else
      {:error, :invalid}
    end
  rescue
    _ -> {:error, :invalid}
  end

  defp validate_trust_roots(_roots), do: {:error, :invalid}

  defp decode_pem_roots(entries) when is_list(entries) do
    Enum.reduce_while(entries, {:ok, []}, fn
      pem, {:ok, acc} when is_binary(pem) and byte_size(pem) in 1..262_144 ->
        decoded = :public_key.pem_decode(pem)

        case decoded do
          entries when entries != [] ->
            certificates =
              for {:Certificate, der, :not_encrypted} <- entries,
                  do: der

            if length(certificates) == length(entries) do
              {:cont, {:ok, acc ++ certificates}}
            else
              {:halt, {:error, :invalid}}
            end

          _ ->
            {:halt, {:error, :invalid}}
        end

      _entry, _acc ->
        {:halt, {:error, :invalid}}
    end)
  rescue
    _ -> {:error, :invalid}
  end

  defp decode_pem_roots(_entries), do: {:error, :invalid}

  defp config,
    do: Application.get_env(:tamandua_server, __MODULE__, [])

  defp decode_chain(chain)
       when chain != [] and length(chain) <= @max_chain_length do
    encoded_size =
      Enum.reduce_while(chain, 0, fn
        encoded, total
        when is_binary(encoded) and byte_size(encoded) <= @max_encoded_certificate_bytes ->
          next = total + byte_size(encoded)

          if next <= @max_encoded_chain_bytes,
            do: {:cont, next},
            else: {:halt, :invalid}

        _encoded, _total ->
          {:halt, :invalid}
      end)

    if encoded_size == :invalid do
      {:error, :android_attestation_chain_invalid}
    else
      Enum.reduce_while(chain, {:ok, []}, fn encoded, {:ok, acc} ->
        case decode_certificate_base64url(encoded) do
          {:ok, der} -> {:cont, {:ok, [der | acc]}}
          {:error, reason} -> {:halt, {:error, reason}}
        end
      end)
      |> case do
        {:ok, reversed} -> {:ok, Enum.reverse(reversed)}
        error -> error
      end
    end
  end

  defp decode_chain(_chain), do: {:error, :android_attestation_chain_invalid}

  defp decode_certificate_base64url(value) when is_binary(value) do
    with {:ok, der} <- Base.url_decode64(value, padding: false),
         true <- byte_size(der) > 0 and byte_size(der) <= @max_certificate_bytes,
         true <- Base.url_encode64(der, padding: false) == value,
         {:ok, _certificate} <- decode_certificate(der) do
      {:ok, der}
    else
      _ -> {:error, :android_attestation_chain_invalid}
    end
  end

  defp decode_certificate_base64url(_value), do: {:error, :android_attestation_chain_invalid}

  defp valid_trust_anchor?(der) do
    with true <- is_binary(der) and byte_size(der) in 1..@max_certificate_bytes,
         {:ok, {:OTPCertificate, tbs, _, _}} <- decode_certificate(der),
         extensions <- elem(tbs, 10),
         {:BasicConstraints, true, _path_length} <-
           extension_value(extensions, {2, 5, 29, 19}),
         key_usage when is_list(key_usage) <- extension_value(extensions, {2, 5, 29, 15}),
         true <- :keyCertSign in key_usage,
         {:Certificate, plain_tbs, _, _} <- :public_key.pkix_decode_cert(der, :plain),
         spki <- :public_key.der_encode(:SubjectPublicKeyInfo, elem(plain_tbs, 7)),
         public_key <-
           :public_key.pem_entry_decode({:SubjectPublicKeyInfo, spki, :not_encrypted}),
         true <- :public_key.pkix_verify(der, public_key) do
      true
    else
      _ -> false
    end
  rescue
    _ -> false
  end

  defp decode_certificate(der) do
    case :public_key.pkix_decode_cert(der, :otp) do
      {:OTPCertificate, _, _, _} = certificate -> {:ok, certificate}
      _ -> {:error, :android_attestation_certificate_invalid}
    end
  rescue
    _ -> {:error, :android_attestation_certificate_invalid}
  end

  defp validate_certificate_times(certificates, now) do
    certificates
    |> Enum.uniq()
    |> Enum.reduce_while(:ok, fn certificate, :ok ->
      case certificate_valid_at?(certificate, now) do
        true -> {:cont, :ok}
        false -> {:halt, {:error, :android_attestation_certificate_not_current}}
      end
    end)
  end

  defp certificate_valid_at?(certificate, now) do
    with {:ok, {:OTPCertificate, tbs, _, _}} <- decode_certificate(certificate),
         {:Validity, not_before, not_after} <- elem(tbs, 5),
         {:ok, not_before} <- parse_asn1_time(not_before),
         {:ok, not_after} <- parse_asn1_time(not_after) do
      DateTime.compare(now, not_before) != :lt and DateTime.compare(now, not_after) != :gt
    else
      _ -> false
    end
  rescue
    _ -> false
  end

  defp parse_asn1_time({:utcTime, value}) do
    value = to_string(value)

    with <<year::binary-size(2), rest::binary-size(11)>> <- value,
         {year, ""} <- Integer.parse(year) do
      parse_asn1_components(if(year < 50, do: 2_000 + year, else: 1_900 + year), rest)
    else
      _ -> {:error, :invalid}
    end
  end

  defp parse_asn1_time({:generalTime, value}) do
    value = to_string(value)

    with <<year::binary-size(4), rest::binary-size(11)>> <- value,
         {year, ""} <- Integer.parse(year) do
      parse_asn1_components(year, rest)
    else
      _ -> {:error, :invalid}
    end
  end

  defp parse_asn1_time(_value), do: {:error, :invalid}

  defp parse_asn1_components(year, value) do
    with <<month::binary-size(2), day::binary-size(2), hour::binary-size(2),
           minute::binary-size(2), second::binary-size(2), "Z">> <- value,
         {month, ""} <- Integer.parse(month),
         {day, ""} <- Integer.parse(day),
         {hour, ""} <- Integer.parse(hour),
         {minute, ""} <- Integer.parse(minute),
         {second, ""} <- Integer.parse(second),
         {:ok, date} <- Date.new(year, month, day),
         {:ok, time} <- Time.new(hour, minute, second),
         {:ok, datetime} <- DateTime.new(date, time, "Etc/UTC") do
      {:ok, datetime}
    else
      _ -> {:error, :invalid}
    end
  end

  defp revoked_certificates(opts) do
    configured =
      Keyword.get(
        opts,
        :revoked_certificate_sha256,
        Keyword.get(config(), :revoked_certificate_sha256, [])
      )

    if is_list(configured) and
         Enum.all?(configured, &(is_binary(&1) and &1 =~ ~r/\A[0-9a-fA-F]{64}\z/)) do
      {:ok, configured |> Enum.map(&String.downcase/1) |> MapSet.new()}
    else
      {:error, :android_attestation_revocation_config_invalid}
    end
  end

  defp reject_revoked(chain, revoked) do
    if Enum.any?(chain, &MapSet.member?(revoked, sha256_hex(&1))) do
      {:error, :android_attestation_certificate_revoked}
    else
      :ok
    end
  end

  defp validate_freshness_receipt(trust_roots, revoked, opts) do
    receipt = Keyword.get(opts, :freshness_receipt, Keyword.get(config(), :freshness_receipt))
    now = Keyword.get(opts, :now, DateTime.utc_now())

    with true <- is_map(receipt) and match?(%DateTime{}, now),
         @freshness_receipt_version <- receipt_value(receipt, :version),
         source when is_binary(source) <- receipt_value(receipt, :source),
         true <-
           source == String.trim(source) and byte_size(source) in 1..128 and
             source =~ ~r/\A[A-Za-z0-9][A-Za-z0-9._:\/-]*\z/,
         key_id when is_binary(key_id) <- receipt_value(receipt, :key_id),
         true <-
           byte_size(key_id) in 1..128 and key_id =~ ~r/\A[A-Za-z0-9][A-Za-z0-9._:-]*\z/,
         {:ok, issued_at, 0} <- DateTime.from_iso8601(receipt_value(receipt, :issued_at)),
         {:ok, expires_at, 0} <- DateTime.from_iso8601(receipt_value(receipt, :expires_at)),
         lifetime when lifetime in 1..@max_receipt_lifetime_seconds <-
           DateTime.diff(expires_at, issued_at, :second),
         true <-
           DateTime.compare(
             issued_at,
             DateTime.add(now, @max_receipt_future_skew_seconds, :second)
           ) !=
             :gt,
         true <- DateTime.compare(expires_at, now) == :gt,
         roots_digest when is_binary(roots_digest) <-
           receipt_value(receipt, :trust_roots_sha256),
         true <- roots_digest == trust_roots_digest(trust_roots),
         revoked_digest when is_binary(revoked_digest) <-
           receipt_value(receipt, :revocation_set_sha256),
         true <- revoked_digest == revocation_digest(MapSet.to_list(revoked)),
         {:ok, governance_key} <- governance_public_key(key_id, opts),
         {:ok, signature} <- canonical_signature(receipt_value(receipt, :signature)),
         true <-
           :crypto.verify(
             :eddsa,
             :none,
             freshness_receipt_payload(receipt),
             signature,
             [governance_key, :ed25519]
           ) do
      {:ok,
       %{
         version: @freshness_receipt_version,
         key_id: key_id,
         source: source,
         issued_at: issued_at,
         expires_at: expires_at,
         now: now
       }}
    else
      _ -> {:error, :android_attestation_governance_receipt_invalid}
    end
  rescue
    _ -> {:error, :android_attestation_governance_receipt_invalid}
  end

  defp receipt_value(receipt, key),
    do: Map.get(receipt, key, Map.get(receipt, Atom.to_string(key)))

  defp governance_public_key(key_id, opts) do
    keys =
      Keyword.get(
        opts,
        :governance_public_keys,
        Keyword.get(config(), :governance_public_keys, %{})
      )

    key = if is_map(keys), do: Map.get(keys, key_id), else: nil

    if is_binary(key) and byte_size(key) == 32,
      do: {:ok, key},
      else: {:error, :invalid}
  rescue
    _ -> {:error, :invalid}
  end

  defp canonical_signature(value) when is_binary(value) do
    with {:ok, signature} <- Base.url_decode64(value, padding: false),
         true <- byte_size(signature) == 64,
         true <- Base.url_encode64(signature, padding: false) == value do
      {:ok, signature}
    else
      _ -> {:error, :invalid}
    end
  end

  defp canonical_signature(_value), do: {:error, :invalid}

  defp freshness_receipt_payload(receipt) do
    [
      @freshness_receipt_protocol,
      "version=" <> to_string(receipt_value(receipt, :version)),
      "key_id=" <> to_string(receipt_value(receipt, :key_id)),
      "source=" <> to_string(receipt_value(receipt, :source)),
      "issued_at=" <> to_string(receipt_value(receipt, :issued_at)),
      "expires_at=" <> to_string(receipt_value(receipt, :expires_at)),
      "trust_roots_sha256=" <> to_string(receipt_value(receipt, :trust_roots_sha256)),
      "revocation_set_sha256=" <> to_string(receipt_value(receipt, :revocation_set_sha256))
    ]
    |> Enum.join("\n")
  end

  defp validate_path(chain, trust_roots) do
    last = List.last(chain)

    case Enum.find(trust_roots, &(&1 == last)) do
      nil ->
        case Enum.find(trust_roots, &safe_issuer?(last, &1)) do
          nil -> {:error, :android_attestation_untrusted_chain}
          anchor -> validate_path_with_anchor(anchor, Enum.reverse(chain))
        end

      anchor ->
        validate_path_with_anchor(anchor, chain |> Enum.drop(-1) |> Enum.reverse())
    end
  end

  defp validate_path_with_anchor(_anchor, []), do: {:error, :android_attestation_leaf_missing}

  defp validate_path_with_anchor(anchor, path) do
    options = [verify_fun: {&path_verify_fun/3, nil}]

    case :public_key.pkix_path_validation(anchor, path, options) do
      {:ok, _} -> {:ok, anchor}
      {:error, _reason} -> {:error, :android_attestation_untrusted_chain}
    end
  rescue
    _ -> {:error, :android_attestation_untrusted_chain}
  end

  defp path_verify_fun(_certificate, {:bad_cert, reason}, state)
       when reason in [:cert_expired, :cert_not_yet_valid],
       do: {:valid, state}

  defp path_verify_fun(_certificate, {:bad_cert, reason}, _state), do: {:fail, reason}
  defp path_verify_fun(_certificate, {:extension, _extension}, state), do: {:unknown, state}
  defp path_verify_fun(_certificate, :valid, state), do: {:valid, state}
  defp path_verify_fun(_certificate, :valid_peer, state), do: {:valid, state}

  defp safe_issuer?(certificate, issuer) do
    :public_key.pkix_is_issuer(certificate, issuer)
  rescue
    _ -> false
  end

  defp verify_leaf_spki(leaf_der, expected_spki) do
    {:Certificate, tbs, _, _} = :public_key.pkix_decode_cert(leaf_der, :plain)
    actual_spki = tbs |> elem(7) |> then(&:public_key.der_encode(:SubjectPublicKeyInfo, &1))

    if actual_spki == expected_spki,
      do: :ok,
      else: {:error, :android_attestation_spki_mismatch}
  rescue
    _ -> {:error, :android_attestation_spki_mismatch}
  end

  defp verify_leaf_constraints({:OTPCertificate, tbs, _, _}) do
    extensions = elem(tbs, 10)

    key_usage = extension_value(extensions, {2, 5, 29, 15})
    basic_constraints = extension_value(extensions, {2, 5, 29, 19})

    cond do
      not (is_list(key_usage) and :digitalSignature in key_usage) ->
        {:error, :android_attestation_leaf_key_usage_invalid}

      not match?({:BasicConstraints, false, _path_length}, basic_constraints) ->
        {:error, :android_attestation_leaf_ca_invalid}

      true ->
        :ok
    end
  rescue
    _ -> {:error, :android_attestation_leaf_constraints_invalid}
  end

  defp extension_value(extensions, oid) do
    case Enum.find(extensions, fn
           {:Extension, ^oid, _critical, _value} -> true
           _ -> false
         end) do
      {:Extension, ^oid, _critical, value} -> value
      _ -> nil
    end
  end

  defp attestation_extension({:OTPCertificate, tbs, _, _}) do
    extensions = elem(tbs, 10)

    case Enum.find(extensions, fn
           {:Extension, @extension_oid, _critical, value} when is_binary(value) -> true
           _ -> false
         end) do
      {:Extension, @extension_oid, _critical, value}
      when byte_size(value) > 0 and byte_size(value) <= @max_extension_bytes ->
        {:ok, value}

      _ ->
        {:error, :android_attestation_extension_missing}
    end
  rescue
    _ -> {:error, :android_attestation_extension_missing}
  end

  defp parse_key_description(der) do
    with {:ok, sequence, <<>>} <- decode_tlv(der),
         true <- universal?(sequence, 16, true),
         {:ok, fields} <- decode_children(sequence.value),
         [
           attestation_version,
           attestation_level,
           keymint_version,
           keymint_level,
           challenge,
           unique_id,
           software_enforced,
           hardware_enforced
         ] <- fields,
         {:ok, attestation_version} <- nonnegative_integer(attestation_version, 2),
         {:ok, attestation_level} <- nonnegative_integer(attestation_level, 10),
         {:ok, keymint_version} <- nonnegative_integer(keymint_version, 2),
         {:ok, keymint_level} <- nonnegative_integer(keymint_level, 10),
         {:ok, challenge} <- octet_string(challenge),
         {:ok, unique_id} <- octet_string(unique_id),
         {:ok, software_authorizations} <- authorization_list(software_enforced),
         {:ok, hardware_authorizations} <- authorization_list(hardware_enforced) do
      {:ok,
       %{
         attestation_version: attestation_version,
         attestation_security_level: attestation_level,
         keymint_version: keymint_version,
         keymint_security_level: keymint_level,
         challenge: challenge,
         unique_id: unique_id,
         software_authorizations: software_authorizations,
         hardware_authorizations: hardware_authorizations
       }}
    else
      _ -> {:error, :android_attestation_extension_invalid}
    end
  end

  defp verify_description(description, expected_challenge) do
    hardware = description.hardware_authorizations
    software = description.software_authorizations
    required_hardware_tags = [1, 2, 3, 5, 10, 503, 702, 704]
    authorization_validation = validate_authorization_tags(software, hardware)

    cond do
      description.attestation_security_level not in [1, 2] ->
        {:error, :android_attestation_software_security_level}

      description.keymint_security_level not in [1, 2] ->
        {:error, :android_attestation_software_security_level}

      description.attestation_security_level != description.keymint_security_level ->
        {:error, :android_attestation_security_level_conflict}

      not challenge_matches?(description.challenge, expected_challenge) ->
        {:error, :android_attestation_challenge_mismatch}

      description.unique_id != <<>> ->
        {:error, :android_attestation_unique_id_forbidden}

      authorization_validation != :ok ->
        authorization_validation

      Enum.any?(required_hardware_tags, &Map.has_key?(software, &1)) ->
        {:error, :android_attestation_authorization_conflict}

      not explicit_null?(hardware, 503) ->
        {:error, :android_attestation_authorization_invalid}

      not exact_set_values?(hardware, 1, [@sign_purpose]) ->
        {:error, :android_attestation_authorization_invalid}

      explicit_integer(hardware, 2) != {:ok, @ec_algorithm} ->
        {:error, :android_attestation_authorization_invalid}

      explicit_integer(hardware, 3) != {:ok, 256} ->
        {:error, :android_attestation_authorization_invalid}

      not exact_set_values?(hardware, 5, [@sha256_digest]) ->
        {:error, :android_attestation_authorization_invalid}

      explicit_integer(hardware, 10) != {:ok, @p256_curve} ->
        {:error, :android_attestation_authorization_invalid}

      explicit_integer(hardware, 702) != {:ok, @generated_origin} ->
        {:error, :android_attestation_authorization_invalid}

      root_of_trust(hardware) != {:ok, true, @verified_boot} ->
        {:error, :android_attestation_root_of_trust_invalid}

      true ->
        :ok
    end
  end

  defp validate_authorization_tags(software, hardware) do
    all_tags = Map.keys(software) ++ Map.keys(hardware)

    cond do
      Enum.any?(@forbidden_authorization_tags, &(&1 in all_tags)) ->
        {:error, :android_attestation_authorization_forbidden}

      Enum.any?(Map.keys(software), &(&1 not in @software_authorization_tags)) ->
        {:error, :android_attestation_authorization_unsupported}

      Enum.any?(Map.keys(hardware), &(&1 not in @hardware_authorization_tags)) ->
        {:error, :android_attestation_authorization_unsupported}

      not valid_optional_integer_tags?(software, [701, 705, 706, 718, 719], 8) ->
        {:error, :android_attestation_authorization_invalid}

      not valid_optional_integer_tags?(hardware, [705, 706, 718, 719], 5) ->
        {:error, :android_attestation_authorization_invalid}

      not valid_optional_attestation_application_id?(software) ->
        {:error, :android_attestation_authorization_invalid}

      true ->
        :ok
    end
  end

  defp valid_optional_integer_tags?(authorizations, tags, max_bytes) do
    Enum.all?(tags, fn tag ->
      case Map.fetch(authorizations, tag) do
        :error -> true
        {:ok, node} -> match?({:ok, _}, explicit_unsigned_integer(node, max_bytes))
      end
    end)
  end

  defp valid_optional_attestation_application_id?(authorizations) do
    case Map.fetch(authorizations, 709) do
      :error ->
        true

      {:ok, node} ->
        with {:ok, [octet]} <- decode_children(node.value),
             {:ok, value} <- octet_string(octet) do
          byte_size(value) in 1..4_096
        else
          _ -> false
        end
    end
  end

  defp challenge_matches?(challenge, expected) when is_binary(expected), do: challenge == expected

  defp challenge_matches?(challenge, {:sha256, expected})
       when is_binary(expected) and byte_size(expected) == 32,
       do: :crypto.hash(:sha256, challenge) == expected

  defp challenge_matches?(_challenge, _expected), do: false

  defp authorization_list(node) do
    with true <- universal?(node, 16, true),
         {:ok, children} <- decode_children(node.value),
         true <- Enum.all?(children, &(&1.class == 2 and &1.constructed)),
         tags <- Enum.map(children, & &1.tag),
         true <- length(tags) == length(Enum.uniq(tags)) do
      {:ok, Map.new(children, &{&1.tag, &1})}
    else
      _ -> {:error, :android_attestation_authorization_invalid}
    end
  end

  defp exact_set_values?(authorizations, tag, expected) do
    with {:ok, node} <- Map.fetch(authorizations, tag),
         {:ok, [set]} <- decode_children(node.value),
         true <- universal?(set, 17, true),
         {:ok, values} <- decode_children(set.value),
         decoded when is_list(decoded) <-
           Enum.map(values, fn value ->
             case nonnegative_integer(value, 2) do
               {:ok, decoded} -> decoded
               _ -> :invalid
             end
           end) do
      decoded == expected
    else
      _ -> false
    end
  end

  defp explicit_integer(authorizations, tag) do
    with {:ok, node} <- Map.fetch(authorizations, tag),
         {:ok, [integer]} <- decode_children(node.value) do
      nonnegative_integer(integer, 2)
    else
      _ -> {:error, :invalid}
    end
  end

  defp explicit_null?(authorizations, tag) do
    with {:ok, node} <- Map.fetch(authorizations, tag),
         {:ok, [null]} <- decode_children(node.value) do
      universal?(null, 5, false) and null.value == <<>>
    else
      _ -> false
    end
  end

  defp explicit_unsigned_integer(node, max_bytes) do
    with {:ok, [integer]} <- decode_children(node.value) do
      nonnegative_integer(integer, 2, max_bytes)
    else
      _ -> {:error, :invalid}
    end
  end

  defp root_of_trust(authorizations) do
    with {:ok, node} <- Map.fetch(authorizations, 704),
         {:ok, [sequence]} <- decode_children(node.value),
         true <- universal?(sequence, 16, true),
         {:ok, fields} <- decode_children(sequence.value),
         [verified_boot_key, device_locked, boot_state, verified_boot_hash] <- fields,
         {:ok, verified_boot_key} <- octet_string(verified_boot_key),
         true <- valid_boot_measurement?(verified_boot_key),
         {:ok, true} <- boolean(device_locked),
         {:ok, boot_state} <- nonnegative_integer(boot_state, 10),
         {:ok, verified_boot_hash} <- octet_string(verified_boot_hash),
         true <- valid_boot_measurement?(verified_boot_hash) do
      {:ok, true, boot_state}
    else
      _ -> {:error, :invalid}
    end
  end

  defp valid_boot_measurement?(value) when is_binary(value) and byte_size(value) == 32 do
    value != :binary.copy(<<0>>, 32) and value != :binary.copy(<<255>>, 32)
  end

  defp valid_boot_measurement?(_value), do: false

  defp octet_string(node) do
    if universal?(node, 4, false), do: {:ok, node.value}, else: {:error, :invalid}
  end

  defp boolean(node) do
    if universal?(node, 1, false) and node.value in [<<0>>, <<255>>],
      do: {:ok, node.value == <<255>>},
      else: {:error, :invalid}
  end

  defp nonnegative_integer(node, tag), do: nonnegative_integer(node, tag, 5)

  defp nonnegative_integer(node, tag, max_bytes) do
    value = node.value

    if universal?(node, tag, false) and byte_size(value) in 1..max_bytes and
         :binary.first(value) < 128 and canonical_integer?(value) do
      {:ok, :binary.decode_unsigned(value)}
    else
      {:error, :invalid}
    end
  end

  defp canonical_integer?(<<0, next, _::binary>>) when next < 128, do: false
  defp canonical_integer?(_value), do: true

  defp universal?(node, tag, constructed),
    do: node.class == 0 and node.tag == tag and node.constructed == constructed

  defp decode_children(value), do: decode_children(value, [], 0)

  defp decode_children(<<>>, acc, _count), do: {:ok, Enum.reverse(acc)}

  defp decode_children(_value, _acc, count) when count >= @max_der_children,
    do: {:error, :too_many_children}

  defp decode_children(value, acc, count) do
    with {:ok, node, rest} <- decode_tlv(value) do
      decode_children(rest, [node | acc], count + 1)
    end
  end

  defp decode_tlv(<<identifier, rest::binary>>) do
    class = identifier >>> 6
    constructed = (identifier &&& 0x20) != 0
    low_tag = identifier &&& 0x1F

    with {:ok, tag, after_tag} <- decode_tag(low_tag, rest),
         {:ok, length, after_length} <- decode_length(after_tag),
         true <- length <= byte_size(after_length),
         <<value::binary-size(length), remaining::binary>> <- after_length do
      {:ok, %{class: class, constructed: constructed, tag: tag, value: value}, remaining}
    else
      _ -> {:error, :invalid_der}
    end
  end

  defp decode_tlv(_value), do: {:error, :invalid_der}

  defp decode_tag(low_tag, rest) when low_tag < 31, do: {:ok, low_tag, rest}

  defp decode_tag(31, <<first, rest::binary>>) when first != 0x80,
    do: decode_high_tag(rest, first &&& 0x7F, (first &&& 0x80) != 0, 1)

  defp decode_tag(31, _rest), do: {:error, :invalid_der}

  defp decode_high_tag(rest, tag, false, _count) when tag >= 31, do: {:ok, tag, rest}

  defp decode_high_tag(<<next, rest::binary>>, tag, true, count) when count < 5,
    do: decode_high_tag(rest, tag <<< 7 ||| (next &&& 0x7F), (next &&& 0x80) != 0, count + 1)

  defp decode_high_tag(_rest, _tag, _more, _count), do: {:error, :invalid_der}

  defp decode_length(<<length, rest::binary>>) when length < 128, do: {:ok, length, rest}

  defp decode_length(<<marker, rest::binary>>) do
    count = marker &&& 0x7F

    if marker != 0x80 and count in 1..4 and byte_size(rest) >= count do
      <<length_bytes::binary-size(count), remaining::binary>> = rest
      length = :binary.decode_unsigned(length_bytes)

      if :binary.first(length_bytes) != 0 and length >= 128,
        do: {:ok, length, remaining},
        else: {:error, :invalid_der}
    else
      {:error, :invalid_der}
    end
  end

  defp decode_length(_value), do: {:error, :invalid_der}

  defp security_level(1), do: "tee"
  defp security_level(2), do: "strongbox"

  defp sha256_hex(value), do: :crypto.hash(:sha256, value) |> Base.encode16(case: :lower)

  defp challenge_sha256_hex({:sha256, digest}) when byte_size(digest) == 32,
    do: Base.encode16(digest, case: :lower)

  defp challenge_sha256_hex(challenge) when is_binary(challenge), do: sha256_hex(challenge)

  defp trust_roots_digest(trust_roots) when is_list(trust_roots) do
    trust_roots
    |> Enum.sort()
    |> length_prefixed_digest()
  end

  defp revocation_digest(revoked) when is_list(revoked) do
    revoked
    |> Enum.map(&String.downcase/1)
    |> Enum.uniq()
    |> Enum.sort()
    |> Enum.map(&Base.decode16!(&1, case: :lower))
    |> length_prefixed_digest()
  rescue
    _ -> "invalid"
  end

  defp length_prefixed_digest(values) do
    values
    |> Enum.map(fn value -> <<byte_size(value)::unsigned-32, value::binary>> end)
    |> IO.iodata_to_binary()
    |> sha256_hex()
  end

  defp chain_sha256(chain) do
    chain
    |> Enum.map(fn certificate ->
      <<byte_size(certificate)::unsigned-32, certificate::binary>>
    end)
    |> IO.iodata_to_binary()
    |> sha256_hex()
  end
end
