defmodule TamanduaServer.Enrollment.CSRCanonicalizer do
  @moduledoc """
  Bounded PKCS#10 CSR and agent-info canonicalization for enrollment Phase 2.

  Only RSA 2048-4096/SHA-256 and P-256/ECDSA-SHA-256 are accepted. The CSR
  signature is verified in-process. Client-requested extensions and subject
  identity are not trusted: this slice rejects every non-empty CSR attribute
  set and never derives an agent identity from the CSR subject.
  """

  use Bitwise

  @max_csr_bytes 32_768
  @max_agent_info_bytes 16_384
  @max_der_depth 32
  @agent_info_fields ~w(agent_version arch domain hostname install_path machine_id os os_build os_name os_type os_version)

  @oid_rsa <<0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01>>
  @oid_sha256_rsa <<0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B>>
  @oid_ec_public_key <<0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01>>
  @oid_prime256v1 <<0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07>>
  @oid_ecdsa_sha256 <<0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02>>

  def canonicalize(csr) when is_binary(csr) and byte_size(csr) <= @max_csr_bytes do
    with {:ok, der} <- decode_input(csr),
         :ok <- bounded_der(der),
         :ok <- validate_der(der),
         {:ok, cri_der, spki_der, signature_algorithm, signature, public_key} <-
           parse_request(der),
         :ok <- verify_signature(cri_der, signature_algorithm, signature, public_key) do
      {:ok,
       %{
         csr_der: der,
         csr_sha256: :crypto.hash(:sha256, der),
         public_key_spki_der: spki_der,
         public_key_sha256: :crypto.hash(:sha256, spki_der),
         key_algorithm: elem(signature_algorithm, 0)
       }}
    else
      {:error, _reason} = error -> error
      _ -> {:error, :invalid_csr}
    end
  rescue
    _ -> {:error, :invalid_csr}
  catch
    _, _ -> {:error, :invalid_csr}
  end

  def canonicalize(csr) when is_binary(csr), do: {:error, :csr_too_large}
  def canonicalize(_csr), do: {:error, :invalid_csr}

  def canonicalize_agent_info(info) when is_map(info) do
    with {:ok, normalized} <- normalize_agent_info(info),
         canonical <- encode_flat_json(normalized),
         true <- byte_size(canonical) <= @max_agent_info_bytes do
      {:ok, canonical}
    else
      false -> {:error, :agent_info_too_large}
      {:error, _reason} = error -> error
    end
  end

  def canonicalize_agent_info(_info), do: {:error, :invalid_agent_info}

  defp decode_input(csr) do
    if :binary.match(csr, "-----BEGIN") == :nomatch do
      {:ok, csr}
    else
      decode_single_pem(csr)
    end
  end

  defp decode_single_pem(pem) do
    trimmed = String.trim(pem)

    regex =
      ~r/\A-----BEGIN (?:NEW )?CERTIFICATE REQUEST-----\r?\n([A-Za-z0-9+\/=\r\n]+)-----END (?:NEW )?CERTIFICATE REQUEST-----\z/

    case Regex.run(regex, trimmed, capture: :all_but_first) do
      [body] ->
        body
        |> String.replace(~r/[\r\n]/, "")
        |> Base.decode64()
        |> case do
          {:ok, der} -> {:ok, der}
          :error -> {:error, :invalid_pem}
        end

      _ ->
        {:error, :invalid_pem}
    end
  end

  defp bounded_der(der) when byte_size(der) in 1..@max_csr_bytes, do: :ok
  defp bounded_der(_der), do: {:error, :csr_too_large}

  defp parse_request(der) do
    with {:ok, 0x30, outer, ^der, <<>>} <- parse_tlv(der),
         {:ok, [cri, signature_algorithm, signature_bit_string]} <- children(outer),
         {:ok, 0x30, cri_content, cri_der, <<>>} <- parse_tlv(cri),
         {:ok, [version, subject, spki_der, attributes]} <- children(cri_content),
         :ok <- validate_request_version(version),
         :ok <- validate_subject(subject),
         :ok <- reject_client_attributes(attributes),
         {:ok, key_algorithm, public_key} <- parse_spki(spki_der),
         {:ok, signature_algorithm} <- parse_signature_algorithm(signature_algorithm),
         :ok <- matching_algorithms(key_algorithm, signature_algorithm),
         {:ok, signature} <- bit_string_value(signature_bit_string) do
      {:ok, cri_der, spki_der, signature_algorithm, signature, public_key}
    else
      {:error, _reason} = error -> error
      _ -> {:error, :invalid_csr_structure}
    end
  end

  defp validate_request_version(version) do
    case parse_tlv(version) do
      {:ok, 0x02, <<0>>, ^version, <<>>} -> :ok
      _ -> {:error, :unsupported_csr_version}
    end
  end

  defp validate_subject(subject) do
    case parse_tlv(subject) do
      {:ok, 0x30, _content, ^subject, <<>>} -> :ok
      _ -> {:error, :invalid_csr_subject}
    end
  end

  defp reject_client_attributes(attributes) do
    case parse_tlv(attributes) do
      {:ok, 0xA0, <<>>, ^attributes, <<>>} -> :ok
      _ -> {:error, :client_extensions_forbidden}
    end
  end

  defp parse_spki(spki_der) do
    with {:ok, 0x30, content, ^spki_der, <<>>} <- parse_tlv(spki_der),
         {:ok, [algorithm, subject_public_key]} <- children(content),
         {:ok, algorithm_children} <- sequence_children(algorithm),
         {:ok, key_bytes} <- bit_string_value(subject_public_key) do
      parse_public_key(algorithm_children, key_bytes)
    else
      {:error, _reason} = error -> error
      _ -> {:error, :invalid_public_key}
    end
  end

  defp parse_public_key([oid, null], key_bytes) do
    with {:ok, @oid_rsa} <- oid_value(oid),
         :ok <- null_value(null),
         {:ok, modulus, exponent} <- parse_rsa_public_key(key_bytes),
         bits <- integer_bits(modulus),
         true <- bits in 2048..4096,
         true <- rem(modulus, 2) == 1,
         true <- exponent == 65_537 do
      {:ok, :rsa_sha256, {:RSAPublicKey, modulus, exponent}}
    else
      _ -> {:error, :unsupported_public_key}
    end
  end

  defp parse_public_key([oid, curve], <<4, _::binary-size(64)>> = point) do
    with {:ok, @oid_ec_public_key} <- oid_value(oid),
         {:ok, @oid_prime256v1} <- oid_value(curve) do
      {:ok, :ecdsa_p256_sha256, {{:ECPoint, point}, {:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}}}}
    else
      _ -> {:error, :unsupported_public_key}
    end
  end

  defp parse_public_key(_algorithm, _key_bytes), do: {:error, :unsupported_public_key}

  defp parse_signature_algorithm(der) do
    with {:ok, children} <- sequence_children(der) do
      case children do
        [oid, null] ->
          with {:ok, @oid_sha256_rsa} <- oid_value(oid),
               :ok <- null_value(null),
               do: {:ok, {:rsa_sha256, :sha256}}

        [oid] ->
          with {:ok, @oid_ecdsa_sha256} <- oid_value(oid),
               do: {:ok, {:ecdsa_p256_sha256, :sha256}}

        _ ->
          {:error, :unsupported_signature_algorithm}
      end
    end
  end

  defp matching_algorithms(key_algorithm, {key_algorithm, _digest}), do: :ok

  defp matching_algorithms(_key_algorithm, _signature_algorithm),
    do: {:error, :algorithm_mismatch}

  defp verify_signature(cri_der, {_algorithm, digest}, signature, public_key) do
    if :public_key.verify(cri_der, digest, signature, public_key),
      do: :ok,
      else: {:error, :invalid_csr_signature}
  rescue
    _ -> {:error, :invalid_csr_signature}
  end

  defp parse_rsa_public_key(der) do
    with {:ok, children} <- sequence_children(der),
         [modulus_der, exponent_der] <- children,
         {:ok, modulus} <- positive_integer(modulus_der),
         {:ok, exponent} <- positive_integer(exponent_der) do
      {:ok, modulus, exponent}
    else
      _ -> {:error, :invalid_public_key}
    end
  end

  defp positive_integer(der) do
    with {:ok, 0x02, bytes, ^der, <<>>} <- parse_tlv(der),
         true <- byte_size(bytes) > 0,
         false <- binary_part(bytes, 0, 1) |> :binary.first() |> band(0x80) != 0,
         :ok <- minimal_positive_integer(bytes) do
      {:ok, :binary.decode_unsigned(bytes)}
    else
      _ -> {:error, :invalid_integer}
    end
  end

  defp minimal_positive_integer(<<0, next, _::binary>>) when next < 0x80,
    do: {:error, :noncanonical_der}

  defp minimal_positive_integer(_bytes), do: :ok

  defp integer_bits(0), do: 0

  defp integer_bits(value) do
    <<most_significant, rest::binary>> = :binary.encode_unsigned(value)
    byte_size(rest) * 8 + significant_bits(most_significant)
  end

  defp significant_bits(byte) when byte >= 0x80, do: 8
  defp significant_bits(byte) when byte >= 0x40, do: 7
  defp significant_bits(byte) when byte >= 0x20, do: 6
  defp significant_bits(byte) when byte >= 0x10, do: 5
  defp significant_bits(byte) when byte >= 0x08, do: 4
  defp significant_bits(byte) when byte >= 0x04, do: 3
  defp significant_bits(byte) when byte >= 0x02, do: 2
  defp significant_bits(byte) when byte >= 0x01, do: 1

  defp sequence_children(der) do
    with {:ok, 0x30, content, ^der, <<>>} <- parse_tlv(der), do: children(content)
  end

  defp oid_value(der) do
    with {:ok, 0x06, value, ^der, <<>>} <- parse_tlv(der), do: {:ok, value}
  end

  defp null_value(der) do
    case parse_tlv(der) do
      {:ok, 0x05, <<>>, ^der, <<>>} -> :ok
      _ -> {:error, :invalid_algorithm_parameters}
    end
  end

  defp bit_string_value(der) do
    case parse_tlv(der) do
      {:ok, 0x03, <<0, value::binary>>, ^der, <<>>} when byte_size(value) > 0 -> {:ok, value}
      _ -> {:error, :invalid_bit_string}
    end
  end

  defp validate_der(der) do
    with {:ok, _tag, _content, ^der, <<>>} <- parse_tlv(der), do: validate_tlv_tree(der, 0)
  end

  defp validate_tlv_tree(_der, depth) when depth > @max_der_depth,
    do: {:error, :der_nesting_too_deep}

  defp validate_tlv_tree(der, depth) do
    with {:ok, tag, content, ^der, <<>>} <- parse_tlv(der) do
      if (tag &&& 0x20) == 0x20, do: validate_children(content, depth + 1), else: :ok
    end
  end

  defp validate_children(<<>>, _depth), do: :ok

  defp validate_children(binary, depth) do
    with {:ok, _tag, _content, raw, rest} <- parse_tlv(binary),
         :ok <- validate_tlv_tree(raw, depth),
         do: validate_children(rest, depth)
  end

  defp children(binary), do: collect_children(binary, [])
  defp collect_children(<<>>, acc), do: {:ok, Enum.reverse(acc)}

  defp collect_children(binary, acc) do
    with {:ok, _tag, _content, raw, rest} <- parse_tlv(binary),
         do: collect_children(rest, [raw | acc])
  end

  defp parse_tlv(<<tag, rest::binary>>) when (tag &&& 0x1F) != 0x1F do
    with {:ok, length, length_bytes, value_and_rest} <- parse_length(rest),
         true <- byte_size(value_and_rest) >= length do
      <<content::binary-size(length), tail::binary>> = value_and_rest
      raw = <<tag, length_bytes::binary, content::binary>>
      {:ok, tag, content, raw, tail}
    else
      _ -> {:error, :invalid_der}
    end
  end

  defp parse_tlv(_binary), do: {:error, :invalid_der}

  defp parse_length(<<length, rest::binary>>) when length < 128,
    do: {:ok, length, <<length>>, rest}

  defp parse_length(<<marker, rest::binary>>) do
    octets = marker &&& 0x7F

    if marker == 0x80 or octets == 0 or octets > 4 or byte_size(rest) < octets do
      {:error, :invalid_der_length}
    else
      <<encoded::binary-size(octets), tail::binary>> = rest
      length = :binary.decode_unsigned(encoded)

      if :binary.first(encoded) == 0 or length < 128 do
        {:error, :noncanonical_der_length}
      else
        {:ok, length, <<marker, encoded::binary>>, tail}
      end
    end
  end

  defp parse_length(_binary), do: {:error, :invalid_der_length}

  defp normalize_agent_info(info) do
    if map_size(info) > length(@agent_info_fields) do
      {:error, :unsupported_agent_info_field}
    else
      Enum.reduce_while(info, {:ok, %{}}, fn {key, value}, {:ok, acc} ->
        normalized_key = if is_atom(key), do: Atom.to_string(key), else: key

        cond do
          not is_binary(normalized_key) or normalized_key not in @agent_info_fields ->
            {:halt, {:error, :unsupported_agent_info_field}}

          Map.has_key?(acc, normalized_key) ->
            {:halt, {:error, :duplicate_agent_info_field}}

          not is_binary(value) or not String.valid?(value) ->
            {:halt, {:error, :invalid_agent_info}}

          byte_size(value) > field_limit(normalized_key) ->
            {:halt, {:error, :agent_info_field_too_large}}

          true ->
            {:cont, {:ok, Map.put(acc, normalized_key, value)}}
        end
      end)
    end
  end

  defp field_limit("install_path"), do: 2_048
  defp field_limit("machine_id"), do: 512
  defp field_limit("hostname"), do: 255
  defp field_limit(_field), do: 1_024

  defp encode_flat_json(map) do
    body =
      map
      |> Enum.sort_by(fn {key, _value} -> key end)
      |> Enum.map_join(",", fn {key, value} ->
        Jason.encode!(key) <> ":" <> Jason.encode!(value)
      end)

    "{" <> body <> "}"
  end
end
