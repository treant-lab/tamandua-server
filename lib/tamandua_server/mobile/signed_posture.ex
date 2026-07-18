defmodule TamanduaServer.Mobile.SignedPosture do
  @moduledoc """
  Pure verifier for the strict Android online signed-posture contract.

  This module does not persist posture, advance replay state, or mutate legacy
  mobile endpoints. Callers must supply server-owned challenge context and add
  tenant-scoped replay storage, active-key lookup, and recovery/rotation gates
  before using a verified envelope as a runtime or enforcement signal.
  """

  @protocol "tamandua.mobile.endpoint-telemetry/v1"
  @schema "tamandua.mobile.endpoint-posture/v1"
  @message_type "endpoint_posture"
  @message_version "1"
  @algorithm "ecdsa-p256-sha256"
  @source "android_foreground_online"
  @max_ttl_milliseconds 300_000
  @device_key_domain "tamandua.mobile.device-key/v1"
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
  @security_checks ~w(
    app_integrity_violation
    debugger_detected
    developer_mode
    adb_enabled
    emulator_detected
    frida_detected
    hook_framework_detected
    native_hook_detected
    root_detected
    runtime_memory_tamper_detected
    code_signature_baseline_configured
    code_signature_drift_detected
  )
  @posture_fields ~w(schema observed_at source risk_score security_checks)
  @canonical_fields ~w(
    protocol
    message_type
    message_version
    organization_id
    installation_id
    platform
    device_key_id
    key_scope_id
    request_id
    challenge_id
    nonce
    posture_sha256
    algorithm
    issued_at
    expires_at
  )
  @metadata_fields ~w(
    external_claim_allowed
    hardware_attestation_verified
    verification_state
    signed_payload_sha256
    signature
  )
  @uuid ~r/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
  @ascii_id ~r/^[A-Za-z0-9][A-Za-z0-9._:-]*$/
  @device_key_id ~r/^tmdk_v1_[A-Za-z0-9_-]{43}$/
  @key_scope_id ~r/^tmdks_v1_[A-Za-z0-9_-]{43}$/
  @private_material ~r/(^|_)(private|secret|seed|keystore_password|password|access_token|refresh_token|api_key|bearer)(_|$)/i
  @expected_context_fields ~w(
    organization_id installation_id device_key_id key_scope_id request_id challenge_id nonce
  )

  @type verification :: %{
          organization_id: String.t(),
          installation_id: String.t(),
          device_key_id: String.t(),
          key_scope_id: String.t(),
          request_id: String.t(),
          challenge_id: String.t(),
          posture_sha256: String.t(),
          signed_payload_sha256: String.t(),
          verified_at: DateTime.t()
        }

  @spec canonical_posture_payload(map()) :: {:ok, binary()} | {:error, atom()}
  def canonical_posture_payload(posture) when is_map(posture) do
    with :ok <- exact_keys(posture, @posture_fields),
         :ok <- reject_private_material(posture),
         :ok <- verify_posture_constants(posture),
         {:ok, risk_score} <- normalize_risk_score(value(posture, "risk_score")),
         {:ok, checks} <- normalize_security_checks(value(posture, "security_checks")) do
      lines =
        [
          {"schema", @schema},
          {"observed_at", value(posture, "observed_at")},
          {"source", @source},
          {"risk_score", risk_score}
        ] ++ Enum.map(@security_checks, &{"security_check." <> &1, Map.fetch!(checks, &1)})

      {:ok, canonical_lines(lines)}
    end
  end

  def canonical_posture_payload(_posture), do: {:error, :invalid_posture}

  @spec posture_digest(map()) :: {:ok, String.t()} | {:error, atom()}
  def posture_digest(posture) do
    with {:ok, payload} <- canonical_posture_payload(posture) do
      {:ok, :crypto.hash(:sha256, payload) |> base64url()}
    end
  end

  @spec canonical_payload(map()) :: {:ok, binary()} | {:error, atom()}
  def canonical_payload(envelope) when is_map(envelope) do
    with :ok <- allowed_keys(envelope, @canonical_fields ++ @metadata_fields),
         :ok <- required_keys(envelope, @canonical_fields),
         :ok <- verify_envelope_shape(envelope) do
      {:ok, canonical_lines(Enum.map(@canonical_fields, &{&1, value(envelope, &1)}))}
    end
  end

  def canonical_payload(_envelope), do: {:error, :invalid_envelope}

  @spec verify(map(), map(), binary(), keyword()) :: {:ok, verification()} | {:error, atom()}
  def verify(envelope, posture, public_key_spki, opts \\ [])

  def verify(envelope, posture, public_key_spki, opts)
      when is_map(envelope) and is_map(posture) and is_binary(public_key_spki) do
    now = Keyword.get(opts, :now, DateTime.utc_now())

    with {:ok, expected_context} <- required_expected_context(opts),
         {:ok, payload} <- canonical_payload(envelope),
         :ok <- verify_server_boundary(envelope),
         :ok <- verify_expected_context(envelope, expected_context),
         :ok <- validate_p256_spki(public_key_spki),
         :ok <- verify_device_key_binding(envelope, public_key_spki),
         {:ok, issued_at, expires_at} <- verify_time_window(envelope, posture, now),
         {:ok, posture_sha256} <- posture_digest(posture),
         :ok <-
           secure_equal(
             posture_sha256,
             value(envelope, "posture_sha256"),
             :posture_digest_mismatch
           ),
         signed_payload_sha256 <- :crypto.hash(:sha256, payload) |> base64url(),
         :ok <-
           secure_equal(
             signed_payload_sha256,
             value(envelope, "signed_payload_sha256"),
             :signed_payload_digest_mismatch
           ),
         {:ok, signature} <- decode_b64(value(envelope, "signature"), 8, 72, :invalid_signature),
         :ok <- validate_p256_der_signature(signature),
         :ok <- verify_p256_signature(public_key_spki, payload, signature) do
      {:ok,
       %{
         organization_id: value(envelope, "organization_id"),
         installation_id: value(envelope, "installation_id"),
         device_key_id: value(envelope, "device_key_id"),
         key_scope_id: value(envelope, "key_scope_id"),
         request_id: value(envelope, "request_id"),
         challenge_id: value(envelope, "challenge_id"),
         posture_sha256: posture_sha256,
         signed_payload_sha256: signed_payload_sha256,
         issued_at: issued_at,
         expires_at: expires_at,
         verified_at: now
       }}
    end
  end

  def verify(_envelope, _posture, _public_key_spki, _opts), do: {:error, :invalid_envelope}

  defp verify_posture_constants(posture) do
    cond do
      value(posture, "schema") != @schema -> {:error, :invalid_posture_schema}
      value(posture, "source") != @source -> {:error, :invalid_posture_source}
      not canonical_utc?(value(posture, "observed_at")) -> {:error, :invalid_time}
      true -> :ok
    end
  end

  defp normalize_risk_score("unknown"), do: {:ok, "unknown"}

  defp normalize_risk_score(value) when is_integer(value) and value >= 0 and value <= 100,
    do: {:ok, Integer.to_string(value)}

  defp normalize_risk_score(_value), do: {:error, :invalid_risk_score}

  defp normalize_security_checks(checks) when is_map(checks) do
    with :ok <- exact_keys(checks, @security_checks) do
      checks
      |> Enum.reduce_while({:ok, %{}}, fn {key, entry}, {:ok, acc} ->
        key = to_string(key)

        case normalize_tristate(entry) do
          {:ok, normalized} -> {:cont, {:ok, Map.put(acc, key, normalized)}}
          {:error, reason} -> {:halt, {:error, reason}}
        end
      end)
    end
  end

  defp normalize_security_checks(_checks), do: {:error, :invalid_security_checks}

  defp normalize_tristate(true), do: {:ok, "true"}
  defp normalize_tristate(false), do: {:ok, "false"}
  defp normalize_tristate("unknown"), do: {:ok, "unknown"}
  defp normalize_tristate(_value), do: {:error, :invalid_security_check}

  defp verify_envelope_shape(envelope) do
    cond do
      value(envelope, "protocol") != @protocol ->
        {:error, :unsupported_protocol}

      value(envelope, "message_type") != @message_type ->
        {:error, :invalid_message_type}

      value(envelope, "message_version") != @message_version ->
        {:error, :invalid_message_version}

      value(envelope, "platform") != "android" ->
        {:error, :unsupported_platform}

      value(envelope, "algorithm") != @algorithm ->
        {:error, :unsupported_algorithm}

      not ascii_id?(value(envelope, "organization_id")) ->
        {:error, :invalid_identifier}

      not ascii_id?(value(envelope, "installation_id")) ->
        {:error, :invalid_identifier}

      not matches?(value(envelope, "device_key_id"), @device_key_id) ->
        {:error, :invalid_identifier}

      not matches?(value(envelope, "key_scope_id"), @key_scope_id) ->
        {:error, :invalid_identifier}

      not uuid?(value(envelope, "request_id")) ->
        {:error, :invalid_request_binding}

      not uuid?(value(envelope, "challenge_id")) ->
        {:error, :invalid_request_binding}

      value(envelope, "request_id") == value(envelope, "challenge_id") ->
        {:error, :invalid_request_binding}

      not digest?(value(envelope, "posture_sha256")) ->
        {:error, :invalid_digest}

      not nonce?(value(envelope, "nonce")) ->
        {:error, :invalid_nonce}

      not canonical_utc?(value(envelope, "issued_at")) ->
        {:error, :invalid_time}

      not canonical_utc?(value(envelope, "expires_at")) ->
        {:error, :invalid_time}

      true ->
        :ok
    end
  end

  defp verify_server_boundary(envelope) do
    case {
      value(envelope, "external_claim_allowed"),
      value(envelope, "hardware_attestation_verified"),
      value(envelope, "verification_state")
    } do
      {false, false, "locally_signed_server_verification_required"} -> :ok
      _other -> {:error, :external_claim_not_allowed}
    end
  end

  defp verify_time_window(envelope, posture, now) do
    with {:ok, issued_at, _} <- DateTime.from_iso8601(value(envelope, "issued_at")),
         {:ok, expires_at, _} <- DateTime.from_iso8601(value(envelope, "expires_at")),
         {:ok, observed_at, _} <- DateTime.from_iso8601(value(posture, "observed_at")),
         true <- DateTime.compare(expires_at, issued_at) == :gt || {:error, :invalid_ttl},
         ttl <- DateTime.diff(expires_at, issued_at, :millisecond),
         true <- ttl <= @max_ttl_milliseconds || {:error, :invalid_ttl},
         true <- DateTime.compare(now, issued_at) != :lt || {:error, :envelope_not_yet_valid},
         true <-
           DateTime.compare(observed_at, issued_at) != :lt ||
             {:error, :invalid_observation_window},
         true <-
           DateTime.compare(observed_at, expires_at) != :gt ||
             {:error, :invalid_observation_window},
         true <- DateTime.compare(now, expires_at) == :lt || {:error, :envelope_expired} do
      {:ok, issued_at, expires_at}
    else
      {:error, _reason} = error -> error
      _ -> {:error, :invalid_time}
    end
  end

  defp exact_keys(map, expected) when is_map(map) do
    actual_keys = Map.keys(map)
    actual = Enum.sort(actual_keys)
    expected = Enum.sort(expected)

    cond do
      not Enum.all?(actual_keys, &is_binary/1) ->
        {:error, :invalid_fields}

      actual == expected ->
        :ok

      Enum.any?(actual, &Regex.match?(@private_material, &1)) ->
        {:error, :private_material_in_posture}

      true ->
        {:error, :invalid_fields}
    end
  end

  defp exact_keys(_map, _expected), do: {:error, :invalid_fields}

  defp allowed_keys(map, allowed) when is_map(map) do
    actual = Map.keys(map)
    extras = actual -- allowed

    cond do
      not Enum.all?(actual, &is_binary/1) ->
        {:error, :invalid_fields}

      extras == [] ->
        :ok

      Enum.any?(extras, &Regex.match?(@private_material, &1)) ->
        {:error, :private_material_in_posture}

      true ->
        {:error, :invalid_fields}
    end
  end

  defp allowed_keys(_map, _allowed), do: {:error, :invalid_fields}

  defp required_keys(map, required) when is_map(map) do
    actual = Map.keys(map)

    if Enum.all?(actual, &is_binary/1) and Enum.all?(required, &(&1 in actual)) do
      :ok
    else
      {:error, :invalid_fields}
    end
  end

  defp required_keys(_map, _required), do: {:error, :invalid_fields}

  defp reject_private_material(value) when is_map(value) do
    Enum.reduce_while(value, :ok, fn {key, entry}, :ok ->
      cond do
        Regex.match?(@private_material, to_string(key)) ->
          {:halt, {:error, :private_material_in_posture}}

        is_map(entry) ->
          reduce_private_material(entry)

        true ->
          {:cont, :ok}
      end
    end)
  end

  defp reduce_private_material(entry) do
    case reject_private_material(entry) do
      :ok -> {:cont, :ok}
      {:error, reason} -> {:halt, {:error, reason}}
    end
  end

  defp canonical_lines(entries) do
    Enum.map_join(entries, "\n", fn {field, value} ->
      field <> "=" <> base64url(to_string(value))
    end)
  end

  defp canonical_utc?(value) when is_binary(value) do
    case {Regex.match?(~r/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/, value),
          DateTime.from_iso8601(value)} do
      {true, {:ok, _datetime, _offset}} -> true
      _ -> false
    end
  end

  defp canonical_utc?(_value), do: false
  defp ascii_id?(value) when is_binary(value), do: Regex.match?(@ascii_id, value)
  defp ascii_id?(_value), do: false
  defp matches?(value, pattern) when is_binary(value), do: Regex.match?(pattern, value)
  defp matches?(_value, _pattern), do: false
  defp uuid?(value) when is_binary(value), do: Regex.match?(@uuid, value)
  defp uuid?(_value), do: false
  defp nonce?(value), do: decoded_size?(value, 32)
  defp digest?(value), do: decoded_size?(value, 32)

  defp decoded_size?(value, size) when is_binary(value) do
    case decode_b64(value, size, size, :invalid_base64url) do
      {:ok, _decoded} -> true
      {:error, _reason} -> false
    end
  end

  defp decoded_size?(_value, _size), do: false

  defp secure_equal(left, right, error) when is_binary(left) and is_binary(right) do
    left_digest = :crypto.hash(:sha256, left)
    right_digest = :crypto.hash(:sha256, right)

    if constant_time_equal?(left_digest, right_digest) do
      :ok
    else
      {:error, error}
    end
  end

  defp secure_equal(_left, _right, error), do: {:error, error}

  defp constant_time_equal?(left, right) do
    left
    |> :crypto.exor(right)
    |> :binary.bin_to_list()
    |> Enum.reduce(0, &Bitwise.bor/2)
    |> Kernel.==(0)
  end

  defp required_expected_context(opts) do
    case Keyword.fetch(opts, :expected_context) do
      {:ok, context} when is_map(context) ->
        case exact_keys(context, @expected_context_fields) do
          :ok -> {:ok, context}
          {:error, _reason} -> {:error, :invalid_expected_context}
        end

      _ ->
        {:error, :expected_context_required}
    end
  end

  defp verify_expected_context(envelope, expected_context) do
    mismatch =
      Enum.reduce(@expected_context_fields, 0, fn field, mismatch ->
        field_mismatch =
          case secure_equal(value(envelope, field), Map.get(expected_context, field), :mismatch) do
            :ok -> 0
            {:error, :mismatch} -> 1
          end

        Bitwise.bor(mismatch, field_mismatch)
      end)

    if mismatch == 0, do: :ok, else: {:error, :expected_context_mismatch}
  end

  defp verify_device_key_binding(envelope, public_key_spki) do
    calculated =
      :crypto.hash(
        :sha256,
        @device_key_domain <>
          <<0>> <> value(envelope, "organization_id") <> <<0>> <> public_key_spki
      )
      |> base64url()

    secure_equal(
      "tmdk_v1_" <> calculated,
      value(envelope, "device_key_id"),
      :device_key_mismatch
    )
  rescue
    _ -> {:error, :invalid_public_key}
  end

  defp validate_p256_spki(
         <<prefix::binary-size(27), _x_coordinate::binary-size(32),
           _y_coordinate::binary-size(32)>>
       )
       when prefix == @p256_spki_prefix,
       do: :ok

  defp validate_p256_spki(_public_key_spki), do: {:error, :invalid_public_key}

  defp validate_p256_der_signature(
         <<0x30, sequence_length, 0x02, r_length, rest::binary>> = signature
       )
       when byte_size(signature) >= 8 and byte_size(signature) <= 72 and
              sequence_length == byte_size(signature) - 2 and r_length >= 1 and r_length <= 33 do
    with true <- byte_size(rest) > r_length + 2,
         <<r::binary-size(r_length), 0x02, s_length, s::binary>> <- rest,
         true <- s_length >= 1 and s_length <= 33 and byte_size(s) == s_length,
         :ok <- validate_der_integer(r),
         :ok <- validate_der_integer(s) do
      :ok
    else
      _ -> {:error, :invalid_signature}
    end
  end

  defp validate_p256_der_signature(_signature), do: {:error, :invalid_signature}

  defp validate_der_integer(bytes) do
    leading_zero = byte_size(bytes) > 1 and :binary.first(bytes) == 0
    <<first, rest::binary>> = bytes
    all_zero = Enum.all?(:binary.bin_to_list(bytes), &(&1 == 0))
    redundant_zero = leading_zero and Bitwise.band(:binary.first(rest), 0x80) == 0

    if all_zero or Bitwise.band(first, 0x80) != 0 or redundant_zero or
         (byte_size(bytes) == 33 and not leading_zero),
       do: {:error, :invalid_signature},
       else: :ok
  end

  defp decode_b64(value, minimum, maximum, error) when is_binary(value) do
    with {:ok, decoded} <- Base.url_decode64(value, padding: false),
         true <- byte_size(decoded) >= minimum and byte_size(decoded) <= maximum,
         true <- Base.url_encode64(decoded, padding: false) == value do
      {:ok, decoded}
    else
      _ -> {:error, error}
    end
  end

  defp decode_b64(_value, _minimum, _maximum, error), do: {:error, error}

  defp verify_p256_signature(public_key_spki, payload, signature) do
    public_key =
      :public_key.pem_entry_decode({:SubjectPublicKeyInfo, public_key_spki, :not_encrypted})

    if :public_key.verify(payload, :sha256, signature, public_key) do
      :ok
    else
      {:error, :invalid_signature}
    end
  rescue
    _ -> {:error, :invalid_public_key}
  catch
    _, _ -> {:error, :invalid_public_key}
  end

  defp value(map, key), do: Map.get(map, key)
  defp base64url(value), do: Base.url_encode64(value, padding: false)
end
