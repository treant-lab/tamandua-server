defmodule TamanduaServer.Agents.CertificateManager do
  @moduledoc """
  Manages agent certificate pinning, validation, and revocation.

  This module provides:
  - Certificate extraction and parsing from connection info
  - Certificate pinning on first connection
  - Certificate verification against pinned certificates
  - Revocation checking
  - Certificate rotation support

  ## Security Model

  1. First Connection: Certificate is extracted, validated, and pinned to agent_id
  2. Subsequent Connections: Certificate must match pinned fingerprint
  3. Revocation: Certificates can be explicitly revoked and will be rejected
  4. Rotation: New certificates can be pinned after revoking old ones

  ## Certificate Pinning

  We pin both:
  - SHA256 fingerprint of the entire certificate
  - SHA256 hash of the public key

  This provides defense against certificate reissuance attacks.
  """

  require Logger
  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Agents.{AgentCertificate, RevokedCertificate}

  @type cert_info :: %{
    fingerprint: String.t(),
    public_key_hash: binary(),
    subject_dn: String.t(),
    issuer_dn: String.t(),
    serial_number: String.t(),
    valid_from: DateTime.t(),
    valid_until: DateTime.t(),
    cn: String.t()
  }

  @doc """
  Validates a certificate and pins it if this is the first connection.

  Returns:
  - {:ok, agent_id} if certificate is valid and authorized
  - {:error, reason} if certificate is invalid or unauthorized
  """
  @spec validate_and_pin(binary(), String.t()) :: {:ok, String.t()} | {:error, atom()}
  def validate_and_pin(cert_der, claimed_agent_id) do
    with {:ok, cert_info} <- parse_certificate(cert_der),
         :ok <- verify_cn_matches(cert_info.cn, claimed_agent_id),
         :ok <- check_not_revoked(cert_info.fingerprint),
         {:ok, agent_id} <- verify_or_pin(cert_info, claimed_agent_id) do
      {:ok, agent_id}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Parses a DER-encoded certificate and extracts relevant information.
  """
  @spec parse_certificate(binary() | tuple()) :: {:ok, cert_info()} | {:error, atom()}
  def parse_certificate(cert_der) do
    try do
      cert_der = normalize_certificate_der!(cert_der)

      # Calculate fingerprint (SHA256 of entire cert)
      fingerprint = :crypto.hash(:sha256, cert_der) |> Base.encode16(case: :lower)

      # Parse certificate
      case :public_key.pkix_decode_cert(cert_der, :otp) do
        {:OTPCertificate, tbs_cert, _sig_algo, _signature} ->
          {:OTPTBSCertificate, _version, serial, _sig, issuer, validity, subject, pub_key_info, _, _, _} = tbs_cert

          # Extract public key hash
          pub_key_hash = extract_public_key_hash(pub_key_info)

          # Extract DN strings
          subject_dn = format_dn(subject)
          issuer_dn = format_dn(issuer)

          # Extract CN
          {:ok, cn} = extract_cn(subject)

          # Extract serial number
          serial_number = format_serial(serial)

          # Extract validity period
          {:Validity, not_before, not_after} = validity
          valid_from = parse_asn1_time(not_before)
          valid_until = parse_asn1_time(not_after)

          cert_info = %{
            fingerprint: fingerprint,
            public_key_hash: pub_key_hash,
            subject_dn: subject_dn,
            issuer_dn: issuer_dn,
            serial_number: serial_number,
            valid_from: valid_from,
            valid_until: valid_until,
            cn: cn
          }

          {:ok, cert_info}

        _ ->
          {:error, :invalid_certificate_format}
      end
    rescue
      e ->
        Logger.error(
          "Certificate parsing error: #{Exception.format(:error, e, __STACKTRACE__)}"
        )

        {:error, :certificate_parse_error}
    end
  end

  @doc """
  Checks if a certificate is revoked.
  """
  @spec check_not_revoked(String.t()) :: :ok | {:error, :revoked}
  def check_not_revoked(fingerprint) do
    case Repo.get_by(RevokedCertificate, fingerprint: fingerprint) do
      nil -> :ok
      %RevokedCertificate{} = revocation ->
        Logger.warning("Certificate revoked: #{fingerprint}, reason: #{revocation.reason}")
        {:error, :revoked}
    end
  end

  @doc """
  Revokes a certificate.
  """
  @spec revoke_certificate(String.t(), keyword()) :: {:ok, RevokedCertificate.t()} | {:error, Ecto.Changeset.t()}
  def revoke_certificate(fingerprint, opts \\ []) do
    attrs = %{
      fingerprint: fingerprint,
      revoked_at: Keyword.get(opts, :revoked_at, DateTime.utc_now() |> DateTime.truncate(:second)),
      revoked_by_id: Keyword.get(opts, :revoked_by_id),
      agent_id: Keyword.get(opts, :agent_id),
      reason: Keyword.get(opts, :reason, "other"),
      notes: Keyword.get(opts, :notes),
      metadata: Keyword.get(opts, :metadata, %{})
    }

    %RevokedCertificate{}
    |> RevokedCertificate.changeset(attrs)
    |> RevokedCertificate.set_revoked_at()
    |> Repo.insert()
  end

  @doc """
  Pins a new certificate for an agent.
  """
  @spec pin_certificate(cert_info(), String.t()) :: {:ok, AgentCertificate.t()} | {:error, Ecto.Changeset.t()}
  def pin_certificate(cert_info, agent_id) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    attrs = %{
      agent_id: agent_id,
      fingerprint: cert_info.fingerprint,
      public_key_hash: cert_info.public_key_hash,
      subject_dn: cert_info.subject_dn,
      issuer_dn: cert_info.issuer_dn,
      serial_number: cert_info.serial_number,
      valid_from: cert_info.valid_from,
      valid_until: cert_info.valid_until,
      first_seen_at: now,
      last_seen_at: now,
      pinned: true
    }

    %AgentCertificate{}
    |> AgentCertificate.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates the last_seen_at timestamp for a certificate.
  """
  @spec update_last_seen(String.t()) :: {:ok, AgentCertificate.t()} | {:error, term()}
  def update_last_seen(fingerprint) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    from(c in AgentCertificate, where: c.fingerprint == ^fingerprint)
    |> Repo.update_all(set: [last_seen_at: now, updated_at: now])

    case Repo.get_by(AgentCertificate, fingerprint: fingerprint) do
      nil -> {:error, :not_found}
      cert -> {:ok, cert}
    end
  end

  @doc """
  Gets the pinned certificate for an agent.
  """
  @spec get_pinned_certificate(String.t()) :: {:ok, AgentCertificate.t()} | {:error, :not_found}
  def get_pinned_certificate(agent_id) do
    case Repo.get_by(AgentCertificate, agent_id: agent_id, pinned: true) do
      nil -> {:error, :not_found}
      cert -> {:ok, cert}
    end
  end

  # Private functions

  defp normalize_certificate_der!(cert_der) when is_binary(cert_der), do: cert_der
  defp normalize_certificate_der!({:Certificate, cert_der, _}) when is_binary(cert_der), do: cert_der
  defp normalize_certificate_der!({:OTPCertificate, _, _, _} = cert), do: :public_key.der_encode(:OTPCertificate, cert)
  defp normalize_certificate_der!(cert_der), do: raise(ArgumentError, "unsupported certificate payload: #{inspect_shape(cert_der)}")

  defp inspect_shape(value) when is_tuple(value), do: "tuple/#{tuple_size(value)} #{inspect(elem(value, 0))}"
  defp inspect_shape(value) when is_list(value), do: "list/#{length(value)}"
  defp inspect_shape(value), do: inspect(value)

  defp verify_or_pin(cert_info, agent_id) do
    case get_pinned_certificate(agent_id) do
      {:ok, pinned_cert} ->
        # Certificate already pinned - verify it matches
        verify_pinned_certificate(cert_info, pinned_cert)

      {:error, :not_found} ->
        # First connection - pin the certificate
        case pin_certificate(cert_info, agent_id) do
          {:ok, _cert} ->
            Logger.info("Certificate pinned for agent #{agent_id}: #{cert_info.fingerprint}")
            {:ok, agent_id}

          {:error, changeset} ->
            Logger.error("Failed to pin certificate for agent #{agent_id}: #{inspect(changeset.errors)}")
            {:error, :pin_failed}
        end
    end
  end

  defp verify_pinned_certificate(cert_info, pinned_cert) do
    cond do
      cert_info.fingerprint != pinned_cert.fingerprint ->
        Logger.warning("Certificate fingerprint mismatch for agent #{pinned_cert.agent_id}")
        {:error, :fingerprint_mismatch}

      cert_info.public_key_hash != pinned_cert.public_key_hash ->
        Logger.warning("Public key hash mismatch for agent #{pinned_cert.agent_id}")
        {:error, :public_key_mismatch}

      true ->
        # Update last seen
        update_last_seen(cert_info.fingerprint)
        {:ok, pinned_cert.agent_id}
    end
  end

  defp verify_cn_matches(cn, claimed_agent_id) do
    if cn == claimed_agent_id do
      :ok
    else
      Logger.warning("Certificate CN (#{cn}) does not match claimed agent_id (#{claimed_agent_id})")
      {:error, :cn_mismatch}
    end
  end

  defp extract_public_key_hash({:OTPSubjectPublicKeyInfo, _algo, pub_key} = pub_key_info) do
    encoded = encode_subject_public_key_info(pub_key_info, pub_key)
    :crypto.hash(:sha256, encoded)
  end

  defp extract_public_key_hash(_), do: <<0::256>>

  defp encode_subject_public_key_info(pub_key_info, pub_key) do
    :public_key.der_encode(:OTPSubjectPublicKeyInfo, pub_key_info)
  rescue
    _ -> encode_public_key(pub_key)
  end

  defp encode_public_key({:ECPoint, point}) when is_binary(point), do: point
  defp encode_public_key({:RSAPublicKey, _, _} = key), do: :public_key.der_encode(:RSAPublicKey, key)
  defp encode_public_key({:DSAPublicKey, _, _, _, _} = key), do: :public_key.der_encode(:DSAPublicKey, key)
  defp encode_public_key(key) when is_binary(key), do: key
  defp encode_public_key(key), do: :erlang.term_to_binary(key)

  defp extract_cn({:rdnSequence, rdn_sequence}) do
    cn =
      rdn_sequence
      |> List.flatten()
      |> Enum.find_value(fn
        {:AttributeTypeAndValue, {2, 5, 4, 3}, {:utf8String, cn}} -> cn
        {:AttributeTypeAndValue, {2, 5, 4, 3}, {:printableString, cn}} -> cn
        _ -> nil
      end)

    if cn, do: {:ok, to_string(cn)}, else: :error
  end

  defp extract_cn(_), do: :error

  defp format_dn({:rdnSequence, rdn_sequence}) do
    rdn_sequence
    |> List.flatten()
    |> Enum.map_join(", ", fn
      {:AttributeTypeAndValue, oid, {:utf8String, value}} ->
        "#{format_oid(oid)}=#{value}"
      {:AttributeTypeAndValue, oid, {:printableString, value}} ->
        "#{format_oid(oid)}=#{value}"
      {:AttributeTypeAndValue, oid, value} when is_binary(value) ->
        "#{format_oid(oid)}=#{value}"
      _ ->
        ""
    end)
  end

  defp format_dn(_), do: "unknown"

  defp format_oid({2, 5, 4, 3}), do: "CN"
  defp format_oid({2, 5, 4, 6}), do: "C"
  defp format_oid({2, 5, 4, 7}), do: "L"
  defp format_oid({2, 5, 4, 8}), do: "ST"
  defp format_oid({2, 5, 4, 10}), do: "O"
  defp format_oid({2, 5, 4, 11}), do: "OU"
  defp format_oid(oid), do: inspect(oid)

  defp format_serial(serial) when is_integer(serial) do
    Integer.to_string(serial, 16)
  end
  defp format_serial(serial) when is_binary(serial) do
    Base.encode16(serial, case: :lower)
  end
  defp format_serial(_), do: "unknown"

  defp parse_asn1_time({:utcTime, time_str}) do
    time_str |> to_string() |> parse_utc_time()
  end

  defp parse_asn1_time({:generalTime, time_str}) do
    time_str |> to_string() |> parse_general_time()
  end

  defp parse_asn1_time(_), do: DateTime.utc_now()

  defp parse_utc_time(<<y::binary-2, m::binary-2, d::binary-2, h::binary-2, mi::binary-2, s::binary-2, "Z">>) do
    year = String.to_integer(y)
    year = if year >= 50, do: 1900 + year, else: 2000 + year
    month = String.to_integer(m)
    day = String.to_integer(d)
    hour = String.to_integer(h)
    minute = String.to_integer(mi)
    second = String.to_integer(s)

    {:ok, dt} = DateTime.new(
      Date.new!(year, month, day),
      Time.new!(hour, minute, second)
    )
    dt
  end

  defp parse_utc_time(_), do: DateTime.utc_now()

  defp parse_general_time(<<y::binary-4, m::binary-2, d::binary-2, h::binary-2, mi::binary-2, s::binary-2, "Z">>) do
    year = String.to_integer(y)
    month = String.to_integer(m)
    day = String.to_integer(d)
    hour = String.to_integer(h)
    minute = String.to_integer(mi)
    second = String.to_integer(s)

    {:ok, dt} = DateTime.new(
      Date.new!(year, month, day),
      Time.new!(hour, minute, second)
    )
    dt
  end

  defp parse_general_time(_), do: DateTime.utc_now()
end
