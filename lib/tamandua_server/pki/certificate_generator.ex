defmodule TamanduaServer.PKI.CertificateGenerator do
  @moduledoc """
  Agent certificate generation for mutual TLS authentication.

  Generates X.509 certificates for agents signed by the intermediate CA.
  Each agent receives a unique certificate with:

  - Subject CN matching agent_id
  - 90-day validity (short-lived for security)
  - Client authentication extended key usage
  - Subject Alternative Names (DNS, IP) for flexibility
  - OCSP and CRL distribution points
  - Serial number tracking for revocation

  ## Certificate Lifecycle

  1. Agent enrollment → Generate certificate
  2. Auto-renewal at 75% of lifetime (67.5 days)
  3. Revocation on agent decommission
  4. Certificate archived for audit trail

  ## Example

      # Generate agent certificate
      {:ok, cert_pem, key_pem} = CertificateGenerator.generate_agent_cert(
        agent_id: "agent-123",
        hostname: "workstation-01.corp.local",
        ip_addresses: ["192.168.1.100"]
      )

      # Check if renewal needed
      if CertificateGenerator.needs_renewal?(cert_pem) do
        {:ok, new_cert, new_key} = CertificateGenerator.renew_agent_cert(agent_id)
      end
  """

  require Logger
  alias TamanduaServer.OSCommand
  alias TamanduaServer.PKI.CertificateAuthority
  alias TamanduaServer.Agents
  alias TamanduaServer.Audit
  alias TamanduaServer.Repo

  @cert_validity_days 90
  # Renew at 75% of lifetime
  @renewal_threshold 0.75
  # RSA 2048 for agents (faster than 4096)
  @key_size 2048

  @doc """
  Generate a new certificate for an agent.

  ## Options

    * `:agent_id` - Unique agent identifier (required)
    * `:hostname` - Agent hostname (required)
    * `:ip_addresses` - List of agent IP addresses (optional)
    * `:dns_names` - Additional DNS SANs (optional)
    * `:validity_days` - Certificate validity (default: 90 days)
    * `:key_size` - RSA key size (default: 2048)

  ## Returns

    * `{:ok, cert_pem, key_pem}` - Certificate and private key in PEM format
    * `{:error, reason}` - Error generating certificate
  """
  def generate_agent_cert(opts) do
    agent_id = Keyword.fetch!(opts, :agent_id)
    hostname = Keyword.fetch!(opts, :hostname)
    ip_addresses = Keyword.get(opts, :ip_addresses, [])
    dns_names = Keyword.get(opts, :dns_names, [hostname])
    validity_days = Keyword.get(opts, :validity_days, @cert_validity_days)
    key_size = Keyword.get(opts, :key_size, @key_size)

    Logger.info("Generating certificate for agent", agent_id: agent_id, hostname: hostname)

    with {:ok, ca_cert} <- CertificateAuthority.get_intermediate_ca_cert(),
         {:ok, ca_key} <- get_ca_private_key(),
         {:ok, private_key_pem} <- generate_private_key(key_size),
         {:ok, csr_pem} <- generate_csr(agent_id, hostname, private_key_pem),
         {:ok, cert_pem} <-
           sign_certificate(
             csr_pem,
             ca_cert,
             ca_key,
             agent_id,
             dns_names,
             ip_addresses,
             validity_days
           ),
         :ok <- store_certificate(agent_id, cert_pem, validity_days) do
      # Audit log
      Audit.log("pki.agent_cert_generated", %{
        agent_id: agent_id,
        hostname: hostname,
        validity_days: validity_days,
        serial_number: extract_serial_number(cert_pem)
      })

      Logger.info("Agent certificate generated successfully", agent_id: agent_id)

      {:ok, cert_pem, private_key_pem}
    else
      {:error, reason} = error ->
        Logger.error("Failed to generate agent certificate",
          agent_id: agent_id,
          reason: inspect(reason)
        )

        error
    end
  end

  @doc """
  Renew an agent's certificate.

  Generates a new certificate with the same subject and SANs as the
  existing certificate. The old certificate remains valid until expiry
  to allow graceful rotation.
  """
  def renew_agent_cert(agent_id) do
    Logger.info("Renewing certificate for agent", agent_id: agent_id)

    case Agents.get_agent(agent_id) do
      nil ->
        {:error, :agent_not_found}

      agent ->
        # Generate new certificate with same parameters
        opts = [
          agent_id: agent_id,
          hostname: agent.hostname,
          ip_addresses: parse_ip_addresses(agent),
          dns_names: parse_dns_names(agent)
        ]

        case generate_agent_cert(opts) do
          {:ok, cert_pem, key_pem} ->
            # Archive old certificate
            if agent.certificate_pem do
              archive_certificate(agent_id, agent.certificate_pem)
            end

            # Update agent with new certificate
            Agents.update_agent_certificate(agent_id, cert_pem)

            Audit.log("pki.agent_cert_renewed", %{
              agent_id: agent_id,
              new_serial: extract_serial_number(cert_pem)
            })

            {:ok, cert_pem, key_pem}

          error ->
            error
        end
    end
  end

  @doc """
  Check if an agent's certificate needs renewal.

  Returns `true` if the certificate has passed the renewal threshold
  (75% of its lifetime by default).
  """
  def needs_renewal?(cert_pem) do
    case extract_expiry(cert_pem) do
      {:ok, expiry_datetime} ->
        now = DateTime.utc_now()
        total_lifetime = DateTime.diff(expiry_datetime, now, :second)
        threshold_lifetime = total_lifetime * @renewal_threshold

        remaining = DateTime.diff(expiry_datetime, now, :second)
        remaining <= threshold_lifetime

      {:error, _} ->
        # If we can't parse expiry, assume renewal needed
        true
    end
  end

  @doc """
  Revoke an agent certificate.

  Adds the certificate to the CRL and updates the certificate status
  in the database. The certificate is immediately invalid for new
  connections.

  ## Revocation Reasons

    * `:unspecified` - General revocation
    * `:key_compromise` - Private key compromised
    * `:ca_compromise` - CA key compromised (rare)
    * `:superseded` - Replaced by new certificate
    * `:cessation_of_operation` - Agent decommissioned
  """
  def revoke_certificate(agent_id, reason \\ :cessation_of_operation) do
    Logger.info("Revoking certificate for agent", agent_id: agent_id, reason: reason)

    case Agents.get_agent(agent_id) do
      nil ->
        {:error, :agent_not_found}

      agent ->
        if agent.certificate_pem do
          serial = extract_serial_number(agent.certificate_pem)

          # Add to CRL
          :ok = TamanduaServer.PKI.RevocationList.revoke_certificate(serial, reason)

          # Update database
          :ok = update_certificate_status(agent_id, :revoked)

          Audit.log("pki.agent_cert_revoked", %{
            agent_id: agent_id,
            serial_number: serial,
            reason: reason
          })

          Logger.info("Agent certificate revoked", agent_id: agent_id, serial: serial)

          :ok
        else
          {:error, :no_certificate}
        end
    end
  end

  @doc """
  Verify a certificate against the CA and check revocation status.

  Returns:
  - `:ok` - Certificate is valid and not revoked
  - `{:error, :revoked}` - Certificate has been revoked
  - `{:error, :expired}` - Certificate has expired
  - `{:error, :invalid_signature}` - Certificate signature invalid
  - `{:error, reason}` - Other validation errors
  """
  def verify_certificate(cert_pem) do
    with :ok <- CertificateAuthority.verify_chain(cert_pem),
         :ok <- check_expiry(cert_pem),
         :ok <- check_revocation(cert_pem) do
      :ok
    end
  end

  @doc """
  Extract the agent_id (CN) from a certificate.
  """
  def extract_agent_id(cert_pem) do
    cert_file = write_temp_file(cert_pem)

    try do
      case openssl(["x509", "-in", cert_file, "-noout", "-subject"]) do
        {output, 0} ->
          # Parse: subject=CN = agent-123, O = Tamandua EDR
          case Regex.run(~r/CN\s*=\s*([^,]+)/, output) do
            [_, cn] -> {:ok, String.trim(cn)}
            _ -> {:error, :cn_not_found}
          end

        _ ->
          {:error, :parse_failed}
      end
    after
      File.rm(cert_file)
    end
  end

  @doc """
  Get certificate information for display.

  Returns a map with certificate details:
  - `subject` - Certificate subject DN
  - `issuer` - Issuer DN
  - `serial_number` - Certificate serial number
  - `not_before` - Validity start date
  - `not_after` - Validity end date
  - `key_usage` - Key usage extensions
  - `san` - Subject Alternative Names
  """
  def get_certificate_info(cert_pem) do
    cert_file = write_temp_file(cert_pem)

    try do
      case openssl(["x509", "-in", cert_file, "-noout", "-text"]) do
        {output, 0} ->
          parse_certificate_info(output)

        _ ->
          {:error, :parse_failed}
      end
    after
      File.rm(cert_file)
    end
  end

  # Private Functions

  defp generate_private_key(key_size) do
    case openssl(["genrsa", "-out", "/dev/stdout", Integer.to_string(key_size)]) do
      {key_pem, 0} ->
        {:ok, String.trim(key_pem)}

      {error, _} ->
        {:error, {:key_generation_failed, error}}
    end
  end

  defp generate_csr(agent_id, hostname, private_key_pem) do
    subject = "/CN=#{agent_id}/O=Tamandua EDR/OU=Agents"

    args = [
      "req",
      "-new",
      "-key",
      "/dev/stdin",
      "-out",
      "/dev/stdout",
      "-subj",
      subject
    ]

    case openssl(args, input: private_key_pem) do
      {csr_pem, 0} ->
        {:ok, String.trim(csr_pem)}

      {error, _} ->
        {:error, {:csr_generation_failed, error}}
    end
  end

  defp sign_certificate(
         csr_pem,
         ca_cert_pem,
         ca_key_pem,
         agent_id,
         dns_names,
         ip_addresses,
         validity_days
       ) do
    # Create OpenSSL config for extensions
    config = build_cert_config(agent_id, dns_names, ip_addresses)
    config_file = write_temp_file(config)

    # Temp files for CA cert and key
    ca_cert_file = write_temp_file(ca_cert_pem)
    ca_key_file = write_temp_file(ca_key_pem)
    csr_file = write_temp_file(csr_pem)

    try do
      args = [
        "x509",
        "-req",
        "-in",
        csr_file,
        "-CA",
        ca_cert_file,
        "-CAkey",
        ca_key_file,
        "-CAcreateserial",
        "-out",
        "/dev/stdout",
        "-days",
        Integer.to_string(validity_days),
        "-extensions",
        "agent_cert",
        "-extfile",
        config_file
      ]

      case openssl(args) do
        {cert_pem, 0} ->
          {:ok, String.trim(cert_pem)}

        {error, _} ->
          {:error, {:signing_failed, error}}
      end
    after
      File.rm(config_file)
      File.rm(ca_cert_file)
      File.rm(ca_key_file)
      File.rm(csr_file)
    end
  end

  defp build_cert_config(agent_id, dns_names, ip_addresses) do
    # Build Subject Alternative Name (SAN) extension
    san_entries = []

    san_entries =
      Enum.reduce(dns_names, san_entries, fn name, acc ->
        ["DNS:#{name}" | acc]
      end)

    san_entries =
      Enum.reduce(ip_addresses, san_entries, fn ip, acc ->
        ["IP:#{ip}" | acc]
      end)

    san_value = Enum.join(Enum.reverse(san_entries), ", ")

    ocsp_url = Application.get_env(:tamandua_server, :ocsp_url, "http://ocsp.tamandua.local/")
    crl_url = Application.get_env(:tamandua_server, :crl_url, "http://crl.tamandua.local/crl.pem")

    """
    [agent_cert]
    subjectKeyIdentifier = hash
    authorityKeyIdentifier = keyid:always,issuer
    basicConstraints = critical, CA:FALSE
    keyUsage = critical, digitalSignature, keyEncipherment
    extendedKeyUsage = clientAuth
    subjectAltName = #{san_value}
    authorityInfoAccess = OCSP;URI:#{ocsp_url}
    crlDistributionPoints = URI:#{crl_url}
    """
  end

  defp get_ca_private_key do
    # This would retrieve the intermediate CA private key
    # For now, we'll access it directly from CertificateAuthority state
    # In production, this should be protected with HSM or key escrow
    GenServer.call(TamanduaServer.PKI.CertificateAuthority, :get_intermediate_ca_key)
  end

  defp store_certificate(agent_id, cert_pem, validity_days) do
    serial = extract_serial_number(cert_pem)
    not_after = calculate_expiry(validity_days)

    params = %{
      agent_id: agent_id,
      certificate_pem: cert_pem,
      serial_number: serial,
      not_after: not_after,
      status: "active",
      inserted_at: DateTime.utc_now(),
      updated_at: DateTime.utc_now()
    }

    Repo.query!(
      """
      INSERT INTO agent_certificates (agent_id, certificate_pem, serial_number, not_after, status, inserted_at, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      ON CONFLICT (agent_id) DO UPDATE SET
        certificate_pem = EXCLUDED.certificate_pem,
        serial_number = EXCLUDED.serial_number,
        not_after = EXCLUDED.not_after,
        updated_at = EXCLUDED.updated_at
      """,
      [
        params.agent_id,
        params.certificate_pem,
        params.serial_number,
        params.not_after,
        params.status,
        params.inserted_at,
        params.updated_at
      ]
    )

    :ok
  end

  defp archive_certificate(agent_id, cert_pem) do
    serial = extract_serial_number(cert_pem)

    Repo.query!(
      """
      INSERT INTO agent_certificates_archive (agent_id, certificate_pem, serial_number, archived_at)
      VALUES ($1, $2, $3, $4)
      """,
      [agent_id, cert_pem, serial, DateTime.utc_now()]
    )

    :ok
  end

  defp update_certificate_status(agent_id, status) do
    Repo.query!(
      "UPDATE agent_certificates SET status = $1, updated_at = $2 WHERE agent_id = $3",
      [to_string(status), DateTime.utc_now(), agent_id]
    )

    :ok
  end

  defp extract_serial_number(cert_pem) do
    cert_file = write_temp_file(cert_pem)

    try do
      case openssl(["x509", "-in", cert_file, "-noout", "-serial"]) do
        {output, 0} ->
          output
          |> String.trim()
          |> String.replace("serial=", "")

        _ ->
          "unknown"
      end
    after
      File.rm(cert_file)
    end
  end

  defp extract_expiry(cert_pem) do
    cert_file = write_temp_file(cert_pem)

    try do
      case openssl(["x509", "-in", cert_file, "-noout", "-enddate"]) do
        {output, 0} ->
          # Parse: notAfter=Mar  1 12:00:00 2026 GMT
          date_str =
            output
            |> String.trim()
            |> String.replace("notAfter=", "")

          case Timex.parse(date_str, "{ASC}") do
            {:ok, datetime} -> {:ok, datetime}
            _ -> {:error, :parse_failed}
          end

        _ ->
          {:error, :parse_failed}
      end
    after
      File.rm(cert_file)
    end
  end

  defp check_expiry(cert_pem) do
    case extract_expiry(cert_pem) do
      {:ok, expiry} ->
        if DateTime.compare(DateTime.utc_now(), expiry) == :lt do
          :ok
        else
          {:error, :expired}
        end

      error ->
        error
    end
  end

  defp check_revocation(cert_pem) do
    serial = extract_serial_number(cert_pem)
    TamanduaServer.PKI.RevocationList.is_revoked?(serial)
  end

  defp calculate_expiry(validity_days) do
    DateTime.utc_now()
    |> DateTime.add(validity_days * 24 * 3600, :second)
  end

  defp parse_ip_addresses(agent) do
    # Parse from agent metadata or last_seen_ip
    case agent do
      %{metadata: %{"ip_addresses" => ips}} when is_list(ips) -> ips
      %{last_seen_ip: ip} when is_binary(ip) -> [ip]
      _ -> []
    end
  end

  defp parse_dns_names(agent) do
    # Parse from agent metadata
    case agent do
      %{metadata: %{"dns_names" => names}} when is_list(names) -> names
      %{hostname: hostname} when is_binary(hostname) -> [hostname]
      _ -> []
    end
  end

  defp parse_certificate_info(openssl_output) do
    # Parse OpenSSL x509 -text output
    info = %{
      subject: parse_field(openssl_output, ~r/Subject: (.+)/),
      issuer: parse_field(openssl_output, ~r/Issuer: (.+)/),
      serial_number: parse_field(openssl_output, ~r/Serial Number:\s*\n?\s*([a-f0-9:]+)/i),
      not_before: parse_field(openssl_output, ~r/Not Before\s*:\s*(.+)/),
      not_after: parse_field(openssl_output, ~r/Not After\s*:\s*(.+)/),
      key_usage: parse_field(openssl_output, ~r/Key Usage:.*\n\s+(.+)/),
      san: parse_field(openssl_output, ~r/Subject Alternative Name:.*\n\s+(.+)/)
    }

    {:ok, info}
  end

  defp parse_field(text, regex) do
    case Regex.run(regex, text) do
      [_, value] -> String.trim(value)
      _ -> nil
    end
  end

  defp write_temp_file(content) do
    path = Path.join(System.tmp_dir!(), "tamandua_cert_#{:rand.uniform(999_999)}.pem")
    File.write!(path, content)
    path
  end

  defp openssl(args, opts \\ []) do
    case OSCommand.run("openssl", args, opts) do
      {:error, reason} -> {inspect(reason), 127}
      result -> result
    end
  end
end
