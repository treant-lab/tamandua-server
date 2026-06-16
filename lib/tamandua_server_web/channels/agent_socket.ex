defmodule TamanduaServerWeb.AgentSocket do
  @moduledoc """
  WebSocket handler for agent connections.

  Handles:
  - Agent authentication (mTLS + token)
  - DB-backed credential validation
  - Connection lifecycle
  - Message routing

  ## Security
  Authentication is performed in layers:
  1. Token validation (JWT with jti claim)
  2. DB-backed credential validation (checks revocation, expiry, org binding)
  3. mTLS certificate validation (required in production)
  4. Agent ID verification against certificate CN

  In production, both token AND mTLS are REQUIRED.

  ## Credential Validation (ACCOUNT_INTEGRITY_THREAT_MODEL.md)
  - Token jti is validated against agent_credentials table
  - Revoked or expired credentials are rejected
  - Organization binding is verified
  - last_used_at is updated for audit trails
  """

  use Phoenix.Socket
  require Logger

  alias TamanduaServer.Agents.{Registry, Worker, CertificateManager, Credentials}
  alias TamanduaServer.Agents.TokenManager.AgentToken
  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.OSCommand
  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant

  import Ecto.Query, only: [from: 2]

  # Maximum legacy token lifetime in seconds (30 days default, configurable).
  # This replaces the legacy max_age: :infinity
  @max_legacy_token_age_seconds 720 * 3600

  # Channels
  channel("agent:*", TamanduaServerWeb.AgentChannel)

  @impl true
  def connect(params, socket, connect_info) do
    env = Application.get_env(:tamandua_server, :env, :prod)

    # SECURITY: Enforce mTLS in production before proceeding
    with :ok <- check_mtls_enforcement(env),
         {:ok, agent_id, cert_info, credential_jti} <- authenticate_agent(params, connect_info),
         {:ok, agent_info} <- extract_agent_info(params) do
      # Extract peer IP from connection info
      peer_ip = extract_peer_ip(connect_info)

      agent_info =
        agent_info
        |> Map.put(:ip_address, peer_ip)
        |> maybe_put_cert_info(cert_info)

      socket =
        socket
        |> assign(:agent_id, agent_id)
        |> assign(:agent_info, agent_info)
        |> assign(:certificate_info, cert_info)
        |> assign(:credential_jti, credential_jti)
        |> assign(:connected_at, System.system_time(:millisecond))

      Logger.info("Agent connected: #{agent_id}, credential_jti: #{credential_jti || "legacy"}")
      {:ok, socket}
    else
      {:error, reason} ->
        Logger.warning(
          "Agent connection rejected: #{inspect(reason)} " <>
            "agent_id=#{inspect(params["agent_id"])} token_hash=#{redacted_token_hash(params["token"])}"
        )

        :error
    end
  end

  @impl true
  def id(socket), do: "agent:#{socket.assigns.agent_id}"

  # Private functions

  # SECURITY: Check mTLS is properly configured in production
  defp check_mtls_enforcement(env) do
    require_mtls = Application.get_env(:tamandua_server, :require_mtls, false)
    ca_cert_path = Application.get_env(:tamandua_server, :ca_cert_path)

    cond do
      # Production requires mTLS to be enabled and configured
      env == :prod and not require_mtls and not lab_light_enabled?() ->
        Logger.critical(
          "SECURITY: Production boot with mTLS disabled! This is a security violation."
        )

        {:error, :mtls_required_in_production}

      env == :prod and require_mtls and is_nil(ca_cert_path) and not lab_light_enabled?() ->
        Logger.critical("SECURITY: mTLS enabled but CA cert path not configured!")
        {:error, :mtls_ca_not_configured}

      true ->
        :ok
    end
  end

  defp authenticate_agent(params, connect_info) do
    token = params["token"]
    agent_id = params["agent_id"]
    env = Application.get_env(:tamandua_server, :env, :prod)
    peer_ip = extract_peer_ip(connect_info)

    with {:ok, claims, jti} <- validate_credentials(token, agent_id, peer_ip),
         {:ok, ^agent_id, cert_info} <- verify_mtls(connect_info, agent_id, env) do
      {:ok, agent_id, cert_info, jti}
    else
      {:error, reason} ->
        Logger.warning(
          "Agent connection rejected: #{inspect(reason)} " <>
            "agent_id=#{inspect(agent_id)} token_hash=#{redacted_token_hash(token)}"
        )

        {:error, reason}

      _ ->
        Logger.warning(
          "Agent connection rejected: authentication_failed " <>
            "agent_id=#{inspect(agent_id)} token_hash=#{redacted_token_hash(token)}"
        )

        {:error, :authentication_failed}
    end
  end

  defp validate_credentials(token, agent_id, peer_ip) do
    env = Application.get_env(:tamandua_server, :env, :prod)

    if not is_nil(token) && not is_nil(agent_id) do
      # Allow dev tokens in dev environment
      if env == :dev && String.starts_with?(token, "dev-") do
        Logger.debug("Dev token accepted for agent #{agent_id}")
        {:ok, %{}, nil}
      else
        validate_socket_token(token, agent_id, env, peer_ip)
      end
    else
      {:error, :missing_credentials}
    end
  rescue
    e ->
      Logger.error("JWT verification error: #{inspect(e)}")
      {:error, :jwt_error}
  end

  defp validate_socket_token(token, agent_id, env, peer_ip) do
    case TamanduaServer.Guardian.decode_and_verify(token) do
      {:ok, claims} ->
        # Validate agent_id match first
        case validate_claims_agent_id(claims, agent_id) do
          {:ok, _} ->
            # Check for jti claim for DB-backed validation
            jti = claims["credential_jti"] || claims["jti"]
            org_id = claims["org_id"] || claims["organization_id"]

            if jti && org_id do
              # DB-backed credential validation
              validate_credential_db(jti, agent_id, org_id, peer_ip, claims, token)
            else
              # Legacy token without jti - allowed in dev/test, blocked in prod
              validate_legacy_claims(claims, agent_id, env)
            end

          error ->
            error
        end

      {:error, reason} ->
        Logger.debug("JWT verification failed: #{inspect(reason)}")

        case validate_active_token_hash_fallback(token, agent_id) do
          {:ok, _claims, _jti} = ok ->
            ok

          {:error, _fallback_reason} ->
            validate_legacy_socket_token(token, agent_id, env)
        end
    end
  end

  defp validate_active_token_hash_fallback(token, agent_id) do
    token_hash = :crypto.hash(:sha256, token) |> Base.encode16(case: :lower)
    now = DateTime.utc_now()

    query =
      from(t in AgentToken,
        where:
          t.agent_id == ^agent_id and
            t.token_hash == ^token_hash and
            is_nil(t.revoked_at) and
            t.expires_at > ^now,
        limit: 1
      )

    case Repo.one(query) do
      %AgentToken{} = token_record ->
        case Repo.get(TamanduaServer.Agents.Agent, agent_id) do
          nil ->
            {:error, :agent_not_found}

          agent ->
            Logger.warning(
              "JWT decode failed for agent #{agent_id}, but active token hash matched; accepting DB-backed token fallback"
            )

            claims = %{
              "agent_id" => agent_id,
              "org_id" => agent.organization_id,
              "organization_id" => agent.organization_id,
              "generation" => token_record.token_generation,
              "type" => "agent"
            }

            {:ok, claims, nil}
        end

      _ ->
        {:error, :token_hash_not_found}
    end
  end

  # DB-backed credential validation
  defp validate_credential_db(jti, agent_id, org_id, peer_ip, claims, token) do
    case MultiTenant.with_organization(org_id, fn ->
           Credentials.validate_and_record_use(jti, agent_id, org_id, peer_ip)
         end) do
      {:ok, _credential} ->
        Logger.debug("DB credential validated for agent #{agent_id}, jti: #{jti}")
        {:ok, claims, jti}

      {:error, :credential_not_found} ->
        validate_agent_token_record(token, agent_id, org_id, claims, jti)

      {:error, :credential_revoked} ->
        # Revocation is authoritative. A revoked credential must NOT be able to
        # reconnect via the transitional AgentToken hash fallback, otherwise an
        # operator's revocation can be bypassed by a stale-but-active token row.
        Logger.warning(
          "Rejecting agent #{agent_id}: credential revoked (jti=#{jti}); " <>
            "no token-hash fallback for revoked credentials"
        )

        {:error, :credential_revoked}

      {:error, :credential_expired} ->
        # Expiry is authoritative as well; do not resurrect an expired credential
        # through the transitional fallback path.
        Logger.warning(
          "Rejecting agent #{agent_id}: credential expired (jti=#{jti}); " <>
            "no token-hash fallback for expired credentials"
        )

        {:error, :credential_expired}

      {:error, :agent_mismatch} ->
        validate_agent_token_record(token, agent_id, org_id, claims, jti, :credential_agent_mismatch)

      {:error, :org_mismatch} ->
        validate_agent_token_record(token, agent_id, org_id, claims, jti, :credential_org_mismatch)

      {:error, reason} ->
        validate_agent_token_record(token, agent_id, org_id, claims, jti, reason)
    end
  rescue
    e ->
      Logger.error(
        "Credential validation failed in organization context: #{Exception.message(e)}"
      )

      {:error, :credential_validation_failed}
  end

  defp validate_agent_token_record(token, agent_id, org_id, claims, jti, credential_reason \\ :credential_not_found) do
    token_hash = :crypto.hash(:sha256, token) |> Base.encode16(case: :lower)
    now = DateTime.utc_now()

    query =
      from(t in AgentToken,
        where:
          t.agent_id == ^agent_id and
            t.token_hash == ^token_hash and
            is_nil(t.revoked_at) and
            t.expires_at > ^now,
        limit: 1
      )

    case MultiTenant.with_organization(org_id, fn -> Repo.one(query) end) do
      %AgentToken{} ->
        Logger.warning(
          "Credential validation #{inspect(credential_reason)} for agent #{agent_id}, jti=#{jti}; " <>
            "active token hash matched, accepting DB-backed transitional token"
        )

        {:ok, claims, jti}

      _ ->
        Logger.warning(
          "Credential validation #{inspect(credential_reason)} for agent #{agent_id}, " <>
            "jti=#{jti}; active token hash not found"
        )

        {:error, credential_reason}
    end
  end

  defp redacted_token_hash(token) when is_binary(token) and byte_size(token) > 0 do
    token
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16(case: :lower)
    |> String.slice(0, 12)
  end

  defp redacted_token_hash(_), do: "none"

  # Legacy tokens without jti - restricted to dev/test
  defp validate_legacy_claims(claims, agent_id, env) do
    if env in [:dev, :test] or lab_light_enabled?() do
      Logger.debug("Legacy JWT (no jti) accepted for agent #{agent_id} in #{env} environment")
      {:ok, claims, nil}
    else
      Logger.warning("Legacy JWT without jti rejected in production for agent #{agent_id}")
      {:error, :jti_required_in_production}
    end
  end

  # SECURITY: Legacy Phoenix.Token validation with FINITE max_age (no more :infinity)
  defp validate_legacy_socket_token(token, agent_id, env) do
    if env in [:dev, :test] or lab_light_enabled?() do
      # Use configurable max_age, default 30 days - NO MORE INFINITY
      max_age =
        Application.get_env(
          :tamandua_server,
          :legacy_token_max_age_seconds,
          @max_legacy_token_age_seconds
        )

      case Phoenix.Token.verify(TamanduaServerWeb.Endpoint, "agent_auth", token, max_age: max_age) do
        {:ok, claims} ->
          case validate_claims_agent_id(claims, agent_id) do
            {:ok, _} ->
              Logger.debug(
                "Legacy Phoenix.Token accepted for agent #{agent_id} (max_age: #{max_age}s)"
              )

              {:ok, claims, nil}

            error ->
              error
          end

        {:error, :expired} ->
          Logger.warning("Legacy token expired for agent #{agent_id}")
          {:error, :token_expired}

        {:error, reason} ->
          Logger.debug("Legacy token verification failed: #{inspect(reason)}")
          {:error, :invalid_token}
      end
    else
      {:error, :invalid_token}
    end
  end

  defp validate_claims_agent_id(claims, agent_id) do
    claims_agent_id = claims["agent_id"] || claims[:agent_id]

    if claims_agent_id == agent_id do
      {:ok, true}
    else
      Logger.warning("Socket token validation failed: agent_id mismatch")
      {:error, :invalid_token}
    end
  end

  defp lab_light_enabled? do
    System.get_env("TAMANDUA_LAB_LIGHT", "false") == "true"
  end

  defp verify_hmac_token(token, agent_id, secret) do
    # Token format: HMAC-SHA256(agent_id + timestamp, secret)
    # Expected: agent_id:timestamp:signature
    case String.split(token, ":") do
      [token_agent_id, timestamp_str, signature] ->
        with true <- token_agent_id == agent_id,
             {timestamp, ""} <- Integer.parse(timestamp_str),
             true <- token_not_expired?(timestamp),
             true <- verify_signature(agent_id, timestamp_str, signature, secret) do
          true
        else
          _ -> false
        end

      _ ->
        false
    end
  end

  defp token_not_expired?(timestamp) do
    # Token valid for 1 hour
    max_age_seconds = Application.get_env(:tamandua_server, :token_max_age_seconds, 3600)
    now = System.system_time(:second)
    timestamp > now - max_age_seconds
  end

  defp verify_signature(agent_id, timestamp, signature, secret) do
    message = "#{agent_id}:#{timestamp}"
    expected = :crypto.mac(:hmac, :sha256, secret, message) |> Base.encode16(case: :lower)
    Plug.Crypto.secure_compare(expected, String.downcase(signature))
  end

  defp verify_mtls(connect_info, agent_id, env) do
    if mtls_required?(env) do
      case extract_client_certificate(connect_info) do
        {:ok, cert_der} ->
          verify_client_certificate(cert_der, agent_id)

        {:error, reason} ->
          Logger.warning("Missing client certificate for agent #{agent_id}")
          {:error, reason}
      end
    else
      # In dev/test, allow without mTLS if not enforced
      {:ok, agent_id, nil}
    end
  end

  defp extract_client_certificate(%{peer_data: %{ssl_cert: cert_der}}) when is_binary(cert_der) do
    {:ok, cert_der}
  end

  defp extract_client_certificate(connect_info) do
    if Application.get_env(:tamandua_server, :mtls_trust_proxy_headers, false) do
      extract_proxy_client_certificate(connect_info)
    else
      {:error, :missing_certificate}
    end
  end

  defp extract_proxy_client_certificate(%{x_headers: headers}) when is_list(headers) do
    verify =
      get_x_header(headers, "x-client-verify") || get_x_header(headers, "x-ssl-client-verify")

    encoded_cert =
      get_x_header(headers, "x-client-cert") || get_x_header(headers, "x-ssl-client-cert")

    cond do
      verify != "SUCCESS" ->
        {:error, :proxy_client_certificate_not_verified}

      is_nil(encoded_cert) or encoded_cert == "" ->
        {:error, :missing_certificate}

      true ->
        encoded_cert
        |> URI.decode_www_form()
        |> pem_to_der()
    end
  end

  defp extract_proxy_client_certificate(_), do: {:error, :missing_certificate}

  defp get_x_header(headers, name) do
    headers
    |> Enum.find_value(fn
      {header, value} when is_binary(header) and is_binary(value) ->
        if String.downcase(header) == name, do: value

      _ ->
        nil
    end)
  end

  defp pem_to_der(pem) when is_binary(pem) do
    case :public_key.pem_decode(pem) do
      [{:Certificate, der, _}] -> {:ok, der}
      _ -> {:error, :invalid_proxy_client_certificate}
    end
  end

  defp mtls_required?(env) do
    not lab_light_enabled?() and
      (env == :prod || Application.get_env(:tamandua_server, :require_mtls, false))
  end

  defp verify_client_certificate(cert_der, agent_id) do
    # Use the CertificateManager for comprehensive validation
    with {:ok, cert_info} <- CertificateManager.parse_certificate(cert_der),
         :ok <- verify_certificate_time(cert_info),
         :ok <- verify_cert_chain_wrapper(cert_der, agent_id),
         {:ok, verified_agent_id} <- CertificateManager.validate_and_pin(cert_der, agent_id),
         :ok <- verify_ocsp_status(cert_der, agent_id) do
      Logger.info(
        "Certificate validated for agent #{verified_agent_id}: #{cert_info.fingerprint}"
      )

      {:ok, verified_agent_id, cert_info}
    else
      {:error, reason} ->
        Logger.warning(
          "Certificate verification failed for agent #{agent_id}: #{inspect(reason)}"
        )

        {:error, reason}
    end
  rescue
    e ->
      Logger.error("Certificate verification error: #{inspect(e)}")
      {:error, :certificate_error}
  end

  defp verify_certificate_time(cert_info) do
    now = DateTime.utc_now()

    cond do
      DateTime.compare(now, cert_info.valid_from) == :lt ->
        Logger.warning("Certificate not yet valid")
        {:error, :certificate_not_yet_valid}

      DateTime.compare(now, cert_info.valid_until) == :gt ->
        Logger.warning("Certificate expired")
        {:error, :certificate_expired}

      true ->
        :ok
    end
  end

  defp verify_cert_chain_wrapper(cert_der, agent_id) do
    if verify_cert_chain(cert_der) do
      :ok
    else
      Logger.warning("Certificate chain verification failed for agent #{agent_id}")
      {:error, :invalid_certificate_chain}
    end
  end

  # SECURITY: Optional OCSP revocation check. Gated behind :ocsp_enabled
  # (default false) so dev/test -- which have no live OCSP responder --
  # are unaffected. Only an explicit :revoked status denies the agent;
  # :good and :unknown (soft-fail) are accepted so a responder outage does
  # not lock out the fleet (see TamanduaServer.PKI.OCSP).
  defp verify_ocsp_status(cert_der, agent_id) do
    if Application.get_env(:tamandua_server, :ocsp_enabled, false) do
      case load_issuer_cert_der() do
        {:ok, issuer_der} ->
          case TamanduaServer.PKI.OCSP.check(cert_der, issuer_der) do
            {:ok, :revoked} ->
              Logger.warning("OCSP: certificate REVOKED for agent #{agent_id}")
              {:error, :certificate_revoked}

            {:ok, status} ->
              Logger.debug("OCSP status #{inspect(status)} for agent #{agent_id}")
              :ok

            {:error, reason} ->
              # OCSP.check only returns :error when soft_fail is disabled.
              Logger.warning("OCSP check failed for agent #{agent_id}: #{inspect(reason)}")
              {:error, :ocsp_check_failed}
          end

        {:error, reason} ->
          Logger.warning(
            "OCSP enabled but issuer cert unavailable for agent #{agent_id}: #{inspect(reason)}; skipping"
          )

          :ok
      end
    else
      :ok
    end
  end

  defp load_issuer_cert_der do
    with {:ok, ca_pem} <- load_ca_bundle(Application.get_env(:tamandua_server, :ca_cert_path)),
         [{:Certificate, der, _} | _] <- :public_key.pem_decode(ca_pem) do
      {:ok, der}
    else
      {:error, _} = error -> error
      _ -> {:error, :issuer_cert_not_found}
    end
  end
  defp certificate_valid_time?({:Validity, not_before, not_after}) do
    now = :calendar.universal_time()
    nb = parse_asn1_time(not_before)
    na = parse_asn1_time(not_after)
    nb <= now and now <= na
  rescue
    e ->
      Logger.warning("Certificate validity time check failed: #{inspect(e)}")
      false
  end

  defp certificate_valid_time?(_), do: true

  defp parse_asn1_time({:utcTime, time_str}) do
    time_str |> to_string() |> parse_utc_time()
  end

  defp parse_asn1_time({:generalTime, time_str}) do
    time_str |> to_string() |> parse_general_time()
  end

  defp parse_asn1_time(_), do: :calendar.universal_time()

  defp parse_utc_time(
         <<y::binary-2, m::binary-2, d::binary-2, h::binary-2, mi::binary-2, s::binary-2, "Z">>
       ) do
    year = String.to_integer(y)
    year = if year >= 50, do: 1900 + year, else: 2000 + year

    {{year, String.to_integer(m), String.to_integer(d)},
     {String.to_integer(h), String.to_integer(mi), String.to_integer(s)}}
  end

  defp parse_utc_time(_), do: :calendar.universal_time()

  defp parse_general_time(
         <<y::binary-4, m::binary-2, d::binary-2, h::binary-2, mi::binary-2, s::binary-2, "Z">>
       ) do
    {{String.to_integer(y), String.to_integer(m), String.to_integer(d)},
     {String.to_integer(h), String.to_integer(mi), String.to_integer(s)}}
  end

  defp parse_general_time(_), do: :calendar.universal_time()

  defp extract_cn({:rdnSequence, rdn_sequence}) do
    # Find CN in RDN sequence
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

  defp verify_cert_chain(cert_der) do
    ca_cert_path = Application.get_env(:tamandua_server, :ca_cert_path)

    case load_ca_bundle(ca_cert_path) do
      {:ok, ca_pem} ->
        verify_against_ca(cert_der, ca_pem)

      {:error, reason} ->
        Logger.error("Failed to load CA bundle for mTLS verification: #{inspect(reason)}")
        false
    end
  end

  defp load_ca_bundle(path) when is_binary(path) and path != "" do
    case File.read(path) do
      {:ok, ca_pem} ->
        {:ok, ca_pem}

      {:error, _reason} ->
        load_ca_bundle_from_pki()
    end
  end

  defp load_ca_bundle(_), do: load_ca_bundle_from_pki()

  defp load_ca_bundle_from_pki do
    with :ok <- TamanduaServer.PKI.CertificateAuthority.ensure_initialized(),
         {:ok, export} <- TamanduaServer.PKI.CertificateAuthority.export_for_agents() do
      {:ok, export.ca_bundle_pem}
    end
  rescue
    e -> {:error, e}
  catch
    :exit, reason -> {:error, reason}
  end

  defp verify_against_ca(cert_der, ca_pem) do
    cert_file =
      write_temp_file(:public_key.pem_encode([{:Certificate, cert_der, :not_encrypted}]))

    ca_file = write_temp_file(ca_pem)

    try do
      case OSCommand.run("openssl", ["verify", "-CAfile", ca_file, cert_file]) do
        {output, 0} ->
          String.contains?(output, "OK")

        {:error, reason} ->
          Logger.warning("Certificate path validation could not run: #{inspect(reason)}")
          false

        {error, _} ->
          Logger.warning("Certificate path validation failed: #{String.trim(error)}")
          false
      end
    rescue
      e ->
        Logger.error("CA verification error: #{inspect(e)}")
        false
    after
      File.rm(cert_file)
      File.rm(ca_file)
    end
  end

  defp write_temp_file(content) do
    path = Path.join(System.tmp_dir!(), "tamandua_mtls_#{System.unique_integer([:positive])}.pem")
    File.write!(path, content)
    path
  end

  defp extract_peer_ip(connect_info) do
    case connect_info do
      %{peer_data: %{address: addr}} when is_tuple(addr) ->
        addr |> :inet.ntoa() |> to_string()

      %{x_headers: headers} when is_list(headers) ->
        case List.keyfind(headers, "x-forwarded-for", 0) do
          {_, ip} -> ip |> String.split(",") |> List.first() |> String.trim()
          nil -> "unknown"
        end

      _ ->
        "unknown"
    end
  end

  defp extract_agent_info(params) do
    info = %{
      hostname: params["hostname"],
      os_type: params["os_type"],
      os_version: params["os_version"],
      agent_version: params["agent_version"],
      machine_id: params["machine_id"],
      capabilities: params["capabilities"] || [],
      collectors: params["collectors"] || %{},
      organization_id: extract_org_id_from_token(params["token"])
    }

    if info.hostname && info.os_type do
      {:ok, info}
    else
      {:error, :incomplete_agent_info}
    end
  end

  defp maybe_put_cert_info(agent_info, nil), do: agent_info

  defp maybe_put_cert_info(agent_info, cert_info) do
    agent_info
    |> Map.put(:certificate_fingerprint, cert_info.fingerprint)
    |> Map.put(:certificate_subject, cert_info.subject_dn)
    |> Map.put(:certificate_valid_until, cert_info.valid_until)
  end

  defp extract_org_id_from_token(nil), do: nil

  defp extract_org_id_from_token(token) do
    if lab_light_enabled?() do
      resolve_lab_org_id()
    else
      do_extract_org_id_from_token(token)
    end
  end

  defp do_extract_org_id_from_token(token) do
    env = Application.get_env(:tamandua_server, :env, :prod)

    case TamanduaServer.Guardian.decode_and_verify(token) do
      {:ok, claims} ->
        claims["org_id"] || claims[:org_id] || claims["organization_id"] ||
          claims[:organization_id]

      {:error, _reason} ->
        extract_legacy_org_id(token, env)
    end
  rescue
    _ -> nil
  end

  defp resolve_lab_org_id do
    slug = System.get_env("LAB_LIGHT_ORG_SLUG", "tamandua-lab")

    Repo.one(
      from(o in Organization,
        where: o.slug == ^slug,
        select: o.id,
        limit: 1
      )
    )
  rescue
    _ -> nil
  end

  defp extract_legacy_org_id(token, env) do
    if env in [:dev, :test] or lab_light_enabled?() do
      # SECURITY: Use finite max_age instead of :infinity
      max_age =
        Application.get_env(
          :tamandua_server,
          :legacy_token_max_age_seconds,
          @max_legacy_token_age_seconds
        )

      case Phoenix.Token.verify(TamanduaServerWeb.Endpoint, "agent_auth", token, max_age: max_age) do
        {:ok, claims} ->
          claims["org_id"] || claims[:org_id] || claims["organization_id"] ||
            claims[:organization_id]

        {:error, _reason} ->
          nil
      end
    else
      nil
    end
  end
end

defmodule TamanduaServerWeb.AgentChannel do
  @moduledoc """
  Channel for handling agent communication.
  """

  use TamanduaServerWeb, :channel
  require Logger

  alias TamanduaServer.Agents.{Registry, Worker}

  @impl true
  def join("agent:" <> agent_id, payload, socket) do
    if socket.assigns.agent_id == agent_id do
      # Extract agent config from join payload (sent by agent)
      agent_config = Map.get(payload, "config", %{})

      # Start worker for this agent
      case start_agent_worker(socket, agent_config) do
        {:ok, worker_pid} ->
          socket =
            socket
            |> assign(:worker_pid, worker_pid)
            |> assign(:agent_config, agent_config)

          send(self(), :after_join)
          {:ok, %{status: "connected"}, socket}

        {:error, reason} ->
          {:error, %{reason: inspect(reason)}}
      end
    else
      {:error, %{reason: "unauthorized"}}
    end
  end

  @impl true
  def handle_info(:after_join, socket) do
    agent_id = socket.assigns.agent_id
    Logger.info("[Channel] after_join START for #{agent_id}")

    # Send initial configuration
    try do
      config = get_agent_config(agent_id)
      Logger.debug("[Channel] after_join: config loaded for #{agent_id}")

      sync_rules_on_join? =
        truthy_config?(get_in(socket.assigns, [:agent_config, "sync_rules_on_join"])) or
          truthy_config?(get_in(config || %{}, ["sync_rules_on_join"]))

      config_payload =
        if sync_rules_on_join? do
          yara = get_yara_rules()
          Logger.debug("[Channel] after_join: #{length(yara)} YARA rules loaded")

          sigma = get_sigma_rules()
          Logger.debug("[Channel] after_join: #{length(sigma)} Sigma rules loaded")

          iocs = get_iocs()
          Logger.debug("[Channel] after_join: #{length(iocs)} IOCs loaded")

          %{
            config: config,
            yara_rules: yara,
            sigma_rules: sigma,
            iocs: iocs,
            rules_deferred: false
          }
        else
          Logger.info("[Channel] after_join: deferring heavy rules/IOC sync for #{agent_id}")

          %{
            config: %{},
            rules_deferred: true
          }
        end

      push(socket, "config", config_payload)

      Logger.info("[Channel] after_join COMPLETE for #{agent_id}")
    rescue
      e ->
        Logger.error("[Channel] after_join rescue for #{agent_id}: #{Exception.message(e)}")
    catch
      kind, reason ->
        Logger.error(
          "[Channel] after_join catch for #{agent_id}: #{inspect(kind)} #{inspect(reason)}"
        )
    end

    {:noreply, socket}
  end

  @impl true
  def handle_info({:send_command, command}, socket) do
    push(socket, "command", command)
    {:noreply, socket}
  end

  @impl true
  def handle_info({:sample_result, result}, socket) do
    # Push ML analysis result back to the agent
    push(socket, "sample_result", %{
      sha256: result.sha256,
      verdict: result.verdict,
      score: result.score,
      confidence: result.confidence,
      family: result.family,
      analyzed_at: result.analyzed_at
    })

    {:noreply, socket}
  end

  def handle_info(_msg, socket), do: {:noreply, socket}

  defp truthy_config?(value) when value in [true, "true", "1", 1, "yes", "on"], do: true
  defp truthy_config?(_), do: false

  @impl true
  def handle_in("heartbeat", payload, socket) do
    with {:ok, socket} <- ensure_worker(socket) do
      Worker.heartbeat(socket.assigns.worker_pid)

      # Process isolation status from heartbeat payload if present
      if isolation_data = Map.get(payload, "isolation") do
        Task.start(fn ->
          TamanduaServer.Agents.process_heartbeat_isolation(
            socket.assigns.agent_id,
            isolation_data
          )
        end)
      end

      if payload["capabilities"] || payload["collectors"] do
        Task.start(fn ->
          TamanduaServer.Agents.update_runtime_capabilities(socket.assigns.agent_id, %{
            "reported_capabilities" => payload["capabilities"],
            "reported_collectors" => payload["collectors"],
            "reported_runtime" => %{
              "reported_at" => DateTime.utc_now() |> DateTime.to_iso8601(),
              "source" => "heartbeat"
            }
          })
        end)
      end

      {:reply,
       {:ok,
        %{
          server_time: System.system_time(:millisecond),
          config_updated: false,
          rules_updated: false
        }}, socket}
    else
      {:error, reason} ->
        Logger.warning(
          "AgentChannel: heartbeat rejected for #{socket.assigns.agent_id}; worker unavailable: #{inspect(reason)}"
        )

        {:reply, {:error, %{reason: "worker_unavailable"}}, socket}
    end
  end

  # Upper bound on events accepted in a single telemetry frame. Protects the
  # ingestion pipeline from an authenticated-but-misbehaving (or compromised)
  # agent flooding an unbounded batch.
  @max_telemetry_batch_size 10_000

  @impl true
  def handle_in("telemetry", %{"events" => events}, socket)
      when is_list(events) and length(events) > @max_telemetry_batch_size do
    Logger.warning(
      "AgentChannel: telemetry batch too large (#{length(events)} > #{@max_telemetry_batch_size}) " <>
        "from #{socket.assigns.agent_id}; rejecting"
    )

    {:reply, {:error, %{reason: "batch_too_large", max: @max_telemetry_batch_size}}, socket}
  end

  @impl true
  def handle_in("telemetry", %{"events" => events} = payload, socket) when is_list(events) do
    with {:ok, socket} <- ensure_worker(socket) do
      Logger.info(
        "AgentChannel: Received telemetry batch with #{length(events)} events from #{socket.assigns.agent_id}"
      )
      log_telemetry_batch_summary(socket.assigns.agent_id, events)

      telemetry_batch = %{
        agent_id: socket.assigns.agent_id,
        events: events,
        batch_timestamp: payload["batch_timestamp"]
      }

      Worker.process_telemetry(socket.assigns.worker_pid, telemetry_batch)

      # Send delivery acknowledgment with batch sequence number.
      # The agent uses this to confirm receipt and stop tracking the
      # in-flight batch.  If the payload does not include a "seq" field
      # (older agents), we skip the ACK push -- the reply below still
      # provides backward-compatible confirmation.
      seq = payload["seq"]

      if seq do
        push(socket, "telemetry:ack", %{
          seq: seq,
          count: length(events)
        })
      end

      {:reply, {:ok, %{received: length(events)}}, socket}
    else
      {:error, reason} ->
        Logger.warning(
          "AgentChannel: telemetry rejected for #{socket.assigns.agent_id}; worker unavailable: #{inspect(reason)}"
        )

        {:reply, {:error, %{reason: "worker_unavailable"}}, socket}
    end
  end

  # Reject malformed telemetry frames (missing or non-list "events") with an
  # explicit error instead of crashing the channel on length/1 of a non-list.
  @impl true
  def handle_in("telemetry", _payload, socket) do
    Logger.warning(
      "AgentChannel: malformed telemetry payload from #{socket.assigns.agent_id}; expected a list of events"
    )

    {:reply, {:error, %{reason: "invalid_payload"}}, socket}
  end

  defp log_telemetry_batch_summary(agent_id, events) when is_list(events) do
    source_counts =
      events
      |> Enum.map(fn event ->
        metadata = event["metadata"] || event[:metadata] || %{}
        metadata["source"] || metadata[:source] || "unknown"
      end)
      |> Enum.frequencies()

    type_counts =
      events
      |> Enum.map(fn event -> event["event_type"] || event[:event_type] || "unknown" end)
      |> Enum.frequencies()
      |> Enum.sort_by(fn {_type, count} -> -count end)
      |> Enum.take(8)

    sample_ids =
      events
      |> Enum.map(fn event -> event["event_id"] || event[:event_id] || event["id"] || event[:id] end)
      |> Enum.reject(&is_nil/1)
      |> Enum.take(5)

    if Map.has_key?(source_counts, "kernel_driver") or should_log_agent_summary?(agent_id) do
      Logger.info(
        "AgentChannel: telemetry summary agent=#{agent_id} sources=#{inspect(source_counts)} types=#{inspect(type_counts)} sample_ids=#{inspect(sample_ids)}"
      )
    end
  end

  defp log_telemetry_batch_summary(_agent_id, _events), do: :ok

  defp should_log_agent_summary?(agent_id) do
    debug_agent_id = System.get_env("TAMANDUA_DEBUG_AGENT_ID")
    to_string(agent_id) in [debug_agent_id, "9390f816-2a0f-47c3-aa4b-2b244fa2d737"]
  end

  @impl true
  def handle_in("binary_sample", payload, socket) do
    sample = %{
      agent_id: socket.assigns.agent_id,
      file_path: payload["file_path"],
      sha256: Base.decode64!(payload["sha256"]),
      content: Base.decode64!(payload["content"]),
      total_size: payload["total_size"],
      entropy: payload["entropy"],
      file_type: payload["file_type"]
    }

    # Push to ML pipeline
    TamanduaServer.Telemetry.Ingestor.push_binary_sample(sample)

    {:reply, {:ok, %{status: "processing"}}, socket}
  end

  @impl true
  def handle_in("sample_submit", payload, socket) do
    # New sample submission handler using Samples context
    agent_id = socket.assigns.agent_id
    sha256 = payload["sha256"]

    # Decompress gzip content if provided
    content =
      case payload["content"] do
        nil ->
          nil

        base64_content ->
          case Base.decode64(base64_content) do
            {:ok, data} ->
              if payload["compressed"] == true do
                try do
                  :zlib.gunzip(data)
                rescue
                  e ->
                    Logger.warning("Sample decompression failed, using raw data: #{inspect(e)}")
                    data
                end
              else
                data
              end

            :error ->
              nil
          end
      end

    sample_attrs = %{
      sha256: sha256,
      sha1: payload["sha1"],
      md5: payload["md5"],
      file_name: payload["file_name"],
      file_size: payload["file_size"],
      file_type: payload["file_type"],
      entropy: payload["entropy"],
      source_agent_id: agent_id,
      source_path: payload["source_path"],
      is_signed: payload["is_signed"],
      signer: payload["signer"],
      content: content,
      # Already decompressed above
      compressed: false
    }

    case TamanduaServer.Samples.create_sample(sample_attrs) do
      {:ok, sample} ->
        # Trigger async ML analysis
        TamanduaServer.Samples.analyze_sample(sample)

        # Send acknowledgment
        {:reply,
         {:ok,
          %{
            status: "received",
            sha256: sample.sha256,
            sample_id: sample.id,
            message: "Sample queued for analysis"
          }}, socket}

      {:error, changeset} ->
        Logger.warning(
          "Failed to create sample from agent #{agent_id}: #{inspect(changeset.errors)}"
        )

        {:reply,
         {:error,
          %{
            status: "error",
            message: "Failed to process sample",
            errors: format_changeset_errors(changeset)
          }}, socket}
    end
  end

  @impl true
  def handle_in("command_response", payload, socket) do
    with {:ok, socket} <- ensure_worker(socket) do
      Worker.command_response(socket.assigns.worker_pid, payload)
      {:noreply, socket}
    else
      {:error, reason} ->
        Logger.warning(
          "AgentChannel: command_response rejected for #{socket.assigns.agent_id}; worker unavailable: #{inspect(reason)}"
        )

        {:noreply, socket}
    end
  end

  @impl true
  def handle_in("logs", %{"logs" => logs} = _payload, socket) when is_list(logs) do
    # Process log batch from agent
    agent_id = socket.assigns.agent_id
    Logger.debug("AgentChannel: Received #{length(logs)} log entries from #{agent_id}")

    # Forward to LogAggregator
    TamanduaServer.Agents.LogAggregator.process_log_batch(agent_id, logs)

    {:reply, {:ok, %{received: length(logs)}}, socket}
  end

  @impl true
  def handle_in("logs", %{"count" => count} = payload, socket) do
    # Handle single log entry
    agent_id = socket.assigns.agent_id
    log_entry = Map.delete(payload, "count")

    TamanduaServer.Agents.LogAggregator.process_log(agent_id, log_entry)

    {:reply, {:ok, %{received: 1}}, socket}
  end

  @impl true
  def handle_in("ai_model_load", payload, socket) do
    agent_id = socket.assigns.agent_id
    Logger.info("AgentChannel: Received ai_model_load event from #{agent_id}")

    case TamanduaServer.AISecurity.ModelLoadHandler.handle_event(agent_id, payload) do
      {:ok, _model_load} ->
        {:reply, {:ok, %{status: "received"}}, socket}

      {:error, _changeset} ->
        {:reply, {:error, %{reason: "invalid_payload"}}, socket}
    end
  end

  @impl true
  def handle_in("shell_output", payload, socket) do
    # Route shell output to the appropriate shell channel via PubSub
    session_id = payload["session_id"]

    if session_id do
      Logger.info(
        "AgentChannel: routing shell_output from #{socket.assigns.agent_id} session=#{session_id} type=#{payload["type"] || "unknown"}"
      )

      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "shell:#{socket.assigns.agent_id}",
        {:agent_message, payload}
      )

      worker_pid = socket.assigns[:worker_pid] || Registry.lookup_agent(socket.assigns.agent_id)

      if worker_pid do
        Worker.realtime_output(worker_pid, payload)
      end
    else
      Logger.warning(
        "AgentChannel: shell_output missing session_id from #{socket.assigns.agent_id}, payload keys: #{inspect(Map.keys(payload))}"
      )
    end

    {:noreply, socket}
  end

  # Catch-all handler for debugging unmatched messages
  @impl true
  def handle_in(event, payload, socket) do
    Logger.warning(
      "AgentChannel: Unhandled event '#{event}' from #{socket.assigns.agent_id}, payload keys: #{inspect(Map.keys(payload))}"
    )

    {:noreply, socket}
  end

  @impl true
  def terminate(reason, socket) do
    Logger.warning(
      "Agent channel terminated: #{socket.assigns.agent_id}, reason: #{inspect(reason)}, caller: #{inspect(self())}"
    )

    # The Worker handles cleanup via its :DOWN monitor on the socket_pid.
    # We do NOT call Registry.unregister here to avoid racing with a
    # reconnecting agent that already registered a new worker.
    :ok
  end

  # Private functions

  defp start_agent_worker(socket, agent_config \\ %{}) do
    agent_id = socket.assigns.agent_id
    socket_pid = self()

    Registry.with_agent_lock(agent_id, fn ->
      do_start_agent_worker(socket, agent_config, socket_pid)
    end)
  end

  defp do_start_agent_worker(socket, agent_config, socket_pid) do
    agent_id = socket.assigns.agent_id

    agent_info =
      socket.assigns.agent_info
      |> Map.put(:worker_pid, nil)
      |> Map.put(:config, agent_config)

    # Clean up any existing worker for this agent (reconnection scenario).
    # The old worker may still be alive if the socket death hasn't propagated yet.
    case Registry.get(agent_id) do
      {:ok, %{worker_pid: wp}} when is_pid(wp) ->
        Logger.info("Stopping previous worker for reconnecting agent #{agent_id}")

        try do
          GenServer.stop(wp, :normal, 5_000)
        catch
          :exit, _ -> :ok
        end

      {:ok, existing} when is_map(existing) ->
        wp = existing[:worker_pid]

        if is_pid(wp) do
          Logger.info("Stopping previous worker for reconnecting agent #{agent_id}")

          try do
            GenServer.stop(wp, :normal, 5_000)
          catch
            :exit, _ -> :ok
          end
        end

      _ ->
        :ok
    end

    DynamicSupervisor.start_child(
      TamanduaServer.Agents.Supervisor,
      {Worker,
       [
         agent_id: agent_id,
         socket_pid: socket_pid,
         agent_info: agent_info
       ]}
    )
  end

  defp ensure_worker(socket) do
    case Map.get(socket.assigns, :worker_pid) do
      pid when is_pid(pid) ->
        if Process.alive?(pid) do
          {:ok, socket}
        else
          case current_registry_worker(socket.assigns.agent_id) do
            {:ok, current_pid} when current_pid != pid ->
              Logger.warning(
                "AgentChannel: rebinding stale socket for #{socket.assigns.agent_id}; current worker is #{inspect(current_pid)}, stale worker was #{inspect(pid)}"
              )

              {:ok, assign(socket, :worker_pid, current_pid)}

            _ ->
              restart_agent_worker(socket, :dead_worker)
          end
        end

      _ ->
        case current_registry_worker(socket.assigns.agent_id) do
          {:ok, current_pid} ->
            Logger.warning(
              "AgentChannel: binding socket without worker for #{socket.assigns.agent_id}; current worker is #{inspect(current_pid)}"
            )

            {:ok, assign(socket, :worker_pid, current_pid)}

          _ ->
            restart_agent_worker(socket, :missing_worker)
        end
    end
  end

  defp current_registry_worker(agent_id) do
    case Registry.get_worker_pid(agent_id) do
      {:ok, pid} when is_pid(pid) ->
        if Process.alive?(pid), do: {:ok, pid}, else: :none

      _ ->
        :none
    end
  end

  defp restart_agent_worker(socket, reason) do
    Logger.warning(
      "AgentChannel: restarting worker for #{socket.assigns.agent_id}: #{inspect(reason)}"
    )

    agent_config = Map.get(socket.assigns, :agent_config, %{})

    case start_agent_worker(socket, agent_config) do
      {:ok, worker_pid} ->
        {:ok, assign(socket, :worker_pid, worker_pid)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp get_agent_config(agent_id) do
    case Registry.get(agent_id) do
      {:ok, agent} -> agent.config
      _ -> default_config()
    end
  end

  defp default_config do
    %{
      heartbeat_interval_seconds: 30,
      batch_size: 100,
      batch_timeout_seconds: 5,
      yara_enabled: true,
      entropy_check_enabled: true,
      entropy_threshold: 7.5,
      excluded_paths: [],
      excluded_processes: []
    }
  end

  defp get_yara_rules do
    TamanduaServer.Detection.list_yara_rules_for_agent()
  rescue
    e ->
      Logger.warning("Failed to load YARA rules: #{inspect(e)}")
      []
  end

  defp get_sigma_rules do
    TamanduaServer.Detection.list_sigma_rules_for_agent()
  rescue
    e ->
      Logger.warning("Failed to load Sigma rules: #{inspect(e)}")
      []
  end

  defp get_iocs do
    TamanduaServer.Detection.list_iocs_for_agent()
  rescue
    e ->
      Logger.warning("Failed to load IOCs: #{inspect(e)}")
      []
  end

  defp format_changeset_errors(%Ecto.Changeset{} = changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
end
