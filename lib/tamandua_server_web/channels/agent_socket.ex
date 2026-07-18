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

  use Phoenix.Socket, log: false
  require Logger

  alias TamanduaServer.Agents
  alias TamanduaServer.Agents.{Registry, Worker, CertificateManager, Credentials}
  alias TamanduaServer.Repo.MultiTenant

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
         {:ok, agent_id, organization_id, cert_info, credential_jti} <-
           authenticate_agent(params, connect_info),
         {:ok, agent_info} <- extract_agent_info(params, organization_id) do
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

      Logger.info(
        "Agent connected: #{agent_id}, credential_ref: #{credential_reference(credential_jti)}"
      )

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
      insecure_agent_socket_allowed?() ->
        Logger.critical(
          "SECURITY: TAMANDUA_ALLOW_INSECURE_AGENT_SOCKET=true; agent mTLS enforcement is disabled for this runtime."
        )

        :ok

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

    with {:ok, canonical_agent_id} <- canonical_uuid(agent_id, :invalid_agent_id),
         {:ok, claims, jti} <- validate_credentials(token, canonical_agent_id, peer_ip),
         {:ok, canonical_organization_id} <-
           authenticated_organization_id(claims, canonical_agent_id, jti),
         {:ok, ^canonical_agent_id, cert_info} <-
           verify_mtls(connect_info, canonical_agent_id, env) do
      {:ok, canonical_agent_id, canonical_organization_id, cert_info, jti}
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
    _ ->
      Logger.error("JWT verification raised while authenticating agent socket")
      {:error, :jwt_error}
  end

  defp validate_socket_token(token, agent_id, env, peer_ip) do
    case TamanduaServer.Guardian.decode_and_verify(token) do
      {:ok, claims} ->
        if managed_credential_claims?(claims) do
          with {:ok, identity} <- validate_managed_identity(claims, agent_id),
               :ok <- validate_exact_tenant_agent(identity.agent_id, identity.organization_id) do
            validate_credential_db(
              identity.jti,
              identity.agent_id,
              identity.organization_id,
              peer_ip,
              claims
            )
          end
        else
          with {:ok, _} <- validate_claims_agent_id(claims, agent_id) do
            validate_legacy_claims(claims, agent_id, env)
          end
        end

      {:error, reason} ->
        Logger.debug("JWT verification failed: #{inspect(reason)}")

        if compact_jwt?(token) do
          {:error, :invalid_token}
        else
          validate_legacy_socket_token(token, agent_id, env)
        end
    end
  end

  # DB-backed credential validation
  defp validate_credential_db(jti, agent_id, org_id, peer_ip, claims) do
    case Credentials.validate_and_record_use(jti, agent_id, org_id, peer_ip) do
      {:ok, _credential} ->
        Logger.debug(
          "DB credential validated for agent #{agent_id}, credential_ref: #{credential_reference(jti)}"
        )

        {:ok, claims, jti}

      {:error, reason} ->
        Logger.warning(
          "Rejecting managed credential for agent #{agent_id}: #{inspect(reason)} " <>
            "credential_ref=#{credential_reference(jti)}"
        )

        {:error, reason}
    end
  rescue
    _ ->
      Logger.error("Credential validation raised in organization context")

      {:error, :credential_validation_failed}
  end

  defp redacted_token_hash(token) when is_binary(token) and byte_size(token) > 0 do
    token
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16(case: :lower)
    |> String.slice(0, 12)
  end

  defp redacted_token_hash(_), do: "none"

  defp credential_reference(jti) when is_binary(jti) and byte_size(jti) > 0 do
    jti
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16(case: :lower)
    |> String.slice(0, 12)
  end

  defp credential_reference(_), do: "legacy"

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
      max_age = legacy_token_max_age_seconds()

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
    subject = claims["sub"] || claims[:sub]

    with {:ok, expected_agent_id} <- canonical_uuid(agent_id, :invalid_token),
         {:ok, claims_agent_id} <- canonical_uuid(claims_agent_id, :invalid_token),
         true <- claims_agent_id === expected_agent_id,
         :ok <- validate_optional_subject(subject, expected_agent_id) do
      {:ok, true}
    else
      _ ->
        Logger.warning("Socket token validation failed: agent identity mismatch")
        {:error, :invalid_token}
    end
  end

  defp managed_credential_claims?(claims) do
    present_claim?(claims, "type", :type) or
      present_claim?(claims, "credential_jti", :credential_jti) or
      present_claim?(claims, "jti", :jti) or
      present_claim?(claims, "org_id", :org_id) or
      present_claim?(claims, "organization_id", :organization_id) or
      present_claim?(claims, "generation", :generation)
  end

  defp validate_managed_identity(claims, requested_agent_id) do
    subject = claims["sub"]
    claims_agent_id = claims["agent_id"]
    org_id = claims["org_id"]
    organization_id = claims["organization_id"]
    credential_jti = claims["credential_jti"]
    jti = claims["jti"]

    with "agent" <- claims["type"],
         {:ok, requested_agent_id} <- canonical_uuid(requested_agent_id, :invalid_token),
         {:ok, subject} <- canonical_uuid(subject, :invalid_token),
         {:ok, claims_agent_id} <- canonical_uuid(claims_agent_id, :invalid_token),
         true <- requested_agent_id === subject and subject === claims_agent_id,
         {:ok, org_id} <- canonical_uuid(org_id, :invalid_token),
         {:ok, organization_id} <- canonical_uuid(organization_id, :invalid_token),
         true <- org_id === organization_id,
         true <- bounded_jti?(credential_jti),
         true <- credential_jti === jti do
      {:ok, %{agent_id: claims_agent_id, organization_id: org_id, jti: credential_jti}}
    else
      _ ->
        Logger.warning(
          "Socket managed token validation failed: ambiguous or missing identity claims"
        )

        {:error, :invalid_token}
    end
  end

  defp validate_exact_tenant_agent(agent_id, organization_id) do
    case MultiTenant.with_organization(organization_id, fn ->
           Agents.get_agent_for_org(organization_id, agent_id)
         end) do
      {:ok, %{id: ^agent_id, organization_id: ^organization_id}} -> :ok
      _ -> {:error, :invalid_token}
    end
  rescue
    _ -> {:error, :invalid_token}
  end

  defp validate_optional_subject(nil, _expected_agent_id), do: :ok

  defp validate_optional_subject(subject, expected_agent_id) do
    case canonical_uuid(subject, :invalid_token) do
      {:ok, ^expected_agent_id} -> :ok
      _ -> {:error, :invalid_token}
    end
  end

  defp present_claim?(claims, string_key, atom_key) do
    Map.has_key?(claims, string_key) or Map.has_key?(claims, atom_key)
  end

  defp bounded_jti?(value), do: is_binary(value) and byte_size(value) in 1..255

  defp canonical_uuid(value, error_reason) when is_binary(value) do
    case Ecto.UUID.cast(value) do
      {:ok, canonical} when canonical === value -> {:ok, canonical}
      {:ok, _normalized} -> {:error, error_reason}
      :error -> {:error, error_reason}
    end
  end

  defp canonical_uuid(_value, error_reason), do: {:error, error_reason}

  defp authenticated_organization_id(claims, agent_id, credential_jti) when is_map(claims) do
    authenticated_organization_id_for_mode(claims, agent_id, credential_jti)
  end

  defp authenticated_organization_id(_claims, _agent_id, _credential_jti),
    do: {:error, :invalid_token}

  defp authenticated_organization_id_for_mode(claims, _agent_id, credential_jti)
       when is_binary(credential_jti) do
    claims
    |> claimed_organization_id()
    |> canonical_uuid(:invalid_token)
  end

  defp authenticated_organization_id_for_mode(claims, agent_id, nil) do
    reconcile_authenticated_organization(
      canonical_claimed_organization_id(claims),
      exact_agent_organization_id(agent_id)
    )
  end

  defp authenticated_organization_id_for_mode(_claims, _agent_id, _credential_jti),
    do: {:error, :invalid_token}

  defp exact_agent_organization_id(agent_id) do
    case Agents.get_agent(agent_id) do
      {:ok, %{id: stored_agent_id, organization_id: organization_id}}
      when stored_agent_id === agent_id ->
        canonical_uuid(organization_id, :invalid_token)

      _ ->
        {:error, :invalid_token}
    end
  rescue
    _ -> {:error, :invalid_token}
  end

  defp canonical_claimed_organization_id(claims) do
    case claimed_organization_id(claims) do
      nil -> :absent
      claimed -> canonical_uuid(claimed, :invalid_token)
    end
  end

  defp reconcile_authenticated_organization({:ok, claimed}, {:ok, stored})
       when claimed === stored,
       do: {:ok, claimed}

  defp reconcile_authenticated_organization({:ok, claimed}, {:error, :invalid_token}),
    do: {:ok, claimed}

  defp reconcile_authenticated_organization(:absent, {:ok, stored}), do: {:ok, stored}
  defp reconcile_authenticated_organization(_, _), do: {:error, :invalid_token}

  defp claimed_organization_id(claims) do
    claims["org_id"] || claims[:org_id] || claims["organization_id"] ||
      claims[:organization_id]
  end

  defp compact_jwt?(token) when is_binary(token) do
    case String.split(token, ".", parts: 4) do
      [header, payload, signature] ->
        Enum.all?([header, payload, signature], &(byte_size(&1) > 0))

      _ ->
        false
    end
  end

  defp compact_jwt?(_), do: false

  defp legacy_token_max_age_seconds do
    case Application.get_env(
           :tamandua_server,
           :legacy_token_max_age_seconds,
           @max_legacy_token_age_seconds
         ) do
      configured when is_integer(configured) and configured > 0 ->
        min(configured, @max_legacy_token_age_seconds)

      _ ->
        @max_legacy_token_age_seconds
    end
  end

  defp lab_light_enabled? do
    System.get_env("TAMANDUA_LAB_LIGHT", "false") == "true"
  end

  defp insecure_agent_socket_allowed? do
    System.get_env("TAMANDUA_ALLOW_INSECURE_AGENT_SOCKET", "false") == "true"
  end

  defp verify_hmac_token(token, agent_id, secret) do
    # Token format: HMAC-SHA256(agent_id + timestamp, secret)
    # Expected: agent_id:timestamp:signature
    case String.split(token, ":") do
      [token_agent_id, timestamp_str, signature] ->
        with true <- token_agent_id === agent_id,
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
    not lab_light_enabled?() and not insecure_agent_socket_allowed?() and
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

  # Upper bound on the number of certificates in a validation path (leaf +
  # intermediates + root). Bounds the issuer walk in build_validation_path/2
  # against malformed or cyclic CA bundles.
  @max_cert_chain_length 8

  defp verify_cert_chain(cert_der) do
    case load_ca_certs() do
      {:ok, ca_certs} ->
        verify_against_ca(cert_der, ca_certs)

      {:error, reason} ->
        Logger.error("Failed to load CA bundle for mTLS verification: #{inspect(reason)}")
        false
    end
  end

  # Loads and decodes the trusted CA bundle into a list of DER certificates.
  # File-based bundles are cached in :persistent_term keyed by path, with the
  # file mtime stored alongside the parsed certs so the bundle is re-read and
  # re-parsed only when the file changes on disk.
  defp load_ca_certs do
    ca_cert_path = Application.get_env(:tamandua_server, :ca_cert_path)
    load_ca_certs(ca_cert_path)
  end

  defp load_ca_certs(path) when is_binary(path) and path != "" do
    case File.stat(path, time: :posix) do
      {:ok, %File.Stat{mtime: mtime}} ->
        cache_key = {__MODULE__, :ca_bundle, path}

        case :persistent_term.get(cache_key, nil) do
          {^mtime, ca_certs} ->
            {:ok, ca_certs}

          _ ->
            with {:ok, ca_pem} <- File.read(path),
                 {:ok, ca_certs} <- decode_ca_bundle(ca_pem) do
              :persistent_term.put(cache_key, {mtime, ca_certs})
              {:ok, ca_certs}
            else
              # A bundle that exists but does not parse stays fail-closed;
              # an unreadable file falls back to the in-process PKI export,
              # matching the previous load_ca_bundle/1 behavior.
              {:error, :no_ca_certificates} = error -> error
              {:error, _} -> load_ca_certs_from_pki()
            end
        end

      {:error, _} ->
        load_ca_certs_from_pki()
    end
  end

  defp load_ca_certs(_), do: load_ca_certs_from_pki()

  defp load_ca_certs_from_pki do
    with {:ok, ca_pem} <- load_ca_bundle_from_pki() do
      decode_ca_bundle(ca_pem)
    end
  end

  defp decode_ca_bundle(ca_pem) do
    ca_certs =
      for {:Certificate, der, :not_encrypted} <- :public_key.pem_decode(ca_pem), do: der

    case ca_certs do
      [] -> {:error, :no_ca_certificates}
      certs -> {:ok, certs}
    end
  rescue
    _ -> {:error, :no_ca_certificates}
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

  # In-VM X.509 path validation (RFC 5280) via :public_key, replacing the
  # previous shell-out to `openssl verify`: no per-connection process spawn,
  # no certificate material written to tmp, and no substring matching on
  # openssl stdout. Fail-closed: any error rejects the certificate.
  # Public (@doc false) so tests can exercise it directly.
  @doc false
  def verify_against_ca(cert_der, ca_certs) when is_list(ca_certs) do
    case build_validation_path(cert_der, ca_certs) do
      {:ok, anchor_der, path} ->
        case :public_key.pkix_path_validation(anchor_der, path, []) do
          {:ok, _} ->
            true

          {:error, reason} ->
            Logger.warning("Certificate path validation failed: #{inspect(reason)}")
            false
        end

      {:error, reason} ->
        Logger.warning("Certificate path validation failed: #{inspect(reason)}")
        false
    end
  rescue
    e ->
      Logger.error("CA verification error: #{inspect(e)}")
      false
  end

  # Builds the RFC 5280 validation path for a leaf certificate by walking
  # issuer links through the trusted bundle (which may contain a chain, e.g.
  # root + intermediate) until a self-signed trust anchor is reached.
  # Returns {:ok, anchor_der, path} where path is ordered from the certificate
  # issued by the anchor down to the leaf (anchor excluded). Signature
  # correctness is enforced by :public_key.pkix_path_validation/3.
  defp build_validation_path(cert_der, ca_certs) do
    do_build_validation_path(cert_der, ca_certs, [cert_der])
  end

  defp do_build_validation_path(_cert_der, _ca_certs, path)
       when length(path) > @max_cert_chain_length do
    {:error, :certificate_chain_too_long}
  end

  defp do_build_validation_path(cert_der, ca_certs, path) do
    case Enum.find(ca_certs, fn ca_der -> :public_key.pkix_is_issuer(cert_der, ca_der) end) do
      nil ->
        {:error, :issuer_not_in_ca_bundle}

      issuer_der ->
        if :public_key.pkix_is_self_signed(issuer_der) do
          {:ok, issuer_der, path}
        else
          do_build_validation_path(issuer_der, List.delete(ca_certs, issuer_der), [
            issuer_der | path
          ])
        end
    end
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

  defp extract_agent_info(params, organization_id) do
    with true <- is_binary(params["hostname"]) and is_binary(params["os_type"]),
         true <- Registry.canonical_organization_id?(organization_id),
         {:ok, capabilities} <-
           Registry.normalize_runtime_capabilities(params["capabilities"] || []) do
      {:ok,
       %{
         hostname: params["hostname"],
         os_type: params["os_type"],
         os_version: params["os_version"],
         agent_version: params["agent_version"],
         machine_id: params["machine_id"],
         capabilities: capabilities,
         collectors: params["collectors"] || %{},
         organization_id: organization_id
       }}
    else
      false -> {:error, :incomplete_agent_info}
      {:error, reason} -> {:error, reason}
    end
  end

  defp maybe_put_cert_info(agent_info, nil), do: agent_info

  defp maybe_put_cert_info(agent_info, cert_info) do
    agent_info
    |> Map.put(:certificate_fingerprint, cert_info.fingerprint)
    |> Map.put(:certificate_subject, cert_info.subject_dn)
    |> Map.put(:certificate_valid_until, cert_info.valid_until)
  end
end

defmodule TamanduaServerWeb.AgentChannel do
  @moduledoc """
  Channel for handling agent communication.
  """

  use Phoenix.Channel, log_join: false
  require Logger

  alias TamanduaServer.Agents.{Registry, Worker}

  @impl true
  def join("agent:" <> agent_id, payload, socket) do
    if socket.assigns.agent_id === agent_id do
      # Extract agent config from join payload (sent by agent)
      agent_config = Map.get(payload, "config", %{})
      connection_epoch = Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false)
      socket = assign(socket, :connection_epoch, connection_epoch)

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
    with {:ok, socket} <- ensure_worker(socket),
         {:ok, runtime} <- normalize_runtime_heartbeat(payload, socket.assigns.agent_id),
         :ok <- publish_runtime_heartbeat(socket, runtime) do
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
          "AgentChannel: heartbeat rejected for #{socket.assigns.agent_id}: #{inspect(reason)}"
        )

        {:reply, {:error, %{reason: heartbeat_error(reason)}}, socket}
    end
  end

  defp normalize_runtime_heartbeat(payload, agent_id) when is_map(payload) do
    with {:ok, capabilities} <- heartbeat_capabilities(payload, agent_id),
         {:ok, broker} <- normalize_screen_session_broker_health(payload["screen_session_broker"]) do
      {:ok, %{capabilities: capabilities, screen_session_broker: broker}}
    end
  end

  defp normalize_runtime_heartbeat(_, _), do: {:error, :invalid_runtime_snapshot}

  defp heartbeat_capabilities(payload, agent_id) do
    if Map.has_key?(payload, "capabilities") do
      Registry.normalize_runtime_capabilities(payload["capabilities"])
    else
      case Registry.get(agent_id) do
        {:ok, runtime} -> Registry.normalize_runtime_capabilities(runtime[:capabilities] || [])
        _ -> {:error, :not_found}
      end
    end
  end

  defp normalize_screen_session_broker_health(nil), do: {:ok, nil}

  defp normalize_screen_session_broker_health(report) when is_map(report) do
    with {:ok, capabilities} <-
           Registry.normalize_runtime_capabilities(report["capabilities"] || []),
         {:ok, algorithms} <-
           Registry.normalize_policy_hash_algorithms(report["policy_hash_algorithms"]) do
      normalized =
        report
        |> Map.take(
          ~w(schema_version platform state ready observed_at transport consent_model detail detail_code degraded_reason unsupported_reason silent_supported session_capture_supported session_id)
        )
        |> Map.put("capabilities", capabilities)
        |> Map.put("policy_hash_algorithms", algorithms)
        |> Map.put("displays", normalize_screen_session_broker_displays(report["displays"]))

      {:ok, normalized}
    end
  end

  defp normalize_screen_session_broker_health(_report),
    do: {:error, :invalid_screen_session_broker}

  defp publish_runtime_heartbeat(socket, runtime) do
    organization_id = socket.assigns.agent_info[:organization_id]

    Registry.update_runtime_snapshot(
      socket.assigns.agent_id,
      organization_id,
      self(),
      socket.assigns.worker_pid,
      socket.assigns.connection_epoch,
      runtime
    )
  end

  defp heartbeat_error(reason)
       when reason in [
              :invalid_runtime_capabilities,
              :invalid_policy_hash_algorithm,
              :invalid_screen_session_broker,
              :invalid_runtime_snapshot
            ],
       do: "invalid_runtime_evidence"

  defp heartbeat_error(:runtime_tenant_mismatch), do: "runtime_tenant_mismatch"
  defp heartbeat_error(:stale_runtime_connection), do: "stale_runtime_connection"
  defp heartbeat_error(_), do: "worker_unavailable"

  defp normalize_screen_session_broker_displays(displays) when is_list(displays) do
    displays
    |> Enum.reduce([], fn display, acc ->
      if is_map(display) do
        normalized = Map.take(display, ~w(id x y width height primary))
        id = normalized["id"]
        width = normalized["width"]
        height = normalized["height"]

        if is_binary(id) and byte_size(id) in 1..128 and is_integer(normalized["x"]) and
             is_integer(normalized["y"]) and is_integer(width) and width in 1..32_768 and
             is_integer(height) and height in 1..32_768 and is_boolean(normalized["primary"]) do
          [normalized | acc]
        else
          acc
        end
      else
        acc
      end
    end)
    |> Enum.reverse()
    |> Enum.take(16)
  end

  defp normalize_screen_session_broker_displays(_displays), do: []

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

  # Upper bound on a single binary sample: 50MB decoded. Base64 inflates by
  # ~4/3, so the encoded payload is size-checked before decoding to avoid
  # allocating for oversized agent-controlled input.
  @max_binary_sample_decoded_bytes 50 * 1024 * 1024
  @max_binary_sample_encoded_bytes div(@max_binary_sample_decoded_bytes * 4, 3)

  @impl true
  def handle_in("binary_sample", payload, socket) do
    case build_binary_sample(payload, socket.assigns.agent_id) do
      {:ok, sample} ->
        # Push to ML pipeline
        TamanduaServer.Telemetry.Ingestor.push_binary_sample(sample)

        {:reply, {:ok, %{status: "processing"}}, socket}

      {:error, reason} ->
        Logger.warning(
          "AgentChannel: rejected binary_sample from #{socket.assigns.agent_id}: #{reason}"
        )

        {:reply, {:error, %{reason: reason}}, socket}
    end
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
      |> Enum.map(fn event ->
        event["event_id"] || event[:event_id] || event["id"] || event[:id]
      end)
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
    case debug_agent_id() do
      nil -> false
      debug_id -> to_string(agent_id) == debug_id
    end
  end

  # Resolves the agent id used to scope verbose lab/debug logging. Reads the
  # TAMANDUA_DEBUG_AGENT_ID env var first, then the :debug_agent_id app config.
  # Returns nil when unset (debug logging disabled); there is deliberately no
  # baked-in fallback id. Public (@doc false) so tests can exercise it.
  @doc false
  def debug_agent_id do
    normalize_debug_agent_id(System.get_env("TAMANDUA_DEBUG_AGENT_ID")) ||
      normalize_debug_agent_id(Application.get_env(:tamandua_server, :debug_agent_id))
  end

  defp normalize_debug_agent_id(value) when is_binary(value) and value != "", do: value
  defp normalize_debug_agent_id(_), do: nil

  # Validates and decodes an agent-submitted binary sample. Agent input is
  # untrusted even post-auth: malformed base64 must not crash the channel
  # (Base.decode64!/1 raises) and oversized content must be rejected before
  # decoding.
  defp build_binary_sample(payload, agent_id) do
    encoded_sha256 = payload["sha256"]
    encoded_content = payload["content"]

    cond do
      not is_binary(encoded_sha256) or not is_binary(encoded_content) ->
        {:error, "invalid_payload"}

      byte_size(encoded_content) > @max_binary_sample_encoded_bytes ->
        {:error, "sample_too_large"}

      true ->
        with {:ok, sha256} <- Base.decode64(encoded_sha256),
             {:ok, content} <- Base.decode64(encoded_content) do
          {:ok,
           %{
             agent_id: agent_id,
             file_path: payload["file_path"],
             sha256: sha256,
             content: content,
             total_size: payload["total_size"],
             entropy: payload["entropy"],
             file_type: payload["file_type"]
           }}
        else
          :error -> {:error, "invalid_payload"}
        end
    end
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
      |> Map.put(:socket_pid, socket_pid)
      |> Map.put(:connection_epoch, socket.assigns.connection_epoch)
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
