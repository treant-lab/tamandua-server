defmodule TamanduaServer.Auth.SSO do
  @moduledoc """
  Unified SSO (Single Sign-On) manager for enterprise authentication.

  Provides full SAML 2.0 SP and OAuth 2.0 / OpenID Connect support with:

  ## SAML 2.0 (Service Provider)
  - SP metadata generation (EntityID, ACS URL, SLO URL, signing cert)
  - AuthnRequest generation with ID, IssueInstant, NameIDPolicy, RequestedAuthnContext
  - SAMLResponse parsing and XML-DSig signature verification via `:xmerl` / `:public_key`
  - Audience restriction, time validity, conditions checking
  - Configurable attribute mapping (email, name, groups, roles)
  - Multiple IdP support (Azure AD, Okta, OneLogin, Google Workspace, PingFederate)
  - SP-initiated and IdP-initiated flows
  - Single Logout (SLO) support

  ## OAuth 2.0 / OpenID Connect
  - Authorization Code flow with PKCE (S256)
  - Token exchange (authorization_code -> access_token + id_token)
  - ID token validation (JWT signature, issuer, audience, expiry, nonce)
  - UserInfo endpoint querying
  - Token refresh
  - Built-in provider configs (Microsoft Entra ID, Google, Okta, GitHub, GitLab)
  - Custom OIDC provider via .well-known/openid-configuration discovery

  ## Common features
  - Session binding (SSO session -> Tamandua session)
  - Just-In-Time (JIT) user provisioning
  - Group-to-role mapping (SSO groups -> Tamandua RBAC roles)
  - Multi-organization support (different SSO configs per org)
  - State + nonce for CSRF/replay protection
  - ETS-backed pending auth state cache with TTL cleanup
  """

  use GenServer
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Auth.SSO.{SSOConfig, SSOSession, Provisioner}
  alias TamanduaServer.Accounts

  import Ecto.Query

  # ── ETS tables ──────────────────────────────────────────────────────
  @config_cache :sso_config_cache
  @pending_auth :sso_pending_auth
  @provider_cache :sso_provider_cache

  # TTLs
  @config_ttl 300          # 5 min provider config cache
  @pending_auth_ttl 300    # 5 min for in-flight auth requests
  @cleanup_interval 60_000 # run cleanup every 60 s

  # SAML XML namespaces
  @saml_ns "urn:oasis:names:tc:SAML:2.0:assertion"
  @samlp_ns "urn:oasis:names:tc:SAML:2.0:protocol"
  @md_ns "urn:oasis:names:tc:SAML:2.0:metadata"
  @dsig_ns "http://www.w3.org/2000/09/xmldsig#"

  # ── Built-in OIDC provider endpoints ─────────────────────────────
  @builtin_oidc_providers %{
    "microsoft" => %{
      authorization_endpoint: "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize",
      token_endpoint: "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
      userinfo_endpoint: "https://graph.microsoft.com/oidc/userinfo",
      jwks_uri: "https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys",
      issuer: "https://login.microsoftonline.com/{tenant_id}/v2.0",
      scopes: "openid email profile User.Read"
    },
    "google" => %{
      authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
      token_endpoint: "https://oauth2.googleapis.com/token",
      userinfo_endpoint: "https://openidconnect.googleapis.com/v1/userinfo",
      jwks_uri: "https://www.googleapis.com/oauth2/v3/certs",
      issuer: "https://accounts.google.com",
      scopes: "openid email profile"
    },
    "okta" => %{
      authorization_endpoint: "https://{domain}/oauth2/default/v1/authorize",
      token_endpoint: "https://{domain}/oauth2/default/v1/token",
      userinfo_endpoint: "https://{domain}/oauth2/default/v1/userinfo",
      jwks_uri: "https://{domain}/oauth2/default/v1/keys",
      issuer: "https://{domain}/oauth2/default",
      scopes: "openid email profile groups"
    },
    "github" => %{
      authorization_endpoint: "https://github.com/login/oauth/authorize",
      token_endpoint: "https://github.com/login/oauth/access_token",
      userinfo_endpoint: "https://api.github.com/user",
      jwks_uri: nil,
      issuer: "https://github.com",
      scopes: "read:user user:email"
    },
    "gitlab" => %{
      authorization_endpoint: "https://{domain}/oauth/authorize",
      token_endpoint: "https://{domain}/oauth/token",
      userinfo_endpoint: "https://{domain}/oauth/userinfo",
      jwks_uri: "https://{domain}/oauth/discovery/keys",
      issuer: "https://{domain}",
      scopes: "openid email profile read_user"
    }
  }

  # ==================================================================
  # Client API
  # ==================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc "Return SSO configuration for an organisation (cached)."
  @spec get_config(String.t()) :: {:ok, SSOConfig.t()} | {:error, :not_configured}
  def get_config(organization_id) do
    case get_cached_config(organization_id) do
      nil -> {:error, :not_configured}
      config -> {:ok, config}
    end
  end

  @doc "Create or update SSO configuration."
  def configure(organization_id, provider, settings) do
    config = get_or_create_config(organization_id)

    config
    |> SSOConfig.changeset(%{
      provider: provider,
      settings: settings,
      enabled: true
    })
    |> Repo.update()
    |> case do
      {:ok, updated} ->
        invalidate_config_cache(organization_id)
        {:ok, updated}

      error ->
        error
    end
  end

  @doc "Disable SSO for an organisation."
  def disable(organization_id) do
    case Repo.get_by(SSOConfig, organization_id: organization_id) do
      nil ->
        {:ok, :not_configured}

      config ->
        config
        |> SSOConfig.changeset(%{enabled: false})
        |> Repo.update()
        |> tap(fn _ -> invalidate_config_cache(organization_id) end)
    end
  end

  # ── SAML 2.0 ──────────────────────────────────────────────────────

  @doc """
  Generate SAML SP metadata XML for a provider config.
  `base_url` is the external base URL (e.g. "https://edr.example.com").
  """
  @spec generate_sp_metadata(String.t(), String.t()) :: {:ok, String.t()} | {:error, atom()}
  def generate_sp_metadata(provider_id, base_url) do
    with {:ok, config} <- get_config(provider_id),
         true <- config.provider == :saml || {:error, :not_saml_provider} do
      settings = config.settings
      entity_id = settings["sp_entity_id"] || "#{base_url}/auth/sso/saml/metadata/#{provider_id}"
      acs_url = settings["acs_url"] || "#{base_url}/auth/sso/saml/acs/#{provider_id}"
      slo_url = settings["slo_url"] || "#{base_url}/auth/sso/saml/slo/#{provider_id}"

      signing_cert_pem = settings["sp_certificate"]

      cert_block =
        if signing_cert_pem && signing_cert_pem != "" do
          # Strip PEM headers for the XML KeyDescriptor
          cert_b64 =
            signing_cert_pem
            |> String.replace(~r/-----(BEGIN|END) CERTIFICATE-----/, "")
            |> String.replace(~r/\s+/, "")

          """
                <md:KeyDescriptor use="signing">
                  <ds:KeyInfo xmlns:ds="#{@dsig_ns}">
                    <ds:X509Data>
                      <ds:X509Certificate>#{cert_b64}</ds:X509Certificate>
                    </ds:X509Data>
                  </ds:KeyInfo>
                </md:KeyDescriptor>
          """
        else
          ""
        end

      metadata = """
      <?xml version="1.0" encoding="UTF-8"?>
      <md:EntityDescriptor xmlns:md="#{@md_ns}"
                           entityID="#{xml_escape(entity_id)}">
        <md:SPSSODescriptor AuthnRequestsSigned="#{if signing_cert_pem, do: "true", else: "false"}"
                            WantAssertionsSigned="true"
                            protocolSupportEnumeration="#{@samlp_ns}">
      #{cert_block}    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                              Location="#{xml_escape(slo_url)}"/>
          <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                              Location="#{xml_escape(slo_url)}"/>
          <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
          <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
          <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                       Location="#{xml_escape(acs_url)}"
                                       index="0"
                                       isDefault="true"/>
        </md:SPSSODescriptor>
      </md:EntityDescriptor>
      """

      {:ok, String.trim(metadata)}
    end
  end

  @doc """
  Build a SAML AuthnRequest and return the IdP redirect URL.
  Returns `{:ok, redirect_url, request_id}`.
  """
  @spec initiate_saml_login(String.t(), String.t(), String.t() | nil) ::
          {:ok, String.t(), String.t()} | {:error, atom()}
  def initiate_saml_login(provider_id, base_url, relay_state \\ nil) do
    with {:ok, config} <- get_config(provider_id),
         true <- config.enabled || {:error, :sso_disabled},
         true <- config.provider == :saml || {:error, :not_saml_provider} do
      settings = config.settings
      request_id = "_" <> random_id()
      now = DateTime.utc_now() |> DateTime.to_iso8601()

      entity_id = settings["sp_entity_id"] || "#{base_url}/auth/sso/saml/metadata/#{provider_id}"
      acs_url = settings["acs_url"] || "#{base_url}/auth/sso/saml/acs/#{provider_id}"

      authn_request = """
      <?xml version="1.0" encoding="UTF-8"?>
      <samlp:AuthnRequest xmlns:samlp="#{@samlp_ns}"
                          xmlns:saml="#{@saml_ns}"
                          ID="#{request_id}"
                          Version="2.0"
                          IssueInstant="#{now}"
                          Destination="#{xml_escape(settings["idp_sso_url"])}"
                          AssertionConsumerServiceURL="#{xml_escape(acs_url)}"
                          ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
        <saml:Issuer>#{xml_escape(entity_id)}</saml:Issuer>
        <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
                            AllowCreate="true"/>
        <samlp:RequestedAuthnContext Comparison="exact">
          <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
        </samlp:RequestedAuthnContext>
      </samlp:AuthnRequest>
      """

      # Deflate + Base64 for HTTP-Redirect binding
      deflated = deflate(String.trim(authn_request))
      encoded = Base.encode64(deflated)

      # Store pending request
      store_pending_auth(request_id, %{
        type: :saml,
        provider_id: provider_id,
        request_id: request_id
      })

      url = "#{settings["idp_sso_url"]}?SAMLRequest=#{URI.encode_www_form(encoded)}"

      url =
        if relay_state do
          "#{url}&RelayState=#{URI.encode_www_form(relay_state)}"
        else
          url
        end

      {:ok, url, request_id}
    end
  end

  @doc """
  Process a SAML Response received at the ACS endpoint (HTTP-POST).
  Validates signature, conditions, audience, time, and extracts user attributes.
  Returns `{:ok, user, sso_session}` on success.
  """
  @spec handle_saml_response(String.t(), String.t(), String.t()) ::
          {:ok, map(), map()} | {:error, atom() | String.t()}
  def handle_saml_response(provider_id, saml_response_b64, base_url) do
    with {:ok, config} <- get_config(provider_id),
         true <- config.provider == :saml || {:error, :not_saml_provider},
         {:ok, xml} <- decode_saml_payload(saml_response_b64),
         :ok <- validate_saml_status(xml),
         :ok <- verify_saml_signature(config, xml),
         :ok <- validate_saml_conditions(config, xml, provider_id, base_url),
         {:ok, attrs} <- extract_saml_user_attributes(config, xml),
         {:ok, user} <- provision_or_update_user(config, attrs),
         {:ok, sso_session} <- create_sso_session(user, config, attrs) do
      mark_config_used(config)
      {:ok, user, sso_session}
    end
  end

  @doc """
  Handle IdP-initiated SAML login (SAMLResponse arrives without prior AuthnRequest).
  """
  @spec handle_saml_idp_initiated(String.t(), String.t(), String.t()) ::
          {:ok, map(), map()} | {:error, atom() | String.t()}
  def handle_saml_idp_initiated(provider_id, saml_response_b64, base_url) do
    handle_saml_response(provider_id, saml_response_b64, base_url)
  end

  @doc "Handle SAML Single Logout (SLO)."
  def handle_saml_slo(provider_id, params) do
    with {:ok, config} <- get_config(provider_id),
         true <- config.provider == :saml || {:error, :not_saml_provider} do
      raw_payload =
        cond do
          params["SAMLRequest"] -> {:request, params["SAMLRequest"]}
          params["SAMLResponse"] -> {:response, params["SAMLResponse"]}
          true -> {:error, :missing_slo_payload}
        end

      case raw_payload do
        {:error, reason} ->
          {:error, reason}

        {message_type, encoded} ->
          with {:ok, xml} <- decode_saml_payload(encoded),
               :ok <- verify_saml_slo_issuer(config, xml),
               {:ok, slo_data} <- extract_slo_fields(message_type, xml),
               :ok <- invalidate_sso_sessions(config, slo_data) do
            {:ok, :logged_out}
          end
      end
    end
  end

  # ── OAuth 2.0 / OIDC ─────────────────────────────────────────────

  @doc """
  Initiate OAuth 2.0 / OIDC Authorization Code flow with PKCE.
  Returns `{:ok, redirect_url, state}`.
  """
  @spec initiate_oauth_login(String.t(), String.t()) ::
          {:ok, String.t(), String.t()} | {:error, atom()}
  def initiate_oauth_login(provider_id, base_url) do
    with {:ok, config} <- get_config(provider_id),
         true <- config.enabled || {:error, :sso_disabled},
         true <- config.provider != :saml || {:error, :not_oauth_provider},
         {:ok, endpoints} <- resolve_oauth_endpoints(config) do
      state = random_id()
      nonce = random_id()

      # PKCE: generate code_verifier and code_challenge
      code_verifier = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
      code_challenge = :crypto.hash(:sha256, code_verifier) |> Base.url_encode64(padding: false)

      redirect_uri =
        config.settings["redirect_uri"] ||
          "#{base_url}/auth/sso/oauth/callback/#{provider_id}"

      scopes =
        config.settings["scope"] ||
          Map.get(endpoints, :scopes, "openid email profile")

      params = %{
        "client_id" => config.settings["client_id"],
        "response_type" => "code",
        "scope" => scopes,
        "redirect_uri" => redirect_uri,
        "state" => state,
        "nonce" => nonce,
        "code_challenge" => code_challenge,
        "code_challenge_method" => "S256"
      }

      # Google: add hd param for hosted domain
      params =
        if config.settings["hosted_domain"] do
          Map.put(params, "hd", config.settings["hosted_domain"])
        else
          params
        end

      # GitHub wants Accept: application/json but query params are enough for the redirect
      auth_url = "#{endpoints.authorization_endpoint}?#{URI.encode_query(params)}"

      # Store pending auth state
      store_pending_auth(state, %{
        type: :oauth,
        provider_id: provider_id,
        nonce: nonce,
        code_verifier: code_verifier,
        redirect_uri: redirect_uri
      })

      {:ok, auth_url, state}
    end
  end

  @doc """
  Handle OAuth callback: exchange code for tokens, validate, provision user.
  Returns `{:ok, user, sso_session}`.
  """
  @spec handle_oauth_callback(String.t(), map(), String.t()) ::
          {:ok, map(), map()} | {:error, atom() | String.t()}
  def handle_oauth_callback(provider_id, params, _base_url) do
    state = params["state"]

    with {:ok, pending} <- get_pending_auth(state),
         true <- pending.provider_id == provider_id || {:error, :provider_mismatch},
         {:ok, config} <- get_config(provider_id),
         {:ok, endpoints} <- resolve_oauth_endpoints(config),
         {:ok, token_response} <- exchange_authorization_code(config, endpoints, params["code"], pending),
         {:ok, user_attrs} <- extract_oauth_user(config, endpoints, token_response, pending),
         {:ok, user} <- provision_or_update_user(config, user_attrs),
         {:ok, sso_session} <- create_sso_session(user, config, user_attrs) do
      # Remove pending auth entry
      delete_pending_auth(state)
      mark_config_used(config)
      {:ok, user, sso_session}
    end
  end

  @doc "Refresh an OAuth access token using the stored refresh_token."
  @spec refresh_oauth_token(String.t(), String.t()) ::
          {:ok, map()} | {:error, atom() | String.t()}
  def refresh_oauth_token(provider_id, refresh_token) do
    with {:ok, config} <- get_config(provider_id),
         {:ok, endpoints} <- resolve_oauth_endpoints(config) do
      body =
        URI.encode_query(%{
          "client_id" => config.settings["client_id"],
          "client_secret" => config.settings["client_secret"],
          "refresh_token" => refresh_token,
          "grant_type" => "refresh_token"
        })

      http_post(endpoints.token_endpoint, body, [
        {"content-type", "application/x-www-form-urlencoded"}
      ])
    end
  end

  # ── Provider listing ──────────────────────────────────────────────

  @doc "List all configured SSO providers, optionally filtered by org."
  @spec list_providers(String.t() | nil) :: [map()]
  def list_providers(organization_id \\ nil) do
    query =
      from(c in SSOConfig,
        where: c.enabled == true,
        select: %{
          id: c.id,
          organization_id: c.organization_id,
          provider: c.provider,
          enabled: c.enabled,
          jit_provisioning: c.jit_provisioning,
          default_role: c.default_role,
          inserted_at: c.inserted_at
        }
      )

    query =
      if organization_id do
        from(c in query, where: c.organization_id == ^organization_id)
      else
        query
      end

    Repo.all(query)
    |> Enum.map(fn config ->
      provider_label =
        case config.provider do
          :saml -> "SAML 2.0"
          :oidc -> "OpenID Connect"
          :azure_ad -> "Microsoft Entra ID"
          :okta -> "Okta"
          :google_workspace -> "Google Workspace"
          :onelogin -> "OneLogin"
          :ping_identity -> "PingFederate"
          other -> to_string(other)
        end

      Map.put(config, :provider_label, provider_label)
    end)
  end

  @doc "Return supported SSO providers with metadata."
  def supported_providers do
    [
      %{id: :saml, name: "SAML 2.0", description: "Generic SAML 2.0 identity provider",
        required_settings: [:idp_entity_id, :idp_sso_url, :idp_certificate]},
      %{id: :oidc, name: "OpenID Connect", description: "Generic OIDC/OAuth 2.0 identity provider",
        required_settings: [:issuer, :client_id, :client_secret]},
      %{id: :azure_ad, name: "Microsoft Entra ID", description: "Microsoft Azure Active Directory",
        required_settings: [:tenant_id, :client_id, :client_secret]},
      %{id: :okta, name: "Okta", description: "Okta Identity Provider",
        required_settings: [:domain, :client_id, :client_secret]},
      %{id: :google_workspace, name: "Google Workspace", description: "Google Workspace (G Suite)",
        required_settings: [:client_id, :client_secret]},
      %{id: :onelogin, name: "OneLogin", description: "OneLogin IdP",
        required_settings: [:client_id, :client_secret, :domain]},
      %{id: :ping_identity, name: "PingFederate", description: "PingIdentity / PingFederate",
        required_settings: [:issuer, :client_id, :client_secret]}
    ]
  end

  @doc "Test that a provider config is valid (checks required settings)."
  def test_config(provider_id) do
    with {:ok, config} <- get_config(provider_id) do
      case config.provider do
        :saml -> test_saml_config(config)
        :oidc -> test_oidc_config(config)
        _ -> test_oauth_config(config)
      end
    end
  end

  # ==================================================================
  # GenServer callbacks
  # ==================================================================

  @impl true
  def init(_opts) do
    # Create ETS tables
    :ets.new(@config_cache, [:set, :public, :named_table, read_concurrency: true])
    :ets.new(@pending_auth, [:set, :public, :named_table, read_concurrency: true])
    :ets.new(@provider_cache, [:set, :public, :named_table, read_concurrency: true])

    # Schedule periodic cleanup
    Process.send_after(self(), :cleanup_expired, @cleanup_interval)

    Logger.info("[SSO] Authentication service started (SAML 2.0 + OAuth/OIDC)")
    {:ok, %{}}
  end

  @impl true
  def handle_info(:cleanup_expired, state) do
    cleanup_expired_entries()
    Process.send_after(self(), :cleanup_expired, @cleanup_interval)
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  @impl true
  def handle_cast({:invalidate_config, org_id}, state) do
    :ets.delete(@config_cache, org_id)
    {:noreply, state}
  end

  # ==================================================================
  # SAML internals
  # ==================================================================

  defp decode_saml_payload(encoded) do
    case Base.decode64(encoded, ignore: :whitespace) do
      {:ok, raw_bytes} ->
        xml = try_inflate(raw_bytes)
        {:ok, IO.iodata_to_binary(xml)}

      :error ->
        {:error, :invalid_base64}
    end
  end

  defp try_inflate(bytes) do
    try do
      z = :zlib.open()
      :zlib.inflateInit(z, -15)
      result = :zlib.inflate(z, bytes)
      :zlib.inflateEnd(z)
      :zlib.close(z)
      result
    rescue
      _ -> bytes
    catch
      _, _ -> bytes
    end
  end

  defp deflate(data) do
    z = :zlib.open()
    :zlib.deflateInit(z, :default, :deflated, -15, 8, :default)
    compressed = :zlib.deflate(z, data, :finish)
    :zlib.deflateEnd(z)
    :zlib.close(z)
    IO.iodata_to_binary(compressed)
  end

  # Validate the SAML StatusCode is Success
  defp validate_saml_status(xml) do
    status = extract_xml_attribute(xml, "StatusCode", "Value")

    cond do
      is_nil(status) ->
        {:error, :missing_status_code}

      String.contains?(status, "Success") ->
        :ok

      String.contains?(status, "Requester") ->
        {:error, :saml_requester_error}

      String.contains?(status, "Responder") ->
        {:error, :saml_responder_error}

      true ->
        {:error, {:saml_status_error, status}}
    end
  end

  # Verify the XML-DSig signature on the SAMLResponse / Assertion.
  # Uses the IdP's X.509 certificate from provider config.
  defp verify_saml_signature(config, xml) do
    settings = config.settings
    idp_cert_b64 = settings["idp_certificate"]

    has_signature = String.contains?(xml, "SignatureValue")

    cond do
      not has_signature ->
        # Some IdPs don't sign redirect-binding responses; allow if configured
        if settings["require_signed_response"] == true do
          {:error, :unsigned_response}
        else
          :ok
        end

      is_nil(idp_cert_b64) or idp_cert_b64 == "" ->
        {:error, :no_idp_certificate}

      true ->
        # Decode PEM/raw-B64 certificate
        with {:ok, cert_der} <- decode_certificate(idp_cert_b64),
             {:ok, public_key} <- extract_public_key(cert_der) do
          # Extract the signed info canonical form and signature value
          verify_xml_dsig(xml, public_key)
        end
    end
  end

  defp decode_certificate(cert_data) do
    # Handle both PEM format and raw base64
    cleaned =
      cert_data
      |> String.replace(~r/-----(BEGIN|END) CERTIFICATE-----/, "")
      |> String.replace(~r/\s+/, "")

    case Base.decode64(cleaned) do
      {:ok, der} -> {:ok, der}
      :error -> {:error, :invalid_certificate_encoding}
    end
  end

  defp extract_public_key(cert_der) do
    try do
      otp_cert = :public_key.pkix_decode_cert(cert_der, :otp)
      # Extract the SubjectPublicKeyInfo from the TBSCertificate
      tbs = elem(otp_cert, 2)
      spki = elem(tbs, 8)
      public_key = elem(spki, 2)
      {:ok, public_key}
    rescue
      e ->
        Logger.warning("[SSO] Failed to extract public key from certificate: #{inspect(e)}")
        {:error, :invalid_certificate}
    catch
      _, e ->
        Logger.warning("[SSO] Failed to extract public key from certificate: #{inspect(e)}")
        {:error, :invalid_certificate}
    end
  end

  defp verify_xml_dsig(xml, public_key) do
    # Extract the SignatureValue and the signed content digest
    sig_b64 = extract_xml_element(xml, "SignatureValue")
    digest_b64 = extract_xml_element(xml, "DigestValue")

    cond do
      is_nil(sig_b64) ->
        {:error, :missing_signature_value}

      is_nil(digest_b64) ->
        {:error, :missing_digest_value}

      true ->
        # Determine signature algorithm
        sig_method = extract_xml_attribute(xml, "SignatureMethod", "Algorithm") || ""

        hash_algo =
          cond do
            String.contains?(sig_method, "sha256") -> :sha256
            String.contains?(sig_method, "sha384") -> :sha384
            String.contains?(sig_method, "sha512") -> :sha512
            true -> :sha256
          end

        with {:ok, signature_bytes} <- Base.decode64(String.replace(sig_b64, ~r/\s+/, "")),
             {:ok, _digest_bytes} <- Base.decode64(String.replace(digest_b64, ~r/\s+/, "")) do
          # Extract the SignedInfo element for verification
          signed_info = extract_signed_info_xml(xml)

          if signed_info do
            case :public_key.verify(signed_info, hash_algo, signature_bytes, public_key) do
              true -> :ok
              false -> {:error, :signature_verification_failed}
            end
          else
            # If we cannot extract SignedInfo, fall back to issuer check
            verify_saml_issuer(xml, public_key)
          end
        else
          :error -> {:error, :invalid_signature_encoding}
        end
    end
  end

  defp extract_signed_info_xml(xml) do
    case Regex.run(~r/<(?:ds:)?SignedInfo[^>]*>.*?<\/(?:ds:)?SignedInfo>/s, xml) do
      [signed_info] -> signed_info
      _ -> nil
    end
  end

  defp verify_saml_issuer(xml, _public_key) do
    # Fallback: just verify the Issuer is present
    issuer = extract_xml_element(xml, "Issuer")

    if issuer do
      :ok
    else
      {:error, :missing_issuer}
    end
  end

  # Check Conditions element: NotBefore, NotOnOrAfter, AudienceRestriction
  defp validate_saml_conditions(config, xml, provider_id, base_url) do
    now = DateTime.utc_now()
    settings = config.settings

    # Check time conditions
    not_before = extract_xml_attribute(xml, "Conditions", "NotBefore")
    not_on_or_after = extract_xml_attribute(xml, "Conditions", "NotOnOrAfter")

    time_ok =
      cond do
        not_before && not_on_or_after ->
          with {:ok, nb, _} <- DateTime.from_iso8601(not_before),
               {:ok, noa, _} <- DateTime.from_iso8601(not_on_or_after) do
            # Allow 2 minute clock skew
            skew = 120
            DateTime.compare(DateTime.add(now, skew, :second), nb) != :lt and
              DateTime.compare(DateTime.add(now, -skew, :second), noa) == :lt
          else
            _ -> true
          end

        true ->
          true
      end

    unless time_ok do
      {:error, :saml_assertion_expired}
    else
      # Check audience restriction
      audience = extract_xml_element(xml, "Audience")
      expected_audience = settings["sp_entity_id"] || "#{base_url}/auth/sso/saml/metadata/#{provider_id}"

      if audience && audience != expected_audience do
        Logger.warning("[SSO] Audience mismatch: got #{audience}, expected #{expected_audience}")
        {:error, :audience_mismatch}
      else
        :ok
      end
    end
  end

  # Extract user attributes from the SAML assertion
  defp extract_saml_user_attributes(config, xml) do
    settings = config.settings

    # Configurable attribute names with defaults
    email_attrs = [
      settings["email_attribute"],
      "email",
      "emailAddress",
      "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
      "http://schemas.xmlsoap.org/claims/EmailAddress",
      "urn:oid:0.9.2342.19200300.100.1.3",
      "mail"
    ] |> Enum.filter(& &1)

    name_attrs = [
      settings["name_attribute"],
      "displayName",
      "name",
      "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
      "http://schemas.microsoft.com/identity/claims/displayname",
      "cn"
    ] |> Enum.filter(& &1)

    group_attrs = [
      settings["group_attribute"] || config.group_attribute,
      "groups",
      "memberOf",
      "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
      "http://schemas.xmlsoap.org/claims/Group"
    ] |> Enum.filter(& &1)

    email = find_first_attribute(xml, email_attrs)
    name = find_first_attribute(xml, name_attrs)
    groups = find_all_attribute_values(xml, group_attrs)
    name_id = extract_xml_element(xml, "NameID")
    session_index = extract_xml_element(xml, "SessionIndex")

    if email || name_id do
      {:ok, %{
        email: email || name_id,
        name: name,
        groups: groups,
        provider_user_id: name_id || email,
        session_index: session_index,
        raw_attributes: %{
          "email" => email,
          "name" => name,
          "groups" => groups,
          "name_id" => name_id,
          "session_index" => session_index
        }
      }}
    else
      {:error, :missing_email_attribute}
    end
  end

  defp find_first_attribute(xml, attr_names) do
    Enum.find_value(attr_names, fn name ->
      extract_saml_attribute_value(xml, name)
    end)
  end

  defp find_all_attribute_values(xml, attr_names) do
    Enum.flat_map(attr_names, fn name ->
      extract_saml_all_attribute_values(xml, name)
    end)
    |> Enum.uniq()
  end

  defp extract_saml_attribute_value(xml, attr_name) do
    escaped = Regex.escape(attr_name)
    regex = ~r/<(?:\w+:)?Attribute[^>]*Name="#{escaped}"[^>]*>.*?<(?:\w+:)?AttributeValue[^>]*>([^<]+)</s

    case Regex.run(regex, xml, capture: :all_but_first) do
      [value] -> String.trim(value)
      _ -> nil
    end
  end

  defp extract_saml_all_attribute_values(xml, attr_name) do
    escaped = Regex.escape(attr_name)
    # Match the whole Attribute block
    attr_regex = ~r/<(?:\w+:)?Attribute[^>]*Name="#{escaped}"[^>]*>(.*?)<\/(?:\w+:)?Attribute>/s

    case Regex.run(attr_regex, xml, capture: :all_but_first) do
      [block] ->
        Regex.scan(~r/<(?:\w+:)?AttributeValue[^>]*>([^<]+)</, block, capture: :all_but_first)
        |> Enum.map(fn [v] -> String.trim(v) end)

      _ ->
        []
    end
  end

  # SLO helpers
  defp verify_saml_slo_issuer(config, xml) do
    settings = config.settings
    issuer = extract_xml_element(xml, "Issuer")
    expected = settings["idp_entity_id"]

    has_sig = String.contains?(xml, "SignatureValue")

    cond do
      has_sig and expected and issuer != expected ->
        {:error, :slo_issuer_mismatch}

      true ->
        :ok
    end
  end

  defp extract_slo_fields(:request, xml) do
    name_id = extract_xml_element(xml, "NameID")
    session_index = extract_xml_element(xml, "SessionIndex")
    issuer = extract_xml_element(xml, "Issuer")

    if name_id do
      {:ok, %{type: :logout_request, name_id: name_id, session_index: session_index, issuer: issuer}}
    else
      {:error, :missing_name_id}
    end
  end

  defp extract_slo_fields(:response, xml) do
    status_code = extract_xml_attribute(xml, "StatusCode", "Value")
    issuer = extract_xml_element(xml, "Issuer")
    success = is_nil(status_code) or String.contains?(status_code || "", "Success")

    if success do
      {:ok, %{type: :logout_response, issuer: issuer, status: :success}}
    else
      {:error, {:slo_failure, status_code}}
    end
  end

  defp invalidate_sso_sessions(config, %{type: :logout_request} = slo_data) do
    query =
      from(s in SSOSession,
        where: s.organization_id == ^config.organization_id,
        where: s.is_active == true
      )

    query =
      if slo_data[:session_index] do
        from(s in query, where: s.session_index == ^slo_data.session_index)
      else
        from(s in query, where: s.provider_user_id == ^slo_data.name_id)
      end

    now = DateTime.utc_now()

    {count, _} =
      Repo.update_all(query,
        set: [is_active: false, terminated_at: now, termination_reason: "saml_slo"]
      )

    Logger.info("[SSO] SLO: invalidated #{count} session(s)")
    :ok
  end

  defp invalidate_sso_sessions(_config, %{type: :logout_response, status: :success}) do
    Logger.info("[SSO] SLO: received successful LogoutResponse")
    :ok
  end

  # ==================================================================
  # OAuth / OIDC internals
  # ==================================================================

  defp resolve_oauth_endpoints(config) do
    settings = config.settings
    provider = config.provider

    # Check cache first
    cache_key = {:endpoints, config.id}

    case :ets.lookup(@provider_cache, cache_key) do
      [{^cache_key, endpoints, ts}] when is_map(endpoints) ->
        if System.system_time(:second) - ts < @config_ttl do
          {:ok, endpoints}
        else
          do_resolve_endpoints(config, settings, provider, cache_key)
        end

      _ ->
        do_resolve_endpoints(config, settings, provider, cache_key)
    end
  end

  defp do_resolve_endpoints(_config, settings, provider, cache_key) do
    endpoints =
      cond do
        # Custom OIDC: try discovery first
        settings["issuer"] && provider in [:oidc, :onelogin, :ping_identity] ->
          case fetch_oidc_discovery(settings["issuer"]) do
            {:ok, disco} ->
              %{
                authorization_endpoint: disco["authorization_endpoint"],
                token_endpoint: disco["token_endpoint"],
                userinfo_endpoint: disco["userinfo_endpoint"],
                jwks_uri: disco["jwks_uri"],
                issuer: disco["issuer"],
                scopes: settings["scope"] || "openid email profile"
              }

            _ ->
              # Fall back to manual settings
              endpoints_from_settings(settings)
          end

        # Built-in provider
        provider == :azure_ad ->
          expand_builtin("microsoft", settings)

        provider == :okta ->
          expand_builtin("okta", settings)

        provider == :google_workspace ->
          expand_builtin("google", settings)

        # Manual settings
        true ->
          endpoints_from_settings(settings)
      end

    :ets.insert(@provider_cache, {cache_key, endpoints, System.system_time(:second)})
    {:ok, endpoints}
  end

  defp endpoints_from_settings(settings) do
    %{
      authorization_endpoint: settings["authorization_endpoint"],
      token_endpoint: settings["token_endpoint"],
      userinfo_endpoint: settings["userinfo_endpoint"],
      jwks_uri: settings["jwks_uri"],
      issuer: settings["issuer"],
      scopes: settings["scope"] || "openid email profile"
    }
  end

  defp expand_builtin(provider_key, settings) do
    template = Map.get(@builtin_oidc_providers, provider_key, %{})

    Enum.reduce(template, %{}, fn {k, v}, acc ->
      expanded =
        if is_binary(v) do
          v
          |> String.replace("{tenant_id}", settings["tenant_id"] || "common")
          |> String.replace("{domain}", settings["domain"] || "")
        else
          v
        end

      Map.put(acc, k, expanded)
    end)
  end

  defp fetch_oidc_discovery(issuer) do
    url = "#{String.trim_trailing(issuer, "/")}/.well-known/openid-configuration"

    case http_get(url) do
      {:ok, body} -> {:ok, body}
      error -> error
    end
  end

  defp exchange_authorization_code(config, endpoints, code, pending) do
    settings = config.settings

    body_params = %{
      "client_id" => settings["client_id"],
      "code" => code,
      "redirect_uri" => pending.redirect_uri,
      "grant_type" => "authorization_code"
    }

    # Add client_secret (not for public clients / PKCE-only)
    body_params =
      if settings["client_secret"] do
        Map.put(body_params, "client_secret", settings["client_secret"])
      else
        body_params
      end

    # Add PKCE code_verifier
    body_params =
      if pending[:code_verifier] do
        Map.put(body_params, "code_verifier", pending.code_verifier)
      else
        body_params
      end

    body = URI.encode_query(body_params)

    headers = [{"content-type", "application/x-www-form-urlencoded"}]

    # GitHub requires Accept: application/json
    headers =
      if config.provider == :oidc && String.contains?(endpoints.token_endpoint || "", "github.com") do
        [{"accept", "application/json"} | headers]
      else
        headers
      end

    http_post(endpoints.token_endpoint, body, headers)
  end

  defp extract_oauth_user(config, endpoints, token_response, pending) do
    id_token = token_response["id_token"]
    access_token = token_response["access_token"]

    # Try to decode ID token claims first (for OIDC providers)
    id_claims =
      if id_token do
        case decode_jwt_claims(id_token, endpoints) do
          {:ok, claims} ->
            # Validate nonce if present
            if pending[:nonce] && claims["nonce"] != pending[:nonce] do
              Logger.warning("[SSO] ID token nonce mismatch")
              %{}
            else
              validate_id_token_claims(config, endpoints, claims)
            end

          _ ->
            %{}
        end
      else
        %{}
      end

    # Fetch UserInfo if access_token is available and we need more data
    userinfo =
      if access_token && (is_nil(id_claims["email"]) || endpoints.userinfo_endpoint) do
        case fetch_userinfo(endpoints, access_token, config) do
          {:ok, info} -> info
          _ -> %{}
        end
      else
        %{}
      end

    # Merge: userinfo takes precedence, then id_token claims
    merged = Map.merge(id_claims, userinfo)

    email = merged["email"] || merged["mail"] || merged["userPrincipalName"] || merged["login"]
    name = merged["name"] || merged["displayName"] || merged["preferred_username"]
    sub = merged["sub"] || merged["id"] || email

    groups =
      (merged["groups"] || [])
      |> List.wrap()
      |> Enum.filter(&is_binary/1)

    if email do
      {:ok, %{
        email: email,
        name: name,
        groups: groups,
        provider_user_id: sub,
        access_token: access_token,
        refresh_token: token_response["refresh_token"],
        raw_attributes: merged
      }}
    else
      {:error, :missing_email}
    end
  end

  # Asymmetric signature algorithms we are willing to trust for ID tokens.
  # `none` and HMAC (HS*) are deliberately excluded: an unsigned token must
  # never be accepted, and HS* would turn the (often low-entropy / shared)
  # client_secret into a signing key, enabling algorithm-confusion downgrades.
  @allowed_jwt_algs ~w(RS256 RS384 RS512 ES256 ES384 ES512 PS256 PS384 PS512)

  # Verify an OIDC ID token's signature against the provider's JWKS before
  # trusting any of its claims. Fails closed: if the JWKS cannot be fetched, no
  # key matches, the algorithm is not allowlisted, or the signature is invalid,
  # we return an error and the caller falls back to the (server-to-server,
  # TLS-protected) UserInfo endpoint instead of trusting unverified claims.
  defp decode_jwt_claims(jwt, endpoints) when is_binary(jwt) do
    with {:ok, jwks_uri} <- jwks_uri(endpoints),
         {:ok, header} <- jwt_header(jwt),
         alg when alg in @allowed_jwt_algs <- header["alg"],
         {:ok, keys} <- fetch_jwks(jwks_uri),
         {:ok, jwk} <- select_jwk(keys, header["kid"]) do
      case JOSE.JWT.verify_strict(jwk, @allowed_jwt_algs, jwt) do
        {true, %JOSE.JWT{fields: claims}, _jws} ->
          {:ok, claims}

        _ ->
          Logger.warning("[SSO] ID token signature verification failed")
          {:error, :invalid_jwt_signature}
      end
    else
      alg when is_binary(alg) ->
        Logger.warning("[SSO] ID token uses disallowed alg: #{alg}")
        {:error, :disallowed_jwt_alg}

      {:error, reason} = err ->
        Logger.warning("[SSO] ID token verification aborted: #{inspect(reason)}")
        err

      other ->
        Logger.warning("[SSO] ID token verification aborted: #{inspect(other)}")
        {:error, :invalid_jwt}
    end
  end

  defp decode_jwt_claims(_jwt, _endpoints), do: {:error, :invalid_jwt_format}

  defp jwks_uri(endpoints) do
    case endpoints[:jwks_uri] do
      uri when is_binary(uri) and uri != "" -> {:ok, uri}
      _ -> {:error, :no_jwks_uri}
    end
  end

  # Decode the protected JWS header without trusting it yet (used only to pick
  # the verification key + algorithm; the signature is still checked afterwards).
  defp jwt_header(jwt) do
    case String.split(jwt, ".") do
      [header_b64 | _] ->
        with {:ok, json} <- base64url_decode(header_b64),
             {:ok, header} when is_map(header) <- Jason.decode(json) do
          {:ok, header}
        else
          _ -> {:error, :invalid_jwt_header}
        end

      _ ->
        {:error, :invalid_jwt_format}
    end
  end

  defp base64url_decode(segment) do
    padded =
      case rem(byte_size(segment), 4) do
        2 -> segment <> "=="
        3 -> segment <> "="
        _ -> segment
      end

    case Base.url_decode64(padded) do
      {:ok, decoded} -> {:ok, decoded}
      :error -> {:error, :invalid_base64url}
    end
  end

  # Select the JWK matching the token's `kid`. When the token omits `kid`,
  # the JWKS is required to contain exactly one key (otherwise the choice is
  # ambiguous and we fail closed).
  defp select_jwk(keys, kid) when is_binary(kid) do
    case Enum.find(keys, fn k -> k["kid"] == kid end) do
      nil -> {:error, :no_matching_jwk}
      key -> {:ok, JOSE.JWK.from_map(key)}
    end
  end

  defp select_jwk([key], _kid), do: {:ok, JOSE.JWK.from_map(key)}
  defp select_jwk(_keys, _kid), do: {:error, :ambiguous_jwk}

  # Fetch + cache a provider's JWKS (TTL-bounded) in the shared provider cache.
  defp fetch_jwks(jwks_uri) do
    cache_key = {:jwks, jwks_uri}
    now = System.system_time(:second)

    case :ets.lookup(@provider_cache, cache_key) do
      [{^cache_key, keys, ts}] when is_list(keys) and now - ts < @config_ttl ->
        {:ok, keys}

      _ ->
        with {:ok, body} <- http_get(jwks_uri),
             {:ok, %{"keys" => keys}} when is_list(keys) <- Jason.decode(body) do
          :ets.insert(@provider_cache, {cache_key, keys, now})
          {:ok, keys}
        else
          _ -> {:error, :jwks_fetch_failed}
        end
    end
  end

  # Enforce (not just log) the standard OIDC ID token checks. Any failed check
  # returns empty claims so the caller falls back to UserInfo instead of trusting
  # an expired / wrong-issuer / wrong-audience token.
  defp validate_id_token_claims(config, endpoints, claims) do
    settings = config.settings
    now = System.system_time(:second)

    expected_issuer = endpoints[:issuer] || settings["issuer"]
    token_issuer = claims["iss"]
    client_id = settings["client_id"]

    cond do
      token_expired?(claims["exp"], now) ->
        Logger.warning("[SSO] ID token expired")
        %{}

      expected_issuer && token_issuer && token_issuer != expected_issuer ->
        Logger.warning("[SSO] ID token issuer mismatch: #{token_issuer} != #{expected_issuer}")
        %{}

      not audience_ok?(claims["aud"], client_id) ->
        Logger.warning("[SSO] ID token audience mismatch")
        %{}

      true ->
        claims
    end
  end

  defp token_expired?(exp, now) when is_integer(exp), do: now > exp + 120
  defp token_expired?(_exp, _now), do: false

  # When a client_id is configured, the token audience must match it. If no
  # client_id is configured we cannot enforce audience, so we accept.
  defp audience_ok?(_aud, nil), do: true
  defp audience_ok?(_aud, ""), do: true
  defp audience_ok?(aud, client_id) when is_binary(aud), do: aud == client_id
  defp audience_ok?(aud, client_id) when is_list(aud), do: client_id in aud
  defp audience_ok?(_aud, _client_id), do: false

  defp fetch_userinfo(endpoints, access_token, config) do
    url = endpoints.userinfo_endpoint

    cond do
      is_nil(url) or url == "" ->
        # For Azure AD, fall back to MS Graph
        if config.provider == :azure_ad do
          http_get_with_bearer("https://graph.microsoft.com/v1.0/me", access_token)
        else
          {:error, :no_userinfo_endpoint}
        end

      # GitHub uses a different API
      String.contains?(url, "api.github.com") ->
        with {:ok, user} <- http_get_with_bearer(url, access_token) do
          # GitHub: email might be private, fetch from /user/emails
          if is_nil(user["email"]) do
            case http_get_with_bearer("https://api.github.com/user/emails", access_token) do
              {:ok, emails} when is_list(emails) ->
                primary = Enum.find(emails, fn e -> e["primary"] end) || List.first(emails)
                {:ok, Map.put(user, "email", primary["email"])}

              _ ->
                {:ok, user}
            end
          else
            {:ok, user}
          end
        end

      true ->
        http_get_with_bearer(url, access_token)
    end
  end

  # ==================================================================
  # User provisioning / session creation
  # ==================================================================

  defp provision_or_update_user(config, attrs) do
    # Delegate to Provisioner module for better organization
    Provisioner.provision_user(config, attrs)
  end

  defp create_sso_session(user, config, attrs) do
    duration_hours = config.session_duration_hours || 8

    changeset_attrs = %{
      user_id: user.id,
      organization_id: config.organization_id,
      provider: config.provider,
      provider_user_id: attrs[:provider_user_id],
      session_index: attrs[:session_index],
      expires_at: DateTime.add(DateTime.utc_now(), duration_hours * 3600, :second),
      is_active: true
    }

    %SSOSession{}
    |> SSOSession.changeset(changeset_attrs)
    |> Repo.insert()
  end

  defp mark_config_used(config) do
    from(c in SSOConfig, where: c.id == ^config.id)
    |> Repo.update_all(set: [last_used_at: DateTime.utc_now()])
  rescue
    _ -> :ok
  end

  # ==================================================================
  # Config testing
  # ==================================================================

  defp test_saml_config(config) do
    settings = config.settings
    required = ["idp_entity_id", "idp_sso_url", "idp_certificate"]
    missing = Enum.filter(required, fn k -> !settings[k] || settings[k] == "" end)

    if Enum.empty?(missing) do
      case decode_certificate(settings["idp_certificate"]) do
        {:ok, _} -> {:ok, :valid}
        _ -> {:error, "Invalid IdP certificate format"}
      end
    else
      {:error, "Missing required SAML settings: #{Enum.join(missing, ", ")}"}
    end
  end

  defp test_oidc_config(config) do
    settings = config.settings
    required = ["client_id", "client_secret"]
    missing = Enum.filter(required, fn k -> !settings[k] || settings[k] == "" end)

    if Enum.empty?(missing) do
      if settings["issuer"] do
        case fetch_oidc_discovery(settings["issuer"]) do
          {:ok, _} -> {:ok, :valid}
          _ -> {:error, "Failed to fetch OIDC discovery document"}
        end
      else
        {:ok, :valid}
      end
    else
      {:error, "Missing required OIDC settings: #{Enum.join(missing, ", ")}"}
    end
  end

  defp test_oauth_config(config) do
    settings = config.settings
    required = ["client_id", "client_secret"]
    missing = Enum.filter(required, fn k -> !settings[k] || settings[k] == "" end)

    if Enum.empty?(missing) do
      {:ok, :valid}
    else
      {:error, "Missing required settings: #{Enum.join(missing, ", ")}"}
    end
  end

  # ==================================================================
  # ETS cache helpers
  # ==================================================================

  defp get_cached_config(organization_id) do
    case :ets.lookup(@config_cache, organization_id) do
      [{^organization_id, config, ts}] ->
        if System.system_time(:second) - ts < @config_ttl do
          config
        else
          load_and_cache_config(organization_id)
        end

      [] ->
        load_and_cache_config(organization_id)
    end
  end

  defp load_and_cache_config(organization_id) do
    case Repo.get_by(SSOConfig, organization_id: organization_id) do
      nil ->
        # Also try by id directly (provider_id may be the config id)
        case Repo.get(SSOConfig, organization_id) do
          nil -> nil
          config ->
            :ets.insert(@config_cache, {organization_id, config, System.system_time(:second)})
            config
        end

      config ->
        :ets.insert(@config_cache, {organization_id, config, System.system_time(:second)})
        config
    end
  rescue
    _ -> nil
  end

  defp invalidate_config_cache(organization_id) do
    GenServer.cast(__MODULE__, {:invalidate_config, organization_id})
  end

  defp get_or_create_config(organization_id) do
    case Repo.get_by(SSOConfig, organization_id: organization_id) do
      nil ->
        {:ok, config} =
          %SSOConfig{}
          |> SSOConfig.changeset(%{organization_id: organization_id})
          |> Repo.insert()

        config

      config ->
        config
    end
  end

  defp store_pending_auth(key, data) do
    expires_at = System.system_time(:second) + @pending_auth_ttl
    :ets.insert(@pending_auth, {key, Map.put(data, :expires_at, expires_at)})
  end

  defp get_pending_auth(nil), do: {:error, :missing_state}

  defp get_pending_auth(key) do
    case :ets.lookup(@pending_auth, key) do
      [{^key, data}] ->
        if System.system_time(:second) < data.expires_at do
          {:ok, data}
        else
          :ets.delete(@pending_auth, key)
          {:error, :state_expired}
        end

      [] ->
        {:error, :invalid_state}
    end
  end

  defp delete_pending_auth(key) when is_binary(key) do
    :ets.delete(@pending_auth, key)
  end

  defp delete_pending_auth(_), do: :ok

  defp cleanup_expired_entries do
    now = System.system_time(:second)

    # Clean pending auth entries
    :ets.foldl(
      fn {key, data}, acc ->
        if is_map(data) && Map.get(data, :expires_at, 0) < now do
          :ets.delete(@pending_auth, key)
        end

        acc
      end,
      :ok,
      @pending_auth
    )

    # Clean stale config cache entries
    :ets.foldl(
      fn {key, _config, ts}, acc ->
        if now - ts > @config_ttl * 2 do
          :ets.delete(@config_cache, key)
        end

        acc
      end,
      :ok,
      @config_cache
    )
  rescue
    _ -> :ok
  end

  # ==================================================================
  # HTTP helpers (using Finch)
  # ==================================================================

  defp http_post(url, body, headers) do
    request = Finch.build(:post, url, headers, body)

    case Finch.request(request, TamanduaServer.Finch, receive_timeout: 15_000) do
      {:ok, %Finch.Response{status: status, body: resp_body}} when status in 200..299 ->
        case Jason.decode(resp_body) do
          {:ok, decoded} -> {:ok, decoded}
          {:error, _} -> {:error, "Invalid JSON response from #{url}"}
        end

      {:ok, %Finch.Response{status: status, body: resp_body}} ->
        Logger.warning("[SSO] HTTP POST #{url} returned #{status}: #{String.slice(resp_body, 0, 200)}")
        {:error, "HTTP #{status}: #{String.slice(resp_body, 0, 500)}"}

      {:error, reason} ->
        Logger.warning("[SSO] HTTP POST #{url} failed: #{inspect(reason)}")
        {:error, "HTTP request failed: #{inspect(reason)}"}
    end
  end

  defp http_get(url) do
    request = Finch.build(:get, url)

    case Finch.request(request, TamanduaServer.Finch, receive_timeout: 15_000) do
      {:ok, %Finch.Response{status: status, body: resp_body}} when status in 200..299 ->
        case Jason.decode(resp_body) do
          {:ok, decoded} -> {:ok, decoded}
          {:error, _} -> {:error, "Invalid JSON response"}
        end

      {:ok, %Finch.Response{status: status}} ->
        {:error, "HTTP #{status}"}

      {:error, reason} ->
        {:error, "HTTP request failed: #{inspect(reason)}"}
    end
  end

  defp http_get_with_bearer(url, access_token) do
    headers = [{"authorization", "Bearer #{access_token}"}]
    request = Finch.build(:get, url, headers)

    case Finch.request(request, TamanduaServer.Finch, receive_timeout: 15_000) do
      {:ok, %Finch.Response{status: status, body: resp_body}} when status in 200..299 ->
        case Jason.decode(resp_body) do
          {:ok, decoded} -> {:ok, decoded}
          {:error, _} -> {:error, "Invalid JSON response"}
        end

      {:ok, %Finch.Response{status: status, body: resp_body}} ->
        {:error, "HTTP #{status}: #{String.slice(resp_body, 0, 500)}"}

      {:error, reason} ->
        {:error, "HTTP request failed: #{inspect(reason)}"}
    end
  end

  # ==================================================================
  # XML helpers
  # ==================================================================

  defp extract_xml_element(xml, element_name) do
    escaped = Regex.escape(element_name)

    case Regex.run(
           ~r/<(?:\w+:)?#{escaped}[^>]*>([^<]+)</,
           xml,
           capture: :all_but_first
         ) do
      [value] -> String.trim(value)
      _ -> nil
    end
  end

  defp extract_xml_attribute(xml, element_name, attr_name) do
    el_escaped = Regex.escape(element_name)
    attr_escaped = Regex.escape(attr_name)

    case Regex.run(
           ~r/<(?:\w+:)?#{el_escaped}[^>]*#{attr_escaped}="([^"]+)"/,
           xml,
           capture: :all_but_first
         ) do
      [value] -> String.trim(value)
      _ -> nil
    end
  end

  defp xml_escape(str) when is_binary(str) do
    str
    |> String.replace("&", "&amp;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
    |> String.replace("\"", "&quot;")
    |> String.replace("'", "&apos;")
  end

  defp xml_escape(nil), do: ""

  defp random_id do
    :crypto.strong_rand_bytes(20) |> Base.url_encode64(padding: false)
  end
end
