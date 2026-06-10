defmodule TamanduaServerWeb.Auth.SSOController do
  @moduledoc """
  Phoenix controller for SSO (SAML 2.0 and OAuth 2.0/OIDC) endpoints.

  ## SAML endpoints
  - `GET  /auth/sso/saml/metadata/:provider_id` - SP metadata XML
  - `GET  /auth/sso/saml/login/:provider_id`    - Initiate SAML login
  - `POST /auth/sso/saml/acs/:provider_id`      - Assertion Consumer Service
  - `GET  /auth/sso/saml/slo/:provider_id`      - Single Logout

  ## OAuth / OIDC endpoints
  - `GET /auth/sso/oauth/authorize/:provider_id` - Initiate OAuth flow
  - `GET /auth/sso/oauth/callback/:provider_id`  - OAuth callback

  ## API endpoints
  - `GET /api/v1/sso/providers` - List configured SSO providers
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Auth.SSO
  alias TamanduaServer.AuditLog
  alias TamanduaServerWeb.UserAuth

  require Logger

  # ── SAML endpoints ────────────────────────────────────────────────

  @doc """
  Serve the SAML SP metadata XML document.
  IdPs consume this to configure the trust relationship.
  """
  def saml_metadata(conn, %{"provider_id" => provider_id}) do
    base_url = get_base_url(conn)

    case SSO.generate_sp_metadata(provider_id, base_url) do
      {:ok, metadata_xml} ->
        conn
        |> put_resp_content_type("application/xml")
        |> send_resp(200, metadata_xml)

      {:error, :not_configured} ->
        conn
        |> put_status(404)
        |> json(%{error: "SSO provider not found"})

      {:error, :not_saml_provider} ->
        conn
        |> put_status(400)
        |> json(%{error: "Provider is not configured for SAML"})

      {:error, reason} ->
        Logger.warning("[SSOController] Metadata generation failed: #{inspect(reason)}")

        conn
        |> put_status(500)
        |> json(%{error: "Failed to generate metadata"})
    end
  end

  @doc """
  Initiate SP-initiated SAML login.
  Builds an AuthnRequest and redirects the user to the IdP SSO URL.
  """
  def saml_login(conn, %{"provider_id" => provider_id} = params) do
    base_url = get_base_url(conn)
    relay_state = params["relay_state"] || params["return_to"]

    case SSO.initiate_saml_login(provider_id, base_url, relay_state) do
      {:ok, redirect_url, _request_id} ->
        redirect(conn, external: redirect_url)

      {:error, :not_configured} ->
        conn
        |> put_flash(:error, "SSO provider not found or not configured.")
        |> redirect(to: "/login")

      {:error, :sso_disabled} ->
        conn
        |> put_flash(:error, "SSO is disabled for this provider.")
        |> redirect(to: "/login")

      {:error, :not_saml_provider} ->
        conn
        |> put_flash(:error, "This provider does not use SAML.")
        |> redirect(to: "/login")

      {:error, reason} ->
        Logger.error("[SSOController] SAML login initiation failed: #{inspect(reason)}")

        conn
        |> put_flash(:error, "SSO login failed. Please try again or contact your administrator.")
        |> redirect(to: "/login")
    end
  end

  @doc """
  SAML Assertion Consumer Service (ACS).
  Receives the SAMLResponse via HTTP-POST from the IdP after successful authentication.
  Handles both SP-initiated and IdP-initiated flows.
  """
  def saml_acs(conn, %{"provider_id" => provider_id} = params) do
    saml_response = params["SAMLResponse"]

    if is_nil(saml_response) || saml_response == "" do
      conn
      |> put_flash(:error, "Missing SAML response.")
      |> redirect(to: "/login")
    else
      base_url = get_base_url(conn)

      case SSO.handle_saml_response(provider_id, saml_response, base_url) do
        {:ok, user, _sso_session} ->
          # Log the SSO login
          log_sso_login(conn, user, :saml, provider_id)

          # Create Tamandua session and redirect
          conn
          |> put_flash(:info, "Signed in via SSO.")
          |> UserAuth.log_in_user(user)

        {:error, :not_configured} ->
          conn
          |> put_flash(:error, "SSO provider not found.")
          |> redirect(to: "/login")

        {:error, :missing_email_attribute} ->
          conn
          |> put_flash(:error, "Your identity provider did not return an email address. Please contact your administrator.")
          |> redirect(to: "/login")

        {:error, :audience_mismatch} ->
          conn
          |> put_flash(:error, "SAML assertion audience does not match. Please check your IdP configuration.")
          |> redirect(to: "/login")

        {:error, :saml_assertion_expired} ->
          conn
          |> put_flash(:error, "SAML assertion has expired. Please try signing in again.")
          |> redirect(to: "/login")

        {:error, :signature_verification_failed} ->
          conn
          |> put_flash(:error, "SAML signature verification failed. Please check the IdP certificate configuration.")
          |> redirect(to: "/login")

        {:error, :domain_not_allowed} ->
          conn
          |> put_flash(:error, "Your email domain is not authorized for this organization.")
          |> redirect(to: "/login")

        {:error, :user_not_found_jit_disabled} ->
          conn
          |> put_flash(:error, "Account not found. Automatic account creation is disabled for this organization.")
          |> redirect(to: "/login")

        {:error, :user_belongs_to_different_org} ->
          conn
          |> put_flash(:error, "This account belongs to a different organization.")
          |> redirect(to: "/login")

        {:error, reason} ->
          Logger.error("[SSOController] SAML ACS failed for provider #{provider_id}: #{inspect(reason)}")

          conn
          |> put_flash(:error, "SSO authentication failed. Please try again.")
          |> redirect(to: "/login")
      end
    end
  end

  @doc """
  SAML Single Logout (SLO) endpoint.
  Handles both IdP-initiated LogoutRequest and LogoutResponse.
  """
  def saml_slo(conn, %{"provider_id" => provider_id} = params) do
    case SSO.handle_saml_slo(provider_id, params) do
      {:ok, :logged_out} ->
        # Also log out the local Tamandua session
        if conn.assigns[:current_user] do
          log_sso_logout(conn, conn.assigns.current_user, provider_id)
        end

        conn
        |> put_flash(:info, "You have been signed out via SSO.")
        |> UserAuth.log_out_user()

      {:error, :not_configured} ->
        conn
        |> put_flash(:error, "SSO provider not found.")
        |> redirect(to: "/login")

      {:error, reason} ->
        Logger.warning("[SSOController] SLO failed for provider #{provider_id}: #{inspect(reason)}")

        conn
        |> put_flash(:info, "Signed out.")
        |> redirect(to: "/login")
    end
  end

  # ── OAuth / OIDC endpoints ─────────────────────────────────────────

  @doc """
  Initiate OAuth 2.0 / OIDC Authorization Code flow.
  Generates PKCE challenge, stores state, and redirects to the authorization endpoint.
  """
  def oauth_authorize(conn, %{"provider_id" => provider_id}) do
    base_url = get_base_url(conn)

    case SSO.initiate_oauth_login(provider_id, base_url) do
      {:ok, redirect_url, _state} ->
        redirect(conn, external: redirect_url)

      {:error, :not_configured} ->
        conn
        |> put_flash(:error, "SSO provider not found or not configured.")
        |> redirect(to: "/login")

      {:error, :sso_disabled} ->
        conn
        |> put_flash(:error, "SSO is disabled for this provider.")
        |> redirect(to: "/login")

      {:error, :not_oauth_provider} ->
        conn
        |> put_flash(:error, "This provider uses SAML, not OAuth/OIDC. Use the SAML login endpoint.")
        |> redirect(to: "/login")

      {:error, reason} ->
        Logger.error("[SSOController] OAuth authorize failed: #{inspect(reason)}")

        conn
        |> put_flash(:error, "SSO login failed. Please try again.")
        |> redirect(to: "/login")
    end
  end

  @doc """
  OAuth 2.0 / OIDC callback endpoint.
  Exchanges the authorization code for tokens, validates the ID token,
  fetches user info, provisions the user, and creates a session.
  """
  def oauth_callback(conn, %{"provider_id" => provider_id} = params) do
    # Check for OAuth error response from provider
    if params["error"] do
      error_desc = params["error_description"] || params["error"]
      Logger.warning("[SSOController] OAuth error from provider #{provider_id}: #{error_desc}")

      conn
      |> put_flash(:error, "Authentication failed: #{error_desc}")
      |> redirect(to: "/login")
    else
      base_url = get_base_url(conn)

      case SSO.handle_oauth_callback(provider_id, params, base_url) do
        {:ok, user, _sso_session} ->
          provider_type = detect_provider_type(provider_id)
          log_sso_login(conn, user, provider_type, provider_id)

          conn
          |> put_flash(:info, "Signed in via SSO.")
          |> UserAuth.log_in_user(user)

        {:error, :invalid_state} ->
          conn
          |> put_flash(:error, "Invalid authentication state. This may be a CSRF attack or your session expired. Please try again.")
          |> redirect(to: "/login")

        {:error, :state_expired} ->
          conn
          |> put_flash(:error, "Authentication session expired. Please try signing in again.")
          |> redirect(to: "/login")

        {:error, :provider_mismatch} ->
          conn
          |> put_flash(:error, "Provider mismatch in callback. Please try signing in again.")
          |> redirect(to: "/login")

        {:error, :missing_email} ->
          conn
          |> put_flash(:error, "Your identity provider did not return an email address. Please ensure your account has a verified email.")
          |> redirect(to: "/login")

        {:error, :domain_not_allowed} ->
          conn
          |> put_flash(:error, "Your email domain is not authorized for this organization.")
          |> redirect(to: "/login")

        {:error, :user_not_found_jit_disabled} ->
          conn
          |> put_flash(:error, "Account not found. Automatic account creation is disabled.")
          |> redirect(to: "/login")

        {:error, :user_belongs_to_different_org} ->
          conn
          |> put_flash(:error, "This account belongs to a different organization.")
          |> redirect(to: "/login")

        {:error, reason} ->
          Logger.error("[SSOController] OAuth callback failed for provider #{provider_id}: #{inspect(reason)}")

          conn
          |> put_flash(:error, "SSO authentication failed. Please try again.")
          |> redirect(to: "/login")
      end
    end
  end

  # ── API endpoints ──────────────────────────────────────────────────

  @doc """
  List all configured and enabled SSO providers.
  Used by the login page to show available SSO buttons.
  """
  def list_providers(conn, params) do
    organization_id = params["organization_id"]
    providers = SSO.list_providers(organization_id)

    # Also include the supported provider types
    supported = SSO.supported_providers()

    json(conn, %{
      providers: providers,
      supported_types: supported
    })
  end

  # ── Private helpers ────────────────────────────────────────────────

  defp get_base_url(conn) do
    scheme = if conn.scheme == :https, do: "https", else: "http"
    port_suffix = port_suffix(conn.scheme, conn.port)
    "#{scheme}://#{conn.host}#{port_suffix}"
  end

  defp port_suffix(:https, 443), do: ""
  defp port_suffix(:http, 80), do: ""
  defp port_suffix(_scheme, port), do: ":#{port}"

  defp log_sso_login(conn, user, provider_type, provider_id) do
    AuditLog.log_login(user,
      ip_address: get_client_ip(conn),
      user_agent: get_user_agent(conn),
      method: "sso_#{provider_type}",
      details: %{
        sso_provider_id: provider_id,
        sso_protocol: to_string(provider_type)
      }
    )
  rescue
    _ -> :ok
  end

  defp log_sso_logout(conn, user, provider_id) do
    AuditLog.log_logout(user,
      ip_address: get_client_ip(conn),
      user_agent: get_user_agent(conn),
      details: %{sso_provider_id: provider_id, method: "sso_slo"}
    )
  rescue
    _ -> :ok
  end

  defp detect_provider_type(provider_id) do
    case SSO.get_config(provider_id) do
      {:ok, config} -> config.provider
      _ -> :oauth
    end
  end

  defp get_client_ip(conn) do
    case get_req_header(conn, "x-forwarded-for") do
      [forwarded | _] ->
        forwarded |> String.split(",") |> List.first() |> String.trim()

      [] ->
        conn.remote_ip |> :inet.ntoa() |> to_string()
    end
  end

  defp get_user_agent(conn) do
    case get_req_header(conn, "user-agent") do
      [ua | _] -> ua
      [] -> nil
    end
  end
end
