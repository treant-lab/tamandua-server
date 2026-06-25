defmodule TamanduaServerWeb.API.V1.EnrollmentController do
  @moduledoc """
  Enrollment API for agent installation and token management.

  Public endpoints (token IS the auth):
  - POST /api/v1/enrollment/validate  — validate installation token
  - POST /api/v1/enrollment/exchange  — exchange token for JWT + agent_id (legacy)
  - POST /api/v1/enrollment/csr       — CSR-based enrollment (recommended, secure)

  Agent endpoints (JWT auth):
  - POST /api/v1/enrollment/renew     — CSR-based certificate renewal

  Admin endpoints (require user authentication):
  - GET    /api/v1/admin/installation-tokens     — list tokens
  - POST   /api/v1/admin/installation-tokens     — generate token
  - DELETE /api/v1/admin/installation-tokens/:id  — revoke token

  ## CSR-Based Enrollment (Recommended)

  The CSR-based flow is more secure because the private key never leaves the agent:
  1. Agent generates RSA keypair locally
  2. Agent sends CSR (public key) to server
  3. Server validates token and signs CSR with intermediate CA
  4. Server returns signed certificate + CA bundle

  The legacy `/exchange` endpoint generates both cert and private key server-side,
  which means the private key is transmitted over the network (even if encrypted).
  """

  use TamanduaServerWeb, :controller
  require Logger

  alias TamanduaServer.Enrollment

  # --------------------------------------------------------------------------
  # Public Enrollment Endpoints (no auth — the token IS the auth)
  # --------------------------------------------------------------------------

  @doc """
  Validate an installation token.

  POST /api/v1/enrollment/validate
  Body: {"token": "..."}
  """
  def validate(conn, %{"token" => token}) do
    case Enrollment.validate_token(token) do
      {:ok, record} ->
        json(conn, %{
          valid: true,
          org_id: record.organization_id
        })

      {:error, reason} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{valid: false, error: enrollment_error(reason)})
    end
  end

  def validate(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required field: token"})
  end

  @doc """
  Exchange an installation token for agent credentials.

  POST /api/v1/enrollment/exchange
  Body: {"token": "...", "agent_info": {...}}
  """
  def exchange(conn, %{"token" => token} = params) do
    agent_info = Map.get(params, "agent_info", %{})

    case Enrollment.exchange_token(token, agent_info) do
      {:ok, credentials} ->
        json(conn, %{
          agent_id: credentials.agent_id,
          jwt: credentials.jwt,
          org_id: credentials.org_id,
          organization_id: credentials.org_id,
          agent_token: credentials.jwt,
          server_url: default_agent_socket_url(conn)
        })

      {:error, reason} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: enrollment_error(reason)})
    end
  end

  def exchange(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required field: token"})
  end

  @doc """
  CSR-based enrollment (secure - private key never leaves agent).

  POST /api/v1/enrollment/csr
  Body: {"token": "...", "csr": "<base64-encoded CSR PEM>", "agent_info": {...}}

  This is the recommended enrollment flow where:
  1. Agent generates RSA keypair locally
  2. Agent sends CSR (containing public key) to server
  3. Server validates token and signs CSR
  4. Server returns signed certificate + CA bundle

  The private key never leaves the agent device.
  """
  def csr_enroll(conn, %{"token" => token, "csr" => csr_b64} = params) do
    agent_info = Map.get(params, "agent_info", %{})

    # Decode CSR from base64
    case Base.decode64(csr_b64) do
      {:ok, csr_pem} ->
        case Enrollment.enroll_with_csr(token, csr_pem, agent_info) do
          {:ok, result} ->
            conn
            |> put_status(:created)
            |> json(%{
              agent_id: result.agent_id,
              jwt: result.jwt,
              org_id: result.org_id,
              organization_id: result.org_id,
              certificate: Base.encode64(result.certificate),
              ca_bundle: Base.encode64(result.ca_bundle),
              server_url: default_agent_socket_url(conn)
            })

          {:error, :invalid_csr} ->
            conn
            |> put_status(:bad_request)
            |> json(%{error: "Invalid CSR format"})

          {:error, :no_cn_in_csr} ->
            conn
            |> put_status(:bad_request)
            |> json(%{error: "CSR must contain a Common Name (CN) for the agent ID"})

          {:error, {:signing_failed, reason}} ->
            render_csr_enrollment_error(conn, {:signing_failed, reason})

          {:error, {:pki_not_ready, reason}} ->
            render_csr_enrollment_error(conn, {:pki_not_ready, reason})

          {:error, reason} when is_binary(reason) ->
            conn
            |> put_status(:unauthorized)
            |> json(%{error: reason})

          {:error, reason} ->
            render_csr_enrollment_error(conn, reason)
        end

      :error ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Invalid base64 encoding for CSR"})
    end
  end

  def csr_enroll(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required fields: token, csr"})
  end

  @doc """
  CSR-based certificate renewal for existing agents.

  POST /api/v1/enrollment/renew
  Body: {"csr": "<base64-encoded CSR PEM>"}
  Auth: Bearer JWT

  Used when an existing agent needs to renew its certificate.
  The agent is already authenticated via JWT (not installation token).
  """
  def csr_renew(conn, %{"csr" => csr_b64}) do
    # Get agent_id from JWT
    agent_id = get_agent_id_from_conn(conn)

    if is_nil(agent_id) do
      conn
      |> put_status(:unauthorized)
      |> json(%{error: "Agent authentication required"})
    else
      case Base.decode64(csr_b64) do
        {:ok, csr_pem} ->
          case Enrollment.renew_certificate_with_csr(agent_id, csr_pem) do
            {:ok, result} ->
              response = %{
                certificate: Base.encode64(result.certificate)
              }

              # Include CA bundle if it was updated
              response =
                if result.ca_bundle do
                  Map.put(response, :ca_bundle, Base.encode64(result.ca_bundle))
                else
                  response
                end

              conn
              |> put_status(:ok)
              |> json(response)

            {:error, :agent_id_mismatch} ->
              conn
              |> put_status(:forbidden)
              |> json(%{error: "CSR agent ID does not match authenticated agent"})

            {:error, {:pki_not_ready, reason}} ->
              conn
              |> put_status(:service_unavailable)
              |> json(%{
                error: "PKI is not ready for certificate renewal",
                details: inspect(reason)
              })

            {:error, reason} ->
              conn
              |> put_status(:internal_server_error)
              |> json(%{error: "Certificate renewal failed", details: inspect(reason)})
          end

        :error ->
          conn
          |> put_status(:bad_request)
          |> json(%{error: "Invalid base64 encoding for CSR"})
      end
    end
  end

  def csr_renew(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required field: csr"})
  end

  @doc """
  Legacy MSI enrollment endpoint.

  Older Windows installer scripts call POST /api/v1/agents/enroll and expect
  `agent_token` / `organization_id` field names. Keep this endpoint as a
  compatibility shim around the canonical /api/v1/enrollment/exchange flow.
  """
  def enroll(conn, %{"token" => token} = params) do
    agent_info =
      params
      |> Map.drop(["token"])
      |> Map.merge(Map.get(params, "agent_info", %{}))

    exchange(conn, %{"token" => token, "agent_info" => agent_info})
  end

  def enroll(conn, params) do
    token = params["enrollment_token"] || params["ENROLLMENT_TOKEN"]

    if is_binary(token) and token != "" do
      enroll(conn, Map.put(params, "token", token))
    else
      conn
      |> put_status(:bad_request)
      |> json(%{error: "Missing required field: token"})
    end
  end

  # --------------------------------------------------------------------------
  # Admin Token Management Endpoints
  # --------------------------------------------------------------------------

  @doc """
  List installation tokens for the current organization.

  GET /api/v1/admin/installation-tokens
  """
  def index(conn, _params) do
    # Extract org_id from the authenticated user's context
    org_id = get_org_id(conn)
    tokens = Enrollment.list_tokens(org_id)

    json(conn, %{
      tokens:
        Enum.map(tokens, fn t ->
          %{
            id: t.id,
            name: t.name,
            created_by: t.created_by,
            expires_at: t.expires_at,
            max_uses: t.max_uses,
            use_count: t.use_count,
            revoked: t.revoked,
            last_used_at: t.last_used_at,
            consumed_at: t.consumed_at,
            consumed_agent_id: t.consumed_agent_id,
            created_at: t.inserted_at
          }
        end)
    })
  end

  @doc """
  Generate a new installation token.

  POST /api/v1/admin/installation-tokens
  Body: {"name": "Production deploy", "max_uses": 100, "expires_at": "..."}
  """
  def create(conn, params) do
    require Logger

    org_id = get_org_id(conn)
    user = get_current_user(conn)

    Logger.info("Creating installation token: org_id=#{inspect(org_id)}, user=#{inspect(user)}")

    if is_nil(org_id) do
      conn
      |> put_status(:unprocessable_entity)
      |> json(%{error: "Cannot create installation token without an organization"})
    else
      attrs = %{
        name: Map.get(params, "name", "Installation Token"),
        created_by: user,
        organization_id: org_id,
        max_uses: Map.get(params, "max_uses"),
        expires_at: parse_expires_at(Map.get(params, "expires_at"))
      }

      try do
        case Enrollment.generate_token(attrs) do
          {:ok, cleartext, record} ->
            conn
            |> put_status(:created)
            |> json(%{
              id: record.id,
              token: cleartext,
              name: record.name,
              created_by: record.created_by,
              expires_at: record.expires_at,
              max_uses: record.max_uses,
              consumed_at: record.consumed_at,
              consumed_agent_id: record.consumed_agent_id,
              message: "Save this token now — it will not be shown again."
            })

          {:error, changeset} ->
            Logger.error("Token generation failed: #{inspect(changeset)}")

            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "Failed to create token", details: format_errors(changeset)})
        end
      rescue
        e ->
          Logger.error("Token generation crashed: #{Exception.format(:error, e, __STACKTRACE__)}")

          conn
          |> put_status(:internal_server_error)
          |> json(%{
            error: "Internal error creating token",
            details: Exception.message(e),
            hint: "Check if organization exists and Argon2 is available"
          })
      end
    end
  end

  @doc """
  Revoke an installation token.

  DELETE /api/v1/admin/installation-tokens/:id
  """
  def delete(conn, %{"id" => id}) do
    org_id = get_org_id(conn)

    case Enrollment.revoke_token(id, org_id) do
      {:ok, _token} ->
        json(conn, %{status: "revoked"})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Token not found"})

      {:error, _} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Failed to revoke token"})
    end
  end

  # --------------------------------------------------------------------------
  # Private Helpers
  # --------------------------------------------------------------------------

  defp get_org_id(conn) do
    case conn.assigns do
      %{current_organization_id: org_id} when is_binary(org_id) -> org_id
      %{current_user: %{organization_id: org_id}} when is_binary(org_id) -> org_id
      _ -> nil
    end
  end

  defp get_current_user(conn) do
    case conn.assigns do
      %{current_user: %{email: email}} -> email
      %{current_user: %{id: id}} -> "user:#{id}"
      _ -> "system"
    end
  end

  defp get_agent_id_from_conn(conn) do
    case conn.assigns do
      %{current_agent_id: agent_id} when is_binary(agent_id) -> agent_id
      %{agent_id: agent_id} when is_binary(agent_id) -> agent_id
      _ -> nil
    end
  end

  defp parse_expires_at(nil), do: nil

  defp parse_expires_at(str) when is_binary(str) do
    case DateTime.from_iso8601(str) do
      {:ok, dt, _offset} -> dt
      _ -> nil
    end
  end

  defp parse_expires_at(_), do: nil

  defp format_errors(%Ecto.Changeset{} = changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> changeset_error_opt(key) |> to_string()
      end)
    end)
  end

  defp changeset_error_opt(opts, "count"), do: Keyword.get(opts, :count, "count")
  defp changeset_error_opt(opts, "validation"), do: Keyword.get(opts, :validation, "validation")
  defp changeset_error_opt(opts, "kind"), do: Keyword.get(opts, :kind, "kind")
  defp changeset_error_opt(opts, "type"), do: Keyword.get(opts, :type, "type")
  defp changeset_error_opt(_opts, key), do: key

  defp format_errors(other), do: inspect(other)

  defp enrollment_error(reason) when is_binary(reason), do: reason
  defp enrollment_error(reason) when is_atom(reason), do: Atom.to_string(reason)
  defp enrollment_error(reason), do: inspect(reason)

  defp render_csr_enrollment_error(conn, {:pki_not_ready, reason}) do
    Logger.error("CSR enrollment PKI is not ready: #{inspect(reason)}")

    conn
    |> put_status(:service_unavailable)
    |> json(%{
      error: "pki_not_ready",
      message: csr_error_message(reason),
      details: csr_error_details(reason)
    })
  end

  defp render_csr_enrollment_error(conn, {:signing_failed, reason}) do
    Logger.error("CSR certificate signing failed: #{inspect(reason)}")

    conn
    |> put_status(:service_unavailable)
    |> json(%{
      error: "certificate_signing_failed",
      message: csr_error_message(reason),
      details: csr_error_details(reason)
    })
  end

  defp render_csr_enrollment_error(conn, {:enrollment_failed, reason}) do
    Logger.error("CSR enrollment failed: #{inspect(reason)}")

    conn
    |> put_status(:internal_server_error)
    |> json(%{
      error: "enrollment_failed",
      message:
        "The server could not complete agent enrollment. Check tamandua_server logs for the stacktrace.",
      details: csr_error_details(reason)
    })
  end

  defp render_csr_enrollment_error(conn, reason) do
    Logger.error("Unexpected CSR enrollment error: #{inspect(reason)}")

    conn
    |> put_status(:internal_server_error)
    |> json(%{
      error: "enrollment_failed",
      message:
        "The server could not complete agent enrollment. Check tamandua_server logs for the stacktrace.",
      details: csr_error_details(reason)
    })
  end

  defp csr_error_message({:executable_not_found, "openssl"}) do
    "OpenSSL is not available in the server container. Rebuild and redeploy tamandua_server with openssl installed."
  end

  defp csr_error_message({:openssl_error, detail}) do
    "OpenSSL failed while preparing the agent certificate: #{String.slice(inspect(detail), 0, 240)}"
  end

  defp csr_error_message(_reason) do
    "The server PKI could not issue the agent certificate right now."
  end

  defp csr_error_details({:executable_not_found, "openssl"}), do: "openssl_not_found"
  defp csr_error_details(:internal_error), do: "internal_error"
  defp csr_error_details(reason), do: inspect(reason)

  defp default_agent_socket_url(conn) do
    configured =
      Application.get_env(:tamandua_server, :agent_public_url) ||
        System.get_env("AGENT_PUBLIC_URL") ||
        System.get_env("TAMANDUA_AGENT_PUBLIC_URL")

    configured || default_agent_socket_url_for_host(conn.host)
  end

  defp default_agent_socket_url_for_host("tamandua.treantlab.org"),
    do: "wss://agents.tamandua.treantlab.org:8443/socket/agent"

  defp default_agent_socket_url_for_host("localhost"),
    do: "ws://localhost:4000/socket/agent"

  defp default_agent_socket_url_for_host("127.0.0.1"),
    do: "ws://127.0.0.1:4000/socket/agent"

  defp default_agent_socket_url_for_host(host),
    do: "wss://agents.#{host}:8443/socket/agent"
end
