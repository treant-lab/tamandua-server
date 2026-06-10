defmodule TamanduaServerWeb.API.V1.AuthController do
  @moduledoc """
  Authentication API for agent token management.

  Endpoints:
  - POST /api/v1/agents/auth/refresh   — Refresh JWT token (agent auth via Bearer token)
  - GET  /api/v1/agents/auth/status    — Check token status (agent auth via Bearer token)
  - POST /api/v1/agents/auth/revoke    — Revoke token(s) (requires admin auth + tenant validation)
  - GET  /api/v1/agents/auth/stats/:agent_id — Token stats (requires user auth + tenant validation)
  """

  use TamanduaServerWeb, :controller
  require Logger

  alias TamanduaServer.Agents
  alias TamanduaServer.Agents.TokenManager

  @doc """
  Refresh an agent's JWT token.

  POST /api/v1/agents/auth/refresh
  Headers: Authorization: Bearer <current_token>
  Body: {} (optional)

  Returns a new token if:
  - Current token is valid
  - Token is within refresh window (default 60% of TTL)
  - Token is not revoked
  - Agent has token rotation enabled

  Response:
  {
    "token": "new_jwt_token",
    "expires_at": "2026-02-21T12:00:00Z",
    "generation": 5,
    "refresh_count": 3
  }
  """
  def refresh(conn, _params) do
    with {:ok, token} <- extract_bearer_token(conn),
         {:ok, new_jwt, token_record} <- refresh_agent_token(token, conn) do
      conn
      |> put_status(:ok)
      |> json(%{
        token: new_jwt,
        expires_at: token_record.expires_at,
        generation: token_record.token_generation,
        refresh_count: token_record.refresh_count,
        message: "Token refreshed successfully"
      })
    else
      {:error, :missing_token} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "Missing authorization token"})

      {:error, :too_early_to_refresh} ->
        conn
        |> put_status(:forbidden)
        |> json(%{
          error: "Token refresh not allowed yet",
          message:
            "Token must reach refresh window (typically 60% of TTL) before it can be refreshed"
        })

      {:error, :token_revoked} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{
          error: "Token has been revoked",
          message: "Please re-enroll the agent to obtain new credentials"
        })

      {:error, :generation_mismatch} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{
          error: "Token generation mismatch",
          message: "A newer token has been issued for this agent"
        })

      {:error, :expired} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{
          error: "Token has expired",
          message: "Please re-enroll the agent to obtain new credentials"
        })

      {:error, reason} ->
        Logger.warning("Token refresh failed: #{inspect(reason)}")

        conn
        |> put_status(:unauthorized)
        |> json(%{error: "Token refresh failed", reason: inspect(reason)})
    end
  end

  @doc """
  Revoke agent token(s).

  POST /api/v1/agents/auth/revoke
  Headers: Authorization: Bearer <user_api_token> or session auth
  Body: {
    "agent_id": "uuid",
    "reason": "security_incident",
    "all_generations": true  // optional, default false
  }

  Requires:
  - User authentication (via api_auth pipeline)
  - Admin role OR agent owner
  - Agent must belong to user's organization (tenant validation)
  """
  def revoke(conn, params) do
    user = conn.assigns[:current_user]
    agent_id = params["agent_id"]
    reason = params["reason"] || "manual_revocation"
    all_generations = params["all_generations"] || false

    cond do
      is_nil(agent_id) ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Missing required field: agent_id"})

      is_nil(user) ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "Authentication required"})

      true ->
        # Verify agent belongs to user's organization (tenant validation)
        # Return 404 (not 403) to avoid enumeration attacks
        case Agents.get_agent_for_org(user.organization_id, agent_id) do
          {:error, :not_found} ->
            Logger.warning("User #{user.id} attempted to revoke agent #{agent_id} from different org")

            conn
            |> put_status(:not_found)
            |> json(%{error: "Agent not found"})

          {:ok, agent} ->
            # Check if user has permission to manage this agent
            if can_manage_agent?(user, agent) do
              case TokenManager.revoke_token(agent_id,
                     reason: reason,
                     all_generations: all_generations
                   ) do
                {:ok, %{revoked_count: count}} ->
                  Logger.info(
                    "User #{user.email} (#{user.id}) revoked #{count} token(s) for agent #{agent_id}, reason: #{reason}"
                  )

                  json(conn, %{
                    status: "revoked",
                    agent_id: agent_id,
                    revoked_count: count,
                    reason: reason
                  })

                {:error, revoke_reason} ->
                  conn
                  |> put_status(:internal_server_error)
                  |> json(%{error: "Revocation failed", reason: inspect(revoke_reason)})
              end
            else
              Logger.warning(
                "User #{user.email} (#{user.id}) unauthorized to revoke agent #{agent_id}"
              )

              conn
              |> put_status(:forbidden)
              |> json(%{error: "Not authorized to manage this agent"})
            end
        end
    end
  end

  @doc """
  Get token status for an agent.

  GET /api/v1/agents/auth/status
  Headers: Authorization: Bearer <token>

  Returns:
  {
    "valid": true,
    "agent_id": "uuid",
    "generation": 5,
    "issued_at": "2026-02-20T12:00:00Z",
    "expires_at": "2026-02-21T12:00:00Z",
    "refresh_eligible": true,
    "time_to_expiry_seconds": 43200,
    "refresh_count": 2
  }
  """
  def status(conn, _params) do
    with {:ok, token} <- extract_bearer_token(conn),
         {:ok, claims} <- TokenManager.validate_token(token),
         {:ok, agent_id, generation} <- extract_token_info(claims),
         {:ok, stats} <- get_token_status(agent_id, generation) do
      json(conn, stats)
    else
      {:error, :missing_token} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{valid: false, error: "Missing authorization token"})

      {:error, :database_error} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{
          valid: false,
          error: "token_status_unavailable",
          retryable: true
        })

      {:error, reason} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{valid: false, error: inspect(reason)})
    end
  end

  @doc """
  Get token statistics for an agent.

  GET /api/v1/agents/auth/stats/:agent_id
  Headers: Authorization: Bearer <user_api_token> or session auth

  Requires:
  - User authentication (via api_auth pipeline)
  - Agent must belong to user's organization (tenant validation)

  Returns aggregate statistics about token usage.
  """
  def stats(conn, %{"agent_id" => agent_id}) do
    user = conn.assigns[:current_user]

    cond do
      is_nil(user) ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "Authentication required"})

      true ->
        # Verify agent belongs to user's organization (tenant validation)
        # Return 404 (not 403) to avoid enumeration attacks
        case Agents.get_agent_for_org(user.organization_id, agent_id) do
          {:error, :not_found} ->
            conn
            |> put_status(:not_found)
            |> json(%{error: "Agent not found"})

          {:ok, _agent} ->
            case TokenManager.get_token_stats(agent_id) do
              {:ok, stats} ->
                json(conn, stats)

              {:error, reason} ->
                conn
                |> put_status(:internal_server_error)
                |> json(%{error: "Failed to retrieve stats", reason: inspect(reason)})
            end
        end
    end
  end

  # Private Functions

  defp extract_bearer_token(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] -> {:ok, token}
      _ -> {:error, :missing_token}
    end
  end

  defp refresh_agent_token(current_token, conn) do
    ip_address = get_client_ip(conn)
    user_agent = get_user_agent(conn)

    TokenManager.refresh_token(current_token,
      ip_address: ip_address,
      user_agent: user_agent
    )
  end

  defp extract_token_info(claims) do
    agent_id = claims["agent_id"]
    generation = claims["generation"]

    if agent_id && generation do
      {:ok, agent_id, generation}
    else
      {:error, :invalid_claims}
    end
  end

  defp get_token_status(agent_id, generation) do
    with {:ok, dumped_agent_id} <- dump_uuid(agent_id) do
      query = """
      SELECT
        t.id,
        t.agent_id::text,
        t.token_generation,
        t.issued_at,
        t.expires_at,
        t.last_refreshed_at,
        t.refresh_count,
        t.revoked_at,
        a.token_refresh_window_percent
      FROM agent_tokens t
      JOIN agents a ON a.id = t.agent_id
      WHERE t.agent_id = $1 AND t.token_generation = $2
      """

      case TamanduaServer.Repo.query(query, [dumped_agent_id, generation]) do
        {:ok, %{rows: [row]}} ->
          [
            _id,
            row_agent_id,
            gen,
            issued_at,
            expires_at,
            last_refreshed,
            refresh_count,
            revoked_at,
            configured_refresh_window
          ] = row

          agent_id = load_uuid_string(row_agent_id)
          issued_at = utc_datetime(issued_at)
          expires_at = utc_datetime(expires_at)
          last_refreshed = utc_datetime(last_refreshed)
          now = DateTime.utc_now()
          time_to_expiry = DateTime.diff(expires_at, now, :second)
          ttl = DateTime.diff(expires_at, issued_at, :second)
          elapsed = DateTime.diff(now, issued_at, :second)
          percent_elapsed = if ttl > 0, do: elapsed / ttl * 100, else: 100.0

          refresh_window = min(configured_refresh_window || 60, 60)
          refresh_eligible = percent_elapsed >= refresh_window and is_nil(revoked_at)

          {:ok,
           %{
             valid: is_nil(revoked_at) and time_to_expiry > 0,
             agent_id: agent_id,
             generation: gen,
             issued_at: issued_at,
             expires_at: expires_at,
             last_refreshed_at: last_refreshed,
             refresh_eligible: refresh_eligible,
             refresh_window_percent: refresh_window,
             time_to_expiry_seconds: max(0, time_to_expiry),
             percent_elapsed: Float.round(percent_elapsed, 2),
             refresh_count: refresh_count,
             revoked: not is_nil(revoked_at)
           }}

        {:ok, %{rows: []}} ->
          {:error, :token_not_found}

        {:error, reason} ->
          Logger.error("Failed to query token status: #{inspect(reason)}")
          {:error, :database_error}
      end
    else
      :error -> {:error, :invalid_agent_id}
    end
  end

  defp dump_uuid(<<_::128>> = uuid), do: {:ok, uuid}

  defp dump_uuid(uuid) when is_binary(uuid) do
    Ecto.UUID.dump(uuid)
  end

  defp dump_uuid(_), do: :error

  defp load_uuid_string(<<_::128>> = uuid) do
    case Ecto.UUID.load(uuid) do
      {:ok, value} -> value
      :error -> Base.encode16(uuid, case: :lower)
    end
  end

  defp load_uuid_string(uuid) when is_binary(uuid), do: uuid
  defp load_uuid_string(uuid), do: to_string(uuid)

  defp utc_datetime(nil), do: nil
  defp utc_datetime(%DateTime{} = datetime), do: datetime

  defp utc_datetime(%NaiveDateTime{} = datetime) do
    datetime
    |> DateTime.from_naive!("Etc/UTC")
  end

  defp get_client_ip(conn) do
    case get_req_header(conn, "x-forwarded-for") do
      [ip | _] -> ip
      _ -> to_string(:inet.ntoa(conn.remote_ip))
    end
  rescue
    _ -> "unknown"
  end

  defp get_user_agent(conn) do
    case get_req_header(conn, "user-agent") do
      [ua | _] -> ua
      _ -> "unknown"
    end
  end

  # Authorization helpers

  @doc false
  # Check if user can manage the given agent.
  # Allowed if:
  # - User is an admin
  # - User is a responder (can execute response actions)
  # - User has explicit agents_manage permission via RBAC
  defp can_manage_agent?(user, _agent) do
    cond do
      # Admin role has full access
      user.role in ["admin", :admin] ->
        true

      # Responder role can manage agents (response actions)
      user.role in ["responder", :responder] ->
        true

      # Check RBAC permissions if available
      function_exported?(TamanduaServer.Authorization.RBAC, :can?, 2) ->
        TamanduaServer.Authorization.RBAC.can?(user, :agents_manage)

      # Default: deny
      true ->
        false
    end
  end
end
