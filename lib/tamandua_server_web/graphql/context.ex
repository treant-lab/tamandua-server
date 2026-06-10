defmodule TamanduaServerWeb.GraphQL.Context do
  @moduledoc """
  Plug for building GraphQL context from request headers.

  Extracts authentication information from:
  - Authorization header (Bearer token)
  - X-API-Key header

  The context is then available in all resolvers via `%{context: context}`.
  """

  @behaviour Plug

  import Plug.Conn

  alias TamanduaServer.Accounts

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    context = build_context(conn)
    Absinthe.Plug.put_options(conn, context: context)
  end

  @doc """
  Build the GraphQL context from the connection.
  """
  def build_context(conn) do
    context = %{}

    context = case get_auth_token(conn) do
      nil -> context
      token -> add_user_to_context(context, token)
    end

    context = case get_api_key(conn) do
      nil -> context
      api_key -> add_api_key_to_context(context, api_key)
    end

    # Add organization from user if present
    context = if context[:current_user_id] do
      user = Accounts.get_user(context[:current_user_id])
      if user do
        Map.put(context, :organization_id, user.organization_id)
      else
        context
      end
    else
      context
    end

    # Add request metadata
    context
    |> Map.put(:remote_ip, get_remote_ip(conn))
    |> Map.put(:user_agent, get_user_agent(conn))
    |> Map.put(:request_id, conn.assigns[:request_id] || Ecto.UUID.generate())
  end

  defp get_auth_token(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] -> token
      _ -> nil
    end
  end

  defp get_api_key(conn) do
    case get_req_header(conn, "x-api-key") do
      [key] -> key
      _ -> nil
    end
  end

  defp add_user_to_context(context, token) do
    case Accounts.get_user_by_session_token(token) do
      nil ->
        # Try JWT validation via Guardian
        case TamanduaServer.Guardian.decode_and_verify(token) do
          {:ok, claims} ->
            user_id = claims["sub"]
            context
            |> Map.put(:current_user_id, user_id)
            |> Map.put(:auth_method, :jwt)

          {:error, _} ->
            context
        end

      user ->
        context
        |> Map.put(:current_user_id, user.id)
        |> Map.put(:auth_method, :session)
    end
  end

  defp add_api_key_to_context(context, api_key) do
    # Validate API key and get associated user/organization
    case validate_api_key(api_key) do
      {:ok, %{user_id: user_id, organization_id: org_id, scopes: scopes}} ->
        context
        |> Map.put(:current_user_id, user_id)
        |> Map.put(:organization_id, org_id)
        |> Map.put(:api_key_scopes, scopes)
        |> Map.put(:auth_method, :api_key)

      {:error, _} ->
        context
    end
  end

  defp validate_api_key(api_key) do
    # Check in API keys table
    case TamanduaServer.Tenants.get_api_key_by_token(api_key) do
      nil ->
        # Also try ETS-based tokens
        case Accounts.get_user_by_api_token(api_key) do
          nil -> {:error, :invalid_api_key}
          user ->
            {:ok, %{
              user_id: user.id,
              organization_id: user.organization_id,
              scopes: ["*"]
            }}
        end

      key ->
        if key.is_active do
          {:ok, %{
            user_id: key.user_id,
            organization_id: key.organization_id,
            scopes: key.scopes || ["*"]
          }}
        else
          {:error, :api_key_inactive}
        end
    end
  rescue
    _ ->
      # If Tenants module not available, try direct token lookup
      case Accounts.get_user_by_api_token(api_key) do
        nil -> {:error, :invalid_api_key}
        user ->
          {:ok, %{
            user_id: user.id,
            organization_id: user.organization_id,
            scopes: ["*"]
          }}
      end
  end

  defp get_remote_ip(conn) do
    # Check for forwarded headers (load balancer/proxy)
    case get_req_header(conn, "x-forwarded-for") do
      [forwarded | _] ->
        forwarded
        |> String.split(",")
        |> List.first()
        |> String.trim()

      [] ->
        case conn.remote_ip do
          {a, b, c, d} -> "#{a}.#{b}.#{c}.#{d}"
          ip -> inspect(ip)
        end
    end
  end

  defp get_user_agent(conn) do
    case get_req_header(conn, "user-agent") do
      [ua | _] -> ua
      [] -> nil
    end
  end
end
