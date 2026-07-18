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
    context = context_from_authenticated_conn(conn)

    context =
      case {context[:current_user_id], get_auth_token(conn)} do
        {nil, token} when is_binary(token) -> add_user_to_context(context, token)
        _ -> context
      end

    context =
      case get_api_key(conn) do
        nil -> context
        api_key -> add_api_key_to_context(context, api_key)
      end

    # Add organization from user only when the authenticated pipeline did not
    # already select one (for example a super-admin tenant context).
    context =
      if context[:current_user_id] && is_nil(context[:organization_id]) do
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

  defp context_from_authenticated_conn(conn) do
    case conn.assigns[:current_user] do
      %{id: user_id} when not is_nil(user_id) ->
        %{
          current_user_id: user_id,
          organization_id:
            conn.assigns[:current_organization_id] || conn.assigns[:organization_id],
          auth_method: :pipeline
        }

      _ ->
        %{}
    end
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
    case validate_api_key(api_key) do
      {:ok, key_context} ->
        constrain_with_api_key(context, key_context)

      {:error, _} ->
        Map.put(context, :auth_error, :invalid_api_key)
    end
  end

  defp constrain_with_api_key(context, %{user_id: key_user_id, organization_id: key_org_id} = key) do
    actor_org_id = context[:organization_id] || actor_organization_id(context[:current_user_id])
    context = if actor_org_id, do: Map.put(context, :organization_id, actor_org_id), else: context

    if actor_org_id && actor_org_id != key_org_id do
      Map.put(context, :auth_error, :api_key_tenant_mismatch)
    else
      context
      |> Map.put_new(:current_user_id, key_user_id)
      |> Map.put_new(:organization_id, key_org_id)
      |> Map.put(:api_key_present, true)
      |> Map.put(:api_key_scope, key.scope)
      |> Map.put(:api_key_permissions, key.permissions)
      |> Map.put(:api_key_scopes, key.scopes)
    end
  end

  defp actor_organization_id(nil), do: nil

  defp actor_organization_id(user_id) do
    case Accounts.get_user(user_id) do
      nil -> nil
      user -> user.organization_id
    end
  end

  defp validate_api_key(api_key) do
    # Real API: `Tenants.find_api_key_by_value/1` (prefix lookup + hash verify;
    # only active keys match). There is no `get_api_key_by_token/1`, and the
    # `APIKey` schema has no `user_id`/`scopes` fields; the actual fields are
    # `created_by_id`, `permissions` (list) and `scope` (string).
    case TamanduaServer.Tenants.find_api_key_by_value(api_key) do
      {:ok, key} ->
        {:ok,
         %{
           user_id: key.created_by_id,
           organization_id: key.organization_id,
           scope: key.scope,
           permissions: key.permissions || [],
           scopes: api_key_scopes(key)
         }}

      {:error, _} ->
        lookup_ets_api_token(api_key)
    end
  rescue
    # The Tenants lookup hits the database; if the Repo is unavailable, fall
    # back to the ETS-based token store so API auth degrades instead of raising.
    _ -> lookup_ets_api_token(api_key)
  end

  defp lookup_ets_api_token(api_key) do
    case Accounts.get_user_by_api_token(api_key) do
      nil ->
        {:error, :invalid_api_key}

      user ->
        {:ok,
         %{
           user_id: user.id,
           organization_id: user.organization_id,
           scope: "full",
           permissions: [],
           scopes: ["*"]
         }}
    end
  end

  # Translate the APIKey schema's `permissions`/`scope` fields into the
  # GraphQL context scope list. A "full"-scope key with no explicit
  # permissions grants everything.
  defp api_key_scopes(key) do
    case {key.permissions, key.scope} do
      {perms, _} when is_list(perms) and perms != [] -> perms
      {_, "full"} -> ["*"]
      {_, scope} when is_binary(scope) -> [scope]
      _ -> []
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
