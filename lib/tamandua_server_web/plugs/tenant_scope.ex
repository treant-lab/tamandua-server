defmodule TamanduaServerWeb.Plugs.TenantScope do
  @moduledoc """
  Plug for enforcing multi-tenant data isolation.

  This plug extracts the current tenant (organization) from the request
  and ensures all subsequent operations are scoped to that tenant.

  ## Authentication Sources

  The tenant can be determined from:
  1. User session (via `current_user.organization_id`)
  2. API key (via `X-API-Key` header)
  3. JWT token (via `Authorization: Bearer` header)

  ## Usage

  Add to your router pipeline:

      pipeline :api_tenant do
        plug TamanduaServerWeb.Plugs.TenantScope
      end

  ## Assigns

  This plug sets the following assigns on the connection:
  - `:current_organization_id` - The tenant's organization ID
  - `:current_organization` - The full organization struct (optional, set if `:preload_org` is true)
  - `:current_api_key` - The API key used for authentication (if applicable)

  ## Options

  - `:preload_org` - Whether to preload the full organization struct (default: false)
  - `:allow_system` - Whether to allow system-level access without tenant (default: false)
  - `:require_active` - Whether to require the organization to be active (default: true)

  ## Example

      # In router
      pipeline :api_tenant do
        plug TamanduaServerWeb.Plugs.TenantScope, preload_org: true
      end

      # In controller
      def index(conn, params) do
        org_id = conn.assigns.current_organization_id
        alerts = Alerts.list_alerts(org_id)
        # ...
      end
  """

  import Plug.Conn
  require Logger

  alias TamanduaServer.{Tenants}
  alias TamanduaServer.Accounts.{APIKey}

  @behaviour Plug

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, opts) do
    preload_org = Keyword.get(opts, :preload_org, false)
    allow_system = Keyword.get(opts, :allow_system, false)
    require_active = Keyword.get(opts, :require_active, true)

    conn
    |> extract_tenant(allow_system)
    |> validate_tenant(require_active)
    |> maybe_preload_organization(preload_org)
    |> check_tenant_result()
  end

  # ---------------------------------------------------------------------------
  # Tenant Extraction
  # ---------------------------------------------------------------------------

  defp extract_tenant(conn, allow_system) do
    cond do
      # 1. Check for API key authentication
      api_key_result = get_api_key_tenant(conn) ->
        handle_api_key_result(conn, api_key_result)

      # 2. Check for user session
      user = conn.assigns[:current_user] ->
        handle_user_tenant(conn, user)

      # 3. Allow system access if configured
      allow_system ->
        {:ok, assign(conn, :current_organization_id, nil)}

      # 4. No tenant found
      true ->
        {:error, conn, :no_tenant}
    end
  end

  defp get_api_key_tenant(conn) do
    case get_req_header(conn, "x-api-key") do
      [raw_key] ->
        Tenants.find_api_key_by_value(raw_key)

      _ ->
        nil
    end
  end

  defp handle_api_key_result(conn, {:ok, %APIKey{} = api_key}) do
    if APIKey.valid?(api_key) do
      # Check IP restriction
      client_ip = get_client_ip(conn)
      if APIKey.ip_allowed?(api_key, client_ip) do
        # Update last used timestamp asynchronously
        Task.start(fn -> Tenants.touch_api_key(api_key) end)

        conn =
          conn
          |> assign(:current_organization_id, api_key.organization_id)
          |> assign(:current_api_key, api_key)
          |> assign(:auth_method, :api_key)

        {:ok, conn}
      else
        {:error, conn, :ip_not_allowed}
      end
    else
      {:error, conn, :api_key_invalid}
    end
  end

  defp handle_api_key_result(conn, {:error, reason}) do
    {:error, conn, reason}
  end

  defp handle_api_key_result(_conn, nil) do
    nil  # No API key provided, continue to next method
  end

  defp handle_user_tenant(conn, user) do
    if user.organization_id do
      conn =
        conn
        |> assign(:current_organization_id, user.organization_id)
        |> assign(:auth_method, :session)

      {:ok, conn}
    else
      {:error, conn, :user_no_organization}
    end
  end

  # ---------------------------------------------------------------------------
  # Tenant Validation
  # ---------------------------------------------------------------------------

  defp validate_tenant({:ok, conn}, require_active) do
    org_id = conn.assigns[:current_organization_id]

    cond do
      is_nil(org_id) ->
        # System access, no validation needed
        {:ok, conn}

      require_active ->
        case Tenants.get_organization(org_id) do
          {:ok, org} ->
            if Tenants.organization_active?(org) do
              {:ok, conn}
            else
              {:error, conn, :organization_suspended}
            end

          {:error, :not_found} ->
            {:error, conn, :organization_not_found}
        end

      true ->
        {:ok, conn}
    end
  end

  defp validate_tenant(error, _require_active), do: error

  # ---------------------------------------------------------------------------
  # Organization Preloading
  # ---------------------------------------------------------------------------

  defp maybe_preload_organization({:ok, conn}, true) do
    org_id = conn.assigns[:current_organization_id]

    if org_id do
      case Tenants.get_organization(org_id) do
        {:ok, org} ->
          {:ok, assign(conn, :current_organization, org)}

        {:error, _} ->
          {:ok, conn}
      end
    else
      {:ok, conn}
    end
  end

  defp maybe_preload_organization(result, _preload), do: result

  # ---------------------------------------------------------------------------
  # Result Handling
  # ---------------------------------------------------------------------------

  defp check_tenant_result({:ok, conn}), do: conn

  defp check_tenant_result({:error, conn, reason}) do
    {status, message} = error_response(reason)

    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(%{error: message, code: to_string(reason)}))
    |> halt()
  end

  defp error_response(:no_tenant) do
    {401, "Authentication required"}
  end

  defp error_response(:invalid_key) do
    {401, "Invalid API key"}
  end

  defp error_response(:invalid_key_format) do
    {401, "Invalid API key format"}
  end

  defp error_response(:api_key_invalid) do
    {401, "API key is expired or inactive"}
  end

  defp error_response(:ip_not_allowed) do
    {403, "Request IP not allowed for this API key"}
  end

  defp error_response(:user_no_organization) do
    {403, "User is not associated with any organization"}
  end

  defp error_response(:organization_suspended) do
    {403, "Organization is suspended"}
  end

  defp error_response(:organization_not_found) do
    {404, "Organization not found"}
  end

  defp error_response(_) do
    {500, "Internal server error"}
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp get_client_ip(conn) do
    # Check for forwarded headers first (for proxies/load balancers)
    forwarded_for =
      conn
      |> get_req_header("x-forwarded-for")
      |> List.first()

    if forwarded_for do
      forwarded_for
      |> String.split(",")
      |> List.first()
      |> String.trim()
    else
      conn.remote_ip
      |> :inet.ntoa()
      |> to_string()
    end
  end
end
