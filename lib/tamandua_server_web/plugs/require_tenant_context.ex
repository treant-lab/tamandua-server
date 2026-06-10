defmodule TamanduaServerWeb.Plugs.RequireTenantContext do
  @moduledoc """
  Enforces tenant context is set before allowing API access.

  Unlike the permissive SetOrganizationContext plug, this plug HALTS
  requests if tenant context is not set. This provides defense-in-depth
  by ensuring all authenticated API requests operate within a tenant scope.

  ## Usage

  Add to router pipeline after authentication and SetOrganizationContext:

      pipeline :api do
        plug :accepts, ["json"]
        plug TamanduaServerWeb.Plugs.APIAuth
        plug TamanduaServerWeb.Plugs.SetOrganizationContext
        plug TamanduaServerWeb.Plugs.RequireTenantContext
      end

  ## Options

    - `:except` - List of path prefixes to skip (e.g., ["/api/v1/health"])
                  These routes bypass the tenant context requirement.

  ## Response

  If tenant context is missing, returns 403 Forbidden:

      {
        "error": "tenant_context_required",
        "message": "Request must be scoped to a tenant organization"
      }

  If organization_id is invalid UUID format, returns 400 Bad Request:

      {
        "error": "invalid_tenant_context",
        "message": "Organization ID must be a valid UUID"
      }

  ## Security Considerations

  - Always place after authentication plugs
  - Use :except sparingly, only for truly public routes
  - Log all enforcement failures for security monitoring
  - Combined with RLS, provides defense-in-depth isolation
  """

  import Plug.Conn

  require Logger

  @behaviour Plug

  @doc """
  Initializes the plug with options.

  ## Options

    - `:except` - List of path prefixes to skip enforcement
  """
  @impl Plug
  def init(opts) do
    %{
      except: Keyword.get(opts, :except, [])
    }
  end

  @doc """
  Checks for tenant context and halts if missing.

  Checks conn.assigns for :current_organization_id which should have been
  set by SetOrganizationContext plug. If missing or invalid, halts with
  appropriate error response.
  """
  @impl Plug
  def call(conn, opts) do
    if path_excepted?(conn.request_path, opts.except) do
      conn
    else
      check_tenant_context(conn)
    end
  end

  # Private Functions

  defp check_tenant_context(conn) do
    case Map.get(conn.assigns, :current_organization_id) do
      nil ->
        Logger.warning(
          "Tenant context enforcement failed: " <>
            "path=#{conn.request_path} " <>
            "method=#{conn.method} " <>
            "reason=missing_organization_id"
        )

        conn
        |> put_status(:forbidden)
        |> put_resp_content_type("application/json")
        |> send_resp(403, Jason.encode!(%{
          error: "tenant_context_required",
          message: "Request must be scoped to a tenant organization"
        }))
        |> halt()

      org_id when is_binary(org_id) ->
        if valid_uuid?(org_id) do
          conn
        else
          Logger.warning(
            "Tenant context enforcement failed: " <>
              "path=#{conn.request_path} " <>
              "method=#{conn.method} " <>
              "reason=invalid_uuid " <>
              "value=#{inspect(org_id)}"
          )

          conn
          |> put_status(:bad_request)
          |> put_resp_content_type("application/json")
          |> send_resp(400, Jason.encode!(%{
            error: "invalid_tenant_context",
            message: "Organization ID must be a valid UUID"
          }))
          |> halt()
        end

      other ->
        Logger.warning(
          "Tenant context enforcement failed: " <>
            "path=#{conn.request_path} " <>
            "method=#{conn.method} " <>
            "reason=invalid_type " <>
            "value=#{inspect(other)}"
        )

        conn
        |> put_status(:bad_request)
        |> put_resp_content_type("application/json")
        |> send_resp(400, Jason.encode!(%{
          error: "invalid_tenant_context",
          message: "Organization ID must be a valid UUID"
        }))
        |> halt()
    end
  end

  defp path_excepted?(request_path, except_list) do
    Enum.any?(except_list, fn prefix ->
      String.starts_with?(request_path, prefix)
    end)
  end

  defp valid_uuid?(value) when is_binary(value) do
    case Ecto.UUID.cast(value) do
      {:ok, _} -> true
      :error -> false
    end
  end

  defp valid_uuid?(_), do: false
end
