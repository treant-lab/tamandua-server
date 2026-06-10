defmodule TamanduaServerWeb.Plugs.TenantSuspension do
  @moduledoc """
  Plug to block requests from suspended tenants.

  This plug should be placed AFTER tenant context is set and BEFORE
  any business logic. It checks if the current organization is active
  and blocks with 403 if suspended or subscription expired.

  ## Suspension Reasons

  - Organization explicitly suspended (billing, compliance, security)
  - Subscription expired and grace period ended
  - Manual administrative action

  ## Blocked Response

  Requests from suspended tenants receive:

      HTTP 403 Forbidden
      {
        "error": "tenant_suspended",
        "message": "Your organization has been suspended. Please contact support."
      }

  ## Options

  - `:except` - List of path prefixes to skip checking

  ## Usage

      # In router.ex pipeline
      plug TamanduaServerWeb.Plugs.TenantSuspension,
        except: [
          "/api/v1/health",
          "/api/v1/auth"
        ]

  ## Example

      pipeline :api_auth do
        plug TamanduaServerWeb.Plugs.APIAuth
        plug TamanduaServerWeb.Plugs.SetOrganizationContext
        plug TamanduaServerWeb.Plugs.RequireTenantContext
        plug TamanduaServerWeb.Plugs.TenantSuspension  # <-- Add after context
      end
  """

  @behaviour Plug

  import Plug.Conn
  alias TamanduaServer.Tenants

  require Logger

  @impl true
  def init(opts) do
    %{
      except: Keyword.get(opts, :except, [])
    }
  end

  @impl true
  def call(conn, opts) do
    if should_check?(conn, opts) do
      check_tenant_active(conn)
    else
      conn
    end
  end

  # ===========================================================================
  # Private Helpers
  # ===========================================================================

  defp should_check?(conn, %{except: except_prefixes}) do
    path = conn.request_path
    not Enum.any?(except_prefixes, &String.starts_with?(path, &1))
  end

  defp check_tenant_active(conn) do
    case conn.assigns[:current_organization] do
      %{is_active: false} = org ->
        Logger.warning("Request blocked: tenant #{org.id} is suspended")
        block_suspended(conn)

      %{} = org ->
        # Also check subscription expiration
        if Tenants.organization_active?(org) do
          conn
        else
          Logger.warning("Request blocked: tenant #{org.id} subscription expired")
          block_expired(conn)
        end

      nil ->
        # No organization context set, let other plugs handle
        # This allows public endpoints that don't require org context
        conn
    end
  end

  defp block_suspended(conn) do
    conn
    |> put_status(:forbidden)
    |> Phoenix.Controller.json(%{
      error: "tenant_suspended",
      message: "Your organization has been suspended. Please contact support.",
      code: "TENANT_SUSPENDED"
    })
    |> halt()
  end

  defp block_expired(conn) do
    conn
    |> put_status(:forbidden)
    |> Phoenix.Controller.json(%{
      error: "subscription_expired",
      message: "Your subscription has expired. Please renew to continue.",
      code: "SUBSCRIPTION_EXPIRED"
    })
    |> halt()
  end
end
