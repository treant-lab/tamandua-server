defmodule TamanduaServerWeb.API.V1.RateLimitController do
  @moduledoc """
  API controller for viewing and managing tenant rate limits.

  Rate limits are configured per-organization based on license tier.
  Admins can view current limits and usage statistics.
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Tenants
  alias TamanduaServer.Accounts.TenantRateLimit

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  Shows the current rate limits for the organization.
  """
  def show(conn, _params) do
    org_id = conn.assigns.current_organization_id

    case Tenants.get_rate_limits(org_id) do
      {:ok, limits} ->
        json(conn, %{
          data: serialize_limits(limits),
          tier_defaults: %{
            trial: TenantRateLimit.defaults_for_tier(:trial),
            pro: TenantRateLimit.defaults_for_tier(:pro),
            enterprise: TenantRateLimit.defaults_for_tier(:enterprise)
          }
        })

      {:error, :not_found} ->
        # Return defaults if no custom limits configured
        org = conn.assigns.current_organization
        tier = org && org.license_tier || :trial
        defaults = TenantRateLimit.defaults_for_tier(tier)

        json(conn, %{
          data: Map.merge(defaults, %{
            organization_id: org_id,
            configured: false
          }),
          tier_defaults: %{
            trial: TenantRateLimit.defaults_for_tier(:trial),
            pro: TenantRateLimit.defaults_for_tier(:pro),
            enterprise: TenantRateLimit.defaults_for_tier(:enterprise)
          }
        })
    end
  end

  @doc """
  Updates rate limits for the organization.

  Only organization admins can update rate limits.
  """
  def update(conn, %{"rate_limits" => params}) do
    org_id = conn.assigns.current_organization_id

    # Ensure admin permission
    user = conn.assigns.current_user
    unless user && user.role in ["admin", "owner"] do
      conn
      |> put_status(:forbidden)
      |> json(%{error: "Only administrators can update rate limits"})
    else
      case Tenants.get_rate_limits(org_id) do
        {:ok, limits} ->
          with {:ok, updated} <- Tenants.update_rate_limits(limits, params) do
            json(conn, %{
              data: serialize_limits(updated),
              message: "Rate limits updated"
            })
          end

        {:error, :not_found} ->
          # Create new limits
          params = Map.put(params, "organization_id", org_id)
          with {:ok, limits} <- create_rate_limits(params) do
            conn
            |> put_status(:created)
            |> json(%{
              data: serialize_limits(limits),
              message: "Rate limits created"
            })
          end
      end
    end
  end

  def update(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing rate_limits parameter"})
  end

  defp create_rate_limits(params) do
    struct(TenantRateLimit)
    |> TenantRateLimit.changeset(params)
    |> TamanduaServer.Repo.insert()
  end

  defp serialize_limits(limits) when is_map(limits) do
    %{
      id: limits.id,
      organization_id: limits.organization_id,
      api_requests_per_minute: limits.api_requests_per_minute,
      api_requests_per_hour: limits.api_requests_per_hour,
      api_requests_per_day: limits.api_requests_per_day,
      events_per_minute: limits.events_per_minute,
      events_per_hour: limits.events_per_hour,
      alert_webhooks_per_hour: limits.alert_webhooks_per_hour,
      max_events_retained_days: limits.max_events_retained_days,
      max_storage_gb: limits.max_storage_gb,
      max_concurrent_hunts: limits.max_concurrent_hunts,
      max_playbooks: limits.max_playbooks,
      max_sigma_rules: limits.max_sigma_rules,
      max_yara_rules: limits.max_yara_rules,
      max_api_keys: limits.max_api_keys,
      configured: true,
      inserted_at: limits.inserted_at,
      updated_at: limits.updated_at
    }
  end
end
