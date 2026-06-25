defmodule TamanduaServerWeb.API.V1.MSSPController do
  @moduledoc """
  MSSP (Managed Security Service Provider) Portal API Controller.

  Provides endpoints for MSSP operators to manage multiple tenant
  organizations from a single dashboard. Used by the MSSPPortal.tsx
  frontend page.

  Delegates to the TamanduaServer.Tenants context for data access.
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Repo
  alias TamanduaServer.Accounts.{Organization, User}
  alias TamanduaServer.TenantScope

  import Ecto.Query

  action_fallback TamanduaServerWeb.FallbackController

  # MSSP endpoints require system-level admin permissions
  plug TamanduaServerWeb.Plugs.RBAC, permission: :system_settings

  @doc """
  List all tenants for the MSSP portal.

  Returns enriched tenant data matching the Tenant interface
  expected by MSSPPortal.tsx, including agent counts, health scores,
  alert counts, and license information.

  ## Query Parameters
  - `status` - Filter by status (active, suspended, trial, expired)
  - `tier` - Filter by license tier (trial, pro, enterprise)
  - `search` - Search by name or slug
  """
  def tenants(conn, params) do
    query = from(o in Organization, order_by: [asc: o.name])

    # Status filter
    query =
      case Map.get(params, "status") do
        "active" -> from o in query, where: o.is_active == true
        "suspended" -> from o in query, where: o.is_active == false
        "trial" -> from o in query, where: o.license_tier == :trial
        _ -> query
      end

    # Tier filter
    query =
      case Map.get(params, "tier") do
        nil -> query
        "" -> query
        tier ->
          case parse_license_tier(tier) do
            nil -> from o in query, where: false
            parsed -> from o in query, where: o.license_tier == ^parsed
          end
      end

    # Search filter
    query =
      case Map.get(params, "search") do
        nil -> query
        "" -> query
        term ->
          search_term = "%#{term}%"
          from o in query,
            where: ilike(o.name, ^search_term) or ilike(o.slug, ^search_term)
      end

    organizations = Repo.all(query)

    tenants = Enum.map(organizations, &serialize_mssp_tenant/1)

    json(conn, %{data: tenants, total: length(tenants)})
  end

  @doc """
  Cross-tenant search.

  Searches across all tenant organizations for alerts, events, agents,
  and users matching the given query.

  ## Query Parameters
  - `q` - Search query (minimum 3 characters)
  """
  def search(conn, params) do
    query = params |> Map.get("q", "") |> to_string() |> String.slice(0, 256)

    if String.length(query) < 3 do
      json(conn, %{data: [], total: 0, message: "Search query must be at least 3 characters"})
    else
      results = cross_tenant_search(query)
      json(conn, %{data: results, total: length(results)})
    end
  end

  # ===========================================================================
  # Private Helpers
  # ===========================================================================

  defp serialize_mssp_tenant(org) when is_map(org) do
    agent_count = safe_tenant_count(TamanduaServer.Agents.Agent, org.id)
    user_count = safe_tenant_count(User, org.id)
    alerts_today = count_alerts_today(org.id)
    critical_alerts = count_critical_alerts(org.id)

    %{
      id: org.id,
      name: org.name,
      slug: org.slug,
      status: mssp_status(org),
      licenseTier: to_string(org.license_tier || "trial"),
      agentCount: agent_count,
      maxAgents: org.max_agents || 5,
      userCount: user_count,
      alertsToday: alerts_today,
      criticalAlerts: critical_alerts,
      healthScore: calculate_health_score(org, agent_count, critical_alerts),
      lastActivity: format_last_activity(org.updated_at),
      subscriptionExpires: format_datetime(org.subscription_expires_at),
      features: %{
        detection: feature_enabled?(org, "detection"),
        hunting: feature_enabled?(org, "hunting"),
        playbooks: feature_enabled?(org, "playbooks"),
        api_access: feature_enabled?(org, "api_access"),
        mssp_features: feature_enabled?(org, "mssp_features")
      },
      metrics: %{
        eventsPerDay: 0,
        responseTime: 0,
        detectionRate: 0,
        mttr: 0
      }
    }
  end

  defp mssp_status(%{is_active: false}), do: "suspended"
  defp mssp_status(%{license_tier: :trial}), do: "trial"
  defp mssp_status(org) when is_map(org) do
    if Organization.subscription_active?(org), do: "active", else: "expired"
  end

  defp feature_enabled?(%{features: nil}, _key), do: false
  defp feature_enabled?(%{features: features}, key) when is_map(features) do
    Map.get(features, key, false) == true ||
      Map.get(features, feature_key(key), false) == true
  rescue
    _ -> false
  end

  defp parse_license_tier("trial"), do: :trial
  defp parse_license_tier("pro"), do: :pro
  defp parse_license_tier("enterprise"), do: :enterprise
  defp parse_license_tier(_), do: nil

  defp feature_key("detection"), do: :detection
  defp feature_key("hunting"), do: :hunting
  defp feature_key("playbooks"), do: :playbooks
  defp feature_key("api_access"), do: :api_access
  defp feature_key("mssp_features"), do: :mssp_features
  defp feature_key(_), do: nil

  defp calculate_health_score(%{is_active: false}, _agents, _critical), do: 0
  defp calculate_health_score(_org, agent_count, critical_alerts) do
    # Simple health score: start at 100, deduct for issues
    base = 100
    critical_penalty = min(critical_alerts * 10, 40)
    agent_penalty = if agent_count == 0, do: 20, else: 0

    max(0, base - critical_penalty - agent_penalty)
  end

  defp count_alerts_today(org_id) do
    today_start = DateTime.utc_now() |> DateTime.to_date() |> DateTime.new!(~T[00:00:00])

    from(a in TamanduaServer.Alerts.Alert,
      where: a.organization_id == ^org_id and a.inserted_at >= ^today_start,
      select: count()
    )
    |> Repo.one()
  rescue
    _ -> 0
  end

  defp count_critical_alerts(org_id) do
    today_start = DateTime.utc_now() |> DateTime.to_date() |> DateTime.new!(~T[00:00:00])

    from(a in TamanduaServer.Alerts.Alert,
      where: a.organization_id == ^org_id
        and a.inserted_at >= ^today_start
        and a.severity in ["critical", "high"],
      select: count()
    )
    |> Repo.one()
  rescue
    _ -> 0
  end

  defp cross_tenant_search(query) do
    search_term = "%#{query}%"

    # Search alerts across all tenants
    alert_results =
      from(a in TamanduaServer.Alerts.Alert,
        join: o in Organization, on: a.organization_id == o.id,
        where: ilike(a.title, ^search_term) or ilike(a.description, ^search_term),
        select: %{
          tenant_id: o.id,
          tenant_name: o.name,
          type: "alert",
          id: a.id,
          title: a.title,
          severity: a.severity,
          timestamp: a.inserted_at
        },
        order_by: [desc: a.inserted_at],
        limit: 20
      )
      |> Repo.all()
      |> Enum.map(fn r ->
        %{
          tenantId: r.tenant_id,
          tenantName: r.tenant_name,
          type: r.type,
          id: r.id,
          title: r.title,
          severity: r.severity,
          timestamp: format_datetime(r.timestamp)
        }
      end)

    # Search agents across all tenants
    agent_results =
      from(ag in TamanduaServer.Agents.Agent,
        join: o in Organization, on: ag.organization_id == o.id,
        where: ilike(ag.hostname, ^search_term),
        select: %{
          tenant_id: o.id,
          tenant_name: o.name,
          id: ag.id,
          title: ag.hostname,
          timestamp: ag.inserted_at
        },
        order_by: [desc: ag.inserted_at],
        limit: 10
      )
      |> Repo.all()
      |> Enum.map(fn r ->
        %{
          tenantId: r.tenant_id,
          tenantName: r.tenant_name,
          type: "agent",
          id: r.id,
          title: r.title,
          severity: nil,
          timestamp: format_datetime(r.timestamp)
        }
      end)

    (alert_results ++ agent_results)
    |> Enum.sort_by(& &1.timestamp, :desc)
    |> Enum.take(30)
  rescue
    e ->
      require Logger
      Logger.warning("Cross-tenant search failed: #{inspect(e)}")
      []
  end

  defp safe_tenant_count(schema, org_id) do
    TenantScope.count_for_tenant(schema, org_id)
  rescue
    _ -> 0
  end

  defp format_last_activity(nil), do: "Never"
  defp format_last_activity(%DateTime{} = dt) do
    DateTime.to_iso8601(dt)
  end
  defp format_last_activity(%NaiveDateTime{} = dt) do
    NaiveDateTime.to_iso8601(dt)
  end
  defp format_last_activity(other), do: to_string(other)

  defp format_datetime(nil), do: nil
  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp format_datetime(%NaiveDateTime{} = dt), do: NaiveDateTime.to_iso8601(dt)
  defp format_datetime(other), do: to_string(other)
end
