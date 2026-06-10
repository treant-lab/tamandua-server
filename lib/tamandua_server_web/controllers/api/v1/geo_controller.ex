defmodule TamanduaServerWeb.API.V1.GeoController do
  @moduledoc """
  API controller for geographic threat data.

  Provides endpoints for the threat map visualization, including:
  - Threat origins by geographic location
  - Agent locations
  - Threat flow connections
  - Summary statistics
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Enrichment.GeoStats

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  Get threat origins with geographic data.

  GET /api/v1/geo/threats

  Query parameters:
  - timeframe: "1h", "6h", "24h", "7d", "30d" (default: "24h")
  - severity: Filter by minimum severity (critical, high, medium, low)
  """
  def threat_origins(conn, params) do
    timeframe = params["timeframe"] || "24h"
    opts = build_opts(conn, params)

    threats = safe_geo_fetch(:threat_origins, [], fn -> GeoStats.get_threat_origins(timeframe, opts) end)
    agents = safe_geo_fetch(:agent_locations, [], fn -> GeoStats.get_agent_locations(opts) end)
    summary = safe_geo_fetch(:summary, empty_summary(timeframe), fn -> GeoStats.get_summary(timeframe, opts) end)

    json(conn, %{
      data: %{
        threats: serialize_threats(threats),
        agents: serialize_agents(agents),
        summary: serialize_summary(summary)
      }
    })
  end

  @doc """
  Get agent locations for map markers.

  GET /api/v1/geo/agents

  Query parameters:
  - status: Filter by status (online, offline, isolated)
  """
  def agent_locations(conn, params) do
    opts = build_opts(conn, params)
    agents = safe_geo_fetch(:agent_locations, [], fn -> GeoStats.get_agent_locations(opts) end)

    json(conn, %{
      data: serialize_agents(agents)
    })
  end

  @doc """
  Get threat flow connections for animated map lines.

  GET /api/v1/geo/flows

  Query parameters:
  - timeframe: "1h", "6h", "24h", "7d", "30d" (default: "24h")
  """
  def threat_flows(conn, params) do
    timeframe = params["timeframe"] || "24h"
    opts = build_opts(conn, params)

    flows = safe_geo_fetch(:threat_flows, [], fn -> GeoStats.get_threat_flows(timeframe, opts) end)

    json(conn, %{
      data: serialize_flows(flows)
    })
  end

  @doc """
  Get summary statistics for the threat map.

  GET /api/v1/geo/summary

  Query parameters:
  - timeframe: "1h", "6h", "24h", "7d", "30d" (default: "24h")
  """
  def summary(conn, params) do
    timeframe = params["timeframe"] || "24h"
    opts = build_opts(conn, params)

    summary = safe_geo_fetch(:summary, empty_summary(timeframe), fn -> GeoStats.get_summary(timeframe, opts) end)

    json(conn, %{
      data: serialize_summary(summary)
    })
  end

  @doc """
  Get all geo data for the threat map in a single request.

  GET /api/v1/geo/map

  Query parameters:
  - timeframe: "1h", "6h", "24h", "7d", "30d" (default: "24h")
  - severity: Filter by minimum severity

  Returns threats, agents, flows, and summary in one response.
  """
  def map_data(conn, params) do
    timeframe = params["timeframe"] || "24h"
    opts = build_opts(conn, params)

    # Fetch all data
    threats = safe_geo_fetch(:threat_origins, [], fn -> GeoStats.get_threat_origins(timeframe, opts) end)
    agents = safe_geo_fetch(:agent_locations, [], fn -> GeoStats.get_agent_locations(opts) end)
    flows = safe_geo_fetch(:threat_flows, [], fn -> GeoStats.get_threat_flows(timeframe, opts) end)
    summary = safe_geo_fetch(:summary, empty_summary(timeframe), fn -> GeoStats.get_summary(timeframe, opts) end)

    json(conn, %{
      data: %{
        threats: serialize_threats(threats),
        agents: serialize_agents(agents),
        flows: serialize_flows(flows),
        summary: serialize_summary(summary),
        timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
      }
    })
  end

  # Private helpers

  defp build_opts(conn, params) do
    opts = []

    # Add organization filter if present in assigns (from auth)
    opts = if org_id = conn.assigns[:organization_id] do
      Keyword.put(opts, :organization_id, org_id)
    else
      opts
    end

    # Add severity filter if provided
    opts = if severity = params["severity"] do
      Keyword.put(opts, :severity, severity)
    else
      opts
    end

    # Add status filter if provided
    opts = if status = params["status"] do
      Keyword.put(opts, :status, status)
    else
      opts
    end

    opts
  end

  defp serialize_threats(threats) do
    Enum.map(threats, fn threat ->
      %{
        source_lat: threat.source_lat,
        source_lon: threat.source_lon,
        source_country: threat.source_country,
        source_country_name: threat[:source_country_name] || threat.source_country,
        threat_type: threat.threat_type,
        count: threat.count,
        severity: threat.severity,
        last_seen: format_datetime(threat[:last_seen])
      }
    end)
  end

  defp serialize_agents(agents) do
    Enum.map(agents, fn agent ->
      %{
        agent_id: agent.agent_id,
        lat: agent.lat,
        lon: agent.lon,
        hostname: agent.hostname,
        status: agent.status,
        country_code: agent[:country_code],
        city: agent[:city],
        os_type: agent[:os_type],
        last_seen: format_datetime(agent[:last_seen])
      }
    end)
  end

  defp serialize_flows(flows) do
    Enum.map(flows, fn flow ->
      %{
        id: flow.id,
        source: flow.source,
        target: flow.target,
        threat_type: flow.threat_type,
        severity: flow.severity,
        count: flow.count
      }
    end)
  end

  defp serialize_summary(summary) do
    %{
      top_countries: summary.top_countries,
      total_threats: summary.total_threats,
      unique_sources: summary.unique_sources,
      unique_threat_types: summary[:unique_threat_types] || 0,
      agents_online: summary[:agents_online] || 0,
      agents_total: summary[:agents_total] || 0,
      severity_counts: summary[:severity_counts] || %{},
      timeframe: summary[:timeframe] || "24h"
    }
  end

  defp format_datetime(nil), do: nil
  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp format_datetime(%NaiveDateTime{} = dt), do: NaiveDateTime.to_iso8601(dt)
  defp format_datetime(other), do: other

  defp safe_geo_fetch(label, fallback, fun) do
    fun.()
  rescue
    exception ->
      require Logger
      Logger.warning("Geo controller #{label} failed: #{Exception.message(exception)}")
      fallback
  catch
    kind, reason ->
      require Logger
      Logger.warning("Geo controller #{label} failed: #{kind} #{inspect(reason)}")
      fallback
  end

  defp empty_summary(timeframe) do
    %{
      top_countries: [],
      total_threats: 0,
      unique_sources: 0,
      unique_threat_types: 0,
      agents_online: 0,
      agents_total: 0,
      severity_counts: %{},
      timeframe: timeframe
    }
  end
end
