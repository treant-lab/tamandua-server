defmodule TamanduaServerWeb.API.V1.LateralMovementController do
  @moduledoc """
  Controller for Lateral Movement Detection and Path Analysis API endpoints.

  Provides access to the host-to-host movement graph, BFS/DFS path analysis,
  blast radius computation, choke-point identification, anomaly listing, and
  attack path simulation.

  ## Endpoints

  - GET  /api/v1/lateral-movement/graph             - Full movement graph
  - GET  /api/v1/lateral-movement/paths/:source_ip   - Paths from source IP
  - GET  /api/v1/lateral-movement/blast-radius/:host_ip - Reachable hosts
  - GET  /api/v1/lateral-movement/choke-points       - Network bottlenecks
  - GET  /api/v1/lateral-movement/anomalies           - Detected anomalies
  - GET  /api/v1/lateral-movement/stats               - Summary statistics
  - POST /api/v1/lateral-movement/simulate            - Simulate attack path
  """
  use TamanduaServerWeb, :controller

  alias TamanduaServer.Detection.LateralMovement

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  Return the lateral movement graph (directed edges between hosts).

  ## Query Parameters
  - `limit`    - Maximum edges to return (default 1000)
  - `since`    - Only edges newer than N seconds ago (integer)
  - `protocol` - Filter by protocol: rdp, smb, ssh, wmi, winrm, psexec, etc.
  """
  def graph(conn, params) do
    opts = [
      limit: parse_int(params["limit"], 1000),
      since: parse_since(params["since"]),
      protocol: params["protocol"]
    ]

    edges = LateralMovement.get_graph(opts)

    json(conn, %{
      data: serialize_edges(edges),
      meta: %{
        count: length(edges),
        limit: opts[:limit],
        protocol: opts[:protocol]
      }
    })
  end

  @doc """
  Find all lateral movement paths originating from `source_ip`.

  ## Path Parameters
  - `source_ip` - The IP to trace paths from

  ## Query Parameters
  - `max_depth` - Maximum hops (default 12)
  - `target_ip` - Optional destination IP to filter paths
  """
  def paths(conn, %{"source_ip" => source_ip} = params) do
    opts = [
      max_depth: parse_int(params["max_depth"], 12),
      target_ip: params["target_ip"]
    ]

    result = LateralMovement.find_paths(source_ip, opts)

    json(conn, %{
      data: %{
        source: result.source,
        target: result.target,
        max_depth: result.max_depth,
        path_count: result.path_count,
        paths: serialize_paths(result.paths),
        highest_risk_path: serialize_path(result.highest_risk_path)
      }
    })
  end

  @doc """
  Compute blast radius (all reachable hosts) from `host_ip`.

  ## Path Parameters
  - `host_ip` - The compromised host IP to analyze
  """
  def blast_radius(conn, %{"host_ip" => host_ip}) do
    result = LateralMovement.blast_radius(host_ip)

    json(conn, %{
      data: %{
        source: result.source,
        reachable_count: result.reachable_count,
        critical_hosts_reachable: result.critical_hosts_reachable,
        max_depth: result.max_depth,
        reachable_hosts: result.reachable_hosts
      }
    })
  end

  @doc """
  Identify network choke points (hosts that bridge segments).

  Returns hosts sorted by their choke score (betweenness centrality
  approximation multiplied by degree and asset criticality).
  """
  def choke_points(conn, _params) do
    points = LateralMovement.choke_points()

    json(conn, %{
      data: points,
      meta: %{count: length(points)}
    })
  end

  @doc """
  List detected lateral movement anomalies.

  ## Query Parameters
  - `limit`    - Maximum anomalies to return (default 200)
  - `severity` - Filter by severity: low, medium, high, critical
  """
  def anomalies(conn, params) do
    opts = [
      limit: parse_int(params["limit"], 200),
      severity: params["severity"]
    ]

    anomalies = LateralMovement.get_anomalies(opts)

    json(conn, %{
      data: serialize_anomalies(anomalies),
      meta: %{
        count: length(anomalies),
        limit: opts[:limit],
        severity_filter: opts[:severity]
      }
    })
  end

  @doc """
  Return summary statistics for the lateral movement engine.
  """
  def stats(conn, _params) do
    stats = LateralMovement.stats()

    json(conn, %{data: stats})
  end

  @doc """
  Simulate an attack path from a source IP towards one or more targets.

  ## Request Body
  - `source_ip` - The starting IP for the simulation (required)
  - `targets`   - List of target IPs (required)
  - `max_depth` - Maximum hops (default 12)
  - `protocol`  - Optional protocol filter
  """
  def simulate(conn, params) do
    source_ip = params["source_ip"]
    targets = params["targets"] || []

    unless source_ip && is_list(targets) && length(targets) > 0 do
      conn
      |> put_status(:bad_request)
      |> json(%{error: "source_ip and targets (non-empty list) are required"})
    else
      opts = [
        max_depth: parse_int(params["max_depth"], 12),
        protocol: params["protocol"]
      ]

      result = LateralMovement.simulate(source_ip, targets, opts)

      json(conn, %{
        data: %{
          source: result.source,
          reachable_count: result.reachable_count,
          total_targets: result.total_targets,
          overall_risk: result.overall_risk,
          max_depth: result.max_depth,
          simulated_at: DateTime.to_iso8601(result.simulated_at),
          targets: Enum.map(result.targets, fn t ->
            %{
              target: t.target,
              reachable: t.reachable,
              path: t.path,
              hop_count: t.hop_count,
              risk_score: t.risk_score,
              protocols_used: t.protocols_used,
              criticality: t.criticality
            }
          end)
        }
      })
    end
  end

  # ===========================================================================
  # Serialization helpers
  # ===========================================================================

  defp serialize_edges(edges) do
    Enum.map(edges, fn edge ->
      %{
        source_ip: edge.source_ip,
        dest_ip: edge.dest_ip,
        protocol: edge.protocol,
        port: edge.port,
        agent_id: edge.agent_id,
        timestamp: safe_to_iso8601(edge.timestamp),
        username: edge.username,
        credential_type: edge.credential_type,
        event_type: edge.event_type
      }
    end)
  end

  defp serialize_paths(paths) do
    Enum.map(paths, &serialize_path/1)
  end

  defp serialize_path(nil), do: nil
  defp serialize_path(path) do
    %{
      path: path.path,
      hop_count: path.hop_count,
      risk_score: path.risk_score,
      protocols: path.protocols,
      island_hopping: path.island_hopping,
      hops: Enum.map(path.hops, fn hop ->
        %{
          source: hop[:source],
          destination: hop[:destination],
          protocol: hop[:protocol],
          port: hop[:port],
          username: hop[:username],
          timestamp: safe_to_iso8601(hop[:timestamp]),
          risk_score: hop[:risk_score],
          mitre: hop[:mitre]
        }
      end)
    }
  end

  defp serialize_anomalies(anomalies) do
    Enum.map(anomalies, fn a ->
      %{
        type: a.type,
        severity: a.severity,
        description: a.description,
        source_ip: a.source_ip,
        dest_ip: a.dest_ip,
        protocol: a.protocol,
        port: a.port,
        username: a.username,
        agent_id: a.agent_id,
        detected_at: safe_to_iso8601(a.detected_at),
        mitre_technique: a[:mitre_technique],
        unique_destinations: a[:unique_destinations]
      }
    end)
  end

  # ===========================================================================
  # Utility
  # ===========================================================================

  defp parse_int(nil, default), do: default
  defp parse_int(val, default) when is_binary(val) do
    case Integer.parse(val) do
      {n, _} -> n
      :error -> default
    end
  end
  defp parse_int(val, _default) when is_integer(val), do: val
  defp parse_int(_, default), do: default

  defp parse_since(nil), do: nil
  defp parse_since(val) when is_binary(val) do
    case Integer.parse(val) do
      {n, _} -> n
      :error -> nil
    end
  end
  defp parse_since(val) when is_integer(val), do: val
  defp parse_since(_), do: nil

  defp safe_to_iso8601(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp safe_to_iso8601(_), do: nil
end
