defmodule TamanduaServerWeb.API.V1.ProvenanceController do
  use TamanduaServerWeb, :controller

  alias TamanduaServer.Detection.Provenance

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  GET /api/v1/provenance/:agent_id/chain/:entity_id

  Walk backward from an entity to find root cause (provenance chain).
  Returns all causal ancestors up to `max_hops` depth.

  Query params:
    - max_hops: Maximum traversal depth (default: 10)
  """
  def chain(conn, %{"agent_id" => agent_id, "entity_id" => entity_id} = params) do
    max_hops = parse_int(params["max_hops"], 10)

    case Provenance.get_provenance_chain(agent_id, entity_id, max_hops: max_hops) do
      {:ok, result} ->
        json(conn, %{data: serialize_graph_result(result)})

      {:error, :entity_not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Entity not found", entity_id: entity_id})
    end
  end

  @doc """
  GET /api/v1/provenance/:agent_id/impact/:entity_id

  Walk forward from an entity to find all affected entities (impact graph).
  Returns all causally downstream entities up to `max_hops` depth.

  Query params:
    - max_hops: Maximum traversal depth (default: 10)
  """
  def impact(conn, %{"agent_id" => agent_id, "entity_id" => entity_id} = params) do
    max_hops = parse_int(params["max_hops"], 10)

    case Provenance.get_impact_graph(agent_id, entity_id, max_hops: max_hops) do
      {:ok, result} ->
        json(conn, %{data: serialize_graph_result(result)})

      {:error, :entity_not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Entity not found", entity_id: entity_id})
    end
  end

  @doc """
  GET /api/v1/provenance/:agent_id/attack-chains

  Find attack chain patterns in the provenance graph.
  Matches known attack patterns (download->execute->persist, inject->C2, etc.)
  against the graph and returns all matches.
  """
  def attack_chains(conn, %{"agent_id" => agent_id}) do
    case Provenance.find_attack_chains(agent_id) do
      {:ok, chains} ->
        json(conn, %{
          data: Enum.map(chains, &serialize_attack_chain/1),
          total: length(chains)
        })

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Failed to find attack chains", reason: inspect(reason)})
    end
  end

  @doc """
  GET /api/v1/provenance/:agent_id/context/:entity_id

  Get all related entities within N hops of a given entity (bidirectional).
  Returns the local neighborhood subgraph for contextual investigation.

  Query params:
    - max_hops: Maximum traversal depth in each direction (default: 3)
  """
  def context(conn, %{"agent_id" => agent_id, "entity_id" => entity_id} = params) do
    max_hops = parse_int(params["max_hops"], 3)

    case Provenance.get_entity_context(agent_id, entity_id, max_hops: max_hops) do
      {:ok, result} ->
        json(conn, %{data: serialize_graph_result(result)})

      {:error, :entity_not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Entity not found", entity_id: entity_id})
    end
  end

  @doc """
  GET /api/v1/provenance/:agent_id/blame/:entity_id

  Trace back to root cause with confidence scoring.
  Returns a blame chain with cumulative confidence for each link.

  Query params:
    - max_hops: Maximum traversal depth (default: 10)
  """
  def blame(conn, %{"agent_id" => agent_id, "entity_id" => entity_id} = params) do
    max_hops = parse_int(params["max_hops"], 10)

    case Provenance.blame_assignment(agent_id, entity_id, max_hops: max_hops) do
      {:ok, result} ->
        json(conn, %{data: serialize_blame_result(result)})

      {:error, :entity_not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Entity not found", entity_id: entity_id})
    end
  end

  @doc """
  GET /api/v1/provenance/:agent_id/stats

  Get graph statistics for an agent (node count, edge count, components).
  """
  def stats(conn, %{"agent_id" => agent_id}) do
    case Provenance.get_stats(agent_id) do
      {:ok, stats} ->
        json(conn, %{data: serialize_stats(stats)})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Failed to get stats", reason: inspect(reason)})
    end
  end

  # ---------------------------------------------------------------------------
  # Serialization helpers
  # ---------------------------------------------------------------------------

  defp serialize_graph_result(result) do
    %{
      entity_id: result.entity_id,
      entity: serialize_node(result.entity),
      nodes: Enum.map(result.nodes, &serialize_node/1),
      edges: Enum.map(result.edges, &serialize_edge/1),
      node_count: result.node_count,
      edge_count: result.edge_count
    }
  end

  defp serialize_node(nil), do: nil

  defp serialize_node(node) do
    %{
      id: Map.get(node, :id) || node.entity_id,
      entity_type: node.entity_type,
      entity_id: node.entity_id,
      attributes: node.attributes,
      first_seen: format_timestamp(node.first_seen),
      last_seen: format_timestamp(node.last_seen)
    }
  end

  defp serialize_edge(edge) do
    %{
      source: edge.source,
      target: edge.target,
      edge_type: edge.edge_type,
      timestamp: format_timestamp(edge.timestamp),
      confidence: edge.confidence
    }
  end

  defp serialize_attack_chain(chain) do
    %{
      pattern_name: chain.pattern_name,
      description: chain.description,
      mitre_techniques: chain.mitre_techniques,
      severity: chain.severity,
      chain_length: chain.chain_length,
      start_entity: chain.start_entity,
      chain_path: chain.chain_path,
      nodes: Enum.map(chain.nodes, &serialize_node/1)
    }
  end

  defp serialize_blame_result(result) do
    %{
      entity_id: result.entity_id,
      entity: serialize_node(result.entity),
      root_cause: if(result.root_cause, do: serialize_blame_entry(result.root_cause), else: nil),
      blame_chain: Enum.map(result.blame_chain, &serialize_blame_entry/1),
      chain_length: result.chain_length
    }
  end

  defp serialize_blame_entry(entry) do
    %{
      entity_id: entry.entity_id,
      entity: serialize_node(entry.entity),
      cumulative_confidence: entry.cumulative_confidence,
      edge_type: Map.get(entry, :edge_type),
      is_root: entry.is_root,
      depth: entry.depth
    }
  end

  defp serialize_stats(stats) do
    %{
      agent_id: stats.agent_id,
      node_count: stats.node_count,
      edge_count: stats.edge_count,
      connected_components: stats.connected_components,
      nodes_by_type: stats.nodes_by_type,
      edges_by_type: stats.edges_by_type,
      computed_at: format_timestamp(stats.computed_at)
    }
  end

  defp format_timestamp(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp format_timestamp(%NaiveDateTime{} = ndt), do: NaiveDateTime.to_iso8601(ndt)
  defp format_timestamp(ts) when is_integer(ts) do
    case DateTime.from_unix(ts, :millisecond) do
      {:ok, dt} -> DateTime.to_iso8601(dt)
      _ -> ts
    end
  end
  defp format_timestamp(other), do: other

  defp parse_int(nil, default), do: default
  defp parse_int(val, default) when is_binary(val) do
    case Integer.parse(val) do
      {int, _} -> int
      :error -> default
    end
  end
  defp parse_int(val, _default) when is_integer(val), do: val
  defp parse_int(_, default), do: default
end
