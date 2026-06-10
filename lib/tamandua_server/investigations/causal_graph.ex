defmodule TamanduaServer.Investigations.CausalGraph do
  @moduledoc """
  Causal analysis engine for investigation storylines.

  Builds directed acyclic graphs (DAGs) of events to determine root cause,
  attack paths, and downstream impact.

  ## Edge Types

  - `spawned` - Process created another process
  - `wrote_file` - Process wrote a file to disk
  - `loaded_dll` - Process loaded a DLL/shared library
  - `connected_to` - Process made a network connection
  - `injected_into` - Process injected code into another process
  - `modified_registry` - Process modified a registry key
  - `escalated_to` - Privilege escalation from one context to another
  - `related_to` - Generic temporal/contextual relationship

  ## Graph Structure

  Nodes represent events/entities (processes, files, network connections).
  Edges represent causal relationships with directional flow (source -> target).

  The graph is returned as `%{nodes: [...], edges: [...]}` suitable for
  D3.js or similar frontend graph visualization libraries.
  """

  alias TamanduaServer.Investigations.Storyline.StoryEvent

  # Node type classification based on event type
  @node_type_map %{
    "process" => "process",
    "file" => "file",
    "network" => "network",
    "dns" => "network",
    "registry" => "registry",
    "injection" => "process",
    "alert" => "alert"
  }

  # Edge visual weight by type (for rendering)
  @edge_weights %{
    "spawned" => 5,
    "wrote_file" => 3,
    "loaded_dll" => 2,
    "connected_to" => 3,
    "injected_into" => 5,
    "modified_registry" => 2,
    "escalated_to" => 5,
    "related_to" => 1
  }

  # Severity to color mapping for visualization
  @severity_colors %{
    "critical" => "#dc2626",
    "high" => "#ea580c",
    "medium" => "#ca8a04",
    "low" => "#16a34a",
    "info" => "#6b7280"
  }

  # ====================================================================
  # Public API
  # ====================================================================

  @doc """
  Build a causal graph from a list of story events and the parent story.

  Returns a map with `:nodes` and `:edges` ready for visualization, plus
  metadata about the graph structure.

  ## Return Structure

  ```
  %{
    nodes: [%{id: ..., label: ..., type: ..., ...}],
    edges: [%{source: ..., target: ..., type: ..., ...}],
    root_cause: %{...} | nil,
    impact_summary: %{...},
    attack_path: [node_ids],
    stats: %{node_count: ..., edge_count: ..., ...}
  }
  ```
  """
  @spec build_graph([StoryEvent.t()], map()) :: map()
  def build_graph(events, story) do
    nodes = build_nodes(events)
    edges = build_edges(events, nodes)

    # Find root cause (earliest event with no incoming edges)
    root_cause = find_root_cause(nodes, edges)

    # Calculate impact chain from root cause
    impact = get_impact_chain(nodes, edges, root_cause)

    # Compute the main attack path
    attack_path = get_attack_path(nodes, edges, root_cause)

    %{
      nodes: nodes,
      edges: edges,
      root_cause: root_cause,
      impact_summary: impact,
      attack_path: attack_path,
      stats: %{
        node_count: length(nodes),
        edge_count: length(edges),
        depth: compute_graph_depth(nodes, edges),
        breadth: compute_graph_breadth(nodes, edges),
        severity_distribution: severity_distribution(nodes),
        edge_type_distribution: edge_type_distribution(edges),
        story_id: story[:id] || story.id
      }
    }
  end

  @doc """
  Find the root cause node in a causal graph.

  The root cause is the earliest event that has no incoming edges (no
  parent event caused it) -- it represents the initial entry point of
  the attack or activity chain.

  If multiple root candidates exist, the one with the earliest timestamp
  is selected.
  """
  @spec find_root_cause([map()], [map()]) :: map() | nil
  def find_root_cause(nodes, edges) do
    # IDs that are targets of some edge (they have a cause)
    target_ids = MapSet.new(edges, & &1.target)

    # Nodes that are never the target of an edge (root candidates)
    root_candidates =
      nodes
      |> Enum.reject(fn node -> MapSet.member?(target_ids, node.id) end)

    # Pick the earliest
    root_candidates
    |> Enum.sort_by(& &1.timestamp)
    |> List.first()
  end

  @doc """
  Get the impact chain -- all nodes reachable downstream from a source node.

  Performs a breadth-first traversal from the source and returns the
  affected nodes with depth information and an impact summary.
  """
  @spec get_impact_chain([map()], [map()], map() | nil) :: map()
  def get_impact_chain(_nodes, _edges, nil) do
    %{
      affected_nodes: [],
      total_affected: 0,
      max_depth: 0,
      affected_types: %{},
      severity_escalation: false
    }
  end

  def get_impact_chain(nodes, edges, source) do
    # Build adjacency list (source -> [targets])
    adj = build_adjacency_list(edges)
    node_map = Map.new(nodes, &{&1.id, &1})

    # BFS from source
    {visited, depths} = bfs(source.id, adj)

    affected =
      visited
      |> MapSet.delete(source.id)
      |> MapSet.to_list()
      |> Enum.map(fn id ->
        node = Map.get(node_map, id, %{})
        Map.put(node, :depth, Map.get(depths, id, 0))
      end)
      |> Enum.sort_by(&Map.get(&1, :depth, 0))

    max_depth = depths |> Map.values() |> Enum.max(fn -> 0 end)

    affected_types =
      affected
      |> Enum.group_by(&Map.get(&1, :type, "unknown"))
      |> Enum.map(fn {type, items} -> {type, length(items)} end)
      |> Map.new()

    # Check if severity escalated along the chain
    severities = affected |> Enum.map(&Map.get(&1, :severity, "low"))
    source_sev_ord = severity_order(source[:severity] || "low")
    escalated = Enum.any?(severities, fn sev ->
      severity_order(sev) > source_sev_ord
    end)

    %{
      affected_nodes: affected,
      total_affected: length(affected),
      max_depth: max_depth,
      affected_types: affected_types,
      severity_escalation: escalated
    }
  end

  @doc """
  Compute the main attack path through the graph.

  Returns an ordered list of node IDs representing the longest path from
  the root cause to the most severe leaf node.
  """
  @spec get_attack_path([map()], [map()], map() | nil) :: [String.t()]
  def get_attack_path(_nodes, _edges, nil), do: []

  def get_attack_path(nodes, edges, root) do
    adj = build_adjacency_list(edges)
    node_map = Map.new(nodes, &{&1.id, &1})

    # Find the most severe leaf (highest severity, then latest timestamp)
    target_ids = MapSet.new(edges, & &1.target)
    source_ids = MapSet.new(edges, & &1.source)

    leaves =
      nodes
      |> Enum.filter(fn node ->
        MapSet.member?(target_ids, node.id) or node.id == root.id
      end)
      |> Enum.reject(fn node ->
        MapSet.member?(source_ids, node.id)
      end)

    # If no real leaves, use nodes with highest severity
    target_node =
      if leaves == [] do
        nodes
        |> Enum.reject(&(&1.id == root.id))
        |> Enum.sort_by(fn n -> {-severity_order(n[:severity] || "low"), n[:timestamp]} end)
        |> List.first()
      else
        leaves
        |> Enum.sort_by(fn n -> {-severity_order(n[:severity] || "low"), n[:timestamp]} end)
        |> List.first()
      end

    if target_node do
      find_path(root.id, target_node.id, adj, node_map)
    else
      [root.id]
    end
  end

  # ====================================================================
  # Private: Node Building
  # ====================================================================

  defp build_nodes(events) do
    events
    |> Enum.map(fn event ->
      node_type = Map.get(@node_type_map, event.event_type, "unknown")
      severity = to_string(event.severity || "low")

      %{
        id: event.id,
        label: build_node_label(event),
        type: node_type,
        event_type: event.event_type,
        timestamp: event.timestamp && DateTime.to_iso8601(event.timestamp),
        severity: severity,
        score: event.score || 0.0,
        color: Map.get(@severity_colors, severity, "#6b7280"),
        # Process info
        pid: event.pid,
        ppid: event.ppid,
        process_name: event.process_name,
        process_path: event.process_path,
        cmdline: event.cmdline,
        # Network info
        remote_ip: event.remote_ip,
        remote_port: event.remote_port,
        domain: event.domain,
        # File info
        file_path: event.file_path,
        file_hash: event.file_hash,
        # MITRE
        mitre_tactic: event.mitre_tactic,
        mitre_technique: event.mitre_technique,
        # Metadata
        agent_id: event.agent_id,
        source_id: event.source_id
      }
    end)
    |> Enum.uniq_by(& &1.id)
  end

  defp build_node_label(event) do
    cond do
      event.process_name -> event.process_name
      event.domain -> event.domain
      event.remote_ip -> "#{event.remote_ip}:#{event.remote_port}"
      event.file_path -> Path.basename(to_string(event.file_path))
      true -> event.event_type || "event"
    end
  end

  # ====================================================================
  # Private: Edge Building
  # ====================================================================

  defp build_edges(events, nodes) do
    node_map = Map.new(nodes, &{&1.id, &1})
    node_by_pid = build_pid_index(nodes)

    # Strategy 1: Explicit parent_event_id links
    explicit_edges = build_explicit_edges(events)

    # Strategy 2: Process parent-child relationships (PID -> PPID)
    process_edges = build_process_edges(events, node_by_pid)

    # Strategy 3: Temporal proximity edges (events within a short time window)
    temporal_edges = build_temporal_edges(events, node_map)

    # Combine, deduplicate, and validate
    all_edges =
      (explicit_edges ++ process_edges ++ temporal_edges)
      |> Enum.uniq_by(fn edge -> {edge.source, edge.target} end)
      |> Enum.reject(fn edge -> edge.source == edge.target end)
      |> Enum.filter(fn edge ->
        Map.has_key?(node_map, edge.source) and Map.has_key?(node_map, edge.target)
      end)

    # Break cycles (ensure DAG property)
    remove_cycles(all_edges, nodes)
  end

  defp build_explicit_edges(events) do
    events
    |> Enum.filter(& &1.parent_event_id)
    |> Enum.map(fn event ->
      %{
        source: event.parent_event_id,
        target: event.id,
        type: event.edge_type || "related_to",
        weight: Map.get(@edge_weights, event.edge_type || "related_to", 1),
        label: event.edge_type || "related_to"
      }
    end)
  end

  defp build_process_edges(events, node_by_pid) do
    events
    |> Enum.filter(fn event -> event.pid && event.ppid end)
    |> Enum.flat_map(fn event ->
      parent_nodes = Map.get(node_by_pid, {event.agent_id, event.ppid}, [])

      parent_nodes
      |> Enum.filter(fn parent_node -> parent_node.id != event.id end)
      |> Enum.take(1)
      |> Enum.map(fn parent_node ->
        %{
          source: parent_node.id,
          target: event.id,
          type: "spawned",
          weight: Map.get(@edge_weights, "spawned", 5),
          label: "spawned"
        }
      end)
    end)
  end

  defp build_temporal_edges(events, _node_map) do
    # Sort events by timestamp
    sorted = Enum.sort_by(events, & &1.timestamp, DateTime)

    # Connect sequential events from the same agent within 30 seconds
    sorted
    |> Enum.chunk_every(2, 1, :discard)
    |> Enum.flat_map(fn [prev, curr] ->
      same_agent = prev.agent_id && prev.agent_id == curr.agent_id

      if same_agent && prev.timestamp && curr.timestamp do
        diff = DateTime.diff(curr.timestamp, prev.timestamp, :second)

        if diff >= 0 and diff <= 30 do
          edge_type = infer_temporal_edge_type(prev, curr)
          [%{
            source: prev.id,
            target: curr.id,
            type: edge_type,
            weight: Map.get(@edge_weights, edge_type, 1),
            label: edge_type
          }]
        else
          []
        end
      else
        []
      end
    end)
  end

  defp infer_temporal_edge_type(prev_event, curr_event) do
    cond do
      prev_event.event_type == "process" and curr_event.event_type == "process" ->
        "spawned"
      prev_event.event_type == "process" and curr_event.event_type == "file" ->
        "wrote_file"
      prev_event.event_type == "process" and curr_event.event_type in ["network", "dns"] ->
        "connected_to"
      prev_event.event_type == "process" and curr_event.event_type == "injection" ->
        "injected_into"
      prev_event.event_type == "process" and curr_event.event_type == "registry" ->
        "modified_registry"
      severity_order(curr_event.severity || "low") > severity_order(prev_event.severity || "low") ->
        "escalated_to"
      true ->
        "related_to"
    end
  end

  defp build_pid_index(nodes) do
    nodes
    |> Enum.filter(& &1.pid)
    |> Enum.group_by(fn node -> {node.agent_id, node.pid} end)
  end

  # ====================================================================
  # Private: Cycle Removal (ensure DAG)
  # ====================================================================

  defp remove_cycles(edges, nodes) do
    # Simple topological approach: remove back-edges using timestamp ordering
    node_order = nodes
                 |> Enum.sort_by(& &1.timestamp)
                 |> Enum.with_index()
                 |> Map.new(fn {node, idx} -> {node.id, idx} end)

    Enum.filter(edges, fn edge ->
      source_order = Map.get(node_order, edge.source, 0)
      target_order = Map.get(node_order, edge.target, 0)
      # Only keep forward edges (source before or equal to target in time)
      source_order <= target_order
    end)
  end

  # ====================================================================
  # Private: Graph Traversal
  # ====================================================================

  defp build_adjacency_list(edges) do
    Enum.reduce(edges, %{}, fn edge, acc ->
      targets = Map.get(acc, edge.source, [])
      Map.put(acc, edge.source, [edge.target | targets])
    end)
  end

  defp bfs(start_id, adj) do
    do_bfs([{start_id, 0}], adj, MapSet.new(), %{start_id => 0})
  end

  defp do_bfs([], _adj, visited, depths), do: {visited, depths}
  defp do_bfs([{node_id, depth} | rest], adj, visited, depths) do
    if MapSet.member?(visited, node_id) do
      do_bfs(rest, adj, visited, depths)
    else
      visited = MapSet.put(visited, node_id)
      neighbors = Map.get(adj, node_id, [])

      new_items = Enum.map(neighbors, fn n -> {n, depth + 1} end)
      new_depths = Enum.reduce(neighbors, depths, fn n, acc ->
        Map.put_new(acc, n, depth + 1)
      end)

      do_bfs(rest ++ new_items, adj, visited, new_depths)
    end
  end

  defp find_path(source_id, target_id, _adj, _node_map) when source_id == target_id do
    [source_id]
  end

  defp find_path(source_id, target_id, adj, _node_map) do
    # BFS to find shortest path
    do_find_path([{source_id, [source_id]}], adj, MapSet.new(), target_id)
  end

  defp do_find_path([], _adj, _visited, _target), do: []
  defp do_find_path([{node_id, path} | rest], adj, visited, target) do
    if node_id == target do
      path
    else
      if MapSet.member?(visited, node_id) do
        do_find_path(rest, adj, visited, target)
      else
        visited = MapSet.put(visited, node_id)
        neighbors = Map.get(adj, node_id, [])

        new_items = Enum.map(neighbors, fn n -> {n, path ++ [n]} end)
        do_find_path(rest ++ new_items, adj, visited, target)
      end
    end
  end

  # ====================================================================
  # Private: Graph Metrics
  # ====================================================================

  defp compute_graph_depth(nodes, edges) do
    root = find_root_cause(nodes, edges)
    if root do
      adj = build_adjacency_list(edges)
      {_visited, depths} = bfs(root.id, adj)
      depths |> Map.values() |> Enum.max(fn -> 0 end)
    else
      0
    end
  end

  defp compute_graph_breadth(_nodes, edges) do
    # Maximum number of edges from a single source
    edges
    |> Enum.group_by(& &1.source)
    |> Enum.map(fn {_source, es} -> length(es) end)
    |> Enum.max(fn -> 0 end)
  end

  defp severity_distribution(nodes) do
    nodes
    |> Enum.group_by(&Map.get(&1, :severity, "low"))
    |> Enum.map(fn {sev, items} -> {sev, length(items)} end)
    |> Map.new()
  end

  defp edge_type_distribution(edges) do
    edges
    |> Enum.group_by(& &1.type)
    |> Enum.map(fn {type, items} -> {type, length(items)} end)
    |> Map.new()
  end

  defp severity_order(severity) do
    %{"critical" => 4, "high" => 3, "medium" => 2, "low" => 1, "info" => 0}
    |> Map.get(to_string(severity), 0)
  end
end
