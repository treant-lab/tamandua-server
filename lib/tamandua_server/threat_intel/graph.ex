defmodule TamanduaServer.ThreatIntel.Graph do
  @moduledoc """
  Threat Intelligence IOC Relationship Graph Engine.

  Maintains an in-memory directed graph of IOC relationships using ETS tables.
  Provides multi-source confidence scoring, time-based decay, relationship
  path finding, and automatic IOC extraction from alerts.

  ## ETS Tables

  - `:ti_graph_nodes`   - IOC nodes keyed by node_id
  - `:ti_graph_edges`   - Directed edges keyed by {source_id, target_id, edge_type}
  - `:ti_graph_sources` - Per-IOC source tracking keyed by {node_id, source_name}

  ## Node Types

  ip, domain, hash_md5, hash_sha1, hash_sha256, url, email,
  threat_actor, campaign, vulnerability, malware_family

  ## Edge Types

  communicates_with, belongs_to, exploits, attributed_to,
  uses, resolves_to, drops, similar_to

  ## Confidence Algorithm

      base_confidence = source_confidence (feed-specific, e.g. MISP=0.7, VT=0.9)
      multi_source_bonus = min(0.3, num_sources * 0.1)
      recency_bonus = if age < 24h: 0.1, if age < 7d: 0.05, else: 0
      age_decay = min(0.5, days_old * 0.005)
      final = min(1.0, base_confidence + multi_source_bonus + recency_bonus - age_decay)

  ## PubSub Integration

  Subscribes to:
  - `"alerts:feed"` - auto-ingest IOCs from new alerts
  - `"threat_intel:ioc_update"` - feed updates

  ## Usage

      # Add nodes and edges
      Graph.add_node(%{id: "1.2.3.4", type: :ip, metadata: %{country: "RU"}})
      Graph.add_edge("hash_abc", "1.2.3.4", :communicates_with, confidence: 0.8)
      Graph.add_source("1.2.3.4", "virustotal", confidence: 0.9)

      # Query the graph
      Graph.get_node("1.2.3.4")
      Graph.get_neighbors("1.2.3.4", depth: 2)
      Graph.find_paths("hash_abc", "apt29", max_depth: 4)
      Graph.enrich_alert(alert)
  """

  use GenServer
  require Logger

  @ets_nodes :ti_graph_nodes
  @ets_edges :ti_graph_edges
  @ets_sources :ti_graph_sources

  @pubsub TamanduaServer.PubSub

  # Periodic timers
  @decay_interval :timer.hours(6)
  @cleanup_interval :timer.hours(6)

  # Confidence thresholds
  @min_confidence_threshold 0.1
  @max_bfs_depth 4
  @default_neighbor_depth 1

  # Source confidence defaults
  @source_confidence %{
    "virustotal" => 0.9,
    "crowdstrike" => 0.9,
    "mandiant" => 0.9,
    "recorded_future" => 0.85,
    "misp" => 0.7,
    "alienvault_otx" => 0.6,
    "abuse.ch" => 0.75,
    "malware_bazaar" => 0.8,
    "urlhaus" => 0.75,
    "threatfox" => 0.75,
    "feodo_tracker" => 0.8,
    "openphish" => 0.6,
    "phishtank" => 0.6,
    "spamhaus" => 0.8,
    "internal" => 0.5,
    "manual" => 0.5,
    "detection" => 0.65,
    "alert" => 0.6
  }

  @valid_node_types ~w(ip domain hash_md5 hash_sha1 hash_sha256 url email
                       threat_actor campaign vulnerability malware_family)a

  @valid_edge_types ~w(communicates_with belongs_to exploits attributed_to
                       uses resolves_to drops similar_to)a

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Add or update an IOC node in the graph.

  ## Parameters

  - `node` - Map with required `:id` and `:type` keys, optional `:metadata` and `:first_seen`

  ## Examples

      Graph.add_node(%{id: "1.2.3.4", type: :ip, metadata: %{country: "RU"}})
      Graph.add_node(%{id: "abc123", type: :hash_sha256})
  """
  @spec add_node(map()) :: :ok | {:error, term()}
  def add_node(node) do
    GenServer.call(__MODULE__, {:add_node, node})
  end

  @doc """
  Create a directed relationship between two nodes.

  ## Parameters

  - `source_id` - The source node ID
  - `target_id` - The target node ID
  - `edge_type` - One of the valid edge types (atom)
  - `opts` - Keyword list with optional `:confidence` (float 0.0-1.0) and `:metadata`

  ## Examples

      Graph.add_edge("hash_abc", "1.2.3.4", :communicates_with, confidence: 0.8)
  """
  @spec add_edge(String.t(), String.t(), atom(), keyword()) :: :ok | {:error, term()}
  def add_edge(source_id, target_id, edge_type, opts \\ []) do
    GenServer.call(__MODULE__, {:add_edge, source_id, target_id, edge_type, opts})
  end

  @doc """
  Record that a specific feed reported this IOC.

  ## Parameters

  - `node_id` - The node ID
  - `source_name` - Name of the reporting feed (e.g. "virustotal", "misp")
  - `opts` - Keyword list with optional `:confidence` override

  ## Examples

      Graph.add_source("1.2.3.4", "virustotal", confidence: 0.9)
  """
  @spec add_source(String.t(), String.t(), keyword()) :: :ok
  def add_source(node_id, source_name, opts \\ []) do
    GenServer.call(__MODULE__, {:add_source, node_id, source_name, opts})
  end

  @doc """
  Get a node with its computed confidence score.

  Returns `nil` if the node does not exist.
  """
  @spec get_node(String.t()) :: map() | nil
  def get_node(node_id) do
    case :ets.lookup(@ets_nodes, node_id) do
      [{^node_id, node}] ->
        confidence = do_compute_confidence(node_id)
        Map.put(node, :confidence, confidence)

      [] ->
        nil
    end
  end

  @doc """
  Get all connected nodes within a configurable depth (1-3).

  ## Options

  - `:depth` - Search depth, 1-3 (default 1)
  - `:edge_types` - Filter by specific edge types (list of atoms)
  """
  @spec get_neighbors(String.t(), keyword()) :: [map()]
  def get_neighbors(node_id, opts \\ []) do
    depth = min(opts[:depth] || @default_neighbor_depth, 3)
    edge_type_filter = opts[:edge_types]
    do_get_neighbors(node_id, depth, edge_type_filter)
  end

  @doc """
  Get IOCs related to a given IOC with the full relationship path.

  Returns a list of maps with `:node`, `:path`, and `:distance` keys.
  """
  @spec get_related_iocs(String.t(), keyword()) :: [map()]
  def get_related_iocs(node_id, opts \\ []) do
    depth = min(opts[:depth] || 2, 3)
    do_get_related_iocs(node_id, depth)
  end

  @doc """
  Compute the multi-source confidence score for a node.

  Returns a float between 0.0 and 1.0.
  """
  @spec compute_confidence(String.t()) :: float()
  def compute_confidence(node_id) do
    do_compute_confidence(node_id)
  end

  @doc """
  Apply periodic confidence decay to all nodes.
  Called automatically by internal timer every 6 hours.
  """
  @spec apply_decay() :: :ok
  def apply_decay do
    GenServer.cast(__MODULE__, :apply_decay)
  end

  @doc """
  Find relationship paths between two IOCs using BFS (max depth 4).

  Returns a list of paths, where each path is a list of
  `%{node_id: id, edge_type: type}` maps.
  """
  @spec find_paths(String.t(), String.t(), keyword()) :: [list()]
  def find_paths(source_id, target_id, opts \\ []) do
    max_depth = min(opts[:max_depth] || @max_bfs_depth, @max_bfs_depth)
    do_find_paths(source_id, target_id, max_depth)
  end

  @doc """
  Get the connected component (subgraph) around a node.

  ## Options

  - `:depth` - Maximum traversal depth (default 2, max 3)
  """
  @spec get_subgraph(String.t(), keyword()) :: map()
  def get_subgraph(node_id, opts \\ []) do
    depth = min(opts[:depth] || 2, 3)
    do_get_subgraph(node_id, depth)
  end

  @doc """
  Get graph statistics: node count, edge count, type distributions.
  """
  @spec stats() :: map()
  def stats do
    node_count = :ets.info(@ets_nodes, :size)
    edge_count = :ets.info(@ets_edges, :size)
    source_count = :ets.info(@ets_sources, :size)

    node_types = count_node_types()
    edge_types = count_edge_types()

    %{
      node_count: node_count,
      edge_count: edge_count,
      source_entries: source_count,
      node_types: node_types,
      edge_types: edge_types
    }
  end

  @doc """
  Extract IOCs from an alert and add to graph with edges.

  Parses alert fields for hashes, IPs, domains, and URLs, creates
  nodes for each, and links them together and to any MITRE techniques.
  """
  @spec ingest_from_alert(map()) :: :ok
  def ingest_from_alert(alert) do
    GenServer.cast(__MODULE__, {:ingest_from_alert, alert})
  end

  @doc """
  Given an alert's IOCs, return related IOCs and threat context from graph.

  Returns a map with `:related_iocs`, `:threat_actors`, `:campaigns`,
  and `:malware_families` discovered by traversing the graph.
  """
  @spec enrich_alert(map()) :: map()
  def enrich_alert(alert) do
    GenServer.call(__MODULE__, {:enrich_alert, alert}, 15_000)
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    # Create ETS tables
    :ets.new(@ets_nodes, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@ets_edges, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@ets_sources, [:named_table, :set, :public, read_concurrency: true])

    # Subscribe to PubSub topics
    Phoenix.PubSub.subscribe(@pubsub, "alerts:feed")
    Phoenix.PubSub.subscribe(@pubsub, "threat_intel:ioc_update")

    # Schedule periodic tasks
    schedule_decay()
    schedule_cleanup()

    Logger.info("[ThreatIntel.Graph] Started with ETS tables initialized")
    {:ok, %{decay_count: 0, cleanup_count: 0}}
  end

  @impl true
  def handle_call({:add_node, node}, _from, state) do
    result = do_add_node(node)
    {:reply, result, state}
  end

  def handle_call({:add_edge, source_id, target_id, edge_type, opts}, _from, state) do
    result = do_add_edge(source_id, target_id, edge_type, opts)
    {:reply, result, state}
  end

  def handle_call({:add_source, node_id, source_name, opts}, _from, state) do
    do_add_source(node_id, source_name, opts)
    {:reply, :ok, state}
  end

  def handle_call({:enrich_alert, alert}, _from, state) do
    result = do_enrich_alert(alert)
    {:reply, result, state}
  end

  @impl true
  def handle_cast(:apply_decay, state) do
    count = do_apply_decay()
    Logger.debug("[ThreatIntel.Graph] Applied decay to #{count} nodes")
    {:noreply, %{state | decay_count: state.decay_count + 1}}
  end

  def handle_cast({:ingest_from_alert, alert}, state) do
    do_ingest_from_alert(alert)
    {:noreply, state}
  end

  @impl true
  def handle_info(:apply_decay, state) do
    count = do_apply_decay()
    Logger.debug("[ThreatIntel.Graph] Periodic decay applied to #{count} nodes")
    schedule_decay()
    {:noreply, %{state | decay_count: state.decay_count + 1}}
  end

  def handle_info(:cleanup_stale, state) do
    removed = do_cleanup_stale()
    if removed > 0 do
      Logger.info("[ThreatIntel.Graph] Cleanup removed #{removed} stale nodes")
    end
    schedule_cleanup()
    {:noreply, %{state | cleanup_count: state.cleanup_count + 1}}
  end

  # PubSub handler: new alert
  def handle_info(%{topic: "alerts:feed", event: "new_alert", payload: alert}, state) do
    do_ingest_from_alert(alert)
    {:noreply, state}
  end

  # PubSub handler: IOC update from threat intel feed
  def handle_info(%{topic: "threat_intel:ioc_update", payload: payload}, state) do
    handle_ioc_update(payload)
    {:noreply, state}
  end

  # Catch-all for unexpected PubSub messages
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ============================================================================
  # Node Operations
  # ============================================================================

  defp do_add_node(node) do
    node_id = node[:id] || node["id"]
    node_type = normalize_type(node[:type] || node["type"])

    if is_nil(node_id) or is_nil(node_type) do
      {:error, :missing_id_or_type}
    else
      if node_type not in @valid_node_types do
        {:error, :invalid_node_type}
      else
        now = DateTime.utc_now()
        metadata = node[:metadata] || node["metadata"] || %{}

        record = %{
          id: node_id,
          type: node_type,
          metadata: metadata,
          first_seen: node[:first_seen] || now,
          last_seen: now,
          inserted_at: now
        }

        # Upsert: update last_seen and merge metadata if exists
        case :ets.lookup(@ets_nodes, node_id) do
          [{^node_id, existing}] ->
            merged_metadata = Map.merge(existing.metadata || %{}, metadata)
            updated = %{existing |
              last_seen: now,
              metadata: merged_metadata
            }
            :ets.insert(@ets_nodes, {node_id, updated})

          [] ->
            :ets.insert(@ets_nodes, {node_id, record})
        end

        :ok
      end
    end
  end

  # ============================================================================
  # Edge Operations
  # ============================================================================

  defp do_add_edge(source_id, target_id, edge_type, opts) do
    edge_type_atom = normalize_type(edge_type)

    if edge_type_atom not in @valid_edge_types do
      {:error, :invalid_edge_type}
    else
      now = DateTime.utc_now()
      confidence = opts[:confidence] || 0.5
      metadata = opts[:metadata] || %{}

      edge_key = {source_id, target_id, edge_type_atom}

      record = %{
        source_id: source_id,
        target_id: target_id,
        edge_type: edge_type_atom,
        confidence: confidence,
        metadata: metadata,
        created_at: now,
        updated_at: now
      }

      # Upsert edge: update confidence if higher
      case :ets.lookup(@ets_edges, edge_key) do
        [{^edge_key, existing}] ->
          updated = %{existing |
            confidence: max(existing.confidence, confidence),
            metadata: Map.merge(existing.metadata || %{}, metadata),
            updated_at: now
          }
          :ets.insert(@ets_edges, {edge_key, updated})

        [] ->
          :ets.insert(@ets_edges, {edge_key, record})
      end

      :ok
    end
  end

  # ============================================================================
  # Source Tracking
  # ============================================================================

  defp do_add_source(node_id, source_name, opts) do
    now = DateTime.utc_now()
    confidence = opts[:confidence] || Map.get(@source_confidence, source_name, 0.5)

    source_key = {node_id, source_name}

    record = %{
      node_id: node_id,
      source_name: source_name,
      confidence: confidence,
      first_reported: now,
      last_reported: now
    }

    case :ets.lookup(@ets_sources, source_key) do
      [{^source_key, existing}] ->
        updated = %{existing |
          confidence: max(existing.confidence, confidence),
          last_reported: now
        }
        :ets.insert(@ets_sources, {source_key, updated})

      [] ->
        :ets.insert(@ets_sources, {source_key, record})
    end
  end

  # ============================================================================
  # Confidence Computation
  # ============================================================================

  defp do_compute_confidence(node_id) do
    sources = get_sources_for_node(node_id)
    node = case :ets.lookup(@ets_nodes, node_id) do
      [{^node_id, n}] -> n
      [] -> nil
    end

    if is_nil(node) do
      0.0
    else
      # Base confidence: highest source confidence
      base_confidence = if sources == [] do
        0.5
      else
        sources
        |> Enum.map(fn s -> s.confidence end)
        |> Enum.max()
      end

      # Multi-source bonus: min(0.3, num_sources * 0.1)
      num_sources = length(sources)
      multi_source_bonus = min(0.3, num_sources * 0.1)

      # Recency bonus based on most recent report
      most_recent = if sources != [] do
        sources
        |> Enum.map(fn s -> s.last_reported end)
        |> Enum.max(DateTime)
      else
        node.last_seen
      end

      recency_bonus = compute_recency_bonus(most_recent)

      # Age decay based on first seen
      age_decay = compute_age_decay(node.first_seen)

      # Final score clamped to [0.0, 1.0]
      final = base_confidence + multi_source_bonus + recency_bonus - age_decay
      min(1.0, max(0.0, final))
    end
  end

  defp compute_recency_bonus(nil), do: 0.0
  defp compute_recency_bonus(timestamp) do
    age_hours = DateTime.diff(DateTime.utc_now(), timestamp, :hour)

    cond do
      age_hours < 24 -> 0.1
      age_hours < 168 -> 0.05
      true -> 0.0
    end
  end

  defp compute_age_decay(nil), do: 0.0
  defp compute_age_decay(first_seen) do
    days_old = DateTime.diff(DateTime.utc_now(), first_seen, :day)
    min(0.5, days_old * 0.005)
  end

  defp get_sources_for_node(node_id) do
    # Match all sources for this node_id
    match_spec = [{{:{}, node_id, :_}, :"$1", [], [:"$1"]}]

    try do
      :ets.select(@ets_sources, match_spec)
    rescue
      _ -> []
    catch
      _ -> []
    end
  end

  # ============================================================================
  # Neighbor Traversal
  # ============================================================================

  defp do_get_neighbors(node_id, depth, edge_type_filter) do
    visited = MapSet.new([node_id])
    do_get_neighbors_bfs([node_id], depth, edge_type_filter, visited, [])
  end

  defp do_get_neighbors_bfs(_, 0, _, _, acc), do: acc
  defp do_get_neighbors_bfs([], _, _, _, acc), do: acc
  defp do_get_neighbors_bfs(frontier, depth, edge_type_filter, visited, acc) do
    # Find all edges from frontier nodes (both outgoing and incoming)
    new_neighbors = Enum.flat_map(frontier, fn nid ->
      outgoing = get_outgoing_edges(nid, edge_type_filter)
      incoming = get_incoming_edges(nid, edge_type_filter)

      out_neighbors = Enum.map(outgoing, fn edge ->
        %{
          node_id: edge.target_id,
          edge_type: edge.edge_type,
          direction: :outgoing,
          edge_confidence: edge.confidence
        }
      end)

      in_neighbors = Enum.map(incoming, fn edge ->
        %{
          node_id: edge.source_id,
          edge_type: edge.edge_type,
          direction: :incoming,
          edge_confidence: edge.confidence
        }
      end)

      out_neighbors ++ in_neighbors
    end)

    # Filter out already visited nodes
    {new_frontier, new_acc, new_visited} =
      Enum.reduce(new_neighbors, {[], acc, visited}, fn neighbor, {frontier_acc, acc_acc, vis_acc} ->
        if MapSet.member?(vis_acc, neighbor.node_id) do
          {frontier_acc, acc_acc, vis_acc}
        else
          node = get_node(neighbor.node_id)
          enriched = Map.merge(neighbor, %{node: node})
          {
            [neighbor.node_id | frontier_acc],
            [enriched | acc_acc],
            MapSet.put(vis_acc, neighbor.node_id)
          }
        end
      end)

    do_get_neighbors_bfs(Enum.uniq(new_frontier), depth - 1, edge_type_filter, new_visited, new_acc)
  end

  defp get_outgoing_edges(node_id, edge_type_filter) do
    # Scan edges where source_id matches
    all_edges = :ets.tab2list(@ets_edges)

    all_edges
    |> Enum.filter(fn {_key, edge} -> edge.source_id == node_id end)
    |> Enum.filter(fn {_key, edge} ->
      is_nil(edge_type_filter) or edge.edge_type in edge_type_filter
    end)
    |> Enum.map(fn {_key, edge} -> edge end)
  end

  defp get_incoming_edges(node_id, edge_type_filter) do
    all_edges = :ets.tab2list(@ets_edges)

    all_edges
    |> Enum.filter(fn {_key, edge} -> edge.target_id == node_id end)
    |> Enum.filter(fn {_key, edge} ->
      is_nil(edge_type_filter) or edge.edge_type in edge_type_filter
    end)
    |> Enum.map(fn {_key, edge} -> edge end)
  end

  # ============================================================================
  # Related IOCs with Path
  # ============================================================================

  defp do_get_related_iocs(node_id, max_depth) do
    visited = MapSet.new([node_id])
    do_related_bfs([{node_id, []}], max_depth, visited, [])
  end

  defp do_related_bfs(_, 0, _, acc), do: acc
  defp do_related_bfs([], _, _, acc), do: acc
  defp do_related_bfs(frontier, depth, visited, acc) do
    {new_frontier, new_acc, new_visited} =
      Enum.reduce(frontier, {[], acc, visited}, fn {nid, path}, {fr_acc, a_acc, v_acc} ->
        edges = get_outgoing_edges(nid, nil) ++ get_incoming_edges(nid, nil)

        Enum.reduce(edges, {fr_acc, a_acc, v_acc}, fn edge, {f, a, v} ->
          neighbor_id = if edge.source_id == nid, do: edge.target_id, else: edge.source_id

          if MapSet.member?(v, neighbor_id) do
            {f, a, v}
          else
            new_path = path ++ [%{from: nid, to: neighbor_id, edge_type: edge.edge_type}]
            node = get_node(neighbor_id)
            entry = %{
              node: node,
              path: new_path,
              distance: length(new_path)
            }
            {
              [{neighbor_id, new_path} | f],
              [entry | a],
              MapSet.put(v, neighbor_id)
            }
          end
        end)
      end)

    do_related_bfs(new_frontier, depth - 1, new_visited, new_acc)
  end

  # ============================================================================
  # Path Finding (BFS)
  # ============================================================================

  defp do_find_paths(source_id, target_id, max_depth) do
    # BFS to find all paths up to max_depth
    queue = :queue.in({source_id, [source_id]}, :queue.new())
    do_bfs_paths(queue, target_id, max_depth, found_paths: [])
  end

  defp do_bfs_paths(queue, target_id, max_depth, found_paths: found_paths) do
    case :queue.out(queue) do
      {:empty, _} ->
        found_paths

      {{:value, {current_id, path}}, rest_queue} ->
        if length(path) > max_depth + 1 do
          # Exceeded max depth, skip
          do_bfs_paths(rest_queue, target_id, max_depth, found_paths: found_paths)
        else
          if current_id == target_id and length(path) > 1 do
            # Found a path
            annotated_path = annotate_path(path)
            new_found = [annotated_path | found_paths]
            # Continue searching for more paths
            do_bfs_paths(rest_queue, target_id, max_depth, found_paths: new_found)
          else
            # Expand neighbors
            edges = get_outgoing_edges(current_id, nil) ++ get_incoming_edges(current_id, nil)
            path_set = MapSet.new(path)

            new_queue = Enum.reduce(edges, rest_queue, fn edge, q ->
              neighbor_id = if edge.source_id == current_id, do: edge.target_id, else: edge.source_id

              if MapSet.member?(path_set, neighbor_id) do
                q
              else
                :queue.in({neighbor_id, path ++ [neighbor_id]}, q)
              end
            end)

            do_bfs_paths(new_queue, target_id, max_depth, found_paths: found_paths)
          end
        end
    end
  end

  defp annotate_path(path) when length(path) < 2, do: []
  defp annotate_path(path) do
    path
    |> Enum.chunk_every(2, 1, :discard)
    |> Enum.map(fn [from_id, to_id] ->
      edge_type = find_edge_type(from_id, to_id)
      %{
        node_id: to_id,
        from: from_id,
        edge_type: edge_type
      }
    end)
  end

  defp find_edge_type(from_id, to_id) do
    # Check outgoing edges from from_id to to_id
    all_edges = :ets.tab2list(@ets_edges)

    case Enum.find(all_edges, fn {_key, edge} ->
      (edge.source_id == from_id and edge.target_id == to_id) or
      (edge.source_id == to_id and edge.target_id == from_id)
    end) do
      {_key, edge} -> edge.edge_type
      nil -> :unknown
    end
  end

  # ============================================================================
  # Subgraph Extraction
  # ============================================================================

  defp do_get_subgraph(node_id, depth) do
    # Collect all nodes and edges within depth
    visited = MapSet.new([node_id])
    {all_nodes, all_edges} = collect_subgraph([node_id], depth, visited, [], [])

    # Build node data
    nodes = Enum.map(MapSet.to_list(all_nodes), fn nid ->
      get_node(nid)
    end)
    |> Enum.reject(&is_nil/1)

    # Deduplicate edges
    unique_edges = Enum.uniq_by(all_edges, fn e ->
      {e.source_id, e.target_id, e.edge_type}
    end)

    %{
      center: node_id,
      nodes: nodes,
      edges: unique_edges,
      node_count: length(nodes),
      edge_count: length(unique_edges)
    }
  end

  defp collect_subgraph(_, 0, visited, edge_acc, _node_acc), do: {visited, edge_acc}
  defp collect_subgraph([], _, visited, edge_acc, _node_acc), do: {visited, edge_acc}
  defp collect_subgraph(frontier, depth, visited, edge_acc, _node_acc) do
    {new_frontier, new_visited, new_edges} =
      Enum.reduce(frontier, {[], visited, edge_acc}, fn nid, {fr, vis, edg} ->
        out_edges = get_outgoing_edges(nid, nil)
        in_edges = get_incoming_edges(nid, nil)
        all_node_edges = out_edges ++ in_edges

        serialized_edges = Enum.map(all_node_edges, fn edge ->
          %{
            source_id: edge.source_id,
            target_id: edge.target_id,
            edge_type: edge.edge_type,
            confidence: edge.confidence
          }
        end)

        neighbor_ids = Enum.flat_map(all_node_edges, fn edge ->
          if edge.source_id == nid, do: [edge.target_id], else: [edge.source_id]
        end)

        new_ids = Enum.reject(neighbor_ids, &MapSet.member?(vis, &1))

        {
          new_ids ++ fr,
          Enum.reduce(new_ids, vis, &MapSet.put(&2, &1)),
          serialized_edges ++ edg
        }
      end)

    collect_subgraph(Enum.uniq(new_frontier), depth - 1, new_visited, new_edges, [])
  end

  # ============================================================================
  # Decay & Cleanup
  # ============================================================================

  defp do_apply_decay do
    now = DateTime.utc_now()
    nodes = :ets.tab2list(@ets_nodes)

    Enum.reduce(nodes, 0, fn {node_id, node}, count ->
      age_days = DateTime.diff(now, node.first_seen, :day)
      decay = min(0.5, age_days * 0.005)

      if decay > 0.0 do
        # Update last_seen to reflect decay check
        updated = %{node | last_seen: now}
        :ets.insert(@ets_nodes, {node_id, updated})
        count + 1
      else
        count
      end
    end)
  end

  defp do_cleanup_stale do
    nodes = :ets.tab2list(@ets_nodes)

    Enum.reduce(nodes, 0, fn {node_id, _node}, count ->
      confidence = do_compute_confidence(node_id)

      if confidence < @min_confidence_threshold do
        # Remove node, its edges, and source entries
        :ets.delete(@ets_nodes, node_id)
        remove_edges_for_node(node_id)
        remove_sources_for_node(node_id)
        count + 1
      else
        count
      end
    end)
  end

  defp remove_edges_for_node(node_id) do
    all_edges = :ets.tab2list(@ets_edges)

    Enum.each(all_edges, fn {key, edge} ->
      if edge.source_id == node_id or edge.target_id == node_id do
        :ets.delete(@ets_edges, key)
      end
    end)
  end

  defp remove_sources_for_node(node_id) do
    all_sources = :ets.tab2list(@ets_sources)

    Enum.each(all_sources, fn {key, source} ->
      if source.node_id == node_id do
        :ets.delete(@ets_sources, key)
      end
    end)
  end

  # ============================================================================
  # Alert Ingestion
  # ============================================================================

  defp do_ingest_from_alert(alert) do
    iocs = extract_iocs_from_alert(alert)

    # Add each IOC as a node
    Enum.each(iocs, fn ioc ->
      do_add_node(%{
        id: ioc.value,
        type: ioc.type,
        metadata: %{
          alert_id: alert_id(alert),
          source: "alert"
        }
      })

      do_add_source(ioc.value, "alert", confidence: 0.6)
    end)

    # Create edges between co-occurring IOCs in the same alert
    if length(iocs) > 1 do
      create_cooccurrence_edges(iocs)
    end

    # Link to threat actors if attribution data is present
    attributed_actors = Map.get(alert, :attributed_actors, []) ++
                        Map.get(alert, "attributed_actors", [])

    Enum.each(attributed_actors, fn actor_name ->
      do_add_node(%{id: actor_name, type: :threat_actor, metadata: %{}})

      Enum.each(iocs, fn ioc ->
        do_add_edge(ioc.value, actor_name, :attributed_to, confidence: 0.5)
      end)
    end)

    # Link to campaign if present
    campaign_id = Map.get(alert, :campaign_id) || Map.get(alert, "campaign_id")
    if campaign_id do
      do_add_node(%{id: campaign_id, type: :campaign, metadata: %{}})

      Enum.each(iocs, fn ioc ->
        do_add_edge(ioc.value, campaign_id, :belongs_to, confidence: 0.5)
      end)
    end
  end

  defp extract_iocs_from_alert(alert) do
    iocs = []

    # Extract hashes
    hash_fields = [
      {:hash_sha256, :sha256}, {:hash_sha1, :sha1}, {:hash_md5, :md5},
      {"sha256", :hash_sha256}, {"sha1", :hash_sha1}, {"md5", :hash_md5},
      {"hash", :hash_sha256}
    ]

    iocs = Enum.reduce(hash_fields, iocs, fn {field, type}, acc ->
      val = Map.get(alert, field) || deep_get(alert, field)
      if is_binary(val) and byte_size(val) > 0 do
        [%{type: type, value: val} | acc]
      else
        acc
      end
    end)

    # Extract IPs from source/destination fields
    ip_fields = [:source_ip, :dest_ip, :remote_ip, "source_ip", "dest_ip", "remote_ip"]

    iocs = Enum.reduce(ip_fields, iocs, fn field, acc ->
      val = Map.get(alert, field) || deep_get(alert, field)
      if is_binary(val) and byte_size(val) > 0 and valid_ip?(val) do
        [%{type: :ip, value: val} | acc]
      else
        acc
      end
    end)

    # Extract domains
    domain_fields = [:domain, :dns_query, "domain", "dns_query"]

    iocs = Enum.reduce(domain_fields, iocs, fn field, acc ->
      val = Map.get(alert, field) || deep_get(alert, field)
      if is_binary(val) and byte_size(val) > 0 do
        [%{type: :domain, value: val} | acc]
      else
        acc
      end
    end)

    # Extract IOCs from nested enrichment data
    enrichment = Map.get(alert, :enrichment) || Map.get(alert, "enrichment") || %{}
    enrichment_iocs = Map.get(enrichment, :iocs) || Map.get(enrichment, "iocs") || []

    iocs = Enum.reduce(enrichment_iocs, iocs, fn eioc, acc ->
      type = normalize_type(eioc[:type] || eioc["type"])
      value = eioc[:value] || eioc["value"]

      if type in @valid_node_types and is_binary(value) do
        [%{type: type, value: value} | acc]
      else
        acc
      end
    end)

    # Deduplicate by value
    iocs
    |> Enum.uniq_by(fn ioc -> ioc.value end)
  end

  defp create_cooccurrence_edges(iocs) do
    # Link hashes to IPs/domains (communicates_with)
    hashes = Enum.filter(iocs, fn i -> i.type in [:hash_sha256, :hash_sha1, :hash_md5] end)
    network_iocs = Enum.filter(iocs, fn i -> i.type in [:ip, :domain, :url] end)

    Enum.each(hashes, fn hash ->
      Enum.each(network_iocs, fn net_ioc ->
        do_add_edge(hash.value, net_ioc.value, :communicates_with, confidence: 0.4)
      end)
    end)

    # Link domains to IPs (resolves_to)
    domains = Enum.filter(iocs, fn i -> i.type == :domain end)
    ips = Enum.filter(iocs, fn i -> i.type == :ip end)

    Enum.each(domains, fn domain ->
      Enum.each(ips, fn ip ->
        do_add_edge(domain.value, ip.value, :resolves_to, confidence: 0.4)
      end)
    end)
  end

  # ============================================================================
  # Alert Enrichment
  # ============================================================================

  defp do_enrich_alert(alert) do
    iocs = extract_iocs_from_alert(alert)

    # For each IOC, find related nodes
    related = Enum.flat_map(iocs, fn ioc ->
      do_get_related_iocs(ioc.value, 2)
    end)
    |> Enum.uniq_by(fn r -> r.node && r.node.id end)
    |> Enum.reject(fn r -> is_nil(r.node) end)

    # Categorize related nodes
    threat_actors = related
    |> Enum.filter(fn r -> r.node && r.node.type == :threat_actor end)
    |> Enum.map(fn r -> %{
        id: r.node.id,
        confidence: r.node.confidence,
        distance: r.distance,
        path: r.path
      }
    end)

    campaigns = related
    |> Enum.filter(fn r -> r.node && r.node.type == :campaign end)
    |> Enum.map(fn r -> %{
        id: r.node.id,
        confidence: r.node.confidence,
        distance: r.distance
      }
    end)

    malware_families = related
    |> Enum.filter(fn r -> r.node && r.node.type == :malware_family end)
    |> Enum.map(fn r -> %{
        id: r.node.id,
        confidence: r.node.confidence,
        distance: r.distance
      }
    end)

    vulnerabilities = related
    |> Enum.filter(fn r -> r.node && r.node.type == :vulnerability end)
    |> Enum.map(fn r -> %{
        id: r.node.id,
        confidence: r.node.confidence,
        distance: r.distance
      }
    end)

    related_iocs = related
    |> Enum.filter(fn r ->
      r.node && r.node.type in [:ip, :domain, :hash_sha256, :hash_sha1, :hash_md5, :url, :email]
    end)
    |> Enum.map(fn r -> %{
        id: r.node.id,
        type: r.node.type,
        confidence: r.node.confidence,
        distance: r.distance,
        path: r.path
      }
    end)

    %{
      alert_iocs: Enum.map(iocs, fn i -> %{type: i.type, value: i.value} end),
      related_iocs: related_iocs,
      threat_actors: threat_actors,
      campaigns: campaigns,
      malware_families: malware_families,
      vulnerabilities: vulnerabilities,
      total_related: length(related)
    }
  end

  # ============================================================================
  # IOC Update Handler (from threat intel feeds)
  # ============================================================================

  defp handle_ioc_update(payload) do
    iocs = payload[:iocs] || payload["iocs"] || [payload]

    Enum.each(List.wrap(iocs), fn ioc ->
      type = normalize_type(ioc[:type] || ioc["type"])
      value = ioc[:value] || ioc["value"]
      source = ioc[:source] || ioc["source"] || "unknown"

      if type in @valid_node_types and is_binary(value) do
        do_add_node(%{
          id: value,
          type: type,
          metadata: Map.drop(ioc, [:type, :value, :source, "type", "value", "source"])
        })

        confidence = Map.get(@source_confidence, source, 0.5)
        do_add_source(value, source, confidence: confidence)
      end
    end)
  end

  # ============================================================================
  # Stats Helpers
  # ============================================================================

  defp count_node_types do
    :ets.tab2list(@ets_nodes)
    |> Enum.reduce(%{}, fn {_id, node}, acc ->
      type_str = to_string(node.type)
      Map.update(acc, type_str, 1, &(&1 + 1))
    end)
  end

  defp count_edge_types do
    :ets.tab2list(@ets_edges)
    |> Enum.reduce(%{}, fn {_key, edge}, acc ->
      type_str = to_string(edge.edge_type)
      Map.update(acc, type_str, 1, &(&1 + 1))
    end)
  end

  # ============================================================================
  # Utility Functions
  # ============================================================================

  defp normalize_type(type) when is_atom(type), do: type
  defp normalize_type(type) when is_binary(type) do
    try do
      String.to_existing_atom(type)
    rescue
      ArgumentError -> String.to_atom(type)
    end
  end
  defp normalize_type(_), do: nil

  defp alert_id(alert) do
    Map.get(alert, :id) || Map.get(alert, "id") || "unknown"
  end

  defp deep_get(map, key) when is_atom(key) do
    Map.get(map, key) || Map.get(map, to_string(key))
  end
  defp deep_get(map, key) when is_binary(key) do
    Map.get(map, key) || Map.get(map, String.to_atom(key))
  rescue
    ArgumentError -> Map.get(map, key)
  end

  defp valid_ip?(str) do
    case :inet.parse_address(String.to_charlist(str)) do
      {:ok, _} -> true
      _ -> false
    end
  end

  defp schedule_decay do
    Process.send_after(self(), :apply_decay, @decay_interval)
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup_stale, @cleanup_interval)
  end
end
