defmodule TamanduaServer.Graph.KnowledgeGraph do
  @moduledoc """
  Enterprise Knowledge Graph - Unified Graph Model of the Entire Environment.

  Maintains a real-time graph of all entities (users, devices, processes, files,
  network endpoints, services, vulnerabilities, alerts, AI models, MCP servers)
  and their relationships across the enterprise.

  Architecture:
  - ETS-backed adjacency list representation for O(1) node lookups
  - Separate ETS tables for nodes and edges to allow independent scaling
  - Subscribes to PubSub for real-time updates from telemetry/alert streams
  - Periodic snapshots to PostgreSQL for durability
  - BFS/DFS graph traversal with visited-set cycle prevention

  Node types: user, device, process, file, network, service, vulnerability,
              alert, ai_model, mcp_server, group

  Edge types: runs_on, accessed_by, connects_to, authenticated_as, exploits,
              escalated_to, communicates_with, child_of, member_of, deployed_on,
              has_vulnerability, triggered_by, manages, resolves_to

  ## Pending Node Enrichment

  When edges reference nodes that don't exist yet, the system creates "pending"
  nodes with minimal metadata (status: :pending, pending_since: timestamp).
  Background jobs (NodeEnrichmentJob) are automatically queued to fetch real
  data from various sources (database, telemetry cache, threat intel APIs).

  Once enriched, nodes transition from :pending to :complete status. Orphaned
  pending nodes (no edges) are automatically pruned after 1 hour.
  """

  use GenServer
  require Logger

  @nodes_table :knowledge_graph_nodes
  @edges_table :knowledge_graph_edges
  @adj_table :knowledge_graph_adjacency
  @reverse_adj_table :knowledge_graph_reverse_adj

  # Periodic snapshot interval: 5 minutes
  @snapshot_interval_ms 300_000
  # Periodic pruning interval: 30 minutes
  @prune_interval_ms 1_800_000
  # Node TTL by type (seconds)
  @node_ttl %{
    process: 86_400,         # 24h
    file: 604_800,           # 7 days
    network: 86_400,         # 24h
    alert: 2_592_000,        # 30 days
    user: 7_776_000,         # 90 days
    device: 7_776_000,       # 90 days
    service: 2_592_000,      # 30 days
    vulnerability: 7_776_000,# 90 days
    ai_model: 7_776_000,     # 90 days
    mcp_server: 2_592_000,   # 30 days
    group: 7_776_000         # 90 days
  }
  @max_nodes 500_000

  @valid_node_types ~w(user device process file network service vulnerability alert ai_model mcp_server group)a
  @valid_edge_types ~w(runs_on accessed_by connects_to authenticated_as exploits escalated_to
                       communicates_with child_of member_of deployed_on has_vulnerability
                       triggered_by manages resolves_to)a

  # ------------------------------------------------------------------
  # Client API
  # ------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Add or update a node in the graph.

  ## Parameters
  - `type` - One of: :user, :device, :process, :file, :network, :service,
    :vulnerability, :alert, :ai_model, :mcp_server, :group
  - `id` - Unique identifier for this node
  - `attrs` - Map of node attributes (varies by type)
  """
  @spec upsert_node(atom(), String.t(), map()) :: :ok
  def upsert_node(type, id, attrs) when type in @valid_node_types do
    GenServer.cast(__MODULE__, {:upsert_node, type, id, attrs})
  end

  @doc """
  Add an edge between two nodes.

  ## Parameters
  - `from` - `{type, id}` tuple for the source node
  - `to` - `{type, id}` tuple for the destination node
  - `edge_type` - Relationship type
  - `attrs` - Optional edge attributes (weight, timestamp, etc.)
  """
  @spec add_edge({atom(), String.t()}, {atom(), String.t()}, atom(), map()) :: :ok
  def add_edge(from, to, edge_type, attrs \\ %{}) when edge_type in @valid_edge_types do
    GenServer.cast(__MODULE__, {:add_edge, from, to, edge_type, attrs})
  end

  @doc """
  Remove a node and all its edges.
  """
  @spec remove_node(atom(), String.t()) :: :ok
  def remove_node(type, id) do
    GenServer.cast(__MODULE__, {:remove_node, type, id})
  end

  @doc """
  Remove a specific edge.
  """
  @spec remove_edge({atom(), String.t()}, {atom(), String.t()}, atom()) :: :ok
  def remove_edge(from, to, edge_type) do
    GenServer.cast(__MODULE__, {:remove_edge, from, to, edge_type})
  end

  @doc """
  Get a node with all its edges.
  """
  @spec get_node(atom(), String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_node(type, id) do
    node_key = {type, id}

    case :ets.lookup(@nodes_table, node_key) do
      [{^node_key, node_data}] ->
        outgoing = get_outgoing_edges(node_key)
        incoming = get_incoming_edges(node_key)

        {:ok, Map.merge(node_data, %{
          outgoing_edges: outgoing,
          incoming_edges: incoming,
          degree: length(outgoing) + length(incoming)
        })}

      [] ->
        {:error, :not_found}
    end
  end

  @doc """
  Get neighbors of a node, optionally filtered by edge type.
  """
  @spec neighbors(atom(), String.t(), atom() | nil) :: {:ok, [map()]}
  def neighbors(type, id, edge_type \\ nil) do
    node_key = {type, id}
    edges = get_outgoing_edges(node_key)

    filtered = if edge_type do
      Enum.filter(edges, fn e -> e.edge_type == edge_type end)
    else
      edges
    end

    neighbor_nodes = Enum.map(filtered, fn edge ->
      case :ets.lookup(@nodes_table, edge.to) do
        [{_key, node_data}] -> Map.put(node_data, :edge, edge)
        [] -> nil
      end
    end)
    |> Enum.reject(&is_nil/1)

    {:ok, neighbor_nodes}
  end

  @doc """
  Find shortest path between two nodes using BFS.
  Returns the path as a list of `{node_key, edge_type}` tuples, or :no_path.
  """
  @spec shortest_path({atom(), String.t()}, {atom(), String.t()}) ::
          {:ok, [map()]} | {:error, :no_path | :not_found}
  def shortest_path(from, to) do
    GenServer.call(__MODULE__, {:shortest_path, from, to}, 30_000)
  end

  @doc """
  Extract a subgraph centered on a node up to the given depth.
  """
  @spec subgraph({atom(), String.t()}, non_neg_integer()) :: {:ok, map()}
  def subgraph(center, depth \\ 2) do
    GenServer.call(__MODULE__, {:subgraph, center, depth}, 30_000)
  end

  @doc """
  Pattern query: find subgraphs matching a pattern.

  Pattern format: list of `{node_type, edge_type, node_type}` triples with
  optional filter maps.

  Example:
      query([
        {:user, :authenticated_as, :device, %{}},
        {:device, :runs_on, :process, %{alert_severity: "critical"}}
      ])
  """
  @spec query([tuple()]) :: {:ok, [map()]}
  def query(pattern) do
    GenServer.call(__MODULE__, {:query, pattern}, 60_000)
  end

  @doc """
  Find all attack paths from internet-facing assets to critical data/services.
  """
  @spec attack_paths(keyword()) :: {:ok, [map()]}
  def attack_paths(opts \\ []) do
    GenServer.call(__MODULE__, {:attack_paths, opts}, 60_000)
  end

  @doc """
  Get graph statistics.
  """
  @spec stats() :: map()
  def stats do
    GenServer.call(__MODULE__, :stats)
  end

  @doc """
  Get pending nodes that need enrichment.
  """
  @spec pending_nodes() :: [map()]
  def pending_nodes do
    GenServer.call(__MODULE__, :pending_nodes, 30_000)
  end

  @doc """
  Bulk ingest nodes and edges (used for initial load or batch updates).
  """
  @spec bulk_ingest([map()], [map()]) :: :ok
  def bulk_ingest(nodes, edges) do
    GenServer.cast(__MODULE__, {:bulk_ingest, nodes, edges})
  end

  # ------------------------------------------------------------------
  # Server Callbacks
  # ------------------------------------------------------------------

  @impl true
  def init(_opts) do
    # Create ETS tables
    :ets.new(@nodes_table, [:set, :public, :named_table, read_concurrency: true])
    :ets.new(@edges_table, [:bag, :public, :named_table, read_concurrency: true])
    :ets.new(@adj_table, [:bag, :public, :named_table, read_concurrency: true])
    :ets.new(@reverse_adj_table, [:bag, :public, :named_table, read_concurrency: true])

    # Subscribe to PubSub topics for real-time updates
    subscribe_to_streams()

    # Schedule periodic tasks
    Process.send_after(self(), :snapshot, @snapshot_interval_ms)
    Process.send_after(self(), :prune, @prune_interval_ms)

    Logger.info("[KnowledgeGraph] Enterprise Knowledge Graph started")

    {:ok, %{
      stats: %{
        nodes_inserted: 0,
        edges_inserted: 0,
        queries_executed: 0,
        snapshots_taken: 0,
        prune_cycles: 0,
        last_snapshot_at: nil
      }
    }}
  end

  # -- Casts: node/edge mutations ------------------------------------

  @impl true
  def handle_cast({:upsert_node, type, id, attrs}, state) do
    do_upsert_node(type, id, attrs)
    new_stats = Map.update!(state.stats, :nodes_inserted, &(&1 + 1))
    {:noreply, %{state | stats: new_stats}}
  end

  @impl true
  def handle_cast({:add_edge, from, to, edge_type, attrs}, state) do
    do_add_edge(from, to, edge_type, attrs)
    new_stats = Map.update!(state.stats, :edges_inserted, &(&1 + 1))
    {:noreply, %{state | stats: new_stats}}
  end

  @impl true
  def handle_cast({:remove_node, type, id}, state) do
    do_remove_node({type, id})
    {:noreply, state}
  end

  @impl true
  def handle_cast({:remove_edge, from, to, edge_type}, state) do
    do_remove_edge(from, to, edge_type)
    {:noreply, state}
  end

  @impl true
  def handle_cast({:bulk_ingest, nodes, edges}, state) do
    Enum.each(nodes, fn n ->
      do_upsert_node(n[:type], n[:id], Map.drop(n, [:type, :id]))
    end)

    Enum.each(edges, fn e ->
      do_add_edge(e[:from], e[:to], e[:edge_type], Map.drop(e, [:from, :to, :edge_type]))
    end)

    node_count = length(nodes)
    edge_count = length(edges)
    Logger.info("[KnowledgeGraph] Bulk ingested #{node_count} nodes, #{edge_count} edges")

    new_stats = state.stats
    |> Map.update!(:nodes_inserted, &(&1 + node_count))
    |> Map.update!(:edges_inserted, &(&1 + edge_count))

    {:noreply, %{state | stats: new_stats}}
  end

  # -- Calls: queries -----------------------------------------------

  @impl true
  def handle_call({:shortest_path, from, to}, _from, state) do
    result = bfs_shortest_path(from, to)
    new_stats = Map.update!(state.stats, :queries_executed, &(&1 + 1))
    {:reply, result, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:subgraph, center, depth}, _from, state) do
    result = extract_subgraph(center, depth)
    new_stats = Map.update!(state.stats, :queries_executed, &(&1 + 1))
    {:reply, {:ok, result}, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:query, pattern}, _from, state) do
    result = execute_pattern_query(pattern)
    new_stats = Map.update!(state.stats, :queries_executed, &(&1 + 1))
    {:reply, {:ok, result}, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:attack_paths, opts}, _from, state) do
    result = find_attack_paths(opts)
    new_stats = Map.update!(state.stats, :queries_executed, &(&1 + 1))
    {:reply, {:ok, result}, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call(:stats, _from, state) do
    pending_count = count_pending_nodes()

    graph_stats = %{
      node_count: :ets.info(@nodes_table, :size),
      edge_count: :ets.info(@edges_table, :size),
      adjacency_entries: :ets.info(@adj_table, :size),
      pending_nodes: pending_count,
      counters: state.stats,
      node_counts_by_type: count_nodes_by_type(),
      memory_bytes: :ets.info(@nodes_table, :memory) * :erlang.system_info(:wordsize) +
                    :ets.info(@edges_table, :memory) * :erlang.system_info(:wordsize) +
                    :ets.info(@adj_table, :memory) * :erlang.system_info(:wordsize)
    }

    {:reply, graph_stats, state}
  end

  @impl true
  def handle_call(:pending_nodes, _from, state) do
    pending = :ets.tab2list(@nodes_table)
    |> Enum.filter(fn {_key, data} -> data[:status] == :pending end)
    |> Enum.map(fn {_key, data} -> data end)
    |> Enum.take(100)  # Limit to 100 for performance

    {:reply, pending, state}
  end

  # -- PubSub event handling ----------------------------------------

  @impl true
  def handle_info({:telemetry_event, event}, state) do
    ingest_telemetry_event(event)
    {:noreply, state}
  end

  @impl true
  def handle_info({:alert_created, alert}, state) do
    ingest_alert(alert)
    {:noreply, state}
  end

  @impl true
  def handle_info({:agent_connected, agent_info}, state) do
    ingest_agent(agent_info)
    {:noreply, state}
  end

  @impl true
  def handle_info({:ai_component_discovered, component}, state) do
    ingest_ai_component(component)
    {:noreply, state}
  end

  @impl true
  def handle_info(:snapshot, state) do
    do_snapshot()
    Process.send_after(self(), :snapshot, @snapshot_interval_ms)
    new_stats = state.stats
    |> Map.update!(:snapshots_taken, &(&1 + 1))
    |> Map.put(:last_snapshot_at, DateTime.utc_now())
    {:noreply, %{state | stats: new_stats}}
  end

  @impl true
  def handle_info(:prune, state) do
    pruned = prune_expired_nodes()
    stale_pending = prune_stale_pending_nodes()

    total_pruned = pruned + stale_pending

    if total_pruned > 0 do
      Logger.info("[KnowledgeGraph] Pruned #{pruned} expired nodes, #{stale_pending} stale pending nodes")
    end

    Process.send_after(self(), :prune, @prune_interval_ms)
    new_stats = Map.update!(state.stats, :prune_cycles, &(&1 + 1))
    {:noreply, %{state | stats: new_stats}}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ------------------------------------------------------------------
  # Node/Edge Operations
  # ------------------------------------------------------------------

  defp do_upsert_node(type, id, attrs) do
    node_key = {type, id}
    now = DateTime.utc_now()

    node_data = attrs
    |> Map.put(:type, type)
    |> Map.put(:id, id)
    |> Map.put(:node_key, node_key)
    |> Map.put(:updated_at, now)
    |> Map.put_new(:created_at, now)
    |> Map.put_new(:risk_score, 0.0)

    # Merge with existing if present
    node_data = case :ets.lookup(@nodes_table, node_key) do
      [{^node_key, existing}] ->
        merged = Map.merge(existing, node_data)

        # If transitioning from pending to complete, remove pending flag
        if existing[:status] == :pending and attrs[:status] == :complete do
          Map.delete(merged, :stub)
        else
          merged
        end

      [] ->
        node_data
    end

    :ets.insert(@nodes_table, {node_key, node_data})

    # Check node count limit
    if :ets.info(@nodes_table, :size) > @max_nodes do
      prune_oldest_nodes(1000)
    end
  end

  defp do_add_edge(from, to, edge_type, attrs) do
    now = DateTime.utc_now()
    edge_key = {from, to, edge_type}

    edge_data = attrs
    |> Map.put(:from, from)
    |> Map.put(:to, to)
    |> Map.put(:edge_type, edge_type)
    |> Map.put(:created_at, now)
    |> Map.put_new(:weight, 1.0)

    # Remove existing edge of same type between same nodes (upsert)
    :ets.match_delete(@edges_table, {edge_key, :_})
    :ets.insert(@edges_table, {edge_key, edge_data})

    # Update adjacency lists
    :ets.insert(@adj_table, {from, {to, edge_type, edge_data}})
    :ets.insert(@reverse_adj_table, {to, {from, edge_type, edge_data}})

    # Validate both endpoint nodes exist, create pending if needed
    ensure_node_exists(from)
    ensure_node_exists(to)
  end

  defp do_remove_node(node_key) do
    # Remove all outgoing edges
    outgoing = :ets.lookup(@adj_table, node_key)
    Enum.each(outgoing, fn {_from, {to, edge_type, _data}} ->
      edge_key = {node_key, to, edge_type}
      :ets.match_delete(@edges_table, {edge_key, :_})
      :ets.match_delete(@reverse_adj_table, {to, {node_key, edge_type, :_}})
    end)
    :ets.delete(@adj_table, node_key)

    # Remove all incoming edges
    incoming = :ets.lookup(@reverse_adj_table, node_key)
    Enum.each(incoming, fn {_to, {from, edge_type, _data}} ->
      edge_key = {from, node_key, edge_type}
      :ets.match_delete(@edges_table, {edge_key, :_})
      :ets.match_delete(@adj_table, {from, {node_key, edge_type, :_}})
    end)
    :ets.delete(@reverse_adj_table, node_key)

    # Remove the node itself
    :ets.delete(@nodes_table, node_key)
  end

  defp do_remove_edge(from, to, edge_type) do
    edge_key = {from, to, edge_type}
    :ets.match_delete(@edges_table, {edge_key, :_})
    :ets.match_delete(@adj_table, {from, {to, edge_type, :_}})
    :ets.match_delete(@reverse_adj_table, {to, {from, edge_type, :_}})
  end

  defp ensure_node_exists({type, id}) do
    node_key = {type, id}
    case :ets.lookup(@nodes_table, node_key) do
      [] ->
        # Create pending node and queue enrichment job
        do_upsert_node(type, id, %{
          status: :pending,
          pending_since: DateTime.utc_now()
        })

        # Queue background job to enrich this node
        queue_enrichment_job(type, id)

      _ ->
        :ok
    end
  end

  defp queue_enrichment_job(type, id) do
    # Queue Oban job to fetch real data for this node
    Task.start(fn ->
      try do
        %{node_type: to_string(type), node_id: id}
        |> TamanduaServer.Jobs.NodeEnrichmentJob.new()
        |> Oban.insert()
      rescue
        e ->
          Logger.debug("[KnowledgeGraph] Failed to queue enrichment for #{type}:#{id}: #{inspect(e)}")
      end
    end)
  end

  defp get_outgoing_edges(node_key) do
    :ets.lookup(@adj_table, node_key)
    |> Enum.map(fn {_from, {to, edge_type, data}} ->
      %{to: to, edge_type: edge_type, data: data}
    end)
  end

  defp get_incoming_edges(node_key) do
    :ets.lookup(@reverse_adj_table, node_key)
    |> Enum.map(fn {_to, {from, edge_type, data}} ->
      %{from: from, edge_type: edge_type, data: data}
    end)
  end

  # ------------------------------------------------------------------
  # Graph Traversal
  # ------------------------------------------------------------------

  defp bfs_shortest_path(from, to) do
    # Verify both nodes exist
    case {:ets.lookup(@nodes_table, from), :ets.lookup(@nodes_table, to)} do
      {[], _} -> {:error, :not_found}
      {_, []} -> {:error, :not_found}
      _ -> do_bfs(from, to)
    end
  end

  defp do_bfs(from, to) do
    # BFS with parent tracking
    queue = :queue.in({from, []}, :queue.new())
    visited = MapSet.new([from])
    bfs_loop(queue, visited, to, 0)
  end

  defp bfs_loop(queue, visited, target, depth) when depth < 50 do
    case :queue.out(queue) do
      {:empty, _} ->
        {:error, :no_path}

      {{:value, {current, path}}, rest_queue} ->
        if current == target do
          {:ok, Enum.reverse(path)}
        else
          # Get all neighbors
          neighbors = :ets.lookup(@adj_table, current)

          {new_queue, new_visited} =
            Enum.reduce(neighbors, {rest_queue, visited}, fn {_from, {to_node, edge_type, _data}}, {q, v} ->
              if MapSet.member?(v, to_node) do
                {q, v}
              else
                step = %{from: current, to: to_node, edge_type: edge_type}
                new_path = [step | path]
                {:queue.in({to_node, new_path}, q), MapSet.put(v, to_node)}
              end
            end)

          bfs_loop(new_queue, new_visited, target, depth + 1)
        end
    end
  end

  defp bfs_loop(_queue, _visited, _target, _depth), do: {:error, :no_path}

  defp extract_subgraph(center, max_depth) do
    # BFS to collect nodes and edges within depth
    nodes = %{}
    edges = []
    queue = :queue.in({center, 0}, :queue.new())
    visited = MapSet.new([center])

    {collected_nodes, collected_edges} =
      subgraph_bfs(queue, visited, nodes, edges, max_depth)

    # Resolve node data
    resolved_nodes = Enum.map(collected_nodes, fn {key, depth} ->
      case :ets.lookup(@nodes_table, key) do
        [{^key, data}] -> Map.put(data, :depth, depth)
        [] -> %{node_key: key, depth: depth, status: :pending}
      end
    end)

    %{
      center: center,
      depth: max_depth,
      nodes: resolved_nodes,
      edges: collected_edges,
      node_count: map_size(collected_nodes),
      edge_count: length(collected_edges)
    }
  end

  defp subgraph_bfs(queue, visited, nodes, edges, max_depth) do
    case :queue.out(queue) do
      {:empty, _} ->
        {nodes, edges}

      {{:value, {current, depth}}, rest_queue} ->
        nodes = Map.put(nodes, current, depth)

        if depth >= max_depth do
          subgraph_bfs(rest_queue, visited, nodes, edges, max_depth)
        else
          # Get outgoing edges
          outgoing = :ets.lookup(@adj_table, current)

          {new_queue, new_visited, new_edges} =
            Enum.reduce(outgoing, {rest_queue, visited, edges}, fn {_from, {to_node, edge_type, data}}, {q, v, e} ->
              edge = %{from: current, to: to_node, edge_type: edge_type, data: data}
              new_e = [edge | e]

              if MapSet.member?(v, to_node) do
                {q, v, new_e}
              else
                {:queue.in({to_node, depth + 1}, q), MapSet.put(v, to_node), new_e}
              end
            end)

          subgraph_bfs(new_queue, new_visited, nodes, new_edges, max_depth)
        end
    end
  end

  # ------------------------------------------------------------------
  # Pattern Query
  # ------------------------------------------------------------------

  defp execute_pattern_query([]), do: []

  defp execute_pattern_query(pattern) do
    # Start from the first pattern step
    [{src_type, edge_type, dst_type, filters} | rest] = normalize_pattern(pattern)

    # Find all nodes of source type
    source_nodes = find_nodes_by_type(src_type)

    # For each source, try to match the full pattern
    results = Enum.flat_map(source_nodes, fn {node_key, node_data} ->
      initial_path = [%{node: node_data, step: 0}]
      match_pattern_step(node_key, edge_type, dst_type, filters, rest, initial_path, 1)
    end)

    Enum.take(results, 1000)
  end

  defp normalize_pattern(pattern) do
    Enum.map(pattern, fn
      {src, edge, dst, filters} -> {src, edge, dst, filters}
      {src, edge, dst} -> {src, edge, dst, %{}}
    end)
  end

  defp match_pattern_step(current_node, edge_type, target_type, filters, remaining_pattern, path, step_num) do
    # Find edges of the right type from current node
    edges = :ets.lookup(@adj_table, current_node)
    |> Enum.filter(fn {_from, {to_node, et, _data}} ->
      {t_type, _t_id} = to_node
      et == edge_type and t_type == target_type
    end)

    Enum.flat_map(edges, fn {_from, {to_node, _et, _data}} ->
      case :ets.lookup(@nodes_table, to_node) do
        [{^to_node, node_data}] ->
          # Apply filters
          if matches_filters?(node_data, filters) do
            new_path = path ++ [%{node: node_data, step: step_num}]

            case remaining_pattern do
              [] ->
                [%{path: new_path, match_length: step_num + 1}]

              [{next_edge, next_dst, next_filters} | rest] ->
                match_pattern_step(to_node, next_edge, next_dst, next_filters, rest, new_path, step_num + 1)

              [{_next_src, next_edge, next_dst, next_filters} | rest] ->
                match_pattern_step(to_node, next_edge, next_dst, next_filters, rest, new_path, step_num + 1)
            end
          else
            []
          end

        [] ->
          []
      end
    end)
  end

  defp matches_filters?(_node_data, filters) when map_size(filters) == 0, do: true

  defp matches_filters?(node_data, filters) do
    Enum.all?(filters, fn {key, value} ->
      node_value = node_data[key]
      cond do
        is_nil(node_value) -> false
        is_binary(value) and String.contains?(value, "*") ->
          pattern = value |> String.replace("*", ".*") |> Regex.compile!()
          Regex.match?(pattern, to_string(node_value))
        true ->
          node_value == value
      end
    end)
  end

  # ------------------------------------------------------------------
  # Attack Path Analysis
  # ------------------------------------------------------------------

  defp find_attack_paths(opts) do
    max_depth = Keyword.get(opts, :max_depth, 8)
    max_paths = Keyword.get(opts, :max_paths, 50)

    # Find internet-facing nodes (devices with external IPs, services with public ports)
    entry_points = find_entry_points()

    # Find critical assets (high criticality devices, sensitive files/services)
    critical_targets = find_critical_targets()

    # BFS from each entry point to find paths to critical targets
    paths = Enum.flat_map(entry_points, fn entry ->
      Enum.flat_map(critical_targets, fn target ->
        case bfs_shortest_path(entry, target) do
          {:ok, path} when length(path) <= max_depth -> [%{
            entry_point: entry,
            target: target,
            path: path,
            hops: length(path),
            risk_score: calculate_path_risk(path)
          }]
          _ -> []
        end
      end)
    end)
    |> Enum.sort_by(& &1.risk_score, :desc)
    |> Enum.take(max_paths)

    paths
  end

  defp find_entry_points do
    :ets.tab2list(@nodes_table)
    |> Enum.filter(fn {_key, data} ->
      (data[:type] == :network and data[:external] == true) or
      (data[:type] == :service and data[:internet_facing] == true) or
      (data[:type] == :device and data[:dmz] == true)
    end)
    |> Enum.map(fn {key, _data} -> key end)
    |> Enum.take(100)
  end

  defp find_critical_targets do
    :ets.tab2list(@nodes_table)
    |> Enum.filter(fn {_key, data} ->
      (data[:criticality] in ["critical", "high"]) or
      (data[:type] == :service and data[:contains_sensitive_data] == true) or
      (data[:type] == :device and data[:role] in ["domain_controller", "database", "key_vault"])
    end)
    |> Enum.map(fn {key, _data} -> key end)
    |> Enum.take(100)
  end

  defp calculate_path_risk(path) do
    # Higher risk for paths through vulnerable or high-privilege nodes
    base_risk = length(path) * 10.0

    vuln_bonus = Enum.reduce(path, 0.0, fn step, acc ->
      to_key = step[:to]
      case :ets.lookup(@nodes_table, to_key) do
        [{_k, data}] ->
          vuln_score = (data[:vulnerability_count] || 0) * 5.0
          priv_score = if data[:is_elevated] || data[:is_admin], do: 15.0, else: 0.0
          acc + vuln_score + priv_score
        [] -> acc
      end
    end)

    min(base_risk + vuln_bonus, 100.0)
  end

  # ------------------------------------------------------------------
  # Telemetry Ingestion
  # ------------------------------------------------------------------

  defp ingest_telemetry_event(event) do
    agent_id = event[:agent_id] || event["agent_id"]
    event_type = event[:event_type] || event["event_type"]
    payload = event[:payload] || event["payload"] || %{}

    case to_string(event_type) do
      type when type in ["process_create", "process"] ->
        ingest_process_event(agent_id, payload)

      type when type in ["network_connect", "network_listen"] ->
        ingest_network_event(agent_id, payload)

      type when type in ["file_create", "file_modify", "file_execute"] ->
        ingest_file_event(agent_id, payload)

      type when type in ["auth_login", "auth_failed"] ->
        ingest_auth_event(agent_id, payload)

      _ ->
        :ok
    end
  end

  defp ingest_process_event(agent_id, payload) do
    pid = payload[:pid] || payload["pid"]
    ppid = payload[:ppid] || payload["ppid"]
    name = payload[:name] || payload["name"]
    path = payload[:path] || payload["path"]

    if pid do
      proc_id = "#{agent_id}:#{pid}"
      do_upsert_node(:process, proc_id, %{
        name: name,
        path: path,
        hash: payload[:sha256] || payload["sha256"],
        signer: payload[:signer] || payload["signer"],
        is_elevated: payload[:is_elevated] || payload["is_elevated"],
        parent_pid: ppid,
        agent_id: agent_id
      })

      # Link process to device
      if agent_id do
        do_add_edge({:process, proc_id}, {:device, agent_id}, :runs_on, %{})
      end

      # Link child to parent
      if ppid do
        parent_id = "#{agent_id}:#{ppid}"
        do_add_edge({:process, proc_id}, {:process, parent_id}, :child_of, %{})
      end
    end
  end

  defp ingest_network_event(agent_id, payload) do
    remote_ip = payload[:remote_ip] || payload["remote_ip"]
    remote_port = payload[:remote_port] || payload["remote_port"]
    pid = payload[:pid] || payload["pid"]

    if remote_ip do
      net_id = "#{remote_ip}:#{remote_port}"
      do_upsert_node(:network, net_id, %{
        ip: remote_ip,
        port: remote_port,
        protocol: payload[:protocol] || payload["protocol"],
        domain: payload[:domain] || payload["domain"]
      })

      if agent_id do
        do_add_edge({:device, agent_id}, {:network, net_id}, :connects_to, %{
          bytes_sent: payload[:bytes_sent] || 0,
          bytes_received: payload[:bytes_received] || 0
        })
      end

      if pid do
        proc_id = "#{agent_id}:#{pid}"
        do_add_edge({:process, proc_id}, {:network, net_id}, :communicates_with, %{})
      end
    end
  end

  defp ingest_file_event(agent_id, payload) do
    file_path = payload[:path] || payload["path"]
    pid = payload[:pid] || payload["pid"]

    if file_path do
      file_id = "#{agent_id}:#{Base.encode16(:crypto.hash(:md5, file_path), case: :lower)}"
      do_upsert_node(:file, file_id, %{
        path: file_path,
        hash: payload[:sha256] || payload["sha256"],
        size: payload[:size] || payload["size"],
        classification: payload[:file_type] || payload["file_type"]
      })

      if pid do
        proc_id = "#{agent_id}:#{pid}"
        do_add_edge({:file, file_id}, {:process, proc_id}, :accessed_by, %{
          operation: payload[:operation] || payload["operation"]
        })
      end
    end
  end

  defp ingest_auth_event(agent_id, payload) do
    user = payload[:user] || payload["user"]

    if user and agent_id do
      do_upsert_node(:user, user, %{
        identity: user,
        last_seen: DateTime.utc_now()
      })

      do_add_edge({:device, agent_id}, {:user, user}, :authenticated_as, %{
        success: payload[:success] || true,
        timestamp: DateTime.utc_now()
      })
    end
  end

  defp ingest_alert(alert) do
    alert_id = alert[:id] || alert.id

    do_upsert_node(:alert, alert_id, %{
      severity: alert[:severity],
      title: alert[:title],
      description: alert[:description],
      mitre_tactics: alert[:mitre_tactics] || [],
      mitre_techniques: alert[:mitre_techniques] || [],
      timestamp: alert[:inserted_at] || DateTime.utc_now()
    })

    # Link to agent/device
    if agent_id = alert[:agent_id] do
      do_add_edge({:alert, alert_id}, {:device, agent_id}, :triggered_by, %{})
    end
  end

  defp ingest_agent(agent_info) do
    agent_id = agent_info[:agent_id] || agent_info[:id]
    hostname = agent_info[:hostname]
    os_type = agent_info[:os_type]

    if agent_id do
      do_upsert_node(:device, agent_id, %{
        hostname: hostname,
        os: os_type,
        agent_status: :connected,
        criticality: agent_info[:criticality] || "medium",
        ip_addresses: agent_info[:ip_addresses] || [],
        last_seen: DateTime.utc_now()
      })
    end
  end

  defp ingest_ai_component(component) do
    comp_id = component[:id] || "#{component[:agent_id]}:#{component[:name]}"

    node_type = case component[:component_type] do
      "mcp_server" -> :mcp_server
      _ -> :ai_model
    end

    do_upsert_node(node_type, comp_id, %{
      name: component[:name],
      component_type: component[:component_type],
      version: component[:version],
      install_path: component[:install_path],
      risk_indicators: component[:risk_indicators] || [],
      network_endpoints: component[:network_endpoints] || []
    })

    if agent_id = component[:agent_id] do
      do_add_edge({node_type, comp_id}, {:device, agent_id}, :deployed_on, %{})
    end
  end

  # ------------------------------------------------------------------
  # Snapshot to PostgreSQL
  # ------------------------------------------------------------------

  defp do_snapshot do
    Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
      try do
        node_count = :ets.info(@nodes_table, :size)
        edge_count = :ets.info(@edges_table, :size)

        # Persist graph summary to database
        snapshot_data = %{
          node_count: node_count,
          edge_count: edge_count,
          node_counts_by_type: count_nodes_by_type(),
          snapshot_at: DateTime.utc_now()
        }

        TamanduaServer.Repo.insert_all("knowledge_graph_snapshots", [
          %{
            id: Ecto.UUID.generate(),
            snapshot_data: snapshot_data,
            node_count: node_count,
            edge_count: edge_count,
            inserted_at: DateTime.utc_now(),
            updated_at: DateTime.utc_now()
          }
        ],
        on_conflict: :nothing,
        conflict_target: [])

        Logger.debug("[KnowledgeGraph] Snapshot saved: #{node_count} nodes, #{edge_count} edges")
      rescue
        e ->
          Logger.debug("[KnowledgeGraph] Snapshot skipped: #{inspect(e)}")
      end
    end)
  end

  # ------------------------------------------------------------------
  # Pruning
  # ------------------------------------------------------------------

  defp prune_expired_nodes do
    now = DateTime.utc_now()

    expired = :ets.tab2list(@nodes_table)
    |> Enum.filter(fn {_key, data} ->
      type = data[:type]
      updated_at = data[:updated_at]
      ttl = Map.get(@node_ttl, type, 604_800)

      updated_at != nil and
        DateTime.diff(now, updated_at, :second) > ttl
    end)
    |> Enum.map(fn {key, _data} -> key end)

    Enum.each(expired, &do_remove_node/1)
    length(expired)
  end

  defp prune_oldest_nodes(count) do
    :ets.tab2list(@nodes_table)
    |> Enum.sort_by(fn {_key, data} -> data[:updated_at] || DateTime.from_unix!(0) end)
    |> Enum.take(count)
    |> Enum.each(fn {key, _data} -> do_remove_node(key) end)
  end

  defp prune_stale_pending_nodes do
    # Remove pending nodes that have been pending for more than 1 hour
    # and have no edges (orphaned)
    now = DateTime.utc_now()
    pending_ttl_seconds = 3600  # 1 hour

    stale_pending = :ets.tab2list(@nodes_table)
    |> Enum.filter(fn {key, data} ->
      data[:status] == :pending and
        data[:pending_since] != nil and
        DateTime.diff(now, data[:pending_since], :second) > pending_ttl_seconds and
        is_orphaned_node?(key)
    end)
    |> Enum.map(fn {key, _data} -> key end)

    Enum.each(stale_pending, &do_remove_node/1)
    length(stale_pending)
  end

  defp is_orphaned_node?(node_key) do
    # A node is orphaned if it has no edges in either direction
    outgoing_count = length(:ets.lookup(@adj_table, node_key))
    incoming_count = length(:ets.lookup(@reverse_adj_table, node_key))
    outgoing_count == 0 and incoming_count == 0
  end

  # ------------------------------------------------------------------
  # Helpers
  # ------------------------------------------------------------------

  defp find_nodes_by_type(type) do
    :ets.tab2list(@nodes_table)
    |> Enum.filter(fn {{t, _id}, _data} -> t == type end)
  end

  defp count_nodes_by_type do
    :ets.tab2list(@nodes_table)
    |> Enum.group_by(fn {{type, _id}, _data} -> type end)
    |> Enum.map(fn {type, entries} -> {type, length(entries)} end)
    |> Map.new()
  end

  defp count_pending_nodes do
    :ets.tab2list(@nodes_table)
    |> Enum.count(fn {_key, data} -> data[:status] == :pending end)
  end

  defp subscribe_to_streams do
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "telemetry:events")
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "alerts:feed")
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "agents:status")
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "ai_security:discovery")
  rescue
    _ -> :ok
  end
end
