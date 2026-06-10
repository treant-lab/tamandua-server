defmodule TamanduaServer.Graph.Analytics do
  @moduledoc """
  Graph Analytics Engine for the Enterprise Knowledge Graph.

  Provides advanced graph analytics capabilities:
  - **Centrality scoring**: identify most-connected/critical nodes
  - **Community detection**: find clusters of related entities
  - **Anomaly detection**: unusual edge patterns, new connections, high-degree nodes
  - **Blast radius estimation**: given a compromised node, what is reachable?
  - **Risk propagation**: propagate risk scores through edges
  - **Attack surface mapping**: enumerate paths from external to internal critical assets

  All analytics read directly from the KnowledgeGraph ETS tables for performance.
  Heavy computations are run asynchronously via Task.Supervisor.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Graph.KnowledgeGraph

  @nodes_table :knowledge_graph_nodes
  @adj_table :knowledge_graph_adjacency
  @reverse_adj_table :knowledge_graph_reverse_adj

  # Analytics cache ETS
  @cache_table :graph_analytics_cache
  # Cache TTL: 5 minutes
  @cache_ttl_ms 300_000
  # Risk propagation decay per hop
  @risk_decay 0.6
  # Max BFS depth for blast radius
  @max_blast_depth 6
  # Recalculation interval: 10 minutes
  @recalc_interval_ms 600_000

  # ------------------------------------------------------------------
  # Client API
  # ------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Calculate centrality scores for all nodes or nodes of a specific type.
  Returns nodes sorted by centrality (most central first).

  Centrality is degree-based: in_degree + out_degree, weighted by neighbor importance.
  """
  @spec centrality(keyword()) :: {:ok, [map()]}
  def centrality(opts \\ []) do
    GenServer.call(__MODULE__, {:centrality, opts}, 60_000)
  end

  @doc """
  Detect communities (clusters) of related entities using label propagation.
  Returns a list of communities, each with their member nodes.
  """
  @spec communities(keyword()) :: {:ok, [map()]}
  def communities(opts \\ []) do
    GenServer.call(__MODULE__, {:communities, opts}, 60_000)
  end

  @doc """
  Detect anomalies in the graph: unusual edge patterns, high-degree nodes,
  new connections to sensitive assets, etc.
  """
  @spec anomalies(keyword()) :: {:ok, [map()]}
  def anomalies(opts \\ []) do
    GenServer.call(__MODULE__, {:anomalies, opts}, 60_000)
  end

  @doc """
  Estimate blast radius for a compromised node. Returns all nodes reachable
  from the compromised node within a configurable depth, with impact scores.
  """
  @spec blast_radius(atom(), String.t(), keyword()) :: {:ok, map()}
  def blast_radius(node_type, node_id, opts \\ []) do
    GenServer.call(__MODULE__, {:blast_radius, {node_type, node_id}, opts}, 60_000)
  end

  @doc """
  Propagate risk scores through the graph. Starting from nodes with known
  risk (alerts, vulnerabilities), propagate risk to connected nodes with decay.
  """
  @spec propagate_risk(keyword()) :: {:ok, map()}
  def propagate_risk(opts \\ []) do
    GenServer.call(__MODULE__, {:propagate_risk, opts}, 60_000)
  end

  @doc """
  Map the attack surface: enumerate all paths from external-facing assets
  to internal critical assets, scoring each path by exploitability.
  """
  @spec attack_surface(keyword()) :: {:ok, map()}
  def attack_surface(opts \\ []) do
    GenServer.call(__MODULE__, {:attack_surface, opts}, 60_000)
  end

  @doc """
  Get analytics summary/dashboard data.
  """
  @spec summary() :: {:ok, map()}
  def summary do
    GenServer.call(__MODULE__, :summary, 30_000)
  end

  # ------------------------------------------------------------------
  # Server Callbacks
  # ------------------------------------------------------------------

  @impl true
  def init(_opts) do
    :ets.new(@cache_table, [:set, :public, :named_table, read_concurrency: true])

    # Schedule periodic recalculation
    Process.send_after(self(), :recalculate, @recalc_interval_ms)

    Logger.info("[GraphAnalytics] Graph Analytics Engine started")

    {:ok, %{
      last_centrality: nil,
      last_communities: nil,
      last_anomalies: nil,
      last_risk_propagation: nil,
      stats: %{
        centrality_runs: 0,
        community_runs: 0,
        anomaly_runs: 0,
        blast_radius_runs: 0,
        risk_propagations: 0
      }
    }}
  end

  @impl true
  def handle_call({:centrality, opts}, _from, state) do
    result = cached_or_compute(:centrality, opts, fn -> compute_centrality(opts) end)
    new_stats = Map.update!(state.stats, :centrality_runs, &(&1 + 1))
    {:reply, {:ok, result}, %{state | stats: new_stats, last_centrality: DateTime.utc_now()}}
  end

  @impl true
  def handle_call({:communities, opts}, _from, state) do
    result = cached_or_compute(:communities, opts, fn -> compute_communities(opts) end)
    new_stats = Map.update!(state.stats, :community_runs, &(&1 + 1))
    {:reply, {:ok, result}, %{state | stats: new_stats, last_communities: DateTime.utc_now()}}
  end

  @impl true
  def handle_call({:anomalies, opts}, _from, state) do
    result = cached_or_compute(:anomalies, opts, fn -> compute_anomalies(opts) end)
    new_stats = Map.update!(state.stats, :anomaly_runs, &(&1 + 1))
    {:reply, {:ok, result}, %{state | stats: new_stats, last_anomalies: DateTime.utc_now()}}
  end

  @impl true
  def handle_call({:blast_radius, node_key, opts}, _from, state) do
    result = compute_blast_radius(node_key, opts)
    new_stats = Map.update!(state.stats, :blast_radius_runs, &(&1 + 1))
    {:reply, {:ok, result}, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:propagate_risk, opts}, _from, state) do
    result = cached_or_compute(:risk_propagation, opts, fn -> compute_risk_propagation(opts) end)
    new_stats = Map.update!(state.stats, :risk_propagations, &(&1 + 1))
    {:reply, {:ok, result}, %{state | stats: new_stats, last_risk_propagation: DateTime.utc_now()}}
  end

  @impl true
  def handle_call({:attack_surface, opts}, _from, state) do
    result = cached_or_compute(:attack_surface, opts, fn -> compute_attack_surface(opts) end)
    {:reply, {:ok, result}, state}
  end

  @impl true
  def handle_call(:summary, _from, state) do
    summary = build_summary(state)
    {:reply, {:ok, summary}, state}
  end

  @impl true
  def handle_info(:recalculate, state) do
    # Background recalculation of expensive analytics
    Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
      try do
        compute_centrality([])
        compute_anomalies([])
        compute_risk_propagation([])
      rescue
        e -> Logger.debug("[GraphAnalytics] Background recalc error: #{inspect(e)}")
      end
    end)

    Process.send_after(self(), :recalculate, @recalc_interval_ms)
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ------------------------------------------------------------------
  # Centrality Scoring
  # ------------------------------------------------------------------

  defp compute_centrality(opts) do
    type_filter = Keyword.get(opts, :type)
    limit = Keyword.get(opts, :limit, 100)

    nodes = :ets.tab2list(@nodes_table)
    |> maybe_filter_by_type(type_filter)

    scored = Enum.map(nodes, fn {node_key, node_data} ->
      out_degree = length(:ets.lookup(@adj_table, node_key))
      in_degree = length(:ets.lookup(@reverse_adj_table, node_key))
      total_degree = out_degree + in_degree

      # Weighted centrality: neighbors with high degree amplify centrality
      neighbor_weight = compute_neighbor_weight(node_key)

      centrality_score = total_degree * 1.0 + neighbor_weight * 0.3

      Map.merge(node_data, %{
        centrality_score: Float.round(centrality_score, 2),
        out_degree: out_degree,
        in_degree: in_degree,
        total_degree: total_degree,
        neighbor_weight: Float.round(neighbor_weight, 2)
      })
    end)
    |> Enum.sort_by(& &1.centrality_score, :desc)
    |> Enum.take(limit)

    cache_result(:centrality, opts, scored)
    scored
  end

  defp compute_neighbor_weight(node_key) do
    :ets.lookup(@adj_table, node_key)
    |> Enum.reduce(0.0, fn {_from, {to_node, _edge_type, _data}}, acc ->
      neighbor_degree = length(:ets.lookup(@adj_table, to_node)) +
                        length(:ets.lookup(@reverse_adj_table, to_node))
      acc + :math.log(max(neighbor_degree, 1) + 1)
    end)
  end

  # ------------------------------------------------------------------
  # Community Detection (Label Propagation)
  # ------------------------------------------------------------------

  defp compute_communities(opts) do
    max_iterations = Keyword.get(opts, :max_iterations, 10)
    min_community_size = Keyword.get(opts, :min_size, 3)

    # Initialize each node with its own label
    nodes = :ets.tab2list(@nodes_table)
    initial_labels = Enum.into(nodes, %{}, fn {key, _data} -> {key, key} end)

    # Iterative label propagation
    final_labels = Enum.reduce(1..max_iterations, initial_labels, fn _iter, labels ->
      propagate_labels(labels, nodes)
    end)

    # Group by label to form communities
    communities = final_labels
    |> Enum.group_by(fn {_node, label} -> label end)
    |> Enum.filter(fn {_label, members} -> length(members) >= min_community_size end)
    |> Enum.map(fn {label, members} ->
      member_keys = Enum.map(members, fn {node_key, _} -> node_key end)

      member_data = Enum.map(member_keys, fn key ->
        case :ets.lookup(@nodes_table, key) do
          [{^key, data}] -> data
          [] -> %{node_key: key, status: :pending}
        end
      end)

      # Determine dominant type in community
      type_counts = Enum.frequencies_by(member_data, & &1[:type])
      dominant_type = type_counts
      |> Enum.max_by(fn {_t, c} -> c end, fn -> {nil, 0} end)
      |> elem(0)

      %{
        id: inspect(label),
        size: length(members),
        dominant_type: dominant_type,
        type_distribution: type_counts,
        members: Enum.take(member_data, 50),
        internal_edges: count_internal_edges(member_keys)
      }
    end)
    |> Enum.sort_by(& &1.size, :desc)

    cache_result(:communities, opts, communities)
    communities
  end

  defp propagate_labels(labels, nodes) do
    Enum.reduce(nodes, labels, fn {node_key, _data}, acc ->
      # Get neighbor labels
      neighbors = :ets.lookup(@adj_table, node_key) ++
                  :ets.lookup(@reverse_adj_table, node_key)

      neighbor_labels = Enum.map(neighbors, fn
        {_from, {to, _et, _d}} -> Map.get(acc, to, to)
        {_to, {from, _et, _d}} -> Map.get(acc, from, from)
      end)

      if Enum.empty?(neighbor_labels) do
        acc
      else
        # Most frequent neighbor label wins
        most_common = neighbor_labels
        |> Enum.frequencies()
        |> Enum.max_by(fn {_label, count} -> count end)
        |> elem(0)

        Map.put(acc, node_key, most_common)
      end
    end)
  end

  defp count_internal_edges(member_keys) do
    member_set = MapSet.new(member_keys)

    Enum.reduce(member_keys, 0, fn key, acc ->
      edges = :ets.lookup(@adj_table, key)
      internal = Enum.count(edges, fn {_from, {to, _et, _d}} ->
        MapSet.member?(member_set, to)
      end)
      acc + internal
    end)
  end

  # ------------------------------------------------------------------
  # Anomaly Detection
  # ------------------------------------------------------------------

  defp compute_anomalies(opts) do
    limit = Keyword.get(opts, :limit, 100)
    recency_hours = Keyword.get(opts, :recency_hours, 24)
    recency_threshold = DateTime.utc_now() |> DateTime.add(-recency_hours * 3600, :second)

    anomalies = []

    # 1. High-degree anomalies (nodes with unusually many connections)
    degree_anomalies = detect_degree_anomalies()
    anomalies = anomalies ++ degree_anomalies

    # 2. New connections to critical assets
    new_connection_anomalies = detect_new_connections(recency_threshold)
    anomalies = anomalies ++ new_connection_anomalies

    # 3. Unusual edge patterns (e.g., process communicating with many unique IPs)
    pattern_anomalies = detect_pattern_anomalies()
    anomalies = anomalies ++ pattern_anomalies

    # 4. Isolated high-risk nodes (high risk but few connections)
    isolation_anomalies = detect_isolation_anomalies()
    anomalies = anomalies ++ isolation_anomalies

    result = anomalies
    |> Enum.sort_by(& &1.severity_score, :desc)
    |> Enum.take(limit)

    cache_result(:anomalies, opts, result)
    result
  end

  defp detect_degree_anomalies do
    nodes = :ets.tab2list(@nodes_table)

    # Calculate mean and stddev of degree per type
    degrees_by_type = Enum.group_by(nodes, fn {{type, _id}, _data} -> type end)
    |> Enum.into(%{}, fn {type, type_nodes} ->
      degrees = Enum.map(type_nodes, fn {key, _data} ->
        length(:ets.lookup(@adj_table, key)) + length(:ets.lookup(@reverse_adj_table, key))
      end)

      mean = if Enum.empty?(degrees), do: 0.0, else: Enum.sum(degrees) / length(degrees)
      variance = if length(degrees) < 2 do
        0.0
      else
        Enum.reduce(degrees, 0.0, fn d, acc -> acc + :math.pow(d - mean, 2) end) / length(degrees)
      end
      stddev = :math.sqrt(variance)

      {type, %{mean: mean, stddev: stddev}}
    end)

    # Find outliers (> 2 stddev above mean)
    Enum.flat_map(nodes, fn {node_key = {type, _id}, data} ->
      degree = length(:ets.lookup(@adj_table, node_key)) +
               length(:ets.lookup(@reverse_adj_table, node_key))

      stats = Map.get(degrees_by_type, type, %{mean: 0, stddev: 0})
      threshold = stats.mean + 2 * max(stats.stddev, 1)

      if degree > threshold and degree > 5 do
        [%{
          type: :high_degree,
          node: data,
          node_key: node_key,
          degree: degree,
          threshold: Float.round(threshold, 1),
          severity_score: min((degree - threshold) / max(stats.stddev, 1) * 20, 100),
          description: "Node #{type}:#{data[:id]} has #{degree} connections (threshold: #{Float.round(threshold, 1)})"
        }]
      else
        []
      end
    end)
  end

  defp detect_new_connections(threshold) do
    # Find edges created recently to critical nodes
    :ets.tab2list(@nodes_table)
    |> Enum.filter(fn {_key, data} ->
      data[:criticality] in ["critical", "high"]
    end)
    |> Enum.flat_map(fn {node_key, node_data} ->
      incoming = :ets.lookup(@reverse_adj_table, node_key)
      |> Enum.filter(fn {_to, {_from, _et, edge_data}} ->
        created = edge_data[:created_at]
        created != nil and DateTime.compare(created, threshold) == :gt
      end)

      Enum.map(incoming, fn {_to, {from_key, edge_type, edge_data}} ->
        %{
          type: :new_connection_to_critical,
          from: from_key,
          to: node_key,
          edge_type: edge_type,
          target_node: node_data,
          edge_created_at: edge_data[:created_at],
          severity_score: 60.0,
          description: "New #{edge_type} connection to critical asset #{node_data[:id]}"
        }
      end)
    end)
  end

  defp detect_pattern_anomalies do
    # Processes communicating with many unique external IPs
    :ets.tab2list(@nodes_table)
    |> Enum.filter(fn {{type, _id}, _data} -> type == :process end)
    |> Enum.flat_map(fn {proc_key, proc_data} ->
      network_edges = :ets.lookup(@adj_table, proc_key)
      |> Enum.filter(fn {_from, {to, et, _d}} ->
        {to_type, _} = to
        et == :communicates_with and to_type == :network
      end)

      unique_targets = length(network_edges)

      if unique_targets > 20 do
        [%{
          type: :high_fan_out,
          node: proc_data,
          node_key: proc_key,
          unique_targets: unique_targets,
          severity_score: min(unique_targets * 2.0, 80.0),
          description: "Process #{proc_data[:name]} communicates with #{unique_targets} unique network endpoints"
        }]
      else
        []
      end
    end)
  end

  defp detect_isolation_anomalies do
    :ets.tab2list(@nodes_table)
    |> Enum.filter(fn {_key, data} ->
      risk = data[:risk_score] || 0.0
      risk > 50
    end)
    |> Enum.flat_map(fn {node_key, node_data} ->
      degree = length(:ets.lookup(@adj_table, node_key)) +
               length(:ets.lookup(@reverse_adj_table, node_key))

      if degree <= 1 do
        [%{
          type: :isolated_high_risk,
          node: node_data,
          node_key: node_key,
          risk_score: node_data[:risk_score],
          degree: degree,
          severity_score: (node_data[:risk_score] || 0) * 0.8,
          description: "High-risk node #{node_data[:type]}:#{node_data[:id]} with only #{degree} connections"
        }]
      else
        []
      end
    end)
  end

  # ------------------------------------------------------------------
  # Blast Radius Estimation
  # ------------------------------------------------------------------

  defp compute_blast_radius(node_key, opts) do
    max_depth = Keyword.get(opts, :max_depth, @max_blast_depth)

    case :ets.lookup(@nodes_table, node_key) do
      [] ->
        %{error: :not_found}

      [{^node_key, source_data}] ->
        # BFS to find all reachable nodes with distance
        {reachable, total_impact} = bfs_blast_radius(node_key, max_depth)

        # Categorize impact
        impact_by_type = Enum.group_by(reachable, fn {key, _dist, _score} ->
          {type, _id} = key
          type
        end)
        |> Enum.map(fn {type, entries} ->
          {type, %{
            count: length(entries),
            total_impact: Enum.reduce(entries, 0.0, fn {_, _, score}, acc -> acc + score end),
            critical_count: Enum.count(entries, fn {key, _, _} ->
              case :ets.lookup(@nodes_table, key) do
                [{_, data}] -> data[:criticality] in ["critical", "high"]
                [] -> false
              end
            end)
          }}
        end)
        |> Map.new()

        %{
          source: source_data,
          source_key: node_key,
          max_depth: max_depth,
          total_reachable: length(reachable),
          total_impact_score: Float.round(total_impact, 2),
          impact_by_type: impact_by_type,
          critical_assets_at_risk: count_critical_in_blast(reachable),
          reachable_nodes: Enum.take(
            Enum.sort_by(reachable, fn {_, _, score} -> -score end),
            200
          )
          |> Enum.map(fn {key, dist, score} ->
            data = case :ets.lookup(@nodes_table, key) do
              [{^key, d}] -> d
              [] -> %{node_key: key}
            end
            Map.merge(data, %{distance: dist, impact_score: Float.round(score, 2)})
          end)
        }
    end
  end

  defp bfs_blast_radius(start, max_depth) do
    queue = :queue.in({start, 0, 100.0}, :queue.new())
    visited = MapSet.new([start])
    reachable = []

    bfs_blast_loop(queue, visited, reachable, max_depth)
  end

  defp bfs_blast_loop(queue, visited, reachable, max_depth) do
    case :queue.out(queue) do
      {:empty, _} ->
        total_impact = Enum.reduce(reachable, 0.0, fn {_, _, score}, acc -> acc + score end)
        {reachable, total_impact}

      {{:value, {current, depth, score}}, rest} ->
        reachable = [{current, depth, score} | reachable]

        if depth >= max_depth do
          bfs_blast_loop(rest, visited, reachable, max_depth)
        else
          neighbors = :ets.lookup(@adj_table, current)
          next_score = score * @risk_decay

          {new_queue, new_visited} =
            Enum.reduce(neighbors, {rest, visited}, fn {_from, {to, _et, _d}}, {q, v} ->
              if MapSet.member?(v, to) do
                {q, v}
              else
                {:queue.in({to, depth + 1, next_score}, q), MapSet.put(v, to)}
              end
            end)

          bfs_blast_loop(new_queue, new_visited, reachable, max_depth)
        end
    end
  end

  defp count_critical_in_blast(reachable) do
    Enum.count(reachable, fn {key, _dist, _score} ->
      case :ets.lookup(@nodes_table, key) do
        [{_, data}] -> data[:criticality] in ["critical", "high"]
        [] -> false
      end
    end)
  end

  # ------------------------------------------------------------------
  # Risk Propagation
  # ------------------------------------------------------------------

  defp compute_risk_propagation(opts) do
    max_hops = Keyword.get(opts, :max_hops, 4)

    # Find all risk sources (alerts, vulnerabilities, high-risk nodes)
    risk_sources = :ets.tab2list(@nodes_table)
    |> Enum.filter(fn {_key, data} ->
      (data[:type] == :alert) or
      (data[:type] == :vulnerability) or
      ((data[:risk_score] || 0) > 70)
    end)

    # Propagate from each source
    propagated_risk = Enum.reduce(risk_sources, %{}, fn {source_key, source_data}, acc ->
      source_risk = source_data[:risk_score] || severity_to_risk(source_data[:severity])
      propagate_from_source(source_key, source_risk, max_hops, acc)
    end)

    # Apply propagated risk to nodes
    updates = Enum.map(propagated_risk, fn {node_key, accumulated_risk} ->
      case :ets.lookup(@nodes_table, node_key) do
        [{^node_key, data}] ->
          current_risk = data[:risk_score] || 0.0
          new_risk = min(current_risk + accumulated_risk * 0.5, 100.0)

          # Update the node
          updated = Map.put(data, :propagated_risk, Float.round(accumulated_risk, 2))
          :ets.insert(@nodes_table, {node_key, updated})

          %{node_key: node_key, original_risk: current_risk, propagated_risk: accumulated_risk, new_risk: new_risk}
        [] ->
          nil
      end
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.sort_by(& &1.propagated_risk, :desc)

    result = %{
      sources_count: length(risk_sources),
      nodes_affected: length(updates),
      top_affected: Enum.take(updates, 50),
      propagation_depth: max_hops,
      computed_at: DateTime.utc_now()
    }

    cache_result(:risk_propagation, opts, result)
    result
  end

  defp propagate_from_source(source_key, risk_value, max_hops, acc) do
    queue = :queue.in({source_key, 0, risk_value}, :queue.new())
    visited = MapSet.new([source_key])
    propagate_bfs(queue, visited, max_hops, acc)
  end

  defp propagate_bfs(queue, visited, max_hops, acc) do
    case :queue.out(queue) do
      {:empty, _} -> acc

      {{:value, {current, depth, risk}}, rest} ->
        # Add risk to accumulator
        acc = Map.update(acc, current, risk, &(&1 + risk))

        if depth >= max_hops or risk < 1.0 do
          propagate_bfs(rest, visited, max_hops, acc)
        else
          neighbors = :ets.lookup(@adj_table, current) ++
                      :ets.lookup(@reverse_adj_table, current)

          next_risk = risk * @risk_decay

          {new_queue, new_visited} =
            Enum.reduce(neighbors, {rest, visited}, fn
              {_from, {to, _et, _d}}, {q, v} ->
                if MapSet.member?(v, to) do
                  {q, v}
                else
                  {:queue.in({to, depth + 1, next_risk}, q), MapSet.put(v, to)}
                end
              {_to, {from, _et, _d}}, {q, v} ->
                if MapSet.member?(v, from) do
                  {q, v}
                else
                  {:queue.in({from, depth + 1, next_risk}, q), MapSet.put(v, from)}
                end
            end)

          propagate_bfs(new_queue, new_visited, max_hops, acc)
        end
    end
  end

  defp severity_to_risk("critical"), do: 90.0
  defp severity_to_risk("high"), do: 70.0
  defp severity_to_risk("medium"), do: 40.0
  defp severity_to_risk("low"), do: 20.0
  defp severity_to_risk(:critical), do: 90.0
  defp severity_to_risk(:high), do: 70.0
  defp severity_to_risk(:medium), do: 40.0
  defp severity_to_risk(:low), do: 20.0
  defp severity_to_risk(_), do: 10.0

  # ------------------------------------------------------------------
  # Attack Surface Mapping
  # ------------------------------------------------------------------

  defp compute_attack_surface(opts) do
    max_depth = Keyword.get(opts, :max_depth, 8)
    max_paths = Keyword.get(opts, :max_paths, 100)

    # Entry points: internet-facing, external, DMZ
    entry_points = :ets.tab2list(@nodes_table)
    |> Enum.filter(fn {_key, data} ->
      data[:internet_facing] == true or
      data[:external] == true or
      data[:dmz] == true or
      (data[:type] == :network and is_external_ip?(data[:ip]))
    end)
    |> Enum.map(fn {key, _} -> key end)

    # Critical targets
    targets = :ets.tab2list(@nodes_table)
    |> Enum.filter(fn {_key, data} ->
      data[:criticality] in ["critical", "high"] or
      data[:contains_sensitive_data] == true or
      data[:role] in ["domain_controller", "database", "key_vault", "certificate_authority"]
    end)
    |> Enum.map(fn {key, _} -> key end)

    # Find paths
    paths = Enum.flat_map(entry_points, fn entry ->
      Enum.flat_map(targets, fn target ->
        case KnowledgeGraph.shortest_path(entry, target) do
          {:ok, path} when length(path) <= max_depth ->
            path_risk = score_attack_path(path)
            [%{
              entry_point: entry,
              target: target,
              hops: length(path),
              path: path,
              risk_score: path_risk,
              vulnerabilities_on_path: count_vulns_on_path(path)
            }]
          _ -> []
        end
      end)
    end)
    |> Enum.sort_by(& &1.risk_score, :desc)
    |> Enum.take(max_paths)

    %{
      entry_points: length(entry_points),
      critical_targets: length(targets),
      total_paths_found: length(paths),
      highest_risk_paths: paths,
      overall_exposure_score: if(Enum.empty?(paths), do: 0.0,
        else: Enum.sum(Enum.map(paths, & &1.risk_score)) / length(paths)),
      computed_at: DateTime.utc_now()
    }
  end

  defp is_external_ip?(nil), do: false
  defp is_external_ip?(ip) when is_binary(ip) do
    not (String.starts_with?(ip, "10.") or
         String.starts_with?(ip, "172.16.") or
         String.starts_with?(ip, "192.168.") or
         String.starts_with?(ip, "127.") or
         ip == "::1")
  end
  defp is_external_ip?(_), do: false

  defp score_attack_path(path) do
    base = 100.0 / max(length(path), 1)  # Shorter paths = higher risk

    Enum.reduce(path, base, fn step, acc ->
      to_key = step[:to]
      case :ets.lookup(@nodes_table, to_key) do
        [{_, data}] ->
          vuln_bonus = (data[:vulnerability_count] || 0) * 3.0
          elevated_bonus = if data[:is_elevated], do: 10.0, else: 0.0
          acc + vuln_bonus + elevated_bonus
        [] -> acc
      end
    end)
    |> min(100.0)
  end

  defp count_vulns_on_path(path) do
    Enum.reduce(path, 0, fn step, acc ->
      to_key = step[:to]
      case :ets.lookup(@nodes_table, to_key) do
        [{_, data}] -> acc + (data[:vulnerability_count] || 0)
        [] -> acc
      end
    end)
  end

  # ------------------------------------------------------------------
  # Summary
  # ------------------------------------------------------------------

  defp build_summary(state) do
    node_count = :ets.info(@nodes_table, :size)
    edge_count = :ets.info(@adj_table, :size)

    # Node distribution
    type_dist = :ets.tab2list(@nodes_table)
    |> Enum.group_by(fn {{type, _}, _} -> type end)
    |> Enum.map(fn {type, entries} -> {type, length(entries)} end)
    |> Map.new()

    # High risk nodes
    high_risk_count = :ets.tab2list(@nodes_table)
    |> Enum.count(fn {_, data} -> (data[:risk_score] || 0) > 70 end)

    %{
      node_count: node_count,
      edge_count: edge_count,
      node_distribution: type_dist,
      high_risk_nodes: high_risk_count,
      stats: state.stats,
      last_centrality: state.last_centrality,
      last_communities: state.last_communities,
      last_anomalies: state.last_anomalies,
      last_risk_propagation: state.last_risk_propagation,
      computed_at: DateTime.utc_now()
    }
  end

  # ------------------------------------------------------------------
  # Caching
  # ------------------------------------------------------------------

  defp cached_or_compute(key, opts, compute_fn) do
    cache_key = {key, :erlang.phash2(opts)}

    case :ets.lookup(@cache_table, cache_key) do
      [{^cache_key, {result, cached_at}}] ->
        age = DateTime.diff(DateTime.utc_now(), cached_at, :millisecond)
        if age < @cache_ttl_ms, do: result, else: compute_fn.()

      [] ->
        compute_fn.()
    end
  end

  defp cache_result(key, opts, result) do
    cache_key = {key, :erlang.phash2(opts)}
    :ets.insert(@cache_table, {cache_key, {result, DateTime.utc_now()}})
  end

  defp maybe_filter_by_type(nodes, nil), do: nodes
  defp maybe_filter_by_type(nodes, type) do
    Enum.filter(nodes, fn {{t, _id}, _data} -> t == type end)
  end
end
