defmodule TamanduaServer.Alerts.CorrelationEngine do
  @moduledoc """
  Advanced alert correlation engine for building multi-dimensional correlation graphs.

  Features:
  - Time-based correlation (events within configurable windows)
  - Entity-based correlation (shared IOCs, users, processes, files)
  - Behavioral correlation (similar MITRE TTPs)
  - ML-based correlation (alert embeddings similarity)
  - Graph-based correlation (multi-hop relationships)
  """
  use GenServer
  require Logger

  import Ecto.Query
  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts.{Alert, AlertCorrelation, GraphBuilder, Timestamp}
  alias TamanduaServer.Agents.Agent

  # Correlation configuration
  @default_time_window_seconds 3600  # 1 hour
  @default_similarity_threshold 0.6
  @max_correlation_depth 3
  @generic_techniques ~w(T1059 T1105 T1027 T1071)

  # Weight factors for correlation scoring
  @weights %{
    temporal: 0.15,
    entity: 0.30,
    behavioral: 0.25,
    ml: 0.20,
    network: 0.10
  }

  ## Client API

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Correlate a single alert with existing alerts.
  Returns list of {alert, score, correlation_type} tuples.
  """
  def correlate_alert(alert_id, opts \\ []) do
    GenServer.call(__MODULE__, {:correlate_alert, alert_id, opts}, 30_000)
  end

  @doc """
  Build correlation graph for a set of alerts.
  Returns graph structure with nodes and edges.
  """
  def build_correlation_graph(alert_ids, opts \\ []) do
    GenServer.call(__MODULE__, {:build_graph, alert_ids, opts}, 60_000)
  end

  @doc """
  Find attack paths between two alerts (multi-hop correlation).
  """
  def find_attack_paths(source_alert_id, target_alert_id, opts \\ []) do
    GenServer.call(__MODULE__, {:find_paths, source_alert_id, target_alert_id, opts}, 30_000)
  end

  @doc """
  Get correlation statistics for an organization.
  """
  def get_correlation_stats(organization_id) do
    GenServer.call(__MODULE__, {:stats, organization_id})
  end

  ## Server Callbacks

  @impl true
  def init(_opts) do
    state = %{
      correlation_cache: %{},
      stats: %{
        correlations_created: 0,
        graphs_built: 0
      }
    }

    Logger.info("[CorrelationEngine] Started")
    {:ok, state}
  end

  @impl true
  def handle_call({:correlate_alert, alert_id, opts}, _from, state) do
    result = do_correlate_alert(alert_id, opts)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:build_graph, alert_ids, opts}, _from, state) do
    result = do_build_correlation_graph(alert_ids, opts)
    new_state = update_in(state.stats.graphs_built, &(&1 + 1))
    {:reply, result, new_state}
  end

  @impl true
  def handle_call({:find_paths, source_id, target_id, opts}, _from, state) do
    result = do_find_attack_paths(source_id, target_id, opts)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:stats, organization_id}, _from, state) do
    result = do_get_stats(organization_id)
    {:reply, result, state}
  end

  ## Private Functions

  defp do_correlate_alert(alert_id, opts) do
    alert = Repo.get(Alert, alert_id) |> Repo.preload([:agent])

    if alert do
      time_window = Keyword.get(opts, :time_window_seconds, @default_time_window_seconds)
      threshold = Keyword.get(opts, :threshold, @default_similarity_threshold)

      # Find candidate alerts within time window
      candidates = find_candidate_alerts(alert, time_window)

      # Score each candidate
      correlations = candidates
      |> Enum.map(fn candidate ->
        score = calculate_correlation_score(alert, candidate)
        correlation_types = determine_correlation_types(alert, candidate)

        {candidate, score, correlation_types}
      end)
      |> Enum.filter(fn {candidate, score, types} ->
        score >= threshold and actionable_correlation?(alert, candidate, types)
      end)
      |> Enum.sort_by(fn {_alert, score, _types} -> -score end)

      # Persist correlations
      Enum.each(correlations, fn {candidate, score, types} ->
        persist_correlation(alert, candidate, score, types)
      end)

      {:ok, correlations}
    else
      {:error, :alert_not_found}
    end
  end

  defp do_build_correlation_graph(alert_ids, opts) do
    depth = Keyword.get(opts, :depth, 2)
    include_ml = Keyword.get(opts, :include_ml, true)

    # Load alerts with correlations
    alerts = from(a in Alert,
      where: a.id in ^alert_ids,
      preload: [:agent, :correlations]
    ) |> Repo.all()

    # Expand to include correlated alerts (multi-hop)
    all_alert_ids = expand_alert_network(alert_ids, depth)

    all_alerts = from(a in Alert,
      where: a.id in ^all_alert_ids,
      preload: [:agent, :correlations]
    ) |> Repo.all()

    # Build graph using GraphBuilder
    graph = GraphBuilder.build_graph(all_alert_ids, opts)

    # Enhance with ML similarity if requested
    graph = if include_ml do
      enhance_with_ml_similarity(graph, all_alerts)
    else
      graph
    end

    # Add correlation metadata
    graph = Map.put(graph, :correlation_metadata, %{
      total_alerts: length(all_alerts),
      correlation_density: calculate_density(graph),
      average_degree: calculate_average_degree(graph),
      components: find_connected_components(graph)
    })

    {:ok, graph}
  end

  defp do_find_attack_paths(source_id, target_id, opts) do
    max_depth = Keyword.get(opts, :max_depth, @max_correlation_depth)
    min_confidence = Keyword.get(opts, :min_confidence, 0.5)

    # BFS to find all paths
    paths = find_paths_bfs(source_id, target_id, max_depth, min_confidence)

    # Score paths by confidence and TTPs
    scored_paths = paths
    |> Enum.map(fn path ->
      score = score_attack_path(path)
      ttps = extract_path_ttps(path)
      {path, score, ttps}
    end)
    |> Enum.sort_by(fn {_path, score, _ttps} -> -score end)

    {:ok, scored_paths}
  end

  defp do_get_stats(organization_id) do
    # Correlation statistics
    correlation_count = from(c in AlertCorrelation,
      join: a in Alert, on: c.alert_id == a.id,
      where: a.organization_id == ^organization_id,
      select: count(c.id)
    ) |> Repo.one()

    # Average correlation confidence
    avg_confidence = from(c in AlertCorrelation,
      join: a in Alert, on: c.alert_id == a.id,
      where: a.organization_id == ^organization_id,
      select: avg(c.confidence)
    ) |> Repo.one() || 0.0

    # Correlation type distribution
    type_distribution = from(c in AlertCorrelation,
      join: a in Alert, on: c.alert_id == a.id,
      where: a.organization_id == ^organization_id,
      group_by: c.correlation_type,
      select: {c.correlation_type, count(c.id)}
    ) |> Repo.all() |> Enum.into(%{})

    # Most correlated alerts
    most_correlated = from(a in Alert,
      left_join: c in AlertCorrelation, on: c.alert_id == a.id or c.related_alert_id == a.id,
      where: a.organization_id == ^organization_id,
      group_by: a.id,
      select: {a.id, a.title, count(c.id)},
      order_by: [desc: count(c.id)],
      limit: 10
    ) |> Repo.all()

    {:ok, %{
      total_correlations: correlation_count,
      average_confidence: Float.round(avg_confidence, 3),
      correlation_types: type_distribution,
      most_correlated_alerts: most_correlated
    }}
  end

  # Correlation Scoring

  defp calculate_correlation_score(alert1, alert2) do
    # Calculate individual scores
    temporal_score = calculate_temporal_score(alert1, alert2)
    entity_score = calculate_entity_score(alert1, alert2)
    behavioral_score = calculate_behavioral_score(alert1, alert2)
    network_score = calculate_network_score(alert1, alert2)
    ml_score = calculate_ml_score(alert1, alert2)

    # Weighted average
    @weights.temporal * temporal_score +
    @weights.entity * entity_score +
    @weights.behavioral * behavioral_score +
    @weights.network * network_score +
    @weights.ml * ml_score
  end

  defp calculate_temporal_score(alert1, alert2) do
    diff_seconds = abs(Timestamp.diff(alert1.inserted_at, alert2.inserted_at, :second) || 86_400)

    cond do
      diff_seconds < 60 -> 1.0          # < 1 minute
      diff_seconds < 300 -> 0.9         # < 5 minutes
      diff_seconds < 900 -> 0.7         # < 15 minutes
      diff_seconds < 1800 -> 0.5        # < 30 minutes
      diff_seconds < 3600 -> 0.3        # < 1 hour
      diff_seconds < 7200 -> 0.2        # < 2 hours
      true -> 0.1
    end
  end

  defp calculate_entity_score(alert1, alert2) do
    evidence1 = alert1.evidence || %{}
    evidence2 = alert2.evidence || %{}

    # Shared IOCs (IPs, domains, hashes)
    iocs1 = extract_iocs(evidence1)
    iocs2 = extract_iocs(evidence2)

    user1 = get_in(evidence1, ["process", "user"]) || get_in(evidence1, [:process, :user])
    user2 = get_in(evidence2, ["process", "user"]) || get_in(evidence2, [:process, :user])
    file1 = get_in(evidence1, ["file", "path"]) || get_in(evidence1, [:file, :path])
    file2 = get_in(evidence2, ["file", "path"]) || get_in(evidence2, [:file, :path])
    proc1 = get_in(evidence1, ["process", "name"]) || get_in(evidence1, [:process, :name])
    proc2 = get_in(evidence2, ["process", "name"]) || get_in(evidence2, [:process, :name])

    scores =
      []
      |> maybe_add_score(MapSet.size(iocs1) > 0 and MapSet.size(iocs2) > 0, jaccard_similarity(iocs1, iocs2) * 1.5)
      |> maybe_add_score(present_equal?(user1, user2), 0.6)
      |> maybe_add_score(present_equal?(file1, file2), 0.8)
      |> maybe_add_score(specific_process_match?(proc1, proc2), 0.25)

    if scores == [] do
      0.0
    else
      Enum.sum(scores) / length(scores)
    end
  end

  defp calculate_behavioral_score(alert1, alert2) do
    techniques1 = MapSet.new(alert1.mitre_techniques || [])
    techniques2 = MapSet.new(alert2.mitre_techniques || [])

    tactics1 = MapSet.new(alert1.mitre_tactics || [])
    tactics2 = MapSet.new(alert2.mitre_tactics || [])

    technique_sim = jaccard_similarity(techniques1, techniques2)
    tactic_sim = jaccard_similarity(tactics1, tactics2)

    # Weight techniques more heavily than tactics
    (technique_sim * 0.7) + (tactic_sim * 0.3)
  end

  defp calculate_network_score(alert1, alert2) do
    cond do
      # Same agent
      alert1.agent_id == alert2.agent_id ->
        0.1

      # Both have agents with IPs
      alert1.agent && alert2.agent &&
      alert1.agent.ip_address && alert2.agent.ip_address ->
        if same_subnet?(alert1.agent.ip_address, alert2.agent.ip_address) do
          0.6
        else
          0.2
        end

      # No network data
      true ->
        0.0
    end
  end

  defp calculate_ml_score(alert1, alert2) do
    _ = {alert1, alert2}
    # Severity similarity is not evidence of relationship. Keep ML contribution
    # disabled until real embeddings or feature vectors are available.
    0.0
  end

  # Helper Functions

  defp find_candidate_alerts(alert, time_window) do
    time_start = DateTime.add(alert.inserted_at, -time_window, :second)
    time_end = DateTime.add(alert.inserted_at, time_window, :second)

    from(a in Alert,
      where: a.id != ^alert.id,
      where: a.inserted_at >= ^time_start and a.inserted_at <= ^time_end,
      where: a.organization_id == ^alert.organization_id,
      order_by: [desc: :inserted_at],
      limit: 200,
      preload: [:agent]
    ) |> Repo.all()
  end

  defp determine_correlation_types(alert1, alert2) do
    diff = abs(Timestamp.diff(alert1.inserted_at, alert2.inserted_at, :second) || 86_400)
    evidence1 = alert1.evidence || %{}
    evidence2 = alert2.evidence || %{}
    techniques1 = MapSet.new(alert1.mitre_techniques || [])
    techniques2 = MapSet.new(alert2.mitre_techniques || [])
    user1 = get_in(evidence1, ["process", "user"]) || get_in(evidence1, [:process, :user])
    user2 = get_in(evidence2, ["process", "user"]) || get_in(evidence2, [:process, :user])

    []
    |> maybe_add_correlation_type(diff < 300, "temporal")
    |> maybe_add_correlation_type(has_shared_iocs?(evidence1, evidence2), "ioc")
    |> maybe_add_correlation_type(MapSet.size(MapSet.intersection(techniques1, techniques2)) > 0, "technique")
    |> maybe_add_correlation_type(alert1.agent_id == alert2.agent_id, "network")
    |> maybe_add_correlation_type(user1 && user2 && user1 == user2, "user")
    |> maybe_add_correlation_type(calculate_behavioral_score(alert1, alert2) > 0.7, "pattern")
  end

  defp maybe_add_correlation_type(types, true, type), do: [type | types]
  defp maybe_add_correlation_type(types, _, _), do: types

  defp actionable_correlation?(alert1, alert2, types) do
    cond do
      "ioc" in types ->
        true

      "user" in types and ("technique" in types or "pattern" in types) ->
        true

      "technique" in types ->
        has_high_fidelity_shared_technique?(alert1, alert2)

      "pattern" in types ->
        true

      true ->
        false
    end
  end

  defp has_high_fidelity_shared_technique?(alert1, alert2) do
    get_shared_techniques(alert1, alert2)
    |> Enum.reject(&(&1 in @generic_techniques))
    |> Enum.any?()
  end

  defp maybe_add_score(scores, true, score) when is_number(score) and score > 0, do: [score | scores]
  defp maybe_add_score(scores, _, _), do: scores

  defp present_equal?(left, right) when is_binary(left) and is_binary(right),
    do: String.trim(left) != "" and left == right

  defp present_equal?(left, right), do: not is_nil(left) and left == right

  defp specific_process_match?(left, right) when is_binary(left) and is_binary(right) do
    normalized = left |> Path.basename() |> String.downcase()

    normalized == (right |> Path.basename() |> String.downcase()) and
      normalized not in ~w(chrome.exe msedge.exe firefox.exe safari.exe powershell.exe pwsh.exe cmd.exe bash sh zsh python python.exe svchost.exe rundll32.exe)
  end

  defp specific_process_match?(_, _), do: false

  defp persist_correlation(alert1, alert2, score, types) do
    # Use primary correlation type (first in list)
    correlation_type = List.first(types) || "temporal"

    metadata = %{
      "correlation_types" => types,
      "shared_techniques" => get_shared_techniques(alert1, alert2),
      "shared_iocs" => get_shared_iocs(alert1, alert2),
      "time_delta_seconds" => Timestamp.diff(alert2.inserted_at, alert1.inserted_at, :second)
    }

    attrs = %{
      alert_id: alert1.id,
      related_alert_id: alert2.id,
      correlation_type: correlation_type,
      confidence: score,
      similarity_score: score,
      metadata: metadata,
      organization_id: alert1.organization_id
    }

    case Repo.insert(%AlertCorrelation{} |> AlertCorrelation.changeset(attrs)) do
      {:ok, _correlation} -> :ok
      {:error, _changeset} -> :ok  # Ignore duplicates
    end
  end

  defp expand_alert_network(alert_ids, max_depth) do
    expand_alert_network_recursive(MapSet.new(alert_ids), 0, max_depth)
    |> MapSet.to_list()
  end

  defp expand_alert_network_recursive(current_set, depth, max_depth) when depth >= max_depth do
    current_set
  end

  defp expand_alert_network_recursive(current_set, depth, max_depth) do
    current_list = MapSet.to_list(current_set)

    # Find all correlated alerts
    related_ids = from(c in AlertCorrelation,
      where: c.alert_id in ^current_list or c.related_alert_id in ^current_list,
      select: {c.alert_id, c.related_alert_id}
    )
    |> Repo.all()
    |> Enum.flat_map(fn {a, b} -> [a, b] end)
    |> Enum.uniq()

    new_set = Enum.reduce(related_ids, current_set, fn id, acc ->
      MapSet.put(acc, id)
    end)

    if MapSet.size(new_set) == MapSet.size(current_set) do
      # No new alerts found
      current_set
    else
      expand_alert_network_recursive(new_set, depth + 1, max_depth)
    end
  end

  defp enhance_with_ml_similarity(graph, alerts) do
    # TODO: Call ML service to compute embedding similarities
    # For now, just return the graph as-is
    graph
  end

  defp calculate_density(graph) do
    nodes = graph.nodes || []
    links = graph.links || []

    n = length(nodes)
    if n < 2 do
      0.0
    else
      max_edges = n * (n - 1) / 2
      length(links) / max_edges
    end
  end

  defp calculate_average_degree(graph) do
    nodes = graph.nodes || []
    links = graph.links || []

    if nodes == [] do
      0.0
    else
      total_degree = Enum.reduce(links, 0, fn _link, acc -> acc + 2 end)
      total_degree / length(nodes)
    end
  end

  defp find_connected_components(graph) do
    # Simple connected components using union-find
    nodes = graph.nodes || []
    links = graph.links || []

    if nodes == [] do
      []
    else
      # Build adjacency map
      adjacency = Enum.reduce(links, %{}, fn link, acc ->
        source = link.source
        target = link.target

        acc
        |> Map.update(source, [target], fn neighbors -> [target | neighbors] end)
        |> Map.update(target, [source], fn neighbors -> [source | neighbors] end)
      end)

      # Find components with DFS
      node_ids = Enum.map(nodes, & &1.id)
      find_components_dfs(node_ids, adjacency, MapSet.new(), [])
    end
  end

  defp find_components_dfs([], _adjacency, _visited, components) do
    components
  end

  defp find_components_dfs([node | rest], adjacency, visited, components) do
    if MapSet.member?(visited, node) do
      find_components_dfs(rest, adjacency, visited, components)
    else
      # DFS to find component
      {component, new_visited} = dfs_component(node, adjacency, visited, [])
      find_components_dfs(rest, adjacency, new_visited, [component | components])
    end
  end

  defp dfs_component(node, adjacency, visited, component) do
    if MapSet.member?(visited, node) do
      {component, visited}
    else
      new_visited = MapSet.put(visited, node)
      new_component = [node | component]

      neighbors = Map.get(adjacency, node, [])

      Enum.reduce(neighbors, {new_component, new_visited}, fn neighbor, {comp, vis} ->
        dfs_component(neighbor, adjacency, vis, comp)
      end)
    end
  end

  defp find_paths_bfs(source_id, target_id, max_depth, min_confidence) do
    find_paths_bfs([[source_id]], MapSet.new([source_id]), target_id, max_depth, min_confidence, [])
  end

  defp find_paths_bfs([], _visited, _target, _max_depth, _min_confidence, paths) do
    paths
  end

  defp find_paths_bfs([current_path | rest_paths], visited, target, max_depth, min_confidence, found_paths) do
    current_node = List.last(current_path)

    if current_node == target do
      # Found a path to target
      find_paths_bfs(rest_paths, visited, target, max_depth, min_confidence, [current_path | found_paths])
    else
      if length(current_path) >= max_depth do
        # Max depth reached
        find_paths_bfs(rest_paths, visited, target, max_depth, min_confidence, found_paths)
      else
        # Find neighbors with sufficient confidence
        neighbors = from(c in AlertCorrelation,
          where: (c.alert_id == ^current_node or c.related_alert_id == ^current_node) and
                 c.confidence >= ^min_confidence,
          select: {c.alert_id, c.related_alert_id, c.confidence}
        )
        |> Repo.all()
        |> Enum.flat_map(fn {a, b, _conf} ->
          [if(a == current_node, do: b, else: a)]
        end)
        |> Enum.reject(fn id -> MapSet.member?(visited, id) end)

        # Create new paths
        new_paths = Enum.map(neighbors, fn neighbor ->
          current_path ++ [neighbor]
        end)

        new_visited = Enum.reduce(neighbors, visited, fn id, acc ->
          MapSet.put(acc, id)
        end)

        find_paths_bfs(rest_paths ++ new_paths, new_visited, target, max_depth, min_confidence, found_paths)
      end
    end
  end

  defp score_attack_path(path) do
    # Score based on path length and correlation strength
    if length(path) < 2 do
      0.0
    else
      # Get correlation confidences for each edge
      edges = Enum.zip(path, tl(path))

      confidences = Enum.map(edges, fn {source, target} ->
        query = from(c in AlertCorrelation,
          where: (c.alert_id == ^source and c.related_alert_id == ^target) or
                 (c.alert_id == ^target and c.related_alert_id == ^source),
          select: c.confidence,
          limit: 1
        )

        Repo.one(query) || 0.0
      end)

      if confidences == [] do
        0.0
      else
        # Average confidence, penalized by path length
        avg_confidence = Enum.sum(confidences) / length(confidences)
        length_penalty = 1.0 / length(path)

        avg_confidence * (0.7 + 0.3 * length_penalty)
      end
    end
  end

  defp extract_path_ttps(path) do
    alerts = from(a in Alert,
      where: a.id in ^path,
      select: %{id: a.id, techniques: a.mitre_techniques, tactics: a.mitre_tactics}
    ) |> Repo.all()

    # Maintain order
    ordered_alerts = Enum.map(path, fn id ->
      Enum.find(alerts, fn a -> a.id == id end)
    end)

    %{
      techniques: ordered_alerts |> Enum.flat_map(& &1.techniques || []) |> Enum.uniq(),
      tactics: ordered_alerts |> Enum.flat_map(& &1.tactics || []) |> Enum.uniq(),
      sequence: Enum.map(ordered_alerts, fn a ->
        %{id: a.id, techniques: a.techniques, tactics: a.tactics}
      end)
    }
  end

  # Utility Functions

  defp extract_iocs(evidence) do
    file_hash_iocs =
      case evidence["file_hashes"] || evidence[:file_hashes] do
        hashes when is_map(hashes) -> Map.values(hashes)
        hashes when is_list(hashes) -> hashes
        _ -> []
      end

    network = map_or_empty(evidence["network"] || evidence[:network])
    process = map_or_empty(evidence["process"] || evidence[:process])
    dns = map_or_empty(evidence["dns"] || evidence[:dns])

    [
      file_hash_iocs,
      [network["remote_ip"] || network[:remote_ip], network["domain"] || network[:domain]],
      [process["sha256"] || process[:sha256]],
      [dns["query"] || dns[:query]]
    ]
    |> List.flatten()
    |> Enum.map(&normalize_ioc/1)
    |> Enum.reject(&is_nil/1)
    |> MapSet.new()
  end

  defp normalize_ioc(value) when is_binary(value) do
    value = value |> String.trim() |> String.downcase()

    cond do
      value == "" -> nil
      value in ["0.0.0.0", "127.0.0.1", "::1", "localhost"] -> nil
      String.starts_with?(value, "192.168.") -> nil
      String.starts_with?(value, "10.") -> nil
      String.starts_with?(value, "172.16.") -> nil
      String.starts_with?(value, "172.17.") -> nil
      String.starts_with?(value, "172.18.") -> nil
      String.starts_with?(value, "172.19.") -> nil
      String.starts_with?(value, "172.2") -> nil
      String.starts_with?(value, "172.30.") -> nil
      String.starts_with?(value, "172.31.") -> nil
      true -> value
    end
  end

  defp normalize_ioc(_), do: nil

  defp map_or_empty(value) when is_map(value), do: value
  defp map_or_empty(_), do: %{}

  defp has_shared_iocs?(evidence1, evidence2) do
    iocs1 = extract_iocs(evidence1)
    iocs2 = extract_iocs(evidence2)

    MapSet.size(MapSet.intersection(iocs1, iocs2)) > 0
  end

  defp get_shared_techniques(alert1, alert2) do
    techniques1 = MapSet.new(alert1.mitre_techniques || [])
    techniques2 = MapSet.new(alert2.mitre_techniques || [])

    MapSet.intersection(techniques1, techniques2) |> MapSet.to_list()
  end

  defp get_shared_iocs(alert1, alert2) do
    iocs1 = extract_iocs(alert1.evidence || %{})
    iocs2 = extract_iocs(alert2.evidence || %{})

    MapSet.intersection(iocs1, iocs2) |> MapSet.to_list()
  end

  defp jaccard_similarity(set1, set2) do
    if MapSet.size(set1) == 0 and MapSet.size(set2) == 0 do
      0.0
    else
      intersection_size = MapSet.intersection(set1, set2) |> MapSet.size()
      union_size = MapSet.union(set1, set2) |> MapSet.size()

      if union_size == 0 do
        0.0
      else
        intersection_size / union_size
      end
    end
  end

  defp same_subnet?(ip1, ip2) do
    # Simple /24 subnet check
    parts1 = String.split(ip1, ".")
    parts2 = String.split(ip2, ".")

    if length(parts1) == 4 and length(parts2) == 4 do
      Enum.take(parts1, 3) == Enum.take(parts2, 3)
    else
      false
    end
  end
end
