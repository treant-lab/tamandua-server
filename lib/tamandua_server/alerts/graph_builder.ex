defmodule TamanduaServer.Alerts.GraphBuilder do
  @moduledoc """
  Builds graph data structures for visualization from alerts and campaigns.

  Provides optimizations for large graphs including:
  - Node clustering for very large graphs (1000+ nodes)
  - Lazy loading support
  - Efficient serialization
  - Graph sampling for performance
  """

  import Ecto.Query
  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts.{Alert, AlertCorrelation, AttackCampaign}
  alias TamanduaServer.Agents.Agent

  @max_nodes_full_graph 500
  @max_nodes_per_cluster 50

  @doc """
  Build a complete graph from a list of alert IDs.

  Options:
  - `:max_nodes` - Maximum nodes to include (default: 500)
  - `:cluster` - Enable clustering for large graphs (default: true)
  - `:depth` - Maximum correlation depth (default: 2)
  """
  def build_graph(alert_ids, opts \\ []) do
    max_nodes = Keyword.get(opts, :max_nodes, @max_nodes_full_graph)
    cluster = Keyword.get(opts, :cluster, true)

    # Load alerts with preloads
    alerts = load_alerts(alert_ids)

    # Determine if clustering is needed
    total_potential_nodes = estimate_node_count(alerts)

    cond do
      total_potential_nodes > max_nodes and cluster ->
        build_clustered_graph(alerts, max_nodes)

      total_potential_nodes > max_nodes ->
        build_sampled_graph(alerts, max_nodes)

      true ->
        build_full_graph(alerts)
    end
  end

  @doc """
  Build graph data for a campaign.
  """
  def build_campaign_graph(campaign_id, opts \\ []) do
    campaign = Repo.get(AttackCampaign, campaign_id)
    |> Repo.preload([campaign_alerts: [:alert]])

    if campaign do
      alert_ids = Enum.map(campaign.campaign_alerts, & &1.alert_id)
      graph = build_graph(alert_ids, opts)

      Map.put(graph, :campaign, %{
        id: campaign.id,
        name: campaign.name,
        severity: campaign.severity,
        status: campaign.status
      })
    else
      empty_graph()
    end
  end

  @doc """
  Get subgraph centered on a specific alert.
  """
  def get_alert_subgraph(alert_id, opts \\ []) do
    depth = Keyword.get(opts, :depth, 2)

    # BFS to find related alerts within depth
    related_ids = find_related_alerts_bfs(alert_id, depth)

    build_graph(related_ids, opts)
  end

  @doc """
  Build an empty graph structure.
  """
  def empty_graph do
    %{
      nodes: [],
      links: [],
      metadata: %{
        clustered: false,
        sampled: false,
        total_nodes: 0,
        total_links: 0
      }
    }
  end

  # Private functions

  defp load_alerts(alert_ids) do
    from(a in Alert,
      where: a.id in ^alert_ids,
      preload: [:agent, :correlations]
    )
    |> Repo.all()
  end

  defp estimate_node_count(alerts) do
    # Rough estimate:
    # - 1 alert node per alert
    # - 1 agent node per unique agent
    # - ~2 IOC nodes per alert
    # - ~1 user node per alert
    # - ~1 process node per alert

    unique_agents = alerts
    |> Enum.map(& &1.agent_id)
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
    |> length()

    length(alerts) + unique_agents + (length(alerts) * 4)
  end

  defp build_full_graph(alerts) do
    nodes = []
    links = []
    node_ids = MapSet.new()

    # Build agent nodes
    {nodes, node_ids} = build_agent_nodes(alerts, nodes, node_ids)

    # Build alert nodes
    {nodes, node_ids} = build_alert_nodes(alerts, nodes, node_ids)

    # Build IOC nodes
    {nodes, node_ids} = build_ioc_nodes(alerts, nodes, node_ids)

    # Build user nodes
    {nodes, node_ids} = build_user_nodes(alerts, nodes, node_ids)

    # Build process nodes
    {nodes, node_ids} = build_process_nodes(alerts, nodes, node_ids)

    # Build links
    links = build_agent_alert_links(alerts, links)
    links = build_correlation_links(alerts, links)
    links = build_ioc_links(alerts, links)
    links = build_user_links(alerts, links)
    links = build_process_links(alerts, links)

    %{
      nodes: nodes,
      links: links,
      metadata: %{
        clustered: false,
        sampled: false,
        total_nodes: length(nodes),
        total_links: length(links)
      }
    }
  end

  defp build_clustered_graph(alerts, max_nodes) do
    # Group alerts by similarity (same agent, same techniques, etc.)
    clusters = cluster_alerts(alerts)

    # Build nodes from clusters
    nodes = Enum.map(clusters, fn {cluster_id, cluster_alerts} ->
      representative = List.first(cluster_alerts)

      %{
        id: "cluster_#{cluster_id}",
        type: "cluster",
        size: length(cluster_alerts),
        severity: max_severity(cluster_alerts),
        techniques: aggregate_techniques(cluster_alerts),
        alert_ids: Enum.map(cluster_alerts, & &1.id),
        representative: %{
          id: representative.id,
          title: representative.title,
          agent_id: representative.agent_id
        }
      }
    end)
    |> Enum.take(max_nodes)

    # Build links between clusters
    links = build_cluster_links(clusters)

    %{
      nodes: nodes,
      links: links,
      metadata: %{
        clustered: true,
        sampled: false,
        total_nodes: length(nodes),
        total_links: length(links),
        cluster_count: length(clusters)
      }
    }
  end

  defp build_sampled_graph(alerts, max_nodes) do
    # Sample alerts based on importance (severity, correlation count)
    scored_alerts = Enum.map(alerts, fn alert ->
      score = calculate_importance_score(alert)
      {alert, score}
    end)
    |> Enum.sort_by(fn {_alert, score} -> -score end)
    |> Enum.take(max_nodes)
    |> Enum.map(fn {alert, _score} -> alert end)

    graph = build_full_graph(scored_alerts)

    %{graph | metadata: Map.put(graph.metadata, :sampled, true)}
  end

  defp cluster_alerts(alerts) do
    # Cluster by agent and technique similarity
    alerts
    |> Enum.group_by(fn alert ->
      techniques = Enum.sort(alert.mitre_techniques || [])
      "#{alert.agent_id}_#{Enum.join(techniques, "_")}"
    end)
    |> Enum.with_index()
    |> Enum.map(fn {{_key, cluster_alerts}, idx} -> {idx, cluster_alerts} end)
  end

  defp build_cluster_links(clusters) do
    # Find correlations between clusters
    cluster_map = Enum.into(clusters, %{})

    for {cluster_id1, alerts1} <- cluster_map,
        {cluster_id2, alerts2} <- cluster_map,
        cluster_id1 < cluster_id2 do

      # Check if any alerts are correlated
      correlated = Enum.any?(alerts1, fn a1 ->
        Enum.any?(alerts2, fn a2 ->
          has_correlation?(a1, a2)
        end)
      end)

      if correlated do
        %{
          source: "cluster_#{cluster_id1}",
          target: "cluster_#{cluster_id2}",
          type: "cluster_link",
          weight: 1
        }
      end
    end
    |> Enum.reject(&is_nil/1)
  end

  defp has_correlation?(alert1, alert2) do
    correlations = alert1.correlations || []

    Enum.any?(correlations, fn corr ->
      corr.related_alert_id == alert2.id
    end)
  end

  defp find_related_alerts_bfs(alert_id, max_depth) do
    find_related_bfs([alert_id], MapSet.new([alert_id]), 0, max_depth)
  end

  defp find_related_bfs(_current, visited, depth, max_depth) when depth >= max_depth do
    MapSet.to_list(visited)
  end

  defp find_related_bfs([], visited, _depth, _max_depth) do
    MapSet.to_list(visited)
  end

  defp find_related_bfs(current, visited, depth, max_depth) do
    # Find neighbors
    neighbors = from(c in AlertCorrelation,
      where: c.alert_id in ^current or c.related_alert_id in ^current,
      select: {c.alert_id, c.related_alert_id}
    )
    |> Repo.all()
    |> Enum.flat_map(fn {a, b} -> [a, b] end)
    |> Enum.uniq()
    |> Enum.reject(fn id -> MapSet.member?(visited, id) end)

    new_visited = Enum.reduce(neighbors, visited, fn id, acc ->
      MapSet.put(acc, id)
    end)

    find_related_bfs(neighbors, new_visited, depth + 1, max_depth)
  end

  defp build_agent_nodes(alerts, nodes, node_ids) do
    alerts
    |> Enum.reduce({nodes, node_ids}, fn alert, {nodes_acc, ids_acc} ->
      if alert.agent && !MapSet.member?(ids_acc, "agent_#{alert.agent.id}") do
        node = %{
          id: "agent_#{alert.agent.id}",
          type: "agent",
          hostname: alert.agent.hostname,
          ip: alert.agent.ip_address,
          os: alert.agent.os_type,
          agent_id: alert.agent.id
        }
        {[node | nodes_acc], MapSet.put(ids_acc, "agent_#{alert.agent.id}")}
      else
        {nodes_acc, ids_acc}
      end
    end)
  end

  defp build_alert_nodes(alerts, nodes, node_ids) do
    alerts
    |> Enum.reduce({nodes, node_ids}, fn alert, {nodes_acc, ids_acc} ->
      node = %{
        id: "alert_#{alert.id}",
        type: "alert",
        title: alert.title,
        severity: alert.severity,
        techniques: alert.mitre_techniques || [],
        tactics: alert.mitre_tactics || [],
        timestamp: alert.inserted_at,
        alert_id: alert.id,
        campaign_id: alert.campaign_id
      }
      {[node | nodes_acc], MapSet.put(ids_acc, "alert_#{alert.id}")}
    end)
  end

  defp build_ioc_nodes(alerts, nodes, node_ids) do
    alerts
    |> Enum.reduce({nodes, node_ids}, fn alert, {nodes_acc, ids_acc} ->
      evidence = alert.evidence || %{}

      # File hashes
      {nodes_acc, ids_acc} = if file_hashes = evidence["file_hashes"] || evidence[:file_hashes] do
        Enum.reduce(file_hashes, {nodes_acc, ids_acc}, fn {_type, hash}, {n_acc, i_acc} ->
          node_id = "ioc_#{hash}"
          if !MapSet.member?(i_acc, node_id) do
            node = %{
              id: node_id,
              type: "ioc",
              ioc_type: "file_hash",
              value: hash
            }
            {[node | n_acc], MapSet.put(i_acc, node_id)}
          else
            {n_acc, i_acc}
          end
        end)
      else
        {nodes_acc, ids_acc}
      end

      # Network IOCs
      if network = evidence["network"] || evidence[:network] do
        if remote_ip = network["remote_ip"] || network[:remote_ip] do
          node_id = "ioc_#{remote_ip}"
          if !MapSet.member?(ids_acc, node_id) do
            node = %{
              id: node_id,
              type: "ioc",
              ioc_type: "ip",
              value: remote_ip
            }
            {[node | nodes_acc], MapSet.put(ids_acc, node_id)}
          else
            {nodes_acc, ids_acc}
          end
        else
          {nodes_acc, ids_acc}
        end
      else
        {nodes_acc, ids_acc}
      end
    end)
  end

  defp build_user_nodes(alerts, nodes, node_ids) do
    alerts
    |> Enum.reduce({nodes, node_ids}, fn alert, {nodes_acc, ids_acc} ->
      evidence = alert.evidence || %{}
      process = evidence["process"] || evidence[:process]
      user = process && (process["user"] || process[:user])

      if user do
        node_id = "user_#{user}"
        if !MapSet.member?(ids_acc, node_id) do
          node = %{
            id: node_id,
            type: "user",
            username: user
          }
          {[node | nodes_acc], MapSet.put(ids_acc, node_id)}
        else
          {nodes_acc, ids_acc}
        end
      else
        {nodes_acc, ids_acc}
      end
    end)
  end

  defp build_process_nodes(alerts, nodes, node_ids) do
    alerts
    |> Enum.reduce({nodes, node_ids}, fn alert, {nodes_acc, ids_acc} ->
      evidence = alert.evidence || %{}
      process = evidence["process"] || evidence[:process]

      if process do
        name = process["name"] || process[:name]
        pid = process["pid"] || process[:pid]

        if name && pid do
          node_id = "process_#{alert.agent_id}_#{pid}"
          if !MapSet.member?(ids_acc, node_id) do
            node = %{
              id: node_id,
              type: "process",
              name: name,
              pid: pid,
              path: process["path"] || process[:path]
            }
            {[node | nodes_acc], MapSet.put(ids_acc, node_id)}
          else
            {nodes_acc, ids_acc}
          end
        else
          {nodes_acc, ids_acc}
        end
      else
        {nodes_acc, ids_acc}
      end
    end)
  end

  defp build_agent_alert_links(alerts, links) do
    alerts
    |> Enum.reduce(links, fn alert, links_acc ->
      if alert.agent do
        link = %{
          source: "agent_#{alert.agent.id}",
          target: "alert_#{alert.id}",
          type: "network"
        }
        [link | links_acc]
      else
        links_acc
      end
    end)
  end

  defp build_correlation_links(alerts, links) do
    alerts
    |> Enum.reduce(links, fn alert, links_acc ->
      Enum.reduce(alert.correlations || [], links_acc, fn correlation, acc ->
        link = %{
          source: "alert_#{alert.id}",
          target: "alert_#{correlation.related_alert_id}",
          type: correlation.correlation_type,
          weight: correlation.confidence * 2,
          metadata: correlation.metadata
        }
        [link | acc]
      end)
    end)
  end

  defp build_ioc_links(alerts, links) do
    alerts
    |> Enum.reduce(links, fn alert, links_acc ->
      evidence = alert.evidence || %{}

      links_acc = if file_hashes = evidence["file_hashes"] || evidence[:file_hashes] do
        Enum.reduce(file_hashes, links_acc, fn {_type, hash}, acc ->
          link = %{
            source: "alert_#{alert.id}",
            target: "ioc_#{hash}",
            type: "ioc"
          }
          [link | acc]
        end)
      else
        links_acc
      end

      if network = evidence["network"] || evidence[:network] do
        if remote_ip = network["remote_ip"] || network[:remote_ip] do
          link = %{
            source: "alert_#{alert.id}",
            target: "ioc_#{remote_ip}",
            type: "ioc"
          }
          [link | links_acc]
        else
          links_acc
        end
      else
        links_acc
      end
    end)
  end

  defp build_user_links(alerts, links) do
    alerts
    |> Enum.reduce(links, fn alert, links_acc ->
      evidence = alert.evidence || %{}
      process = evidence["process"] || evidence[:process]
      user = process && (process["user"] || process[:user])

      if user do
        link = %{
          source: "alert_#{alert.id}",
          target: "user_#{user}",
          type: "shared_credentials"
        }
        [link | links_acc]
      else
        links_acc
      end
    end)
  end

  defp build_process_links(alerts, links) do
    alerts
    |> Enum.reduce(links, fn alert, links_acc ->
      evidence = alert.evidence || %{}
      process = evidence["process"] || evidence[:process]

      if process do
        name = process["name"] || process[:name]
        pid = process["pid"] || process[:pid]

        if name && pid do
          node_id = "process_#{alert.agent_id}_#{pid}"
          link = %{
            source: "alert_#{alert.id}",
            target: node_id,
            type: "parent_child"
          }
          [link | links_acc]
        else
          links_acc
        end
      else
        links_acc
      end
    end)
  end

  defp calculate_importance_score(alert) do
    severity_score = case alert.severity do
      "critical" -> 10
      "high" -> 7
      "medium" -> 4
      "low" -> 2
      "info" -> 1
      _ -> 0
    end

    correlation_score = length(alert.correlations || []) * 2
    technique_score = length(alert.mitre_techniques || [])

    severity_score + correlation_score + technique_score
  end

  defp max_severity(alerts) do
    alerts
    |> Enum.map(& &1.severity)
    |> Enum.max_by(&severity_rank/1, fn -> "medium" end)
  end

  defp severity_rank("critical"), do: 4
  defp severity_rank("high"), do: 3
  defp severity_rank("medium"), do: 2
  defp severity_rank("low"), do: 1
  defp severity_rank("info"), do: 0
  defp severity_rank(_), do: 0

  defp aggregate_techniques(alerts) do
    alerts
    |> Enum.flat_map(& &1.mitre_techniques || [])
    |> Enum.uniq()
  end
end
