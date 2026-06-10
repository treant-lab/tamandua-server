defmodule TamanduaServer.Investigations.GraphBuilder do
  @moduledoc """
  Builds detailed investigation graphs from telemetry events and alerts.

  Constructs graphs with:
  - Process execution trees (parent-child relationships)
  - File access nodes (read, write, execute, delete)
  - Network connection nodes (IP, domain, port)
  - Registry modification nodes (Windows)
  - User context nodes
  - DLL/module load nodes
  - Timeline-based evolution

  Performance optimized with max 1000 nodes and efficient deduplication.
  """

  import Ecto.Query
  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Telemetry.{Event, ClickHouseQuery}
  alias TamanduaServer.Agents.Agent

  require Logger

  @max_nodes 1000
  @max_events_per_alert 500

  @type graph_node :: %{
          id: String.t(),
          type: atom(),
          label: String.t(),
          timestamp: DateTime.t(),
          metadata: map(),
          suspicious: boolean(),
          mitre_techniques: list(String.t())
        }

  @type edge :: %{
          source: String.t(),
          target: String.t(),
          type: atom(),
          label: String.t(),
          timestamp: DateTime.t(),
          metadata: map()
        }

  @type graph :: %{
          nodes: list(node()),
          edges: list(edge()),
          timeline: %{
            start: DateTime.t(),
            end: DateTime.t(),
            buckets: list(map())
          },
          metadata: map()
        }

  @doc """
  Build investigation graph from alert ID(s).

  Options:
  - `:depth` - How many hops from alert to include (default: 2)
  - `:time_window` - Time window in minutes before/after alert (default: 60)
  - `:include_benign` - Include non-suspicious events (default: false)
  - `:max_nodes` - Maximum nodes to include (default: 1000)
  """
  @spec build_from_alert(binary() | list(binary()), keyword()) :: graph()
  def build_from_alert(alert_ids, opts \\ []) when is_list(alert_ids) do
    depth = Keyword.get(opts, :depth, 2)
    time_window = Keyword.get(opts, :time_window, 60)
    include_benign = Keyword.get(opts, :include_benign, false)
    max_nodes = Keyword.get(opts, :max_nodes, @max_nodes)

    # Load alerts with related data
    alerts = load_alerts(alert_ids)

    if Enum.empty?(alerts) do
      empty_graph()
    else
      # Build graph from alerts and their events
      build_graph(alerts, depth, time_window, include_benign, max_nodes)
    end
  end

  def build_from_alert(alert_id, opts) when is_binary(alert_id) do
    build_from_alert([alert_id], opts)
  end

  @doc """
  Build investigation graph from telemetry event range.

  Options:
  - `:agent_id` - Filter by specific agent (required)
  - `:start_time` - Start of time range (required)
  - `:end_time` - End of time range (required)
  - `:event_types` - Filter by event types (optional)
  - `:max_nodes` - Maximum nodes to include (default: 1000)
  """
  @spec build_from_events(keyword()) :: graph()
  def build_from_events(opts) do
    agent_id = Keyword.fetch!(opts, :agent_id)
    start_time = Keyword.fetch!(opts, :start_time)
    end_time = Keyword.fetch!(opts, :end_time)
    event_types = Keyword.get(opts, :event_types, [])
    max_nodes = Keyword.get(opts, :max_nodes, @max_nodes)

    # Query events from ClickHouse or PostgreSQL
    events = load_events(agent_id, start_time, end_time, event_types)

    build_graph_from_events(events, max_nodes)
  end

  @doc """
  Expand graph around a specific node by one hop.

  Returns new nodes and edges connected to the given node ID.
  """
  @spec expand_node(graph(), String.t(), keyword()) :: graph()
  def expand_node(graph, node_id, opts \\ []) do
    # Find the node
    node = Enum.find(graph.nodes, fn n -> n.id == node_id end)

    if node do
      # Load related events based on node type
      new_elements = expand_by_type(node, opts)

      # Merge into existing graph
      merge_graph_elements(graph, new_elements)
    else
      graph
    end
  end

  @doc """
  Filter graph by time range.

  Returns only nodes and edges within the specified time window.
  """
  @spec filter_by_time(graph(), DateTime.t(), DateTime.t()) :: graph()
  def filter_by_time(graph, start_time, end_time) do
    filtered_nodes =
      Enum.filter(graph.nodes, fn node ->
        DateTime.compare(node.timestamp, start_time) != :lt and
          DateTime.compare(node.timestamp, end_time) != :gt
      end)

    node_ids = MapSet.new(filtered_nodes, & &1.id)

    filtered_edges =
      Enum.filter(graph.edges, fn edge ->
        MapSet.member?(node_ids, edge.source) and MapSet.member?(node_ids, edge.target)
      end)

    %{graph | nodes: filtered_nodes, edges: filtered_edges}
  end

  @doc """
  Export graph to GraphML format for analysis tools (Gephi, Cytoscape).
  """
  @spec export_graphml(graph()) :: String.t()
  def export_graphml(graph) do
    """
    <?xml version="1.0" encoding="UTF-8"?>
    <graphml xmlns="http://graphml.graphdrawing.org/xmlns"
             xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
             xsi:schemaLocation="http://graphml.graphdrawing.org/xmlns
             http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd">
      <key id="label" for="node" attr.name="label" attr.type="string"/>
      <key id="type" for="node" attr.name="type" attr.type="string"/>
      <key id="timestamp" for="node" attr.name="timestamp" attr.type="string"/>
      <key id="suspicious" for="node" attr.name="suspicious" attr.type="boolean"/>
      <key id="edge_type" for="edge" attr.name="type" attr.type="string"/>
      <key id="edge_label" for="edge" attr.name="label" attr.type="string"/>
      <graph id="G" edgedefault="directed">
        #{render_nodes_xml(graph.nodes)}
        #{render_edges_xml(graph.edges)}
      </graph>
    </graphml>
    """
  end

  # Private functions

  defp empty_graph do
    %{
      nodes: [],
      edges: [],
      timeline: %{
        start: DateTime.utc_now(),
        end: DateTime.utc_now(),
        buckets: []
      },
      metadata: %{
        node_count: 0,
        edge_count: 0,
        suspicious_count: 0
      }
    }
  end

  defp load_alerts(alert_ids) do
    from(a in Alert,
      where: a.id in ^alert_ids,
      preload: [:agent]
    )
    |> Repo.all()
  end

  defp load_events(agent_id, start_time, end_time, event_types) do
    base_query =
      from(e in Event,
        where: e.agent_id == ^agent_id,
        where: e.timestamp >= ^start_time,
        where: e.timestamp <= ^end_time,
        order_by: [asc: e.timestamp],
        limit: @max_events_per_alert
      )

    query =
      if Enum.empty?(event_types) do
        base_query
      else
        from(e in base_query, where: e.event_type in ^event_types)
      end

    Repo.all(query)
  end

  defp build_graph(alerts, depth, time_window, include_benign, max_nodes) do
    # Extract time range from alerts
    {start_time, end_time} = calculate_time_range(alerts, time_window)

    # Collect all events related to alerts
    all_events = collect_alert_events(alerts, start_time, end_time)

    # Build graph from events
    graph = build_graph_from_events(all_events, max_nodes)

    # Add alert nodes
    graph = add_alert_nodes(graph, alerts)

    # Filter suspicious if needed
    graph =
      if include_benign do
        graph
      else
        filter_suspicious(graph)
      end

    # Calculate timeline buckets
    graph = add_timeline_buckets(graph)

    # Add metadata
    %{
      graph
      | metadata: %{
          node_count: length(graph.nodes),
          edge_count: length(graph.edges),
          suspicious_count: count_suspicious(graph.nodes),
          alert_count: length(alerts),
          time_range: %{start: start_time, end: end_time}
        }
    }
  end

  defp build_graph_from_events(events, max_nodes) do
    # Initialize accumulators
    nodes = %{}
    edges = []
    process_tree = %{}

    # Process events to build graph
    {nodes, edges, _process_tree} =
      events
      |> Enum.take(max_nodes * 2)
      |> Enum.reduce({nodes, edges, process_tree}, fn event, acc ->
        process_event(event, acc)
      end)

    # Convert to list and limit
    node_list =
      nodes
      |> Map.values()
      |> Enum.sort_by(& &1.timestamp, DateTime)
      |> Enum.take(max_nodes)

    node_ids = MapSet.new(node_list, & &1.id)

    # Filter edges to only include nodes we kept
    edge_list =
      Enum.filter(edges, fn edge ->
        MapSet.member?(node_ids, edge.source) and MapSet.member?(node_ids, edge.target)
      end)

    %{
      nodes: node_list,
      edges: edge_list,
      timeline: %{
        start: get_earliest_timestamp(node_list),
        end: get_latest_timestamp(node_list),
        buckets: []
      },
      metadata: %{}
    }
  end

  defp process_event(event, {nodes, edges, process_tree}) do
    case event.event_type do
      "process" <> _ -> process_process_event(event, {nodes, edges, process_tree})
      "file" <> _ -> process_file_event(event, {nodes, edges, process_tree})
      "network" <> _ -> process_network_event(event, {nodes, edges, process_tree})
      "dns" <> _ -> process_dns_event(event, {nodes, edges, process_tree})
      "registry" <> _ -> process_registry_event(event, {nodes, edges, process_tree})
      "module_load" -> process_module_event(event, {nodes, edges, process_tree})
      _ -> {nodes, edges, process_tree}
    end
  end

  defp process_process_event(event, {nodes, edges, process_tree}) do
    payload = event.payload || %{}
    pid = get_in(payload, ["pid"]) || get_in(payload, [:pid])
    name = get_in(payload, ["name"]) || get_in(payload, [:name])
    parent_pid = get_in(payload, ["parent_pid"]) || get_in(payload, [:parent_pid])
    path = get_in(payload, ["path"]) || get_in(payload, [:path])
    command_line = get_in(payload, ["command_line"]) || get_in(payload, [:command_line])
    user = get_in(payload, ["user"]) || get_in(payload, [:user])
    is_elevated = get_in(payload, ["is_elevated"]) || get_in(payload, [:is_elevated])

    process_id = "process_#{event.agent_id}_#{pid}"

    # Add process node
    node = %{
      id: process_id,
      type: :process,
      label: name || "unknown",
      timestamp: event.timestamp,
      metadata: %{
        pid: pid,
        name: name,
        path: path,
        command_line: command_line,
        user: user,
        is_elevated: is_elevated,
        agent_id: event.agent_id
      },
      suspicious: is_suspicious?(event),
      mitre_techniques: extract_mitre_techniques(event)
    }

    nodes = Map.put(nodes, process_id, node)

    # Add user node if present
    {nodes, edges} =
      if user do
        user_id = "user_#{user}"

        user_node = %{
          id: user_id,
          type: :user,
          label: user,
          timestamp: event.timestamp,
          metadata: %{username: user},
          suspicious: false,
          mitre_techniques: []
        }

        edge = %{
          source: user_id,
          target: process_id,
          type: :executes,
          label: "executes",
          timestamp: event.timestamp,
          metadata: %{elevated: is_elevated}
        }

        {Map.put(nodes, user_id, user_node), [edge | edges]}
      else
        {nodes, edges}
      end

    # Add parent-child relationship
    {nodes, edges, process_tree} =
      if parent_pid do
        parent_id = "process_#{event.agent_id}_#{parent_pid}"

        edge = %{
          source: parent_id,
          target: process_id,
          type: :spawns,
          label: "spawns",
          timestamp: event.timestamp,
          metadata: %{}
        }

        process_tree = Map.put(process_tree, process_id, parent_id)
        {nodes, [edge | edges], process_tree}
      else
        {nodes, edges, process_tree}
      end

    {nodes, edges, process_tree}
  end

  defp process_file_event(event, {nodes, edges, process_tree}) do
    payload = event.payload || %{}
    file_path = get_in(payload, ["path"]) || get_in(payload, [:path])
    action = get_in(payload, ["action"]) || get_in(payload, [:action])
    hash = get_in(payload, ["hash"]) || get_in(payload, [:hash])
    pid = get_in(payload, ["pid"]) || get_in(payload, [:pid])

    return_if_nil(file_path, {nodes, edges, process_tree})

    file_id = "file_#{hash || file_path |> String.replace("/", "_") |> String.replace("\\", "_")}"

    # Add file node
    node = %{
      id: file_id,
      type: :file,
      label: Path.basename(file_path),
      timestamp: event.timestamp,
      metadata: %{
        path: file_path,
        action: action,
        hash: hash
      },
      suspicious: is_suspicious?(event),
      mitre_techniques: extract_mitre_techniques(event)
    }

    nodes = Map.put(nodes, file_id, node)

    # Link process to file
    edges =
      if pid do
        process_id = "process_#{event.agent_id}_#{pid}"

        edge = %{
          source: process_id,
          target: file_id,
          type: file_action_to_edge_type(action),
          label: action || "access",
          timestamp: event.timestamp,
          metadata: %{action: action}
        }

        [edge | edges]
      else
        edges
      end

    {nodes, edges, process_tree}
  end

  defp process_network_event(event, {nodes, edges, process_tree}) do
    payload = event.payload || %{}
    remote_ip = get_in(payload, ["remote_ip"]) || get_in(payload, [:remote_ip])
    remote_port = get_in(payload, ["remote_port"]) || get_in(payload, [:remote_port])
    protocol = get_in(payload, ["protocol"]) || get_in(payload, [:protocol])
    pid = get_in(payload, ["pid"]) || get_in(payload, [:pid])
    domain = get_in(payload, ["domain"]) || get_in(payload, [:domain])

    return_if_nil(remote_ip, {nodes, edges, process_tree})

    network_id = "network_#{remote_ip}_#{remote_port}"

    # Add network node
    node = %{
      id: network_id,
      type: :network,
      label: "#{remote_ip}:#{remote_port}",
      timestamp: event.timestamp,
      metadata: %{
        ip: remote_ip,
        port: remote_port,
        protocol: protocol,
        domain: domain
      },
      suspicious: is_suspicious?(event),
      mitre_techniques: extract_mitre_techniques(event)
    }

    nodes = Map.put(nodes, network_id, node)

    # Link process to network
    edges =
      if pid do
        process_id = "process_#{event.agent_id}_#{pid}"

        edge = %{
          source: process_id,
          target: network_id,
          type: :connects_to,
          label: "connects to",
          timestamp: event.timestamp,
          metadata: %{protocol: protocol}
        }

        [edge | edges]
      else
        edges
      end

    {nodes, edges, process_tree}
  end

  defp process_dns_event(event, {nodes, edges, process_tree}) do
    payload = event.payload || %{}
    query = get_in(payload, ["query"]) || get_in(payload, [:query])
    answers = get_in(payload, ["answers"]) || get_in(payload, [:answers]) || []
    pid = get_in(payload, ["pid"]) || get_in(payload, [:pid])

    return_if_nil(query, {nodes, edges, process_tree})

    dns_id = "dns_#{query}"

    # Add DNS node
    node = %{
      id: dns_id,
      type: :dns,
      label: query,
      timestamp: event.timestamp,
      metadata: %{
        query: query,
        answers: answers
      },
      suspicious: is_suspicious?(event),
      mitre_techniques: extract_mitre_techniques(event)
    }

    nodes = Map.put(nodes, dns_id, node)

    # Link process to DNS
    edges =
      if pid do
        process_id = "process_#{event.agent_id}_#{pid}"

        edge = %{
          source: process_id,
          target: dns_id,
          type: :resolves,
          label: "resolves",
          timestamp: event.timestamp,
          metadata: %{}
        }

        [edge | edges]
      else
        edges
      end

    {nodes, edges, process_tree}
  end

  defp process_registry_event(event, {nodes, edges, process_tree}) do
    payload = event.payload || %{}
    key = get_in(payload, ["key"]) || get_in(payload, [:key])
    value = get_in(payload, ["value"]) || get_in(payload, [:value])
    action = get_in(payload, ["action"]) || get_in(payload, [:action])
    pid = get_in(payload, ["pid"]) || get_in(payload, [:pid])

    return_if_nil(key, {nodes, edges, process_tree})

    reg_id = "registry_#{key |> String.replace("\\", "_")}"

    # Add registry node
    node = %{
      id: reg_id,
      type: :registry,
      label: key |> String.split("\\") |> List.last() || key,
      timestamp: event.timestamp,
      metadata: %{
        key: key,
        value: value,
        action: action
      },
      suspicious: is_suspicious?(event),
      mitre_techniques: extract_mitre_techniques(event)
    }

    nodes = Map.put(nodes, reg_id, node)

    # Link process to registry
    edges =
      if pid do
        process_id = "process_#{event.agent_id}_#{pid}"

        edge = %{
          source: process_id,
          target: reg_id,
          type: registry_action_to_edge_type(action),
          label: action || "modifies",
          timestamp: event.timestamp,
          metadata: %{action: action}
        }

        [edge | edges]
      else
        edges
      end

    {nodes, edges, process_tree}
  end

  defp process_module_event(event, {nodes, edges, process_tree}) do
    payload = event.payload || %{}
    module_path = get_in(payload, ["path"]) || get_in(payload, [:path])
    pid = get_in(payload, ["pid"]) || get_in(payload, [:pid])
    hash = get_in(payload, ["hash"]) || get_in(payload, [:hash])

    return_if_nil(module_path, {nodes, edges, process_tree})

    module_id = "module_#{hash || module_path |> String.replace("/", "_") |> String.replace("\\", "_")}"

    # Add module node
    node = %{
      id: module_id,
      type: :module,
      label: Path.basename(module_path),
      timestamp: event.timestamp,
      metadata: %{
        path: module_path,
        hash: hash
      },
      suspicious: is_suspicious?(event),
      mitre_techniques: extract_mitre_techniques(event)
    }

    nodes = Map.put(nodes, module_id, node)

    # Link process to module
    edges =
      if pid do
        process_id = "process_#{event.agent_id}_#{pid}"

        edge = %{
          source: process_id,
          target: module_id,
          type: :loads,
          label: "loads",
          timestamp: event.timestamp,
          metadata: %{}
        }

        [edge | edges]
      else
        edges
      end

    {nodes, edges, process_tree}
  end

  defp add_alert_nodes(graph, alerts) do
    alert_nodes =
      Enum.map(alerts, fn alert ->
        %{
          id: "alert_#{alert.id}",
          type: :alert,
          label: alert.title,
          timestamp: alert.inserted_at,
          metadata: %{
            alert_id: alert.id,
            severity: alert.severity,
            description: alert.description,
            techniques: alert.mitre_techniques || [],
            tactics: alert.mitre_tactics || []
          },
          suspicious: true,
          mitre_techniques: alert.mitre_techniques || []
        }
      end)

    %{graph | nodes: graph.nodes ++ alert_nodes}
  end

  defp calculate_time_range(alerts, time_window_minutes) do
    earliest =
      alerts
      |> Enum.map(& &1.inserted_at)
      |> Enum.min(DateTime, fn -> DateTime.utc_now() end)

    latest =
      alerts
      |> Enum.map(& &1.inserted_at)
      |> Enum.max(DateTime, fn -> DateTime.utc_now() end)

    start_time = DateTime.add(earliest, -time_window_minutes * 60, :second)
    end_time = DateTime.add(latest, time_window_minutes * 60, :second)

    {start_time, end_time}
  end

  defp collect_alert_events(alerts, start_time, end_time) do
    # Get all event IDs from alerts
    event_ids =
      alerts
      |> Enum.flat_map(fn alert -> alert.event_ids || [] end)
      |> Enum.uniq()

    # Load events from PostgreSQL
    pg_events =
      if Enum.empty?(event_ids) do
        []
      else
        from(e in Event,
          where: e.id in ^event_ids,
          order_by: [asc: e.timestamp]
        )
        |> Repo.all()
      end

    # Also query time-range events from ClickHouse if available
    agent_ids = alerts |> Enum.map(& &1.agent_id) |> Enum.uniq() |> Enum.reject(&is_nil/1)

    ch_events =
      Enum.flat_map(agent_ids, fn agent_id ->
        case ClickHouseQuery.timeline(agent_id, start_time, end_time, limit: 500) do
          {:ok, events} -> events
          _ -> []
        end
      end)

    # Combine and deduplicate
    (pg_events ++ ch_events)
    |> Enum.uniq_by(fn
      %Event{id: id} -> id
      event when is_map(event) -> event["event_id"] || event[:event_id]
    end)
  end

  defp filter_suspicious(graph) do
    suspicious_nodes = Enum.filter(graph.nodes, & &1.suspicious)
    node_ids = MapSet.new(suspicious_nodes, & &1.id)

    # Keep edges if at least one endpoint is suspicious
    filtered_edges =
      Enum.filter(graph.edges, fn edge ->
        MapSet.member?(node_ids, edge.source) or MapSet.member?(node_ids, edge.target)
      end)

    # Add back connected benign nodes
    connected_node_ids =
      filtered_edges
      |> Enum.flat_map(fn edge -> [edge.source, edge.target] end)
      |> MapSet.new()

    final_nodes = Enum.filter(graph.nodes, fn node -> MapSet.member?(connected_node_ids, node.id) end)

    %{graph | nodes: final_nodes, edges: filtered_edges}
  end

  defp add_timeline_buckets(graph) do
    if Enum.empty?(graph.nodes) do
      graph
    else
      start_time = graph.timeline.start
      end_time = graph.timeline.end

      # Create 20 time buckets
      bucket_count = 20
      duration_seconds = DateTime.diff(end_time, start_time)
      bucket_size = max(div(duration_seconds, bucket_count), 1)

      buckets =
        0..(bucket_count - 1)
        |> Enum.map(fn i ->
          bucket_start = DateTime.add(start_time, i * bucket_size, :second)
          bucket_end = DateTime.add(start_time, (i + 1) * bucket_size, :second)

          events_in_bucket =
            Enum.count(graph.nodes, fn node ->
              DateTime.compare(node.timestamp, bucket_start) != :lt and
                DateTime.compare(node.timestamp, bucket_end) == :lt
            end)

          %{
            start: bucket_start,
            end: bucket_end,
            count: events_in_bucket
          }
        end)

      put_in(graph, [:timeline, :buckets], buckets)
    end
  end

  defp count_suspicious(nodes) do
    Enum.count(nodes, & &1.suspicious)
  end

  defp get_earliest_timestamp([]), do: DateTime.utc_now()

  defp get_earliest_timestamp(nodes) do
    nodes
    |> Enum.map(& &1.timestamp)
    |> Enum.min(DateTime, fn -> DateTime.utc_now() end)
  end

  defp get_latest_timestamp([]), do: DateTime.utc_now()

  defp get_latest_timestamp(nodes) do
    nodes
    |> Enum.map(& &1.timestamp)
    |> Enum.max(DateTime, fn -> DateTime.utc_now() end)
  end

  defp is_suspicious?(event) do
    severity = event.severity || "info"
    severity in ["high", "critical"] or
      (event.enrichment && Map.get(event.enrichment, "is_suspicious")) or
      not Enum.empty?(extract_mitre_techniques(event))
  end

  defp extract_mitre_techniques(event) do
    enrichment = event.enrichment || %{}
    techniques = Map.get(enrichment, "mitre_techniques") || Map.get(enrichment, :mitre_techniques) || []
    if is_list(techniques), do: techniques, else: []
  end

  defp file_action_to_edge_type("create"), do: :creates
  defp file_action_to_edge_type("write"), do: :writes
  defp file_action_to_edge_type("read"), do: :reads
  defp file_action_to_edge_type("delete"), do: :deletes
  defp file_action_to_edge_type("rename"), do: :renames
  defp file_action_to_edge_type("execute"), do: :executes
  defp file_action_to_edge_type(_), do: :accesses

  defp registry_action_to_edge_type("create"), do: :creates
  defp registry_action_to_edge_type("set"), do: :modifies
  defp registry_action_to_edge_type("delete"), do: :deletes
  defp registry_action_to_edge_type(_), do: :modifies

  defp expand_by_type(node, _opts) do
    # Placeholder for node expansion logic
    # Would query additional events related to this node
    %{nodes: [], edges: []}
  end

  defp merge_graph_elements(graph, new_elements) do
    # Merge new nodes and edges, avoiding duplicates
    existing_node_ids = MapSet.new(graph.nodes, & &1.id)

    new_nodes =
      Enum.reject(new_elements.nodes, fn node ->
        MapSet.member?(existing_node_ids, node.id)
      end)

    %{
      graph
      | nodes: graph.nodes ++ new_nodes,
        edges: graph.edges ++ new_elements.edges
    }
  end

  defp render_nodes_xml(nodes) do
    Enum.map_join(nodes, "\n        ", fn node ->
      """
      <node id="#{escape_xml(node.id)}">
        <data key="label">#{escape_xml(node.label)}</data>
        <data key="type">#{node.type}</data>
        <data key="timestamp">#{node.timestamp}</data>
        <data key="suspicious">#{node.suspicious}</data>
      </node>
      """
    end)
  end

  defp render_edges_xml(edges) do
    Enum.with_index(edges)
    |> Enum.map_join("\n        ", fn {edge, idx} ->
      """
      <edge id="e#{idx}" source="#{escape_xml(edge.source)}" target="#{escape_xml(edge.target)}">
        <data key="edge_type">#{edge.type}</data>
        <data key="edge_label">#{escape_xml(edge.label)}</data>
      </edge>
      """
    end)
  end

  defp escape_xml(value) when is_binary(value) do
    value
    |> String.replace("&", "&amp;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
    |> String.replace("\"", "&quot;")
    |> String.replace("'", "&apos;")
  end

  defp escape_xml(value), do: escape_xml(to_string(value))

  # Helper to return early if value is nil
  defp return_if_nil(nil, default), do: default
  defp return_if_nil(_, _), do: nil
end
