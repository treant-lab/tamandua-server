defmodule TamanduaServer.Storyline.Renderer do
  @moduledoc """
  Storyline Renderer - Generates visualization-ready graph data.

  The Renderer transforms causal chain data into a format optimized for
  frontend visualization, supporting:
  - Multiple node types: process, file, network, registry, user, dns
  - Multiple edge types: spawned, wrote, read, connected, modified, resolved
  - Timeline positioning for horizontal timeline view
  - Severity-based highlighting
  - Malicious path highlighting

  Output format is designed for D3.js/vis.js graph rendering.
  """

  require Logger

  @node_types [:process, :file, :network, :registry, :user, :dns]
  @edge_types [:spawned, :wrote, :read, :connected, :modified, :resolved, :deleted, :created, :renamed, :accessed]

  @type rendered_node :: %{
    id: String.t(),
    type: String.t(),
    label: String.t(),
    pid: integer() | nil,
    timestamp: String.t() | nil,
    x: number(),
    y: number(),
    severity: String.t(),
    highlighted: boolean(),
    suspicious: boolean(),
    data: map(),
    detections: list()
  }

  @type rendered_edge :: %{
    id: String.t(),
    source: String.t(),
    target: String.t(),
    type: String.t(),
    label: String.t(),
    timestamp: String.t() | nil,
    animated: boolean(),
    color: String.t()
  }

  @type graph_data :: %{
    nodes: list(rendered_node()),
    edges: list(rendered_edge()),
    stats: map(),
    layout: map()
  }

  @doc """
  Render a causal chain with alert context into graph data.
  """
  @spec render(map(), map(), keyword()) :: {:ok, graph_data()} | {:error, term()}
  def render(causal_chain, alert, opts \\ []) do
    layout_type = Keyword.get(opts, :layout, :timeline)
    highlight_path = Keyword.get(opts, :highlight_malicious, true)

    # Convert internal nodes to rendered format
    nodes = render_nodes(causal_chain.nodes, alert, layout_type)

    # Convert internal edges to rendered format
    edges = render_edges(causal_chain.edges, nodes, highlight_path)

    # Calculate layout positions
    nodes = calculate_layout(nodes, edges, layout_type)

    # Highlight malicious path if enabled
    {nodes, edges} = if highlight_path do
      highlight_malicious_path(nodes, edges, alert)
    else
      {nodes, edges}
    end

    graph_data = %{
      nodes: nodes,
      edges: edges,
      stats: calculate_stats(nodes, edges),
      layout: %{
        type: layout_type,
        width: calculate_width(nodes),
        height: calculate_height(nodes)
      }
    }

    {:ok, graph_data}
  end

  @doc """
  Render from events without an alert context.
  """
  @spec render_from_events(map(), String.t(), keyword()) :: {:ok, graph_data()} | {:error, term()}
  def render_from_events(causal_chain, _agent_id, opts \\ []) do
    layout_type = Keyword.get(opts, :layout, :timeline)
    highlight_path = Keyword.get(opts, :highlight_suspicious, true)

    # Convert internal nodes to rendered format
    nodes = render_nodes(causal_chain.nodes, nil, layout_type)

    # Convert internal edges to rendered format
    edges = render_edges(causal_chain.edges, nodes, highlight_path)

    # Calculate layout positions
    nodes = calculate_layout(nodes, edges, layout_type)

    # Highlight suspicious nodes
    {nodes, edges} = if highlight_path do
      highlight_suspicious_path(nodes, edges)
    else
      {nodes, edges}
    end

    graph_data = %{
      nodes: nodes,
      edges: edges,
      stats: calculate_stats(nodes, edges),
      layout: %{
        type: layout_type,
        width: calculate_width(nodes),
        height: calculate_height(nodes)
      }
    }

    {:ok, graph_data}
  end

  @doc """
  Export storyline graph to different formats.
  """
  @spec export(graph_data(), atom()) :: {:ok, binary()} | {:error, term()}
  def export(graph_data, format) do
    case format do
      :json -> {:ok, Jason.encode!(graph_data)}
      :dot -> export_to_dot(graph_data)
      :mermaid -> export_to_mermaid(graph_data)
      _ -> {:error, :unsupported_format}
    end
  end

  # Private functions

  defp render_nodes(nodes, alert, layout_type) do
    # Get alert-related node IDs for highlighting
    alert_node_ids = if alert do
      extract_alert_node_ids(alert)
    else
      MapSet.new()
    end

    nodes
    |> Enum.with_index()
    |> Enum.map(fn {node, index} ->
      render_single_node(node, index, alert_node_ids, layout_type)
    end)
  end

  defp render_single_node(node, index, alert_node_ids, layout_type) do
    is_highlighted = MapSet.member?(alert_node_ids, node.id)

    severity = determine_node_severity(node)

    %{
      id: node.id,
      type: Atom.to_string(node.type),
      label: truncate_label(node.entity_name, 30),
      full_label: node.entity_name,
      pid: node.data[:pid],
      timestamp: format_timestamp(node.timestamp),
      timestamp_raw: normalize_datetime(node.timestamp),
      x: 0.0,  # Will be calculated in layout
      y: calculate_y_position(node.type, index, layout_type),
      severity: severity,
      highlighted: is_highlighted || node.suspicious,
      suspicious: node.suspicious,
      data: sanitize_node_data(node.data),
      detections: format_detections(node_detections(node))
    }
  end

  defp render_edges(edges, rendered_nodes, highlight_path) do
    # Build a map of node IDs to their suspicious status
    suspicious_map = rendered_nodes
    |> Enum.map(fn n -> {n.id, n.suspicious} end)
    |> Map.new()

    edges
    |> Enum.map(fn edge ->
      is_suspicious_edge = highlight_path &&
        (Map.get(suspicious_map, edge.source, false) ||
         Map.get(suspicious_map, edge.target, false))

      %{
        id: edge.id,
        source: edge.source,
        target: edge.target,
        type: Atom.to_string(edge.type),
        label: edge.label || Atom.to_string(edge.type),
        timestamp: format_timestamp(edge.timestamp),
        animated: is_suspicious_edge,
        color: get_edge_color(edge.type, is_suspicious_edge)
      }
    end)
  end

  defp calculate_layout(nodes, edges, :timeline) do
    # Timeline layout: X position based on timestamp, Y based on type
    time_sorted = nodes
    |> Enum.filter(& &1.timestamp_raw)
    |> Enum.sort_by(&datetime_sort_key(&1.timestamp_raw))

    if length(time_sorted) == 0 do
      # No timestamps - use simple grid layout
      calculate_grid_layout(nodes, edges)
    else
      min_time = hd(time_sorted).timestamp_raw
      max_time = List.last(time_sorted).timestamp_raw
      time_range = max(DateTime.diff(max_time, min_time, :second), 1)

      # Layout width: 100px per minute, min 800px, max 3000px
      layout_width = min(3000, max(800, div(time_range, 60) * 100))

      nodes
      |> Enum.map(fn node ->
        x = if node.timestamp_raw do
          elapsed = DateTime.diff(node.timestamp_raw, min_time, :second)
          padding = 100
          padding + (elapsed / time_range) * (layout_width - 2 * padding)
        else
          100.0  # Default position for nodes without timestamps
        end

        Map.put(node, :x, Float.round(x, 1))
      end)
    end
  end

  defp calculate_layout(nodes, edges, :hierarchical) do
    # Hierarchical layout: Process tree structure
    calculate_hierarchical_layout(nodes, edges)
  end

  defp calculate_layout(nodes, edges, :force) do
    # Force-directed layout (basic version - frontend will refine)
    calculate_grid_layout(nodes, edges)
  end

  defp calculate_layout(nodes, edges, _) do
    calculate_grid_layout(nodes, edges)
  end

  defp calculate_grid_layout(nodes, _edges) do
    # Group nodes by type
    nodes_by_type = Enum.group_by(nodes, & &1.type)

    type_order = ["process", "file", "network", "dns", "registry", "user"]
    y_spacing = 150
    x_spacing = 120

    Enum.flat_map(type_order, fn type ->
      type_nodes = Map.get(nodes_by_type, type, [])

      type_nodes
      |> Enum.with_index()
      |> Enum.map(fn {node, index} ->
        y = Enum.find_index(type_order, &(&1 == type)) * y_spacing + 50
        x = 100 + index * x_spacing

        node
        |> Map.put(:x, x * 1.0)
        |> Map.put(:y, y * 1.0)
      end)
    end)
  end

  defp calculate_hierarchical_layout(nodes, edges) do
    # Build adjacency map
    children_map = edges
    |> Enum.filter(&(&1.type == "spawned"))
    |> Enum.group_by(& &1.source)
    |> Map.new(fn {k, v} -> {k, Enum.map(v, & &1.target)} end)

    # Find root nodes (no incoming spawn edges)
    all_targets = edges
    |> Enum.filter(&(&1.type == "spawned"))
    |> Enum.map(& &1.target)
    |> MapSet.new()

    process_nodes = Enum.filter(nodes, &(&1.type == "process"))
    root_pids = process_nodes
    |> Enum.reject(fn n -> MapSet.member?(all_targets, n.id) end)
    |> Enum.map(& &1.id)

    # Calculate depths
    depths = calculate_depths(root_pids, children_map)

    # Group by depth for X positioning
    nodes_by_depth = nodes
    |> Enum.group_by(fn n -> Map.get(depths, n.id, 0) end)

    x_spacing = 180
    y_spacing = 100

    Enum.flat_map(nodes_by_depth, fn {depth, depth_nodes} ->
      depth_nodes
      |> Enum.with_index()
      |> Enum.map(fn {node, index} ->
        x = 100 + depth * x_spacing
        y = 50 + index * y_spacing

        node
        |> Map.put(:x, x * 1.0)
        |> Map.put(:y, y * 1.0)
      end)
    end)
  end

  defp calculate_depths(root_ids, children_map, depth \\ 0, acc \\ %{}) do
    if Enum.empty?(root_ids) do
      acc
    else
      acc = Enum.reduce(root_ids, acc, fn id, a -> Map.put(a, id, depth) end)

      next_level = root_ids
      |> Enum.flat_map(fn id -> Map.get(children_map, id, []) end)
      |> Enum.uniq()

      calculate_depths(next_level, children_map, depth + 1, acc)
    end
  end

  defp calculate_y_position(type, _index, :timeline) do
    # Y position based on entity type for timeline view
    type_y = %{
      process: 100,
      file: 250,
      network: 400,
      dns: 400,
      registry: 550,
      user: 50
    }

    Map.get(type_y, type, 300) * 1.0
  end

  defp calculate_y_position(_type, index, _layout) do
    (50 + rem(index, 10) * 80) * 1.0
  end

  defp highlight_malicious_path(nodes, edges, alert) do
    # Find nodes related to the alert
    alert_node_ids = extract_alert_node_ids(alert)

    # Traverse backwards from alert nodes to find the path
    malicious_path = find_path_to_root(alert_node_ids, edges)

    # Highlight nodes in the path
    nodes = Enum.map(nodes, fn node ->
      if MapSet.member?(malicious_path, node.id) do
        Map.put(node, :highlighted, true)
      else
        node
      end
    end)

    # Highlight edges in the path
    edges = Enum.map(edges, fn edge ->
      if MapSet.member?(malicious_path, edge.source) && MapSet.member?(malicious_path, edge.target) do
        edge
        |> Map.put(:animated, true)
        |> Map.put(:color, "#ef4444")  # Red for malicious path
      else
        edge
      end
    end)

    {nodes, edges}
  end

  defp highlight_suspicious_path(nodes, edges) do
    # Find suspicious nodes
    suspicious_ids = nodes
    |> Enum.filter(& &1.suspicious)
    |> Enum.map(& &1.id)
    |> MapSet.new()

    # Find connected suspicious nodes
    connected_suspicious = find_connected_nodes(suspicious_ids, edges)

    # Update highlighting
    nodes = Enum.map(nodes, fn node ->
      if MapSet.member?(connected_suspicious, node.id) do
        Map.put(node, :highlighted, true)
      else
        node
      end
    end)

    # Update edge colors
    edges = Enum.map(edges, fn edge ->
      if MapSet.member?(connected_suspicious, edge.source) ||
         MapSet.member?(connected_suspicious, edge.target) do
        edge
        |> Map.put(:animated, true)
        |> Map.put(:color, "#f97316")  # Orange for suspicious
      else
        edge
      end
    end)

    {nodes, edges}
  end

  defp find_path_to_root(target_ids, edges) when is_struct(target_ids, MapSet) do
    find_path_to_root(MapSet.to_list(target_ids), edges)
  end
  defp find_path_to_root(target_ids, edges) do
    # Build reverse adjacency (target -> sources)
    reverse_adj = edges
    |> Enum.reduce(%{}, fn edge, acc ->
      Map.update(acc, edge.target, [edge.source], &[edge.source | &1])
    end)

    # BFS backwards
    do_bfs(target_ids, reverse_adj, MapSet.new(target_ids))
  end

  defp do_bfs([], _adj, visited), do: visited
  defp do_bfs(current, adj, visited) do
    next = current
    |> Enum.flat_map(fn id -> Map.get(adj, id, []) end)
    |> Enum.reject(&MapSet.member?(visited, &1))

    if Enum.empty?(next) do
      visited
    else
      new_visited = Enum.reduce(next, visited, &MapSet.put(&2, &1))
      do_bfs(next, adj, new_visited)
    end
  end

  defp find_connected_nodes(start_ids, edges) do
    # Build adjacency (bidirectional)
    adj = edges
    |> Enum.reduce(%{}, fn edge, acc ->
      acc
      |> Map.update(edge.source, [edge.target], &[edge.target | &1])
      |> Map.update(edge.target, [edge.source], &[edge.source | &1])
    end)

    do_bfs(MapSet.to_list(start_ids), adj, start_ids)
  end

  defp extract_alert_node_ids(nil), do: MapSet.new()
  defp extract_alert_node_ids(alert) do
    ids = []

    # Extract from evidence
    process = alert.evidence[:process] || get_in(alert.evidence, ["process"])
    if process do
      pid = process[:pid] || process["pid"]
      if pid, do: ids = ["process_#{pid}" | ids]
    end

    # Extract from process chain
    process_chain = alert.process_chain || []
    chain_ids = Enum.map(process_chain, fn p ->
      pid = p[:pid] || p["pid"]
      "process_#{pid}"
    end)

    MapSet.new(ids ++ chain_ids)
  end

  defp determine_node_severity(node) do
    cond do
      length(node_detections(node)) > 0 ->
        # Get highest severity from detections
        node_detections(node)
        |> Enum.map(&(Map.get(&1, :severity) || Map.get(&1, "severity") || "info"))
        |> Enum.map(&severity_rank/1)
        |> Enum.max()
        |> severity_from_rank()

      node.suspicious ->
        "medium"

      true ->
        "info"
    end
  end

  defp severity_rank("critical"), do: 4
  defp severity_rank("high"), do: 3
  defp severity_rank("medium"), do: 2
  defp severity_rank("low"), do: 1
  defp severity_rank(_), do: 0

  defp severity_from_rank(4), do: "critical"
  defp severity_from_rank(3), do: "high"
  defp severity_from_rank(2), do: "medium"
  defp severity_from_rank(1), do: "low"
  defp severity_from_rank(_), do: "info"

  defp get_edge_color(type, is_suspicious) do
    if is_suspicious do
      "#ef4444"  # Red for suspicious
    else
      case type do
        :spawned -> "#3b82f6"    # Blue
        :connected -> "#22c55e"  # Green
        :resolved -> "#8b5cf6"   # Purple
        :wrote -> "#f59e0b"      # Amber
        :modified -> "#f59e0b"   # Amber
        :read -> "#6366f1"       # Indigo
        :deleted -> "#ef4444"    # Red
        :created -> "#10b981"    # Emerald
        _ -> "#64748b"           # Gray
      end
    end
  end

  defp truncate_label(nil, _max), do: "Unknown"
  defp truncate_label(label, max) when is_binary(label) do
    if String.length(label) > max do
      String.slice(label, 0, max - 3) <> "..."
    else
      label
    end
  end
  defp truncate_label(label, _max), do: to_string(label)

  defp format_timestamp(nil), do: nil
  defp format_timestamp(%DateTime{} = dt) do
    Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S")
  end
  defp format_timestamp(%NaiveDateTime{} = ndt) do
    ndt
    |> DateTime.from_naive!("Etc/UTC")
    |> Calendar.strftime("%Y-%m-%d %H:%M:%S")
  end
  defp format_timestamp(ts) when is_binary(ts), do: ts
  defp format_timestamp(_), do: nil

  defp normalize_datetime(%DateTime{} = dt), do: dt

  defp normalize_datetime(%NaiveDateTime{} = ndt) do
    DateTime.from_naive!(ndt, "Etc/UTC")
  end

  defp normalize_datetime(value) when is_binary(value) do
    trimmed = String.trim(value)

    case DateTime.from_iso8601(trimmed) do
      {:ok, dt, _offset} ->
        dt

      _ ->
        case NaiveDateTime.from_iso8601(String.trim_trailing(trimmed, "Z")) do
          {:ok, ndt} -> DateTime.from_naive!(ndt, "Etc/UTC")
          _ -> nil
        end
    end
  end

  defp normalize_datetime(value) when is_integer(value) do
    unit = if abs(value) > 10_000_000_000, do: :millisecond, else: :second

    case DateTime.from_unix(value, unit) do
      {:ok, dt} -> dt
      _ -> nil
    end
  end

  defp normalize_datetime(_), do: nil

  defp datetime_sort_key(value) do
    case normalize_datetime(value) do
      %DateTime{} = dt -> DateTime.to_unix(dt, :microsecond)
      _ -> 0
    end
  end

  defp format_detections(detections) do
    Enum.map(detections, fn det ->
      rule_name =
        det[:rule_name] || det["rule_name"] || det[:ruleName] || det["ruleName"] ||
          det[:name] || det["name"] || det[:rule] || det["rule"]

      detection_type =
        det[:detection_type] || det["detection_type"] || det[:type] || det["type"]

      techniques =
        det[:mitre_techniques] || det["mitre_techniques"] ||
          det[:mitreTechniques] || det["mitreTechniques"] ||
          List.wrap(det[:mitre_technique] || det["mitre_technique"] || det[:mitreTechnique] || det["mitreTechnique"])

      %{
        ruleName: rule_name || detection_type || "Detection",
        detectionType: detection_type || "unknown",
        description: det[:description] || det["description"] || "",
        severity: det[:severity] || det["severity"] || "info",
        mitreTechniques: techniques
      }
    end)
  end

  defp node_detections(node) when is_map(node) do
    Map.get(node, :detections) || Map.get(node, "detections") || []
  end

  defp node_detections(_), do: []

  defp sanitize_node_data(data) when is_map(data) do
    data
    |> Map.drop([:password, :secret, :token, :credential, "password", "secret", "token", "credential"])
    |> Enum.map(fn {k, v} -> {to_string(k), sanitize_value(v)} end)
    |> Map.new()
  end
  defp sanitize_node_data(_), do: %{}

  defp sanitize_value(v) when is_binary(v), do: v
  defp sanitize_value(v) when is_number(v), do: v
  defp sanitize_value(v) when is_boolean(v), do: v
  defp sanitize_value(nil), do: nil
  defp sanitize_value(v) when is_list(v), do: Enum.map(v, &sanitize_value/1)
  defp sanitize_value(v) when is_map(v), do: sanitize_node_data(v)
  defp sanitize_value(v), do: to_string(v)

  defp calculate_stats(nodes, edges) do
    %{
      total_nodes: length(nodes),
      total_edges: length(edges),
      process_count: Enum.count(nodes, &(&1.type == "process")),
      file_count: Enum.count(nodes, &(&1.type == "file")),
      network_count: Enum.count(nodes, &(&1.type == "network")),
      dns_count: Enum.count(nodes, &(&1.type == "dns")),
      registry_count: Enum.count(nodes, &(&1.type == "registry")),
      suspicious_count: Enum.count(nodes, &(&1.suspicious)),
      detection_count: nodes |> Enum.flat_map(&node_detections/1) |> length()
    }
  end

  defp calculate_width(nodes) do
    max_x = nodes
    |> Enum.map(& &1.x)
    |> Enum.max(fn -> 800 end)

    max(800, round(max_x + 200))
  end

  defp calculate_height(nodes) do
    max_y = nodes
    |> Enum.map(& &1.y)
    |> Enum.max(fn -> 600 end)

    max(600, round(max_y + 100))
  end

  # Export functions

  defp export_to_dot(graph_data) do
    nodes_dot = graph_data.nodes
    |> Enum.map(fn node ->
      shape = case node.type do
        "process" -> "ellipse"
        "file" -> "box"
        "network" -> "diamond"
        "dns" -> "hexagon"
        "registry" -> "parallelogram"
        _ -> "ellipse"
      end

      color = if node.highlighted, do: "red", else: "black"

      ~s("#{node.id}" [label="#{escape_dot(node.label)}" shape=#{shape} color=#{color}])
    end)
    |> Enum.join("\n  ")

    edges_dot = graph_data.edges
    |> Enum.map(fn edge ->
      style = if edge.animated, do: "bold", else: "solid"
      ~s("#{edge.source}" -> "#{edge.target}" [label="#{edge.label}" style=#{style}])
    end)
    |> Enum.join("\n  ")

    dot = """
    digraph Storyline {
      rankdir=LR;
      node [fontname="Arial"];
      edge [fontname="Arial"];

      #{nodes_dot}

      #{edges_dot}
    }
    """

    {:ok, dot}
  end

  defp export_to_mermaid(graph_data) do
    nodes_mermaid = graph_data.nodes
    |> Enum.map(fn node ->
      shape = case node.type do
        "process" -> {"{", "}"}
        "file" -> {"[", "]"}
        "network" -> {"((", "))"}
        "dns" -> {"{{", "}}"}
        "registry" -> {"[/", "\\]"}
        _ -> {"(", ")"}
      end

      {open, close} = shape
      "  #{escape_mermaid_id(node.id)}#{open}\"#{escape_mermaid(node.label)}\"#{close}"
    end)
    |> Enum.join("\n")

    edges_mermaid = graph_data.edges
    |> Enum.map(fn edge ->
      arrow = if edge.animated, do: "==>", else: "-->"
      "  #{escape_mermaid_id(edge.source)} #{arrow}|#{edge.label}| #{escape_mermaid_id(edge.target)}"
    end)
    |> Enum.join("\n")

    mermaid = """
    graph LR
    #{nodes_mermaid}

    #{edges_mermaid}
    """

    {:ok, mermaid}
  end

  defp escape_dot(str) when is_binary(str) do
    str
    |> String.replace("\"", "\\\"")
    |> String.replace("\n", "\\n")
  end
  defp escape_dot(str), do: to_string(str)

  defp escape_mermaid(str) when is_binary(str) do
    str
    |> String.replace("\"", "'")
    |> String.replace("\n", " ")
  end
  defp escape_mermaid(str), do: to_string(str)

  defp escape_mermaid_id(id) when is_binary(id) do
    id
    |> String.replace(~r/[^a-zA-Z0-9_]/, "_")
  end
  defp escape_mermaid_id(id), do: to_string(id)
end
