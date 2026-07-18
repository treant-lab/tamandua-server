defmodule TamanduaServerWeb.API.V1.InvestigationController do
  @moduledoc """
  Investigation Graph API controller.

  Provides endpoints for building investigation graphs suitable for
  D3.js/vis.js visualization. Returns nodes and edges representing
  processes, network connections, file operations, and DNS queries.

  This enables CrowdStrike-like attack graph visualization for threat hunting.
  """
  use TamanduaServerWeb, :controller

  alias TamanduaServer.Repo
  alias TamanduaServer.Agents
  alias TamanduaServer.Alerts
  alias TamanduaServer.Detection.Correlator

  require Logger

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  Build an investigation graph starting from an alert.

  Returns a graph structure with nodes and edges suitable for D3.js visualization.
  Includes processes, network connections, file operations, and DNS queries.

  ## Parameters
    - id: Alert ID to start investigation from
    - depth: How deep to explore process tree (default: 3)
    - time_window_minutes: Time window for correlating events (default: 60)
  """
  def show(conn, %{"id" => alert_id} = params) do
    depth = parse_int(params["depth"], 3)
    time_window = parse_int(params["time_window_minutes"], 60)
    org_id = current_organization_id(conn)

    with {:ok, org_id} <- require_organization(org_id),
         {:ok, alert} <- Alerts.get_alert_for_org(org_id, alert_id),
         {:ok, graph_data} <- build_investigation_graph(alert, depth, time_window, org_id) do
      json(conn, %{data: graph_data})
    else
      {:error, reason} ->
        conn
        |> put_status(error_status(reason))
        |> json(%{error: reason})
    end
  end

  @doc """
  Build investigation graph from a process.

  ## Parameters
    - agent_id: Required - the agent ID
    - pid: Required - the process ID to investigate
    - depth: How deep to explore (default: 3)
    - time_window_minutes: Time window for events (default: 60)
  """
  def from_process(conn, %{"agent_id" => agent_id, "pid" => pid_param} = params) do
    pid = parse_int(pid_param, 0)
    depth = parse_int(params["depth"], 3)
    time_window = parse_int(params["time_window_minutes"], 60)
    org_id = current_organization_id(conn)

    with {:ok, org_id} <- require_organization(org_id),
         {:ok, _agent} <- Agents.get_agent_for_org(org_id, agent_id),
         {:ok, graph_data} <- build_process_investigation_graph(agent_id, pid, depth, time_window, org_id) do
      json(conn, %{data: graph_data})
    else
      {:error, reason} ->
        conn
        |> put_status(error_status(reason))
        |> json(%{error: reason})
    end
  end

  def from_process(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required parameters: agent_id and pid"})
  end

  @doc """
  Build investigation graph from an event.

  ## Parameters
    - event_id: Required - the event ID to investigate
    - depth: How deep to explore (default: 3)
    - time_window_minutes: Time window for events (default: 60)
  """
  def from_event(conn, %{"event_id" => event_id} = params) do
    depth = parse_int(params["depth"], 3)
    time_window = parse_int(params["time_window_minutes"], 60)
    org_id = current_organization_id(conn)

    case get_event_for_org(event_id, org_id) do
      {:ok, event} ->
        agent_id = event.agent_id
        pid = get_in(event.payload, ["pid"]) || get_in(event.payload, [:pid]) || 0

        case build_process_investigation_graph(agent_id, pid, depth, time_window, org_id) do
          {:ok, graph_data} ->
            # Add the triggering event as a highlighted node
            graph_data = Map.update!(graph_data, :nodes, fn nodes ->
              Enum.map(nodes, fn node ->
                if node.id == "event_#{event_id}" do
                  Map.put(node, :highlighted, true)
                else
                  node
                end
              end)
            end)

            json(conn, %{data: graph_data})

          {:error, reason} ->
            conn
            |> put_status(:not_found)
            |> json(%{error: reason})
        end

      {:error, reason} ->
        conn
        |> put_status(error_status(reason))
        |> json(%{error: reason})
    end
  end

  def from_event(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required parameter: event_id"})
  end

  @doc """
  Get timeline of events for an investigation.

  ## Parameters
    - agent_id: Required - the agent ID
    - pid: Optional - filter by process ID
    - time_window_minutes: Time window (default: 60)
    - limit: Maximum events (default: 200)
  """
  def timeline(conn, %{"agent_id" => agent_id} = params) do
    pid = params["pid"] && parse_int(params["pid"], nil)
    time_window = parse_int(params["time_window_minutes"], 60)
    limit = parse_int(params["limit"], 200)
    org_id = current_organization_id(conn)

    with {:ok, org_id} <- require_organization(org_id),
         {:ok, _agent} <- Agents.get_agent_for_org(org_id, agent_id) do
      time_threshold = DateTime.utc_now()
      |> DateTime.add(-time_window * 60, :second)

      events = get_investigation_events(agent_id, pid, time_threshold, limit, org_id)

      timeline = events
      |> Enum.sort_by(& &1.timestamp)
      |> Enum.map(&format_timeline_entry/1)

      json(conn, %{
        data: %{
          agent_id: agent_id,
          events: timeline,
          event_count: length(timeline),
          time_window_minutes: time_window
        }
      })
    else
      {:error, reason} ->
        conn
        |> put_status(error_status(reason))
        |> json(%{error: reason})
    end
  end

  def timeline(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required parameter: agent_id"})
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp get_event_for_org(_event_id, nil), do: {:error, :organization_required}

  defp get_event_for_org(event_id, org_id) do
    query = """
    SELECT e.id, e.event_type, e.timestamp, e.payload, e.severity, e.detections, e.agent_id
    FROM events e
    INNER JOIN agents a ON a.id = e.agent_id
    WHERE e.id = $1
      AND a.organization_id = $2
    LIMIT 1
    """

    case Repo.query(query, [dump_uuid!(event_id), dump_uuid!(org_id)]) do
      {:ok, %{rows: [[id, event_type, timestamp, payload, severity, detections, agent_id]]}} ->
        {:ok, %{
          id: id,
          event_type: event_type,
          timestamp: timestamp,
          payload: payload || %{},
          severity: severity,
          detections: detections || [],
          agent_id: agent_id
        }}
      _ ->
        {:error, :not_found}
    end
  end

  defp build_investigation_graph(alert, depth, time_window, org_id) do
    agent_id = alert.agent_id
    event_ids = alert.event_ids || []

    # Get all events for this alert within the current tenant.
    events = get_alert_events(event_ids, org_id)

    # Find primary process from events
    primary_pid = events
    |> Enum.find_value(fn e ->
      get_in(e, [:payload, "pid"]) || get_in(e, [:payload, :pid])
    end) || 0

    build_process_investigation_graph(agent_id, primary_pid, depth, time_window, org_id)
  end

  defp build_process_investigation_graph(agent_id, start_pid, depth, time_window, org_id) do
    time_threshold = DateTime.utc_now()
    |> DateTime.add(-time_window * 60, :second)

    # Get process tree
    process_tree_result = Correlator.get_process_tree(agent_id)

    # Get all events for this agent scoped to the organization.
    events = get_investigation_events(agent_id, nil, time_threshold, 500, org_id)

    nodes = []
    edges = []

    # Add process nodes from tree
    {process_nodes, process_edges} = case process_tree_result do
      {:ok, graph} ->
        build_process_nodes_from_graph(graph, start_pid, depth)
      {:error, _} ->
        # Build process nodes from events
        build_process_nodes_from_events(events, start_pid, depth)
    end

    nodes = nodes ++ process_nodes

    # Add network nodes and edges
    network_events = Enum.filter(events, fn e ->
      e.event_type in ["network_connect", "network_listen", "network_connection"]
    end)

    {network_nodes, network_edges} = build_network_nodes(network_events, process_nodes)

    # Add DNS nodes and edges
    dns_events = Enum.filter(events, fn e ->
      e.event_type in ["dns_query", "dns"]
    end)

    {dns_nodes, dns_edges} = build_dns_nodes(dns_events, process_nodes)

    # Add file nodes and edges
    file_events = Enum.filter(events, fn e ->
      e.event_type in ["file_create", "file_modify", "file_delete", "file_execute"]
    end)

    {file_nodes, file_edges} = build_file_nodes(file_events, process_nodes)

    # Add registry nodes and edges
    registry_events = Enum.filter(events, fn e ->
      e.event_type in ["registry_modify", "registry_create", "registry_delete"]
    end)

    {registry_nodes, registry_edges} = build_registry_nodes(registry_events, process_nodes)

    all_nodes = (nodes ++ network_nodes ++ dns_nodes ++ file_nodes ++ registry_nodes)
    |> Enum.uniq_by(& &1.id)

    all_edges = (process_edges ++ edges ++ network_edges ++ dns_edges ++ file_edges ++ registry_edges)
    |> Enum.uniq_by(fn e -> {e.source, e.target, e.type} end)

    # Calculate statistics
    stats = %{
      process_count: length(process_nodes),
      network_count: length(network_nodes),
      dns_count: length(dns_nodes),
      file_count: length(file_nodes),
      registry_count: length(registry_nodes),
      total_nodes: length(all_nodes),
      total_edges: length(all_edges)
    }

    {:ok, %{
      agent_id: agent_id,
      start_pid: start_pid,
      nodes: all_nodes,
      edges: all_edges,
      stats: stats,
      time_window_minutes: time_window
    }}
  end

  defp build_process_nodes_from_graph(graph, start_pid, _depth) do
    vertices = Graph.vertices(graph)
    edges = Graph.edges(graph)

    nodes = vertices
    |> Enum.map(fn pid ->
      labels = Graph.vertex_labels(graph, pid)
      info = List.first(labels) || %{}

      severity = calculate_process_severity(info)

      %{
        id: "process_#{pid}",
        type: "process",
        label: info[:name] || "PID #{pid}",
        pid: pid,
        data: %{
          pid: pid,
          name: info[:name],
          path: info[:path],
          cmdline: info[:cmdline],
          user: info[:user],
          sha256: info[:sha256],
          start_time: info[:start_time]
        },
        severity: severity,
        highlighted: pid == start_pid,
        detections: []
      }
    end)

    edge_list = edges
    |> Enum.map(fn edge ->
      %{
        source: "process_#{edge.v1}",
        target: "process_#{edge.v2}",
        type: "spawned",
        label: "spawned"
      }
    end)

    {nodes, edge_list}
  end

  defp build_process_nodes_from_events(events, start_pid, _depth) do
    process_events = events
    |> Enum.filter(fn e -> e.event_type in ["process_create", "process"] end)

    process_map = process_events
    |> Enum.reduce(%{}, fn e, acc ->
      pid = get_in(e.payload, ["pid"]) || get_in(e.payload, [:pid])
      if pid do
        Map.put(acc, pid, e)
      else
        acc
      end
    end)

    nodes = process_map
    |> Enum.map(fn {pid, event} ->
      payload = event.payload
      severity = calculate_event_severity(event)

      %{
        id: "process_#{pid}",
        type: "process",
        label: payload["name"] || payload[:name] || "PID #{pid}",
        pid: pid,
        data: %{
          pid: pid,
          ppid: payload["ppid"] || payload[:ppid],
          name: payload["name"] || payload[:name],
          path: payload["path"] || payload[:path],
          cmdline: payload["command_line"] || payload["cmdline"] || payload[:cmdline],
          user: payload["user"] || payload[:user],
          sha256: payload["sha256"] || payload[:sha256]
        },
        severity: severity,
        highlighted: pid == start_pid,
        detections: event.detections || []
      }
    end)

    edges = process_map
    |> Enum.flat_map(fn {pid, event} ->
      ppid = get_in(event.payload, ["ppid"]) || get_in(event.payload, [:ppid])
      if ppid && Map.has_key?(process_map, ppid) do
        [%{
          source: "process_#{ppid}",
          target: "process_#{pid}",
          type: "spawned",
          label: "spawned"
        }]
      else
        []
      end
    end)

    {nodes, edges}
  end

  defp build_network_nodes(network_events, process_nodes) do
    # Get set of process PIDs we have
    process_pids = process_nodes
    |> Enum.map(fn n -> n.pid end)
    |> MapSet.new()

    # Group network events by destination
    grouped = network_events
    |> Enum.group_by(fn e ->
      remote_ip = get_in(e.payload, ["remote_ip"]) || get_in(e.payload, [:remote_ip])
      remote_port = get_in(e.payload, ["remote_port"]) || get_in(e.payload, [:remote_port])
      "#{remote_ip}:#{remote_port}"
    end)

    nodes = grouped
    |> Enum.map(fn {dest, events} ->
      first_event = List.first(events)
      remote_ip = get_in(first_event.payload, ["remote_ip"]) || get_in(first_event.payload, [:remote_ip])
      remote_port = get_in(first_event.payload, ["remote_port"]) || get_in(first_event.payload, [:remote_port])

      %{
        id: "network_#{dest}",
        type: "network",
        label: dest,
        data: %{
          remote_ip: remote_ip,
          remote_port: remote_port,
          connection_count: length(events),
          protocols: events |> Enum.map(fn e -> e.payload["protocol"] || e.payload[:protocol] end) |> Enum.uniq(),
          first_seen: events |> Enum.map(& &1.timestamp) |> Enum.min(DateTime, fn -> nil end),
          last_seen: events |> Enum.map(& &1.timestamp) |> Enum.max(DateTime, fn -> nil end)
        },
        severity: calculate_network_severity(events),
        detections: events |> Enum.flat_map(& &1.detections || [])
      }
    end)

    edges = network_events
    |> Enum.flat_map(fn e ->
      pid = get_in(e.payload, ["pid"]) || get_in(e.payload, [:pid])
      remote_ip = get_in(e.payload, ["remote_ip"]) || get_in(e.payload, [:remote_ip])
      remote_port = get_in(e.payload, ["remote_port"]) || get_in(e.payload, [:remote_port])
      dest = "#{remote_ip}:#{remote_port}"

      if pid && MapSet.member?(process_pids, pid) do
        [%{
          source: "process_#{pid}",
          target: "network_#{dest}",
          type: "network_connection",
          label: e.payload["protocol"] || e.payload[:protocol] || "TCP"
        }]
      else
        []
      end
    end)
    |> Enum.uniq_by(fn e -> {e.source, e.target} end)

    {nodes, edges}
  end

  defp build_dns_nodes(dns_events, process_nodes) do
    process_pids = process_nodes
    |> Enum.map(fn n -> n.pid end)
    |> MapSet.new()

    grouped = dns_events
    |> Enum.group_by(fn e ->
      get_in(e.payload, ["query"]) || get_in(e.payload, [:query]) || "unknown"
    end)

    nodes = grouped
    |> Enum.map(fn {domain, events} ->
      %{
        id: "dns_#{domain}",
        type: "dns",
        label: domain,
        data: %{
          domain: domain,
          query_count: length(events),
          first_seen: events |> Enum.map(& &1.timestamp) |> Enum.min(DateTime, fn -> nil end),
          resolved_ips: events
            |> Enum.flat_map(fn e ->
              result = e.payload["result"] || e.payload[:result]
              if is_list(result), do: result, else: [result]
            end)
            |> Enum.filter(& &1)
            |> Enum.uniq()
        },
        severity: "info",
        detections: events |> Enum.flat_map(& &1.detections || [])
      }
    end)

    edges = dns_events
    |> Enum.flat_map(fn e ->
      pid = get_in(e.payload, ["pid"]) || get_in(e.payload, [:pid])
      domain = get_in(e.payload, ["query"]) || get_in(e.payload, [:query]) || "unknown"

      if pid && MapSet.member?(process_pids, pid) do
        [%{
          source: "process_#{pid}",
          target: "dns_#{domain}",
          type: "dns_query",
          label: "queried"
        }]
      else
        []
      end
    end)
    |> Enum.uniq_by(fn e -> {e.source, e.target} end)

    {nodes, edges}
  end

  defp build_file_nodes(file_events, process_nodes) do
    process_pids = process_nodes
    |> Enum.map(fn n -> n.pid end)
    |> MapSet.new()

    # Limit file nodes to prevent overwhelming the graph
    significant_events = file_events
    |> Enum.filter(fn e ->
      # Only include files with detections or suspicious paths
      has_detections = length(e.detections || []) > 0
      path = get_in(e.payload, ["path"]) || get_in(e.payload, [:path]) || ""
      suspicious_path = String.contains?(path, ["temp", "appdata", "programdata", "public"]) ||
                        String.ends_with?(path, [".exe", ".dll", ".ps1", ".bat", ".vbs", ".js"])
      has_detections || suspicious_path
    end)
    |> Enum.take(50)

    grouped = significant_events
    |> Enum.group_by(fn e ->
      get_in(e.payload, ["path"]) || get_in(e.payload, [:path]) || "unknown"
    end)

    nodes = grouped
    |> Enum.map(fn {path, events} ->
      operations = events
      |> Enum.map(fn e ->
        e.payload["operation"] || e.payload[:operation] || e.event_type
      end)
      |> Enum.uniq()

      %{
        id: "file_#{:erlang.phash2(path)}",
        type: "file",
        label: Path.basename(path),
        data: %{
          path: path,
          operations: operations,
          operation_count: length(events),
          sha256: events |> Enum.find_value(fn e -> e.payload["sha256"] || e.payload[:sha256] end)
        },
        severity: calculate_file_severity(events),
        detections: events |> Enum.flat_map(& &1.detections || [])
      }
    end)

    edges = significant_events
    |> Enum.flat_map(fn e ->
      pid = get_in(e.payload, ["pid"]) || get_in(e.payload, [:pid])
      path = get_in(e.payload, ["path"]) || get_in(e.payload, [:path]) || "unknown"
      operation = e.payload["operation"] || e.payload[:operation] || e.event_type

      if pid && MapSet.member?(process_pids, pid) do
        [%{
          source: "process_#{pid}",
          target: "file_#{:erlang.phash2(path)}",
          type: "file_operation",
          label: operation
        }]
      else
        []
      end
    end)
    |> Enum.uniq_by(fn e -> {e.source, e.target, e.label} end)

    {nodes, edges}
  end

  defp build_registry_nodes(registry_events, process_nodes) do
    process_pids = process_nodes
    |> Enum.map(fn n -> n.pid end)
    |> MapSet.new()

    # Limit and filter registry nodes
    significant_events = registry_events
    |> Enum.filter(fn e ->
      key = get_in(e.payload, ["key"]) || get_in(e.payload, [:key]) || ""
      # Only persistence-related keys
      String.contains?(String.downcase(key), ["run", "services", "startup", "shell", "winlogon"])
    end)
    |> Enum.take(30)

    grouped = significant_events
    |> Enum.group_by(fn e ->
      get_in(e.payload, ["key"]) || get_in(e.payload, [:key]) || "unknown"
    end)

    nodes = grouped
    |> Enum.map(fn {key, events} ->
      %{
        id: "registry_#{:erlang.phash2(key)}",
        type: "registry",
        label: key |> String.split("\\") |> List.last(),
        data: %{
          key: key,
          modification_count: length(events),
          values: events |> Enum.flat_map(fn e ->
            value = e.payload["value"] || e.payload[:value]
            if value, do: [value], else: []
          end) |> Enum.uniq()
        },
        severity: "high", # Registry persistence is usually high severity
        detections: events |> Enum.flat_map(& &1.detections || [])
      }
    end)

    edges = significant_events
    |> Enum.flat_map(fn e ->
      pid = get_in(e.payload, ["pid"]) || get_in(e.payload, [:pid])
      key = get_in(e.payload, ["key"]) || get_in(e.payload, [:key]) || "unknown"

      if pid && MapSet.member?(process_pids, pid) do
        [%{
          source: "process_#{pid}",
          target: "registry_#{:erlang.phash2(key)}",
          type: "registry_modification",
          label: "modified"
        }]
      else
        []
      end
    end)
    |> Enum.uniq_by(fn e -> {e.source, e.target} end)

    {nodes, edges}
  end

  defp get_alert_events(event_ids, org_id) when is_list(event_ids) and event_ids != [] and not is_nil(org_id) do
    query = """
    SELECT e.id, e.event_type, e.timestamp, e.payload, e.severity, e.detections, e.agent_id
    FROM events e
    INNER JOIN agents a ON a.id = e.agent_id
    WHERE e.id = ANY($1)
      AND a.organization_id = $2
    ORDER BY e.timestamp ASC
    """

    binary_ids = Enum.map(event_ids, &dump_uuid!/1)

    case Repo.query(query, [binary_ids, dump_uuid!(org_id)]) do
      {:ok, result} ->
        Enum.map(result.rows, fn [id, event_type, timestamp, payload, severity, detections, agent_id] ->
          %{
            id: id,
            event_type: event_type,
            timestamp: timestamp,
            payload: payload || %{},
            severity: severity,
            detections: detections || [],
            agent_id: agent_id
          }
        end)
      _ -> []
    end
  end

  defp get_alert_events(_, _), do: []

  defp get_investigation_events(agent_id, pid, time_threshold, limit, org_id) do
    base_query = """
    SELECT e.id, e.event_type, e.timestamp, e.payload, e.severity, e.detections, e.agent_id
    FROM events e
    INNER JOIN agents a ON a.id = e.agent_id
    WHERE e.agent_id = $1
      AND a.organization_id = $2
      AND e.timestamp >= $3
    """

    binary_agent_id = dump_uuid!(agent_id)
    binary_org_id = dump_uuid!(org_id)

    {query, params} = if pid do
      {base_query <> " AND (e.payload->>'pid')::int = $4 ORDER BY e.timestamp DESC LIMIT $5",
       [binary_agent_id, binary_org_id, time_threshold, pid, limit]}
    else
      {base_query <> " ORDER BY e.timestamp DESC LIMIT $4",
       [binary_agent_id, binary_org_id, time_threshold, limit]}
    end

    case Repo.query(query, params) do
      {:ok, result} ->
        Enum.map(result.rows, fn [id, event_type, timestamp, payload, severity, detections, agent_id] ->
          %{
            id: id,
            event_type: event_type,
            timestamp: timestamp,
            payload: payload || %{},
            severity: severity,
            detections: detections || [],
            agent_id: agent_id
          }
        end)
      {:error, err} ->
        Logger.warning("Failed to get investigation events: #{inspect(err)}")
        []
    end
  end

  defp calculate_process_severity(info) do
    name = (info[:name] || "") |> String.downcase()

    cond do
      name in ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"] -> "medium"
      info[:is_signed] == false -> "low"
      true -> "info"
    end
  end

  defp calculate_event_severity(event) do
    cond do
      length(event.detections || []) > 0 -> "high"
      event.severity in ["critical", "high"] -> event.severity
      true -> "info"
    end
  end

  defp calculate_network_severity(events) do
    cond do
      Enum.any?(events, fn e -> length(e.detections || []) > 0 end) -> "high"
      Enum.any?(events, fn e -> e.severity in ["critical", "high"] end) -> "medium"
      true -> "info"
    end
  end

  defp calculate_file_severity(events) do
    cond do
      Enum.any?(events, fn e -> length(e.detections || []) > 0 end) -> "high"
      Enum.any?(events, fn e ->
        path = (e.payload["path"] || e.payload[:path] || "") |> String.downcase()
        String.ends_with?(path, [".exe", ".dll", ".ps1", ".bat", ".vbs"])
      end) -> "medium"
      true -> "info"
    end
  end

  defp format_timeline_entry(event) do
    %{
      id: event.id,
      timestamp: event.timestamp,
      event_type: event.event_type,
      severity: event.severity,
      summary: summarize_event(event),
      icon: event_type_icon(event.event_type),
      pid: get_in(event.payload, ["pid"]) || get_in(event.payload, [:pid]),
      detections: event.detections || [],
      payload: event.payload
    }
  end

  defp summarize_event(event) do
    payload = event.payload

    case event.event_type do
      type when type in ["process_create", "process"] ->
        name = payload["name"] || payload[:name] || "unknown"
        pid = payload["pid"] || payload[:pid]
        "Process created: #{name} (PID: #{pid})"

      type when type in ["network_connect", "network_connection"] ->
        remote_ip = payload["remote_ip"] || payload[:remote_ip]
        remote_port = payload["remote_port"] || payload[:remote_port]
        "Connection to #{remote_ip}:#{remote_port}"

      type when type in ["dns_query", "dns"] ->
        query = payload["query"] || payload[:query]
        "DNS query: #{query}"

      type when type in ["file_create", "file_modify", "file_delete"] ->
        path = payload["path"] || payload[:path]
        op = String.replace(event.event_type, "file_", "")
        "File #{op}: #{Path.basename(path || "unknown")}"

      "registry_modify" ->
        key = payload["key"] || payload[:key]
        "Registry modified: #{key |> String.split("\\") |> List.last()}"

      _ ->
        "#{event.event_type} event"
    end
  end

  defp event_type_icon(event_type) do
    case event_type do
      type when type in ["process_create", "process"] -> "cpu"
      type when type in ["network_connect", "network_connection", "network_listen"] -> "globe"
      type when type in ["dns_query", "dns"] -> "server"
      type when type in ["file_create", "file_modify", "file_delete", "file_execute"] -> "file"
      "registry_modify" -> "settings"
      _ -> "activity"
    end
  end

  defp parse_int(nil, default), do: default
  defp parse_int(val, _default) when is_integer(val), do: val
  defp parse_int(val, default) when is_binary(val) do
    case Integer.parse(val) do
      {int, _} -> int
      :error -> default
    end
  end
  defp parse_int(_, default), do: default

  defp current_organization_id(conn) do
    conn.assigns[:current_organization_id] ||
      conn.assigns[:organization_id] ||
      get_in(conn.assigns, [:current_user, Access.key(:organization_id)])
  end

  defp require_organization(nil), do: {:error, :organization_required}
  defp require_organization(org_id), do: {:ok, org_id}

  defp error_status(:organization_required), do: :bad_request
  defp error_status(:not_found), do: :not_found
  defp error_status(_), do: :not_found

  # Convert a string UUID to the 16-byte binary format Postgrex expects
  defp dump_uuid!(uuid) when is_binary(uuid) do
    case Ecto.UUID.dump(uuid) do
      {:ok, binary} -> binary
      :error -> uuid
    end
  end
  defp dump_uuid!(other), do: other
end
