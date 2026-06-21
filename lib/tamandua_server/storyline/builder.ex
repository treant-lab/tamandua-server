defmodule TamanduaServer.Storyline.Builder do
  @moduledoc """
  Storyline Builder - Constructs causal chains and identifies root causes.

  The Builder module is responsible for:
  - Building process trees with lateral connections
  - Establishing file/registry/network causality
  - Tracking user context and privilege changes
  - Automatic root cause identification

  This is the core analysis engine that transforms raw events into
  a structured attack narrative.
  """

  require Logger

  @type storyline_node :: %{
    id: String.t(),
    type: atom(),
    entity_id: String.t(),
    entity_name: String.t(),
    timestamp: DateTime.t() | nil,
    data: map(),
    suspicious: boolean(),
    detections: list(),
    depth: integer()
  }

  @type edge :: %{
    id: String.t(),
    source: String.t(),
    target: String.t(),
    type: atom(),
    label: String.t(),
    timestamp: DateTime.t() | nil,
    data: map()
  }

  @type causal_chain :: %{
    nodes: list(node()),
    edges: list(edge()),
    process_tree: map(),
    file_operations: list(),
    network_connections: list(),
    registry_modifications: list(),
    user_context: map()
  }

  @doc """
  Build a causal chain from a list of events.

  This function:
  1. Groups events by type
  2. Builds the process tree
  3. Establishes causality between different entity types
  4. Links file/network/registry operations to their originating processes
  """
  @spec build_causal_chain(list()) :: {:ok, causal_chain()} | {:error, term()}
  def build_causal_chain(events) when is_list(events) do
    # Group events by type
    grouped = group_events_by_type(events)

    # Build process tree first (this is the backbone)
    process_tree = build_process_tree(grouped.process_events)

    # Build nodes and edges
    {nodes, edges} = build_graph_from_events(events, process_tree)

    # Identify suspicious patterns
    nodes = mark_suspicious_nodes(nodes, edges)

    causal_chain = %{
      nodes: nodes,
      edges: edges,
      process_tree: process_tree,
      file_operations: grouped.file_events,
      network_connections: grouped.network_events,
      registry_modifications: grouped.registry_events,
      user_context: extract_user_context(events)
    }

    {:ok, causal_chain}
  end

  @doc """
  Identify the root cause of an attack from the causal chain.

  Root cause identification uses several heuristics:
  1. Earliest process with suspicious activity
  2. Process that spawned the most suspicious children
  3. Entry point processes (browsers, email clients, etc.)
  4. Processes with the earliest timestamp that have detections
  """
  @spec identify_root_cause(causal_chain()) :: {:ok, map()} | {:error, term()}
  def identify_root_cause(causal_chain) do
    nodes = causal_chain.nodes
    edges = causal_chain.edges

    # Get all process nodes
    process_nodes = Enum.filter(nodes, &(&1.type == :process))

    # Score each process as potential root cause
    scored_processes = process_nodes
    |> Enum.map(fn node ->
      score = calculate_root_cause_score(node, nodes, edges, causal_chain)
      {node, score}
    end)
    |> Enum.sort_by(fn {_, score} -> -score end)

    case scored_processes do
      [{root_node, score} | _] when score > 0 ->
        root_cause = %{
          node_id: root_node.id,
          type: root_node.type,
          entity_name: root_node.entity_name,
          process_name: root_node.data[:name] || root_node.entity_name,
          cmdline: root_node.data[:cmdline],
          path: root_node.data[:path],
          pid: root_node.data[:pid],
          ppid: root_node.data[:ppid],
          user: root_node.data[:user],
          timestamp: root_node.timestamp,
          confidence_score: normalize_score(score),
          reasoning: explain_root_cause(root_node, score)
        }
        {:ok, root_cause}

      _ ->
        {:ok, nil}
    end
  end

  @doc """
  Build privilege escalation chain from events.
  """
  @spec build_privilege_chain(list()) :: list()
  def build_privilege_chain(events) do
    events
    |> Enum.filter(fn event ->
      event.event_type in ["privilege_change", "token_manipulation", "process_create"]
    end)
    |> Enum.sort_by(&(Map.get(&1, :timestamp) |> datetime_sort_key()))
    |> Enum.chunk_every(2, 1, :discard)
    |> Enum.filter(fn [prev, curr] ->
      # Detect privilege escalation
      prev_elevated = get_in(prev.payload, ["is_elevated"]) || false
      curr_elevated = get_in(curr.payload, ["is_elevated"]) || false
      !prev_elevated && curr_elevated
    end)
    |> Enum.map(fn [prev, curr] ->
      %{
        from_process: extract_process_info(prev),
        to_process: extract_process_info(curr),
        timestamp: curr.timestamp,
        type: :privilege_escalation
      }
    end)
  end

  @doc """
  Build lateral movement indicators.
  """
  @spec build_lateral_movement_chain(list()) :: list()
  def build_lateral_movement_chain(events) do
    # Look for patterns indicating lateral movement
    lateral_indicators = []

    # Remote service access
    remote_services = events
    |> Enum.filter(fn event ->
      event.event_type in ["network_connect", "smb_session", "rdp_session", "wmi_exec", "psexec"]
    end)
    |> Enum.map(fn event ->
      %{
        type: :remote_access,
        target: get_in(event.payload, ["remote_addr"]) || get_in(event.payload, ["target_host"]),
        service: event.event_type,
        timestamp: event.timestamp,
        process: get_in(event.payload, ["process_name"])
      }
    end)

    # Credential usage on remote systems
    credential_use = events
    |> Enum.filter(fn event ->
      event.event_type in ["logon", "authentication"] &&
        get_in(event.payload, ["logon_type"]) in ["Network", "RemoteInteractive", "10", "3"]
    end)
    |> Enum.map(fn event ->
      %{
        type: :remote_auth,
        user: get_in(event.payload, ["user"]),
        target: get_in(event.payload, ["target_host"]),
        logon_type: get_in(event.payload, ["logon_type"]),
        timestamp: event.timestamp
      }
    end)

    lateral_indicators ++ remote_services ++ credential_use
  end

  # Private functions

  defp group_events_by_type(events) do
    %{
      process_events: Enum.filter(events, &process_event?/1),
      file_events: Enum.filter(events, &file_event?/1),
      network_events: Enum.filter(events, &network_event?/1),
      registry_events: Enum.filter(events, &registry_event?/1),
      dns_events: Enum.filter(events, &dns_event?/1),
      user_events: Enum.filter(events, &user_event?/1)
    }
  end

  defp process_event?(event) do
    event.event_type in ["process_create", "process_terminate", "process_inject", "process_hollow"]
  end

  defp file_event?(event) do
    event.event_type in ["file_create", "file_modify", "file_delete", "file_read", "file_rename"]
  end

  defp network_event?(event) do
    event.event_type in ["network_connect", "network_listen", "network_accept", "network_send", "network_receive"]
  end

  defp registry_event?(event) do
    event.event_type in ["registry_write", "registry_delete", "registry_create", "registry_read"]
  end

  defp dns_event?(event) do
    event.event_type in ["dns_query", "dns_response"]
  end

  defp user_event?(event) do
    event.event_type in ["logon", "logoff", "privilege_change", "authentication"]
  end

  defp build_process_tree(process_events) do
    # Build a map of PID -> process info
    processes = process_events
    |> Enum.filter(&(&1.event_type == "process_create"))
    |> Enum.reduce(%{}, fn event, acc ->
      pid = get_in(event.payload, ["pid"])
      if pid do
        Map.put(acc, pid, %{
          pid: pid,
          ppid: payload_value(event.payload, ["ppid", "parent_pid"]),
          name: payload_value(event.payload, ["name", "process_name", "image", "exe"]),
          path: payload_value(event.payload, ["path", "image_path", "executable_path"]),
          cmdline: payload_value(event.payload, ["cmdline", "command_line", "commandline", "command"]),
          decoded_command: payload_value(event.payload, ["decoded_command"]),
          embedded_urls: payload_value(event.payload, ["embedded_urls"]) || [],
          user: payload_value(event.payload, ["user", "username", "user_name"]),
          timestamp: event.timestamp,
          sha256: payload_value(event.payload, ["sha256", "hash_sha256"]),
          is_elevated: payload_value(event.payload, ["is_elevated"]) || false,
          is_signed: payload_value(event.payload, ["is_signed"]) || false,
          signer: payload_value(event.payload, ["signer"]),
          parent_name: payload_value(event.payload, ["parent_name", "parent_process_name"]),
          parent_path: payload_value(event.payload, ["parent_path", "parent_executable_path", "parent_process_path"]),
          children: [],
          detections: detections_for(event)
        })
      else
        acc
      end
    end)

    # Build parent-child relationships
    Enum.reduce(processes, processes, fn {pid, proc}, acc ->
      ppid = proc.ppid
      if ppid && Map.has_key?(acc, ppid) do
        parent = Map.get(acc, ppid)
        updated_parent = Map.update!(parent, :children, &([pid | &1]))
        Map.put(acc, ppid, updated_parent)
      else
        acc
      end
    end)
  end

  defp build_graph_from_events(events, process_tree) do
    nodes = []
    edges = []

    # Add process nodes
    {process_nodes, process_edges} = build_process_nodes_and_edges(process_tree)
    nodes = nodes ++ process_nodes
    edges = edges ++ process_edges

    # Add file nodes and edges
    {file_nodes, file_edges} = build_file_nodes_and_edges(events, process_tree)
    nodes = nodes ++ file_nodes
    edges = edges ++ file_edges

    # Add network nodes and edges
    {network_nodes, network_edges} = build_network_nodes_and_edges(events, process_tree)
    nodes = nodes ++ network_nodes
    edges = edges ++ network_edges

    # Add DNS nodes and edges
    {dns_nodes, dns_edges} = build_dns_nodes_and_edges(events, process_tree)
    nodes = nodes ++ dns_nodes
    edges = edges ++ dns_edges

    # Add registry nodes and edges
    {registry_nodes, registry_edges} = build_registry_nodes_and_edges(events, process_tree)
    nodes = nodes ++ registry_nodes
    edges = edges ++ registry_edges

    # Deduplicate nodes
    nodes = nodes
    |> Enum.uniq_by(& &1.id)

    {nodes, edges}
  end

  defp build_process_nodes_and_edges(process_tree) do
    nodes = process_tree
    |> Map.values()
    |> Enum.map(fn proc ->
      %{
        id: "process_#{proc.pid}",
        type: :process,
        entity_id: to_string(proc.pid),
        entity_name: proc.name || "Unknown Process",
        timestamp: proc.timestamp,
        data: %{
          pid: proc.pid,
          ppid: proc.ppid,
          name: proc.name,
          path: proc.path,
          cmdline: proc.cmdline,
          decoded_command: proc.decoded_command,
          embedded_urls: proc.embedded_urls,
          user: proc.user,
          sha256: proc.sha256,
          is_elevated: proc.is_elevated,
          is_signed: proc.is_signed,
          signer: proc.signer,
          parent_name: proc.parent_name,
          parent_path: proc.parent_path
        },
        suspicious: is_process_suspicious?(proc),
        detections: detections_for(proc),
        depth: 0
      }
    end)

    edges = process_tree
    |> Map.values()
    |> Enum.flat_map(fn proc ->
      if proc.ppid && Map.has_key?(process_tree, proc.ppid) do
        [%{
          id: "edge_spawn_#{proc.ppid}_#{proc.pid}",
          source: "process_#{proc.ppid}",
          target: "process_#{proc.pid}",
          type: :spawned,
          label: "spawned",
          timestamp: proc.timestamp,
          data: %{}
        }]
      else
        []
      end
    end)

    {nodes, edges}
  end

  defp build_file_nodes_and_edges(events, process_tree) do
    file_events = Enum.filter(events, &file_event?/1)

    # Group by file path to avoid duplicates
    files_by_path = file_events
    |> Enum.group_by(fn event ->
      get_in(event.payload, ["path"]) || get_in(event.payload, ["file_path"])
    end)
    |> Map.delete(nil)

    nodes = files_by_path
    |> Enum.map(fn {path, events} ->
      first_event = hd(events)
      %{
        id: "file_#{hash_path(path)}",
        type: :file,
        entity_id: path,
        entity_name: Path.basename(path),
        timestamp: first_event.timestamp,
        data: %{
          path: path,
          sha256: get_in(first_event.payload, ["sha256"]),
          operations: Enum.map(events, & &1.event_type) |> Enum.uniq()
        },
        suspicious: is_file_suspicious?(path, events),
        detections: Enum.flat_map(events, &detections_for/1),
        depth: 0
      }
    end)

    edges = file_events
    |> Enum.flat_map(fn event ->
      path = get_in(event.payload, ["path"]) || get_in(event.payload, ["file_path"])
      pid = get_in(event.payload, ["pid"])

      if path && pid && Map.has_key?(process_tree, pid) do
        edge_type = case event.event_type do
          "file_create" -> :wrote
          "file_modify" -> :modified
          "file_delete" -> :deleted
          "file_read" -> :read
          "file_rename" -> :renamed
          _ -> :accessed
        end

        [%{
          id: "edge_file_#{pid}_#{hash_path(path)}_#{event.id}",
          source: "process_#{pid}",
          target: "file_#{hash_path(path)}",
          type: edge_type,
          label: Atom.to_string(edge_type),
          timestamp: event.timestamp,
          data: %{operation: event.event_type}
        }]
      else
        []
      end
    end)
    |> Enum.uniq_by(fn e -> {e.source, e.target, e.type} end)

    {nodes, edges}
  end

  defp build_network_nodes_and_edges(events, process_tree) do
    network_events = Enum.filter(events, &network_event?/1)

    # Group by remote address
    connections_by_remote = network_events
    |> Enum.group_by(fn event ->
      addr = remote_address(event.payload)
      port = remote_port(event.payload)
      "#{addr}:#{port}"
    end)
    |> Map.delete(":")
    |> Map.delete(nil)

    nodes = connections_by_remote
    |> Enum.map(fn {remote, events} ->
      first_event = hd(events)
      addr = remote_address(first_event.payload)
      port = remote_port(first_event.payload)

      %{
        id: "network_#{hash_path(remote)}",
        type: :network,
        entity_id: remote,
        entity_name: "#{addr}:#{port}",
        timestamp: first_event.timestamp,
        data: %{
          remote_addr: addr,
          remote_ip: addr,
          remote_port: port,
          local_ip: payload_value(first_event.payload, ["local_ip", "source_ip", "src_ip"]),
          local_port: payload_value(first_event.payload, ["local_port", "source_port", "src_port"]),
          protocol: payload_value(first_event.payload, ["protocol"]) || "tcp",
          direction: payload_value(first_event.payload, ["direction"]),
          process_name: payload_value(first_event.payload, ["process_name", "name"]),
          domain: payload_value(first_event.payload, ["domain", "sni", "tls_sni"]),
          connection_count: length(events)
        },
        suspicious: is_network_suspicious?(addr, port, events),
        detections: Enum.flat_map(events, &detections_for/1),
        depth: 0
      }
    end)

    edges = network_events
    |> Enum.flat_map(fn event ->
      addr = remote_address(event.payload)
      port = remote_port(event.payload)
      pid = payload_value(event.payload, ["pid", "process_id"])
      remote = "#{addr}:#{port}"

      if addr && pid && Map.has_key?(process_tree, pid) do
        [%{
          id: "edge_network_#{pid}_#{hash_path(remote)}_#{event.id}",
          source: "process_#{pid}",
          target: "network_#{hash_path(remote)}",
          type: :connected,
          label: "connected",
          timestamp: event.timestamp,
          data: %{protocol: payload_value(event.payload, ["protocol"])}
        }]
      else
        []
      end
    end)
    |> Enum.uniq_by(fn e -> {e.source, e.target} end)

    {nodes, edges}
  end

  defp build_dns_nodes_and_edges(events, process_tree) do
    dns_events = Enum.filter(events, &dns_event?/1)

    # Group by domain
    queries_by_domain = dns_events
    |> Enum.group_by(fn event ->
      get_in(event.payload, ["query"]) || get_in(event.payload, ["domain"])
    end)
    |> Map.delete(nil)

    nodes = queries_by_domain
    |> Enum.map(fn {domain, events} ->
      first_event = hd(events)
      resolved_ip = get_in(first_event.payload, ["resolved_ip"]) ||
                    get_in(first_event.payload, ["response"])

      %{
        id: "dns_#{hash_path(domain)}",
        type: :dns,
        entity_id: domain,
        entity_name: domain,
        timestamp: first_event.timestamp,
        data: %{
          domain: domain,
          resolved_ip: resolved_ip,
          query_type: get_in(first_event.payload, ["query_type"]) || "A",
          query_count: length(events)
        },
        suspicious: is_dns_suspicious?(domain, events),
        detections: Enum.flat_map(events, &detections_for/1),
        depth: 0
      }
    end)

    edges = dns_events
    |> Enum.flat_map(fn event ->
      domain = get_in(event.payload, ["query"]) || get_in(event.payload, ["domain"])
      pid = get_in(event.payload, ["pid"])

      if domain && pid && Map.has_key?(process_tree, pid) do
        [%{
          id: "edge_dns_#{pid}_#{hash_path(domain)}_#{event.id}",
          source: "process_#{pid}",
          target: "dns_#{hash_path(domain)}",
          type: :resolved,
          label: "resolved",
          timestamp: event.timestamp,
          data: %{}
        }]
      else
        []
      end
    end)
    |> Enum.uniq_by(fn e -> {e.source, e.target} end)

    {nodes, edges}
  end

  defp build_registry_nodes_and_edges(events, process_tree) do
    registry_events = Enum.filter(events, &registry_event?/1)

    # Group by registry key
    keys_by_path = registry_events
    |> Enum.group_by(fn event ->
      get_in(event.payload, ["key"]) || get_in(event.payload, ["registry_key"])
    end)
    |> Map.delete(nil)

    nodes = keys_by_path
    |> Enum.map(fn {key, events} ->
      first_event = hd(events)

      %{
        id: "registry_#{hash_path(key)}",
        type: :registry,
        entity_id: key,
        entity_name: key |> String.split("\\") |> List.last() || key,
        timestamp: first_event.timestamp,
        data: %{
          key: key,
          value_name: get_in(first_event.payload, ["value_name"]),
          value_data: get_in(first_event.payload, ["value_data"]),
          operations: Enum.map(events, & &1.event_type) |> Enum.uniq()
        },
        suspicious: is_registry_suspicious?(key, events),
        detections: Enum.flat_map(events, &detections_for/1),
        depth: 0
      }
    end)

    edges = registry_events
    |> Enum.flat_map(fn event ->
      key = get_in(event.payload, ["key"]) || get_in(event.payload, ["registry_key"])
      pid = get_in(event.payload, ["pid"])

      if key && pid && Map.has_key?(process_tree, pid) do
        edge_type = case event.event_type do
          "registry_write" -> :modified
          "registry_create" -> :created
          "registry_delete" -> :deleted
          "registry_read" -> :read
          _ -> :accessed
        end

        [%{
          id: "edge_registry_#{pid}_#{hash_path(key)}_#{event.id}",
          source: "process_#{pid}",
          target: "registry_#{hash_path(key)}",
          type: edge_type,
          label: Atom.to_string(edge_type),
          timestamp: event.timestamp,
          data: %{operation: event.event_type}
        }]
      else
        []
      end
    end)
    |> Enum.uniq_by(fn e -> {e.source, e.target, e.type} end)

    {nodes, edges}
  end

  defp mark_suspicious_nodes(nodes, edges) do
    # Build adjacency map for traversal
    adjacency = edges
    |> Enum.reduce(%{}, fn edge, acc ->
      Map.update(acc, edge.source, [edge.target], &[edge.target | &1])
    end)

    # Find nodes that are connected to suspicious nodes
    suspicious_node_ids = nodes
    |> Enum.filter(& &1.suspicious)
    |> Enum.map(& &1.id)
    |> MapSet.new()

    # Propagate suspicion to parent nodes (reverse direction)
    reverse_adjacency = edges
    |> Enum.reduce(%{}, fn edge, acc ->
      Map.update(acc, edge.target, [edge.source], &[edge.source | &1])
    end)

    # Mark nodes that led to suspicious activity
    nodes
    |> Enum.map(fn node ->
      connected_suspicious = Map.get(adjacency, node.id, [])
      |> Enum.any?(&MapSet.member?(suspicious_node_ids, &1))

      leads_to_suspicious = Map.get(reverse_adjacency, node.id, [])
      |> Enum.any?(&MapSet.member?(suspicious_node_ids, &1))

      if connected_suspicious || leads_to_suspicious do
        Map.put(node, :suspicious, true)
      else
        node
      end
    end)
  end

  defp extract_user_context(events) do
    users = events
    |> Enum.map(fn event ->
      get_in(event.payload, ["user"])
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()

    privilege_changes = events
    |> Enum.filter(&(&1.event_type in ["privilege_change", "token_manipulation"]))

    %{
      users: users,
      privilege_changes: length(privilege_changes),
      primary_user: List.first(users)
    }
  end

  # Suspicious detection helpers

  defp is_process_suspicious?(proc) do
    suspicious_processes = [
      "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
      "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
      "msiexec.exe", "wmic.exe", "psexec.exe", "mimikatz.exe"
    ]

    name_lower = String.downcase(proc.name || "")

    # Check for suspicious process names
    has_suspicious_name = Enum.any?(suspicious_processes, fn sp ->
      String.contains?(name_lower, String.downcase(sp))
    end)

    # Check for suspicious command line patterns
    cmdline = String.downcase(proc.cmdline || "")
    has_suspicious_cmdline = String.contains?(cmdline, "-enc") ||
      String.contains?(cmdline, "-encoded") ||
      String.contains?(cmdline, "downloadstring") ||
      String.contains?(cmdline, "invoke-expression") ||
      String.contains?(cmdline, "iex") ||
      String.contains?(cmdline, "hidden") ||
      String.contains?(cmdline, "-nop")

    # Check for detections
    has_detections = length(detections_for(proc)) > 0

    # Check for unsigned elevated process
    unsigned_elevated = proc.is_elevated && !proc.is_signed

    has_suspicious_name || has_suspicious_cmdline || has_detections || unsigned_elevated
  end

  defp is_file_suspicious?(path, events) do
    path_lower = String.downcase(path || "")

    # Suspicious file locations
    suspicious_paths = [
      "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp",
      "\\programdata\\", "\\public\\", "\\downloads\\"
    ]

    # Suspicious file extensions
    suspicious_extensions = [
      ".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js",
      ".hta", ".scr", ".pif", ".com"
    ]

    has_suspicious_path = Enum.any?(suspicious_paths, &String.contains?(path_lower, &1))
    has_suspicious_extension = Enum.any?(suspicious_extensions, &String.ends_with?(path_lower, &1))
    has_detections = events |> Enum.any?(&(length(detections_for(&1)) > 0))

    (has_suspicious_path && has_suspicious_extension) || has_detections
  end

  defp is_network_suspicious?(addr, port, events) do
    # Check for suspicious ports
    suspicious_ports = [4444, 5555, 6666, 8888, 9999, 1337, 31337, 443, 80]
    port_int = parse_port(port)

    # Check for detections
    has_detections = events |> Enum.any?(&(length(detections_for(&1)) > 0))

    # Check for known bad patterns
    is_suspicious_port = port_int in suspicious_ports

    # External IP communication
    is_external = !is_private_ip?(addr)

    (is_suspicious_port && is_external) || has_detections
  end

  defp parse_port(port) when is_integer(port), do: port

  defp parse_port(port) when is_binary(port) do
    case Integer.parse(port) do
      {value, _} -> value
      :error -> nil
    end
  end

  defp parse_port(_), do: nil

  defp is_dns_suspicious?(domain, events) do
    domain_lower = String.downcase(domain || "")

    # Check for DGA-like patterns (high entropy, random-looking)
    has_dga_pattern = String.length(domain_lower) > 20 &&
      Regex.match?(~r/[0-9a-f]{16,}/, domain_lower)

    # Check for suspicious TLDs
    suspicious_tlds = [".ru", ".cn", ".tk", ".ml", ".ga", ".cf", ".top", ".xyz", ".pw"]
    has_suspicious_tld = Enum.any?(suspicious_tlds, &String.ends_with?(domain_lower, &1))

    # Check for detections
    has_detections = events |> Enum.any?(&(length(detections_for(&1)) > 0))

    has_dga_pattern || has_suspicious_tld || has_detections
  end

  defp is_registry_suspicious?(key, events) do
    key_lower = String.downcase(key || "")

    # Suspicious registry locations
    suspicious_keys = [
      "\\run", "\\runonce", "\\policies\\explorer\\run",
      "\\services\\", "\\shell\\open\\command",
      "\\userinit", "\\shell", "\\load",
      "\\image file execution options"
    ]

    has_suspicious_key = Enum.any?(suspicious_keys, &String.contains?(key_lower, &1))
    has_detections = events |> Enum.any?(&(length(detections_for(&1)) > 0))

    has_suspicious_key || has_detections
  end

  defp is_private_ip?(ip) when is_binary(ip) do
    cond do
      String.starts_with?(ip, "10.") -> true
      String.starts_with?(ip, "192.168.") -> true
      String.starts_with?(ip, "172.") ->
        case String.split(ip, ".") |> Enum.at(1) do
          second when is_binary(second) ->
            num = String.to_integer(second)
            num >= 16 && num <= 31
          _ -> false
        end
      String.starts_with?(ip, "127.") -> true
      ip == "localhost" -> true
      true -> false
    end
  end
  defp is_private_ip?(_), do: false

  # Root cause scoring

  defp calculate_root_cause_score(node, all_nodes, edges, _causal_chain) do
    score = 0

    # Earlier timestamp = higher score
    time_score = if node.timestamp do
      all_timestamps = all_nodes
      |> Enum.map(& &1.timestamp)
      |> Enum.map(&normalize_datetime/1)
      |> Enum.reject(&is_nil/1)
      |> Enum.sort_by(&datetime_sort_key/1)

      if length(all_timestamps) > 0 do
        earliest = hd(all_timestamps)
        case normalize_datetime(node.timestamp) do
          %DateTime{} = node_time ->
            diff = DateTime.diff(node_time, earliest, :second)
            max(0, 100 - diff)  # Higher score for earlier events

          _ ->
            0
        end
      else
        0
      end
    else
      0
    end

    # Count outgoing edges (spawned children)
    outgoing_count = edges
    |> Enum.count(&(&1.source == node.id))

    # Count suspicious children
    suspicious_children_count = edges
    |> Enum.filter(&(&1.source == node.id))
    |> Enum.map(& &1.target)
    |> Enum.count(fn target_id ->
      Enum.find(all_nodes, &(&1.id == target_id))
      |> case do
        nil -> false
        child -> child.suspicious
      end
    end)

    # Entry point process bonus
    entry_point_bonus = if is_entry_point_process?(node) do
      50
    else
      0
    end

    # Has detections bonus
    detection_bonus = length(detections_for(node)) * 20

    score + time_score + (outgoing_count * 5) + (suspicious_children_count * 30) +
      entry_point_bonus + detection_bonus
  end

  defp is_entry_point_process?(node) do
    name_lower = String.downcase(node.entity_name || "")

    entry_points = [
      "outlook", "thunderbird", "chrome", "firefox", "edge", "iexplore",
      "msword", "excel", "winword", "powerpnt", "acrobat", "reader"
    ]

    Enum.any?(entry_points, &String.contains?(name_lower, &1))
  end

  defp normalize_score(score) do
    min(score / 500.0, 1.0) |> Float.round(2)
  end

  defp explain_root_cause(node, score) do
    reasons = []

    reasons = if is_entry_point_process?(node) do
      ["Entry point application (email/browser/office)" | reasons]
    else
      reasons
    end

    reasons = if node.suspicious do
      ["Has suspicious characteristics" | reasons]
    else
      reasons
    end

    reasons = if length(detections_for(node)) > 0 do
      ["Has #{length(detections_for(node))} detection(s)" | reasons]
    else
      reasons
    end

    reasons = if score > 200 do
      ["High root cause confidence score" | reasons]
    else
      reasons
    end

    Enum.join(reasons, "; ")
  end

  defp detections_for(item) when is_map(item) do
    payload = Map.get(item, :payload) || Map.get(item, "payload") || %{}

    Map.get(item, :detections) ||
      Map.get(item, "detections") ||
      Map.get(payload, "detections") ||
      Map.get(payload, :detections) ||
      []
  end

  defp detections_for(_), do: []

  defp payload_value(payload, keys) when is_map(payload) and is_list(keys) do
    Enum.find_value(keys, fn key ->
      Map.get(payload, key) || Map.get(payload, to_string(key)) ||
        if(is_atom(key), do: nil, else: Map.get(payload, String.to_atom(key)))
    end)
  rescue
    _ -> nil
  end

  defp payload_value(_, _), do: nil

  defp remote_address(payload) do
    payload_value(payload, [
      "remote_addr",
      "remote_ip",
      "dest_ip",
      "dst_ip",
      "destination_ip",
      "ip"
    ])
  end

  defp remote_port(payload) do
    payload_value(payload, [
      "remote_port",
      "dest_port",
      "dst_port",
      "destination_port",
      "port"
    ])
  end

  defp extract_process_info(event) do
    %{
      pid: payload_value(event.payload, ["pid", "process_id"]),
      name: payload_value(event.payload, ["name", "process_name", "image", "exe"]),
      user: payload_value(event.payload, ["user", "username", "user_name"]),
      is_elevated: payload_value(event.payload, ["is_elevated"]) || false
    }
  end

  defp hash_path(path) when is_binary(path) do
    :crypto.hash(:sha256, path) |> Base.encode16(case: :lower) |> String.slice(0, 12)
  end
  defp hash_path(_), do: "unknown"

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
end
