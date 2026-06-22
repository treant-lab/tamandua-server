defmodule TamanduaServer.Detection.Timeline do
  @moduledoc """
  Attack Timeline/Storyline Engine

  Correlates disparate security events into cohesive attack narratives,
  similar to SentinelOne Storyline and CrowdStrike Process Tree.

  Features:
  - Process ancestry correlation (parent-child chains)
  - Lateral movement tracking across hosts
  - MITRE ATT&CK kill chain phase mapping
  - Automatic incident grouping
  - Timeline visualization data generation

  This is a UNIQUE DIFFERENTIATOR - provides better context than raw alerts.
  """

  import Ecto.Query
  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Alerts.Timestamp
  alias TamanduaServer.Telemetry.Event

  require Logger

  # MITRE ATT&CK Kill Chain phases in order
  @kill_chain_phases [
    "reconnaissance",
    "resource_development",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact"
  ]

  @doc """
  Build an attack timeline for a specific alert, correlating all related events.

  Returns a structured timeline with:
  - Root process (initial compromise point)
  - Process tree with all descendants
  - Related network connections
  - File operations
  - Registry modifications
  - MITRE ATT&CK phase progression
  """
  def build_timeline(alert_id) do
    alert = Repo.get!(Alert, alert_id)

    # Get all events associated with this alert
    events = get_alert_events(alert)

    # Build process ancestry tree
    process_tree = build_process_tree(events)

    # Correlate network events to processes
    network_timeline = correlate_network_events(events, process_tree)

    # Correlate file events to processes
    file_timeline = correlate_file_events(events, process_tree)

    # Build MITRE ATT&CK phase progression
    mitre_progression = build_mitre_progression(events)

    # Calculate attack metrics
    metrics = calculate_attack_metrics(events, process_tree)

    %{
      alert_id: alert_id,
      agent_id: alert.agent_id,
      timestamp_start: get_earliest_timestamp(events),
      timestamp_end: get_latest_timestamp(events),
      process_tree: process_tree,
      network_timeline: network_timeline,
      file_timeline: file_timeline,
      mitre_progression: mitre_progression,
      metrics: metrics,
      summary: generate_attack_summary(events, process_tree, mitre_progression)
    }
  end

  @doc """
  Correlate events across multiple agents to detect lateral movement.
  """
  def detect_lateral_movement(organization_id, time_window_minutes \\ 60) do
    time_threshold = DateTime.utc_now()
    |> DateTime.add(-time_window_minutes * 60, :second)

    # Get all recent authentication and network events
    events = get_lateral_movement_candidates(organization_id, time_threshold)

    # Group by credential/user
    events
    |> Enum.group_by(&extract_user_context/1)
    |> Enum.filter(fn {_user, user_events} ->
      # Multiple hosts in short time = potential lateral movement
      unique_hosts = user_events
      |> Enum.map(& &1.agent_id)
      |> Enum.uniq()
      |> length()

      unique_hosts > 1
    end)
    |> Enum.map(fn {user, user_events} ->
      build_lateral_movement_chain(user, user_events)
    end)
  end

  @doc """
  Build an incident from correlated alerts/events.
  Groups related alerts into a single incident with attack narrative.
  """
  def build_incident(alert_ids) when is_list(alert_ids) do
    alerts = from(a in Alert, where: a.id in ^alert_ids)
    |> Repo.all()

    # Get all events from all alerts
    all_events = Enum.flat_map(alerts, &get_alert_events/1)

    # Build combined process tree
    process_tree = build_process_tree(all_events)

    # Find root cause (initial access point)
    root_cause = find_root_cause(all_events, process_tree)

    # Build attack chain
    attack_chain = build_attack_chain(all_events, process_tree)

    # Calculate severity (highest among alerts)
    severity = calculate_incident_severity(alerts)

    # Generate timeline entries
    timeline_entries = build_timeline_entries(all_events)

    %{
      alert_ids: alert_ids,
      event_count: length(all_events),
      severity: severity,
      root_cause: root_cause,
      attack_chain: attack_chain,
      process_tree: process_tree,
      timeline: timeline_entries,
      mitre_coverage: calculate_mitre_coverage(all_events),
      affected_assets: get_affected_assets(alerts),
      recommended_actions: generate_recommendations(attack_chain)
    }
  end

  @doc """
  Auto-correlate alerts into incidents based on common attributes.
  """
  def auto_correlate_alerts(organization_id, opts \\ []) do
    time_window = Keyword.get(opts, :time_window_minutes, 60)
    min_correlation_score = Keyword.get(opts, :min_score, 0.7)
    limit = opts |> Keyword.get(:limit, 100) |> min(250)

    time_threshold = DateTime.utc_now()
    |> DateTime.add(-time_window * 60, :second)

    # Get recent uncorrelated alerts
    base_query = from(a in Alert,
      where: a.inserted_at >= ^time_threshold
        and a.status == "new",
      order_by: [asc: a.inserted_at],
      limit: ^limit
    )

    # Add organization filter if provided
    alerts = if organization_id do
      from(a in base_query, where: a.organization_id == ^organization_id)
    else
      base_query
    end
    |> Repo.all(timeout: 8_000)

    # Cluster alerts by correlation score
    cluster_alerts(alerts, min_correlation_score)
  rescue
    error in [DBConnection.ConnectionError, Postgrex.Error] ->
      Logger.warning("Timeline auto-correlate alerts failed: #{Exception.message(error)}")
      []
  catch
    :exit, reason ->
      Logger.warning("Timeline auto-correlate alerts failed: exit #{inspect(reason)}")
      []
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp get_alert_events(%Alert{event_ids: event_ids}) when is_list(event_ids) do
    case event_ids do
      [] -> []
      ids ->
        Event
        |> where([e], e.id in ^ids)
        |> order_by([e], asc: e.timestamp)
        |> Repo.all()
        |> Enum.map(fn event ->
          %{
            id: event.id,
            event_type: event.event_type,
            timestamp: event.timestamp,
            payload: event.payload || %{},
            severity: event.severity,
            detections: event_detections(event),
            agent_id: event.agent_id
          }
        end)
    end
  end

  defp build_process_tree(events) do
    # Extract process events
    process_events = events
    |> Enum.filter(&is_process_event/1)
    |> Enum.sort_by(&Timestamp.sort_key(&1.timestamp))

    # Build parent-child map
    process_map = process_events
    |> Enum.reduce(%{}, fn event, acc ->
      payload = event.payload || %{}
      pid = payload_value(payload, ["pid", :pid, "process_id", :process_id])
      ppid = payload_value(payload, ["ppid", :ppid, "parent_pid", :parent_pid])

      name =
        payload_value(payload, [
          "name",
          :name,
          "process_name",
          :process_name,
          "image_name",
          :image_name
        ])

      path =
        payload_value(payload, [
          "path",
          :path,
          "image_path",
          :image_path,
          "process_path",
          :process_path
        ])

      cmdline =
        payload_value(payload, [
          "command_line",
          :command_line,
          "cmdline",
          :cmdline,
          "command",
          :command,
          "process_command_line",
          :process_command_line
        ])

      if pid do
        Map.put(acc, pid, %{
          pid: pid,
          ppid: ppid,
          name: name,
          path: path,
          command_line: cmdline,
          timestamp: event.timestamp,
          detections: event_detections(event),
          children: [],
          events: [event]
        })
      else
        acc
      end
    end)

    # Build tree structure
    build_tree_structure(process_map)
  end

  defp payload_value(payload, keys) when is_map(payload) do
    Enum.find_value(keys, fn key -> Map.get(payload, key) end)
  end

  defp payload_value(_, _), do: nil

  defp build_tree_structure(process_map) do
    # Find root processes (ppid not in map or ppid is 0/1)
    roots = process_map
    |> Enum.filter(fn {_pid, proc} ->
      ppid = proc.ppid
      ppid == nil or ppid == 0 or ppid == 1 or not Map.has_key?(process_map, ppid)
    end)
    |> Enum.map(fn {pid, _} -> pid end)

    # Build tree from each root
    Enum.map(roots, fn root_pid ->
      build_subtree(root_pid, process_map)
    end)
  end

  defp build_subtree(pid, process_map) do
    case Map.get(process_map, pid) do
      nil -> nil
      process ->
        children_pids = process_map
        |> Enum.filter(fn {_p, proc} -> proc.ppid == pid end)
        |> Enum.map(fn {p, _} -> p end)

        children = Enum.map(children_pids, &build_subtree(&1, process_map))
        |> Enum.reject(&is_nil/1)

        Map.put(process, :children, children)
    end
  end

  defp correlate_network_events(events, process_tree) do
    network_events = events
    |> Enum.filter(&is_network_event/1)
    |> Enum.sort_by(&Timestamp.sort_key(&1.timestamp))

    # Get all PIDs from process tree
    all_pids = extract_all_pids(process_tree)

    # Correlate network events to processes
    Enum.map(network_events, fn event ->
      pid = get_in(event, [:payload, "pid"]) || get_in(event, [:payload, :pid])
      remote_ip = get_in(event, [:payload, "remote_ip"]) || get_in(event, [:payload, :remote_ip])
      remote_port = get_in(event, [:payload, "remote_port"]) || get_in(event, [:payload, :remote_port])
      protocol = get_in(event, [:payload, "protocol"]) || get_in(event, [:payload, :protocol])

      %{
        timestamp: event.timestamp,
        pid: pid,
        in_process_tree: pid in all_pids,
        remote_ip: remote_ip,
        remote_port: remote_port,
        protocol: protocol,
        direction: get_in(event, [:payload, "direction"]) || get_in(event, [:payload, :direction]),
        bytes_sent: get_in(event, [:payload, "bytes_sent"]) || get_in(event, [:payload, :bytes_sent]) || 0,
        bytes_received: get_in(event, [:payload, "bytes_received"]) || get_in(event, [:payload, :bytes_received]) || 0,
        process_name: get_in(event, [:payload, "process_name"]) || get_in(event, [:payload, :process_name]),
        local_ip: get_in(event, [:payload, "local_ip"]) || get_in(event, [:payload, :local_ip]),
        local_port: get_in(event, [:payload, "local_port"]) || get_in(event, [:payload, :local_port]),
        detections: event_detections(event)
      }
    end)
  end

  defp correlate_file_events(events, process_tree) do
    file_events = events
    |> Enum.filter(&is_file_event/1)
    |> Enum.sort_by(& &1.timestamp)

    all_pids = extract_all_pids(process_tree)

    Enum.map(file_events, fn event ->
      pid = get_in(event, [:payload, "pid"]) || get_in(event, [:payload, :pid])
      path = get_in(event, [:payload, "path"]) || get_in(event, [:payload, :path])
      operation = get_in(event, [:payload, "operation"]) || get_in(event, [:payload, :operation])

      %{
        timestamp: event.timestamp,
        pid: pid,
        in_process_tree: pid in all_pids,
        path: path,
        operation: operation,
        hash: get_in(event, [:payload, "hash"]),
        detections: event_detections(event)
      }
    end)
  end

  defp build_mitre_progression(events) do
    # Extract all MITRE tactics from events
    tactics = events
    |> Enum.flat_map(fn event ->
      Enum.flat_map(event_detections(event), fn detection ->
        (detection["mitre_tactics"] || detection[:mitre_tactics] || [])
        |> Enum.map(fn tactic ->
          {normalize_tactic(tactic), event.timestamp}
        end)
      end)
    end)
    |> Enum.group_by(fn {tactic, _} -> tactic end, fn {_, ts} -> ts end)
    |> Enum.map(fn {tactic, timestamps} ->
      {tactic, Enum.min_by(timestamps, &Timestamp.sort_key/1)}
    end)
    |> Enum.sort_by(fn {tactic, _} ->
      Enum.find_index(@kill_chain_phases, &(&1 == tactic)) || 999
    end)

    # Build progression with timestamps
    Enum.map(tactics, fn {tactic, first_seen} ->
      %{
        phase: tactic,
        first_seen: first_seen,
        phase_index: Enum.find_index(@kill_chain_phases, &(&1 == tactic)) || -1,
        human_name: humanize_tactic(tactic)
      }
    end)
  end

  defp calculate_attack_metrics(events, process_tree) do
    %{
      total_events: length(events),
      unique_processes: count_unique_processes(events),
      tree_depth: calculate_tree_depth(process_tree),
      duration_seconds: calculate_duration(events),
      network_connections: count_network_events(events),
      file_operations: count_file_events(events),
      detection_count: count_detections(events),
      mitre_techniques_count: count_unique_techniques(events)
    }
  end

  defp generate_attack_summary(events, process_tree, mitre_progression) do
    # Generate natural language summary
    root_process = find_root_process(process_tree)
    phases = Enum.map(mitre_progression, & &1.human_name)

    initial_access = case mitre_progression do
      [first | _] -> first.human_name
      [] -> "Unknown"
    end

    """
    Attack detected starting from #{root_process_name(root_process)}.
    Kill chain progression: #{Enum.join(phases, " → ")}.
    Initial access method: #{initial_access}.
    Total events: #{length(events)}, spanning #{calculate_duration(events)} seconds.
    """
  end

  # ============================================================================
  # Lateral Movement Detection
  # ============================================================================

  defp get_lateral_movement_candidates(organization_id, time_threshold) do
    query = """
    SELECT e.id, e.event_type, e.timestamp, e.payload, e.agent_id
    FROM events e
    JOIN agents a ON e.agent_id = a.id
    WHERE ($1::uuid IS NULL OR a.organization_id = $1)
      AND e.timestamp >= $2
      AND e.event_type IN ('authentication', 'network_connection', 'remote_service')
    ORDER BY e.timestamp ASC
    """

    case Repo.query(query, [organization_id, time_threshold]) do
      {:ok, result} ->
        Enum.map(result.rows, fn [id, event_type, timestamp, payload, agent_id] ->
          %{
            id: id,
            event_type: event_type,
            timestamp: timestamp,
            payload: payload || %{},
            agent_id: agent_id
          }
        end)
      {:error, _} -> []
    end
  end

  defp extract_user_context(event) do
    payload = event.payload
    user = payload["user"] || payload["username"] || payload[:user] || "unknown"
    domain = payload["domain"] || payload[:domain] || ""

    "#{domain}\\#{user}"
  end

  defp build_lateral_movement_chain(user, events) do
    sorted_events = Enum.sort_by(events, &Timestamp.sort_key(&1.timestamp))

    %{
      user: user,
      events: sorted_events,
      hosts: events |> Enum.map(& &1.agent_id) |> Enum.uniq(),
      first_seen: List.first(sorted_events).timestamp,
      last_seen: List.last(sorted_events).timestamp,
      hop_count: events |> Enum.map(& &1.agent_id) |> Enum.uniq() |> length()
    }
  end

  # ============================================================================
  # Incident Building
  # ============================================================================

  defp find_root_cause(events, _process_tree) do
    # Find the earliest event that might be initial access
    events
    |> Enum.filter(fn event ->
      tactics = extract_tactics(event)
      "initial_access" in tactics or "execution" in tactics
    end)
    |> Enum.min_by(&Timestamp.sort_key(&1.timestamp), fn -> nil end)
  end

  defp build_attack_chain(events, _process_tree) do
    events
    |> Enum.sort_by(&Timestamp.sort_key(&1.timestamp))
    |> Enum.map(fn event ->
      %{
        timestamp: event.timestamp,
        event_type: event.event_type,
        summary: summarize_event(event),
        mitre_tactics: extract_tactics(event),
        mitre_techniques: extract_techniques(event),
        severity: event.severity
      }
    end)
  end

  defp calculate_incident_severity(alerts) do
    severity_order = %{"critical" => 4, "high" => 3, "medium" => 2, "low" => 1, "info" => 0}

    alerts
    |> Enum.map(& &1.severity)
    |> Enum.max_by(&Map.get(severity_order, &1, 0), fn -> "medium" end)
  end

  defp build_timeline_entries(events) do
    events
    |> Enum.sort_by(&Timestamp.sort_key(&1.timestamp))
    |> Enum.map(fn event ->
      %{
        timestamp: event.timestamp,
        event_type: event.event_type,
        description: summarize_event(event),
        severity: event.severity,
        icon: event_type_icon(event.event_type),
        details: event.payload
      }
    end)
  end

  defp calculate_mitre_coverage(events) do
    techniques = events
    |> Enum.flat_map(&extract_techniques/1)
    |> Enum.uniq()

    tactics = events
    |> Enum.flat_map(&extract_tactics/1)
    |> Enum.uniq()

    %{
      techniques: techniques,
      technique_count: length(techniques),
      tactics: tactics,
      tactic_count: length(tactics),
      kill_chain_coverage: length(tactics) / length(@kill_chain_phases) * 100
    }
  end

  defp get_affected_assets(alerts) do
    alerts
    |> Enum.map(& &1.agent_id)
    |> Enum.uniq()
  end

  defp generate_recommendations(attack_chain) do
    # Generate recommendations based on detected techniques
    all_techniques = Enum.flat_map(attack_chain, & &1.mitre_techniques)

    recommendations = []

    recommendations = if "T1059" in all_techniques or String.starts_with?(Enum.join(all_techniques), "T1059") do
      ["Block or restrict script interpreters (PowerShell, cmd, bash) on affected systems" | recommendations]
    else
      recommendations
    end

    recommendations = if "T1003" in all_techniques do
      ["Enable Credential Guard and check for credential dumping tools" | recommendations]
    else
      recommendations
    end

    recommendations = if "T1486" in all_techniques do
      ["CRITICAL: Isolate affected systems immediately - Ransomware detected" | recommendations]
    else
      recommendations
    end

    recommendations = if "T1071" in all_techniques do
      ["Block C2 IP addresses and domains at firewall/proxy" | recommendations]
    else
      recommendations
    end

    recommendations ++ [
      "Collect forensic evidence before remediation",
      "Reset credentials for affected users",
      "Review and patch vulnerabilities used for initial access"
    ]
  end

  # ============================================================================
  # Alert Clustering
  # ============================================================================

  defp cluster_alerts(alerts, min_score) do
    # Simple clustering based on correlation score
    alerts
    |> Enum.reduce([], fn alert, clusters ->
      matching_cluster = Enum.find_index(clusters, fn cluster ->
        Enum.any?(cluster, fn existing ->
          correlation_score(alert, existing) >= min_score
        end)
      end)

      case matching_cluster do
        nil -> [[alert] | clusters]
        idx ->
          List.update_at(clusters, idx, &[alert | &1])
      end
    end)
    |> Enum.map(&Enum.reverse/1)
    |> Enum.filter(fn cluster -> length(cluster) > 1 end)
  end

  defp correlation_score(alert1, alert2) do
    scores = [
      agent_score(alert1.agent_id, alert2.agent_id),
      time_score(alert1.inserted_at, alert2.inserted_at),
      technique_score(alert1.mitre_techniques, alert2.mitre_techniques),
      tactic_score(alert1.mitre_tactics, alert2.mitre_tactics)
    ]

    Enum.sum(scores) / length(scores)
  end

  defp agent_score(id1, id2), do: if(id1 == id2, do: 1.0, else: 0.3)

  defp time_score(t1, t2) do
    diff = abs(time_diff_seconds(t1, t2))
    cond do
      diff < 60 -> 1.0
      diff < 300 -> 0.8
      diff < 900 -> 0.6
      diff < 3600 -> 0.4
      true -> 0.1
    end
  end

  defp time_diff_seconds(t1, t2), do: Timestamp.diff(t1, t2, :second) || 0

  defp technique_score(tech1, tech2) do
    common = MapSet.intersection(MapSet.new(tech1 || []), MapSet.new(tech2 || []))
    total = MapSet.union(MapSet.new(tech1 || []), MapSet.new(tech2 || []))

    if MapSet.size(total) == 0, do: 0.5, else: MapSet.size(common) / MapSet.size(total)
  end

  defp tactic_score(tac1, tac2), do: technique_score(tac1, tac2)

  # ============================================================================
  # Helper Functions
  # ============================================================================

  defp is_process_event(event), do: event.event_type in ["process_create", "process_start", "process", "process_terminate"]
  defp is_network_event(event), do: event.event_type in ["network", "network_connection", "network_connect", "network_listen", "network_close", "dns", "dns_query"]
  defp is_file_event(event), do: event.event_type in ["file", "file_create", "file_modify", "file_delete", "file_rename", "file_execute"]

  defp extract_all_pids(process_tree) do
    process_tree
    |> List.wrap()
    |> Enum.flat_map(&extract_pids_from_node/1)
  end

  defp extract_pids_from_node(nil), do: []
  defp extract_pids_from_node(node) do
    [node.pid | Enum.flat_map(node.children || [], &extract_pids_from_node/1)]
  end

  defp normalize_tactic(tactic) do
    tactic
    |> to_string()
    |> String.downcase()
    |> String.replace(" ", "_")
    |> String.replace("-", "_")
  end

  defp humanize_tactic(tactic) do
    tactic
    |> to_string()
    |> String.split("_")
    |> Enum.map(&String.capitalize/1)
    |> Enum.join(" ")
  end

  defp get_earliest_timestamp(events) do
    events
    |> Enum.map(& &1.timestamp)
    |> Enum.min_by(&Timestamp.sort_key/1, fn -> DateTime.utc_now() end)
  end

  defp get_latest_timestamp(events) do
    events
    |> Enum.map(& &1.timestamp)
    |> Enum.max_by(&Timestamp.sort_key(&1, :first), fn -> DateTime.utc_now() end)
  end

  defp count_unique_processes(events) do
    events
    |> Enum.filter(&is_process_event/1)
    |> Enum.map(fn e -> get_in(e, [:payload, "pid"]) || get_in(e, [:payload, :pid]) end)
    |> Enum.uniq()
    |> length()
  end

  defp calculate_tree_depth(tree) do
    tree
    |> List.wrap()
    |> Enum.map(&node_depth/1)
    |> Enum.max(fn -> 0 end)
  end

  defp node_depth(nil), do: 0
  defp node_depth(%{children: children}) do
    1 + (children |> Enum.map(&node_depth/1) |> Enum.max(fn -> 0 end))
  end

  defp calculate_duration(events) do
    case events do
      [] -> 0
      _ ->
        earliest = get_earliest_timestamp(events)
        latest = get_latest_timestamp(events)
        Timestamp.diff(latest, earliest, :second) || 0
    end
  end

  defp count_network_events(events), do: Enum.count(events, &is_network_event/1)
  defp count_file_events(events), do: Enum.count(events, &is_file_event/1)

  defp event_detections(event) when is_map(event) do
    payload = Map.get(event, :payload) || Map.get(event, "payload") || %{}

    Map.get(event, :detections) ||
      Map.get(event, "detections") ||
      Map.get(payload, "detections") ||
      Map.get(payload, :detections) ||
      []
  end

  defp event_detections(_), do: []

  defp count_detections(events) do
    events
    |> Enum.flat_map(&event_detections/1)
    |> length()
  end

  defp count_unique_techniques(events) do
    events
    |> Enum.flat_map(&extract_techniques/1)
    |> Enum.uniq()
    |> length()
  end

  defp extract_tactics(event) do
    event_detections(event)
    |> Enum.flat_map(fn d -> d["mitre_tactics"] || d[:mitre_tactics] || [] end)
    |> Enum.map(&normalize_tactic/1)
  end

  defp extract_techniques(event) do
    event_detections(event)
    |> Enum.flat_map(fn d -> d["mitre_techniques"] || d[:mitre_techniques] || [] end)
  end

  defp find_root_process([root | _]), do: root
  defp find_root_process(_), do: nil

  defp root_process_name(nil), do: "unknown process"
  defp root_process_name(proc), do: proc.name || proc.path || "PID #{proc.pid}"

  defp summarize_event(event) do
    payload = event.payload

    case event.event_type do
      type when type in ["process_create", "process_start", "process"] ->
        name = payload["name"] || payload[:name]
        "Process started: #{name}"

      type when type in ["network", "network_connection"] ->
        ip = payload["remote_ip"] || payload[:remote_ip]
        port = payload["remote_port"] || payload[:remote_port]
        "Network connection to #{ip}:#{port}"

      "dns" ->
        query = payload["query"] || payload[:query]
        "DNS query: #{query}"

      type when type in ["file", "file_create", "file_modify"] ->
        path = payload["path"] || payload[:path]
        op = payload["operation"] || payload[:operation] || "accessed"
        "File #{op}: #{path}"

      "registry" ->
        key = payload["key"] || payload[:key]
        "Registry modified: #{key}"

      _ ->
        "#{event.event_type} event"
    end
  end

  defp event_type_icon(event_type) do
    case event_type do
      type when type in ["process_create", "process_start", "process"] -> "cpu"
      type when type in ["network", "network_connection"] -> "globe"
      "dns" -> "server"
      type when type in ["file", "file_create", "file_modify", "file_delete"] -> "file"
      "registry" -> "settings"
      "honeyfile" -> "alert-triangle"
      _ -> "activity"
    end
  end
end
