defmodule TamanduaServer.Detection.Provenance do
  @moduledoc """
  Provenance Graph Engine for causal analysis.

  Builds directed acyclic graphs (DAGs) showing entity relationships for
  security investigations. Tracks what caused what across processes, files,
  network connections, registry keys, users, and domains.

  The graph answers questions like:
  - "What process downloaded this malicious file?" (backward traversal)
  - "What did this compromised process touch?" (forward traversal)
  - "Does this sequence match a known attack pattern?" (pattern matching)
  - "What is the root cause of this alert?" (blame assignment)

  ## Architecture

  Each agent gets its own ETS-backed provenance graph. Nodes represent
  entities (processes, files, network endpoints, etc.) and edges represent
  causal relationships (created, wrote, executed, etc.) with timestamps
  and confidence scores.

  Graph traversal is done in-memory via ETS for speed. Periodic cleanup
  removes stale data beyond the retention window (default 72 hours).

  ## Node Types

  - `:process` — Running process (keyed by pid:name:start_time)
  - `:file` — File on disk (keyed by path:hash)
  - `:network` — Network endpoint (keyed by ip:port)
  - `:registry` — Registry key (keyed by hive:key)
  - `:user` — User account (keyed by domain:username)
  - `:domain` — DNS domain (keyed by domain name)

  ## Edge Types

  - `:spawned` — Process created child process
  - `:executed` — Process executed a file
  - `:wrote` — Process wrote to a file
  - `:read` — Process read from a file
  - `:deleted` — Process deleted a file
  - `:modified` — Process modified a registry key
  - `:connected_to` — Process connected to network endpoint
  - `:injected_into` — Process injected code into another process
  - `:loaded` — Process loaded a library/module
  - `:created` — Generic creation relationship
  """

  use GenServer
  require Logger

  alias TamanduaServer.Detection.{EventTypes}

  # ---------------------------------------------------------------------------
  # ETS table names
  # ---------------------------------------------------------------------------

  @nodes_table :provenance_nodes
  @edges_table :provenance_edges
  @adjacency_table :provenance_adjacency

  # ---------------------------------------------------------------------------
  # Limits and defaults
  # ---------------------------------------------------------------------------

  @max_nodes_per_agent 100_000
  @default_max_hops 10
  @retention_hours 72
  @cleanup_interval_ms :timer.minutes(10)

  # ---------------------------------------------------------------------------
  # Attack chain pattern definitions
  #
  # Each pattern is a list of edge/node type sequences that, when found in the
  # provenance graph, indicate a known attack technique. Patterns are matched
  # using subgraph walks starting from any node that matches the first step.
  # ---------------------------------------------------------------------------

  @attack_chain_patterns [
    %{
      name: "download_execute_persist",
      description: "File downloaded, executed, then persistence established",
      mitre_techniques: ["T1105", "T1059", "T1547"],
      severity: :critical,
      steps: [
        %{edge_type: :connected_to, target_type: :network},
        %{edge_type: :wrote, target_type: :file},
        %{edge_type: :executed, target_type: :process},
        %{edge_type: :modified, target_type: :registry}
      ]
    },
    %{
      name: "download_execute",
      description: "File downloaded and executed (payload delivery)",
      mitre_techniques: ["T1105", "T1204"],
      severity: :high,
      steps: [
        %{edge_type: :connected_to, target_type: :network},
        %{edge_type: :wrote, target_type: :file},
        %{edge_type: :executed, target_type: :process}
      ]
    },
    %{
      name: "inject_and_connect",
      description: "Process injection followed by network connection (C2 via injected process)",
      mitre_techniques: ["T1055", "T1071"],
      severity: :critical,
      steps: [
        %{edge_type: :injected_into, target_type: :process},
        %{edge_type: :connected_to, target_type: :network}
      ]
    },
    %{
      name: "lateral_movement_chain",
      description: "Process spawns shell, connects to remote host, spawns remote process",
      mitre_techniques: ["T1021", "T1059", "T1570"],
      severity: :critical,
      steps: [
        %{edge_type: :spawned, target_type: :process},
        %{edge_type: :connected_to, target_type: :network},
        %{edge_type: :spawned, target_type: :process}
      ]
    },
    %{
      name: "credential_theft_chain",
      description: "Process reads sensitive files or injects into LSASS",
      mitre_techniques: ["T1003", "T1555"],
      severity: :critical,
      steps: [
        %{edge_type: :spawned, target_type: :process},
        %{edge_type: :injected_into, target_type: :process},
        %{edge_type: :read, target_type: :file}
      ]
    },
    %{
      name: "data_exfiltration",
      description: "File read, compressed/staged, then sent over network",
      mitre_techniques: ["T1560", "T1041"],
      severity: :high,
      steps: [
        %{edge_type: :read, target_type: :file},
        %{edge_type: :wrote, target_type: :file},
        %{edge_type: :connected_to, target_type: :network}
      ]
    },
    %{
      name: "ransomware_chain",
      description: "Process reads files, writes encrypted versions, modifies registry",
      mitre_techniques: ["T1486", "T1490"],
      severity: :critical,
      steps: [
        %{edge_type: :read, target_type: :file},
        %{edge_type: :wrote, target_type: :file},
        %{edge_type: :deleted, target_type: :file}
      ]
    }
  ]

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Record a telemetry event into the provenance graph.

  Extracts entities and causal relationships from the event and adds them
  as nodes and edges in the agent's graph.
  """
  @spec record_event(String.t(), map()) :: :ok
  def record_event(agent_id, event) do
    GenServer.cast(__MODULE__, {:record_event, agent_id, event})
  end

  @doc """
  Walk backward from an entity to find root cause.

  Returns a list of nodes and edges forming the provenance chain from
  the given entity back to the earliest causal ancestor, up to `max_hops`.
  Uses BFS for shortest-path root cause identification.
  """
  @spec get_provenance_chain(String.t(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def get_provenance_chain(agent_id, entity_id, opts \\ []) do
    GenServer.call(__MODULE__, {:get_provenance_chain, agent_id, entity_id, opts})
  end

  @doc """
  Walk forward from an entity to find all affected entities.

  Returns a list of nodes and edges showing everything causally downstream
  of the given entity. Useful for impact assessment after compromise.
  """
  @spec get_impact_graph(String.t(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def get_impact_graph(agent_id, entity_id, opts \\ []) do
    GenServer.call(__MODULE__, {:get_impact_graph, agent_id, entity_id, opts})
  end

  @doc """
  Match known attack patterns against the provenance graph.

  Scans the graph for subgraph patterns matching known attack chains
  (download->execute->persist, inject->C2, etc.). Returns all matches
  with severity and MITRE technique mappings.
  """
  @spec find_attack_chains(String.t(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def find_attack_chains(agent_id, opts \\ []) do
    GenServer.call(__MODULE__, {:find_attack_chains, agent_id, opts}, 30_000)
  end

  @doc """
  Get all related entities within N hops of a given entity.

  Returns the local neighborhood subgraph in both directions (causes and
  effects) for contextual investigation.
  """
  @spec get_entity_context(String.t(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def get_entity_context(agent_id, entity_id, opts \\ []) do
    GenServer.call(__MODULE__, {:get_entity_context, agent_id, entity_id, opts})
  end

  @doc """
  Trace back to root cause with confidence scoring.

  Like `get_provenance_chain/3` but assigns a confidence score to each
  link in the chain based on edge type, temporal proximity, and number
  of corroborating edges.
  """
  @spec blame_assignment(String.t(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def blame_assignment(agent_id, entity_id, opts \\ []) do
    GenServer.call(__MODULE__, {:blame_assignment, agent_id, entity_id, opts})
  end

  @doc """
  Link same entity across endpoints.

  Merges entities that represent the same real-world object seen on different
  agents (e.g., same file hash, same user account, same domain contacted).
  """
  @spec merge_entities(String.t(), String.t(), String.t()) :: :ok
  def merge_entities(agent_id, entity_id_a, entity_id_b) do
    GenServer.cast(__MODULE__, {:merge_entities, agent_id, entity_id_a, entity_id_b})
  end

  @doc """
  Get graph statistics for an agent.
  """
  @spec get_stats(String.t()) :: {:ok, map()} | {:error, term()}
  def get_stats(agent_id) do
    GenServer.call(__MODULE__, {:get_stats, agent_id})
  end

  # ---------------------------------------------------------------------------
  # Server callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(_opts) do
    :ets.new(@nodes_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@edges_table, [:named_table, :bag, :public, read_concurrency: true])
    :ets.new(@adjacency_table, [:named_table, :bag, :public, read_concurrency: true])

    schedule_cleanup()

    Logger.info("Provenance Graph Engine started")
    {:ok, %{event_count: 0}}
  end

  @impl true
  def handle_cast({:record_event, agent_id, event}, state) do
    do_record_event(agent_id, event)
    {:noreply, %{state | event_count: state.event_count + 1}}
  end

  @impl true
  def handle_cast({:merge_entities, agent_id, entity_id_a, entity_id_b}, state) do
    do_merge_entities(agent_id, entity_id_a, entity_id_b)
    {:noreply, state}
  end

  @impl true
  def handle_call({:get_provenance_chain, agent_id, entity_id, opts}, _from, state) do
    result = do_get_provenance_chain(agent_id, entity_id, opts)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_impact_graph, agent_id, entity_id, opts}, _from, state) do
    result = do_get_impact_graph(agent_id, entity_id, opts)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:find_attack_chains, agent_id, opts}, _from, state) do
    result = do_find_attack_chains(agent_id, opts)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_entity_context, agent_id, entity_id, opts}, _from, state) do
    result = do_get_entity_context(agent_id, entity_id, opts)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:blame_assignment, agent_id, entity_id, opts}, _from, state) do
    result = do_blame_assignment(agent_id, entity_id, opts)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_stats, agent_id}, _from, state) do
    result = do_get_stats(agent_id)
    {:reply, result, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    do_cleanup()
    schedule_cleanup()
    {:noreply, state}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ---------------------------------------------------------------------------
  # Event recording — entity and relationship extraction
  # ---------------------------------------------------------------------------

  defp do_record_event(agent_id, event) do
    event_type = EventTypes.normalize(event[:event_type] || event["event_type"])
    payload = event[:payload] || event["payload"] || %{}
    timestamp = event[:timestamp] || event["timestamp"] || DateTime.utc_now()
    event_id = event[:event_id] || event["event_id"]

    # Check node limit before adding
    if node_count_for_agent(agent_id) >= @max_nodes_per_agent do
      Logger.warning("Provenance: Node limit reached for agent #{agent_id}, skipping event")
      :limit_reached
    else
      case event_type do
        :process_create -> record_process_create(agent_id, payload, timestamp, event_id)
        :process_terminate -> record_process_terminate(agent_id, payload, timestamp, event_id)
        :process_inject -> record_process_inject(agent_id, payload, timestamp, event_id)
        :file_create -> record_file_write(agent_id, payload, timestamp, event_id)
        :file_modify -> record_file_write(agent_id, payload, timestamp, event_id)
        :file_delete -> record_file_delete(agent_id, payload, timestamp, event_id)
        :file_execute -> record_file_execute(agent_id, payload, timestamp, event_id)
        :network_connect -> record_network_connect(agent_id, payload, timestamp, event_id)
        :registry_set -> record_registry_modify(agent_id, payload, timestamp, event_id)
        :dns_query -> record_dns_query(agent_id, payload, timestamp, event_id)
        :authentication -> record_authentication(agent_id, payload, timestamp, event_id)
        :logon -> record_authentication(agent_id, payload, timestamp, event_id)
        :login -> record_authentication(agent_id, payload, timestamp, event_id)
        _ -> :ignored
      end
    end
  end

  defp record_process_create(agent_id, payload, timestamp, event_id) do
    pid = payload[:pid] || payload["pid"]
    ppid = payload[:ppid] || payload["ppid"]
    name = payload[:name] || payload["name"] || ""
    path = payload[:path] || payload["path"] || ""
    start_time = payload[:start_time] || payload["start_time"]
    user = payload[:user] || payload["user"]
    sha256 = payload[:sha256] || payload["sha256"]
    cmdline = payload[:cmdline] || payload["cmdline"]

    # Create process node
    process_id = make_entity_id(:process, %{pid: pid, name: name, start_time: start_time})
    upsert_node(agent_id, process_id, :process, %{
      pid: pid,
      ppid: ppid,
      name: name,
      path: path,
      cmdline: cmdline,
      user: user,
      sha256: sha256,
      start_time: start_time
    }, timestamp)

    # Create parent -> child edge if parent exists
    if ppid && ppid > 0 do
      parent_id = find_process_by_pid(agent_id, ppid)

      if parent_id do
        add_edge(agent_id, parent_id, process_id, :spawned, timestamp, event_id, 1.0)
      end
    end

    # Create user node and link
    if user do
      user_id = make_entity_id(:user, %{user: user})
      upsert_node(agent_id, user_id, :user, %{username: user}, timestamp)
      add_edge(agent_id, user_id, process_id, :created, timestamp, event_id, 0.9)
    end

    # Create file node for the executable
    if path != "" do
      file_id = make_entity_id(:file, %{path: path, sha256: sha256})
      upsert_node(agent_id, file_id, :file, %{path: path, sha256: sha256}, timestamp)
      add_edge(agent_id, process_id, file_id, :executed, timestamp, event_id, 1.0)
    end

    :ok
  end

  defp record_process_terminate(agent_id, payload, timestamp, _event_id) do
    pid = payload[:pid] || payload["pid"]
    name = payload[:name] || payload["name"] || ""
    start_time = payload[:start_time] || payload["start_time"]

    process_id = make_entity_id(:process, %{pid: pid, name: name, start_time: start_time})
    update_node_last_seen(agent_id, process_id, timestamp)

    :ok
  end

  defp record_process_inject(agent_id, payload, timestamp, event_id) do
    source_pid = payload[:pid] || payload["pid"] || payload[:source_pid] || payload["source_pid"]
    target_pid = payload[:target_pid] || payload["target_pid"]

    source_id = find_process_by_pid(agent_id, source_pid)
    target_id = find_process_by_pid(agent_id, target_pid)

    if source_id && target_id do
      add_edge(agent_id, source_id, target_id, :injected_into, timestamp, event_id, 1.0)
    end

    :ok
  end

  defp record_file_write(agent_id, payload, timestamp, event_id) do
    pid = payload[:pid] || payload["pid"]
    path = payload[:path] || payload["path"] || ""
    sha256 = payload[:sha256] || payload["sha256"]

    if path != "" do
      file_id = make_entity_id(:file, %{path: path, sha256: sha256})
      upsert_node(agent_id, file_id, :file, %{path: path, sha256: sha256}, timestamp)

      process_id = find_process_by_pid(agent_id, pid)

      if process_id do
        add_edge(agent_id, process_id, file_id, :wrote, timestamp, event_id, 1.0)
      end
    end

    :ok
  end

  defp record_file_delete(agent_id, payload, timestamp, event_id) do
    pid = payload[:pid] || payload["pid"]
    path = payload[:path] || payload["path"] || ""

    if path != "" do
      file_id = make_entity_id(:file, %{path: path, sha256: nil})
      upsert_node(agent_id, file_id, :file, %{path: path}, timestamp)

      process_id = find_process_by_pid(agent_id, pid)

      if process_id do
        add_edge(agent_id, process_id, file_id, :deleted, timestamp, event_id, 1.0)
      end
    end

    :ok
  end

  defp record_file_execute(agent_id, payload, timestamp, event_id) do
    pid = payload[:pid] || payload["pid"]
    path = payload[:path] || payload["path"] || ""
    sha256 = payload[:sha256] || payload["sha256"]

    if path != "" do
      file_id = make_entity_id(:file, %{path: path, sha256: sha256})
      upsert_node(agent_id, file_id, :file, %{path: path, sha256: sha256}, timestamp)

      process_id = find_process_by_pid(agent_id, pid)

      if process_id do
        add_edge(agent_id, process_id, file_id, :executed, timestamp, event_id, 1.0)
      end
    end

    :ok
  end

  defp record_network_connect(agent_id, payload, timestamp, event_id) do
    pid = payload[:pid] || payload["pid"]
    remote_ip = payload[:remote_ip] || payload["remote_ip"]
    remote_port = payload[:remote_port] || payload["remote_port"]
    domain = payload[:domain] || payload["domain"]

    if remote_ip do
      network_id = make_entity_id(:network, %{ip: remote_ip, port: remote_port})
      upsert_node(agent_id, network_id, :network, %{
        ip: remote_ip,
        port: remote_port,
        protocol: payload[:protocol] || payload["protocol"]
      }, timestamp)

      process_id = find_process_by_pid(agent_id, pid)

      if process_id do
        add_edge(agent_id, process_id, network_id, :connected_to, timestamp, event_id, 1.0)
      end

      # Link domain if present
      if domain do
        domain_id = make_entity_id(:domain, %{domain: domain})
        upsert_node(agent_id, domain_id, :domain, %{domain: domain}, timestamp)
        add_edge(agent_id, network_id, domain_id, :connected_to, timestamp, event_id, 0.9)
      end
    end

    :ok
  end

  defp record_registry_modify(agent_id, payload, timestamp, event_id) do
    pid = payload[:pid] || payload["pid"]
    key = payload[:key] || payload["key"] || ""
    value = payload[:value] || payload["value"]
    hive = payload[:hive] || payload["hive"] || ""

    if key != "" do
      reg_id = make_entity_id(:registry, %{hive: hive, key: key})
      upsert_node(agent_id, reg_id, :registry, %{
        hive: hive,
        key: key,
        value: value
      }, timestamp)

      process_id = find_process_by_pid(agent_id, pid)

      if process_id do
        add_edge(agent_id, process_id, reg_id, :modified, timestamp, event_id, 1.0)
      end
    end

    :ok
  end

  defp record_dns_query(agent_id, payload, timestamp, event_id) do
    pid = payload[:pid] || payload["pid"]
    query = payload[:query] || payload["query"] || payload[:domain] || payload["domain"]

    if query do
      domain_id = make_entity_id(:domain, %{domain: query})
      upsert_node(agent_id, domain_id, :domain, %{
        domain: query,
        query_type: payload[:query_type] || payload["query_type"],
        response: payload[:response] || payload["response"]
      }, timestamp)

      process_id = find_process_by_pid(agent_id, pid)

      if process_id do
        add_edge(agent_id, process_id, domain_id, :connected_to, timestamp, event_id, 0.8)
      end
    end

    :ok
  end

  defp record_authentication(agent_id, payload, timestamp, event_id) do
    user = payload[:user] || payload["user"] || payload[:username] || payload["username"]
    pid = payload[:pid] || payload["pid"]

    if user do
      user_id = make_entity_id(:user, %{user: user})
      upsert_node(agent_id, user_id, :user, %{
        username: user,
        domain: payload[:domain] || payload["domain"],
        logon_type: payload[:logon_type] || payload["logon_type"]
      }, timestamp)

      process_id = find_process_by_pid(agent_id, pid)

      if process_id do
        add_edge(agent_id, user_id, process_id, :created, timestamp, event_id, 0.7)
      end
    end

    :ok
  end

  # ---------------------------------------------------------------------------
  # Graph storage primitives
  # ---------------------------------------------------------------------------

  defp upsert_node(agent_id, entity_id, entity_type, attributes, timestamp) do
    key = {agent_id, entity_id}

    case :ets.lookup(@nodes_table, key) do
      [{^key, existing}] ->
        # Update last_seen and merge attributes
        merged_attrs = Map.merge(existing.attributes, attributes, fn _k, v1, v2 ->
          if v2 == nil, do: v1, else: v2
        end)

        updated = %{existing |
          attributes: merged_attrs,
          last_seen: timestamp
        }

        :ets.insert(@nodes_table, {key, updated})

      [] ->
        node = %{
          entity_type: entity_type,
          entity_id: entity_id,
          attributes: attributes,
          first_seen: timestamp,
          last_seen: timestamp
        }

        :ets.insert(@nodes_table, {key, node})
    end
  end

  defp update_node_last_seen(agent_id, entity_id, timestamp) do
    key = {agent_id, entity_id}

    case :ets.lookup(@nodes_table, key) do
      [{^key, existing}] ->
        :ets.insert(@nodes_table, {key, %{existing | last_seen: timestamp}})

      [] ->
        :ok
    end
  end

  defp add_edge(agent_id, source_id, target_id, edge_type, timestamp, event_id, confidence) do
    edge = %{
      source_node_id: source_id,
      target_node_id: target_id,
      edge_type: edge_type,
      timestamp: timestamp,
      event_id: event_id,
      confidence: confidence
    }

    # Store edge keyed by agent_id for retrieval
    :ets.insert(@edges_table, {{agent_id, source_id, target_id, edge_type}, edge})

    # Store forward adjacency: source -> target
    :ets.insert(@adjacency_table, {{agent_id, :forward, source_id}, {target_id, edge_type, timestamp, confidence}})

    # Store reverse adjacency: target -> source
    :ets.insert(@adjacency_table, {{agent_id, :reverse, target_id}, {source_id, edge_type, timestamp, confidence}})
  end

  defp get_node(agent_id, entity_id) do
    key = {agent_id, entity_id}

    case :ets.lookup(@nodes_table, key) do
      [{^key, node}] -> node
      [] -> nil
    end
  end

  defp get_forward_neighbors(agent_id, entity_id) do
    :ets.lookup(@adjacency_table, {agent_id, :forward, entity_id})
    |> Enum.map(fn {_key, {target_id, edge_type, timestamp, confidence}} ->
      %{target_id: target_id, edge_type: edge_type, timestamp: timestamp, confidence: confidence}
    end)
  end

  defp get_reverse_neighbors(agent_id, entity_id) do
    :ets.lookup(@adjacency_table, {agent_id, :reverse, entity_id})
    |> Enum.map(fn {_key, {source_id, edge_type, timestamp, confidence}} ->
      %{source_id: source_id, edge_type: edge_type, timestamp: timestamp, confidence: confidence}
    end)
  end

  # ---------------------------------------------------------------------------
  # Entity ID generation
  # ---------------------------------------------------------------------------

  defp make_entity_id(:process, %{pid: pid, name: name, start_time: start_time}) do
    "proc:#{pid}:#{name || ""}:#{start_time || ""}"
  end

  defp make_entity_id(:file, %{path: path, sha256: sha256}) do
    hash_part = if sha256, do: sha256, else: "nohash"
    "file:#{path}:#{hash_part}"
  end

  defp make_entity_id(:network, %{ip: ip, port: port}) do
    "net:#{ip}:#{port || "any"}"
  end

  defp make_entity_id(:registry, %{hive: hive, key: key}) do
    "reg:#{hive}:#{key}"
  end

  defp make_entity_id(:user, %{user: user}) do
    "user:#{user}"
  end

  defp make_entity_id(:domain, %{domain: domain}) do
    "domain:#{domain}"
  end

  # ---------------------------------------------------------------------------
  # Process PID lookup helper
  #
  # Finds the most recently created process entity matching a given PID.
  # Since process entity IDs include start_time, we scan the nodes table
  # for a process with a matching PID attribute.
  # ---------------------------------------------------------------------------

  defp find_process_by_pid(_agent_id, nil), do: nil
  defp find_process_by_pid(_agent_id, 0), do: nil

  defp find_process_by_pid(agent_id, pid) do
    # Scan for process nodes with matching PID
    # This is bounded by the max_nodes_per_agent limit
    :ets.tab2list(@nodes_table)
    |> Enum.filter(fn {{a_id, entity_id}, node} ->
      a_id == agent_id &&
        node.entity_type == :process &&
        String.starts_with?(entity_id, "proc:#{pid}:")
    end)
    |> Enum.sort_by(fn {_key, node} -> node.last_seen end, {:desc, DateTime})
    |> case do
      [{_key, node} | _] -> node.entity_id
      [] -> nil
    end
  end

  # ---------------------------------------------------------------------------
  # Graph traversal — backward (provenance chain / root cause)
  # ---------------------------------------------------------------------------

  defp do_get_provenance_chain(agent_id, entity_id, opts) do
    max_hops = Keyword.get(opts, :max_hops, @default_max_hops)

    case get_node(agent_id, entity_id) do
      nil ->
        {:error, :entity_not_found}

      start_node ->
        {visited_nodes, visited_edges} = bfs_backward(agent_id, entity_id, max_hops)

        nodes = Enum.map(visited_nodes, fn nid ->
          node = get_node(agent_id, nid)
          if node, do: Map.put(node, :id, nid), else: nil
        end)
        |> Enum.reject(&is_nil/1)

        {:ok, %{
          entity_id: entity_id,
          entity: start_node,
          nodes: nodes,
          edges: visited_edges,
          node_count: length(nodes),
          edge_count: length(visited_edges),
          max_depth: max_hops
        }}
    end
  end

  defp bfs_backward(agent_id, start_id, max_hops) do
    do_bfs(agent_id, [start_id], MapSet.new([start_id]), [], 0, max_hops, :reverse)
  end

  # ---------------------------------------------------------------------------
  # Graph traversal — forward (impact graph)
  # ---------------------------------------------------------------------------

  defp do_get_impact_graph(agent_id, entity_id, opts) do
    max_hops = Keyword.get(opts, :max_hops, @default_max_hops)

    case get_node(agent_id, entity_id) do
      nil ->
        {:error, :entity_not_found}

      start_node ->
        {visited_nodes, visited_edges} = bfs_forward(agent_id, entity_id, max_hops)

        nodes = Enum.map(visited_nodes, fn nid ->
          node = get_node(agent_id, nid)
          if node, do: Map.put(node, :id, nid), else: nil
        end)
        |> Enum.reject(&is_nil/1)

        {:ok, %{
          entity_id: entity_id,
          entity: start_node,
          nodes: nodes,
          edges: visited_edges,
          node_count: length(nodes),
          edge_count: length(visited_edges),
          max_depth: max_hops
        }}
    end
  end

  defp bfs_forward(agent_id, start_id, max_hops) do
    do_bfs(agent_id, [start_id], MapSet.new([start_id]), [], 0, max_hops, :forward)
  end

  # ---------------------------------------------------------------------------
  # Shared BFS implementation
  # ---------------------------------------------------------------------------

  defp do_bfs(_agent_id, [], visited, edges, _depth, _max_hops, _direction) do
    {MapSet.to_list(visited), edges}
  end

  defp do_bfs(_agent_id, _queue, visited, edges, depth, max_hops, _direction) when depth >= max_hops do
    {MapSet.to_list(visited), edges}
  end

  defp do_bfs(agent_id, queue, visited, edges, depth, max_hops, direction) do
    {next_queue, new_visited, new_edges} =
      Enum.reduce(queue, {[], visited, edges}, fn node_id, {q_acc, v_acc, e_acc} ->
        neighbors = case direction do
          :forward -> get_forward_neighbors(agent_id, node_id)
          :reverse -> get_reverse_neighbors(agent_id, node_id)
        end

        Enum.reduce(neighbors, {q_acc, v_acc, e_acc}, fn neighbor, {q, v, e} ->
          neighbor_id = case direction do
            :forward -> neighbor.target_id
            :reverse -> neighbor.source_id
          end

          edge = case direction do
            :forward ->
              %{source: node_id, target: neighbor_id, edge_type: neighbor.edge_type,
                timestamp: neighbor.timestamp, confidence: neighbor.confidence}
            :reverse ->
              %{source: neighbor_id, target: node_id, edge_type: neighbor.edge_type,
                timestamp: neighbor.timestamp, confidence: neighbor.confidence}
          end

          if MapSet.member?(v, neighbor_id) do
            # Already visited, but still add the edge for completeness
            {q, v, [edge | e]}
          else
            {[neighbor_id | q], MapSet.put(v, neighbor_id), [edge | e]}
          end
        end)
      end)

    do_bfs(agent_id, next_queue, new_visited, new_edges, depth + 1, max_hops, direction)
  end

  # ---------------------------------------------------------------------------
  # Entity context (bidirectional N-hop neighborhood)
  # ---------------------------------------------------------------------------

  defp do_get_entity_context(agent_id, entity_id, opts) do
    max_hops = Keyword.get(opts, :max_hops, 3)

    case get_node(agent_id, entity_id) do
      nil ->
        {:error, :entity_not_found}

      start_node ->
        # Walk both directions
        {backward_nodes, backward_edges} = bfs_backward(agent_id, entity_id, max_hops)
        {forward_nodes, forward_edges} = bfs_forward(agent_id, entity_id, max_hops)

        # Merge and deduplicate
        all_node_ids = Enum.uniq(backward_nodes ++ forward_nodes)
        all_edges = Enum.uniq_by(backward_edges ++ forward_edges, fn e ->
          {e.source, e.target, e.edge_type}
        end)

        nodes = Enum.map(all_node_ids, fn nid ->
          node = get_node(agent_id, nid)
          if node, do: Map.put(node, :id, nid), else: nil
        end)
        |> Enum.reject(&is_nil/1)

        {:ok, %{
          entity_id: entity_id,
          entity: start_node,
          nodes: nodes,
          edges: all_edges,
          node_count: length(nodes),
          edge_count: length(all_edges),
          max_hops: max_hops
        }}
    end
  end

  # ---------------------------------------------------------------------------
  # Attack chain pattern matching
  # ---------------------------------------------------------------------------

  defp do_find_attack_chains(agent_id, _opts) do
    # Get all process nodes as potential starting points
    process_nodes = get_nodes_by_type(agent_id, :process)

    matches =
      Enum.flat_map(@attack_chain_patterns, fn pattern ->
        Enum.flat_map(process_nodes, fn {node_id, _node} ->
          match_pattern_from_node(agent_id, node_id, pattern.steps, [node_id])
          |> Enum.map(fn chain_path ->
            %{
              pattern_name: pattern.name,
              description: pattern.description,
              mitre_techniques: pattern.mitre_techniques,
              severity: pattern.severity,
              chain_path: chain_path,
              chain_length: length(chain_path),
              start_entity: node_id,
              nodes: Enum.map(chain_path, fn nid ->
                node = get_node(agent_id, nid)
                if node, do: Map.put(node, :id, nid), else: nil
              end) |> Enum.reject(&is_nil/1)
            }
          end)
        end)
      end)
      # Deduplicate by start entity + pattern name
      |> Enum.uniq_by(fn m -> {m.start_entity, m.pattern_name} end)

    {:ok, matches}
  end

  defp match_pattern_from_node(_agent_id, _current_id, [], path) do
    # All steps matched — return the successful path
    [Enum.reverse(path)]
  end

  defp match_pattern_from_node(agent_id, current_id, [step | remaining_steps], path) do
    required_edge = step.edge_type
    required_target_type = step.target_type

    # Find forward neighbors matching the required edge type
    neighbors = get_forward_neighbors(agent_id, current_id)

    matching_neighbors =
      Enum.filter(neighbors, fn neighbor ->
        neighbor.edge_type == required_edge &&
          node_matches_type?(agent_id, neighbor.target_id, required_target_type) &&
          neighbor.target_id not in path  # prevent cycles
      end)

    # Recurse for each matching neighbor
    Enum.flat_map(matching_neighbors, fn neighbor ->
      match_pattern_from_node(
        agent_id,
        neighbor.target_id,
        remaining_steps,
        [neighbor.target_id | path]
      )
    end)
  end

  defp node_matches_type?(agent_id, entity_id, expected_type) do
    case get_node(agent_id, entity_id) do
      nil -> false
      node -> node.entity_type == expected_type
    end
  end

  # ---------------------------------------------------------------------------
  # Blame assignment — backward walk with confidence decay
  # ---------------------------------------------------------------------------

  defp do_blame_assignment(agent_id, entity_id, opts) do
    max_hops = Keyword.get(opts, :max_hops, @default_max_hops)

    case get_node(agent_id, entity_id) do
      nil ->
        {:error, :entity_not_found}

      start_node ->
        blame_chain = walk_blame_chain(agent_id, entity_id, max_hops, 1.0, MapSet.new([entity_id]), [])

        # Sort by cumulative confidence (most likely root cause first)
        sorted_chain = Enum.sort_by(blame_chain, fn entry -> entry.cumulative_confidence end, :desc)

        # Identify root cause: the first node in the chain with no further predecessors
        # or the node with highest cumulative confidence that is a root
        root_cause = sorted_chain
        |> Enum.filter(fn entry ->
          get_reverse_neighbors(agent_id, entry.entity_id) == []
        end)
        |> List.first()

        {:ok, %{
          entity_id: entity_id,
          entity: start_node,
          blame_chain: sorted_chain,
          root_cause: root_cause,
          chain_length: length(sorted_chain),
          max_depth: max_hops
        }}
    end
  end

  defp walk_blame_chain(_agent_id, _entity_id, 0, _confidence, _visited, acc), do: acc

  defp walk_blame_chain(agent_id, entity_id, remaining_hops, cumulative_confidence, visited, acc) do
    predecessors = get_reverse_neighbors(agent_id, entity_id)

    if predecessors == [] do
      # This is a root — add it with current confidence
      node = get_node(agent_id, entity_id)
      entry = %{
        entity_id: entity_id,
        entity: node,
        cumulative_confidence: cumulative_confidence,
        is_root: true,
        depth: @default_max_hops - remaining_hops
      }

      [entry | acc]
    else
      # Walk each predecessor with decayed confidence
      Enum.reduce(predecessors, acc, fn pred, acc_inner ->
        source_id = pred.source_id

        if MapSet.member?(visited, source_id) do
          acc_inner
        else
          # Confidence decays multiplicatively along the chain
          edge_confidence = pred.confidence || 1.0
          new_confidence = cumulative_confidence * edge_confidence * 0.95

          node = get_node(agent_id, source_id)
          entry = %{
            entity_id: source_id,
            entity: node,
            cumulative_confidence: new_confidence,
            edge_type: pred.edge_type,
            is_root: false,
            depth: @default_max_hops - remaining_hops
          }

          new_visited = MapSet.put(visited, source_id)

          walk_blame_chain(
            agent_id,
            source_id,
            remaining_hops - 1,
            new_confidence,
            new_visited,
            [entry | acc_inner]
          )
        end
      end)
    end
  end

  # ---------------------------------------------------------------------------
  # Entity merging
  # ---------------------------------------------------------------------------

  defp do_merge_entities(agent_id, entity_id_a, entity_id_b) do
    node_a = get_node(agent_id, entity_id_a)
    node_b = get_node(agent_id, entity_id_b)

    if node_a && node_b do
      # Merge B into A: move all edges from B to point to A
      # Forward edges from B
      forward_b = get_forward_neighbors(agent_id, entity_id_b)
      Enum.each(forward_b, fn neighbor ->
        add_edge(agent_id, entity_id_a, neighbor.target_id, neighbor.edge_type,
                 neighbor.timestamp, nil, neighbor.confidence)
      end)

      # Reverse edges to B
      reverse_b = get_reverse_neighbors(agent_id, entity_id_b)
      Enum.each(reverse_b, fn neighbor ->
        add_edge(agent_id, neighbor.source_id, entity_id_a, neighbor.edge_type,
                 neighbor.timestamp, nil, neighbor.confidence)
      end)

      # Merge attributes into A
      merged_attrs = Map.merge(node_a.attributes, node_b.attributes, fn _k, v1, v2 ->
        if v2 == nil, do: v1, else: v2
      end)

      earliest = min_timestamp(node_a.first_seen, node_b.first_seen)
      latest = max_timestamp(node_a.last_seen, node_b.last_seen)

      :ets.insert(@nodes_table, {{agent_id, entity_id_a}, %{node_a |
        attributes: merged_attrs,
        first_seen: earliest,
        last_seen: latest
      }})

      # Remove node B
      :ets.delete(@nodes_table, {agent_id, entity_id_b})

      Logger.debug("Provenance: Merged entity #{entity_id_b} into #{entity_id_a} for agent #{agent_id}")
    end
  end

  # ---------------------------------------------------------------------------
  # Statistics
  # ---------------------------------------------------------------------------

  defp do_get_stats(agent_id) do
    nodes = get_all_nodes_for_agent(agent_id)
    edges = get_all_edges_for_agent(agent_id)

    # Count by type
    node_type_counts = nodes
    |> Enum.map(fn {_key, node} -> node.entity_type end)
    |> Enum.frequencies()

    edge_type_counts = edges
    |> Enum.map(fn {_key, edge} -> edge.edge_type end)
    |> Enum.frequencies()

    # Find connected components using union-find
    component_count = count_connected_components(agent_id, nodes)

    {:ok, %{
      agent_id: agent_id,
      node_count: length(nodes),
      edge_count: length(edges),
      connected_components: component_count,
      nodes_by_type: node_type_counts,
      edges_by_type: edge_type_counts,
      computed_at: DateTime.utc_now()
    }}
  end

  defp count_connected_components(agent_id, nodes) do
    node_ids = Enum.map(nodes, fn {{_a, nid}, _node} -> nid end)

    # Simple BFS-based component counting
    {_visited, count} =
      Enum.reduce(node_ids, {MapSet.new(), 0}, fn nid, {visited, count} ->
        if MapSet.member?(visited, nid) do
          {visited, count}
        else
          # BFS from this node in both directions
          component_nodes = bfs_both_directions(agent_id, nid)
          new_visited = Enum.reduce(component_nodes, visited, &MapSet.put(&2, &1))
          {new_visited, count + 1}
        end
      end)

    count
  end

  defp bfs_both_directions(agent_id, start_id) do
    do_bfs_both(agent_id, [start_id], MapSet.new([start_id]))
    |> MapSet.to_list()
  end

  defp do_bfs_both(_agent_id, [], visited), do: visited

  defp do_bfs_both(agent_id, queue, visited) do
    next_queue =
      Enum.flat_map(queue, fn nid ->
        forward = get_forward_neighbors(agent_id, nid) |> Enum.map(& &1.target_id)
        reverse = get_reverse_neighbors(agent_id, nid) |> Enum.map(& &1.source_id)
        (forward ++ reverse) |> Enum.reject(&MapSet.member?(visited, &1))
      end)
      |> Enum.uniq()

    new_visited = Enum.reduce(next_queue, visited, &MapSet.put(&2, &1))
    do_bfs_both(agent_id, next_queue, new_visited)
  end

  # ---------------------------------------------------------------------------
  # Helper: get all nodes/edges for an agent
  # ---------------------------------------------------------------------------

  defp get_all_nodes_for_agent(agent_id) do
    :ets.tab2list(@nodes_table)
    |> Enum.filter(fn {{a_id, _entity_id}, _node} -> a_id == agent_id end)
  end

  defp get_all_edges_for_agent(agent_id) do
    :ets.tab2list(@edges_table)
    |> Enum.filter(fn {{a_id, _src, _tgt, _type}, _edge} -> a_id == agent_id end)
  end

  defp get_nodes_by_type(agent_id, entity_type) do
    :ets.tab2list(@nodes_table)
    |> Enum.filter(fn {{a_id, _entity_id}, node} ->
      a_id == agent_id && node.entity_type == entity_type
    end)
    |> Enum.map(fn {{_a_id, entity_id}, node} -> {entity_id, node} end)
  end

  defp node_count_for_agent(agent_id) do
    :ets.tab2list(@nodes_table)
    |> Enum.count(fn {{a_id, _entity_id}, _node} -> a_id == agent_id end)
  end

  # ---------------------------------------------------------------------------
  # Cleanup — remove nodes/edges older than retention window
  # ---------------------------------------------------------------------------

  defp do_cleanup do
    cutoff = DateTime.utc_now() |> DateTime.add(-@retention_hours * 3600, :second)

    # Remove stale nodes
    stale_nodes =
      :ets.tab2list(@nodes_table)
      |> Enum.filter(fn {_key, node} ->
        compare_timestamp(node.last_seen, cutoff) == :lt
      end)

    stale_node_keys = Enum.map(stale_nodes, fn {key, _} -> key end)

    Enum.each(stale_node_keys, fn key ->
      {agent_id, entity_id} = key
      :ets.delete(@nodes_table, key)

      # Remove adjacency entries
      :ets.delete(@adjacency_table, {agent_id, :forward, entity_id})
      :ets.delete(@adjacency_table, {agent_id, :reverse, entity_id})
    end)

    # Remove stale edges
    :ets.tab2list(@edges_table)
    |> Enum.each(fn {key, edge} ->
      if compare_timestamp(edge.timestamp, cutoff) == :lt do
        :ets.delete(@edges_table, key)
      end
    end)

    if length(stale_node_keys) > 0 do
      Logger.debug("Provenance cleanup: removed #{length(stale_node_keys)} stale nodes")
    end
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval_ms)
  end

  # ---------------------------------------------------------------------------
  # Timestamp comparison helpers
  # ---------------------------------------------------------------------------

  defp compare_timestamp(%DateTime{} = a, %DateTime{} = b), do: DateTime.compare(a, b)
  defp compare_timestamp(%NaiveDateTime{} = a, %DateTime{} = b) do
    DateTime.compare(DateTime.from_naive!(a, "Etc/UTC"), b)
  end
  defp compare_timestamp(ts, %DateTime{} = b) when is_integer(ts) do
    DateTime.compare(DateTime.from_unix!(ts, :millisecond), b)
  end
  defp compare_timestamp(_, _), do: :lt

  defp min_timestamp(%DateTime{} = a, %DateTime{} = b) do
    if DateTime.compare(a, b) == :lt, do: a, else: b
  end
  defp min_timestamp(a, _b), do: a

  defp max_timestamp(%DateTime{} = a, %DateTime{} = b) do
    if DateTime.compare(a, b) == :gt, do: a, else: b
  end
  defp max_timestamp(a, _b), do: a
end
