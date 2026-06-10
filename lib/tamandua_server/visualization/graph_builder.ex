defmodule TamandUAServer.Visualization.GraphBuilder do
  @moduledoc """
  Builds 3D network graphs from telemetry data for visualization

  Constructs nodes and edges representing:
  - Agents, users, processes, files, network connections
  - Relationships: spawned, accessed, connected, authenticated
  - Attack paths with MITRE ATT&CK technique annotations
  - Time-series evolution for replay mode
  """

  require Logger

  alias TamandUAServer.{Repo, Agents, Telemetry, Detection, Alerts}
  alias TamandUAServer.Telemetry.Event
  alias TamandUAServer.Alerts.Alert

  import Ecto.Query

  @type graph_node :: %{
          id: String.t(),
          type: String.t(),
          data: map(),
          position: %{x: float(), y: float(), z: float()}
        }

  @type edge :: %{
          id: String.t(),
          source_id: String.t(),
          target_id: String.t(),
          type: String.t(),
          data: map()
        }

  @type graph :: %{
          nodes: [node()],
          edges: [edge()],
          timeline_events: [map()],
          timeline_start: DateTime.t(),
          timeline_end: DateTime.t(),
          timeline_duration: integer()
        }

  @doc """
  Build complete network graph from all available data
  """
  @spec build_graph(keyword()) :: {:ok, graph()} | {:error, term()}
  def build_graph(opts \\ []) do
    time_window = Keyword.get(opts, :time_window, 3600)
    max_nodes = Keyword.get(opts, :max_nodes, 10_000)
    max_edges = Keyword.get(opts, :max_edges, 50_000)

    start_time = DateTime.utc_now() |> DateTime.add(-time_window, :second)
    end_time = DateTime.utc_now()

    try do
      # Build nodes
      agent_nodes = build_agent_nodes()
      user_nodes = build_user_nodes(start_time, end_time)
      process_nodes = build_process_nodes(start_time, end_time)
      file_nodes = build_file_nodes(start_time, end_time)
      network_nodes = build_network_nodes(start_time, end_time)
      threat_nodes = build_threat_actor_nodes()

      all_nodes =
        (agent_nodes ++ user_nodes ++ process_nodes ++ file_nodes ++ network_nodes ++
           threat_nodes)
        |> Enum.take(max_nodes)

      # Build edges
      spawn_edges = build_spawn_edges(process_nodes)
      access_edges = build_access_edges(process_nodes, file_nodes)
      network_edges = build_network_edges(process_nodes, network_nodes)
      auth_edges = build_auth_edges(user_nodes, agent_nodes)
      lateral_edges = build_lateral_movement_edges(start_time, end_time)
      exfil_edges = build_exfiltration_edges(start_time, end_time)

      all_edges =
        (spawn_edges ++ access_edges ++ network_edges ++ auth_edges ++ lateral_edges ++
           exfil_edges)
        |> Enum.take(max_edges)

      # Build timeline events
      timeline_events = build_timeline_events(start_time, end_time)

      graph = %{
        nodes: all_nodes,
        edges: all_edges,
        timeline_events: timeline_events,
        timeline_start: start_time,
        timeline_end: end_time,
        timeline_duration: DateTime.diff(end_time, start_time)
      }

      {:ok, graph}
    rescue
      e ->
        Logger.error("Failed to build graph: #{inspect(e)}")
        {:error, e}
    end
  end

  @doc """
  Build agent nodes from registered agents
  """
  def build_agent_nodes do
    Agents.list_agents()
    |> Enum.map(fn agent ->
      type =
        cond do
          agent.metadata["os_type"] == "mobile" -> "mobile"
          agent.metadata["server_role"] -> "server"
          true -> "agent"
        end

      %{
        id: "agent:#{agent.id}",
        type: type,
        data: %{
          agent_id: agent.id,
          name: agent.hostname,
          hostname: agent.hostname,
          ip: agent.ip_address,
          os: agent.metadata["os_name"],
          version: agent.version,
          status: agent.status,
          last_seen: agent.last_seen_at
        },
        position: generate_position(:agent, agent)
      }
    end)
  end

  @doc """
  Build user nodes from authentication events
  """
  def build_user_nodes(start_time, end_time) do
    query =
      from e in Event,
        where: e.event_type == "auth" and e.timestamp >= ^start_time and e.timestamp <= ^end_time,
        select: {e.payload["username"], e.payload["success"], e.agent_id},
        distinct: true

    Repo.all(query)
    |> Enum.map(fn {username, success, agent_id} ->
      type =
        cond do
          is_privileged_user?(username) -> "privileged_user"
          is_compromised_user?(username) -> "compromised_user"
          true -> "user"
        end

      %{
        id: "user:#{username}",
        type: type,
        data: %{
          username: username,
          name: username,
          privileged: type == "privileged_user",
          compromised: type == "compromised_user",
          agent_id: agent_id
        },
        position: generate_position(:user, username)
      }
    end)
  end

  @doc """
  Build process nodes from process events
  """
  def build_process_nodes(start_time, end_time) do
    query =
      from e in Event,
        where:
          e.event_type == "process" and e.timestamp >= ^start_time and e.timestamp <= ^end_time,
        select: {e.payload["pid"], e.payload["name"], e.payload["cmdline"], e.agent_id},
        distinct: true,
        limit: 5000

    Repo.all(query)
    |> Enum.map(fn {pid, name, cmdline, agent_id} ->
      type =
        cond do
          is_malicious_process?(name, cmdline) -> "malicious_process"
          is_suspicious_process?(name, cmdline) -> "suspicious_process"
          true -> "process"
        end

      %{
        id: "process:#{agent_id}:#{pid}",
        type: type,
        data: %{
          pid: pid,
          name: name,
          cmdline: cmdline,
          agent_id: agent_id,
          malicious: type == "malicious_process",
          suspicious: type == "suspicious_process"
        },
        position: generate_position(:process, {agent_id, pid})
      }
    end)
  end

  @doc """
  Build file nodes from file events
  """
  def build_file_nodes(start_time, end_time) do
    query =
      from e in Event,
        where: e.event_type == "file" and e.timestamp >= ^start_time and e.timestamp <= ^end_time,
        select: {e.payload["path"], e.payload["operation"], e.agent_id},
        distinct: true,
        limit: 5000

    Repo.all(query)
    |> Enum.map(fn {path, _operation, agent_id} ->
      type =
        cond do
          is_executable?(path) -> "executable"
          is_script?(path) -> "script"
          true -> "file"
        end

      %{
        id: "file:#{agent_id}:#{Base.encode64(path)}",
        type: type,
        data: %{
          path: path,
          name: Path.basename(path),
          agent_id: agent_id
        },
        position: generate_position(:file, {agent_id, path})
      }
    end)
  end

  @doc """
  Build network connection nodes
  """
  def build_network_nodes(start_time, end_time) do
    query =
      from e in Event,
        where:
          e.event_type == "network" and e.timestamp >= ^start_time and e.timestamp <= ^end_time,
        select: {e.payload["remote_ip"], e.payload["remote_port"], e.payload["direction"]},
        distinct: true,
        limit: 2000

    Repo.all(query)
    |> Enum.map(fn {remote_ip, remote_port, direction} ->
      type = if is_external_ip?(remote_ip), do: "external", else: "network"

      %{
        id: "network:#{remote_ip}:#{remote_port}",
        type: type,
        data: %{
          ip: remote_ip,
          port: remote_port,
          direction: direction,
          external: type == "external"
        },
        position: generate_position(:network, remote_ip)
      }
    end)
  end

  @doc """
  Build threat actor nodes from attributed alerts
  """
  def build_threat_actor_nodes do
    query =
      from a in Alert,
        where: not is_nil(a.metadata["threat_actor"]),
        select: a.metadata["threat_actor"],
        distinct: true

    Repo.all(query)
    |> Enum.map(fn actor ->
      %{
        id: "threat:#{actor}",
        type: "threat_actor",
        data: %{
          name: actor,
          attribution: get_threat_attribution(actor)
        },
        position: generate_position(:threat, actor)
      }
    end)
  end

  @doc """
  Build process spawn edges (parent-child relationships)
  """
  def build_spawn_edges(process_nodes) do
    agent_processes =
      process_nodes
      |> Enum.group_by(& &1.data.agent_id)

    Enum.flat_map(agent_processes, fn {agent_id, processes} ->
      # Query process tree relationships
      pids = Enum.map(processes, & &1.data.pid)

      query =
        from e in Event,
          where:
            e.event_type == "process" and e.agent_id == ^agent_id and
              e.payload["pid"] in ^pids,
          select: {e.payload["pid"], e.payload["ppid"]}

      Repo.all(query)
      |> Enum.filter(fn {_pid, ppid} -> ppid && ppid in pids end)
      |> Enum.map(fn {pid, ppid} ->
        %{
          id: "spawn:#{agent_id}:#{ppid}:#{pid}",
          source_id: "process:#{agent_id}:#{ppid}",
          target_id: "process:#{agent_id}:#{pid}",
          type: "spawn",
          data: %{
            agent_id: agent_id
          }
        }
      end)
    end)
  end

  @doc """
  Build file access edges
  """
  def build_access_edges(process_nodes, file_nodes) do
    # Simplified: create edges based on recent file events
    agent_processes = Enum.group_by(process_nodes, & &1.data.agent_id)
    agent_files = Enum.group_by(file_nodes, & &1.data.agent_id)

    Enum.flat_map(agent_processes, fn {agent_id, processes} ->
      files = Map.get(agent_files, agent_id, [])

      for process <- processes, file <- files do
        %{
          id: "access:#{process.id}:#{file.id}",
          source_id: process.id,
          target_id: file.id,
          type: "access",
          data: %{
            agent_id: agent_id
          }
        }
      end
      |> Enum.take(100)
    end)
  end

  @doc """
  Build network connection edges
  """
  def build_network_edges(process_nodes, network_nodes) do
    # Sample network connections
    Enum.flat_map(process_nodes, fn process ->
      # Take sample of network nodes
      network_nodes
      |> Enum.take_random(min(3, length(network_nodes)))
      |> Enum.map(fn network ->
        %{
          id: "network:#{process.id}:#{network.id}",
          source_id: process.id,
          target_id: network.id,
          type: "network",
          data: %{
            protocol: "tcp"
          }
        }
      end)
    end)
    |> Enum.take(5000)
  end

  @doc """
  Build authentication edges
  """
  def build_auth_edges(user_nodes, agent_nodes) do
    Enum.flat_map(user_nodes, fn user ->
      agent_id = user.data.agent_id

      agent_nodes
      |> Enum.filter(&(&1.data.agent_id == agent_id))
      |> Enum.map(fn agent ->
        %{
          id: "auth:#{user.id}:#{agent.id}",
          source_id: user.id,
          target_id: agent.id,
          type: "auth",
          data: %{}
        }
      end)
    end)
  end

  @doc """
  Build lateral movement edges
  """
  def build_lateral_movement_edges(start_time, end_time) do
    query =
      from a in Alert,
        where:
          a.inserted_at >= ^start_time and a.inserted_at <= ^end_time and
            fragment("? -> 'technique' ->> 'tactic' = ?", a.metadata, "lateral-movement"),
        select: {a.agent_id, a.metadata["source_host"], a.metadata["target_host"]}

    Repo.all(query)
    |> Enum.map(fn {agent_id, source, target} ->
      %{
        id: "lateral:#{source}:#{target}",
        source_id: "agent:#{source}",
        target_id: "agent:#{target}",
        type: "lateral",
        data: %{
          agent_id: agent_id,
          technique: "lateral_movement"
        }
      }
    end)
  end

  @doc """
  Build data exfiltration edges
  """
  def build_exfiltration_edges(start_time, end_time) do
    query =
      from a in Alert,
        where:
          a.inserted_at >= ^start_time and a.inserted_at <= ^end_time and
            fragment("? -> 'technique' ->> 'tactic' = ?", a.metadata, "exfiltration"),
        select: {a.agent_id, a.metadata["destination_ip"], a.metadata["bytes_sent"]}

    Repo.all(query)
    |> Enum.map(fn {agent_id, dest_ip, bytes} ->
      %{
        id: "exfil:#{agent_id}:#{dest_ip}",
        source_id: "agent:#{agent_id}",
        target_id: "network:#{dest_ip}",
        type: "exfil",
        data: %{
          bytes: bytes,
          destination: dest_ip
        }
      }
    end)
  end

  @doc """
  Build timeline events from alerts
  """
  def build_timeline_events(start_time, end_time) do
    query =
      from a in Alert,
        where: a.inserted_at >= ^start_time and a.inserted_at <= ^end_time,
        order_by: [asc: a.inserted_at],
        select: %{
          id: a.id,
          timestamp: a.inserted_at,
          severity: a.severity,
          rule_name: a.rule_name,
          agent_id: a.agent_id,
          technique: a.metadata["technique"]
        }

    Repo.all(query)
    |> Enum.map(fn event ->
      %{
        id: event.id,
        time: DateTime.to_unix(event.timestamp),
        severity: event.severity,
        title: event.rule_name,
        technique: event.technique,
        agent_id: event.agent_id
      }
    end)
  end

  @doc """
  Get a specific node by ID
  """
  def get_node(node_id) do
    # Parse node type and identifiers from ID
    # This is a simplified implementation
    %{
      id: node_id,
      type: "unknown",
      data: %{},
      position: %{x: 0, y: 0, z: 0}
    }
  end

  @doc """
  Search nodes by query string
  """
  def search_nodes(query) when byte_size(query) < 2, do: []

  def search_nodes(query) do
    query_lower = String.downcase(query)

    # Search in agents
    agents =
      Agents.list_agents()
      |> Enum.filter(fn agent ->
        String.contains?(String.downcase(agent.hostname || ""), query_lower) ||
          String.contains?(String.downcase(agent.ip_address || ""), query_lower)
      end)
      |> Enum.map(fn agent ->
        %{
          id: "agent:#{agent.id}",
          type: "agent",
          name: agent.hostname,
          hostname: agent.hostname,
          ip: agent.ip_address
        }
      end)
      |> Enum.take(10)

    # Search in events (simplified)
    # This would be more sophisticated in production
    agents
  end

  @doc """
  Get edges connected to a node
  """
  def get_node_edges(node_id) do
    # This would query the actual edges
    # Simplified implementation
    []
  end

  @doc """
  Get incremental graph updates since a timestamp
  """
  def get_graph_updates(since_time) do
    # Query new events since timestamp
    # Return incremental updates
    {:ok, []}
  end

  # Private helper functions

  defp generate_position(:agent, agent) do
    # Use consistent hash for positioning
    hash = :erlang.phash2(agent.id, 10_000)
    angle = hash / 10_000 * 2 * :math.pi()
    radius = 50

    %{
      x: :math.cos(angle) * radius,
      y: 0,
      z: :math.sin(angle) * radius
    }
  end

  defp generate_position(:user, username) do
    hash = :erlang.phash2(username, 10_000)
    angle = hash / 10_000 * 2 * :math.pi()
    radius = 30

    %{
      x: :math.cos(angle) * radius,
      y: 20,
      z: :math.sin(angle) * radius
    }
  end

  defp generate_position(:process, {agent_id, pid}) do
    agent_hash = :erlang.phash2(agent_id, 1000)
    pid_hash = :erlang.phash2(pid, 1000)

    agent_angle = agent_hash / 1000 * 2 * :math.pi()
    agent_radius = 50

    %{
      x: :math.cos(agent_angle) * agent_radius + (:rand.uniform() - 0.5) * 10,
      y: pid_hash / 1000 * 20 - 10,
      z: :math.sin(agent_angle) * agent_radius + (:rand.uniform() - 0.5) * 10
    }
  end

  defp generate_position(:file, {agent_id, path}) do
    agent_hash = :erlang.phash2(agent_id, 1000)
    file_hash = :erlang.phash2(path, 1000)

    agent_angle = agent_hash / 1000 * 2 * :math.pi()
    agent_radius = 50

    %{
      x: :math.cos(agent_angle) * agent_radius + (:rand.uniform() - 0.5) * 15,
      y: -20 + file_hash / 1000 * 10,
      z: :math.sin(agent_angle) * agent_radius + (:rand.uniform() - 0.5) * 15
    }
  end

  defp generate_position(:network, ip) do
    hash = :erlang.phash2(ip, 10_000)
    angle = hash / 10_000 * 2 * :math.pi()
    radius = if is_external_ip?(ip), do: 80, else: 60

    %{
      x: :math.cos(angle) * radius,
      y: 30,
      z: :math.sin(angle) * radius
    }
  end

  defp generate_position(:threat, actor) do
    hash = :erlang.phash2(actor, 1000)
    angle = hash / 1000 * 2 * :math.pi()
    radius = 100

    %{
      x: :math.cos(angle) * radius,
      y: 50,
      z: :math.sin(angle) * radius
    }
  end

  defp is_privileged_user?(username) do
    username in ["root", "administrator", "admin", "system"] ||
      String.ends_with?(username, "-admin")
  end

  defp is_compromised_user?(username) do
    # Check if user has any high-severity alerts
    query =
      from a in Alert,
        where:
          fragment("? -> 'username' = ?", a.metadata, ^username) and a.severity == "critical",
        limit: 1

    Repo.exists?(query)
  end

  defp is_malicious_process?(name, cmdline) do
    # Check if process has any malicious alerts
    malicious_patterns = [
      "mimikatz",
      "psexec",
      "metasploit",
      "cobaltstrike",
      "powershell -enc",
      "cmd.exe /c echo"
    ]

    search_text = "#{name} #{cmdline}" |> String.downcase()

    Enum.any?(malicious_patterns, fn pattern ->
      String.contains?(search_text, pattern)
    end)
  end

  defp is_suspicious_process?(name, cmdline) do
    suspicious_patterns = [
      "powershell",
      "wscript",
      "cscript",
      "regsvr32",
      "rundll32",
      "mshta"
    ]

    search_text = "#{name} #{cmdline}" |> String.downcase()

    Enum.any?(suspicious_patterns, fn pattern ->
      String.contains?(search_text, pattern)
    end)
  end

  defp is_executable?(path) do
    String.ends_with?(String.downcase(path), [".exe", ".dll", ".sys", ".bin"])
  end

  defp is_script?(path) do
    String.ends_with?(String.downcase(path), [
      ".ps1",
      ".bat",
      ".cmd",
      ".vbs",
      ".js",
      ".py",
      ".sh"
    ])
  end

  defp is_external_ip?(ip) do
    # Check if IP is private
    !String.starts_with?(ip, ["10.", "172.", "192.168.", "127."])
  end

  defp get_threat_attribution(actor) do
    # This would query a threat intelligence database
    %{
      country: "Unknown",
      motivation: "Unknown",
      techniques: []
    }
  end
end
