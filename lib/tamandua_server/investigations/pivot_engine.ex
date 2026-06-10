defmodule TamanduaServer.Investigations.PivotEngine do
  @moduledoc """
  Core engine for executing investigation pivots.

  Provides efficient queries to pivot from various entities (IP, hash, user, process, etc.)
  to related data across the EDR platform. Results are cached for performance.
  """

  import Ecto.Query
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.Telemetry.Event
  alias TamanduaServer.Investigations.PivotChain
  alias TamanduaServer.Cache

  @max_results 100
  @cache_ttl 300

  @type pivot_type ::
          :ip_pivot
          | :hash_pivot
          | :user_pivot
          | :process_pivot
          | :file_pivot
          | :domain_pivot
          | :agent_pivot

  @type pivot_result :: %{
          entity_type: atom(),
          entity_value: String.t(),
          results: list(map()),
          total_count: integer(),
          truncated: boolean(),
          cached: boolean(),
          query_time_ms: integer()
        }

  @doc """
  Pivot from an IP address to all related alerts and agents.
  """
  @spec pivot_from_ip(String.t(), binary(), keyword()) :: pivot_result()
  def pivot_from_ip(ip_address, org_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, @max_results)
    use_cache = Keyword.get(opts, :cache, true)

    cache_key = "pivot:ip:#{ip_address}:#{org_id}"

    if use_cache do
      Cache.fetch(cache_key, @cache_ttl, fn ->
        execute_ip_pivot(ip_address, org_id, limit)
      end)
    else
      execute_ip_pivot(ip_address, org_id, limit)
    end
  end

  defp execute_ip_pivot(ip_address, org_id, limit) do
    start_time = System.monotonic_time(:millisecond)

    # Find agents with this IP
    agents =
      from(a in Agent,
        where: a.organization_id == ^org_id,
        where: a.ip_address == ^ip_address,
        limit: ^limit,
        select: %{
          type: "agent",
          id: a.id,
          hostname: a.hostname,
          ip_address: a.ip_address,
          os_type: a.os_type,
          status: a.status,
          last_seen: a.last_seen
        }
      )
      |> Repo.all()

    # Find alerts related to this IP (from enrichment data)
    alerts =
      from(a in Alert,
        where: a.organization_id == ^org_id,
        where: fragment("enrichment @> ?", ^%{"network" => %{"remote_ip" => ip_address}}),
        or_where: fragment("evidence @> ?", ^%{"network" => %{"remote_ip" => ip_address}}),
        order_by: [desc: a.inserted_at],
        limit: ^limit,
        select: %{
          type: "alert",
          id: a.id,
          title: a.title,
          severity: a.severity,
          status: a.status,
          agent_id: a.agent_id,
          timestamp: a.inserted_at,
          mitre_techniques: a.mitre_techniques
        }
      )
      |> Repo.all()

    # Find events with this IP
    events =
      from(e in Event,
        join: a in Agent,
        on: e.agent_id == a.id,
        where: a.organization_id == ^org_id,
        where:
          fragment("payload->>'remote_ip' = ?", ^ip_address) or
            fragment("payload->>'dst_ip' = ?", ^ip_address) or
            fragment("payload->>'src_ip' = ?", ^ip_address),
        order_by: [desc: e.timestamp],
        limit: ^limit,
        select: %{
          type: "event",
          id: e.id,
          event_type: e.event_type,
          agent_id: e.agent_id,
          timestamp: e.timestamp,
          payload: e.payload
        }
      )
      |> Repo.all()

    all_results = agents ++ alerts ++ events
    total_count = length(all_results)
    truncated = total_count >= limit

    query_time_ms = System.monotonic_time(:millisecond) - start_time

    %{
      entity_type: :ip,
      entity_value: ip_address,
      results: all_results,
      total_count: total_count,
      truncated: truncated,
      cached: false,
      query_time_ms: query_time_ms
    }
  end

  @doc """
  Pivot from a file hash to all detections and executions.
  """
  @spec pivot_from_hash(String.t(), binary(), keyword()) :: pivot_result()
  def pivot_from_hash(file_hash, org_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, @max_results)
    use_cache = Keyword.get(opts, :cache, true)

    cache_key = "pivot:hash:#{file_hash}:#{org_id}"

    if use_cache do
      Cache.fetch(cache_key, @cache_ttl, fn ->
        execute_hash_pivot(file_hash, org_id, limit)
      end)
    else
      execute_hash_pivot(file_hash, org_id, limit)
    end
  end

  defp execute_hash_pivot(file_hash, org_id, limit) do
    start_time = System.monotonic_time(:millisecond)

    # Normalize hash (remove prefix if present)
    normalized_hash = String.downcase(file_hash) |> String.replace(~r/^(sha256:|md5:|sha1:)/, "")

    # Find alerts with this hash
    alerts =
      from(a in Alert,
        where: a.organization_id == ^org_id,
        where:
          fragment("evidence->>'sha256' = ?", ^normalized_hash) or
            fragment("evidence->>'md5' = ?", ^normalized_hash) or
            fragment("evidence->'file_hashes'->>'sha256' = ?", ^normalized_hash) or
            fragment("evidence->'file_hashes'->>'md5' = ?", ^normalized_hash),
        order_by: [desc: a.inserted_at],
        limit: ^limit,
        preload: [:agent],
        select: %{
          type: "alert",
          id: a.id,
          title: a.title,
          severity: a.severity,
          agent_id: a.agent_id,
          agent: a.agent,
          timestamp: a.inserted_at,
          evidence: a.evidence
        }
      )
      |> Repo.all()

    # Find process events with this hash
    events =
      from(e in Event,
        join: a in Agent,
        on: e.agent_id == a.id,
        where: a.organization_id == ^org_id,
        where: e.event_type in ["ProcessCreate", "FileWrite", "FileModify"],
        where:
          fragment("payload->>'sha256' = ?", ^normalized_hash) or
            fragment("payload->>'md5' = ?", ^normalized_hash),
        order_by: [desc: e.timestamp],
        limit: ^limit,
        select: %{
          type: "event",
          id: e.id,
          event_type: e.event_type,
          agent_id: e.agent_id,
          timestamp: e.timestamp,
          payload: e.payload
        }
      )
      |> Repo.all()

    all_results = alerts ++ events
    total_count = length(all_results)
    truncated = total_count >= limit

    query_time_ms = System.monotonic_time(:millisecond) - start_time

    %{
      entity_type: :hash,
      entity_value: file_hash,
      results: all_results,
      total_count: total_count,
      truncated: truncated,
      cached: false,
      query_time_ms: query_time_ms
    }
  end

  @doc """
  Pivot from a username to all activity by that user.
  """
  @spec pivot_from_user(String.t(), binary(), keyword()) :: pivot_result()
  def pivot_from_user(username, org_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, @max_results)
    use_cache = Keyword.get(opts, :cache, true)

    cache_key = "pivot:user:#{username}:#{org_id}"

    if use_cache do
      Cache.fetch(cache_key, @cache_ttl, fn ->
        execute_user_pivot(username, org_id, limit)
      end)
    else
      execute_user_pivot(username, org_id, limit)
    end
  end

  defp execute_user_pivot(username, org_id, limit) do
    start_time = System.monotonic_time(:millisecond)

    # Find alerts related to this user
    alerts =
      from(a in Alert,
        where: a.organization_id == ^org_id,
        where:
          fragment("evidence->'process'->>'user' = ?", ^username) or
            fragment("enrichment->>'user' = ?", ^username),
        order_by: [desc: a.inserted_at],
        limit: ^limit,
        preload: [:agent],
        select: %{
          type: "alert",
          id: a.id,
          title: a.title,
          severity: a.severity,
          agent_id: a.agent_id,
          agent: a.agent,
          timestamp: a.inserted_at,
          evidence: a.evidence
        }
      )
      |> Repo.all()

    # Find events by this user
    events =
      from(e in Event,
        join: a in Agent,
        on: e.agent_id == a.id,
        where: a.organization_id == ^org_id,
        where:
          fragment("payload->>'user' = ?", ^username) or
            fragment("payload->>'username' = ?", ^username),
        order_by: [desc: e.timestamp],
        limit: ^limit,
        select: %{
          type: "event",
          id: e.id,
          event_type: e.event_type,
          agent_id: e.agent_id,
          timestamp: e.timestamp,
          payload: e.payload
        }
      )
      |> Repo.all()

    all_results = alerts ++ events
    total_count = length(all_results)
    truncated = total_count >= limit

    query_time_ms = System.monotonic_time(:millisecond) - start_time

    %{
      entity_type: :user,
      entity_value: username,
      results: all_results,
      total_count: total_count,
      truncated: truncated,
      cached: false,
      query_time_ms: query_time_ms
    }
  end

  @doc """
  Pivot from a process (by name or PID) to network connections, child processes, and file access.
  """
  @spec pivot_from_process(String.t() | integer(), binary(), binary(), keyword()) :: pivot_result()
  def pivot_from_process(process_identifier, agent_id, org_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, @max_results)
    start_time = System.monotonic_time(:millisecond)

    # Find process events
    process_events =
      from(e in Event,
        join: a in Agent,
        on: e.agent_id == a.id,
        where: a.organization_id == ^org_id,
        where: e.agent_id == ^agent_id,
        where: e.event_type in ["ProcessCreate", "ProcessTerminate"],
        where:
          fragment("payload->>'process_name' = ?", ^to_string(process_identifier)) or
            fragment("payload->>'pid' = ?", ^to_string(process_identifier)),
        order_by: [desc: e.timestamp],
        limit: ^limit,
        select: %{
          type: "process_event",
          id: e.id,
          event_type: e.event_type,
          agent_id: e.agent_id,
          timestamp: e.timestamp,
          payload: e.payload
        }
      )
      |> Repo.all()

    # Find network connections from this process
    network_events =
      from(e in Event,
        join: a in Agent,
        on: e.agent_id == a.id,
        where: a.organization_id == ^org_id,
        where: e.agent_id == ^agent_id,
        where: e.event_type in ["NetworkConnect", "DnsQuery"],
        where:
          fragment("payload->>'process_name' = ?", ^to_string(process_identifier)) or
            fragment("payload->>'pid' = ?", ^to_string(process_identifier)),
        order_by: [desc: e.timestamp],
        limit: ^limit,
        select: %{
          type: "network_event",
          id: e.id,
          event_type: e.event_type,
          agent_id: e.agent_id,
          timestamp: e.timestamp,
          payload: e.payload
        }
      )
      |> Repo.all()

    # Find file operations from this process
    file_events =
      from(e in Event,
        join: a in Agent,
        on: e.agent_id == a.id,
        where: a.organization_id == ^org_id,
        where: e.agent_id == ^agent_id,
        where: e.event_type in ["FileWrite", "FileModify", "FileDelete", "FileRead"],
        where:
          fragment("payload->>'process_name' = ?", ^to_string(process_identifier)) or
            fragment("payload->>'pid' = ?", ^to_string(process_identifier)),
        order_by: [desc: e.timestamp],
        limit: ^limit,
        select: %{
          type: "file_event",
          id: e.id,
          event_type: e.event_type,
          agent_id: e.agent_id,
          timestamp: e.timestamp,
          payload: e.payload
        }
      )
      |> Repo.all()

    all_results = process_events ++ network_events ++ file_events
    total_count = length(all_results)
    truncated = total_count >= limit

    query_time_ms = System.monotonic_time(:millisecond) - start_time

    %{
      entity_type: :process,
      entity_value: to_string(process_identifier),
      results: all_results,
      total_count: total_count,
      truncated: truncated,
      cached: false,
      query_time_ms: query_time_ms
    }
  end

  @doc """
  Pivot from a file path to execution history and where it was written/read.
  """
  @spec pivot_from_file(String.t(), binary(), keyword()) :: pivot_result()
  def pivot_from_file(file_path, org_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, @max_results)
    start_time = System.monotonic_time(:millisecond)

    # Normalize path for comparison
    normalized_path = String.downcase(file_path)

    # Find file events
    file_events =
      from(e in Event,
        join: a in Agent,
        on: e.agent_id == a.id,
        where: a.organization_id == ^org_id,
        where: e.event_type in ["FileWrite", "FileModify", "FileDelete", "FileRead"],
        where: fragment("LOWER(payload->>'file_path') = ?", ^normalized_path),
        order_by: [desc: e.timestamp],
        limit: ^limit,
        preload: [agent: a],
        select: %{
          type: "file_event",
          id: e.id,
          event_type: e.event_type,
          agent_id: e.agent_id,
          agent: e.agent,
          timestamp: e.timestamp,
          payload: e.payload
        }
      )
      |> Repo.all()

    # Find process executions of this file
    process_events =
      from(e in Event,
        join: a in Agent,
        on: e.agent_id == a.id,
        where: a.organization_id == ^org_id,
        where: e.event_type == "ProcessCreate",
        where:
          fragment("LOWER(payload->>'image_path') = ?", ^normalized_path) or
            fragment("LOWER(payload->>'path') = ?", ^normalized_path),
        order_by: [desc: e.timestamp],
        limit: ^limit,
        select: %{
          type: "execution_event",
          id: e.id,
          event_type: e.event_type,
          agent_id: e.agent_id,
          timestamp: e.timestamp,
          payload: e.payload
        }
      )
      |> Repo.all()

    # Find alerts related to this file
    alerts =
      from(a in Alert,
        where: a.organization_id == ^org_id,
        where:
          fragment("LOWER(evidence->'file'->>'path') = ?", ^normalized_path) or
            fragment("LOWER(evidence->>'file_path') = ?", ^normalized_path),
        order_by: [desc: a.inserted_at],
        limit: ^limit,
        select: %{
          type: "alert",
          id: a.id,
          title: a.title,
          severity: a.severity,
          agent_id: a.agent_id,
          timestamp: a.inserted_at,
          evidence: a.evidence
        }
      )
      |> Repo.all()

    all_results = file_events ++ process_events ++ alerts
    total_count = length(all_results)
    truncated = total_count >= limit

    query_time_ms = System.monotonic_time(:millisecond) - start_time

    %{
      entity_type: :file,
      entity_value: file_path,
      results: all_results,
      total_count: total_count,
      truncated: truncated,
      cached: false,
      query_time_ms: query_time_ms
    }
  end

  @doc """
  Pivot from a domain to DNS queries, connections, and alerts.
  """
  @spec pivot_from_domain(String.t(), binary(), keyword()) :: pivot_result()
  def pivot_from_domain(domain, org_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, @max_results)
    use_cache = Keyword.get(opts, :cache, true)

    cache_key = "pivot:domain:#{domain}:#{org_id}"

    if use_cache do
      Cache.fetch(cache_key, @cache_ttl, fn ->
        execute_domain_pivot(domain, org_id, limit)
      end)
    else
      execute_domain_pivot(domain, org_id, limit)
    end
  end

  defp execute_domain_pivot(domain, org_id, limit) do
    start_time = System.monotonic_time(:millisecond)

    # Find DNS queries for this domain
    dns_events =
      from(e in Event,
        join: a in Agent,
        on: e.agent_id == a.id,
        where: a.organization_id == ^org_id,
        where: e.event_type == "DnsQuery",
        where:
          fragment("payload->>'query' = ?", ^domain) or
            fragment("payload->>'domain' = ?", ^domain),
        order_by: [desc: e.timestamp],
        limit: ^limit,
        select: %{
          type: "dns_event",
          id: e.id,
          event_type: e.event_type,
          agent_id: e.agent_id,
          timestamp: e.timestamp,
          payload: e.payload
        }
      )
      |> Repo.all()

    # Find network connections to this domain
    network_events =
      from(e in Event,
        join: a in Agent,
        on: e.agent_id == a.id,
        where: a.organization_id == ^org_id,
        where: e.event_type == "NetworkConnect",
        where: fragment("payload->>'domain' = ?", ^domain),
        order_by: [desc: e.timestamp],
        limit: ^limit,
        select: %{
          type: "network_event",
          id: e.id,
          event_type: e.event_type,
          agent_id: e.agent_id,
          timestamp: e.timestamp,
          payload: e.payload
        }
      )
      |> Repo.all()

    # Find alerts related to this domain
    alerts =
      from(a in Alert,
        where: a.organization_id == ^org_id,
        where:
          fragment("evidence->'network'->>'domain' = ?", ^domain) or
            fragment("enrichment->>'domain' = ?", ^domain),
        order_by: [desc: a.inserted_at],
        limit: ^limit,
        select: %{
          type: "alert",
          id: a.id,
          title: a.title,
          severity: a.severity,
          agent_id: a.agent_id,
          timestamp: a.inserted_at,
          evidence: a.evidence
        }
      )
      |> Repo.all()

    all_results = dns_events ++ network_events ++ alerts
    total_count = length(all_results)
    truncated = total_count >= limit

    query_time_ms = System.monotonic_time(:millisecond) - start_time

    %{
      entity_type: :domain,
      entity_value: domain,
      results: all_results,
      total_count: total_count,
      truncated: truncated,
      cached: false,
      query_time_ms: query_time_ms
    }
  end

  @doc """
  Pivot from an agent to all telemetry, alerts, and processes.
  """
  @spec pivot_from_agent(binary(), binary(), keyword()) :: pivot_result()
  def pivot_from_agent(agent_id, org_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, @max_results)
    start_time = System.monotonic_time(:millisecond)

    # Get agent details
    agent =
      from(a in Agent,
        where: a.id == ^agent_id,
        where: a.organization_id == ^org_id,
        select: %{
          type: "agent",
          id: a.id,
          hostname: a.hostname,
          ip_address: a.ip_address,
          os_type: a.os_type,
          status: a.status,
          last_seen: a.last_seen
        }
      )
      |> Repo.one()

    if agent do
      # Find alerts on this agent
      alerts =
        from(a in Alert,
          where: a.organization_id == ^org_id,
          where: a.agent_id == ^agent_id,
          order_by: [desc: a.inserted_at],
          limit: ^limit,
          select: %{
            type: "alert",
            id: a.id,
            title: a.title,
            severity: a.severity,
            status: a.status,
            timestamp: a.inserted_at,
            mitre_techniques: a.mitre_techniques
          }
        )
        |> Repo.all()

      # Find recent events
      events =
        from(e in Event,
          where: e.agent_id == ^agent_id,
          order_by: [desc: e.timestamp],
          limit: ^limit,
          select: %{
            type: "event",
            id: e.id,
            event_type: e.event_type,
            timestamp: e.timestamp,
            severity: e.severity
          }
        )
        |> Repo.all()

      # Get recent processes
      processes =
        from(e in Event,
          where: e.agent_id == ^agent_id,
          where: e.event_type == "ProcessCreate",
          order_by: [desc: e.timestamp],
          limit: 50,
          select: %{
            type: "process",
            id: e.id,
            timestamp: e.timestamp,
            payload: e.payload
          }
        )
        |> Repo.all()

      all_results = [agent] ++ alerts ++ events ++ processes
      total_count = length(all_results)
      truncated = total_count >= limit

      query_time_ms = System.monotonic_time(:millisecond) - start_time

      %{
        entity_type: :agent,
        entity_value: agent_id,
        results: all_results,
        total_count: total_count,
        truncated: truncated,
        cached: false,
        query_time_ms: query_time_ms
      }
    else
      %{
        entity_type: :agent,
        entity_value: agent_id,
        results: [],
        total_count: 0,
        truncated: false,
        cached: false,
        query_time_ms: System.monotonic_time(:millisecond) - start_time
      }
    end
  end

  @doc """
  Build a graph representation from pivot results.
  """
  @spec build_pivot_graph(list(pivot_result())) :: %{nodes: list(), links: list()}
  def build_pivot_graph(pivot_results) do
    nodes = []
    links = []
    node_ids = MapSet.new()

    {nodes, links, _node_ids} =
      Enum.reduce(pivot_results, {nodes, links, node_ids}, fn pivot_result, {n_acc, l_acc, ids_acc} ->
        # Add source node
        source_id = "#{pivot_result.entity_type}_#{pivot_result.entity_value}"

        {n_acc, ids_acc} =
          if !MapSet.member?(ids_acc, source_id) do
            source_node = %{
              id: source_id,
              type: pivot_result.entity_type,
              value: pivot_result.entity_value,
              label: pivot_result.entity_value
            }
            {[source_node | n_acc], MapSet.put(ids_acc, source_id)}
          else
            {n_acc, ids_acc}
          end

        # Add result nodes and links
        Enum.reduce(pivot_result.results, {n_acc, l_acc, ids_acc}, fn result, {n2_acc, l2_acc, ids2_acc} ->
          result_type = result[:type] || result["type"]
          result_id = "#{result_type}_#{result[:id] || result["id"]}"

          {n2_acc, ids2_acc} =
            if !MapSet.member?(ids2_acc, result_id) do
              result_node = %{
                id: result_id,
                type: result_type,
                data: result,
                label: get_result_label(result)
              }
              {[result_node | n2_acc], MapSet.put(ids2_acc, result_id)}
            else
              {n2_acc, ids2_acc}
            end

          # Add link
          link = %{
            source: source_id,
            target: result_id,
            type: "pivot",
            relationship: "related_to"
          }

          {n2_acc, [link | l2_acc], ids2_acc}
        end)
      end)

    %{nodes: nodes, links: links}
  end

  defp get_result_label(result) do
    case result[:type] || result["type"] do
      "alert" -> result[:title] || result["title"] || "Alert"
      "agent" -> result[:hostname] || result["hostname"] || "Agent"
      "event" -> result[:event_type] || result["event_type"] || "Event"
      "process" ->
        payload = result[:payload] || result["payload"] || %{}
        payload["process_name"] || payload[:process_name] || "Process"
      _ -> "Unknown"
    end
  end

  @doc """
  Save a pivot chain for later replay or sharing.
  """
  @spec save_pivot_chain(map(), binary(), binary()) :: {:ok, PivotChain.t()} | {:error, Ecto.Changeset.t()}
  def save_pivot_chain(chain_data, org_id, user_id) do
    %PivotChain{}
    |> PivotChain.changeset(
      Map.merge(chain_data, %{
        organization_id: org_id,
        created_by_id: user_id
      })
    )
    |> Repo.insert()
  end

  @doc """
  Load a saved pivot chain.
  """
  @spec load_pivot_chain(binary()) :: {:ok, PivotChain.t()} | {:error, :not_found}
  def load_pivot_chain(chain_id) do
    case Repo.get(PivotChain, chain_id) do
      nil -> {:error, :not_found}
      chain -> {:ok, chain}
    end
  end

  @doc """
  List all pivot chains for an organization.
  """
  @spec list_pivot_chains(binary(), keyword()) :: list(PivotChain.t())
  def list_pivot_chains(org_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 50)
    include_templates = Keyword.get(opts, :include_templates, true)

    query =
      from(p in PivotChain,
        where: p.organization_id == ^org_id,
        order_by: [desc: p.updated_at],
        limit: ^limit,
        preload: [:created_by]
      )

    query =
      if include_templates do
        query
      else
        from(p in query, where: p.is_template == false)
      end

    Repo.all(query)
  end

  @doc """
  Delete a pivot chain.
  """
  @spec delete_pivot_chain(binary()) :: {:ok, PivotChain.t()} | {:error, Ecto.Changeset.t()}
  def delete_pivot_chain(chain_id) do
    case Repo.get(PivotChain, chain_id) do
      nil -> {:error, :not_found}
      chain -> Repo.delete(chain)
    end
  end

  @doc """
  Get common pivot templates.
  """
  @spec get_pivot_templates() :: list(map())
  def get_pivot_templates do
    [
      %{
        name: "Lateral Movement Investigation",
        description: "Investigate potential lateral movement from an initial compromise",
        steps: [
          %{action: "pivot_from_ip", description: "Find all agents and alerts for suspicious IP"},
          %{action: "pivot_from_user", description: "Investigate user account used"},
          %{action: "pivot_from_process", description: "Analyze processes spawned"},
          %{action: "pivot_from_file", description: "Track file execution and writes"}
        ]
      },
      %{
        name: "Malware Analysis",
        description: "Deep dive into malware execution and propagation",
        steps: [
          %{action: "pivot_from_hash", description: "Find all instances of malware hash"},
          %{action: "pivot_from_file", description: "Track file locations and executions"},
          %{action: "pivot_from_process", description: "Analyze process behavior"},
          %{action: "pivot_from_domain", description: "Identify C2 communications"}
        ]
      },
      %{
        name: "Credential Theft Investigation",
        description: "Investigate potential credential theft and misuse",
        steps: [
          %{action: "pivot_from_user", description: "Review all user activity"},
          %{action: "pivot_from_agent", description: "Check compromised endpoint"},
          %{action: "pivot_from_process", description: "Analyze credential dumping tools"},
          %{action: "pivot_from_ip", description: "Track network activity"}
        ]
      },
      %{
        name: "Data Exfiltration Hunt",
        description: "Hunt for signs of data exfiltration",
        steps: [
          %{action: "pivot_from_domain", description: "Investigate suspicious domains"},
          %{action: "pivot_from_ip", description: "Track external connections"},
          %{action: "pivot_from_file", description: "Find archived or compressed files"},
          %{action: "pivot_from_process", description: "Identify upload tools"}
        ]
      }
    ]
  end
end
