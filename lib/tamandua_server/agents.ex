defmodule TamanduaServer.Agents do
  @moduledoc """
  The Agents context.

  All functions that access agent data support multi-tenancy through
  organization_id filtering. Use the tenant-scoped versions when operating
  in a multi-tenant context.
  """

  import Ecto.Query, warn: false
  require Logger
  alias TamanduaServer.Repo
  alias TamanduaServer.TenantScope

  alias TamanduaServer.Agents.Agent

  @database_presence_stale_after_seconds 120
  @mobile_database_presence_stale_after_seconds :timer.hours(24) |> div(1000)

  # ===========================================================================
  # Tenant-Scoped Functions
  # ===========================================================================

  @doc """
  Returns the list of agents for an organization.

  ## Options
  - `:status` - Filter by status (online, offline, isolated)
  - `:limit` - Maximum number of results
  - `:offset` - Offset for pagination

  ## Examples

      iex> list_agents_for_org(org_id)
      [%Agent{}, ...]
  """
  def list_agents_for_org(organization_id, opts \\ []) do
    opts = normalize_opts(opts)

    query =
      Agent
      |> TenantScope.scope_to_tenant(organization_id)
      |> order_by([a], desc: a.last_seen_at)

    query =
      if status = Keyword.get(opts, :status) do
        where(query, [a], a.status == ^to_string(status))
      else
        query
      end

    query =
      if limit = parse_positive_int(Keyword.get(opts, :limit)) do
        limit(query, ^limit)
      else
        query
      end

    query =
      if offset = parse_non_negative_int(Keyword.get(opts, :offset)) do
        offset(query, ^offset)
      else
        query
      end

    query
    |> Repo.all()
    |> deduplicate_endpoint_records()
  end

  @doc """
  Gets a single agent scoped to an organization.

  Returns `{:ok, agent}` or `{:error, :not_found}`.
  """
  def get_agent_for_org(organization_id, agent_id) do
    case TenantScope.get_scoped(Agent, organization_id, agent_id) do
      nil -> {:error, :not_found}
      agent -> {:ok, agent}
    end
  end

  @doc """
  Gets a single agent scoped to an organization, raises if not found.
  """
  def get_agent_for_org!(organization_id, agent_id) do
    TenantScope.get_scoped!(Agent, organization_id, agent_id)
  end

  @doc """
  Creates an agent for an organization.
  """
  def create_agent_for_org(organization_id, attrs) do
    %Agent{}
    |> Agent.changeset(attrs)
    |> TenantScope.put_tenant(organization_id)
    |> Repo.insert()
  end

  @doc """
  Counts agents for an organization.
  """
  def count_agents_for_org(organization_id) do
    organization_id
    |> list_all_for_org()
    |> length()
  end

  @doc """
  Counts online agents for an organization.
  """
  def count_online_for_org(organization_id) do
    organization_id
    |> list_all_for_org()
    |> Enum.count(&(normalize_status(&1) == :online))
  end

  @doc """
  Counts isolated agents for an organization.
  """
  def count_isolated_for_org(organization_id) do
    organization_id
    |> list_all_for_org()
    |> Enum.count(&(normalize_status(&1) == :isolated))
  end

  @doc """
  Counts agents by OS type for an organization.
  """
  def count_by_os_for_org(organization_id) do
    Agent
    |> TenantScope.scope_to_tenant(organization_id)
    |> group_by([a], a.os_type)
    |> select([a], {a.os_type, count(a.id)})
    |> Repo.all()
    |> Enum.into(%{})
  end

  @doc """
  Counts agents by version for an organization.
  """
  def count_by_version_for_org(organization_id) do
    Agent
    |> TenantScope.scope_to_tenant(organization_id)
    |> group_by([a], a.agent_version)
    |> select([a], {a.agent_version, count(a.id)})
    |> Repo.all()
    |> Enum.into(%{})
  end

  @doc """
  Lists all agents for an organization from both ETS registry and database.
  """
  def list_all_for_org(organization_id) do
    # Get live agents from ETS registry, filtered by org
    live_agents =
      TamanduaServer.Agents.Registry.list_all()
      |> Enum.filter(fn a -> a[:organization_id] == organization_id end)

    live_ids = MapSet.new(live_agents, & &1.agent_id)
    live_hostnames = MapSet.new(live_agents, & &1[:hostname])

    # Get offline agents from DB
    db_agents =
      try do
        Agent
        |> TenantScope.scope_to_tenant(organization_id)
        |> where([a], a.id not in ^MapSet.to_list(live_ids))
        |> order_by([a], desc: a.last_seen_at)
        |> Repo.all()
        |> Enum.map(fn a ->
          %{
            agent_id: a.id,
            hostname: a.hostname,
            ip_address: a.ip_address || "",
            os_type: a.os_type,
            os_version: a.os_version,
            agent_version: a.agent_version,
            status: database_presence_status(a),
            last_seen_at: a.last_seen_at,
            organization_id: a.organization_id
          }
        end)
        |> deduplicate_agents(live_hostnames)
      rescue
        e ->
          Logger.warning(
            "[Agents] Failed to list offline agents for org #{organization_id}: #{Exception.message(e)}"
          )

          []
      end

    (live_agents ++ db_agents)
    |> deduplicate_endpoint_records()
  end

  # ===========================================================================
  # Legacy Functions (for backward compatibility)
  # ===========================================================================

  @doc """
  Returns the list of agents.

  ## Examples

      iex> list_agents()
      [%Agent{}, ...]

  """
  def list_agents do
    Repo.all(Agent)
  end

  @doc """
  Gets a single agent.

  Raises `Ecto.NoResultsError` if the Agent does not exist.

  ## Examples

      iex> get_agent!(123)
      %Agent{}

      iex> get_agent!(456)
      ** (Ecto.NoResultsError)

  """
  def get_agent!(id), do: Repo.get!(Agent, id)

  @doc """
  Creates a agent.

  ## Examples

      iex> create_agent(%{field: value})
      {:ok, %Agent{}}

      iex> create_agent(%{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def create_agent(attrs \\ %{}) do
    %Agent{}
    |> Agent.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a agent.

  ## Examples

      iex> update_agent(agent, %{field: new_value})
      {:ok, %Agent{}}

      iex> update_agent(agent, %{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def update_agent(%Agent{} = agent, attrs) do
    agent
    |> Agent.changeset(attrs)
    |> Repo.update()
  end

  def update_runtime_capabilities(agent_id, runtime) when is_map(runtime) do
    with {:ok, agent} <- get_agent(agent_id) do
      config = Map.merge(agent.config || %{}, compact_runtime(runtime))
      update_agent(agent, %{config: config})
    end
  end

  @doc """
  Marks an agent online and refreshes `last_seen_at`.

  When `organization_id` is provided the update is tenant-scoped, which keeps
  socket lifecycle writes bound to the authenticated agent's organization.
  """
  def mark_agent_online(agent_id, organization_id \\ nil) do
    update_agent_presence(agent_id, organization_id, "online", refresh_last_seen?: true)
  end

  @doc """
  Marks an agent offline without refreshing `last_seen_at`.

  `last_seen_at` is evidence of the last successful heartbeat/telemetry path.
  Updating it during disconnect or timeout creates misleading records such as
  `status = offline` with a current `last_seen_at`, which hides stale-presence
  bugs during long benchmark runs.

  When `organization_id` is provided the update is tenant-scoped, which keeps
  socket lifecycle writes bound to the authenticated agent's organization.
  """
  def mark_agent_offline(agent_id, organization_id \\ nil) do
    update_agent_presence(agent_id, organization_id, "offline", refresh_last_seen?: false)
  end

  @doc """
  Marks database records as offline when they still say online but no live
  registry entry has refreshed them recently.

  This is a persistence safety net. Real online state should still come from
  the agent registry/socket heartbeat; the DB should not keep stale online rows
  after process crashes, deploys, or abrupt disconnects.
  """
  def mark_stale_online_agents_offline(live_agent_ids \\ [], stale_after_seconds \\ 120) do
    now = NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second)
    cutoff = NaiveDateTime.add(now, -stale_after_seconds, :second)

    live_agent_ids =
      live_agent_ids
      |> List.wrap()
      |> Enum.reject(&is_nil/1)

    query =
      Agent
      |> where([a], a.status == "online")
      |> where(
        [a],
        is_nil(a.last_seen_at) or a.last_seen_at < ^cutoff
      )
      |> where(
        [a],
        not fragment(
          "lower(coalesce(?, '')) in ('android', 'ios') or coalesce(?->>'source', '') = 'tamandua_mobile' or coalesce(?, ARRAY[]::varchar[]) @> ARRAY['mobile_endpoint']::varchar[]",
          a.os_type,
          a.config,
          a.tags
        )
      )
      |> maybe_exclude_live_presence_ids(live_agent_ids)

    case Repo.update_all(query, set: [status: "offline", updated_at: now]) do
      {count, _} when count > 0 ->
        Logger.info("[Agents] Marked #{count} stale DB-online agent record(s) offline")
        {:ok, count}

      {0, _} ->
        {:ok, 0}
    end
  rescue
    e ->
      Logger.warning(
        "[Agents] Failed to mark stale online agents offline: #{Exception.message(e)}"
      )

      {:error, :update_failed}
  end

  defp update_agent_presence(agent_id, organization_id, status, opts) do
    now = NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second)

    query =
      Agent
      |> where([a], a.id == ^agent_id)
      |> maybe_scope_presence_update(organization_id)

    updates =
      if Keyword.fetch!(opts, :refresh_last_seen?) do
        [status: status, last_seen_at: now, updated_at: now]
      else
        [status: status, updated_at: now]
      end

    case Repo.update_all(query, set: updates) do
      {count, _} when count > 0 -> :ok
      {0, _} -> {:error, :not_found}
    end
  rescue
    Ecto.Query.CastError ->
      {:error, :invalid_id}

    e ->
      Logger.warning(
        "[Agents] Failed to mark agent #{agent_id} #{status}: #{Exception.message(e)}"
      )

      {:error, :update_failed}
  end

  defp maybe_scope_presence_update(query, nil), do: query

  defp maybe_scope_presence_update(query, organization_id),
    do: where(query, [a], a.organization_id == ^organization_id)

  defp maybe_exclude_live_presence_ids(query, []), do: query

  defp maybe_exclude_live_presence_ids(query, live_agent_ids),
    do: where(query, [a], a.id not in ^live_agent_ids)

  defp compact_runtime(runtime) do
    runtime
    |> Enum.reject(fn {_key, value} -> value in [nil, [], %{}] end)
    |> Enum.into(%{})
  end

  @doc """
  Deletes a agent.

  ## Examples

      iex> delete_agent(agent)
      {:ok, %Agent{}}

      iex> delete_agent(agent)
      {:error, %Ecto.Changeset{}}

  """
  def delete_agent(%Agent{} = agent) do
    Repo.delete(agent)
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking agent changes.

  ## Examples

      iex> change_agent(agent)
      %Ecto.Changeset{data: %Agent{}}

  """
  def change_agent(%Agent{} = agent, attrs \\ %{}) do
    Agent.changeset(agent, attrs)
  end

  @doc """
  Counts total agents from the ETS registry.
  """
  def count_agents do
    TamanduaServer.Agents.Registry.list_all() |> length()
  end

  @doc """
  Alias for count_agents.
  """
  def count_all, do: count_agents()

  @doc """
  Counts online agents from the ETS registry.
  """
  def count_online do
    TamanduaServer.Agents.Registry.list_by_status(:online) |> length()
  end

  @doc """
  Counts isolated agents from the ETS registry.
  """
  def count_isolated do
    TamanduaServer.Agents.Registry.list_by_status(:isolated) |> length()
  end

  @doc """
  Lists all agents from the ETS registry (live connected agents).
  """
  def list_all do
    # Get live agents from ETS registry
    live_agents = TamanduaServer.Agents.Registry.list_all()
    live_ids = MapSet.new(live_agents, & &1.agent_id)
    live_hostnames = MapSet.new(live_agents, & &1[:hostname])

    # Also get agents from DB that may be offline (not in ETS)
    db_agents =
      try do
        import Ecto.Query

        Repo.all(
          from(a in Agent,
            where: a.id not in ^MapSet.to_list(live_ids),
            order_by: [desc: a.last_seen_at]
          )
        )
        |> Enum.map(fn a ->
          %{
            agent_id: a.id,
            hostname: a.hostname,
            ip_address: a.ip_address || "",
            os_type: a.os_type,
            os_version: a.os_version,
            agent_version: a.agent_version,
            status: database_presence_status(a),
            last_seen_at: a.last_seen_at
          }
        end)
        |> deduplicate_agents(live_hostnames)
      rescue
        e ->
          Logger.warning(
            "[Agents] Failed to list offline agents from DB: #{Exception.message(e)}"
          )

          []
      end

    (live_agents ++ db_agents)
    |> deduplicate_endpoint_records()
  end

  # Deduplicate offline DB agents: skip agents whose hostname is already online,
  # and keep only the most recently seen entry per hostname among offline agents.
  defp deduplicate_agents(db_agents, live_hostnames) do
    db_agents
    |> Enum.reject(fn a -> MapSet.member?(live_hostnames, a.hostname) end)
    |> Enum.uniq_by(& &1.hostname)
  end

  defp deduplicate_endpoint_records(agents) when is_list(agents) do
    agents
    |> Enum.sort_by(&endpoint_sort_key/1, :desc)
    |> Enum.uniq_by(&endpoint_identity/1)
  end

  defp endpoint_identity(agent) do
    machine_id = get_agent_field(agent, :machine_id)
    hostname = get_agent_field(agent, :hostname)
    org_id = get_agent_field(agent, :organization_id)

    cond do
      is_binary(machine_id) and byte_size(machine_id) > 0 ->
        {:machine_id, org_id, machine_id}

      is_binary(hostname) and hostname != "" ->
        {:hostname, org_id, String.downcase(hostname)}

      true ->
        {:agent_id, get_agent_field(agent, :agent_id) || get_agent_field(agent, :id)}
    end
  end

  defp endpoint_sort_key(agent) do
    status_rank =
      case normalize_status(agent) do
        :online -> 3
        :isolated -> 2
        :degraded -> 1
        _ -> 0
      end

    last_seen =
      agent
      |> get_agent_field(:last_seen_at)
      |> datetime_sort_value()

    {status_rank, last_seen}
  end

  defp normalize_status(agent) do
    agent
    |> get_agent_field(:status)
    |> to_string()
    |> String.downcase()
    |> case do
      "online" -> :online
      "isolated" -> :isolated
      "degraded" -> :degraded
      _ -> :offline
    end
  end

  defp database_presence_status(%Agent{status: status}) when status == "isolated", do: :isolated

  defp database_presence_status(%Agent{status: "online", last_seen_at: last_seen_at} = agent) do
    # Dashboard and mTLS ingestion can run in separate BEAM runtimes. In that
    # shape the local ETS registry may be empty while the ingestion runtime has
    # just persisted a heartbeat. Treat only recent persisted presence as live;
    # stale online rows are still collapsed to offline below.
    if recent_presence?(last_seen_at, presence_stale_after_seconds(agent)),
      do: :online,
      else: :offline
  end

  defp database_presence_status(_agent), do: :offline

  defp presence_stale_after_seconds(%Agent{} = agent) do
    if mobile_agent?(agent),
      do: @mobile_database_presence_stale_after_seconds,
      else: @database_presence_stale_after_seconds
  end

  defp mobile_agent?(%Agent{os_type: os_type, config: config, tags: tags}) do
    os = os_type |> to_string() |> String.downcase()
    source = config |> normalize_map() |> Map.get("source") |> to_string()
    tags = tags || []

    String.contains?(os, "android") or String.contains?(os, "ios") or
      source == "tamandua_mobile" or "mobile_endpoint" in tags
  end

  defp normalize_map(map) when is_map(map) do
    Map.new(map, fn
      {key, value} when is_atom(key) -> {Atom.to_string(key), value}
      {key, value} -> {key, value}
    end)
  end

  defp normalize_map(_), do: %{}

  defp recent_presence?(nil, _stale_after_seconds), do: false

  defp recent_presence?(%NaiveDateTime{} = last_seen_at, stale_after_seconds) do
    cutoff =
      NaiveDateTime.utc_now()
      |> NaiveDateTime.truncate(:second)
      |> NaiveDateTime.add(-stale_after_seconds, :second)

    NaiveDateTime.compare(last_seen_at, cutoff) != :lt
  end

  defp recent_presence?(%DateTime{} = last_seen_at, stale_after_seconds) do
    cutoff = DateTime.add(DateTime.utc_now(), -stale_after_seconds, :second)
    DateTime.compare(last_seen_at, cutoff) != :lt
  end

  defp recent_presence?(_last_seen_at, _stale_after_seconds), do: false

  defp datetime_sort_value(%NaiveDateTime{} = dt), do: NaiveDateTime.to_gregorian_seconds(dt)
  defp datetime_sort_value(%DateTime{} = dt), do: DateTime.to_unix(dt)
  defp datetime_sort_value(nil), do: 0

  defp datetime_sort_value(value) when is_integer(value), do: value

  defp datetime_sort_value(value) when is_binary(value) do
    with {:ok, dt, _} <- DateTime.from_iso8601(value) do
      DateTime.to_unix(dt)
    else
      _ -> 0
    end
  end

  defp datetime_sort_value(_), do: 0

  defp get_agent_field(%Agent{} = agent, field), do: Map.get(agent, field)

  defp get_agent_field(agent, field) when is_map(agent),
    do: Map.get(agent, field) || Map.get(agent, to_string(field))

  defp get_agent_field(_, _), do: nil

  defp normalize_opts(opts) when is_map(opts) do
    opts
    |> Enum.map(fn {key, value} -> {normalize_opt_key(key), value} end)
    |> Keyword.new()
  end

  defp normalize_opts(opts) when is_list(opts), do: opts
  defp normalize_opts(_), do: []

  defp normalize_opt_key(key) when is_atom(key), do: key
  defp normalize_opt_key("status"), do: :status
  defp normalize_opt_key("limit"), do: :limit
  defp normalize_opt_key("offset"), do: :offset
  defp normalize_opt_key(key) when is_binary(key), do: key
  defp normalize_opt_key(key), do: key

  defp parse_positive_int(value) when is_integer(value) and value > 0, do: value

  defp parse_positive_int(value) when is_binary(value) do
    case Integer.parse(value) do
      {int, ""} when int > 0 -> int
      _ -> nil
    end
  end

  defp parse_positive_int(_), do: nil

  defp parse_non_negative_int(value) when is_integer(value) and value >= 0, do: value

  defp parse_non_negative_int(value) when is_binary(value) do
    case Integer.parse(value) do
      {int, ""} when int >= 0 -> int
      _ -> nil
    end
  end

  defp parse_non_negative_int(_), do: nil

  @doc """
  Gets a single agent by id, returns nil if not found.
  First checks the ETS Registry, then falls back to database.
  """
  def get(id) do
    case TamanduaServer.Agents.Registry.get(id) do
      {:ok, agent} ->
        agent

      {:error, :not_found} ->
        # Try database only if id looks like a UUID
        if uuid?(id), do: Repo.get(Agent, id), else: nil
    end
  end

  defp uuid?(string) when is_binary(string) do
    case Ecto.UUID.cast(string) do
      {:ok, _} -> true
      :error -> false
    end
  end

  defp uuid?(_), do: false

  @doc """
  Gets process tree for an agent.
  Returns a hierarchical list of process nodes.

  For large process trees (>500 processes), returns only top-level processes
  with a `truncated: true` flag. Use the paginated `list_processes/2` and
  `get_process_children/3` functions for lazy loading in those cases.
  """
  def get_process_tree(agent) when is_struct(agent, Agent) do
    get_process_tree(agent.id)
  end

  def get_process_tree(agent) when is_map(agent) do
    # Handle Registry maps
    get_process_tree(agent[:agent_id] || agent[:id])
  end

  def get_process_tree(agent_id) when is_binary(agent_id) do
    alias TamanduaServer.Detection.Correlator

    case Correlator.get_process_tree(agent_id) do
      {:ok, graph} ->
        build_tree_from_graph(graph)

      {:error, :not_found} ->
        {:ok, []}
    end
  end

  def get_process_tree(_), do: {:ok, []}

  @doc """
  Returns a flat, paginated list of processes for an agent with parent_pid info.

  ## Options
  - `:limit` - Max results per page (default 100)
  - `:offset` - Offset for pagination (default 0)

  Returns `{:ok, %{processes: [...], total: N, limit: L, offset: O}}` or
  `{:error, :not_found}`.
  """
  def list_processes(agent_id, opts \\ []) when is_binary(agent_id) do
    alias TamanduaServer.Detection.Correlator

    limit = Keyword.get(opts, :limit, 100) |> min(500) |> max(1)
    offset = Keyword.get(opts, :offset, 0) |> max(0)

    case Correlator.get_process_tree(agent_id) do
      {:ok, graph} ->
        vertices = Graph.vertices(graph)
        total = length(vertices)

        processes =
          vertices
          |> Enum.sort()
          |> Enum.drop(offset)
          |> Enum.take(limit)
          |> Enum.map(fn pid -> build_flat_process_node(graph, pid) end)
          |> Enum.filter(&(&1 != nil))

        {:ok, %{processes: processes, total: total, limit: limit, offset: offset}}

      {:error, :not_found} ->
        {:ok, %{processes: [], total: 0, limit: limit, offset: offset}}
    end
  end

  @doc """
  Returns direct children of a process for lazy tree expansion.

  ## Options
  - `:limit` - Max children to return (default 200)
  - `:offset` - Offset for pagination (default 0)

  Returns `{:ok, %{children: [...], total: N, parent_pid: pid}}` or
  `{:error, :not_found}`.
  """
  def get_process_children(agent_id, pid, opts \\ []) when is_binary(agent_id) do
    alias TamanduaServer.Detection.Correlator

    limit = Keyword.get(opts, :limit, 200) |> min(500) |> max(1)
    offset = Keyword.get(opts, :offset, 0) |> max(0)

    case Correlator.get_process_tree(agent_id) do
      {:ok, graph} ->
        if Graph.has_vertex?(graph, pid) do
          all_children = Graph.out_neighbors(graph, pid) |> Enum.sort()
          total = length(all_children)

          children =
            all_children
            |> Enum.drop(offset)
            |> Enum.take(limit)
            |> Enum.map(fn child_pid ->
              node = build_flat_process_node(graph, child_pid)

              if node do
                child_count = Graph.out_neighbors(graph, child_pid) |> length()
                Map.put(node, :child_count, child_count)
              end
            end)
            |> Enum.filter(&(&1 != nil))

          {:ok, %{children: children, total: total, parent_pid: pid}}
        else
          {:error, :not_found}
        end

      {:error, :not_found} ->
        {:error, :not_found}
    end
  end

  @doc """
  Returns the ancestor chain from a process up to the root (init/PID 0).

  Returns `{:ok, ancestors}` where ancestors is a list ordered from the
  immediate parent up to the root, or `{:error, :not_found}`.
  """
  def get_process_ancestors(agent_id, pid) when is_binary(agent_id) do
    alias TamanduaServer.Detection.Correlator

    case Correlator.get_process_tree(agent_id) do
      {:ok, graph} ->
        if Graph.has_vertex?(graph, pid) do
          ancestors = trace_ancestors(graph, pid, MapSet.new(), [])
          {:ok, ancestors}
        else
          {:error, :not_found}
        end

      {:error, :not_found} ->
        {:error, :not_found}
    end
  end

  # Trace ancestors up the tree, guarding against cycles
  defp trace_ancestors(graph, pid, visited, acc) do
    case Graph.in_neighbors(graph, pid) do
      [parent | _] when not is_nil(parent) ->
        if MapSet.member?(visited, parent) do
          # Cycle detected, stop
          acc
        else
          node = build_flat_process_node(graph, parent)

          if node do
            trace_ancestors(graph, parent, MapSet.put(visited, parent), acc ++ [node])
          else
            acc
          end
        end

      _ ->
        acc
    end
  end

  # Build a flat process node (no recursive children) from the graph
  defp build_flat_process_node(_graph, pid) when is_nil(pid), do: nil

  defp build_flat_process_node(graph, pid) do
    if Graph.has_vertex?(graph, pid) do
      labels = Graph.vertex_labels(graph, pid)
      info = List.first(labels) || %{}

      child_count = Graph.out_neighbors(graph, pid) |> length()

      ppid =
        case Graph.in_neighbors(graph, pid) do
          [parent | _] when not is_nil(parent) -> parent
          _ -> 0
        end

      %{
        pid: pid || 0,
        ppid: ppid || 0,
        name:
          case to_string(info[:name] || "") do
            "" -> "Process_#{pid || 0}"
            n -> n
          end,
        path: to_string(info[:path] || ""),
        cmdline: to_string(info[:cmdline] || ""),
        user: to_string(info[:user] || "unknown"),
        start_time: info[:start_time],
        sha256: info[:sha256],
        is_elevated: !!info[:is_elevated],
        is_signed: !!info[:is_signed],
        signer: info[:signer],
        child_count: child_count,
        children: [],
        detections: [],
        cpu_usage: info[:cpu_usage],
        memory_bytes: info[:memory_bytes],
        company_name: info[:company_name],
        file_description: info[:file_description],
        product_name: info[:product_name],
        file_version: info[:file_version],
        entropy: info[:entropy]
      }
    else
      nil
    end
  end

  # Build a hierarchical tree from the process graph with timeout protection.
  # For large graphs (>500 processes), returns only top-level nodes with truncated flag.
  defp build_tree_from_graph(graph) do
    require Logger

    vertex_count = Graph.vertices(graph) |> length()

    try do
      task =
        Task.async(fn ->
          if vertex_count > 500 do
            # Large graph: return top-level only with truncation flag
            build_top_level_only(graph, vertex_count)
          else
            {:ok, do_build_tree_from_graph(graph)}
          end
        end)

      case Task.yield(task, 5000) || Task.shutdown(task) do
        {:ok, result} ->
          result

        nil ->
          Logger.warning(
            "Process tree building timed out after 5 seconds (#{vertex_count} processes)"
          )

          {:error, :timeout}
      end
    rescue
      e ->
        Logger.error("Error building process tree: #{inspect(e)}")
        {:error, :build_failed}
    end
  end

  # For large trees, return only top-level processes without recursing into children.
  # Each node includes a child_count so the frontend knows it can lazy-load.
  defp build_top_level_only(graph, total_count) do
    vertices = Graph.vertices(graph)

    roots =
      vertices
      |> Enum.filter(fn pid ->
        case Graph.in_neighbors(graph, pid) do
          [] -> true
          parents -> Enum.all?(parents, fn p -> p not in vertices end)
        end
      end)

    top_level =
      Enum.map(roots, fn root_pid ->
        node = build_flat_process_node(graph, root_pid)

        if node do
          child_count = Graph.out_neighbors(graph, root_pid) |> length()
          Map.put(node, :child_count, child_count)
        end
      end)
      |> Enum.filter(&(&1 != nil))

    {:ok, top_level, %{truncated: true, total_processes: total_count}}
  end

  defp do_build_tree_from_graph(graph) do
    # Find root processes (those with no parents or parent not in graph)
    vertices = Graph.vertices(graph)

    roots =
      vertices
      |> Enum.filter(fn pid ->
        case Graph.in_neighbors(graph, pid) do
          [] -> true
          parents -> Enum.all?(parents, fn p -> p not in vertices end)
        end
      end)

    # Build tree starting from each root
    Enum.map(roots, fn root_pid ->
      build_process_node(graph, root_pid)
    end)
    |> Enum.filter(&(&1 != nil))
  end

  defp build_process_node(_graph, pid) when is_nil(pid), do: nil

  defp build_process_node(graph, pid) do
    # Guard against invalid PIDs
    if Graph.has_vertex?(graph, pid) do
      # Get vertex labels (process info)
      labels = Graph.vertex_labels(graph, pid)
      info = List.first(labels) || %{}

      # Get children
      children =
        Graph.out_neighbors(graph, pid)
        |> Enum.map(fn child_pid -> build_process_node(graph, child_pid) end)
        |> Enum.filter(&(&1 != nil))

      # Find parent PID with nil guard
      ppid =
        case Graph.in_neighbors(graph, pid) do
          [parent | _] when not is_nil(parent) -> parent
          _ -> 0
        end

      %{
        pid: pid || 0,
        ppid: ppid || 0,
        name:
          case to_string(info[:name] || "") do
            "" -> "Process_#{pid || 0}"
            n -> n
          end,
        path: to_string(info[:path] || ""),
        cmdline: to_string(info[:cmdline] || ""),
        user: to_string(info[:user] || "unknown"),
        start_time: info[:start_time],
        sha256: info[:sha256],
        is_elevated: !!info[:is_elevated],
        is_signed: !!info[:is_signed],
        signer: info[:signer],
        child_count: length(children),
        children: children || [],
        detections: [],
        # Extended PE metadata and resource usage
        cpu_usage: info[:cpu_usage],
        memory_bytes: info[:memory_bytes],
        company_name: info[:company_name],
        file_description: info[:file_description],
        product_name: info[:product_name],
        file_version: info[:file_version],
        entropy: info[:entropy]
      }
    else
      nil
    end
  end

  @doc """
  Count agents by OS type.
  """
  def count_by_os do
    from(a in Agent,
      group_by: a.os_type,
      select: {a.os_type, count(a.id)}
    )
    |> Repo.all()
    |> Enum.into(%{})
  end

  @doc """
  Count agents by version.
  """
  def count_by_version do
    from(a in Agent,
      group_by: a.agent_version,
      select: {a.agent_version, count(a.id)}
    )
    |> Repo.all()
    |> Enum.into(%{})
  end

  @doc """
  Gets a single agent, returning {:ok, agent} or {:error, :not_found}.
  """
  def get_agent(id) do
    case Repo.get(Agent, id) do
      nil -> {:error, :not_found}
      agent -> {:ok, agent}
    end
  end

  @doc """
  Sends a command to an agent.
  """
  def send_command(agent_id, command) when is_map(command) do
    # Find the agent's WebSocket connection via Registry
    case Registry.lookup(TamanduaServer.Agents.Registry, agent_id) do
      [{pid, _}] ->
        send(pid, {:send_command, command})
        {:ok, :sent}

      [] ->
        {:error, :agent_not_connected}
    end
  end

  # ===========================================================================
  # Isolation Status Management
  # ===========================================================================

  @doc """
  Update the isolation status for an agent.

  Stores the detailed isolation status JSON from the agent and optionally
  updates the agent status to "isolated" or back to "online".

  Broadcasts the isolation state change via PubSub for real-time dashboard updates.
  """
  def update_isolation_status(agent_id, isolation_status) when is_map(isolation_status) do
    state = Map.get(isolation_status, "state", "disabled")

    agent_status =
      case state do
        s when s in ["isolated", "partial"] -> "isolated"
        "disabled" -> "online"
        # don't change status on "failed"
        _ -> nil
      end

    attrs =
      %{isolation_status: isolation_status}
      |> then(fn attrs ->
        if agent_status, do: Map.put(attrs, :status, agent_status), else: attrs
      end)

    with {:ok, agent} <- get_agent_safe(agent_id),
         {:ok, updated} <- update_agent(agent, attrs) do
      # Broadcast isolation state change via PubSub
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "agent:#{agent_id}",
        {:isolation_state_changed,
         %{
           agent_id: agent_id,
           isolation_status: isolation_status,
           agent_status: updated.status,
           timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
         }}
      )

      # Also broadcast to the global agents topic for dashboard
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "agents:isolation",
        {:isolation_state_changed,
         %{
           agent_id: agent_id,
           hostname: updated.hostname,
           state: state,
           method: Map.get(isolation_status, "method"),
           timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
         }}
      )

      {:ok, updated}
    end
  end

  @doc """
  Get the current isolation status for an agent.

  Returns `{:ok, status_map}` or `{:error, reason}`.
  """
  def get_isolation_status(agent_id) do
    case get_agent_safe(agent_id) do
      {:ok, %Agent{isolation_status: nil}} ->
        {:ok,
         %{
           "state" => "disabled",
           "method" => nil,
           "rules_applied" => [],
           "allowlisted_connections" => [],
           "connectivity_test" => %{
             "server_reachable" => false,
             "dns_works" => false,
             "internet_blocked" => false,
             "server_latency_ms" => nil,
             "details" => nil
           },
           "applied_at" => nil,
           "filter_count" => 0,
           "error" => nil
         }}

      {:ok, %Agent{isolation_status: status}} ->
        {:ok, status}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Clear the isolation status for an agent (after de-isolation).
  """
  def clear_isolation_status(agent_id) do
    case get_agent_safe(agent_id) do
      {:ok, agent} ->
        update_agent(agent, %{
          isolation_status: nil,
          status: "online",
          isolation_expires_at: nil,
          previous_network_state: nil
        })

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Set isolation exceptions for an agent.

  Exceptions are whitelisted connections that bypass isolation rules.
  Examples:
  - %{type: "ip", value: "10.0.0.5"}
  - %{type: "port", value: 443}
  - %{type: "domain", value: "updates.company.com"}
  """
  def set_isolation_exceptions(agent_id, exceptions) when is_list(exceptions) do
    case get_agent_safe(agent_id) do
      {:ok, agent} ->
        update_agent(agent, %{isolation_exceptions: exceptions})

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Get isolation exceptions for an agent.
  Returns empty list if none are set.
  """
  def get_isolation_exceptions(agent_id) do
    case get_agent_safe(agent_id) do
      {:ok, agent} ->
        {:ok, agent.isolation_exceptions || []}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Add an isolation exception to an agent's existing list.
  """
  def add_isolation_exception(agent_id, exception) when is_map(exception) do
    case get_agent_safe(agent_id) do
      {:ok, agent} ->
        current_exceptions = agent.isolation_exceptions || []
        new_exceptions = [exception | current_exceptions] |> Enum.uniq()
        update_agent(agent, %{isolation_exceptions: new_exceptions})

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Remove an isolation exception from an agent's list.
  """
  def remove_isolation_exception(agent_id, exception) when is_map(exception) do
    case get_agent_safe(agent_id) do
      {:ok, agent} ->
        current_exceptions = agent.isolation_exceptions || []
        new_exceptions = Enum.reject(current_exceptions, &(&1 == exception))
        update_agent(agent, %{isolation_exceptions: new_exceptions})

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Process an isolation status update from a heartbeat payload.

  This is called by the agent channel when the heartbeat includes
  isolation data, keeping the server's view up to date.
  """
  def process_heartbeat_isolation(agent_id, isolation_payload) when is_map(isolation_payload) do
    isolated = Map.get(isolation_payload, "isolated", false)
    state = Map.get(isolation_payload, "state", "disabled")

    # Only update if there's meaningful isolation data
    if isolated do
      # Update the agent record with heartbeat isolation data
      case get_agent_safe(agent_id) do
        {:ok, agent} ->
          # Merge heartbeat data into existing isolation_status
          current = agent.isolation_status || %{}

          updated =
            Map.merge(current, %{
              "state" => state,
              "method" => Map.get(isolation_payload, "method", Map.get(current, "method")),
              "filter_count" =>
                Map.get(isolation_payload, "filter_count", Map.get(current, "filter_count")),
              "server_reachable" => Map.get(isolation_payload, "server_reachable"),
              "dns_works" => Map.get(isolation_payload, "dns_works"),
              "internet_blocked" => Map.get(isolation_payload, "internet_blocked"),
              "last_heartbeat_at" => DateTime.utc_now() |> DateTime.to_iso8601()
            })

          update_agent(agent, %{isolation_status: updated})

        {:error, _} ->
          :ok
      end
    else
      # Agent reports it's not isolated -- check if we thought it was
      case get_agent_safe(agent_id) do
        {:ok, %Agent{status: "isolated"} = agent} ->
          # Agent says not isolated but we have it as isolated -- clear
          update_agent(agent, %{
            isolation_status: nil,
            status: "online"
          })

        _ ->
          :ok
      end
    end
  end

  # Safe get_agent that returns {:ok, agent} or {:error, :not_found}
  defp get_agent_safe(agent_id) do
    case Repo.get(Agent, agent_id) do
      nil -> {:error, :not_found}
      agent -> {:ok, agent}
    end
  rescue
    Ecto.Query.CastError -> {:error, :invalid_id}
    _ -> {:error, :not_found}
  end

  # ===========================================================================
  # Agent Credential Management
  # ===========================================================================

  alias TamanduaServer.Agents.Credentials

  @doc """
  Issue a new credential for an agent.

  This creates a DB-backed credential record that will be validated
  on socket connect. The returned jti should be included in the JWT
  token issued to the agent.

  ## Options
  - `:ttl_hours` - Token lifetime in hours (default: 24)
  - `:ip_address` - IP address where credential was issued
  - `:issued_by_user_id` - User who issued the credential

  ## Examples

      iex> issue_agent_credential(agent.id, agent.organization_id)
      {:ok, "abc123xyz", %AgentCredential{}}
  """
  def issue_agent_credential(agent_id, organization_id, opts \\ []) do
    Credentials.issue_credential(agent_id, organization_id, opts)
  end

  @doc """
  Revoke an agent credential by jti.

  This immediately prevents the credential from being used.
  Connected agents using this credential will be disconnected on
  their next validation (e.g., reconnect or heartbeat).

  ## Examples

      iex> revoke_agent_credential("abc123xyz", "compromised")
      {:ok, %AgentCredential{}}
  """
  def revoke_agent_credential(jti, reason \\ "manual_revocation") do
    Credentials.revoke(jti, reason)
  end

  @doc """
  Revoke all credentials for an agent.

  Use this when decommissioning an agent or if the agent is compromised.

  ## Examples

      iex> revoke_all_agent_credentials(agent_id, "agent_decommissioned")
      {:ok, 3}
  """
  def revoke_all_agent_credentials(agent_id, reason \\ "agent_credentials_revoked") do
    Credentials.revoke_all_for_agent(agent_id, reason)
  end

  @doc """
  Revoke all credentials for an organization.

  Use this when an organization is suspended or compromised.
  This is a security emergency action.

  ## Examples

      iex> revoke_all_org_credentials(org_id, "organization_suspended")
      {:ok, 42}
  """
  def revoke_all_org_credentials(organization_id, reason \\ "organization_credentials_revoked") do
    Credentials.revoke_all_for_organization(organization_id, reason)
  end

  @doc """
  List active credentials for an agent.

  ## Examples

      iex> list_agent_credentials(agent_id)
      [%AgentCredential{}, ...]
  """
  def list_agent_credentials(agent_id) do
    Credentials.list_active_for_agent(agent_id)
  end

  @doc """
  Get credential statistics for an agent.

  Returns a map with:
  - total: Total credentials ever issued
  - active: Currently valid credentials
  - revoked: Revoked credentials
  - expired: Expired (non-revoked) credentials
  - total_uses: Total successful authentications
  - last_used: Info about most recent use

  ## Examples

      iex> get_agent_credential_stats(agent_id)
      %{total: 5, active: 1, revoked: 2, expired: 2, total_uses: 150, ...}
  """
  def get_agent_credential_stats(agent_id) do
    Credentials.get_stats(agent_id)
  end

  @doc """
  Validate a credential by jti.

  This does NOT update usage tracking. Use for quick checks.

  ## Examples

      iex> validate_agent_credential("abc123xyz", agent_id, org_id)
      {:ok, %AgentCredential{}}

      iex> validate_agent_credential("revoked_jti", agent_id, org_id)
      {:error, :credential_revoked}
  """
  def validate_agent_credential(jti, agent_id, organization_id) do
    Credentials.validate(jti, agent_id, organization_id)
  end

  @doc """
  Check if a credential is valid (exists and not revoked/expired).

  ## Examples

      iex> credential_valid?("abc123xyz")
      true

      iex> credential_valid?("nonexistent")
      false
  """
  def credential_valid?(jti) do
    Credentials.valid?(jti)
  end

  @doc """
  Clean up expired credentials older than the specified days.

  This is typically called by a scheduled job.

  ## Examples

      iex> cleanup_expired_credentials(30)
      {:ok, 15}
  """
  def cleanup_expired_credentials(older_than_days \\ 30) do
    Credentials.cleanup_expired(older_than_days)
  end
end
