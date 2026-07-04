defmodule TamanduaServerWeb.GraphQL.Resolvers.AgentResolver do
  @moduledoc """
  GraphQL resolvers for Agent queries and fields.
  """

  require Logger

  alias TamanduaServer.{Agents, Alerts, Repo}
  alias TamanduaServer.Telemetry
  import Ecto.Query

  # Query resolvers

  def list_agents(_parent, args, %{context: context}) do
    org_id = context[:organization_id]

    # SECURITY: Never fall back to global data - organization context is required
    if is_nil(org_id) do
      {:error, "Organization context required"}
    else
      filter = Map.get(args, :filter, %{})
      pagination = Map.get(args, :pagination, %{})

      opts = [
        limit: pagination[:limit] || 50,
        offset: pagination[:offset] || 0
      ]

      # Apply status filter
      opts = if filter[:status], do: Keyword.put(opts, :status, filter[:status]), else: opts

      agents = Agents.list_agents_for_org(org_id, opts)

      # Apply additional filters in memory (could be optimized with Ecto queries)
      agents = apply_filters(agents, filter)

      {:ok, agents}
    end
  end

  def get_agent(_parent, %{id: id}, %{context: context}) do
    org_id = context[:organization_id]

    # SECURITY: Never fall back to global data - organization context is required
    if is_nil(org_id) do
      {:error, "Organization context required"}
    else
      case Agents.get_agent_for_org(org_id, id) do
        {:ok, agent} -> {:ok, agent}
        {:error, :not_found} -> {:error, "Agent not found"}
        nil -> {:error, "Agent not found"}
      end
    end
  end

  def agent_stats(_parent, _args, %{context: context}) do
    org_id = context[:organization_id]

    # SECURITY: Never fall back to global data - organization context is required
    if is_nil(org_id) do
      {:error, "Organization context required"}
    else
      total = Agents.count_agents_for_org(org_id)
      online = Agents.count_online_for_org(org_id)
      isolated = Agents.count_isolated_for_org(org_id)

      {:ok, %{
        total: total,
        online: online,
        offline: total - online - isolated,
        isolated: isolated,
        by_os: Agents.count_by_os_for_org(org_id),
        by_version: %{}
      }}
    end
  end

  # Field resolvers

  def alerts(agent, args, _resolution) do
    limit = args[:limit] || 50
    status = args[:status]
    severity = args[:severity]

    query = from(a in TamanduaServer.Alerts.Alert,
      where: a.agent_id == ^agent.id,
      order_by: [desc: a.inserted_at],
      limit: ^limit
    )

    query = if status, do: where(query, [a], a.status == ^status), else: query
    query = if severity, do: where(query, [a], a.severity == ^severity), else: query

    {:ok, Repo.all(query)}
  end

  def events(agent, args, _resolution) do
    limit = args[:limit] || 100
    event_type = args[:event_type]
    since = args[:since]

    query = from(e in TamanduaServer.Telemetry.Event,
      where: e.agent_id == ^agent.id,
      order_by: [desc: e.timestamp],
      limit: ^limit
    )

    query = if event_type, do: where(query, [e], e.event_type == ^event_type), else: query
    query = if since, do: where(query, [e], e.timestamp >= ^since), else: query

    {:ok, Repo.all(query)}
  end

  def process_tree(agent, _args, _resolution) do
    tree = Agents.get_process_tree(agent)
    {:ok, tree}
  end

  def baseline_status(agent, _args, _resolution) do
    # Get baseline learning status from Baseline module
    case TamanduaServer.Detection.Baseline.get_learning_status(agent.id) do
      {:ok, status} ->
        {:ok, %{
          status: status.status,
          started_at: status.started_at,
          ends_at: status.ends_at,
          patterns_learned: status.patterns_count,
          anomalies_detected: status.anomalies_count
        }}

      {:error, :not_found} ->
        {:ok, %{
          status: "disabled",
          started_at: nil,
          ends_at: nil,
          patterns_learned: 0,
          anomalies_detected: 0
        }}
    end
  rescue
    Ecto.NoResultsError ->
      {:ok, %{
        status: "disabled",
        started_at: nil,
        ends_at: nil,
        patterns_learned: 0,
        anomalies_detected: 0
      }}

    error ->
      Logger.warning("baseline_status resolver failed for agent=#{inspect(agent.id)}: #{inspect(error)}")
      {:ok, %{
        status: "unknown",
        started_at: nil,
        ends_at: nil,
        patterns_learned: 0,
        anomalies_detected: 0
      }}
  end

  # Mutation resolvers

  def isolate_agent(_parent, %{input: input}, %{context: context}) do
    agent_id = input.agent_id
    _reason = input[:reason] || "Isolated via GraphQL API"

    # Org-scope authorization: previously this mutation executed against ANY
    # agent_id with no tenancy check (and called the nonexistent
    # Executor.isolate_host/2, crashing at runtime). The actor is enforced by
    # the Response Executor: cross-org targets are rejected as :unauthorized.
    with {:ok, actor} <- actor_from_context(context) do
      case TamanduaServer.Response.Executor.isolate_network(agent_id, allowed_ips: [], actor: actor) do
        {:ok, _result} ->
          {:ok, %{
            success: true,
            message: "Agent isolation command executed"
          }}

        {:error, :unauthorized} ->
          # Do not leak whether the agent exists in another organization.
          {:ok, %{success: false, message: "Agent not found"}}

        {:error, reason} ->
          {:ok, %{
            success: false,
            message: "Failed to isolate: #{inspect(reason)}"
          }}
      end
    end
  end

  def unisolate_agent(_parent, %{agent_id: agent_id}, %{context: context}) do
    with {:ok, actor} <- actor_from_context(context) do
      case TamanduaServer.Response.Executor.unisolate_network(agent_id, actor: actor) do
        {:ok, _result} ->
          {:ok, %{
            success: true,
            message: "Agent de-isolation command executed"
          }}

        {:error, :unauthorized} ->
          {:ok, %{success: false, message: "Agent not found"}}

        {:error, reason} ->
          {:ok, %{
            success: false,
            message: "Failed to unisolate: #{inspect(reason)}"
          }}
      end
    end
  end

  # Build a response-executor actor from the Absinthe context. Fails closed
  # when no organization context is present (unauthenticated or misconfigured
  # callers must not be able to fire response actions).
  defp actor_from_context(context) do
    case context[:organization_id] do
      nil -> {:error, "Not authorized: missing organization context"}
      org_id -> {:ok, %{organization_id: org_id, user_id: context[:current_user_id]}}
    end
  end

  def restart_agent(_parent, %{agent_id: agent_id}, %{context: _context}) do
    case Agents.send_command(agent_id, %{type: "restart"}) do
      {:ok, :sent} ->
        {:ok, %{success: true, message: "Restart command sent"}}

      {:error, :agent_not_connected} ->
        {:ok, %{success: false, message: "Agent not connected"}}
    end
  end

  # Private helpers

  defp apply_filters(agents, filter) do
    agents
    |> maybe_filter_hostname(filter[:hostname_contains])
    |> maybe_filter_ip(filter[:ip_address])
    |> maybe_filter_os(filter[:os_type])
    |> maybe_filter_tags(filter[:tags])
    |> maybe_filter_version(filter[:version])
  end

  defp maybe_filter_hostname(agents, nil), do: agents
  defp maybe_filter_hostname(agents, pattern) do
    pattern = String.downcase(pattern)
    Enum.filter(agents, fn a ->
      hostname = Map.get(a, :hostname) || a.hostname || ""
      String.contains?(String.downcase(hostname), pattern)
    end)
  end

  defp maybe_filter_ip(agents, nil), do: agents
  defp maybe_filter_ip(agents, ip) do
    Enum.filter(agents, fn a ->
      agent_ip = Map.get(a, :ip_address) || a.ip_address || ""
      agent_ip == ip
    end)
  end

  defp maybe_filter_os(agents, nil), do: agents
  defp maybe_filter_os(agents, os) do
    Enum.filter(agents, fn a ->
      agent_os = Map.get(a, :os_type) || a.os_type || ""
      String.downcase(agent_os) == String.downcase(os)
    end)
  end

  defp maybe_filter_tags(agents, nil), do: agents
  defp maybe_filter_tags(agents, []), do: agents
  defp maybe_filter_tags(agents, tags) do
    Enum.filter(agents, fn a ->
      agent_tags = Map.get(a, :tags) || []
      Enum.any?(tags, &(&1 in agent_tags))
    end)
  end

  defp maybe_filter_version(agents, nil), do: agents
  defp maybe_filter_version(agents, version) do
    Enum.filter(agents, fn a ->
      agent_version = Map.get(a, :agent_version) || a.agent_version || ""
      agent_version == version
    end)
  end
end
