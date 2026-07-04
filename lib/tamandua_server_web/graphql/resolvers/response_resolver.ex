defmodule TamanduaServerWeb.GraphQL.Resolvers.ResponseResolver do
  @moduledoc """
  GraphQL resolvers for Response Actions.
  """

  require Logger

  alias TamanduaServer.{Agents, Accounts, Repo}
  alias TamanduaServer.Response.Executor
  alias TamanduaServer.Response.Audit
  alias TamanduaServer.Alerts.Alert
  import Ecto.Query

  # Field resolvers

  def agent(action, _args, %{context: context}) do
    if action.agent_id do
      org_id = context[:organization_id]

      # Use tenant-scoped lookup to prevent BOLA/IDOR
      case Agents.get_agent_for_org(org_id, action.agent_id) do
        {:ok, agent} -> {:ok, agent}
        {:error, :not_found} -> {:ok, nil}
      end
    else
      {:ok, nil}
    end
  end

  def requested_by(action, _args, _resolution) do
    if action.requested_by_id do
      {:ok, Accounts.get_user(action.requested_by_id)}
    else
      {:ok, nil}
    end
  end

  def alert(action, _args, _resolution) do
    if action.alert_id do
      {:ok, Repo.get(Alert, action.alert_id)}
    else
      {:ok, nil}
    end
  end

  # Query resolvers

  def response_audit(_parent, args, %{context: context}) do
    filter = Map.get(args, :filter, %{})
    pagination = Map.get(args, :pagination, %{})

    opts = [
      limit: pagination[:limit] || 50,
      offset: pagination[:offset] || 0,
      action_type: filter[:action_type],
      status: filter[:status],
      agent_id: filter[:agent_id],
      requested_by_id: filter[:requested_by_id],
      alert_id: filter[:alert_id],
      since: filter[:since],
      until: filter[:until]
    ]

    entries = Audit.list_actions(opts)
    {:ok, entries}
  rescue
    error ->
      Logger.warning("response_audit resolver failed: #{inspect(error)}")
      {:ok, []}
  end

  # Mutation resolvers

  def kill_process(_parent, %{input: input}, %{context: context}) do
    agent_id = input.agent_id
    pid = input.pid
    user_id = context[:current_user_id]

    # SECURITY: org-scoped actor is required; the Response Executor rejects
    # cross-organization targets with :unauthorized (fail closed).
    with {:ok, actor} <- actor_from_context(context) do
      opts = [
        requested_by: user_id,
        alert_id: input[:alert_id],
        force: input[:force] || false,
        reason: input[:reason],
        actor: actor
      ]

      case Executor.kill_process(agent_id, pid, opts) do
        {:ok, result} ->
          {:ok, %{
            success: true,
            agent_id: agent_id,
            pid: pid,
            process_name: result[:process_name],
            message: "Process terminated successfully",
            action_id: result[:action_id]
          }}

        {:error, :unauthorized} ->
          # Do not leak whether the agent exists in another organization.
          {:ok, %{
            success: false,
            agent_id: agent_id,
            pid: pid,
            process_name: nil,
            message: "Agent not found",
            action_id: nil
          }}

        {:error, reason} ->
          {:ok, %{
            success: false,
            agent_id: agent_id,
            pid: pid,
            process_name: nil,
            message: "Failed to kill process: #{inspect(reason)}",
            action_id: nil
          }}
      end
    end
  end

  def quarantine_file(_parent, %{input: input}, %{context: context}) do
    agent_id = input.agent_id
    path = input.path
    user_id = context[:current_user_id]

    # SECURITY: org-scoped actor is required; the Response Executor rejects
    # cross-organization targets with :unauthorized (fail closed).
    with {:ok, actor} <- actor_from_context(context) do
      opts = [
        requested_by: user_id,
        alert_id: input[:alert_id],
        reason: input[:reason],
        delete_original: input[:delete_original] || false,
        actor: actor
      ]

      case Executor.quarantine_file(agent_id, path, opts) do
        {:ok, result} ->
          {:ok, %{
            success: true,
            agent_id: agent_id,
            path: path,
            sha256: result[:sha256],
            quarantine_path: result[:quarantine_path],
            message: "File quarantined successfully",
            action_id: result[:action_id]
          }}

        {:error, :unauthorized} ->
          # Do not leak whether the agent exists in another organization.
          {:ok, %{
            success: false,
            agent_id: agent_id,
            path: path,
            sha256: nil,
            quarantine_path: nil,
            message: "Agent not found",
            action_id: nil
          }}

        {:error, reason} ->
          {:ok, %{
            success: false,
            agent_id: agent_id,
            path: path,
            sha256: nil,
            quarantine_path: nil,
            message: "Failed to quarantine file: #{inspect(reason)}",
            action_id: nil
          }}
      end
    end
  end

  def isolate_host(_parent, %{input: input}, %{context: context}) do
    agent_id = input.agent_id
    user_id = context[:current_user_id]

    opts = [
      requested_by: user_id,
      alert_id: input[:alert_id],
      reason: input[:reason],
      allow_dns: input[:allow_dns] || false,
      allow_edr: input[:allow_edr] || true
    ]

    case Executor.isolate_host(agent_id, opts) do
      {:ok, result} ->
        {:ok, %{
          success: true,
          agent_id: agent_id,
          hostname: result[:hostname],
          previous_status: result[:previous_status],
          message: "Host isolated successfully",
          action_id: result[:action_id]
        }}

      {:error, reason} ->
        {:ok, %{
          success: false,
          agent_id: agent_id,
          hostname: nil,
          previous_status: nil,
          message: "Failed to isolate host: #{inspect(reason)}",
          action_id: nil
        }}
    end
  end

  def unisolate_host(_parent, %{agent_id: agent_id}, %{context: context}) do
    user_id = context[:current_user_id]

    opts = [requested_by: user_id]

    case Executor.unisolate_host(agent_id, opts) do
      {:ok, result} ->
        {:ok, %{
          success: true,
          agent_id: agent_id,
          hostname: result[:hostname],
          previous_status: "isolated",
          message: "Host unisolated successfully",
          action_id: result[:action_id]
        }}

      {:error, reason} ->
        {:ok, %{
          success: false,
          agent_id: agent_id,
          hostname: nil,
          previous_status: nil,
          message: "Failed to unisolate host: #{inspect(reason)}",
          action_id: nil
        }}
    end
  end

  def block_ip(_parent, %{input: input}, %{context: context}) do
    ip = input.ip
    user_id = context[:current_user_id]

    opts = [
      requested_by: user_id,
      agent_id: input[:agent_id],
      direction: input[:direction] || "both",
      reason: input[:reason],
      duration_hours: input[:duration_hours]
    ]

    case Executor.block_ip(ip, opts) do
      {:ok, result} ->
        {:ok, %{
          success: true,
          value: ip,
          type: "ip",
          agents_affected: result[:agents_affected] || 1,
          message: "IP blocked successfully"
        }}

      {:error, reason} ->
        {:ok, %{
          success: false,
          value: ip,
          type: "ip",
          agents_affected: 0,
          message: "Failed to block IP: #{inspect(reason)}"
        }}
    end
  end

  def block_domain(_parent, %{input: input}, %{context: context}) do
    domain = input.domain
    user_id = context[:current_user_id]

    opts = [
      requested_by: user_id,
      agent_id: input[:agent_id],
      reason: input[:reason],
      add_to_ioc: input[:add_to_ioc] || true
    ]

    case Executor.block_domain(domain, opts) do
      {:ok, result} ->
        {:ok, %{
          success: true,
          value: domain,
          type: "domain",
          agents_affected: result[:agents_affected] || 1,
          message: "Domain blocked successfully"
        }}

      {:error, reason} ->
        {:ok, %{
          success: false,
          value: domain,
          type: "domain",
          agents_affected: 0,
          message: "Failed to block domain: #{inspect(reason)}"
        }}
    end
  end

  def scan_path(_parent, %{input: input}, %{context: context}) do
    agent_id = input.agent_id
    path = input.path
    user_id = context[:current_user_id]

    opts = [
      requested_by: user_id,
      recursive: input[:recursive] || true,
      quick_scan: input[:quick_scan] || false,
      auto_quarantine: input[:auto_quarantine] || false
    ]

    case Executor.trigger_scan(agent_id, path, opts) do
      {:ok, result} ->
        {:ok, %{
          success: true,
          agent_id: agent_id,
          path: path,
          files_scanned: result[:files_scanned] || 0,
          threats_found: result[:threats_found] || 0,
          threats: result[:threats] || [],
          action_id: result[:action_id]
        }}

      :ok ->
        # Simple success without result details
        {:ok, %{
          success: true,
          agent_id: agent_id,
          path: path,
          files_scanned: 0,
          threats_found: 0,
          threats: [],
          action_id: nil
        }}

      {:error, reason} ->
        {:ok, %{
          success: false,
          agent_id: agent_id,
          path: path,
          files_scanned: 0,
          threats_found: 0,
          threats: [],
          action_id: nil
        }}
    end
  end

  def collect_forensics(_parent, %{input: input}, %{context: context}) do
    agent_id = input.agent_id
    user_id = context[:current_user_id]

    # SECURITY: org-scoped actor is required; the Response Executor rejects
    # cross-organization targets with :unauthorized (fail closed).
    with {:ok, actor} <- actor_from_context(context) do
      opts = [
        requested_by: user_id,
        type: input[:collection_type] || "full",
        paths: input[:paths] || [],
        include_memory: input[:include_memory] || false,
        investigation_id: input[:investigation_id],
        actor: actor
      ]

      case Executor.collect_forensics(agent_id, opts) do
        {:ok, collection_id} ->
          {:ok, %{
            success: true,
            collection_id: collection_id,
            agent_id: agent_id,
            status: "in_progress",
            artifacts_count: 0,
            size_bytes: 0,
            message: "Forensics collection started"
          }}

        {:error, :unauthorized} ->
          # Do not leak whether the agent exists in another organization.
          {:ok, %{
            success: false,
            collection_id: nil,
            agent_id: agent_id,
            status: "failed",
            artifacts_count: 0,
            size_bytes: 0,
            message: "Agent not found"
          }}

        {:error, reason} ->
          {:ok, %{
            success: false,
            collection_id: nil,
            agent_id: agent_id,
            status: "failed",
            artifacts_count: 0,
            size_bytes: 0,
            message: "Failed to start collection: #{inspect(reason)}"
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
end
