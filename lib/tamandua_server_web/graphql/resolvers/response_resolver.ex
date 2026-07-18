defmodule TamanduaServerWeb.GraphQL.Resolvers.ResponseResolver do
  @moduledoc """
  GraphQL resolvers for Response Actions.
  """

  require Logger

  alias TamanduaServer.{Agents, Alerts, Investigations, Repo, Response}
  alias TamanduaServer.Accounts.User
  alias TamanduaServer.Response.Executor
  alias TamanduaServer.Alerts.Alert

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

  def requested_by(action, _args, %{context: context}) do
    if action.executed_by_id && context[:organization_id] do
      {:ok,
       Repo.get_by(User,
         id: action.executed_by_id,
         organization_id: context[:organization_id]
       )}
    else
      {:ok, nil}
    end
  end

  def alert(action, _args, %{context: context}) do
    if action.alert_id && context[:organization_id] do
      {:ok,
       Repo.get_by(Alert,
         id: action.alert_id,
         organization_id: context[:organization_id]
       )}
    else
      {:ok, nil}
    end
  end

  # Query resolvers

  def response_audit(_parent, args, %{context: context}) do
    filter = Map.get(args, :filter, %{})
    pagination = Map.get(args, :pagination, %{})

    entries =
      Response.list_actions(%{
        organization_id: context[:organization_id],
        limit: pagination[:limit] || 50,
        offset: pagination[:offset] || 0,
        action_type: filter[:action_type],
        status: filter[:status],
        agent_id: filter[:agent_id],
        requested_by_id: filter[:requested_by_id],
        alert_id: filter[:alert_id],
        since: filter[:since],
        until: filter[:until]
      })

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

    # SECURITY: org-scoped actor is required; the Response Executor rejects
    # cross-organization targets with :unauthorized (fail closed).
    with {:ok, actor} <- actor_from_context(context),
         {:ok, alert_id} <- alert_id_for_org(input[:alert_id], actor.organization_id) do
      opts = [
        alert_id: alert_id,
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
            action_id: result[:action_id],
            audit_status: result[:audit_status]
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

    # SECURITY: org-scoped actor is required; the Response Executor rejects
    # cross-organization targets with :unauthorized (fail closed).
    with {:ok, actor} <- actor_from_context(context),
         {:ok, alert_id} <- alert_id_for_org(input[:alert_id], actor.organization_id) do
      opts = [
        alert_id: alert_id,
        reason: input[:reason],
        # The Executor's quarantine option key is `:delete_after` (not
        # `:delete_original`) — map the GraphQL input onto the real API.
        delete_after: input[:delete_original] || false,
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
            action_id: result[:action_id],
            audit_status: result[:audit_status]
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

    # Real API: `Executor.isolate_host/1` is a zero-option alias for
    # `Executor.isolate_network/2`, which is the actual isolation entry point
    # and supports the `:actor` option for org-scoped authorization (fail
    # closed). The GraphQL inputs `allow_dns`/`allow_edr`/`reason` are NOT
    # supported by the Executor and are intentionally ignored.
    with {:ok, actor} <- actor_from_context(context) do
      case Executor.isolate_network(agent_id, actor: actor) do
        {:ok, result} ->
          {:ok, %{
            success: true,
            agent_id: agent_id,
            hostname: result[:hostname],
            previous_status: result[:previous_status],
            message: "Host isolated successfully",
            action_id: result[:action_id]
          }}

        {:error, :unauthorized} ->
          # Do not leak whether the agent exists in another organization.
          {:ok, %{
            success: false,
            agent_id: agent_id,
            hostname: nil,
            previous_status: nil,
            message: "Agent not found",
            action_id: nil
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
  end

  def unisolate_host(_parent, %{agent_id: agent_id}, %{context: context}) do
    # Real API: there is no `Executor.unisolate_host/2` — de-isolation is
    # `Executor.unisolate_network/2` (supports `:actor` for org scoping,
    # fail closed).
    with {:ok, actor} <- actor_from_context(context) do
      case Executor.unisolate_network(agent_id, actor: actor) do
        {:ok, result} ->
          {:ok, %{
            success: true,
            agent_id: agent_id,
            hostname: result[:hostname],
            previous_status: "isolated",
            message: "Host unisolated successfully",
            action_id: result[:action_id]
          }}

        {:error, :unauthorized} ->
          # Do not leak whether the agent exists in another organization.
          {:ok, %{
            success: false,
            agent_id: agent_id,
            hostname: nil,
            previous_status: nil,
            message: "Agent not found",
            action_id: nil
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
  end

  def block_ip(_parent, %{input: input}, %{context: context}) do
    ip = input.ip

    # Real API: there is no `Executor.block_ip/2`. Blocking is performed per
    # agent via `Executor.execute_action(agent_id, "block_ip", payload)` (same
    # path the REST ResponseController uses), so a target agent is required —
    # fleet-wide blocking has no backend implementation. `duration_hours` is
    # not supported by the agent command payload and is intentionally ignored.
    case input[:agent_id] do
      nil ->
        {:error, "not implemented: fleet-wide IP block requires agent_id (no fleet dispatcher exists)"}

      agent_id ->
        with {:ok, actor} <- actor_from_context(context) do
          payload = %{
            ip: ip,
            direction: input[:direction] || "both",
            reason: input[:reason] || "manual_block"
          }

          case Executor.execute_action(agent_id, "block_ip", payload, actor: actor) do
            {:ok, _result} ->
              {:ok, %{
                success: true,
                value: ip,
                type: "ip",
                agents_affected: 1,
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
    end
  end

  def block_domain(_parent, %{input: input}, %{context: context}) do
    domain = input.domain

    # Real API: there is no `Executor.block_domain/2`. Blocking is performed
    # per agent via `Executor.execute_action(agent_id, "block_domain", payload)`
    # (same path the REST ResponseController uses), so a target agent is
    # required. `add_to_ioc` is not implemented here (the REST endpoint adds
    # the domain to the DNSAnalyzer blocklist separately) and is ignored.
    case input[:agent_id] do
      nil ->
        {:error, "not implemented: fleet-wide domain block requires agent_id (no fleet dispatcher exists)"}

      agent_id ->
        with {:ok, actor} <- actor_from_context(context) do
          payload = %{
            domain: domain,
            reason: input[:reason] || "manual_block"
          }

          case Executor.execute_action(agent_id, "block_domain", payload, actor: actor) do
            {:ok, _result} ->
              {:ok, %{
                success: true,
                value: domain,
                type: "domain",
                agents_affected: 1,
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
    end
  end

  def scan_path(_parent, %{input: input}, %{context: context}) do
    agent_id = input.agent_id
    path = input.path

    # Real API: `Executor.trigger_scan/2` takes no options — the configurable
    # entry point is `Executor.scan_path/3`. Propagate the organization-scoped
    # actor so cross-tenant targets fail closed. `Map.get/3` intentionally
    # preserves an explicit `recursive: false` (using `|| true` silently
    # changed it back to true).
    with {:ok, actor} <- actor_from_context(context) do
      opts = [recursive: Map.get(input, :recursive, true), actor: actor]

      case Executor.scan_path(agent_id, path, opts) do
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

        {:error, _reason} ->
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
  end

  def collect_forensics(_parent, %{input: input}, %{context: context}) do
    agent_id = input.agent_id

    # SECURITY: org-scoped actor is required; the Response Executor rejects
    # cross-organization targets with :unauthorized (fail closed).
    with {:ok, actor} <- actor_from_context(context),
         :ok <- supported_forensic_paths(input[:paths]),
         {:ok, investigation_id} <-
           investigation_id_for_org(input[:investigation_id], actor.organization_id) do
      opts = [
        type: input[:collection_type] || "full",
        memory_dump: input[:include_memory] || false,
        investigation_id: investigation_id,
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
          Logger.warning("Forensic collection could not start: #{inspect(reason)}")

          {:ok, %{
            success: false,
            collection_id: nil,
            agent_id: agent_id,
            status: "failed",
            artifacts_count: 0,
            size_bytes: 0,
            message: "Failed to start collection"
          }}
      end
    else
      {:error, :not_found} ->
        {:ok, %{
          success: false,
          collection_id: nil,
          agent_id: agent_id,
          status: "failed",
          artifacts_count: 0,
          size_bytes: 0,
          message: "Resource not found"
        }}

      {:error, :unsupported_paths} ->
        {:ok, %{
          success: false,
          collection_id: nil,
          agent_id: agent_id,
          status: "failed",
          artifacts_count: 0,
          size_bytes: 0,
          message: "Custom forensic paths are not supported"
        }}

      error ->
        error
    end
  end

  defp supported_forensic_paths(nil), do: :ok
  defp supported_forensic_paths([]), do: :ok
  defp supported_forensic_paths(_paths), do: {:error, :unsupported_paths}

  defp investigation_id_for_org(nil, _organization_id), do: {:ok, nil}

  defp investigation_id_for_org(investigation_id, organization_id) do
    with {:ok, canonical_organization_id} <- Ecto.UUID.cast(organization_id),
         {:ok, canonical_investigation_id} <- Ecto.UUID.cast(investigation_id),
         {:ok, _investigation} <-
           Investigations.get_investigation_for_org(
             canonical_organization_id,
             canonical_investigation_id
           ) do
      {:ok, canonical_investigation_id}
    else
      _ -> {:error, :not_found}
    end
  rescue
    _ -> {:error, :not_found}
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

  defp alert_id_for_org(nil, _organization_id), do: {:ok, nil}

  defp alert_id_for_org(alert_id, organization_id) do
    case Alerts.get_alert_for_org(organization_id, alert_id) do
      {:ok, _alert} -> {:ok, alert_id}
      {:error, :not_found} -> {:error, "Alert not found"}
    end
  end
end
