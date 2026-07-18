defmodule TamanduaServerWeb.API.V1.HealingController do
  @moduledoc """
  Controller for Self-Healing API endpoints.

  Provides automated remediation capabilities including
  executing healing actions, viewing history, and rolling
  back changes when needed.
  """
  use TamanduaServerWeb, :controller

  require Logger

  alias TamanduaServer.Agents
  alias TamanduaServer.Response
  alias TamanduaServer.Response.Executor

  action_fallback TamanduaServerWeb.FallbackController

  @pre_action_state_table :healing_pre_action_state

  # Non-reversible action types -- these cannot be meaningfully rolled back
  @non_reversible_actions ~w(clear_temp_files flush_dns repair_system_files kill_malicious_process)

  # Ensure the ETS table exists for storing pre-action state snapshots.
  # Called lazily on first use so the table persists across requests.
  defp ensure_ets_table do
    case :ets.whereis(@pre_action_state_table) do
      :undefined ->
        :ets.new(@pre_action_state_table, [:set, :public, :named_table])

      _ref ->
        @pre_action_state_table
    end
  end

  @doc """
  Execute a self-healing action on an agent.

  ## Body Parameters
  - `agent_id` - Target agent identifier (required)
  - `action_type` - Type of healing action (required)
  - `params` - Action-specific parameters
  - `auto_rollback` - Enable automatic rollback on failure (default: false)
  - `timeout` - Action timeout in seconds (default: 30)

  ## Supported Action Types
  - `restart_service` - Restart a system service
  - `clear_temp_files` - Remove temporary and cache files
  - `repair_permissions` - Fix file/directory permissions
  - `restart_process` - Restart a specific process
  - `flush_dns` - Clear DNS cache
  - `reset_firewall` - Reset firewall rules to baseline
  - `quarantine_and_restore` - Quarantine threat and restore from backup
  """
  def execute(conn, %{"agent_id" => agent_id, "action_type" => action_type} = params) do
    # Authorize: the target agent must belong to the caller's organization.
    # Errors fall through to FallbackController (403 forbidden / 404 not_found).
    with {:ok, _agent, org_id} <- authorize_agent(conn, agent_id) do
      do_execute(conn, agent_id, action_type, params, org_id)
    end
  end

  def execute(conn, _params) do
    conn
    |> put_status(400)
    |> json(%{success: false, error: "Missing required parameters: agent_id, action_type"})
  end

  defp do_execute(conn, agent_id, action_type, params, org_id) do
    user = conn.assigns[:current_user]
    healing_params = Map.get(params, "params", %{})
    auto_rollback = Map.get(params, "auto_rollback", false)
    timeout = parse_int(Map.get(params, "timeout"), 30)

    # Validate action type
    case validate_action_type(action_type) do
      :ok ->
        # Create healing action record
        action_attrs = %{
          agent_id: agent_id,
          action_type: "heal_#{action_type}",
          parameters: Map.merge(healing_params, %{
            "auto_rollback" => auto_rollback,
            "timeout" => timeout
          }),
          status: "pending",
          source: "self_healing",
          organization_id: org_id,
          executed_by_id: user && user.id
        }

        with {:ok, action} <- Response.create_action(action_attrs),
             pre_state <- save_pre_action_state(action.id, action_type, agent_id, healing_params),
             {:ok, result} <- execute_healing_action(agent_id, action_type, healing_params, timeout) do
          # Persist the pre-action state in the action's result map so it
          # survives ETS table loss (e.g. node restart) and is available
          # for rollback at any future point.
          Response.update_action_result(action, %{
            status: "success",
            result: Map.merge(result || %{}, %{"pre_action_state" => pre_state}),
            executed_at: DateTime.utc_now()
          })

          json(conn, %{
            success: true,
            data: %{
              action_id: action.id,
              action_type: action_type,
              agent_id: agent_id,
              status: "completed",
              result: result,
              rollback_available: can_rollback?(action_type),
              non_reversible: action_type in @non_reversible_actions
            }
          })
        else
          {:error, :agent_not_found} ->
            {:error, :not_found}

          {:error, :agent_offline} ->
            conn
            |> put_status(503)
            |> json(%{success: false, error: "Agent is offline"})

          {:error, reason} when is_binary(reason) ->
            conn
            |> put_status(400)
            |> json(%{success: false, error: reason})

          {:error, reason} ->
            conn
            |> put_status(500)
            |> json(%{success: false, error: inspect(reason)})
        end

      {:error, message} ->
        conn
        |> put_status(400)
        |> json(%{success: false, error: message})
    end
  end

  @doc """
  Get healing action history.

  ## Query Parameters
  - `agent_id` - Filter by agent
  - `action_type` - Filter by action type
  - `status` - Filter by status: "pending", "success", "failed", "rolled_back"
  - `since` - ISO8601 timestamp for time-based filtering
  - `limit` - Maximum number of results (default: 100)
  """
  def history(conn, params) do
    case current_org_id(conn) do
      nil -> {:error, :forbidden}
      org_id -> do_history(conn, params, org_id)
    end
  end

  defp do_history(conn, params, org_id) do
    filters = %{
      agent_id: params["agent_id"],
      status: params["status"],
      # Always scope history to the caller's organization to prevent
      # cross-tenant disclosure of response actions.
      organization_id: org_id,
      limit: parse_int(params["limit"], 100)
    }

    # Filter for healing actions
    actions = Response.list_actions(filters)
    |> Enum.filter(fn action ->
      String.starts_with?(action.action_type || "", "heal_") or
      action.parameters["source"] == "self_healing"
    end)
    |> filter_by_action_type(params["action_type"])
    |> filter_by_since(params["since"])
    |> Enum.take(filters.limit)

    json(conn, %{
      data: Enum.map(actions, &serialize_action/1),
      meta: %{
        count: length(actions),
        filters: Map.take(filters, [:agent_id, :status])
      }
    })
  end

  @doc """
  Rollback a previously executed healing action.

  ## Path Parameters
  - `action_id` - ID of the action to rollback

  ## Body Parameters
  - `reason` - Reason for rollback (optional)
  """
  def rollback(conn, %{"action_id" => action_id} = params) do
    reason = Map.get(params, "reason", "Manual rollback requested")

    case Response.get_action!(action_id) do
      nil ->
        {:error, :not_found}

      action ->
        # Authorize: the action must belong to the caller's organization.
        # Cross-org actions are reported as 404 to avoid leaking existence.
        with {:ok, org_id} <- authorize_action(conn, action) do
          do_rollback(conn, action, action_id, reason, org_id)
        end
    end
  rescue
    Ecto.NoResultsError ->
      {:error, :not_found}

    Ecto.Query.CastError ->
      # Malformed action_id (not a valid UUID) -- treat as not found
      # instead of surfacing a 500.
      {:error, :not_found}
  end

  def rollback(conn, _params) do
    conn
    |> put_status(400)
    |> json(%{success: false, error: "Missing required parameter: action_id"})
  end

  defp do_rollback(conn, action, action_id, reason, org_id) do
    user = conn.assigns[:current_user]

    if can_rollback_action?(action) do
      case execute_rollback(action, reason) do
        {:ok, rollback_result} ->
          # Create rollback action record
          rollback_attrs = %{
            agent_id: action.agent_id,
            action_type: "rollback_#{action.action_type}",
            parameters: %{
              "original_action_id" => action_id,
              "reason" => reason
            },
            status: "success",
            result: rollback_result,
            executed_at: DateTime.utc_now(),
            organization_id: org_id,
            executed_by_id: user && user.id
          }

          {:ok, _rollback_action} = Response.create_action(rollback_attrs)

          # Update original action status
          Response.update_action_result(action, %{
            status: "rolled_back",
            error_message: reason
          })

          json(conn, %{
            success: true,
            data: %{
              action_id: action_id,
              status: "rolled_back",
              rollback_result: rollback_result
            }
          })

        {:error, :non_reversible, message} ->
          # The action type is inherently non-reversible.
          # Return 422 (Unprocessable Entity) with a descriptive explanation.
          conn
          |> put_status(422)
          |> json(%{
            success: false,
            error: "Action is non-reversible",
            reason: message,
            action_type: String.replace_prefix(action.action_type || "", "heal_", "")
          })

        {:error, rollback_error} ->
          conn
          |> put_status(500)
          |> json(%{success: false, error: "Rollback failed: #{inspect(rollback_error)}"})
      end
    else
      conn
      |> put_status(400)
      |> json(%{
        success: false,
        error: "Action cannot be rolled back",
        reason: get_rollback_error_reason(action)
      })
    end
  end

  # ── Organization authorization helpers ────────────────────────────────

  # Resolve the caller's organization from the authenticated connection.
  defp current_org_id(conn) do
    conn.assigns[:current_organization_id] ||
      (conn.assigns[:current_user] && conn.assigns[:current_user].organization_id)
  end

  # Verify the target agent belongs to the caller's organization.
  # Returns {:ok, agent, org_id} on success, {:error, :forbidden} when the
  # caller has no organization context, or {:error, :not_found} when the
  # agent does not exist within the caller's organization (avoids leaking
  # the existence of agents in other tenants).
  defp authorize_agent(conn, agent_id) do
    case current_org_id(conn) do
      nil ->
        {:error, :forbidden}

      org_id ->
        with {:ok, _uuid} <- cast_uuid(agent_id),
             {:ok, agent} <- Agents.get_agent_for_org(org_id, agent_id) do
          {:ok, agent, org_id}
        else
          _ -> {:error, :not_found}
        end
    end
  end

  defp cast_uuid(value) when is_binary(value), do: Ecto.UUID.cast(value)
  defp cast_uuid(_value), do: :error

  # Verify a response action belongs to the caller's organization.
  # New actions carry an explicit organization_id stamp; legacy actions
  # (organization_id is nil) are authorized through their agent's tenancy.
  defp authorize_action(conn, action) do
    case current_org_id(conn) do
      nil ->
        {:error, :forbidden}

      org_id ->
        cond do
          action.organization_id == org_id ->
            {:ok, org_id}

          is_nil(action.organization_id) and not is_nil(action.agent_id) ->
            case Agents.get_agent_for_org(org_id, action.agent_id) do
              {:ok, _agent} -> {:ok, org_id}
              {:error, :not_found} -> {:error, :not_found}
            end

          true ->
            {:error, :not_found}
        end
    end
  end

  # Private functions

  @valid_action_types ~w(
    restart_service
    clear_temp_files
    repair_permissions
    restart_process
    flush_dns
    reset_firewall
    quarantine_and_restore
    kill_malicious_process
    block_network_connection
    restore_registry
    repair_system_files
  )

  defp validate_action_type(action_type) do
    if action_type in @valid_action_types do
      :ok
    else
      {:error, "Invalid action type. Supported types: #{Enum.join(@valid_action_types, ", ")}"}
    end
  end

  defp execute_healing_action(agent_id, action_type, params, _timeout) do
    # Map healing actions to executor commands
    case action_type do
      "restart_service" ->
        service_name = params["service_name"] || params["service"]
        if service_name do
          Executor.execute_action(agent_id, "restart_service", %{service: service_name})
        else
          {:error, "Missing required parameter: service_name"}
        end

      "clear_temp_files" ->
        paths = params["paths"] || default_temp_paths()
        Executor.execute_action(agent_id, "clear_files", %{paths: paths, recursive: true})

      "repair_permissions" ->
        path = params["path"]
        if path do
          Executor.execute_action(agent_id, "repair_permissions", %{
            path: path,
            owner: params["owner"],
            permissions: params["permissions"]
          })
        else
          {:error, "Missing required parameter: path"}
        end

      "restart_process" ->
        process_name = params["process_name"] || params["name"]
        if process_name do
          Executor.execute_action(agent_id, "restart_process", %{name: process_name})
        else
          {:error, "Missing required parameter: process_name"}
        end

      "flush_dns" ->
        Executor.execute_action(agent_id, "flush_dns", %{})

      "reset_firewall" ->
        Executor.execute_action(agent_id, "reset_firewall", %{
          profile: params["profile"] || "default"
        })

      "quarantine_and_restore" ->
        file_path = params["file_path"]
        if file_path do
          Executor.execute_action(agent_id, "quarantine_and_restore", %{
            path: file_path,
            backup_path: params["backup_path"]
          })
        else
          {:error, "Missing required parameter: file_path"}
        end

      "kill_malicious_process" ->
        pid = params["pid"]
        if pid do
          Executor.execute_action(agent_id, "kill_process", %{pid: pid, force: true})
        else
          {:error, "Missing required parameter: pid"}
        end

      "block_network_connection" ->
        Executor.execute_action(agent_id, "block_connection", %{
          ip: params["ip"],
          port: params["port"],
          direction: params["direction"] || "outbound"
        })

      "restore_registry" ->
        Executor.execute_action(agent_id, "restore_registry", %{
          key: params["key"],
          backup_id: params["backup_id"]
        })

      "repair_system_files" ->
        Executor.execute_action(agent_id, "repair_system_files", %{
          scope: params["scope"] || "critical"
        })

      _ ->
        {:error, "Unknown action type: #{action_type}"}
    end
  end

  @rollbackable_actions ~w(
    restart_service
    reset_firewall
    block_network_connection
    restore_registry
    repair_permissions
    quarantine_and_restore
    restart_process
  )

  defp can_rollback?(action_type), do: action_type in @rollbackable_actions

  defp can_rollback_action?(action) do
    action_type = String.replace_prefix(action.action_type || "", "heal_", "")
    action.status in ["success", "completed"] and can_rollback?(action_type)
  end

  defp get_rollback_error_reason(action) do
    action_type = String.replace_prefix(action.action_type || "", "heal_", "")

    cond do
      action.status in ["pending", "executing"] ->
        "Action is still in progress"

      action.status == "rolled_back" ->
        "Action was already rolled back"

      action.status == "failed" ->
        "Cannot rollback a failed action"

      action_type in @non_reversible_actions ->
        "This action type (#{action_type}) is non-reversible and cannot be rolled back"

      not can_rollback?(action_type) ->
        "This action type (#{action_type}) does not support rollback"

      true ->
        "Unknown reason"
    end
  end

  defp execute_rollback(action, reason) do
    agent_id = action.agent_id
    action_type = String.replace_prefix(action.action_type || "", "heal_", "")
    original_params = action.parameters || %{}
    action_result = action.result || %{}
    pre_state = get_pre_action_state(action.id, original_params, action_result)

    Logger.info(
      "Executing rollback for action #{action.id} (#{action_type}) on agent #{agent_id}, reason: #{reason}"
    )

    rollback_action(action_type, agent_id, original_params, pre_state)
  end

  # ── Rollback implementations per action type ──────────────────────────

  defp rollback_action("restart_service", agent_id, original_params, pre_state) do
    # Rolling back a service restart: send a stop_service command to undo
    # the restart. If the pre-action state captured the service as stopped,
    # we stop it; otherwise we restart again (idempotent fallback).
    service = original_params["service"] || original_params["service_name"]

    unless service do
      {:error, "Cannot rollback restart_service: missing service name in original parameters"}
    else
      previous_state = get_in_state(pre_state, ["service_state"])

      if previous_state == "stopped" do
        Logger.info("Rolling back restart_service: stopping service #{service}")
        Executor.execute_action(agent_id, "stop_service", %{service: service})
      else
        # The service was already running before we restarted it, so
        # restarting again is the safe idempotent rollback.
        Logger.info("Rolling back restart_service: re-restarting service #{service} (was already running)")
        Executor.execute_action(agent_id, "restart_service", %{service: service})
      end
    end
  end

  defp rollback_action("clear_temp_files", _agent_id, _original_params, _pre_state) do
    # Clearing temp files is a destructive action -- the deleted files
    # cannot be restored because they were removed from disk.
    Logger.warning("Rollback requested for clear_temp_files: action is non-reversible")

    {:error, :non_reversible,
     "clear_temp_files is a destructive action. " <>
       "Deleted temporary files cannot be restored. " <>
       "The system will rebuild temp/cache files as needed during normal operation."}
  end

  defp rollback_action("repair_permissions", agent_id, original_params, pre_state) do
    # Restore the original permissions that were captured before the repair.
    path = original_params["path"]

    unless path do
      {:error, "Cannot rollback repair_permissions: missing path in original parameters"}
    else
      original_owner = get_in_state(pre_state, ["original_owner"]) || original_params["original_owner"]
      original_permissions = get_in_state(pre_state, ["original_permissions"]) || original_params["original_permissions"]

      if original_owner || original_permissions do
        Logger.info("Rolling back repair_permissions on #{path}: restoring owner=#{original_owner}, perms=#{original_permissions}")

        Executor.execute_action(agent_id, "repair_permissions", %{
          path: path,
          owner: original_owner,
          permissions: original_permissions
        })
      else
        {:error,
         "Cannot rollback repair_permissions: original permissions were not captured before the action. " <>
           "No pre-action state available for path: #{path}"}
      end
    end
  end

  defp rollback_action("restart_process", _agent_id, original_params, pre_state) do
    # Restarting a process replaces the original process (new PID).
    # The original process state (memory, open handles, etc.) is lost and
    # cannot be recovered.
    process_name = original_params["process_name"] || original_params["name"]

    Logger.warning(
      "Rollback requested for restart_process (#{process_name}): " <>
        "original process state is lost and non-reversible"
    )

    {:error, :non_reversible,
     "restart_process is non-reversible. " <>
       "The original process '#{process_name}' was replaced with a new instance and its " <>
       "prior state (PID #{get_in_state(pre_state, ["original_pid"]) || "unknown"}, memory, handles) cannot be restored. " <>
       "The current instance will continue running."}
  end

  defp rollback_action("flush_dns", _agent_id, _original_params, _pre_state) do
    # DNS cache is an ephemeral, OS-managed resource. Once flushed,
    # entries are rebuilt automatically through normal DNS resolution.
    Logger.warning("Rollback requested for flush_dns: action is non-reversible")

    {:error, :non_reversible,
     "flush_dns is non-reversible. " <>
       "The DNS cache is rebuilt automatically by the operating system as new DNS " <>
       "lookups occur during normal network activity. No manual restoration is needed."}
  end

  defp rollback_action("reset_firewall", agent_id, original_params, pre_state) do
    # Restore the previous firewall rules that were captured before the reset.
    backup_id = get_in_state(pre_state, ["firewall_backup_id"]) || original_params["pre_action_backup_id"]
    previous_rules = get_in_state(pre_state, ["firewall_rules"])

    cond do
      backup_id ->
        Logger.info("Rolling back reset_firewall: restoring from backup #{backup_id}")

        Executor.execute_action(agent_id, "restore_firewall", %{
          backup_id: backup_id,
          profile: original_params["profile"] || "default"
        })

      previous_rules ->
        Logger.info("Rolling back reset_firewall: restoring #{length(previous_rules)} captured rules")

        Executor.execute_action(agent_id, "restore_firewall_rules", %{
          rules: previous_rules,
          profile: original_params["profile"] || "default"
        })

      true ->
        {:error,
         "Cannot rollback reset_firewall: no pre-action firewall state was captured. " <>
           "The firewall is currently at baseline/default. You may need to manually reconfigure rules."}
    end
  end

  defp rollback_action("quarantine_and_restore", agent_id, original_params, pre_state) do
    # Send a restore_from_quarantine command to the agent to reverse
    # the quarantine operation and put the file back at its original path.
    file_path = original_params["file_path"] || original_params["path"]
    quarantine_id = get_in_state(pre_state, ["quarantine_id"])
    backup_path = original_params["backup_path"]

    unless file_path do
      {:error, "Cannot rollback quarantine_and_restore: missing file_path in original parameters"}
    else
      Logger.info("Rolling back quarantine_and_restore: restoring #{file_path} from quarantine")

      Executor.execute_action(agent_id, "restore_from_quarantine", %{
        original_path: file_path,
        quarantine_id: quarantine_id,
        backup_path: backup_path
      })
    end
  end

  defp rollback_action("block_network_connection", agent_id, original_params, _pre_state) do
    # Unblock the network connection that was previously blocked.
    ip = original_params["ip"]
    port = original_params["port"]
    direction = original_params["direction"] || "outbound"

    unless ip do
      {:error, "Cannot rollback block_network_connection: missing IP address in original parameters"}
    else
      Logger.info("Rolling back block_network_connection: unblocking #{ip}:#{port} #{direction}")

      Executor.execute_action(agent_id, "unblock_connection", %{
        ip: ip,
        port: port,
        direction: direction
      })
    end
  end

  defp rollback_action("restore_registry", agent_id, original_params, pre_state) do
    # Restore the registry to the state before the restore action was applied.
    key = original_params["key"]
    pre_restore_backup_id = get_in_state(pre_state, ["registry_backup_id"]) || original_params["pre_restore_backup_id"]

    unless key do
      {:error, "Cannot rollback restore_registry: missing registry key in original parameters"}
    else
      if pre_restore_backup_id do
        Logger.info("Rolling back restore_registry for key #{key} using backup #{pre_restore_backup_id}")

        Executor.execute_action(agent_id, "restore_registry", %{
          key: key,
          backup_id: pre_restore_backup_id
        })
      else
        {:error,
         "Cannot rollback restore_registry: no pre-restore backup was captured for key: #{key}. " <>
           "The registry key is in its post-restore state."}
      end
    end
  end

  defp rollback_action("kill_malicious_process", _agent_id, original_params, _pre_state) do
    # A killed process cannot be restored -- its PID is gone and its
    # in-memory state is permanently lost.
    pid = original_params["pid"]

    Logger.warning("Rollback requested for kill_malicious_process (PID #{pid}): action is non-reversible")

    {:error, :non_reversible,
     "kill_malicious_process is non-reversible. " <>
       "Process PID #{pid} has been terminated and its state cannot be restored. " <>
       "If the process is a legitimate service, use restart_service to bring it back."}
  end

  defp rollback_action("repair_system_files", _agent_id, _original_params, _pre_state) do
    # System file repair (e.g., sfc /scannow) modifies OS-protected files
    # and the previous state cannot be cleanly rolled back.
    Logger.warning("Rollback requested for repair_system_files: action is non-reversible")

    {:error, :non_reversible,
     "repair_system_files is non-reversible. " <>
       "System files have been repaired to their verified OS state. " <>
       "Rolling back would reintroduce potentially corrupted files."}
  end

  @supported_rollback_actions ~w(
    restart_service clear_temp_files repair_permissions restart_process
    flush_dns reset_firewall quarantine_and_restore block_network_connection
    restore_registry kill_malicious_process repair_system_files
  )

  defp rollback_action(action_type, _agent_id, _original_params, _pre_state) do
    Logger.warning(
      "Rollback requested for unsupported action type",
      action_type: action_type,
      supported_types: @supported_rollback_actions
    )

    {:error, :unsupported_action_type,
     "Rollback is not supported for action type '#{action_type}'. " <>
       "Supported action types: #{Enum.join(@supported_rollback_actions, ", ")}"}
  end

  # ── Pre-action state capture ────────────────────────────────────────
  #
  # Before executing a healing action we snapshot whatever state is
  # relevant for a potential rollback.  The snapshot is stored in an
  # ETS table keyed by the action record ID and is also persisted into
  # the action's result map in the database.

  @doc false
  defp save_pre_action_state(action_id, action_type, agent_id, params) do
    ensure_ets_table()

    pre_state =
      case action_type do
        "restart_service" ->
          # Ask the agent for the current service state so we know whether
          # to stop or restart on rollback.
          service = params["service_name"] || params["service"]
          service_state = query_agent_service_state(agent_id, service)
          %{"service_state" => service_state, "service" => service}

        "clear_temp_files" ->
          # Snapshot the list of files that will be deleted. This is
          # informational only -- the action is destructive.
          paths = params["paths"] || default_temp_paths()
          %{"paths" => paths, "note" => "destructive_action_files_cannot_be_restored"}

        "repair_permissions" ->
          # Capture the current owner and permission bits before repair.
          path = params["path"]
          current_perms = query_agent_file_permissions(agent_id, path)
          %{
            "path" => path,
            "original_owner" => current_perms["owner"],
            "original_permissions" => current_perms["permissions"]
          }

        "restart_process" ->
          # Record the current PID so the rollback message is informative.
          process_name = params["process_name"] || params["name"]
          current_pid = query_agent_process_pid(agent_id, process_name)
          %{"process_name" => process_name, "original_pid" => current_pid}

        "flush_dns" ->
          %{"note" => "non_reversible_dns_cache_rebuilds_naturally"}

        "reset_firewall" ->
          # Ask the agent to create a firewall backup before the reset.
          backup_result = create_agent_firewall_backup(agent_id)
          %{
            "firewall_backup_id" => backup_result["backup_id"],
            "firewall_rules" => backup_result["rules"],
            "profile" => params["profile"] || "default"
          }

        "quarantine_and_restore" ->
          # Record the file path and generate a quarantine tracking ID.
          file_path = params["file_path"]
          quarantine_id = generate_quarantine_id()
          %{
            "file_path" => file_path,
            "quarantine_id" => quarantine_id,
            "backup_path" => params["backup_path"]
          }

        "block_network_connection" ->
          %{
            "ip" => params["ip"],
            "port" => params["port"],
            "direction" => params["direction"] || "outbound"
          }

        "restore_registry" ->
          # Ask the agent to snapshot the current registry key value
          # before the restore overwrites it.
          key = params["key"]
          backup_result = create_agent_registry_backup(agent_id, key)
          %{
            "key" => key,
            "registry_backup_id" => backup_result["backup_id"]
          }

        "kill_malicious_process" ->
          %{"pid" => params["pid"], "note" => "non_reversible_process_terminated"}

        "repair_system_files" ->
          %{"scope" => params["scope"] || "critical", "note" => "non_reversible_os_repair"}

        _ ->
          %{}
      end

    # Store in ETS for fast in-process retrieval during rollback
    :ets.insert(@pre_action_state_table, {action_id, pre_state})

    Logger.debug("Captured pre-action state for action #{action_id} (#{action_type}): #{inspect(pre_state)}")
    pre_state
  end

  @doc false
  defp get_pre_action_state(action_id, original_params, action_result \\ %{}) do
    ensure_ets_table()

    # Try ETS first (fast path, same node)
    case :ets.lookup(@pre_action_state_table, action_id) do
      [{^action_id, state}] when is_map(state) and map_size(state) > 0 ->
        state

      _ ->
        # Fallback 1: check the persisted result map on the action record
        # (the pre_action_state is stored in the result during execution)
        case action_result do
          %{"pre_action_state" => state} when is_map(state) ->
            state

          _ ->
            # Fallback 2: check the parameters map
            case original_params["pre_action_state"] do
              state when is_map(state) -> state
              _ -> %{}
            end
        end
    end
  end

  # Safe accessor for nested pre-action state values.
  # Returns nil if the key path does not exist.
  defp get_in_state(nil, _keys), do: nil
  defp get_in_state(state, keys) when is_map(state), do: get_in(state, keys)
  defp get_in_state(_state, _keys), do: nil

  # ── Agent query helpers ───────────────────────────────────────────────
  #
  # These functions query the agent for current state before executing
  # a healing action.  They use Executor.execute_action under the hood
  # and return a best-effort result map (empty map on failure).

  defp query_agent_service_state(agent_id, service) do
    case Executor.execute_action(agent_id, "query_service_state", %{service: service}) do
      {:ok, %{"state" => state}} -> state
      {:ok, %{state: state}} -> state
      _ -> "unknown"
    end
  rescue
    _ -> "unknown"
  end

  defp query_agent_file_permissions(agent_id, path) do
    case Executor.execute_action(agent_id, "query_file_permissions", %{path: path}) do
      {:ok, result} when is_map(result) -> result
      _ -> %{}
    end
  rescue
    _ -> %{}
  end

  defp query_agent_process_pid(agent_id, process_name) do
    case Executor.execute_action(agent_id, "query_process_info", %{name: process_name}) do
      {:ok, %{"pid" => pid}} -> pid
      {:ok, %{pid: pid}} -> pid
      _ -> nil
    end
  rescue
    _ -> nil
  end

  defp create_agent_firewall_backup(agent_id) do
    case Executor.execute_action(agent_id, "backup_firewall", %{}) do
      {:ok, result} when is_map(result) -> result
      _ -> %{}
    end
  rescue
    _ -> %{}
  end

  defp create_agent_registry_backup(agent_id, key) do
    case Executor.execute_action(agent_id, "backup_registry_key", %{key: key}) do
      {:ok, result} when is_map(result) -> result
      _ -> %{}
    end
  rescue
    _ -> %{}
  end

  defp generate_quarantine_id do
    # Generate a unique quarantine tracking identifier
    "qtn_" <> Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)
  end

  defp default_temp_paths do
    [
      "C:\\Windows\\Temp\\*",
      "C:\\Users\\*\\AppData\\Local\\Temp\\*",
      "/tmp/*",
      "/var/tmp/*"
    ]
  end

  defp serialize_action(action) do
    %{
      id: action.id,
      agent_id: action.agent_id,
      action_type: action.action_type,
      parameters: action.parameters,
      status: action.status,
      result: action.result,
      error_message: action.error_message,
      executed_at: format_datetime(action.executed_at),
      created_at: format_datetime(action.inserted_at),
      rollback_available: can_rollback_action?(action)
    }
  end

  defp filter_by_action_type(actions, nil), do: actions
  defp filter_by_action_type(actions, action_type) do
    Enum.filter(actions, fn action ->
      (action.action_type || "") == "heal_#{action_type}" or
      (action.action_type || "") == action_type
    end)
  end

  defp filter_by_since(actions, nil), do: actions
  defp filter_by_since(actions, since_str) do
    case DateTime.from_iso8601(since_str) do
      {:ok, since, _} ->
        Enum.filter(actions, fn action ->
          case action.inserted_at do
            %NaiveDateTime{} = dt ->
              DateTime.compare(DateTime.from_naive!(dt, "Etc/UTC"), since) != :lt
            %DateTime{} = dt ->
              DateTime.compare(dt, since) != :lt
            _ ->
              true
          end
        end)
      _ ->
        actions
    end
  end

  defp format_datetime(nil), do: nil
  defp format_datetime(%NaiveDateTime{} = dt), do: NaiveDateTime.to_iso8601(dt)
  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)

  defp parse_int(nil, default), do: default
  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> default
    end
  end
  defp parse_int(value, _default) when is_integer(value), do: value
  defp parse_int(_, default), do: default
end
