defmodule TamanduaServer.Response.Executor do
  @moduledoc """
  Handles the execution of response actions on agents.

  This module is responsible for:
  - Sending commands to agents via their Worker process
  - Handling command responses and timeouts
  - Persisting response action history
  """

  require Logger

  alias TamanduaServer.Agents.{Registry, Worker}
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Response.Action
  alias TamanduaServer.Response.ResponseHistory
  alias TamanduaServer.Solana.RemediationAttestation
  alias TamanduaServerWeb.Endpoint

  @command_timeout 30_000
  @max_retries 3
  @initial_retry_delay 1_000
  @collections_table :executor_forensic_collections

  @doc false
  def ensure_collections_table do
    if :ets.whereis(@collections_table) == :undefined do
      :ets.new(@collections_table, [:set, :named_table, :public, read_concurrency: true])
    end

    :ok
  end

  @doc """
  Executes a response action on a given agent.

  This sends the command to the agent via WebSocket and waits for a response.
  """
  @spec execute_response(Alert.t() | nil, map()) :: {:ok, map()} | {:error, atom() | String.t()}
  def execute_response(alert, %{action_type: action_type, agent_id: agent_id, params: params} = action) do
    Logger.info("Executing response action #{action_type} on agent #{agent_id}")

    result =
      case remote_target(action) do
        nil ->
          execute_with_retry(agent_id, action_type, params, @max_retries, @initial_retry_delay)

        target_agent_id ->
          dispatch_to_agent(target_agent_id, build_command(action_type, params))
      end

    case result do
      {:ok, response} ->
        if alert, do: record_action(alert.id, agent_id, action_type, params, :success, response)

        # Trigger Proof of Remediation attestation asynchronously
        maybe_attest_remediation(agent_id, action_type, params, response, alert)

        {:ok, response}

      {:error, reason} ->
        if alert, do: record_action(alert.id, agent_id, action_type, params, :failed, %{error: inspect(reason)})
        {:error, reason}
    end
  end

  defp execute_with_retry(agent_id, action_type, params, retries_left, delay) do
    case Registry.get(agent_id) do
      {:ok, agent_info} ->
        worker_pid = agent_info[:worker_pid]

        if worker_pid && Process.alive?(worker_pid) do
          command = build_command(action_type, params)

          case Worker.send_command(worker_pid, command, timeout: @command_timeout) do
            {:ok, response} ->
              Logger.info("Response action #{action_type} executed successfully on agent #{agent_id}")
              {:ok, response}

            {:error, :disconnected} ->
              Logger.warning("Agent #{agent_id} disconnected while executing #{action_type}")
              {:error, :agent_disconnected}

            {:error, :timeout} when retries_left > 0 ->
              Logger.warning("Command #{action_type} timed out on agent #{agent_id}, retrying (#{retries_left} left)")
              Process.sleep(delay)
              execute_with_retry(agent_id, action_type, params, retries_left - 1, delay * 2)

            {:error, reason} when retries_left > 0 and reason not in [:agent_disconnected, :agent_not_found] ->
              Logger.warning("Command #{action_type} failed on agent #{agent_id}: #{inspect(reason)}, retrying (#{retries_left} left)")
              Process.sleep(delay)
              execute_with_retry(agent_id, action_type, params, retries_left - 1, delay * 2)

            {:error, reason} ->
              Logger.error("Failed to execute #{action_type} on agent #{agent_id}: #{inspect(reason)}")
              {:error, reason}
          end
        else
          Logger.warning("Agent #{agent_id} worker is not available")
          {:error, :agent_offline}
        end

      _ ->
        Logger.warning("Attempted to execute response on unknown agent ID: #{agent_id}")
        {:error, :agent_not_found}
    end
  end

  @doc """
  Executes a response action without an associated alert.
  Useful for manual responses or automated playbooks.
  """
  @spec execute_action(String.t(), String.t(), map()) :: {:ok, map()} | {:error, atom() | String.t()}
  def execute_action(agent_id, action_type, params \\ %{}) do
    execute_response(nil, %{
      action_type: action_type,
      agent_id: agent_id,
      params: params
    })
  end

  @doc """
  Dispatch a command to a remote agent over its Phoenix.Channel WebSocket
  connection.

  Looks up the agent in the in-memory `Registry` to verify the agent is
  currently online, then broadcasts a `"command"` event on the agent's
  channel topic (`"agent:<agent_id>"`) using `Endpoint.broadcast/3`.

  This is a fire-and-forget transport path used when an action carries a
  `target_agent_id` (or `:target_agent_id`) field, indicating the command
  should be routed to a remote endpoint rather than executed locally on the
  server.  It returns immediately without waiting for the agent's
  `command_response` reply -- callers that need an end-to-end ack should use
  `execute_response/2` without a `target_agent_id` so the command flows
  through `Worker.send_command/3`.

  Returns:
    - `{:ok, %{dispatched: true, transport: :websocket}}` when a live
      channel is found and the broadcast is emitted.
    - `{:error, :agent_offline}` when no live channel is registered for
      the agent.
  """
  @spec dispatch_to_agent(String.t(), map()) :: {:ok, map()} | {:error, :agent_offline}
  def dispatch_to_agent(agent_id, command) when is_binary(agent_id) and is_map(command) do
    case Registry.get(agent_id) do
      {:ok, agent_info} ->
        worker_pid = agent_info[:worker_pid]

        if worker_pid && Process.alive?(worker_pid) do
          topic = "agent:#{agent_id}"
          action_type = command[:command_type] || command["command_type"]

          Logger.info(
            "Dispatching command #{inspect(action_type)} to agent #{agent_id} via WebSocket topic #{topic}"
          )

          Endpoint.broadcast(topic, "command", command)
          {:ok, %{dispatched: true, transport: :websocket}}
        else
          Logger.warning("dispatch_to_agent: agent #{agent_id} has no live channel")
          {:error, :agent_offline}
        end

      _ ->
        Logger.warning("dispatch_to_agent: agent #{agent_id} not found in registry")
        {:error, :agent_offline}
    end
  end

  @doc """
  Kill a process on the agent.
  """
  @spec kill_process(String.t(), integer(), keyword()) :: {:ok, map()} | {:error, atom()}
  def kill_process(agent_id, pid, opts \\ []) do
    execute_action(agent_id, "kill_process", %{
      pid: pid,
      force: Keyword.get(opts, :force, false)
    })
  end

  @doc """
  Quarantine a file on the agent.
  """
  @spec quarantine_file(String.t(), String.t(), keyword()) :: {:ok, map()} | {:error, atom()}
  def quarantine_file(agent_id, path, opts \\ []) do
    # Safety instrumentation: when the target resolves to a protected entity,
    # either BLOCK the action (when enforcement is enabled) or log a would-block
    # warning while leaving control flow unchanged (report-only default).
    cond do
      protected_target?(path) and response_safety_enforce?() ->
        Logger.warning("[ResponseSafety] BLOCKED response on protected target: #{path} (enforcing)")

        TamanduaServer.Response.Audit.log_action(
          "response_blocked",
          %{action: "quarantine_file", path: path, mode: "enforce", reason: "protected_target"},
          agent_id,
          :system
        )

        {:error, :protected_target}

      protected_target?(path) ->
        Logger.warning("[ResponseSafety] would-block response on protected target: #{path} (report-only)")

        TamanduaServer.Response.Audit.log_action(
          "response_would_block",
          %{action: "quarantine_file", path: path, mode: "report-only", reason: "protected_target"},
          agent_id,
          :system
        )

        execute_action(agent_id, "quarantine_file", %{
          path: path,
          delete_after: Keyword.get(opts, :delete_after, false)
        })

      true ->
        execute_action(agent_id, "quarantine_file", %{
          path: path,
          delete_after: Keyword.get(opts, :delete_after, false)
        })
    end
  end

  @doc """
  Isolate network on the agent.

  After the command executes, the agent returns a detailed `IsolationStatus`
  struct as `result_data`.  We persist it on the agent record and broadcast
  the change via PubSub for real-time dashboard updates.
  """
  @spec isolate_network(String.t(), keyword()) :: {:ok, map()} | {:error, atom()}
  def isolate_network(agent_id, opts \\ []) do
    result = execute_action(agent_id, "isolate_network", %{
      allowed_ips: Keyword.get(opts, :allowed_ips, []),
      duration_seconds: Keyword.get(opts, :duration, 0)
    })

    # Process isolation status from the agent response
    case result do
      {:ok, %{"result_data" => isolation_status}} when is_map(isolation_status) ->
        TamanduaServer.Agents.update_isolation_status(agent_id, isolation_status)
        result

      {:ok, response} when is_map(response) ->
        # Legacy response or minimal status -- still try to update
        TamanduaServer.Agents.update_isolation_status(agent_id, response)
        result

      _ ->
        result
    end
  end

  @doc """
  Remove network isolation on the agent.

  After the command executes, the agent returns a detailed `IsolationStatus`
  struct confirming the de-isolation.  We update the agent record to clear
  the isolation state and broadcast the change.
  """
  @spec unisolate_network(String.t()) :: {:ok, map()} | {:error, atom()}
  def unisolate_network(agent_id) do
    result = execute_action(agent_id, "unisolate_network", %{})

    # Process de-isolation status from the agent response
    case result do
      {:ok, %{"result_data" => isolation_status}} when is_map(isolation_status) ->
        state = Map.get(isolation_status, "state", "disabled")
        if state == "disabled" do
          TamanduaServer.Agents.clear_isolation_status(agent_id)
        else
          TamanduaServer.Agents.update_isolation_status(agent_id, isolation_status)
        end
        result

      {:ok, _response} ->
        # Assume de-isolation succeeded if we got a success response
        TamanduaServer.Agents.clear_isolation_status(agent_id)
        result

      _ ->
        result
    end
  end

  @doc """
  Scan a specific path on the agent.
  """
  @spec scan_path(String.t(), String.t(), keyword()) :: {:ok, map()} | {:error, atom()}
  def scan_path(agent_id, path, opts \\ []) do
    execute_action(agent_id, "scan_path", %{
      path: path,
      recursive: Keyword.get(opts, :recursive, true),
      max_depth: Keyword.get(opts, :max_depth, 5)
    })
  end

  @doc """
  Trigger a scan on a specific path on the agent.
  Alias for scan_path with default options.
  """
  @spec trigger_scan(String.t(), String.t()) :: {:ok, map()} | {:error, atom()}
  def trigger_scan(agent_id, path) do
    Logger.info("Triggering scan on agent #{agent_id} for path: #{path}")
    scan_path(agent_id, path, recursive: true)
  end

  @doc """
  Isolate host from network.
  Alias for isolate_network/1 with default options.
  """
  @spec isolate_host(String.t()) :: {:ok, map()} | {:error, atom()}
  def isolate_host(agent_id) do
    Logger.info("Isolating host #{agent_id} from network")
    isolate_network(agent_id, [])
  end

  @doc """
  Collect forensic data from the agent.

  Options:
    - :memory_dump - Collect memory dump (default: false)
    - :process_list - Collect running processes (default: true)
    - :network_connections - Collect network connections (default: true)
    - :registry_hives - Collect registry hives (Windows only, default: false)
    - :event_logs - Collect event logs (default: true)
    - :prefetch - Collect prefetch files (Windows only, default: false)
    - :browser_history - Collect browser history (default: false)
  """
  @spec collect_forensics(String.t(), map() | keyword()) :: {:ok, String.t()} | {:error, atom()}
  def collect_forensics(agent_id, options \\ %{}) do
    Logger.info("Collecting forensics from agent #{agent_id} with options: #{inspect(options)}")

    # Normalize options to a map (callers may pass keyword lists)
    options = if is_list(options), do: Map.new(options), else: options

    default_options = %{
      memory_dump: false,
      process_list: true,
      network_connections: true,
      registry_hives: false,
      event_logs: true,
      prefetch: false,
      browser_history: false
    }

    merged_options = Map.merge(default_options, options)

    # Generate a collection ID and track it
    collection_id = Ecto.UUID.generate()
    collection_type = Map.get(options, :type, "full")
    now = DateTime.utc_now()

    ensure_collections_table()

    collection_record = %{
      id: collection_id,
      agent_id: agent_id,
      type: collection_type,
      status: "in_progress",
      progress: 0,
      artifacts: [],
      size_bytes: 0,
      started_at: now,
      completed_at: nil,
      error_message: nil,
      requested_by: Map.get(options, :requested_by)
    }

    :ets.insert(@collections_table, {collection_id, collection_record})

    # Execute the forensics collection asynchronously to avoid blocking
    Task.start(fn ->
      case execute_action(agent_id, "collect_forensics", merged_options) do
        {:ok, response} ->
          artifacts = Map.get(response, "artifacts", [])
          size_bytes = Map.get(response, "size_bytes", 0)

          updated = %{
            collection_record
            | status: "completed",
              progress: 100,
              artifacts: artifacts,
              size_bytes: size_bytes,
              completed_at: DateTime.utc_now()
          }

          :ets.insert(@collections_table, {collection_id, updated})

        {:error, reason} ->
          updated = %{
            collection_record
            | status: "failed",
              error_message: inspect(reason),
              completed_at: DateTime.utc_now()
          }

          :ets.insert(@collections_table, {collection_id, updated})
      end
    end)

    {:ok, collection_id}
  end

  @doc """
  Collect an artifact from the agent.
  """
  @spec collect_artifact(String.t(), String.t(), String.t()) :: {:ok, map()} | {:error, atom()}
  def collect_artifact(agent_id, path, artifact_type \\ "file") do
    execute_action(agent_id, "collect_artifact", %{
      path: path,
      artifact_type: artifact_type
    })
  end

  @doc """
  Get the status of a forensic evidence collection.

  Looks up the collection in the in-memory ETS table that is populated
  by `collect_forensics/2`.  Returns the collection status map on success
  or `{:error, :not_found}` when no collection with the given ID exists.
  """
  @spec get_collection_status(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_collection_status(collection_id) do
    ensure_collections_table()

    case :ets.lookup(@collections_table, collection_id) do
      [{^collection_id, record}] ->
        {:ok, record}

      [] ->
        {:error, :not_found}
    end
  end

  @doc """
  Registers a response action to be executed.
  This queues the action if the agent is offline.
  """
  @spec register_response_action(Alert.t(), map()) :: {:ok, :registered | :executed} | {:error, any()}
  def register_response_action(%Alert{} = alert, action_details) do
    Logger.info("Registering response action for alert #{alert.id}: #{inspect(action_details)}")

    agent_id = action_details[:agent_id]

    # Check if agent is online
    case Registry.get(agent_id) do
      {:ok, agent_info} when is_map_key(agent_info, :worker_pid) ->
        # Agent is online, execute immediately
        case execute_response(alert, action_details) do
          {:ok, _} -> {:ok, :executed}
          error -> error
        end

      _ ->
        # Agent is offline, queue the action
        queue_action(alert.id, agent_id, action_details)
        {:ok, :registered}
    end
  end

  # Private functions

  # Protected targets that should NEVER be killed/quarantined/isolated in a real
  # deployment. This is REPORT-ONLY instrumentation: callers log a "would-block"
  # message but do not change behavior. Match is on the case-insensitive basename
  # so both bare names ("lsass.exe") and full paths ("C:\\...\\lsass.exe") match.
  @protected_targets ~w(
    lsass.exe system services.exe csrss.exe wininit.exe winlogon.exe smss.exe
    tamandua_agent tamandua_agent.exe tamandua_watchdog tamandua_watchdog.exe
    tamandua_driver tamandua_driver.sys
  )

  @spec protected_target?(any()) :: boolean()
  defp protected_target?(name_or_path) when is_binary(name_or_path) do
    basename = name_or_path |> Path.basename() |> String.downcase()
    basename in @protected_targets
  end

  defp protected_target?(_), do: false

  # Whether the response-safety guard should ENFORCE (block) rather than merely
  # report. Defaults to false: report-only behavior is preserved unless an
  # operator explicitly opts in via `config :tamandua_server, :response_safety_enforce, true`.
  defp response_safety_enforce?, do: Application.get_env(:tamandua_server, :response_safety_enforce, false)

  defp build_command(action_type, params) do
    %{
      command_type: action_type,
      payload: params
    }
  end

  # Extract a `target_agent_id` (atom or string keyed) from the action map.
  # When present, the action should be dispatched directly to the remote
  # agent's WebSocket channel via `dispatch_to_agent/2` rather than going
  # through the local Worker GenServer call path.  Returns nil when the
  # action targets the local server (no remote routing required).
  defp remote_target(%{target_agent_id: target}) when is_binary(target) and target != "", do: target
  defp remote_target(%{"target_agent_id" => target}) when is_binary(target) and target != "", do: target
  defp remote_target(_), do: nil

  defp record_action(alert_id, agent_id, action_type, params, status, result) do
    now = DateTime.utc_now()

    # Record the action in the database for audit trail
    action_attrs = %{
      alert_id: alert_id,
      agent_id: agent_id,
      action_type: to_string(action_type),
      parameters: params,
      status: to_string(status),
      result: result,
      executed_at: now
    }

    # Also record to DETS-backed in-memory history for fast lookup and deduplication
    ResponseHistory.record(action_attrs)

    case TamanduaServer.Response.create_action(action_attrs) do
      {:ok, _action} ->
        :ok

      {:error, reason} ->
        Logger.error("Failed to record response action: #{inspect(reason)}")
        :error
    end
  rescue
    e ->
      Logger.error("Error recording response action: #{inspect(e)}")
      :error
  end

  defp queue_action(alert_id, agent_id, action_details) do
    # Store in database for later execution when agent comes online
    Logger.info("Queuing action for offline agent #{agent_id}")

    action_attrs = %{
      alert_id: alert_id,
      agent_id: agent_id,
      action_type: to_string(action_details[:action_type]),
      parameters: action_details[:params] || %{},
      status: "pending"
    }

    case TamanduaServer.Response.create_action(action_attrs) do
      {:ok, action} ->
        Logger.info("Action #{action.id} queued for agent #{agent_id}")
        {:ok, action}

      {:error, reason} ->
        Logger.error("Failed to queue action for agent #{agent_id}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Process all pending actions for an agent that just came online.
  Should be called when an agent connects.
  """
  @spec process_pending_actions(String.t()) :: {:ok, list()} | {:error, any()}
  def process_pending_actions(agent_id) do
    Logger.info("Processing pending actions for agent #{agent_id}")

    pending_actions = TamanduaServer.Response.get_pending_actions(agent_id)

    results =
      Enum.map(pending_actions, fn action ->
        Logger.info("Executing queued action #{action.id} (#{action.action_type}) on agent #{agent_id}")

        # Mark as executing
        {:ok, action} = TamanduaServer.Response.update_action_result(action, %{status: "executing"})

        # Execute the action
        result = execute_action(agent_id, action.action_type, action.parameters || %{})

        # Update action with result
        case result do
          {:ok, response} ->
            TamanduaServer.Response.update_action_result(action, %{
              status: "success",
              result: response,
              executed_at: DateTime.utc_now()
            })
            {:ok, action.id}

          {:error, reason} ->
            TamanduaServer.Response.update_action_result(action, %{
              status: "failed",
              error_message: inspect(reason),
              executed_at: DateTime.utc_now()
            })
            {:error, action.id, reason}
        end
      end)

    successful = Enum.filter(results, fn
      {:ok, _} -> true
      _ -> false
    end)

    failed = Enum.filter(results, fn
      {:error, _, _} -> true
      _ -> false
    end)

    Logger.info("Processed #{length(pending_actions)} pending actions: #{length(successful)} successful, #{length(failed)} failed")

    {:ok, results}
  end

  @doc """
  Cancel a pending action.
  """
  @spec cancel_action(String.t()) :: {:ok, Action.t()} | {:error, any()}
  def cancel_action(action_id) do
    case TamanduaServer.Response.get_action!(action_id) do
      %{status: "pending"} = action ->
        TamanduaServer.Response.update_action_result(action, %{
          status: "cancelled",
          executed_at: DateTime.utc_now()
        })

      action when is_map(action) ->
        {:error, :action_not_pending}
    end
  rescue
    Ecto.NoResultsError -> {:error, :not_found}
  end

  # ---------------------------------------------------------------------------
  # Proof of Remediation Attestation
  # ---------------------------------------------------------------------------

  # Action types that should trigger on-chain remediation attestation
  @attestable_actions ~w(
    kill_process quarantine_file isolate_network unisolate_network
    scan_path create_snapshot restore_file restore_files
    ransomware_remediate collect_forensics
  )

  defp maybe_attest_remediation(agent_id, action_type, params, response, alert) do
    # Only attest significant remediation actions, not all commands
    if action_type in @attestable_actions and TamanduaServer.Solana.Client.enabled?() do
      # Run attestation asynchronously to not block the response
      Task.start(fn ->
        organization_id = if alert, do: alert.organization_id, else: nil

        case RemediationAttestation.attest_from_executor(
               agent_id,
               action_type,
               params,
               response,
               alert: alert,
               organization_id: organization_id
             ) do
          {:ok, tx_signature} ->
            Logger.info("[Executor] Remediation attested on Solana: #{tx_signature}")

            # If there's an alert, update it with the remediation attestation
            if alert do
              update_alert_remediation_tx(alert, tx_signature)
            end

          {:error, reason} ->
            Logger.warning("[Executor] Remediation attestation failed: #{inspect(reason)}")
        end
      end)
    end
  end

  defp update_alert_remediation_tx(alert, tx_signature) do
    # Update the alert with remediation transaction ID
    # Store in enrichment metadata to track remediation proof
    current_enrichment = alert.enrichment || %{}

    updated_enrichment =
      Map.merge(current_enrichment, %{
        "remediation_tx_id" => tx_signature,
        "remediation_attested_at" => DateTime.utc_now() |> DateTime.to_iso8601()
      })

    TamanduaServer.Alerts.update_alert(alert, %{enrichment: updated_enrichment})
  rescue
    e ->
      Logger.warning("[Executor] Failed to update alert with remediation tx: #{inspect(e)}")
  end

  # ---------------------------------------------------------------------------
  # Network Isolation (stateful, delegated to NetworkIsolation GenServer)
  # ---------------------------------------------------------------------------

  alias TamanduaServer.Response.NetworkIsolation

  @doc """
  Isolate an agent with stateful tracking via the NetworkIsolation GenServer.

  Unlike `isolate_network/2` which is a fire-and-forget command, this function
  tracks isolation state in-memory and persists it to the agent record.

  Supports isolation levels:
    - :full    - Block all traffic except management channel
    - :partial - Block internet, allow LAN
    - :process - Block specific process(es) from network access
  """
  @spec managed_isolate(String.t(), NetworkIsolation.isolation_level(), keyword()) ::
          {:ok, NetworkIsolation.isolation_state()} | {:error, term()}
  def managed_isolate(agent_id, level \\ :full, opts \\ []) do
    NetworkIsolation.isolate(agent_id, level, opts)
  end

  @doc """
  Remove managed network isolation from an agent.
  """
  @spec managed_deisolate(String.t(), keyword()) :: :ok | {:error, term()}
  def managed_deisolate(agent_id, opts \\ []) do
    NetworkIsolation.deisolate(agent_id, opts)
  end

  @doc """
  Get the current managed isolation state for an agent.
  """
  @spec get_isolation_state(String.t()) ::
          {:ok, NetworkIsolation.isolation_state()} | {:error, :not_isolated}
  def get_isolation_state(agent_id) do
    NetworkIsolation.get_state(agent_id)
  end

  @doc """
  List all agents currently under managed network isolation.
  """
  @spec list_isolated_agents() :: [NetworkIsolation.isolation_state()]
  def list_isolated_agents do
    NetworkIsolation.list_isolated()
  end
end
