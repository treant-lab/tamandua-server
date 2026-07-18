defmodule TamanduaServer.Response.Executor do
  @moduledoc """
  Handles the execution of response actions on agents.

  This module is responsible for:
  - Sending commands to agents via their Worker process
  - Handling command responses and timeouts
  - Persisting response action history
  """

  require Logger

  alias TamanduaServer.Agents.{CommandManager, Registry, Worker}
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Accounts.User
  alias TamanduaServer.Response.Action
  alias TamanduaServer.Response.ResponseHistory
  alias TamanduaServer.Repo
  alias TamanduaServer.Solana.RemediationAttestation

  @command_timeout 30_000
  @max_retries 3
  @initial_retry_delay 1_000
  defmodule CollectionStore do
    @moduledoc """
    Bounded, node-local ownership boundary for transient forensic collection
    status. This store is intentionally volatile: process or node restart loses
    its records. Durable supervision/reconciliation is a separate P2 lane.
    """
    use GenServer

    @max_active_global 64
    @max_active_per_tenant 8
    @max_retained_records 2_048
    @active_ttl_ms :timer.hours(1)
    @retained_ttl_ms :timer.hours(24)

    def start do
      case GenServer.start(__MODULE__, :ok, name: __MODULE__) do
        {:ok, _pid} -> :ok
        {:error, {:already_started, _pid}} -> :ok
        {:error, reason} -> {:error, reason}
      end
    end

    def reserve(record) do
      case Process.whereis(__MODULE__) do
        nil -> {:error, :collection_store_unavailable}
        _pid -> GenServer.call(__MODULE__, {:reserve, record})
      end
    catch
      :exit, _reason -> {:error, :collection_store_unavailable}
    end

    def finish(collection_id, terminal_fields) do
      case Process.whereis(__MODULE__) do
        nil -> {:error, :collection_store_unavailable}
        _pid -> GenServer.call(__MODULE__, {:finish, collection_id, terminal_fields})
      end
    catch
      :exit, _reason -> {:error, :collection_store_unavailable}
    end

    def get(collection_id) do
      case Process.whereis(__MODULE__) do
        nil -> {:error, :not_found}
        _pid -> GenServer.call(__MODULE__, {:get, collection_id})
      end
    catch
      :exit, _reason -> {:error, :not_found}
    end

    @impl true
    def init(:ok) do
      table =
        :ets.new(:executor_forensic_collections, [
          :set,
          :named_table,
          :protected,
          read_concurrency: true
        ])

      {:ok, %{table: table}}
    end

    @impl true
    def handle_call(
          {:reserve, %{id: collection_id, organization_id: organization_id} = record},
          _from,
          state
        ) do
      now_mono = System.monotonic_time(:millisecond)
      cleanup_expired(state.table, now_mono)

      active_records = active_records(state.table)
      tenant_active = Enum.count(active_records, &(&1.organization_id == organization_id))

      admission =
        cond do
          :ets.info(state.table, :size) >= @max_retained_records ->
            {:error, :collection_admission_limited}

          length(active_records) >= @max_active_global ->
            {:error, :collection_admission_limited}

          tenant_active >= @max_active_per_tenant ->
            {:error, :collection_admission_limited}

          true ->
            true = :ets.insert(state.table, {collection_id, record, now_mono})
            :ok
        end

      {:reply, admission, state}
    end

    def handle_call({:finish, collection_id, terminal_fields}, _from, state) do
      now_mono = System.monotonic_time(:millisecond)
      cleanup_expired(state.table, now_mono)

      reply =
        case :ets.lookup(state.table, collection_id) do
          [{^collection_id, %{status: "in_progress"} = record, _reserved_at}] ->
            updated = Map.merge(record, terminal_fields)
            true = :ets.insert(state.table, {collection_id, updated, now_mono})
            :ok

          _ ->
            {:error, :not_found}
        end

      {:reply, reply, state}
    end

    def handle_call({:get, collection_id}, _from, state) do
      now_mono = System.monotonic_time(:millisecond)
      cleanup_expired(state.table, now_mono)

      reply =
        case :ets.lookup(state.table, collection_id) do
          [{^collection_id, record, _updated_at}] -> {:ok, record}
          [] -> {:error, :not_found}
        end

      {:reply, reply, state}
    end

    defp active_records(table) do
      table
      |> :ets.tab2list()
      |> Enum.flat_map(fn
        {_id, %{status: "in_progress"} = record, _updated_at} -> [record]
        _ -> []
      end)
    end

    defp cleanup_expired(table, now_mono) do
      table
      |> :ets.tab2list()
      |> Enum.each(fn
        {collection_id, %{status: "in_progress"}, updated_at}
        when now_mono - updated_at >= @active_ttl_ms ->
          :ets.delete(table, collection_id)

        {collection_id, _record, updated_at}
        when now_mono - updated_at >= @retained_ttl_ms ->
          :ets.delete(table, collection_id)

        _ ->
          :ok
      end)
    end
  end

  defp ensure_collections_table do
    case CollectionStore.start() do
      :ok -> :ok
      {:error, reason} ->
        Logger.error("Unable to start forensic collection store: #{inspect(reason)}")
        {:error, :collection_store_unavailable}
    end
  end

  @doc """
  Executes a response action on a given agent.

  This sends the command to the agent via WebSocket and waits for a response.

  ## Authorization

  The action map may carry an `:actor` (or `"actor"`) entry identifying who
  requested the action:

    * `%{organization_id: org_id, user_id: user_id}` — a user/API actor. The
      target agent MUST belong to `org_id`; otherwise the action is rejected
      with `{:error, :unauthorized}` and an audit entry is written. This closes
      the cross-organization response bypass: without this check any
      authenticated caller could kill/isolate/quarantine on ANY agent.
    * `:system` — an internal/autonomous actor. Alert/agent organization
      consistency is verified against the tenant-owned agent row. Without an
      alert, an explicit `organization_id` is required on the action.
    * absent — rejected. Legacy callers cannot dispatch without an actor and
      authoritative tenant scope.
  """
  @spec execute_response(Alert.t() | nil, map()) :: {:ok, map()} | {:error, term()}
  def execute_response(alert, %{action_type: action_type, agent_id: agent_id, params: params} = action) do
    case authorize_response(alert, action) do
      :ok ->
        with {:ok, tracked_action} <- prepare_tracked_action(alert, action) do
          do_execute_response(alert, action, tracked_action)
        end

      {:error, :unauthorized} ->
        actor = response_actor(action)

        Logger.warning(
          "BLOCKED unauthorized response action #{action_type} on agent #{agent_id} " <>
            "(organization scope mismatch, actor: #{inspect(sanitize_actor(actor))})"
        )

        audit_unauthorized_response(agent_id, action_type, params, actor, alert)

        {:error, :unauthorized}
    end
  end

  defp do_execute_response(
         alert,
         %{action_type: action_type, agent_id: agent_id, params: params} = action,
         tracked_action
       ) do
    actor = response_actor(action)
    idempotency_key = Map.get(action, :idempotency_key)
    Logger.info("Executing response action #{action_type} on agent #{agent_id}")

    result =
      case remote_target(action) do
        nil ->
          execute_with_retry(
            agent_id,
            action_type,
            params,
            idempotency_key,
            @max_retries,
            @initial_retry_delay
          )

        target_agent_id ->
          dispatch_to_agent(target_agent_id, build_command(action_type, params, idempotency_key))
      end

    case result do
      {:ok, response} ->
        response =
          finalize_response_action(
            tracked_action,
            alert,
            agent_id,
            action_type,
            params,
            :success,
            response,
            actor
          )
          |> attach_action_metadata(response)

        # Trigger Proof of Remediation attestation asynchronously
        maybe_attest_remediation(agent_id, action_type, params, response, alert)

        {:ok, response}

      {:error, reason} ->
        finalize_response_action(
          tracked_action,
          alert,
          agent_id,
          action_type,
          params,
          :failed,
          %{error: inspect(reason)},
          actor
        )

        {:error, reason}
    end
  end

  defp execute_with_retry(agent_id, action_type, params, idempotency_key, retries_left, delay) do
    case Registry.get(agent_id) do
      {:ok, agent_info} ->
        worker_pid = agent_info[:worker_pid]

        if worker_pid && Process.alive?(worker_pid) do
          command = build_command(action_type, params, idempotency_key)

          case send_worker_command(worker_pid, command) do
            {:ok, response} ->
              Logger.info("Response action #{action_type} executed successfully on agent #{agent_id}")
              {:ok, response}

            {:error, :disconnected} ->
              Logger.warning("Agent #{agent_id} disconnected while executing #{action_type}")
              {:error, :agent_disconnected}

            {:error, :timeout} when retries_left > 0 ->
              Logger.warning("Command #{action_type} timed out on agent #{agent_id}, retrying (#{retries_left} left)")
              Process.sleep(delay)
              execute_with_retry(
                agent_id,
                action_type,
                params,
                idempotency_key,
                retries_left - 1,
                delay * 2
              )

            {:error, reason} when retries_left > 0 and reason not in [:agent_disconnected, :agent_not_found] ->
              Logger.warning("Command #{action_type} failed on agent #{agent_id}: #{inspect(reason)}, retrying (#{retries_left} left)")
              Process.sleep(delay)
              execute_with_retry(
                agent_id,
                action_type,
                params,
                idempotency_key,
                retries_left - 1,
                delay * 2
              )

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

  defp send_worker_command(worker_pid, command) do
    Worker.send_command(worker_pid, command, timeout: @command_timeout)
  catch
    :exit, {:timeout, _call} -> {:error, :timeout}
    :exit, reason -> {:error, {:worker_call_exit, reason}}
  end

  @doc """
  Executes a response action without an associated alert.
  Useful for manual responses or automated playbooks.

  Options:
    - `:actor` - `%{organization_id: org_id, user_id: user_id}` or `:system`.
      When a user actor is given the target agent must belong to the actor's
      organization (see `execute_response/2`).
  """
  @spec execute_action(String.t(), String.t(), map(), keyword()) ::
          {:ok, map()} | {:error, atom() | String.t()}
  def execute_action(agent_id, action_type, params \\ %{}, opts \\ []) do
    action = %{
      action_type: action_type,
      agent_id: agent_id,
      params: params
    }

    action =
      case Keyword.get(opts, :actor) do
        nil -> action
        actor -> Map.put(action, :actor, actor)
      end

    action =
      case Keyword.get(opts, :idempotency_key) do
        key when is_binary(key) and key != "" -> Map.put(action, :idempotency_key, key)
        _ -> action
      end

    action =
      action
      |> maybe_put(:alert_id, Keyword.get(opts, :alert_id))
      |> maybe_put(:organization_id, Keyword.get(opts, :organization_id))
      |> maybe_put(:persist_action, Keyword.get(opts, :persist_action))

    execute_response(nil, action)
  end

  @doc """
  Dispatch a command to a remote agent through the persisted command queue.

  Looks up the agent in the in-memory `Registry` to verify the agent is
  currently online (live worker process), then queues the command via
  `Agents.CommandManager.queue_command/4`. The agent worker pushes the
  persisted command over the agent's live channel
  (`Worker.dispatch_persisted_command/2`) as
  `%{command_id, command_type, payload, timestamp}` and persists the
  agent's `command_response` onto the `AgentCommand` row.

  This replaces a previous `Endpoint.broadcast(topic, "command", command)`
  fastlane that emitted only `%{command_type, payload}`. The Rust agent
  deserializes the `"command"` event into a `Command` struct that requires
  `command_id` and `timestamp` (apps/tamandua_agent/src/transport/mod.rs,
  `serde_json::from_value::<Command>` inside `if let Ok(...)`), so the old
  broadcast never parsed on the agent and was silently dropped while the
  server recorded the action as successful. Queueing through
  CommandManager produces the full wire contract and adds crash-safe
  redelivery on reconnect.

  This path is used when an action carries a `target_agent_id` (or
  `:target_agent_id`) field, indicating the command should be routed to a
  remote endpoint rather than executed locally on the server. It returns
  as soon as the command is queued -- callers that need an end-to-end ack
  should use `execute_response/2` without a `target_agent_id` so the
  command flows through `Worker.send_command/3`.

  Returns:
    - `{:ok, %{dispatched: true, transport: :websocket, command_id: id}}`
      when a live channel is found and the command is queued for push.
    - `{:error, :agent_offline}` when no live channel is registered for
      the agent.
    - `{:error, {:invalid_command, errors}}` when the command type is not
      in the `AgentCommand` allowlist or the changeset is otherwise
      invalid (previously such commands were broadcast and silently
      dropped by the agent).
  """
  @spec dispatch_to_agent(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def dispatch_to_agent(agent_id, command) when is_binary(agent_id) and is_map(command) do
    case Registry.get(agent_id) do
      {:ok, agent_info} ->
        worker_pid = agent_info[:worker_pid]

        if worker_pid && Process.alive?(worker_pid) do
          action_type = command[:command_type] || command["command_type"]
          payload = command[:payload] || command["payload"] || %{}
          idempotency_key = command[:idempotency_key] || command["idempotency_key"]

          case CommandManager.queue_command(
                 agent_id,
                 action_type,
                 payload,
                 idempotency_key: idempotency_key
               ) do
            {:ok, cmd} ->
              Logger.info(
                "Queued command #{inspect(action_type)} for agent #{agent_id} " <>
                  "(command_id #{cmd.id}, push via agent worker)"
              )

              {:ok, %{dispatched: true, transport: :websocket, command_id: cmd.id}}

            {:error, %Ecto.Changeset{} = changeset} ->
              Logger.warning(
                "dispatch_to_agent: rejected command #{inspect(action_type)} for agent " <>
                  "#{agent_id}: #{inspect(changeset.errors)}"
              )

              {:error, {:invalid_command, changeset.errors}}

            {:error, reason} ->
              Logger.warning(
                "dispatch_to_agent: failed to queue command #{inspect(action_type)} for " <>
                  "agent #{agent_id}: #{inspect(reason)}"
              )

              {:error, reason}
          end
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

  Options:
    - `:force` - force kill (default: false)
    - `:actor` - `%{organization_id: org_id, user_id: user_id}` or `:system`;
      org-scoped actors may only target agents in their own organization
      (see `execute_response/2`).
  """
  @spec kill_process(String.t(), integer(), keyword()) :: {:ok, map()} | {:error, term()}
  def kill_process(agent_id, pid, opts \\ []) do
    params =
      %{pid: pid, force: Keyword.get(opts, :force, false)}
      |> maybe_put(:reason, Keyword.get(opts, :reason))

    execute_action(agent_id, "kill_process", params,
      actor: Keyword.get(opts, :actor),
      alert_id: Keyword.get(opts, :alert_id),
      organization_id: Keyword.get(opts, :organization_id),
      persist_action: true
    )
  end

  @doc """
  Quarantine a file on the agent.
  """
  @spec quarantine_file(String.t(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
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
          audit_actor_from_opts(opts),
          audit_scope_from_opts(opts)
        )

        {:error, :protected_target}

      protected_target?(path) ->
        Logger.warning("[ResponseSafety] would-block response on protected target: #{path} (report-only)")

        TamanduaServer.Response.Audit.log_action(
          "response_would_block",
          %{action: "quarantine_file", path: path, mode: "report-only", reason: "protected_target"},
          agent_id,
          audit_actor_from_opts(opts),
          audit_scope_from_opts(opts)
        )

        execute_quarantine(agent_id, path, opts)

      true ->
        execute_quarantine(agent_id, path, opts)
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
    }, actor: Keyword.get(opts, :actor))

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
  @spec unisolate_network(String.t(), keyword()) :: {:ok, map()} | {:error, atom()}
  def unisolate_network(agent_id, opts \\ []) do
    result = execute_action(agent_id, "unisolate_network", %{}, actor: Keyword.get(opts, :actor))

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
    }, actor: Keyword.get(opts, :actor))
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
    with {:ok, normalized_options} <- normalize_forensic_options(options) do
      # The actor is authorization metadata, not a command option — pop it so
      # it is never forwarded to the agent as part of the command payload.
      {actor, command_options} = pop_actor(normalized_options)

      case authorize_actor_for_agent(actor, agent_id) do
        :ok ->
          with :ok <- validate_forensic_options(command_options),
               {:ok, organization_id, requested_by} <- forensic_actor_identity(actor) do
            do_collect_forensics(
              agent_id,
              command_options,
              actor,
              organization_id,
              requested_by
            )
          end

        {:error, :unauthorized} ->
          Logger.warning(
            "BLOCKED unauthorized forensics collection on agent #{agent_id} " <>
              "(organization scope mismatch, actor: #{inspect(sanitize_actor(actor))})"
          )

          audit_unauthorized_response(agent_id, "collect_forensics", command_options, actor, nil)
          {:error, :unauthorized}
      end
    end
  end

  defp do_collect_forensics(agent_id, options, actor, organization_id, requested_by) do
    Logger.info("Collecting forensics from agent #{agent_id} with options: #{inspect(options)}")

    default_options = %{
      memory_dump: false,
      process_list: true,
      network_connections: true,
      registry_hives: false,
      event_logs: true,
      prefetch: false,
      browser_history: false
    }

    command_options =
      options
      |> Map.drop([
        :requested_by,
        "requested_by",
        :investigation_id,
        "investigation_id",
        :paths,
        "paths"
      ])
      |> then(&Map.merge(default_options, &1))

    # Generate a collection ID and track it
    collection_id = Ecto.UUID.generate()
    collection_type = Map.get(options, :type, "full")
    now = DateTime.utc_now()

    collection_record = %{
      id: collection_id,
      organization_id: organization_id,
      agent_id: agent_id,
      investigation_id: Map.get(options, :investigation_id),
      type: collection_type,
      status: "in_progress",
      progress: 0,
      artifacts: [],
      size_bytes: 0,
      started_at: now,
      completed_at: nil,
      error_message: nil,
      requested_by: requested_by
    }

    with :ok <- ensure_collections_table(),
         :ok <- CollectionStore.reserve(collection_record) do
      # Execute the forensics collection asynchronously to avoid blocking.
      # The task sends updates through CollectionStore; it never writes the
      # protected ETS table directly.
      case Task.start(fn ->
             case execute_action(agent_id, "collect_forensics", command_options, actor: actor) do
               {:ok, response} ->
                 CollectionStore.finish(collection_id, %{
                   status: "completed",
                   progress: 100,
                   artifacts: bounded_forensic_artifacts(Map.get(response, "artifacts", [])),
                   size_bytes: bounded_non_negative_integer(Map.get(response, "size_bytes", 0)),
                   completed_at: DateTime.utc_now()
                 })

               {:error, reason} ->
                 CollectionStore.finish(collection_id, %{
                   status: "failed",
                   error_message: forensic_error_category(reason),
                   completed_at: DateTime.utc_now()
                 })
             end
           end) do
        {:ok, _pid} ->
          {:ok, collection_id}

        {:error, _reason} ->
          CollectionStore.finish(collection_id, %{
            status: "failed",
            error_message: "task_start_failed",
            completed_at: DateTime.utc_now()
          })

          {:error, :collection_start_failed}
      end
    end
  end

  @doc """
  Collect an artifact from the agent.
  """
  @spec collect_artifact(String.t(), String.t(), String.t(), keyword() | map()) ::
          {:ok, map()} | {:error, atom()}
  def collect_artifact(agent_id, path, artifact_type \\ "file", opts \\ []) do
    opts = if is_list(opts), do: Map.new(opts), else: opts
    {actor, _opts} = pop_actor(opts)

    case authorize_actor_for_agent(actor, agent_id) do
      :ok ->
        execute_action(
          agent_id,
          "collect_artifact",
          %{
            path: path,
            artifact_type: artifact_type
          },
          actor: actor
        )

      {:error, :unauthorized} ->
        Logger.warning(
          "BLOCKED unauthorized artifact collection on agent #{agent_id} " <>
            "(organization scope mismatch, actor: #{inspect(sanitize_actor(actor))})"
        )

        audit_unauthorized_response(
          agent_id,
          "collect_artifact",
          %{path: path, artifact_type: artifact_type},
          actor,
          nil
        )

        {:error, :unauthorized}
    end
  end

  @doc """
  Get the status of a forensic evidence collection.

  Looks up the collection in the in-memory ETS table populated by
  `collect_forensics/2` and returns it only when its canonical organization
  matches the requested tenant. Missing and foreign IDs are indistinguishable.
  """
  @spec get_collection_status(String.t(), String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_collection_status(organization_id, collection_id) do
    with {:ok, canonical_organization_id} <- canonical_uuid(organization_id),
         {:ok, canonical_collection_id} <- canonical_uuid(collection_id),
         {:ok, %{organization_id: ^canonical_organization_id} = record} <-
           CollectionStore.get(canonical_collection_id) do
      {:ok, record}
    else
      _ -> {:error, :not_found}
    end
  end

  @doc false
  @spec get_collection_status(String.t()) :: {:error, :organization_scope_required}
  def get_collection_status(_collection_id), do: {:error, :organization_scope_required}

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

  # ---------------------------------------------------------------------------
  # Organization-scope authorization
  # ---------------------------------------------------------------------------

  defp response_actor(%{actor: actor}), do: actor
  defp response_actor(%{"actor" => actor}), do: actor
  defp response_actor(_), do: nil

  defp pop_actor(options) when is_map(options) do
    case Map.pop(options, :actor) do
      {nil, remaining} -> Map.pop(remaining, "actor")
      result -> result
    end
  end

  # Authorize a response action before execution.
  #
  # - With a user actor (`%{organization_id: ...}`): the target agent must
  #   belong to the actor's organization (fail closed).
  # - With `:system`: an alert organization or explicit action organization is
  #   required and checked against the database. Missing actors fail closed.
  defp authorize_response(alert, action) do
    agent_id = remote_target(action) || action[:agent_id] || action["agent_id"]

    case response_actor(action) do
      nil -> {:error, :unauthorized}
      :system -> authorize_system_scope(alert, action, agent_id)
      %{} = actor ->
        with :ok <- authorize_actor_for_agent(actor, agent_id),
             :ok <- authorize_actor_for_alert(actor, alert) do
          :ok
        end

      _other -> {:error, :unauthorized}
    end
  end

  # Direct collector entrypoints have no separate organization argument, so
  # only an explicitly tenant-scoped actor can authorize them.
  defp authorize_actor_for_agent(nil, _agent_id), do: {:error, :unauthorized}
  defp authorize_actor_for_agent(:system, _agent_id), do: {:error, :unauthorized}

  defp authorize_actor_for_agent(%{} = actor, agent_id) do
    actor_org = actor[:organization_id] || actor["organization_id"]

    with {:ok, canonical_actor_org} <- canonical_uuid(actor_org),
         :ok <-
           in_tenant_scope(canonical_actor_org, fn ->
             validate_actor_user(actor, canonical_actor_org)
           end),
         :ok <- db_org_check(canonical_actor_org, agent_id) do
      :ok
    else
      _ -> {:error, :unauthorized}
    end
  end

  defp authorize_actor_for_agent(_actor, _agent_id), do: {:error, :unauthorized}

  defp authorize_actor_for_alert(_actor, nil), do: :ok

  defp authorize_actor_for_alert(actor, alert) do
    actor_org = actor[:organization_id] || actor["organization_id"]
    alert_org = Map.get(alert, :organization_id)

    with {:ok, canonical_actor_org} <- canonical_uuid(actor_org),
         {:ok, canonical_alert_org} <- canonical_uuid(alert_org),
         true <- canonical_actor_org == canonical_alert_org do
      :ok
    else
      _ -> {:error, :unauthorized}
    end
  end

  defp authorize_alert_scope(alert, agent_id) do
    alert_org = Map.get(alert, :organization_id)

    case alert_org do
      organization_id when is_binary(organization_id) and organization_id != "" ->
        db_org_check(organization_id, agent_id)

      _ ->
        {:error, :unauthorized}
    end
  end

  defp authorize_system_scope(nil, action, agent_id) do
    case action[:organization_id] || action["organization_id"] do
      organization_id when is_binary(organization_id) and organization_id != "" ->
        db_org_check(organization_id, agent_id)

      _ ->
        {:error, :unauthorized}
    end
  end

  defp authorize_system_scope(alert, _action, agent_id),
    do: authorize_alert_scope(alert, agent_id)

  # Every allow decision is checked against the tenant-owned database row.
  # Registry state is transport presence only and never tenancy authority.
  defp db_org_check(actor_org, agent_id) do
    with {:ok, canonical_organization_id} <- canonical_uuid(actor_org),
         {:ok, canonical_agent_id} <- canonical_uuid(agent_id) do
      case TamanduaServer.Agents.get_agent_for_org(
             canonical_organization_id,
             canonical_agent_id
           ) do
        {:ok, _agent} -> :ok
        _ -> {:error, :unauthorized}
      end
    else
      _ -> {:error, :unauthorized}
    end
  rescue
    _ -> {:error, :unauthorized}
  end

  # Best-effort audit of a blocked cross-org response attempt. Must never
  # crash the caller (the DB may be unavailable); failures are logged.
  defp audit_unauthorized_response(agent_id, action_type, params, actor, alert) do
    actor_ref =
      case actor do
        %{} = a -> a[:user_id] || a["user_id"] || :system
        _ -> :system
      end

    TamanduaServer.Response.Audit.log_action(
      "response_unauthorized",
      %{
        action: to_string(action_type),
        params: sanitize_params(params),
        reason: "organization_scope_mismatch",
        actor: sanitize_actor(actor)
      },
      agent_id,
      actor_ref,
      audit_organization(actor, alert, agent_id)
    )
  rescue
    e ->
      Logger.error("Failed to audit unauthorized response attempt: #{inspect(e)}")
      :error
  end

  defp sanitize_actor(%{} = actor) do
    %{
      organization_id: actor[:organization_id] || actor["organization_id"],
      user_id: actor[:user_id] || actor["user_id"]
    }
  end

  defp sanitize_actor(actor), do: actor

  defp sanitize_params(params) when is_map(params), do: params
  defp sanitize_params(params), do: %{"value" => inspect(params)}

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp actor_organization(%{} = actor),
    do: actor[:organization_id] || actor["organization_id"]

  defp actor_organization(_actor), do: nil

  defp audit_organization(actor, alert, _agent_id) do
    actor_organization(actor) ||
      (alert && Map.get(alert, :organization_id))
  end

  defp execute_quarantine(agent_id, path, opts) do
    params =
      %{path: path, delete_after: Keyword.get(opts, :delete_after, false)}
      |> maybe_put(:reason, Keyword.get(opts, :reason))

    execute_action(agent_id, "quarantine_file", params,
      actor: Keyword.get(opts, :actor),
      alert_id: Keyword.get(opts, :alert_id),
      organization_id: Keyword.get(opts, :organization_id),
      persist_action: true
    )
  end

  defp audit_scope_from_opts(opts) do
    case Keyword.get(opts, :actor) do
      %{} = actor -> actor_organization(actor)
      _ -> Keyword.get(opts, :organization_id)
    end
  end

  defp audit_actor_from_opts(opts) do
    case Keyword.get(opts, :actor) do
      %{} = actor -> actor_user_id(actor) || :system
      _ -> :system
    end
  end

  defp prepare_tracked_action(_alert, %{persist_action: value}) when value not in [true], do: {:ok, nil}
  defp prepare_tracked_action(_alert, %{"persist_action" => value}) when value not in [true], do: {:ok, nil}
  defp prepare_tracked_action(_alert, action) when not is_map_key(action, :persist_action), do: {:ok, nil}

  defp prepare_tracked_action(alert, action) do
    actor = response_actor(action)
    agent_id = remote_target(action) || action[:agent_id] || action["agent_id"]

    with {:ok, organization_id} <- response_organization(alert, actor, action),
         {:ok, persisted_action} <-
           in_tenant_scope(organization_id, fn ->
             with :ok <- validate_actor_user(actor, organization_id),
                  :ok <- validate_action_alert(action, alert, organization_id) do
               TamanduaServer.Response.create_action(%{
                 alert_id: action[:alert_id] || action["alert_id"] || (alert && alert.id),
                 agent_id: agent_id,
                 action_type: to_string(action[:action_type] || action["action_type"]),
                 parameters: action[:params] || action["params"] || %{},
                 status: "executing",
                 executed_by_id: actor_user_id(actor),
                 organization_id: organization_id
               })
             end
           end) do
      {:ok, persisted_action}
    else
      {:error, reason} ->
        Logger.error("Response action was not executed because its audit record could not be owned/persisted: #{inspect(reason)}")
        {:error, {:action_recording_failed, reason}}
    end
  end

  defp response_organization(_alert, %{} = actor, _action) do
    canonical_response_organization(actor_organization(actor))
  end

  defp response_organization(%{organization_id: organization_id}, _actor, _action)
       when is_binary(organization_id) and organization_id != "",
       do: canonical_response_organization(organization_id)

  defp response_organization(_alert, :system, action) do
    canonical_response_organization(action[:organization_id] || action["organization_id"])
  end

  defp response_organization(_alert, _actor, _action),
    do: {:error, :organization_scope_required}

  defp canonical_response_organization(organization_id) do
    case canonical_uuid(organization_id) do
      {:ok, canonical_organization_id} -> {:ok, canonical_organization_id}
      {:error, _reason} -> {:error, :organization_scope_required}
    end
  end

  @forensic_option_keys [
    :actor,
    :type,
    :memory_dump,
    :process_list,
    :network_connections,
    :registry_hives,
    :event_logs,
    :prefetch,
    :browser_history,
    :investigation_id,
    :requested_by,
    :paths
  ]
  @max_forensic_options 16
  @max_forensic_type_bytes 32
  @max_forensic_artifacts 128
  @max_forensic_artifact_bytes 16_384

  defp normalize_forensic_options(options)
       when is_map(options) and map_size(options) <= @max_forensic_options do
    Enum.reduce_while(options, {:ok, %{}}, fn {key, value}, {:ok, normalized} ->
      with {:ok, canonical_key} <- canonical_forensic_option_key(key),
           false <- Map.has_key?(normalized, canonical_key) do
        {:cont, {:ok, Map.put(normalized, canonical_key, value)}}
      else
        _ -> {:halt, {:error, :invalid_options}}
      end
    end)
  end

  defp normalize_forensic_options(options) when is_list(options),
    do: normalize_forensic_keyword_options(options, %{}, 0)

  defp normalize_forensic_options(_options), do: {:error, :invalid_options}

  defp normalize_forensic_keyword_options([], normalized, _count), do: {:ok, normalized}

  defp normalize_forensic_keyword_options(
         [{key, value} | rest],
         normalized,
         count
       )
       when is_atom(key) and count < @max_forensic_options do
    with {:ok, canonical_key} <- canonical_forensic_option_key(key),
         false <- Map.has_key?(normalized, canonical_key) do
      normalize_forensic_keyword_options(
        rest,
        Map.put(normalized, canonical_key, value),
        count + 1
      )
    else
      _ -> {:error, :invalid_options}
    end
  end

  defp normalize_forensic_keyword_options(_options, _normalized, _count),
    do: {:error, :invalid_options}

  defp canonical_forensic_option_key(key) when key in @forensic_option_keys, do: {:ok, key}

  defp canonical_forensic_option_key(key) when is_binary(key) do
    case Enum.find(@forensic_option_keys, &(Atom.to_string(&1) == key)) do
      nil -> {:error, :invalid_options}
      atom_key -> {:ok, atom_key}
    end
  end

  defp canonical_forensic_option_key(_key), do: {:error, :invalid_options}

  defp validate_forensic_options(options)
       when is_map(options) and map_size(options) <= @max_forensic_options do
    Enum.reduce_while(options, :ok, fn {key, value}, :ok ->
      case validate_forensic_option(key, value) do
        :ok -> {:cont, :ok}
        {:error, _reason} = error -> {:halt, error}
      end
    end)
  end

  defp validate_forensic_options(_options), do: {:error, :invalid_options}

  defp validate_forensic_option(key, _value) when key not in @forensic_option_keys,
    do: {:error, :invalid_options}

  defp validate_forensic_option(:actor, %{}), do: :ok

  defp validate_forensic_option(:type, value)
       when is_binary(value) and byte_size(value) > 0 and
              byte_size(value) <= @max_forensic_type_bytes,
       do: :ok

  defp validate_forensic_option(key, value)
       when key in [
              :memory_dump,
              :process_list,
              :network_connections,
              :registry_hives,
              :event_logs,
              :prefetch,
              :browser_history
            ] and is_boolean(value),
       do: :ok

  defp validate_forensic_option(key, nil)
       when key in [:investigation_id, :requested_by, :paths],
       do: :ok

  defp validate_forensic_option(key, value)
       when key in [:investigation_id, :requested_by] and is_binary(value) do
    case canonical_uuid(value) do
      {:ok, _canonical_uuid} -> :ok
      _ -> {:error, :invalid_options}
    end
  end

  defp validate_forensic_option(:paths, []), do: :ok
  defp validate_forensic_option(_key, _value), do: {:error, :invalid_options}

  defp bounded_forensic_artifacts(artifacts) when is_list(artifacts) do
    artifacts
    |> Enum.take(@max_forensic_artifacts)
    |> Enum.filter(fn artifact ->
      try do
        :erlang.external_size(artifact) <= @max_forensic_artifact_bytes
      rescue
        _ -> false
      end
    end)
  end

  defp bounded_forensic_artifacts(_artifacts), do: []

  defp bounded_non_negative_integer(value)
       when is_integer(value) and value >= 0 and value <= 9_223_372_036_854_775_807,
       do: value

  defp bounded_non_negative_integer(_value), do: 0

  defp forensic_error_category(:timeout), do: "timeout"
  defp forensic_error_category({:timeout, _detail}), do: "timeout"
  defp forensic_error_category(:unauthorized), do: "unauthorized"
  defp forensic_error_category(:not_connected), do: "unavailable"
  defp forensic_error_category(:agent_not_found), do: "unavailable"
  defp forensic_error_category({:error, reason}), do: forensic_error_category(reason)
  defp forensic_error_category(_reason), do: "command_failed"

  defp canonical_uuid(value) when is_binary(value), do: Ecto.UUID.cast(value)
  defp canonical_uuid(_value), do: :error

  defp actor_user_id(%{} = actor), do: actor[:user_id] || actor["user_id"]
  defp actor_user_id(_actor), do: nil

  defp forensic_actor_identity(%{} = actor) do
    with {:ok, organization_id} <-
           canonical_uuid(actor[:organization_id] || actor["organization_id"]),
         {:ok, requested_by} <- canonical_uuid(actor_user_id(actor)) do
      {:ok, organization_id, requested_by}
    else
      _ -> {:error, :unauthorized}
    end
  end

  defp forensic_actor_identity(_actor), do: {:error, :unauthorized}

  defp validate_actor_user(%{} = actor, organization_id) do
    case actor_user_id(actor) do
      nil ->
        {:error, :actor_identity_required}

      user_id ->
        with {:ok, canonical_user_id} <- canonical_uuid(user_id),
             %User{} <-
               Repo.get_by(User,
                 id: canonical_user_id,
                 organization_id: organization_id
               ) do
          :ok
        else
          _ -> {:error, :actor_scope_mismatch}
        end
    end
  rescue
    _ -> {:error, :actor_scope_mismatch}
  end

  defp validate_actor_user(_actor, _organization_id), do: :ok

  defp validate_action_alert(_action, %{organization_id: organization_id}, organization_id), do: :ok

  defp validate_action_alert(action, nil, organization_id) do
    case action[:alert_id] || action["alert_id"] do
      nil ->
        :ok

      alert_id ->
        case TamanduaServer.Alerts.get_alert_for_org(organization_id, alert_id) do
          {:ok, _alert} -> :ok
          _ -> {:error, :alert_scope_mismatch}
        end
    end
  rescue
    _ -> {:error, :alert_scope_mismatch}
  end

  defp validate_action_alert(_action, _alert, _organization_id),
    do: {:error, :alert_scope_mismatch}

  defp finalize_response_action(nil, alert, agent_id, action_type, params, status, result, actor) do
    if alert, do: record_action(alert.id, agent_id, action_type, params, status, result, actor)
    nil
  end

  defp finalize_response_action(%Action{} = action, _alert, _agent_id, _action_type, _params, status, result, _actor) do
    attrs = %{status: to_string(status), result: result, executed_at: DateTime.utc_now()}

    update_result =
      in_tenant_scope(action.organization_id, fn ->
        action |> Action.result_changeset(attrs) |> Repo.update()
      end)

    case update_result do
      {:ok, completed_action} -> completed_action
      {:error, reason} ->
        Logger.error("Response command completed but its audit outcome could not be persisted: #{inspect(reason)}")
        %{id: action.id, audit_status: "degraded"}
    end
  rescue
    error ->
      Logger.error("Response command completed but audit finalization crashed: #{inspect(error)}")
      %{id: action.id, audit_status: "degraded"}
  end

  defp in_tenant_scope(organization_id, fun)
       when is_binary(organization_id) and organization_id != "" and is_function(fun, 0) do
    TamanduaServer.Repo.MultiTenant.with_organization(organization_id, fun)
  rescue
    error -> {:error, {:tenant_scope_failed, error}}
  end

  defp in_tenant_scope(_organization_id, _fun), do: {:error, :organization_scope_required}

  defp attach_action_metadata(nil, response), do: response

  defp attach_action_metadata(action, response) when is_map(response) do
    response
    |> Map.put(:action_id, action.id)
    |> Map.put(:audit_status, Map.get(action, :audit_status, "complete"))
  end

  defp attach_action_metadata(action, response),
    do: %{
      response: response,
      action_id: action.id,
      audit_status: Map.get(action, :audit_status, "complete")
    }

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

  defp build_command(action_type, params, idempotency_key \\ nil) do
    command = %{
      command_type: action_type,
      payload: params
    }

    if is_binary(idempotency_key) and idempotency_key != "" do
      Map.put(command, :idempotency_key, idempotency_key)
    else
      command
    end
  end

  # Extract a `target_agent_id` (atom or string keyed) from the action map.
  # When present, the action should be dispatched directly to the remote
  # agent's WebSocket channel via `dispatch_to_agent/2` rather than going
  # through the local Worker GenServer call path.  Returns nil when the
  # action targets the local server (no remote routing required).
  defp remote_target(%{target_agent_id: target}) when is_binary(target) and target != "", do: target
  defp remote_target(%{"target_agent_id" => target}) when is_binary(target) and target != "", do: target
  defp remote_target(_), do: nil

  defp record_action(alert_id, agent_id, action_type, params, status, result, actor) do
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

    # Record actor identity (who requested the action) when available so the
    # audit trail can attribute responses to a user and organization.
    action_attrs =
      case actor do
        %{} = a ->
          action_attrs
          |> maybe_put(:executed_by_id, a[:user_id] || a["user_id"])
          |> maybe_put(:organization_id, a[:organization_id] || a["organization_id"])

        _ ->
          action_attrs
      end

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
