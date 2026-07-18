defmodule TamanduaServer.Agents.Worker do
  @moduledoc """
  GenServer worker for managing a single agent connection.

  Each connected agent has a dedicated worker that:
  - Maintains WebSocket connection state
  - Processes incoming telemetry
  - Sends commands to the agent
  - Handles heartbeats
  """

  use GenServer, restart: :temporary
  require Logger

  alias TamanduaServer.Agents.{Registry, Agent, OrgLookup, AgentCommand}
  alias TamanduaServer.Agents
  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Alerts
  alias TamanduaServer.Telemetry.Ingestor
  alias TamanduaServer.Detection.Engine
  alias TamanduaServer.Repo

  import Ecto.Query

  # Initial joins can be DB-heavy while the channel loads config/rules/IOCs.
  # Keep the liveness window larger than that startup path so queued heartbeats
  # are not mistaken for a dead agent during reconnect or benchmark bursts.
  @heartbeat_timeout :timer.seconds(180)
  @db_heartbeat_throttle :timer.seconds(30)
  @presence_tick_interval :timer.seconds(30)

  # Default batch size for (re)delivering queued commands on connect/notify.
  @pending_command_batch_limit 50
  @command_result_statuses ~w(ok degraded unsupported failed)

  defstruct [
    :agent_id,
    :socket_pid,
    :hostname,
    :organization_id,
    :os_type,
    :config,
    :connected_at,
    :last_heartbeat,
    :last_db_heartbeat,
    # command_id => GenServer.from() of the caller awaiting the agent's reply.
    # Kept in state (not the process dictionary) so it is visible, testable,
    # and cleaned up deterministically on reply/timeout/disconnect.
    command_callbacks: %{},
    # realtime command_id => {event, payload} for in-flight "rt_*" commands.
    realtime_commands: %{}
  ]

  # Client API

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @doc """
  Send a command to the agent.
  """
  @spec send_command(pid(), map(), keyword()) :: {:ok, String.t()} | {:error, term()}
  def send_command(pid, command, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, 30_000)
    GenServer.call(pid, {:send_command, command}, timeout)
  end

  @doc """
  Process incoming telemetry from the agent.
  """
  @spec process_telemetry(pid(), map()) :: :ok
  def process_telemetry(pid, telemetry) do
    GenServer.cast(pid, {:telemetry, telemetry})
  end

  @doc """
  Handle heartbeat from agent.
  """
  @spec heartbeat(pid()) :: :ok
  def heartbeat(pid) do
    GenServer.cast(pid, :heartbeat)
  end

  @doc """
  Handle command response from agent.
  """
  @spec command_response(pid(), map()) :: :ok
  def command_response(pid, response) do
    GenServer.cast(pid, {:command_response, response})
  end

  @doc """
  Mark realtime shell output as progress for agents that stream PTY data without
  sending a separate command_response ack for each realtime command.
  """
  @spec realtime_output(pid(), map()) :: :ok
  def realtime_output(pid, payload) do
    GenServer.cast(pid, {:realtime_output, payload})
  end

  @doc """
  Get current state of the worker.
  """
  @spec get_state(pid()) :: map()
  def get_state(pid) do
    GenServer.call(pid, :get_state)
  end

  # Server callbacks

  @impl true
  def init(opts) do
    agent_id = Keyword.fetch!(opts, :agent_id)
    socket_pid = Keyword.fetch!(opts, :socket_pid)
    agent_info = Keyword.fetch!(opts, :agent_info)

    with {:ok, organization_id} <- authenticated_organization_id(agent_info),
         :ok <- persist_agent_to_db(agent_id, agent_info, organization_id),
         :ok <- Registry.register(agent_id, Map.put(agent_info, :worker_pid, self())) do
      state = %__MODULE__{
        agent_id: agent_id,
        socket_pid: socket_pid,
        hostname: agent_info[:hostname],
        organization_id: organization_id,
        os_type: agent_info[:os_type],
        config: agent_info[:config] || %{},
        connected_at: System.system_time(:millisecond),
        last_heartbeat: System.system_time(:millisecond),
        last_db_heartbeat: System.system_time(:millisecond)
      }

      # Monitor the socket process only after persistence and registration succeed.
      Process.monitor(socket_pid)

      schedule_heartbeat_check()
      schedule_presence_tick()

      # Avoid blocking channel join on database latency during worker init.
      # In the light lab environment, the first boot can be DB-heavy.
      Process.send_after(self(), :send_pending_commands, 0)

      Logger.info("Worker started for agent #{agent_id}")
      {:ok, state}
    else
      {:error, reason} ->
        Logger.warning("Worker rejected for agent #{agent_id}: #{inspect(reason)}")
        {:stop, reason}
    end
  end

  defp authenticated_organization_id(agent_info) do
    organization_id = agent_info[:organization_id]

    cond do
      not Registry.canonical_organization_id?(organization_id) ->
        {:error, :invalid_organization_id}

      match?(%Organization{id: ^organization_id}, Repo.get(Organization, organization_id)) ->
        {:ok, organization_id}

      true ->
        {:error, :organization_not_found}
    end
  rescue
    error -> {:error, {:organization_lookup_failed, error}}
  end

  defp persist_agent_to_db(agent_id, agent_info, organization_id) do
    now = NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second)

    # Generate a machine_id from agent_id if not provided
    machine_id = agent_info[:machine_id] || :crypto.hash(:sha256, agent_id)

    config =
      agent_info
      |> Map.get(:config, %{})
      |> put_reported_agent_runtime(agent_info)

    # Build base attributes
    attrs = %{
      id: agent_id,
      hostname: agent_info[:hostname] || "unknown",
      ip_address: agent_info[:ip_address] || "unknown",
      os_type: agent_info[:os_type] || "unknown",
      os_version: agent_info[:os_version],
      agent_version: agent_info[:agent_version],
      machine_id: machine_id,
      status: "online",
      last_seen_at: now,
      config: config,
      organization_id: organization_id,
      inserted_at: now,
      updated_at: now
    }

    # Add certificate information if present
    attrs = maybe_add_cert_fields(attrs, agent_info)

    # Fields to update on conflict
    update_fields = [
      :hostname,
      :ip_address,
      :os_type,
      :os_version,
      :agent_version,
      :status,
      :last_seen_at,
      :config,
      :updated_at
    ]

    # Add certificate fields to update list if present
    update_fields =
      if agent_info[:certificate_fingerprint] do
        [:certificate_fingerprint, :certificate_subject, :certificate_valid_until | update_fields]
      else
        update_fields
      end

    case Repo.transaction(fn ->
           with :ok <- lock_agent_identity(agent_id),
                :ok <- ensure_agent_tenant_matches(agent_id, organization_id),
                {count, _} when count in [0, 1] <-
                  Repo.insert_all(
                    Agent,
                    [attrs],
                    on_conflict: {:replace, update_fields},
                    conflict_target: :id
                  ),
                :ok <- ensure_agent_tenant_matches(agent_id, organization_id) do
             :ok
           else
             {:error, reason} -> Repo.rollback(reason)
             error -> Repo.rollback({:agent_persistence_failed, error})
           end
         end) do
      {:ok, :ok} ->
        OrgLookup.put(agent_id, organization_id)
        Logger.debug("Agent #{agent_id} persisted to database")
        :ok

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    error -> {:error, {:agent_persistence_failed, error}}
  end

  defp lock_agent_identity(agent_id) do
    case Repo.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [agent_id]) do
      {:ok, _result} -> :ok
      {:error, reason} -> {:error, {:agent_lock_failed, reason}}
    end
  end

  defp ensure_agent_tenant_matches(agent_id, organization_id) do
    case Repo.get(Agent, agent_id) do
      nil -> :ok
      %Agent{organization_id: ^organization_id} -> :ok
      %Agent{} -> {:error, :agent_tenant_mismatch}
    end
  end

  defp put_reported_agent_runtime(config, agent_info) do
    config = config || %{}

    config
    |> maybe_put_config("reported_capabilities", agent_info[:capabilities])
    |> maybe_put_config("reported_collectors", agent_info[:collectors])
    |> maybe_put_config("reported_runtime", %{
      "reported_at" => DateTime.utc_now() |> DateTime.to_iso8601(),
      "source" => "agent_connect"
    })
  end

  defp maybe_put_config(config, _key, value) when value in [nil, [], %{}], do: config
  defp maybe_put_config(config, key, value), do: Map.put(config, key, value)

  defp maybe_add_cert_fields(attrs, agent_info) do
    if agent_info[:certificate_fingerprint] do
      attrs
      |> Map.put(:certificate_fingerprint, agent_info[:certificate_fingerprint])
      |> Map.put(:certificate_subject, agent_info[:certificate_subject])
      |> Map.put(:certificate_valid_until, to_naive(agent_info[:certificate_valid_until]))
    else
      attrs
    end
  end

  defp to_naive(nil), do: nil
  defp to_naive(%DateTime{} = dt), do: DateTime.to_naive(dt)
  defp to_naive(%NaiveDateTime{} = ndt), do: ndt

  @impl true
  def handle_call({:send_command, command}, from, state) do
    command_type =
      Map.get(command, :command_type) ||
        Map.get(command, "command_type") ||
        Map.get(command, :type) ||
        Map.get(command, "type")

    command_params =
      Map.get(command, :payload) ||
        Map.get(command, "payload") ||
        Map.get(command, :params) ||
        Map.get(command, "params", %{})

    priority = Map.get(command, :priority) || Map.get(command, "priority", 0)
    timeout_seconds = Map.get(command, :timeout) || Map.get(command, "timeout", 3600)

    idempotency_key =
      Map.get(command, :idempotency_key) || Map.get(command, "idempotency_key")

    # Insert command into database (idempotent when a key is provided)
    case AgentCommand.insert_new(%{
           agent_id: state.agent_id,
           command_type: to_string(command_type),
           command_params: command_params,
           priority: priority,
           status: "pending",
           idempotency_key: idempotency_key,
           expires_at: AgentCommand.utc_now_second() |> DateTime.add(timeout_seconds, :second)
         }) do
      {:ok, cmd} ->
        # Send the command immediately
        full_command = %{
          command_id: cmd.id,
          command_type: cmd.command_type,
          payload: cmd.command_params,
          timestamp: DateTime.to_unix(cmd.inserted_at, :millisecond)
        }

        send(state.socket_pid, {:send_command, full_command})

        # Mark as sent in database (increments dispatch bookkeeping)
        Repo.update!(AgentCommand.mark_dispatched(cmd))

        # Store the GenServer caller in state for reply later.
        # This allows us to reply when we get the response from the agent.
        state = put_command_callback(state, cmd.id, from)

        # Schedule a timeout for this specific command
        Process.send_after(self(), {:command_timeout, cmd.id}, timeout_seconds * 1000)

        {:noreply, state}

      {:existing, cmd} ->
        # Idempotency-key hit: a UI/API retry of an already-created command.
        # Do not insert or re-dispatch. Terminal rows replay their persisted
        # result; in-flight rows attach this caller to the original command so
        # they cannot be mistaken for a successful execution.
        Logger.info(
          "Idempotent send_command replay for agent #{state.agent_id}: " <>
            "key=#{inspect(idempotency_key)} existing command #{cmd.id} (#{cmd.status})"
        )

        case cmd.status do
          "completed" ->
            {:reply, {:ok, cmd.result || %{command_id: cmd.id, status: "completed"}}, state}

          "failed" ->
            {:reply, {:error, cmd.error || :command_failed}, state}

          status when status in ["pending", "sent", "acknowledged"] ->
            {:reply, {:error, {:command_in_progress, cmd.id}}, state}

          status ->
            {:reply, {:error, {:command_state_unknown, cmd.id, status}}, state}
        end

      {:error, changeset} ->
        Logger.error("Failed to insert command: #{inspect(changeset.errors)}")
        {:reply, {:error, :command_insert_failed}, state}
    end
  end

  @impl true
  def handle_call(:get_state, _from, state) do
    # Count pending commands from database
    pending_count =
      Repo.one(
        from(c in AgentCommand,
          where:
            c.agent_id == ^state.agent_id and c.status in ["pending", "sent", "acknowledged"],
          select: count(c.id)
        )
      )

    info = %{
      agent_id: state.agent_id,
      hostname: state.hostname,
      os_type: state.os_type,
      connected_at: state.connected_at,
      last_heartbeat: state.last_heartbeat,
      pending_commands: pending_count
    }

    {:reply, info, state}
  end

  @impl true
  def handle_cast({:telemetry, telemetry_batch}, state) do
    events = telemetry_batch[:events] || []
    Logger.debug("Worker: Processing #{length(events)} events for agent #{state.agent_id}")

    Registry.heartbeat(state.agent_id)
    now = System.system_time(:millisecond)
    state = maybe_persist_online_heartbeat(%{state | last_heartbeat: now}, now)

    # Forward to Broadway pipeline for processing
    Ingestor.push_batch(telemetry_batch)

    # Quick check for critical events
    check_critical_events(telemetry_batch, state)

    {:noreply, state}
  end

  @impl true
  def handle_cast(:heartbeat, state) do
    Registry.heartbeat(state.agent_id)

    now = System.system_time(:millisecond)
    state = maybe_persist_online_heartbeat(%{state | last_heartbeat: now}, now)

    {:noreply, state}
  end

  @impl true
  def handle_cast({:command_response, response}, state) do
    # Phoenix Channel payloads use string keys from JSON
    command_id = response["command_id"] || response[:command_id]
    success = command_response_success(response)
    result_status = command_response_result_status(response)
    response_command_type = response["command_type"] || response[:command_type]

    status = command_response_lifecycle_status(response, success, result_status)

    result =
      response
      |> command_response_result()
      |> audit_command_result(response_command_type, result_status, response)

    error =
      response["error"] || response[:error] || response["error_message"] ||
        response[:error_message]

    cond do
      realtime_command_id?(command_id) ->
        {context, realtime_commands} = Map.pop(state.realtime_commands, command_id)
        state = %{state | realtime_commands: realtime_commands}
        handle_realtime_command_response(command_id, status, error, response, context, state)
        {:noreply, state}

      true ->
        handle_persisted_command_response(command_id, status, result, error, response, state)
    end
  end

  @impl true
  def handle_cast({:realtime_output, payload}, state) do
    {:noreply, acknowledge_realtime_output(payload, state)}
  end

  defp handle_persisted_command_response(command_id, status, result, error, response, state) do
    case Repo.get_by(AgentCommand, id: command_id, agent_id: state.agent_id) do
      nil ->
        Logger.warning(
          "Received response for unknown command or wrong agent: command=#{inspect(command_id)} agent=#{state.agent_id}"
        )

        {:noreply, state}

      %AgentCommand{status: terminal} when terminal in ["completed", "failed"] ->
        Logger.debug(
          "Ignoring duplicate terminal response for command #{command_id} on agent #{state.agent_id}"
        )

        {from, state} = pop_command_callback(state, command_id)

        if from do
          reply =
            if terminal == "completed" do
              {:ok, result || response}
            else
              {:error, error || command_failed_error(result) || "Command failed"}
            end

          GenServer.reply(from, reply)
        end

        {:noreply, state}

      cmd ->
        # Update command status in database
        changeset =
          case status do
            "acknowledged" ->
              AgentCommand.mark_acknowledged(cmd)

            "completed" ->
              AgentCommand.mark_completed(cmd, result)

            "failed" ->
              mark_command_failed(
                cmd,
                error || command_failed_error(result) || "Unknown error",
                result
              )

            _ ->
              AgentCommand.mark_completed(cmd, result)
          end

        case Repo.update(changeset) do
          {:ok, _} ->
            :ok

          {:error, reason} ->
            Logger.warning(
              "Failed to persist command #{command_id} status update: #{inspect(reason)}"
            )
        end

        if status == "acknowledged" do
          # ACK means the endpoint accepted the command, not that the response
          # action completed. Keep the original caller attached until a
          # completed/failed response or timeout arrives.
          {:noreply, state}
        else
          {from, state} = pop_command_callback(state, command_id)

          case from do
            nil ->
              Logger.debug("No callback waiting for command #{command_id}")

            from when status == "completed" ->
              GenServer.reply(from, {:ok, result || response})

            from ->
              GenServer.reply(
                from,
                {:error, error || command_failed_error(result) || "Command failed"}
              )
          end

          {:noreply, state}
        end
    end
  end

  defp command_response_success(response) when is_map(response) do
    cond do
      Map.has_key?(response, "success") -> Map.get(response, "success")
      Map.has_key?(response, :success) -> Map.get(response, :success)
      true -> nil
    end
  end

  defp command_response_result(response) when is_map(response) do
    response["result"] || response[:result] || response["result_data"] || response[:result_data]
  end

  defp command_response_result_status(response) when is_map(response) do
    response["result_status"] || response[:result_status]
  end

  defp command_response_lifecycle_status(response, success, result_status) do
    explicit_status = response["status"] || response[:status]

    case explicit_status && String.downcase(to_string(explicit_status)) do
      "acknowledged" ->
        "acknowledged"

      status when status in ["failed", "error"] ->
        "failed"

      status when status in ["completed", "complete", "success", "ok"] ->
        "completed"

      _ ->
        cond do
          success == false -> "failed"
          normalize_result_status(result_status) == "failed" -> "failed"
          true -> "completed"
        end
    end
  end

  defp audit_command_result(result, command_type, result_status, response) do
    normalized_status = normalize_result_status(result_status)

    result
    |> result_map()
    |> maybe_put_audit_value("command_type", command_type)
    |> maybe_put_audit_value("result_status", normalized_status)
    |> maybe_put_audit_value("executed_at", response["executed_at"] || response[:executed_at])
    |> maybe_put_command_delivery_audit(response, normalized_status)
  end

  defp result_map(nil), do: %{}
  defp result_map(%{} = result), do: result
  defp result_map(result), do: %{"value" => result}

  defp maybe_put_audit_value(result, _key, nil), do: result
  defp maybe_put_audit_value(result, _key, ""), do: result
  defp maybe_put_audit_value(result, key, value), do: Map.put_new(result, key, value)

  defp maybe_put_command_delivery_audit(result, response, normalized_status) do
    existing = result["command_delivery"] || result[:command_delivery]

    if is_map(existing) do
      result
    else
      audit = %{
        "schema_version" => "tamandua.command_delivery_audit/v1",
        "received_by_server_at" =>
          DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601(),
        "executed_at" => response["executed_at"] || response[:executed_at],
        "agent_reported_status" => normalized_status,
        "agent_response_audit" => result["response_audit"] || result[:response_audit]
      }

      Map.put(result, "command_delivery", audit)
    end
  end

  defp normalize_result_status(status) when is_atom(status),
    do: status |> Atom.to_string() |> normalize_result_status()

  defp normalize_result_status(status) when is_binary(status) do
    normalized = status |> String.trim() |> String.downcase()

    if normalized in @command_result_statuses do
      normalized
    else
      nil
    end
  end

  defp normalize_result_status(_status), do: nil

  defp command_failed_error(%{} = result) do
    result["error"] || result[:error] || result["message"] || result[:message]
  end

  defp command_failed_error(_result), do: nil

  defp mark_command_failed(command, error, result) do
    command
    |> AgentCommand.mark_failed(error)
    |> Ecto.Changeset.change(result: result)
  end

  @impl true
  def handle_info({:DOWN, _ref, :process, pid, reason}, %{socket_pid: pid} = state) do
    Logger.info("Socket disconnected for agent #{state.agent_id}: #{inspect(reason)}")

    unregister_and_mark_offline_if_current(state)

    # Reply error to any pending command callbacks
    Enum.each(state.command_callbacks, fn {_cmd_id, from} ->
      GenServer.reply(from, {:error, :disconnected})
    end)

    {:stop, :normal, %{state | command_callbacks: %{}}}
  end

  @impl true
  def handle_info(:check_heartbeat, state) do
    now = System.system_time(:millisecond)
    elapsed = now - state.last_heartbeat

    if elapsed > @heartbeat_timeout do
      Logger.warning("Agent #{state.agent_id} heartbeat timeout")
      create_agent_blinded_alert(state, elapsed)
      unregister_and_mark_offline_if_current(state)
      {:stop, :heartbeat_timeout, state}
    else
      schedule_heartbeat_check()
      {:noreply, state}
    end
  end

  @impl true
  def handle_info(:send_pending_commands, state) do
    {:noreply, maybe_send_pending_commands(state)}
  end

  @impl true
  def handle_info(:persist_presence_tick, state) do
    now = System.system_time(:millisecond)

    state =
      if Process.alive?(state.socket_pid) do
        Registry.heartbeat(state.agent_id)
        maybe_persist_online_heartbeat(%{state | last_heartbeat: now}, now)
      else
        state
      end

    schedule_presence_tick()
    {:noreply, state}
  end

  @impl true
  def handle_info({:push_to_agent, event, payload}, state) do
    command_type = realtime_command_type(event, payload)
    command_id = "rt_" <> Base.encode16(:crypto.strong_rand_bytes(12), case: :lower)

    full_command = %{
      command_id: command_id,
      command_type: command_type,
      payload: payload,
      timestamp: System.system_time(:millisecond)
    }

    state = %{
      state
      | realtime_commands: Map.put(state.realtime_commands, command_id, {event, payload || %{}})
    }

    if command_type == "shell_input" do
      Logger.debug("Realtime command #{command_id} #{command_type} sent to #{state.agent_id}")
    else
      Logger.info("Realtime command #{command_id} #{command_type} sent to #{state.agent_id}")
    end

    send(state.socket_pid, {:send_command, full_command})
    Process.send_after(self(), {:realtime_command_timeout, command_id}, 15_000)
    {:noreply, state}
  end

  @impl true
  def handle_info({:realtime_command_timeout, command_id}, state) do
    {context, realtime_commands} = Map.pop(state.realtime_commands, command_id)
    state = %{state | realtime_commands: realtime_commands}

    case context do
      nil ->
        :ok

      {event, payload} ->
        Logger.warning("Realtime command #{command_id} #{event} timed out for #{state.agent_id}")

        maybe_broadcast_realtime_timeout(state.agent_id, event, payload)
    end

    {:noreply, state}
  end

  @impl true
  def handle_info({:command_timeout, command_id}, state) do
    # Check if command is still pending
    case Repo.get(AgentCommand, command_id) do
      nil ->
        # Command doesn't exist; drop any stale callback for it
        {_from, state} = pop_command_callback(state, command_id)
        {:noreply, state}

      cmd ->
        if cmd.status not in ["completed", "failed"] do
          Logger.warning("Command #{command_id} timed out for agent #{state.agent_id}")

          # Mark as failed in database
          case Repo.update(AgentCommand.mark_failed(cmd, "Command timeout")) do
            {:ok, _} ->
              :ok

            {:error, reason} ->
              Logger.warning(
                "Failed to persist timeout for command #{command_id}: #{inspect(reason)}"
              )
          end

          # Reply to caller if still waiting
          {from, state} = pop_command_callback(state, command_id)

          case from do
            nil -> :ok
            from -> GenServer.reply(from, {:error, :timeout})
          end

          {:noreply, state}
        else
          # Terminal already (caller was answered on command_response);
          # just make sure no callback entry leaks.
          {_from, state} = pop_command_callback(state, command_id)
          {:noreply, state}
        end
    end
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  @impl true
  def terminate(reason, state) do
    Logger.info("Worker terminating for agent #{state.agent_id}: #{inspect(reason)}")
    unregister_and_mark_offline_if_current(state)
    :ok
  end

  # Private functions

  defp schedule_heartbeat_check do
    Process.send_after(self(), :check_heartbeat, @heartbeat_timeout)
  end

  defp schedule_presence_tick do
    Process.send_after(self(), :persist_presence_tick, @presence_tick_interval)
  end

  defp create_agent_blinded_alert(state, elapsed_ms) do
    attrs = %{
      severity: "high",
      title: "Agent heartbeat lost without clean shutdown",
      description:
        "Tamandua stopped receiving heartbeats from #{state.hostname || state.agent_id} while its agent socket was still registered. Treat as possible agent blinding, tamper, or BYOVD activity until proven otherwise.",
      agent_id: state.agent_id,
      organization_id: state.organization_id,
      mitre_tactics: ["defense-evasion"],
      mitre_techniques: ["T1562"],
      threat_score: 0.82,
      dedup_key: "agent_blinded:#{state.agent_id}",
      raw_event: %{
        "event_type" => "agent_blinded",
        "source" => "agent_runtime",
        "agent_id" => state.agent_id,
        "hostname" => state.hostname,
        "os_type" => state.os_type,
        "elapsed_ms" => elapsed_ms,
        "heartbeat_timeout_ms" => @heartbeat_timeout,
        "connected_at_ms" => state.connected_at,
        "last_heartbeat_ms" => state.last_heartbeat
      },
      detection_metadata: %{
        "source" => "agent_runtime",
        "category" => "agent_self_protection",
        "detection_type" => "agent_blinded",
        "rule_id" => "agent_blinded_heartbeat_timeout_v1",
        "clean_shutdown_observed" => false,
        "containment" => "server_side_alert_only"
      },
      evidence: %{
        "agent" => %{
          "id" => state.agent_id,
          "hostname" => state.hostname,
          "os_type" => state.os_type,
          "last_heartbeat_ms" => state.last_heartbeat,
          "elapsed_ms" => elapsed_ms
        }
      },
      recommended_response:
        "Verify endpoint health from network/identity telemetry and investigate recent driver-load or tamper indicators before trusting endpoint-only absence of alerts.",
      false_positive_notes:
        "Expected during host sleep, network loss, server failover, or controlled agent restart if no clean shutdown signal is wired yet."
    }

    case Alerts.create_alert(attrs) do
      {:ok, _alert} ->
        :ok

      {:error, reason} ->
        Logger.warning(
          "Failed to create agent blinded alert for #{state.agent_id}: #{inspect(reason)}"
        )

        :ok
    end
  end

  defp maybe_persist_online_heartbeat(state, now) do
    if now - state.last_db_heartbeat >= @db_heartbeat_throttle do
      case Agents.mark_agent_online(state.agent_id, state.organization_id) do
        :ok ->
          %{state | last_db_heartbeat: now}

        {:error, reason} ->
          Logger.debug("Failed to persist heartbeat for #{state.agent_id}: #{inspect(reason)}")
          state
      end
    else
      state
    end
  end

  defp unregister_and_mark_offline_if_current(state) do
    if current_worker?(state.agent_id) do
      Registry.unregister(state.agent_id)

      case Agents.mark_agent_offline(state.agent_id, state.organization_id) do
        :ok ->
          :ok

        {:error, reason} ->
          Logger.debug("Failed to mark #{state.agent_id} offline: #{inspect(reason)}")
      end
    else
      Logger.debug(
        "Skipping unregister/offline for #{state.agent_id} because a newer worker is active"
      )
    end
  end

  defp current_worker?(agent_id) do
    case Registry.get(agent_id) do
      {:ok, %{worker_pid: wp}} when wp == self() -> true
      {:ok, entry} when is_map(entry) -> entry[:worker_pid] == self()
      {:error, :not_found} -> true
      _ -> false
    end
  end

  defp maybe_send_pending_commands(state) do
    if skip_pending_commands_on_init?() do
      state
    else
      send_pending_commands(state)
    end
  rescue
    e ->
      Logger.warning("Failed to send pending commands for #{state.agent_id}: #{inspect(e)}")
      state
  catch
    :exit, reason ->
      Logger.warning("Pending command lookup exited for #{state.agent_id}: #{inspect(reason)}")
      state
  end

  # (Re)deliver queued commands: "pending" (never pushed) and "sent" (pushed
  # but never acknowledged — the worker/channel may have died between
  # mark_sent and actual delivery). Agent-side execution is idempotent by
  # command id, so re-delivering "sent" is safe. AgentCommand.dispatch_decision/2
  # guards against tight redelivery loops (attempt cap + cooldown).
  defp send_pending_commands(state) do
    # Get deliverable commands from database, ordered by priority and age
    commands =
      AgentCommand.pending_for_agent(state.agent_id, pending_command_batch_limit())
      |> Repo.all()

    {dispatched, state} =
      Enum.reduce(commands, {0, state}, fn cmd, {dispatched, state} ->
        case AgentCommand.dispatch_decision(cmd) do
          :dispatch ->
            dispatch_persisted_command(cmd, state)
            {dispatched + 1, state}

          :skip_recently_dispatched ->
            # An attempt is already in flight (< cooldown); don't double-push.
            {dispatched, state}

          {:fail, reason} ->
            {dispatched, fail_exhausted_command(cmd, reason, state)}
        end
      end)

    if dispatched > 0 do
      Logger.info("Sent #{dispatched} pending commands to agent #{state.agent_id}")
    end

    state
  end

  defp dispatch_persisted_command(cmd, state) do
    full_command = %{
      command_id: cmd.id,
      command_type: cmd.command_type,
      payload: cmd.command_params,
      timestamp: DateTime.to_unix(cmd.inserted_at, :millisecond)
    }

    send(state.socket_pid, {:send_command, full_command})

    # Mark as sent and record the dispatch attempt
    Repo.update!(AgentCommand.mark_dispatched(cmd))

    # Calculate timeout based on expires_at
    timeout_ms =
      if cmd.expires_at do
        diff = DateTime.diff(cmd.expires_at, DateTime.utc_now(), :millisecond)
        # At least 1 second
        max(diff, 1000)
      else
        # Default 1 hour
        3600 * 1000
      end

    # Schedule timeout
    Process.send_after(self(), {:command_timeout, cmd.id}, timeout_ms)
    :ok
  end

  defp fail_exhausted_command(cmd, reason, state) do
    Logger.warning(
      "Command #{cmd.id} (#{cmd.command_type}) for agent #{state.agent_id} " <>
        "exhausted dispatch attempts: #{reason}"
    )

    case Repo.update(AgentCommand.mark_failed(cmd, reason)) do
      {:ok, _} ->
        :ok

      {:error, update_error} ->
        Logger.warning(
          "Failed to persist dispatch exhaustion for command #{cmd.id}: #{inspect(update_error)}"
        )
    end

    # If a caller from this worker is still waiting on it, unblock them.
    {from, state} = pop_command_callback(state, cmd.id)

    case from do
      nil -> :ok
      from -> GenServer.reply(from, {:error, :dispatch_limit_exceeded})
    end

    state
  end

  defp pending_command_batch_limit do
    Application.get_env(
      :tamandua_server,
      :pending_command_batch_limit,
      @pending_command_batch_limit
    )
  end

  defp put_command_callback(state, command_id, from) do
    %{state | command_callbacks: Map.put(state.command_callbacks, command_id, from)}
  end

  defp pop_command_callback(state, command_id) do
    {from, callbacks} = Map.pop(state.command_callbacks, command_id)
    {from, %{state | command_callbacks: callbacks}}
  end

  defp skip_pending_commands_on_init? do
    System.get_env("TAMANDUA_LAB_LIGHT", "false") == "true"
  end

  defp realtime_command_type("shell:start", _payload), do: "shell_start"
  defp realtime_command_type("shell:input", %{"type" => "resize"}), do: "shell_resize"
  defp realtime_command_type("shell:input", %{"type" => "terminate"}), do: "shell_terminate"
  defp realtime_command_type("shell:input", _payload), do: "shell_input"
  defp realtime_command_type("shell:resize", _payload), do: "shell_resize"
  defp realtime_command_type("shell:terminate", _payload), do: "shell_terminate"

  defp realtime_command_type(event, _payload),
    do: event |> to_string() |> String.replace(":", "_")

  defp handle_realtime_command_response(command_id, status, error, response, context, state) do
    Logger.info(
      "Realtime command response #{command_id} for #{state.agent_id}: " <>
        "status=#{inspect(status)} success=#{inspect(response["success"] || response[:success])} " <>
        "error=#{inspect(error)}"
    )

    case context do
      {"shell:start", %{"session_id" => session_id}} ->
        if realtime_failed?(status, error, response) do
          broadcast_shell_message(state.agent_id, %{
            "type" => "error",
            "session_id" => session_id,
            "message" => error || "Failed to start shell"
          })
        end

      {"shell:input", %{"session_id" => session_id}} ->
        if realtime_failed?(status, error, response) do
          broadcast_shell_message(state.agent_id, %{
            "type" => "error",
            "session_id" => session_id,
            "message" => error || "Shell input failed"
          })
        end

      _ ->
        :ok
    end
  end

  defp realtime_failed?(status, error, response) do
    response["success"] == false or response[:success] == false or status in ["failed", :failed] or
      not is_nil(error)
  end

  defp acknowledge_realtime_output(payload, state) when is_map(payload) do
    session_id = payload["session_id"] || payload[:session_id]

    case payload["type"] || payload[:type] do
      "session_started" -> acknowledge_realtime_command("shell:start", session_id, state)
      "data" -> acknowledge_realtime_command("shell:input", session_id, state)
      "builtin_result" -> acknowledge_realtime_command("shell:input", session_id, state)
      _ -> state
    end
  end

  defp acknowledge_realtime_output(_, state), do: state

  defp acknowledge_realtime_command(_event, nil, state), do: state

  defp acknowledge_realtime_command(event, session_id, state) do
    state.realtime_commands
    |> Enum.find(fn
      {_command_id, {^event, %{"session_id" => ^session_id}}} -> true
      {_command_id, {^event, %{session_id: ^session_id}}} -> true
      _ -> false
    end)
    |> case do
      {command_id, _context} ->
        %{state | realtime_commands: Map.delete(state.realtime_commands, command_id)}

      nil ->
        state
    end
  end

  defp maybe_broadcast_realtime_timeout(_agent_id, "shell:start", %{"session_id" => _session_id}),
    do: :ok

  defp maybe_broadcast_realtime_timeout(_agent_id, "shell:input", %{"session_id" => _session_id}),
    do: :ok

  defp maybe_broadcast_realtime_timeout(_agent_id, _event, _payload), do: :ok

  defp broadcast_shell_message(agent_id, payload) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "shell:#{agent_id}",
      {:agent_message, payload}
    )
  end

  defp default_shell_name(%{os_type: os}) when is_binary(os) do
    if String.downcase(os) == "windows", do: "cmd.exe", else: "/bin/sh"
  end

  defp default_shell_name(_state), do: "shell"

  defp realtime_command_id?(command_id) when is_binary(command_id),
    do: String.starts_with?(command_id, "rt_")

  defp realtime_command_id?(_), do: false

  defp check_critical_events(telemetry_batch, state) do
    # Check for events that need immediate attention
    events = telemetry_batch[:events] || []

    Enum.each(events, fn event ->
      event_type = event[:event_type] || event["event_type"]

      case event_type do
        type when type in [:honeyfile_access, "honeyfile_access"] ->
          # Honeyfile triggered - immediate response
          Engine.handle_critical_event(state.agent_id, event)

        type when type in [:process_inject, "process_inject"] ->
          # Process injection detected
          Engine.handle_critical_event(state.agent_id, event)

        _ ->
          :ok
      end
    end)
  end
end
