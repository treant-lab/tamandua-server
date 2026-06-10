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
  @command_stale_timeout :timer.seconds(45)

  defstruct [
    :agent_id,
    :socket_pid,
    :hostname,
    :organization_id,
    :os_type,
    :config,
    :connected_at,
    :last_heartbeat,
    :last_db_heartbeat
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
    organization_id = persist_agent_to_db(agent_id, agent_info)
    agent_info =
      Map.put(agent_info, :organization_id, organization_id || agent_info[:organization_id])

    state = %__MODULE__{
      agent_id: agent_id,
      socket_pid: socket_pid,
      hostname: agent_info[:hostname],
      organization_id: agent_info[:organization_id],
      os_type: agent_info[:os_type],
      config: agent_info[:config] || %{},
      connected_at: System.system_time(:millisecond),
      last_heartbeat: System.system_time(:millisecond),
      last_db_heartbeat: System.system_time(:millisecond)
    }

    # Monitor the socket process
    Process.monitor(socket_pid)

    # Register in the agent registry
    Registry.register(agent_id, Map.put(agent_info, :worker_pid, self()))

    # Schedule heartbeat check
    schedule_heartbeat_check()
    schedule_presence_tick()

    # Avoid blocking channel join on database latency during worker init.
    # In the light lab environment, the first boot can be DB-heavy.
    Process.send_after(self(), :send_pending_commands, 0)

    Logger.info("Worker started for agent #{agent_id}")
    {:ok, state}
  end

  defp persist_agent_to_db(agent_id, agent_info) do
    now = NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second)

    # Get organization_id from agent info, OrgLookup cache, or generate a dev fallback
    org_id =
      agent_info[:organization_id]
      |> ensure_valid_org_id()
      |> case do
        nil -> ensure_valid_org_id(OrgLookup.get_org_id(agent_id))
        valid -> valid
      end

    unless org_id do
      Logger.warning("No organization_id found for agent #{agent_id}; agent will have nil org_id until assigned")
    end

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
      organization_id: org_id,
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
      :organization_id,
      :status,
      :last_seen_at,
      :config,
      :updated_at
    ]

    # Add certificate fields to update list if present
    update_fields = if agent_info[:certificate_fingerprint] do
      [:certificate_fingerprint, :certificate_subject, :certificate_valid_until | update_fields]
    else
      update_fields
    end

    # Upsert: insert or update on conflict
    case Repo.insert_all(
      Agent,
      [attrs],
      on_conflict: {:replace, update_fields},
      conflict_target: :id
    ) do
      {1, _} ->
        Logger.debug("Agent #{agent_id} persisted to database")
        if org_id, do: OrgLookup.put(agent_id, org_id)
        org_id

      {0, _} ->
        Logger.debug("Agent #{agent_id} already exists, updated")
        if org_id, do: OrgLookup.put(agent_id, org_id)
        org_id

      error ->
        Logger.error("Failed to persist agent #{agent_id}: #{inspect(error)}")
        org_id
    end
  rescue
    e ->
      Logger.error("Error persisting agent to database: #{inspect(e)}")
      agent_info[:organization_id]
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

  defp ensure_valid_org_id(nil), do: nil
  defp ensure_valid_org_id(org_id) do
    case Repo.get(Organization, org_id) do
      nil ->
        Logger.warning("Organization #{org_id} missing for agent persistence; falling back to nil org_id")
        nil
      _org ->
        org_id
    end
  rescue
    _ -> nil
  end

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

    # Insert command into database
    case Repo.insert(%AgentCommand{
      agent_id: state.agent_id,
      command_type: to_string(command_type),
      command_params: command_params,
      priority: priority,
      status: "pending",
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

        # Mark as sent in database
        Repo.update!(AgentCommand.mark_sent(cmd))

        # Store the GenServer caller in process dictionary for reply later
        # This allows us to reply when we get the response from the agent
        Process.put({:command_callback, cmd.id}, from)

        # Schedule a timeout for this specific command
        Process.send_after(self(), {:command_timeout, cmd.id}, timeout_seconds * 1000)

        {:noreply, state}

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
        from c in AgentCommand,
        where: c.agent_id == ^state.agent_id and c.status in ["pending", "sent", "acknowledged"],
        select: count(c.id)
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
    success = response["success"] || response[:success]

    status =
      response["status"] ||
        response[:status] ||
        if(success == false, do: "failed", else: "completed")

    result = response["result"] || response[:result] || response["result_data"] || response[:result_data]
    error = response["error"] || response[:error] || response["error_message"] || response[:error_message]

    cond do
      realtime_command_id?(command_id) ->
        handle_realtime_command_response(command_id, status, result, error, response, state)
        {:noreply, state}

      true ->
        handle_persisted_command_response(command_id, status, result, error, response, state)
    end
  end

  @impl true
  def handle_cast({:realtime_output, payload}, state) do
    acknowledge_realtime_output(payload)
    {:noreply, state}
  end

  defp handle_persisted_command_response(command_id, status, result, error, response, state) do
    case Repo.get(AgentCommand, command_id) do
      nil ->
        Logger.warning("Received response for unknown command: #{inspect(command_id)}")

        {:noreply, state}

      cmd ->
        # Update command status in database
        changeset =
          case status do
            "acknowledged" -> AgentCommand.mark_acknowledged(cmd)
            "completed" -> AgentCommand.mark_completed(cmd, result)
            "failed" -> AgentCommand.mark_failed(cmd, error || "Unknown error")
            _ -> AgentCommand.mark_completed(cmd, result)
          end

        case Repo.update(changeset) do
          {:ok, _} ->
            :ok

          {:error, reason} ->
            Logger.warning(
              "Failed to persist command #{command_id} status update: #{inspect(reason)}"
            )
        end

        # Reply to the caller if they're still waiting
        case Process.get({:command_callback, command_id}) do
          nil ->
            Logger.debug("No callback waiting for command #{command_id}")

          from ->
            GenServer.reply(from, {:ok, result || response})
            Process.delete({:command_callback, command_id})
        end

        {:noreply, state}
    end
  end

  @impl true
  def handle_info({:DOWN, _ref, :process, pid, reason}, %{socket_pid: pid} = state) do
    Logger.info("Socket disconnected for agent #{state.agent_id}: #{inspect(reason)}")

    unregister_and_mark_offline_if_current(state)

    # Reply error to any pending command callbacks
    Process.get()
    |> Enum.filter(fn {key, _value} ->
      case key do
        {:command_callback, _cmd_id} -> true
        _ -> false
      end
    end)
    |> Enum.each(fn {{:command_callback, _cmd_id}, from} ->
      GenServer.reply(from, {:error, :disconnected})
    end)

    {:stop, :normal, state}
  end

  @impl true
  def handle_info(:check_heartbeat, state) do
    now = System.system_time(:millisecond)
    elapsed = now - state.last_heartbeat

    if elapsed > @heartbeat_timeout do
      Logger.warning("Agent #{state.agent_id} heartbeat timeout")
      unregister_and_mark_offline_if_current(state)
      {:stop, :heartbeat_timeout, state}
    else
      schedule_heartbeat_check()
      {:noreply, state}
    end
  end

  @impl true
  def handle_info(:send_pending_commands, state) do
    maybe_send_pending_commands(state)
    {:noreply, state}
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

    Process.put({:realtime_command, command_id}, {event, payload || %{}})
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
    case Process.get({:realtime_command, command_id}) do
      nil ->
        :ok

      {event, payload} ->
        Process.delete({:realtime_command, command_id})

        Logger.warning(
          "Realtime command #{command_id} #{event} timed out for #{state.agent_id}"
        )

        maybe_broadcast_realtime_timeout(state.agent_id, event, payload)
    end

    {:noreply, state}
  end

  @impl true
  def handle_info({:command_timeout, command_id}, state) do
    # Check if command is still pending
    case Repo.get(AgentCommand, command_id) do
      nil ->
        # Command doesn't exist, ignore
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
          case Process.get({:command_callback, command_id}) do
            nil -> :ok
            from ->
              GenServer.reply(from, {:error, :timeout})
              Process.delete({:command_callback, command_id})
          end
        end

        {:noreply, state}
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
        :ok -> :ok

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
      :ok
    else
      send_pending_commands(state)
    end
  rescue
    e ->
      Logger.warning("Failed to send pending commands for #{state.agent_id}: #{inspect(e)}")
      :ok
  catch
    :exit, reason ->
      Logger.warning("Pending command lookup exited for #{state.agent_id}: #{inspect(reason)}")
      :ok
  end

  defp send_pending_commands(state) do
    # Get pending commands from database, ordered by priority and age
    commands =
      AgentCommand.pending_for_agent(state.agent_id, 10)
      |> Repo.all()

    Enum.each(commands, fn cmd ->
      full_command = %{
        command_id: cmd.id,
        command_type: cmd.command_type,
        payload: cmd.command_params,
        timestamp: DateTime.to_unix(cmd.inserted_at, :millisecond)
      }

      send(state.socket_pid, {:send_command, full_command})

      # Mark as sent
      Repo.update!(AgentCommand.mark_sent(cmd))

      # Calculate timeout based on expires_at
      timeout_ms =
        if cmd.expires_at do
          diff = DateTime.diff(cmd.expires_at, DateTime.utc_now(), :millisecond)
          max(diff, 1000)  # At least 1 second
        else
          3600 * 1000  # Default 1 hour
        end

      # Schedule timeout
      Process.send_after(self(), {:command_timeout, cmd.id}, timeout_ms)
    end)

    if length(commands) > 0 do
      Logger.info("Sent #{length(commands)} pending commands to agent #{state.agent_id}")
    end
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
  defp realtime_command_type(event, _payload), do: event |> to_string() |> String.replace(":", "_")

  defp handle_realtime_command_response(command_id, status, result, error, response, state) do
    context = Process.get({:realtime_command, command_id})
    Process.delete({:realtime_command, command_id})

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

  defp acknowledge_realtime_output(payload) when is_map(payload) do
    session_id = payload["session_id"] || payload[:session_id]

    case payload["type"] || payload[:type] do
      "session_started" -> acknowledge_realtime_command("shell:start", session_id)
      "data" -> acknowledge_realtime_command("shell:input", session_id)
      "builtin_result" -> acknowledge_realtime_command("shell:input", session_id)
      _ -> :ok
    end
  end

  defp acknowledge_realtime_output(_), do: :ok

  defp acknowledge_realtime_command(_event, nil), do: :ok

  defp acknowledge_realtime_command(event, session_id) do
    Process.get()
    |> Enum.find(fn
      {{:realtime_command, _command_id}, {^event, %{"session_id" => ^session_id}}} -> true
      {{:realtime_command, _command_id}, {^event, %{session_id: ^session_id}}} -> true
      _ -> false
    end)
    |> case do
      {{:realtime_command, command_id}, _context} ->
        Process.delete({:realtime_command, command_id})

      _ ->
        :ok
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
      case event[:event_type] do
        :honeyfile_access ->
          # Honeyfile triggered - immediate response
          Engine.handle_critical_event(state.agent_id, event)

        :process_inject ->
          # Process injection detected
          Engine.handle_critical_event(state.agent_id, event)

        _ ->
          :ok
      end
    end)
  end
end
