defmodule TamanduaServer.Response.ProcessManager do
  @moduledoc """
  Process Manager for Live Response

  Handles process management commands including:
  - Process tree enumeration
  - Process termination (kill)
  - Process suspend/resume
  - Priority management
  - Handle inspection
  - Memory dumping

  ## Delivery contract (asynchronous)

  Every function queues a persisted command through
  `TamanduaServer.Agents.CommandManager.queue_command/4` and returns
  `{:ok, %{command_id: id, status: :queued}}` immediately. The command is
  pushed to the agent over its live channel by `Agents.Worker`
  (`dispatch_persisted_command/2`), and the agent's `command_response` is
  persisted back onto the `AgentCommand` row by the worker
  (`handle_persisted_command_response/6`). Poll the outcome with
  `CommandManager.get_command(command_id)`: `command.result` holds the
  agent's `result_data` once `command.status` is `"completed"`.

  There is deliberately NO synchronous wait here: the previous
  implementation broadcast `{:command, ...}` on the `"agent:<id>"` PubSub
  topic (no handler existed anywhere, the message died in the agent
  channel's catch-all `handle_info/2`) and then blocked in a `receive` for
  a `{:command_result, ...}` message that could never arrive - a
  guaranteed 30s timeout. It also called the nonexistent module
  `TamanduaServer.Agents.AgentRegistry`, so it crashed before even
  reaching the dead broadcast.
  """

  alias TamanduaServer.Agents.CommandManager
  require Logger

  @doc """
  Get process tree from an agent.

  Options:
  - `include_security_checks` - Include security detections (default: true)
  - `filter_elevated` - Only return elevated processes (default: false)

  Returns:
  - `{:ok, %{command_id: id, status: :queued}}` - command queued for the agent;
    the tree arrives asynchronously in `AgentCommand.result`
  - `{:error, reason}`
  """
  def get_process_tree(agent_id, opts \\ []) do
    include_security_checks = Keyword.get(opts, :include_security_checks, true)
    filter_elevated = Keyword.get(opts, :filter_elevated, false)

    payload = %{
      include_security_checks: include_security_checks,
      filter_elevated: filter_elevated
    }

    case execute_command(agent_id, :process_tree_list, payload) do
      {:ok, queued} ->
        {:ok, queued}

      {:error, reason} = error ->
        Logger.error("Failed to queue process tree request for agent #{agent_id}: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Kill a process on the agent.

  Options:
  - `force` - Use SIGKILL/TerminateProcess instead of graceful termination (default: false)

  Returns:
  - `{:ok, %{command_id: id, status: :queued}}`
  - `{:error, reason}`
  """
  def kill_process(agent_id, pid, opts \\ []) do
    force = Keyword.get(opts, :force, false)

    payload = %{
      pid: pid,
      force: force
    }

    case execute_command(agent_id, :process_kill, payload) do
      {:ok, queued} ->
        Logger.info("Process kill for pid #{pid} queued for agent #{agent_id} (command #{queued.command_id})")
        {:ok, queued}

      {:error, reason} = error ->
        Logger.error("Failed to queue kill for process #{pid} on agent #{agent_id}: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Suspend all threads of a process.

  Returns:
  - `{:ok, %{command_id: id, status: :queued}}`
  - `{:error, reason}`
  """
  def suspend_process(agent_id, pid) do
    payload = %{pid: pid}

    case execute_command(agent_id, :process_suspend, payload) do
      {:ok, queued} ->
        Logger.info("Process suspend for pid #{pid} queued for agent #{agent_id} (command #{queued.command_id})")
        {:ok, queued}

      {:error, reason} = error ->
        Logger.error("Failed to queue suspend for process #{pid} on agent #{agent_id}: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Resume all threads of a process.

  Returns:
  - `{:ok, %{command_id: id, status: :queued}}`
  - `{:error, reason}`
  """
  def resume_process(agent_id, pid) do
    payload = %{pid: pid}

    case execute_command(agent_id, :process_resume, payload) do
      {:ok, queued} ->
        Logger.info("Process resume for pid #{pid} queued for agent #{agent_id} (command #{queued.command_id})")
        {:ok, queued}

      {:error, reason} = error ->
        Logger.error("Failed to queue resume for process #{pid} on agent #{agent_id}: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Set process priority.

  Priority levels:
  - "realtime" - Real-time priority (use with caution)
  - "high" - High priority
  - "above_normal" - Above normal priority
  - "normal" - Normal priority
  - "below_normal" - Below normal priority
  - "idle" / "low" - Idle priority

  Returns:
  - `{:ok, %{command_id: id, status: :queued}}`
  - `{:error, reason}`
  """
  def set_process_priority(agent_id, pid, priority) when priority in [
    "realtime", "high", "above_normal", "normal", "below_normal", "idle", "low"
  ] do
    payload = %{
      pid: pid,
      priority: priority
    }

    case execute_command(agent_id, :process_set_priority, payload) do
      {:ok, queued} ->
        Logger.info("Priority #{priority} for pid #{pid} queued for agent #{agent_id} (command #{queued.command_id})")
        {:ok, queued}

      {:error, reason} = error ->
        Logger.error("Failed to queue priority change for process #{pid} on agent #{agent_id}: #{inspect(reason)}")
        error
    end
  end

  def set_process_priority(_agent_id, _pid, priority) do
    {:error, "Invalid priority: #{priority}"}
  end

  @doc """
  List handles (open files, sockets, registry keys, etc.) for a process.

  Options:
  - `type` - Filter by handle type: "file", "socket", "registry", etc. (default: all)

  Returns:
  - `{:ok, %{command_id: id, status: :queued}}`
  - `{:error, reason}`
  """
  def list_handles(agent_id, pid, opts \\ []) do
    handle_type = Keyword.get(opts, :type)

    payload = %{
      pid: pid,
      type: handle_type
    }

    case execute_command(agent_id, :process_list_handles, payload) do
      {:ok, queued} ->
        {:ok, queued}

      {:error, reason} = error ->
        Logger.error("Failed to queue handle listing for process #{pid} on agent #{agent_id}: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Create a process memory dump (minidump).

  Options:
  - `include_strings` - Also extract strings from memory (default: false)

  Returns:
  - `{:ok, %{command_id: id, status: :queued}}`
  - `{:error, reason}`
  """
  def create_process_dump(agent_id, pid, opts \\ []) do
    include_strings = Keyword.get(opts, :include_strings, false)

    payload = %{
      pid: pid,
      include_strings: include_strings
    }

    case execute_command(agent_id, :process_create_dump, payload) do
      {:ok, queued} ->
        Logger.info("Memory dump for pid #{pid} queued for agent #{agent_id} (command #{queued.command_id})")
        {:ok, queued}

      {:error, reason} = error ->
        Logger.error("Failed to queue dump for process #{pid} on agent #{agent_id}: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Batch operation: Queue kill commands for multiple processes.

  Returns:
  - `{:ok, %{succeeded: [%{pid: pid, result: %{command_id: id, status: :queued}}],
     failed: [%{pid: pid, reason: reason}]}}` - `succeeded` means the command
    was queued, not that the process has been killed
  """
  def kill_processes(agent_id, pids, opts \\ []) when is_list(pids) do
    results =
      pids
      |> Enum.map(fn pid ->
        case kill_process(agent_id, pid, opts) do
          {:ok, result} -> {:ok, pid, result}
          {:error, reason} -> {:error, pid, reason}
        end
      end)

    succeeded =
      results
      |> Enum.filter(&match?({:ok, _, _}, &1))
      |> Enum.map(fn {:ok, pid, result} -> %{pid: pid, result: result} end)

    failed =
      results
      |> Enum.filter(&match?({:error, _, _}, &1))
      |> Enum.map(fn {:error, pid, reason} -> %{pid: pid, reason: reason} end)

    {:ok, %{succeeded: succeeded, failed: failed}}
  end

  # Private functions

  # Queue the command through the persisted AgentCommand pipeline (the only
  # dispatch path with a live consumer: CommandManager.queue_command/4 ->
  # Worker.dispatch_persisted_command/2 -> push(socket, "command", ...)).
  # All command types used here are implemented by the Rust agent
  # (transport/mod.rs `CommandType`, handlers in live_response/process_manager.rs)
  # and whitelisted in `AgentCommand.@valid_command_types`.
  defp execute_command(agent_id, command_type, payload) do
    case CommandManager.queue_command(agent_id, command_type, payload) do
      {:ok, command} ->
        {:ok, %{command_id: command.id, status: :queued}}

      {:error, :agent_not_found} ->
        # The in-memory Agents.Registry only tracks connected agents, so a
        # miss means the agent is offline or was never enrolled.
        {:error, "Agent not found or offline"}

      {:error, %Ecto.Changeset{} = changeset} ->
        {:error, "Failed to queue command: #{inspect(changeset.errors)}"}

      {:error, reason} ->
        {:error, "Failed to queue command: #{inspect(reason)}"}
    end
  end
end
