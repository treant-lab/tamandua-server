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

  Integrates with the agent command infrastructure to execute
  process operations on remote endpoints.
  """

  alias TamanduaServer.{Agents, Response}
  alias TamanduaServer.Agents.AgentRegistry
  require Logger

  @doc """
  Get process tree from an agent.

  Options:
  - `include_security_checks` - Include security detections (default: true)
  - `filter_elevated` - Only return elevated processes (default: false)

  Returns:
  - `{:ok, %{processes: [...], tree: [...], count: integer}}`
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
      {:ok, result} ->
        {:ok, result.result_data}

      {:error, reason} = error ->
        Logger.error("Failed to get process tree from agent #{agent_id}: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Kill a process on the agent.

  Options:
  - `force` - Use SIGKILL/TerminateProcess instead of graceful termination (default: false)

  Returns:
  - `{:ok, %{pid: integer}}`
  - `{:error, reason}`
  """
  def kill_process(agent_id, pid, opts \\ []) do
    force = Keyword.get(opts, :force, false)

    payload = %{
      pid: pid,
      force: force
    }

    case execute_command(agent_id, :process_kill, payload) do
      {:ok, result} ->
        Logger.info("Process #{pid} killed on agent #{agent_id}")
        {:ok, result.result_data}

      {:error, reason} = error ->
        Logger.error("Failed to kill process #{pid} on agent #{agent_id}: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Suspend all threads of a process.

  Returns:
  - `{:ok, %{pid: integer, status: "suspended", threads_suspended: integer}}`
  - `{:error, reason}`
  """
  def suspend_process(agent_id, pid) do
    payload = %{pid: pid}

    case execute_command(agent_id, :process_suspend, payload) do
      {:ok, result} ->
        Logger.info("Process #{pid} suspended on agent #{agent_id}")
        {:ok, result.result_data}

      {:error, reason} = error ->
        Logger.error("Failed to suspend process #{pid} on agent #{agent_id}: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Resume all threads of a process.

  Returns:
  - `{:ok, %{pid: integer, status: "resumed", threads_resumed: integer}}`
  - `{:error, reason}`
  """
  def resume_process(agent_id, pid) do
    payload = %{pid: pid}

    case execute_command(agent_id, :process_resume, payload) do
      {:ok, result} ->
        Logger.info("Process #{pid} resumed on agent #{agent_id}")
        {:ok, result.result_data}

      {:error, reason} = error ->
        Logger.error("Failed to resume process #{pid} on agent #{agent_id}: #{inspect(reason)}")
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
  - `{:ok, %{pid: integer, priority: string}}`
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
      {:ok, result} ->
        Logger.info("Process #{pid} priority set to #{priority} on agent #{agent_id}")
        {:ok, result.result_data}

      {:error, reason} = error ->
        Logger.error("Failed to set priority for process #{pid} on agent #{agent_id}: #{inspect(reason)}")
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
  - `{:ok, %{pid: integer, handles: [...], count: integer}}`
  - `{:error, reason}`
  """
  def list_handles(agent_id, pid, opts \\ []) do
    handle_type = Keyword.get(opts, :type)

    payload = %{
      pid: pid,
      type: handle_type
    }

    case execute_command(agent_id, :process_list_handles, payload) do
      {:ok, result} ->
        {:ok, result.result_data}

      {:error, reason} = error ->
        Logger.error("Failed to list handles for process #{pid} on agent #{agent_id}: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Create a process memory dump (minidump).

  Options:
  - `include_strings` - Also extract strings from memory (default: false)

  Returns:
  - `{:ok, %{pid: integer, path: string, size: integer}}`
  - `{:error, reason}`
  """
  def create_process_dump(agent_id, pid, opts \\ []) do
    include_strings = Keyword.get(opts, :include_strings, false)

    payload = %{
      pid: pid,
      include_strings: include_strings
    }

    case execute_command(agent_id, :process_create_dump, payload) do
      {:ok, result} ->
        Logger.info("Memory dump created for process #{pid} on agent #{agent_id}")
        {:ok, result.result_data}

      {:error, reason} = error ->
        Logger.error("Failed to create dump for process #{pid} on agent #{agent_id}: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Batch operation: Kill multiple processes.

  Returns:
  - `{:ok, %{succeeded: [...], failed: [...]}}`
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

  defp execute_command(agent_id, command_type, payload) do
    # Check if agent is online
    case AgentRegistry.get_agent(agent_id) do
      {:ok, agent_info} when agent_info.status == :online ->
        # Create response action
        attrs = %{
          agent_id: agent_id,
          command_type: command_type,
          payload: payload,
          status: "pending",
          initiated_by: "system"  # TODO: Get from current user context
        }

        case Response.create_action(attrs) do
          {:ok, action} ->
            # Send command to agent via channel
            command_id = action.id

            # This would integrate with your channel infrastructure
            # to actually send the command to the agent
            send_command_to_agent(agent_id, command_type, payload, command_id)

            # Wait for result (with timeout)
            wait_for_result(command_id, 30_000)

          {:error, reason} ->
            {:error, "Failed to create action: #{inspect(reason)}"}
        end

      {:ok, _agent_info} ->
        {:error, "Agent is offline"}

      {:error, reason} ->
        {:error, "Agent not found: #{inspect(reason)}"}
    end
  end

  defp send_command_to_agent(agent_id, command_type, payload, command_id) do
    # This would use Phoenix.PubSub or Phoenix.Channel to send
    # the command to the agent
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "agent:#{agent_id}",
      {:command, command_type, payload, command_id}
    )
  end

  defp wait_for_result(command_id, timeout) do
    # In a real implementation, this would use a GenServer or Task
    # to wait for the command result with a timeout
    #
    # For now, return a placeholder
    receive do
      {:command_result, ^command_id, result} ->
        {:ok, result}
    after
      timeout ->
        {:error, :timeout}
    end
  end
end
