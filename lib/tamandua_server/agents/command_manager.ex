defmodule TamanduaServer.Agents.CommandManager do
  @moduledoc """
  High-level API for managing agent commands with persistent storage.

  This module provides functions to queue, query, and manage commands
  sent to agents. Commands are persisted to PostgreSQL and survive
  worker crashes and server restarts.

  ## Usage

      # Queue a command for an agent
      {:ok, command} = CommandManager.queue_command(agent_id, :kill_process, %{pid: 1234}, priority: 5)

      # Get pending commands for an agent
      commands = CommandManager.pending_commands(agent_id)

      # Get command status
      {:ok, command} = CommandManager.get_command(command_id)

      # Cancel a pending command
      :ok = CommandManager.cancel_command(command_id)
  """

  require Logger

  alias TamanduaServer.Agents.{AgentCommand, Registry}
  alias TamanduaServer.Repo

  @doc """
  Queue a command for an agent.

  ## Options

  - `:priority` - Command priority (0-10, default: 0)
  - `:timeout` - Timeout in seconds (default: 3600)

  ## Examples

      iex> CommandManager.queue_command("agent-123", :kill_process, %{pid: 1234}, priority: 5)
      {:ok, %AgentCommand{}}

      iex> CommandManager.queue_command("nonexistent", :kill_process, %{})
      {:error, :agent_not_found}
  """
  @spec queue_command(String.t(), atom() | String.t(), map(), keyword()) ::
          {:ok, AgentCommand.t()} | {:error, term()}
  def queue_command(agent_id, command_type, params \\ %{}, opts \\ []) do
    # Verify agent exists and is online
    case Registry.get(agent_id) do
      {:error, :not_found} ->
        {:error, :agent_not_found}

      {:ok, _agent_info} ->
        priority = Keyword.get(opts, :priority, 0)
        timeout_seconds = Keyword.get(opts, :timeout, 3600)

        attrs = %{
          agent_id: agent_id,
          command_type: to_string(command_type),
          # Normalize keys to strings so the in-memory struct matches what a
          # jsonb round-trip returns (Postgres jsonb always yields string keys).
          command_params: stringify_keys(params),
          priority: priority,
          status: "pending",
          expires_at: DateTime.add(DateTime.utc_now(), timeout_seconds, :second)
        }

        case Repo.insert(AgentCommand.changeset(%AgentCommand{}, attrs)) do
          {:ok, command} ->
            # Notify the agent worker to send the command
            notify_worker(agent_id)
            {:ok, command}

          {:error, changeset} ->
            {:error, changeset}
        end
    end
  end

  @doc """
  Get a command by ID.
  """
  @spec get_command(String.t()) :: {:ok, AgentCommand.t()} | {:error, :not_found}
  def get_command(command_id) do
    case Repo.get(AgentCommand, command_id) do
      nil -> {:error, :not_found}
      command -> {:ok, command}
    end
  end

  @doc """
  Get all pending commands for an agent.
  """
  @spec pending_commands(String.t()) :: [AgentCommand.t()]
  def pending_commands(agent_id) do
    AgentCommand.pending_for_agent(agent_id)
    |> Repo.all()
  end

  @doc """
  Get all active (pending/sent/acknowledged) commands for an agent.
  """
  @spec active_commands(String.t()) :: [AgentCommand.t()]
  def active_commands(agent_id) do
    AgentCommand.active_for_agent(agent_id)
    |> Repo.all()
  end

  @doc """
  Cancel a pending command.

  Only commands in "pending" status can be cancelled.
  Commands already sent will not be cancelled.
  """
  @spec cancel_command(String.t()) :: :ok | {:error, term()}
  def cancel_command(command_id) do
    case Repo.get(AgentCommand, command_id) do
      nil ->
        {:error, :not_found}

      command ->
        if command.status == "pending" do
          command
          |> AgentCommand.mark_failed("Cancelled by user")
          |> Repo.update()

          :ok
        else
          {:error, :already_sent}
        end
    end
  end

  @doc """
  Get command statistics for an agent.

  Returns counts by status and average completion time.
  """
  @spec command_stats(String.t()) :: map()
  def command_stats(agent_id) do
    import Ecto.Query

    # Count by status
    status_counts =
      from(c in AgentCommand,
        where: c.agent_id == ^agent_id,
        group_by: c.status,
        select: {c.status, count(c.id)}
      )
      |> Repo.all()
      |> Map.new()

    # Average completion time (in seconds) for completed commands
    avg_completion =
      from(c in AgentCommand,
        where: c.agent_id == ^agent_id,
        where: c.status == "completed",
        where: not is_nil(c.completed_at),
        select:
          avg(
            fragment(
              "EXTRACT(EPOCH FROM (? - ?))",
              c.completed_at,
              c.inserted_at
            )
          )
      )
      |> Repo.one()

    %{
      by_status: status_counts,
      avg_completion_seconds: if(avg_completion, do: Float.round(avg_completion, 2), else: nil),
      total: Enum.sum(Map.values(status_counts))
    }
  end

  @doc """
  Retry a failed command by creating a new command with the same parameters.
  """
  @spec retry_command(String.t()) :: {:ok, AgentCommand.t()} | {:error, term()}
  def retry_command(command_id) do
    case Repo.get(AgentCommand, command_id) do
      nil ->
        {:error, :not_found}

      command ->
        queue_command(
          command.agent_id,
          command.command_type,
          command.command_params,
          priority: command.priority
        )
    end
  end

  # Private Functions

  defp notify_worker(agent_id) do
    # Send a message to the worker to check for new pending commands
    case Registry.get(agent_id) do
      {:ok, %{worker_pid: pid}} when is_pid(pid) ->
        send(pid, :send_pending_commands)

      _ ->
        Logger.debug("Agent #{agent_id} worker not found, command will be sent on reconnect")
    end
  end

  defp stringify_keys(value) when is_map(value) do
    Map.new(value, fn {key, nested_value} ->
      {to_string(key), stringify_keys(nested_value)}
    end)
  end

  defp stringify_keys(value) when is_list(value), do: Enum.map(value, &stringify_keys/1)
  defp stringify_keys(value), do: value
end
