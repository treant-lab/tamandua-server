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
  - `:idempotency_key` - Stable per-agent key; replays return the existing
    command without inserting or dispatching a duplicate.

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
        idempotency_key = Keyword.get(opts, :idempotency_key)

        attrs = %{
          agent_id: agent_id,
          command_type: to_string(command_type),
          # Normalize keys to strings so the in-memory struct matches what a
          # jsonb round-trip returns (Postgres jsonb always yields string keys).
          command_params: stringify_keys(params),
          priority: priority,
          status: "pending",
          idempotency_key: idempotency_key,
          expires_at: DateTime.add(DateTime.utc_now(), timeout_seconds, :second)
        }

        case AgentCommand.insert_new(attrs) do
          {:ok, command} ->
            # Notify the agent worker to send the command
            notify_worker(agent_id)
            {:ok, command}

          {:existing, command} ->
            Logger.info(
              "Idempotent queue replay for agent #{agent_id}: " <>
                "key=#{inspect(idempotency_key)} command=#{command.id}"
            )

            {:ok, command}

          {:error, changeset} ->
            {:error, changeset}
        end
    end
  end

  @doc """
  Queue the same osquery SQL statement for all eligible live agents in an
  organization.

  This is the lightweight fleet-query path: it reuses the existing
  `osquery_query` live-response command instead of introducing a separate
  query language. By default only online/isolated agents that reported the
  `osquery_query` capability are targeted.

  Options:

  - `:agent_ids` - optional allowlist of live agent IDs
  - `:priority` - command priority (default: 1)
  - `:timeout` - command timeout in seconds (default: 300)
  - `:max_rows` - forwarded to the agent osquery runner
  - `:max_output_bytes` - forwarded to the agent osquery runner
  - `:max_targets` - maximum number of eligible agents to queue before marking
    the rest skipped
  - `:require_capability` - require reported osquery capability (default: true)
  - `:fleet_query_run_id` - optional persistent fleet-query correlation ID
  """
  @spec queue_fleet_osquery(String.t(), String.t(), keyword()) :: %{
          queued: [AgentCommand.t()],
          skipped: [%{agent_id: String.t() | nil, reason: atom()}],
          total_targets: non_neg_integer()
        }
  def queue_fleet_osquery(organization_id, query, opts \\ [])
      when is_binary(organization_id) and is_binary(query) do
    agent_ids = Keyword.get(opts, :agent_ids)
    priority = Keyword.get(opts, :priority, 1)
    timeout = Keyword.get(opts, :timeout, 300)
    require_capability = Keyword.get(opts, :require_capability, true)
    fleet_query_run_id = Keyword.get(opts, :fleet_query_run_id)
    max_targets = Keyword.get(opts, :max_targets)

    params =
      %{
        query: query,
        max_rows: Keyword.get(opts, :max_rows),
        max_output_bytes: Keyword.get(opts, :max_output_bytes),
        fleet_query_run_id: fleet_query_run_id
      }
      |> Enum.reject(fn {_key, value} -> is_nil(value) end)
      |> Map.new()

    organization_id
    |> Registry.list_for_org()
    |> Enum.filter(&fleet_agent_requested?(&1, agent_ids))
    |> Enum.reduce(%{queued: [], skipped: [], total_targets: 0}, fn agent, acc ->
      acc = %{acc | total_targets: acc.total_targets + 1}

      cond do
        fleet_max_targets_reached?(acc, max_targets) ->
          skip_fleet_agent(acc, agent, :max_targets_exceeded)

        not fleet_agent_online?(agent) ->
          skip_fleet_agent(acc, agent, :agent_offline)

        require_capability and not fleet_agent_supports_osquery?(agent) ->
          skip_fleet_agent(acc, agent, :missing_osquery_capability)

        true ->
          case queue_command(agent.agent_id, :osquery_query, params,
                 priority: priority,
                 timeout: timeout
               ) do
            {:ok, command} ->
              %{acc | queued: [command | acc.queued]}

            {:error, reason} ->
              skip_fleet_agent(acc, agent, reason)
          end
      end
    end)
    |> reverse_fleet_result()
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
      avg_completion_seconds: round_numeric(avg_completion, 2),
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

      %AgentCommand{command_type: "screen_capture"} ->
        # A capture retry needs a new artifact, reason audit and one-time upload
        # credential. Replaying persisted parameters would reuse an expired or
        # consumed secret and bypass the dedicated capture request flow.
        {:error, :non_retryable_command}

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

  defp fleet_agent_requested?(_agent, nil), do: true

  defp fleet_agent_requested?(agent, agent_ids) when is_list(agent_ids) do
    agent.agent_id in Enum.map(agent_ids, &to_string/1)
  end

  defp fleet_agent_online?(agent), do: agent.status in [:online, :isolated, "online", "isolated"]

  defp fleet_max_targets_reached?(_acc, nil), do: false

  defp fleet_max_targets_reached?(acc, max_targets) when is_integer(max_targets) do
    max_targets >= 0 and length(acc.queued) >= max_targets
  end

  defp fleet_max_targets_reached?(_acc, _max_targets), do: false

  defp fleet_agent_supports_osquery?(agent) do
    capabilities =
      (agent[:capabilities] || agent["capabilities"] || [])
      |> Enum.map(&normalize_capability/1)

    Enum.any?(capabilities, &(&1 in ["osquery_query", "remote_query"]))
  end

  defp normalize_capability(capability) do
    capability
    |> to_string()
    |> String.downcase()
    |> String.replace("-", "_")
  end

  defp skip_fleet_agent(acc, agent, reason) do
    skipped = %{
      agent_id: agent[:agent_id] || agent["agent_id"],
      reason: normalize_skip_reason(reason)
    }

    %{acc | skipped: [skipped | acc.skipped]}
  end

  defp normalize_skip_reason(reason) when is_atom(reason), do: reason
  defp normalize_skip_reason(%Ecto.Changeset{}), do: :invalid_command
  defp normalize_skip_reason(_reason), do: :queue_failed

  defp reverse_fleet_result(result) do
    %{result | queued: Enum.reverse(result.queued), skipped: Enum.reverse(result.skipped)}
  end

  defp stringify_keys(value) when is_map(value) do
    Map.new(value, fn {key, nested_value} ->
      {to_string(key), stringify_keys(nested_value)}
    end)
  end

  defp stringify_keys(value) when is_list(value), do: Enum.map(value, &stringify_keys/1)
  defp stringify_keys(value), do: value

  defp round_numeric(nil, _precision), do: nil

  defp round_numeric(%Decimal{} = value, precision) do
    value
    |> Decimal.to_float()
    |> Float.round(precision)
  end

  defp round_numeric(value, precision) when is_integer(value) do
    value
    |> :erlang.float()
    |> Float.round(precision)
  end

  defp round_numeric(value, precision) when is_float(value), do: Float.round(value, precision)
end
