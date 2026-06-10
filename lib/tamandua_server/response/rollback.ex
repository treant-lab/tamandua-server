defmodule TamanduaServer.Response.Rollback do
  @moduledoc """
  Ransomware Rollback Orchestrator

  Coordinates file rollback operations on agents by sending commands via
  WebSocket to the agent's file journal system. Supports three rollback modes:

  - **Storyline rollback**: Undo all file changes associated with a specific
    attack chain / storyline ID. This is the primary mode used after a
    ransomware detection, where all changes from the malicious process tree
    are reverted.

  - **Time-range rollback**: Undo all file changes within a time window.
    Useful when the exact storyline is unknown but the attack timeframe is
    established through investigation.

  - **Single-file rollback**: Restore a specific file to its pre-modification
    state. Used for targeted recovery during incident response.

  The agent maintains a local SQLite journal with compressed backups of
  original file content, enabling fast local rollback without network
  dependency. On Windows, VSS (Volume Shadow Copy) integration provides
  additional full-volume snapshot capability.

  ## Integration with Alert Pipeline

  When a ransomware alert is confirmed, the playbook engine can automatically
  trigger a storyline rollback:

      Rollback.rollback_storyline(agent_id, storyline_id, opts)

  ## Architecture

      [Dashboard/Playbook] --> [Rollback Module] --> [WebSocket] --> [Agent]
                                     |                                  |
                                     |                          [File Journal]
                                     |                          [SQLite + Backups]
                                     |                                  |
                                     +--- wait for result <--- [Rollback Result]
  """

  require Logger

  alias TamanduaServer.Agents.{Registry, Worker}
  alias TamanduaServer.Response.Executor

  @rollback_timeout 120_000  # 2 minutes - rollback can take time for many files

  @doc """
  Roll back all file changes associated with a storyline (attack chain).

  This is the primary rollback mode used after ransomware detection. The agent
  will undo all file modifications (writes, deletes, renames) linked to the
  given storyline ID, processing them newest-first.

  ## Parameters

    - `agent_id` - The target agent's unique identifier
    - `storyline_id` - The attack chain / storyline identifier
    - `opts` - Optional keyword list:
      - `:timeout` - Command timeout in ms (default: 120_000)
      - `:audit` - Whether to record an audit entry (default: true)

  ## Returns

    - `{:ok, result}` where result contains `:restored_count`, `:failed_count`,
      `:skipped_count`, `:restored_files`, and `:failed_files`
    - `{:error, reason}` on failure
  """
  @spec rollback_storyline(String.t(), String.t(), keyword()) ::
          {:ok, map()} | {:error, atom() | String.t()}
  def rollback_storyline(agent_id, storyline_id, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, @rollback_timeout)

    Logger.info(
      "Initiating storyline rollback on agent #{agent_id} for storyline #{storyline_id}"
    )

    params = %{
      "rollback_type" => "storyline",
      "storyline_id" => storyline_id
    }

    case send_rollback_command(agent_id, params, timeout) do
      {:ok, result} ->
        Logger.info(
          "Storyline rollback complete on agent #{agent_id}: " <>
            "restored=#{result["restored_count"]}, " <>
            "failed=#{result["failed_count"]}, " <>
            "skipped=#{result["skipped_count"]}"
        )

        if Keyword.get(opts, :audit, true) do
          record_rollback_audit(agent_id, "storyline", %{
            storyline_id: storyline_id,
            result: result
          })
        end

        {:ok, result}

      {:error, reason} = error ->
        Logger.error(
          "Storyline rollback failed on agent #{agent_id}: #{inspect(reason)}"
        )

        error
    end
  end

  @doc """
  Roll back all file changes within a time range.

  Useful when the exact attack storyline is unknown but the timeframe has been
  established through investigation. All file modifications recorded in the
  journal between `start_time` and `end_time` will be reverted.

  ## Parameters

    - `agent_id` - The target agent's unique identifier
    - `start_time` - Start of the time range (Unix timestamp in seconds)
    - `end_time` - End of the time range (Unix timestamp in seconds)
    - `opts` - Optional keyword list (same as `rollback_storyline/3`)

  ## Returns

    - `{:ok, result}` with rollback statistics
    - `{:error, reason}` on failure
  """
  @spec rollback_timerange(String.t(), integer(), integer(), keyword()) ::
          {:ok, map()} | {:error, atom() | String.t()}
  def rollback_timerange(agent_id, start_time, end_time, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, @rollback_timeout)

    Logger.info(
      "Initiating time-range rollback on agent #{agent_id} " <>
        "from #{start_time} to #{end_time}"
    )

    params = %{
      "rollback_type" => "timerange",
      "start_time" => start_time,
      "end_time" => end_time
    }

    case send_rollback_command(agent_id, params, timeout) do
      {:ok, result} ->
        Logger.info(
          "Time-range rollback complete on agent #{agent_id}: " <>
            "restored=#{result["restored_count"]}, " <>
            "failed=#{result["failed_count"]}"
        )

        if Keyword.get(opts, :audit, true) do
          record_rollback_audit(agent_id, "timerange", %{
            start_time: start_time,
            end_time: end_time,
            result: result
          })
        end

        {:ok, result}

      {:error, reason} = error ->
        Logger.error(
          "Time-range rollback failed on agent #{agent_id}: #{inspect(reason)}"
        )

        error
    end
  end

  @doc """
  Restore a single file to its pre-modification state.

  Looks up the most recent un-rolled-back journal entry for the given file
  path and restores the original content from the backup.

  ## Parameters

    - `agent_id` - The target agent's unique identifier
    - `file_path` - Absolute path to the file on the agent
    - `opts` - Optional keyword list (same as `rollback_storyline/3`)

  ## Returns

    - `{:ok, %{"restored" => true/false}}` indicating whether the file was restored
    - `{:error, reason}` on failure
  """
  @spec rollback_file(String.t(), String.t(), keyword()) ::
          {:ok, map()} | {:error, atom() | String.t()}
  def rollback_file(agent_id, file_path, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, @rollback_timeout)

    Logger.info("Initiating single-file rollback on agent #{agent_id} for #{file_path}")

    params = %{
      "rollback_type" => "file",
      "file_path" => file_path
    }

    case send_rollback_command(agent_id, params, timeout) do
      {:ok, result} ->
        Logger.info("File rollback result on agent #{agent_id}: #{inspect(result)}")

        if Keyword.get(opts, :audit, true) do
          record_rollback_audit(agent_id, "file", %{
            file_path: file_path,
            result: result
          })
        end

        {:ok, result}

      {:error, reason} = error ->
        Logger.error("File rollback failed on agent #{agent_id}: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Query the agent for file journal statistics.

  Returns information about the journal database size, number of entries,
  backup storage usage, and entry age range.

  ## Parameters

    - `agent_id` - The target agent's unique identifier

  ## Returns

    - `{:ok, stats}` with journal statistics map
    - `{:error, reason}` on failure
  """
  @spec get_journal_stats(String.t()) :: {:ok, map()} | {:error, atom() | String.t()}
  def get_journal_stats(agent_id) do
    Logger.debug("Querying journal stats for agent #{agent_id}")

    params = %{"action" => "get_stats"}

    case send_journal_query(agent_id, params) do
      {:ok, stats} ->
        {:ok, stats}

      {:error, reason} = error ->
        Logger.warning("Failed to get journal stats from agent #{agent_id}: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Trigger a manual cleanup of old journal entries and orphaned backups.

  The agent's journal automatically cleans up entries older than the configured
  retention period, but this allows forcing a cleanup cycle.

  ## Parameters

    - `agent_id` - The target agent's unique identifier

  ## Returns

    - `{:ok, %{"cleaned" => true}}` on success
    - `{:error, reason}` on failure
  """
  @spec cleanup_journal(String.t()) :: {:ok, map()} | {:error, atom() | String.t()}
  def cleanup_journal(agent_id) do
    Logger.info("Triggering journal cleanup on agent #{agent_id}")

    params = %{"action" => "cleanup"}

    case send_journal_query(agent_id, params) do
      {:ok, result} ->
        {:ok, result}

      {:error, reason} = error ->
        Logger.error("Journal cleanup failed on agent #{agent_id}: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Create a VSS snapshot on a Windows agent.

  Triggers creation of a Volume Shadow Copy on the specified volume,
  providing a full-volume snapshot for comprehensive rollback capability.

  ## Parameters

    - `agent_id` - The target agent's unique identifier
    - `volume` - The volume to snapshot (e.g., "C:")

  ## Returns

    - `{:ok, %{"snapshot_id" => id}}` with the new snapshot identifier
    - `{:error, reason}` on failure (including non-Windows agents)
  """
  @spec create_vss_snapshot(String.t(), String.t()) ::
          {:ok, map()} | {:error, atom() | String.t()}
  def create_vss_snapshot(agent_id, volume \\ "C:") do
    Logger.info("Creating VSS snapshot on agent #{agent_id} for volume #{volume}")

    Executor.execute_response(nil, %{
      action_type: "create_snapshot",
      agent_id: agent_id,
      params: %{"volume" => volume}
    })
  end

  # ===========================================================================
  # Private Functions
  # ===========================================================================

  # Send a rollback command to the agent via the executor.
  defp send_rollback_command(agent_id, params, timeout) do
    # Map rollback types to the appropriate agent command type
    command_type =
      case params["rollback_type"] do
        "storyline" -> "ransomware_remediate"
        "timerange" -> "ransomware_remediate"
        "file" -> "restore_file"
        _ -> "ransomware_remediate"
      end

    Executor.execute_response(nil, %{
      action_type: command_type,
      agent_id: agent_id,
      params: Map.put(params, "timeout", timeout)
    })
  end

  # Send a journal query command to the agent.
  defp send_journal_query(agent_id, params) do
    Executor.execute_response(nil, %{
      action_type: "journal_query",
      agent_id: agent_id,
      params: params
    })
  end

  # Record a rollback operation in the audit log.
  defp record_rollback_audit(agent_id, rollback_type, details) do
    Logger.info(
      "Rollback audit: agent=#{agent_id} type=#{rollback_type} " <>
        "details=#{inspect(details, limit: 200)}"
    )

    # Broadcast rollback event to dashboard subscribers
    TamanduaServerWeb.Endpoint.broadcast(
      "dashboard:alerts",
      "rollback_completed",
      %{
        agent_id: agent_id,
        rollback_type: rollback_type,
        details: details,
        timestamp: DateTime.utc_now() |> DateTime.to_unix()
      }
    )
  rescue
    error ->
      Logger.warning("Failed to record rollback audit: #{inspect(error)}")
  end
end
