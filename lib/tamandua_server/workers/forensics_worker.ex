defmodule TamanduaServer.Workers.ForensicsWorker do
  @moduledoc """
  Oban worker for forensic artifact collection.

  Coordinates with remote agents to collect artifacts and track progress.
  Handles compression, encryption, and upload orchestration.
  """

  use Oban.Worker,
    queue: :forensics,
    max_attempts: 3,
    priority: 1

  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Forensics
  alias TamanduaServer.Forensics.Artifact
  alias TamanduaServer.Agents

  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"artifact_id" => artifact_id}}) do
    Logger.info("[ForensicsWorker] Starting collection for artifact #{artifact_id}")

    with {:ok, artifact} <- Forensics.get_artifact(artifact_id),
         :ok <- validate_artifact(artifact),
         {:ok, artifact} <- mark_started(artifact),
         {:ok, command_id} <- send_collection_command(artifact),
         {:ok, artifact} <- monitor_collection(artifact, command_id) do

      Logger.info("[ForensicsWorker] Collection completed for artifact #{artifact_id}")
      :ok
    else
      {:error, :agent_offline} ->
        # Agent offline, will retry
        Logger.warning("[ForensicsWorker] Agent offline for artifact #{artifact_id}, will retry")
        {:snooze, 300}  # Retry in 5 minutes

      {:error, reason} = error ->
        Logger.error("[ForensicsWorker] Collection failed for artifact #{artifact_id}: #{inspect(reason)}")
        Forensics.mark_failed(artifact_id, "Collection failed: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Enqueue a new forensics collection job.
  """
  def enqueue(artifact_id) do
    %{artifact_id: artifact_id}
    |> __MODULE__.new()
    |> Oban.insert()
  end

  # Private Functions

  defp validate_artifact(artifact) do
    cond do
      artifact.status not in ["queued", "pending"] ->
        {:error, :invalid_status}

      is_nil(artifact.agent_id) ->
        {:error, :missing_agent_id}

      true ->
        :ok
    end
  end

  defp mark_started(artifact) do
    artifact
    |> Artifact.mark_started()
    |> Repo.update()
  end

  defp send_collection_command(artifact) do
    params = build_collection_params(artifact)

    case Agents.send_command(artifact.agent_id, params) do
      {:ok, command_id} ->
        {:ok, command_id}

      {:error, :agent_offline} ->
        {:error, :agent_offline}

      {:error, reason} ->
        Logger.error("[ForensicsWorker] Failed to send command: #{inspect(reason)}")
        {:error, :command_send_failed}
    end
  end

  defp build_collection_params(artifact) do
    %{
      type: :collect_artifact,
      params: %{
        artifact_id: artifact.id,
        artifact_type: artifact.artifact_type,
        artifact_subtype: artifact.artifact_subtype,
        parameters: artifact.parameters,
        compression: artifact.compression_type,
        encrypted: artifact.encrypted,
        encryption_key_id: artifact.encryption_key_id
      },
      timeout: 3600  # 1 hour timeout for large collections
    }
  end

  defp monitor_collection(artifact, command_id) do
    # Poll for command completion
    # In production, this would use Phoenix channels for real-time updates
    max_wait = 3600  # 1 hour
    poll_interval = 5  # 5 seconds
    iterations = div(max_wait, poll_interval)

    result = Enum.reduce_while(1..iterations, nil, fn _i, _acc ->
      Process.sleep(poll_interval * 1000)

      case check_command_status(command_id) do
        {:completed, result_data} ->
          {:halt, {:ok, result_data}}

        {:failed, error} ->
          {:halt, {:error, error}}

        :pending ->
          {:cont, nil}

        :acknowledged ->
          {:cont, nil}
      end
    end)

    case result do
      {:ok, result_data} ->
        complete_collection(artifact, result_data)

      {:error, error} ->
        {:error, error}

      nil ->
        {:error, :timeout}
    end
  end

  defp check_command_status(command_id) do
    # Query command status from database
    case Repo.get_by(TamanduaServer.Agents.AgentCommand, id: command_id) do
      nil ->
        :pending

      command ->
        case command.status do
          "completed" ->
            {:completed, command.result_data}

          "failed" ->
            {:failed, command.error_message}

          "acknowledged" ->
            :acknowledged

          _ ->
            :pending
        end
    end
  end

  defp complete_collection(artifact, result_data) do
    completion_attrs = %{
      file_path: result_data["file_path"],
      file_size: result_data["file_size"],
      sha256_hash: result_data["sha256_hash"],
      compression_type: result_data["compression_type"] || artifact.compression_type,
      encrypted: result_data["encrypted"] || artifact.encrypted,
      evidence_seal_hash: result_data["evidence_seal_hash"],
      metadata: Map.merge(artifact.metadata, result_data["metadata"] || %{})
    }

    Forensics.mark_completed(artifact.id, completion_attrs)
  end
end
