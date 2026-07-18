defmodule TamanduaServer.Workers.EvidenceSessionFrameWorker do
  use Oban.Worker,
    queue: :default,
    max_attempts: 3,
    unique: [period: 1200, fields: [:worker, :args]]

  alias TamanduaServer.LiveResponse.{EvidenceFrameDispatcher, EvidenceSessions}

  @impl Oban.Worker
  def perform(%Oban.Job{
        args: %{"organization_id" => org, "session_id" => id, "frame_index" => index}
      })
      when is_binary(org) and is_binary(id) and is_integer(index) do
    EvidenceSessions.lock_for_frame(org, id, index, fn session ->
      started = System.monotonic_time()
      result = EvidenceFrameDispatcher.dispatch(session, index)
      EvidenceSessions.emit_frame(session, result, System.monotonic_time() - started)

      case result do
        {:ok, {:mobile_aggregate, artifacts, command}} ->
          EvidenceSessions.audit(session, "evidence_session_mobile_command_queued", %{
            frame_count: length(artifacts),
            artifact_ids: Enum.map(artifacts, fn {artifact, _token} -> artifact.id end),
            mobile_command_id: command.id
          })

          EvidenceSessions.advance_mobile_aggregate(session, command.id)

        {:ok, artifact} ->
          EvidenceSessions.audit(session, "evidence_session_frame_queued", %{
            frame_index: index,
            artifact_id: artifact.id
          })

          updated = EvidenceSessions.advance(session, index)

          if index + 1 < updated.frame_count do
            EvidenceSessions.enqueue_frame(updated, index + 1, updated.interval_seconds)
          end

        {:error, reason} ->
          EvidenceSessions.audit(session, "evidence_session_frame_failed", %{
            frame_index: index,
            reason: inspect(reason) |> String.slice(0, 200)
          })

          updated = EvidenceSessions.advance(session, index)

          if index + 1 < updated.frame_count do
            EvidenceSessions.enqueue_frame(updated, index + 1, updated.interval_seconds)
          end
      end

      :ok
    end)
    |> case do
      {:ok, _} -> :ok
      {:error, reason} -> {:discard, reason}
    end
  end

  def perform(_), do: {:discard, :invalid_arguments}
end
