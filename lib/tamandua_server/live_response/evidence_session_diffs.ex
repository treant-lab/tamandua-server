defmodule TamanduaServer.LiveResponse.EvidenceSessionDiffs do
  @moduledoc "Tenant-scoped persisted metrics for bounded comparisons between two ready PNG frames."
  import Ecto.Query

  alias TamanduaServer.LiveResponse.{
    EvidencePngDiff,
    EvidenceSession,
    EvidenceSessionDiff,
    ScreenCaptureArtifact
  }

  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant
  alias TamanduaServer.AuditLog

  @ttl_seconds 3_600

  def create(organization_id, session_id, left_id, right_id, actor) do
    started = System.monotonic_time()

    result =
      MultiTenant.with_organization(organization_id, fn ->
        cleanup()

        with %EvidenceSession{} = session <-
               Repo.get_by(EvidenceSession, id: session_id, organization_id: organization_id),
             %ScreenCaptureArtifact{} = left <- artifact(session, left_id),
             %ScreenCaptureArtifact{} = right <- artifact(session, right_id),
             :ok <- ensure_distinct_artifacts(left, right),
             {:ok, metrics} <- bounded_compare(left.content, right.content) do
          result =
            %EvidenceSessionDiff{}
            |> EvidenceSessionDiff.changeset(%{
              organization_id: organization_id,
              evidence_session_id: session.id,
              left_artifact_id: left.id,
              right_artifact_id: right.id,
              metrics: metrics,
              expires_at: DateTime.add(DateTime.utc_now(), @ttl_seconds)
            })
            |> Repo.insert()

          case result do
            {:ok, diff} ->
              AuditLog.log(%{
                action: "evidence_session_diff_created",
                action_type: "live_response",
                resource_type: "evidence_session_diff",
                resource_id: diff.id,
                organization_id: organization_id,
                severity: :info,
                details: %{
                  session_id: session.id,
                  left_artifact_id: left.id,
                  right_artifact_id: right.id,
                  requested_by_id: actor && actor.id
                }
              })

            _ ->
              :ok
          end

          result
        else
          nil -> {:error, :not_found}
          error -> error
        end
      end)

    :telemetry.execute(
      [:tamandua, :evidence_session, :diff],
      %{duration: System.monotonic_time() - started, count: 1},
      %{status: if(match?({:ok, _}, result), do: "ok", else: "error"), platform: "unknown"}
    )

    result
  end

  defp artifact(session, id) do
    Repo.get_by(ScreenCaptureArtifact,
      id: id,
      organization_id: session.organization_id,
      evidence_session_id: session.id,
      status: "ready"
    )
  end

  defp ensure_distinct_artifacts(%{id: id}, %{id: id}), do: {:error, :same_artifact}
  defp ensure_distinct_artifacts(_, _), do: :ok

  defp bounded_compare(left, right) do
    case :global.trans({__MODULE__, :png_diff}, fn -> timed_compare(left, right) end, [node()], 0) do
      :aborted -> {:error, :diff_busy}
      result -> result
    end
  end

  defp timed_compare(left, right) do
    task = Task.async(fn -> EvidencePngDiff.compare(left, right) end)

    case Task.yield(task, 2_000) || Task.shutdown(task, :brutal_kill) do
      {:ok, result} -> result
      _ -> {:error, :diff_cpu_limit_exceeded}
    end
  end

  defp cleanup do
    now = DateTime.utc_now()

    EvidenceSessionDiff
    |> where([d], d.expires_at <= ^now)
    |> Repo.delete_all()
  end

  def cleanup_expired(organization_id) do
    MultiTenant.with_organization(organization_id, fn ->
      now = DateTime.utc_now()
      EvidenceSessionDiff |> where([d], d.expires_at <= ^now) |> Repo.delete_all()
    end)
  end
end
