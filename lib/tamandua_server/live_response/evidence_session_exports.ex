defmodule TamanduaServer.LiveResponse.EvidenceSessionExports do
  @moduledoc "Tenant-scoped, short-lived ZIP evidence packages with independently hashed entries."
  import Ecto.Query

  alias TamanduaServer.LiveResponse.{
    EvidenceSessionContext,
    EvidenceSessionExport,
    EvidenceSessions
  }

  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant
  alias TamanduaServer.AuditLog

  @max_package_bytes 67_108_864
  @ttl_seconds 3_600

  @doc false
  def build_package(session, context), do: package(session, context)

  def create(organization_id, session_id, actor) do
    started = System.monotonic_time()

    result =
      with {:ok, session} <- EvidenceSessions.get_for_export(organization_id, session_id),
           :ok <- exportable?(session),
           {:ok, context} <- context(session),
           {:ok, zip} <- package(session, context),
           true <- byte_size(zip) <= @max_package_bytes do
        MultiTenant.with_organization(organization_id, fn ->
          cleanup()
          digest = sha256(zip)

          result =
            %EvidenceSessionExport{}
            |> EvidenceSessionExport.changeset(%{
              organization_id: organization_id,
              evidence_session_id: session.id,
              requested_by_id: actor && actor.id,
              sha256: digest,
              size: byte_size(zip),
              content: zip,
              expires_at: DateTime.add(DateTime.utc_now(), @ttl_seconds)
            })
            |> Repo.insert()

          case result do
            {:ok, export} ->
              AuditLog.log(%{
                action: "evidence_session_export_created",
                action_type: "live_response",
                resource_type: "evidence_session_export",
                resource_id: export.id,
                organization_id: organization_id,
                severity: :warning,
                details: %{session_id: session.id, sha256: digest, size: byte_size(zip)}
              })

            _ ->
              :ok
          end

          result
        end)
      else
        false -> {:error, :package_too_large}
        error -> error
      end

    emit(result, started)
    result
  end

  def get(organization_id, export_id, actor \\ nil) do
    MultiTenant.with_organization(organization_id, fn ->
      cleanup()

      case Repo.get_by(EvidenceSessionExport, id: export_id, organization_id: organization_id) do
        nil ->
          {:error, :not_found}

        export ->
          AuditLog.log(%{
            action: "evidence_session_export_downloaded",
            action_type: "live_response",
            resource_type: "evidence_session_export",
            resource_id: export.id,
            organization_id: organization_id,
            severity: :warning,
            details: %{session_id: export.evidence_session_id, actor_id: actor && actor.id}
          })

          {:ok, export}
      end
    end)
  end

  def cleanup_expired(organization_id) do
    MultiTenant.with_organization(organization_id, fn ->
      now = DateTime.utc_now()
      EvidenceSessionExport |> where([e], e.expires_at <= ^now) |> Repo.delete_all()
    end)
  end

  defp exportable?(%{status: status}) when status in ["completed", "partial"], do: :ok
  defp exportable?(_), do: {:error, :session_not_ready}

  defp context(session) do
    from = DateTime.add(session.started_at || session.inserted_at, -30)
    to = DateTime.add(session.completed_at || DateTime.utc_now(), 30)
    EvidenceSessionContext.build(session.organization_id, session.agent_id, from, to)
  end

  defp package(session, context) do
    ready = Enum.filter(session.artifacts, &(&1.status == "ready" and is_binary(&1.content)))
    total = Enum.reduce(ready, 0, &(byte_size(&1.content) + &2))

    if total > @max_package_bytes do
      {:error, :package_too_large}
    else
      frame_manifest =
        Enum.map(ready, fn artifact ->
          %{
            index: artifact.frame_index,
            filename: "frames/#{artifact.frame_index}.png",
            artifact_id: artifact.id,
            captured_at: artifact.captured_at,
            size: artifact.size,
            sha256: artifact.sha256
          }
        end)

      manifest = %{
        schema_version: "tamandua.evidence_package/v1",
        session: %{
          id: session.id,
          organization_id: session.organization_id,
          agent_id: session.agent_id,
          reason: session.reason,
          status: session.status,
          frame_count: session.frame_count,
          interval_seconds: session.interval_seconds,
          started_at: session.started_at,
          completed_at: session.completed_at,
          alert_id: session.alert_id,
          investigation_id: session.investigation_id,
          case_id: session.case_id
        },
        frames: frame_manifest,
        context_sha256: sha256(Jason.encode!(context))
      }

      entries =
        [
          {~c"manifest.json", Jason.encode!(manifest)},
          {~c"context.json", Jason.encode!(context)}
        ] ++
          Enum.map(ready, fn artifact ->
            {String.to_charlist("frames/#{artifact.frame_index}.png"), artifact.content}
          end)

      case :zip.create(~c"evidence.zip", entries, [:memory]) do
        {:ok, {_name, zip}} -> {:ok, zip}
        {:error, _} -> {:error, :package_failed}
      end
    end
  end

  defp cleanup do
    now = DateTime.utc_now()

    EvidenceSessionExport
    |> where([e], e.expires_at <= ^now)
    |> Repo.delete_all()
  end

  defp sha256(value), do: :crypto.hash(:sha256, value) |> Base.encode16(case: :lower)

  defp emit(result, started) do
    :telemetry.execute(
      [:tamandua, :evidence_session, :export],
      %{duration: System.monotonic_time() - started, count: 1},
      %{status: if(match?({:ok, _}, result), do: "ok", else: "error"), platform: "unknown"}
    )
  end
end
