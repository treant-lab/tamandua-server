defmodule TamanduaServer.LiveResponse.EvidenceSessions do
  @moduledoc "Lifecycle and scheduling for bounded screen-capture evidence sessions."
  import Ecto.Query

  alias TamanduaServer.LiveResponse.{
    EvidenceSession,
    ScreenCapture,
    ScreenCaptureArtifact,
    ScreenCaptureArtifacts
  }

  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant
  alias TamanduaServer.Workers.EvidenceSessionFrameWorker
  alias TamanduaServer.Mobile.MDMCommand
  alias TamanduaServer.AuditLog
  alias TamanduaServer.Agents
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.AISecurity.Investigation
  alias TamanduaServer.Investigations.CaseInvestigation

  @normal_max_frames 10
  @long_max_frames 30
  @long_max_duration_seconds 1_800
  @approval_ttl_seconds 900
  @max_export_bytes 67_108_864
  @artifact_metadata_fields [
    :id,
    :organization_id,
    :agent_id,
    :evidence_session_id,
    :frame_index,
    :status,
    :mime,
    :size,
    :sha256,
    :captured_at,
    :expires_at,
    :failure_reason
  ]

  def create(organization_id, agent_id, params, actor) do
    started = System.monotonic_time()
    long? = params["long_session"] == true
    max_frames = if long?, do: @long_max_frames, else: @normal_max_frames

    with {:ok, agent} <- Agents.get_agent_for_org(organization_id, agent_id),
         {:ok, frame_count} <- bounded_int(params["frame_count"], 2, max_frames),
         :ok <- validate_platform_frame_count(agent, frame_count),
         {:ok, interval} <- bounded_int(params["interval_seconds"], 5, 60),
         true <- (frame_count - 1) * interval <= @long_max_duration_seconds,
         :ok <- validate_links(organization_id, params),
         {:ok, request} <- ScreenCapture.validate_request(Map.put_new(params, "ttl_seconds", 300)) do
      capture_request = request |> stringify_keys() |> Map.put("platform", platform(agent))

      expires_at =
        DateTime.add(
          DateTime.utc_now(),
          (frame_count - 1) * interval + request.ttl_seconds,
          :second
        )

      MultiTenant.with_organization(organization_id, fn ->
        Repo.transaction(fn ->
          approval_status = if long?, do: "pending", else: "not_required"
          status = if long?, do: "pending_approval", else: "scheduled"

          session =
            %EvidenceSession{}
            |> EvidenceSession.create_changeset(%{
              organization_id: organization_id,
              agent_id: agent_id,
              status: status,
              reason: request.reason,
              capture_request: capture_request,
              frame_count: frame_count,
              interval_seconds: interval,
              requested_by_id: actor && actor.id,
              requested_by_email: actor && actor.email,
              expires_at: expires_at,
              approval_status: approval_status,
              approval_expires_at:
                if(long?, do: DateTime.add(DateTime.utc_now(), @approval_ttl_seconds)),
              alert_id: params["alert_id"],
              investigation_id: params["investigation_id"],
              case_id: params["case_id"]
            })
            |> Repo.insert!()

          if not long?, do: enqueue_frame(session, 0, 0)

          audit(session, "evidence_session_created", %{
            frame_count: frame_count,
            interval_seconds: interval,
            approval_status: approval_status,
            platform: platform(agent)
          })

          emit(:created, System.monotonic_time() - started, %{
            platform: platform(agent),
            status: status
          })

          session
        end)
      end)
    else
      false -> {:error, :duration_too_long}
      error -> error
    end
  end

  def approve(organization_id, session_id, actor) do
    with :ok <- can_approve?(actor), do: do_approve(organization_id, session_id, actor)
  end

  defp do_approve(organization_id, session_id, actor) do
    result =
      MultiTenant.with_organization(organization_id, fn ->
        Repo.transaction(fn ->
          session =
            EvidenceSession
            |> where([s], s.id == ^session_id and s.organization_id == ^organization_id)
            |> lock("FOR UPDATE")
            |> Repo.one()

          now = DateTime.utc_now()

          cond do
            is_nil(session) ->
              Repo.rollback(:not_found)

            session.status != "pending_approval" or session.approval_status != "pending" ->
              Repo.rollback(:not_pending_approval)

            is_nil(actor) or is_nil(actor.id) ->
              Repo.rollback(:unauthorized)

            session.requested_by_id == actor.id ->
              Repo.rollback(:self_approval_forbidden)

            is_nil(session.approval_expires_at) or
                DateTime.compare(session.approval_expires_at, now) != :gt ->
              expired =
                session
                |> Ecto.Changeset.change(
                  status: "expired",
                  approval_status: "expired",
                  completed_at: now
                )
                |> Repo.update!()

              audit(expired, "evidence_session_approval_expired", %{approver_id: actor.id})
              {:approval_expired, expired}

            true ->
              approved =
                session
                |> Ecto.Changeset.change(
                  status: "scheduled",
                  approval_status: "approved",
                  approved_by_id: actor.id,
                  approved_at: now,
                  expires_at:
                    DateTime.add(
                      now,
                      (session.frame_count - 1) * session.interval_seconds +
                        (session.capture_request["ttl_seconds"] || 300)
                    )
                )
                |> Repo.update!()

              enqueue_frame(approved, 0, 0)
              audit(approved, "evidence_session_approved", %{approver_id: actor.id})
              approved
          end
        end)
      end)

    case result do
      {:ok, {:approval_expired, _session}} -> {:error, :approval_expired}
      other -> other
    end
  end

  defp can_approve?(nil), do: {:error, :unauthorized}

  defp can_approve?(actor) do
    if TamanduaServer.Accounts.user_can?(actor, :response_approve),
      do: :ok,
      else: {:error, :unauthorized}
  rescue
    _ -> {:error, :unauthorized}
  end

  def get(organization_id, session_id) do
    MultiTenant.with_organization(organization_id, fn ->
      case Repo.get_by(EvidenceSession, id: session_id, organization_id: organization_id) do
        nil ->
          {:error, :not_found}

        session ->
          ScreenCaptureArtifacts.cleanup_expired(organization_id)
          session = session |> expire_pending_approval() |> refresh_terminal()

          {:ok,
           session
           |> Repo.preload(
             artifacts:
               from(a in ScreenCaptureArtifact,
                 order_by: a.frame_index,
                 select: struct(a, ^@artifact_metadata_fields)
               )
           )}
      end
    end)
  end

  def get_for_export(organization_id, session_id) do
    MultiTenant.with_organization(organization_id, fn ->
      ScreenCaptureArtifacts.cleanup_expired(organization_id)

      case Repo.get_by(EvidenceSession, id: session_id, organization_id: organization_id) do
        nil ->
          {:error, :not_found}

        session ->
          {count, bytes} =
            ScreenCaptureArtifact
            |> where(
              [a],
              a.evidence_session_id == ^session.id and a.organization_id == ^organization_id and
                a.status == "ready" and not is_nil(a.content)
            )
            |> select([a], {count(a.id), sum(a.size)})
            |> Repo.one()

          bytes = bytes || 0

          cond do
            count == 0 ->
              {:error, :session_not_ready}

            bytes > @max_export_bytes ->
              {:error, :package_too_large}

            true ->
              artifacts =
                ScreenCaptureArtifact
                |> where(
                  [a],
                  a.evidence_session_id == ^session.id and
                    a.organization_id == ^organization_id and a.status == "ready"
                )
                |> order_by([a], a.frame_index)
                |> Repo.all()

              {:ok, %{session | artifacts: artifacts}}
          end
      end
    end)
  end

  def cancel(organization_id, session_id, actor) do
    MultiTenant.with_organization(organization_id, fn ->
      Repo.transaction(fn ->
        session =
          EvidenceSession
          |> where([s], s.id == ^session_id and s.organization_id == ^organization_id)
          |> lock("FOR UPDATE")
          |> Repo.one()

        cond do
          is_nil(session) ->
            Repo.rollback(:not_found)

          session.status in ["completed", "partial", "cancelled", "failed", "expired"] ->
            session

          true ->
            now = DateTime.utc_now()

            session =
              session
              |> Ecto.Changeset.change(
                status: "cancelled",
                approval_status:
                  if(session.approval_status == "pending",
                    do: "expired",
                    else: session.approval_status
                  ),
                cancelled_at: now,
                completed_at: now
              )
              |> Repo.update!()

            cancel_mobile_command(session, actor)
            cancel_pending_artifacts(session)
            audit(session, "evidence_session_cancelled", %{actor_id: actor && actor.id})
            session
        end
      end)
    end)
  end

  def lock_for_frame(organization_id, session_id, frame_index, fun) do
    MultiTenant.with_organization(organization_id, fn ->
      Repo.transaction(fn ->
        session =
          EvidenceSession
          |> where([s], s.id == ^session_id and s.organization_id == ^organization_id)
          |> lock("FOR UPDATE")
          |> Repo.one()

        cond do
          is_nil(session) ->
            Repo.rollback(:not_found)

          session.status not in ["scheduled", "running"] ->
            {:skip, session.status}

          DateTime.compare(session.expires_at, DateTime.utc_now()) != :gt ->
            session
            |> Ecto.Changeset.change(status: "expired", completed_at: DateTime.utc_now())
            |> Repo.update!()

            {:skip, "expired"}

          session.next_frame_index != frame_index ->
            {:skip, "out_of_sequence"}

          true ->
            fun.(session)
        end
      end)
    end)
  end

  def advance(session, frame_index) do
    next = frame_index + 1

    session
    |> Ecto.Changeset.change(%{
      status: "running",
      next_frame_index: next,
      started_at: session.started_at || DateTime.utc_now(),
      completed_at: nil
    })
    |> Repo.update!()
  end

  def advance_mobile_aggregate(session, mobile_command_id) do
    session
    |> Ecto.Changeset.change(%{
      status: "running",
      next_frame_index: session.frame_count,
      mobile_command_id: mobile_command_id,
      started_at: session.started_at || DateTime.utc_now(),
      completed_at: nil
    })
    |> Repo.update!()
  end

  def reconcile_mobile_command(%MDMCommand{command_type: "evidence_session"} = command)
      when command.status in ["completed", "failed"] do
    case Repo.get_by(EvidenceSession,
           mobile_command_id: command.id,
           organization_id: command.organization_id
         ) do
      nil ->
        {:ok, nil}

      %EvidenceSession{status: status} = session
      when status in ["completed", "partial", "cancelled", "failed", "expired"] ->
        {:ok, session}

      session ->
        reason =
          if command.status == "completed",
            do: "mobile_command_completed_without_upload_ack",
            else: "mobile_evidence_session_command_failed"

        ScreenCaptureArtifact
        |> where([a], a.evidence_session_id == ^session.id and a.status == "pending")
        |> Repo.all()
        |> Enum.each(&ScreenCaptureArtifacts.mark_failed(&1, reason))

        refreshed = session |> Repo.reload!() |> refresh_terminal()

        audit(refreshed, "evidence_session_mobile_command_terminal", %{
          mobile_command_id: command.id,
          mobile_command_status: command.status,
          terminal_status: refreshed.status
        })

        {:ok, refreshed}
    end
  end

  def reconcile_mobile_command(_command), do: {:ok, nil}

  def enqueue_frame(session, index, delay_seconds) do
    %{
      "organization_id" => session.organization_id,
      "session_id" => session.id,
      "frame_index" => index
    }
    |> EvidenceSessionFrameWorker.new(schedule_in: delay_seconds)
    |> Oban.insert!()
  end

  defp expire_pending_approval(
         %EvidenceSession{status: "pending_approval", approval_status: "pending"} = session
       ) do
    if is_nil(session.approval_expires_at) or
         DateTime.compare(session.approval_expires_at, DateTime.utc_now()) != :gt do
      expired =
        session
        |> Ecto.Changeset.change(
          status: "expired",
          approval_status: "expired",
          completed_at: DateTime.utc_now()
        )
        |> Repo.update!()

      audit(expired, "evidence_session_approval_expired", %{})
      expired
    else
      session
    end
  end

  defp expire_pending_approval(session), do: session

  defp refresh_terminal(%EvidenceSession{status: status} = session)
       when status in ["cancelled", "failed", "expired", "completed", "partial"],
       do: session

  defp refresh_terminal(session) do
    counts =
      ScreenCaptureArtifact
      |> where([a], a.evidence_session_id == ^session.id)
      |> group_by([a], a.status)
      |> select([a], {a.status, count(a.id)})
      |> Repo.all()
      |> Map.new()

    pending = Map.get(counts, "pending", 0)
    ready = Map.get(counts, "ready", 0)
    failed = Map.get(counts, "failed", 0) + Map.get(counts, "expired", 0)
    recorded = Enum.sum(Map.values(counts))
    missing = max(session.frame_count - recorded, 0)

    cond do
      session.next_frame_index < session.frame_count or pending > 0 ->
        session

      ready == session.frame_count ->
        update_terminal(session, "completed", nil, ready / session.frame_count)

      ready > 0 and failed + missing > 0 ->
        update_terminal(
          session,
          "partial",
          "one_or_more_frames_failed",
          ready / session.frame_count
        )

      ready == 0 and failed + missing >= session.frame_count ->
        update_terminal(session, "failed", "all_frames_failed", 0.0)

      true ->
        update_terminal(session, "failed", "incomplete_frame_set", ready / session.frame_count)
    end
  end

  defp update_terminal(session, status, reason, coverage) do
    completed_at = DateTime.utc_now()

    updated =
      session
      |> Ecto.Changeset.change(
        status: status,
        failure_reason: reason,
        completed_at: completed_at
      )
      |> Repo.update!()

    emit(:completed, session_duration_native(session, completed_at), %{
      status: status,
      coverage: coverage,
      platform: get_in(session.capture_request || %{}, ["platform"]) || "unknown"
    })

    updated
  end

  def fail(session, reason) do
    completed_at = DateTime.utc_now()

    failed =
      session
      |> Ecto.Changeset.change(
        status: "failed",
        failure_reason: inspect(reason, limit: 10) |> String.slice(0, 500),
        completed_at: completed_at
      )
      |> Repo.update!()

    emit(:failed, session_duration_native(session, completed_at), %{
      status: "failed",
      platform: get_in(session.capture_request || %{}, ["platform"]) || "unknown"
    })

    failed
  end

  def audit(session, action, details) do
    AuditLog.log(%{
      action: action,
      action_type: "live_response",
      resource_type: "screen_capture_evidence_session",
      resource_id: session.id,
      organization_id: session.organization_id,
      severity: :warning,
      details: Map.merge(%{agent_id: session.agent_id, status: session.status}, details)
    })
  end

  defp cancel_pending_artifacts(session) do
    ScreenCaptureArtifact
    |> where([a], a.evidence_session_id == ^session.id and a.status == "pending")
    |> Repo.all()
    |> Enum.each(fn artifact ->
      if artifact.command_id,
        do: TamanduaServer.Agents.CommandManager.cancel_command(artifact.command_id)

      if artifact.mobile_command_id do
        case Repo.get(TamanduaServer.Mobile.MDMCommand, artifact.mobile_command_id) do
          nil -> :ok
          command -> Repo.delete(command)
        end
      end

      ScreenCaptureArtifacts.mark_failed(artifact, "evidence_session_cancelled")
    end)
  end

  defp cancel_mobile_command(%EvidenceSession{mobile_command_id: nil}, _actor), do: :ok

  defp cancel_mobile_command(session, actor) do
    case Repo.get_by(MDMCommand,
           id: session.mobile_command_id,
           organization_id: session.organization_id
         ) do
      nil ->
        :ok

      %MDMCommand{status: "pending"} = command ->
        Repo.delete!(command)
        :ok

      %MDMCommand{status: "sent"} = command ->
        %MDMCommand{}
        |> MDMCommand.changeset(%{
          command_type: "cancel_evidence_session",
          device_id: command.device_id,
          organization_id: session.organization_id,
          requested_by: "evidence_session_cancel:#{(actor && actor.id) || "system"}",
          status: "pending",
          payload: %{
            schema_version: "tamandua.screen_evidence_session_cancel/v1",
            session_id: session.id,
            request_id: session.id
          }
        })
        |> Repo.insert!()

        :ok

      _terminal ->
        :ok
    end
  end

  defp bounded_int(value, min, max) when is_integer(value) and value >= min and value <= max,
    do: {:ok, value}

  defp bounded_int(_, _, _), do: {:error, :invalid_bounds}

  defp validate_platform_frame_count(agent, frame_count) do
    if platform(agent) == "android" and frame_count > @normal_max_frames,
      do: {:error, :android_evidence_session_frame_count_unsupported},
      else: :ok
  end

  defp validate_links(organization_id, params) do
    MultiTenant.with_organization(organization_id, fn ->
      with :ok <- linked?(Alert, params["alert_id"], organization_id),
           :ok <- linked?(Investigation, params["investigation_id"], organization_id),
           :ok <- linked?(CaseInvestigation, params["case_id"], organization_id) do
        :ok
      end
    end)
  end

  defp linked?(_schema, nil, _organization_id), do: :ok

  defp linked?(schema, id, organization_id) when is_binary(id) do
    case Ecto.UUID.cast(id) do
      {:ok, uuid} ->
        case Repo.get_by(schema, id: uuid, organization_id: organization_id) do
          nil -> {:error, :invalid_link}
          _ -> :ok
        end

      :error ->
        {:error, :invalid_link}
    end
  end

  defp linked?(_, _, _), do: {:error, :invalid_link}

  defp platform(%{os_type: value}) when is_binary(value), do: String.downcase(value)
  defp platform(_), do: "unknown"

  defp emit(operation, duration, metadata) do
    {coverage, metadata} = Map.pop(metadata, :coverage)

    measurements =
      %{duration: duration, count: 1}
      |> maybe_put_measurement(:coverage, coverage)

    :telemetry.execute(
      [:tamandua, :evidence_session, operation],
      measurements,
      Map.put_new(metadata, :platform, "unknown")
    )
  end

  defp maybe_put_measurement(measurements, _key, nil), do: measurements
  defp maybe_put_measurement(measurements, key, value), do: Map.put(measurements, key, value)

  defp session_duration_native(session, completed_at) do
    started_at = session.started_at || session.inserted_at

    case started_at do
      %DateTime{} ->
        completed_at
        |> DateTime.diff(started_at, :microsecond)
        |> max(0)
        |> System.convert_time_unit(:microsecond, :native)

      %NaiveDateTime{} ->
        completed_at
        |> DateTime.to_naive()
        |> NaiveDateTime.diff(started_at, :microsecond)
        |> max(0)
        |> System.convert_time_unit(:microsecond, :native)

      _ ->
        0
    end
  end

  def emit_frame(session, result, duration) do
    emit(:frame, duration, %{
      status: if(match?({:ok, _}, result), do: "ok", else: "error"),
      platform: get_in(session.capture_request || %{}, ["platform"]) || "unknown"
    })
  end

  defp stringify_keys(map) when is_map(map) do
    Map.new(map, fn {key, value} -> {to_string(key), stringify_keys(value)} end)
  end

  defp stringify_keys(list) when is_list(list), do: Enum.map(list, &stringify_keys/1)
  defp stringify_keys(value), do: value
end
