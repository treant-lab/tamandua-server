defmodule TamanduaServerWeb.API.V1.EvidenceSessionController do
  use TamanduaServerWeb, :controller

  alias TamanduaServer.LiveResponse.{
    EvidenceSessionContext,
    EvidenceSessionDiffs,
    EvidenceSessionExports,
    EvidenceSessions
  }

  def create(conn, %{"agent_id" => agent_id} = params) do
    with :ok <- authorize(conn),
         {:ok, session} <-
           EvidenceSessions.create(org_id(conn), agent_id, params, conn.assigns[:current_user]) do
      conn
      |> put_status(:accepted)
      |> put_resp_header("cache-control", "no-store, private")
      |> json(%{data: serialize(session)})
    else
      {:error, :unauthorized} ->
        conn |> put_status(:forbidden) |> json(%{error: "Insufficient permissions"})

      {:error, :not_found} ->
        conn |> put_status(:not_found) |> json(%{error: "Agent not found"})

      {:error, reason} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: public_error(reason)})
    end
  end

  def show(conn, %{"session_id" => id}) do
    with :ok <- authorize(conn), {:ok, session} <- EvidenceSessions.get(org_id(conn), id) do
      conn
      |> put_resp_header("cache-control", "no-store, private")
      |> json(%{data: serialize(session, build_context(session))})
    else
      {:error, :unauthorized} ->
        conn |> put_status(:forbidden) |> json(%{error: "Insufficient permissions"})

      {:error, :not_found} ->
        conn |> put_status(:not_found) |> json(%{error: "Evidence session not found"})
    end
  end

  def cancel(conn, %{"session_id" => id}) do
    with :ok <- authorize(conn),
         {:ok, session} <- EvidenceSessions.cancel(org_id(conn), id, conn.assigns[:current_user]) do
      json(conn, %{data: serialize(session)})
    else
      {:error, :unauthorized} ->
        conn |> put_status(:forbidden) |> json(%{error: "Insufficient permissions"})

      {:error, :not_found} ->
        conn |> put_status(:not_found) |> json(%{error: "Evidence session not found"})
    end
  end

  def approve(conn, %{"session_id" => id}) do
    with :ok <- authorize_approval(conn),
         {:ok, session} <- EvidenceSessions.approve(org_id(conn), id, conn.assigns[:current_user]) do
      json(conn, %{data: serialize(session)})
    else
      {:error, :unauthorized} ->
        conn |> put_status(:forbidden) |> json(%{error: "Insufficient permissions"})

      {:error, :not_found} ->
        conn |> put_status(:not_found) |> json(%{error: "Evidence session not found"})

      {:error, reason} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: public_error(reason)})
    end
  end

  def create_export(conn, %{"session_id" => id}) do
    with :ok <- authorize(conn),
         {:ok, export} <-
           EvidenceSessionExports.create(org_id(conn), id, conn.assigns[:current_user]) do
      conn
      |> put_status(:created)
      |> put_resp_header("cache-control", "no-store, private")
      |> json(%{
        data: %{
          id: export.id,
          sha256: export.sha256,
          size: export.size,
          expires_at: export.expires_at,
          download_url: "/api/v1/live-response/evidence-session-exports/#{export.id}"
        }
      })
    else
      {:error, :unauthorized} ->
        conn |> put_status(:forbidden) |> json(%{error: "Insufficient permissions"})

      {:error, :not_found} ->
        conn |> put_status(:not_found) |> json(%{error: "Evidence session not found"})

      {:error, reason} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: public_error(reason)})
    end
  end

  def download_export(conn, %{"export_id" => id}) do
    with :ok <- authorize(conn),
         {:ok, export} <-
           EvidenceSessionExports.get(org_id(conn), id, conn.assigns[:current_user]) do
      conn
      |> put_resp_header("cache-control", "no-store, private")
      |> put_resp_header(
        "content-disposition",
        ~s(attachment; filename="evidence-#{export.evidence_session_id}.zip")
      )
      |> put_resp_header("x-content-sha256", export.sha256)
      |> put_resp_content_type("application/zip")
      |> send_resp(200, export.content)
    else
      {:error, :unauthorized} ->
        conn |> put_status(:forbidden) |> json(%{error: "Insufficient permissions"})

      {:error, :not_found} ->
        conn |> put_status(:not_found) |> json(%{error: "Evidence export not found"})
    end
  end

  def create_diff(conn, %{
        "session_id" => id,
        "left_artifact_id" => left,
        "right_artifact_id" => right
      }) do
    with :ok <- authorize(conn),
         {:ok, diff} <-
           EvidenceSessionDiffs.create(org_id(conn), id, left, right, conn.assigns[:current_user]) do
      conn
      |> put_status(:created)
      |> put_resp_header("cache-control", "no-store, private")
      |> json(%{data: %{id: diff.id, metrics: diff.metrics, expires_at: diff.expires_at}})
    else
      {:error, :unauthorized} ->
        conn |> put_status(:forbidden) |> json(%{error: "Insufficient permissions"})

      {:error, :not_found} ->
        conn |> put_status(:not_found) |> json(%{error: "Evidence frame not found"})

      {:error, reason} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: public_error(reason)})
    end
  end

  defp serialize(session, context \\ nil) do
    %{
      schema_version: "tamandua.screen_evidence_session/v2",
      id: session.id,
      agent_id: session.agent_id,
      status: session.status,
      reason: session.reason,
      frame_count: session.frame_count,
      interval_seconds: session.interval_seconds,
      frames_dispatched: session.next_frame_index,
      expires_at: session.expires_at,
      started_at: session.started_at,
      completed_at: session.completed_at,
      cancelled_at: session.cancelled_at,
      failure_reason: session.failure_reason,
      approval_status: session.approval_status,
      approval_expires_at: session.approval_expires_at,
      approved_by_id: session.approved_by_id,
      approved_at: session.approved_at,
      mobile_command_id: session.mobile_command_id,
      links: %{
        alert_id: session.alert_id,
        investigation_id: session.investigation_id,
        case_id: session.case_id
      },
      context: context,
      continuous: false,
      input_control: false,
      frames:
        Enum.map(
          if(is_list(Map.get(session, :artifacts)), do: session.artifacts, else: []),
          fn artifact ->
            %{
              index: artifact.frame_index,
              artifact_id: artifact.id,
              status: artifact.status,
              mime: artifact.mime,
              size: artifact.size,
              sha256: artifact.sha256,
              captured_at: artifact.captured_at,
              expires_at: artifact.expires_at,
              failure_reason: artifact.failure_reason,
              content_url:
                if artifact.status == "ready" do
                  "/api/v1/live-response/#{session.agent_id}/screen-captures/#{artifact.id}/content"
                end,
              status_url:
                "/api/v1/live-response/#{session.agent_id}/screen-captures/#{artifact.id}"
            }
          end
        )
    }
  end

  defp build_context(session) do
    from = DateTime.add(session.started_at || session.inserted_at, -30, :second)
    to = DateTime.add(session.completed_at || DateTime.utc_now(), 30, :second)

    case EvidenceSessionContext.build(session.organization_id, session.agent_id, from, to) do
      {:ok, context} ->
        context

      {:error, reason} ->
        %{
          schema_version: EvidenceSessionContext.schema_version(),
          process: %{state: "unavailable", reason: to_string(reason), events: []},
          network: %{state: "unavailable", reason: to_string(reason), events: []}
        }
    end
  end

  defp authorize(conn) do
    user = conn.assigns[:current_user]
    if user && safe_can?(user), do: :ok, else: {:error, :unauthorized}
  end

  defp authorize_approval(conn) do
    if TamanduaServer.Accounts.user_can?(conn.assigns[:current_user], :response_approve),
      do: :ok,
      else: {:error, :unauthorized}
  rescue
    _ -> {:error, :unauthorized}
  end

  defp safe_can?(user) do
    TamanduaServer.Authorization.RBAC.can?(user, :live_response_screen)
  rescue
    _ -> false
  end

  defp public_error(:invalid_bounds),
    do: "frame_count or interval_seconds is outside the allowed bounds"

  defp public_error(:duration_too_long), do: "evidence session duration exceeds the maximum"
  defp public_error(:approval_expired), do: "evidence session approval expired"

  defp public_error(:self_approval_forbidden),
    do: "requester cannot approve the same long session"

  defp public_error(:not_pending_approval), do: "evidence session is not pending approval"

  defp public_error(:invalid_link),
    do: "linked alert, investigation, or case was not found in this tenant"

  defp public_error(:session_not_ready), do: "evidence session is not ready for export"
  defp public_error(:package_too_large), do: "evidence package exceeds the maximum size"

  defp public_error(:incompatible_images),
    do: "evidence frames have incompatible PNG dimensions or format"

  defp public_error(:unsupported_png), do: "PNG format is unsupported for bounded diff"
  defp public_error(:same_artifact), do: "two different evidence frames are required"
  defp public_error(:diff_cpu_limit_exceeded), do: "evidence diff exceeded the CPU time limit"
  defp public_error(:diff_busy), do: "evidence diff capacity is busy; retry later"
  defp public_error(:reason_required), do: "reason is required"
  defp public_error(:reason_too_long), do: "reason is too long"
  defp public_error(:invalid_ttl_seconds), do: "ttl_seconds is invalid"
  defp public_error(_), do: "Evidence session request was rejected"

  defp org_id(conn) do
    conn.assigns[:current_organization_id] ||
      get_in(conn.assigns, [:current_organization, Access.key(:id)]) ||
      get_in(conn.assigns, [:current_user, Access.key(:organization_id)])
  end
end
