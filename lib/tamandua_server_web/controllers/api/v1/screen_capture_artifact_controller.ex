defmodule TamanduaServerWeb.API.V1.ScreenCaptureArtifactController do
  @moduledoc "Secure upload, status and content delivery for screen snapshots."

  use TamanduaServerWeb, :controller

  alias TamanduaServer.LiveResponse.{ScreenCapture, ScreenCaptureArtifacts}

  @max_bytes 8_388_608

  def upload(conn, %{"artifact_id" => artifact_id}) do
    with {:ok, token} <- bearer_token(conn),
         {:ok, declared_length} <- validate_declared_length(conn),
         {:ok, body, conn} <- read_bounded_body(conn),
         :ok <- verify_actual_length(body, declared_length),
         {:ok, artifact} <-
           ScreenCaptureArtifacts.upload(
             artifact_id,
             token,
             content_type(conn),
             first_header(conn, "x-tamandua-sha256"),
             first_header(conn, "x-tamandua-captured-at"),
             body
           ) do
      conn
      |> put_status(:created)
      |> put_resp_header("cache-control", "no-store, private")
      |> json(%{
        data: %{
          schema_version: ScreenCapture.schema_version(),
          artifact_id: artifact.id,
          status: artifact.status,
          size: artifact.size,
          sha256: artifact.sha256
        }
      })
    else
      {:error, reason} -> upload_error(conn, reason)
    end
  end

  def show(conn, %{"agent_id" => agent_id, "artifact_id" => artifact_id}) do
    with :ok <- authorize_screen(conn),
         {:ok, artifact} <-
           ScreenCaptureArtifacts.get_for_tenant(
             current_organization_id(conn),
             agent_id,
             artifact_id
           ) do
      conn
      |> put_resp_header("cache-control", "no-store, private")
      |> json(%{data: serialize_status(artifact, agent_id)})
    else
      {:error, :unauthorized} ->
        conn |> put_status(:forbidden) |> json(%{error: "Insufficient permissions"})

      {:error, :not_found} ->
        conn |> put_status(:not_found) |> json(%{error: "Artifact not found"})

      {:error, reason} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: to_string(reason)})
    end
  end

  def content(conn, %{"agent_id" => agent_id, "artifact_id" => artifact_id}) do
    with :ok <- authorize_screen(conn),
         {:ok, artifact} <-
           ScreenCaptureArtifacts.get_for_tenant(
             current_organization_id(conn),
             agent_id,
             artifact_id
           ),
         :ok <- artifact_ready(artifact) do
      conn
      |> put_resp_content_type("image/png")
      |> put_resp_header("cache-control", "no-store, no-cache, must-revalidate, private")
      |> put_resp_header("pragma", "no-cache")
      |> put_resp_header("x-content-type-options", "nosniff")
      |> put_resp_header("content-disposition", "inline; filename=screen-capture.png")
      |> send_resp(:ok, artifact.content)
    else
      {:error, :unauthorized} ->
        conn |> put_status(:forbidden) |> json(%{error: "Insufficient permissions"})

      {:error, :not_found} ->
        conn |> put_status(:not_found) |> json(%{error: "Artifact not found"})

      {:error, :pending} ->
        conn |> put_status(:conflict) |> json(%{error: "Artifact upload is pending"})

      {:error, :expired} ->
        conn |> put_status(:gone) |> json(%{error: "Artifact expired"})

      {:error, :failed} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "Artifact capture failed"})
    end
  end

  defp serialize_status(artifact, agent_id) do
    content_url =
      if artifact.status == "ready" do
        "/api/v1/live-response/#{agent_id}/screen-captures/#{artifact.id}/content"
      end

    %{
      schema_version: ScreenCapture.schema_version(),
      command_id: artifact.command_id || artifact.mobile_command_id,
      artifact: %{
        id: artifact.id,
        status: artifact.status,
        mime: artifact.mime,
        size: artifact.size,
        sha256: artifact.sha256,
        captured_at: iso8601(artifact.captured_at),
        display: artifact.display,
        expires_at: iso8601(artifact.expires_at),
        uploaded_at: iso8601(artifact.uploaded_at),
        failure_reason: artifact.failure_reason,
        content_url: content_url
      }
    }
  end

  defp artifact_ready(%{status: "ready", content: content}) when is_binary(content), do: :ok
  defp artifact_ready(%{status: "pending"}), do: {:error, :pending}
  defp artifact_ready(%{status: "expired"}), do: {:error, :expired}
  defp artifact_ready(_artifact), do: {:error, :failed}

  defp authorize_screen(conn) do
    if TamanduaServer.Authorization.RBAC.can?(
         conn.assigns[:current_user],
         :live_response_screen
       ) do
      :ok
    else
      {:error, :unauthorized}
    end
  rescue
    _ -> {:error, :unauthorized}
  end

  defp current_organization_id(conn) do
    conn.assigns[:current_organization_id] || conn.assigns[:current_user].organization_id
  end

  defp bearer_token(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] when byte_size(token) > 0 -> {:ok, token}
      _ -> {:error, :invalid_token}
    end
  end

  defp validate_declared_length(conn) do
    case get_req_header(conn, "content-length") do
      [value] ->
        case Integer.parse(value) do
          {length, ""} when length > 0 and length <= @max_bytes -> {:ok, length}
          {length, ""} when length > @max_bytes -> {:error, :upload_too_large}
          _ -> {:error, :invalid_content_length}
        end

      _ ->
        {:error, :invalid_content_length}
    end
  end

  defp verify_actual_length(body, declared_length) do
    if byte_size(body) == declared_length, do: :ok, else: {:error, :content_length_mismatch}
  end

  defp read_bounded_body(conn, acc \\ <<>>) do
    remaining = @max_bytes + 1 - byte_size(acc)

    if remaining <= 0 do
      {:error, :upload_too_large}
    else
      case Plug.Conn.read_body(conn, length: remaining, read_length: min(remaining, 1_048_576)) do
        {:ok, chunk, conn} ->
          body = acc <> chunk

          if byte_size(body) <= @max_bytes,
            do: {:ok, body, conn},
            else: {:error, :upload_too_large}

        {:more, chunk, conn} ->
          read_bounded_body(conn, acc <> chunk)

        {:error, _reason} ->
          {:error, :invalid_upload}
      end
    end
  end

  defp content_type(conn) do
    conn
    |> get_req_header("content-type")
    |> List.first()
    |> case do
      nil -> nil
      value -> value |> String.split(";", parts: 2) |> hd() |> String.trim() |> String.downcase()
    end
  end

  defp first_header(conn, name), do: conn |> get_req_header(name) |> List.first()

  defp upload_error(conn, reason) when reason in [:invalid_token, :not_found] do
    conn |> put_status(:not_found) |> json(%{error: "Upload target not found"})
  end

  defp upload_error(conn, :expired),
    do: conn |> put_status(:gone) |> json(%{error: "Upload expired"})

  defp upload_error(conn, :upload_too_large),
    do: conn |> put_status(:payload_too_large) |> json(%{error: "PNG exceeds 8 MiB"})

  defp upload_error(conn, :unsupported_mime),
    do:
      conn |> put_status(:unsupported_media_type) |> json(%{error: "Only image/png is accepted"})

  defp upload_error(conn, :upload_not_pending),
    do: conn |> put_status(:conflict) |> json(%{error: "Upload credential already consumed"})

  defp upload_error(conn, reason)
       when reason in [
              :invalid_content_length,
              :content_length_mismatch,
              :invalid_upload,
              :empty_upload,
              :invalid_png,
              :invalid_sha256,
              :sha256_mismatch,
              :invalid_captured_at
            ] do
    conn |> put_status(:unprocessable_entity) |> json(%{error: to_string(reason)})
  end

  defp iso8601(nil), do: nil
  defp iso8601(datetime), do: DateTime.to_iso8601(datetime)
end
