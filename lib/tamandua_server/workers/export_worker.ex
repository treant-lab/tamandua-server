defmodule TamanduaServer.Workers.ExportWorker do
  @moduledoc """
  Oban worker for background alert export processing.

  Handles:
  - Generating export files (CSV, JSON, PDF)
  - Progress tracking
  - Delivery via email, S3, or SFTP
  - Error handling and retries
  """

  use Oban.Worker,
    queue: :exports,
    max_attempts: 3,
    priority: 2

  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts.{Exporter, ExportJob}

  @impl Oban.Worker
  def perform(%Oban.Job{args: args} = _job) do
    export_job_id = args["export_job_id"]
    delivery_config = args["delivery_config"] || %{}

    Logger.info("[ExportWorker] Starting export job #{export_job_id}")

    with {:ok, export_job} <- Exporter.get_export_job(export_job_id),
         {:ok, export_job} <- generate_export(export_job),
         {:ok, _export_job} <- deliver_export(export_job, delivery_config) do
      Logger.info("[ExportWorker] Export job #{export_job_id} completed successfully")
      :ok
    else
      {:error, :not_found} ->
        Logger.warning("[ExportWorker] Export job #{export_job_id} not found")
        :ok

      {:error, reason} ->
        Logger.error("[ExportWorker] Export job #{export_job_id} failed: #{inspect(reason)}")
        mark_job_failed(export_job_id, reason)
        {:error, reason}
    end
  end

  # ===========================================================================
  # Export Generation
  # ===========================================================================

  defp generate_export(export_job) do
    Logger.info("[ExportWorker] Generating #{export_job.format} export for job #{export_job.id}")

    case Exporter.generate_export(export_job) do
      {:ok, file_info} ->
        export_job
        |> ExportJob.complete_changeset(file_info)
        |> Repo.update()

      {:error, reason} ->
        Logger.error("[ExportWorker] Export generation failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  # ===========================================================================
  # Delivery
  # ===========================================================================

  defp deliver_export(export_job, delivery_config) do
    case export_job.delivery_method do
      "download" ->
        # No delivery needed, just provide download URL
        {:ok, export_job}

      "email" ->
        deliver_via_email(export_job, delivery_config)

      "s3" ->
        deliver_via_s3(export_job, delivery_config)

      "sftp" ->
        deliver_via_sftp(export_job, delivery_config)

      other ->
        Logger.warning("[ExportWorker] Unknown delivery method: #{other}")
        {:ok, export_job}
    end
  end

  defp deliver_via_email(export_job, config) do
    recipients = config["recipients"] || []
    subject = config["subject"] || "Alert Export Report"
    message = config["message"] || "Your requested alert export is attached."

    Logger.info("[ExportWorker] Delivering export via email to #{inspect(recipients)}")

    # The composing/delivery function lives in Mailer.ExportEmail, not Mailer.
    case TamanduaServer.Mailer.ExportEmail.deliver_export_email(
           recipients,
           subject,
           message,
           export_job.file_path
         ) do
      {:ok, _} ->
        export_job
        |> ExportJob.delivery_changeset("delivered")
        |> Repo.update()

      {:error, reason} ->
        Logger.error("[ExportWorker] Email delivery failed: #{inspect(reason)}")

        export_job
        |> ExportJob.delivery_changeset("failed", inspect(reason))
        |> Repo.update()

        {:error, reason}
    end
  end

  defp deliver_via_s3(export_job, config) do
    bucket = config["bucket"]
    key = config["key"] || "exports/#{Path.basename(export_job.file_path)}"
    region = config["region"] || "us-east-1"

    Logger.info("[ExportWorker] Uploading export to S3: s3://#{bucket}/#{key}")

    with {:ok, file_data} <- File.read(export_job.file_path),
         {:ok, _} <- upload_to_s3(bucket, key, file_data, region) do
      export_job
      |> ExportJob.delivery_changeset("delivered")
      |> Repo.update()
    else
      {:error, reason} ->
        Logger.error("[ExportWorker] S3 upload failed: #{inspect(reason)}")

        export_job
        |> ExportJob.delivery_changeset("failed", inspect(reason))
        |> Repo.update()

        {:error, reason}
    end
  end

  defp upload_to_s3(bucket, key, data, region) do
    ExAws.S3.put_object(bucket, key, data)
    |> ExAws.request(region: region)
  end

  defp deliver_via_sftp(export_job, config) do
    host = config["host"]
    port = config["port"] || 22
    username = config["username"]
    password = config["password"]
    remote_path = config["remote_path"] || "/exports/#{Path.basename(export_job.file_path)}"

    Logger.info("[ExportWorker] Uploading export via SFTP to #{host}:#{port}")

    with {:ok, conn} <- connect_sftp(host, port, username, password),
         {:ok, file_data} <- File.read(export_job.file_path),
         :ok <- write_sftp_file(conn, remote_path, file_data),
         :ok <- disconnect_sftp(conn) do
      export_job
      |> ExportJob.delivery_changeset("delivered")
      |> Repo.update()
    else
      {:error, reason} ->
        Logger.error("[ExportWorker] SFTP upload failed: #{inspect(reason)}")

        export_job
        |> ExportJob.delivery_changeset("failed", inspect(reason))
        |> Repo.update()

        {:error, reason}
    end
  end

  # SFTP helpers (using Erlang's :ssh_sftp)
  defp connect_sftp(host, port, username, password) do
    case :ssh_sftp.start_channel(
           String.to_charlist(host),
           port: port,
           user: String.to_charlist(username),
           password: String.to_charlist(password),
           silently_accept_hosts: true
         ) do
      {:ok, channel_pid} -> {:ok, channel_pid}
      {:error, reason} -> {:error, reason}
    end
  end

  defp write_sftp_file(conn, remote_path, data) do
    case :ssh_sftp.write_file(conn, String.to_charlist(remote_path), data) do
      :ok -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp disconnect_sftp(conn) do
    :ssh_sftp.stop_channel(conn)
    :ok
  end

  # ===========================================================================
  # Error Handling
  # ===========================================================================

  defp mark_job_failed(export_job_id, reason) do
    case Exporter.get_export_job(export_job_id) do
      {:ok, export_job} ->
        export_job
        |> ExportJob.fail_changeset(inspect(reason))
        |> Repo.update()

      {:error, _} ->
        :ok
    end
  end
end
