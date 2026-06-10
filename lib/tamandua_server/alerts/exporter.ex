defmodule TamanduaServer.Alerts.Exporter do
  @moduledoc """
  Alert export orchestrator.

  Handles:
  - Creating export jobs
  - Generating exports in CSV, JSON, and PDF formats
  - Managing export templates
  - Coordinating with ExportWorker for background processing
  """

  import Ecto.Query
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts
  alias TamanduaServer.Alerts.{Alert, ExportTemplate, ExportJob}
  alias TamanduaServer.Workers.ExportWorker

  @upload_dir Application.compile_env(:tamandua_server, :export_upload_dir, "priv/static/exports")
  @url_expiry_hours 24

  # ===========================================================================
  # Export Job Management
  # ===========================================================================

  @doc """
  Creates and enqueues an export job.

  ## Options
  - `:format` - Export format (csv, json, pdf) [required]
  - `:filter_json` - Alert filter criteria
  - `:columns` - List of columns to include
  - `:delivery_method` - How to deliver (download, email, s3, sftp)
  - `:delivery_config` - Delivery configuration (email addresses, etc.)
  - `:template_id` - Use saved template
  - `:triggered_by` - manual or scheduled
  """
  def create_export(organization_id, user_id, opts) do
    attrs = %{
      organization_id: organization_id,
      user_id: user_id,
      format: Keyword.fetch!(opts, :format),
      filter_json: Keyword.get(opts, :filter_json, %{}),
      columns: Keyword.get(opts, :columns, ExportTemplate.default_columns()),
      delivery_method: Keyword.get(opts, :delivery_method, "download"),
      triggered_by: Keyword.get(opts, :triggered_by, "manual"),
      template_id: Keyword.get(opts, :template_id)
    }

    with {:ok, job} <- create_export_job(attrs),
         {:ok, _oban_job} <- enqueue_export_job(job, Keyword.get(opts, :delivery_config)) do
      {:ok, job}
    end
  end

  defp create_export_job(attrs) do
    %ExportJob{}
    |> ExportJob.changeset(attrs)
    |> Repo.insert()
  end

  defp enqueue_export_job(job, delivery_config) do
    %{
      "export_job_id" => job.id,
      "delivery_config" => delivery_config || %{}
    }
    |> ExportWorker.new()
    |> Oban.insert()
  end

  @doc """
  Gets an export job by ID.
  """
  def get_export_job(job_id) do
    case Repo.get(ExportJob, job_id) do
      nil -> {:error, :not_found}
      job -> {:ok, job}
    end
  end

  @doc """
  Gets export job for organization (with tenant check).
  """
  def get_export_job_for_org(organization_id, job_id) do
    case Repo.get_by(ExportJob, id: job_id, organization_id: organization_id) do
      nil -> {:error, :not_found}
      job -> {:ok, job}
    end
  end

  @doc """
  Lists export jobs for an organization.
  """
  def list_export_jobs(organization_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 50)
    offset = Keyword.get(opts, :offset, 0)

    ExportJob
    |> where([j], j.organization_id == ^organization_id)
    |> order_by([j], [desc: j.inserted_at])
    |> limit(^limit)
    |> offset(^offset)
    |> Repo.all()
  end

  @doc """
  Cancels a pending or processing export job.
  """
  def cancel_export_job(job_id) do
    with {:ok, job} <- get_export_job(job_id),
         true <- job.status in ["pending", "processing"] do
      job
      |> Ecto.Changeset.change(%{status: "cancelled", completed_at: DateTime.utc_now()})
      |> Repo.update()
    else
      false -> {:error, :cannot_cancel_completed_job}
      error -> error
    end
  end

  # ===========================================================================
  # Export Template Management
  # ===========================================================================

  @doc """
  Creates an export template.
  """
  def create_template(attrs) do
    %ExportTemplate{}
    |> ExportTemplate.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates an export template.
  """
  def update_template(template, attrs) do
    template
    |> ExportTemplate.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Gets a template by ID.
  """
  def get_template(template_id) do
    case Repo.get(ExportTemplate, template_id) do
      nil -> {:error, :not_found}
      template -> {:ok, template}
    end
  end

  @doc """
  Lists templates for an organization.
  """
  def list_templates(organization_id, user_id) do
    ExportTemplate
    |> where([t], t.organization_id == ^organization_id)
    |> where([t], t.created_by_id == ^user_id or t.is_shared == true)
    |> order_by([t], [desc: t.inserted_at])
    |> Repo.all()
  end

  @doc """
  Deletes a template.
  """
  def delete_template(template) do
    Repo.delete(template)
  end

  @doc """
  Updates template last_run_at timestamp.
  """
  def mark_template_run(template_id) do
    from(t in ExportTemplate, where: t.id == ^template_id)
    |> Repo.update_all(set: [last_run_at: DateTime.utc_now()])
  end

  # ===========================================================================
  # Export Generation (called by ExportWorker)
  # ===========================================================================

  @doc """
  Generates an export file and returns file info.
  Called by ExportWorker in background.
  """
  def generate_export(job) do
    job = Repo.preload(job, [:organization, :user])

    # Fetch alerts with filter
    alerts = fetch_alerts_for_export(job)

    # Update job with total count
    job = job
    |> ExportJob.start_changeset(length(alerts))
    |> Repo.update!()

    # Generate export based on format
    case job.format do
      "csv" -> generate_csv_export(job, alerts)
      "json" -> generate_json_export(job, alerts)
      "pdf" -> generate_pdf_export(job, alerts)
    end
  end

  defp fetch_alerts_for_export(job) do
    query = Alert
    |> where([a], a.organization_id == ^job.organization_id)
    |> preload([:agent, :assigned_to])

    # Apply filter
    query = if job.filter_json && map_size(job.filter_json) > 0 do
      Alerts.FilterBuilder.apply_filter(query, job.filter_json)
    else
      query
    end

    # Order by inserted_at desc
    query = order_by(query, [a], [desc: a.inserted_at])

    Repo.all(query)
  end

  defp generate_csv_export(job, alerts) do
    filename = "alerts_export_#{job.id}.csv"
    file_path = Path.join([@upload_dir, filename])

    # Ensure directory exists
    File.mkdir_p!(@upload_dir)

    # Generate CSV content
    csv_data = TamanduaServer.Alerts.Exporters.CSVExporter.generate(alerts, job.columns)

    # Write to file
    File.write!(file_path, csv_data)

    # Generate presigned URL
    url = generate_download_url(filename)
    expires_at = DateTime.utc_now() |> DateTime.add(@url_expiry_hours, :hour)

    {:ok, %{
      file_path: file_path,
      file_size: File.stat!(file_path).size,
      download_url: url,
      url_expires_at: expires_at
    }}
  rescue
    e ->
      Logger.error("[Exporter] CSV generation failed: #{inspect(e)}")
      {:error, "Failed to generate CSV: #{Exception.message(e)}"}
  end

  defp generate_json_export(job, alerts) do
    filename = "alerts_export_#{job.id}.json"
    file_path = Path.join([@upload_dir, filename])

    File.mkdir_p!(@upload_dir)

    json_data = TamanduaServer.Alerts.Exporters.JSONExporter.generate(alerts, job.columns)

    File.write!(file_path, json_data)

    url = generate_download_url(filename)
    expires_at = DateTime.utc_now() |> DateTime.add(@url_expiry_hours, :hour)

    {:ok, %{
      file_path: file_path,
      file_size: File.stat!(file_path).size,
      download_url: url,
      url_expires_at: expires_at
    }}
  rescue
    e ->
      Logger.error("[Exporter] JSON generation failed: #{inspect(e)}")
      {:error, "Failed to generate JSON: #{Exception.message(e)}"}
  end

  defp generate_pdf_export(job, alerts) do
    filename = "alerts_export_#{job.id}.pdf"
    file_path = Path.join([@upload_dir, filename])

    File.mkdir_p!(@upload_dir)

    {:ok, pdf_data} = TamanduaServer.Alerts.Exporters.PDFExporter.generate(alerts, job.columns)

    File.write!(file_path, pdf_data)

    url = generate_download_url(filename)
    expires_at = DateTime.utc_now() |> DateTime.add(@url_expiry_hours, :hour)

    {:ok, %{
      file_path: file_path,
      file_size: File.stat!(file_path).size,
      download_url: url,
      url_expires_at: expires_at
    }}
  rescue
    e ->
      Logger.error("[Exporter] PDF generation failed: #{inspect(e)}")
      {:error, "Failed to generate PDF: #{Exception.message(e)}"}
  end

  defp generate_download_url(filename) do
    # In production, this would be a presigned S3 URL
    # For now, return static file URL
    endpoint_url = TamanduaServerWeb.Endpoint.url()
    "#{endpoint_url}/exports/#{filename}"
  end

  # ===========================================================================
  # Cleanup
  # ===========================================================================

  @doc """
  Cleans up expired export files and jobs.
  Should be called by a scheduled worker.
  """
  def cleanup_expired_exports do
    now = DateTime.utc_now()

    # Delete expired export files
    expired_jobs = from(j in ExportJob,
      where: j.status == "completed" and j.url_expires_at < ^now
    )
    |> Repo.all()

    Enum.each(expired_jobs, fn job ->
      if job.file_path && File.exists?(job.file_path) do
        File.rm(job.file_path)
        Logger.info("[Exporter] Deleted expired export: #{job.file_path}")
      end
    end)

    # Delete old job records (keep for retention_days from template or default 7 days)
    cutoff = DateTime.add(now, -7, :day)

    from(j in ExportJob,
      where: j.completed_at < ^cutoff
    )
    |> Repo.delete_all()

    :ok
  end
end
