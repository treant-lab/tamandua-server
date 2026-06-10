defmodule TamanduaServer.Audit.ActivityExporter do
  @moduledoc """
  Exports audit logs to various formats (CSV, JSON, PDF).
  Supports scheduled exports and large dataset streaming.
  """

  import Ecto.Query
  alias TamanduaServer.Repo
  alias TamanduaServer.Audit.AuditLog
  alias TamanduaServer.Audit.AuditExport

  @export_dir "/tmp/tamandua_exports"

  @doc """
  Creates an export job.
  """
  def create_export(attrs) do
    %AuditExport{}
    |> AuditExport.changeset(attrs)
    |> Repo.insert()
    |> case do
      {:ok, export} ->
        # Start async export process
        Task.start(fn -> process_export(export.id) end)
        {:ok, export}
      
      error ->
        error
    end
  end

  @doc """
  Exports audit logs to CSV format.
  """
  def export_to_csv(organization_id, filters, output_path) do
    File.mkdir_p!(Path.dirname(output_path))
    file = File.open!(output_path, [:write, :utf8])

    # Write CSV header
    IO.write(file, csv_header())

    # Stream and write data
    query = build_export_query(organization_id, filters)
    
    Repo.stream(query)
    |> Stream.chunk_every(1000)
    |> Enum.each(fn chunk ->
      csv_data = Enum.map_join(chunk, "\n", &audit_log_to_csv_row/1)
      IO.write(file, csv_data <> "\n")
    end)

    File.close(file)
    {:ok, File.stat!(output_path).size}
  end

  @doc """
  Exports audit logs to JSON format.
  """
  def export_to_json(organization_id, filters, output_path) do
    File.mkdir_p!(Path.dirname(output_path))
    file = File.open!(output_path, [:write, :utf8])

    IO.write(file, "[\n")

    query = build_export_query(organization_id, filters)
    
    Repo.stream(query)
    |> Stream.chunk_every(1000)
    |> Stream.with_index()
    |> Enum.each(fn {chunk, index} ->
      json_chunk = Enum.map(chunk, &audit_log_to_map/1)
      json_data = Jason.encode!(json_chunk)
      
      # Remove outer brackets
      json_data = String.slice(json_data, 1..-2//1)
      
      if index > 0, do: IO.write(file, ",\n")
      IO.write(file, json_data)
    end)

    IO.write(file, "\n]")
    File.close(file)
    {:ok, File.stat!(output_path).size}
  end

  @doc """
  Processes an export job asynchronously.
  """
  def process_export(export_id) do
    export = Repo.get!(AuditExport, export_id) |> Repo.preload(:organization)
    
    # Update status to processing
    export
    |> Ecto.Changeset.change(%{status: "processing", progress: 0})
    |> Repo.update!()

    try do
      output_path = Path.join(@export_dir, "#{export.id}.#{export.export_type}")
      
      result = case export.export_type do
        "csv" -> export_to_csv(export.organization_id, export.filters, output_path)
        "json" -> export_to_json(export.organization_id, export.filters, output_path)
        "pdf" -> export_to_pdf(export.organization_id, export.filters, output_path)
      end

      case result do
        {:ok, file_size} ->
          expires_at = DateTime.add(DateTime.utc_now(), 7 * 24 * 3600, :second)
          
          export
          |> Ecto.Changeset.change(%{
            status: "completed",
            progress: 100,
            file_path: output_path,
            file_size: file_size,
            expires_at: expires_at
          })
          |> Repo.update!()
          
        {:error, reason} ->
          export
          |> Ecto.Changeset.change(%{
            status: "failed",
            error_message: inspect(reason)
          })
          |> Repo.update!()
      end
    rescue
      e ->
        export
        |> Ecto.Changeset.change(%{
          status: "failed",
          error_message: Exception.message(e)
        })
        |> Repo.update!()
    end
  end

  # Private functions

  defp build_export_query(organization_id, filters) do
    query = from a in AuditLog,
      where: a.organization_id == ^organization_id,
      order_by: [desc: a.inserted_at],
      preload: [:user]

    apply_filters(query, filters)
  end

  defp apply_filters(query, filters) do
    Enum.reduce(filters, query, fn
      {"from_date", from_date}, q -> where(q, [a], a.inserted_at >= ^from_date)
      {"to_date", to_date}, q -> where(q, [a], a.inserted_at <= ^to_date)
      {"user_id", user_id}, q -> where(q, [a], a.user_id == ^user_id)
      {"action", action}, q -> where(q, [a], a.action == ^action)
      {"category", category}, q -> where(q, [a], a.category == ^category)
      _, q -> q
    end)
  end

  defp csv_header do
    "Timestamp,User,Action,Resource Type,Resource ID,IP Address,Success,Severity,Category,Suspicious\n"
  end

  defp audit_log_to_csv_row(log) do
    [
      format_timestamp(log.inserted_at),
      get_user_email(log.user),
      log.action,
      log.resource_type,
      log.resource_id || "",
      log.ip_address || "",
      log.success,
      log.severity,
      log.category,
      log.suspicious
    ]
    |> Enum.map(&escape_csv_field/1)
    |> Enum.join(",")
  end

  defp audit_log_to_map(log) do
    %{
      id: log.id,
      timestamp: log.inserted_at,
      user: get_user_email(log.user),
      action: log.action,
      resource_type: log.resource_type,
      resource_id: log.resource_id,
      ip_address: log.ip_address,
      success: log.success,
      severity: log.severity,
      category: log.category,
      metadata: log.metadata,
      suspicious: log.suspicious,
      suspicious_reason: log.suspicious_reason
    }
  end

  defp escape_csv_field(value) when is_binary(value) do
    if String.contains?(value, [",", "\"", "\n"]) do
      "\"#{String.replace(value, "\"", "\"\"")}\""
    else
      value
    end
  end
  defp escape_csv_field(value), do: to_string(value)

  defp format_timestamp(nil), do: ""
  defp format_timestamp(timestamp), do: DateTime.to_iso8601(timestamp)

  defp get_user_email(nil), do: "System"
  defp get_user_email(%{email: email}), do: email

  defp export_to_pdf(_org_id, _filters, _path) do
    # PDF export would use a library like Puppeteer or wkhtmltopdf
    {:error, "PDF export not yet implemented"}
  end
end

# Schema moved to separate file: a_audit_export.ex (TamanduaServer.Audit.AuditExport)
