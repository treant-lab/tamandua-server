defmodule TamanduaServerWeb.API.V1.SandboxController do
  @moduledoc """
  API Controller for Sandbox Detonation and Dynamic Analysis.

  Provides endpoints for:
  - Submitting files for sandbox detonation
  - Retrieving normalized behavioral reports
  - Checking submission status
  - Viewing sandbox usage statistics
  - Force re-analysis of previously submitted files
  """

  use TamanduaServerWeb, :controller

  require Logger

  alias TamanduaServer.Detection.Sandbox

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  POST /api/v1/sandbox/submit

  Submit a file for sandbox detonation.

  Accepts multipart form data with:
  - `file` - The file to analyze (required)
  - `sha256` - Pre-computed SHA256 hash (optional, computed if missing)
  - `source` - Submission source (optional, e.g. "manual", "quarantine")
  - `alert_id` - Associated alert ID (optional)

  Also accepts JSON body with base64-encoded file data:
  - `file_data` - Base64-encoded file content (required)
  - `file_name` - Original file name (optional)
  - `sha256` - Pre-computed SHA256 hash (optional)
  - `source` - Submission source (optional)
  - `alert_id` - Associated alert ID (optional)
  """
  def submit(conn, params) do
    case extract_file_bytes(conn, params) do
      {:ok, file_bytes, metadata} ->
        case Sandbox.submit(file_bytes, metadata) do
          {:ok, :cached, report} ->
            json(conn, %{
              data: %{
                status: "cached",
                message: "A recent report already exists for this file",
                report: sanitize_report(report)
              }
            })

          {:ok, submission_id} ->
            conn
            |> put_status(:accepted)
            |> json(%{
              data: %{
                submission_id: submission_id,
                status: "submitted",
                message: "File submitted for sandbox analysis"
              }
            })

          {:error, :no_sandboxes_enabled} ->
            conn
            |> put_status(:service_unavailable)
            |> json(%{error: "No sandbox providers are configured. Set API keys for VirusTotal, Any.run, Hybrid Analysis, Cuckoo, or Joe Sandbox."})

          {:error, :all_submissions_failed} ->
            conn
            |> put_status(:bad_gateway)
            |> json(%{error: "All sandbox submissions failed. Check API keys and provider availability."})

          {:error, reason} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "Submission failed: #{inspect(reason)}"})
        end

      {:error, :no_file} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "No file provided. Upload via multipart 'file' field or JSON 'file_data' (base64)."})

      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Invalid file data: #{inspect(reason)}"})
    end
  end

  @doc """
  GET /api/v1/sandbox/report/:hash

  Get the sandbox detonation report for a file by its SHA256 hash.
  Returns the aggregated report with results from all sandboxes.
  """
  def report(conn, %{"hash" => hash}) do
    normalized_hash = String.downcase(String.trim(hash))

    case Sandbox.get_report(normalized_hash) do
      {:ok, report} ->
        json(conn, %{data: sanitize_report(report)})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "No sandbox report found for hash: #{normalized_hash}"})
    end
  end

  @doc """
  GET /api/v1/sandbox/status/:submission_id

  Check the status of a sandbox submission by its ID.
  """
  def status(conn, %{"submission_id" => submission_id}) do
    case Sandbox.get_submission_status(submission_id) do
      {:ok, status_data} ->
        json(conn, %{data: status_data})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "No submission found with ID: #{submission_id}"})
    end
  end

  @doc """
  GET /api/v1/sandbox/stats

  Get sandbox usage statistics including submission counts,
  verdict distributions, IOC extraction counts, and per-sandbox metrics.
  """
  def stats(conn, _params) do
    stats = Sandbox.get_stats()
    config = Sandbox.get_config()

    json(conn, %{
      data: %{
        stats: stats,
        config: config
      }
    })
  end

  @doc """
  POST /api/v1/sandbox/resubmit/:hash

  Force re-analysis of a file by its SHA256 hash.
  Bypasses the deduplication TTL and submits to configured sandboxes.
  Only works with sandboxes that support hash-based lookup (e.g. VirusTotal).
  """
  def resubmit(conn, %{"hash" => hash}) do
    normalized_hash = String.downcase(String.trim(hash))

    case Sandbox.resubmit(normalized_hash) do
      {:ok, submission_id} ->
        conn
        |> put_status(:accepted)
        |> json(%{
          data: %{
            submission_id: submission_id,
            status: "resubmitted",
            message: "File re-submitted for sandbox analysis",
            file_hash: normalized_hash
          }
        })

      {:error, :no_sandboxes_enabled} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{error: "No sandbox providers are configured."})

      {:error, :no_sandbox_supports_hash_resubmit} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "No configured sandbox supports hash-based re-analysis. Upload the file directly instead."})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Resubmission failed: #{inspect(reason)}"})
    end
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  # Extract file bytes from either multipart upload or JSON base64
  defp extract_file_bytes(_conn, %{"file" => %Plug.Upload{} = upload} = params) do
    case File.read(upload.path) do
      {:ok, file_bytes} ->
        metadata = %{
          sha256: params["sha256"],
          file_name: upload.filename || params["file_name"],
          source: params["source"] || "manual",
          alert_id: params["alert_id"]
        }
        {:ok, file_bytes, metadata}

      {:error, reason} ->
        {:error, {:file_read_failed, reason}}
    end
  end

  defp extract_file_bytes(_conn, %{"file_data" => file_data} = params) when is_binary(file_data) do
    case Base.decode64(file_data) do
      {:ok, file_bytes} ->
        metadata = %{
          sha256: params["sha256"],
          file_name: params["file_name"] || "uploaded_sample",
          source: params["source"] || "manual",
          alert_id: params["alert_id"]
        }
        {:ok, file_bytes, metadata}

      :error ->
        {:error, :invalid_base64}
    end
  end

  defp extract_file_bytes(_conn, _params), do: {:error, :no_file}

  # Sanitize report for JSON serialization (remove raw_report if too large)
  defp sanitize_report(report) when is_map(report) do
    report
    |> Map.update(:sandbox_reports, [], fn reports ->
      Enum.map(reports, fn r ->
        Map.take(r, [:sandbox, :verdict, :score])
      end)
    end)
    |> Map.update(:behaviors, [], fn behaviors ->
      Enum.take(behaviors || [], 50)
    end)
    |> ensure_serializable()
  end

  # Convert atoms and structs to JSON-safe values
  defp ensure_serializable(data) when is_map(data) do
    data
    |> Map.drop([:raw_report, :__struct__])
    |> Enum.map(fn {k, v} -> {ensure_key(k), ensure_serializable(v)} end)
    |> Map.new()
  end

  defp ensure_serializable(data) when is_list(data) do
    Enum.map(data, &ensure_serializable/1)
  end

  defp ensure_serializable(data) when is_atom(data) and not is_boolean(data) and not is_nil(data) do
    Atom.to_string(data)
  end

  defp ensure_serializable(data), do: data

  defp ensure_key(k) when is_atom(k), do: Atom.to_string(k)
  defp ensure_key(k), do: k
end
