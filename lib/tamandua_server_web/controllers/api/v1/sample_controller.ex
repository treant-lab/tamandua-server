defmodule TamanduaServerWeb.API.V1.SampleController do
  @moduledoc """
  API controller for file sample analysis.

  Provides endpoints for:
  - Submitting samples for ML analysis
  - Retrieving analysis results
  - Batch sample processing
  - Sample statistics
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Samples
  alias TamanduaServer.Samples.Sample

  action_fallback TamanduaServerWeb.FallbackController

  # -------------------------------------------------------------------
  # Submit & Analyze
  # -------------------------------------------------------------------

  @doc """
  Submit a sample for ML analysis.

  POST /api/v1/samples/analyze

  ## Request Body
  - sha256: (required) SHA256 hash of the file
  - content: (optional) Base64-encoded file content (raw or gzip compressed)
  - compressed: (optional) true if content is gzip compressed
  - sha1: (optional) SHA1 hash
  - md5: (optional) MD5 hash
  - file_name: (optional) Original file name
  - file_size: (optional) File size in bytes
  - file_type: (optional) File type (pe, elf, script, etc.)
  - entropy: (optional) Pre-calculated entropy
  - source_agent_id: (optional) ID of submitting agent
  - source_path: (optional) Original file path on the agent

  ## Response
  - 200: Analysis result (if sample was already analyzed or sync mode)
  - 202: Analysis queued (async mode)
  - 400: Invalid request
  """
  def analyze(conn, %{"sha256" => sha256} = params) do
    # Decode base64 content if provided
    content = decode_content(params["content"])
    compressed = params["compressed"] == true || params["compressed"] == "true"

    sample_attrs = %{
      sha256: sha256,
      sha1: params["sha1"],
      md5: params["md5"],
      file_name: params["file_name"],
      file_size: params["file_size"],
      file_type: params["file_type"] || detect_file_type(content),
      entropy: parse_float(params["entropy"]),
      source_agent_id: params["source_agent_id"],
      source_path: params["source_path"],
      is_signed: params["is_signed"],
      signer: params["signer"],
      content: content,
      compressed: compressed
    }

    with {:ok, sample} <- Samples.create_sample(sample_attrs) do
      # Check if already analyzed
      if Sample.analyzed?(sample) do
        render_analysis_result(conn, sample, :ok)
      else
        # Trigger analysis
        sync = params["sync"] == true || params["sync"] == "true"

        if sync do
          # Synchronous analysis
          case Samples.analyze_sample_sync(sample) do
            {:ok, updated} ->
              render_analysis_result(conn, updated, :ok)

            {:error, reason} ->
              conn
              |> put_status(:service_unavailable)
              |> json(%{error: "analysis_failed", message: inspect(reason)})
          end
        else
          # Async analysis
          Samples.analyze_sample(sample)

          conn
          |> put_status(:accepted)
          |> json(%{
            data: %{
              sha256: sample.sha256,
              status: "analyzing",
              message: "Sample queued for analysis",
              poll_url: "/api/v1/samples/#{sample.sha256}/result"
            }
          })
        end
      end
    end
  end

  def analyze(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "missing_sha256", message: "sha256 parameter is required"})
  end

  # -------------------------------------------------------------------
  # Get Sample Info
  # -------------------------------------------------------------------

  @doc """
  Get sample information by SHA256.

  GET /api/v1/samples/:sha256
  """
  def show(conn, %{"sha256" => sha256}) do
    case Samples.get_sample_by_hash(sha256) do
      nil ->
        {:error, :not_found}

      sample ->
        json(conn, %{data: serialize_sample(sample)})
    end
  end

  # -------------------------------------------------------------------
  # Get Analysis Result
  # -------------------------------------------------------------------

  @doc """
  Get ML analysis result for a sample.

  GET /api/v1/samples/:sha256/result
  """
  def result(conn, %{"sha256" => sha256}) do
    case Samples.get_analysis_result(sha256) do
      {:ok, result} ->
        json(conn, %{
          data: %{
            sha256: result.sha256,
            verdict: result.verdict,
            score: result.score,
            confidence: result.confidence,
            family: result.family,
            analyzed_at: result.analyzed_at,
            file_name: result.file_name,
            file_type: result.file_type,
            file_size: result.file_size,
            threat_assessment: assess_threat(result)
          }
        })

      {:error, :not_found} ->
        {:error, :not_found}

      {:error, :not_analyzed} ->
        conn
        |> put_status(:accepted)
        |> json(%{
          data: %{
            sha256: sha256,
            status: "pending",
            message: "Analysis not yet complete"
          }
        })
    end
  end

  # -------------------------------------------------------------------
  # Batch Analysis
  # -------------------------------------------------------------------

  @doc """
  Submit multiple samples for analysis.

  POST /api/v1/samples/batch

  ## Request Body
  - samples: Array of sample objects, each with sha256 and optional content
  """
  def batch_analyze(conn, %{"samples" => samples}) when is_list(samples) do
    results = Enum.map(samples, fn sample_params ->
      sha256 = sample_params["sha256"]
      content = decode_content(sample_params["content"])

      sample_attrs = %{
        sha256: sha256,
        sha1: sample_params["sha1"],
        md5: sample_params["md5"],
        file_name: sample_params["file_name"],
        file_size: sample_params["file_size"],
        file_type: sample_params["file_type"],
        entropy: parse_float(sample_params["entropy"]),
        source_agent_id: sample_params["source_agent_id"],
        source_path: sample_params["source_path"],
        content: content,
        compressed: sample_params["compressed"] == true
      }

      case Samples.create_sample(sample_attrs) do
        {:ok, sample} ->
          # Queue async analysis
          Samples.analyze_sample(sample)
          %{sha256: sha256, status: "queued", id: sample.id}

        {:error, changeset} ->
          %{sha256: sha256, status: "error", errors: format_errors(changeset)}
      end
    end)

    json(conn, %{
      data: %{
        results: results,
        total: length(results),
        queued: Enum.count(results, &(&1.status == "queued"))
      }
    })
  end

  def batch_analyze(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "invalid_request", message: "samples array required"})
  end

  # -------------------------------------------------------------------
  # List & Stats
  # -------------------------------------------------------------------

  @doc """
  List samples with filtering.

  GET /api/v1/samples
  """
  def index(conn, params) do
    opts = [
      limit: parse_int(params["limit"], 50),
      offset: parse_int(params["offset"], 0),
      verdict: params["verdict"],
      agent_id: params["agent_id"],
      file_type: params["file_type"],
      analyzed: parse_bool(params["analyzed"])
    ]

    {samples, total} = Samples.list_samples(opts)

    json(conn, %{
      data: Enum.map(samples, &serialize_sample/1),
      meta: %{
        total: total,
        limit: opts[:limit],
        offset: opts[:offset]
      }
    })
  end

  @doc """
  Get sample statistics.

  GET /api/v1/samples/stats
  """
  def stats(conn, _params) do
    stats = Samples.stats()

    json(conn, %{
      data: %{
        total_samples: stats.total_samples,
        pending_analysis: stats.pending_analysis,
        by_verdict: stats.by_verdict,
        storage: stats.storage
      }
    })
  end

  # -------------------------------------------------------------------
  # Private Helpers
  # -------------------------------------------------------------------

  defp decode_content(nil), do: nil
  defp decode_content(""), do: nil
  defp decode_content(content) when is_binary(content) do
    case Base.decode64(content) do
      {:ok, decoded} -> decoded
      :error -> nil
    end
  end

  defp detect_file_type(nil), do: "unknown"
  defp detect_file_type(content) when byte_size(content) < 4, do: "unknown"
  defp detect_file_type(<<0x4D, 0x5A, _::binary>>), do: "pe"  # MZ header (Windows PE)
  defp detect_file_type(<<0x7F, 0x45, 0x4C, 0x46, _::binary>>), do: "elf"  # ELF header
  defp detect_file_type(<<0xCA, 0xFE, 0xBA, 0xBE, _::binary>>), do: "macho"  # Mach-O fat
  defp detect_file_type(<<0xCF, 0xFA, 0xED, 0xFE, _::binary>>), do: "macho"  # Mach-O 64
  defp detect_file_type(<<0xFE, 0xED, 0xFA, 0xCF, _::binary>>), do: "macho"  # Mach-O 64 (BE)
  defp detect_file_type(<<0x50, 0x4B, 0x03, 0x04, _::binary>>), do: "zip"  # ZIP/JAR/APK
  defp detect_file_type(<<0x25, 0x50, 0x44, 0x46, _::binary>>), do: "pdf"  # PDF
  defp detect_file_type(<<0xD0, 0xCF, 0x11, 0xE0, _::binary>>), do: "ole"  # OLE (Office)
  defp detect_file_type(content) do
    # Check for script content
    cond do
      String.starts_with?(content, "#!/") -> "script"
      String.starts_with?(content, "<?") -> "script"
      String.contains?(content, "function ") -> "script"
      String.contains?(content, "import ") -> "script"
      true -> "unknown"
    end
  rescue
    _ -> "unknown"
  end

  defp render_analysis_result(conn, %Sample{} = sample, status) do
    conn
    |> put_status(status)
    |> json(%{
      data: %{
        sha256: sample.sha256,
        verdict: sample.ml_verdict,
        score: sample.ml_score,
        confidence: sample.ml_confidence,
        family: sample.ml_family,
        analyzed_at: sample.ml_analyzed_at,
        file_name: sample.file_name,
        file_type: sample.file_type,
        file_size: sample.file_size,
        threat_assessment: assess_threat_sample(sample)
      }
    })
  end

  defp assess_threat(%{verdict: verdict, confidence: conf}) do
    case verdict do
      "malicious" ->
        cond do
          conf >= 0.95 -> %{level: "critical", action: "quarantine_immediately"}
          conf >= 0.85 -> %{level: "high", action: "quarantine_recommended"}
          conf >= 0.70 -> %{level: "medium", action: "investigate"}
          true -> %{level: "low", action: "monitor"}
        end

      "suspicious" ->
        %{level: "medium", action: "investigate"}

      "clean" ->
        %{level: "safe", action: "allow"}

      _ ->
        %{level: "unknown", action: "investigate"}
    end
  end

  defp assess_threat_sample(%Sample{ml_verdict: verdict, ml_confidence: conf}) do
    assess_threat(%{verdict: verdict, confidence: conf || 0.0})
  end

  defp serialize_sample(%Sample{} = sample) do
    %{
      id: sample.id,
      sha256: sample.sha256,
      sha1: sample.sha1,
      md5: sample.md5,
      file_name: sample.file_name,
      file_size: sample.file_size,
      file_type: sample.file_type,
      source_agent_id: sample.source_agent_id,
      source_path: sample.source_path,
      ml_verdict: sample.ml_verdict,
      ml_score: sample.ml_score,
      ml_confidence: sample.ml_confidence,
      ml_family: sample.ml_family,
      ml_analyzed_at: sample.ml_analyzed_at,
      is_signed: sample.is_signed,
      signer: sample.signer,
      entropy: sample.entropy,
      first_seen: sample.first_seen,
      last_seen: sample.last_seen,
      submission_count: sample.submission_count,
      analyzed: Sample.analyzed?(sample),
      threat_level: Sample.threat_level(sample),
      inserted_at: sample.inserted_at,
      updated_at: sample.updated_at
    }
  end

  defp format_errors(%Ecto.Changeset{} = changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end

  defp parse_int(nil, default), do: default
  defp parse_int(val, default) when is_binary(val) do
    case Integer.parse(val) do
      {int, _} -> int
      :error -> default
    end
  end
  defp parse_int(val, _) when is_integer(val), do: val
  defp parse_int(_, default), do: default

  defp parse_float(nil), do: nil
  defp parse_float(val) when is_float(val), do: val
  defp parse_float(val) when is_integer(val), do: val / 1.0
  defp parse_float(val) when is_binary(val) do
    case Float.parse(val) do
      {f, _} -> f
      :error -> nil
    end
  end
  defp parse_float(_), do: nil

  defp parse_bool(nil), do: nil
  defp parse_bool(true), do: true
  defp parse_bool(false), do: false
  defp parse_bool("true"), do: true
  defp parse_bool("false"), do: false
  defp parse_bool("1"), do: true
  defp parse_bool("0"), do: false
  defp parse_bool(_), do: nil
end
