defmodule TamanduaServer.Samples do
  @moduledoc """
  Context for managing file samples submitted for ML analysis.

  Provides functions to:
  - Create and store samples
  - Query samples by hash or other attributes
  - Trigger ML analysis
  - Retrieve analysis results
  """

  import Ecto.Query
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Samples.{Sample, Storage}
  alias TamanduaServer.Detection.ML.Client, as: MLClient

  # -------------------------------------------------------------------
  # Sample Creation & Storage
  # -------------------------------------------------------------------

  @doc """
  Create a new sample or update an existing one if the SHA256 already exists.

  When a sample with the same SHA256 is submitted again, we update the
  submission_count and last_seen timestamp instead of creating a duplicate.

  ## Parameters
  - attrs: Map with sample attributes including:
    - sha256: (required) The SHA256 hash of the file
    - content: (optional) The binary content to store
    - file_name, file_size, file_type, etc.

  ## Returns
  - {:ok, sample} on success (either newly created or existing)
  - {:error, changeset} on validation failure
  """
  @spec create_sample(map()) :: {:ok, Sample.t()} | {:error, Ecto.Changeset.t()}
  def create_sample(attrs) do
    sha256 = normalize_sha256(attrs[:sha256] || attrs["sha256"])

    case get_sample_by_hash(sha256) do
      nil ->
        # New sample - create it
        do_create_sample(attrs, sha256)

      existing ->
        # Existing sample - update submission metadata
        update_submission(existing, attrs)
    end
  end

  defp do_create_sample(attrs, sha256) do
    now = DateTime.utc_now()
    content = attrs[:content] || attrs["content"]
    compressed = attrs[:compressed] || attrs["compressed"] || false

    # Store the binary content if provided
    stored_path =
      if content && byte_size(content) > 0 do
        case Storage.store(sha256, content, compressed: compressed) do
          {:ok, path} -> path
          {:error, reason} ->
            Logger.warning("Failed to store sample #{sha256}: #{inspect(reason)}")
            nil
        end
      else
        nil
      end

    sample_attrs =
      attrs
      |> Map.drop([:content, "content", :compressed, "compressed"])
      |> Map.put(:sha256, sha256)
      |> Map.put(:stored_path, stored_path)
      |> Map.put(:first_seen, now)
      |> Map.put(:last_seen, now)
      |> Map.put(:submission_count, 1)

    %Sample{}
    |> Sample.changeset(sample_attrs)
    |> Repo.insert()
  end

  defp update_submission(existing, attrs) do
    resubmit_attrs = %{
      last_seen: DateTime.utc_now(),
      source_agent_id: attrs[:source_agent_id] || attrs["source_agent_id"] || existing.source_agent_id,
      source_path: attrs[:source_path] || attrs["source_path"] || existing.source_path
    }

    existing
    |> Sample.resubmit_changeset(resubmit_attrs)
    |> Repo.update()
  end

  @doc """
  Get a sample by its SHA256 hash.
  """
  @spec get_sample_by_hash(String.t()) :: Sample.t() | nil
  def get_sample_by_hash(nil), do: nil

  def get_sample_by_hash(sha256) do
    sha256 = normalize_sha256(sha256)
    Repo.get_by(Sample, sha256: sha256)
  end

  @doc """
  Get a sample by ID.
  """
  @spec get_sample(binary()) :: Sample.t() | nil
  def get_sample(id), do: Repo.get(Sample, id)

  @doc """
  Get a sample by ID, raising if not found.
  """
  @spec get_sample!(binary()) :: Sample.t()
  def get_sample!(id), do: Repo.get!(Sample, id)

  @doc """
  List samples with optional filtering and pagination.

  ## Options
  - :limit - max results (default: 50)
  - :offset - pagination offset (default: 0)
  - :verdict - filter by ML verdict
  - :agent_id - filter by source agent
  - :file_type - filter by file type
  - :analyzed - filter by analysis status (true/false)
  - :order_by - order field (default: :inserted_at)
  - :order_dir - :asc or :desc (default: :desc)
  """
  @spec list_samples(keyword()) :: {[Sample.t()], integer()}
  def list_samples(opts \\ []) do
    limit = Keyword.get(opts, :limit, 50)
    offset = Keyword.get(opts, :offset, 0)
    order_by = Keyword.get(opts, :order_by, :inserted_at)
    order_dir = Keyword.get(opts, :order_dir, :desc)

    base_query = from(s in Sample)

    query =
      base_query
      |> filter_by_verdict(Keyword.get(opts, :verdict))
      |> filter_by_agent(Keyword.get(opts, :agent_id))
      |> filter_by_file_type(Keyword.get(opts, :file_type))
      |> filter_by_analyzed(Keyword.get(opts, :analyzed))
      |> order_by([s], [{^order_dir, field(s, ^order_by)}])

    total = Repo.aggregate(query, :count)

    samples =
      query
      |> limit(^limit)
      |> offset(^offset)
      |> Repo.all()

    {samples, total}
  end

  @doc """
  List samples pending ML analysis.
  """
  @spec list_pending_analysis(keyword()) :: [Sample.t()]
  def list_pending_analysis(opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)

    from(s in Sample,
      where: is_nil(s.ml_analyzed_at),
      where: not is_nil(s.stored_path),
      order_by: [asc: s.inserted_at],
      limit: ^limit
    )
    |> Repo.all()
  end

  # -------------------------------------------------------------------
  # ML Analysis
  # -------------------------------------------------------------------

  @doc """
  Trigger ML analysis for a sample.

  This is an asynchronous operation. The analysis is performed in the background
  and the sample is updated with results when complete.

  ## Returns
  - {:ok, :analyzing} - Analysis started
  - {:ok, :already_analyzed} - Sample was already analyzed
  - {:error, :no_content} - Sample has no stored content
  - {:error, reason} - Other error
  """
  @spec analyze_sample(Sample.t()) :: {:ok, atom()} | {:error, term()}
  def analyze_sample(%Sample{ml_analyzed_at: ml_at} = sample) when not is_nil(ml_at) do
    Logger.debug("Sample #{sample.sha256} already analyzed at #{ml_at}")
    {:ok, :already_analyzed}
  end

  def analyze_sample(%Sample{stored_path: nil} = sample) do
    Logger.warning("Cannot analyze sample #{sample.sha256}: no stored content")
    {:error, :no_content}
  end

  def analyze_sample(%Sample{} = sample) do
    # Start async analysis
    Task.start(fn -> do_analyze_sample(sample) end)
    {:ok, :analyzing}
  end

  @doc """
  Trigger ML analysis and wait for the result (synchronous).
  """
  @spec analyze_sample_sync(Sample.t()) :: {:ok, Sample.t()} | {:error, term()}
  def analyze_sample_sync(%Sample{ml_analyzed_at: ml_at} = sample) when not is_nil(ml_at) do
    {:ok, sample}
  end

  def analyze_sample_sync(%Sample{stored_path: nil}) do
    {:error, :no_content}
  end

  def analyze_sample_sync(%Sample{} = sample) do
    do_analyze_sample(sample)
  end

  defp do_analyze_sample(%Sample{} = sample) do
    Logger.info("Starting ML analysis for sample #{sample.sha256}")

    with {:ok, content} <- Storage.read(sample.stored_path),
         {:ok, prediction} <- call_ml_service(sample, content) do
      # Update the sample with ML results
      update_sample_result(sample, prediction)
    else
      {:error, reason} = error ->
        Logger.error("ML analysis failed for #{sample.sha256}: #{inspect(reason)}")
        # Mark as analyzed with unknown verdict to avoid retrying
        update_sample_result(sample, %{
          ml_verdict: "unknown",
          ml_score: 0.0,
          ml_confidence: 0.0,
          ml_family: nil
        })
        error
    end
  end

  defp call_ml_service(%Sample{} = sample, content) do
    ml_sample = %{
      sha256: decode_sha256(sample.sha256),
      content: content,
      file_type: sample.file_type || "unknown",
      entropy: sample.entropy || 0.0,
      metadata: %{
        file_name: sample.file_name,
        file_size: sample.file_size,
        source_agent_id: sample.source_agent_id
      }
    }

    case MLClient.predict(ml_sample) do
      {:ok, result} ->
        {:ok, %{
          ml_verdict: normalize_verdict(result.prediction),
          ml_score: result.confidence || 0.0,
          ml_confidence: result.confidence || 0.0,
          ml_family: result.malware_family
        }}

      {:error, _} = error ->
        error
    end
  end

  defp normalize_verdict("malicious"), do: "malicious"
  defp normalize_verdict("suspicious"), do: "suspicious"
  defp normalize_verdict("benign"), do: "clean"
  defp normalize_verdict("clean"), do: "clean"
  defp normalize_verdict(_), do: "unknown"

  @doc """
  Get the analysis result for a sample by SHA256.
  """
  @spec get_analysis_result(String.t()) :: {:ok, map()} | {:error, :not_found | :not_analyzed}
  def get_analysis_result(sha256) do
    case get_sample_by_hash(sha256) do
      nil ->
        {:error, :not_found}

      %Sample{ml_analyzed_at: nil} ->
        {:error, :not_analyzed}

      sample ->
        {:ok, %{
          sha256: sample.sha256,
          verdict: sample.ml_verdict,
          score: sample.ml_score,
          confidence: sample.ml_confidence,
          family: sample.ml_family,
          analyzed_at: sample.ml_analyzed_at,
          file_name: sample.file_name,
          file_type: sample.file_type,
          file_size: sample.file_size
        }}
    end
  end

  @doc """
  Update a sample with ML analysis results.
  """
  @spec update_sample_result(Sample.t(), map()) :: {:ok, Sample.t()} | {:error, Ecto.Changeset.t()}
  def update_sample_result(%Sample{} = sample, result) do
    result_with_timestamp = Map.put(result, :ml_analyzed_at, DateTime.utc_now())

    sample
    |> Sample.ml_result_changeset(result_with_timestamp)
    |> Repo.update()
    |> tap(fn
      {:ok, updated} ->
        Logger.info("Updated ML result for #{sample.sha256}: #{updated.ml_verdict}")
        # Trigger alert if malicious
        maybe_create_alert(updated)
        # Broadcast result to the source agent
        broadcast_result_to_agent(updated)

      {:error, changeset} ->
        Logger.error("Failed to update ML result for #{sample.sha256}: #{inspect(changeset.errors)}")
    end)
  end

  defp broadcast_result_to_agent(%Sample{source_agent_id: nil}), do: :ok

  defp broadcast_result_to_agent(%Sample{source_agent_id: agent_id} = sample) do
    # Broadcast the result to the agent via Phoenix.PubSub
    result = %{
      sha256: sample.sha256,
      verdict: sample.ml_verdict,
      score: sample.ml_score,
      confidence: sample.ml_confidence,
      family: sample.ml_family,
      analyzed_at: sample.ml_analyzed_at
    }

    # Send to the agent's channel process
    TamanduaServerWeb.Endpoint.broadcast("agent:#{agent_id}", "sample_result", result)
  rescue
    e ->
      Logger.warning("Failed to broadcast sample result to agent #{agent_id}: #{inspect(e)}")
      :ok
  end

  defp maybe_create_alert(%Sample{ml_verdict: "malicious"} = sample) do
    # Create an alert for malicious samples
    Task.start(fn ->
      TamanduaServer.Alerts.create_alert(%{
        title: "Malware detected: #{sample.ml_family || "Unknown family"}",
        description: "ML analysis detected malicious file: #{sample.file_name || sample.sha256}",
        severity: severity_from_confidence(sample.ml_confidence),
        source: "ml",
        agent_id: sample.source_agent_id,
        threat_score: sample.ml_score || 0.0,
        enrichment: %{
          "sha256" => sample.sha256,
          "file_path" => sample.source_path,
          "ml_confidence" => sample.ml_confidence,
          "malware_family" => sample.ml_family
        }
      })
    end)
  end

  defp maybe_create_alert(_sample), do: :ok

  defp severity_from_confidence(conf) when is_nil(conf), do: "medium"
  defp severity_from_confidence(conf) when conf >= 0.9, do: "critical"
  defp severity_from_confidence(conf) when conf >= 0.7, do: "high"
  defp severity_from_confidence(conf) when conf >= 0.5, do: "medium"
  defp severity_from_confidence(_), do: "low"

  # -------------------------------------------------------------------
  # Batch Operations
  # -------------------------------------------------------------------

  @doc """
  Analyze multiple samples in batch.
  """
  @spec analyze_batch([Sample.t()]) :: {:ok, [map()]}
  def analyze_batch(samples) do
    results = Enum.map(samples, fn sample ->
      case analyze_sample_sync(sample) do
        {:ok, updated} ->
          %{sha256: updated.sha256, status: :analyzed, verdict: updated.ml_verdict}

        {:error, reason} ->
          %{sha256: sample.sha256, status: :error, error: reason}
      end
    end)

    {:ok, results}
  end

  @doc """
  Process pending samples in a batch (for background job).
  """
  @spec process_pending_batch(integer()) :: {:ok, integer()}
  def process_pending_batch(batch_size \\ 10) do
    samples = list_pending_analysis(limit: batch_size)

    if length(samples) > 0 do
      Logger.info("Processing #{length(samples)} pending samples for ML analysis")
      analyze_batch(samples)
    end

    {:ok, length(samples)}
  end

  # -------------------------------------------------------------------
  # Statistics
  # -------------------------------------------------------------------

  @doc """
  Get sample statistics.
  """
  @spec stats() :: map()
  def stats do
    total = Repo.aggregate(Sample, :count)

    by_verdict =
      from(s in Sample,
        group_by: s.ml_verdict,
        select: {s.ml_verdict, count(s.id)}
      )
      |> Repo.all()
      |> Enum.into(%{})

    pending =
      from(s in Sample,
        where: is_nil(s.ml_analyzed_at),
        where: not is_nil(s.stored_path)
      )
      |> Repo.aggregate(:count)

    storage_stats = Storage.stats()

    %{
      total_samples: total,
      pending_analysis: pending,
      by_verdict: by_verdict,
      storage: storage_stats
    }
  end

  # -------------------------------------------------------------------
  # Private Helpers
  # -------------------------------------------------------------------

  defp normalize_sha256(nil), do: nil
  defp normalize_sha256(sha256) when is_binary(sha256) do
    sha256 |> String.downcase() |> String.trim()
  end

  defp decode_sha256(hex) when is_binary(hex) do
    case Base.decode16(hex, case: :mixed) do
      {:ok, bytes} -> bytes
      :error -> <<>>
    end
  end

  defp filter_by_verdict(query, nil), do: query
  defp filter_by_verdict(query, verdict) do
    where(query, [s], s.ml_verdict == ^verdict)
  end

  defp filter_by_agent(query, nil), do: query
  defp filter_by_agent(query, agent_id) do
    where(query, [s], s.source_agent_id == ^agent_id)
  end

  defp filter_by_file_type(query, nil), do: query
  defp filter_by_file_type(query, file_type) do
    where(query, [s], s.file_type == ^file_type)
  end

  defp filter_by_analyzed(query, nil), do: query
  defp filter_by_analyzed(query, true) do
    where(query, [s], not is_nil(s.ml_analyzed_at))
  end
  defp filter_by_analyzed(query, false) do
    where(query, [s], is_nil(s.ml_analyzed_at))
  end
end
