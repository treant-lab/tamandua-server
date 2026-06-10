defmodule TamanduaServer.AISecurity.BackdoorAnalysis do
  @moduledoc """
  Context for managing AI model backdoor analysis records.

  Provides functions to record, query, and analyze the history of backdoor
  analysis performed on AI/ML model files. Analysis is performed via the
  Python ML service using weight distribution and spectral (SVD) analysis.

  ## Analysis Flow

  1. User triggers deep analysis from AI Models dashboard
  2. MLClient calls Python service `/ai-security/analyze-backdoor`
  3. Results are recorded via `record_analysis/1`
  4. Dashboard updates via PubSub broadcast

  ## Score Interpretation

  - `backdoor_score < 0.3` - Low risk (green)
  - `backdoor_score 0.3-0.6` - Medium risk (yellow)
  - `backdoor_score 0.6-0.8` - High risk (orange)
  - `backdoor_score > 0.8` - Critical (red)
  """

  import Ecto.Query
  alias TamanduaServer.Repo
  alias TamanduaServer.AISecurity.BackdoorAnalysis.AnalysisRecord

  @doc """
  Record a new backdoor analysis result.

  ## Examples

      iex> record_analysis(%{model_id: "ai_abc123", backdoor_score: 0.25})
      {:ok, %AnalysisRecord{}}

      iex> record_analysis(%{model_id: nil})
      {:error, %Ecto.Changeset{}}
  """
  @spec record_analysis(map()) :: {:ok, AnalysisRecord.t()} | {:error, Ecto.Changeset.t()}
  def record_analysis(attrs) do
    %AnalysisRecord{}
    |> AnalysisRecord.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Get the most recent backdoor analysis for a model.

  Returns `nil` if no analysis exists for the model.

  ## Examples

      iex> get_latest_analysis("ai_abc123")
      %AnalysisRecord{backdoor_score: 0.25}

      iex> get_latest_analysis("unknown_model")
      nil
  """
  @spec get_latest_analysis(String.t()) :: AnalysisRecord.t() | nil
  def get_latest_analysis(model_id) do
    AnalysisRecord
    |> where([r], r.model_id == ^model_id)
    |> order_by([r], desc: r.inserted_at)
    |> limit(1)
    |> Repo.one()
  end

  @doc """
  Get a backdoor analysis by file hash.

  Useful for cache lookup - if we've already analyzed a file with this hash,
  we can return the cached result instead of re-analyzing.

  ## Examples

      iex> get_analysis_by_hash("sha256:abc123...")
      %AnalysisRecord{backdoor_score: 0.25}
  """
  @spec get_analysis_by_hash(String.t()) :: AnalysisRecord.t() | nil
  def get_analysis_by_hash(file_hash) do
    AnalysisRecord
    |> where([r], r.file_hash == ^file_hash)
    |> order_by([r], desc: r.inserted_at)
    |> limit(1)
    |> Repo.one()
  end

  @doc """
  List backdoor analysis history for a model, ordered by inserted_at descending.

  ## Options
    * `:limit` - Maximum number of records to return (default: 10)
    * `:offset` - Number of records to skip (default: 0)

  ## Examples

      iex> list_analyses("ai_abc123")
      [%AnalysisRecord{}, ...]

      iex> list_analyses("ai_abc123", limit: 5)
      [%AnalysisRecord{}, ...]
  """
  @spec list_analyses(String.t(), keyword()) :: [AnalysisRecord.t()]
  def list_analyses(model_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 10)
    offset = Keyword.get(opts, :offset, 0)

    AnalysisRecord
    |> where([r], r.model_id == ^model_id)
    |> order_by([r], desc: r.inserted_at)
    |> limit(^limit)
    |> offset(^offset)
    |> Repo.all()
  end

  @doc """
  Get aggregate statistics for backdoor analyses on a model.

  Returns a map with:
    * `:total_analyses` - Total number of analyses performed
    * `:avg_backdoor_score` - Average backdoor score
    * `:max_backdoor_score` - Highest backdoor score seen
    * `:suspicious_count` - Number of analyses flagged as suspicious
    * `:last_analyzed` - Timestamp of most recent analysis

  ## Examples

      iex> analysis_stats("ai_abc123")
      %{total_analyses: 5, avg_backdoor_score: 0.3, max_backdoor_score: 0.45, ...}
  """
  @spec analysis_stats(String.t()) :: map()
  def analysis_stats(model_id) do
    query = from r in AnalysisRecord,
      where: r.model_id == ^model_id,
      select: %{
        total_analyses: count(r.id),
        avg_backdoor_score: avg(r.backdoor_score),
        max_backdoor_score: max(r.backdoor_score),
        suspicious_count: count(fragment("CASE WHEN ? = true THEN 1 END", r.is_suspicious)),
        last_analyzed: max(r.inserted_at)
      }

    Repo.one(query) || %{
      total_analyses: 0,
      avg_backdoor_score: nil,
      max_backdoor_score: nil,
      suspicious_count: 0,
      last_analyzed: nil
    }
  end

  @doc """
  List recent backdoor analyses across all models.

  Useful for activity feeds and audit views.

  ## Options
    * `:limit` - Maximum number of records (default: 20)
    * `:suspicious_only` - Only return analyses flagged as suspicious
    * `:agent_id` - Filter by agent
  """
  @spec list_recent(keyword()) :: [AnalysisRecord.t()]
  def list_recent(opts \\ []) do
    limit = Keyword.get(opts, :limit, 20)
    suspicious_only = Keyword.get(opts, :suspicious_only, false)
    agent_id = Keyword.get(opts, :agent_id)

    AnalysisRecord
    |> maybe_filter_suspicious(suspicious_only)
    |> maybe_filter_agent(agent_id)
    |> order_by([r], desc: r.inserted_at)
    |> limit(^limit)
    |> Repo.all()
  end

  @doc """
  Get global statistics for all backdoor analyses.

  Returns aggregate metrics for dashboards.
  """
  @spec global_stats() :: map()
  def global_stats do
    query = from r in AnalysisRecord,
      select: %{
        total_analyses: count(r.id),
        unique_models: count(r.model_id, :distinct),
        suspicious_count: count(fragment("CASE WHEN ? = true THEN 1 END", r.is_suspicious)),
        avg_backdoor_score: avg(r.backdoor_score),
        avg_analysis_time_ms: avg(r.analysis_time_ms)
      }

    Repo.one(query) || %{
      total_analyses: 0,
      unique_models: 0,
      suspicious_count: 0,
      avg_backdoor_score: nil,
      avg_analysis_time_ms: nil
    }
  end

  @doc """
  Delete old analysis records for data retention.

  ## Options
    * `:older_than_days` - Delete records older than this many days (default: 90)
  """
  @spec cleanup_old_records(keyword()) :: {non_neg_integer(), nil | [term()]}
  def cleanup_old_records(opts \\ []) do
    days = Keyword.get(opts, :older_than_days, 90)
    cutoff = NaiveDateTime.add(NaiveDateTime.utc_now(), -days * 24 * 60 * 60, :second)

    AnalysisRecord
    |> where([r], r.inserted_at < ^cutoff)
    |> Repo.delete_all()
  end

  @doc """
  Format an analysis record for chart rendering.

  Transforms the raw analysis data into structures optimized for
  rendering weight distribution and spectral charts in the dashboard.

  ## Returns

  A map with:
    * `:scores` - Weight, spectral, and combined scores
    * `:weight_chart` - List of layers formatted for horizontal bar chart
    * `:spectral_chart` - List of layers formatted for SVD spectrum chart
    * `:outlier_layers` - Combined list of all outlier layer names

  ## Example

      iex> format_for_charts(analysis_record)
      %{
        scores: %{weight: 0.25, spectral: 0.30, combined: 0.28},
        weight_chart: [%{name: "layer1.weight", score: 0.15, is_outlier: false}],
        spectral_chart: [%{name: "classifier", singular_values: [...], ...}],
        outlier_layers: ["layer5.weight"]
      }
  """
  @spec format_for_charts(AnalysisRecord.t() | nil) :: map() | nil
  def format_for_charts(nil), do: nil

  def format_for_charts(%AnalysisRecord{} = record) do
    %{
      scores: %{
        weight: record.weight_score,
        spectral: record.spectral_score,
        combined: record.backdoor_score
      },
      weight_chart: format_weight_chart(record.weight_details),
      spectral_chart: format_spectral_chart(record.spectral_details),
      outlier_layers:
        ((record.weight_outlier_layers || []) ++ (record.spectral_outlier_layers || []))
        |> Enum.uniq()
    }
  end

  # Format weight details for horizontal bar chart display
  defp format_weight_chart(nil), do: []
  defp format_weight_chart(%{}), do: []

  defp format_weight_chart(%{"layers" => layers}) when is_list(layers) do
    layers
    |> Enum.take(10)  # Limit to top 10 layers for display
    |> Enum.map(fn layer ->
      %{
        name: truncate_layer_name(layer["name"] || "unknown", 20),
        full_name: layer["name"] || "unknown",
        score: layer["anomaly_score"] || 0.0,
        is_outlier: layer["is_outlier"] || false,
        mean: layer["mean"],
        std: layer["std"],
        z_score: layer["z_score"]
      }
    end)
    |> Enum.sort_by(& &1.score, :desc)
  end

  defp format_weight_chart(%{layers: layers}) when is_list(layers) do
    layers
    |> Enum.take(10)
    |> Enum.map(fn layer ->
      %{
        name: truncate_layer_name(layer[:name] || layer["name"] || "unknown", 20),
        full_name: layer[:name] || layer["name"] || "unknown",
        score: layer[:anomaly_score] || layer["anomaly_score"] || 0.0,
        is_outlier: layer[:is_outlier] || layer["is_outlier"] || false,
        mean: layer[:mean] || layer["mean"],
        std: layer[:std] || layer["std"],
        z_score: layer[:z_score] || layer["z_score"]
      }
    end)
    |> Enum.sort_by(& &1.score, :desc)
  end

  defp format_weight_chart(_), do: []

  # Format spectral details for singular value spectrum chart
  defp format_spectral_chart(nil), do: []
  defp format_spectral_chart(%{}), do: []

  defp format_spectral_chart(%{"layers" => layers}) when is_list(layers) do
    layers
    |> Enum.take(5)  # Limit to top 5 layers for SVD display
    |> Enum.map(fn layer ->
      svs = layer["singular_values"] || []
      outliers = layer["sv_outliers"] || []

      %{
        name: truncate_layer_name(layer["name"] || "unknown", 20),
        full_name: layer["name"] || "unknown",
        singular_values: Enum.take(svs, 10),  # Top 10 SVs
        sv_outlier_indices: outliers,
        score: layer["anomaly_score"] || 0.0,
        top_sv_ratio: layer["top_sv_ratio"],
        spectral_gap: layer["spectral_gap"]
      }
    end)
  end

  defp format_spectral_chart(%{layers: layers}) when is_list(layers) do
    layers
    |> Enum.take(5)
    |> Enum.map(fn layer ->
      svs = layer[:singular_values] || layer["singular_values"] || []
      outliers = layer[:sv_outliers] || layer["sv_outliers"] || []

      %{
        name: truncate_layer_name(layer[:name] || layer["name"] || "unknown", 20),
        full_name: layer[:name] || layer["name"] || "unknown",
        singular_values: Enum.take(svs, 10),
        sv_outlier_indices: outliers,
        score: layer[:anomaly_score] || layer["anomaly_score"] || 0.0,
        top_sv_ratio: layer[:top_sv_ratio] || layer["top_sv_ratio"],
        spectral_gap: layer[:spectral_gap] || layer["spectral_gap"]
      }
    end)
  end

  defp format_spectral_chart(_), do: []

  # Truncate layer names for chart display
  defp truncate_layer_name(name, max_len) when is_binary(name) and byte_size(name) > max_len do
    String.slice(name, 0, max_len - 3) <> "..."
  end

  defp truncate_layer_name(name, _max_len) when is_binary(name), do: name
  defp truncate_layer_name(_, _), do: "unknown"

  # Private helpers

  defp maybe_filter_suspicious(query, false), do: query
  defp maybe_filter_suspicious(query, true) do
    where(query, [r], r.is_suspicious == true)
  end

  defp maybe_filter_agent(query, nil), do: query
  defp maybe_filter_agent(query, agent_id) do
    where(query, [r], r.agent_id == ^agent_id)
  end
end
