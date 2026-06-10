defmodule TamanduaServer.Alerts.SimilarityDetector do
  @moduledoc """
  Client for the ML-based alert similarity detection service.

  Provides:
  - Alert embedding generation
  - Similarity calculation
  - Automatic clustering
  - Duplicate detection
  - Similar alert retrieval
  """

  require Logger
  alias TamanduaServer.Alerts.Alert

  @ml_service_url Application.compile_env(:tamandua_server, :ml_service_url, "http://localhost:8000")
  @similarity_threshold 0.8
  @request_timeout 30_000

  # ==================== Public API ====================

  @doc """
  Generate embeddings for a list of alerts.

  ## Examples

      iex> alerts = [%Alert{title: "Malware detected", ...}, ...]
      iex> SimilarityDetector.embed_alerts(alerts)
      {:ok, %{embeddings: [[0.1, 0.2, ...]], alert_ids: ["uuid-1", ...]}}
  """
  def embed_alerts(alerts) when is_list(alerts) do
    url = "#{@ml_service_url}/api/v1/similarity/embed"

    # Convert alerts to API format
    alert_inputs = Enum.map(alerts, &alert_to_input/1)

    body = Jason.encode!(%{alerts: alert_inputs})

    case HTTPoison.post(url, body, headers(), recv_timeout: @request_timeout) do
      {:ok, %{status_code: 200, body: response_body}} ->
        case Jason.decode(response_body) do
          {:ok, data} ->
            {:ok, %{
              embeddings: data["embeddings"],
              alert_ids: data["alert_ids"],
              num_alerts: data["num_alerts"]
            }}

          {:error, reason} ->
            Logger.error("Failed to decode embed response: #{inspect(reason)}")
            {:error, :decode_error}
        end

      {:ok, %{status_code: status_code, body: body}} ->
        Logger.error("ML service returned error: #{status_code} - #{body}")
        {:error, {:http_error, status_code}}

      {:error, reason} ->
        Logger.error("HTTP request failed: #{inspect(reason)}")
        {:error, :http_request_failed}
    end
  end

  @doc """
  Compute pairwise similarity matrix for alert embeddings.

  ## Examples

      iex> embeddings = [[0.1, 0.2, ...], ...]
      iex> SimilarityDetector.compute_similarity(embeddings)
      {:ok, %{similarity_matrix: [[1.0, 0.8, ...], ...], statistics: %{...}}}
  """
  def compute_similarity(embeddings, metric \\ "cosine") do
    url = "#{@ml_service_url}/api/v1/similarity/compute"

    body = Jason.encode!(%{embeddings: embeddings, metric: metric})

    case HTTPoison.post(url, body, headers(), recv_timeout: @request_timeout) do
      {:ok, %{status_code: 200, body: response_body}} ->
        case Jason.decode(response_body) do
          {:ok, data} ->
            {:ok, %{
              similarity_matrix: data["similarity_matrix"],
              statistics: data["statistics"]
            }}

          {:error, reason} ->
            Logger.error("Failed to decode similarity response: #{inspect(reason)}")
            {:error, :decode_error}
        end

      {:ok, %{status_code: status_code, body: body}} ->
        Logger.error("ML service returned error: #{status_code} - #{body}")
        {:error, {:http_error, status_code}}

      {:error, reason} ->
        Logger.error("HTTP request failed: #{inspect(reason)}")
        {:error, :http_request_failed}
    end
  end

  @doc """
  Cluster similar alerts using HDBSCAN.

  ## Examples

      iex> embeddings = [[0.1, 0.2, ...], ...]
      iex> alert_ids = ["uuid-1", "uuid-2", ...]
      iex> SimilarityDetector.cluster_alerts(embeddings, alert_ids)
      {:ok, %{cluster_labels: [0, 0, 1, -1, ...], cluster_leaders: %{0 => 0, 1 => 2}, ...}}
  """
  def cluster_alerts(embeddings, alert_ids, opts \\ []) do
    url = "#{@ml_service_url}/api/v1/similarity/cluster"

    alert_timestamps = Keyword.get(opts, :alert_timestamps)
    min_cluster_size = Keyword.get(opts, :min_cluster_size, 2)

    body = Jason.encode!(%{
      embeddings: embeddings,
      alert_ids: alert_ids,
      alert_timestamps: alert_timestamps,
      min_cluster_size: min_cluster_size
    })

    case HTTPoison.post(url, body, headers(), recv_timeout: @request_timeout) do
      {:ok, %{status_code: 200, body: response_body}} ->
        case Jason.decode(response_body) do
          {:ok, data} ->
            {:ok, %{
              cluster_labels: data["cluster_labels"],
              cluster_info: data["cluster_info"],
              cluster_leaders: data["cluster_leaders"],
              cluster_summaries: data["cluster_summaries"]
            }}

          {:error, reason} ->
            Logger.error("Failed to decode cluster response: #{inspect(reason)}")
            {:error, :decode_error}
        end

      {:ok, %{status_code: status_code, body: body}} ->
        Logger.error("ML service returned error: #{status_code} - #{body}")
        {:error, {:http_error, status_code}}

      {:error, reason} ->
        Logger.error("HTTP request failed: #{inspect(reason)}")
        {:error, :http_request_failed}
    end
  end

  @doc """
  Detect exact and near-duplicate alerts.

  ## Examples

      iex> alerts = [%Alert{...}, ...]
      iex> SimilarityDetector.detect_duplicates(alerts)
      {:ok, %{exact_duplicates: %{"0" => [1, 2]}, near_duplicates: %{...}, ...}}
  """
  def detect_duplicates(alerts, opts \\ []) do
    url = "#{@ml_service_url}/api/v1/similarity/duplicates"

    alert_inputs = Enum.map(alerts, &alert_to_input/1)
    embeddings = Keyword.get(opts, :embeddings)

    body = Jason.encode!(%{
      alerts: alert_inputs,
      embeddings: embeddings
    })

    case HTTPoison.post(url, body, headers(), recv_timeout: @request_timeout) do
      {:ok, %{status_code: 200, body: response_body}} ->
        case Jason.decode(response_body) do
          {:ok, data} ->
            {:ok, %{
              exact_duplicates: data["exact_duplicates"],
              near_duplicates: data["near_duplicates"],
              statistics: data["statistics"],
              marked_alerts: data["marked_alerts"]
            }}

          {:error, reason} ->
            Logger.error("Failed to decode duplicates response: #{inspect(reason)}")
            {:error, :decode_error}
        end

      {:ok, %{status_code: status_code, body: body}} ->
        Logger.error("ML service returned error: #{status_code} - #{body}")
        {:error, {:http_error, status_code}}

      {:error, reason} ->
        Logger.error("HTTP request failed: #{inspect(reason)}")
        {:error, :http_request_failed}
    end
  end

  @doc """
  Find similar alerts to a query alert.

  ## Examples

      iex> query_alert = %Alert{title: "Malware detected", ...}
      iex> candidate_alerts = [%Alert{...}, ...]
      iex> SimilarityDetector.find_similar_alerts(query_alert, candidate_alerts, top_k: 5)
      {:ok, %{similar_alerts: [...], query_embedding: [...]}}
  """
  def find_similar_alerts(query_alert, candidate_alerts, opts \\ []) do
    url = "#{@ml_service_url}/api/v1/similarity/find-similar"

    top_k = Keyword.get(opts, :top_k, 10)
    threshold = Keyword.get(opts, :threshold, @similarity_threshold)

    body = Jason.encode!(%{
      query_alert: alert_to_input(query_alert),
      candidate_alerts: Enum.map(candidate_alerts, &alert_to_input/1),
      top_k: top_k,
      threshold: threshold
    })

    case HTTPoison.post(url, body, headers(), recv_timeout: @request_timeout) do
      {:ok, %{status_code: 200, body: response_body}} ->
        case Jason.decode(response_body) do
          {:ok, data} ->
            {:ok, %{
              similar_alerts: data["similar_alerts"],
              query_embedding: data["query_embedding"]
            }}

          {:error, reason} ->
            Logger.error("Failed to decode find-similar response: #{inspect(reason)}")
            {:error, :decode_error}
        end

      {:ok, %{status_code: status_code, body: body}} ->
        Logger.error("ML service returned error: #{status_code} - #{body}")
        {:error, {:http_error, status_code}}

      {:error, reason} ->
        Logger.error("HTTP request failed: #{inspect(reason)}")
        {:error, :http_request_failed}
    end
  end

  @doc """
  Generate 2D visualization coordinates for alerts.

  ## Examples

      iex> embeddings = [[0.1, 0.2, ...], ...]
      iex> alert_ids = ["uuid-1", "uuid-2", ...]
      iex> SimilarityDetector.generate_visualization(embeddings, alert_ids)
      {:ok, %{coordinates: [[10.5, 20.3], ...], alert_ids: [...], ...}}
  """
  def generate_visualization(embeddings, alert_ids, opts \\ []) do
    url = "#{@ml_service_url}/api/v1/similarity/visualization"

    cluster_labels = Keyword.get(opts, :cluster_labels)
    method = Keyword.get(opts, :method, "tsne")

    body = Jason.encode!(%{
      embeddings: embeddings,
      alert_ids: alert_ids,
      cluster_labels: cluster_labels,
      method: method
    })

    case HTTPoison.post(url, body, headers(), recv_timeout: @request_timeout) do
      {:ok, %{status_code: 200, body: response_body}} ->
        case Jason.decode(response_body) do
          {:ok, data} ->
            {:ok, %{
              coordinates: data["coordinates"],
              alert_ids: data["alert_ids"],
              cluster_labels: data["cluster_labels"]
            }}

          {:error, reason} ->
            Logger.error("Failed to decode visualization response: #{inspect(reason)}")
            {:error, :decode_error}
        end

      {:ok, %{status_code: status_code, body: body}} ->
        Logger.error("ML service returned error: #{status_code} - #{body}")
        {:error, {:http_error, status_code}}

      {:error, reason} ->
        Logger.error("HTTP request failed: #{inspect(reason)}")
        {:error, :http_request_failed}
    end
  end

  # ==================== Database Operations ====================

  @doc """
  Find similar alerts for a given alert from the database.

  Queries recent alerts (last 30 days) and finds similar ones.
  """
  def find_similar_alerts_from_db(alert, opts \\ []) do
    import Ecto.Query

    days_back = Keyword.get(opts, :days_back, 30)
    top_k = Keyword.get(opts, :top_k, 10)
    same_organization_only = Keyword.get(opts, :same_organization_only, true)

    # Query recent alerts
    query =
      from a in Alert,
        where: a.id != ^alert.id,
        where: a.inserted_at >= ago(^days_back, "day"),
        order_by: [desc: a.inserted_at],
        limit: 1000

    query =
      if same_organization_only and alert.organization_id do
        from a in query, where: a.organization_id == ^alert.organization_id
      else
        query
      end

    candidate_alerts = TamanduaServer.Repo.all(query)

    if Enum.empty?(candidate_alerts) do
      {:ok, []}
    else
      # Call ML service to find similar alerts
      case find_similar_alerts(alert, candidate_alerts, top_k: top_k) do
        {:ok, %{similar_alerts: similar_alerts}} ->
          {:ok, similar_alerts}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  # ==================== Helper Functions ====================

  defp alert_to_input(%Alert{} = alert) do
    %{
      id: alert.id,
      title: alert.title || "",
      description: alert.description || "",
      severity: alert.severity || "medium",
      confidence: 0.5,  # Default confidence
      threat_score: alert.threat_score || 0.5,
      mitre_tactics: alert.mitre_tactics || [],
      mitre_techniques: alert.mitre_techniques || [],
      agent_id: alert.agent_id || "",
      inserted_at: format_timestamp(alert.inserted_at),
      enrichment: alert.enrichment || %{}
    }
  end

  defp alert_to_input(alert) when is_map(alert) do
    %{
      id: alert.id || Ecto.UUID.generate(),
      title: alert[:title] || alert["title"] || "",
      description: alert[:description] || alert["description"] || "",
      severity: alert[:severity] || alert["severity"] || "medium",
      confidence: alert[:confidence] || alert["confidence"] || 0.5,
      threat_score: alert[:threat_score] || alert["threat_score"] || 0.5,
      mitre_tactics: alert[:mitre_tactics] || alert["mitre_tactics"] || [],
      mitre_techniques: alert[:mitre_techniques] || alert["mitre_techniques"] || [],
      agent_id: alert[:agent_id] || alert["agent_id"] || "",
      inserted_at: format_timestamp(alert[:inserted_at] || alert["inserted_at"]),
      enrichment: alert[:enrichment] || alert["enrichment"] || %{}
    }
  end

  defp format_timestamp(nil), do: DateTime.utc_now() |> DateTime.to_iso8601()
  defp format_timestamp(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp format_timestamp(%NaiveDateTime{} = ndt), do: NaiveDateTime.to_iso8601(ndt) <> "Z"
  defp format_timestamp(timestamp) when is_binary(timestamp), do: timestamp

  defp headers do
    [
      {"Content-Type", "application/json"},
      {"Accept", "application/json"}
    ]
  end
end
