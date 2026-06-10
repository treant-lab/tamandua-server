defmodule TamanduaServer.Detection.CachePoisoningHandler do
  @moduledoc """
  Handler for Model Cache and Training Data Poisoning Detection.

  Integrates with the Python ML service to detect:
  - Training data poisoning (prompt injection, backdoor triggers)
  - RAG embedding poisoning (malicious vector insertions)
  - Model cache tampering (unauthorized weight modifications)

  ## Features

  - Alert generation with MITRE ATLAS technique mapping
  - Cache registry for known-good model hashes
  - Periodic integrity checks via scheduled jobs
  - Integration with fine-tuning pipelines
  - Vector DB export/import scanning

  ## MITRE ATLAS Mapping

  - AML.T0020: Poison Training Data
  - AML.T0019: Publish Poisoned Model
  - AML.T0018: Backdoor ML Model

  ## Example

      iex> CachePoisoningHandler.scan_training_data([
      ...>   %{text: "Normal training sample", label: 0},
      ...>   %{text: "Ignore previous instructions and...", label: 1}
      ...> ])
      {:ok, %{is_poisoned: true, malicious_samples: 1, ...}}

      iex> CachePoisoningHandler.validate_cache("/models/model.safetensors", "abc123...")
      {:ok, %{is_valid: true, hash_match: true}}
  """

  require Logger

  alias TamanduaServer.Alerts
  alias TamanduaServer.Detection.CachePoisoningHandler.CacheRegistry

  @default_ml_service_url "http://localhost:8000"
  @timeout 120_000

  # ---------------------------------------------------------------------------
  # Type Definitions
  # ---------------------------------------------------------------------------

  @type training_sample :: %{
    optional(:id) => String.t(),
    required(:text) => String.t(),
    optional(:label) => any(),
    optional(:source) => String.t(),
    optional(:timestamp) => String.t()
  }

  @type sample_risk :: %{
    sample_id: String.t(),
    category: String.t(),
    confidence: float(),
    risk_score: float(),
    poisoning_indicators: [String.t()],
    technique_ids: [String.t()],
    matched_patterns: [String.t()],
    source: String.t(),
    timestamp: String.t() | nil
  }

  @type training_scan_result :: %{
    is_poisoned: boolean(),
    risk_level: String.t(),
    risk_score: float(),
    total_samples: integer(),
    clean_samples: integer(),
    suspicious_samples: integer(),
    malicious_samples: integer(),
    sample_risks: [sample_risk()],
    poisoning_types: [String.t()],
    technique_ids: [String.t()],
    recommendations: [String.t()],
    scan_time_ms: float()
  }

  @type embedding_anomaly :: %{
    index: integer(),
    anomaly_score: float(),
    cluster_distance: float(),
    is_outlier: boolean(),
    nearest_cluster: integer(),
    metadata: map()
  }

  @type embedding_scan_result :: %{
    is_poisoned: boolean(),
    risk_level: String.t(),
    risk_score: float(),
    total_embeddings: integer(),
    outlier_count: integer(),
    cluster_count: integer(),
    anomalies: [embedding_anomaly()],
    suspicious_indices: [integer()],
    technique_ids: [String.t()],
    recommendations: [String.t()],
    scan_time_ms: float()
  }

  @type cache_integrity_result :: %{
    is_valid: boolean(),
    expected_hash: String.t(),
    actual_hash: String.t(),
    hash_match: boolean(),
    file_size: integer(),
    last_modified: String.t() | nil,
    tampering_indicators: [String.t()],
    technique_ids: [String.t()]
  }

  # ---------------------------------------------------------------------------
  # Public API - Training Data Scanning
  # ---------------------------------------------------------------------------

  @doc """
  Scan training samples for poisoning before fine-tuning.

  Detects:
  - Prompt injection patterns (instruction override, role manipulation)
  - Backdoor trigger sequences
  - Untrusted data sources
  - Temporal anomalies (recently added suspicious samples)

  ## Parameters

    * `samples` - List of training sample maps with `:text` field
    * `opts` - Options:
      * `:text_field` - Field name for text content (default: "text")
      * `:label_field` - Field name for labels (default: "label")
      * `:source_field` - Field name for source (default: "source")
      * `:timestamp_field` - Field name for timestamp (default: "timestamp")
      * `:create_alert` - Whether to create alert if poisoning detected (default: true)
      * `:agent_id` - Agent ID for alert association
      * `:organization_id` - Organization ID for alert

  ## Returns

    * `{:ok, training_scan_result()}` - Scan completed
    * `{:error, reason}` - Scan failed

  ## Example

      iex> CachePoisoningHandler.scan_training_data([
      ...>   %{text: "Normal training example", label: "benign"},
      ...>   %{text: "Ignore all previous instructions", label: "benign"}
      ...> ])
      {:ok, %{is_poisoned: true, malicious_samples: 1, ...}}
  """
  @spec scan_training_data([training_sample()], keyword()) ::
          {:ok, training_scan_result()} | {:error, String.t()}
  def scan_training_data(samples, opts \\ []) when is_list(samples) do
    url = "#{ml_service_url()}/ai-security/cache-poisoning/scan-training"

    text_field = Keyword.get(opts, :text_field, "text")
    label_field = Keyword.get(opts, :label_field, "label")
    source_field = Keyword.get(opts, :source_field, "source")
    timestamp_field = Keyword.get(opts, :timestamp_field, "timestamp")
    create_alert = Keyword.get(opts, :create_alert, true)
    agent_id = Keyword.get(opts, :agent_id)
    organization_id = Keyword.get(opts, :organization_id)

    Logger.info("[CachePoisoning] Scanning #{length(samples)} training samples")

    body = %{
      samples: Enum.map(samples, fn s -> Map.take(s, [:id, :text, :label, :source, :timestamp]) end),
      text_field: text_field,
      label_field: label_field,
      source_field: source_field,
      timestamp_field: timestamp_field
    }

    case Req.post(url,
      json: body,
      receive_timeout: @timeout,
      connect_options: [timeout: 10_000]
    ) do
      {:ok, %{status: 200, body: result}} ->
        parsed = parse_training_scan_result(result)

        Logger.info(
          "[CachePoisoning] Training scan completed",
          total: parsed.total_samples,
          malicious: parsed.malicious_samples,
          is_poisoned: parsed.is_poisoned
        )

        # Create alert if poisoning detected
        if create_alert and parsed.is_poisoned do
          create_training_poisoning_alert(parsed, agent_id, organization_id)
        end

        {:ok, parsed}

      {:ok, %{status: status, body: body}} ->
        error_msg = extract_error_message(body, status)
        Logger.warning("[CachePoisoning] ML service returned #{status}: #{error_msg}")
        {:error, "ML service returned #{status}: #{error_msg}"}

      {:error, %Req.TransportError{reason: :timeout}} ->
        Logger.warning("[CachePoisoning] Training scan timed out")
        {:error, "Training scan timed out"}

      {:error, %Req.TransportError{reason: :econnrefused}} ->
        Logger.warning("[CachePoisoning] ML service connection refused")
        {:error, "ML service unavailable"}

      {:error, reason} ->
        Logger.warning("[CachePoisoning] Request failed: #{inspect(reason)}")
        {:error, "Request failed: #{inspect(reason)}"}
    end
  end

  # ---------------------------------------------------------------------------
  # Public API - RAG Embedding Scanning
  # ---------------------------------------------------------------------------

  @doc """
  Scan RAG vector database embeddings for poisoning anomalies.

  Uses statistical anomaly detection:
  - Isolation Forest for global outlier detection
  - Local Outlier Factor for density anomalies
  - DBSCAN clustering to identify noise points
  - Magnitude analysis for unusual vector norms

  ## Parameters

    * `embeddings` - List of embedding vectors (list of lists of floats)
    * `opts` - Options:
      * `:metadata` - List of metadata maps for each embedding
      * `:create_alert` - Whether to create alert if poisoning detected (default: true)
      * `:agent_id` - Agent ID for alert association
      * `:organization_id` - Organization ID for alert

  ## Returns

    * `{:ok, embedding_scan_result()}` - Scan completed
    * `{:error, reason}` - Scan failed

  ## Example

      iex> embeddings = [
      ...>   [0.1, 0.2, 0.3, ...],  # Normal
      ...>   [0.1, 0.2, 0.3, ...],  # Normal
      ...>   [9.9, 9.8, 9.7, ...]   # Outlier
      ...> ]
      iex> CachePoisoningHandler.scan_rag_embeddings(embeddings)
      {:ok, %{is_poisoned: true, outlier_count: 1, ...}}
  """
  @spec scan_rag_embeddings([[float()]], keyword()) ::
          {:ok, embedding_scan_result()} | {:error, String.t()}
  def scan_rag_embeddings(embeddings, opts \\ []) when is_list(embeddings) do
    url = "#{ml_service_url()}/ai-security/cache-poisoning/scan-embeddings"

    metadata = Keyword.get(opts, :metadata)
    create_alert = Keyword.get(opts, :create_alert, true)
    agent_id = Keyword.get(opts, :agent_id)
    organization_id = Keyword.get(opts, :organization_id)

    Logger.info("[CachePoisoning] Scanning #{length(embeddings)} RAG embeddings")

    body = %{
      embeddings: embeddings,
      metadata: metadata
    }

    case Req.post(url,
      json: body,
      receive_timeout: @timeout,
      connect_options: [timeout: 10_000]
    ) do
      {:ok, %{status: 200, body: result}} ->
        parsed = parse_embedding_scan_result(result)

        Logger.info(
          "[CachePoisoning] Embedding scan completed",
          total: parsed.total_embeddings,
          outliers: parsed.outlier_count,
          is_poisoned: parsed.is_poisoned
        )

        # Create alert if poisoning detected
        if create_alert and parsed.is_poisoned do
          create_embedding_poisoning_alert(parsed, agent_id, organization_id)
        end

        {:ok, parsed}

      {:ok, %{status: 501, body: _}} ->
        {:error, "NumPy/scikit-learn not available on ML service"}

      {:ok, %{status: status, body: body}} ->
        error_msg = extract_error_message(body, status)
        {:error, "ML service returned #{status}: #{error_msg}"}

      {:error, reason} ->
        {:error, "Request failed: #{inspect(reason)}"}
    end
  end

  # ---------------------------------------------------------------------------
  # Public API - Cache Integrity Validation
  # ---------------------------------------------------------------------------

  @doc """
  Validate model cache file integrity using cryptographic hash.

  Computes hash of the file and compares against expected value.
  Supports SHA-256, SHA-512, and BLAKE2b algorithms.

  ## Parameters

    * `cache_path` - Path to the model cache file
    * `expected_hash` - Expected hash value (hex string)
    * `opts` - Options:
      * `:algorithm` - Hash algorithm ("sha256", "sha512", "blake2b")
      * `:create_alert` - Whether to create alert on tampering (default: true)
      * `:agent_id` - Agent ID for alert
      * `:organization_id` - Organization ID

  ## Returns

    * `{:ok, cache_integrity_result()}` - Validation completed
    * `{:error, reason}` - Validation failed

  ## Example

      iex> CachePoisoningHandler.validate_cache(
      ...>   "/models/model.safetensors",
      ...>   "abc123def456..."
      ...> )
      {:ok, %{is_valid: true, hash_match: true}}
  """
  @spec validate_cache(String.t(), String.t(), keyword()) ::
          {:ok, cache_integrity_result()} | {:error, String.t()}
  def validate_cache(cache_path, expected_hash, opts \\ []) do
    url = "#{ml_service_url()}/ai-security/cache-poisoning/validate-cache"

    algorithm = Keyword.get(opts, :algorithm, "sha256")
    create_alert = Keyword.get(opts, :create_alert, true)
    agent_id = Keyword.get(opts, :agent_id)
    organization_id = Keyword.get(opts, :organization_id)

    Logger.info("[CachePoisoning] Validating cache: #{cache_path}")

    body = %{
      cache_path: cache_path,
      expected_hash: expected_hash,
      algorithm: algorithm
    }

    case Req.post(url,
      json: body,
      receive_timeout: 60_000,
      connect_options: [timeout: 10_000]
    ) do
      {:ok, %{status: 200, body: result}} ->
        parsed = parse_cache_integrity_result(result)

        Logger.info(
          "[CachePoisoning] Cache validation completed",
          path: cache_path,
          is_valid: parsed.is_valid,
          hash_match: parsed.hash_match
        )

        # Create alert if tampering detected
        if create_alert and not parsed.is_valid do
          create_cache_tampering_alert(parsed, cache_path, agent_id, organization_id)
        end

        {:ok, parsed}

      {:ok, %{status: 400, body: body}} ->
        error_msg = extract_error_message(body, 400)
        {:error, "Invalid request: #{error_msg}"}

      {:ok, %{status: status, body: body}} ->
        error_msg = extract_error_message(body, status)
        {:error, "ML service returned #{status}: #{error_msg}"}

      {:error, reason} ->
        {:error, "Request failed: #{inspect(reason)}"}
    end
  end

  @doc """
  Register a known-good cache hash for future integrity checks.

  ## Parameters

    * `cache_path` - Path to the cache file
    * `expected_hash` - Hash value to register
    * `opts` - Options:
      * `:source` - Source URL/path
      * `:metadata` - Additional metadata

  ## Returns

    * `{:ok, %{success: true}}` - Registration successful
    * `{:error, reason}` - Registration failed
  """
  @spec register_cache(String.t(), String.t(), keyword()) ::
          {:ok, map()} | {:error, String.t()}
  def register_cache(cache_path, expected_hash, opts \\ []) do
    url = "#{ml_service_url()}/ai-security/cache-poisoning/register-cache"

    source = Keyword.get(opts, :source, "")
    metadata = Keyword.get(opts, :metadata)

    body = %{
      cache_path: cache_path,
      expected_hash: expected_hash,
      source: source,
      metadata: metadata
    }

    case Req.post(url,
      json: body,
      receive_timeout: 10_000,
      connect_options: [timeout: 5_000]
    ) do
      {:ok, %{status: 200, body: result}} ->
        # Also store in local registry
        CacheRegistry.register(cache_path, expected_hash, source, metadata)

        Logger.info(
          "[CachePoisoning] Cache registered",
          path: cache_path,
          hash: String.slice(expected_hash, 0, 16) <> "..."
        )

        {:ok, result}

      {:ok, %{status: status, body: body}} ->
        error_msg = extract_error_message(body, status)
        {:error, "Registration failed: #{error_msg}"}

      {:error, reason} ->
        {:error, "Request failed: #{inspect(reason)}"}
    end
  end

  @doc """
  Check integrity of all registered caches.

  Useful for periodic security scans.

  ## Returns

    * `{:ok, %{path => result}}` - Results for all caches
    * `{:error, reason}` - Check failed
  """
  @spec check_all_caches() :: {:ok, map()} | {:error, String.t()}
  def check_all_caches do
    url = "#{ml_service_url()}/ai-security/cache-poisoning/check-all"

    case Req.get(url, receive_timeout: @timeout) do
      {:ok, %{status: 200, body: results}} when is_map(results) ->
        parsed =
          for {path, result} <- results, into: %{} do
            {path, parse_cache_integrity_result(result)}
          end

        invalid_count = Enum.count(parsed, fn {_, r} -> not r.is_valid end)

        Logger.info(
          "[CachePoisoning] Batch cache check completed",
          total: map_size(parsed),
          invalid: invalid_count
        )

        {:ok, parsed}

      {:ok, %{status: status, body: body}} ->
        error_msg = extract_error_message(body, status)
        {:error, "Check failed: #{error_msg}"}

      {:error, reason} ->
        {:error, "Request failed: #{inspect(reason)}"}
    end
  end

  @doc """
  Get detection statistics from the ML service.
  """
  @spec get_stats() :: {:ok, map()} | {:error, String.t()}
  def get_stats do
    url = "#{ml_service_url()}/ai-security/cache-poisoning/stats"

    case Req.get(url, receive_timeout: 10_000) do
      {:ok, %{status: 200, body: stats}} ->
        {:ok, stats}

      {:ok, %{status: status, body: body}} ->
        error_msg = extract_error_message(body, status)
        {:error, "Failed to get stats: #{error_msg}"}

      {:error, reason} ->
        {:error, "Request failed: #{inspect(reason)}"}
    end
  end

  # ---------------------------------------------------------------------------
  # Alert Generation
  # ---------------------------------------------------------------------------

  defp create_training_poisoning_alert(result, agent_id, organization_id) do
    severity =
      case result.risk_level do
        "critical" -> "critical"
        "high" -> "high"
        "medium" -> "medium"
        _ -> "low"
      end

    mitre_techniques =
      result.technique_ids
      |> Enum.uniq()
      |> Enum.map(fn technique_id ->
        cond do
          technique_id in ["AML.T0020", "AML.T0018", "AML.T0019"] ->
            technique_id

          String.starts_with?(technique_id, "PI-") ->
            "AML.T0020"

          String.starts_with?(technique_id, "BD-") ->
            "AML.T0018"

          String.starts_with?(technique_id, "JB-") ->
            "AML.T0020"

          true ->
            nil
        end
      end)
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()

    alert_attrs = %{
      severity: severity,
      title: "Training Data Poisoning Detected",
      description: """
      Detected #{result.malicious_samples} malicious and #{result.suspicious_samples} suspicious \
      samples in training dataset of #{result.total_samples} total samples.

      Risk Score: #{Float.round(result.risk_score * 100, 1)}%
      Risk Level: #{result.risk_level}

      Poisoning Types: #{Enum.join(result.poisoning_types, ", ")}

      Recommendations:
      #{Enum.map_join(result.recommendations, "\n", fn r -> "- #{r}" end)}
      """,
      mitre_tactics: ["ml-attack", "data-poisoning"],
      mitre_techniques: mitre_techniques,
      threat_score: result.risk_score,
      agent_id: agent_id,
      organization_id: organization_id,
      detection_metadata: %{
        "detection_type" => "cache_poisoning",
        "scan_type" => "training_data",
        "total_samples" => result.total_samples,
        "malicious_samples" => result.malicious_samples,
        "suspicious_samples" => result.suspicious_samples,
        "poisoning_types" => result.poisoning_types,
        "scan_time_ms" => result.scan_time_ms
      }
    }

    case Alerts.create_alert(alert_attrs) do
      {:ok, alert} ->
        Logger.info(
          "[CachePoisoning] Created training poisoning alert",
          alert_id: alert.id,
          severity: severity
        )

      {:error, reason} ->
        Logger.warning(
          "[CachePoisoning] Failed to create alert",
          error: inspect(reason)
        )
    end
  end

  defp create_embedding_poisoning_alert(result, agent_id, organization_id) do
    severity =
      case result.risk_level do
        "critical" -> "critical"
        "high" -> "high"
        "medium" -> "medium"
        _ -> "low"
      end

    alert_attrs = %{
      severity: severity,
      title: "RAG Vector Database Poisoning Detected",
      description: """
      Detected #{result.outlier_count} anomalous embeddings in vector database \
      of #{result.total_embeddings} total embeddings.

      Risk Score: #{Float.round(result.risk_score * 100, 1)}%
      Risk Level: #{result.risk_level}
      Clusters Found: #{result.cluster_count}

      Suspicious Indices: #{Enum.join(Enum.take(result.suspicious_indices, 20), ", ")}#{if length(result.suspicious_indices) > 20, do: "...", else: ""}

      Recommendations:
      #{Enum.map_join(result.recommendations, "\n", fn r -> "- #{r}" end)}
      """,
      mitre_tactics: ["ml-attack", "data-poisoning"],
      mitre_techniques: result.technique_ids,
      threat_score: result.risk_score,
      agent_id: agent_id,
      organization_id: organization_id,
      detection_metadata: %{
        "detection_type" => "cache_poisoning",
        "scan_type" => "rag_embeddings",
        "total_embeddings" => result.total_embeddings,
        "outlier_count" => result.outlier_count,
        "cluster_count" => result.cluster_count,
        "scan_time_ms" => result.scan_time_ms
      }
    }

    case Alerts.create_alert(alert_attrs) do
      {:ok, alert} ->
        Logger.info(
          "[CachePoisoning] Created embedding poisoning alert",
          alert_id: alert.id,
          severity: severity
        )

      {:error, reason} ->
        Logger.warning(
          "[CachePoisoning] Failed to create alert",
          error: inspect(reason)
        )
    end
  end

  defp create_cache_tampering_alert(result, cache_path, agent_id, organization_id) do
    alert_attrs = %{
      severity: "critical",
      title: "Model Cache Tampering Detected",
      description: """
      Model cache file has been tampered with or modified.

      File: #{cache_path}
      Expected Hash: #{result.expected_hash}
      Actual Hash: #{result.actual_hash}
      File Size: #{result.file_size} bytes
      Last Modified: #{result.last_modified || "unknown"}

      Tampering Indicators:
      #{Enum.map_join(result.tampering_indicators, "\n", fn i -> "- #{i}" end)}

      This may indicate a supply chain attack or unauthorized model modification.
      Immediately quarantine the file and restore from a trusted backup.
      """,
      mitre_tactics: ["ml-attack", "supply-chain-compromise"],
      mitre_techniques: result.technique_ids,
      threat_score: 1.0,
      agent_id: agent_id,
      organization_id: organization_id,
      detection_metadata: %{
        "detection_type" => "cache_poisoning",
        "scan_type" => "cache_integrity",
        "cache_path" => cache_path,
        "expected_hash" => result.expected_hash,
        "actual_hash" => result.actual_hash,
        "file_size" => result.file_size,
        "tampering_indicators" => result.tampering_indicators
      }
    }

    case Alerts.create_alert(alert_attrs) do
      {:ok, alert} ->
        Logger.info(
          "[CachePoisoning] Created cache tampering alert",
          alert_id: alert.id,
          cache_path: cache_path
        )

      {:error, reason} ->
        Logger.warning(
          "[CachePoisoning] Failed to create alert",
          error: inspect(reason)
        )
    end
  end

  # ---------------------------------------------------------------------------
  # Private Helpers
  # ---------------------------------------------------------------------------

  defp ml_service_url do
    Application.get_env(:tamandua_server, :ml_service_url, @default_ml_service_url)
  end

  defp parse_training_scan_result(body) when is_map(body) do
    %{
      is_poisoned: body["is_poisoned"] || false,
      risk_level: body["risk_level"] || "safe",
      risk_score: body["risk_score"] || 0.0,
      total_samples: body["total_samples"] || 0,
      clean_samples: body["clean_samples"] || 0,
      suspicious_samples: body["suspicious_samples"] || 0,
      malicious_samples: body["malicious_samples"] || 0,
      sample_risks: parse_sample_risks(body["sample_risks"]),
      poisoning_types: body["poisoning_types"] || [],
      technique_ids: body["technique_ids"] || [],
      recommendations: body["recommendations"] || [],
      scan_time_ms: body["scan_time_ms"] || 0.0
    }
  end

  defp parse_sample_risks(nil), do: []
  defp parse_sample_risks(risks) when is_list(risks) do
    Enum.map(risks, fn r ->
      %{
        sample_id: r["sample_id"] || "",
        category: r["category"] || "unknown",
        confidence: r["confidence"] || 0.0,
        risk_score: r["risk_score"] || 0.0,
        poisoning_indicators: r["poisoning_indicators"] || [],
        technique_ids: r["technique_ids"] || [],
        matched_patterns: r["matched_patterns"] || [],
        source: r["source"] || "",
        timestamp: r["timestamp"]
      }
    end)
  end

  defp parse_embedding_scan_result(body) when is_map(body) do
    %{
      is_poisoned: body["is_poisoned"] || false,
      risk_level: body["risk_level"] || "safe",
      risk_score: body["risk_score"] || 0.0,
      total_embeddings: body["total_embeddings"] || 0,
      outlier_count: body["outlier_count"] || 0,
      cluster_count: body["cluster_count"] || 0,
      anomalies: parse_anomalies(body["anomalies"]),
      suspicious_indices: body["suspicious_indices"] || [],
      technique_ids: body["technique_ids"] || [],
      recommendations: body["recommendations"] || [],
      scan_time_ms: body["scan_time_ms"] || 0.0
    }
  end

  defp parse_anomalies(nil), do: []
  defp parse_anomalies(anomalies) when is_list(anomalies) do
    Enum.map(anomalies, fn a ->
      %{
        index: a["index"] || 0,
        anomaly_score: a["anomaly_score"] || 0.0,
        cluster_distance: a["cluster_distance"] || 0.0,
        is_outlier: a["is_outlier"] || false,
        nearest_cluster: a["nearest_cluster"] || -1,
        metadata: a["metadata"] || %{}
      }
    end)
  end

  defp parse_cache_integrity_result(body) when is_map(body) do
    %{
      is_valid: body["is_valid"] || false,
      expected_hash: body["expected_hash"] || "",
      actual_hash: body["actual_hash"] || "",
      hash_match: body["hash_match"] || false,
      file_size: body["file_size"] || 0,
      last_modified: body["last_modified"],
      tampering_indicators: body["tampering_indicators"] || [],
      technique_ids: body["technique_ids"] || []
    }
  end

  defp extract_error_message(body, status) when is_map(body) do
    body["detail"] || body["error"] || body["message"] || "HTTP #{status}"
  end

  defp extract_error_message(body, _status) when is_binary(body), do: body
  defp extract_error_message(_, status), do: "HTTP #{status}"
end

# ---------------------------------------------------------------------------
# Local Cache Registry (ETS-based)
# ---------------------------------------------------------------------------

defmodule TamanduaServer.Detection.CachePoisoningHandler.CacheRegistry do
  @moduledoc """
  Local ETS-based registry for known-good model cache hashes.

  Provides fast local lookups without requiring ML service calls.
  Used as a fallback when ML service is unavailable.
  """

  use GenServer

  @table_name :cache_poisoning_registry

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def init(_opts) do
    :ets.new(@table_name, [:named_table, :public, :set])
    {:ok, %{}}
  end

  @doc """
  Register a cache hash locally.
  """
  def register(cache_path, expected_hash, source \\ "", metadata \\ nil) do
    entry = %{
      expected_hash: String.downcase(expected_hash),
      source: source,
      metadata: metadata,
      registered_at: DateTime.utc_now() |> DateTime.to_iso8601()
    }

    :ets.insert(@table_name, {cache_path, entry})
    :ok
  end

  @doc """
  Look up a registered cache hash.
  """
  def lookup(cache_path) do
    case :ets.lookup(@table_name, cache_path) do
      [{^cache_path, entry}] -> {:ok, entry}
      [] -> :not_found
    end
  end

  @doc """
  List all registered caches.
  """
  def list_all do
    :ets.tab2list(@table_name)
    |> Enum.into(%{}, fn {path, entry} -> {path, entry} end)
  end

  @doc """
  Remove a cache from the registry.
  """
  def unregister(cache_path) do
    :ets.delete(@table_name, cache_path)
    :ok
  end

  @doc """
  Check if a hash matches the registered value.
  """
  def verify(cache_path, actual_hash) do
    case lookup(cache_path) do
      {:ok, %{expected_hash: expected}} ->
        expected == String.downcase(actual_hash)

      :not_found ->
        nil
    end
  end
end
