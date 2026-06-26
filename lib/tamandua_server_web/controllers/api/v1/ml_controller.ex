defmodule TamanduaServerWeb.API.V1.MLController do
  @moduledoc """
  ML Service Management API Controller.

  Provides endpoints for:
  - Model information and status
  - Binary sample analysis
  - Batch predictions
  - Model management (reload, statistics)
  - Training job management
  """

  use TamanduaServerWeb, :controller
  require Logger

  alias TamanduaServer.Detection.ML.Client, as: MLClient
  alias TamanduaServer.Detection.Engine

  action_fallback TamanduaServerWeb.FallbackController

  # Default ML service URL from config or environment
  @ml_service_url Application.compile_env(:tamandua_server, :ml_service_url, "http://localhost:8000")

  def action(conn, _opts) do
    apply(__MODULE__, action_name(conn), [conn, conn.params])
  rescue
    exception ->
      Logger.warning("ML API action #{action_name(conn)} failed: #{Exception.message(exception)}")

      conn
      |> put_status(:service_unavailable)
      |> json(%{
        error: "ml_service_unavailable",
        message: "ML service is unavailable",
        detail: Exception.message(exception)
      })
  catch
    :exit, {:noproc, _} ->
      conn
      |> put_status(:service_unavailable)
      |> json(%{error: "ml_service_unavailable", message: "ML service is not running in this boot profile"})

    :exit, {:timeout, _} ->
      conn
      |> put_status(:gateway_timeout)
      |> json(%{error: "ml_service_timeout", message: "ML service timed out"})

    kind, reason ->
      Logger.warning("ML API action #{action_name(conn)} failed: #{inspect(kind)} #{inspect(reason)}")

      conn
      |> put_status(:service_unavailable)
      |> json(%{error: "ml_service_unavailable", message: "ML service is unavailable"})
  end

  # -------------------------------------------------------------------
  # Model Information
  # -------------------------------------------------------------------

  @doc """
  Get ML service health and model information.

  Performs a real health check against the ML service via the ML Client,
  and retrieves model metadata. Returns both health status and model
  details, or an appropriate error if the service is down.
  """
  def status(conn, _params) do
    healthy = MLClient.healthy?()

    model_info = case MLClient.model_info() do
      {:ok, info} -> info
      {:error, _} -> nil
    end

    status_code = if healthy, do: 200, else: 503

    conn
    |> put_status(status_code)
    |> json(%{
      data: %{
        healthy: healthy,
        model: model_info,
        service_url: ml_service_url()
      }
    })
  end

  @doc """
  Get ML model metrics for the dynamic detection dashboard.
  Returns model performance metrics in the format expected by DynamicDetection.tsx.

  Fetches real metrics from the ML service via the ML Client. If the ML service
  is unavailable, returns an error response with status 503.

  ## Response Format
  - model_name: Name of the model
  - version: Model version
  - accuracy: Model accuracy (0-100)
  - precision: Model precision (0-100)
  - recall: Model recall (0-100)
  - f1_score: F1 score (0-100)
  - last_trained: ISO8601 timestamp of last training
  - samples_processed: Total samples processed
  - inference_latency: Average inference time in ms
  """
  def metrics(conn, _params) do
    ml_client_result =
      try do
        MLClient.get_metrics()
      catch
        :exit, reason -> {:error, {:ml_client_unavailable, reason}}
      rescue
        error -> {:error, error}
      end

    case ml_client_result do
      {:ok, metrics} ->
        json(conn, transform_ml_metrics(metrics))

      {:error, :ml_service_unavailable} ->
        conn
        |> put_status(:service_unavailable)
        |> json(unavailable_ml_metrics("ML service is not reachable. The circuit breaker is open."))

      {:error, reason} ->
        # Fall back to fetching directly if the client returned a different error.
        case fetch_ml_metrics() do
          {:ok, metrics} ->
            json(conn, metrics)

          {:error, _} ->
            conn
            |> put_status(:service_unavailable)
            |> json(unavailable_ml_metrics("ML service returned an error: #{inspect(reason)}"))
        end
    end
  end

  defp unavailable_ml_metrics(message) do
    %{
      status: "unavailable",
      message: message,
      models: [],
      metrics: %{
        accuracy: 0,
        precision: 0,
        recall: 0,
        f1_score: 0,
        samples_processed: 0,
        inference_latency: 0
      }
    }
  end

  @doc """
  List available ML models.

  Fetches model list from the ML service. If the service is unavailable,
  returns a 503 error response.
  """
  def list_models(conn, _params) do
    case fetch_ml_models() do
      {:ok, models} ->
        json(conn, %{data: models})

      {:error, reason} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{
          error: "ml_service_unavailable",
          message: "Could not retrieve models from ML service: #{inspect(reason)}"
        })
    end
  end

  @doc """
  Get detailed model information.
  """
  def model_info(conn, _params) do
    case MLClient.model_info() do
      {:ok, info} ->
        json(conn, %{
          data: %{
            version: info["model_version"],
            encoder: info["encoder"],
            latent_dim: info["latent_dim"],
            similarity_markers: info["similarity_markers"],
            dissimilarity_markers: info["dissimilarity_markers"],
            training_samples: info["training_samples"],
            accuracy: info["accuracy"],
            zsl_recall: info["zsl_recall"],
            device: info["device"],
            trained: info["training_samples"] > 0
          }
        })

      {:error, reason} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{error: "ml_service_unavailable", message: inspect(reason)})
    end
  end

  # -------------------------------------------------------------------
  # Predictions
  # -------------------------------------------------------------------

  @doc """
  Analyze a single binary sample.

  ## Request Body
  - content: Base64-encoded binary content
  - sha256: SHA256 hash of the binary
  - file_type: Type of file (pe, elf, script, unknown)
  - entropy: Pre-calculated entropy (optional)
  """
  def predict(conn, params) do
    case build_prediction_sample(params) do
      {:ok, sample} ->
        case MLClient.predict(sample) do
          {:ok, prediction} ->
            # Also trigger alert creation if malicious
            if prediction.prediction == "malicious" do
              Engine.analyze_binary(sample)
            end

            json(conn, %{
              data: %{
                sha256: params["sha256"],
                prediction: prediction.prediction,
                confidence: Float.round(prediction.confidence, 4),
                malware_family: prediction.malware_family,
                s_space_distance: Float.round(prediction.s_space_distance || 0.0, 4),
                similar_samples: prediction.similar_samples || [],
                processing_time_ms: prediction.processing_time_ms,
                model_version: prediction.model_version,
                threat_assessment: assess_threat(prediction)
              }
            })

          {:error, :ml_service_unavailable} ->
            conn
            |> put_status(:service_unavailable)
            |> json(%{
              error: "ml_service_unavailable",
              message: "ML service is not reachable. Circuit breaker is open. Try again later."
            })

          {:error, reason} ->
            conn
            |> put_status(:service_unavailable)
            |> json(%{error: "prediction_failed", message: inspect(reason)})
        end

      {:error, message} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "invalid_request", message: message})
    end
  end

  @doc """
  Analyze multiple binary samples in batch.

  ## Request Body
  - samples: List of sample objects with content, sha256, file_type, entropy
  """
  def predict_batch(conn, %{"samples" => samples}) when is_list(samples) do
    case build_prediction_samples(samples) do
      {:ok, parsed_samples} ->
        case MLClient.predict_batch(parsed_samples) do
          {:ok, predictions} ->
            results = Enum.zip(samples, predictions)
            |> Enum.map(fn {sample, prediction} ->
              %{
                sha256: sample["sha256"],
                prediction: prediction.prediction,
                confidence: Float.round(prediction.confidence, 4),
                malware_family: prediction.malware_family,
                threat_assessment: assess_threat(prediction)
              }
            end)

            # Calculate batch statistics
            stats = calculate_batch_stats(predictions)

            json(conn, %{
              data: %{
                predictions: results,
                statistics: stats,
                total_samples: length(samples)
              }
            })

          {:error, :ml_service_unavailable} ->
            conn
            |> put_status(:service_unavailable)
            |> json(%{
              error: "ml_service_unavailable",
              message: "ML service is not reachable. Circuit breaker is open. Try again later."
            })

          {:error, reason} ->
            conn
            |> put_status(:service_unavailable)
            |> json(%{error: "batch_prediction_failed", message: inspect(reason)})
        end

      {:error, message} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "invalid_request", message: message})
    end
  end

  def predict_batch(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "invalid_request", message: "samples array required"})
  end

  # -------------------------------------------------------------------
  # Model Management
  # -------------------------------------------------------------------

  @doc """
  Request model reload (after weight updates).
  """
  def reload_model(conn, _params) do
    # This would call the ML service reload endpoint
    url = System.get_env("ML_SERVICE_URL", "http://localhost:8000")
    request = Finch.build(:post, "#{url}/model/reload", [
      {"content-type", "application/json"}
    ])

    case Finch.request(request, TamanduaServer.Finch, receive_timeout: 30_000) do
      {:ok, %{status: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, result} ->
            json(conn, %{
              data: %{
                status: "reloaded",
                version: result["version"],
                message: "Model reloaded successfully"
              }
            })

          {:error, _} ->
            json(conn, %{data: %{status: "reloaded", message: "Model reloaded"}})
        end

      {:ok, %{status: status}} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{error: "reload_failed", message: "ML service returned #{status}"})

      {:error, reason} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{error: "reload_failed", message: inspect(reason)})
    end
  end

  # -------------------------------------------------------------------
  # Statistics & Metrics
  # -------------------------------------------------------------------

  @doc """
  Get ML prediction statistics.
  """
  def statistics(conn, _params) do
    detection_stats = Engine.get_stats()

    # Get cache stats
    cache_stats = get_prediction_cache_stats()

    json(conn, %{
      data: %{
        predictions: %{
          total: detection_stats.ml_predictions,
          cached: cache_stats.hits,
          cache_miss: cache_stats.misses
        },
        detections: %{
          total: detection_stats.detections,
          alerts_created: detection_stats.alerts_created
        },
        model: get_model_summary()
      }
    })
  end

  @doc """
  Get ML prediction history with optional filters.
  """
  def prediction_history(conn, params) do
    limit = bounded_limit(params["limit"], 100, 250)
    offset = bounded_offset(params["offset"])
    prediction_type = normalize_filter(params["prediction"])

    # Query from alerts that were created by ML
    import Ecto.Query

    query =
      from(a in TamanduaServer.Alerts.Alert,
        where:
          ilike(a.title, "ML Detection:%") or
            ilike(a.title, "Malware detected:%") or
            ilike(a.title, "Agent detection: OFFLINE_ML%") or
            fragment("lower(coalesce(?->>'detection_type', '')) = 'ml'", a.detection_metadata) or
            fragment("lower(coalesce(?->>'source', '')) = 'ml'", a.detection_metadata) or
            fragment("lower(coalesce(?->>'detection_source', '')) = 'ml'", a.detection_metadata) or
            fragment("lower(coalesce(?->>'rule_name', '')) LIKE 'offline_ml%'", a.detection_metadata) or
            fragment("coalesce(?->>'onnx_model_version', '') != ''", a.detection_metadata) or
            fragment("coalesce(?->>'ml_model', '') != ''", a.detection_metadata),
        order_by: [desc: a.inserted_at],
        limit: ^limit,
        offset: ^offset
      )

    query =
      if prediction_type do
        where(
          query,
          [a],
          ilike(a.title, ^"%#{prediction_type}%") or
            fragment("lower(coalesce(?->>'prediction', '')) = lower(?)", a.detection_metadata, ^prediction_type) or
            fragment("lower(coalesce(?->>'rule_name', '')) LIKE lower(?)", a.detection_metadata, ^"%#{prediction_type}%")
        )
      else
        query
      end

    alerts = safe_repo_all(query, "ML prediction history")

    predictions =
      Enum.map(alerts, fn alert ->
        metadata = alert.detection_metadata || %{}

        %{
          id: alert.id,
          agent_id: alert.agent_id,
          prediction:
            metadata_field(metadata, "prediction") ||
              prediction_from_rule_name(metadata_field(metadata, "rule_name")) ||
              extract_prediction_from_title(alert.title),
          malware_family:
            metadata_field(metadata, "malware_family") ||
              metadata_field(metadata, "family") ||
              extract_family_from_title(alert.title),
          model_version:
            metadata_field(metadata, "model_version") ||
              metadata_field(metadata, "onnx_model_version") ||
              metadata_field(metadata, "ml_model"),
          confidence:
            metadata_field(metadata, "confidence") ||
              metadata_field(metadata, "ml_confidence"),
          threat_score: alert.threat_score,
          timestamp: alert.inserted_at
        }
      end)

    json(conn, %{
      data: predictions,
      meta: %{
        total: length(predictions),
        limit: limit,
        offset: offset
      }
    })
  end

  # -------------------------------------------------------------------
  # Training
  # -------------------------------------------------------------------

  @doc """
  Get available training datasets information.
  """
  def training_datasets(conn, _params) do
    # This would typically query the file system or database for available datasets
    datasets = [
      %{
        id: "synthetic",
        name: "Synthetic Dataset",
        description: "Auto-generated synthetic samples for testing",
        samples: %{malware: 1000, goodware: 1000},
        ready: true
      },
      %{
        id: "telemetry",
        name: "Telemetry Dataset",
        description: "Samples collected from agent telemetry",
        samples: count_telemetry_samples(),
        ready: count_telemetry_samples()[:total] > 200
      }
    ]

    json(conn, %{data: datasets})
  end

  @doc """
  Trigger model training (async job).
  """
  def start_training(conn, params) do
    dataset_id = params["dataset_id"] || "synthetic"
    epochs = parse_int(params["epochs"], 50)
    batch_size = parse_int(params["batch_size"], 32)

    # Queue training job via Oban
    job_params = %{
      "dataset_id" => dataset_id,
      "epochs" => epochs,
      "batch_size" => batch_size,
      "requested_by" => get_current_user_id(conn),
      "requested_at" => DateTime.utc_now() |> DateTime.to_iso8601()
    }

    case TamanduaServer.Jobs.MLTrainingJob.new(job_params) |> Oban.insert() do
      {:ok, job} ->
        conn
        |> put_status(:accepted)
        |> json(%{
          data: %{
            job_id: job.id,
            status: "queued",
            message: "Training job queued",
            config: %{
              dataset: dataset_id,
              epochs: epochs,
              batch_size: batch_size
            }
          }
        })

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "job_creation_failed", details: inspect(changeset.errors)})
    end
  rescue
    e ->
      conn
      |> put_status(:internal_server_error)
      |> json(%{error: "training_failed", message: Exception.message(e)})
  end

  @doc """
  Trigger model training - simplified endpoint for MLDashboard.tsx.

  ## Request Body (from MLDashboard.tsx)
  - dataset: Dataset name/id
  - epochs: Number of training epochs
  - batch_size: Training batch size
  """
  def train(conn, params) do
    # Map frontend param names to internal format
    dataset_id = params["dataset"] || params["dataset_id"] || "synthetic"
    epochs = parse_int(params["epochs"], 50)
    batch_size = parse_int(params["batch_size"], 32)

    # First, try to forward to the real ML service
    case forward_training_request(dataset_id, epochs, batch_size) do
      {:ok, response} ->
        conn
        |> put_status(:accepted)
        |> json(%{
          data: %{
            status: "started",
            message: "Training initiated on ML service",
            job_id: response["job_id"],
            config: %{
              dataset: dataset_id,
              epochs: epochs,
              batch_size: batch_size
            }
          }
        })

      {:error, :service_unavailable} ->
        # Fall back to local job queue if ML service is unavailable
        job_params = %{
          "dataset_id" => dataset_id,
          "epochs" => epochs,
          "batch_size" => batch_size,
          "requested_by" => get_current_user_id(conn),
          "requested_at" => DateTime.utc_now() |> DateTime.to_iso8601()
        }

        case queue_training_job(job_params) do
          {:ok, job} ->
            conn
            |> put_status(:accepted)
            |> json(%{
              data: %{
                status: "queued",
                message: "Training job queued (ML service unavailable, using local queue)",
                job_id: job.id,
                config: %{
                  dataset: dataset_id,
                  epochs: epochs,
                  batch_size: batch_size
                }
              }
            })

          {:error, reason} ->
            conn
            |> put_status(:service_unavailable)
            |> json(%{
              error: "training_unavailable",
              message: "ML service unavailable and local queue failed: #{inspect(reason)}"
            })
        end

      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "training_failed", message: inspect(reason)})
    end
  end

  @doc """
  Get training job status.

  First attempts to fetch real training status from the ML service
  (GET /training/status/{job_id}). If that fails, falls back to
  looking up the Oban job in the local database.
  """
  def training_status(conn, %{"job_id" => job_id}) do
    # Try the ML service first for real-time training status
    case MLClient.get_training_status(job_id) do
      {:ok, status} ->
        json(conn, %{
          data: %{
            job_id: status["job_id"] || job_id,
            status: status["status"],
            progress: status["progress"],
            current_epoch: status["current_epoch"],
            total_epochs: status["total_epochs"],
            train_loss: status["train_loss"],
            val_loss: status["val_loss"],
            started_at: status["started_at"],
            completed_at: status["completed_at"],
            error: status["error"]
          }
        })

      {:error, :not_found} ->
        # Fall back to Oban job lookup
        fetch_oban_training_status(conn, job_id)

      {:error, _reason} ->
        # ML service unavailable, try Oban
        fetch_oban_training_status(conn, job_id)
    end
  end

  # -------------------------------------------------------------------
  # Private Helpers
  # -------------------------------------------------------------------

  defp build_prediction_sample(params) when is_map(params) do
    with {:ok, content} <- decode_sample_content(params["content"]) do
      {:ok,
       %{
         sha256: decode_hash(params["sha256"]),
         content: content,
         file_type: params["file_type"] || "unknown",
         entropy: params["entropy"] || 0.0,
         metadata: params["metadata"] || %{}
       }}
    end
  end

  defp build_prediction_sample(_params), do: {:error, "sample must be an object"}

  defp build_prediction_samples(samples) do
    result =
      samples
      |> Enum.with_index()
      |> Enum.reduce_while({:ok, []}, fn {sample, index}, {:ok, acc} ->
        case build_prediction_sample(sample) do
          {:ok, parsed} -> {:cont, {:ok, [parsed | acc]}}
          {:error, message} -> {:halt, {:error, "samples[#{index}]: #{message}"}}
        end
      end)

    case result do
      {:ok, parsed} -> {:ok, Enum.reverse(parsed)}
      error -> error
    end
  end

  defp decode_sample_content(content) when is_binary(content) and byte_size(content) > 0 do
    case Base.decode64(content) do
      {:ok, decoded} -> {:ok, decoded}
      :error -> {:error, "content must be valid base64"}
    end
  end

  defp decode_sample_content(_content), do: {:error, "content is required"}

  defp decode_hash(nil), do: <<>>
  defp decode_hash(hex) when is_binary(hex) do
    case Base.decode16(hex, case: :mixed) do
      {:ok, bytes} -> bytes
      :error -> <<>>
    end
  end

  defp assess_threat(prediction) do
    confidence = prediction.confidence || 0.0

    case prediction.prediction do
      "malicious" ->
        cond do
          confidence >= 0.95 -> %{level: "critical", action: "quarantine_immediately"}
          confidence >= 0.85 -> %{level: "high", action: "quarantine_recommended"}
          confidence >= 0.70 -> %{level: "medium", action: "investigate"}
          true -> %{level: "low", action: "monitor"}
        end

      "suspicious" ->
        %{level: "medium", action: "investigate"}

      "benign" ->
        %{level: "safe", action: "allow"}

      _ ->
        %{level: "unknown", action: "investigate"}
    end
  end

  defp calculate_batch_stats(predictions) do
    total = length(predictions)

    by_prediction = Enum.group_by(predictions, & &1.prediction)

    %{
      total: total,
      malicious: length(by_prediction["malicious"] || []),
      suspicious: length(by_prediction["suspicious"] || []),
      benign: length(by_prediction["benign"] || []),
      average_confidence: if(total > 0,
        do: Enum.sum(Enum.map(predictions, & &1.confidence)) / total,
        else: 0.0
      ),
      high_confidence_malicious: Enum.count(predictions, fn p ->
        p.prediction == "malicious" && p.confidence >= 0.85
      end)
    }
  end

  defp get_prediction_cache_stats do
    # Simplified cache stats
    %{hits: 0, misses: 0}
  end

  defp get_model_summary do
    case MLClient.model_info() do
      {:ok, info} ->
        %{
          version: info["model_version"],
          trained: info["training_samples"] > 0,
          accuracy: info["accuracy"]
        }

      {:error, _} ->
        %{version: "unknown", trained: false, accuracy: 0.0}
    end
  end

  defp count_telemetry_samples do
    # This would count actual samples from telemetry
    %{malware: 0, goodware: 0, total: 0}
  end

  defp extract_prediction_from_title(title) do
    if is_binary(title) and String.contains?(title, ["Malware detected", "ML Detection", "OFFLINE_ML"]),
      do: "malicious",
      else: "unknown"
  end

  defp extract_family_from_title(title) when is_binary(title) do
    case Regex.run(~r/(?:Malware detected|ML Detection): (.+)$/, title) do
      [_, family] -> family
      _ -> nil
    end
  end

  defp extract_family_from_title(_), do: nil

  defp parse_int(nil, default), do: default
  defp parse_int(val, default) when is_binary(val) do
    case Integer.parse(val) do
      {int, _} -> int
      :error -> default
    end
  end
  defp parse_int(val, _) when is_integer(val), do: val
  defp parse_int(_, default), do: default

  defp bounded_limit(value, default, max_limit) do
    value
    |> parse_int(default)
    |> max(1)
    |> min(max_limit)
  end

  defp bounded_offset(value) do
    value
    |> parse_int(0)
    |> max(0)
  end

  defp normalize_filter(value) when is_binary(value) do
    value = String.trim(value)
    if value == "", do: nil, else: value
  end

  defp normalize_filter(_), do: nil

  defp metadata_field(metadata, key) when is_map(metadata) do
    Map.get(metadata, key) || Map.get(metadata, metadata_atom_key(key))
  end

  defp metadata_field(_, _), do: nil

  defp metadata_atom_key("prediction"), do: :prediction
  defp metadata_atom_key("rule_name"), do: :rule_name
  defp metadata_atom_key("malware_family"), do: :malware_family
  defp metadata_atom_key("family"), do: :family
  defp metadata_atom_key("model_version"), do: :model_version
  defp metadata_atom_key("onnx_model_version"), do: :onnx_model_version
  defp metadata_atom_key("ml_model"), do: :ml_model
  defp metadata_atom_key("confidence"), do: :confidence
  defp metadata_atom_key("ml_confidence"), do: :ml_confidence
  defp metadata_atom_key(_), do: nil

  defp prediction_from_rule_name(rule_name) when is_binary(rule_name) do
    rule_name
    |> String.downcase()
    |> then(fn
      "offline_ml" <> _ -> "malicious"
      "ml_" <> _ -> "malicious"
      _ -> nil
    end)
  end

  defp prediction_from_rule_name(_), do: nil

  defp safe_repo_all(query, label) do
    TamanduaServer.Repo.all(query, timeout: 8_000)
  rescue
    exception ->
      Logger.warning("[MLController] #{label} failed: #{Exception.message(exception)}")
      []
  catch
    :exit, reason ->
      Logger.warning("[MLController] #{label} failed: exit #{inspect(reason)}")
      []
  end

  # -------------------------------------------------------------------
  # ML Service Communication Helpers
  # -------------------------------------------------------------------

  defp ml_service_url do
    System.get_env("ML_SERVICE_URL") ||
      Application.get_env(:tamandua_server, :ml_service_url) ||
      @ml_service_url
  end

  @doc false
  defp fetch_ml_metrics do
    url = "#{ml_service_url()}/metrics"
    request = Finch.build(:get, url, [{"accept", "application/json"}])

    case Finch.request(request, TamanduaServer.Finch, receive_timeout: 5_000) do
      {:ok, %{status: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, data} ->
            # Transform ML service response to frontend format
            {:ok, transform_ml_metrics(data)}

          {:error, _} = error ->
            error
        end

      {:ok, %{status: status}} ->
        {:error, {:http_error, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp transform_ml_metrics(data) do
    # The ML service may return metrics in various formats
    # Transform to the format expected by DynamicDetection.tsx
    %{
      model_name: data["model_name"] || data["name"] || "Malware-SMELL",
      version: data["version"] || data["model_version"] || "1.0.0",
      accuracy: normalize_metric(data["accuracy"]),
      precision: normalize_metric(data["precision"]),
      recall: normalize_metric(data["recall"]),
      f1_score: normalize_metric(data["f1_score"] || data["f1"]),
      last_trained: data["last_trained"] || data["trained_at"] || DateTime.utc_now() |> DateTime.to_iso8601(),
      samples_processed: data["samples_processed"] || data["total_predictions"] || 0,
      inference_latency: data["inference_latency"] || data["avg_latency_ms"] || 0
    }
  end

  # Convert metrics from 0-1 range to 0-100 if needed
  defp normalize_metric(nil), do: 0.0
  defp normalize_metric(val) when is_number(val) and val <= 1.0, do: val * 100
  defp normalize_metric(val) when is_number(val), do: val
  defp normalize_metric(_), do: 0.0

  # mock_ml_metrics/0 has been removed. The metrics/2 action now returns
  # a proper 503 error when the ML service is unavailable instead of
  # serving fabricated data.

  defp fetch_ml_models do
    ["/predict/models", "/models/versions", "/models"]
    |> Enum.reduce_while({:error, :not_attempted}, fn path, _last_error ->
      url = "#{ml_service_url()}#{path}"
      request = Finch.build(:get, url, [{"accept", "application/json"}])

      case Finch.request(request, TamanduaServer.Finch, receive_timeout: 5_000) do
        {:ok, %{status: 200, body: body}} ->
          case Jason.decode(body) do
            {:ok, data} -> {:halt, {:ok, normalize_model_list(data)}}
            {:error, reason} -> {:cont, {:error, {:invalid_json, path, reason}}}
          end

        {:ok, %{status: status}} ->
          {:cont, {:error, {:http_error, path, status}}}

        {:error, reason} ->
          {:cont, {:error, {path, reason}}}
      end
    end)
  end

  defp normalize_model_list(%{"data" => models}) when is_list(models), do: models
  defp normalize_model_list(%{"models" => models}) when is_list(models), do: models
  defp normalize_model_list(%{"versions" => versions}) when is_list(versions), do: versions
  defp normalize_model_list(models) when is_list(models), do: models
  defp normalize_model_list(model) when is_map(model), do: [model]
  defp normalize_model_list(_), do: []

  defp forward_training_request(dataset_id, epochs, batch_size) do
    url = "#{ml_service_url()}/train"

    body = Jason.encode!(%{
      dataset: dataset_id,
      epochs: epochs,
      batch_size: batch_size
    })

    request = Finch.build(:post, url, [
      {"content-type", "application/json"},
      {"accept", "application/json"}
    ], body)

    case Finch.request(request, TamanduaServer.Finch, receive_timeout: 30_000) do
      {:ok, %{status: status, body: response_body}} when status in [200, 201, 202] ->
        case Jason.decode(response_body) do
          {:ok, data} -> {:ok, data}
          {:error, _} -> {:ok, %{"status" => "started"}}
        end

      {:ok, %{status: 503}} ->
        {:error, :service_unavailable}

      {:ok, %{status: status, body: body}} ->
        {:error, {:http_error, status, body}}

      {:error, %Mint.TransportError{}} ->
        {:error, :service_unavailable}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp queue_training_job(job_params) do
    # Try to queue via Oban if available
    try do
      case TamanduaServer.Jobs.MLTrainingJob.new(job_params) |> Oban.insert() do
        {:ok, job} -> {:ok, job}
        {:error, changeset} -> {:error, changeset.errors}
      end
    rescue
      UndefinedFunctionError ->
        {:error, :training_worker_unavailable}

      e ->
        {:error, Exception.message(e)}
    end
  end

  defp get_current_user_id(conn) do
    case conn.assigns[:current_user] do
      %{id: id} -> id
      %{"id" => id} -> id
      _ -> nil
    end
  end

  defp fetch_oban_training_status(conn, job_id) do
    case parse_int(job_id, nil) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "not_found", message: "Training job not found"})

      int_id ->
        case Oban.Job |> TamanduaServer.Repo.get(int_id) do
          nil ->
            conn
            |> put_status(:not_found)
            |> json(%{error: "not_found", message: "Training job not found"})

          job ->
            json(conn, %{
              data: %{
                job_id: job.id,
                status: job.state,
                inserted_at: job.inserted_at,
                attempted_at: job.attempted_at,
                completed_at: job.completed_at,
                errors: job.errors,
                args: job.args
              }
            })
        end
    end
  end
end
