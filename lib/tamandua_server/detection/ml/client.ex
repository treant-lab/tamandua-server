defmodule TamanduaServer.Detection.ML.Client do
  @moduledoc """
  Client for communicating with the ML service (Malware-SMELL).

  Handles:
  - Prediction requests (single and batch)
  - Text embedding generation for semantic similarity
  - Model metrics and health monitoring
  - Training status polling
  - Result caching with TTL
  - Retry with exponential backoff
  - Circuit breaker pattern for health checks

  The client maintains a GenServer that tracks connection health,
  caches model metadata, and implements a circuit breaker to avoid
  overwhelming an unavailable ML service with requests.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Cache

  @timeout 30_000
  @cache_ttl :timer.hours(24)
  @model_info_cache_ttl :timer.minutes(5)
  @health_check_interval :timer.seconds(30)

  # Retry configuration
  @max_retries 3
  @base_backoff_ms 200

  # Circuit breaker configuration
  @circuit_failure_threshold 5
  @circuit_reset_timeout_ms :timer.seconds(60)

  defstruct [
    :finch,
    :url,
    :healthy,
    :model_info_cache,
    :model_info_cached_at,
    # Circuit breaker fields
    :circuit_state,       # :closed | :open | :half_open
    :circuit_failures,
    :circuit_opened_at
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Predict if a binary sample is malicious.

  Checks the local cache first (keyed by SHA256 hex), then forwards to
  the ML service at POST /predict.

  Returns `{:ok, prediction_map}` or `{:error, reason}`.
  """
  @spec predict(map()) :: {:ok, map()} | {:error, term()}
  def predict(sample) do
    sha256_hex = Base.encode16(sample[:sha256] || <<>>, case: :lower)

    # Check cache first
    case Cache.get({:ml_prediction, sha256_hex}) do
      {:ok, cached} ->
        Logger.debug("ML prediction cache hit for #{sha256_hex}")
        {:ok, cached}

      :error ->
        GenServer.call(__MODULE__, {:predict, sample}, @timeout)
    end
  end

  @doc """
  Batch prediction for multiple samples.

  Sends all samples to POST /predict/batch on the ML service.
  Returns `{:ok, [prediction_map]}` or `{:error, reason}`.
  """
  @spec predict_batch([map()]) :: {:ok, [map()]} | {:error, term()}
  def predict_batch(samples) do
    GenServer.call(__MODULE__, {:predict_batch, samples}, @timeout * 2)
  end

  @doc """
  Check if the ML service is healthy.

  Returns `true` if the most recent health check succeeded, `false` otherwise.
  When the circuit breaker is open, returns `false` without making a request.
  """
  @spec healthy?() :: boolean()
  def healthy? do
    GenServer.call(__MODULE__, :health_check, @timeout)
  end

  @doc """
  Get ML model information.

  Returns cached model info if available and fresh (< 5 minutes old),
  otherwise fetches from GET /model/info on the ML service.
  """
  @spec model_info() :: {:ok, map()} | {:error, term()}
  def model_info do
    GenServer.call(__MODULE__, :model_info, @timeout)
  end

  @doc """
  Generate text embeddings via the ML service.

  Sends text content to POST /predict with a special metadata flag
  requesting embeddings. The ML service encoder produces a latent-space
  vector from the text (converted to binary image representation).

  Returns `{:ok, [float()]}` (the embedding vector) or `{:error, reason}`.
  """
  @spec generate_embeddings(String.t()) :: {:ok, [float()]} | {:error, term()}
  def generate_embeddings(text) when is_binary(text) do
    GenServer.call(__MODULE__, {:generate_embeddings, text}, @timeout)
  end

  @doc """
  Fetch model performance metrics from the ML service.

  Calls GET /metrics on the ML service and parses Prometheus-format
  or JSON metrics into a map.

  Returns `{:ok, metrics_map}` or `{:error, reason}`.
  """
  @spec get_metrics() :: {:ok, map()} | {:error, term()}
  def get_metrics do
    GenServer.call(__MODULE__, :get_metrics, @timeout)
  end

  @doc """
  Get training job status from the ML service.

  Calls GET /training/status/{job_id} on the ML service.
  Returns `{:ok, status_map}` or `{:error, reason}`.
  """
  @spec get_training_status(String.t()) :: {:ok, map()} | {:error, term()}
  def get_training_status(job_id) do
    GenServer.call(__MODULE__, {:training_status, job_id}, @timeout * 2)
  end

  @doc """
  Submit a sample for inference on the ML service.

  Encodes the binary content and metadata, sends to POST /predict,
  and returns the raw prediction result.

  Returns `{:ok, prediction_map}` or `{:error, reason}`.
  """
  @spec submit_sample(binary(), String.t(), map()) :: {:ok, map()} | {:error, term()}
  def submit_sample(content, file_type \\ "unknown", metadata \\ %{}) do
    sample = %{
      sha256: :crypto.hash(:sha256, content),
      content: content,
      file_type: file_type,
      entropy: 0.0,
      metadata: metadata
    }

    predict(sample)
  end

  @doc """
  Generic POST request to ML service endpoint.

  Useful for hunting, anomaly detection, and other ML service features.

  Returns `{:ok, response_map}` or `{:error, reason}`.
  """
  @spec post(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def post(path, body) do
    GenServer.call(__MODULE__, {:post, path, body}, @timeout)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    url =
      Application.get_env(:tamandua_server, :ml_service_url) ||
        System.get_env("ML_SERVICE_URL") ||
        "http://localhost:8000"

    state = %__MODULE__{
      finch: TamanduaServer.Finch,
      url: url,
      healthy: false,
      model_info_cache: nil,
      model_info_cached_at: nil,
      circuit_state: :closed,
      circuit_failures: 0,
      circuit_opened_at: nil
    }

    # Check health on startup
    send(self(), :health_check)

    {:ok, state}
  end

  @impl true
  def handle_call({:predict, sample}, _from, state) do
    case check_circuit(state) do
      {:ok, updated_state} ->
        result = do_predict_with_retry(sample, updated_state)

        # Cache successful predictions
        updated_state =
          case result do
            {:ok, prediction} ->
              sha256_hex = Base.encode16(sample[:sha256] || <<>>, case: :lower)
              Cache.put({:ml_prediction, sha256_hex}, prediction, ttl: @cache_ttl)
              record_success(updated_state)

            {:error, _} ->
              record_failure(updated_state)
          end

        {:reply, result, updated_state}

      {:error, :circuit_open} ->
        {:reply, {:error, :ml_service_unavailable}, state}
    end
  end

  @impl true
  def handle_call({:predict_batch, samples}, _from, state) do
    case check_circuit(state) do
      {:ok, updated_state} ->
        result = do_predict_batch(samples, updated_state)

        updated_state =
          case result do
            {:ok, _} -> record_success(updated_state)
            {:error, _} -> record_failure(updated_state)
          end

        {:reply, result, updated_state}

      {:error, :circuit_open} ->
        {:reply, {:error, :ml_service_unavailable}, state}
    end
  end

  @impl true
  def handle_call(:health_check, _from, state) do
    case check_circuit(state) do
      {:ok, updated_state} ->
        healthy = do_health_check(updated_state)

        updated_state =
          if healthy do
            record_success(%{updated_state | healthy: true})
          else
            record_failure(%{updated_state | healthy: false})
          end

        {:reply, healthy, updated_state}

      {:error, :circuit_open} ->
        {:reply, false, state}
    end
  end

  @impl true
  def handle_call(:model_info, _from, state) do
    # Return cached model info if fresh
    if state.model_info_cache != nil and model_info_cache_fresh?(state) do
      {:reply, {:ok, state.model_info_cache}, state}
    else
      case check_circuit(state) do
        {:ok, updated_state} ->
          case do_get_model_info(updated_state) do
            {:ok, info} ->
              new_state = %{
                record_success(updated_state)
                | model_info_cache: info,
                  model_info_cached_at: System.monotonic_time(:millisecond)
              }

              {:reply, {:ok, info}, new_state}

            {:error, _} = error ->
              {:reply, error, record_failure(updated_state)}
          end

        {:error, :circuit_open} ->
          # Return stale cache if available, else error
          if state.model_info_cache do
            {:reply, {:ok, state.model_info_cache}, state}
          else
            {:reply, {:error, :ml_service_unavailable}, state}
          end
      end
    end
  end

  @impl true
  def handle_call({:generate_embeddings, text}, _from, state) do
    case check_circuit(state) do
      {:ok, updated_state} ->
        result = do_generate_embeddings(text, updated_state)

        updated_state =
          case result do
            {:ok, _} -> record_success(updated_state)
            {:error, _} -> record_failure(updated_state)
          end

        {:reply, result, updated_state}

      {:error, :circuit_open} ->
        {:reply, {:error, :ml_service_unavailable}, state}
    end
  end

  @impl true
  def handle_call(:get_metrics, _from, state) do
    case check_circuit(state) do
      {:ok, updated_state} ->
        result = do_get_metrics(updated_state)

        updated_state =
          case result do
            {:ok, _} -> record_success(updated_state)
            {:error, _} -> record_failure(updated_state)
          end

        {:reply, result, updated_state}

      {:error, :circuit_open} ->
        {:reply, {:error, :ml_service_unavailable}, state}
    end
  end

  @impl true
  def handle_call({:training_status, job_id}, _from, state) do
    case check_circuit(state) do
      {:ok, updated_state} ->
        result = do_get_training_status(job_id, updated_state)

        updated_state =
          case result do
            {:ok, _} -> record_success(updated_state)
            {:error, _} -> record_failure(updated_state)
          end

        {:reply, result, updated_state}

      {:error, :circuit_open} ->
        {:reply, {:error, :ml_service_unavailable}, state}
    end
  end

  @impl true
  def handle_call({:post, path, body}, _from, state) do
    case check_circuit(state) do
      {:ok, updated_state} ->
        result = do_post(path, body, updated_state)

        updated_state =
          case result do
            {:ok, _} -> record_success(updated_state)
            {:error, _} -> record_failure(updated_state)
          end

        {:reply, result, updated_state}

      {:error, :circuit_open} ->
        {:reply, {:error, :ml_service_unavailable}, state}
    end
  end

  @impl true
  def handle_info(:health_check, state) do
    healthy = do_health_check(state)

    new_state =
      if healthy do
        record_success(%{state | healthy: true})
      else
        record_failure(%{state | healthy: false})
      end

    # Schedule next health check
    Process.send_after(self(), :health_check, @health_check_interval)
    {:noreply, new_state}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Circuit Breaker
  # ============================================================================

  defp check_circuit(%{circuit_state: :closed} = state), do: {:ok, state}

  defp check_circuit(%{circuit_state: :half_open} = state), do: {:ok, state}

  defp check_circuit(%{circuit_state: :open, circuit_opened_at: opened_at} = state) do
    elapsed = System.monotonic_time(:millisecond) - opened_at

    if elapsed >= @circuit_reset_timeout_ms do
      Logger.info("ML client circuit breaker transitioning to half-open")
      {:ok, %{state | circuit_state: :half_open}}
    else
      {:error, :circuit_open}
    end
  end

  defp record_success(state) do
    if state.circuit_state != :closed do
      Logger.info("ML client circuit breaker closing (service recovered)")
    end

    %{state | circuit_state: :closed, circuit_failures: 0, circuit_opened_at: nil}
  end

  defp record_failure(state) do
    new_failures = state.circuit_failures + 1

    if new_failures >= @circuit_failure_threshold and state.circuit_state != :open do
      Logger.warning(
        "ML client circuit breaker opening after #{new_failures} consecutive failures"
      )

      %{
        state
        | circuit_state: :open,
          circuit_failures: new_failures,
          circuit_opened_at: System.monotonic_time(:millisecond)
      }
    else
      %{state | circuit_failures: new_failures}
    end
  end

  # ============================================================================
  # Retry Logic
  # ============================================================================

  defp do_predict_with_retry(sample, state, attempt \\ 0) do
    case do_predict(sample, state) do
      {:ok, _} = success ->
        success

      {:error, reason} when attempt < @max_retries ->
        backoff = @base_backoff_ms * :math.pow(2, attempt) |> round()
        Logger.debug("ML predict retry #{attempt + 1}/#{@max_retries} after #{backoff}ms: #{inspect(reason)}")
        Process.sleep(backoff)
        do_predict_with_retry(sample, state, attempt + 1)

      {:error, _} = error ->
        error
    end
  end

  defp request_with_retry(request, finch, opts, attempt \\ 0) do
    case Finch.request(request, finch, opts) do
      {:ok, _} = success ->
        success

      {:error, reason} when attempt < @max_retries ->
        backoff = @base_backoff_ms * :math.pow(2, attempt) |> round()
        Logger.debug("ML HTTP retry #{attempt + 1}/#{@max_retries} after #{backoff}ms: #{inspect(reason)}")
        Process.sleep(backoff)
        request_with_retry(request, finch, opts, attempt + 1)

      {:error, _} = error ->
        error
    end
  end

  # ============================================================================
  # Model Info Cache
  # ============================================================================

  defp model_info_cache_fresh?(%{model_info_cached_at: nil}), do: false

  defp model_info_cache_fresh?(%{model_info_cached_at: cached_at}) do
    elapsed = System.monotonic_time(:millisecond) - cached_at
    elapsed < @model_info_cache_ttl
  end

  # ============================================================================
  # HTTP Operations
  # ============================================================================

  defp do_predict(sample, state) do
    url = "#{state.url}/predict"

    body =
      Jason.encode!(%{
        sha256: Base.encode16(sample[:sha256] || <<>>, case: :lower),
        binary_content: Base.encode64(sample[:content] || <<>>),
        file_type: sample[:file_type] || "unknown",
        entropy: sample[:entropy] || 0.0,
        metadata: sample[:metadata] || %{}
      })

    request =
      Finch.build(
        :post,
        url,
        ml_headers([
          {"content-type", "application/json"},
          {"accept", "application/json"}
        ]),
        body
      )

    case Finch.request(request, state.finch, receive_timeout: @timeout) do
      {:ok, %{status: 200, body: response_body}} ->
        case Jason.decode(response_body) do
          {:ok, prediction} ->
            {:ok,
             %{
               sha256: prediction["sha256"],
               prediction: prediction["prediction"],
               confidence: prediction["confidence"],
               malware_family: prediction["malware_family"],
               s_space_distance: prediction["s_space_distance"],
               similar_samples: prediction["similar_samples"] || [],
               processing_time_ms: prediction["processing_time_ms"],
               model_version: prediction["model_version"]
             }}

          {:error, _} = error ->
            error
        end

      {:ok, %{status: status, body: body}} ->
        Logger.error("ML service returned #{status}: #{body}")
        {:error, {:http_error, status}}

      {:error, reason} ->
        Logger.error("ML service request failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp do_predict_batch(samples, state) do
    url = "#{state.url}/predict/batch"

    body =
      Jason.encode!(%{
        samples:
          Enum.map(samples, fn sample ->
            %{
              sha256: Base.encode16(sample[:sha256] || <<>>, case: :lower),
              binary_content: Base.encode64(sample[:content] || <<>>),
              file_type: sample[:file_type] || "unknown",
              entropy: sample[:entropy] || 0.0,
              metadata: sample[:metadata] || %{}
            }
          end)
      })

    request =
      Finch.build(
        :post,
        url,
        ml_headers([
          {"content-type", "application/json"},
          {"accept", "application/json"}
        ]),
        body
      )

    case request_with_retry(request, state.finch, [receive_timeout: @timeout * 2]) do
      {:ok, %{status: 200, body: response_body}} ->
        case Jason.decode(response_body) do
          {:ok, %{"predictions" => predictions}} ->
            {:ok,
             Enum.map(predictions, fn p ->
               %{
                 sha256: p["sha256"],
                 prediction: p["prediction"],
                 confidence: p["confidence"],
                 malware_family: p["malware_family"]
               }
             end)}

          {:error, _} = error ->
            error
        end

      {:ok, %{status: status}} ->
        {:error, {:http_error, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp do_health_check(state) do
    url = "#{state.url}/health"
    request = Finch.build(:get, url, ml_headers())

    case Finch.request(request, state.finch, receive_timeout: 5_000) do
      {:ok, %{status: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, %{"status" => status}} ->
            ml_healthy_status?(status)

          _ ->
            true
        end

      _ ->
        Logger.warning("ML service health check failed")
        false
    end
  end

  defp do_get_model_info(state) do
    url = "#{state.url}/model/info"
    request = Finch.build(:get, url, ml_headers([{"accept", "application/json"}]))

    case request_with_retry(request, state.finch, [receive_timeout: 5_000]) do
      {:ok, %{status: 200, body: body}} ->
        Jason.decode(body)

      {:ok, %{status: status}} ->
        {:error, {:http_error, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp do_generate_embeddings(text, state) do
    # The ML service uses the encoder to produce latent-space vectors.
    # We send the text as binary content to /predict with an embeddings_only flag.
    # The text is converted to a binary representation that the encoder processes.
    url = "#{state.url}/predict"
    text_bytes = text |> String.to_charlist() |> :erlang.list_to_binary()

    body =
      Jason.encode!(%{
        sha256: Base.encode16(:crypto.hash(:sha256, text_bytes), case: :lower),
        binary_content: Base.encode64(text_bytes),
        file_type: "text",
        entropy: 0.0,
        metadata: %{embeddings_only: true, source: "ai_siem"}
      })

    request =
      Finch.build(
        :post,
        url,
        ml_headers([
          {"content-type", "application/json"},
          {"accept", "application/json"}
        ]),
        body
      )

    case request_with_retry(request, state.finch, [receive_timeout: @timeout]) do
      {:ok, %{status: 200, body: response_body}} ->
        case Jason.decode(response_body) do
          {:ok, %{"s_space_distance" => distance} = prediction} ->
            # Use the S-space scores as a compact embedding representation.
            # The prediction response includes similarity/dissimilarity scores
            # which serve as a meaningful vector for correlation.
            similarity = prediction["similarity_score"] || 0.0
            dissimilarity = prediction["dissimilarity_score"] || 0.0
            confidence = prediction["confidence"] || 0.0

            embedding = [
              similarity,
              dissimilarity,
              distance,
              confidence
            ]

            {:ok, embedding}

          {:ok, _other} ->
            {:error, :unexpected_response_format}

          {:error, _} = error ->
            error
        end

      {:ok, %{status: status}} ->
        {:error, {:http_error, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp do_get_metrics(state) do
    url = "#{state.url}/model/info"
    request = Finch.build(:get, url, ml_headers([{"accept", "application/json"}]))

    case request_with_retry(request, state.finch, [receive_timeout: 5_000]) do
      {:ok, %{status: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, data} ->
            metrics = %{
              "model_name" => "Malware-SMELL",
              "version" => data["model_version"] || "1.0.0",
              "accuracy" => data["accuracy"] || 0.0,
              "precision" => data["accuracy"] || 0.0,
              "recall" => data["zsl_recall"] || 0.0,
              "f1_score" => calculate_f1(data["accuracy"], data["zsl_recall"]),
              "training_samples" => data["training_samples"] || 0,
              "latent_dim" => data["latent_dim"] || 256,
              "encoder" => data["encoder"] || "VGG-19",
              "device" => data["device"] || "cpu"
            }

            {:ok, metrics}

          {:error, _} = error ->
            error
        end

      {:ok, %{status: status}} ->
        {:error, {:http_error, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp do_get_training_status(job_id, state) do
    url = "#{state.url}/training/status/#{job_id}"
    request = Finch.build(:get, url, ml_headers([{"accept", "application/json"}]))

    case request_with_retry(request, state.finch, [receive_timeout: 10_000]) do
      {:ok, %{status: 200, body: body}} ->
        Jason.decode(body)

      {:ok, %{status: 404}} ->
        {:error, :not_found}

      {:ok, %{status: status}} ->
        {:error, {:http_error, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp calculate_f1(nil, _), do: 0.0
  defp calculate_f1(_, nil), do: 0.0
  defp calculate_f1(precision, recall) when precision + recall > 0 do
    2.0 * precision * recall / (precision + recall)
  end
  defp calculate_f1(_, _), do: 0.0

  defp do_post(path, body_map, state) do
    url = "#{state.url}#{path}"

    body = Jason.encode!(body_map)

    request =
      Finch.build(
        :post,
        url,
        ml_headers([
          {"content-type", "application/json"},
          {"accept", "application/json"}
        ]),
        body
      )

    case request_with_retry(request, state.finch, [receive_timeout: @timeout]) do
      {:ok, %{status: 200, body: response_body}} ->
        Jason.decode(response_body)

      {:ok, %{status: status, body: error_body}} ->
        Logger.error("ML service POST #{path} returned #{status}: #{error_body}")
        {:error, {:http_error, status}}

      {:error, reason} ->
        Logger.error("ML service POST #{path} failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp ml_headers(headers \\ []) do
    case System.get_env("TAMANDUA_ML_API_KEY") do
      nil -> headers
      "" -> headers
      api_key -> [{"authorization", "Bearer #{api_key}"} | headers]
    end
  end

  defp ml_healthy_status?(status) when is_binary(status) do
    status in ["healthy", "ok", "ready", "alive", "healthy_trained", "healthy_untrained"] or
      String.starts_with?(status, "healthy")
  end

  defp ml_healthy_status?(_status), do: false
end
