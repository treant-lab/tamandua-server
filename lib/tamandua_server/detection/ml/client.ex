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
  - Circuit breaker pattern shared across all callers

  ## Architecture (refactored)

  HTTP requests execute in the **caller's process** — the GenServer is no
  longer a serialization point. Previously every prediction funneled through
  `GenServer.call(__MODULE__, ..., 30_000)` while the server ran retries with
  `Process.sleep/1` inline (worst case ~2 minutes holding the singleton while
  callers exited at 30s). Now:

  - Concurrency is bounded by the shared Finch pool (`TamanduaServer.Finch`,
    `:default` pool), not by a singleton GenServer.
  - Circuit-breaker state lives in a public ETS table (`:tamandua_ml_client_circuit`)
    owned by the GenServer. Hot-path reads are plain `:ets.lookup/2`; state
    transitions are atomic (`:ets.select_replace/2` compare-and-swap and
    `:ets.update_counter/3`) performed from caller processes.
  - Half-open admits **exactly one** probe: the open→half-open transition is a
    CAS that also stamps the probe token, so concurrent callers racing at the
    reset deadline get at most one winner; everyone else receives a fast
    `{:error, :ml_service_unavailable}` until the probe resolves. A stale-probe
    reclaim (probe holder died without reporting) is also CAS-guarded.
  - The GenServer only owns the ETS table and runs the periodic background
    health check (every 30s).

  ## Circuit table layout

  Single record keyed by `:circuit`:

      {:circuit, state, failures, opened_at_ms, probe_acquired_at_ms}

  where `state` is `:closed | :open | :half_open`, timestamps are
  `System.monotonic_time(:millisecond)` (0 = unset). Plus `{:healthy, boolean}`
  (last background health-check result) and `{:model_info, info, cached_at_ms}`.

  ## Time budget

  Callers previously hit a 30s `GenServer.call` timeout while the server could
  spend far longer in retries. The retry ladder is now sized so that
  `attempts x receive_timeout + backoff sleeps (200 + 400ms)` fits inside the
  documented per-call budget (3 attempts = 1 initial + 2 retries):

  - `predict/1`, `generate_embeddings/1`, `post/2`:
    3 x 9_500ms + 600ms = 29_100ms  < 30_000ms budget
  - `predict_batch/1`: 3 x 19_500ms + 600ms = 59_100ms < 60_000ms budget
  - `model_info/0`, `get_metrics/0`: 3 x 5_000ms + 600ms = 15_600ms < 30_000ms
  - `get_training_status/1`: 3 x 10_000ms + 600ms = 30_600ms < 60_000ms
  - `healthy?/0`: single attempt, 5_000ms (no retry, unchanged)
  """

  use GenServer
  require Logger

  alias TamanduaServer.Cache

  @finch TamanduaServer.Finch
  @circuit_table :tamandua_ml_client_circuit

  # Prediction result cache TTL (Cache.put/3 takes seconds)
  @cache_ttl_seconds 86_400
  @model_info_cache_ttl :timer.minutes(5)
  @health_check_interval :timer.seconds(30)

  # Retry configuration — see "Time budget" in the moduledoc.
  # NOTE: @max_retries reduced 3 -> 2 and per-attempt receive_timeouts sized
  # so the total ladder fits the documented caller budget.
  @max_retries 2
  @base_backoff_ms 200
  @predict_receive_timeout_ms 9_500
  @batch_receive_timeout_ms 19_500
  @short_receive_timeout_ms 5_000
  @training_receive_timeout_ms 10_000
  @health_receive_timeout_ms 5_000

  # Circuit breaker configuration
  @circuit_failure_threshold 5
  @circuit_reset_timeout_ms :timer.seconds(60)
  # If a half-open probe holder dies without reporting, allow a new probe
  # after this long. Must exceed the worst-case single-call budget (batch:
  # ~59.1s) so a live probe is never preempted.
  @half_open_probe_stale_ms 65_000

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Predict if a binary sample is malicious.

  Checks the local cache first (keyed by SHA256 hex), then forwards to
  the ML service at POST /predict. The HTTP request runs in the caller's
  process, gated by the shared circuit breaker.

  Returns `{:ok, prediction_map}` or `{:error, reason}`.
  """
  @spec predict(map()) :: {:ok, map()} | {:error, term()}
  def predict(sample) do
    sha256_hex = Base.encode16(sample[:sha256] || <<>>, case: :lower)

    # Check cache first (Cache.get/1 returns {:ok, value} | :miss)
    case Cache.get({:ml_prediction, sha256_hex}) do
      {:ok, cached} ->
        Logger.debug("ML prediction cache hit for #{sha256_hex}")
        {:ok, cached}

      _miss ->
        with_circuit(fn ->
          case with_retry(fn -> do_predict(sample, service_url()) end, "ML predict") do
            {:ok, prediction} = ok ->
              Cache.put({:ml_prediction, sha256_hex}, prediction, @cache_ttl_seconds)
              ok

            {:error, _} = error ->
              error
          end
        end)
    end
  end

  @doc """
  Batch prediction for multiple samples.

  Sends all samples to POST /predict/batch on the ML service.
  Returns `{:ok, [prediction_map]}` or `{:error, reason}`.
  """
  @spec predict_batch([map()]) :: {:ok, [map()]} | {:error, term()}
  def predict_batch(samples) do
    with_circuit(fn -> do_predict_batch(samples, service_url()) end)
  end

  @doc """
  Check if the ML service is healthy.

  Performs a live GET /health check from the caller's process.
  When the circuit breaker is open, returns `false` without making a request.
  """
  @spec healthy?() :: boolean()
  def healthy? do
    case check_circuit() do
      {:ok, token} ->
        healthy = do_health_check(service_url())

        if healthy do
          record_success(token)
        else
          record_failure(token)
        end

        healthy

      {:error, _} ->
        false
    end
  end

  @doc """
  Get ML model information.

  Returns cached model info if available and fresh (< 5 minutes old),
  otherwise fetches from GET /model/info on the ML service. When the
  circuit is open, a stale cache entry is returned if available.
  """
  @spec model_info() :: {:ok, map()} | {:error, term()}
  def model_info do
    case model_info_cache() do
      {:fresh, info} ->
        {:ok, info}

      cache ->
        case check_circuit() do
          {:ok, token} ->
            case do_get_model_info(service_url()) do
              {:ok, info} ->
                record_success(token)
                put_model_info_cache(info)
                {:ok, info}

              {:error, _} = error ->
                record_failure(token)
                error
            end

          {:error, _} ->
            # Return stale cache if available, else error
            case cache do
              {:stale, info} -> {:ok, info}
              :none -> {:error, :ml_service_unavailable}
            end
        end
    end
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
    with_circuit(fn -> do_generate_embeddings(text, service_url()) end)
  end

  @doc """
  Fetch model performance metrics from the ML service.

  Calls GET /model/info on the ML service and parses the response
  into a metrics map.

  Returns `{:ok, metrics_map}` or `{:error, reason}`.
  """
  @spec get_metrics() :: {:ok, map()} | {:error, term()}
  def get_metrics do
    with_circuit(fn -> do_get_metrics(service_url()) end)
  end

  @doc """
  Get training job status from the ML service.

  Calls GET /training/status/{job_id} on the ML service.
  Returns `{:ok, status_map}` or `{:error, reason}`.
  """
  @spec get_training_status(String.t()) :: {:ok, map()} | {:error, term()}
  def get_training_status(job_id) do
    with_circuit(fn -> do_get_training_status(job_id, service_url()) end)
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
    with_circuit(fn -> do_post(path, body, service_url()) end)
  end

  @doc """
  Introspect the shared circuit breaker (for dashboards/ops/tests).

  Returns `%{state: :closed | :open | :half_open, failures: n, healthy: boolean}`.
  """
  @spec circuit_status() :: %{state: atom(), failures: non_neg_integer(), healthy: boolean()}
  def circuit_status do
    status =
      case :ets.lookup(@circuit_table, :circuit) do
        [{:circuit, state, failures, _opened_at, _probe_at}] ->
          %{state: state, failures: failures}

        [] ->
          %{state: :closed, failures: 0}
      end

    healthy =
      case :ets.lookup(@circuit_table, :healthy) do
        [{:healthy, h}] -> h
        [] -> false
      end

    Map.put(status, :healthy, healthy)
  rescue
    ArgumentError -> %{state: :closed, failures: 0, healthy: false}
  end

  @doc """
  Force the circuit breaker back to closed with zero failures.

  Operational escape hatch (also used by tests).
  """
  @spec reset_circuit() :: :ok
  def reset_circuit do
    :ets.insert(@circuit_table, {:circuit, :closed, 0, 0, 0})
    :ok
  rescue
    ArgumentError -> :ok
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    ensure_table()

    # Check health on startup
    send(self(), :health_check)

    {:ok, %{}}
  end

  @impl true
  def handle_info(:health_check, state) do
    healthy = do_health_check(service_url())

    record_health_result(healthy)
    :ets.insert(@circuit_table, {:healthy, healthy})

    # Schedule next health check
    Process.send_after(self(), :health_check, @health_check_interval)
    {:noreply, state}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  defp ensure_table do
    if :ets.whereis(@circuit_table) == :undefined do
      :ets.new(@circuit_table, [
        :named_table,
        :set,
        :public,
        read_concurrency: true,
        write_concurrency: true
      ])
    end

    :ets.insert_new(@circuit_table, {:circuit, :closed, 0, 0, 0})
    :ets.insert_new(@circuit_table, {:healthy, false})
    :ok
  end

  # ============================================================================
  # Circuit Breaker (public ETS, atomic transitions from caller processes)
  # ============================================================================

  # Admission check. Returns:
  #   {:ok, :closed} — circuit closed, request admitted
  #   {:ok, :probe}  — this caller won the single half-open probe slot
  #   {:error, :circuit_open | :not_started}
  defp check_circuit do
    case :ets.lookup(@circuit_table, :circuit) do
      [{:circuit, :closed, _f, _o, _p}] ->
        {:ok, :closed}

      [{:circuit, :open, _f, opened_at, _p}] ->
        if now_ms() - opened_at >= @circuit_reset_timeout_ms and acquire_half_open_probe() do
          Logger.info("ML client circuit breaker transitioning to half-open")
          {:ok, :probe}
        else
          {:error, :circuit_open}
        end

      [{:circuit, :half_open, _f, _o, probe_at}] ->
        if now_ms() - probe_at >= @half_open_probe_stale_ms and reacquire_stale_probe() do
          Logger.warning("ML client half-open probe went stale; admitting a replacement probe")
          {:ok, :probe}
        else
          {:error, :circuit_open}
        end

      [] ->
        {:error, :not_started}
    end
  rescue
    ArgumentError -> {:error, :not_started}
  end

  # Atomic CAS: :open -> :half_open, stamping the probe token in the same
  # operation so exactly one racing caller becomes the probe.
  defp acquire_half_open_probe do
    now = now_ms()

    match_spec = [
      {{:circuit, :open, :"$1", :"$2", :_},
       [{:>=, {:-, now, :"$2"}, @circuit_reset_timeout_ms}],
       [{{:circuit, :half_open, :"$1", :"$2", now}}]}
    ]

    :ets.select_replace(@circuit_table, match_spec) == 1
  end

  # Atomic CAS: re-stamp a stale probe token (previous probe holder died
  # without reporting). Only one racing caller wins.
  defp reacquire_stale_probe do
    now = now_ms()

    match_spec = [
      {{:circuit, :half_open, :"$1", :"$2", :"$3"},
       [{:>=, {:-, now, :"$3"}, @half_open_probe_stale_ms}],
       [{{:circuit, :half_open, :"$1", :"$2", now}}]}
    ]

    :ets.select_replace(@circuit_table, match_spec) == 1
  end

  # Successful probe closes the circuit.
  defp record_success(:probe), do: force_close()

  # Success while closed resets the consecutive-failure counter (CAS so we
  # never stomp an :open/:half_open record written concurrently).
  defp record_success(:closed) do
    match_spec = [
      {{:circuit, :closed, :"$1", :"$2", :"$3"}, [{:>, :"$1", 0}],
       [{{:circuit, :closed, 0, :"$2", :"$3"}}]}
    ]

    :ets.select_replace(@circuit_table, match_spec)
    :ok
  rescue
    ArgumentError -> :ok
  end

  # Failed probe reopens the circuit (CAS from :half_open only).
  defp record_failure(:probe) do
    now = now_ms()

    match_spec = [
      {{:circuit, :half_open, :"$1", :_, :_}, [], [{{:circuit, :open, :"$1", now, 0}}]}
    ]

    if :ets.select_replace(@circuit_table, match_spec) == 1 do
      Logger.warning("ML client circuit breaker reopening after failed half-open probe")
    end

    :ok
  rescue
    ArgumentError -> :ok
  end

  # Failure while closed: atomic counter increment; opening is a CAS guarded
  # on the threshold so exactly one process performs (and logs) the transition.
  defp record_failure(:closed) do
    failures = :ets.update_counter(@circuit_table, :circuit, {3, 1})

    if failures >= @circuit_failure_threshold do
      now = now_ms()

      match_spec = [
        {{:circuit, :closed, :"$1", :_, :_}, [{:>=, :"$1", @circuit_failure_threshold}],
         [{{:circuit, :open, :"$1", now, 0}}]}
      ]

      if :ets.select_replace(@circuit_table, match_spec) == 1 do
        Logger.warning(
          "ML client circuit breaker opening after #{failures} consecutive failures"
        )
      end
    end

    :ok
  rescue
    ArgumentError -> :ok
  end

  defp force_close do
    previous =
      case :ets.lookup(@circuit_table, :circuit) do
        [{:circuit, state, _f, _o, _p}] -> state
        [] -> :closed
      end

    :ets.insert(@circuit_table, {:circuit, :closed, 0, 0, 0})

    if previous != :closed do
      Logger.info("ML client circuit breaker closing (service recovered)")
    end

    :ok
  rescue
    ArgumentError -> :ok
  end

  # Background health check keeps the original semantics: success closes the
  # circuit unconditionally, failure counts toward the threshold.
  defp record_health_result(true), do: force_close()
  defp record_health_result(false), do: record_failure(:closed)

  # Run `fun` under circuit admission, reporting the outcome atomically from
  # the caller's process.
  defp with_circuit(fun) do
    case check_circuit() do
      {:ok, token} ->
        case fun.() do
          {:ok, _} = ok ->
            record_success(token)
            ok

          {:error, _} = error ->
            record_failure(token)
            error
        end

      {:error, _} ->
        {:error, :ml_service_unavailable}
    end
  end

  defp now_ms, do: System.monotonic_time(:millisecond)

  # ============================================================================
  # Retry Logic (runs in the caller's process — see Time budget)
  # ============================================================================

  # Retries any {:error, _} result (transport errors, HTTP status errors,
  # decode errors) — preserves the previous do_predict_with_retry semantics.
  defp with_retry(fun, label, attempt \\ 0) do
    case fun.() do
      {:ok, _} = success ->
        success

      {:error, reason} when attempt < @max_retries ->
        backoff = (@base_backoff_ms * :math.pow(2, attempt)) |> round()

        Logger.debug(
          "#{label} retry #{attempt + 1}/#{@max_retries} after #{backoff}ms: #{inspect(reason)}"
        )

        Process.sleep(backoff)
        with_retry(fun, label, attempt + 1)

      {:error, _} = error ->
        error
    end
  end

  # Retries transport-level errors only (Finch {:error, _}), like before.
  defp request_with_retry(request, opts, attempt \\ 0) do
    case Finch.request(request, @finch, opts) do
      {:ok, _} = success ->
        success

      {:error, reason} when attempt < @max_retries ->
        backoff = (@base_backoff_ms * :math.pow(2, attempt)) |> round()

        Logger.debug(
          "ML HTTP retry #{attempt + 1}/#{@max_retries} after #{backoff}ms: #{inspect(reason)}"
        )

        Process.sleep(backoff)
        request_with_retry(request, opts, attempt + 1)

      {:error, _} = error ->
        error
    end
  end

  # ============================================================================
  # Model Info Cache (ETS, last-write-wins)
  # ============================================================================

  defp model_info_cache do
    case :ets.lookup(@circuit_table, :model_info) do
      [{:model_info, info, cached_at}] ->
        if now_ms() - cached_at < @model_info_cache_ttl do
          {:fresh, info}
        else
          {:stale, info}
        end

      [] ->
        :none
    end
  rescue
    ArgumentError -> :none
  end

  defp put_model_info_cache(info) do
    :ets.insert(@circuit_table, {:model_info, info, now_ms()})
    :ok
  rescue
    ArgumentError -> :ok
  end

  # ============================================================================
  # Configuration
  # ============================================================================

  defp service_url do
    Application.get_env(:tamandua_server, :ml_service_url) ||
      System.get_env("ML_SERVICE_URL") ||
      "http://localhost:8000"
  end

  # ============================================================================
  # HTTP Operations (all execute in the caller's process)
  # ============================================================================

  defp do_predict(sample, base_url) do
    url = "#{base_url}/predict"

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

    case Finch.request(request, @finch, receive_timeout: @predict_receive_timeout_ms) do
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
             }
             |> put_trained_state(prediction)}

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

  defp do_predict_batch(samples, base_url) do
    url = "#{base_url}/predict/batch"

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

    case request_with_retry(request, receive_timeout: @batch_receive_timeout_ms) do
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
               |> put_trained_state(p)
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

  # Forward the additive trained-state fields from the ML service response
  # (model_trained: bool, training_samples: int) into the atom-keyed
  # prediction map. Consumers (e.g. EngineWorker.calculate_ml_threat_score)
  # check for an *explicit* model_trained == false, so fields absent in the
  # JSON (older service versions) must stay absent — no defaulting.
  defp put_trained_state(map, prediction) do
    Enum.reduce(
      [{:model_trained, "model_trained"}, {:training_samples, "training_samples"}],
      map,
      fn {atom_key, json_key}, acc ->
        case prediction do
          %{^json_key => value} -> Map.put(acc, atom_key, value)
          _ -> acc
        end
      end
    )
  end

  defp do_health_check(base_url) do
    url = "#{base_url}/health"
    request = Finch.build(:get, url, ml_headers())

    case Finch.request(request, @finch, receive_timeout: @health_receive_timeout_ms) do
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

  defp do_get_model_info(base_url) do
    url = "#{base_url}/model/info"
    request = Finch.build(:get, url, ml_headers([{"accept", "application/json"}]))

    case request_with_retry(request, receive_timeout: @short_receive_timeout_ms) do
      {:ok, %{status: 200, body: body}} ->
        Jason.decode(body)

      {:ok, %{status: status}} ->
        {:error, {:http_error, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp do_generate_embeddings(text, base_url) do
    # The ML service uses the encoder to produce latent-space vectors.
    # We send the text as binary content to /predict with an embeddings_only flag.
    # The text is converted to a binary representation that the encoder processes.
    url = "#{base_url}/predict"
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

    case request_with_retry(request, receive_timeout: @predict_receive_timeout_ms) do
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

  defp do_get_metrics(base_url) do
    url = "#{base_url}/model/info"
    request = Finch.build(:get, url, ml_headers([{"accept", "application/json"}]))

    case request_with_retry(request, receive_timeout: @short_receive_timeout_ms) do
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

  defp do_get_training_status(job_id, base_url) do
    url = "#{base_url}/training/status/#{job_id}"
    request = Finch.build(:get, url, ml_headers([{"accept", "application/json"}]))

    case request_with_retry(request, receive_timeout: @training_receive_timeout_ms) do
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

  defp do_post(path, body_map, base_url) do
    url = "#{base_url}#{path}"

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

    case request_with_retry(request, receive_timeout: @predict_receive_timeout_ms) do
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
