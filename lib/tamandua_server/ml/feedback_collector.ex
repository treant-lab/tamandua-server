defmodule TamanduaServer.ML.FeedbackCollector do
  @moduledoc """
  Feedback Collector for Incremental ML Learning.

  Collects analyst feedback on detections and forwards to ML service
  for incremental model updates. Integrates with AnalystFeedback and
  ModelManager to provide end-to-end feedback loop.

  ## Workflow

  1. Analyst provides feedback (confirm/reject detection)
  2. Feedback is recorded in AnalystFeedback
  3. FeedbackCollector aggregates and formats for ML service
  4. Sends feedback batch to ML service for incremental training
  5. Tracks feedback→model update cycle

  ## Integration

  - Receives feedback from AnalystFeedback via PubSub
  - Fetches sample binaries from file system or S3
  - Sends feedback batches to ML service API
  - Monitors incremental training progress
  """

  use GenServer
  require Logger


  # ── Configuration ────────────────────────────────────────────────────

  @feedback_batch_size 50
  @feedback_batch_interval_ms :timer.minutes(15)
  @cleanup_interval_ms :timer.hours(6)
  @ml_service_url Application.compile_env(:tamandua_server, :ml_service_url, "http://localhost:8000")
  @feedback_retention_days 30

  @feedback_queue_table :ml_feedback_queue
  @training_jobs_table :ml_training_jobs

  # ── State ─────────────────────────────────────────────────────────────

  defstruct [
    :stats,
    :ml_client,
    :last_batch_sent
  ]

  # ── Client API ───────────────────────────────────────────────────────

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Queue feedback for incremental learning.

  Feedback is batched and sent periodically to the ML service.
  """
  @spec queue_feedback(String.t(), String.t(), atom(), map()) :: :ok
  def queue_feedback(alert_id, sample_hash, verdict, metadata \\ %{}) do
    GenServer.cast(__MODULE__, {:queue_feedback, alert_id, sample_hash, verdict, metadata})
  end

  @doc """
  Manually trigger sending feedback batch to ML service.
  """
  @spec send_feedback_batch() :: {:ok, map()} | {:error, term()}
  def send_feedback_batch do
    GenServer.call(__MODULE__, :send_feedback_batch, :timer.seconds(30))
  end

  @doc """
  Get feedback collector statistics.
  """
  @spec stats() :: map()
  def stats do
    GenServer.call(__MODULE__, :stats)
  end

  @doc """
  Get pending feedback count.
  """
  @spec pending_count() :: non_neg_integer()
  def pending_count do
    :ets.info(@feedback_queue_table, :size) || 0
  end

  @doc """
  Get training job status.
  """
  @spec get_training_job(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_training_job(job_id) do
    case :ets.lookup(@training_jobs_table, job_id) do
      [{^job_id, job}] -> {:ok, job}
      [] -> {:error, :not_found}
    end
  end

  # ── Server callbacks ──────────────────────────────────────────────────

  @impl true
  def init(_opts) do
    :ets.new(@feedback_queue_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@training_jobs_table, [:named_table, :set, :public, read_concurrency: true])

    # Subscribe to feedback events
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "ml:feedback")

    # Schedule periodic batch sending and retention cleanup
    schedule_batch_send()
    schedule_cleanup()

    # HTTP client for ML service
    ml_client = %{
      base_url: @ml_service_url,
      timeout: 30_000
    }

    state = %__MODULE__{
      stats: %{
        feedback_queued: 0,
        batches_sent: 0,
        training_jobs_started: 0,
        training_jobs_completed: 0,
        training_jobs_failed: 0
      },
      ml_client: ml_client,
      last_batch_sent: nil
    }

    Logger.info("[FeedbackCollector] Started (ML service: #{@ml_service_url})")
    {:ok, state}
  end

  @impl true
  def handle_cast({:queue_feedback, alert_id, sample_hash, verdict, metadata}, state) do
    now = DateTime.utc_now()
    feedback_id = generate_feedback_id()

    feedback = %{
      feedback_id: feedback_id,
      alert_id: alert_id,
      sample_hash: sample_hash,
      verdict: verdict,
      metadata: metadata,
      queued_at: now,
      sent: false
    }

    :ets.insert(@feedback_queue_table, {feedback_id, feedback})

    stats = Map.update!(state.stats, :feedback_queued, &(&1 + 1))
    {:noreply, %{state | stats: stats}}
  end

  @impl true
  def handle_call(:send_feedback_batch, _from, state) do
    result = do_send_feedback_batch(state)

    case result do
      {:ok, response} ->
        stats = Map.update!(state.stats, :batches_sent, &(&1 + 1))
        {:reply, {:ok, response}, %{state | stats: stats, last_batch_sent: DateTime.utc_now()}}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call(:stats, _from, state) do
    pending = :ets.info(@feedback_queue_table, :size) || 0
    jobs = :ets.info(@training_jobs_table, :size) || 0

    result = Map.merge(state.stats, %{
      pending_feedback: pending,
      training_jobs: jobs,
      last_batch_sent: state.last_batch_sent
    })

    {:reply, result, state}
  end

  @impl true
  def handle_info(:send_batch, state) do
    do_send_feedback_batch(state)
    schedule_batch_send()
    {:noreply, state}
  end

  def handle_info({:retrain_recommended, model_type, reason}, state) do
    Logger.info("[FeedbackCollector] Retraining recommended for #{model_type}: #{reason}")

    # Could trigger automatic incremental training here
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "ml:training",
      {:incremental_training_recommended, model_type, reason}
    )

    {:noreply, state}
  end

  def handle_info({:training_job_update, job_id, status, metrics}, state) do
    case :ets.lookup(@training_jobs_table, job_id) do
      [{^job_id, job}] ->
        updated_job = Map.merge(job, %{
          status: status,
          metrics: metrics,
          updated_at: DateTime.utc_now()
        })

        :ets.insert(@training_jobs_table, {job_id, updated_job})

        # Update stats based on status
        stats = case status do
          :completed ->
            Map.update!(state.stats, :training_jobs_completed, &(&1 + 1))
          :failed ->
            Map.update!(state.stats, :training_jobs_failed, &(&1 + 1))
          _ ->
            state.stats
        end

        {:noreply, %{state | stats: stats}}

      [] ->
        {:noreply, state}
    end
  end

  def handle_info(:cleanup, state) do
    cleanup_old_feedback()
    cleanup_old_training_jobs()
    schedule_cleanup()
    {:noreply, state}
  end

  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ── Private: batch sending ────────────────────────────────────────────

  defp do_send_feedback_batch(state) do
    # Get pending feedback
    pending = :ets.tab2list(@feedback_queue_table)
                |> Enum.filter(fn {_id, feedback} -> !feedback.sent end)
                |> Enum.take(@feedback_batch_size)

    if length(pending) == 0 do
      {:ok, %{message: "No pending feedback", count: 0}}
    else
      Logger.info("[FeedbackCollector] Sending feedback batch", count: length(pending))

      # Prepare feedback samples
      samples = pending
                |> Enum.map(fn {_id, feedback} -> prepare_feedback_sample(feedback) end)
                |> Enum.reject(&is_nil/1)

      if length(samples) == 0 do
        {:ok, %{message: "No valid samples", count: 0}}
      else
        # Send to ML service
        case send_to_ml_service(samples, state.ml_client) do
          {:ok, response} ->
            # Mark as sent
            Enum.each(pending, fn {id, feedback} ->
              :ets.insert(@feedback_queue_table, {id, %{feedback | sent: true}})
            end)

            # Create training job record if training started
            if response["job_id"] do
              job = %{
                job_id: response["job_id"],
                model_type: response["model_type"] || "malware_smell",
                samples_count: length(samples),
                status: :running,
                created_at: DateTime.utc_now(),
                updated_at: DateTime.utc_now(),
                metrics: %{}
              }

              :ets.insert(@training_jobs_table, {response["job_id"], job})
            end

            {:ok, response}

          {:error, reason} ->
            Logger.error("[FeedbackCollector] Failed to send feedback batch", error: inspect(reason))
            {:error, reason}
        end
      end
    end
  end

  defp prepare_feedback_sample(feedback) do
    # Convert verdict to label
    label = case feedback.verdict do
      v when v in [:true_positive, :storyline_confirmed] -> 1
      v when v in [:false_positive, :true_negative, :storyline_dismissed] -> 0
      _ -> nil
    end

    if is_nil(label) do
      nil
    else
      # Load binary data
      binary_data = load_sample_binary(feedback.sample_hash)

      if is_nil(binary_data) do
        Logger.warning("[FeedbackCollector] Could not load binary for sample", hash: feedback.sample_hash)
        nil
      else
        %{
          sample_hash: feedback.sample_hash,
          binary_data: Base.encode64(binary_data),
          label: label,
          confidence: feedback.metadata[:confidence] || 1.0,
          metadata: %{
            alert_id: feedback.alert_id,
            verdict: to_string(feedback.verdict),
            queued_at: feedback.queued_at
          }
        }
      end
    end
  end

  defp load_sample_binary(sample_hash) do
    # Try multiple locations
    paths = [
      Path.join([Application.get_env(:tamandua_server, :quarantine_dir, "/var/tamandua/quarantine"), "#{sample_hash}.bin"]),
      Path.join([Application.get_env(:tamandua_server, :samples_dir, "/var/tamandua/samples"), "#{sample_hash}.bin"]),
    ]

    Enum.find_value(paths, fn path ->
      if File.exists?(path) do
        case File.read(path) do
          {:ok, data} -> data
          {:error, _} -> nil
        end
      else
        nil
      end
    end)
  end

  defp send_to_ml_service(samples, ml_client) do
    url = "#{ml_client.base_url}/api/v1/training/incremental"

    payload = %{
      samples: samples,
      mode: "incremental",
      validate: true
    }

    headers = [
      {"Content-Type", "application/json"},
      {"X-API-Key", Application.get_env(:tamandua_server, :ml_api_key, "")}
    ]

    case TamanduaServer.HttpClient.post(url, Jason.encode!(payload), headers, timeout: ml_client.timeout, recv_timeout: ml_client.timeout) do
      {:ok, %{status_code: 200, body: body}} ->
        {:ok, Jason.decode!(body)}

      {:ok, %{status_code: status, body: body}} ->
        {:error, {:http_error, status, body}}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    e ->
      {:error, {:exception, Exception.message(e)}}
  end

  # ── Private: cleanup ──────────────────────────────────────────────────

  defp schedule_batch_send do
    Process.send_after(self(), :send_batch, @feedback_batch_interval_ms)
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval_ms)
  end

  # Evict terminal (completed/failed) training jobs past the retention window.
  # Running jobs are kept regardless of age.
  defp cleanup_old_training_jobs do
    cutoff =
      DateTime.utc_now()
      |> DateTime.add(-@feedback_retention_days * 24 * 60 * 60, :second)

    @training_jobs_table
    |> :ets.tab2list()
    |> Enum.each(fn {id, job} ->
      if job.status in [:completed, :failed] and
           DateTime.compare(job.updated_at, cutoff) == :lt do
        :ets.delete(@training_jobs_table, id)
      end
    end)

    :ok
  end

  defp generate_feedback_id do
    :crypto.strong_rand_bytes(12) |> Base.encode16(case: :lower)
  end

  # ── Public: cleanup task ──────────────────────────────────────────────

  @doc """
  Clean up old sent feedback records.
  """
  def cleanup_old_feedback do
    cutoff = DateTime.utc_now() |> DateTime.add(-@feedback_retention_days * 24 * 60 * 60, :second)

    @feedback_queue_table
    |> :ets.tab2list()
    |> Enum.filter(fn {_id, feedback} ->
      feedback.sent and DateTime.compare(feedback.queued_at, cutoff) == :lt
    end)
    |> Enum.each(fn {id, _} ->
      :ets.delete(@feedback_queue_table, id)
    end)

    :ok
  end
end
