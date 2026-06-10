defmodule TamanduaServer.ML.TrainingScheduler do
  @moduledoc """
  GenServer for scheduled and on-demand ML model retraining.

  Responsibilities:
  - Weekly scheduled retraining checks
  - On-demand retraining via API or internal triggers
  - Coordinates with ML service via HTTP API (POST /training/start)
  - Tracks training job status (queued, training, validating, complete, failed)
  - After training completes, auto-registers the new model version in ModelManager
  - Polls ML service for job progress updates

  ## Training Job Lifecycle

      queued -> training -> validating -> complete -> (auto-register model)
                                       -> failed

  ## ETS Tables

  - `:ml_training_jobs` - {job_id, job_record}
  """

  use GenServer
  require Logger

  alias TamanduaServer.ML.ModelManager

  # ── Configuration ────────────────────────────────────────────────────

  @weekly_check_interval_ms :timer.hours(168)
  @job_poll_interval_ms :timer.seconds(30)
  @ml_service_timeout 30_000

  @jobs_table :ml_training_jobs

  # ── State ─────────────────────────────────────────────────────────────

  defstruct [
    :active_jobs,
    :stats,
    :last_weekly_check
  ]

  # ── Client API ───────────────────────────────────────────────────────

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Schedule a retraining job for a model type.
  Returns `{:ok, job_id}` or `{:error, reason}`.
  """
  @spec schedule_retraining(String.t(), map()) :: {:ok, String.t()} | {:error, term()}
  def schedule_retraining(model_type, opts \\ %{}) do
    GenServer.call(__MODULE__, {:schedule_retraining, model_type, opts})
  end

  @doc """
  Get the status of a training job.
  """
  @spec get_job_status(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_job_status(job_id) do
    case :ets.lookup(@jobs_table, job_id) do
      [{^job_id, job}] -> {:ok, job}
      [] -> {:error, :not_found}
    end
  end

  @doc """
  List all training jobs.
  """
  @spec list_jobs() :: [map()]
  def list_jobs do
    @jobs_table
    |> :ets.tab2list()
    |> Enum.map(fn {_id, job} -> job end)
    |> Enum.sort_by(& &1.created_at, {:desc, DateTime})
  end

  @doc """
  Cancel a queued or running training job.
  """
  @spec cancel_job(String.t()) :: :ok | {:error, term()}
  def cancel_job(job_id) do
    GenServer.call(__MODULE__, {:cancel_job, job_id})
  end

  @doc """
  Get scheduler statistics.
  """
  @spec stats() :: map()
  def stats do
    GenServer.call(__MODULE__, :stats)
  end

  # ── Server callbacks ──────────────────────────────────────────────────

  @impl true
  def init(_opts) do
    :ets.new(@jobs_table, [:named_table, :set, :public, read_concurrency: true])

    schedule_weekly_check()

    state = %__MODULE__{
      active_jobs: MapSet.new(),
      stats: %{
        jobs_created: 0,
        jobs_completed: 0,
        jobs_failed: 0,
        jobs_cancelled: 0,
        models_registered: 0
      },
      last_weekly_check: DateTime.utc_now()
    }

    Logger.info("[TrainingScheduler] Started")
    {:ok, state}
  end

  @impl true
  def handle_call({:schedule_retraining, model_type, opts}, _from, state) do
    # Check for duplicate active jobs for same model type
    active_for_type =
      state.active_jobs
      |> Enum.filter(fn job_id ->
        case :ets.lookup(@jobs_table, job_id) do
          [{_, job}] -> job.model_type == model_type and job.status in [:queued, :training, :validating]
          [] -> false
        end
      end)

    if Enum.any?(active_for_type) do
      {:reply, {:error, :training_already_in_progress}, state}
    else
      job_id = generate_job_id()
      now = DateTime.utc_now()

      job = %{
        job_id: job_id,
        model_type: model_type,
        status: :queued,
        reason: opts[:reason] || :manual,
        dataset_size: opts[:dataset_size] || 0,
        epochs: opts[:epochs] || 50,
        batch_size: opts[:batch_size] || 32,
        progress: 0.0,
        current_epoch: 0,
        total_epochs: opts[:epochs] || 50,
        train_loss: nil,
        val_loss: nil,
        ml_job_id: nil,
        created_at: now,
        started_at: nil,
        completed_at: nil,
        error: nil,
        result_version: nil
      }

      :ets.insert(@jobs_table, {job_id, job})

      # Start the job asynchronously
      Task.Supervisor.start_child(
        TamanduaServer.TaskSupervisor,
        fn -> execute_training_job(job_id) end
      )

      active_jobs = MapSet.put(state.active_jobs, job_id)
      stats = Map.update!(state.stats, :jobs_created, &(&1 + 1))

      Logger.info("[TrainingScheduler] Queued training job #{job_id} for #{model_type} (reason: #{opts[:reason] || :manual})")
      {:reply, {:ok, job_id}, %{state | active_jobs: active_jobs, stats: stats}}
    end
  end

  def handle_call({:cancel_job, job_id}, _from, state) do
    case :ets.lookup(@jobs_table, job_id) do
      [{^job_id, job}] ->
        if job.status in [:queued, :training, :validating] do
          updated = %{job | status: :cancelled, completed_at: DateTime.utc_now(), error: "Cancelled by user"}
          :ets.insert(@jobs_table, {job_id, updated})

          active_jobs = MapSet.delete(state.active_jobs, job_id)
          stats = Map.update!(state.stats, :jobs_cancelled, &(&1 + 1))

          {:reply, :ok, %{state | active_jobs: active_jobs, stats: stats}}
        else
          {:reply, {:error, :job_not_active}, state}
        end

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  def handle_call(:stats, _from, state) do
    job_count = :ets.info(@jobs_table, :size) || 0
    active_count = MapSet.size(state.active_jobs)

    result = Map.merge(state.stats, %{
      total_jobs: job_count,
      active_jobs: active_count,
      last_weekly_check: state.last_weekly_check
    })

    {:reply, result, state}
  end

  @impl true
  def handle_info({:job_completed, job_id, result}, state) do
    active_jobs = MapSet.delete(state.active_jobs, job_id)

    state = case result do
      {:ok, _version} ->
        stats = state.stats
                |> Map.update!(:jobs_completed, &(&1 + 1))
                |> Map.update!(:models_registered, &(&1 + 1))
        %{state | stats: stats}

      {:error, _reason} ->
        stats = Map.update!(state.stats, :jobs_failed, &(&1 + 1))
        %{state | stats: stats}
    end

    {:noreply, %{state | active_jobs: active_jobs}}
  end

  def handle_info(:weekly_check, state) do
    Logger.info("[TrainingScheduler] Running weekly retraining check")

    # Check each model type with AnalystFeedback
    try do
      model_types = get_model_types_from_registry()

      Enum.each(model_types, fn model_type ->
        case TamanduaServer.ML.AnalystFeedback.should_retrain?(model_type) do
          {true, reason} ->
            Logger.info("[TrainingScheduler] Auto-scheduling retraining for #{model_type}: #{reason}")
            schedule_retraining(model_type, %{reason: reason})

          {false, _} ->
            :ok
        end
      end)
    rescue
      e ->
        Logger.error("[TrainingScheduler] Weekly check failed: #{Exception.message(e)}")
    end

    schedule_weekly_check()
    {:noreply, %{state | last_weekly_check: DateTime.utc_now()}}
  end

  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ── Private: training execution ───────────────────────────────────────

  defp execute_training_job(job_id) do
    case :ets.lookup(@jobs_table, job_id) do
      [{^job_id, job}] ->
        # Update status to training
        updated = %{job | status: :training, started_at: DateTime.utc_now()}
        :ets.insert(@jobs_table, {job_id, updated})

        # Send training request to ML service
        case start_ml_training(job) do
          {:ok, ml_job_id} ->
            :ets.insert(@jobs_table, {job_id, %{updated | ml_job_id: ml_job_id}})
            poll_training_progress(job_id, ml_job_id)

          {:error, reason} ->
            failed = %{updated |
              status: :failed,
              error: "Failed to start ML training: #{inspect(reason)}",
              completed_at: DateTime.utc_now()
            }
            :ets.insert(@jobs_table, {job_id, failed})
            send(self_pid(), {:job_completed, job_id, {:error, reason}})
        end

      [] ->
        Logger.error("[TrainingScheduler] Job #{job_id} not found when executing")
    end
  end

  defp start_ml_training(job) do
    url = ml_service_url() <> "/training/start"

    body = Jason.encode!(%{
      data_path: "retraining",
      epochs: job.epochs,
      batch_size: job.batch_size,
      mode: "production"
    })

    request = Finch.build(:post, url, [
      {"content-type", "application/json"},
      {"accept", "application/json"}
    ], body)

    case Finch.request(request, TamanduaServer.Finch, receive_timeout: @ml_service_timeout) do
      {:ok, %{status: status, body: response_body}} when status in [200, 201, 202] ->
        case Jason.decode(response_body) do
          {:ok, %{"job_id" => ml_job_id}} -> {:ok, ml_job_id}
          {:ok, data} -> {:ok, data["job_id"] || generate_job_id()}
          {:error, _} -> {:ok, generate_job_id()}
        end

      {:ok, %{status: status, body: body}} ->
        {:error, {:http_error, status, body}}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp poll_training_progress(job_id, ml_job_id) do
    case :ets.lookup(@jobs_table, job_id) do
      [{^job_id, job}] when job.status in [:training, :validating] ->
        case fetch_ml_job_status(ml_job_id) do
          {:ok, ml_status} ->
            updated = apply_ml_status(job, ml_status)
            :ets.insert(@jobs_table, {job_id, updated})

            case updated.status do
              :complete ->
                handle_training_complete(job_id, updated)

              :failed ->
                send(self_pid(), {:job_completed, job_id, {:error, updated.error}})

              _ ->
                # Keep polling
                Process.sleep(@job_poll_interval_ms)
                poll_training_progress(job_id, ml_job_id)
            end

          {:error, _reason} ->
            # ML service might be temporarily unavailable; retry
            Process.sleep(@job_poll_interval_ms)
            poll_training_progress(job_id, ml_job_id)
        end

      [{^job_id, %{status: :cancelled}}] ->
        Logger.info("[TrainingScheduler] Job #{job_id} was cancelled, stopping poll")

      _ ->
        Logger.error("[TrainingScheduler] Job #{job_id} not found during polling")
    end
  end

  defp fetch_ml_job_status(ml_job_id) do
    url = ml_service_url() <> "/training/status/#{ml_job_id}"

    request = Finch.build(:get, url, [{"accept", "application/json"}])

    case Finch.request(request, TamanduaServer.Finch, receive_timeout: 10_000) do
      {:ok, %{status: 200, body: body}} ->
        Jason.decode(body)

      {:ok, %{status: 404}} ->
        {:error, :not_found}

      {:ok, %{status: status}} ->
        {:error, {:http_error, status}}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp apply_ml_status(job, ml_status) do
    status = case ml_status["status"] do
      "queued" -> :queued
      "running" -> :training
      "validating" -> :validating
      "completed" -> :complete
      "failed" -> :failed
      "cancelled" -> :cancelled
      _ -> job.status
    end

    %{job |
      status: status,
      progress: ml_status["progress"] || job.progress,
      current_epoch: ml_status["current_epoch"] || job.current_epoch,
      total_epochs: ml_status["total_epochs"] || job.total_epochs,
      train_loss: ml_status["train_loss"] || job.train_loss,
      val_loss: ml_status["val_loss"] || job.val_loss,
      error: ml_status["error"] || job.error,
      completed_at: if(status in [:complete, :failed], do: DateTime.utc_now(), else: job.completed_at)
    }
  end

  defp handle_training_complete(job_id, job) do
    # Auto-increment version
    new_version = next_version(job.model_type)

    # Register the new model
    metadata = %{
      training_job_id: job_id,
      ml_job_id: job.ml_job_id,
      epochs: job.total_epochs,
      train_loss: job.train_loss,
      val_loss: job.val_loss,
      dataset_size: job.dataset_size,
      trained_at: DateTime.utc_now()
    }

    case ModelManager.register_model(job.model_type, new_version, metadata) do
      {:ok, _record} ->
        # Update job with the result version
        updated = %{job | result_version: new_version}
        :ets.insert(@jobs_table, {job_id, updated})

        Logger.info("[TrainingScheduler] Training complete for #{job.model_type}, registered v#{new_version}")
        send(self_pid(), {:job_completed, job_id, {:ok, new_version}})

      {:error, reason} ->
        Logger.error("[TrainingScheduler] Failed to register model after training: #{inspect(reason)}")
        send(self_pid(), {:job_completed, job_id, {:error, reason}})
    end
  end

  # ── Private: version management ───────────────────────────────────────

  defp next_version(model_type) do
    history = ModelManager.get_model_history(model_type)

    case history do
      [latest | _] ->
        increment_version(latest.version)

      [] ->
        "1.0.0"
    end
  end

  defp increment_version(version) do
    case String.split(version, ".") do
      [major, minor, patch] ->
        new_patch = String.to_integer(patch) + 1
        "#{major}.#{minor}.#{new_patch}"

      _ ->
        "1.0.0"
    end
  rescue
    _ -> "1.0.0"
  end

  # ── Private: helpers ──────────────────────────────────────────────────

  defp ml_service_url do
    System.get_env("ML_SERVICE_URL") ||
      Application.get_env(:tamandua_server, :ml_service_url, "http://localhost:8000")
  end

  defp self_pid do
    Process.whereis(__MODULE__) || self()
  end

  defp get_model_types_from_registry do
    ModelManager.list_all_models()
    |> Enum.map(& &1.model_type)
    |> Enum.uniq()
  rescue
    _ -> ["malware_smell"]
  end

  defp generate_job_id do
    :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)
  end

  defp schedule_weekly_check do
    Process.send_after(self(), :weekly_check, @weekly_check_interval_ms)
  end
end
