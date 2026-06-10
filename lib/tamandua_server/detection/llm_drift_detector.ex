defmodule TamanduaServer.Detection.LLMDriftDetector do
  @moduledoc """
  GenServer for LLM output drift detection.

  Collects LLM inference outputs and periodically checks for drift
  against established baselines via the ML service.

  Uses ETS for high-concurrency sample collection and tracks:
  - Output token distributions
  - Confidence score distributions
  - Response latency patterns
  """

  use GenServer
  require Logger
  alias Phoenix.PubSub
  alias TamanduaServer.Detection.ML.DriftClient

  @ets_table :llm_drift_samples
  @check_interval_ms 30 * 60 * 1000  # 30 minutes
  @min_samples_for_check 100
  @max_samples_per_model 1000

  # ============================================================================
  # Types
  # ============================================================================

  @type output_sample :: %{
    agent_id: String.t(),
    model_id: String.t(),
    output_tokens: non_neg_integer(),
    confidence: float(),
    latency_ms: non_neg_integer(),
    response_category: String.t(),
    timestamp: DateTime.t()
  }

  @type drift_status :: %{
    model_id: String.t(),
    samples_collected: non_neg_integer(),
    last_check: DateTime.t() | nil,
    drift_detected: boolean(),
    drift_score: float(),
    alerts: list()
  }

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Record an LLM inference output sample for drift analysis.
  """
  @spec record_sample(output_sample()) :: :ok
  def record_sample(sample) do
    GenServer.cast(__MODULE__, {:record_sample, sample})
  end

  @doc """
  Force a drift check for a specific model.
  """
  @spec check_drift(String.t(), String.t()) :: {:ok, map()} | {:error, term()}
  def check_drift(agent_id, model_id) do
    GenServer.call(__MODULE__, {:check_drift, agent_id, model_id}, 30_000)
  end

  @doc """
  Get current drift status for a model.
  """
  @spec get_status(String.t()) :: {:ok, drift_status()} | {:error, :not_found}
  def get_status(model_id) do
    GenServer.call(__MODULE__, {:get_status, model_id})
  end

  @doc """
  Get all active drift alerts.
  """
  @spec get_active_alerts() :: list()
  def get_active_alerts do
    GenServer.call(__MODULE__, :get_active_alerts)
  end

  @doc """
  Get drift statistics across all models.
  """
  @spec get_statistics() :: map()
  def get_statistics do
    GenServer.call(__MODULE__, :get_statistics)
  end

  @doc """
  Get all tracked models and their sample counts.
  """
  @spec list_models() :: list({String.t(), non_neg_integer()})
  def list_models do
    GenServer.call(__MODULE__, :list_models)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    table = :ets.new(@ets_table, [
      :set,
      :named_table,
      :public,
      read_concurrency: true,
      write_concurrency: true
    ])

    # Subscribe to inference events
    PubSub.subscribe(TamanduaServer.PubSub, "inference:completed")

    # Schedule periodic drift checks
    schedule_check()

    Logger.info("[LLMDriftDetector] Started")

    {:ok, %{
      table: table,
      model_status: %{},
      active_alerts: [],
      total_samples: 0,
      total_checks: 0,
      total_drift_detected: 0
    }}
  end

  @impl true
  def handle_cast({:record_sample, sample}, state) do
    model_key = sample.model_id

    # Get or create sample list for model
    samples = case :ets.lookup(@ets_table, model_key) do
      [{^model_key, existing}] -> existing
      [] -> []
    end

    # Add sample, keeping max count
    updated = [sample | samples] |> Enum.take(@max_samples_per_model)
    :ets.insert(@ets_table, {model_key, updated})

    # Update model status
    new_status = Map.update(state.model_status, model_key, %{
      samples_collected: 1,
      last_check: nil,
      drift_detected: false,
      drift_score: 0.0,
      alerts: []
    }, fn status ->
      %{status | samples_collected: length(updated)}
    end)

    {:noreply, %{state |
      model_status: new_status,
      total_samples: state.total_samples + 1
    }}
  end

  @impl true
  def handle_call({:check_drift, agent_id, model_id}, _from, state) do
    case :ets.lookup(@ets_table, model_id) do
      [{^model_id, samples}] when length(samples) >= @min_samples_for_check ->
        result = perform_drift_check(agent_id, model_id, samples)

        # Update status
        new_status = Map.put(state.model_status, model_id, %{
          samples_collected: length(samples),
          last_check: DateTime.utc_now(),
          drift_detected: result.overall_drift_detected,
          drift_score: result.drift_score || 0.0,
          alerts: result.alerts || []
        })

        # Update counters
        new_state = %{state |
          model_status: new_status,
          total_checks: state.total_checks + 1,
          total_drift_detected: if(result.overall_drift_detected,
            do: state.total_drift_detected + 1,
            else: state.total_drift_detected)
        }

        # Broadcast drift event if detected
        if result.overall_drift_detected do
          broadcast_drift_event(model_id, result)
        end

        {:reply, {:ok, result}, new_state}

      [{^model_id, samples}] ->
        {:reply, {:error, {:insufficient_samples, length(samples), @min_samples_for_check}}, state}

      [] ->
        {:reply, {:error, :no_samples}, state}
    end
  end

  @impl true
  def handle_call({:get_status, model_id}, _from, state) do
    case Map.get(state.model_status, model_id) do
      nil -> {:reply, {:error, :not_found}, state}
      status -> {:reply, {:ok, status}, state}
    end
  end

  @impl true
  def handle_call(:get_active_alerts, _from, state) do
    {:reply, state.active_alerts, state}
  end

  @impl true
  def handle_call(:get_statistics, _from, state) do
    stats = %{
      total_samples: state.total_samples,
      total_checks: state.total_checks,
      total_drift_detected: state.total_drift_detected,
      models_tracked: map_size(state.model_status),
      active_alerts: length(state.active_alerts)
    }
    {:reply, stats, state}
  end

  @impl true
  def handle_call(:list_models, _from, state) do
    models = Enum.map(state.model_status, fn {model_id, status} ->
      {model_id, status.samples_collected}
    end)
    {:reply, models, state}
  end

  @impl true
  def handle_info(:periodic_check, state) do
    # Check drift for all models with sufficient samples
    Enum.each(state.model_status, fn {model_id, status} ->
      if status.samples_collected >= @min_samples_for_check do
        # Use a default agent_id for periodic checks
        Task.start(fn ->
          check_drift("system", model_id)
        end)
      end
    end)

    schedule_check()
    {:noreply, state}
  end

  @impl true
  def handle_info({:inference_completed, event}, state) do
    # Auto-record from inference events
    sample = %{
      agent_id: event.agent_id,
      model_id: event.model_id || "unknown",
      output_tokens: event.output_tokens || 0,
      confidence: event.confidence || 0.5,
      latency_ms: event.latency_ms || 0,
      response_category: event.category || "general",
      timestamp: DateTime.utc_now()
    }

    record_sample(sample)
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp schedule_check do
    Process.send_after(self(), :periodic_check, @check_interval_ms)
  end

  defp perform_drift_check(agent_id, model_id, samples) do
    case DriftClient.check_llm_drift(agent_id, model_id, samples) do
      {:ok, result} -> result
      {:error, reason} ->
        Logger.error("[LLMDriftDetector] Drift check failed: #{inspect(reason)}")
        %{overall_drift_detected: false, drift_score: 0.0, alerts: [], error: reason}
    end
  end

  defp broadcast_drift_event(model_id, result) do
    PubSub.broadcast(
      TamanduaServer.PubSub,
      "drift:detected",
      {:drift_detected, %{
        model_id: model_id,
        drift_score: result.drift_score,
        timestamp: DateTime.utc_now(),
        alerts: result.alerts
      }}
    )
  end
end
