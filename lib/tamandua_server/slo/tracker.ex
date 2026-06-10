defmodule TamanduaServer.SLO.Tracker do
  @moduledoc """
  SLO Tracker - Collects and tracks SLI metrics for all services.

  Tracks:
  - API service (Phoenix endpoints)
  - Event processing (Broadway pipeline)
  - Detection engine
  - ML service
  - Database operations

  Stores metrics in ETS for fast access and periodically aggregates to database.
  """

  use GenServer
  require Logger

  alias TamanduaServer.SLO.Calculator
  alias TamanduaServer.SLO.ErrorBudget

  @ets_table :slo_metrics
  @collection_interval :timer.minutes(1)
  @aggregation_interval :timer.minutes(5)

  defstruct [
    :ets_table,
    :last_aggregation,
    :current_window,
    :historical_windows
  ]

  # Client API

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Record API request latency.
  """
  @spec record_api_request(non_neg_integer(), boolean(), String.t()) :: :ok
  def record_api_request(latency_ms, success?, endpoint \\ "unknown") do
    GenServer.cast(__MODULE__, {:record_api_request, latency_ms, success?, endpoint})
  end

  @doc """
  Record event processing latency.
  """
  @spec record_event_processing(non_neg_integer(), boolean()) :: :ok
  def record_event_processing(latency_ms, success?) do
    GenServer.cast(__MODULE__, {:record_event_processing, latency_ms, success?})
  end

  @doc """
  Record detection engine operation.
  """
  @spec record_detection(non_neg_integer(), boolean(), atom()) :: :ok
  def record_detection(latency_ms, success?, engine_type \\ :yara) do
    GenServer.cast(__MODULE__, {:record_detection, latency_ms, success?, engine_type})
  end

  @doc """
  Record ML service prediction.
  """
  @spec record_ml_prediction(non_neg_integer(), boolean()) :: :ok
  def record_ml_prediction(latency_ms, success?) do
    GenServer.cast(__MODULE__, {:record_ml_prediction, latency_ms, success?})
  end

  @doc """
  Record system availability check.
  """
  @spec record_availability_check(boolean()) :: :ok
  def record_availability_check(is_up?) do
    GenServer.cast(__MODULE__, {:record_availability, is_up?})
  end

  @doc """
  Get current SLI metrics for all services.
  """
  @spec current_metrics() :: map()
  def current_metrics do
    GenServer.call(__MODULE__, :current_metrics)
  end

  @doc """
  Get SLI metrics for a specific service.
  """
  @spec service_metrics(atom()) :: map()
  def service_metrics(service) do
    GenServer.call(__MODULE__, {:service_metrics, service})
  end

  @doc """
  Get error budget status.
  """
  @spec error_budget_status() :: map()
  def error_budget_status do
    GenServer.call(__MODULE__, :error_budget_status)
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    # Create ETS table for fast metric storage
    table = :ets.new(@ets_table, [:named_table, :public, :duplicate_bag, read_concurrency: true])

    state = %__MODULE__{
      ets_table: table,
      last_aggregation: DateTime.utc_now(),
      current_window: init_window(),
      historical_windows: []
    }

    # Schedule periodic collection and aggregation
    schedule_collection()
    schedule_aggregation()

    Logger.info("SLO Tracker initialized")
    {:ok, state}
  end

  @impl true
  def handle_cast({:record_api_request, latency_ms, success?, endpoint}, state) do
    timestamp = System.system_time(:millisecond)

    :ets.insert(@ets_table, {:api_latency, timestamp, latency_ms})
    :ets.insert(@ets_table, {:api_request, timestamp, success?})
    :ets.insert(@ets_table, {:api_endpoint, timestamp, endpoint})

    # Update live metrics
    TamanduaServer.Observability.SLAMonitor.record_api_latency(latency_ms)

    {:noreply, state}
  end

  @impl true
  def handle_cast({:record_event_processing, latency_ms, success?}, state) do
    timestamp = System.system_time(:millisecond)

    :ets.insert(@ets_table, {:event_latency, timestamp, latency_ms})
    :ets.insert(@ets_table, {:event_processing, timestamp, success?})

    TamanduaServer.Observability.SLAMonitor.record_event_latency(latency_ms)

    {:noreply, state}
  end

  @impl true
  def handle_cast({:record_detection, latency_ms, success?, engine_type}, state) do
    timestamp = System.system_time(:millisecond)

    :ets.insert(@ets_table, {:detection_latency, timestamp, latency_ms})
    :ets.insert(@ets_table, {:detection_result, timestamp, success?})
    :ets.insert(@ets_table, {:detection_engine, timestamp, engine_type})

    TamanduaServer.Observability.SLAMonitor.record_detection_latency(latency_ms)

    {:noreply, state}
  end

  @impl true
  def handle_cast({:record_ml_prediction, latency_ms, success?}, state) do
    timestamp = System.system_time(:millisecond)

    :ets.insert(@ets_table, {:ml_latency, timestamp, latency_ms})
    :ets.insert(@ets_table, {:ml_prediction, timestamp, success?})

    {:noreply, state}
  end

  @impl true
  def handle_cast({:record_availability, is_up?}, state) do
    timestamp = System.system_time(:millisecond)
    status = if is_up?, do: 1, else: 0

    :ets.insert(@ets_table, {:availability, timestamp, status})

    TamanduaServer.Observability.SLAMonitor.record_availability(status)

    {:noreply, state}
  end

  @impl true
  def handle_call(:current_metrics, _from, state) do
    metrics = calculate_current_metrics()
    {:reply, metrics, state}
  end

  @impl true
  def handle_call({:service_metrics, service}, _from, state) do
    metrics = calculate_service_metrics(service)
    {:reply, metrics, state}
  end

  @impl true
  def handle_call(:error_budget_status, _from, state) do
    # Get availability samples
    availability_samples = get_recent_samples(:availability, 60)  # Last hour
    uptime_samples = Enum.map(availability_samples, fn {_ts, status} -> status end)

    # Calculate error budget
    budget = ErrorBudget.calculate_budget(uptime_samples, 30)

    # Calculate burn rate
    short_samples = get_recent_samples(:availability, 5) |> Enum.map(fn {_ts, s} -> s end)
    long_samples = get_recent_samples(:availability, 60) |> Enum.map(fn {_ts, s} -> s end)
    burn_rate = ErrorBudget.calculate_burn_rate(short_samples, long_samples)

    status = Map.merge(budget, %{burn_rate: burn_rate})

    {:reply, status, state}
  end

  @impl true
  def handle_info(:collect, state) do
    # Periodic collection - check system health
    is_up = check_system_health()
    record_availability_check(is_up)

    schedule_collection()
    {:noreply, state}
  end

  @impl true
  def handle_info(:aggregate, state) do
    # Aggregate metrics and save to historical windows
    state = perform_aggregation(state)

    schedule_aggregation()
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Private Functions

  defp init_window do
    %{
      start_time: DateTime.utc_now(),
      api: %{latencies: [], requests: [], errors: []},
      events: %{latencies: [], processed: [], errors: []},
      detections: %{latencies: [], total: [], errors: []},
      ml: %{latencies: [], predictions: [], errors: []},
      availability: []
    }
  end

  defp calculate_current_metrics do
    now = System.system_time(:millisecond)
    one_hour_ago = now - (60 * 60 * 1000)

    # Get samples from last hour
    api_latencies = get_samples_in_range(:api_latency, one_hour_ago, now)
    api_requests = get_samples_in_range(:api_request, one_hour_ago, now)

    event_latencies = get_samples_in_range(:event_latency, one_hour_ago, now)
    event_results = get_samples_in_range(:event_processing, one_hour_ago, now)

    detection_latencies = get_samples_in_range(:detection_latency, one_hour_ago, now)
    detection_results = get_samples_in_range(:detection_result, one_hour_ago, now)

    ml_latencies = get_samples_in_range(:ml_latency, one_hour_ago, now)
    ml_results = get_samples_in_range(:ml_prediction, one_hour_ago, now)

    availability_samples = get_samples_in_range(:availability, one_hour_ago, now)

    # Calculate SLIs
    %{
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
      api: %{
        latency: Calculator.calculate_latency(api_latencies, :api),
        error_rate: calculate_error_rate_from_results(api_requests),
        throughput: Calculator.calculate_throughput(length(api_requests), :hour, :api)
      },
      event_processing: %{
        latency: Calculator.calculate_latency(event_latencies, :events),
        error_rate: calculate_error_rate_from_results(event_results),
        throughput: Calculator.calculate_throughput(length(event_results), :hour, :events)
      },
      detection: %{
        latency: Calculator.calculate_latency(detection_latencies, :detection),
        error_rate: calculate_error_rate_from_results(detection_results),
        throughput: Calculator.calculate_throughput(length(detection_results), :hour, :detection)
      },
      ml_service: %{
        latency: Calculator.calculate_latency(ml_latencies, :ml),
        error_rate: calculate_error_rate_from_results(ml_results),
        throughput: Calculator.calculate_throughput(length(ml_results), :hour, :ml)
      },
      availability: Calculator.calculate_availability(availability_samples, :hour)
    }
  end

  defp calculate_service_metrics(service) do
    case service do
      :api -> get_service_slis(:api_latency, :api_request)
      :events -> get_service_slis(:event_latency, :event_processing)
      :detection -> get_service_slis(:detection_latency, :detection_result)
      :ml -> get_service_slis(:ml_latency, :ml_prediction)
      _ -> %{error: "Unknown service"}
    end
  end

  defp get_service_slis(latency_key, result_key) do
    now = System.system_time(:millisecond)
    one_hour_ago = now - (60 * 60 * 1000)

    latencies = get_samples_in_range(latency_key, one_hour_ago, now)
    results = get_samples_in_range(result_key, one_hour_ago, now)

    %{
      latency: Calculator.calculate_latency(latencies, :service),
      error_rate: calculate_error_rate_from_results(results),
      throughput: Calculator.calculate_throughput(length(results), :hour, :service),
      sample_count: length(results)
    }
  end

  defp get_samples_in_range(key, start_ts, end_ts) do
    :ets.select(@ets_table, [
      {{key, :"$1", :"$2"}, [{:andalso, {:>=, :"$1", start_ts}, {:"=<", :"$1", end_ts}}], [:"$2"]}
    ])
  end

  defp get_recent_samples(key, minutes) do
    now = System.system_time(:millisecond)
    cutoff = now - (minutes * 60 * 1000)

    :ets.select(@ets_table, [
      {{key, :"$1", :"$2"}, [{:>=, :"$1", cutoff}], [{{:"$1", :"$2"}}]}
    ])
  end

  defp calculate_error_rate_from_results(results) do
    total = length(results)
    errors = Enum.count(results, &(&1 == false))
    Calculator.calculate_error_rate(total, errors)
  end

  defp check_system_health do
    # Check if critical services are up
    try do
      # Check database
      TamanduaServer.Repo.__adapter__().checked_out?()

      # Check Broadway pipeline
      broadway_running = Process.whereis(TamanduaServer.Telemetry.Ingestor) != nil

      # Check agent registry
      registry_running = Process.whereis(TamanduaServer.Agents.Registry) != nil

      broadway_running and registry_running
    rescue
      _ -> false
    end
  end

  defp perform_aggregation(state) do
    # Calculate metrics for the current window
    metrics = calculate_current_metrics()

    # Create historical window entry
    window_entry = %{
      timestamp: DateTime.utc_now(),
      duration_minutes: 5,
      metrics: metrics
    }

    # Add to historical windows (keep last 12 = 1 hour)
    historical = [window_entry | state.historical_windows] |> Enum.take(288)  # 24 hours

    # Reset current window
    %{state |
      last_aggregation: DateTime.utc_now(),
      current_window: init_window(),
      historical_windows: historical
    }
  end

  defp schedule_collection do
    Process.send_after(self(), :collect, @collection_interval)
  end

  defp schedule_aggregation do
    Process.send_after(self(), :aggregate, @aggregation_interval)
  end
end
