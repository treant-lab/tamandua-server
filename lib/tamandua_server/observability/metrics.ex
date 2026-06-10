defmodule TamanduaServer.Observability.Metrics do
  @moduledoc """
  Prometheus metrics for Tamandua EDR.

  Exposes metrics for:
  - Agent connections and status
  - Event processing throughput
  - Detection engine performance
  - Alert generation rates
  - System resources
  - Cluster health
  """

  use GenServer
  require Logger

  @metrics_port 9568
  @collection_interval :timer.seconds(15)

  # Metric definitions
  @agent_metrics [
    :tamandua_agents_total,
    :tamandua_agents_online,
    :tamandua_agents_offline,
    :tamandua_agents_isolated
  ]

  @event_metrics [
    :tamandua_events_received_total,
    :tamandua_events_processed_total,
    :tamandua_events_failed_total,
    :tamandua_events_per_second,
    :tamandua_event_processing_latency_ms
  ]

  @detection_metrics [
    :tamandua_detections_total,
    :tamandua_detections_by_severity,
    :tamandua_detections_by_technique,
    :tamandua_detection_latency_ms,
    :tamandua_yara_scans_total,
    :tamandua_sigma_evaluations_total,
    :tamandua_ml_predictions_total
  ]

  @alert_metrics [
    :tamandua_alerts_total,
    :tamandua_alerts_by_severity,
    :tamandua_alerts_resolved_total,
    :tamandua_alert_mttr_seconds
  ]

  defstruct [
    :metrics_server,
    counters: %{},
    gauges: %{},
    histograms: %{}
  ]

  # Client API

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Increment a counter metric.
  """
  @spec increment(atom(), integer(), keyword()) :: :ok
  def increment(metric, value \\ 1, labels \\ []) do
    GenServer.cast(__MODULE__, {:increment, metric, value, labels})
  end

  @doc """
  Set a gauge value.
  """
  @spec set_gauge(atom(), number(), keyword()) :: :ok
  def set_gauge(metric, value, labels \\ []) do
    GenServer.cast(__MODULE__, {:set_gauge, metric, value, labels})
  end

  @doc """
  Record a histogram observation.
  """
  @spec observe(atom(), number(), keyword()) :: :ok
  def observe(metric, value, labels \\ []) do
    GenServer.cast(__MODULE__, {:observe, metric, value, labels})
  end

  @doc """
  Get all metrics in Prometheus text format.
  """
  @spec prometheus_format() :: String.t()
  def prometheus_format do
    GenServer.call(__MODULE__, :prometheus_format)
  end

  @doc """
  Get metrics as a map for internal use.
  """
  @spec get_all() :: map()
  def get_all do
    GenServer.call(__MODULE__, :get_all)
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    state = %__MODULE__{
      counters: init_counters(),
      gauges: init_gauges(),
      histograms: init_histograms()
    }

    # Start metrics HTTP server
    start_metrics_server()

    # Schedule periodic collection
    schedule_collection()

    Logger.info("Observability metrics initialized on port #{@metrics_port}")
    {:ok, state}
  end

  @impl true
  def handle_cast({:increment, metric, value, labels}, state) do
    key = {metric, labels_to_key(labels)}
    counters = Map.update(state.counters, key, value, &(&1 + value))
    {:noreply, %{state | counters: counters}}
  end

  @impl true
  def handle_cast({:set_gauge, metric, value, labels}, state) do
    key = {metric, labels_to_key(labels)}
    gauges = Map.put(state.gauges, key, value)
    {:noreply, %{state | gauges: gauges}}
  end

  @impl true
  def handle_cast({:observe, metric, value, labels}, state) do
    key = {metric, labels_to_key(labels)}

    histograms = Map.update(state.histograms, key, [value], fn observations ->
      # Keep last 1000 observations
      Enum.take([value | observations], 1000)
    end)

    {:noreply, %{state | histograms: histograms}}
  end

  @impl true
  def handle_call(:prometheus_format, _from, state) do
    output = format_prometheus(state)
    {:reply, output, state}
  end

  @impl true
  def handle_call(:get_all, _from, state) do
    metrics = %{
      counters: state.counters,
      gauges: state.gauges,
      histograms: summarize_histograms(state.histograms)
    }
    {:reply, metrics, state}
  end

  @impl true
  def handle_info(:collect, state) do
    state = collect_system_metrics(state)
    schedule_collection()
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Private Functions

  defp init_counters do
    %{}
  end

  defp init_gauges do
    %{}
  end

  defp init_histograms do
    %{}
  end

  defp labels_to_key([]), do: ""
  defp labels_to_key(labels) do
    labels
    |> Enum.sort()
    |> Enum.map(fn {k, v} -> "#{k}=\"#{v}\"" end)
    |> Enum.join(",")
  end

  defp schedule_collection do
    Process.send_after(self(), :collect, @collection_interval)
  end

  defp start_metrics_server do
    # Start a simple HTTP server for metrics
    dispatch = :cowboy_router.compile([
      {:_, [
        {"/metrics", TamanduaServer.Observability.MetricsHandler, []},
        {"/health", TamanduaServer.Observability.HealthHandler, []}
      ]}
    ])

    {:ok, _} = :cowboy.start_clear(
      :metrics_http,
      [port: @metrics_port],
      %{env: %{dispatch: dispatch}}
    )
  rescue
    e ->
      Logger.warning("Failed to start metrics server: #{inspect(e)}")
  end

  defp collect_system_metrics(state) do
    now = System.system_time(:millisecond)

    # Collect agent metrics
    agent_stats = TamanduaServer.Agents.Registry.count_by_status()
    total_agents = Enum.sum(Map.values(agent_stats))

    gauges = state.gauges
    |> Map.put({:tamandua_agents_total, ""}, total_agents)
    |> Map.put({:tamandua_agents_online, ""}, Map.get(agent_stats, :online, 0))
    |> Map.put({:tamandua_agents_offline, ""}, Map.get(agent_stats, :offline, 0))
    |> Map.put({:tamandua_agents_isolated, ""}, Map.get(agent_stats, :isolated, 0))

    # System metrics
    gauges = gauges
    |> Map.put({:tamandua_erlang_process_count, ""}, length(Process.list()))
    |> Map.put({:tamandua_erlang_memory_bytes, "type=\"total\""}, :erlang.memory(:total))
    |> Map.put({:tamandua_erlang_memory_bytes, "type=\"processes\""}, :erlang.memory(:processes))
    |> Map.put({:tamandua_erlang_memory_bytes, "type=\"ets\""}, :erlang.memory(:ets))
    |> Map.put({:tamandua_cluster_node_count, ""}, length(Node.list()) + 1)

    # Collect cluster metrics if available
    gauges = try do
      cluster_health = TamanduaServer.Cluster.HealthMonitor.cluster_health()
      Map.put(gauges, {:tamandua_cluster_healthy, ""}, if(cluster_health.status == :healthy, do: 1, else: 0))
    rescue
      _ -> gauges
    end

    %{state | gauges: gauges}
  end

  defp format_prometheus(state) do
    lines = []

    # Format counters
    counter_lines = Enum.flat_map(state.counters, fn {{metric, labels}, value} ->
      label_str = if labels == "", do: "", else: "{#{labels}}"
      [
        "# TYPE #{metric} counter",
        "#{metric}#{label_str} #{value}"
      ]
    end)

    # Format gauges
    gauge_lines = Enum.flat_map(state.gauges, fn {{metric, labels}, value} ->
      label_str = if labels == "", do: "", else: "{#{labels}}"
      [
        "# TYPE #{metric} gauge",
        "#{metric}#{label_str} #{value}"
      ]
    end)

    # Format histograms
    histogram_lines = Enum.flat_map(state.histograms, fn {{metric, labels}, observations} ->
      label_str = if labels == "", do: "", else: "{#{labels}}"
      summary = calculate_histogram_summary(observations)

      [
        "# TYPE #{metric} histogram",
        "#{metric}_sum#{label_str} #{summary.sum}",
        "#{metric}_count#{label_str} #{summary.count}",
        "#{metric}_bucket{le=\"0.01\"#{if labels != "", do: ",#{labels}", else: ""}} #{summary.bucket_001}",
        "#{metric}_bucket{le=\"0.05\"#{if labels != "", do: ",#{labels}", else: ""}} #{summary.bucket_005}",
        "#{metric}_bucket{le=\"0.1\"#{if labels != "", do: ",#{labels}", else: ""}} #{summary.bucket_01}",
        "#{metric}_bucket{le=\"0.5\"#{if labels != "", do: ",#{labels}", else: ""}} #{summary.bucket_05}",
        "#{metric}_bucket{le=\"1\"#{if labels != "", do: ",#{labels}", else: ""}} #{summary.bucket_1}",
        "#{metric}_bucket{le=\"5\"#{if labels != "", do: ",#{labels}", else: ""}} #{summary.bucket_5}",
        "#{metric}_bucket{le=\"+Inf\"#{if labels != "", do: ",#{labels}", else: ""}} #{summary.count}"
      ]
    end)

    (counter_lines ++ gauge_lines ++ histogram_lines)
    |> Enum.uniq()
    |> Enum.join("\n")
  end

  defp calculate_histogram_summary(observations) do
    sorted = Enum.sort(observations)
    count = length(sorted)
    sum = Enum.sum(sorted)

    %{
      count: count,
      sum: sum,
      bucket_001: Enum.count(sorted, &(&1 <= 0.01)),
      bucket_005: Enum.count(sorted, &(&1 <= 0.05)),
      bucket_01: Enum.count(sorted, &(&1 <= 0.1)),
      bucket_05: Enum.count(sorted, &(&1 <= 0.5)),
      bucket_1: Enum.count(sorted, &(&1 <= 1)),
      bucket_5: Enum.count(sorted, &(&1 <= 5))
    }
  end

  defp summarize_histograms(histograms) do
    Enum.map(histograms, fn {key, observations} ->
      sorted = Enum.sort(observations)
      count = length(sorted)

      summary = if count > 0 do
        %{
          count: count,
          min: Enum.min(sorted),
          max: Enum.max(sorted),
          avg: Enum.sum(sorted) / count,
          p50: percentile(sorted, 50),
          p90: percentile(sorted, 90),
          p99: percentile(sorted, 99)
        }
      else
        %{count: 0}
      end

      {key, summary}
    end)
    |> Map.new()
  end

  defp percentile(sorted_list, p) do
    count = length(sorted_list)
    if count == 0 do
      0
    else
      index = round(p / 100 * count) - 1
      index = max(0, min(index, count - 1))
      Enum.at(sorted_list, index)
    end
  end
end
