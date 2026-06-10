defmodule TamanduaServer.Cluster.AutoScaler do
  @moduledoc """
  Auto-scaling coordinator for the Tamandua cluster.

  Monitors cluster metrics and coordinates scaling decisions:
  - CPU utilization across nodes
  - Memory pressure
  - Event queue depth
  - Connection count
  - Processing latency

  Supports scaling strategies:
  - Kubernetes HPA via metrics endpoint
  - AWS Auto Scaling Groups
  - Azure VMSS
  - Custom webhook triggers
  """

  use GenServer
  require Logger

  @metrics_interval :timer.seconds(15)
  @scale_cooldown :timer.minutes(5)

  # Scaling thresholds
  @cpu_scale_up_threshold 80
  @cpu_scale_down_threshold 30
  @memory_scale_up_threshold 85
  @queue_depth_scale_up_threshold 10_000
  @latency_scale_up_threshold_ms 500
  @min_nodes 2
  @max_nodes 20

  defstruct [
    :last_scale_action,
    :scale_cooldown_until,
    metrics_history: [],
    current_recommendations: %{}
  ]

  # Client API

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Get current scaling metrics.
  """
  @spec get_metrics() :: map()
  def get_metrics do
    GenServer.call(__MODULE__, :get_metrics)
  end

  @doc """
  Get scaling recommendation.
  """
  @spec get_recommendation() :: {:scale_up, integer()} | {:scale_down, integer()} | :no_change
  def get_recommendation do
    GenServer.call(__MODULE__, :get_recommendation)
  end

  @doc """
  Trigger a scaling action (for manual intervention).
  """
  @spec trigger_scale(atom(), integer()) :: :ok | {:error, term()}
  def trigger_scale(direction, count) when direction in [:up, :down] do
    GenServer.call(__MODULE__, {:trigger_scale, direction, count})
  end

  @doc """
  Get metrics in Prometheus format for Kubernetes HPA.
  """
  @spec prometheus_metrics() :: String.t()
  def prometheus_metrics do
    GenServer.call(__MODULE__, :prometheus_metrics)
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    state = %__MODULE__{}

    # Schedule periodic metrics collection
    schedule_metrics_collection()

    Logger.info("Auto-scaler initialized")
    {:ok, state}
  end

  @impl true
  def handle_call(:get_metrics, _from, state) do
    metrics = collect_cluster_metrics()
    {:reply, metrics, state}
  end

  @impl true
  def handle_call(:get_recommendation, _from, state) do
    recommendation = calculate_scaling_recommendation(state)
    {:reply, recommendation, state}
  end

  @impl true
  def handle_call({:trigger_scale, direction, count}, _from, state) do
    result = execute_scaling_action(direction, count, state)
    {:reply, result, update_scale_cooldown(state)}
  end

  @impl true
  def handle_call(:prometheus_metrics, _from, state) do
    metrics = format_prometheus_metrics(state)
    {:reply, metrics, state}
  end

  @impl true
  def handle_info(:collect_metrics, state) do
    metrics = collect_cluster_metrics()

    # Store in history (keep last 20 samples)
    history = [metrics | Enum.take(state.metrics_history, 19)]

    # Calculate recommendation based on trends
    recommendation = calculate_scaling_recommendation(%{state | metrics_history: history})

    # Auto-execute scaling if enabled and not in cooldown
    state = if auto_scaling_enabled?() and not in_cooldown?(state) do
      maybe_execute_scaling(recommendation, state)
    else
      state
    end

    # Broadcast metrics to monitoring
    broadcast_metrics(metrics, recommendation)

    schedule_metrics_collection()
    {:noreply, %{state | metrics_history: history, current_recommendations: recommendation}}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Private Functions

  defp schedule_metrics_collection do
    Process.send_after(self(), :collect_metrics, @metrics_interval)
  end

  defp collect_cluster_metrics do
    nodes = [node() | Node.list()]

    # Collect metrics from all nodes
    node_metrics = Enum.map(nodes, fn n ->
      case :rpc.call(n, __MODULE__, :collect_local_metrics, [], 5000) do
        {:badrpc, _} -> nil
        metrics -> Map.put(metrics, :node, n)
      end
    end)
    |> Enum.reject(&is_nil/1)

    # Aggregate metrics
    %{
      timestamp: System.system_time(:millisecond),
      node_count: length(nodes),
      nodes: node_metrics,
      cluster: aggregate_node_metrics(node_metrics)
    }
  end

  @doc false
  def collect_local_metrics do
    %{
      cpu_percent: get_cpu_utilization(),
      memory_percent: get_memory_utilization(),
      queue_depth: get_queue_depth(),
      connection_count: get_connection_count(),
      event_rate: get_event_rate(),
      processing_latency_ms: get_processing_latency(),
      agent_count: get_local_agent_count()
    }
  end

  defp aggregate_node_metrics(node_metrics) do
    if Enum.empty?(node_metrics) do
      %{
        avg_cpu: 0,
        avg_memory: 0,
        total_queue_depth: 0,
        total_connections: 0,
        total_event_rate: 0,
        avg_latency_ms: 0,
        total_agents: 0
      }
    else
      count = length(node_metrics)

      %{
        avg_cpu: Enum.sum(Enum.map(node_metrics, & &1.cpu_percent)) / count,
        avg_memory: Enum.sum(Enum.map(node_metrics, & &1.memory_percent)) / count,
        total_queue_depth: Enum.sum(Enum.map(node_metrics, & &1.queue_depth)),
        total_connections: Enum.sum(Enum.map(node_metrics, & &1.connection_count)),
        total_event_rate: Enum.sum(Enum.map(node_metrics, & &1.event_rate)),
        avg_latency_ms: Enum.sum(Enum.map(node_metrics, & &1.processing_latency_ms)) / count,
        total_agents: Enum.sum(Enum.map(node_metrics, & &1.agent_count))
      }
    end
  end

  defp get_cpu_utilization do
    case :cpu_sup.util() do
      {:ok, usage} -> usage
      _ -> 0
    end
  rescue
    _ -> 0
  end

  defp get_memory_utilization do
    case :memsup.get_system_memory_data() do
      [{:total_memory, total}, {:free_memory, free} | _] when total > 0 ->
        ((total - free) / total) * 100

      _ ->
        0
    end
  rescue
    _ -> 0
  end

  defp get_queue_depth do
    # Get Broadway queue depth
    case Process.whereis(TamanduaServer.Telemetry.Ingestor) do
      nil -> 0
      pid ->
        case Process.info(pid, :message_queue_len) do
          {:message_queue_len, len} -> len
          _ -> 0
        end
    end
  end

  defp get_connection_count do
    length(:ranch.procs(TamanduaServerWeb.Endpoint.HTTP, :connections))
  rescue
    _ -> 0
  end

  defp get_event_rate do
    # Events per second (would need proper tracking)
    0
  end

  defp get_processing_latency do
    # Average processing latency in ms
    0
  end

  defp get_local_agent_count do
    TamanduaServer.Agents.Registry.list_all()
    |> Enum.count()
  end

  defp calculate_scaling_recommendation(state) do
    history = state.metrics_history

    if length(history) < 3 do
      :no_change
    else
      # Calculate trends from recent metrics
      recent = Enum.take(history, 5)
      cluster_metrics = Enum.map(recent, & &1.cluster)

      avg_cpu = Enum.sum(Enum.map(cluster_metrics, & &1.avg_cpu)) / length(cluster_metrics)
      avg_memory = Enum.sum(Enum.map(cluster_metrics, & &1.avg_memory)) / length(cluster_metrics)
      avg_queue = Enum.sum(Enum.map(cluster_metrics, & &1.total_queue_depth)) / length(cluster_metrics)
      avg_latency = Enum.sum(Enum.map(cluster_metrics, & &1.avg_latency_ms)) / length(cluster_metrics)

      current_nodes = List.first(history).node_count

      cond do
        # Scale up conditions
        avg_cpu > @cpu_scale_up_threshold and current_nodes < @max_nodes ->
          nodes_to_add = min(2, @max_nodes - current_nodes)
          {:scale_up, nodes_to_add}

        avg_memory > @memory_scale_up_threshold and current_nodes < @max_nodes ->
          nodes_to_add = min(2, @max_nodes - current_nodes)
          {:scale_up, nodes_to_add}

        avg_queue > @queue_depth_scale_up_threshold and current_nodes < @max_nodes ->
          {:scale_up, 1}

        avg_latency > @latency_scale_up_threshold_ms and current_nodes < @max_nodes ->
          {:scale_up, 1}

        # Scale down conditions
        avg_cpu < @cpu_scale_down_threshold and
        avg_memory < 50 and
        avg_queue < 100 and
        current_nodes > @min_nodes ->
          {:scale_down, 1}

        true ->
          :no_change
      end
    end
  end

  defp auto_scaling_enabled? do
    Application.get_env(:tamandua_server, :auto_scaling_enabled, false)
  end

  defp in_cooldown?(state) do
    case state.scale_cooldown_until do
      nil -> false
      cooldown_until -> System.system_time(:millisecond) < cooldown_until
    end
  end

  defp update_scale_cooldown(state) do
    %{state |
      scale_cooldown_until: System.system_time(:millisecond) + @scale_cooldown,
      last_scale_action: System.system_time(:millisecond)
    }
  end

  defp maybe_execute_scaling(:no_change, state), do: state

  defp maybe_execute_scaling({direction, count}, state) do
    case execute_scaling_action(direction, count, state) do
      :ok ->
        Logger.info("Auto-scaling executed: #{direction} by #{count}")
        update_scale_cooldown(state)

      {:error, reason} ->
        Logger.warning("Auto-scaling failed: #{inspect(reason)}")
        state
    end
  end

  defp execute_scaling_action(direction, count, _state) do
    scaling_provider = Application.get_env(:tamandua_server, :scaling_provider, :kubernetes)

    case scaling_provider do
      :kubernetes ->
        execute_kubernetes_scale(direction, count)

      :aws ->
        execute_aws_scale(direction, count)

      :azure ->
        execute_azure_scale(direction, count)

      :webhook ->
        execute_webhook_scale(direction, count)

      _ ->
        {:error, :unknown_provider}
    end
  end

  defp execute_kubernetes_scale(direction, count) do
    # Update deployment replica count
    namespace = Application.get_env(:tamandua_server, :k8s_namespace, "default")
    deployment = Application.get_env(:tamandua_server, :k8s_deployment, "tamandua-server")

    delta = case direction do
      :up -> count
      :down -> -count
    end

    # This would use the Kubernetes API
    Logger.info("Would scale Kubernetes deployment #{namespace}/#{deployment} by #{delta}")
    :ok
  end

  defp execute_aws_scale(direction, count) do
    # Update ASG desired capacity
    asg_name = Application.get_env(:tamandua_server, :aws_asg_name)

    Logger.info("Would scale AWS ASG #{asg_name} #{direction} by #{count}")
    :ok
  end

  defp execute_azure_scale(direction, count) do
    # Update VMSS instance count
    vmss_name = Application.get_env(:tamandua_server, :azure_vmss_name)

    Logger.info("Would scale Azure VMSS #{vmss_name} #{direction} by #{count}")
    :ok
  end

  defp execute_webhook_scale(direction, count) do
    webhook_url = Application.get_env(:tamandua_server, :scaling_webhook_url)

    if webhook_url do
      payload = Jason.encode!(%{
        action: "scale",
        direction: direction,
        count: count,
        timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
      })

      case Req.post(webhook_url, body: payload, headers: [{"content-type", "application/json"}]) do
        {:ok, %{status: status}} when status in 200..299 ->
          :ok

        {:ok, %{status: status}} ->
          {:error, {:http_error, status}}

        {:error, reason} ->
          {:error, reason}
      end
    else
      {:error, :no_webhook_configured}
    end
  end

  defp broadcast_metrics(metrics, recommendation) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "cluster:metrics",
      {:scaling_metrics, metrics, recommendation}
    )
  end

  defp format_prometheus_metrics(state) do
    metrics = List.first(state.metrics_history) || %{cluster: %{}}
    cluster = metrics[:cluster] || %{}

    """
    # HELP tamandua_cluster_cpu_percent Average CPU utilization across cluster
    # TYPE tamandua_cluster_cpu_percent gauge
    tamandua_cluster_cpu_percent #{cluster[:avg_cpu] || 0}

    # HELP tamandua_cluster_memory_percent Average memory utilization across cluster
    # TYPE tamandua_cluster_memory_percent gauge
    tamandua_cluster_memory_percent #{cluster[:avg_memory] || 0}

    # HELP tamandua_cluster_node_count Number of nodes in cluster
    # TYPE tamandua_cluster_node_count gauge
    tamandua_cluster_node_count #{metrics[:node_count] || 1}

    # HELP tamandua_cluster_queue_depth Total event queue depth
    # TYPE tamandua_cluster_queue_depth gauge
    tamandua_cluster_queue_depth #{cluster[:total_queue_depth] || 0}

    # HELP tamandua_cluster_agent_count Total connected agents
    # TYPE tamandua_cluster_agent_count gauge
    tamandua_cluster_agent_count #{cluster[:total_agents] || 0}

    # HELP tamandua_cluster_event_rate Events per second across cluster
    # TYPE tamandua_cluster_event_rate gauge
    tamandua_cluster_event_rate #{cluster[:total_event_rate] || 0}

    # HELP tamandua_cluster_latency_ms Average processing latency
    # TYPE tamandua_cluster_latency_ms gauge
    tamandua_cluster_latency_ms #{cluster[:avg_latency_ms] || 0}
    """
  end
end
