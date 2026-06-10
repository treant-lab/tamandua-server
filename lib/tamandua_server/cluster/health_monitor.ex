defmodule TamanduaServer.Cluster.HealthMonitor do
  @moduledoc """
  Monitors cluster health and node availability.

  Tracks:
  - Node responsiveness
  - Network partitions
  - Resource utilization per node
  - Service availability
  """

  use GenServer
  require Logger

  @health_check_interval :timer.seconds(10)
  @node_timeout :timer.seconds(5)

  defstruct [
    node_health: %{},
    last_partition_detected: nil,
    cluster_status: :healthy
  ]

  # Client API

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Get overall cluster health status.
  """
  @spec cluster_health() :: map()
  def cluster_health do
    GenServer.call(__MODULE__, :cluster_health)
  end

  @doc """
  Get health status for a specific node.
  """
  @spec node_health(node()) :: {:ok, map()} | {:error, :not_found}
  def node_health(node_name) do
    GenServer.call(__MODULE__, {:node_health, node_name})
  end

  @doc """
  Check if cluster is healthy.
  """
  @spec healthy?() :: boolean()
  def healthy? do
    GenServer.call(__MODULE__, :healthy?)
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    state = %__MODULE__{}

    # Start health monitoring
    schedule_health_check()

    # Monitor node events
    :net_kernel.monitor_nodes(true)

    Logger.info("Cluster health monitor started")
    {:ok, state}
  end

  @impl true
  def handle_call(:cluster_health, _from, state) do
    health = %{
      status: state.cluster_status,
      node_count: map_size(state.node_health) + 1,
      nodes: Map.merge(state.node_health, %{node() => local_health()}),
      last_partition: state.last_partition_detected,
      timestamp: System.system_time(:millisecond)
    }
    {:reply, health, state}
  end

  @impl true
  def handle_call({:node_health, node_name}, _from, state) do
    if node_name == node() do
      {:reply, {:ok, local_health()}, state}
    else
      case Map.get(state.node_health, node_name) do
        nil -> {:reply, {:error, :not_found}, state}
        health -> {:reply, {:ok, health}, state}
      end
    end
  end

  @impl true
  def handle_call(:healthy?, _from, state) do
    {:reply, state.cluster_status == :healthy, state}
  end

  @impl true
  def handle_info(:health_check, state) do
    state = perform_health_check(state)
    schedule_health_check()
    {:noreply, state}
  end

  @impl true
  def handle_info({:nodeup, node_name}, state) do
    Logger.info("Node joined cluster: #{node_name}")
    state = update_cluster_status(state)
    {:noreply, state}
  end

  @impl true
  def handle_info({:nodedown, node_name}, state) do
    Logger.warning("Node left cluster: #{node_name}")

    node_health = Map.delete(state.node_health, node_name)
    state = %{state | node_health: node_health}
    state = update_cluster_status(state)

    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Private Functions

  defp schedule_health_check do
    Process.send_after(self(), :health_check, @health_check_interval)
  end

  defp perform_health_check(state) do
    nodes = Node.list()

    node_health = Enum.reduce(nodes, %{}, fn node_name, acc ->
      case check_node_health(node_name) do
        {:ok, health} ->
          Map.put(acc, node_name, health)

        {:error, _reason} ->
          # Node unreachable
          Map.put(acc, node_name, %{status: :unreachable, timestamp: System.system_time(:millisecond)})
      end
    end)

    state = %{state | node_health: node_health}
    update_cluster_status(state)
  end

  defp check_node_health(node_name) do
    task = Task.async(fn ->
      :rpc.call(node_name, __MODULE__, :get_local_health, [], @node_timeout)
    end)

    case Task.yield(task, @node_timeout) || Task.shutdown(task) do
      {:ok, {:badrpc, reason}} ->
        {:error, reason}

      {:ok, health} ->
        {:ok, Map.put(health, :timestamp, System.system_time(:millisecond))}

      nil ->
        {:error, :timeout}
    end
  end

  @doc false
  def get_local_health do
    local_health()
  end

  defp local_health do
    %{
      status: :healthy,
      cpu_percent: get_cpu_utilization(),
      memory_percent: get_memory_utilization(),
      process_count: length(Process.list()),
      message_queue_total: total_message_queue_length(),
      uptime_seconds: :erlang.statistics(:wall_clock) |> elem(0) |> div(1000),
      schedulers: System.schedulers_online(),
      timestamp: System.system_time(:millisecond)
    }
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

  defp total_message_queue_length do
    Process.list()
    |> Enum.reduce(0, fn pid, acc ->
      case Process.info(pid, :message_queue_len) do
        {:message_queue_len, len} -> acc + len
        _ -> acc
      end
    end)
  end

  defp update_cluster_status(state) do
    # Determine overall cluster status
    all_nodes = [node() | Node.list()]
    healthy_count = Enum.count(Map.values(state.node_health), fn h ->
      h[:status] == :healthy
    end) + 1  # Include local node

    status = cond do
      healthy_count == length(all_nodes) ->
        :healthy

      healthy_count >= div(length(all_nodes), 2) + 1 ->
        :degraded

      true ->
        :critical
    end

    if status != state.cluster_status do
      Logger.warning("Cluster status changed: #{state.cluster_status} -> #{status}")

      # Broadcast status change
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "cluster:events",
        {:cluster_status_changed, status}
      )
    end

    %{state | cluster_status: status}
  end
end
