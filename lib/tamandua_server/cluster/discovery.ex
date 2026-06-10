defmodule TamanduaServer.Cluster.Discovery do
  @moduledoc """
  Handles cluster node discovery and connection.

  Supports multiple discovery strategies:
  - DNS-based discovery (Kubernetes headless services)
  - Gossip protocol (libcluster gossip)
  - Static node list
  - etcd-based discovery
  """

  use GenServer
  require Logger

  @discovery_interval :timer.seconds(10)
  @connect_timeout :timer.seconds(5)

  defstruct [
    :topology,
    :dns_query,
    :static_nodes,
    connected_nodes: MapSet.new(),
    failed_connects: %{}
  ]

  # Client API

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Get all connected cluster nodes.
  """
  @spec connected_nodes() :: [node()]
  def connected_nodes do
    GenServer.call(__MODULE__, :connected_nodes)
  end

  @doc """
  Get cluster status including node count and health.
  """
  @spec cluster_status() :: map()
  def cluster_status do
    GenServer.call(__MODULE__, :cluster_status)
  end

  @doc """
  Force immediate node discovery.
  """
  @spec discover_now() :: :ok
  def discover_now do
    GenServer.cast(__MODULE__, :discover_now)
  end

  @doc """
  Check if this node is the cluster leader.
  """
  @spec is_leader?() :: boolean()
  def is_leader? do
    # Leader is the node with the lowest name (alphabetically)
    nodes = [node() | Node.list()]
    node() == Enum.min(nodes)
  end

  # Server Callbacks

  @impl true
  def init(opts) do
    topology = get_topology()
    state = %__MODULE__{
      topology: topology,
      dns_query: Application.get_env(:tamandua_server, :cluster_dns_query),
      static_nodes: Application.get_env(:tamandua_server, :cluster_nodes, [])
    }

    # Start discovery
    schedule_discovery(0)

    # Monitor node connections/disconnections
    :net_kernel.monitor_nodes(true)

    Logger.info("Cluster discovery started with topology: #{topology}")
    {:ok, state}
  end

  @impl true
  def handle_call(:connected_nodes, _from, state) do
    {:reply, MapSet.to_list(state.connected_nodes), state}
  end

  @impl true
  def handle_call(:cluster_status, _from, state) do
    status = %{
      topology: state.topology,
      current_node: node(),
      connected_nodes: MapSet.to_list(state.connected_nodes),
      node_count: MapSet.size(state.connected_nodes) + 1,
      is_leader: is_leader?(),
      failed_connections: Map.keys(state.failed_connects)
    }
    {:reply, status, state}
  end

  @impl true
  def handle_cast(:discover_now, state) do
    state = discover_nodes(state)
    {:noreply, state}
  end

  @impl true
  def handle_info(:discover, state) do
    state = discover_nodes(state)
    schedule_discovery(@discovery_interval)
    {:noreply, state}
  end

  @impl true
  def handle_info({:nodeup, node}, state) do
    Logger.info("Node connected: #{node}")
    state = %{state |
      connected_nodes: MapSet.put(state.connected_nodes, node),
      failed_connects: Map.delete(state.failed_connects, node)
    }

    # Notify cluster state manager
    TamanduaServer.Cluster.StateManager.sync_with_node(node)

    # Broadcast node up event
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "cluster:events",
      {:node_up, node}
    )

    {:noreply, state}
  end

  @impl true
  def handle_info({:nodedown, node}, state) do
    Logger.warning("Node disconnected: #{node}")
    state = %{state |
      connected_nodes: MapSet.delete(state.connected_nodes, node)
    }

    # Notify for agent redistribution
    TamanduaServer.Cluster.HashRing.node_removed(node)

    # Broadcast node down event
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "cluster:events",
      {:node_down, node}
    )

    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Private Functions

  defp get_topology do
    case Application.get_env(:tamandua_server, :cluster_topology, :none) do
      :dns -> :dns
      :gossip -> :gossip
      :static -> :static
      :etcd -> :etcd
      :kubernetes -> :kubernetes
      _ -> :none
    end
  end

  defp schedule_discovery(delay) do
    Process.send_after(self(), :discover, delay)
  end

  defp discover_nodes(%{topology: :none} = state), do: state

  defp discover_nodes(%{topology: :dns} = state) do
    case discover_dns(state.dns_query) do
      {:ok, nodes} ->
        connect_to_nodes(nodes, state)

      {:error, reason} ->
        Logger.warning("DNS discovery failed: #{inspect(reason)}")
        state
    end
  end

  defp discover_nodes(%{topology: :static} = state) do
    connect_to_nodes(state.static_nodes, state)
  end

  defp discover_nodes(%{topology: :kubernetes} = state) do
    # Use DNS SRV records for Kubernetes headless service
    case discover_kubernetes_dns() do
      {:ok, nodes} ->
        connect_to_nodes(nodes, state)

      {:error, reason} ->
        Logger.warning("Kubernetes discovery failed: #{inspect(reason)}")
        state
    end
  end

  defp discover_nodes(state), do: state

  defp discover_dns(nil), do: {:error, :no_dns_query}
  defp discover_dns(query) do
    case :inet_res.lookup(String.to_charlist(query), :in, :a) do
      [] ->
        {:error, :no_results}

      ips ->
        nodes = Enum.map(ips, fn ip ->
          # Construct node name from IP
          ip_str = :inet.ntoa(ip) |> to_string()
          release_name = Application.get_env(:tamandua_server, :release_name, "tamandua")
          String.to_atom("#{release_name}@#{ip_str}")
        end)
        {:ok, nodes}
    end
  end

  defp discover_kubernetes_dns do
    # Get pods via DNS SRV lookup for headless service
    service_name = Application.get_env(:tamandua_server, :k8s_service_name, "tamandua-server")
    namespace = Application.get_env(:tamandua_server, :k8s_namespace, "default")

    dns_name = "#{service_name}.#{namespace}.svc.cluster.local"

    case :inet_res.lookup(String.to_charlist(dns_name), :in, :a) do
      [] ->
        {:error, :no_pods_found}

      ips ->
        release_name = Application.get_env(:tamandua_server, :release_name, "tamandua")
        nodes = Enum.map(ips, fn ip ->
          ip_str = :inet.ntoa(ip) |> to_string()
          String.to_atom("#{release_name}@#{ip_str}")
        end)
        {:ok, nodes}
    end
  end

  defp connect_to_nodes(nodes, state) do
    current_node = node()

    Enum.reduce(nodes, state, fn target_node, acc ->
      if target_node != current_node and not MapSet.member?(acc.connected_nodes, target_node) do
        case Node.connect(target_node) do
          true ->
            Logger.info("Connected to node: #{target_node}")
            %{acc |
              connected_nodes: MapSet.put(acc.connected_nodes, target_node),
              failed_connects: Map.delete(acc.failed_connects, target_node)
            }

          false ->
            Logger.debug("Failed to connect to node: #{target_node}")
            failures = Map.get(acc.failed_connects, target_node, 0) + 1
            %{acc | failed_connects: Map.put(acc.failed_connects, target_node, failures)}

          :ignored ->
            acc
        end
      else
        acc
      end
    end)
  end
end
