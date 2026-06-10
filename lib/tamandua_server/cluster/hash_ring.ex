defmodule TamanduaServer.Cluster.HashRing do
  @moduledoc """
  Consistent hashing ring for distributing agents across cluster nodes.

  Provides:
  - Deterministic agent-to-node mapping
  - Minimal redistribution on node changes
  - Virtual nodes for better load balancing
  - Weighted node distribution
  """

  use GenServer
  require Logger

  @virtual_nodes 150
  @ets_table :tamandua_hash_ring

  defstruct [
    ring: nil,
    nodes: %{},
    virtual_nodes: @virtual_nodes
  ]

  # Client API

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Get the node responsible for handling a given agent.
  """
  @spec get_node(String.t()) :: node()
  def get_node(agent_id) do
    case :ets.lookup(@ets_table, :ring) do
      [{:ring, ring}] when ring != nil ->
        hash = hash_key(agent_id)
        find_node(ring, hash)

      _ ->
        # Fallback to local node if ring not initialized
        node()
    end
  end

  @doc """
  Check if an agent should be handled by this node.
  """
  @spec is_local?(String.t()) :: boolean()
  def is_local?(agent_id) do
    get_node(agent_id) == node()
  end

  @doc """
  Get all agents that should be on this node.
  """
  @spec local_agent_ids([String.t()]) :: [String.t()]
  def local_agent_ids(all_agent_ids) do
    Enum.filter(all_agent_ids, &is_local?/1)
  end

  @doc """
  Add a node to the hash ring.
  """
  @spec add_node(node(), keyword()) :: :ok
  def add_node(node_name, opts \\ []) do
    GenServer.call(__MODULE__, {:add_node, node_name, opts})
  end

  @doc """
  Remove a node from the hash ring.
  """
  @spec remove_node(node()) :: :ok
  def remove_node(node_name) do
    GenServer.call(__MODULE__, {:remove_node, node_name})
  end

  @doc """
  Called when a node leaves the cluster.
  Triggers agent redistribution.
  """
  @spec node_removed(node()) :: :ok
  def node_removed(node_name) do
    GenServer.cast(__MODULE__, {:node_removed, node_name})
  end

  @doc """
  Get the current ring state for debugging.
  """
  @spec ring_info() :: map()
  def ring_info do
    GenServer.call(__MODULE__, :ring_info)
  end

  @doc """
  Get agents that need to be migrated after ring change.
  Returns {agents_leaving_this_node, agents_coming_to_this_node}
  """
  @spec get_migration_plan([String.t()]) :: {[String.t()], [String.t()]}
  def get_migration_plan(all_agent_ids) do
    GenServer.call(__MODULE__, {:get_migration_plan, all_agent_ids})
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    # Create ETS table for fast lookups
    :ets.new(@ets_table, [:named_table, :set, :public, read_concurrency: true])

    # Initialize ring with current node
    state = %__MODULE__{}
    state = do_add_node(state, node(), [])

    # Subscribe to cluster events
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "cluster:events")

    Logger.info("Hash ring initialized with #{@virtual_nodes} virtual nodes per node")
    {:ok, state}
  end

  @impl true
  def handle_call({:add_node, node_name, opts}, _from, state) do
    state = do_add_node(state, node_name, opts)
    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:remove_node, node_name}, _from, state) do
    state = do_remove_node(state, node_name)
    {:reply, :ok, state}
  end

  @impl true
  def handle_call(:ring_info, _from, state) do
    info = %{
      nodes: Map.keys(state.nodes),
      node_count: map_size(state.nodes),
      virtual_nodes_per_node: state.virtual_nodes,
      total_ring_points: map_size(state.nodes) * state.virtual_nodes
    }
    {:reply, info, state}
  end

  @impl true
  def handle_call({:get_migration_plan, agent_ids}, _from, state) do
    current_node = node()

    {leaving, staying} = Enum.split_with(agent_ids, fn agent_id ->
      # Agent is leaving if it was local but now maps to different node
      get_node(agent_id) != current_node
    end)

    # Agents coming are handled by the target node checking is_local?
    {:reply, {leaving, staying}, state}
  end

  @impl true
  def handle_cast({:node_removed, node_name}, state) do
    state = do_remove_node(state, node_name)
    trigger_agent_redistribution()
    {:noreply, state}
  end

  @impl true
  def handle_info({:node_up, node_name}, state) do
    state = do_add_node(state, node_name, [])
    {:noreply, state}
  end

  @impl true
  def handle_info({:node_down, node_name}, state) do
    state = do_remove_node(state, node_name)
    trigger_agent_redistribution()
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # Private Functions

  defp do_add_node(state, node_name, opts) do
    weight = Keyword.get(opts, :weight, 1)
    virtual_count = state.virtual_nodes * weight

    # Generate virtual node positions
    virtual_positions = for i <- 1..virtual_count do
      key = "#{node_name}:#{i}"
      {hash_key(key), node_name}
    end

    # Update nodes map
    nodes = Map.put(state.nodes, node_name, %{
      weight: weight,
      virtual_count: virtual_count
    })

    # Rebuild ring
    ring = rebuild_ring(nodes, state.virtual_nodes)
    :ets.insert(@ets_table, {:ring, ring})

    Logger.info("Added node #{node_name} to hash ring (weight: #{weight})")
    %{state | nodes: nodes, ring: ring}
  end

  defp do_remove_node(state, node_name) do
    nodes = Map.delete(state.nodes, node_name)

    ring = rebuild_ring(nodes, state.virtual_nodes)
    :ets.insert(@ets_table, {:ring, ring})

    Logger.info("Removed node #{node_name} from hash ring")
    %{state | nodes: nodes, ring: ring}
  end

  defp rebuild_ring(nodes, virtual_nodes_count) do
    nodes
    |> Enum.flat_map(fn {node_name, %{weight: weight}} ->
      virtual_count = virtual_nodes_count * weight
      for i <- 1..virtual_count do
        key = "#{node_name}:#{i}"
        {hash_key(key), node_name}
      end
    end)
    |> Enum.sort_by(fn {hash, _node} -> hash end)
    |> :array.from_list()
  end

  defp hash_key(key) when is_binary(key) do
    :crypto.hash(:sha256, key)
    |> :binary.decode_unsigned()
  end

  defp hash_key(key), do: hash_key(to_string(key))

  defp find_node(ring, hash) do
    size = :array.size(ring)

    if size == 0 do
      node()
    else
      # Binary search for the node
      index = binary_search(ring, hash, 0, size - 1)
      {_hash, node_name} = :array.get(index, ring)
      node_name
    end
  end

  defp binary_search(ring, hash, low, high) when low <= high do
    mid = div(low + high, 2)
    {ring_hash, _node} = :array.get(mid, ring)

    cond do
      hash < ring_hash and mid == 0 ->
        # Wrap around to first node
        0

      hash < ring_hash ->
        binary_search(ring, hash, low, mid - 1)

      hash > ring_hash and mid == high ->
        # Wrap around to first node
        0

      hash > ring_hash ->
        binary_search(ring, hash, mid + 1, high)

      true ->
        mid
    end
  end

  defp binary_search(_ring, _hash, _low, _high) do
    # Wrap around to first node
    0
  end

  defp trigger_agent_redistribution do
    # Notify agent registry to check agent ownership
    spawn(fn ->
      # Small delay to allow ring to settle
      Process.sleep(1000)

      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "cluster:events",
        :redistribute_agents
      )
    end)
  end
end
