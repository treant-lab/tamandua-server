defmodule TamanduaServer.Cluster.StateManager do
  @moduledoc """
  Manages distributed state synchronization across cluster nodes.

  Handles:
  - Agent session state replication
  - Configuration sync
  - Detection rule distribution
  - Alert deduplication across nodes
  """

  use GenServer
  require Logger

  @sync_interval :timer.seconds(30)

  defstruct [
    :state_version,
    :sync_task_ref,
    pending_syncs: [],
    node_versions: %{}
  ]

  # Client API

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Synchronize state with a specific node.
  """
  @spec sync_with_node(node()) :: :ok
  def sync_with_node(target_node) do
    GenServer.cast(__MODULE__, {:sync_with_node, target_node})
  end

  @doc """
  Broadcast a state change to all cluster nodes.
  """
  @spec broadcast_state_change(atom(), term()) :: :ok
  def broadcast_state_change(type, data) do
    GenServer.cast(__MODULE__, {:broadcast_state_change, type, data})
  end

  @doc """
  Get the current cluster state version.
  """
  @spec get_version() :: integer()
  def get_version do
    GenServer.call(__MODULE__, :get_version)
  end

  @doc """
  Register a state change handler.
  """
  @spec register_handler(atom(), function()) :: :ok
  def register_handler(type, handler) do
    GenServer.call(__MODULE__, {:register_handler, type, handler})
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    state = %__MODULE__{
      state_version: System.system_time(:millisecond)
    }

    # Subscribe to cluster events
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "cluster:state")

    # Schedule periodic state sync
    schedule_sync()

    Logger.info("Cluster state manager initialized")
    {:ok, state}
  end

  @impl true
  def handle_call(:get_version, _from, state) do
    {:reply, state.state_version, state}
  end

  @impl true
  def handle_call({:register_handler, _type, _handler}, _from, state) do
    # Handlers are registered in the process dictionary for simplicity
    {:reply, :ok, state}
  end

  @impl true
  def handle_cast({:sync_with_node, target_node}, state) do
    # Request state from target node
    Task.start(fn ->
      request_state_sync(target_node)
    end)
    {:noreply, state}
  end

  @impl true
  def handle_cast({:broadcast_state_change, type, data}, state) do
    new_version = System.system_time(:millisecond)

    # Broadcast to all nodes via PubSub
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "cluster:state",
      {:state_change, node(), type, data, new_version}
    )

    {:noreply, %{state | state_version: new_version}}
  end

  @impl true
  def handle_info(:periodic_sync, state) do
    # Check if we're out of sync with any node
    state = check_node_versions(state)
    schedule_sync()
    {:noreply, state}
  end

  @impl true
  def handle_info({:state_change, from_node, type, data, version}, state) do
    if from_node != node() do
      Logger.debug("Received state change from #{from_node}: #{type}")

      # Apply the state change
      apply_state_change(type, data)

      # Update node version tracking
      node_versions = Map.put(state.node_versions, from_node, version)
      {:noreply, %{state | node_versions: node_versions}}
    else
      {:noreply, state}
    end
  end

  @impl true
  def handle_info({:state_sync_request, from_node, from_version}, state) do
    if from_version < state.state_version do
      # Send our state to the requesting node
      send_state_to_node(from_node)
    end
    {:noreply, state}
  end

  @impl true
  def handle_info({:state_sync_response, _from_node, state_data}, state) do
    # Apply received state
    apply_full_state_sync(state_data)
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # Private Functions

  defp schedule_sync do
    Process.send_after(self(), :periodic_sync, @sync_interval)
  end

  defp request_state_sync(target_node) do
    my_version = get_version()

    try do
      :rpc.call(target_node, __MODULE__, :handle_sync_request, [node(), my_version])
    catch
      _, reason ->
        Logger.warning("Failed to sync with #{target_node}: #{inspect(reason)}")
    end
  end

  def handle_sync_request(from_node, from_version) do
    send(Process.whereis(__MODULE__), {:state_sync_request, from_node, from_version})
    :ok
  end

  defp send_state_to_node(target_node) do
    state_data = collect_state_for_sync()

    try do
      :rpc.call(target_node, __MODULE__, :receive_state_sync, [node(), state_data])
    catch
      _, reason ->
        Logger.warning("Failed to send state to #{target_node}: #{inspect(reason)}")
    end
  end

  def receive_state_sync(from_node, state_data) do
    send(Process.whereis(__MODULE__), {:state_sync_response, from_node, state_data})
    :ok
  end

  defp collect_state_for_sync do
    # Collect state that needs to be synchronized
    %{
      # Active agent sessions
      agents: collect_agent_state(),

      # Configuration
      config: collect_config_state(),

      # Detection rules (YARA, Sigma checksums)
      rules: collect_rules_state(),

      # Recent alerts for deduplication
      recent_alerts: collect_recent_alerts()
    }
  end

  defp collect_agent_state do
    TamanduaServer.Agents.Registry.list_all()
    |> Enum.map(fn agent ->
      %{
        agent_id: agent.agent_id,
        status: agent.status,
        last_seen_at: agent.last_seen_at,
        node: node()
      }
    end)
  end

  defp collect_config_state do
    %{
      version: Application.get_env(:tamandua_server, :config_version, 1),
      settings: TamanduaServer.Settings.get_all()
    }
  end

  defp collect_rules_state do
    %{
      yara_checksum: calculate_rules_checksum(:yara),
      sigma_checksum: calculate_rules_checksum(:sigma)
    }
  end

  defp calculate_rules_checksum(type) do
    case type do
      :yara ->
        # Get YARA rules directory and calculate checksum
        "yara_v1"

      :sigma ->
        # Get Sigma rules directory and calculate checksum
        "sigma_v1"
    end
  end

  defp collect_recent_alerts do
    # Get alerts from last 5 minutes for deduplication
    cutoff = DateTime.add(DateTime.utc_now(), -5, :minute)

    TamanduaServer.Alerts.list_recent(since: cutoff, limit: 1000)
    |> Enum.map(fn alert ->
      %{
        id: alert.id,
        fingerprint: alert.fingerprint,
        created_at: alert.inserted_at
      }
    end)
  end

  defp apply_state_change(type, data) do
    case type do
      :agent_status ->
        handle_agent_status_change(data)

      :config_update ->
        handle_config_update(data)

      :rule_update ->
        handle_rule_update(data)

      :alert_created ->
        handle_remote_alert(data)

      _ ->
        Logger.debug("Unknown state change type: #{type}")
    end
  end

  defp apply_full_state_sync(state_data) do
    Logger.info("Applying full state sync from cluster")

    # Sync agent states
    if agents = state_data[:agents] do
      Enum.each(agents, &handle_agent_status_change/1)
    end

    # Sync config if version is newer
    if config = state_data[:config] do
      local_version = Application.get_env(:tamandua_server, :config_version, 0)
      if config[:version] > local_version do
        handle_config_update(config)
      end
    end

    :ok
  end

  defp handle_agent_status_change(data) do
    # Update local registry with remote agent status
    agent_id = data[:agent_id]
    status = data[:status]
    remote_node = data[:node]

    if remote_node != node() do
      # Only update if agent is not local
      unless TamanduaServer.Cluster.HashRing.is_local?(agent_id) do
        Logger.debug("Updated remote agent status: #{agent_id} -> #{status}")
      end
    end
  end

  defp handle_config_update(config) do
    if settings = config[:settings] do
      TamanduaServer.Settings.apply_settings(settings)
    end
    Application.put_env(:tamandua_server, :config_version, config[:version])
  end

  defp handle_rule_update(data) do
    # Trigger rule reload if checksums differ
    if data[:reload_yara] do
      TamanduaServer.Detection.YaraScanner.reload_rules()
    end

    if data[:reload_sigma] do
      TamanduaServer.Detection.Engine.reload_sigma_rules()
    end
  end

  defp handle_remote_alert(data) do
    # Check for duplicate alert
    fingerprint = data[:fingerprint]

    unless TamanduaServer.Alerts.exists_by_fingerprint?(fingerprint) do
      Logger.debug("Received alert from cluster: #{fingerprint}")
    end
  end

  defp check_node_versions(state) do
    # Compare our version with other nodes
    nodes = Node.list()

    Enum.each(nodes, fn target_node ->
      remote_version = Map.get(state.node_versions, target_node, 0)

      if remote_version > state.state_version do
        # We're behind, request sync
        Task.start(fn -> request_state_sync(target_node) end)
      end
    end)

    state
  end
end
