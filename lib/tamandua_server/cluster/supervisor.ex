defmodule TamanduaServer.Cluster.Supervisor do
  @moduledoc """
  Supervisor for cluster-related processes.

  Manages:
  - Node discovery and connection
  - Agent distribution across nodes
  - Distributed state synchronization
  - Cross-node event broadcasting
  """

  use Supervisor
  require Logger

  def start_link(opts) do
    Supervisor.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    children = [
      # Node discovery and cluster formation
      TamanduaServer.Cluster.Discovery,

      # Consistent hashing ring for agent distribution
      TamanduaServer.Cluster.HashRing,

      # Distributed state manager
      TamanduaServer.Cluster.StateManager,

      # Cross-node PubSub bridge
      TamanduaServer.Cluster.PubSubBridge,

      # Cluster health monitor
      TamanduaServer.Cluster.HealthMonitor,

      # Auto-scaling coordinator
      TamanduaServer.Cluster.AutoScaler
    ]

    opts = [strategy: :one_for_one, name: __MODULE__]
    Supervisor.init(children, opts)
  end
end
