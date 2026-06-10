defmodule TamanduaServer.Cluster.DistributedBroadway do
  @moduledoc """
  Distributed Broadway pipeline configuration for horizontal scaling.

  Enables:
  - Sharded event processing across nodes
  - Consistent routing of events to the right node
  - Automatic rebalancing on node changes
  - Cross-node batch aggregation
  """

  require Logger

  @doc """
  Configure Broadway pipeline for distributed processing.

  Options:
  - `:shard_count` - Number of shards (default: node_count * 4)
  - `:local_concurrency` - Processors per node (default: schedulers * 2)
  - `:batch_size` - Batch size for processing (default: 100)
  """
  @spec broadway_config(keyword()) :: keyword()
  def broadway_config(opts \\ []) do
    node_count = max(length(Node.list()) + 1, 1)
    shard_count = Keyword.get(opts, :shard_count, node_count * 4)
    local_concurrency = Keyword.get(opts, :local_concurrency, System.schedulers_online() * 2)
    batch_size = Keyword.get(opts, :batch_size, 100)

    [
      name: TamanduaServer.Telemetry.DistributedIngestor,
      producer: [
        module: {TamanduaServer.Cluster.DistributedProducer, [
          shard_count: shard_count,
          node_selector: &select_processing_node/2
        ]},
        transformer: {__MODULE__, :transform_message, []},
        concurrency: 1
      ],
      processors: [
        default: [
          concurrency: local_concurrency,
          max_demand: 10,
          min_demand: 5
        ]
      ],
      batchers: [
        persistence: [
          batch_size: batch_size,
          batch_timeout: 1_000,
          concurrency: 4
        ],
        detection: [
          batch_size: 50,
          batch_timeout: 500,
          concurrency: 2
        ],
        ml: [
          batch_size: 10,
          batch_timeout: 5_000,
          concurrency: 2
        ]
      ],
      partition_by: &partition_by_agent/1,
      context: %{
        node_count: node_count,
        shard_count: shard_count
      }
    ]
  end

  @doc """
  Transform incoming message for distributed processing.
  """
  def transform_message(event, _opts) do
    %Broadway.Message{
      data: event,
      acknowledger: {Broadway.NoopAcknowledger, nil, nil},
      metadata: %{
        received_at: System.system_time(:millisecond),
        source_node: node()
      }
    }
  end

  @doc """
  Partition events by agent ID for consistent processing.
  """
  def partition_by_agent(%Broadway.Message{data: event}) do
    agent_id = event[:agent_id] || event["agent_id"] || "default"

    # Use consistent hashing to determine partition
    :erlang.phash2(agent_id)
  end

  @doc """
  Select the node that should process a given event.
  """
  @spec select_processing_node(term(), integer()) :: node()
  def select_processing_node(event, _shard_count) do
    agent_id = case event do
      %{agent_id: id} -> id
      %{"agent_id" => id} -> id
      _ -> "default"
    end

    # Use hash ring for consistent node selection
    TamanduaServer.Cluster.HashRing.get_node(agent_id)
  end

  @doc """
  Check if this node should process a given event.
  """
  @spec should_process_locally?(term()) :: boolean()
  def should_process_locally?(event) do
    agent_id = case event do
      %{agent_id: id} -> id
      %{"agent_id" => id} -> id
      _ -> "default"
    end

    TamanduaServer.Cluster.HashRing.is_local?(agent_id)
  end

  @doc """
  Forward an event to the appropriate node for processing.
  """
  @spec forward_to_node(term()) :: :ok | {:error, term()}
  def forward_to_node(event) do
    target_node = select_processing_node(event, 0)

    if target_node == node() do
      # Process locally
      TamanduaServer.Telemetry.Ingestor.push_event(event)
    else
      # Forward to target node
      case :rpc.call(target_node, TamanduaServer.Telemetry.Ingestor, :push_event, [event]) do
        {:badrpc, reason} ->
          Logger.warning("Failed to forward event to #{target_node}: #{inspect(reason)}")
          # Fallback to local processing
          TamanduaServer.Telemetry.Ingestor.push_event(event)

        result ->
          result
      end
    end
  end

  @doc """
  Aggregate statistics across all nodes.
  """
  @spec aggregate_stats() :: map()
  def aggregate_stats do
    nodes = [node() | Node.list()]

    stats = Enum.map(nodes, fn n ->
      case :rpc.call(n, __MODULE__, :local_stats, []) do
        {:badrpc, _} -> %{}
        stats -> stats
      end
    end)

    # Merge stats from all nodes
    Enum.reduce(stats, %{
      total_events: 0,
      total_alerts: 0,
      events_per_second: 0,
      processing_latency_ms: []
    }, fn node_stats, acc ->
      %{
        total_events: acc.total_events + Map.get(node_stats, :events_processed, 0),
        total_alerts: acc.total_alerts + Map.get(node_stats, :alerts_generated, 0),
        events_per_second: acc.events_per_second + Map.get(node_stats, :events_per_second, 0),
        processing_latency_ms: acc.processing_latency_ms ++ Map.get(node_stats, :latencies, [])
      }
    end)
  end

  @doc """
  Get local processing statistics.
  """
  @spec local_stats() :: map()
  def local_stats do
    # Get stats from Broadway pipeline
    case Broadway.topology(TamanduaServer.Telemetry.Ingestor) do
      {:ok, topology} ->
        %{
          events_processed: get_processed_count(),
          alerts_generated: get_alert_count(),
          events_per_second: calculate_throughput(),
          latencies: get_recent_latencies(),
          processors: length(topology.processors),
          batchers: length(topology.batchers)
        }

      _ ->
        %{}
    end
  end

  # Private helper functions

  defp get_processed_count do
    # Would track in ETS or similar
    0
  end

  defp get_alert_count do
    0
  end

  defp calculate_throughput do
    0.0
  end

  defp get_recent_latencies do
    []
  end
end
