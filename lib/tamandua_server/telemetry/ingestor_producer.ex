defmodule TamanduaServer.Telemetry.IngestorProducer do
  @moduledoc """
  GenStage producer for Broadway telemetry pipeline.

  Provides a push-based interface for sending events to the Broadway pipeline.
  Uses an ETS table for the queue to allow push from outside the Broadway process.
  """

  use GenStage
  require Logger

  @queue_table :ingestor_queue
  @queue_max_size 10_000

  def start_link(opts) do
    GenStage.start_link(__MODULE__, opts)
  end

  @doc """
  Push messages to the producer queue via ETS.
  Returns :ok if successful.
  """
  @spec push_messages(list()) :: :ok | {:error, :queue_full}
  def push_messages(messages) when is_list(messages) do
    # Ensure ETS table exists
    ensure_table_exists()

    # Get current queue size
    queue_size = :ets.info(@queue_table, :size)

    if queue_size + length(messages) > @queue_max_size do
      # Drop oldest messages to make room
      to_drop = queue_size + length(messages) - @queue_max_size
      drop_oldest(to_drop)
      Logger.warning("Dropped #{to_drop} messages due to queue overflow")
    end

    # Insert messages with monotonic keys for ordering
    timestamp = System.monotonic_time()
    messages
    |> Enum.with_index()
    |> Enum.each(fn {msg, idx} ->
      key = {timestamp, idx}
      :ets.insert(@queue_table, {key, msg})
    end)

    :ok
  end

  @doc """
  Get current queue depth for monitoring.
  """
  @spec queue_depth() :: non_neg_integer()
  def queue_depth do
    ensure_table_exists()
    :ets.info(@queue_table, :size)
  end

  # Ensure ETS table exists (create if not)
  defp ensure_table_exists do
    case :ets.whereis(@queue_table) do
      :undefined ->
        :ets.new(@queue_table, [:named_table, :ordered_set, :public, write_concurrency: true])
      _ ->
        :ok
    end
  end

  defp drop_oldest(0), do: :ok
  defp drop_oldest(n) do
    case :ets.first(@queue_table) do
      :"$end_of_table" -> :ok
      key ->
        :ets.delete(@queue_table, key)
        drop_oldest(n - 1)
    end
  end

  # GenStage callbacks

  @impl true
  def init(_opts) do
    # Create or ensure ETS table exists
    ensure_table_exists()
    # Poll for messages periodically
    schedule_poll()
    {:producer, %{demand: 0}}
  end

  @impl true
  def handle_demand(incoming_demand, state) do
    new_state = %{state | demand: state.demand + incoming_demand}
    dispatch_events(new_state)
  end

  @impl true
  def handle_info(:poll, state) do
    schedule_poll()
    dispatch_events(state)
  end

  # Catch-all for any unexpected message (e.g. stray monitor :DOWN, late
  # timers). Without this, an unmatched message would crash the producer and
  # stall the entire ingest pipeline. Ignoring unknown messages keeps demand
  # flowing.
  @impl true
  def handle_info(_msg, state) do
    {:noreply, [], state}
  end

  defp schedule_poll do
    Process.send_after(self(), :poll, 100)
  end

  # Private functions

  defp dispatch_events(%{demand: demand} = state) do
    if demand > 0 do
      events = take_events_from_ets(demand)
      remaining_demand = demand - length(events)
      {:noreply, events, %{state | demand: remaining_demand}}
    else
      {:noreply, [], state}
    end
  end

  defp take_events_from_ets(count) do
    take_events_from_ets(count, [])
  end

  defp take_events_from_ets(0, acc), do: Enum.reverse(acc)

  defp take_events_from_ets(count, acc) do
    case :ets.first(@queue_table) do
      :"$end_of_table" ->
        Enum.reverse(acc)
      key ->
        [{^key, event}] = :ets.lookup(@queue_table, key)
        :ets.delete(@queue_table, key)
        take_events_from_ets(count - 1, [event | acc])
    end
  end
end
