defmodule TamanduaServer.XDR.IngestorProducer do
  @moduledoc """
  GenStage producer for the XDR Broadway pipeline.

  Receives events from various sources:
  - API ingestion endpoints
  - Webhook receivers
  - Syslog listeners
  - Polling connectors
  """

  use GenStage
  require Logger

  @max_queue_size 10_000

  def start_link(opts) do
    GenStage.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Push messages to the producer queue.
  """
  @spec push_messages([map()]) :: :ok
  def push_messages(messages) do
    GenStage.cast(__MODULE__, {:push, messages})
  end

  @doc """
  Get queue statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenStage.call(__MODULE__, :get_stats)
  end

  # Callbacks

  @impl true
  def init(_opts) do
    state = %{
      queue: :queue.new(),
      demand: 0,
      total_pushed: 0,
      total_delivered: 0
    }

    Logger.info("XDR IngestorProducer started")
    {:producer, state}
  end

  @impl true
  def handle_cast({:push, messages}, state) do
    # Add messages to queue
    queue = Enum.reduce(messages, state.queue, fn msg, q ->
      if :queue.len(q) < @max_queue_size do
        :queue.in(msg, q)
      else
        Logger.warning("XDR IngestorProducer: Queue full, dropping message")
        q
      end
    end)

    state = %{state |
      queue: queue,
      total_pushed: state.total_pushed + length(messages)
    }

    # Try to satisfy demand
    {events, state} = take_events(state, state.demand)
    {:noreply, events, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    stats = %{
      queue_size: :queue.len(state.queue),
      pending_demand: state.demand,
      total_pushed: state.total_pushed,
      total_delivered: state.total_delivered
    }

    {:reply, stats, [], state}
  end

  @impl true
  def handle_demand(demand, state) do
    {events, state} = take_events(state, state.demand + demand)
    {:noreply, events, state}
  end

  defp take_events(state, demand) when demand > 0 do
    {events, queue} = take_from_queue(state.queue, demand, [])

    state = %{state |
      queue: queue,
      demand: demand - length(events),
      total_delivered: state.total_delivered + length(events)
    }

    {Enum.reverse(events), state}
  end

  defp take_events(state, _demand), do: {[], state}

  defp take_from_queue(queue, 0, acc), do: {acc, queue}

  defp take_from_queue(queue, count, acc) do
    case :queue.out(queue) do
      {{:value, event}, rest} ->
        take_from_queue(rest, count - 1, [event | acc])

      {:empty, _} ->
        {acc, queue}
    end
  end
end
