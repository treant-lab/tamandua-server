defmodule TamanduaServer.Telemetry.IngestorProducer do
  @moduledoc """
  GenStage producer for Broadway telemetry pipeline.

  Provides a push-based interface for sending events to the Broadway pipeline.
  Uses an ETS table for the queue to allow push from outside the Broadway process.

  ## Durability model

  The ETS queue table is created and owned ONLY by the producer process in
  `init/1`. Pushers never create the table: if the producer (and therefore the
  table) is not up, `push_messages/1` returns `{:error, :unavailable}`, logs at
  `:error`, and emits a `[:tamandua, :ingestor, :queue_unavailable]` telemetry
  event. This prevents the historical failure mode where a transient pusher
  process created (and owned) the named table, silently destroying the whole
  queue when it exited.

  Queue keys are `:erlang.unique_integer([:monotonic])` values: strictly
  ordered and collision-free across concurrent pushers (the previous
  `{System.monotonic_time(), index}` scheme allowed concurrent pushers to
  collide and overwrite each other's events in the `ordered_set`).

  ## Telemetry events

    * `[:tamandua, :ingestor, :queue_unavailable]` — measurements
      `%{count: n}` (messages that could not be enqueued), metadata
      `%{table: table}`.
    * `[:tamandua, :ingestor, :dropped]` — measurements `%{count: n}`
      (oldest messages dropped on overflow), metadata
      `%{table: table, reason: :overflow}`.
  """

  use GenStage
  require Logger

  @queue_table :ingestor_queue
  @queue_max_size 10_000

  @unavailable_event [:tamandua, :ingestor, :queue_unavailable]
  @dropped_event [:tamandua, :ingestor, :dropped]

  def start_link(opts) do
    GenStage.start_link(__MODULE__, opts)
  end

  @doc """
  Push messages to the producer queue via ETS.

  Returns `:ok` on success. Returns `{:error, :unavailable}` (with an error
  log and a `[:tamandua, :ingestor, :queue_unavailable]` telemetry event) when
  the queue table does not exist, i.e. the producer has not started or has
  died. Pushers deliberately do NOT create the table.

  On overflow the oldest messages are dropped (bounded memory); each drop is
  reported via the `[:tamandua, :ingestor, :dropped]` telemetry counter and a
  warning log.

  The optional `table` argument exists for tests; production callers use the
  default.
  """
  @spec push_messages(list()) :: :ok | {:error, :unavailable}
  def push_messages(messages, table \\ @queue_table) when is_list(messages) do
    case :ets.whereis(table) do
      :undefined ->
        report_unavailable(length(messages), table)

      _tid ->
        do_push(messages, table)
    end
  end

  @doc """
  Get current queue depth for monitoring.

  Returns 0 when the queue table does not exist (monitoring must not create
  the table nor crash).
  """
  @spec queue_depth() :: non_neg_integer()
  def queue_depth(table \\ @queue_table) do
    case :ets.info(table, :size) do
      size when is_integer(size) -> size
      _ -> 0
    end
  end

  # GenStage callbacks

  @impl true
  def init(opts) do
    table = Keyword.get(opts, :queue_table, @queue_table)

    # The producer is the ONLY process that creates the queue table. It is
    # :public so external pushers can insert, but its lifecycle is tied to the
    # producer (supervised by Broadway), never to a transient pusher.
    if :ets.whereis(table) == :undefined do
      :ets.new(table, [:named_table, :ordered_set, :public, write_concurrency: true])
    end

    # Poll for messages periodically
    schedule_poll()
    {:producer, %{demand: 0, table: table}}
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

  defp do_push(messages, table) do
    case :ets.info(table, :size) do
      queue_size when is_integer(queue_size) ->
        incoming = length(messages)
        overflow = queue_size + incoming - @queue_max_size

        if overflow > 0 do
          # Drop oldest messages to make room (bounded memory), but make the
          # loss observable: telemetry counter + warning log.
          drop_oldest(table, overflow)

          :telemetry.execute(@dropped_event, %{count: overflow}, %{
            table: table,
            reason: :overflow
          })

          Logger.warning("Dropped #{overflow} messages due to queue overflow")
        end

        Enum.each(messages, fn msg ->
          # Collision-free monotonic keys: safe under concurrent pushers,
          # ordering preserved by the ordered_set.
          :ets.insert(table, {:erlang.unique_integer([:monotonic]), msg})
        end)

        :ok

      _ ->
        report_unavailable(length(messages), table)
    end
  rescue
    # The table can disappear between the availability check and the inserts
    # if the producer dies mid-push. Never swallow the loss with :ok — report
    # it explicitly.
    ArgumentError ->
      report_unavailable(length(messages), table)
  end

  defp report_unavailable(count, table) do
    Logger.error(
      "Ingestor queue table #{inspect(table)} unavailable (producer down?); " <>
        "rejecting #{count} message(s)"
    )

    :telemetry.execute(@unavailable_event, %{count: count}, %{table: table})
    {:error, :unavailable}
  end

  defp drop_oldest(_table, 0), do: :ok

  defp drop_oldest(table, n) do
    case :ets.first(table) do
      :"$end_of_table" ->
        :ok

      key ->
        :ets.delete(table, key)
        drop_oldest(table, n - 1)
    end
  end

  defp dispatch_events(%{demand: demand, table: table} = state) do
    if demand > 0 do
      events = take_events_from_ets(table, demand)
      remaining_demand = demand - length(events)
      {:noreply, events, %{state | demand: remaining_demand}}
    else
      {:noreply, [], state}
    end
  end

  defp take_events_from_ets(table, count) do
    take_events_from_ets(table, count, [])
  end

  defp take_events_from_ets(_table, 0, acc), do: Enum.reverse(acc)

  defp take_events_from_ets(table, count, acc) do
    # The producer owns the table, so it cannot disappear while this runs.
    case :ets.first(table) do
      :"$end_of_table" ->
        Enum.reverse(acc)

      key ->
        case :ets.take(table, key) do
          [{^key, event}] ->
            take_events_from_ets(table, count - 1, [event | acc])

          _ ->
            # Concurrently consumed (should not happen with a single
            # producer); just move on.
            take_events_from_ets(table, count - 1, acc)
        end
    end
  end
end
