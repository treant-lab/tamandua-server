defmodule TamanduaServer.Telemetry.IngestorProducerTest do
  @moduledoc """
  Durability tests for the telemetry ingest queue.

  Each test uses its own uniquely named ETS queue table (via the
  `:queue_table` init option / the optional `table` argument on
  `push_messages/2`) so the tests never interfere with the application's live
  `:ingestor_queue` table owned by the Broadway-supervised producer.

  No DB access required — plain ExUnit.
  """

  use ExUnit.Case, async: false

  alias TamanduaServer.Telemetry.IngestorProducer

  @unavailable_event [:tamandua, :ingestor, :queue_unavailable]
  @dropped_event [:tamandua, :ingestor, :dropped]

  defmodule TestConsumer do
    use GenStage

    def start_link({producer, test_pid}) do
      GenStage.start_link(__MODULE__, {producer, test_pid})
    end

    @impl true
    def init({producer, test_pid}) do
      {:consumer, test_pid, subscribe_to: [{producer, max_demand: 10}]}
    end

    @impl true
    def handle_events(events, _from, test_pid) do
      send(test_pid, {:consumed, events})
      {:noreply, [], test_pid}
    end
  end

  defp start_producer(table) do
    {:ok, pid} = IngestorProducer.start_link(queue_table: table)
    pid
  end

  defp attach_telemetry(event) do
    handler_id = {__MODULE__, event, make_ref()}
    test_pid = self()

    :ok =
      :telemetry.attach(
        handler_id,
        event,
        fn ev, measurements, metadata, _config ->
          send(test_pid, {:telemetry, ev, measurements, metadata})
        end,
        nil
      )

    on_exit(fn -> :telemetry.detach(handler_id) end)
    handler_id
  end

  describe "table ownership / durability" do
    test "queue survives the death of a pusher process" do
      table = :ingestor_queue_test_pusher_death
      start_producer(table)

      parent = self()

      {pusher, ref} =
        spawn_monitor(fn ->
          result = IngestorProducer.push_messages([%{id: 1}, %{id: 2}], table)
          send(parent, {:push_result, result})
        end)

      assert_receive {:push_result, :ok}
      assert_receive {:DOWN, ^ref, :process, ^pusher, _reason}

      # The pusher is dead; the table (owned by the producer, not the pusher)
      # and its contents must still be intact.
      assert :ets.whereis(table) != :undefined
      assert IngestorProducer.queue_depth(table) == 2

      values = table |> :ets.tab2list() |> Enum.map(fn {_k, v} -> v end)
      assert Enum.sort_by(values, & &1.id) == [%{id: 1}, %{id: 2}]
    end

    test "push_messages does not create the table and returns {:error, :unavailable} before producer start" do
      table = :ingestor_queue_test_unavailable
      attach_telemetry(@unavailable_event)

      assert :ets.whereis(table) == :undefined

      assert {:error, :unavailable} =
               IngestorProducer.push_messages([%{id: 1}, %{id: 2}, %{id: 3}], table)

      # Pushers must NOT create the table (that was the durability bug: the
      # first transient pusher used to own the whole queue).
      assert :ets.whereis(table) == :undefined

      assert_receive {:telemetry, @unavailable_event, %{count: 3}, %{table: ^table}}
    end

    test "queue_depth returns 0 without creating a missing table" do
      table = :ingestor_queue_test_depth_missing

      assert IngestorProducer.queue_depth(table) == 0
      assert :ets.whereis(table) == :undefined
    end
  end

  describe "key uniqueness and ordering" do
    test "no events are lost under concurrent pushes" do
      table = :ingestor_queue_test_concurrent
      start_producer(table)

      pushers = 8
      per_pusher = 250

      tasks =
        for p <- 1..pushers do
          Task.async(fn ->
            1..per_pusher
            |> Enum.map(&{p, &1})
            |> Enum.chunk_every(10)
            |> Enum.each(fn chunk ->
              assert :ok = IngestorProducer.push_messages(chunk, table)
            end)
          end)
        end

      Task.await_many(tasks, 10_000)

      # With the old {monotonic_time, index} keys, concurrent pushers could
      # collide in the ordered_set and silently overwrite events. Unique
      # monotonic integers must preserve every event.
      assert IngestorProducer.queue_depth(table) == pushers * per_pusher

      events = table |> :ets.tab2list() |> Enum.map(fn {_k, v} -> v end)
      expected = for p <- 1..pushers, i <- 1..per_pusher, do: {p, i}
      assert Enum.sort(events) == Enum.sort(expected)
    end

    test "events from a single pusher are kept in push order" do
      table = :ingestor_queue_test_ordering
      start_producer(table)

      assert :ok = IngestorProducer.push_messages([%{seq: 1}], table)
      assert :ok = IngestorProducer.push_messages([%{seq: 2}, %{seq: 3}], table)

      # ordered_set + monotonic unique keys => tab2list is in key order.
      values = table |> :ets.tab2list() |> Enum.map(fn {_k, v} -> v end)
      assert values == [%{seq: 1}, %{seq: 2}, %{seq: 3}]
    end
  end

  describe "overflow" do
    test "overflow drops oldest, keeps the cap, and emits a dropped telemetry counter" do
      table = :ingestor_queue_test_overflow
      start_producer(table)
      attach_telemetry(@dropped_event)

      cap = 10_000

      assert :ok = IngestorProducer.push_messages(Enum.map(1..cap, &%{seq: &1}), table)
      assert IngestorProducer.queue_depth(table) == cap
      refute_received {:telemetry, @dropped_event, _, _}

      overflow_batch = Enum.map((cap + 1)..(cap + 5), &%{seq: &1})
      assert :ok = IngestorProducer.push_messages(overflow_batch, table)

      assert_receive {:telemetry, @dropped_event, %{count: 5},
                      %{table: ^table, reason: :overflow}}

      # Bounded memory: still at the cap, oldest 5 gone, newest 5 present.
      assert IngestorProducer.queue_depth(table) == cap

      first_key = :ets.first(table)
      assert [{^first_key, %{seq: 6}}] = :ets.lookup(table, first_key)

      last_key = :ets.last(table)
      last_seq = cap + 5
      assert [{^last_key, %{seq: ^last_seq}}] = :ets.lookup(table, last_key)
    end
  end

  describe "dispatch" do
    test "pushed events are delivered to a subscribed consumer" do
      table = :ingestor_queue_test_dispatch
      producer = start_producer(table)
      {:ok, _consumer} = TestConsumer.start_link({producer, self()})

      assert :ok = IngestorProducer.push_messages([%{seq: 1}, %{seq: 2}], table)

      consumed = collect_consumed([], 2)
      assert Enum.sort_by(consumed, & &1.seq) == [%{seq: 1}, %{seq: 2}]
      assert IngestorProducer.queue_depth(table) == 0
    end
  end

  defp collect_consumed(acc, want) when length(acc) >= want, do: acc

  defp collect_consumed(acc, want) do
    receive do
      {:consumed, events} -> collect_consumed(acc ++ events, want)
    after
      2_000 -> flunk("expected #{want} consumed events, got #{inspect(acc)}")
    end
  end
end
