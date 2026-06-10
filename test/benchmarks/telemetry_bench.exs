defmodule TamanduaServer.Benchmarks.TelemetryBench do
  @moduledoc """
  Benchmarks for telemetry ingestion and processing.

  Run with:
    mix run test/benchmarks/telemetry_bench.exs
  """

  alias TamanduaServer.Telemetry.{Ingestor, Event, Enrichment}
  alias TamanduaServer.Repo

  def run do
    # Setup test data
    setup_test_data()

    Benchee.run(
      %{
        # Single event ingestion
        "ingest_single_event" => fn ->
          event = generate_event()
          Ingestor.process_event(event)
        end,

        # Batch ingestion (small)
        "ingest_batch_10" => fn ->
          events = Enum.map(1..10, fn _ -> generate_event() end)
          Ingestor.process_batch(events)
        end,

        # Batch ingestion (medium)
        "ingest_batch_100" => fn ->
          events = Enum.map(1..100, fn _ -> generate_event() end)
          Ingestor.process_batch(events)
        end,

        # Batch ingestion (large)
        "ingest_batch_1000" => fn ->
          events = Enum.map(1..1000, fn _ -> generate_event() end)
          Ingestor.process_batch(events)
        end,

        # Event enrichment
        "enrich_event" => fn ->
          event = generate_event()
          Enrichment.enrich(event)
        end,

        # Event to database (insert)
        "event_to_db_insert" => fn ->
          event = generate_event()
          Event.changeset(%Event{}, event)
          |> Repo.insert()
        end,

        # Query events (small result set)
        "query_events_100" => fn ->
          Event
          |> limit(100)
          |> Repo.all()
        end,

        # Query events (medium result set)
        "query_events_1000" => fn ->
          Event
          |> limit(1000)
          |> Repo.all()
        end,

        # Query events with filter
        "query_events_filtered" => fn ->
          Event
          |> where([e], e.type == "ProcessCreate")
          |> limit(100)
          |> Repo.all()
        end,

        # Query events with complex filter
        "query_events_complex_filter" => fn ->
          Event
          |> where([e], e.type == "ProcessCreate")
          |> where([e], fragment("?->>'User' = ?", e.payload, "SYSTEM"))
          |> order_by([e], desc: e.timestamp)
          |> limit(100)
          |> Repo.all()
        end,

        # Event aggregation
        "aggregate_events_by_type" => fn ->
          Event
          |> group_by([e], e.type)
          |> select([e], {e.type, count(e.id)})
          |> Repo.all()
        end,

        # Time series query (last hour)
        "query_timeseries_1h" => fn ->
          cutoff = DateTime.utc_now() |> DateTime.add(-3600, :second)
          Event
          |> where([e], e.timestamp > ^cutoff)
          |> Repo.all()
        end,

        # Broadway pipeline throughput
        "broadway_process_batch" => fn ->
          messages = Enum.map(1..100, fn i ->
            %Broadway.Message{
              data: generate_event(),
              acknowledger: {__MODULE__, :ack_id, i}
            }
          end)
          TamanduaServer.Telemetry.Broadway.handle_batch(:default, messages, nil, nil)
        end,

        # Event deduplication check
        "check_duplicate" => fn ->
          event = generate_event()
          Ingestor.is_duplicate?(event)
        end,

        # Event sampling decision
        "sampling_decision" => fn ->
          event = generate_event()
          TamanduaServer.Telemetry.Sampler.should_sample?(event)
        end,

        # JSON encoding/decoding
        "json_encode_event" => fn ->
          event = generate_event()
          Jason.encode!(event)
        end,

        "json_decode_event" => fn ->
          event = generate_event()
          json = Jason.encode!(event)
          Jason.decode!(json)
        end,

        # MessagePack encoding (if available)
        "msgpack_encode_event" => fn ->
          event = generate_event()
          Msgpax.pack!(event)
        end,

        "msgpack_decode_event" => fn ->
          event = generate_event()
          packed = Msgpax.pack!(event)
          Msgpax.unpack!(packed)
        end
      },
      time: 10,
      memory_time: 2,
      warmup: 2,
      formatters: [
        {Benchee.Formatters.HTML, file: "benchmarks/output/telemetry_bench.html"},
        Benchee.Formatters.Console
      ],
      print: [
        configuration: false,
        fast_warning: false
      ]
    )
  end

  # Helper functions

  defp setup_test_data do
    # Setup any necessary test data in database
    :ok
  end

  defp generate_event do
    %{
      agent_id: "agent-#{:rand.uniform(100)}",
      type: Enum.random(["ProcessCreate", "FileCreate", "NetworkConnect", "RegistrySet"]),
      timestamp: DateTime.utc_now(),
      payload: %{
        "EventID" => :rand.uniform(1000),
        "Image" => "C:\\Windows\\System32\\test.exe",
        "CommandLine" => "test.exe --flag value",
        "User" => "SYSTEM",
        "ProcessId" => :rand.uniform(10000),
        "ParentProcessId" => :rand.uniform(10000),
        "SHA256" => generate_hash(),
        "Entropy" => :rand.uniform() * 8.0,
        "RemoteIP" => generate_ip(),
        "RemotePort" => :rand.uniform(65535),
        "DestinationPort" => :rand.uniform(65535),
        "Protocol" => Enum.random(["tcp", "udp", "icmp"]),
        "IntegrityLevel" => Enum.random(["Low", "Medium", "High", "System"]),
        "IsSigned" => Enum.random([true, false]),
        "IsElevated" => Enum.random([true, false])
      }
    }
  end

  defp generate_hash do
    :crypto.strong_rand_bytes(32)
    |> Base.encode16(case: :lower)
  end

  defp generate_ip do
    "#{:rand.uniform(255)}.#{:rand.uniform(255)}.#{:rand.uniform(255)}.#{:rand.uniform(255)}"
  end

  # Broadway acknowledger callbacks
  def ack(_ack_ref, _successful, _failed), do: :ok
end

# Run benchmarks if called directly
if System.argv() == [] do
  TamanduaServer.Benchmarks.TelemetryBench.run()
end
