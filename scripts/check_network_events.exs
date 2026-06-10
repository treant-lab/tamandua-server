alias TamanduaServer.Repo
alias TamanduaServer.Telemetry.Event
import Ecto.Query

# Count all events
total_count = Repo.aggregate(Event, :count, :id)
IO.puts("Total events in database: #{total_count}")

# Get event types
types = Repo.all(from e in Event, select: e.event_type, distinct: true)
IO.puts("\nEvent types found: #{inspect(types)}")

# Count network_connect events
network_count = Repo.one(from e in Event, where: e.event_type == "network_connect", select: count())
IO.puts("\nNetwork connect events: #{network_count}")

# Get first 3 network events to see their payload structure
network_events = Repo.all(
  from e in Event,
  where: e.event_type == "network_connect",
  limit: 3,
  order_by: [desc: e.timestamp]
)

IO.puts("\n--- Sample network event payloads ---")
Enum.each(network_events, fn event ->
  IO.puts("\nEvent ID: #{event.id}")
  IO.puts("Payload keys: #{inspect(Map.keys(event.payload || %{}))}")
  IO.puts("Full payload: #{inspect(event.payload)}")
end)

if network_count == 0 do
  IO.puts("\n=== No network_connect events found ===")
  IO.puts("Looking for events with 'network' in event_type:")

  network_related = Repo.all(
    from e in Event,
    where: ilike(e.event_type, "%network%"),
    limit: 5
  )

  Enum.each(network_related, fn event ->
    IO.puts("\n  Event type: #{event.event_type}")
    IO.puts("  Payload keys: #{inspect(Map.keys(event.payload || %{}))}")
  end)
end
