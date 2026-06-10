defmodule TamanduaServer.Telemetry.Enrichment.AsyncWorker do
  @moduledoc """
  GenServer for asynchronous enrichment of events after initial persistence.

  Handles expensive enrichment operations that don't need to block the
  Broadway pipeline:
  - Deep threat intel lookups
  - External API calls
  - ML-based enrichment
  - Historical context building

  Events are enriched asynchronously and the enrichment field is updated
  in the database.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Telemetry.Event
  alias TamanduaServer.Telemetry.Enrichment.{ThreatIntel, Geo, Asset, User}

  @max_queue_size 10_000
  @process_interval 100  # Process every 100ms

  # ──────────────────────────────────────────────────────────────────
  # Client API
  # ──────────────────────────────────────────────────────────────────

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Enqueue an event for asynchronous enrichment.

  Returns :ok immediately. The event will be enriched in the background.
  """
  def enrich_async(event_id) when is_binary(event_id) do
    GenServer.cast(__MODULE__, {:enrich_event, event_id})
  end

  @doc """
  Enqueue multiple events for asynchronous enrichment.
  """
  def enrich_async_batch(event_ids) when is_list(event_ids) do
    GenServer.cast(__MODULE__, {:enrich_batch, event_ids})
  end

  @doc """
  Get worker statistics.
  """
  def stats do
    GenServer.call(__MODULE__, :stats)
  end

  # ──────────────────────────────────────────────────────────────────
  # Server Callbacks
  # ──────────────────────────────────────────────────────────────────

  @impl true
  def init(_opts) do
    # Schedule periodic processing
    schedule_processing()

    state = %{
      queue: :queue.new(),
      queue_size: 0,
      processed: 0,
      failed: 0,
      started_at: System.system_time(:second)
    }

    Logger.info("AsyncWorker started")

    {:ok, state}
  end

  @impl true
  def handle_cast({:enrich_event, event_id}, state) do
    state = enqueue(event_id, state)
    {:noreply, state}
  end

  @impl true
  def handle_cast({:enrich_batch, event_ids}, state) do
    state = Enum.reduce(event_ids, state, fn event_id, acc ->
      enqueue(event_id, acc)
    end)

    {:noreply, state}
  end

  @impl true
  def handle_call(:stats, _from, state) do
    uptime = System.system_time(:second) - state.started_at

    stats = %{
      queue_size: state.queue_size,
      processed: state.processed,
      failed: state.failed,
      uptime_seconds: uptime,
      throughput: if(uptime > 0, do: state.processed / uptime, else: 0)
    }

    {:reply, stats, state}
  end

  @impl true
  def handle_info(:process_queue, state) do
    state = process_batch(state)
    schedule_processing()
    {:noreply, state}
  end

  # Catch-all: ignore stray messages (e.g. late Task results) to stay alive.
  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ──────────────────────────────────────────────────────────────────
  # Private Functions
  # ──────────────────────────────────────────────────────────────────

  defp enqueue(event_id, state) do
    if state.queue_size >= @max_queue_size do
      Logger.warning("AsyncWorker queue full (#{@max_queue_size}), dropping event #{event_id}")
      %{state | failed: state.failed + 1}
    else
      queue = :queue.in(event_id, state.queue)
      %{state | queue: queue, queue_size: state.queue_size + 1}
    end
  end

  defp schedule_processing do
    Process.send_after(self(), :process_queue, @process_interval)
  end

  defp process_batch(state) do
    # Process up to 10 events per batch
    batch_size = 10
    {events, state} = dequeue_batch(state, batch_size)

    if length(events) > 0 do
      results = Task.async_stream(
        events,
        &enrich_event/1,
        max_concurrency: 4,
        timeout: 30_000,
        on_timeout: :kill_task
      )
      |> Enum.to_list()

      succeeded = Enum.count(results, fn
        {:ok, :ok} -> true
        _ -> false
      end)

      failed = length(results) - succeeded

      %{state | processed: state.processed + succeeded, failed: state.failed + failed}
    else
      state
    end
  end

  defp dequeue_batch(state, count) do
    do_dequeue_batch(state, count, [])
  end

  defp do_dequeue_batch(state, 0, acc), do: {Enum.reverse(acc), state}
  defp do_dequeue_batch(%{queue_size: 0} = state, _count, acc), do: {Enum.reverse(acc), state}

  defp do_dequeue_batch(state, count, acc) do
    case :queue.out(state.queue) do
      {{:value, event_id}, queue} ->
        new_state = %{state | queue: queue, queue_size: state.queue_size - 1}
        do_dequeue_batch(new_state, count - 1, [event_id | acc])

      {:empty, _queue} ->
        {Enum.reverse(acc), state}
    end
  end

  defp enrich_event(event_id) do
    case Repo.get(Event, event_id) do
      nil ->
        Logger.debug("Event #{event_id} not found for enrichment")
        {:error, :not_found}

      event ->
        # Convert to map for enrichment functions
        event_map = %{
          agent_id: event.agent_id,
          event_type: event.event_type,
          payload: event.payload,
          enrichment: event.enrichment || %{}
        }

        # Apply all enrichment functions
        enriched = event_map
        |> ThreatIntel.enrich_event()
        |> Geo.enrich_event()
        |> Asset.enrich_event()
        |> User.enrich_event()

        # Update event in database with new enrichment
        case update_event_enrichment(event, enriched.enrichment) do
          {:ok, _updated_event} ->
            :ok

          {:error, reason} ->
            Logger.warning("Failed to update enrichment for event #{event_id}: #{inspect(reason)}")
            {:error, reason}
        end
    end
  rescue
    e ->
      Logger.error("Enrichment failed for event #{event_id}: #{Exception.message(e)}")
      {:error, :enrichment_failed}
  end

  defp update_event_enrichment(event, enrichment) do
    import Ecto.Changeset

    event
    |> change(enrichment: enrichment)
    |> Repo.update()
  end
end
