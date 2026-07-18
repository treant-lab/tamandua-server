defmodule TamanduaServer.XDR.Ingestor do
  @moduledoc """
  Broadway pipeline for ingesting and processing XDR (Extended Detection and Response) data.

  Supports multiple log formats:
  - CEF (Common Event Format)
  - LEEF (Log Event Extended Format)
  - JSON (structured logs)
  - Syslog (RFC 5424 and RFC 3164)

  Events are normalized to a common schema, enriched with threat intelligence,
  and correlated with endpoint telemetry before storage.
  """

  use Broadway
  require Logger

  alias Broadway.Message
  alias TamanduaServer.XDR.{NormalizedEvent, Parser, Correlator}
  alias TamanduaServer.Repo

  @batch_size 100
  @batch_timeout 2_000

  def start_link(opts) do
    Broadway.start_link(__MODULE__,
      name: __MODULE__,
      producer: [
        module: {TamanduaServer.XDR.IngestorProducer, []},
        transformer: {__MODULE__, :transform, []},
        concurrency: 1
      ],
      processors: [
        default: [
          concurrency: System.schedulers_online() * 2,
          max_demand: 10
        ]
      ],
      batchers: [
        default: [
          batch_size: @batch_size,
          batch_timeout: @batch_timeout,
          concurrency: 4
        ],
        correlation: [
          batch_size: 20,
          batch_timeout: 5_000,
          concurrency: 2
        ]
      ],
      context: opts
    )
  end

  @doc """
  Push raw events for processing.

  ## Options
  - :source_type - Type of source (firewall, proxy, email, cloud, network)
  - :source_id - UUID of the XDR source
  - :source_name - Name of the source
  - :log_format - Format hint (cef, leef, json, syslog)
  - :organization_id - Organization UUID
  """
  @spec push_events([binary() | map()], keyword()) :: :ok
  def push_events(events, opts \\ []) do
    messages = Enum.map(events, fn event ->
      %{
        raw: event,
        opts: opts
      }
    end)

    TamanduaServer.XDR.IngestorProducer.push_messages(messages)
    Logger.debug("XDR Ingestor: Pushed #{length(messages)} events")
    :ok
  end

  @doc """
  Push a single raw event for processing.
  """
  @spec push_event(binary() | map(), keyword()) :: :ok
  def push_event(event, opts \\ []) do
    push_events([event], opts)
  end

  @doc """
  Ingest events synchronously (for API calls).
  Returns the count of successfully processed events.
  """
  @spec ingest_sync([binary() | map()], keyword()) :: {:ok, integer()} | {:error, term()}
  def ingest_sync(events, opts \\ []) do
    processed = events
    |> Enum.map(fn event -> parse_and_normalize(event, opts) end)
    |> Enum.reject(&is_nil/1)
    |> persist_events()

    case processed do
      {:ok, count} -> {:ok, count}
      {:error, reason} -> {:error, reason}
    end
  end

  # Broadway callbacks

  @impl true
  def handle_message(_processor, %Message{data: %{raw: raw, opts: opts}} = message, _context) do
    case parse_and_normalize(raw, opts) do
      nil ->
        Logger.warning("XDR Ingestor: Failed to parse event")
        Message.failed(message, :parse_error)

      normalized when is_map(normalized) ->
        # Check if this event should be correlated with endpoint data
        if should_correlate?(normalized) do
          message
          |> Message.update_data(fn _ -> normalized end)
          |> Message.put_batcher(:correlation)
        else
          message
          |> Message.update_data(fn _ -> normalized end)
          |> Message.put_batcher(:default)
        end
    end
  end

  @impl true
  def handle_batch(:default, messages, _batch_info, _context) do
    events = Enum.map(messages, fn %Message{data: event} -> event end)

    case persist_events(events) do
      {:ok, count} ->
        Logger.debug("XDR Ingestor: Persisted #{count} events")
        broadcast_events(events)
        messages

      {:error, reason} ->
        Logger.error("XDR Ingestor: Failed to persist events: #{inspect(reason)}")
        Enum.map(messages, fn msg -> Message.failed(msg, reason) end)
    end
  end

  @impl true
  def handle_batch(:correlation, messages, _batch_info, _context) do
    events = Enum.map(messages, fn %Message{data: event} -> event end)

    # Attempt correlation with endpoint telemetry
    correlated_events = Enum.map(events, &correlate_event/1)

    case persist_events(correlated_events) do
      {:ok, count} ->
        Logger.info("XDR Ingestor: Persisted #{count} correlated events")
        broadcast_events(correlated_events)
        messages

      {:error, reason} ->
        Logger.error("XDR Ingestor: Failed to persist correlated events: #{inspect(reason)}")
        Enum.map(messages, fn msg -> Message.failed(msg, reason) end)
    end
  end

  @impl true
  def handle_failed(messages, _context) do
    Logger.error("XDR Ingestor: #{length(messages)} events failed processing")
    messages
  end

  # Transformer callback
  def transform(event, _opts) do
    %Message{
      data: event,
      acknowledger: {Broadway.NoopAcknowledger, nil, nil}
    }
  end

  # Private functions

  defp parse_and_normalize(raw, opts) do
    source_type = Keyword.get(opts, :source_type, "custom")
    log_format = Keyword.get(opts, :log_format) || detect_format(raw)

    # Parse based on format
    parsed = case log_format do
      "cef" -> Parser.CEF.parse(raw)
      "leef" -> Parser.LEEF.parse(raw)
      "json" -> Parser.JSON.parse(raw)
      "syslog" -> Parser.Syslog.parse(raw)
      _ -> Parser.Generic.parse(raw)
    end

    case parsed do
      {:ok, event_data} ->
        NormalizedEvent.normalize(event_data, source_type,
          source_name: Keyword.get(opts, :source_name),
          source_id: Keyword.get(opts, :source_id),
          log_format: log_format,
          organization_id: Keyword.get(opts, :organization_id),
          raw_event: if(is_binary(raw), do: raw, else: Jason.encode!(raw))
        )

      {:error, reason} ->
        Logger.warning("XDR Ingestor: Parse error: #{inspect(reason)}")
        nil
    end
  end

  defp detect_format(raw) when is_binary(raw) do
    cond do
      String.starts_with?(raw, "CEF:") -> "cef"
      String.starts_with?(raw, "LEEF:") -> "leef"
      String.starts_with?(raw, "{") -> "json"
      String.starts_with?(raw, "<") and String.contains?(raw, ">") -> "syslog"
      true -> "syslog"  # Default to syslog parsing
    end
  end

  defp detect_format(raw) when is_map(raw), do: "json"
  defp detect_format(_), do: "generic"

  # Correlate a single normalized event with endpoint telemetry via
  # Correlator.correlate_with_endpoint/1 and annotate the event's
  # :enrichment map with a compact match summary. Events pass through
  # unchanged when there are no matches or the Correlator is unavailable.
  defp correlate_event(event) do
    case Correlator.correlate_with_endpoint(event) do
      {:ok, %{matches: matches, match_count: count, correlated_at: correlated_at}} when count > 0 ->
        summary = %{
          match_count: count,
          correlated_at: correlated_at,
          matches:
            Enum.map(matches, fn m ->
              %{id: m[:id] || m[:event_id], score: m[:correlation_score]}
            end)
        }

        Map.update(
          event,
          :enrichment,
          %{endpoint_correlation: summary},
          &Map.put(&1 || %{}, :endpoint_correlation, summary)
        )

      _ ->
        event
    end
  catch
    :exit, reason ->
      Logger.warning("XDR Ingestor: Correlator unavailable: #{inspect(reason)}")
      event
  end

  defp should_correlate?(event) do
    # Correlate if event has IP addresses that might match endpoints
    # or if it's a high-severity event
    (event[:source_ip] != nil or event[:dest_ip] != nil) and
    event[:severity] in ["critical", "high", "medium"]
  end

  defp persist_events([]), do: {:ok, 0}

  defp persist_events(events) do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    event_maps = Enum.map(events, fn event ->
      Map.merge(event, %{
        id: Ecto.UUID.generate(),
        ingested_at: now
      })
      |> Map.drop([:__struct__, :__meta__])
    end)

    case Repo.insert_all(NormalizedEvent, event_maps, on_conflict: :nothing, returning: false) do
      {count, _} -> {:ok, count}
      error -> {:error, error}
    end
  rescue
    e ->
      Logger.error("XDR Ingestor: Database error: #{inspect(e)}")
      {:error, e}
  end

  defp broadcast_events(events) do
    # Group by organization for efficient broadcasting
    events
    |> Enum.group_by(& &1[:organization_id])
    |> Enum.each(fn {org_id, org_events} ->
      if org_id do
        Phoenix.PubSub.broadcast(
          TamanduaServer.PubSub,
          "xdr:#{org_id}:events",
          {:new_xdr_events, org_events}
        )
      end
    end)

    # Broadcast to global XDR channel
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "xdr:events",
      {:new_xdr_events, events}
    )
  end
end
