defmodule TamanduaServer.Profiling.TelemetryHandler do
  @moduledoc """
  Telemetry handler for performance profiling.

  Collects metrics from:
  - Ecto queries
  - Phoenix requests
  - Broadway pipelines
  - GenServer calls
  """

  require Logger

  @doc """
  Attach telemetry handlers
  """
  def attach do
    events = [
      [:phoenix, :endpoint, :stop],
      [:phoenix, :router_dispatch, :stop],
      [:tamandua_server, :repo, :query],
      [:broadway, :processor, :message, :stop],
      [:broadway, :batcher, :batch, :stop],
      [:oban, :job, :stop]
    ]

    :telemetry.attach_many(
      "tamandua-profiling-handler",
      events,
      &handle_event/4,
      nil
    )
  end

  @doc """
  Detach telemetry handlers
  """
  def detach do
    :telemetry.detach("tamandua-profiling-handler")
  end

  # Event handlers

  def handle_event([:phoenix, :endpoint, :stop], measurements, metadata, _config) do
    duration_ms = System.convert_time_unit(measurements.duration, :native, :millisecond)

    if duration_ms > 1000 do
      Logger.warning(
        "Slow Phoenix request: #{metadata.request_path} took #{duration_ms}ms"
      )
    end

    record_metric("phoenix.request.duration", duration_ms, %{
      path: metadata.request_path,
      method: metadata.method
    })
  end

  def handle_event([:tamandua_server, :repo, :query], measurements, metadata, _config) do
    duration_ms = System.convert_time_unit(measurements.query_time, :native, :millisecond)

    if duration_ms > 100 do
      Logger.warning("Slow Ecto query: #{inspect(metadata.query)} took #{duration_ms}ms")
    end

    record_metric("ecto.query.duration", duration_ms, %{
      source: metadata.source,
      result: metadata.result
    })
  end

  def handle_event([:broadway, :processor, :message, :stop], measurements, metadata, _config) do
    duration_ms = System.convert_time_unit(measurements.duration, :native, :millisecond)

    record_metric("broadway.processor.duration", duration_ms, %{
      name: metadata.name,
      index: metadata.index
    })
  end

  def handle_event([:broadway, :batcher, :batch, :stop], measurements, metadata, _config) do
    duration_ms = System.convert_time_unit(measurements.duration, :native, :millisecond)

    record_metric("broadway.batch.duration", duration_ms, %{
      name: metadata.name,
      batcher: metadata.batcher,
      batch_size: metadata.batch_info.size
    })
  end

  def handle_event([:oban, :job, :stop], measurements, metadata, _config) do
    duration_ms = System.convert_time_unit(measurements.duration, :native, :millisecond)

    record_metric("oban.job.duration", duration_ms, %{
      worker: metadata.worker,
      queue: metadata.queue,
      state: metadata.state
    })
  end

  def handle_event(_event, _measurements, _metadata, _config) do
    :ok
  end

  # Private functions

  defp record_metric(name, value, tags) do
    # Send to Prometheus/StatsD/etc
    # For now, just log
    Logger.debug("Metric: #{name} = #{value} #{inspect(tags)}")
  end
end
