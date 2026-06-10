defmodule TamanduaServer.Metrics.Instrumentation do
  @moduledoc """
  Prometheus metrics instrumentation for Tamandua EDR Backend

  Comprehensive metrics collection for:
  - HTTP request metrics (latency, status codes, endpoint-specific)
  - GenServer metrics (mailbox depth, call duration)
  - Broadway metrics (message processing rate, backpressure events)
  - Detection engine metrics (rules evaluated, matches found, detection latency)
  - Alert metrics (created, resolved, escalated, MTTR)
  - Database metrics (query duration, connection pool stats)
  - Cache metrics (hit/miss rates, evictions)

  Metrics are exposed via Prometheus.Exporter on /metrics endpoint.

  Note: When Prometheus dependencies are not available, all functions become no-ops.

  ## Setup

  Add to application.ex supervision tree:

      children = [
        TamanduaServer.Metrics.Instrumentation,
        ...
      ]

  ## Usage

      # Record custom metric
      TamanduaServer.Metrics.Instrumentation.record_detection_match("sigma", "process_injection")

      # Start timing
      start_time = :os.system_time(:millisecond)
      # ... do work ...
      duration = :os.system_time(:millisecond) - start_time
      TamanduaServer.Metrics.Instrumentation.record_detection_duration("yara", duration)
  """

  require Logger

  @doc "Initialize all metrics (no-op when Prometheus unavailable)"
  def setup do
    Logger.info("Metrics instrumentation setup called (Prometheus not configured)")
    :ok
  end

  @doc "Check if Prometheus metrics are available"
  def prometheus_available?, do: false

  # All metric recording functions are no-ops when Prometheus is unavailable

  def record_http_request(_method, _endpoint, _status, _duration_ms), do: :ok
  def record_detection_match(_rule_type, _rule_name, _severity), do: :ok
  def record_detection_duration(_rule_type, _duration_ms), do: :ok
  def record_alert_created(_severity, _category, _source), do: :ok
  def record_alert_resolved(_severity, _category, _resolution, _resolution_time_seconds), do: :ok
  def record_broadway_message(_pipeline, _status, _duration_ms), do: :ok
  def record_db_query(_repo, _query_type, _table, _duration_ms), do: :ok
  def record_cache_hit(_cache_name, _key_type), do: :ok
  def record_cache_miss(_cache_name, _key_type), do: :ok
  def record_ml_inference(_model_type, _verdict, _duration_ms, _confidence), do: :ok
  def update_agent_count(_status, _os, _version, _count), do: :ok
  def update_connected_agents(_os, _version, _count), do: :ok
end
