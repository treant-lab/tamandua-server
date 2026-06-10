defmodule TamanduaServer.Agents.HealthMetrics do
  @moduledoc """
  Schema for storing agent health metrics.

  This module provides persistent storage for agent health metrics in PostgreSQL,
  complemented by time-series storage in ClickHouse for historical trending.

  ## Fields

  - `agent_id`: The agent this metric belongs to
  - `timestamp`: When the metric was collected
  - `cpu_usage`: Overall CPU usage percentage
  - `memory_usage`: Memory usage percentage
  - `disk_usage`: Disk usage percentage
  - `network_rx_bytes_per_sec`: Network receive bandwidth
  - `network_tx_bytes_per_sec`: Network transmit bandwidth
  - `events_per_sec`: Event processing rate
  - `detection_latency_us`: Average detection latency in microseconds
  - `collector_metrics`: JSON map of per-collector metrics
  - `error_count`: Total errors in this period
  - `health_score`: Calculated health score (0-100)
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Agents.Agent

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "agent_health_metrics" do
    belongs_to :agent, Agent, type: :binary_id

    field :timestamp, :utc_datetime
    field :cpu_usage, :float
    field :cpu_per_core, {:array, :float}
    field :cpu_load_avg_1m, :float
    field :cpu_load_avg_5m, :float
    field :cpu_load_avg_15m, :float

    field :memory_usage, :float
    field :memory_total, :integer
    field :memory_used, :integer
    field :memory_available, :integer
    field :swap_total, :integer
    field :swap_used, :integer

    field :disk_usage, :float
    field :disk_total, :integer
    field :disk_used, :integer
    field :disk_read_bytes_per_sec, :integer
    field :disk_write_bytes_per_sec, :integer
    field :disk_iops, :integer

    field :network_rx_bytes_per_sec, :integer
    field :network_tx_bytes_per_sec, :integer
    field :network_rx_packets_per_sec, :integer
    field :network_tx_packets_per_sec, :integer
    field :network_errors_per_sec, :integer
    field :network_active_connections, :integer
    field :websocket_latency_ms, :integer

    field :events_per_sec, :float
    field :events_processed, :integer
    field :events_queued, :integer
    field :events_dropped, :integer
    field :event_latency_p50_us, :integer
    field :event_latency_p95_us, :integer
    field :event_latency_p99_us, :integer

    field :detection_latency_us, :integer
    field :yara_scans, :integer
    field :sigma_evaluations, :integer
    field :ml_inferences, :integer
    field :detections_triggered, :integer

    field :error_count, :integer
    field :errors_per_min, :float
    field :error_by_component, :map
    field :error_by_severity, :map

    field :collector_metrics, :map
    field :health_score, :integer
    field :uptime_seconds, :integer

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(metrics, attrs) do
    metrics
    |> cast(attrs, [
      :agent_id,
      :timestamp,
      :cpu_usage,
      :cpu_per_core,
      :cpu_load_avg_1m,
      :cpu_load_avg_5m,
      :cpu_load_avg_15m,
      :memory_usage,
      :memory_total,
      :memory_used,
      :memory_available,
      :swap_total,
      :swap_used,
      :disk_usage,
      :disk_total,
      :disk_used,
      :disk_read_bytes_per_sec,
      :disk_write_bytes_per_sec,
      :disk_iops,
      :network_rx_bytes_per_sec,
      :network_tx_bytes_per_sec,
      :network_rx_packets_per_sec,
      :network_tx_packets_per_sec,
      :network_errors_per_sec,
      :network_active_connections,
      :websocket_latency_ms,
      :events_per_sec,
      :events_processed,
      :events_queued,
      :events_dropped,
      :event_latency_p50_us,
      :event_latency_p95_us,
      :event_latency_p99_us,
      :detection_latency_us,
      :yara_scans,
      :sigma_evaluations,
      :ml_inferences,
      :detections_triggered,
      :error_count,
      :errors_per_min,
      :error_by_component,
      :error_by_severity,
      :collector_metrics,
      :health_score,
      :uptime_seconds
    ])
    |> validate_required([:agent_id, :timestamp])
    |> validate_number(:cpu_usage, greater_than_or_equal_to: 0, less_than_or_equal_to: 100)
    |> validate_number(:memory_usage, greater_than_or_equal_to: 0, less_than_or_equal_to: 100)
    |> validate_number(:disk_usage, greater_than_or_equal_to: 0, less_than_or_equal_to: 100)
    |> validate_number(:health_score, greater_than_or_equal_to: 0, less_than_or_equal_to: 100)
    |> foreign_key_constraint(:agent_id)
  end

  @doc """
  Store health metrics from agent telemetry event.
  """
  def store_metrics(agent_id, telemetry_event) do
    attrs = parse_telemetry(agent_id, telemetry_event)

    %__MODULE__{}
    |> changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Get latest metrics for an agent.
  """
  def get_latest(agent_id) do
    from(m in __MODULE__,
      where: m.agent_id == ^agent_id,
      order_by: [desc: m.timestamp],
      limit: 1
    )
    |> Repo.one()
  end

  @doc """
  Get metrics for an agent within a time range.
  """
  def get_range(agent_id, start_time, end_time) do
    from(m in __MODULE__,
      where: m.agent_id == ^agent_id,
      where: m.timestamp >= ^start_time and m.timestamp <= ^end_time,
      order_by: [desc: m.timestamp]
    )
    |> Repo.all()
  end

  @doc """
  Get recent metrics (last N records).
  """
  def get_recent(agent_id, limit \\ 100) do
    from(m in __MODULE__,
      where: m.agent_id == ^agent_id,
      order_by: [desc: m.timestamp],
      limit: ^limit
    )
    |> Repo.all()
  end

  @doc """
  Calculate aggregated metrics for a time window.
  """
  def aggregate_metrics(agent_id, window_start, window_end) do
    from(m in __MODULE__,
      where: m.agent_id == ^agent_id,
      where: m.timestamp >= ^window_start and m.timestamp <= ^window_end,
      select: %{
        avg_cpu: avg(m.cpu_usage),
        max_cpu: max(m.cpu_usage),
        avg_memory: avg(m.memory_usage),
        max_memory: max(m.memory_usage),
        avg_disk: avg(m.disk_usage),
        max_disk: max(m.disk_usage),
        avg_events_per_sec: avg(m.events_per_sec),
        total_events: sum(m.events_processed),
        total_errors: sum(m.error_count),
        avg_health_score: avg(m.health_score),
        min_health_score: min(m.health_score),
        count: count(m.id)
      }
    )
    |> Repo.one()
  end

  @doc """
  Get fleet-wide statistics.
  """
  def fleet_stats(time_window_minutes \\ 60) do
    cutoff = DateTime.utc_now() |> DateTime.add(-time_window_minutes * 60, :second)

    from(m in __MODULE__,
      where: m.timestamp >= ^cutoff,
      group_by: m.agent_id,
      select: %{
        agent_id: m.agent_id,
        avg_cpu: avg(m.cpu_usage),
        avg_memory: avg(m.memory_usage),
        avg_disk: avg(m.disk_usage),
        avg_health_score: avg(m.health_score),
        total_events: sum(m.events_processed),
        total_errors: sum(m.error_count)
      }
    )
    |> Repo.all()
  end

  @doc """
  Clean up old metrics (retention policy).
  """
  def cleanup_old_metrics(retention_days \\ 30) do
    cutoff = DateTime.utc_now() |> DateTime.add(-retention_days * 86400, :second)

    from(m in __MODULE__,
      where: m.timestamp < ^cutoff
    )
    |> Repo.delete_all()
  end

  # Private Functions

  defp parse_telemetry(agent_id, event) do
    payload = Map.get(event, "payload") || Map.get(event, :payload, %{})

    # Extract CPU metrics
    cpu = Map.get(payload, "cpu") || Map.get(payload, :cpu, %{})
    cpu_usage = Map.get(cpu, "overall_usage") || Map.get(cpu, :overall_usage, 0.0)
    cpu_per_core = Map.get(cpu, "per_core") || Map.get(cpu, :per_core, [])
    load_avg = Map.get(cpu, "load_average") || Map.get(cpu, :load_average)

    {load_1m, load_5m, load_15m} = case load_avg do
      [l1, l5, l15] -> {l1, l5, l15}
      {l1, l5, l15} -> {l1, l5, l15}
      _ -> {nil, nil, nil}
    end

    # Extract memory metrics
    memory = Map.get(payload, "memory") || Map.get(payload, :memory, %{})
    memory_usage = Map.get(memory, "usage_percent") || Map.get(memory, :usage_percent, 0.0)
    memory_total = Map.get(memory, "total") || Map.get(memory, :total, 0)
    memory_used = Map.get(memory, "used") || Map.get(memory, :used, 0)
    memory_available = Map.get(memory, "available") || Map.get(memory, :available, 0)
    swap_total = Map.get(memory, "swap_total") || Map.get(memory, :swap_total, 0)
    swap_used = Map.get(memory, "swap_used") || Map.get(memory, :swap_used, 0)

    # Extract disk metrics
    disk = Map.get(payload, "disk") || Map.get(payload, :disk, %{})
    disk_usage = Map.get(disk, "usage_percent") || Map.get(disk, :usage_percent, 0.0)
    disk_total = Map.get(disk, "total") || Map.get(disk, :total, 0)
    disk_used = Map.get(disk, "used") || Map.get(disk, :used, 0)
    disk_read_bytes = Map.get(disk, "read_bytes_per_sec") || Map.get(disk, :read_bytes_per_sec, 0)
    disk_write_bytes = Map.get(disk, "write_bytes_per_sec") || Map.get(disk, :write_bytes_per_sec, 0)
    disk_iops = Map.get(disk, "iops") || Map.get(disk, :iops, 0)

    # Extract network metrics
    network = Map.get(payload, "network") || Map.get(payload, :network, %{})
    network_rx_bytes = Map.get(network, "rx_bytes_per_sec") || Map.get(network, :rx_bytes_per_sec, 0)
    network_tx_bytes = Map.get(network, "tx_bytes_per_sec") || Map.get(network, :tx_bytes_per_sec, 0)
    network_rx_packets = Map.get(network, "rx_packets_per_sec") || Map.get(network, :rx_packets_per_sec, 0)
    network_tx_packets = Map.get(network, "tx_packets_per_sec") || Map.get(network, :tx_packets_per_sec, 0)
    network_errors = Map.get(network, "errors_per_sec") || Map.get(network, :errors_per_sec, 0)
    network_connections = Map.get(network, "active_connections") || Map.get(network, :active_connections, 0)
    websocket_latency = Map.get(network, "websocket_latency_ms") || Map.get(network, :websocket_latency_ms)

    # Extract event processing metrics
    events = Map.get(payload, "event_processing") || Map.get(payload, :event_processing, %{})
    events_per_sec = Map.get(events, "events_per_sec") || Map.get(events, :events_per_sec, 0.0)
    events_processed = Map.get(events, "events_processed") || Map.get(events, :events_processed, 0)
    events_queued = Map.get(events, "events_queued") || Map.get(events, :events_queued, 0)
    events_dropped = Map.get(events, "events_dropped") || Map.get(events, :events_dropped, 0)
    event_latency_p50 = Map.get(events, "latency_p50_us") || Map.get(events, :latency_p50_us, 0)
    event_latency_p95 = Map.get(events, "latency_p95_us") || Map.get(events, :latency_p95_us, 0)
    event_latency_p99 = Map.get(events, "latency_p99_us") || Map.get(events, :latency_p99_us, 0)

    # Extract detection metrics
    detection = Map.get(payload, "detection") || Map.get(payload, :detection, %{})
    detection_latency = Map.get(detection, "avg_detection_latency_us") || Map.get(detection, :avg_detection_latency_us, 0)
    yara_scans = Map.get(detection, "yara_scans") || Map.get(detection, :yara_scans, 0)
    sigma_evals = Map.get(detection, "sigma_evaluations") || Map.get(detection, :sigma_evaluations, 0)
    ml_inferences = Map.get(detection, "ml_inferences") || Map.get(detection, :ml_inferences, 0)
    detections = Map.get(detection, "detections_triggered") || Map.get(detection, :detections_triggered, 0)

    # Extract error metrics
    errors = Map.get(payload, "errors") || Map.get(payload, :errors, %{})
    error_count = Map.get(errors, "total_errors") || Map.get(errors, :total_errors, 0)
    errors_per_min = Map.get(errors, "errors_per_min") || Map.get(errors, :errors_per_min, 0.0)
    error_by_component = Map.get(errors, "by_component") || Map.get(errors, :by_component, %{})
    error_by_severity = Map.get(errors, "by_severity") || Map.get(errors, :by_severity, %{})

    # Extract collector metrics
    collectors = Map.get(payload, "collectors") || Map.get(payload, :collectors, %{})

    # Extract general fields
    timestamp_ms = Map.get(payload, "timestamp") || Map.get(payload, :timestamp) ||
                   Map.get(event, "timestamp") || Map.get(event, :timestamp, System.system_time(:millisecond))
    timestamp = DateTime.from_unix!(timestamp_ms, :millisecond)

    uptime_seconds = Map.get(payload, "uptime_seconds") || Map.get(payload, :uptime_seconds, 0)

    # Calculate health score
    health_score = calculate_health_score(%{
      cpu_usage: cpu_usage,
      memory_usage: memory_usage,
      disk_usage: disk_usage,
      error_count: error_count,
      events_dropped: events_dropped
    })

    %{
      agent_id: agent_id,
      timestamp: timestamp,
      cpu_usage: cpu_usage,
      cpu_per_core: cpu_per_core,
      cpu_load_avg_1m: load_1m,
      cpu_load_avg_5m: load_5m,
      cpu_load_avg_15m: load_15m,
      memory_usage: memory_usage,
      memory_total: memory_total,
      memory_used: memory_used,
      memory_available: memory_available,
      swap_total: swap_total,
      swap_used: swap_used,
      disk_usage: disk_usage,
      disk_total: disk_total,
      disk_used: disk_used,
      disk_read_bytes_per_sec: disk_read_bytes,
      disk_write_bytes_per_sec: disk_write_bytes,
      disk_iops: disk_iops,
      network_rx_bytes_per_sec: network_rx_bytes,
      network_tx_bytes_per_sec: network_tx_bytes,
      network_rx_packets_per_sec: network_rx_packets,
      network_tx_packets_per_sec: network_tx_packets,
      network_errors_per_sec: network_errors,
      network_active_connections: network_connections,
      websocket_latency_ms: websocket_latency,
      events_per_sec: events_per_sec,
      events_processed: events_processed,
      events_queued: events_queued,
      events_dropped: events_dropped,
      event_latency_p50_us: event_latency_p50,
      event_latency_p95_us: event_latency_p95,
      event_latency_p99_us: event_latency_p99,
      detection_latency_us: detection_latency,
      yara_scans: yara_scans,
      sigma_evaluations: sigma_evals,
      ml_inferences: ml_inferences,
      detections_triggered: detections,
      error_count: error_count,
      errors_per_min: errors_per_min,
      error_by_component: error_by_component,
      error_by_severity: error_by_severity,
      collector_metrics: collectors,
      health_score: health_score,
      uptime_seconds: uptime_seconds
    }
  end

  defp calculate_health_score(metrics) do
    score = 100

    # Deduct for high CPU
    score = if metrics.cpu_usage > 95, do: score - 30, else: score
    score = if metrics.cpu_usage > 80 and metrics.cpu_usage <= 95, do: score - 15, else: score

    # Deduct for high memory
    score = if metrics.memory_usage > 95, do: score - 25, else: score
    score = if metrics.memory_usage > 85 and metrics.memory_usage <= 95, do: score - 10, else: score

    # Deduct for high disk
    score = if metrics.disk_usage > 90, do: score - 20, else: score
    score = if metrics.disk_usage > 80 and metrics.disk_usage <= 90, do: score - 10, else: score

    # Deduct for errors
    score = if metrics.error_count > 100, do: score - 20, else: score
    score = if metrics.error_count > 10 and metrics.error_count <= 100, do: score - 5, else: score

    # Deduct for dropped events
    score = if metrics.events_dropped > 100, do: score - 15, else: score

    max(0, score)
  end
end
