defmodule TamanduaServer.Repo.Migrations.CreateAgentHealthMetrics do
  use Ecto.Migration

  def change do
    create_if_not_exists table(:agent_health_metrics, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:agent_id, references(:agents, type: :binary_id, on_delete: :delete_all), null: false)

      add(:timestamp, :utc_datetime, null: false)

      add(:cpu_usage, :float)
      add(:cpu_per_core, {:array, :float})
      add(:cpu_load_avg_1m, :float)
      add(:cpu_load_avg_5m, :float)
      add(:cpu_load_avg_15m, :float)

      add(:memory_usage, :float)
      add(:memory_total, :bigint)
      add(:memory_used, :bigint)
      add(:memory_available, :bigint)
      add(:swap_total, :bigint)
      add(:swap_used, :bigint)

      add(:disk_usage, :float)
      add(:disk_total, :bigint)
      add(:disk_used, :bigint)
      add(:disk_read_bytes_per_sec, :bigint)
      add(:disk_write_bytes_per_sec, :bigint)
      add(:disk_iops, :integer)

      add(:network_rx_bytes_per_sec, :bigint)
      add(:network_tx_bytes_per_sec, :bigint)
      add(:network_rx_packets_per_sec, :integer)
      add(:network_tx_packets_per_sec, :integer)
      add(:network_errors_per_sec, :integer)
      add(:network_active_connections, :integer)
      add(:websocket_latency_ms, :integer)

      add(:events_per_sec, :float)
      add(:events_processed, :integer)
      add(:events_queued, :integer)
      add(:events_dropped, :integer)
      add(:event_latency_p50_us, :integer)
      add(:event_latency_p95_us, :integer)
      add(:event_latency_p99_us, :integer)

      add(:detection_latency_us, :integer)
      add(:yara_scans, :integer)
      add(:sigma_evaluations, :integer)
      add(:ml_inferences, :integer)
      add(:detections_triggered, :integer)

      add(:error_count, :integer)
      add(:errors_per_min, :float)
      add(:error_by_component, :map)
      add(:error_by_severity, :map)

      add(:collector_metrics, :map)
      add(:health_score, :integer)
      add(:uptime_seconds, :integer)

      timestamps(type: :utc_datetime)
    end

    create_if_not_exists(index(:agent_health_metrics, [:agent_id, :timestamp]))
    create_if_not_exists(index(:agent_health_metrics, [:timestamp]))
  end
end
