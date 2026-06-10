defmodule TamanduaServer.Cache.Metrics do
  @moduledoc """
  Prometheus metrics for cache performance monitoring.

  Tracks cache hits, misses, hit rates, evictions, and latency across
  all cache types (Redis, ETS) for Grafana dashboards.

  Note: When Prometheus dependencies are not available, all functions become no-ops.

  ## Metrics

  ### Counters
  - `cache_hits_total` - Total cache hits by cache type and namespace
  - `cache_misses_total` - Total cache misses by cache type and namespace
  - `cache_evictions_total` - Total cache evictions

  ### Gauges
  - `cache_size_bytes` - Current cache size in bytes
  - `cache_entries_total` - Number of entries in cache
  - `cache_hit_rate_percent` - Current hit rate percentage

  ### Histograms
  - `cache_operation_duration_milliseconds` - Operation latency (get, put, delete)

  ## Usage

      # Instrument cache operations
      Metrics.record_hit(:redis, "alert")
      Metrics.record_miss(:ets, "yara_rules")
      Metrics.record_operation_duration(:redis, :get, duration_ms)
  """

  require Logger

  @cache_types [:redis, :ets]

  @doc "Check if Prometheus metrics are available"
  def prometheus_available?, do: false

  @doc "Initialize metrics (no-op when Prometheus unavailable)"
  def setup do
    Logger.info("[Cache.Metrics] Metrics setup called (Prometheus not configured)")
    :ok
  end

  @doc "Records a cache hit (no-op)."
  def record_hit(_cache_type, _namespace \\ "default"), do: :ok

  @doc "Records a cache miss (no-op)."
  def record_miss(_cache_type, _namespace \\ "default"), do: :ok

  @doc "Records a cache eviction (no-op)."
  def record_eviction(_cache_type, _namespace \\ "default"), do: :ok

  @doc "Updates cache size metric (no-op)."
  def update_cache_size(_cache_type, _namespace, _size_bytes), do: :ok

  @doc "Updates cache entry count metric (no-op)."
  def update_cache_entries(_cache_type, _namespace, _count), do: :ok

  @doc "Updates cache hit rate metric (no-op)."
  def update_hit_rate(_cache_type, _namespace, _hit_rate_percent), do: :ok

  @doc "Records cache operation duration (no-op)."
  def record_operation_duration(_cache_type, _operation, _duration_ms), do: :ok

  @doc """
  Wrapper for timing cache operations.

  ## Examples

      Metrics.time_operation(:redis, :get, fn ->
        RedisCache.get("key")
      end)
  """
  def time_operation(_cache_type, _operation, fun) when is_function(fun, 0) do
    fun.()
  end

  @doc "Collects current metrics from all caches (no-op)."
  def collect_metrics, do: :ok

  @doc """
  Formats metrics for Grafana dashboard.
  """
  def grafana_dashboard do
    %{
      title: "Tamandua Cache Performance",
      panels: [
        %{
          title: "Cache Hit Rate",
          type: "graph",
          targets: [
            %{
              expr: "rate(cache_hits_total[5m]) / (rate(cache_hits_total[5m]) + rate(cache_misses_total[5m]))",
              legendFormat: "{{cache_type}} - {{namespace}}"
            }
          ]
        },
        %{
          title: "Cache Entries",
          type: "graph",
          targets: [
            %{
              expr: "cache_entries_total",
              legendFormat: "{{cache_type}} - {{namespace}}"
            }
          ]
        },
        %{
          title: "Cache Operation Latency (p95)",
          type: "graph",
          targets: [
            %{
              expr: "histogram_quantile(0.95, rate(cache_operation_duration_milliseconds_bucket[5m]))",
              legendFormat: "{{cache_type}} - {{operation}}"
            }
          ]
        },
        %{
          title: "Cache Evictions",
          type: "graph",
          targets: [
            %{
              expr: "rate(cache_evictions_total[5m])",
              legendFormat: "{{cache_type}} - {{namespace}}"
            }
          ]
        }
      ]
    }
  end
end
