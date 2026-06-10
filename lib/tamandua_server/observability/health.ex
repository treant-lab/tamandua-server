defmodule TamanduaServer.Observability.Health do
  @moduledoc """
  Comprehensive health check system for Tamandua EDR.

  Provides:
  - Liveness checks (is the service running?)
  - Readiness checks (can it accept traffic?)
  - Deep health checks (all dependencies healthy?)
  - SLA monitoring
  """

  use GenServer
  require Logger

  @check_interval :timer.seconds(30)
  @sla_window :timer.hours(1)

  defstruct [
    :status,
    checks: %{},
    sla_data: [],
    last_check: nil
  ]

  # Client API

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Quick liveness check - is the service running?
  """
  @spec liveness() :: :ok | {:error, term()}
  def liveness do
    if Process.whereis(__MODULE__), do: :ok, else: {:error, :not_running}
  end

  @doc """
  Readiness check - can the service accept traffic?
  """
  @spec readiness() :: {:ok, map()} | {:error, map()}
  def readiness do
    GenServer.call(__MODULE__, :readiness, 5000)
  catch
    :exit, _ -> {:error, %{status: :timeout, message: "Health check timed out"}}
  end

  @doc """
  Deep health check - all components and dependencies.
  """
  @spec deep_check() :: {:ok, map()} | {:error, map()}
  def deep_check do
    GenServer.call(__MODULE__, :deep_check, 30000)
  catch
    :exit, _ -> {:error, %{status: :timeout, message: "Deep health check timed out"}}
  end

  @doc """
  Get SLA metrics for the specified window.
  """
  @spec sla_metrics(integer()) :: map()
  def sla_metrics(window_minutes \\ 60) do
    GenServer.call(__MODULE__, {:sla_metrics, window_minutes})
  end

  @doc """
  Get current health status as JSON-friendly map.
  """
  @spec status() :: map()
  def status do
    GenServer.call(__MODULE__, :status)
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    state = %__MODULE__{
      status: :initializing
    }

    # Perform initial health check
    send(self(), :check)

    # Schedule periodic checks
    schedule_check()

    Logger.info("Health check system initialized")
    {:ok, state}
  end

  @impl true
  def handle_call(:readiness, _from, state) do
    # Quick checks for readiness
    checks = %{
      database: check_database(),
      pubsub: check_pubsub()
    }

    all_healthy = Enum.all?(checks, fn {_, status} -> status == :healthy end)

    response = %{
      status: if(all_healthy, do: :ready, else: :not_ready),
      checks: checks,
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
    }

    if all_healthy do
      {:reply, {:ok, response}, state}
    else
      {:reply, {:error, response}, state}
    end
  end

  @impl true
  def handle_call(:deep_check, _from, state) do
    checks = perform_all_checks()

    all_healthy = Enum.all?(checks, fn {_, v} ->
      v[:status] == :healthy
    end)

    response = %{
      status: if(all_healthy, do: :healthy, else: :unhealthy),
      checks: checks,
      node: node(),
      cluster_size: length(Node.list()) + 1,
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
    }

    new_state = %{state |
      checks: checks,
      status: if(all_healthy, do: :healthy, else: :unhealthy),
      last_check: System.system_time(:millisecond)
    }

    if all_healthy do
      {:reply, {:ok, response}, new_state}
    else
      {:reply, {:error, response}, new_state}
    end
  end

  @impl true
  def handle_call({:sla_metrics, window_minutes}, _from, state) do
    cutoff = System.system_time(:millisecond) - (window_minutes * 60 * 1000)

    recent_data = Enum.filter(state.sla_data, fn entry ->
      entry.timestamp > cutoff
    end)

    total_checks = length(recent_data)
    healthy_checks = Enum.count(recent_data, & &1.healthy)

    availability = if total_checks > 0 do
      (healthy_checks / total_checks) * 100
    else
      100.0
    end

    metrics = %{
      window_minutes: window_minutes,
      total_checks: total_checks,
      healthy_checks: healthy_checks,
      availability_percent: Float.round(availability, 4),
      meets_sla: availability >= 99.99,
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
    }

    {:reply, metrics, state}
  end

  @impl true
  def handle_call(:status, _from, state) do
    status = %{
      status: state.status,
      checks: format_checks(state.checks),
      last_check: format_timestamp(state.last_check),
      node: node(),
      uptime_seconds: :erlang.statistics(:wall_clock) |> elem(0) |> div(1000)
    }
    {:reply, status, state}
  end

  @impl true
  def handle_info(:check, state) do
    checks = perform_all_checks()

    all_healthy = Enum.all?(checks, fn {_, v} ->
      v[:status] == :healthy
    end)

    # Record for SLA tracking
    sla_entry = %{
      timestamp: System.system_time(:millisecond),
      healthy: all_healthy
    }

    # Keep SLA data for the window
    cutoff = System.system_time(:millisecond) - @sla_window
    sla_data = [sla_entry | state.sla_data]
    |> Enum.filter(& &1.timestamp > cutoff)
    |> Enum.take(1000)

    new_state = %{state |
      checks: checks,
      status: if(all_healthy, do: :healthy, else: :unhealthy),
      last_check: System.system_time(:millisecond),
      sla_data: sla_data
    }

    # Log if status changed
    if state.status != new_state.status do
      Logger.warning("Health status changed: #{state.status} -> #{new_state.status}")
    end

    schedule_check()
    {:noreply, new_state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Private Functions

  defp schedule_check do
    Process.send_after(self(), :check, @check_interval)
  end

  defp perform_all_checks do
    # Run checks in parallel
    tasks = [
      {:database, Task.async(fn -> check_database_detailed() end)},
      {:redis, Task.async(fn -> check_redis() end)},
      {:rabbitmq, Task.async(fn -> check_rabbitmq() end)},
      {:ml_service, Task.async(fn -> check_ml_service() end)},
      {:broadway, Task.async(fn -> check_broadway() end)},
      {:detection_engine, Task.async(fn -> check_detection_engine() end)},
      {:cluster, Task.async(fn -> check_cluster() end)},
      {:disk_space, Task.async(fn -> check_disk_space() end)},
      {:memory, Task.async(fn -> check_memory() end)}
    ]

    Enum.map(tasks, fn {name, task} ->
      result = Task.await(task, 10000)
      {name, result}
    end)
    |> Map.new()
  rescue
    _ ->
      %{error: %{status: :error, message: "Health check failed"}}
  end

  defp check_database do
    case TamanduaServer.Repo.query("SELECT 1", []) do
      {:ok, _} -> :healthy
      _ -> :unhealthy
    end
  rescue
    _ -> :unhealthy
  end

  defp check_database_detailed do
    start = System.monotonic_time(:millisecond)

    result = case TamanduaServer.Repo.query("SELECT 1", []) do
      {:ok, _} ->
        # Check pool status
        %{
          status: :healthy,
          latency_ms: System.monotonic_time(:millisecond) - start
        }

      {:error, reason} ->
        %{
          status: :unhealthy,
          error: inspect(reason)
        }
    end

    result
  rescue
    e ->
      %{status: :unhealthy, error: Exception.message(e)}
  end

  defp check_pubsub do
    if Process.whereis(TamanduaServer.PubSub) do
      :healthy
    else
      :unhealthy
    end
  end

  defp check_redis do
    # Check if cache is working
    try do
      test_key = "health_check_#{System.system_time()}"
      TamanduaServer.Cache.put(test_key, "test", ttl: 5)

      case TamanduaServer.Cache.get(test_key) do
        "test" -> %{status: :healthy}
        _ -> %{status: :unhealthy, error: "Cache read failed"}
      end
    rescue
      e -> %{status: :unhealthy, error: Exception.message(e)}
    end
  end

  defp check_rabbitmq do
    # Check Broadway producer connection
    case Process.whereis(TamanduaServer.Telemetry.Ingestor) do
      nil -> %{status: :unhealthy, error: "Broadway not running"}
      _pid -> %{status: :healthy}
    end
  end

  defp check_ml_service do
    ml_url = Application.get_env(:tamandua_server, :ml_service_url, "http://localhost:8000")

    case Req.get("#{ml_url}/health", receive_timeout: 5000) do
      {:ok, %{status: 200}} -> %{status: :healthy}
      {:ok, %{status: status}} -> %{status: :unhealthy, error: "ML service returned #{status}"}
      {:error, reason} -> %{status: :unhealthy, error: inspect(reason)}
    end
  rescue
    e -> %{status: :unhealthy, error: Exception.message(e)}
  end

  defp check_broadway do
    case Process.whereis(TamanduaServer.Telemetry.Ingestor) do
      nil ->
        %{status: :unhealthy, error: "Broadway not running"}

      pid ->
        case Process.info(pid, :message_queue_len) do
          {:message_queue_len, len} when len < 10000 ->
            %{status: :healthy, queue_length: len}

          {:message_queue_len, len} ->
            %{status: :degraded, queue_length: len, warning: "High queue depth"}

          _ ->
            %{status: :unhealthy, error: "Cannot read queue length"}
        end
    end
  end

  defp check_detection_engine do
    case Process.whereis(TamanduaServer.Detection.Engine) do
      nil -> %{status: :unhealthy, error: "Detection engine not running"}
      _pid -> %{status: :healthy}
    end
  end

  defp check_cluster do
    nodes = Node.list()
    node_count = length(nodes) + 1

    try do
      health = TamanduaServer.Cluster.HealthMonitor.cluster_health()
      %{
        status: if(health.status == :healthy, do: :healthy, else: :degraded),
        node_count: node_count,
        cluster_status: health.status
      }
    rescue
      _ ->
        %{status: :healthy, node_count: node_count, note: "Cluster monitor not available"}
    end
  end

  defp check_disk_space do
    # Check available disk space
    case :disksup.get_disk_data() do
      [{_, total, percent_used} | _] when is_integer(percent_used) ->
        if percent_used < 90 do
          %{status: :healthy, usage_percent: percent_used, total_mb: div(total, 1024)}
        else
          %{status: :warning, usage_percent: percent_used, warning: "Disk space low"}
        end

      _ ->
        %{status: :healthy, note: "Disk check not available"}
    end
  rescue
    _ -> %{status: :healthy, note: "Disk check not available"}
  end

  defp check_memory do
    case :memsup.get_system_memory_data() do
      data when is_list(data) ->
        total = Keyword.get(data, :total_memory, 0)
        free = Keyword.get(data, :free_memory, 0)
        used_percent = if total > 0, do: ((total - free) / total) * 100, else: 0

        if used_percent < 90 do
          %{status: :healthy, usage_percent: Float.round(used_percent, 2)}
        else
          %{status: :warning, usage_percent: Float.round(used_percent, 2), warning: "Memory usage high"}
        end

      _ ->
        %{status: :healthy, note: "Memory check not available"}
    end
  rescue
    _ -> %{status: :healthy, note: "Memory check not available"}
  end

  defp format_checks(checks) do
    Enum.map(checks, fn {name, details} ->
      {name, %{
        status: details[:status] || :unknown,
        details: Map.drop(details, [:status])
      }}
    end)
    |> Map.new()
  end

  defp format_timestamp(nil), do: nil
  defp format_timestamp(ms) do
    ms
    |> DateTime.from_unix!(:millisecond)
    |> DateTime.to_iso8601()
  end
end
