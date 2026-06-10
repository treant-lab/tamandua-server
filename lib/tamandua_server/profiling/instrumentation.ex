defmodule TamanduaServer.Profiling.Instrumentation do
  @moduledoc """
  Performance profiling instrumentation for Tamandua Server.

  Provides comprehensive profiling capabilities:
  - CPU profiling with :fprof and :eprof
  - Memory profiling with :recon
  - GenServer mailbox monitoring
  - Ecto query profiling
  - Broadway pipeline profiling
  - Phoenix request profiling
  - Distributed tracing integration
  """

  require Logger

  @doc """
  Start CPU profiling with :fprof
  """
  def start_fprof(duration_ms \\ 30_000) do
    Logger.info("Starting fprof CPU profiling for #{duration_ms}ms")

    :fprof.trace([:start, procs: :all])

    # Stop after duration
    Process.send_after(self(), :stop_fprof, duration_ms)

    :ok
  end

  @doc """
  Stop CPU profiling and analyze results
  """
  def stop_fprof do
    Logger.info("Stopping fprof CPU profiling")

    :fprof.trace(:stop)
    :fprof.profile()
    :fprof.analyse(totals: true, sort: :own)

    :ok
  end

  @doc """
  Start process profiling with :eprof
  """
  def start_eprof(pids \\ :all, duration_ms \\ 30_000) do
    Logger.info("Starting eprof process profiling for #{duration_ms}ms")

    :eprof.start()
    :eprof.start_profiling(if pids == :all, do: Process.list(), else: pids)

    Process.send_after(self(), :stop_eprof, duration_ms)

    :ok
  end

  @doc """
  Stop process profiling
  """
  def stop_eprof do
    Logger.info("Stopping eprof process profiling")

    :eprof.stop_profiling()
    :eprof.analyze(:total)
    :eprof.stop()

    :ok
  end

  @doc """
  Get memory statistics using :recon
  """
  def memory_stats do
    %{
      processes: :recon.proc_count(:memory, 10),
      binary_memory: :recon.bin_leak(10),
      total_memory: :erlang.memory(),
      gc_stats: :recon.node_stats_print(1, 1)
    }
  end

  @doc """
  Get process information
  """
  def process_info(limit \\ 25) do
    %{
      by_memory: :recon.proc_count(:memory, limit),
      by_reductions: :recon.proc_count(:reductions, limit),
      by_message_queue: :recon.proc_count(:message_queue_len, limit)
    }
  end

  @doc """
  Get GenServer mailbox depths
  """
  def genserver_mailbox_depths do
    Process.list()
    |> Enum.filter(&is_genserver?/1)
    |> Enum.map(fn pid ->
      case Process.info(pid, [:registered_name, :message_queue_len]) do
        [{:registered_name, name}, {:message_queue_len, len}] when len > 0 ->
          {name || pid, len}

        _ ->
          nil
      end
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.sort_by(fn {_name, len} -> -len end)
  end

  @doc """
  Profile Ecto queries
  """
  def ecto_query_stats(limit \\ 10) do
    TamanduaServer.Repo.all_running()
    |> Enum.map(fn {_ref, query, params, _opts} ->
      %{
        query: inspect(query),
        params: inspect(params)
      }
    end)
    |> Enum.take(limit)
  end

  @doc """
  Get Broadway pipeline statistics
  """
  def broadway_stats do
    # Get all Broadway producers
    broadway_names = get_broadway_pipelines()

    Enum.map(broadway_names, fn name ->
      case Broadway.topology(name) do
        {:ok, topology} ->
          %{
            name: name,
            topology: topology,
            producers: get_producer_stats(name),
            processors: get_processor_stats(name),
            batchers: get_batcher_stats(name)
          }

        {:error, _} ->
          nil
      end
    end)
    |> Enum.reject(&is_nil/1)
  end

  @doc """
  Get Phoenix request profiling data
  """
  def phoenix_request_stats do
    # This would integrate with Telemetry events
    # For now, return placeholder
    %{
      total_requests: 0,
      avg_response_time: 0,
      p50: 0,
      p95: 0,
      p99: 0
    }
  end

  @doc """
  Detect potential bottlenecks
  """
  def detect_bottlenecks do
    mailbox_depths = genserver_mailbox_depths()
    process_info = process_info(10)

    bottlenecks = []

    # Check for deep mailboxes
    bottlenecks =
      if Enum.any?(mailbox_depths, fn {_name, len} -> len > 1000 end) do
        deep_mailboxes =
          Enum.filter(mailbox_depths, fn {_name, len} -> len > 1000 end)

        [{:deep_mailboxes, deep_mailboxes} | bottlenecks]
      else
        bottlenecks
      end

    # Check for memory-hungry processes
    bottlenecks =
      case process_info[:by_memory] do
        [{_pid, mem, _info} | _] when mem > 100_000_000 ->
          [{:high_memory_processes, process_info[:by_memory]} | bottlenecks]

        _ ->
          bottlenecks
      end

    # Check for high reductions (CPU usage)
    bottlenecks =
      case process_info[:by_reductions] do
        [{_pid, reds, _info} | _] when reds > 10_000_000 ->
          [{:high_cpu_processes, process_info[:by_reductions]} | bottlenecks]

        _ ->
          bottlenecks
      end

    bottlenecks
  end

  @doc """
  Generate profiling report
  """
  def generate_report do
    %{
      timestamp: DateTime.utc_now(),
      memory: memory_stats(),
      processes: process_info(),
      mailboxes: genserver_mailbox_depths(),
      broadway: broadway_stats(),
      bottlenecks: detect_bottlenecks(),
      system_info: %{
        schedulers: :erlang.system_info(:schedulers),
        logical_processors: :erlang.system_info(:logical_processors),
        uptime: :erlang.statistics(:wall_clock) |> elem(0),
        run_queue: :erlang.statistics(:run_queue)
      }
    }
  end

  # Private functions

  defp is_genserver?(pid) do
    case Process.info(pid, :dictionary) do
      {:dictionary, dict} ->
        Keyword.has_key?(dict, :"$initial_call") &&
          match?({GenServer, _, _}, Keyword.get(dict, :"$initial_call"))

      _ ->
        false
    end
  end

  defp get_broadway_pipelines do
    # Get all registered Broadway pipelines
    Process.registered()
    |> Enum.filter(fn name ->
      name
      |> Atom.to_string()
      |> String.contains?("Broadway")
    end)
  end

  defp get_producer_stats(broadway_name) do
    # Get producer statistics
    []
  end

  defp get_processor_stats(broadway_name) do
    # Get processor statistics
    []
  end

  defp get_batcher_stats(broadway_name) do
    # Get batcher statistics
    []
  end
end
