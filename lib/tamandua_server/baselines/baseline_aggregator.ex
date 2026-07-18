defmodule TamanduaServer.Baselines.BaselineAggregator do
  @moduledoc """
  Aggregates baselines from all agents to create global baselines.

  Receives baseline uploads from agents, aggregates them across the fleet,
  and generates global baselines that can be distributed back to agents.

  ## Architecture

  - Stores individual agent baselines in PostgreSQL
  - Computes global baselines by aggregating statistics from all agents
  - Provides API for agents to upload/download baselines
  - Tracks baseline drift over time

  ## Baseline Types

  1. **Process Baselines**: Aggregated across all agents running the same process
  2. **Network Baselines**: Common network patterns across the organization
  3. **File Access Baselines**: Expected file access patterns
  4. **User Baselines**: User behavior patterns (per user or aggregated)
  """

  use GenServer
  require Logger
  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Baselines.{AgentBaseline, GlobalBaseline, BaselineDrift}

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Upload baselines from an agent.
  """
  def upload_baselines(agent_id, baseline_data) do
    GenServer.call(__MODULE__, {:upload_baselines, agent_id, baseline_data}, :timer.seconds(30))
  end

  @doc """
  Download global baselines for an agent.
  """
  def download_baselines(agent_id, baseline_types \\ :all) do
    GenServer.call(__MODULE__, {:download_baselines, agent_id, baseline_types})
  end

  @doc """
  Recompute global baselines from all agent data.
  """
  def recompute_global_baselines do
    GenServer.cast(__MODULE__, :recompute_global_baselines)
  end

  @doc """
  Get baseline statistics.
  """
  def get_statistics do
    GenServer.call(__MODULE__, :get_statistics)
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    Logger.info("Starting baseline aggregator")

    # Schedule periodic global baseline recomputation
    schedule_recompute()

    # Schedule drift detection
    schedule_drift_detection()

    state = %{
      last_recompute: nil,
      last_drift_check: nil,
      stats: %{
        agents_with_baselines: 0,
        total_baselines: 0,
        last_upload: nil
      }
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:upload_baselines, agent_id, baseline_data}, _from, state) do
    case process_baseline_upload(agent_id, baseline_data) do
      {:ok, count} ->
        Logger.info("Received #{count} baselines from agent #{agent_id}")

        new_state = update_in(state.stats.last_upload, fn _ -> DateTime.utc_now() end)

        {:reply, {:ok, count}, new_state}

      {:error, reason} = error ->
        Logger.error("Failed to process baseline upload from agent #{agent_id}: #{inspect(reason)}")
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:download_baselines, agent_id, baseline_types}, _from, state) do
    case fetch_global_baselines(agent_id, baseline_types) do
      {:ok, baselines} ->
        Logger.debug("Sent #{length(baselines)} global baselines to agent #{agent_id}")
        {:reply, {:ok, baselines}, state}

      {:error, reason} = error ->
        Logger.error("Failed to fetch global baselines for agent #{agent_id}: #{inspect(reason)}")
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call(:get_statistics, _from, state) do
    stats = compute_statistics()
    {:reply, {:ok, stats}, put_in(state.stats, stats)}
  end

  @impl true
  def handle_cast(:recompute_global_baselines, state) do
    Logger.info("Starting global baseline recomputation")

    Task.start(fn ->
      case aggregate_global_baselines() do
        {:ok, count} ->
          Logger.info("Successfully recomputed #{count} global baselines")

        {:error, reason} ->
          Logger.error("Failed to recompute global baselines: #{inspect(reason)}")
      end
    end)

    new_state = put_in(state.last_recompute, DateTime.utc_now())
    {:noreply, new_state}
  end

  @impl true
  def handle_info(:recompute_global_baselines, state) do
    handle_cast(:recompute_global_baselines, state)
    schedule_recompute()
    {:noreply, state}
  end

  @impl true
  def handle_info(:detect_drift, state) do
    Logger.debug("Running baseline drift detection")

    Task.start(fn ->
      detect_and_record_drift()
    end)

    schedule_drift_detection()
    new_state = put_in(state.last_drift_check, DateTime.utc_now())
    {:noreply, new_state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Private Functions

  defp process_baseline_upload(agent_id, baseline_data) do
    # Decompress if compressed
    data = decompress_if_needed(baseline_data)

    # Parse baseline data
    case Jason.decode(data) do
      {:ok, baselines} when is_list(baselines) ->
        # Store agent baselines
        count = Enum.reduce(baselines, 0, fn baseline, acc ->
          case store_agent_baseline(agent_id, baseline) do
            {:ok, _} -> acc + 1
            {:error, _} -> acc
          end
        end)

        {:ok, count}

      {:error, reason} ->
        {:error, {:decode_error, reason}}
    end
  end

  defp store_agent_baseline(agent_id, baseline) do
    attrs = %{
      agent_id: agent_id,
      baseline_type: baseline["baseline_type"] || "process",
      baseline_key: baseline["baseline_key"] || baseline["process_name"],
      baseline_data: baseline,
      learning_samples: baseline["learning_samples"] || 0,
      first_seen: parse_timestamp(baseline["first_seen"]),
      last_updated: parse_timestamp(baseline["last_updated"]),
      version: baseline["version"] || 1
    }

    # Upsert agent baseline
    %AgentBaseline{}
    |> AgentBaseline.changeset(attrs)
    |> Repo.insert_or_update()
  end

  defp fetch_global_baselines(_agent_id, baseline_types) do
    # Fetch global baselines based on requested types
    query =
      if baseline_types == :all do
        GlobalBaseline
      else
        GlobalBaseline
        |> where([b], b.baseline_type in ^List.wrap(baseline_types))
      end

    baselines =
      query
      |> order_by([b], desc: b.updated_at)
      |> Repo.all()
      |> Enum.map(& &1.baseline_data)

    {:ok, baselines}
  end

  defp aggregate_global_baselines do
    # Group agent baselines by type and key
    agent_baselines =
      AgentBaseline
      |> where([b], b.last_updated > ago(30, "day"))
      |> Repo.all()
      |> Enum.group_by(fn b -> {b.baseline_type, b.baseline_key} end)

    count =
      Enum.reduce(agent_baselines, 0, fn {{type, key}, baselines}, acc ->
        case compute_global_baseline(type, key, baselines) do
          {:ok, global_baseline} ->
            store_global_baseline(type, key, global_baseline)
            acc + 1

          {:error, reason} ->
            Logger.warning("Failed to compute global baseline for #{type}:#{key}: #{inspect(reason)}")
            acc
        end
      end)

    {:ok, count}
  end

  defp compute_global_baseline("process", key, agent_baselines) do
    # Aggregate process baselines
    all_data = Enum.map(agent_baselines, & &1.baseline_data)

    # Compute aggregate statistics
    memory_values = Enum.flat_map(all_data, &get_in(&1, ["memory_values"]) || [])
    cpu_values = Enum.flat_map(all_data, &get_in(&1, ["cpu_values"]) || [])

    # Aggregate network destinations
    network_destinations =
      all_data
      |> Enum.flat_map(&(get_in(&1, ["common_network_destinations"]) || %{}) |> Map.to_list())
      |> Enum.group_by(fn {dest, _} -> dest end, fn {_, count} -> count end)
      |> Enum.map(fn {dest, counts} -> {dest, Enum.sum(counts)} end)
      |> Enum.sort_by(fn {_, count} -> count end, :desc)
      |> Enum.take(100)
      |> Map.new()

    global_baseline = %{
      "process_name" => key,
      "avg_memory_mb" => calculate_mean(memory_values),
      "stddev_memory_mb" => calculate_stddev(memory_values),
      "avg_cpu_percent" => calculate_mean(cpu_values),
      "stddev_cpu_percent" => calculate_stddev(cpu_values),
      "common_network_destinations" => network_destinations,
      "agent_count" => length(agent_baselines),
      "total_samples" => Enum.sum(Enum.map(all_data, &(&1["learning_samples"] || 0)))
    }

    {:ok, global_baseline}
  end

  defp compute_global_baseline(_type, _key, _baselines) do
    # TODO: Implement for other baseline types
    {:error, :not_implemented}
  end

  defp store_global_baseline(type, key, baseline_data) do
    attrs = %{
      baseline_type: type,
      baseline_key: key,
      baseline_data: baseline_data,
      agent_count: baseline_data["agent_count"] || 0,
      total_samples: baseline_data["total_samples"] || 0,
      updated_at: DateTime.utc_now()
    }

    %GlobalBaseline{}
    |> GlobalBaseline.changeset(attrs)
    |> Repo.insert_or_update()
  end

  defp detect_and_record_drift do
    # Compare current global baselines with historical versions
    # to detect significant drift

    GlobalBaseline
    |> Repo.all()
    |> Enum.each(fn baseline ->
      case check_baseline_drift(baseline) do
        {:drift_detected, drift_percent} when drift_percent > 50.0 ->
          Logger.warning("Significant drift detected in #{baseline.baseline_type}:#{baseline.baseline_key}: #{drift_percent}%")

          record_drift(baseline, drift_percent)

        _ ->
          :ok
      end
    end)
  end

  defp check_baseline_drift(_baseline) do
    # Compare with previous version (would need historical tracking)
    # For now, return no drift
    {:ok, :no_drift}
  end

  defp record_drift(baseline, drift_percent) do
    %BaselineDrift{}
    |> BaselineDrift.changeset(%{
      baseline_type: baseline.baseline_type,
      baseline_key: baseline.baseline_key,
      drift_percent: drift_percent,
      direction: "unknown",
      detected_at: DateTime.utc_now()
    })
    |> Repo.insert()
  end

  defp compute_statistics do
    %{
      agents_with_baselines: count_agents_with_baselines(),
      total_agent_baselines: Repo.aggregate(AgentBaseline, :count),
      total_global_baselines: Repo.aggregate(GlobalBaseline, :count),
      last_upload: get_last_upload_time(),
      oldest_baseline: get_oldest_baseline_time(),
      newest_baseline: get_newest_baseline_time()
    }
  end

  defp count_agents_with_baselines do
    AgentBaseline
    |> select([b], b.agent_id)
    |> distinct(true)
    |> Repo.aggregate(:count)
  end

  defp get_last_upload_time do
    AgentBaseline
    |> select([b], max(b.inserted_at))
    |> Repo.one()
  end

  defp get_oldest_baseline_time do
    GlobalBaseline
    |> select([b], min(b.inserted_at))
    |> Repo.one()
  end

  defp get_newest_baseline_time do
    GlobalBaseline
    |> select([b], max(b.updated_at))
    |> Repo.one()
  end

  defp decompress_if_needed(data) when is_binary(data) do
    # Check for gzip magic bytes (0x1f, 0x8b)
    case data do
      <<0x1F, 0x8B, _rest::binary>> ->
        :zlib.gunzip(data)

      _ ->
        data
    end
  end

  defp parse_timestamp(nil), do: nil
  defp parse_timestamp(ts) when is_integer(ts) do
    DateTime.from_unix!(ts)
  end
  defp parse_timestamp(ts) when is_binary(ts) do
    case DateTime.from_iso8601(ts) do
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end

  defp calculate_mean([]), do: 0.0
  defp calculate_mean(values) do
    Enum.sum(values) / length(values)
  end

  defp calculate_stddev([]), do: 0.0
  defp calculate_stddev(values) do
    mean = calculate_mean(values)
    variance = Enum.reduce(values, 0, fn v, acc -> acc + :math.pow(v - mean, 2) end) / length(values)
    :math.sqrt(variance)
  end

  defp schedule_recompute do
    # Recompute every hour
    Process.send_after(self(), :recompute_global_baselines, :timer.hours(1))
  end

  defp schedule_drift_detection do
    # Check drift every 6 hours
    Process.send_after(self(), :detect_drift, :timer.hours(6))
  end
end
