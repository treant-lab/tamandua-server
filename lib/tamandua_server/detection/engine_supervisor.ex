defmodule TamanduaServer.Detection.EngineSupervisor do
  @moduledoc """
  Supervisor for the sharded detection engine architecture.

  Manages N detection worker processes (sharded by agent_id hash) to distribute
  event analysis load across CPU cores. At 10k+ agents generating 100 events/sec
  each, a single GenServer becomes a bottleneck. This supervisor spawns
  `@num_shards` independent workers, each handling a deterministic subset of
  agents based on `:erlang.phash2(agent_id, @num_shards)`.

  Shared state (Sigma rules, IOCs, YARA rule metadata) is stored in public ETS
  tables with `read_concurrency: true` so every worker can read rules without
  contention. Rule reloads write to ETS atomically -- all workers see new rules
  immediately without message passing.

  Detection statistics are stored in a write-optimised ETS table
  (`:detection_stats`) so workers can bump counters concurrently.
  """

  use Supervisor
  require Logger

  @num_shards 16

  def start_link(opts) do
    Supervisor.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc "Returns the configured number of shards."
  @spec num_shards() :: pos_integer()
  def num_shards, do: @num_shards

  @impl true
  def init(_opts) do
    TamanduaServer.Detection.RuleLoader.init_tables()

    # ── Shared ETS tables ──────────────────────────────────────────────
    # These are :public and :named_table so any process (workers, the
    # Engine facade, Broadway processors) can read from them.

    create_ets_table(:detection_sigma_rules, [:set, :public, :named_table, {:read_concurrency, true}])
    create_ets_table(:detection_yara_rules, [:set, :public, :named_table, {:read_concurrency, true}])
    create_ets_table(:detection_ioc_rules, [:set, :public, :named_table, {:read_concurrency, true}])
    create_ets_table(:detection_stats, [:set, :public, :named_table, {:write_concurrency, true}])

    # Seed per-shard stat counters so :ets.update_counter never fails on
    # a missing key. Uses {shard, stat_name} composite keys with integer
    # values for truly atomic counter increments.
    stat_keys = [
      :events_analyzed,
      :detections,
      :ml_predictions,
      :alerts_created,
      :alerts_suppressed,
      :alerts_severity_reduced,
      :alerts_health_suppressed,
      :alerts_health_adjusted,
      :yara_scans
    ]

    for shard <- 0..(@num_shards - 1), key <- stat_keys do
      # insert_new preserves existing counters across supervisor restarts
      :ets.insert_new(:detection_stats, {{shard, key}, 0})
    end

    Logger.info("[EngineSupervisor] Starting #{@num_shards} detection worker shards")

    children =
      for shard <- 0..(@num_shards - 1) do
        Supervisor.child_spec(
          {TamanduaServer.Detection.EngineWorker, shard: shard},
          id: {TamanduaServer.Detection.EngineWorker, shard}
        )
      end

    Supervisor.init(children, strategy: :one_for_one, max_restarts: 50, max_seconds: 60)
  end

  # ── Helpers ────────────────────────────────────────────────────────

  @doc """
  Aggregate detection statistics across all shards.
  Reads the per-shard maps from :detection_stats and sums them.
  """
  @stat_keys [
    :events_analyzed,
    :detections,
    :ml_predictions,
    :alerts_created,
    :alerts_suppressed,
    :alerts_severity_reduced,
    :alerts_health_suppressed,
    :alerts_health_adjusted,
    :yara_scans
  ]

  @spec aggregate_stats() :: map()
  def aggregate_stats do
    Map.new(@stat_keys, fn key ->
      total =
        Enum.reduce(0..(@num_shards - 1), 0, fn shard, acc ->
          case :ets.lookup(:detection_stats, {shard, key}) do
            [{{^shard, ^key}, count}] -> acc + count
            _ -> acc
          end
        end)

      {key, total}
    end)
  end

  @doc """
  Atomically increment a statistic counter for a given shard.

  Uses `:ets.update_counter/3` which is a single atomic operation —
  no read-modify-write race even with concurrent callers.
  """
  @spec update_shard_stat(non_neg_integer(), atom()) :: :ok
  def update_shard_stat(shard, key) do
    :ets.update_counter(:detection_stats, {shard, key}, {2, 1}, {{shard, key}, 0})
    :ok
  rescue
    ArgumentError ->
      # Table not yet created (race during startup) — safe to drop
      :ok
  end

  # Create an ETS table, handling the case where it already exists
  # (e.g. after a supervisor restart).
  defp create_ets_table(name, opts) do
    case :ets.whereis(name) do
      :undefined ->
        :ets.new(name, opts)
      _ref ->
        # Table already exists (supervisor restarted but ETS persists
        # because the owner is the supervisor process itself).
        :ok
    end
  rescue
    ArgumentError ->
      # Table already exists - this is fine on restart
      :ok
  end
end
