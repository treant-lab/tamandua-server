defmodule TamanduaServer.Detection.AgentRiskScoreStore do
  @moduledoc """
  ETS-backed per-agent / per-process cache of the agent-side
  deterministic risk score snapshot (`RiskScoreSnapshot`).

  Tenancy: cache key is `{agent_id, process_key}`. `agent_id` is the
  channel-authenticated identifier validated upstream; never use
  `process_key` alone as the key (the snapshot's `process_key` is a
  lowercased basename and is not unique across tenants).

  Read/write contract:
    - `put/2` upserts an entry. Idempotent and concurrency-safe.
    - `get/2` returns `nil` if missing, or the snapshot map otherwise.
      Callers must check freshness via `RiskScoreSnapshot.stale?/3`.

  Cleanup: every 5 minutes a periodic sweep evicts entries whose
  `snapshot_at_ms` is older than `@max_age_ms`. This keeps the table
  bounded even when agents disconnect mid-run.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Detection.RiskScoreSnapshot

  @table :agent_risk_score_cache
  @cleanup_interval_ms 5 * 60 * 1000
  # Evict entries older than 30 minutes — agents emit snapshots every
  # few seconds when the feature is on; anything older than that means
  # the agent has gone away or stopped emitting.
  @max_age_ms 30 * 60 * 1000

  # ── Public API ─────────────────────────────────────────────────────

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Upsert a snapshot for `{agent_id, process_key}`. The snapshot map MUST
  match `RiskScoreSnapshot.t()`. Returns `:ok`. Silently no-ops when
  `agent_id` is `nil` (defense in depth — should never reach here).
  """
  @spec put(String.t() | nil, RiskScoreSnapshot.t()) :: :ok
  def put(nil, _snap), do: :ok

  def put(agent_id, %{process_key: pk} = snap) when is_binary(agent_id) and is_binary(pk) do
    ensure_table()
    :ets.insert(@table, {{agent_id, pk}, snap})
    :ok
  end

  def put(_, _), do: :ok

  @doc """
  Look up the latest snapshot for `{agent_id, process_key}`. Returns
  `nil` if no entry exists. Caller is responsible for staleness checks.
  """
  @spec get(String.t() | nil, String.t() | nil) :: RiskScoreSnapshot.t() | nil
  def get(nil, _process_key), do: nil
  def get(_agent_id, nil), do: nil
  def get(_agent_id, ""), do: nil

  def get(agent_id, process_key) when is_binary(agent_id) and is_binary(process_key) do
    ensure_table()
    key = {agent_id, String.downcase(process_key)}

    case :ets.lookup(@table, key) do
      [{^key, snap}] -> snap
      [] -> nil
    end
  end

  def get(_, _), do: nil

  @doc "Total entry count. Used by tests and ops telemetry."
  @spec size() :: non_neg_integer()
  def size do
    ensure_table()
    :ets.info(@table, :size)
  end

  @doc "Manual cleanup. Returns the number of entries evicted."
  @spec cleanup(non_neg_integer()) :: non_neg_integer()
  def cleanup(now_ms \\ System.system_time(:millisecond)) do
    ensure_table()
    cutoff = now_ms - @max_age_ms

    # ETS match spec: select entries with snapshot_at_ms < cutoff
    spec = [
      {{:"$1", %{snapshot_at_ms: :"$2"}}, [{:<, :"$2", cutoff}], [:"$1"]}
    ]

    keys = :ets.select(@table, spec)

    Enum.each(keys, fn key -> :ets.delete(@table, key) end)
    length(keys)
  end

  @doc "Drop the entire cache. Test-only."
  @spec reset() :: :ok
  def reset do
    ensure_table()
    :ets.delete_all_objects(@table)
    :ok
  end

  # ── GenServer callbacks ────────────────────────────────────────────

  @impl true
  def init(_opts) do
    ensure_table()
    schedule_cleanup()
    {:ok, %{}}
  end

  @impl true
  def handle_info(:cleanup, state) do
    evicted = cleanup()

    if evicted > 0 do
      Logger.debug("[AgentRiskScoreStore] evicted #{evicted} stale entries")
    end

    schedule_cleanup()
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ── Internal ───────────────────────────────────────────────────────

  defp ensure_table do
    case :ets.whereis(@table) do
      :undefined ->
        try do
          :ets.new(@table, [
            :set,
            :public,
            :named_table,
            read_concurrency: true,
            write_concurrency: true
          ])
        rescue
          ArgumentError -> :ok
        end

      _ ->
        :ok
    end
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval_ms)
  end
end
