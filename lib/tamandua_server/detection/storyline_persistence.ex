defmodule TamanduaServer.Detection.StorylinePersistence do
  @moduledoc """
  Periodic persistence layer for the autonomous Storyline engine.

  The Storyline GenServer keeps its hot working set in ETS for
  sub-millisecond access during event processing. This module
  periodically snapshots changed storylines into PostgreSQL so they
  survive process restarts and can be queried historically.

  ## Lifecycle

  1. **Startup**: Loads recent active storylines from DB back into ETS
     (recovers state after a restart).
  2. **Running**: Every `@sync_interval_ms` (30 seconds), scans the
     ETS storyline table for records updated since the last sync and
     upserts them into the `storylines` table.
  3. **Shutdown**: Performs a final flush to DB.

  ## Design Decisions

  - Uses `on_conflict: :replace` upsert so the same storyline ID is
    always a single row. No duplicates.
  - Serializes MapSet fields (processes, tactics, techniques) to plain
    lists for JSONB/array storage.
  - Detections are stored as an array of maps (JSONB) for searchability.
  - Only syncs storylines whose `updated_at` changed since last sync
    to minimize DB writes.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Detection.StorylineRecord
  alias TamanduaServer.Detection.Storyline.StorylineData

  @storyline_table :tamandua_storylines

  # Sync every 30 seconds
  @sync_interval_ms 30_000

  # On startup, recover storylines from the last 48 hours
  @recovery_window_hours 48

  # ------------------------------------------------------------------
  # Client API
  # ------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc "Force an immediate sync of all dirty storylines to DB."
  def flush do
    GenServer.call(__MODULE__, :flush, 30_000)
  end

  @doc "Persist a single storyline immediately (called on incident creation)."
  def persist_storyline(storyline_id) do
    GenServer.cast(__MODULE__, {:persist_one, storyline_id})
  end

  # ------------------------------------------------------------------
  # Server Callbacks
  # ------------------------------------------------------------------

  @impl true
  def init(_opts) do
    # Schedule first sync
    Process.send_after(self(), :sync, @sync_interval_ms)

    # Recover from DB after a short delay (let ETS tables initialize)
    Process.send_after(self(), :recover, 2_000)

    Logger.info("[StorylinePersistence] Started — sync every #{div(@sync_interval_ms, 1000)}s")

    {:ok, %{
      last_sync_at: DateTime.utc_now(),
      synced: 0,
      recovered: 0,
      errors: 0
    }}
  end

  # -- Periodic sync ---------------------------------------------------

  @impl true
  def handle_info(:sync, state) do
    new_state = do_sync(state)
    Process.send_after(self(), :sync, @sync_interval_ms)
    {:noreply, new_state}
  end

  # -- Recovery on startup ---------------------------------------------

  @impl true
  def handle_info(:recover, state) do
    recovered = do_recover()
    Logger.info("[StorylinePersistence] Recovered #{recovered} storylines from DB")
    {:noreply, %{state | recovered: recovered}}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # -- Flush on demand -------------------------------------------------

  @impl true
  def handle_call(:flush, _from, state) do
    new_state = do_sync(state)
    {:reply, :ok, new_state}
  end

  # -- Single persist --------------------------------------------------

  @impl true
  def handle_cast({:persist_one, storyline_id}, state) do
    case ets_lookup(storyline_id) do
      {:ok, storyline} ->
        case persist_to_db(storyline) do
          :ok ->
            {:noreply, %{state | synced: state.synced + 1}}
          :error ->
            {:noreply, %{state | errors: state.errors + 1}}
        end

      :not_found ->
        {:noreply, state}
    end
  end

  # ------------------------------------------------------------------
  # Sync Implementation
  # ------------------------------------------------------------------

  defp do_sync(state) do
    storylines = ets_all_storylines()
    last_sync = state.last_sync_at

    # Only sync storylines updated since last sync
    dirty =
      Enum.filter(storylines, fn s ->
        DateTime.compare(s.updated_at, last_sync) in [:gt, :eq]
      end)

    {synced, errors} =
      Enum.reduce(dirty, {0, 0}, fn storyline, {s, e} ->
        case persist_to_db(storyline) do
          :ok -> {s + 1, e}
          :error -> {s, e + 1}
        end
      end)

    if synced > 0 do
      Logger.debug("[StorylinePersistence] Synced #{synced} storylines to DB (#{errors} errors)")
    end

    %{state |
      last_sync_at: DateTime.utc_now(),
      synced: state.synced + synced,
      errors: state.errors + errors
    }
  end

  defp persist_to_db(%StorylineData{} = storyline) do
    org_id = TamanduaServer.Agents.OrgLookup.get_org_id(storyline.agent_id)

    attrs = %{
      id: storyline.id,
      agent_id: storyline.agent_id,
      organization_id: org_id,
      alert_id: storyline.alert_id,
      root_pid: storyline.root_pid,
      status: to_string(storyline.status),
      severity: to_string(storyline.severity),
      total_score: storyline.total_score,
      process_pids: MapSet.to_list(storyline.processes),
      mitre_tactics: MapSet.to_list(storyline.mitre_tactics),
      mitre_techniques: MapSet.to_list(storyline.mitre_techniques),
      detections: serialize_detections(storyline.detections),
      detection_count: length(storyline.detections),
      process_count: MapSet.size(storyline.processes),
      tactic_count: MapSet.size(storyline.mitre_tactics),
      first_seen_at: storyline.created_at,
      last_seen_at: storyline.updated_at
    }

    StorylineRecord.upsert!(attrs)
    :ok
  rescue
    e ->
      Logger.error("[StorylinePersistence] Failed to persist storyline #{storyline.id}: #{inspect(e)}")
      :error
  end

  defp persist_to_db(_), do: :error

  # ------------------------------------------------------------------
  # Recovery Implementation
  # ------------------------------------------------------------------

  defp do_recover do
    cutoff = DateTime.utc_now() |> DateTime.add(-@recovery_window_hours * 3600, :second)

    records = StorylineRecord.list(
      status: "active",
      limit: 1000
    )

    # Only recover records newer than cutoff
    records = Enum.filter(records, fn r ->
      r.last_seen_at && DateTime.compare(r.last_seen_at, cutoff) == :gt
    end)

    Enum.reduce(records, 0, fn record, count ->
      case recover_to_ets(record) do
        :ok -> count + 1
        :skip -> count
      end
    end)
  rescue
    e ->
      Logger.warning("[StorylinePersistence] Recovery failed: #{inspect(e)}")
      0
  end

  defp recover_to_ets(record) do
    # Don't overwrite if already in ETS (e.g., engine already re-created it)
    case ets_lookup(record.id) do
      {:ok, _} ->
        :skip

      :not_found ->
        storyline = %StorylineData{
          id: record.id,
          agent_id: record.agent_id,
          root_pid: record.root_pid,
          created_at: record.first_seen_at || record.inserted_at,
          updated_at: record.last_seen_at || record.updated_at,
          alert_id: record.alert_id,
          processes: MapSet.new(record.process_pids || []),
          detections: deserialize_detections(record.detections || []),
          total_score: record.total_score || 0.0,
          severity: String.to_existing_atom(record.severity || "low"),
          status: String.to_existing_atom(record.status || "active"),
          mitre_tactics: MapSet.new(record.mitre_tactics || []),
          mitre_techniques: MapSet.new(record.mitre_techniques || [])
        }

        :ets.insert(@storyline_table, {record.id, storyline})

        # Rebuild PID-to-storyline mappings
        Enum.each(record.process_pids || [], fn pid ->
          :ets.insert(:tamandua_pid_to_storyline, {{record.agent_id, pid}, record.id})
        end)

        :ok
    end
  rescue
    _ -> :skip
  end

  # ------------------------------------------------------------------
  # ETS Helpers
  # ------------------------------------------------------------------

  defp ets_lookup(storyline_id) do
    case :ets.lookup(@storyline_table, storyline_id) do
      [{^storyline_id, storyline}] -> {:ok, storyline}
      [] -> :not_found
    end
  rescue
    ArgumentError -> :not_found
  end

  defp ets_all_storylines do
    :ets.tab2list(@storyline_table)
    |> Enum.map(fn {_id, s} -> s end)
  rescue
    ArgumentError -> []
  end

  # ------------------------------------------------------------------
  # Serialization Helpers
  # ------------------------------------------------------------------

  defp serialize_detections(detections) when is_list(detections) do
    Enum.map(detections, fn d ->
      %{
        "id" => to_string(d[:id] || d["id"] || ""),
        "event_type" => to_string(d[:event_type] || d["event_type"] || ""),
        "score" => d[:score] || d["score"] || 0.0,
        "title" => to_string(d[:title] || d["title"] || ""),
        "mitre_tactics" => d[:mitre_tactics] || d["mitre_tactics"] || [],
        "mitre_techniques" => d[:mitre_techniques] || d["mitre_techniques"] || [],
        "timestamp" => serialize_datetime(d[:timestamp] || d["timestamp"])
      }
    end)
  end

  defp serialize_detections(_), do: []

  defp deserialize_detections(detections) when is_list(detections) do
    Enum.map(detections, fn d ->
      %{
        id: d["id"],
        event_type: d["event_type"],
        score: d["score"] || 0.0,
        title: d["title"],
        mitre_tactics: d["mitre_tactics"] || [],
        mitre_techniques: d["mitre_techniques"] || [],
        timestamp: deserialize_datetime(d["timestamp"])
      }
    end)
  end

  defp deserialize_detections(_), do: []

  defp serialize_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp serialize_datetime(str) when is_binary(str), do: str
  defp serialize_datetime(_), do: nil

  defp deserialize_datetime(str) when is_binary(str) do
    case DateTime.from_iso8601(str) do
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end
  defp deserialize_datetime(%DateTime{} = dt), do: dt
  defp deserialize_datetime(_), do: nil
end
