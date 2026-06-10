defmodule TamanduaServer.Alerts.Deduplication do
  @moduledoc """
  Alert Deduplication Engine.

  Provides high-performance, ETS-backed alert deduplication with sliding
  window aggregation. Within a configurable time window (default 5 minutes),
  identical alerts are grouped and the `occurrence_count` on the existing
  alert row is incremented rather than creating new rows.

  ## Architecture

  - **ETS-based fast lookup**: The `:alert_dedup_windows` table stores active
    dedup windows keyed by dedup hash for O(1) lookups on the hot path.
  - **Sliding window aggregation**: Each window tracks the alert ID, first
    occurrence time, last occurrence time, and occurrence count.
  - **Configurable hash fields**: Dedup hashes are generated from
    `rule_id + agent_id + primary_entity` by default, with per-type overrides.
  - **Periodic cleanup**: A timer sweeps expired windows from ETS.
  - **Stats tracking**: Dedup rate, window sizes, top duplicated alerts.
  - **PubSub integration**: Subscribes to `"alerts:feed"` for real-time
    awareness. Broadcasts stats to `"alerts:dedup_stats"`.

  ## Integration

  The alert creation path in `TamanduaServer.Alerts.create_alert/1` can call
  `check_and_deduplicate/1` before inserting a new row. The function returns
  either `{:new, attrs}` (proceed with insert) or
  `{:duplicate, existing_alert_id, count}` (skip insert, bump count).
  """

  use GenServer
  require Logger

  import Ecto.Query, warn: false

  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts.Alert

  # ── ETS Tables ────────────────────────────────────────────────────

  # Active dedup windows: {dedup_hash, %{alert_id, first_at, last_at, count, severity, title}}
  @dedup_table :alert_dedup_windows
  # Stats counters: {key, value}
  @stats_table :alert_dedup_stats

  # ── Defaults ──────────────────────────────────────────────────────

  # Default sliding window duration in seconds (5 minutes)
  @default_window_seconds 300
  # Cleanup interval (every 60 seconds)
  @cleanup_interval :timer.seconds(60)
  # Stats broadcast interval (every 30 seconds)
  @stats_broadcast_interval :timer.seconds(30)
  # Maximum number of top-duplicated entries to track
  @top_duplicated_limit 20

  # ── Hash field configuration per alert type ───────────────────────

  # Maps event_type prefixes to the fields used for dedup hash generation.
  # Alerts whose detection_metadata contains an event_type matching one of
  # these keys will use the specified fields instead of the defaults.
  @hash_fields_by_type %{
    "process" => [:rule_id, :agent_id, :process_name],
    "network" => [:rule_id, :agent_id, :remote_ip],
    "dns" => [:rule_id, :agent_id, :query],
    "file" => [:rule_id, :agent_id, :file_path],
    "registry" => [:rule_id, :agent_id, :registry_path]
  }

  # ═══════════════════════════════════════════════════════════════════
  # Client API
  # ═══════════════════════════════════════════════════════════════════

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Check whether an alert with the given attributes is a duplicate of an
  existing alert within the active dedup window.

  This is the primary integration point for the alert creation pipeline.

  ## Parameters

  - `attrs` - The alert attributes map (pre-insertion). Must contain at
    minimum `:title` and `:severity`. May contain `:agent_id`,
    `:detection_metadata`, `:evidence`, `:raw_event`, and `:dedup_key`.

  ## Returns

  - `{:new, attrs}` - No duplicate found. The attrs map is returned with
    a `:dedup_key` field set (if not already present). The caller should
    proceed with alert insertion.
  - `{:duplicate, existing_alert_id, new_count}` - A duplicate was found
    within the active window. The existing alert's `occurrence_count` and
    `last_seen_at` have already been updated in the database. The caller
    should skip insertion.
  """
  @spec check_and_deduplicate(map()) :: {:new, map()} | {:duplicate, String.t(), non_neg_integer()}
  def check_and_deduplicate(attrs) do
    GenServer.call(__MODULE__, {:check_and_deduplicate, attrs})
  catch
    :exit, _ ->
      # If GenServer is down, fall through to allow normal alert creation
      Logger.warning("[Dedup] GenServer unavailable, allowing alert creation")
      dedup_key = compute_dedup_hash(attrs)
      {:new, Map.put(attrs, :dedup_key, dedup_key)}
  end

  @doc """
  Record that a new alert was created with the given dedup key.

  Called after successful alert insertion so the dedup window is
  registered for future duplicate checks.

  ## Parameters

  - `dedup_key` - The dedup hash string
  - `alert_id` - The ID of the newly created alert
  - `attrs` - The alert attributes (for metadata in the window entry)
  """
  @spec register_new_alert(String.t(), String.t(), map()) :: :ok
  def register_new_alert(dedup_key, alert_id, attrs) do
    GenServer.cast(__MODULE__, {:register_new_alert, dedup_key, alert_id, attrs})
  end

  @doc """
  Get current deduplication statistics.

  Returns a map with:
  - `:total_checked` - Total alerts checked for dedup
  - `:total_deduplicated` - Total alerts deduplicated (skipped)
  - `:total_new` - Total new alerts allowed through
  - `:dedup_rate` - Percentage of alerts deduplicated
  - `:active_windows` - Number of active dedup windows in ETS
  - `:window_seconds` - Current window duration
  - `:top_duplicated` - List of top duplicated alert patterns
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  catch
    :exit, _ -> default_stats()
  end

  @doc """
  Force cleanup of expired dedup windows.
  """
  @spec cleanup_expired() :: non_neg_integer()
  def cleanup_expired do
    GenServer.call(__MODULE__, :cleanup_expired)
  catch
    :exit, _ -> 0
  end

  @doc """
  Generate a deterministic dedup hash for the given alert attributes.

  The hash is based on:
  - `rule_id` (from detection_metadata or title fallback)
  - `agent_id`
  - Primary entity (process name, file path, IP, DNS query, etc.)

  Per-type hash field overrides are applied based on the event type
  in the detection metadata.

  ## Parameters

  - `attrs` - Alert attributes map

  ## Returns

  A 40-character lowercase hex string (SHA-256 truncated).
  """
  @spec compute_dedup_hash(map()) :: String.t()
  def compute_dedup_hash(attrs) do
    event_type = extract_event_type(attrs)
    hash_fields = Map.get(@hash_fields_by_type, event_type_prefix(event_type), [:rule_id, :agent_id, :primary_entity])

    key_parts = Enum.map(hash_fields, fn field ->
      extract_hash_field(attrs, field)
    end)

    key_material = Enum.join(key_parts, ":")
    :crypto.hash(:sha256, key_material) |> Base.encode16(case: :lower) |> binary_part(0, 40)
  end

  @doc """
  Get the configured dedup window duration in seconds.
  """
  @spec window_seconds() :: non_neg_integer()
  def window_seconds do
    Application.get_env(:tamandua_server, :alert_dedup_window_seconds, @default_window_seconds)
  end

  # ═══════════════════════════════════════════════════════════════════
  # GenServer Implementation
  # ═══════════════════════════════════════════════════════════════════

  @impl true
  def init(_opts) do
    # Create ETS tables
    create_ets_tables()

    # Initialize stats counters
    init_stats()

    # Schedule periodic tasks
    schedule_cleanup()
    schedule_stats_broadcast()

    # Subscribe to PubSub for real-time alert awareness
    subscribe_to_alerts()

    Logger.info(
      "[Dedup] Alert Deduplication Engine started " <>
        "(window=#{window_seconds()}s, cleanup_interval=#{div(@cleanup_interval, 1000)}s)"
    )

    {:ok, %{started_at: System.system_time(:second)}}
  end

  @impl true
  def handle_call({:check_and_deduplicate, attrs}, _from, state) do
    dedup_key = attrs[:dedup_key] || compute_dedup_hash(attrs)
    attrs = Map.put(attrs, :dedup_key, dedup_key)

    increment_stat(:total_checked)

    result = case lookup_active_window(dedup_key) do
      {:ok, window} ->
        # Duplicate found in ETS window -- increment in DB and ETS
        new_count = window.count + 1
        now = System.system_time(:second)

        # Update the ETS window entry
        update_window(dedup_key, %{window | count: new_count, last_at: now})

        # Update the database alert
        update_existing_alert(window.alert_id, new_count)

        # Track in top-duplicated
        track_top_duplicated(dedup_key, window)

        increment_stat(:total_deduplicated)

        {:duplicate, window.alert_id, new_count}

      :not_found ->
        # Check database as fallback (window may have been lost on restart)
        case find_duplicate_in_db(dedup_key) do
          {:ok, existing_alert} ->
            new_count = (existing_alert.occurrence_count || 1) + 1
            now = System.system_time(:second)

            # Populate ETS window from DB hit
            window = %{
              alert_id: existing_alert.id,
              first_at: System.system_time(:second) - window_seconds() + 60,
              last_at: now,
              count: new_count,
              severity: existing_alert.severity,
              title: existing_alert.title
            }

            insert_window(dedup_key, window)
            update_existing_alert(existing_alert.id, new_count)
            track_top_duplicated(dedup_key, window)

            increment_stat(:total_deduplicated)

            {:duplicate, existing_alert.id, new_count}

          :not_found ->
            increment_stat(:total_new)
            {:new, attrs}
        end
    end

    {:reply, result, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    stats = build_stats(state)
    {:reply, stats, state}
  end

  @impl true
  def handle_call(:cleanup_expired, _from, state) do
    deleted = do_cleanup_expired()
    {:reply, deleted, state}
  end

  @impl true
  def handle_cast({:register_new_alert, dedup_key, alert_id, attrs}, state) do
    now = System.system_time(:second)

    window = %{
      alert_id: alert_id,
      first_at: now,
      last_at: now,
      count: 1,
      severity: to_string(attrs[:severity] || "medium"),
      title: to_string(attrs[:title] || "")
    }

    insert_window(dedup_key, window)
    {:noreply, state}
  end

  @impl true
  def handle_info(:cleanup_expired, state) do
    deleted = do_cleanup_expired()

    if deleted > 0 do
      Logger.debug("[Dedup] Cleaned up #{deleted} expired dedup windows")
    end

    schedule_cleanup()
    {:noreply, state}
  end

  @impl true
  def handle_info(:broadcast_stats, state) do
    stats = build_stats(state)
    broadcast_dedup_stats(stats)
    schedule_stats_broadcast()
    {:noreply, state}
  end

  # Handle PubSub messages (alert feed events)
  @impl true
  def handle_info(%Phoenix.Socket.Broadcast{event: "new_alert", payload: payload}, state) do
    # When a new alert is broadcast, ensure its dedup window is registered
    if dedup_key = payload[:dedup_key] || payload["dedup_key"] do
      alert_id = payload[:id] || payload["id"]

      if alert_id && !has_window?(dedup_key) do
        now = System.system_time(:second)

        window = %{
          alert_id: to_string(alert_id),
          first_at: now,
          last_at: now,
          count: 1,
          severity: to_string(payload[:severity] || payload["severity"] || "medium"),
          title: to_string(payload[:title] || payload["title"] || "")
        }

        insert_window(dedup_key, window)
      end
    end

    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ═══════════════════════════════════════════════════════════════════
  # ETS Operations
  # ═══════════════════════════════════════════════════════════════════

  defp create_ets_tables do
    if :ets.whereis(@dedup_table) == :undefined do
      :ets.new(@dedup_table, [
        :named_table, :set, :public,
        read_concurrency: true, write_concurrency: true
      ])
    end

    if :ets.whereis(@stats_table) == :undefined do
      :ets.new(@stats_table, [
        :named_table, :set, :public,
        read_concurrency: true, write_concurrency: true
      ])
    end
  end

  defp init_stats do
    :ets.insert(@stats_table, {:total_checked, 0})
    :ets.insert(@stats_table, {:total_deduplicated, 0})
    :ets.insert(@stats_table, {:total_new, 0})
    :ets.insert(@stats_table, {:top_duplicated, []})
  end

  defp increment_stat(key) do
    try do
      :ets.update_counter(@stats_table, key, {2, 1})
    rescue
      ArgumentError ->
        :ets.insert(@stats_table, {key, 1})
    end
  end

  defp get_stat(key) do
    case :ets.lookup(@stats_table, key) do
      [{^key, value}] -> value
      [] -> 0
    end
  rescue
    _ -> 0
  end

  defp lookup_active_window(dedup_key) do
    now = System.system_time(:second)
    cutoff = now - window_seconds()

    case :ets.lookup(@dedup_table, dedup_key) do
      [{^dedup_key, window}] ->
        if window.last_at >= cutoff do
          {:ok, window}
        else
          # Window has expired -- remove it
          :ets.delete(@dedup_table, dedup_key)
          :not_found
        end

      [] ->
        :not_found
    end
  rescue
    _ -> :not_found
  end

  defp insert_window(dedup_key, window) do
    :ets.insert(@dedup_table, {dedup_key, window})
  rescue
    _ -> :ok
  end

  defp update_window(dedup_key, window) do
    :ets.insert(@dedup_table, {dedup_key, window})
  rescue
    _ -> :ok
  end

  defp has_window?(dedup_key) do
    case :ets.lookup(@dedup_table, dedup_key) do
      [{^dedup_key, _}] -> true
      [] -> false
    end
  rescue
    _ -> false
  end

  defp do_cleanup_expired do
    now = System.system_time(:second)
    cutoff = now - window_seconds()

    # Iterate all entries and delete expired ones
    all_entries = try do
      :ets.tab2list(@dedup_table)
    rescue
      _ -> []
    end

    deleted =
      Enum.reduce(all_entries, 0, fn {dedup_key, window}, acc ->
        if window.last_at < cutoff do
          :ets.delete(@dedup_table, dedup_key)
          acc + 1
        else
          acc
        end
      end)

    if deleted > 0 do
      increment_stat(:total_cleaned)
    end

    deleted
  end

  # ═══════════════════════════════════════════════════════════════════
  # Database Operations
  # ═══════════════════════════════════════════════════════════════════

  defp find_duplicate_in_db(dedup_key) do
    ws = window_seconds()
    cutoff = NaiveDateTime.utc_now() |> NaiveDateTime.add(-ws, :second)

    query = from(a in Alert,
      where: a.dedup_key == ^dedup_key,
      where: a.inserted_at >= ^cutoff,
      where: a.status not in ["resolved", "false_positive"],
      order_by: [desc: a.inserted_at],
      limit: 1
    )

    case Repo.one(query) do
      nil -> :not_found
      alert -> {:ok, alert}
    end
  rescue
    e ->
      Logger.warning("[Dedup] DB lookup failed: #{inspect(e)}")
      :not_found
  end

  defp update_existing_alert(alert_id, new_count) do
    now = DateTime.utc_now()

    from(a in Alert, where: a.id == ^alert_id)
    |> Repo.update_all(
      set: [occurrence_count: new_count, last_seen_at: now, updated_at: NaiveDateTime.utc_now()]
    )
  rescue
    e ->
      Logger.warning("[Dedup] Failed to update alert #{alert_id}: #{inspect(e)}")
  end

  # ═══════════════════════════════════════════════════════════════════
  # Hash Generation
  # ═══════════════════════════════════════════════════════════════════

  defp extract_hash_field(attrs, :rule_id) do
    extract_rule_id(attrs)
  end

  defp extract_hash_field(attrs, :agent_id) do
    to_string(attrs[:agent_id] || attrs["agent_id"] || "")
  end

  defp extract_hash_field(attrs, :primary_entity) do
    extract_primary_entity(attrs)
  end

  defp extract_hash_field(attrs, :process_name) do
    evidence = attrs[:evidence] || attrs["evidence"] || %{}
    process = evidence[:process] || evidence["process"] || %{}
    to_string(process[:name] || process["name"] || "")
  end

  defp extract_hash_field(attrs, :file_path) do
    evidence = attrs[:evidence] || attrs["evidence"] || %{}
    file = evidence[:file] || evidence["file"] || %{}
    process = evidence[:process] || evidence["process"] || %{}
    to_string(file[:path] || file["path"] || process[:path] || process["path"] || "")
  end

  defp extract_hash_field(attrs, :remote_ip) do
    raw_event = attrs[:raw_event] || attrs["raw_event"] || %{}
    to_string(raw_event[:remote_ip] || raw_event["remote_ip"] || "")
  end

  defp extract_hash_field(attrs, :query) do
    raw_event = attrs[:raw_event] || attrs["raw_event"] || %{}
    to_string(raw_event[:query] || raw_event["query"] || "")
  end

  defp extract_hash_field(attrs, :registry_path) do
    raw_event = attrs[:raw_event] || attrs["raw_event"] || %{}
    to_string(raw_event[:registry_path] || raw_event["registry_path"] || "")
  end

  defp extract_hash_field(_attrs, _field), do: ""

  defp extract_rule_id(attrs) do
    detection_meta = attrs[:detection_metadata] || attrs["detection_metadata"] || %{}

    rule_name = detection_meta[:rule_name] || detection_meta["rule_name"]
    rule_type = detection_meta[:rule_type] || detection_meta["rule_type"]

    cond do
      rule_name && rule_name != "" -> "#{rule_type}:#{rule_name}"
      true -> to_string(attrs[:title] || attrs["title"] || "unknown")
    end
  end

  defp extract_primary_entity(attrs) do
    evidence = attrs[:evidence] || attrs["evidence"] || %{}
    file = evidence[:file] || evidence["file"] || %{}
    process = evidence[:process] || evidence["process"] || %{}
    raw_event = attrs[:raw_event] || attrs["raw_event"] || %{}

    process_name = process[:name] || process["name"]
    process_path = process[:path] || process["path"]
    file_path = file[:path] || file["path"]
    remote_ip = raw_event[:remote_ip] || raw_event["remote_ip"]
    query = raw_event[:query] || raw_event["query"]

    cond do
      file_path && file_path != "" -> to_string(file_path)
      process_name && process_name != "" -> to_string(process_name)
      process_path && process_path != "" -> to_string(process_path)
      remote_ip && remote_ip != "" -> to_string(remote_ip)
      query && query != "" -> to_string(query)
      true -> ""
    end
  end

  defp extract_event_type(attrs) do
    detection_meta = attrs[:detection_metadata] || attrs["detection_metadata"] || %{}
    to_string(detection_meta[:event_type] || detection_meta["event_type"] || "")
  end

  defp event_type_prefix(event_type) when is_binary(event_type) do
    case String.split(event_type, "_", parts: 2) do
      [prefix | _] -> prefix
      _ -> event_type
    end
  end

  defp event_type_prefix(_), do: ""

  # ═══════════════════════════════════════════════════════════════════
  # Stats & Top Duplicated Tracking
  # ═══════════════════════════════════════════════════════════════════

  defp track_top_duplicated(dedup_key, window) do
    entry = %{
      dedup_key: dedup_key,
      alert_id: window.alert_id,
      title: window.title,
      severity: window.severity,
      count: window.count,
      last_at: window.last_at
    }

    current_top = case :ets.lookup(@stats_table, :top_duplicated) do
      [{:top_duplicated, list}] when is_list(list) -> list
      _ -> []
    end

    # Update or insert entry
    updated = current_top
    |> Enum.reject(fn e -> e.dedup_key == dedup_key end)
    |> List.insert_at(0, entry)
    |> Enum.sort_by(fn e -> -e.count end)
    |> Enum.take(@top_duplicated_limit)

    :ets.insert(@stats_table, {:top_duplicated, updated})
  rescue
    _ -> :ok
  end

  defp build_stats(state) do
    total_checked = get_stat(:total_checked)
    total_deduplicated = get_stat(:total_deduplicated)
    total_new = get_stat(:total_new)

    active_windows = try do
      :ets.info(@dedup_table, :size)
    rescue
      _ -> 0
    end

    top_duplicated = case :ets.lookup(@stats_table, :top_duplicated) do
      [{:top_duplicated, list}] when is_list(list) -> list
      _ -> []
    end

    dedup_rate = if total_checked > 0 do
      Float.round(total_deduplicated / total_checked * 100, 1)
    else
      0.0
    end

    uptime_seconds = System.system_time(:second) - Map.get(state, :started_at, System.system_time(:second))

    %{
      total_checked: total_checked,
      total_deduplicated: total_deduplicated,
      total_new: total_new,
      dedup_rate: dedup_rate,
      active_windows: active_windows,
      window_seconds: window_seconds(),
      top_duplicated: Enum.map(top_duplicated, fn entry ->
        %{
          dedup_key: entry.dedup_key,
          alert_id: entry.alert_id,
          title: entry.title,
          severity: entry.severity,
          occurrence_count: entry.count
        }
      end),
      uptime_seconds: uptime_seconds
    }
  end

  # ═══════════════════════════════════════════════════════════════════
  # PubSub
  # ═══════════════════════════════════════════════════════════════════

  defp subscribe_to_alerts do
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "alerts:feed")
  rescue
    _ -> :ok
  end

  defp broadcast_dedup_stats(stats) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "alerts:dedup_stats",
      {:dedup_stats_update, stats}
    )
  rescue
    _ -> :ok
  end

  # ═══════════════════════════════════════════════════════════════════
  # Scheduling
  # ═══════════════════════════════════════════════════════════════════

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup_expired, @cleanup_interval)
  end

  defp schedule_stats_broadcast do
    Process.send_after(self(), :broadcast_stats, @stats_broadcast_interval)
  end

  # ═══════════════════════════════════════════════════════════════════
  # Helpers
  # ═══════════════════════════════════════════════════════════════════

  defp default_stats do
    %{
      total_checked: 0,
      total_deduplicated: 0,
      total_new: 0,
      dedup_rate: 0.0,
      active_windows: 0,
      window_seconds: window_seconds(),
      top_duplicated: [],
      uptime_seconds: 0
    }
  end
end
