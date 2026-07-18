defmodule TamanduaServer.Detection.TemporalScorer do
  @moduledoc """
  Temporal proximity scoring for the correlation engine.

  Adds time-based analysis to complement the spatial (PID/user) correlation
  already present in the Correlator. Tracks event timing patterns to detect:

  - **Time-window clustering**: Groups events by proximity (very_tight/tight/loose)
  - **Behavioral units**: Events from the same process within 1 second = single unit
  - **Time decay scoring**: Recent events weighted higher than older ones
  - **Event coalescence**: Merges identical rapid events into weighted singles
  - **Temporal anomalies**: Off-hours activity, abnormal timing, rapid succession
  - **Sequence entropy**: Distinguishes beacons (low entropy) from user activity (high)

  Uses ETS for all hot-path operations. Events older than 1 hour are
  periodically purged.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Detection.{Config, EventTypes}

  @table_name :temporal_events

  # ---------------------------------------------------------------------------
  # Time-window clustering thresholds (seconds)
  # ---------------------------------------------------------------------------
  @very_tight_seconds 5
  @tight_seconds 60
  @loose_seconds 300

  # Behavioral unit: events from same process within this many ms = one unit

  # Time decay reference points (seconds ago -> weight)
  @decay_points [
    {0, 1.0},
    {60, 0.8},
    {300, 0.5},
    {3600, 0.1}
  ]

  # Business hours (UTC). Configurable via application env.
  @default_business_start 8
  @default_business_end 18

  # Rapid succession thresholds
  @rapid_file_ops_per_second 1_000
  @rapid_network_per_second 500
  @rapid_process_per_second 100

  # Cleanup: purge events older than 1 hour
  @event_ttl_ms :timer.hours(1)
  @cleanup_interval_ms :timer.minutes(5)

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Return a temporal proximity score (0.0 - 1.0) for `event` relative to
  recent events from the same agent.

  The score combines:
  - Time-window cluster density
  - Time-decay weighting of nearby events
  - Burst penalty when rapid succession is detected
  """
  @spec score_event(map(), String.t(), keyword()) :: float()
  def score_event(event, agent_id, opts \\ []) do
    # Hot path: read directly from ETS to avoid GenServer bottleneck
    now_ms = event_timestamp_ms(event)
    window_ms = Keyword.get(opts, :window_ms, :timer.seconds(@loose_seconds))

    recent = lookup_recent(agent_id, now_ms, window_ms)

    # Store the incoming event (fire-and-forget)
    GenServer.cast(__MODULE__, {:record_event, agent_id, event})

    compute_proximity_score(event, recent, now_ms)
  end

  @doc """
  Return all events that belong to the same temporal cluster as the
  reference event.

  Cluster proximity defaults to `:tight` (60 s).
  """
  @spec get_temporal_cluster(map(), String.t(), keyword()) :: [map()]
  def get_temporal_cluster(event, agent_id, opts \\ []) do
    proximity = Keyword.get(opts, :proximity, :tight)
    window_ms = proximity_to_ms(proximity)
    now_ms = event_timestamp_ms(event)

    lookup_recent(agent_id, now_ms, window_ms)
    |> Enum.map(fn {_key, entry} -> entry.event end)
  end

  @doc """
  Detect temporal anomalies for the given agent and return a list of
  anomaly maps (may be empty).

  Checks:
  - Off-hours activity
  - Rapid succession (ransomware / wiper indicator)
  - Low-entropy intervals (beacon detection)
  """
  @spec detect_temporal_anomalies(String.t(), keyword()) :: [map()]
  def detect_temporal_anomalies(agent_id, opts \\ []) do
    window_ms = Keyword.get(opts, :window_ms, :timer.minutes(10))
    now_ms = System.system_time(:millisecond)

    recent = lookup_recent(agent_id, now_ms, window_ms)
    entries = Enum.map(recent, fn {_k, e} -> e end)

    anomalies = []
    anomalies = anomalies ++ detect_off_hours(entries)
    anomalies = anomalies ++ detect_rapid_succession(entries, now_ms)
    anomalies = anomalies ++ detect_low_entropy_intervals(entries)
    anomalies
  end

  @doc """
  Score how "bursty" recent activity is for a given agent and event type.

  Returns a float 0.0 (no burst) to 1.0 (extreme burst).
  """
  @spec get_burst_score(String.t(), atom(), keyword()) :: float()
  def get_burst_score(agent_id, event_type, opts \\ []) do
    window_ms = Keyword.get(opts, :window_ms, :timer.seconds(10))
    now_ms = System.system_time(:millisecond)

    recent = lookup_recent(agent_id, now_ms, window_ms)

    matching =
      recent
      |> Enum.filter(fn {_k, entry} ->
        EventTypes.normalize(entry.event_type) == event_type
      end)

    count = length(matching)
    window_seconds = max(window_ms / 1_000, 1)
    rate = count / window_seconds

    threshold = burst_threshold_for(event_type)

    cond do
      rate >= threshold * 2 -> 1.0
      rate >= threshold -> 0.5 + 0.5 * ((rate - threshold) / threshold)
      rate >= threshold * 0.5 -> rate / threshold * 0.5
      true -> 0.0
    end
    |> min(1.0)
  end

  @doc """
  Coalesce identical events within `window_ms` into single weighted entries.

  Returns a list of `%{event: map(), count: integer(), weight: float()}`.
  """
  @spec coalesce_events(String.t(), keyword()) :: [map()]
  def coalesce_events(agent_id, opts \\ []) do
    window_ms = Keyword.get(opts, :window_ms, :timer.seconds(10))
    now_ms = System.system_time(:millisecond)

    recent = lookup_recent(agent_id, now_ms, window_ms)

    recent
    |> Enum.map(fn {_k, entry} -> entry end)
    |> Enum.group_by(&coalescence_key/1)
    |> Enum.map(fn {_key, entries} ->
      representative = List.first(entries)
      count = length(entries)
      weight = 1.0 + :math.log2(max(count, 1))

      %{
        event: representative.event,
        event_type: representative.event_type,
        count: count,
        weight: Float.round(weight, 3),
        first_ts: entries |> Enum.map(& &1.timestamp_ms) |> Enum.min(),
        last_ts: entries |> Enum.map(& &1.timestamp_ms) |> Enum.max()
      }
    end)
    |> Enum.sort_by(& &1.last_ts, :desc)
  end

  @doc """
  Classify the temporal proximity between two timestamps.

  Returns one of `:very_tight`, `:tight`, `:loose`, or `:unrelated`.
  """
  @spec classify_proximity(integer(), integer()) :: atom()
  def classify_proximity(ts1_ms, ts2_ms) do
    diff_seconds = abs(ts1_ms - ts2_ms) / 1_000

    cond do
      diff_seconds < @very_tight_seconds -> :very_tight
      diff_seconds < @tight_seconds -> :tight
      diff_seconds < @loose_seconds -> :loose
      true -> :unrelated
    end
  end

  @doc """
  Compute the time-decay weight for an event that occurred `age_ms`
  milliseconds ago.
  """
  @spec time_decay_weight(non_neg_integer()) :: float()
  def time_decay_weight(age_ms) do
    age_s = age_ms / 1_000
    interpolate_decay(age_s)
  end

  # ---------------------------------------------------------------------------
  # GenServer callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(_opts) do
    :ets.new(@table_name, [:named_table, :ordered_set, :public, read_concurrency: true])

    schedule_cleanup()

    Logger.info("Temporal Scorer started")
    {:ok, %{events_recorded: 0}}
  end

  @impl true
  def handle_cast({:record_event, agent_id, event}, state) do
    store_event(agent_id, event)
    {:noreply, %{state | events_recorded: state.events_recorded + 1}}
  end

  @impl true
  def handle_info(:cleanup, state) do
    purge_expired()
    schedule_cleanup()
    {:noreply, state}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ---------------------------------------------------------------------------
  # ETS storage
  # ---------------------------------------------------------------------------

  # Key: {agent_id, timestamp_ms, unique_ref}  (ordered_set gives time ordering)
  defp store_event(agent_id, event) do
    ts_ms = event_timestamp_ms(event)
    payload = event[:payload] || event["payload"] || %{}
    pid = payload[:pid] || payload["pid"]
    event_type = event[:event_type] || event["event_type"]
    event_id = event[:event_id] || event["event_id"] || make_ref()

    entry = %{
      agent_id: agent_id,
      event_id: event_id,
      event_type: event_type,
      timestamp_ms: ts_ms,
      pid: pid,
      event: event
    }

    key = {agent_id, ts_ms, event_id}
    :ets.insert(@table_name, {key, entry})
  end

  # Look up recent events for an agent within a time window.
  # Uses the ordered_set key range for efficient scanning.
  defp lookup_recent(agent_id, reference_ms, window_ms) do
    lower = reference_ms - window_ms
    upper = reference_ms + window_ms

    # We need to scan the range {agent_id, lower, _} .. {agent_id, upper, _}
    # ETS ordered_set with tuple keys sorts lexicographically by element.
    match_spec = [
      {
        {{:"$1", :"$2", :_}, :"$3"},
        [
          {:andalso,
           {:andalso, {:==, :"$1", agent_id}, {:>=, :"$2", lower}},
           {:"=<", :"$2", upper}}
        ],
        [{{:"$2", :"$3"}}]
      }
    ]

    :ets.select(@table_name, match_spec)
  rescue
    ArgumentError -> []
  end

  defp purge_expired do
    threshold = System.system_time(:millisecond) - @event_ttl_ms

    match_spec = [
      {
        {{:_, :"$1", :_}, :_},
        [{:<, :"$1", threshold}],
        [true]
      }
    ]

    deleted = :ets.select_delete(@table_name, match_spec)
    if deleted > 0 do
      Logger.debug("Temporal Scorer cleanup: purged #{deleted} expired events")
    end
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval_ms)
  end

  # ---------------------------------------------------------------------------
  # Scoring internals
  # ---------------------------------------------------------------------------

  defp compute_proximity_score(_event, recent, now_ms) do
    if recent == [] do
      0.0
    else
      # 1. Density component: how many events are in the very-tight window?
      very_tight_count =
        Enum.count(recent, fn {ts, _entry} ->
          abs(now_ms - ts) < @very_tight_seconds * 1_000
        end)

      tight_count =
        Enum.count(recent, fn {ts, _entry} ->
          abs(now_ms - ts) < @tight_seconds * 1_000
        end)

      total = length(recent)

      density =
        cond do
          very_tight_count >= 10 -> 1.0
          very_tight_count >= 5 -> 0.85
          tight_count >= 10 -> 0.7
          tight_count >= 5 -> 0.55
          total >= 5 -> 0.4
          total >= 2 -> 0.25
          true -> 0.1
        end

      # 2. Decay-weighted component: average weight of nearby events
      decay_sum =
        Enum.reduce(recent, 0.0, fn {ts, _entry}, acc ->
          age_ms = abs(now_ms - ts)
          acc + time_decay_weight(age_ms)
        end)

      avg_decay = if total > 0, do: decay_sum / total, else: 0.0

      # 3. Combine: 60% density, 40% decay
      score = density * 0.6 + avg_decay * 0.4
      Float.round(min(score, 1.0), 4)
    end
  end

  # Piecewise linear interpolation across @decay_points
  defp interpolate_decay(age_s) when age_s <= 0, do: 1.0

  defp interpolate_decay(age_s) do
    points = @decay_points

    case find_bracket(points, age_s) do
      {nil, _} ->
        # Before first point (shouldn't happen since we handle <= 0 above)
        1.0

      {_, nil} ->
        # Beyond last point
        {_last_s, last_w} = List.last(points)
        max(last_w, 0.0)

      {{s1, w1}, {s2, w2}} ->
        # Linear interpolation
        t = (age_s - s1) / max(s2 - s1, 1)
        w1 + (w2 - w1) * t
    end
  end

  defp find_bracket(points, age_s) do
    pairs = Enum.chunk_every(points, 2, 1, :discard)

    result =
      Enum.find(pairs, fn [{s1, _}, {s2, _}] ->
        age_s >= s1 and age_s <= s2
      end)

    case result do
      [{s1, w1}, {s2, w2}] -> {{s1, w1}, {s2, w2}}
      nil ->
        {_last_s, _last_w} = List.last(points)
        if age_s > elem(List.last(points), 0) do
          {List.last(points), nil}
        else
          {nil, List.first(points)}
        end
    end
  end

  # ---------------------------------------------------------------------------
  # Temporal anomaly detectors
  # ---------------------------------------------------------------------------

  defp detect_off_hours(entries) do
    business_start = Config.get(:business_hours_start, @default_business_start)
    business_end = Config.get(:business_hours_end, @default_business_end)

    # Only consider security-relevant event types, not routine telemetry
    security_types = MapSet.new([
      :process_create, :file_create, :file_modify, :registry_set,
      :network_connect, :module_load, :script_execute
    ])

    off_hours_events =
      Enum.filter(entries, fn entry ->
        event_type = entry[:event_type]
        is_security = is_nil(event_type) or MapSet.member?(security_types, event_type)

        is_security and
          case DateTime.from_unix(entry.timestamp_ms, :millisecond) do
            {:ok, dt} ->
              hour = dt.hour
              hour < business_start or hour >= business_end

            _ ->
              false
          end
      end)

    # High threshold: normal systems generate many events off-hours.
    # Only flag when there's an unusual volume of security-relevant events.
    if length(off_hours_events) >= 500 do
      [%{
        type: :off_hours_activity,
        description: "#{length(off_hours_events)} security events outside business hours (#{business_start}:00-#{business_end}:00 UTC)",
        count: length(off_hours_events),
        severity: :low,
        mitre_tactics: ["defense_evasion"],
        mitre_techniques: ["T1036"]
      }]
    else
      []
    end
  end

  defp detect_rapid_succession(entries, now_ms) do
    # Only look at the last 5 seconds
    recent =
      Enum.filter(entries, fn e ->
        now_ms - e.timestamp_ms < 5_000
      end)

    by_category =
      recent
      |> Enum.group_by(fn e ->
        EventTypes.category(EventTypes.normalize(e.event_type))
      end)

    anomalies = []

    anomalies =
      anomalies ++
        check_category_burst(by_category, :file, @rapid_file_ops_per_second,
          "Rapid file operations",
          "ransomware indicator",
          ["impact"],
          ["T1486"]
        )

    anomalies =
      anomalies ++
        check_category_burst(by_category, :network, @rapid_network_per_second,
          "Rapid network connections",
          "data exfiltration or scanning indicator",
          ["exfiltration", "discovery"],
          ["T1041", "T1046"]
        )

    anomalies =
      anomalies ++
        check_category_burst(by_category, :process, @rapid_process_per_second,
          "Rapid process creation",
          "fork bomb or automated exploitation indicator",
          ["execution"],
          ["T1059"]
        )

    anomalies
  end

  defp check_category_burst(by_category, category, threshold, title, detail, tactics, techniques) do
    events = Map.get(by_category, category, [])
    count = length(events)
    # 5-second window -> per-second rate
    rate = count / 5

    if rate >= threshold do
      [%{
        type: :rapid_succession,
        description: "#{title} detected: #{count} events in 5 seconds (#{Float.round(rate, 1)}/s) - #{detail}",
        count: count,
        rate_per_second: Float.round(rate, 1),
        category: category,
        severity: :high,
        mitre_tactics: tactics,
        mitre_techniques: techniques
      }]
    else
      []
    end
  end

  defp detect_low_entropy_intervals(entries) when length(entries) < 10, do: []

  defp detect_low_entropy_intervals(entries) do
    # Compute inter-event intervals
    timestamps =
      entries
      |> Enum.map(& &1.timestamp_ms)
      |> Enum.sort()

    intervals =
      timestamps
      |> Enum.chunk_every(2, 1, :discard)
      |> Enum.map(fn [a, b] -> b - a end)
      |> Enum.filter(&(&1 > 0))

    if length(intervals) < 5 do
      []
    else
      entropy = interval_entropy(intervals)

      if entropy < 1.5 do
        mean_interval = Enum.sum(intervals) / length(intervals)

        [%{
          type: :beacon_pattern,
          description: "Low-entropy timing pattern detected (entropy #{Float.round(entropy, 2)}). Mean interval #{Float.round(mean_interval / 1_000, 1)}s across #{length(intervals)} events - possible beaconing / C2 callback",
          entropy: Float.round(entropy, 4),
          mean_interval_ms: Float.round(mean_interval, 1),
          sample_count: length(intervals),
          severity: :high,
          mitre_tactics: ["command_and_control"],
          mitre_techniques: ["T1071", "T1573"]
        }]
      else
        []
      end
    end
  end

  # Shannon entropy over binned intervals.
  # We bucket intervals into 500 ms bins and compute entropy over the
  # resulting probability distribution.
  defp interval_entropy(intervals) do
    bin_size = 500

    bins =
      intervals
      |> Enum.map(&div(&1, bin_size))
      |> Enum.frequencies()

    total = Enum.sum(Map.values(bins))

    bins
    |> Map.values()
    |> Enum.reduce(0.0, fn count, acc ->
      p = count / total
      if p > 0, do: acc - p * :math.log2(p), else: acc
    end)
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp event_timestamp_ms(event) do
    raw = event[:timestamp] || event["timestamp"]

    case raw do
      nil ->
        System.system_time(:millisecond)

      ms when is_integer(ms) and ms > 1_000_000_000_000 ->
        ms

      s when is_integer(s) ->
        s * 1_000

      %DateTime{} = dt ->
        DateTime.to_unix(dt, :millisecond)

      %NaiveDateTime{} = ndt ->
        ndt |> DateTime.from_naive!("Etc/UTC") |> DateTime.to_unix(:millisecond)

      _ ->
        System.system_time(:millisecond)
    end
  end

  defp proximity_to_ms(:very_tight), do: @very_tight_seconds * 1_000
  defp proximity_to_ms(:tight), do: @tight_seconds * 1_000
  defp proximity_to_ms(:loose), do: @loose_seconds * 1_000
  defp proximity_to_ms(_), do: @loose_seconds * 1_000

  defp coalescence_key(entry) do
    # Two events are "identical" if they share event_type + pid
    {entry.event_type, entry.pid}
  end

  defp burst_threshold_for(event_type) do
    category = EventTypes.category(event_type)

    case category do
      :file -> @rapid_file_ops_per_second / 5
      :network -> @rapid_network_per_second / 5
      :process -> @rapid_process_per_second / 5
      _ -> 50
    end
  end
end
