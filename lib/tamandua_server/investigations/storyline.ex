defmodule TamanduaServer.Investigations.Storyline do
  @moduledoc """
  Investigation Storyline Engine - attack narrative generation and management.

  Groups related alerts and events into coherent attack stories with causal
  chains, MITRE ATT&CK kill chain mapping, and automatic correlation.

  ## Architecture

  - ETS tables for active stories (fast reads, GenServer-serialized writes)
  - PubSub subscription to "alerts:feed" for auto-ingesting new alerts
  - Periodic cleanup of old/resolved stories
  - Causal graph delegation to `CausalGraph` module

  ## Story Lifecycle

      new alert -> auto_correlate -> find_matching_story? -> add_event / create_story
      story(open) -> investigating -> resolved | false_positive

  ## Auto-Grouping Criteria

  Alerts are grouped into the same story when they share:
  1. Same agent + time window (configurable, default 5 minutes)
  2. Same process tree (PID lineage via parent/child relationships)
  3. Sequential MITRE ATT&CK kill chain stages
  4. Shared IOCs (same IP, domain, or file hash)
  """

  use GenServer
  require Logger

  alias TamanduaServer.Investigations.CausalGraph

  # ETS table names
  @stories_table :investigation_stories
  @story_events_table :investigation_story_events
  @story_index_table :investigation_story_index

  # Auto-grouping time window in seconds (5 minutes)
  @default_time_window_seconds 300
  # Cleanup interval: every 10 minutes
  @cleanup_interval_ms 600_000
  # Resolved stories are retained for 24 hours before cleanup
  @resolved_retention_seconds 86_400
  # Maximum events per story before we stop auto-adding
  @max_events_per_story 500

  # MITRE ATT&CK kill chain stages in order
  @kill_chain_stages [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact"
  ]

  # Severity ordering for score calculations (used in story scoring)
  # Accessed via severity_weight/1 helper
  @severity_weights %{
    "critical" => 100,
    "high" => 75,
    "medium" => 50,
    "low" => 25,
    "info" => 10
  }

  @severity_order %{
    "critical" => 4,
    "high" => 3,
    "medium" => 2,
    "low" => 1,
    "info" => 0
  }

  # ====================================================================
  # Structs
  # ====================================================================

  defmodule Story do
    @moduledoc false
    defstruct [
      :id,
      :title,
      :description,
      :created_at,
      :updated_at,
      :resolved_at,
      :resolution,
      :resolution_notes,
      # Grouping keys
      :agent_id,
      :root_process_pid,
      :root_process_name,
      # State
      state: :open,
      severity: "low",
      score: 0.0,
      # Collections
      alert_ids: [],
      event_nodes: [],
      iocs: MapSet.new(),
      mitre_tactics: MapSet.new(),
      mitre_techniques: MapSet.new(),
      process_pids: MapSet.new(),
      agent_ids: MapSet.new(),
      # Metadata
      event_count: 0,
      alert_count: 0
    ]
  end

  defmodule StoryEvent do
    @moduledoc false
    defstruct [
      :id,
      :story_id,
      :timestamp,
      :event_type,
      :source_id,
      :agent_id,
      # Process context
      :pid,
      :ppid,
      :process_name,
      :process_path,
      :cmdline,
      # Network context
      :remote_ip,
      :remote_port,
      :domain,
      # File context
      :file_path,
      :file_hash,
      # MITRE mapping
      :mitre_tactic,
      :mitre_technique,
      # Severity / score
      :severity,
      :score,
      # Causal graph edge info
      :edge_type,
      :parent_event_id,
      # Raw data
      :raw_data
    ]
  end

  # ====================================================================
  # Client API
  # ====================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Create a new investigation story from an alert or list of events.

  Accepts either a single alert map or a list of event maps.
  Returns `{:ok, story_id}` on success.
  """
  @spec create_story(map() | [map()]) :: {:ok, String.t()} | {:error, term()}
  def create_story(alert_or_events) do
    GenServer.call(__MODULE__, {:create_story, alert_or_events})
  end

  @doc """
  Add an event or alert to an existing story.

  The event map should include at minimum `:timestamp` and either
  alert fields or telemetry event fields.
  """
  @spec add_event_to_story(String.t(), map()) :: :ok | {:error, term()}
  def add_event_to_story(story_id, event) do
    GenServer.call(__MODULE__, {:add_event, story_id, event})
  end

  @doc """
  Merge two stories into one.

  The second story is absorbed into the first. All events, alerts,
  IOCs, and MITRE mappings are combined. The second story is removed.
  """
  @spec merge_stories(String.t(), String.t()) :: {:ok, String.t()} | {:error, term()}
  def merge_stories(story_id_1, story_id_2) do
    GenServer.call(__MODULE__, {:merge, story_id_1, story_id_2})
  end

  @doc """
  Get a story by ID.

  Returns the full story struct serialized as a map.
  """
  @spec get_story(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_story(story_id) do
    case :ets.lookup(@stories_table, story_id) do
      [{^story_id, story}] -> {:ok, serialize_story(story)}
      [] -> {:error, :not_found}
    end
  rescue
    ArgumentError -> {:error, :not_found}
  end

  @doc """
  Get the chronological timeline of events in a story.

  Returns events sorted by timestamp ascending.
  """
  @spec get_story_timeline(String.t()) :: {:ok, [map()]} | {:error, :not_found}
  def get_story_timeline(story_id) do
    case :ets.lookup(@stories_table, story_id) do
      [{^story_id, _story}] ->
        events = get_story_events(story_id)
        timeline =
          events
          |> Enum.sort_by(& &1.timestamp, DateTime)
          |> Enum.map(&serialize_event/1)

        {:ok, timeline}

      [] ->
        {:error, :not_found}
    end
  rescue
    ArgumentError -> {:error, :not_found}
  end

  @doc """
  Get the causal graph for a story, suitable for visualization.

  Returns a map with `:nodes` and `:edges` for graph rendering.
  """
  @spec get_story_graph(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_story_graph(story_id) do
    case :ets.lookup(@stories_table, story_id) do
      [{^story_id, story}] ->
        events = get_story_events(story_id)
        graph = CausalGraph.build_graph(events, story)
        {:ok, graph}

      [] ->
        {:error, :not_found}
    end
  rescue
    ArgumentError -> {:error, :not_found}
  end

  @doc """
  Get all active (non-resolved) stories, with optional filters.

  ## Options
  - `:agent_id` - Filter by agent
  - `:min_severity` - Minimum severity level
  - `:state` - Filter by state (`:open`, `:investigating`, `:resolved`, `:false_positive`)
  - `:limit` - Maximum results (default 50)
  """
  @spec get_active_stories(keyword()) :: {:ok, [map()]}
  def get_active_stories(filters \\ []) do
    limit = Keyword.get(filters, :limit, 50)
    agent_id = Keyword.get(filters, :agent_id)
    min_severity = Keyword.get(filters, :min_severity)
    state_filter = Keyword.get(filters, :state)

    stories =
      :ets.tab2list(@stories_table)
      |> Enum.map(fn {_id, story} -> story end)
      |> maybe_filter_agent(agent_id)
      |> maybe_filter_state(state_filter)
      |> maybe_filter_min_severity(min_severity)
      |> Enum.sort_by(& &1.updated_at, {:desc, DateTime})
      |> Enum.take(limit)
      |> Enum.map(&serialize_story/1)

    {:ok, stories}
  rescue
    ArgumentError -> {:ok, []}
  end

  @doc """
  Resolve a story with a resolution verdict and optional notes.

  Valid resolutions: `:resolved`, `:false_positive`
  """
  @spec resolve_story(String.t(), map()) :: :ok | {:error, term()}
  def resolve_story(story_id, resolution) do
    GenServer.call(__MODULE__, {:resolve, story_id, resolution})
  end

  @doc """
  Find or create a story for a new alert (auto-correlation).

  Tries to match the alert to an existing story based on:
  1. Same agent + time window
  2. Same process tree (PID lineage)
  3. MITRE kill chain progression
  4. Shared IOCs

  If no match is found, creates a new story.
  Returns `{:ok, story_id}`.
  """
  @spec auto_correlate(map()) :: {:ok, String.t()}
  def auto_correlate(alert) do
    GenServer.call(__MODULE__, {:auto_correlate, alert})
  end

  @doc """
  Get MITRE ATT&CK kill chain coverage for a story.

  Returns a map showing which stages are covered and which techniques
  are observed at each stage.
  """
  @spec get_kill_chain_coverage(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_kill_chain_coverage(story_id) do
    case :ets.lookup(@stories_table, story_id) do
      [{^story_id, story}] ->
        events = get_story_events(story_id)
        coverage = build_kill_chain_coverage(story, events)
        {:ok, coverage}

      [] ->
        {:error, :not_found}
    end
  rescue
    ArgumentError -> {:error, :not_found}
  end

  @doc """
  Return summary statistics about the Investigation Storyline engine.
  """
  @spec stats() :: map()
  def stats do
    GenServer.call(__MODULE__, :stats)
  end

  # ====================================================================
  # Server Callbacks
  # ====================================================================

  @impl true
  def init(_opts) do
    # Create ETS tables
    :ets.new(@stories_table, [
      :set, :public, :named_table,
      read_concurrency: true
    ])

    :ets.new(@story_events_table, [
      :bag, :public, :named_table,
      read_concurrency: true
    ])

    :ets.new(@story_index_table, [
      :bag, :public, :named_table,
      read_concurrency: true
    ])

    # Subscribe to alert feed for auto-correlation
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "alerts:feed")

    # Schedule periodic cleanup
    Process.send_after(self(), :cleanup, @cleanup_interval_ms)

    Logger.info("[Investigations.Storyline] Investigation Storyline Engine started")

    {:ok, %{
      stats: %{
        stories_created: 0,
        stories_resolved: 0,
        stories_merged: 0,
        events_ingested: 0,
        auto_correlations: 0,
        last_cleanup: nil
      }
    }}
  end

  # ------------------------------------------------------------------
  # handle_call
  # ------------------------------------------------------------------

  @impl true
  def handle_call({:create_story, alert_or_events}, _from, state) do
    {result, state} = do_create_story(alert_or_events, state)
    {:reply, result, state}
  end

  def handle_call({:add_event, story_id, event}, _from, state) do
    {result, state} = do_add_event(story_id, event, state)
    {:reply, result, state}
  end

  def handle_call({:merge, id1, id2}, _from, state) do
    {result, state} = do_merge(id1, id2, state)
    {:reply, result, state}
  end

  def handle_call({:resolve, story_id, resolution}, _from, state) do
    {result, state} = do_resolve(story_id, resolution, state)
    {:reply, result, state}
  end

  def handle_call({:auto_correlate, alert}, _from, state) do
    {result, state} = do_auto_correlate(alert, state)
    {:reply, result, state}
  end

  def handle_call(:stats, _from, state) do
    total_stories = ets_size(@stories_table)
    total_events = ets_size(@story_events_table)

    active_count =
      :ets.tab2list(@stories_table)
      |> Enum.count(fn {_id, s} -> s.state in [:open, :investigating] end)

    reply = Map.merge(state.stats, %{
      total_stories: total_stories,
      active_stories: active_count,
      total_events: total_events
    })

    {:reply, reply, state}
  rescue
    _ -> {:reply, state.stats, state}
  end

  # ------------------------------------------------------------------
  # handle_info - PubSub & periodic
  # ------------------------------------------------------------------

  @impl true
  def handle_info(%{event: "new_alert", payload: alert_payload}, state) do
    # Auto-correlate new alerts from PubSub broadcast
    {_result, state} = do_auto_correlate(normalize_alert_payload(alert_payload), state)
    {:noreply, state}
  end

  def handle_info(:cleanup, state) do
    do_cleanup()
    Process.send_after(self(), :cleanup, @cleanup_interval_ms)
    state = put_in(state, [:stats, :last_cleanup], DateTime.utc_now())
    {:noreply, state}
  end

  # Catch-all for unhandled PubSub messages
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ====================================================================
  # Private: Story Creation
  # ====================================================================

  defp do_create_story(alert_or_events, state) when is_map(alert_or_events) do
    do_create_story([alert_or_events], state)
  end

  defp do_create_story(events, state) when is_list(events) do
    now = DateTime.utc_now()
    story_id = generate_id()

    # Extract metadata from all events
    agent_id = events |> Enum.find_value(fn e -> e[:agent_id] || e["agent_id"] end)
    alert_ids = events |> Enum.flat_map(fn e -> List.wrap(e[:id] || e["id"]) end) |> Enum.uniq()
    title = build_story_title(events)

    story = %Story{
      id: story_id,
      title: title,
      description: build_story_description(events),
      created_at: now,
      updated_at: now,
      agent_id: agent_id,
      agent_ids: MapSet.new(List.wrap(agent_id)),
      alert_ids: alert_ids,
      state: :open,
      event_count: 0,
      alert_count: length(alert_ids)
    }

    # Ingest each event into the story
    story = Enum.reduce(events, story, fn event, acc ->
      story_event = build_story_event(story_id, event)
      insert_story_event(story_event)
      update_story_from_event(acc, story_event, event)
    end)

    # Persist story
    :ets.insert(@stories_table, {story_id, story})

    # Build indexes
    index_story(story)

    state = update_in(state, [:stats, :stories_created], &(&1 + 1))
    state = update_in(state, [:stats, :events_ingested], &(&1 + length(events)))

    Logger.info("[Investigations.Storyline] Created story #{story_id} with #{length(events)} event(s)")

    {{:ok, story_id}, state}
  end

  # ====================================================================
  # Private: Add Event
  # ====================================================================

  defp do_add_event(story_id, event, state) do
    case :ets.lookup(@stories_table, story_id) do
      [{^story_id, story}] ->
        if story.event_count >= @max_events_per_story do
          {{:error, :story_full}, state}
        else
          story_event = build_story_event(story_id, event)
          insert_story_event(story_event)

          story = update_story_from_event(story, story_event, event)
          :ets.insert(@stories_table, {story_id, story})

          # Update indexes
          index_story(story)

          state = update_in(state, [:stats, :events_ingested], &(&1 + 1))
          {:ok, state}
        end

      [] ->
        {{:error, :not_found}, state}
    end
  rescue
    _ -> {{:error, :internal}, state}
  end

  # ====================================================================
  # Private: Merge
  # ====================================================================

  defp do_merge(id1, id2, state) when id1 == id2 do
    {{:error, :same_story}, state}
  end

  defp do_merge(id1, id2, state) do
    with [{^id1, story1}] <- :ets.lookup(@stories_table, id1),
         [{^id2, story2}] <- :ets.lookup(@stories_table, id2) do

      # Move all events from story2 to story1
      events2 = get_story_events(id2)
      Enum.each(events2, fn event ->
        moved = %{event | story_id: id1}
        :ets.delete_object(@story_events_table, {id2, event})
        insert_story_event(moved)
      end)

      # Merge story metadata
      merged = %Story{story1 |
        alert_ids: Enum.uniq(story1.alert_ids ++ story2.alert_ids),
        iocs: MapSet.union(story1.iocs, story2.iocs),
        mitre_tactics: MapSet.union(story1.mitre_tactics, story2.mitre_tactics),
        mitre_techniques: MapSet.union(story1.mitre_techniques, story2.mitre_techniques),
        process_pids: MapSet.union(story1.process_pids, story2.process_pids),
        agent_ids: MapSet.union(story1.agent_ids, story2.agent_ids),
        event_count: story1.event_count + story2.event_count,
        alert_count: story1.alert_count + story2.alert_count,
        score: max(story1.score, story2.score),
        severity: max_severity(story1.severity, story2.severity),
        updated_at: DateTime.utc_now()
      }

      # Persist merged story and remove old one
      :ets.insert(@stories_table, {id1, merged})
      :ets.delete(@stories_table, id2)

      # Update indexes
      remove_story_indexes(id2)
      index_story(merged)

      state = update_in(state, [:stats, :stories_merged], &(&1 + 1))

      Logger.info("[Investigations.Storyline] Merged story #{id2} into #{id1}")
      {{:ok, id1}, state}
    else
      [] -> {{:error, :not_found}, state}
    end
  rescue
    _ -> {{:error, :internal}, state}
  end

  # ====================================================================
  # Private: Resolve
  # ====================================================================

  defp do_resolve(story_id, resolution, state) do
    case :ets.lookup(@stories_table, story_id) do
      [{^story_id, story}] ->
        resolution_state = case resolution[:state] || resolution["state"] do
          "resolved" -> :resolved
          "false_positive" -> :false_positive
          state when is_atom(state) and state in [:resolved, :false_positive] -> state
          _ -> :resolved
        end

        notes = resolution[:notes] || resolution["notes"]

        updated = %Story{story |
          state: resolution_state,
          resolved_at: DateTime.utc_now(),
          resolution: to_string(resolution_state),
          resolution_notes: notes,
          updated_at: DateTime.utc_now()
        }

        :ets.insert(@stories_table, {story_id, updated})

        state = update_in(state, [:stats, :stories_resolved], &(&1 + 1))

        Logger.info("[Investigations.Storyline] Resolved story #{story_id} as #{resolution_state}")
        {:ok, state}

      [] ->
        {{:error, :not_found}, state}
    end
  rescue
    _ -> {{:error, :internal}, state}
  end

  # ====================================================================
  # Private: Auto-Correlation
  # ====================================================================

  defp do_auto_correlate(alert, state) do
    agent_id = alert[:agent_id] || alert["agent_id"]
    alert_time = extract_timestamp(alert)

    # Try to find a matching existing story
    matching_story_id = find_matching_story(alert, agent_id, alert_time)

    state = update_in(state, [:stats, :auto_correlations], &(&1 + 1))

    case matching_story_id do
      nil ->
        # No match found, create new story
        {result, state} = do_create_story(alert, state)
        {result, state}

      story_id ->
        # Add to existing story
        {_result, state} = do_add_event(story_id, alert, state)
        {{:ok, story_id}, state}
    end
  end

  defp find_matching_story(alert, agent_id, alert_time) do
    # Strategy 1: Same agent + time window
    match_by_agent_time(agent_id, alert_time)
    # Strategy 2: Same process tree (PID lineage)
    |> or_try(fn -> match_by_process_tree(alert) end)
    # Strategy 3: MITRE kill chain progression
    |> or_try(fn -> match_by_kill_chain(alert, agent_id) end)
    # Strategy 4: Shared IOCs
    |> or_try(fn -> match_by_shared_iocs(alert) end)
  end

  defp match_by_agent_time(nil, _time), do: nil
  defp match_by_agent_time(agent_id, alert_time) do
    window = @default_time_window_seconds
    cutoff = DateTime.add(alert_time, -window, :second)

    :ets.tab2list(@stories_table)
    |> Enum.filter(fn {_id, story} ->
      story.agent_id == agent_id and
      story.state in [:open, :investigating] and
      DateTime.compare(story.updated_at, cutoff) != :lt
    end)
    |> Enum.sort_by(fn {_id, story} -> story.updated_at end, {:desc, DateTime})
    |> case do
      [{id, _story} | _] -> id
      [] -> nil
    end
  rescue
    _ -> nil
  end

  defp match_by_process_tree(alert) do
    pid = alert[:pid] || alert["pid"] || get_in_nested(alert, [:evidence, :process, :pid])
    ppid = alert[:ppid] || alert["ppid"] || get_in_nested(alert, [:evidence, :process, :ppid])

    pids = [pid, ppid] |> Enum.reject(&is_nil/1) |> MapSet.new()

    if MapSet.size(pids) == 0 do
      nil
    else
      :ets.tab2list(@stories_table)
      |> Enum.filter(fn {_id, story} ->
        story.state in [:open, :investigating] and
        not MapSet.disjoint?(story.process_pids, pids)
      end)
      |> Enum.sort_by(fn {_id, story} -> story.updated_at end, {:desc, DateTime})
      |> case do
        [{id, _story} | _] -> id
        [] -> nil
      end
    end
  rescue
    _ -> nil
  end

  defp match_by_kill_chain(_alert, nil), do: nil
  defp match_by_kill_chain(alert, agent_id) do
    alert_tactics = extract_tactics(alert)

    if alert_tactics == [] do
      nil
    else
      alert_stages = Enum.map(alert_tactics, &tactic_to_stage_index/1)
                     |> Enum.reject(&is_nil/1)

      if alert_stages == [] do
        nil
      else
        :ets.tab2list(@stories_table)
        |> Enum.filter(fn {_id, story} ->
          story.agent_id == agent_id and
          story.state in [:open, :investigating] and
          MapSet.size(story.mitre_tactics) > 0
        end)
        |> Enum.filter(fn {_id, story} ->
          story_stages = story.mitre_tactics
                        |> MapSet.to_list()
                        |> Enum.map(&tactic_to_stage_index/1)
                        |> Enum.reject(&is_nil/1)

          # Check if the alert extends the kill chain (next stage or adjacent)
          Enum.any?(alert_stages, fn alert_stage ->
            Enum.any?(story_stages, fn story_stage ->
              abs(alert_stage - story_stage) <= 2
            end)
          end)
        end)
        |> Enum.sort_by(fn {_id, story} -> story.score end, :desc)
        |> case do
          [{id, _story} | _] -> id
          [] -> nil
        end
      end
    end
  rescue
    _ -> nil
  end

  defp match_by_shared_iocs(alert) do
    alert_iocs = extract_iocs_from_alert(alert)

    if MapSet.size(alert_iocs) == 0 do
      nil
    else
      :ets.tab2list(@stories_table)
      |> Enum.filter(fn {_id, story} ->
        story.state in [:open, :investigating] and
        not MapSet.disjoint?(story.iocs, alert_iocs)
      end)
      |> Enum.sort_by(fn {_id, story} -> MapSet.size(MapSet.intersection(story.iocs, alert_iocs)) end, :desc)
      |> case do
        [{id, _story} | _] -> id
        [] -> nil
      end
    end
  rescue
    _ -> nil
  end

  # ====================================================================
  # Private: Story Event Building
  # ====================================================================

  defp build_story_event(story_id, event) do
    evidence = event[:evidence] || event["evidence"] || %{}
    process = evidence[:process] || evidence["process"] || %{}
    raw_event = event[:raw_event] || event["raw_event"] || %{}
    tactics = extract_tactics(event)
    techniques = extract_techniques(event)

    %StoryEvent{
      id: generate_id(),
      story_id: story_id,
      timestamp: extract_timestamp(event),
      event_type: detect_event_type(event),
      source_id: event[:id] || event["id"],
      agent_id: event[:agent_id] || event["agent_id"],
      # Process context
      pid: process[:pid] || process["pid"] || event[:pid] || event["pid"],
      ppid: process[:ppid] || process["ppid"] || event[:ppid] || event["ppid"],
      process_name: process[:name] || process["name"] || event[:process_name] || event["process_name"],
      process_path: process[:path] || process["path"],
      cmdline: process[:cmdline] || process["cmdline"],
      # Network context
      remote_ip: raw_event[:remote_ip] || raw_event["remote_ip"],
      remote_port: raw_event[:remote_port] || raw_event["remote_port"],
      domain: raw_event[:query] || raw_event["query"] || raw_event[:domain] || raw_event["domain"],
      # File context
      file_path: raw_event[:file_path] || raw_event["file_path"],
      file_hash: process[:sha256] || process["sha256"] || raw_event[:sha256] || raw_event["sha256"],
      # MITRE
      mitre_tactic: List.first(tactics),
      mitre_technique: List.first(techniques),
      # Severity
      severity: event[:severity] || event["severity"] || "low",
      score: event[:threat_score] || event["threat_score"] || 0.0,
      # Causal
      edge_type: infer_edge_type(event),
      parent_event_id: nil,
      # Raw
      raw_data: event
    }
  end

  defp update_story_from_event(story, story_event, original_event) do
    now = DateTime.utc_now()
    alert_id = original_event[:id] || original_event["id"]
    tactics = extract_tactics(original_event)
    techniques = extract_techniques(original_event)
    iocs = extract_iocs_from_alert(original_event)

    pids = [story_event.pid, story_event.ppid]
           |> Enum.reject(&is_nil/1)

    event_severity = to_string(story_event.severity || "low")
    event_score = story_event.score || severity_weight(event_severity)

    %Story{story |
      updated_at: now,
      event_count: story.event_count + 1,
      alert_ids: if(alert_id, do: Enum.uniq([alert_id | story.alert_ids]), else: story.alert_ids),
      alert_count: if(alert_id, do: story.alert_count + 1, else: story.alert_count),
      mitre_tactics: Enum.reduce(tactics, story.mitre_tactics, &MapSet.put(&2, &1)),
      mitre_techniques: Enum.reduce(techniques, story.mitre_techniques, &MapSet.put(&2, &1)),
      iocs: MapSet.union(story.iocs, iocs),
      process_pids: Enum.reduce(pids, story.process_pids, &MapSet.put(&2, &1)),
      agent_ids: if(story_event.agent_id, do: MapSet.put(story.agent_ids, story_event.agent_id), else: story.agent_ids),
      score: max(story.score, event_score),
      severity: max_severity(story.severity, event_severity),
      agent_id: story.agent_id || story_event.agent_id,
      root_process_name: story.root_process_name || story_event.process_name,
      root_process_pid: story.root_process_pid || story_event.pid
    }
  end

  # ====================================================================
  # Private: Kill Chain Coverage
  # ====================================================================

  defp build_kill_chain_coverage(story, events) do
    # Build a map of stage -> techniques observed
    tactic_techniques =
      events
      |> Enum.reduce(%{}, fn event, acc ->
        tactic = event.mitre_tactic
        technique = event.mitre_technique

        if tactic do
          techniques = Map.get(acc, tactic, [])
          updated = if technique, do: Enum.uniq([technique | techniques]), else: techniques
          Map.put(acc, tactic, updated)
        else
          acc
        end
      end)

    # Build ordered coverage list
    stages = Enum.map(@kill_chain_stages, fn stage ->
      techniques = Map.get(tactic_techniques, stage, [])
      covered = techniques != [] or MapSet.member?(story.mitre_tactics, stage)

      %{
        stage: stage,
        covered: covered,
        techniques: techniques,
        display_name: stage_display_name(stage)
      }
    end)

    covered_count = Enum.count(stages, & &1.covered)

    %{
      stages: stages,
      total_stages: length(@kill_chain_stages),
      covered_stages: covered_count,
      coverage_percentage: Float.round(covered_count / length(@kill_chain_stages) * 100, 1),
      all_tactics: MapSet.to_list(story.mitre_tactics),
      all_techniques: MapSet.to_list(story.mitre_techniques)
    }
  end

  # ====================================================================
  # Private: Indexing
  # ====================================================================

  defp index_story(story) do
    # Index by agent_id for fast lookup
    if story.agent_id do
      :ets.insert(@story_index_table, {{:agent, story.agent_id}, story.id})
    end

    # Index by IOCs
    Enum.each(MapSet.to_list(story.iocs), fn ioc ->
      :ets.insert(@story_index_table, {{:ioc, ioc}, story.id})
    end)

    # Index by process PIDs
    Enum.each(MapSet.to_list(story.process_pids), fn pid ->
      :ets.insert(@story_index_table, {{:pid, story.agent_id, pid}, story.id})
    end)
  rescue
    _ -> :ok
  end

  defp remove_story_indexes(story_id) do
    # Remove all index entries pointing to this story
    :ets.tab2list(@story_index_table)
    |> Enum.each(fn {key, sid} ->
      if sid == story_id do
        :ets.delete_object(@story_index_table, {key, sid})
      end
    end)
  rescue
    _ -> :ok
  end

  # ====================================================================
  # Private: Cleanup
  # ====================================================================

  defp do_cleanup do
    now = DateTime.utc_now()
    cutoff = DateTime.add(now, -@resolved_retention_seconds, :second)

    # Remove old resolved stories
    removed =
      :ets.tab2list(@stories_table)
      |> Enum.filter(fn {_id, story} ->
        story.state in [:resolved, :false_positive] and
        story.resolved_at != nil and
        DateTime.compare(story.resolved_at, cutoff) == :lt
      end)
      |> Enum.map(fn {id, _story} ->
        # Remove events
        :ets.delete(@story_events_table, id)
        # Remove indexes
        remove_story_indexes(id)
        # Remove story
        :ets.delete(@stories_table, id)
        id
      end)

    if length(removed) > 0 do
      Logger.info("[Investigations.Storyline] Cleaned up #{length(removed)} old stories")
    end
  rescue
    _ -> :ok
  end

  # ====================================================================
  # Private: Helpers
  # ====================================================================

  defp get_story_events(story_id) do
    :ets.lookup(@story_events_table, story_id)
    |> Enum.map(fn {_id, event} -> event end)
  rescue
    _ -> []
  end

  defp insert_story_event(event) do
    :ets.insert(@story_events_table, {event.story_id, event})
  end

  defp generate_id do
    "story_" <> (:crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower))
  end

  defp extract_timestamp(event) do
    ts = event[:inserted_at] || event["inserted_at"] ||
         event[:timestamp] || event["timestamp"] ||
         event[:created_at] || event["created_at"]

    case ts do
      %DateTime{} -> ts
      %NaiveDateTime{} = ndt -> DateTime.from_naive!(ndt, "Etc/UTC")
      str when is_binary(str) ->
        case DateTime.from_iso8601(str) do
          {:ok, dt, _} -> dt
          _ -> DateTime.utc_now()
        end
      _ -> DateTime.utc_now()
    end
  end

  defp extract_tactics(event) do
    tactics = event[:mitre_tactics] || event["mitre_tactics"] || []
    if is_list(tactics), do: tactics, else: List.wrap(tactics)
  end

  defp extract_techniques(event) do
    techniques = event[:mitre_techniques] || event["mitre_techniques"] || []
    if is_list(techniques), do: techniques, else: List.wrap(techniques)
  end

  defp extract_iocs_from_alert(alert) do
    evidence = alert[:evidence] || alert["evidence"] || %{}
    raw_event = alert[:raw_event] || alert["raw_event"] || %{}
    process = evidence[:process] || evidence["process"] || %{}

    iocs = []

    # File hashes
    sha256 = process[:sha256] || process["sha256"]
    iocs = if sha256, do: [sha256 | iocs], else: iocs

    # IP addresses
    remote_ip = raw_event[:remote_ip] || raw_event["remote_ip"]
    iocs = if remote_ip, do: [remote_ip | iocs], else: iocs

    # Domains
    domain = raw_event[:query] || raw_event["query"] || raw_event[:domain] || raw_event["domain"]
    iocs = if domain, do: [domain | iocs], else: iocs

    MapSet.new(iocs)
  end

  defp detect_event_type(event) do
    title = to_string(event[:title] || event["title"] || "")
    event_type = event[:event_type] || event["event_type"]

    cond do
      event_type != nil -> to_string(event_type)
      String.contains?(String.downcase(title), "process") -> "process"
      String.contains?(String.downcase(title), "network") -> "network"
      String.contains?(String.downcase(title), "dns") -> "dns"
      String.contains?(String.downcase(title), "file") -> "file"
      String.contains?(String.downcase(title), "registry") -> "registry"
      String.contains?(String.downcase(title), "injection") -> "injection"
      true -> "alert"
    end
  end

  defp infer_edge_type(event) do
    event_type = detect_event_type(event)

    case event_type do
      "process" -> "spawned"
      "file" -> "wrote_file"
      "network" -> "connected_to"
      "dns" -> "connected_to"
      "registry" -> "modified_registry"
      "injection" -> "injected_into"
      _ -> "related_to"
    end
  end

  defp tactic_to_stage_index(tactic) do
    Enum.find_index(@kill_chain_stages, &(&1 == tactic))
  end

  defp severity_weight(severity) do
    Map.get(@severity_weights, to_string(severity), 10)
  end

  defp max_severity(sev1, sev2) do
    ord1 = Map.get(@severity_order, to_string(sev1), 0)
    ord2 = Map.get(@severity_order, to_string(sev2), 0)
    if ord1 >= ord2, do: to_string(sev1), else: to_string(sev2)
  end

  defp stage_display_name(stage) do
    stage
    |> String.replace("-", " ")
    |> String.split(" ")
    |> Enum.map(&String.capitalize/1)
    |> Enum.join(" ")
  end

  defp build_story_title(events) do
    first = List.first(events) || %{}
    title = first[:title] || first["title"]
    process_name = get_in_nested(first, [:evidence, :process, :name])
    agent_id = first[:agent_id] || first["agent_id"]

    cond do
      title -> "Investigation: #{title}"
      process_name && agent_id -> "Investigation: #{process_name} on #{agent_id}"
      process_name -> "Investigation: #{process_name}"
      agent_id -> "Investigation on #{agent_id}"
      true -> "Investigation #{DateTime.utc_now() |> DateTime.to_iso8601()}"
    end
  end

  defp build_story_description(events) do
    count = length(events)
    tactics = events
              |> Enum.flat_map(&extract_tactics/1)
              |> Enum.uniq()

    if tactics != [] do
      "Auto-generated story from #{count} event(s). MITRE tactics: #{Enum.join(tactics, ", ")}"
    else
      "Auto-generated story from #{count} event(s)."
    end
  end

  defp normalize_alert_payload(payload) when is_map(payload) do
    # Ensure we have atom or string keys the extractor functions can handle
    payload
  end

  defp get_in_nested(map, keys) when is_map(map) and is_list(keys) do
    Enum.reduce_while(keys, map, fn key, acc ->
      val = acc[key] || acc[to_string(key)]
      if is_map(val), do: {:cont, val}, else: {:halt, val}
    end)
  rescue
    _ -> nil
  end
  defp get_in_nested(_, _), do: nil

  defp or_try(nil, fun), do: fun.()
  defp or_try(result, _fun), do: result

  defp ets_size(table) do
    :ets.info(table, :size) || 0
  rescue
    _ -> 0
  end

  # ====================================================================
  # Private: Filters
  # ====================================================================

  defp maybe_filter_agent(stories, nil), do: stories
  defp maybe_filter_agent(stories, agent_id) do
    Enum.filter(stories, &(&1.agent_id == agent_id))
  end

  defp maybe_filter_state(stories, nil), do: stories
  defp maybe_filter_state(stories, state) when is_atom(state) do
    Enum.filter(stories, &(&1.state == state))
  end
  defp maybe_filter_state(stories, state) when is_binary(state) do
    atom_state = safe_to_atom(state)
    if atom_state, do: Enum.filter(stories, &(&1.state == atom_state)), else: stories
  end

  defp maybe_filter_min_severity(stories, nil), do: stories
  defp maybe_filter_min_severity(stories, min_sev) do
    min_ord = Map.get(@severity_order, to_string(min_sev), 0)
    Enum.filter(stories, fn s ->
      Map.get(@severity_order, to_string(s.severity), 0) >= min_ord
    end)
  end

  defp safe_to_atom(str) when str in ~w(open investigating resolved false_positive) do
    String.to_existing_atom(str)
  rescue
    ArgumentError -> nil
  end
  defp safe_to_atom(_), do: nil

  # ====================================================================
  # Private: Serialization
  # ====================================================================

  defp serialize_story(%Story{} = story) do
    %{
      id: story.id,
      title: story.title,
      description: story.description,
      state: to_string(story.state),
      severity: story.severity,
      score: story.score,
      agent_id: story.agent_id,
      agent_ids: MapSet.to_list(story.agent_ids),
      root_process_pid: story.root_process_pid,
      root_process_name: story.root_process_name,
      alert_ids: story.alert_ids,
      alert_count: story.alert_count,
      event_count: story.event_count,
      iocs: MapSet.to_list(story.iocs),
      mitre_tactics: MapSet.to_list(story.mitre_tactics),
      mitre_techniques: MapSet.to_list(story.mitre_techniques),
      process_pids: MapSet.to_list(story.process_pids),
      resolution: story.resolution,
      resolution_notes: story.resolution_notes,
      created_at: story.created_at && DateTime.to_iso8601(story.created_at),
      updated_at: story.updated_at && DateTime.to_iso8601(story.updated_at),
      resolved_at: story.resolved_at && DateTime.to_iso8601(story.resolved_at)
    }
  end

  defp serialize_event(%StoryEvent{} = event) do
    %{
      id: event.id,
      story_id: event.story_id,
      timestamp: event.timestamp && DateTime.to_iso8601(event.timestamp),
      event_type: event.event_type,
      source_id: event.source_id,
      agent_id: event.agent_id,
      pid: event.pid,
      ppid: event.ppid,
      process_name: event.process_name,
      process_path: event.process_path,
      cmdline: event.cmdline,
      remote_ip: event.remote_ip,
      remote_port: event.remote_port,
      domain: event.domain,
      file_path: event.file_path,
      file_hash: event.file_hash,
      mitre_tactic: event.mitre_tactic,
      mitre_technique: event.mitre_technique,
      severity: event.severity,
      score: event.score,
      edge_type: event.edge_type,
      parent_event_id: event.parent_event_id
    }
  end
end
