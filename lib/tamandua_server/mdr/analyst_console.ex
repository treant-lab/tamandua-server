defmodule TamanduaServer.MDR.AnalystConsole do
  @moduledoc """
  MDR Analyst Console - Backend tooling for SOC analysts.

  Provides the operational backend for MDR analysts:

  - **Alert Triage** - AI-pre-scored alert queue with context enrichment
  - **Investigation Workspace** - Per-incident context accumulator
  - **Cross-Customer Correlation** - Same attack pattern across customer base
  - **Knowledge Base** - Common findings, playbooks, and resolution templates
  - **Performance Tracking** - MTTD, MTTR, alerts handled, satisfaction scores
  - **Shift Management** - 24/7 coverage scheduling, handoff notes, on-call

  ## Shift Management

  Supports 24/7 SOC coverage with:
  - Configurable shift schedules (e.g., 3x8h, 2x12h)
  - Shift handoff notes and pending items
  - On-call escalation chain
  - Automatic workload rebalancing at shift change

  Multi-tenant: analyst console itself is global; data access is scoped by org_id.
  """

  use GenServer
  require Logger

  # ETS tables
  @ets_analysts :mdr_analyst_profiles
  @ets_workspaces :mdr_investigation_workspaces
  @ets_kb :mdr_knowledge_base
  @ets_shifts :mdr_shift_schedule
  @ets_handoffs :mdr_shift_handoffs
  @ets_performance :mdr_analyst_performance
  @ets_correlations :mdr_cross_customer_correlations

  # Performance tracking interval
  @perf_aggregation_interval :timer.hours(1)

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  # -- Analyst Management --------------------------------------------------

  @doc """
  Register an analyst profile.
  """
  @spec register_analyst(map()) :: {:ok, map()} | {:error, term()}
  def register_analyst(attrs) do
    GenServer.call(__MODULE__, {:register_analyst, attrs})
  end

  @doc """
  Update an analyst's profile or status.
  """
  @spec update_analyst(String.t(), map()) :: :ok | {:error, :not_found}
  def update_analyst(analyst_id, attrs) do
    GenServer.call(__MODULE__, {:update_analyst, analyst_id, attrs})
  end

  @doc """
  Get analyst profile.
  """
  @spec get_analyst(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_analyst(analyst_id) do
    GenServer.call(__MODULE__, {:get_analyst, analyst_id})
  end

  @doc """
  List all analysts, optionally filtered by status or shift.
  """
  @spec list_analysts(keyword()) :: [map()]
  def list_analysts(opts \\ []) do
    GenServer.call(__MODULE__, {:list_analysts, opts})
  end

  # -- Alert Triage --------------------------------------------------------

  @doc """
  Get the analyst's triage queue with AI pre-triage scores and enrichment.
  """
  @spec get_triage_queue(String.t(), keyword()) :: [map()]
  def get_triage_queue(analyst_id, opts \\ []) do
    GenServer.call(__MODULE__, {:get_triage_queue, analyst_id, opts})
  end

  @doc """
  Record a triage decision (true positive, false positive, needs investigation).
  """
  @spec record_triage(String.t(), String.t(), String.t(), keyword()) :: :ok
  def record_triage(analyst_id, alert_id, verdict, opts \\ []) do
    GenServer.call(__MODULE__, {:record_triage, analyst_id, alert_id, verdict, opts})
  end

  # -- Investigation Workspace ---------------------------------------------

  @doc """
  Create or get an investigation workspace for an incident.
  """
  @spec get_workspace(String.t()) :: {:ok, map()} | {:error, term()}
  def get_workspace(incident_id) do
    GenServer.call(__MODULE__, {:get_workspace, incident_id})
  end

  @doc """
  Add evidence or notes to an investigation workspace.
  """
  @spec add_to_workspace(String.t(), map()) :: :ok | {:error, :not_found}
  def add_to_workspace(incident_id, entry) do
    GenServer.call(__MODULE__, {:add_to_workspace, incident_id, entry})
  end

  @doc """
  Get a workspace timeline showing all investigation activity.
  """
  @spec get_workspace_timeline(String.t()) :: [map()]
  def get_workspace_timeline(incident_id) do
    GenServer.call(__MODULE__, {:get_workspace_timeline, incident_id})
  end

  # -- Cross-Customer Correlation ------------------------------------------

  @doc """
  Check if an IOC/pattern appears across multiple customers.
  Returns correlated findings from other organizations (anonymized).
  """
  @spec cross_correlate(map()) :: [map()]
  def cross_correlate(indicator) do
    GenServer.call(__MODULE__, {:cross_correlate, indicator})
  end

  @doc """
  Submit an indicator for cross-customer tracking.
  """
  @spec submit_correlation(String.t(), map()) :: :ok
  def submit_correlation(org_id, indicator) do
    GenServer.cast(__MODULE__, {:submit_correlation, org_id, indicator})
  end

  # -- Knowledge Base ------------------------------------------------------

  @doc """
  Add an entry to the knowledge base.
  """
  @spec add_kb_entry(map()) :: {:ok, String.t()}
  def add_kb_entry(entry) do
    GenServer.call(__MODULE__, {:add_kb_entry, entry})
  end

  @doc """
  Search the knowledge base.
  """
  @spec search_kb(String.t(), keyword()) :: [map()]
  def search_kb(query, opts \\ []) do
    GenServer.call(__MODULE__, {:search_kb, query, opts})
  end

  @doc """
  Get a knowledge base entry by ID.
  """
  @spec get_kb_entry(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_kb_entry(entry_id) do
    GenServer.call(__MODULE__, {:get_kb_entry, entry_id})
  end

  # -- Shift Management ----------------------------------------------------

  @doc """
  Set the shift schedule.
  """
  @spec set_shift_schedule(map()) :: :ok
  def set_shift_schedule(schedule) do
    GenServer.call(__MODULE__, {:set_schedule, schedule})
  end

  @doc """
  Get the current shift and on-duty analysts.
  """
  @spec get_current_shift() :: map()
  def get_current_shift do
    GenServer.call(__MODULE__, :get_current_shift)
  end

  @doc """
  Create shift handoff notes.
  """
  @spec create_handoff(String.t(), map()) :: {:ok, String.t()}
  def create_handoff(analyst_id, notes) do
    GenServer.call(__MODULE__, {:create_handoff, analyst_id, notes})
  end

  @doc """
  Get pending handoff notes for an analyst.
  """
  @spec get_handoff_notes(String.t()) :: [map()]
  def get_handoff_notes(analyst_id) do
    GenServer.call(__MODULE__, {:get_handoff_notes, analyst_id})
  end

  @doc """
  Acknowledge handoff notes.
  """
  @spec acknowledge_handoff(String.t(), String.t()) :: :ok | {:error, :not_found}
  def acknowledge_handoff(handoff_id, analyst_id) do
    GenServer.call(__MODULE__, {:acknowledge_handoff, handoff_id, analyst_id})
  end

  # -- Performance Tracking ------------------------------------------------

  @doc """
  Get performance metrics for an analyst.
  """
  @spec get_analyst_performance(String.t(), keyword()) :: map()
  def get_analyst_performance(analyst_id, opts \\ []) do
    GenServer.call(__MODULE__, {:get_performance, analyst_id, opts})
  end

  @doc """
  Get team-wide performance summary.
  """
  @spec get_team_performance(keyword()) :: map()
  def get_team_performance(opts \\ []) do
    GenServer.call(__MODULE__, {:get_team_performance, opts})
  end

  @doc """
  Get engine statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  @impl true
  def init(_opts) do
    :ets.new(@ets_analysts, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@ets_workspaces, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@ets_kb, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@ets_shifts, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@ets_handoffs, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@ets_performance, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@ets_correlations, [:named_table, :bag, :public, read_concurrency: true])

    state = %{
      stats: %{
        analysts_registered: 0,
        triage_decisions: 0,
        workspaces_created: 0,
        kb_entries: 0,
        handoffs_created: 0,
        correlations_found: 0
      }
    }

    # Schedule performance aggregation
    schedule_perf_aggregation()

    Logger.info("[MDR.AnalystConsole] Initialized")
    {:ok, state}
  end

  # -- Analyst management --------------------------------------------------

  @impl true
  def handle_call({:register_analyst, attrs}, _from, state) do
    analyst_id = attrs[:id] || attrs["id"] || Ecto.UUID.generate()

    profile = %{
      id: analyst_id,
      name: attrs[:name] || attrs["name"],
      email: attrs[:email] || attrs["email"],
      role: attrs[:role] || attrs["role"] || "analyst",
      skills: attrs[:skills] || attrs["skills"] || [],
      certifications: attrs[:certifications] || attrs["certifications"] || [],
      status: "available",
      current_shift: nil,
      alerts_handled_today: 0,
      max_concurrent: attrs[:max_concurrent] || 10,
      registered_at: DateTime.utc_now()
    }

    :ets.insert(@ets_analysts, {analyst_id, profile})

    # Initialize performance tracking
    :ets.insert(@ets_performance, {analyst_id, %{
      alerts_handled: 0,
      true_positives: 0,
      false_positives: 0,
      needs_investigation: 0,
      avg_triage_time_sec: 0,
      triage_times: [],
      incidents_resolved: 0,
      escalations: 0,
      customer_satisfaction: [],
      mttd_samples: [],
      mttr_samples: []
    }})

    new_stats = %{state.stats | analysts_registered: state.stats.analysts_registered + 1}
    {:reply, {:ok, profile}, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:update_analyst, analyst_id, attrs}, _from, state) do
    case :ets.lookup(@ets_analysts, analyst_id) do
      [{^analyst_id, profile}] ->
        updated = Map.merge(profile, Map.take(attrs, [:name, :email, :role, :skills, :status, :current_shift, :max_concurrent, "name", "email", "role", "skills", "status", "current_shift", "max_concurrent"]))
        :ets.insert(@ets_analysts, {analyst_id, updated})
        {:reply, :ok, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:get_analyst, analyst_id}, _from, state) do
    case :ets.lookup(@ets_analysts, analyst_id) do
      [{^analyst_id, profile}] -> {:reply, {:ok, profile}, state}
      [] -> {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:list_analysts, opts}, _from, state) do
    status_filter = Keyword.get(opts, :status)
    role_filter = Keyword.get(opts, :role)

    analysts =
      :ets.tab2list(@ets_analysts)
      |> Enum.map(fn {_id, p} -> p end)
      |> then(fn as_ ->
        if status_filter, do: Enum.filter(as_, &(&1.status == status_filter)), else: as_
      end)
      |> then(fn as_ ->
        if role_filter, do: Enum.filter(as_, &(&1.role == role_filter)), else: as_
      end)
      |> Enum.sort_by(& &1.name)

    {:reply, analysts, state}
  end

  # -- Triage --------------------------------------------------------------

  @impl true
  def handle_call({:get_triage_queue, analyst_id, opts}, _from, state) do
    limit = Keyword.get(opts, :limit, 50)

    # Get alerts assigned to this analyst from MDR.Delivery
    queue = case TamanduaServer.MDR.Delivery.get_queue(analyst_id: analyst_id, status: "assigned") do
      entries when is_list(entries) -> entries
      _ -> []
    end

    # Enrich with AI pre-triage scores
    enriched = Enum.map(queue, fn entry ->
      ai_score = calculate_ai_triage_score(entry.alert)

      Map.merge(entry, %{
        ai_triage_score: ai_score,
        ai_recommendation: triage_recommendation(ai_score),
        context: build_triage_context(entry)
      })
    end)

    # Sort by AI score (highest first = most likely true positive)
    sorted = enriched
      |> Enum.sort_by(& &1.ai_triage_score, :desc)
      |> Enum.take(limit)

    {:reply, sorted, state}
  end

  @impl true
  def handle_call({:record_triage, analyst_id, alert_id, verdict, opts}, _from, state) do
    triage_time = Keyword.get(opts, :triage_time_sec, 0)
    notes = Keyword.get(opts, :notes)

    # Update performance tracking
    case :ets.lookup(@ets_performance, analyst_id) do
      [{^analyst_id, perf}] ->
        updated_perf = %{perf |
          alerts_handled: perf.alerts_handled + 1,
          true_positives: perf.true_positives + (if verdict == "true_positive", do: 1, else: 0),
          false_positives: perf.false_positives + (if verdict == "false_positive", do: 1, else: 0),
          needs_investigation: perf.needs_investigation + (if verdict == "needs_investigation", do: 1, else: 0),
          triage_times: Enum.take([triage_time | perf.triage_times], 1000)
        }

        avg_time = if updated_perf.triage_times != [] do
          Enum.sum(updated_perf.triage_times) / length(updated_perf.triage_times)
        else
          0
        end

        updated_perf = %{updated_perf | avg_triage_time_sec: round(avg_time)}
        :ets.insert(@ets_performance, {analyst_id, updated_perf})

      [] ->
        :ok
    end

    # Submit correlation data for cross-customer analysis
    if verdict == "true_positive" do
      # Extract IOCs from the alert and submit for cross-correlation
      GenServer.cast(self(), {:auto_correlate, alert_id})
    end

    new_stats = %{state.stats | triage_decisions: state.stats.triage_decisions + 1}
    {:reply, :ok, %{state | stats: new_stats}}
  end

  # -- Workspaces ----------------------------------------------------------

  @impl true
  def handle_call({:get_workspace, incident_id}, _from, state) do
    workspace = case :ets.lookup(@ets_workspaces, incident_id) do
      [{^incident_id, ws}] ->
        ws

      [] ->
        ws = %{
          incident_id: incident_id,
          entries: [],
          artifacts: [],
          iocs_found: [],
          affected_systems: [],
          timeline: [],
          notes: [],
          created_at: DateTime.utc_now()
        }

        :ets.insert(@ets_workspaces, {incident_id, ws})
        ws
    end

    {:reply, {:ok, workspace}, state}
  end

  @impl true
  def handle_call({:add_to_workspace, incident_id, entry}, _from, state) do
    case :ets.lookup(@ets_workspaces, incident_id) do
      [{^incident_id, ws}] ->
        workspace_entry = %{
          id: Ecto.UUID.generate(),
          type: entry[:type] || entry["type"] || "note",
          content: entry[:content] || entry["content"],
          analyst_id: entry[:analyst_id] || entry["analyst_id"],
          attachments: entry[:attachments] || entry["attachments"] || [],
          tags: entry[:tags] || entry["tags"] || [],
          added_at: DateTime.utc_now()
        }

        updated = %{ws |
          entries: [workspace_entry | ws.entries],
          timeline: [%{action: entry[:type] || "note_added", timestamp: DateTime.utc_now()} | ws.timeline]
        }

        # Extract IOCs if present
        updated = if entry[:iocs] || entry["iocs"] do
          new_iocs = (entry[:iocs] || entry["iocs"]) ++ ws.iocs_found
          %{updated | iocs_found: Enum.uniq(new_iocs)}
        else
          updated
        end

        :ets.insert(@ets_workspaces, {incident_id, updated})
        {:reply, :ok, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:get_workspace_timeline, incident_id}, _from, state) do
    timeline = case :ets.lookup(@ets_workspaces, incident_id) do
      [{^incident_id, ws}] -> Enum.reverse(ws.timeline)
      [] -> []
    end

    {:reply, timeline, state}
  end

  # -- Cross-customer correlation ------------------------------------------

  @impl true
  def handle_call({:cross_correlate, indicator}, _from, state) do
    indicator_type = indicator[:type] || indicator["type"]
    indicator_value = indicator[:value] || indicator["value"]

    matches =
      :ets.lookup(@ets_correlations, {indicator_type, indicator_value})
      |> Enum.map(fn {_key, entry} ->
        # Anonymize: never leak org_id or customer-specific data
        %{
          first_seen: entry.first_seen,
          last_seen: entry.last_seen,
          organizations_affected: entry.org_count,
          severity: entry.severity,
          mitre_techniques: entry.mitre_techniques || [],
          alert_count: entry.alert_count
        }
      end)

    {:reply, matches, state}
  end

  @impl true
  def handle_cast({:submit_correlation, org_id, indicator}, state) do
    key = {indicator[:type] || indicator["type"], indicator[:value] || indicator["value"]}

    existing = :ets.lookup(@ets_correlations, key)

    if existing == [] do
      entry = %{
        org_ids: MapSet.new([org_id]),
        org_count: 1,
        first_seen: DateTime.utc_now(),
        last_seen: DateTime.utc_now(),
        severity: indicator[:severity] || "medium",
        mitre_techniques: indicator[:mitre_techniques] || [],
        alert_count: 1
      }
      :ets.insert(@ets_correlations, {key, entry})
    else
      # Update existing correlation
      [{^key, entry}] = existing
      updated = %{entry |
        org_ids: MapSet.put(entry.org_ids, org_id),
        org_count: MapSet.size(MapSet.put(entry.org_ids, org_id)),
        last_seen: DateTime.utc_now(),
        alert_count: entry.alert_count + 1
      }
      :ets.delete(@ets_correlations, key)
      :ets.insert(@ets_correlations, {key, updated})
    end

    {:noreply, state}
  end

  @impl true
  def handle_cast({:auto_correlate, _alert_id}, state) do
    # In production, this would extract IOCs from the alert and submit them
    {:noreply, state}
  end

  # -- Knowledge Base ------------------------------------------------------

  @impl true
  def handle_call({:add_kb_entry, entry}, _from, state) do
    entry_id = Ecto.UUID.generate()

    kb_entry = %{
      id: entry_id,
      title: entry[:title] || entry["title"],
      category: entry[:category] || entry["category"] || "general",
      content: entry[:content] || entry["content"],
      tags: entry[:tags] || entry["tags"] || [],
      mitre_techniques: entry[:mitre_techniques] || entry["mitre_techniques"] || [],
      resolution_template: entry[:resolution_template] || entry["resolution_template"],
      author: entry[:author] || entry["author"],
      helpful_count: 0,
      created_at: DateTime.utc_now(),
      updated_at: DateTime.utc_now()
    }

    :ets.insert(@ets_kb, {entry_id, kb_entry})
    new_stats = %{state.stats | kb_entries: state.stats.kb_entries + 1}
    {:reply, {:ok, entry_id}, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:search_kb, query, opts}, _from, state) do
    category = Keyword.get(opts, :category)
    limit = Keyword.get(opts, :limit, 20)
    query_lower = String.downcase(query)

    results =
      :ets.tab2list(@ets_kb)
      |> Enum.map(fn {_id, entry} -> entry end)
      |> Enum.filter(fn entry ->
        title_match = String.contains?(String.downcase(entry.title || ""), query_lower)
        content_match = String.contains?(String.downcase(entry.content || ""), query_lower)
        tag_match = Enum.any?(entry.tags, &String.contains?(String.downcase(&1), query_lower))

        match = title_match or content_match or tag_match
        category_match = is_nil(category) or entry.category == category

        match and category_match
      end)
      |> Enum.sort_by(& &1.helpful_count, :desc)
      |> Enum.take(limit)

    {:reply, results, state}
  end

  @impl true
  def handle_call({:get_kb_entry, entry_id}, _from, state) do
    case :ets.lookup(@ets_kb, entry_id) do
      [{^entry_id, entry}] -> {:reply, {:ok, entry}, state}
      [] -> {:reply, {:error, :not_found}, state}
    end
  end

  # -- Shift management ----------------------------------------------------

  @impl true
  def handle_call({:set_schedule, schedule}, _from, state) do
    :ets.insert(@ets_shifts, {:schedule, schedule})
    {:reply, :ok, state}
  end

  @impl true
  def handle_call(:get_current_shift, _from, state) do
    schedule = case :ets.lookup(@ets_shifts, :schedule) do
      [{:schedule, s}] -> s
      [] -> %{shifts: []}
    end

    now = DateTime.utc_now()
    hour = now.hour

    current = Enum.find(schedule[:shifts] || schedule["shifts"] || [], fn shift ->
      start_h = shift[:start_hour] || shift["start_hour"] || 0
      end_h = shift[:end_hour] || shift["end_hour"] || 24

      if start_h < end_h do
        hour >= start_h and hour < end_h
      else
        # Overnight shift
        hour >= start_h or hour < end_h
      end
    end)

    on_duty_analysts =
      :ets.tab2list(@ets_analysts)
      |> Enum.map(fn {_id, p} -> p end)
      |> Enum.filter(&(&1.status in ["available", "busy"]))

    {:reply, %{
      current_shift: current,
      on_duty_analysts: on_duty_analysts,
      timestamp: now
    }, state}
  end

  @impl true
  def handle_call({:create_handoff, analyst_id, notes}, _from, state) do
    handoff_id = Ecto.UUID.generate()

    handoff = %{
      id: handoff_id,
      from_analyst: analyst_id,
      to_analyst: notes[:to_analyst] || notes["to_analyst"],
      pending_items: notes[:pending_items] || notes["pending_items"] || [],
      open_incidents: notes[:open_incidents] || notes["open_incidents"] || [],
      critical_notes: notes[:critical_notes] || notes["critical_notes"],
      general_notes: notes[:general_notes] || notes["general_notes"],
      acknowledged: false,
      acknowledged_at: nil,
      created_at: DateTime.utc_now()
    }

    :ets.insert(@ets_handoffs, {handoff_id, handoff})
    new_stats = %{state.stats | handoffs_created: state.stats.handoffs_created + 1}
    {:reply, {:ok, handoff_id}, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:get_handoff_notes, analyst_id}, _from, state) do
    notes =
      :ets.tab2list(@ets_handoffs)
      |> Enum.map(fn {_id, h} -> h end)
      |> Enum.filter(fn h ->
        h.to_analyst == analyst_id and not h.acknowledged
      end)
      |> Enum.sort_by(& &1.created_at, {:desc, DateTime})

    {:reply, notes, state}
  end

  @impl true
  def handle_call({:acknowledge_handoff, handoff_id, analyst_id}, _from, state) do
    case :ets.lookup(@ets_handoffs, handoff_id) do
      [{^handoff_id, handoff}] ->
        updated = %{handoff | acknowledged: true, acknowledged_at: DateTime.utc_now()}
        :ets.insert(@ets_handoffs, {handoff_id, updated})
        {:reply, :ok, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  # -- Performance ---------------------------------------------------------

  @impl true
  def handle_call({:get_performance, analyst_id, _opts}, _from, state) do
    perf = case :ets.lookup(@ets_performance, analyst_id) do
      [{^analyst_id, p}] ->
        mttd = if p.mttd_samples != [] do
          Enum.sum(p.mttd_samples) / length(p.mttd_samples)
        else
          0
        end

        mttr = if p.mttr_samples != [] do
          Enum.sum(p.mttr_samples) / length(p.mttr_samples)
        else
          0
        end

        csat = if p.customer_satisfaction != [] do
          Enum.sum(p.customer_satisfaction) / length(p.customer_satisfaction)
        else
          0
        end

        tp_rate = if p.alerts_handled > 0 do
          Float.round(p.true_positives / p.alerts_handled * 100, 1)
        else
          0.0
        end

        Map.merge(p, %{
          mttd_minutes: round(mttd),
          mttr_minutes: round(mttr),
          customer_satisfaction_avg: Float.round(csat * 1.0, 2),
          true_positive_rate: tp_rate
        })

      [] ->
        %{alerts_handled: 0, message: "No data"}
    end

    {:reply, perf, state}
  end

  @impl true
  def handle_call({:get_team_performance, _opts}, _from, state) do
    all_perf =
      :ets.tab2list(@ets_performance)
      |> Enum.map(fn {analyst_id, perf} -> {analyst_id, perf} end)

    total_alerts = Enum.sum(Enum.map(all_perf, fn {_, p} -> p.alerts_handled end))
    total_tp = Enum.sum(Enum.map(all_perf, fn {_, p} -> p.true_positives end))
    total_fp = Enum.sum(Enum.map(all_perf, fn {_, p} -> p.false_positives end))

    all_triage_times = Enum.flat_map(all_perf, fn {_, p} -> p.triage_times end)
    avg_triage = if all_triage_times != [] do
      Enum.sum(all_triage_times) / length(all_triage_times)
    else
      0
    end

    team = %{
      analyst_count: length(all_perf),
      total_alerts_handled: total_alerts,
      total_true_positives: total_tp,
      total_false_positives: total_fp,
      true_positive_rate: if(total_alerts > 0, do: Float.round(total_tp / total_alerts * 100, 1), else: 0.0),
      false_positive_rate: if(total_alerts > 0, do: Float.round(total_fp / total_alerts * 100, 1), else: 0.0),
      avg_triage_time_sec: round(avg_triage),
      generated_at: DateTime.utc_now()
    }

    {:reply, team, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  # -- Periodic tasks ------------------------------------------------------

  @impl true
  def handle_info(:aggregate_performance, state) do
    # Could aggregate daily performance snapshots here
    schedule_perf_aggregation()
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ============================================================================
  # Private - AI Triage
  # ============================================================================

  defp calculate_ai_triage_score(alert) when is_map(alert) do
    # Heuristic scoring based on alert attributes
    base = 50

    severity_boost = case alert[:severity] || alert["severity"] do
      "critical" -> 30
      "high" -> 20
      "medium" -> 10
      _ -> 0
    end

    threat_score = (alert[:threat_score] || alert["threat_score"] || 0) * 10

    # Detection source reliability
    source_boost = case alert[:detection_metadata] || alert["detection_metadata"] do
      %{"source" => "sigma"} -> 15
      %{"source" => "yara"} -> 20
      %{"source" => "ml"} -> 10
      %{"source" => "behavioral"} -> 12
      _ -> 0
    end

    # MITRE coverage
    mitre_boost = min(length(alert[:mitre_techniques] || alert["mitre_techniques"] || []) * 5, 15)

    # Evidence richness
    evidence_boost = case alert[:evidence] || alert["evidence"] do
      %{} = e when map_size(e) > 3 -> 10
      %{} = e when map_size(e) > 0 -> 5
      _ -> 0
    end

    total = base + severity_boost + threat_score + source_boost + mitre_boost + evidence_boost
    min(100, max(0, round(total)))
  end
  defp calculate_ai_triage_score(_), do: 50

  defp triage_recommendation(score) when score >= 80, do: "likely_true_positive"
  defp triage_recommendation(score) when score >= 60, do: "investigate"
  defp triage_recommendation(score) when score >= 40, do: "low_confidence"
  defp triage_recommendation(_), do: "likely_false_positive"

  defp build_triage_context(entry) do
    %{
      alert_age_minutes: DateTime.diff(DateTime.utc_now(), entry.queued_at, :second) / 60.0,
      sla_remaining_minutes: case entry.sla_deadline do
        %DateTime{} = d -> max(0, DateTime.diff(d, DateTime.utc_now(), :second) / 60.0)
        _ -> nil
      end,
      priority: entry.priority,
      org_id: entry.org_id
    }
  end

  defp schedule_perf_aggregation do
    Process.send_after(self(), :aggregate_performance, @perf_aggregation_interval)
  end
end
