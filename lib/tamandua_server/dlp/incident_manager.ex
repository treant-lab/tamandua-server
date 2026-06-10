defmodule TamanduaServer.DLP.IncidentManager do
  @moduledoc """
  DLP Incident Manager.

  Tracks DLP policy violations as incidents, managing the full lifecycle from
  detection through investigation and resolution. Integrates with the existing
  alert system for unified security event management.

  Features:
  - Incident creation from DLP policy violations
  - Severity escalation for repeated violations (same user/process)
  - Per-agent and per-user violation tracking
  - Dashboard statistics (top violators, data types, trends)
  - Integration with TamanduaServer.Alerts for unified alerting
  - Organization-scoped incident tracking for multi-tenancy

  ## Incident Schema

      %{
        id: binary_id,
        agent_id: string,
        user: string,
        source_process: string,
        source_path: string,
        destination: string,
        classifier_matches: [classifier_types],
        policy_id: binary_id,
        policy_name: string,
        action_taken: string,
        severity: string,
        content_hash: string,
        content_size: integer,
        max_confidence: float,
        status: "open" | "investigating" | "resolved" | "false_positive",
        escalation_level: integer,
        org_id: binary_id,
        created_at: datetime,
        updated_at: datetime
      }
  """

  use GenServer
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.DLP.PolicyEngine

  # ETS tables
  @incidents_table :dlp_incidents
  @incident_stats_table :dlp_incident_stats
  @violation_tracker_table :dlp_violation_tracker

  # Escalation thresholds
  @escalation_thresholds [
    {3, "medium"},     # 3 violations -> escalate to medium
    {5, "high"},       # 5 violations -> escalate to high
    {10, "critical"}   # 10 violations -> escalate to critical
  ]

  # ===========================================================================
  # Client API
  # ===========================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Record a new DLP incident from a telemetry event.

  Params:
  - agent_id: Agent that detected the violation
  - event: The DLP telemetry event from the agent
  - policy: The policy that was violated
  - action_taken: The enforcement action taken
  """
  def record_incident(agent_id, event, policy, action_taken) do
    GenServer.call(__MODULE__, {:record_incident, agent_id, event, policy, action_taken})
  end

  @doc """
  List DLP incidents, optionally filtered by organization, status, or severity.
  """
  def list_incidents(filters \\ %{}) do
    GenServer.call(__MODULE__, {:list_incidents, filters})
  end

  @doc """
  Get a specific incident by ID.
  """
  def get_incident(incident_id) do
    GenServer.call(__MODULE__, {:get_incident, incident_id})
  end

  @doc """
  Update incident status (investigating, resolved, false_positive).
  """
  def update_status(incident_id, new_status, analyst_notes \\ nil) do
    GenServer.call(__MODULE__, {:update_status, incident_id, new_status, analyst_notes})
  end

  @doc """
  Get dashboard statistics for DLP incidents.
  """
  def get_dashboard_stats(org_id \\ nil) do
    GenServer.call(__MODULE__, {:get_dashboard_stats, org_id})
  end

  @doc """
  Get top violators (users with most DLP incidents).
  """
  def get_top_violators(org_id \\ nil, limit \\ 10) do
    GenServer.call(__MODULE__, {:get_top_violators, org_id, limit})
  end

  @doc """
  Get top data types detected across incidents.
  """
  def get_top_data_types(org_id \\ nil, limit \\ 10) do
    GenServer.call(__MODULE__, {:get_top_data_types, org_id, limit})
  end

  @doc """
  Get incident trend over time (hourly counts for the last 24 hours).
  """
  def get_trend(org_id \\ nil) do
    GenServer.call(__MODULE__, {:get_trend, org_id})
  end

  # ===========================================================================
  # GenServer Implementation
  # ===========================================================================

  @impl true
  def init(_opts) do
    Logger.info("[DLP.IncidentManager] Starting DLP Incident Manager")

    # Create ETS tables
    :ets.new(@incidents_table, [:set, :named_table, :public, read_concurrency: true])
    :ets.new(@incident_stats_table, [:set, :named_table, :public, write_concurrency: true])
    :ets.new(@violation_tracker_table, [:set, :named_table, :public, write_concurrency: true])

    # Initialize stats
    :ets.insert(@incident_stats_table, {:total_incidents, 0})
    :ets.insert(@incident_stats_table, {:open_incidents, 0})
    :ets.insert(@incident_stats_table, {:blocked_count, 0})
    :ets.insert(@incident_stats_table, {:warned_count, 0})
    :ets.insert(@incident_stats_table, {:logged_count, 0})
    :ets.insert(@incident_stats_table, {:escalated_count, 0})

    # Subscribe to DLP-related PubSub events
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "dlp:events")

    # Load recent incidents from database
    send(self(), :load_recent_incidents)

    # Schedule periodic cleanup
    Process.send_after(self(), :cleanup, 3_600_000)

    {:ok, %{}}
  end

  @impl true
  def handle_info(:load_recent_incidents, state) do
    case load_incidents_from_db() do
      {:ok, count} ->
        Logger.info("[DLP.IncidentManager] Loaded #{count} recent incidents from database")
      {:error, reason} ->
        Logger.debug("[DLP.IncidentManager] DB load skipped: #{inspect(reason)}")
    end
    {:noreply, state}
  end

  def handle_info(:cleanup, state) do
    # Remove incidents older than 30 days from ETS (they remain in DB)
    cutoff = DateTime.add(DateTime.utc_now(), -30 * 24 * 3600)

    :ets.tab2list(@incidents_table)
    |> Enum.each(fn {id, incident} ->
      if DateTime.compare(incident.created_at, cutoff) == :lt do
        :ets.delete(@incidents_table, id)
      end
    end)

    # Clean up old violation tracker entries
    :ets.tab2list(@violation_tracker_table)
    |> Enum.each(fn {key, %{last_violation: last}} ->
      if DateTime.compare(last, cutoff) == :lt do
        :ets.delete(@violation_tracker_table, key)
      end
    end)

    # Re-schedule cleanup
    Process.send_after(self(), :cleanup, 3_600_000)
    {:noreply, state}
  end

  # Handle PubSub DLP events
  def handle_info({:dlp_event, agent_id, event_data}, state) do
    # Auto-evaluate incoming DLP events against policies
    org_id = Map.get(event_data, "org_id") || Map.get(event_data, :org_id)
    classifiers = Map.get(event_data, "classifier_types") || Map.get(event_data, :classifier_types, [])
    destination = Map.get(event_data, "destination") || Map.get(event_data, :destination, "unknown")

    case PolicyEngine.evaluate_event(org_id, classifiers, destination) do
      {:ok, matches} when matches != [] ->
        for {policy, action} <- matches do
          record_incident_internal(agent_id, event_data, policy, action)
        end

      _ ->
        :ok
    end

    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  @impl true
  def handle_call({:record_incident, agent_id, event, policy, action_taken}, _from, state) do
    incident = record_incident_internal(agent_id, event, policy, action_taken)
    {:reply, {:ok, incident}, state}
  end

  def handle_call({:list_incidents, filters}, _from, state) do
    incidents = :ets.tab2list(@incidents_table)
    |> Enum.map(fn {_id, incident} -> incident end)
    |> apply_filters(filters)
    |> Enum.sort_by(& &1.created_at, {:desc, DateTime})

    {:reply, {:ok, incidents}, state}
  end

  def handle_call({:get_incident, incident_id}, _from, state) do
    case :ets.lookup(@incidents_table, incident_id) do
      [{^incident_id, incident}] -> {:reply, {:ok, incident}, state}
      [] -> {:reply, {:error, :not_found}, state}
    end
  end

  def handle_call({:update_status, incident_id, new_status, analyst_notes}, _from, state) do
    case :ets.lookup(@incidents_table, incident_id) do
      [{^incident_id, incident}] ->
        updated = incident
        |> Map.put(:status, new_status)
        |> Map.put(:updated_at, DateTime.utc_now())
        |> Map.put(:analyst_notes, analyst_notes || incident[:analyst_notes])

        :ets.insert(@incidents_table, {incident_id, updated})
        persist_incident(updated)

        # Update open/closed counts
        if incident.status == "open" and new_status != "open" do
          safe_decrement(@incident_stats_table, :open_incidents)
        end

        Logger.info("[DLP.IncidentManager] Incident #{incident_id} status -> #{new_status}")
        {:reply, {:ok, updated}, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  def handle_call({:get_dashboard_stats, org_id}, _from, state) do
    incidents = :ets.tab2list(@incidents_table)
    |> Enum.map(fn {_id, inc} -> inc end)
    |> filter_by_org(org_id)

    now = DateTime.utc_now()
    last_24h = DateTime.add(now, -24 * 3600)
    last_7d = DateTime.add(now, -7 * 24 * 3600)

    stats = %{
      total_incidents: length(incidents),
      open_incidents: Enum.count(incidents, & &1.status == "open"),
      incidents_24h: Enum.count(incidents, fn i ->
        DateTime.compare(i.created_at, last_24h) == :gt
      end),
      incidents_7d: Enum.count(incidents, fn i ->
        DateTime.compare(i.created_at, last_7d) == :gt
      end),
      by_severity: %{
        critical: Enum.count(incidents, & &1.severity == "critical"),
        high: Enum.count(incidents, & &1.severity == "high"),
        medium: Enum.count(incidents, & &1.severity == "medium"),
        low: Enum.count(incidents, & &1.severity == "low")
      },
      by_action: %{
        blocked: Enum.count(incidents, & &1.action_taken == "block"),
        warned: Enum.count(incidents, & &1.action_taken == "warn"),
        logged: Enum.count(incidents, & &1.action_taken == "log"),
        encrypted: Enum.count(incidents, & &1.action_taken == "encrypt")
      },
      by_destination: incidents
        |> Enum.group_by(& &1.destination)
        |> Enum.map(fn {dest, incs} -> {dest, length(incs)} end)
        |> Map.new(),
      escalated_count: get_counter(:escalated_count)
    }

    {:reply, {:ok, stats}, state}
  end

  def handle_call({:get_top_violators, org_id, limit}, _from, state) do
    violators = :ets.tab2list(@incidents_table)
    |> Enum.map(fn {_id, inc} -> inc end)
    |> filter_by_org(org_id)
    |> Enum.group_by(& &1.user)
    |> Enum.map(fn {user, incidents} ->
      %{
        user: user,
        incident_count: length(incidents),
        latest_incident: incidents |> Enum.max_by(& &1.created_at) |> Map.get(:created_at),
        top_severity: incidents
          |> Enum.map(& &1.severity)
          |> Enum.max_by(&severity_rank/1),
        data_types: incidents
          |> Enum.flat_map(& &1.classifier_matches)
          |> Enum.uniq()
      }
    end)
    |> Enum.sort_by(& &1.incident_count, :desc)
    |> Enum.take(limit)

    {:reply, {:ok, violators}, state}
  end

  def handle_call({:get_top_data_types, org_id, limit}, _from, state) do
    data_types = :ets.tab2list(@incidents_table)
    |> Enum.map(fn {_id, inc} -> inc end)
    |> filter_by_org(org_id)
    |> Enum.flat_map(& &1.classifier_matches)
    |> Enum.frequencies()
    |> Enum.sort_by(fn {_type, count} -> count end, :desc)
    |> Enum.take(limit)
    |> Enum.map(fn {type, count} -> %{data_type: type, count: count} end)

    {:reply, {:ok, data_types}, state}
  end

  def handle_call({:get_trend, org_id}, _from, state) do
    now = DateTime.utc_now()
    incidents = :ets.tab2list(@incidents_table)
    |> Enum.map(fn {_id, inc} -> inc end)
    |> filter_by_org(org_id)

    # Build hourly buckets for the last 24 hours
    trend = for hour_offset <- 23..0 do
      bucket_start = DateTime.add(now, -hour_offset * 3600)
      bucket_end = DateTime.add(now, -(hour_offset - 1) * 3600)

      count = Enum.count(incidents, fn inc ->
        DateTime.compare(inc.created_at, bucket_start) != :lt and
        DateTime.compare(inc.created_at, bucket_end) == :lt
      end)

      %{
        hour: Calendar.strftime(bucket_start, "%Y-%m-%d %H:00"),
        count: count
      }
    end

    {:reply, {:ok, trend}, state}
  end

  # ===========================================================================
  # Private Helpers
  # ===========================================================================

  defp record_incident_internal(agent_id, event, policy, action_taken) do
    incident_id = Ecto.UUID.generate()
    now = DateTime.utc_now()

    user = extract_field(event, "user", "unknown")
    source_process = extract_field(event, "process_name", "unknown")
    destination = extract_field(event, "destination", "unknown")
    classifier_matches = extract_field(event, "classifier_types",
      extract_field(event, "matches", [])
      |> extract_classifier_types()
    )

    # Check for escalation
    tracker_key = {agent_id, user, source_process}
    {escalation_level, severity} = check_escalation(tracker_key, policy)

    incident = %{
      id: incident_id,
      agent_id: agent_id,
      user: user,
      source_process: source_process,
      source_path: extract_field(event, "source_path", ""),
      destination: destination,
      classifier_matches: classifier_matches,
      policy_id: Map.get(policy, :id, Map.get(policy, "id")),
      policy_name: Map.get(policy, :name, Map.get(policy, "name", "Unknown")),
      action_taken: action_taken,
      severity: severity,
      content_hash: extract_field(event, "content_hash", ""),
      content_size: extract_field(event, "content_size", 0),
      max_confidence: extract_field(event, "max_confidence", 0.0),
      status: "open",
      escalation_level: escalation_level,
      analyst_notes: nil,
      org_id: Map.get(policy, :org_id, Map.get(policy, "org_id")),
      created_at: now,
      updated_at: now
    }

    # Store in ETS
    :ets.insert(@incidents_table, {incident_id, incident})

    # Update stats
    :ets.update_counter(@incident_stats_table, :total_incidents, 1)
    :ets.update_counter(@incident_stats_table, :open_incidents, 1)

    case action_taken do
      "block" -> :ets.update_counter(@incident_stats_table, :blocked_count, 1)
      "warn" -> :ets.update_counter(@incident_stats_table, :warned_count, 1)
      _ -> :ets.update_counter(@incident_stats_table, :logged_count, 1)
    end

    if escalation_level > 0 do
      :ets.update_counter(@incident_stats_table, :escalated_count, 1)
    end

    # Persist to DB
    persist_incident(incident)

    # Broadcast to dashboard
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "dlp:incidents",
      {:new_dlp_incident, incident}
    )

    # Create an alert for high-severity incidents
    if severity in ["high", "critical"] do
      create_alert(incident)
    end

    Logger.info(
      "[DLP.IncidentManager] Incident #{incident_id}: " <>
      "#{source_process} -> #{destination} [#{action_taken}] " <>
      "severity=#{severity} classifiers=#{inspect(classifier_matches)}"
    )

    incident
  end

  defp check_escalation(tracker_key, policy) do
    base_severity = Map.get(policy, :severity, Map.get(policy, "severity", "medium"))
    now = DateTime.utc_now()

    case :ets.lookup(@violation_tracker_table, tracker_key) do
      [{^tracker_key, tracker}] ->
        count = tracker.count + 1
        :ets.insert(@violation_tracker_table, {tracker_key, %{tracker |
          count: count,
          last_violation: now
        }})

        # Determine escalation
        {level, escalated_severity} = @escalation_thresholds
        |> Enum.reverse()
        |> Enum.find({0, base_severity}, fn {threshold, _sev} -> count >= threshold end)

        {level, max_severity(base_severity, escalated_severity)}

      [] ->
        :ets.insert(@violation_tracker_table, {tracker_key, %{
          count: 1,
          first_violation: now,
          last_violation: now
        }})

        {0, base_severity}
    end
  end

  defp max_severity(a, b) do
    if severity_rank(a) >= severity_rank(b), do: a, else: b
  end

  defp severity_rank("critical"), do: 4
  defp severity_rank("high"), do: 3
  defp severity_rank("medium"), do: 2
  defp severity_rank("low"), do: 1
  defp severity_rank(_), do: 0

  defp extract_field(event, key, default) when is_map(event) do
    Map.get(event, key, Map.get(event, String.to_atom(key), default))
  rescue
    _ -> default
  end
  defp extract_field(_, _, default), do: default

  defp extract_classifier_types(matches) when is_list(matches) do
    Enum.flat_map(matches, fn
      %{"classifier_type" => type} -> [type]
      %{classifier_type: type} -> [to_string(type)]
      type when is_binary(type) -> [type]
      _ -> []
    end)
    |> Enum.uniq()
  end
  defp extract_classifier_types(_), do: []

  defp apply_filters(incidents, filters) do
    incidents
    |> filter_by_org(Map.get(filters, :org_id, Map.get(filters, "org_id")))
    |> maybe_filter(:status, Map.get(filters, :status, Map.get(filters, "status")))
    |> maybe_filter(:severity, Map.get(filters, :severity, Map.get(filters, "severity")))
    |> maybe_filter(:agent_id, Map.get(filters, :agent_id, Map.get(filters, "agent_id")))
    |> maybe_filter(:user, Map.get(filters, :user, Map.get(filters, "user")))
  end

  defp filter_by_org(incidents, nil), do: incidents
  defp filter_by_org(incidents, org_id) do
    Enum.filter(incidents, & &1.org_id == org_id)
  end

  defp maybe_filter(incidents, _field, nil), do: incidents
  defp maybe_filter(incidents, field, value) do
    Enum.filter(incidents, fn inc -> Map.get(inc, field) == value end)
  end

  defp safe_decrement(table, key) do
    case :ets.lookup(table, key) do
      [{^key, val}] when val > 0 ->
        :ets.update_counter(table, key, -1)
      _ -> :ok
    end
  end

  defp get_counter(key) do
    case :ets.lookup(@incident_stats_table, key) do
      [{^key, val}] -> val
      [] -> 0
    end
  end

  defp create_alert(incident) do
    Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
      try do
        Phoenix.PubSub.broadcast(TamanduaServer.PubSub, "alerts:feed", %{
          type: "dlp_violation",
          severity: incident.severity,
          title: "DLP Policy Violation: #{incident.policy_name}",
          description: "#{incident.source_process} attempted to transfer " <>
            "#{inspect(incident.classifier_matches)} data to #{incident.destination}. " <>
            "Action: #{incident.action_taken}.",
          agent_id: incident.agent_id,
          user: incident.user,
          metadata: %{
            dlp_incident_id: incident.id,
            policy_id: incident.policy_id,
            destination: incident.destination,
            classifier_matches: incident.classifier_matches,
            escalation_level: incident.escalation_level
          }
        })
      rescue
        e -> Logger.debug("[DLP.IncidentManager] Alert broadcast failed: #{inspect(e)}")
      end
    end)
  end

  defp load_incidents_from_db do
    try do
      import Ecto.Query

      cutoff = DateTime.add(DateTime.utc_now(), -7 * 24 * 3600)

      query = from(i in "dlp_incidents",
        where: i.inserted_at > ^cutoff,
        select: %{
          id: i.id,
          agent_id: i.agent_id,
          user: i.user_name,
          source_process: i.source_process,
          source_path: i.source_path,
          destination: i.destination,
          classifier_matches: i.classifier_matches,
          policy_id: i.policy_id,
          policy_name: i.policy_name,
          action_taken: i.action_taken,
          severity: i.severity,
          content_hash: i.content_hash,
          content_size: i.content_size,
          max_confidence: i.max_confidence,
          status: i.status,
          escalation_level: i.escalation_level,
          org_id: i.organization_id,
          created_at: i.inserted_at,
          updated_at: i.updated_at
        },
        order_by: [desc: i.inserted_at],
        limit: 10_000
      )

      incidents = Repo.all(query)

      for incident <- incidents do
        :ets.insert(@incidents_table, {incident.id, incident})
      end

      {:ok, length(incidents)}
    rescue
      e ->
        Logger.debug("[DLP.IncidentManager] DB load skipped: #{inspect(e)}")
        {:ok, 0}
    end
  end

  defp persist_incident(incident) do
    Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
      try do
        Repo.insert_all("dlp_incidents", [%{
          id: incident.id,
          agent_id: incident.agent_id,
          user_name: incident.user,
          source_process: incident.source_process,
          source_path: incident.source_path,
          destination: incident.destination,
          classifier_matches: incident.classifier_matches,
          policy_id: incident.policy_id,
          policy_name: incident.policy_name,
          action_taken: incident.action_taken,
          severity: incident.severity,
          content_hash: incident.content_hash,
          content_size: incident.content_size,
          max_confidence: incident.max_confidence,
          status: incident.status,
          escalation_level: incident.escalation_level,
          organization_id: incident.org_id,
          inserted_at: incident.created_at,
          updated_at: incident.updated_at
        }],
          on_conflict: {:replace_all_except, [:id, :inserted_at]},
          conflict_target: :id
        )
      rescue
        e -> Logger.debug("[DLP.IncidentManager] Persist failed: #{inspect(e)}")
      end
    end)
  end
end
