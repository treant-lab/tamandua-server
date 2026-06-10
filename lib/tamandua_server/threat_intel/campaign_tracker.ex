defmodule TamanduaServer.ThreatIntel.CampaignTracker do
  @moduledoc """
  Campaign Tracker GenServer.

  Tracks active campaigns by clustering related alerts that share
  attributed threat actors within a configurable time window.

  ## Campaign Detection

  Every 15 minutes, the tracker scans recent high-confidence attributions
  and groups alerts by attributed actor within a 24-hour window. If 3 or
  more alerts are attributed to the same actor within the window, a campaign
  is automatically created (or updated).

  ## IOC -> Alert -> Agent Relationships

  The tracker maintains an ETS-backed index that maps:
  - IOC values -> alert IDs that matched them
  - Alert IDs -> agent IDs where the alert fired
  - Agent IDs -> campaign IDs the agent is part of

  This enables rapid lookup of "which agents were impacted by a given IOC"
  and "which campaigns involve a given agent".

  ## Campaign Scope and Timeline

  Each campaign tracks:
  - `timeline` - Chronological list of significant events (alert created,
    IOC matched, new agent impacted, severity escalation)
  - `scope` - Summary of affected endpoints, IOCs, timespan, geographic spread

  ## Severity Escalation

  When new matches are found for an active campaign:
  - If new agents are impacted, severity may escalate
  - If new IOC types are observed, severity may escalate
  - If match velocity increases, severity may escalate
  - Campaign severity is always >= the max severity of its alerts

  ## Campaigns

  Each campaign contains:
  - `id` - Unique identifier
  - `name` - Auto-generated or manually set
  - `actor` - The attributed threat actor name
  - `start_time` - Earliest alert timestamp
  - `end_time` - Latest alert timestamp
  - `alert_ids` - List of alert IDs in the campaign
  - `affected_agents` - Unique agent IDs involved
  - `ioc_values` - Distinct IOC values observed
  - `ioc_count` - Number of distinct IOCs observed
  - `severity` - Campaign severity (escalates automatically)
  - `status` - "active" or "resolved"
  - `timeline` - List of timestamped events
  - `scope` - Campaign scope summary

  Campaigns are stored in an ETS table for fast lookup.
  """

  use GenServer
  require Logger

  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Persistence

  @ets_table :campaign_tracker_campaigns
  @ets_ioc_index :campaign_tracker_ioc_index
  @ets_agent_index :campaign_tracker_agent_index
  @auto_detect_interval :timer.minutes(15)
  @dets_flush_interval :timer.seconds(60)
  @alert_window_hours 24
  @min_alerts_for_campaign 3
  @min_attribution_confidence 0.4
  @pubsub TamanduaServer.PubSub
  @topic "campaign_tracker"

  # Severity levels for escalation comparison
  @severity_levels %{"low" => 1, "medium" => 2, "high" => 3, "critical" => 4}

  # TTL for campaign data: campaigns older than 90 days are pruned on load
  @campaign_ttl_days 90

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  List all tracked campaigns.

  ## Options
  - `:status` - Filter by status ("active" or "resolved")
  - `:limit` - Maximum number of campaigns (default: 50)
  - `:actor` - Filter by actor name
  - `:min_severity` - Minimum severity level ("low", "medium", "high", "critical")
  """
  @spec list_campaigns(keyword()) :: [map()]
  def list_campaigns(opts \\ []) do
    GenServer.call(__MODULE__, {:list_campaigns, opts})
  end

  @doc """
  Get a single campaign by ID, including full timeline and scope.
  """
  @spec get_campaign(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_campaign(campaign_id) do
    GenServer.call(__MODULE__, {:get_campaign, campaign_id})
  end

  @doc """
  Get a campaign's detailed scope: affected endpoints, IOCs, timespan.
  """
  @spec get_campaign_scope(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_campaign_scope(campaign_id) do
    GenServer.call(__MODULE__, {:get_campaign_scope, campaign_id})
  end

  @doc """
  Record an attribution result for campaign tracking.

  Called after an alert is successfully attributed. The tracker uses this
  data during the periodic auto-detect sweep.

  Also accepts retroactive scanner results with IOC values for indexing.
  """
  @spec record_attribution(map()) :: :ok
  def record_attribution(attribution) do
    GenServer.cast(__MODULE__, {:record_attribution, attribution})
  end

  @doc """
  Manually trigger campaign auto-detection.
  """
  @spec auto_detect_campaigns() :: :ok
  def auto_detect_campaigns do
    GenServer.cast(__MODULE__, :auto_detect_campaigns)
  end

  @doc """
  Resolve a campaign (mark as no longer active).
  """
  @spec resolve_campaign(String.t()) :: {:ok, map()} | {:error, :not_found}
  def resolve_campaign(campaign_id) do
    GenServer.call(__MODULE__, {:resolve_campaign, campaign_id})
  end

  @doc """
  Look up campaigns that involve a specific IOC value.
  """
  @spec campaigns_for_ioc(String.t()) :: [map()]
  def campaigns_for_ioc(ioc_value) do
    GenServer.call(__MODULE__, {:campaigns_for_ioc, ioc_value})
  end

  @doc """
  Look up campaigns that affect a specific agent.
  """
  @spec campaigns_for_agent(String.t()) :: [map()]
  def campaigns_for_agent(agent_id) do
    GenServer.call(__MODULE__, {:campaigns_for_agent, agent_id})
  end

  @doc """
  Get campaign tracker statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    # TTL filter: prune campaigns older than @campaign_ttl_days on load
    ttl_cutoff = DateTime.add(DateTime.utc_now(), -@campaign_ttl_days, :day)

    campaign_filter = fn
      {_id, campaign} when is_map(campaign) ->
        case campaign[:updated_at] || campaign[:created_at] do
          %DateTime{} = ts -> DateTime.compare(ts, ttl_cutoff) != :lt
          _ -> true
        end

      _ ->
        true
    end

    {:ok, dets_campaigns} =
      Persistence.init_persistent_ets(@ets_table, "campaign_tracker_campaigns",
        filter_fn: campaign_filter
      )

    {:ok, dets_ioc_index} =
      Persistence.init_persistent_ets(@ets_ioc_index, "campaign_tracker_ioc_index")

    {:ok, dets_agent_index} =
      Persistence.init_persistent_ets(@ets_agent_index, "campaign_tracker_agent_index")

    restored_campaigns = :ets.info(@ets_table, :size)
    restored_iocs = :ets.info(@ets_ioc_index, :size)
    restored_agents = :ets.info(@ets_agent_index, :size)

    state = %{
      stats: %{
        campaigns_created: 0,
        campaigns_resolved: 0,
        campaigns_escalated: 0,
        auto_detect_runs: 0,
        attributions_recorded: 0,
        iocs_indexed: 0
      },
      dets_refs: %{
        campaigns: dets_campaigns,
        ioc_index: dets_ioc_index,
        agent_index: dets_agent_index
      }
    }

    # Schedule initial auto-detection after a brief startup delay
    Process.send_after(self(), :auto_detect, :timer.seconds(30))
    schedule_dets_flush()

    Logger.info(
      "[CampaignTracker] Initialized with IOC and agent indexes, " <>
        "restored #{restored_campaigns} campaigns, #{restored_iocs} IOCs, #{restored_agents} agents from DETS"
    )

    {:ok, state}
  end

  @impl true
  def handle_call({:list_campaigns, opts}, _from, state) do
    campaigns = do_list_campaigns(opts)
    {:reply, campaigns, state}
  end

  @impl true
  def handle_call({:get_campaign, campaign_id}, _from, state) do
    result = case :ets.lookup(@ets_table, campaign_id) do
      [{^campaign_id, campaign}] -> {:ok, campaign}
      [] -> {:error, :not_found}
    end
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_campaign_scope, campaign_id}, _from, state) do
    result = case :ets.lookup(@ets_table, campaign_id) do
      [{^campaign_id, campaign}] ->
        scope = build_campaign_scope(campaign)
        {:ok, scope}
      [] ->
        {:error, :not_found}
    end
    {:reply, result, state}
  end

  @impl true
  def handle_call({:resolve_campaign, campaign_id}, _from, state) do
    case :ets.lookup(@ets_table, campaign_id) do
      [{^campaign_id, campaign}] ->
        updated = campaign
        |> Map.put(:status, "resolved")
        |> Map.put(:end_time, DateTime.utc_now())
        |> add_timeline_event("resolved", "Campaign resolved")

        # Write-through: campaign resolution is a significant state change
        Persistence.write_through(@ets_table, state.dets_refs.campaigns, campaign_id, updated)
        new_stats = Map.update!(state.stats, :campaigns_resolved, &(&1 + 1))
        broadcast_campaign_update(campaign_id, :resolved, updated)
        {:reply, {:ok, updated}, %{state | stats: new_stats}}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:campaigns_for_ioc, ioc_value}, _from, state) do
    campaign_ids = case :ets.lookup(@ets_ioc_index, ioc_value) do
      [{^ioc_value, ids}] -> ids
      [] -> []
    end

    campaigns = Enum.flat_map(campaign_ids, fn id ->
      case :ets.lookup(@ets_table, id) do
        [{^id, campaign}] -> [campaign]
        [] -> []
      end
    end)

    {:reply, campaigns, state}
  end

  @impl true
  def handle_call({:campaigns_for_agent, agent_id}, _from, state) do
    campaign_ids = case :ets.lookup(@ets_agent_index, agent_id) do
      [{^agent_id, ids}] -> ids
      [] -> []
    end

    campaigns = Enum.flat_map(campaign_ids, fn id ->
      case :ets.lookup(@ets_table, id) do
        [{^id, campaign}] -> [campaign]
        [] -> []
      end
    end)

    {:reply, campaigns, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    stats = Map.merge(state.stats, %{
      active_campaigns: count_campaigns_by_status("active"),
      resolved_campaigns: count_campaigns_by_status("resolved"),
      total_campaigns: :ets.info(@ets_table, :size),
      indexed_iocs: :ets.info(@ets_ioc_index, :size),
      indexed_agents: :ets.info(@ets_agent_index, :size)
    })
    {:reply, stats, state}
  end

  @impl true
  def handle_cast({:record_attribution, attribution}, state) do
    # Index IOC values from retroactive scanner or attribution engine
    ioc_values = attribution[:ioc_values] || attribution["ioc_values"] || []
    Enum.each(ioc_values, fn ioc_value ->
      index_ioc(ioc_value, attribution)
    end)

    new_stats = state.stats
    |> Map.update!(:attributions_recorded, &(&1 + 1))
    |> Map.update!(:iocs_indexed, &(&1 + length(ioc_values)))

    {:noreply, %{state | stats: new_stats}}
  end

  @impl true
  def handle_cast(:auto_detect_campaigns, state) do
    new_state = run_auto_detect(state)
    {:noreply, new_state}
  end

  @impl true
  def handle_info(:auto_detect, state) do
    new_state = run_auto_detect(state)
    # Schedule next run
    Process.send_after(self(), :auto_detect, @auto_detect_interval)
    {:noreply, new_state}
  end

  @impl true
  def handle_info(:dets_flush, state) do
    # Periodic batch flush of all campaign-related ETS tables to DETS
    dets = state.dets_refs
    Persistence.flush(@ets_table, dets.campaigns)
    Persistence.flush(@ets_ioc_index, dets.ioc_index)
    Persistence.flush(@ets_agent_index, dets.agent_index)

    schedule_dets_flush()
    Logger.debug("[CampaignTracker] DETS flush completed")
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    if dets = state[:dets_refs] do
      Logger.info("[CampaignTracker] Shutting down, flushing state to DETS")
      Persistence.flush(@ets_table, dets.campaigns)
      Persistence.flush(@ets_ioc_index, dets.ioc_index)
      Persistence.flush(@ets_agent_index, dets.agent_index)

      Persistence.close(dets.campaigns)
      Persistence.close(dets.ioc_index)
      Persistence.close(dets.agent_index)
    end

    :ok
  end

  # ============================================================================
  # Private - Campaign Listing
  # ============================================================================

  defp do_list_campaigns(opts) do
    limit = Keyword.get(opts, :limit, 50)
    status_filter = Keyword.get(opts, :status)
    actor_filter = Keyword.get(opts, :actor)
    min_severity = Keyword.get(opts, :min_severity)

    campaigns =
      :ets.tab2list(@ets_table)
      |> Enum.map(fn {_, campaign} -> campaign end)

    campaigns = if status_filter do
      Enum.filter(campaigns, fn c -> c.status == status_filter end)
    else
      campaigns
    end

    campaigns = if actor_filter do
      Enum.filter(campaigns, fn c -> c.actor == actor_filter end)
    else
      campaigns
    end

    campaigns = if min_severity do
      min_level = Map.get(@severity_levels, min_severity, 0)
      Enum.filter(campaigns, fn c ->
        campaign_level = Map.get(@severity_levels, c[:severity] || "low", 0)
        campaign_level >= min_level
      end)
    else
      campaigns
    end

    campaigns
    |> Enum.sort_by(fn c -> c.end_time || c.start_time end, {:desc, DateTime})
    |> Enum.take(limit)
  end

  defp count_campaigns_by_status(status) do
    :ets.foldl(fn {_, campaign}, count ->
      if campaign.status == status, do: count + 1, else: count
    end, 0, @ets_table)
  end

  # ============================================================================
  # Private - IOC and Agent Indexing
  # ============================================================================

  defp index_ioc(ioc_value, _attribution) when is_nil(ioc_value), do: :ok
  defp index_ioc(ioc_value, _attribution) do
    # We store {ioc_value, [campaign_ids]} -- campaigns are linked later
    # during auto-detect. For now, just ensure the entry exists.
    case :ets.lookup(@ets_ioc_index, ioc_value) do
      [{^ioc_value, _ids}] -> :ok
      [] -> :ets.insert(@ets_ioc_index, {ioc_value, []})
    end
  end

  defp update_ioc_index(campaign_id, ioc_values) do
    Enum.each(ioc_values, fn ioc_value ->
      case :ets.lookup(@ets_ioc_index, ioc_value) do
        [{^ioc_value, existing_ids}] ->
          unless campaign_id in existing_ids do
            :ets.insert(@ets_ioc_index, {ioc_value, [campaign_id | existing_ids]})
          end
        [] ->
          :ets.insert(@ets_ioc_index, {ioc_value, [campaign_id]})
      end
    end)
  end

  defp update_agent_index(campaign_id, agent_ids) do
    Enum.each(agent_ids, fn agent_id ->
      unless is_nil(agent_id) do
        case :ets.lookup(@ets_agent_index, agent_id) do
          [{^agent_id, existing_ids}] ->
            unless campaign_id in existing_ids do
              :ets.insert(@ets_agent_index, {agent_id, [campaign_id | existing_ids]})
            end
          [] ->
            :ets.insert(@ets_agent_index, {agent_id, [campaign_id]})
        end
      end
    end)
  end

  # ============================================================================
  # Private - Campaign Scope
  # ============================================================================

  defp build_campaign_scope(campaign) do
    duration_hours = if campaign.start_time && campaign.end_time do
      DateTime.diff(campaign.end_time, campaign.start_time, :second) / 3600.0
      |> Float.round(1)
    else
      0.0
    end

    %{
      campaign_id: campaign.id,
      actor: campaign.actor,
      severity: campaign[:severity] || "medium",
      affected_endpoints: length(campaign.affected_agents),
      affected_agent_ids: campaign.affected_agents,
      ioc_count: campaign.ioc_count,
      ioc_values: campaign[:ioc_values] || [],
      alert_count: length(campaign.alert_ids),
      timespan: %{
        start_time: campaign.start_time,
        end_time: campaign.end_time,
        duration_hours: duration_hours
      },
      mitre_techniques: campaign[:mitre_techniques] || [],
      timeline_events: length(campaign[:timeline] || []),
      confidence: campaign[:confidence] || 0.0
    }
  end

  # ============================================================================
  # Private - Auto-Detection
  # ============================================================================

  defp run_auto_detect(state) do
    try do
      do_auto_detect(state)
    rescue
      e ->
        Logger.error("[CampaignTracker] Auto-detect failed: #{inspect(e)}")
        state
    end
  end

  defp do_auto_detect(state) do
    # Query recent alerts with attribution data from the last 24 hours
    cutoff = DateTime.add(DateTime.utc_now(), -@alert_window_hours, :hour)

    attributed_alerts =
      from(a in Alert,
        where: a.inserted_at >= ^cutoff,
        where: a.attribution_confidence >= ^@min_attribution_confidence,
        where: fragment("cardinality(?) > 0", a.attributed_actors),
        select: %{
          id: a.id,
          agent_id: a.agent_id,
          severity: a.severity,
          attributed_actors: a.attributed_actors,
          attribution_confidence: a.attribution_confidence,
          attribution_details: a.attribution_details,
          campaign_id: a.campaign_id,
          mitre_techniques: a.mitre_techniques,
          evidence: a.evidence,
          inserted_at: a.inserted_at
        },
        order_by: [asc: a.inserted_at]
      )
      |> Repo.all()

    if length(attributed_alerts) == 0 do
      Logger.debug("[CampaignTracker] No attributed alerts in window, skipping")
      new_stats = Map.update!(state.stats, :auto_detect_runs, &(&1 + 1))
      %{state | stats: new_stats}
    else
      # Group alerts by each attributed actor
      actor_groups = group_alerts_by_actor(attributed_alerts)

      # Create or update campaigns for groups meeting the threshold
      escalation_count = Enum.reduce(actor_groups, 0, fn {actor_name, alerts}, acc ->
        if length(alerts) >= @min_alerts_for_campaign do
          escalated = create_or_update_campaign(actor_name, alerts)
          if escalated, do: acc + 1, else: acc
        else
          acc
        end
      end)

      Logger.info(
        "[CampaignTracker] Auto-detect completed: #{length(attributed_alerts)} attributed alerts, " <>
        "#{map_size(actor_groups)} actor groups, #{escalation_count} escalations"
      )

      new_stats = state.stats
      |> Map.update!(:auto_detect_runs, &(&1 + 1))
      |> Map.update!(:campaigns_escalated, &(&1 + escalation_count))

      %{state | stats: new_stats}
    end
  end

  defp group_alerts_by_actor(alerts) do
    Enum.reduce(alerts, %{}, fn alert, acc ->
      Enum.reduce(alert.attributed_actors, acc, fn actor_name, inner_acc ->
        Map.update(inner_acc, actor_name, [alert], fn existing -> [alert | existing] end)
      end)
    end)
  end

  # Returns true if severity was escalated, false otherwise
  defp create_or_update_campaign(actor_name, alerts) do
    alert_ids = Enum.map(alerts, & &1.id)
    affected_agents = alerts |> Enum.map(& &1.agent_id) |> Enum.reject(&is_nil/1) |> Enum.uniq()
    start_time = alerts |> Enum.map(& &1.inserted_at) |> Enum.min(DateTime)
    end_time = alerts |> Enum.map(& &1.inserted_at) |> Enum.max(DateTime)

    # Collect distinct IOC values from alert evidence and attribution details
    ioc_values = alerts
    |> Enum.flat_map(fn a ->
      details = a.attribution_details || %{}
      evidence = a[:evidence] || %{}
      iocs_from_details = details["matching_iocs"] || details[:matching_iocs] || []
      ioc_from_evidence = evidence["ioc_value"] || evidence[:ioc_value]
      if ioc_from_evidence, do: [ioc_from_evidence | iocs_from_details], else: iocs_from_details
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()

    ioc_count = length(ioc_values)

    # Calculate average confidence
    avg_confidence = alerts
    |> Enum.map(& &1.attribution_confidence)
    |> Enum.reject(&is_nil/1)
    |> case do
      [] -> 0.0
      confs -> Enum.sum(confs) / length(confs)
    end

    # Determine campaign severity from alerts
    alert_severity = determine_campaign_severity(alerts)

    # Collect MITRE techniques across all alerts
    techniques = alerts
    |> Enum.flat_map(& &1.mitre_techniques || [])
    |> Enum.uniq()

    # Check if a campaign for this actor already exists and is active
    existing = find_active_campaign_for_actor(actor_name)

    {campaign_id, escalated} = case existing do
      nil ->
        # Create new campaign
        id = "camp_#{:crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)}"

        timeline = [
          timeline_event("created", "Campaign auto-detected for actor #{actor_name}"),
          timeline_event("alert_cluster", "#{length(alert_ids)} alerts attributed to #{actor_name}")
        ]

        campaign = %{
          id: id,
          name: "#{actor_name} Campaign - #{Calendar.strftime(start_time, "%Y-%m-%d")}",
          actor: actor_name,
          start_time: start_time,
          end_time: end_time,
          alert_ids: alert_ids,
          affected_agents: affected_agents,
          ioc_values: ioc_values,
          ioc_count: ioc_count,
          severity: alert_severity,
          status: "active",
          confidence: Float.round(avg_confidence, 3),
          mitre_techniques: techniques,
          timeline: timeline,
          created_at: DateTime.utc_now(),
          updated_at: DateTime.utc_now()
        }
        :ets.insert(@ets_table, {id, campaign})

        # Update indexes
        update_ioc_index(id, ioc_values)
        update_agent_index(id, affected_agents)

        Logger.info("[CampaignTracker] Created campaign #{id} for actor #{actor_name}: #{length(alert_ids)} alerts, severity=#{alert_severity}")

        broadcast_campaign_update(id, :created, campaign)

        Map.update!(campaign, :id, fn _ -> id end)
        {id, false}

      {existing_id, existing_campaign} ->
        # Update existing campaign
        prev_agents = existing_campaign.affected_agents
        prev_ioc_values = existing_campaign[:ioc_values] || []
        prev_severity = existing_campaign[:severity] || "medium"

        merged_alert_ids = Enum.uniq(existing_campaign.alert_ids ++ alert_ids)
        merged_agents = Enum.uniq(prev_agents ++ affected_agents)
        merged_ioc_values = Enum.uniq(prev_ioc_values ++ ioc_values)
        merged_techniques = Enum.uniq((existing_campaign[:mitre_techniques] || []) ++ techniques)
        new_end = if DateTime.compare(end_time, existing_campaign.end_time) == :gt, do: end_time, else: existing_campaign.end_time

        # Determine if we should escalate severity
        new_severity = escalate_severity(
          prev_severity,
          alert_severity,
          length(merged_agents) - length(prev_agents),
          length(merged_ioc_values) - length(prev_ioc_values)
        )

        was_escalated = severity_level(new_severity) > severity_level(prev_severity)

        # Build timeline events for this update
        new_timeline_events = []
        new_timeline_events = if length(merged_agents) > length(prev_agents) do
          new_agent_count = length(merged_agents) - length(prev_agents)
          [timeline_event("new_agents", "#{new_agent_count} new endpoint(s) impacted") | new_timeline_events]
        else
          new_timeline_events
        end

        new_timeline_events = if length(merged_ioc_values) > length(prev_ioc_values) do
          new_ioc_count = length(merged_ioc_values) - length(prev_ioc_values)
          [timeline_event("new_iocs", "#{new_ioc_count} new IOC(s) observed") | new_timeline_events]
        else
          new_timeline_events
        end

        new_timeline_events = if was_escalated do
          [timeline_event("escalated", "Severity escalated from #{prev_severity} to #{new_severity}") | new_timeline_events]
        else
          new_timeline_events
        end

        existing_timeline = existing_campaign[:timeline] || []
        merged_timeline = existing_timeline ++ Enum.reverse(new_timeline_events)

        updated = %{existing_campaign |
          alert_ids: merged_alert_ids,
          affected_agents: merged_agents,
          end_time: new_end,
          ioc_count: length(merged_ioc_values),
          confidence: Float.round(max(existing_campaign.confidence, avg_confidence), 3),
          mitre_techniques: merged_techniques,
          updated_at: DateTime.utc_now()
        }
        |> Map.put(:ioc_values, merged_ioc_values)
        |> Map.put(:severity, new_severity)
        |> Map.put(:timeline, merged_timeline)

        :ets.insert(@ets_table, {existing_id, updated})

        # Update indexes with new entries
        update_ioc_index(existing_id, ioc_values)
        update_agent_index(existing_id, affected_agents)

        if was_escalated do
          Logger.info("[CampaignTracker] ESCALATED campaign #{existing_id}: #{prev_severity} -> #{new_severity}")
          broadcast_campaign_update(existing_id, :escalated, updated)
        else
          Logger.debug("[CampaignTracker] Updated campaign #{existing_id} for actor #{actor_name}, now #{length(merged_alert_ids)} alerts")
          broadcast_campaign_update(existing_id, :updated, updated)
        end

        {existing_id, was_escalated}
    end

    # Update alert records with the campaign_id (fire-and-forget)
    unlinked_alert_ids = Enum.filter(alert_ids, fn id ->
      alert = Enum.find(alerts, fn a -> a.id == id end)
      is_nil(alert.campaign_id)
    end)

    if length(unlinked_alert_ids) > 0 do
      Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
        try do
          from(a in Alert, where: a.id in ^unlinked_alert_ids)
          |> Repo.update_all(set: [campaign_id: campaign_id])
        rescue
          e -> Logger.warning("[CampaignTracker] Failed to link alerts to campaign: #{inspect(e)}")
        end
      end)
    end

    escalated
  end

  # ============================================================================
  # Private - Severity Escalation
  # ============================================================================

  defp determine_campaign_severity(alerts) do
    # Campaign severity is at least the max severity of its constituent alerts
    alerts
    |> Enum.map(fn a -> a[:severity] || "medium" end)
    |> Enum.max_by(&severity_level/1, fn -> "medium" end)
  end

  defp escalate_severity(current_severity, alert_severity, new_agent_count, new_ioc_count) do
    current_level = severity_level(current_severity)
    alert_level = severity_level(alert_severity)

    # Start with the higher of current or alert severity
    base_level = max(current_level, alert_level)

    # Boost for new agents being impacted
    agent_boost = cond do
      new_agent_count >= 5 -> 2
      new_agent_count >= 2 -> 1
      true -> 0
    end

    # Boost for new IOC types appearing
    ioc_boost = cond do
      new_ioc_count >= 5 -> 1
      true -> 0
    end

    final_level = min(base_level + agent_boost + ioc_boost, 4)
    severity_from_level(final_level)
  end

  defp severity_level(severity) do
    Map.get(@severity_levels, severity, 1)
  end

  defp severity_from_level(level) do
    case level do
      l when l >= 4 -> "critical"
      3 -> "high"
      2 -> "medium"
      _ -> "low"
    end
  end

  # ============================================================================
  # Private - Timeline Events
  # ============================================================================

  defp timeline_event(event_type, description) do
    %{
      timestamp: DateTime.utc_now(),
      event_type: event_type,
      description: description
    }
  end

  defp add_timeline_event(campaign, event_type, description) do
    existing = campaign[:timeline] || []
    event = timeline_event(event_type, description)
    Map.put(campaign, :timeline, existing ++ [event])
  end

  # ============================================================================
  # Private - PubSub Broadcasting
  # ============================================================================

  defp broadcast_campaign_update(campaign_id, event, campaign) do
    try do
      payload = %{
        campaign_id: campaign_id,
        event: event,
        campaign: campaign,
        timestamp: DateTime.utc_now()
      }
      Phoenix.PubSub.broadcast(@pubsub, @topic, {:campaign_update, payload})
    rescue
      _ -> :ok
    catch
      :exit, _ -> :ok
    end
  end

  # ============================================================================
  # Private - Lookup Helpers
  # ============================================================================

  defp find_active_campaign_for_actor(actor_name) do
    :ets.foldl(fn {id, campaign}, acc ->
      if campaign.status == "active" and campaign.actor == actor_name do
        {id, campaign}
      else
        acc
      end
    end, nil, @ets_table)
  end

  defp schedule_dets_flush do
    Process.send_after(self(), :dets_flush, @dets_flush_interval)
  end
end
