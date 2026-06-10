defmodule TamanduaServer.Deception.Analytics do
  @moduledoc """
  Deception Analytics - Attacker Behavior Analysis

  Analyzes interactions with deception artifacts to:
  - Profile attacker behavior patterns
  - Extract TTPs (Tactics, Techniques, and Procedures)
  - Reconstruct attack timelines
  - Identify attacker objectives and capabilities
  - Generate threat intelligence from decoy interactions

  Comparable to Attivo ThreatDefend Analytics or Illusive Attack Intelligence.
  """

  use GenServer
  require Logger
  alias TamanduaServer.Deception.Breadcrumbs

  # ============================================================================
  # Types
  # ============================================================================

  @type attacker_profile :: %{
          id: String.t(),
          first_seen: DateTime.t(),
          last_seen: DateTime.t(),
          source_ips: [String.t()],
          agents_targeted: [String.t()],
          decoy_interactions: non_neg_integer(),
          ttps: [ttp()],
          risk_score: float(),
          status: :active | :dormant | :neutralized,
          indicators: [indicator()],
          timeline: [timeline_event()]
        }

  @type ttp :: %{
          tactic: String.t(),
          technique_id: String.t(),
          technique_name: String.t(),
          sub_technique: String.t() | nil,
          evidence_count: non_neg_integer(),
          first_observed: DateTime.t(),
          last_observed: DateTime.t()
        }

  @type indicator :: %{
          type: :ip | :domain | :hash | :username | :credential | :user_agent | :tool,
          value: String.t(),
          confidence: float(),
          first_seen: DateTime.t(),
          last_seen: DateTime.t(),
          context: map()
        }

  @type timeline_event :: %{
          timestamp: DateTime.t(),
          event_type: String.t(),
          agent_id: String.t(),
          decoy_type: atom(),
          decoy_id: String.t(),
          source_ip: String.t() | nil,
          details: map(),
          mitre_technique: String.t() | nil
        }

  @type interaction_event :: %{
          event_id: String.t(),
          agent_id: String.t(),
          timestamp: DateTime.t(),
          decoy_type: atom(),
          decoy_id: String.t(),
          canary_token: String.t(),
          interaction_type: String.t(),
          source_ip: String.t() | nil,
          source_port: non_neg_integer() | nil,
          process_name: String.t() | nil,
          process_pid: non_neg_integer() | nil,
          user: String.t() | nil,
          credentials_captured: map() | nil,
          data_captured: String.t() | nil,
          mitre_techniques: [String.t()],
          metadata: map()
        }

  # ============================================================================
  # State
  # ============================================================================

  defstruct attacker_profiles: %{},
            interactions: [],
            indicators: %{},
            active_attacks: %{},
            stats: %{
              total_interactions: 0,
              unique_attackers: 0,
              ttps_extracted: 0,
              indicators_generated: 0,
              by_tactic: %{},
              by_technique: %{},
              by_decoy_type: %{}
            }

  # ============================================================================
  # GenServer API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Record a decoy interaction event.
  """
  def record_interaction(event) do
    GenServer.cast(__MODULE__, {:record_interaction, event})
  end

  @doc """
  Get attacker profiles.
  """
  def list_attacker_profiles(opts \\ []) do
    GenServer.call(__MODULE__, {:list_profiles, opts})
  end

  @doc """
  Get a specific attacker profile.
  """
  def get_attacker_profile(profile_id) do
    GenServer.call(__MODULE__, {:get_profile, profile_id})
  end

  @doc """
  Get attack timeline for a specific attacker or agent.
  """
  def get_timeline(opts \\ []) do
    GenServer.call(__MODULE__, {:get_timeline, opts})
  end

  @doc """
  Get extracted TTPs.
  """
  def get_ttps(opts \\ []) do
    GenServer.call(__MODULE__, {:get_ttps, opts})
  end

  @doc """
  Get indicators of compromise from deception data.
  """
  def get_indicators(opts \\ []) do
    GenServer.call(__MODULE__, {:get_indicators, opts})
  end

  @doc """
  Get analytics statistics.
  """
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Get active attacks in progress.
  """
  def get_active_attacks do
    GenServer.call(__MODULE__, :get_active_attacks)
  end

  @doc """
  Correlate interactions to identify attack campaigns.
  """
  def correlate_attacks do
    GenServer.call(__MODULE__, :correlate_attacks)
  end

  @doc """
  Generate threat intelligence report from deception data.
  """
  def generate_intel_report(opts \\ []) do
    GenServer.call(__MODULE__, {:generate_report, opts})
  end

  @doc """
  Get deployment effectiveness metrics.
  """
  def get_effectiveness_metrics do
    GenServer.call(__MODULE__, :get_effectiveness)
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    Logger.info("Starting Deception Analytics Engine")

    # Schedule periodic analysis
    schedule_analysis()

    {:ok, %__MODULE__{}}
  end

  @impl true
  def handle_cast({:record_interaction, event}, state) do
    Logger.info(
      "Recording deception interaction: #{event.interaction_type} on #{event.decoy_type}"
    )

    # Add to interactions list
    new_interactions = [event | state.interactions] |> Enum.take(10000)

    # Update or create attacker profile
    {profile_id, profiles} = update_attacker_profile(event, state.attacker_profiles)

    # Extract indicators
    new_indicators = extract_indicators(event, state.indicators)

    # Update active attacks
    active_attacks = update_active_attacks(event, profile_id, state.active_attacks)

    # Update statistics
    new_stats = update_interaction_stats(event, state.stats)

    new_state = %{
      state
      | interactions: new_interactions,
        attacker_profiles: profiles,
        indicators: new_indicators,
        active_attacks: active_attacks,
        stats: new_stats
    }

    # Trigger alert if high-value decoy accessed
    if high_value_decoy?(event.decoy_type) do
      broadcast_high_priority_alert(event)
    end

    {:noreply, new_state}
  end

  @impl true
  def handle_call({:list_profiles, opts}, _from, state) do
    profiles =
      state.attacker_profiles
      |> Map.values()
      |> filter_profiles(opts)
      |> Enum.sort_by(& &1.last_seen, {:desc, DateTime})

    {:reply, {:ok, profiles}, state}
  end

  @impl true
  def handle_call({:get_profile, profile_id}, _from, state) do
    case Map.get(state.attacker_profiles, profile_id) do
      nil -> {:reply, {:error, :not_found}, state}
      profile -> {:reply, {:ok, profile}, state}
    end
  end

  @impl true
  def handle_call({:get_timeline, opts}, _from, state) do
    timeline =
      state.interactions
      |> filter_interactions(opts)
      |> Enum.map(&interaction_to_timeline_event/1)
      |> Enum.sort_by(& &1.timestamp, {:desc, DateTime})
      |> Enum.take(Keyword.get(opts, :limit, 100))

    {:reply, {:ok, timeline}, state}
  end

  @impl true
  def handle_call({:get_ttps, opts}, _from, state) do
    ttps =
      state.attacker_profiles
      |> Map.values()
      |> filter_profiles(opts)
      |> Enum.flat_map(& &1.ttps)
      |> aggregate_ttps()
      |> Enum.sort_by(& &1.evidence_count, :desc)

    {:reply, {:ok, ttps}, state}
  end

  @impl true
  def handle_call({:get_indicators, opts}, _from, state) do
    indicators =
      state.indicators
      |> Map.values()
      |> List.flatten()
      |> filter_indicators(opts)
      |> Enum.sort_by(& &1.confidence, :desc)

    {:reply, {:ok, indicators}, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    stats =
      state.stats
      |> Map.put(:attacker_profiles, map_size(state.attacker_profiles))
      |> Map.put(:total_indicators, count_indicators(state.indicators))
      |> Map.put(:active_attacks, map_size(state.active_attacks))

    {:reply, {:ok, stats}, state}
  end

  @impl true
  def handle_call(:get_active_attacks, _from, state) do
    active =
      state.active_attacks
      |> Map.values()
      |> Enum.filter(&attack_is_active?/1)
      |> Enum.sort_by(& &1.last_activity, {:desc, DateTime})

    {:reply, {:ok, active}, state}
  end

  @impl true
  def handle_call(:correlate_attacks, _from, state) do
    campaigns = correlate_attack_campaigns(state)
    {:reply, {:ok, campaigns}, state}
  end

  @impl true
  def handle_call({:generate_report, opts}, _from, state) do
    report = generate_threat_intel_report(state, opts)
    {:reply, {:ok, report}, state}
  end

  @impl true
  def handle_call(:get_effectiveness, _from, state) do
    metrics = calculate_effectiveness_metrics(state)
    {:reply, {:ok, metrics}, state}
  end

  @impl true
  def handle_info(:periodic_analysis, state) do
    Logger.debug("Running periodic deception analysis")

    # Age out old active attacks
    now = DateTime.utc_now()

    active_attacks =
      state.active_attacks
      |> Enum.filter(fn {_id, attack} ->
        age_hours = DateTime.diff(now, attack.last_activity, :hour)
        age_hours < 24
      end)
      |> Map.new()

    # Recalculate risk scores
    profiles =
      state.attacker_profiles
      |> Enum.map(fn {id, profile} ->
        {id, %{profile | risk_score: calculate_risk_score(profile)}}
      end)
      |> Map.new()

    schedule_analysis()

    {:noreply, %{state | active_attacks: active_attacks, attacker_profiles: profiles}}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions - Profile Management
  # ============================================================================

  defp update_attacker_profile(event, profiles) do
    # Determine attacker identity (source IP or process context)
    attacker_key = determine_attacker_key(event)

    profile =
      case Map.get(profiles, attacker_key) do
        nil ->
          create_new_profile(attacker_key, event)

        existing ->
          update_existing_profile(existing, event)
      end

    {attacker_key, Map.put(profiles, attacker_key, profile)}
  end

  defp determine_attacker_key(event) do
    # Use source IP if available, otherwise use process context
    cond do
      event.source_ip && event.source_ip != "" ->
        "ip:#{event.source_ip}"

      event.process_name && event.user ->
        "local:#{event.agent_id}:#{event.user}:#{event.process_name}"

      true ->
        "unknown:#{event.agent_id}:#{event.event_id}"
    end
  end

  defp create_new_profile(id, event) do
    now = DateTime.utc_now()

    %{
      id: id,
      first_seen: now,
      last_seen: now,
      source_ips: if(event.source_ip, do: [event.source_ip], else: []),
      agents_targeted: [event.agent_id],
      decoy_interactions: 1,
      ttps: extract_ttps_from_event(event),
      risk_score: calculate_initial_risk_score(event),
      status: :active,
      indicators: [],
      timeline: [interaction_to_timeline_event(event)]
    }
  end

  defp update_existing_profile(profile, event) do
    %{
      profile
      | last_seen: DateTime.utc_now(),
        source_ips: add_unique(profile.source_ips, event.source_ip),
        agents_targeted: add_unique(profile.agents_targeted, event.agent_id),
        decoy_interactions: profile.decoy_interactions + 1,
        ttps: merge_ttps(profile.ttps, extract_ttps_from_event(event)),
        timeline:
          [interaction_to_timeline_event(event) | profile.timeline]
          |> Enum.take(100)
    }
  end

  defp add_unique(list, nil), do: list
  defp add_unique(list, value), do: Enum.uniq([value | list])

  # ============================================================================
  # Private Functions - TTP Extraction
  # ============================================================================

  defp extract_ttps_from_event(event) do
    now = DateTime.utc_now()

    event.mitre_techniques
    |> Enum.map(fn technique_id ->
      {tactic, name, sub} = get_technique_details(technique_id)

      %{
        tactic: tactic,
        technique_id: technique_id,
        technique_name: name,
        sub_technique: sub,
        evidence_count: 1,
        first_observed: now,
        last_observed: now
      }
    end)
  end

  defp merge_ttps(existing, new) do
    all = existing ++ new

    all
    |> Enum.group_by(& &1.technique_id)
    |> Enum.map(fn {_id, ttps} ->
      merged =
        Enum.reduce(ttps, fn ttp, acc ->
          %{
            acc
            | evidence_count: acc.evidence_count + ttp.evidence_count,
              first_observed: min_datetime(acc.first_observed, ttp.first_observed),
              last_observed: max_datetime(acc.last_observed, ttp.last_observed)
          }
        end)

      merged
    end)
  end

  defp aggregate_ttps(ttp_lists) do
    ttp_lists
    |> List.flatten()
    |> Enum.group_by(& &1.technique_id)
    |> Enum.map(fn {_id, ttps} ->
      Enum.reduce(ttps, fn ttp, acc ->
        %{
          acc
          | evidence_count: acc.evidence_count + ttp.evidence_count,
            first_observed: min_datetime(acc.first_observed, ttp.first_observed),
            last_observed: max_datetime(acc.last_observed, ttp.last_observed)
        }
      end)
    end)
  end

  defp get_technique_details(technique_id) do
    # Map technique IDs to details
    techniques = %{
      "T1552.001" => {"credential-access", "Unsecured Credentials: Credentials In Files", nil},
      "T1552.004" => {"credential-access", "Unsecured Credentials: Private Keys", nil},
      "T1555.003" => {"credential-access", "Credentials from Password Stores: Web Browsers", nil},
      "T1539" => {"credential-access", "Steal Web Session Cookie", nil},
      "T1021.004" => {"lateral-movement", "Remote Services: SSH", nil},
      "T1021.001" => {"lateral-movement", "Remote Services: RDP", nil},
      "T1021.002" => {"lateral-movement", "Remote Services: SMB", nil},
      "T1078.004" => {"persistence", "Valid Accounts: Cloud Accounts", nil},
      "T1110" => {"credential-access", "Brute Force", nil},
      "T1046" => {"discovery", "Network Service Scanning", nil},
      "T1135" => {"discovery", "Network Share Discovery", nil},
      "T1005" => {"collection", "Data from Local System", nil},
      "T1486" => {"impact", "Data Encrypted for Impact", nil}
    }

    Map.get(techniques, technique_id, {"unknown", technique_id, nil})
  end

  # ============================================================================
  # Private Functions - Indicator Extraction
  # ============================================================================

  defp extract_indicators(event, indicators) do
    now = DateTime.utc_now()
    new_indicators = []

    # Extract IP indicator
    new_indicators =
      if event.source_ip && event.source_ip != "" do
        indicator = %{
          type: :ip,
          value: event.source_ip,
          confidence: 0.9,
          first_seen: now,
          last_seen: now,
          context: %{
            decoy_type: event.decoy_type,
            agent_id: event.agent_id
          }
        }

        [indicator | new_indicators]
      else
        new_indicators
      end

    # Extract username indicator
    new_indicators =
      if event.credentials_captured && event.credentials_captured["username"] do
        indicator = %{
          type: :username,
          value: event.credentials_captured["username"],
          confidence: 0.8,
          first_seen: now,
          last_seen: now,
          context: %{
            decoy_type: event.decoy_type,
            auth_method: event.credentials_captured["auth_method"]
          }
        }

        [indicator | new_indicators]
      else
        new_indicators
      end

    # Add to existing indicators
    Enum.reduce(new_indicators, indicators, fn ind, acc ->
      key = "#{ind.type}:#{ind.value}"
      existing = Map.get(acc, key, [])
      Map.put(acc, key, [ind | existing])
    end)
  end

  defp filter_indicators(indicators, opts) do
    indicators
    |> Enum.filter(fn ind ->
      type_filter = Keyword.get(opts, :type)
      min_confidence = Keyword.get(opts, :min_confidence, 0.0)

      (is_nil(type_filter) || ind.type == type_filter) &&
        ind.confidence >= min_confidence
    end)
  end

  defp count_indicators(indicators) do
    indicators |> Map.values() |> List.flatten() |> length()
  end

  # ============================================================================
  # Private Functions - Active Attack Tracking
  # ============================================================================

  defp update_active_attacks(event, profile_id, active_attacks) do
    attack_key = "#{profile_id}:#{event.agent_id}"

    attack =
      case Map.get(active_attacks, attack_key) do
        nil ->
          %{
            id: attack_key,
            profile_id: profile_id,
            agent_id: event.agent_id,
            started_at: DateTime.utc_now(),
            last_activity: DateTime.utc_now(),
            interaction_count: 1,
            decoy_types_accessed: [event.decoy_type],
            status: :in_progress
          }

        existing ->
          %{
            existing
            | last_activity: DateTime.utc_now(),
              interaction_count: existing.interaction_count + 1,
              decoy_types_accessed:
                Enum.uniq([event.decoy_type | existing.decoy_types_accessed])
          }
      end

    Map.put(active_attacks, attack_key, attack)
  end

  defp attack_is_active?(attack) do
    age_minutes = DateTime.diff(DateTime.utc_now(), attack.last_activity, :minute)
    age_minutes < 60
  end

  # ============================================================================
  # Private Functions - Risk Scoring
  # ============================================================================

  defp calculate_initial_risk_score(event) do
    base_score =
      case event.decoy_type do
        :ssh_key -> 90
        :cloud_credential -> 95
        :api_token -> 85
        :kube_config -> 90
        :credential -> 80
        :browser_password -> 75
        :document -> 60
        _ -> 50
      end

    # Adjust based on interaction type
    interaction_modifier =
      case event.interaction_type do
        "auth_attempt" -> 10
        "credential_capture" -> 15
        "file_access" -> 5
        _ -> 0
      end

    min(100, base_score + interaction_modifier)
  end

  defp calculate_risk_score(profile) do
    base_score = 50

    # Factor in number of interactions
    interaction_score = min(20, profile.decoy_interactions * 2)

    # Factor in number of agents targeted
    agent_score = min(20, length(profile.agents_targeted) * 5)

    # Factor in TTP diversity
    ttp_score = min(10, length(profile.ttps) * 2)

    # Recency factor
    age_hours = DateTime.diff(DateTime.utc_now(), profile.last_seen, :hour)

    recency_score =
      cond do
        age_hours < 1 -> 10
        age_hours < 24 -> 5
        true -> 0
      end

    min(100, base_score + interaction_score + agent_score + ttp_score + recency_score)
  end

  # ============================================================================
  # Private Functions - Correlation & Analysis
  # ============================================================================

  defp correlate_attack_campaigns(state) do
    # Group profiles that share indicators or timing
    profiles = Map.values(state.attacker_profiles)

    # Simple correlation: profiles with overlapping IPs or close timing
    profiles
    |> Enum.group_by(fn profile ->
      # Use first source IP as campaign key, or time-based grouping
      List.first(profile.source_ips) || "campaign-#{div(:erlang.phash2(profile.id), 1000)}"
    end)
    |> Enum.map(fn {campaign_key, campaign_profiles} ->
      %{
        campaign_id: campaign_key,
        profile_count: length(campaign_profiles),
        total_interactions: Enum.sum(Enum.map(campaign_profiles, & &1.decoy_interactions)),
        agents_targeted:
          campaign_profiles
          |> Enum.flat_map(& &1.agents_targeted)
          |> Enum.uniq()
          |> length(),
        ttps: aggregate_ttps(Enum.map(campaign_profiles, & &1.ttps)),
        first_seen:
          campaign_profiles
          |> Enum.map(& &1.first_seen)
          |> Enum.min(DateTime),
        last_seen:
          campaign_profiles
          |> Enum.map(& &1.last_seen)
          |> Enum.max(DateTime)
      }
    end)
    |> Enum.sort_by(& &1.total_interactions, :desc)
  end

  defp generate_threat_intel_report(state, opts) do
    timeframe_hours = Keyword.get(opts, :timeframe_hours, 24)
    cutoff = DateTime.add(DateTime.utc_now(), -timeframe_hours * 3600, :second)

    recent_interactions =
      state.interactions
      |> Enum.filter(&(DateTime.compare(&1.timestamp, cutoff) == :gt))

    active_profiles =
      state.attacker_profiles
      |> Map.values()
      |> Enum.filter(&(DateTime.compare(&1.last_seen, cutoff) == :gt))

    %{
      generated_at: DateTime.utc_now(),
      timeframe_hours: timeframe_hours,
      summary: %{
        total_interactions: length(recent_interactions),
        unique_attackers: length(active_profiles),
        agents_targeted:
          recent_interactions
          |> Enum.map(& &1.agent_id)
          |> Enum.uniq()
          |> length(),
        high_risk_attackers:
          active_profiles
          |> Enum.filter(&(&1.risk_score >= 80))
          |> length()
      },
      top_ttps:
        active_profiles
        |> Enum.flat_map(& &1.ttps)
        |> aggregate_ttps()
        |> Enum.take(10),
      indicators:
        state.indicators
        |> Map.values()
        |> List.flatten()
        |> Enum.filter(&(DateTime.compare(&1.last_seen, cutoff) == :gt))
        |> Enum.sort_by(& &1.confidence, :desc)
        |> Enum.take(50),
      attacker_profiles:
        active_profiles
        |> Enum.sort_by(& &1.risk_score, :desc)
        |> Enum.take(10)
        |> Enum.map(&summarize_profile/1),
      recommendations: generate_recommendations(state)
    }
  end

  defp summarize_profile(profile) do
    %{
      id: profile.id,
      risk_score: profile.risk_score,
      interactions: profile.decoy_interactions,
      agents_targeted: length(profile.agents_targeted),
      top_ttps: Enum.take(profile.ttps, 5),
      first_seen: profile.first_seen,
      last_seen: profile.last_seen
    }
  end

  defp generate_recommendations(state) do
    recommendations = []

    # Check for active high-risk attackers
    high_risk_count =
      state.attacker_profiles
      |> Map.values()
      |> Enum.count(&(&1.risk_score >= 80 && &1.status == :active))

    recommendations =
      if high_risk_count > 0 do
        [
          %{
            type: :urgent,
            title: "High-Risk Attackers Detected",
            description:
              "#{high_risk_count} high-risk attackers are actively interacting with decoys",
            action: "Review attacker profiles and consider containment"
          }
          | recommendations
        ]
      else
        recommendations
      end

    # Check for lateral movement patterns
    lateral_movement_count =
      state.attacker_profiles
      |> Map.values()
      |> Enum.count(&(length(&1.agents_targeted) > 1))

    recommendations =
      if lateral_movement_count > 0 do
        [
          %{
            type: :warning,
            title: "Potential Lateral Movement",
            description: "#{lateral_movement_count} attackers targeting multiple endpoints",
            action: "Investigate network segmentation and access controls"
          }
          | recommendations
        ]
      else
        recommendations
      end

    # Check for credential theft patterns
    cred_theft_count =
      state.interactions
      |> Enum.count(&(&1.decoy_type in [:credential, :ssh_key, :api_token, :cloud_credential]))

    recommendations =
      if cred_theft_count > 5 do
        [
          %{
            type: :info,
            title: "Credential Decoys Active",
            description:
              "#{cred_theft_count} interactions with credential decoys detected",
            action: "Ensure production credentials are rotated and MFA is enforced"
          }
          | recommendations
        ]
      else
        recommendations
      end

    recommendations
  end

  defp calculate_effectiveness_metrics(state) do
    total_deployed = Breadcrumbs.get_stats() |> elem(1) |> Map.get(:total_breadcrumbs, 0)

    total_accessed =
      state.interactions
      |> length()

    detection_rate = if total_deployed > 0, do: total_accessed / total_deployed * 100, else: 0

    # Time to detection (average)
    ttd_samples =
      state.interactions
      |> Enum.take(100)
      |> Enum.map(fn interaction ->
        # Time from deployment to first access
        10
      end)

    avg_ttd = if length(ttd_samples) > 0, do: Enum.sum(ttd_samples) / length(ttd_samples), else: 0

    %{
      total_decoys_deployed: total_deployed,
      total_decoys_accessed: total_accessed,
      detection_rate_percent: Float.round(detection_rate, 2),
      average_time_to_detection_minutes: Float.round(avg_ttd, 2),
      unique_attackers_detected: map_size(state.attacker_profiles),
      ttps_extracted: state.stats.ttps_extracted,
      indicators_generated: count_indicators(state.indicators),
      decoy_effectiveness_by_type: calculate_effectiveness_by_type(state)
    }
  end

  defp calculate_effectiveness_by_type(state) do
    state.interactions
    |> Enum.group_by(& &1.decoy_type)
    |> Enum.map(fn {type, interactions} ->
      {type, length(interactions)}
    end)
    |> Map.new()
  end

  # ============================================================================
  # Private Functions - Utilities
  # ============================================================================

  defp interaction_to_timeline_event(event) do
    %{
      timestamp: event.timestamp,
      event_type: event.interaction_type,
      agent_id: event.agent_id,
      decoy_type: event.decoy_type,
      decoy_id: event.decoy_id,
      source_ip: event.source_ip,
      details: event.metadata,
      mitre_technique: List.first(event.mitre_techniques)
    }
  end

  defp filter_profiles(profiles, opts) do
    profiles
    |> Enum.filter(fn profile ->
      status_filter = Keyword.get(opts, :status)
      min_score = Keyword.get(opts, :min_risk_score, 0)

      (is_nil(status_filter) || profile.status == status_filter) &&
        profile.risk_score >= min_score
    end)
  end

  defp filter_interactions(interactions, opts) do
    interactions
    |> Enum.filter(fn int ->
      agent_filter = Keyword.get(opts, :agent_id)
      type_filter = Keyword.get(opts, :decoy_type)

      (is_nil(agent_filter) || int.agent_id == agent_filter) &&
        (is_nil(type_filter) || int.decoy_type == type_filter)
    end)
  end

  defp update_interaction_stats(event, stats) do
    stats
    |> Map.update!(:total_interactions, &(&1 + 1))
    |> update_in([:by_tactic], fn by_tactic ->
      tactic = get_primary_tactic(event.mitre_techniques)
      Map.update(by_tactic, tactic, 1, &(&1 + 1))
    end)
    |> update_in([:by_technique], fn by_technique ->
      Enum.reduce(event.mitre_techniques, by_technique, fn tech, acc ->
        Map.update(acc, tech, 1, &(&1 + 1))
      end)
    end)
    |> update_in([:by_decoy_type], fn by_type ->
      Map.update(by_type, event.decoy_type, 1, &(&1 + 1))
    end)
  end

  defp get_primary_tactic([technique_id | _]) do
    {tactic, _, _} = get_technique_details(technique_id)
    tactic
  end

  defp get_primary_tactic([]), do: "unknown"

  defp high_value_decoy?(type) do
    type in [:ssh_key, :cloud_credential, :api_token, :kube_config]
  end

  defp broadcast_high_priority_alert(event) do
    alert = %{
      type: "deception_high_value",
      severity: "critical",
      title: "High-Value Decoy Accessed",
      description:
        "A #{event.decoy_type} decoy was accessed on agent #{event.agent_id}",
      source_ip: event.source_ip,
      mitre_techniques: event.mitre_techniques,
      timestamp: DateTime.utc_now()
    }

    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "deception:alerts",
      {:high_priority_alert, alert}
    )
  end

  defp min_datetime(dt1, dt2) do
    if DateTime.compare(dt1, dt2) == :lt, do: dt1, else: dt2
  end

  defp max_datetime(dt1, dt2) do
    if DateTime.compare(dt1, dt2) == :gt, do: dt1, else: dt2
  end

  defp schedule_analysis do
    # Run analysis every 15 minutes
    Process.send_after(self(), :periodic_analysis, :timer.minutes(15))
  end
end
