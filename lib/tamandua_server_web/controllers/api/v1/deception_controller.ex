defmodule TamanduaServerWeb.API.V1.DeceptionController do
  @moduledoc """
  API controller for Deception Technology management.

  Provides endpoints for:
  - Breadcrumb/decoy management
  - Attacker profile viewing
  - Deception analytics
  - Indicator extraction
  - Threat intelligence from deception
  """

  use TamanduaServerWeb, :controller
  require Logger

  alias TamanduaServer.Deception.{Breadcrumbs, Analytics}
  alias TamanduaServer.Agents

  # ============================================================================
  # Statistics & Overview
  # ============================================================================

  @doc """
  Get overall deception statistics.
  """
  def stats(conn, _params) do
    {:ok, breadcrumb_stats} = Breadcrumbs.get_stats()
    {:ok, analytics_stats} = Analytics.get_stats()

    stats = %{
      totalDecoys: Map.get(breadcrumb_stats, :total_breadcrumbs, 0),
      activeDecoys: Map.get(breadcrumb_stats, :active_breadcrumbs, 0),
      accessedDecoys: Map.get(breadcrumb_stats, :accessed_breadcrumbs, 0),
      uniqueAttackers: Map.get(analytics_stats, :attacker_profiles, 0),
      totalInteractions: Map.get(analytics_stats, :total_interactions, 0),
      interactionsToday: get_interactions_today(analytics_stats),
      ttpsExtracted: Map.get(analytics_stats, :ttps_extracted, 0),
      indicatorsGenerated: Map.get(analytics_stats, :total_indicators, 0),
      agentsWithDecoys: Map.get(breadcrumb_stats, :agents_with_breadcrumbs, 0),
      detectionRate: calculate_detection_rate(breadcrumb_stats)
    }

    json(conn, %{stats: stats})
  end

  @doc """
  Get comprehensive dashboard data.
  """
  def dashboard(conn, params) do
    limit = Map.get(params, "limit", 20) |> parse_int(20)
    organization_id = conn.assigns[:current_user].organization_id

    {:ok, breadcrumb_stats} = Breadcrumbs.get_stats()
    {:ok, analytics_stats} = Analytics.get_stats()
    {:ok, breadcrumbs} = Breadcrumbs.list_breadcrumbs(limit: limit)
    {:ok, attackers} = Analytics.list_attacker_profiles(limit: limit)
    {:ok, indicators} = Analytics.get_indicators(limit: 50)
    {:ok, profiles} = Breadcrumbs.list_profiles()
    {:ok, timeline} = Analytics.get_timeline(limit: limit)
    {:ok, active_attacks} = Analytics.get_active_attacks()

    stats = %{
      totalDecoys: Map.get(breadcrumb_stats, :total_breadcrumbs, 0),
      activeDecoys: Map.get(breadcrumb_stats, :active_breadcrumbs, 0),
      accessedDecoys: Map.get(breadcrumb_stats, :accessed_breadcrumbs, 0),
      uniqueAttackers: Map.get(analytics_stats, :attacker_profiles, 0),
      totalInteractions: Map.get(analytics_stats, :total_interactions, 0),
      interactionsToday: get_interactions_today(analytics_stats),
      ttpsExtracted: Map.get(analytics_stats, :ttps_extracted, 0),
      indicatorsGenerated: Map.get(analytics_stats, :total_indicators, 0),
      agentsWithDecoys: Map.get(breadcrumb_stats, :agents_with_breadcrumbs, 0),
      detectionRate: calculate_detection_rate(breadcrumb_stats)
    }

    # Generate recommendations (scoped to organization for multi-tenancy)
    recommendations = generate_recommendations(breadcrumbs, attackers, analytics_stats, organization_id)

    json(conn, %{
      stats: stats,
      breadcrumbs: Enum.map(breadcrumbs, &serialize_breadcrumb/1),
      attackers: Enum.map(attackers, &serialize_attacker/1),
      indicators: Enum.map(indicators, &serialize_indicator/1),
      profiles: Enum.map(profiles, &serialize_profile/1),
      timeline: Enum.map(timeline, &serialize_timeline_event/1),
      activeAttacks: Enum.map(active_attacks, &serialize_active_attack/1),
      recommendations: recommendations
    })
  end

  # ============================================================================
  # Breadcrumb Management
  # ============================================================================

  @doc """
  List all breadcrumbs/decoys.
  """
  def list_breadcrumbs(conn, params) do
    opts = [
      status: parse_atom(params["status"]),
      type: parse_atom(params["type"]),
      agent_id: params["agent_id"],
      limit: parse_int(params["limit"], 100)
    ] |> Keyword.reject(fn {_k, v} -> is_nil(v) end)

    {:ok, breadcrumbs} = Breadcrumbs.list_breadcrumbs(opts)

    json(conn, %{
      breadcrumbs: Enum.map(breadcrumbs, &serialize_breadcrumb/1),
      total: length(breadcrumbs)
    })
  end

  @doc """
  Get breadcrumbs for a specific agent.
  """
  def agent_breadcrumbs(conn, %{"agent_id" => agent_id}) do
    case Breadcrumbs.get_agent_breadcrumbs(agent_id) do
      {:ok, breadcrumbs} ->
        {:ok, recommendations} = Breadcrumbs.get_recommendations(agent_id)

        json(conn, %{
          agentId: agent_id,
          breadcrumbs: Enum.map(breadcrumbs, &serialize_breadcrumb/1),
          total: length(breadcrumbs),
          recommendations: recommendations
        })

      {:error, reason} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: to_string(reason)})
    end
  end

  @doc """
  Deploy breadcrumbs to an agent.
  """
  def deploy_to_agent(conn, %{"agent_id" => agent_id} = params) do
    opts = [
      types: parse_types(params["types"]),
      density: parse_atom(params["density"]) || :medium
    ] |> Keyword.reject(fn {_k, v} -> is_nil(v) end)

    case Breadcrumbs.deploy_to_agent(agent_id, opts) do
      {:ok, count} ->
        Logger.info("Deployed #{count} breadcrumbs to agent #{agent_id}")

        json(conn, %{
          success: true,
          agentId: agent_id,
          deployed: count,
          message: "Successfully deployed #{count} breadcrumbs"
        })

      {:error, :agent_not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Agent not found"})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: to_string(reason)})
    end
  end

  @doc """
  Deploy breadcrumbs by profile.
  """
  def deploy_by_profile(conn, %{"profile_id" => profile_id}) do
    case Breadcrumbs.deploy_by_profile(profile_id) do
      {:ok, result} ->
        Logger.info("Deployed breadcrumbs using profile #{profile_id}: #{inspect(result)}")

        json(conn, %{
          success: true,
          profileId: profile_id,
          agentsDeployed: result.agents,
          breadcrumbsDeployed: result.breadcrumbs
        })

      {:error, :profile_not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Profile not found"})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: to_string(reason)})
    end
  end

  @doc """
  Rotate breadcrumbs for an agent.
  """
  def rotate_breadcrumbs(conn, %{"agent_id" => agent_id}) do
    case Breadcrumbs.rotate_agent_breadcrumbs(agent_id) do
      {:ok, count} ->
        Logger.info("Rotated #{count} breadcrumbs for agent #{agent_id}")

        json(conn, %{
          success: true,
          agentId: agent_id,
          rotated: count,
          message: "Successfully rotated #{count} breadcrumbs"
        })

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: to_string(reason)})
    end
  end

  # ============================================================================
  # Deployment Profiles
  # ============================================================================

  @doc """
  List deployment profiles.
  """
  def list_profiles(conn, _params) do
    {:ok, profiles} = Breadcrumbs.list_profiles()

    json(conn, %{
      profiles: Enum.map(profiles, &serialize_profile/1)
    })
  end

  @doc """
  Create or update a deployment profile.
  """
  def upsert_profile(conn, params) do
    profile = %{
      id: params["id"],
      name: params["name"],
      description: params["description"],
      decoy_types: parse_types(params["decoy_types"]),
      target_paths: params["target_paths"] || [],
      os_types: parse_os_types(params["os_types"]),
      density: parse_atom(params["density"]) || :medium,
      rotation_interval_hours: parse_int(params["rotation_interval_hours"], 168),
      enabled: params["enabled"] != false
    }

    case Breadcrumbs.upsert_profile(profile) do
      {:ok, saved_profile} ->
        json(conn, %{
          success: true,
          profile: serialize_profile(saved_profile)
        })

      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: to_string(reason)})
    end
  end

  # ============================================================================
  # Attacker Profiles
  # ============================================================================

  @doc """
  List attacker profiles.
  """
  def list_attackers(conn, params) do
    opts = [
      status: parse_atom(params["status"]),
      min_risk_score: parse_int(params["min_risk_score"], 0),
      limit: parse_int(params["limit"], 50)
    ] |> Keyword.reject(fn {_k, v} -> is_nil(v) end)

    {:ok, attackers} = Analytics.list_attacker_profiles(opts)

    json(conn, %{
      attackers: Enum.map(attackers, &serialize_attacker/1),
      total: length(attackers)
    })
  end

  @doc """
  Get a specific attacker profile.
  """
  def show_attacker(conn, %{"id" => id}) do
    case Analytics.get_attacker_profile(id) do
      {:ok, attacker} ->
        json(conn, %{attacker: serialize_attacker(attacker)})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Attacker profile not found"})
    end
  end

  # ============================================================================
  # Analytics & Intelligence
  # ============================================================================

  @doc """
  Get attack timeline.
  """
  def timeline(conn, params) do
    opts = [
      agent_id: params["agent_id"],
      decoy_type: parse_atom(params["decoy_type"]),
      limit: parse_int(params["limit"], 100)
    ] |> Keyword.reject(fn {_k, v} -> is_nil(v) end)

    {:ok, events} = Analytics.get_timeline(opts)

    json(conn, %{
      timeline: Enum.map(events, &serialize_timeline_event/1),
      total: length(events)
    })
  end

  @doc """
  Get extracted TTPs.
  """
  def ttps(conn, params) do
    opts = [
      attacker_id: params["attacker_id"],
      limit: parse_int(params["limit"], 100)
    ] |> Keyword.reject(fn {_k, v} -> is_nil(v) end)

    {:ok, ttps} = Analytics.get_ttps(opts)

    json(conn, %{
      ttps: Enum.map(ttps, &serialize_ttp/1),
      total: length(ttps)
    })
  end

  @doc """
  Get indicators of compromise.
  """
  def indicators(conn, params) do
    opts = [
      type: parse_atom(params["type"]),
      min_confidence: parse_float(params["min_confidence"], 0.0),
      limit: parse_int(params["limit"], 100)
    ] |> Keyword.reject(fn {_k, v} -> is_nil(v) end)

    {:ok, indicators} = Analytics.get_indicators(opts)

    json(conn, %{
      indicators: Enum.map(indicators, &serialize_indicator/1),
      total: length(indicators)
    })
  end

  @doc """
  Get active attacks in progress.
  """
  def active_attacks(conn, _params) do
    {:ok, attacks} = Analytics.get_active_attacks()

    json(conn, %{
      activeAttacks: Enum.map(attacks, &serialize_active_attack/1),
      total: length(attacks)
    })
  end

  @doc """
  Correlate attacks into campaigns.
  """
  def correlate(conn, _params) do
    {:ok, campaigns} = Analytics.correlate_attacks()

    json(conn, %{
      campaigns: campaigns,
      total: length(campaigns)
    })
  end

  @doc """
  Generate threat intelligence report.
  """
  def intel_report(conn, params) do
    opts = [
      timeframe_hours: parse_int(params["timeframe_hours"], 24),
      format: params["format"] || "json"
    ]

    {:ok, report} = Analytics.generate_intel_report(opts)

    case opts[:format] do
      "stix" ->
        conn
        |> put_resp_content_type("application/json")
        |> send_resp(200, convert_to_stix(report))

      _ ->
        json(conn, %{report: report})
    end
  end

  @doc """
  Get deception effectiveness metrics.
  """
  def effectiveness(conn, _params) do
    {:ok, metrics} = Analytics.get_effectiveness_metrics()

    json(conn, %{metrics: metrics})
  end

  # ============================================================================
  # Interaction Recording (called by agents)
  # ============================================================================

  @doc """
  Record a deception interaction event from an agent.
  """
  def record_interaction(conn, params) do
    event = %{
      event_id: params["event_id"] || Ecto.UUID.generate(),
      agent_id: params["agent_id"],
      timestamp: parse_timestamp(params["timestamp"]),
      decoy_type: parse_atom(params["decoy_type"]) || :unknown,
      decoy_id: params["decoy_id"],
      canary_token: params["canary_token"],
      interaction_type: params["interaction_type"],
      source_ip: params["source_ip"],
      source_port: params["source_port"],
      process_name: params["process_name"],
      process_pid: params["process_pid"],
      user: params["user"],
      credentials_captured: params["credentials_captured"],
      data_captured: params["data_captured"],
      mitre_techniques: params["mitre_techniques"] || [],
      metadata: params["metadata"] || %{}
    }

    Analytics.record_interaction(event)

    # Also record in breadcrumbs if we have a canary token
    if event.canary_token do
      Breadcrumbs.record_access(event.agent_id, event.canary_token, %{
        timestamp: event.timestamp,
        source_ip: event.source_ip,
        process_name: event.process_name
      })
    end

    Logger.warning(
      "Deception triggered: #{event.interaction_type} on #{event.decoy_type} " <>
      "agent=#{event.agent_id} source_ip=#{event.source_ip}"
    )

    json(conn, %{success: true, eventId: event.event_id})
  end

  # ============================================================================
  # Serialization
  # ============================================================================

  defp serialize_breadcrumb(bc) do
    agent_hostname = get_agent_hostname(bc.agent_id)

    %{
      id: bc.id,
      type: to_string(bc.type),
      agentId: bc.agent_id,
      agentHostname: agent_hostname,
      path: bc.path,
      canaryToken: bc.canary_token,
      status: to_string(bc.status),
      deployedAt: format_datetime(bc.deployed_at),
      lastRotatedAt: format_datetime(bc.last_rotated_at),
      accessCount: bc.access_count,
      contentHash: bc.content_hash
    }
  end

  defp serialize_profile(profile) do
    %{
      id: profile.id,
      name: profile.name,
      description: profile.description,
      decoyTypes: Enum.map(profile.decoy_types, &to_string/1),
      targetPaths: profile.target_paths,
      osTypes: Enum.map(profile.os_types, &to_string/1),
      density: to_string(profile.density),
      rotationIntervalHours: profile.rotation_interval_hours,
      enabled: profile.enabled
    }
  end

  defp serialize_attacker(attacker) do
    %{
      id: attacker.id,
      riskScore: attacker.risk_score,
      firstSeen: format_datetime(attacker.first_seen),
      lastSeen: format_datetime(attacker.last_seen),
      sourceIps: attacker.source_ips,
      agentsTargeted: attacker.agents_targeted,
      interactions: attacker.decoy_interactions,
      ttps: Enum.map(attacker.ttps, &serialize_ttp/1),
      status: to_string(attacker.status)
    }
  end

  defp serialize_ttp(ttp) do
    %{
      tactic: ttp.tactic,
      techniqueId: ttp.technique_id,
      techniqueName: ttp.technique_name,
      subTechnique: ttp.sub_technique,
      evidenceCount: ttp.evidence_count,
      firstObserved: format_datetime(ttp.first_observed),
      lastObserved: format_datetime(ttp.last_observed)
    }
  end

  defp serialize_indicator(indicator) do
    %{
      type: to_string(indicator.type),
      value: indicator.value,
      confidence: indicator.confidence,
      firstSeen: format_datetime(indicator.first_seen),
      lastSeen: format_datetime(indicator.last_seen),
      context: indicator.context
    }
  end

  defp serialize_timeline_event(event) do
    agent_hostname = get_agent_hostname(event.agent_id)

    %{
      timestamp: format_datetime(event.timestamp),
      eventType: event.event_type,
      agentId: event.agent_id,
      agentHostname: agent_hostname,
      decoyType: to_string(event.decoy_type),
      decoyId: event.decoy_id,
      sourceIp: event.source_ip,
      mitreTechnique: event.mitre_technique,
      details: event.details
    }
  end

  defp serialize_active_attack(attack) do
    %{
      id: attack.id,
      profileId: attack.profile_id,
      agentId: attack.agent_id,
      startedAt: format_datetime(attack.started_at),
      lastActivity: format_datetime(attack.last_activity),
      interactionCount: attack.interaction_count,
      decoyTypesAccessed: Enum.map(attack.decoy_types_accessed, &to_string/1),
      status: to_string(attack.status)
    }
  end

  # ============================================================================
  # Helpers
  # ============================================================================

  defp get_agent_hostname(agent_id) do
    case Agents.get_agent(agent_id) do
      {:ok, agent} -> agent.hostname
      _ -> "Unknown"
    end
  end

  defp get_interactions_today(stats) do
    # This would ideally filter by today's date
    Map.get(stats, :total_interactions, 0)
  end

  defp calculate_detection_rate(stats) do
    total = Map.get(stats, :total_breadcrumbs, 0)
    accessed = Map.get(stats, :accessed_breadcrumbs, 0)

    if total > 0 do
      Float.round(accessed / total * 100, 1)
    else
      0.0
    end
  end

  defp generate_recommendations(breadcrumbs, attackers, _stats, organization_id) do
    recommendations = []

    # Check for high-risk attackers
    high_risk = Enum.filter(attackers, &(&1.risk_score >= 80))
    recommendations = if length(high_risk) > 0 do
      [%{
        type: "investigate",
        priority: "critical",
        title: "#{length(high_risk)} High-Risk Attackers Detected",
        description: "Immediate investigation recommended for active attackers with high risk scores"
      } | recommendations]
    else
      recommendations
    end

    # Check for agents without decoys (scoped to organization for multi-tenancy)
    agents_with_decoys = breadcrumbs
      |> Enum.map(& &1.agent_id)
      |> Enum.uniq()
      |> MapSet.new()

    all_agents = Agents.list_all_for_org(organization_id)
    agents_without = Enum.reject(all_agents, &MapSet.member?(agents_with_decoys, &1[:agent_id] || &1.id))

    recommendations = if length(agents_without) > 0 do
      [%{
        type: "add_decoy",
        priority: "medium",
        title: "#{length(agents_without)} Agents Without Decoys",
        description: "Consider deploying breadcrumbs to improve detection coverage"
      } | recommendations]
    else
      recommendations
    end

    # Check for stale decoys
    stale_count = breadcrumbs
      |> Enum.filter(fn bc ->
        age_days = DateTime.diff(DateTime.utc_now(), bc.deployed_at, :day)
        age_days > 30 && bc.status == :active
      end)
      |> length()

    recommendations = if stale_count > 5 do
      [%{
        type: "rotate",
        priority: "low",
        title: "#{stale_count} Stale Decoys",
        description: "Some decoys have not been rotated in over 30 days"
      } | recommendations]
    else
      recommendations
    end

    recommendations
  end

  defp convert_to_stix(report) do
    # Convert report to STIX 2.1 format
    stix_bundle = %{
      type: "bundle",
      id: "bundle--#{Ecto.UUID.generate()}",
      objects: []
    }

    # Add indicators
    indicator_objects = Enum.map(report.indicators, fn ind ->
      %{
        type: "indicator",
        id: "indicator--#{Ecto.UUID.generate()}",
        created: DateTime.to_iso8601(DateTime.utc_now()),
        modified: DateTime.to_iso8601(DateTime.utc_now()),
        name: "#{ind.type}: #{ind.value}",
        indicator_types: ["malicious-activity"],
        pattern: build_stix_pattern(ind),
        pattern_type: "stix",
        valid_from: ind.first_seen,
        confidence: round(ind.confidence * 100),
        labels: ["deception-derived"]
      }
    end)

    # Add attack patterns for TTPs
    ttp_objects = Enum.map(report.top_ttps, fn ttp ->
      %{
        type: "attack-pattern",
        id: "attack-pattern--#{Ecto.UUID.generate()}",
        created: DateTime.to_iso8601(DateTime.utc_now()),
        modified: DateTime.to_iso8601(DateTime.utc_now()),
        name: ttp.technique_name,
        external_references: [
          %{
            source_name: "mitre-attack",
            external_id: ttp.technique_id,
            url: "https://attack.mitre.org/techniques/#{ttp.technique_id}/"
          }
        ]
      }
    end)

    %{stix_bundle | objects: indicator_objects ++ ttp_objects}
    |> Jason.encode!()
  end

  defp build_stix_pattern(indicator) do
    case indicator.type do
      :ip -> "[ipv4-addr:value = '#{indicator.value}']"
      :domain -> "[domain-name:value = '#{indicator.value}']"
      :username -> "[user-account:user_id = '#{indicator.value}']"
      _ -> "[x-tamandua:value = '#{indicator.value}']"
    end
  end

  defp parse_int(nil, default), do: default
  defp parse_int(val, default) when is_binary(val) do
    case Integer.parse(val) do
      {int, _} -> int
      :error -> default
    end
  end
  defp parse_int(val, _default) when is_integer(val), do: val

  defp parse_float(nil, default), do: default
  defp parse_float(val, default) when is_binary(val) do
    case Float.parse(val) do
      {float, _} -> float
      :error -> default
    end
  end
  defp parse_float(val, _default) when is_float(val), do: val

  defp parse_atom(nil), do: nil
  defp parse_atom(val) when is_atom(val), do: val
  defp parse_atom(val) when is_binary(val) do
    try do
      String.to_existing_atom(val)
    rescue
      ArgumentError -> nil
    end
  end

  defp parse_types(nil), do: nil
  defp parse_types(types) when is_list(types) do
    Enum.map(types, &parse_atom/1)
  end
  defp parse_types(types) when is_binary(types) do
    types
    |> String.split(",")
    |> Enum.map(&String.trim/1)
    |> Enum.map(&parse_atom/1)
  end

  defp parse_os_types(nil), do: [:windows, :linux, :macos]
  defp parse_os_types(types) when is_list(types) do
    Enum.map(types, &parse_atom/1)
  end
  defp parse_os_types(types) when is_binary(types) do
    types
    |> String.split(",")
    |> Enum.map(&String.trim/1)
    |> Enum.map(&parse_atom/1)
  end

  defp parse_timestamp(nil), do: DateTime.utc_now()
  defp parse_timestamp(ts) when is_binary(ts) do
    case DateTime.from_iso8601(ts) do
      {:ok, dt, _} -> dt
      _ -> DateTime.utc_now()
    end
  end
  defp parse_timestamp(%DateTime{} = dt), do: dt
  defp parse_timestamp(ts) when is_integer(ts) do
    DateTime.from_unix!(ts, :millisecond)
  end

  defp format_datetime(nil), do: nil
  defp format_datetime(%DateTime{} = dt) do
    DateTime.to_iso8601(dt)
  end
  defp format_datetime(dt) when is_binary(dt), do: dt
end
