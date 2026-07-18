defmodule TamanduaServer.Agents.Geofencing do
  @moduledoc """
  Core geofencing engine that evaluates rules and enforces policies
  based on agent location.

  Features:
  - Rule evaluation (expected/allowed/restricted regions)
  - Policy enforcement (MFA, isolation, restrictions)
  - Alert generation for unexpected locations
  - Travel request approval
  """

  require Logger
  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Agents.{
    Agent,
    AgentCommand,
    GeofencingRule,
    GeoPolicy,
    GeoPolicyEnforcement,
    GeoTravelRequest,
    LocationTracker,
    Registry
  }
  alias TamanduaServer.Alerts.Alert

  @doc """
  Evaluate geofencing for an agent's current location.
  This is called whenever an agent connects or changes location.
  """
  def evaluate_location(agent_id) do
    with {:ok, agent} <- get_agent(agent_id),
         {:ok, location} <- LocationTracker.get_current_location(agent_id),
         rules <- get_applicable_rules(agent),
         policies <- get_applicable_policies(location, agent.organization_id) do
      # Evaluate rules
      rule_results = Enum.map(rules, &evaluate_rule(&1, location, agent))

      # Check for violations
      violations =
        rule_results
        |> Enum.filter(fn {_rule, result} -> result.violation end)
        |> Enum.sort_by(fn {rule, _result} -> rule.priority end, :desc)

      # Enforce policies
      policy_results = Enum.map(policies, &enforce_policy(&1, agent, location))

      # Generate alerts for violations
      for {rule, result} <- violations do
        generate_geofence_alert(agent, location, rule, result)
      end

      # Check for travel requests
      approved_travel = check_travel_approval(agent_id, location)

      {:ok,
       %{
         location: location,
         rules_evaluated: length(rules),
         violations: length(violations),
         policies_enforced: length(policy_results),
         approved_travel: approved_travel
       }}
    end
  end

  @doc """
  Get applicable geofencing rules for an agent.
  """
  def get_applicable_rules(agent) do
    query =
      from r in GeofencingRule,
        where: r.organization_id == ^agent.organization_id and r.is_enabled == true,
        order_by: [desc: r.priority]

    Repo.all(query)
    |> Enum.filter(&rule_applies_to_agent?(&1, agent))
  end

  @doc """
  Check if a rule applies to a specific agent.
  """
  def rule_applies_to_agent?(rule, agent) do
    case rule.scope_type do
      "all" ->
        true

      "agent" ->
        agent.id in rule.scope_ids

      "group" ->
        # Check if agent is in any of the groups
        agent_groups = get_agent_groups(agent.id)
        Enum.any?(rule.scope_ids, &(&1 in agent_groups))

      "tag" ->
        # Check if agent has any of the tags
        Enum.any?(rule.scope_tags, &(&1 in agent.tags))

      _ ->
        false
    end
  end

  @doc """
  Evaluate a geofencing rule against a location.
  """
  def evaluate_rule(rule, location, _agent) do
    result = %{
      violation: false,
      type: nil,
      message: nil,
      should_alert: false,
      should_isolate: false
    }

    cond do
      # Check if in restricted region
      location.is_restricted || has_region_overlap?(location.matched_region_ids, rule.restricted_region_ids) ->
        {rule,
         %{
           result
           | violation: true,
             type: :restricted_region,
             message: "Agent in restricted region: #{location.country_name}",
             should_alert: true,
             should_isolate: rule.auto_isolate_restricted
         }}

      # Check if in expected or allowed region
      has_region_overlap?(location.matched_region_ids, rule.expected_region_ids) ||
          has_region_overlap?(location.matched_region_ids, rule.allowed_region_ids) ->
        {rule, result}

      # Unexpected location
      rule.alert_on_unexpected ->
        {rule,
         %{
           result
           | violation: true,
             type: :unexpected_location,
             message: "Agent in unexpected location: #{location.country_name}, #{location.city}",
             should_alert: true,
             should_isolate: false
         }}

      true ->
        {rule, result}
    end
  end

  @doc """
  Get applicable geo policies for a location.
  """
  def get_applicable_policies(location, organization_id) do
    query =
      from p in GeoPolicy,
        where: p.organization_id == ^organization_id and p.is_enabled == true,
        order_by: [desc: p.priority]

    Repo.all(query)
    |> Enum.filter(&policy_applies_to_location?(&1, location))
  end

  @doc """
  Check if a policy applies to a specific location.
  """
  def policy_applies_to_location?(policy, location) do
    cond do
      # Apply to restricted regions
      policy.apply_to_restricted && location.is_restricted ->
        true

      # Apply to unexpected regions
      policy.apply_to_unexpected && location.is_expected == false ->
        true

      # Apply to specific regions
      has_region_overlap?(location.matched_region_ids, policy.region_ids) ->
        true

      true ->
        false
    end
  end

  @doc """
  Enforce a geo policy on an agent.
  """
  def enforce_policy(policy, agent, location) do
    enforcements = []

    # MFA required
    enforcements =
      if policy.require_mfa do
        [enforce_mfa(policy, agent, location) | enforcements]
      else
        enforcements
      end

    # Feature restrictions
    enforcements =
      if not Enum.empty?(policy.disable_features) do
        [enforce_feature_restrictions(policy, agent, location) | enforcements]
      else
        enforcements
      end

    # File restrictions
    enforcements =
      if policy.restrict_file_downloads || policy.restrict_file_uploads do
        [enforce_file_restrictions(policy, agent, location) | enforcements]
      else
        enforcements
      end

    # Enhanced monitoring
    enforcements =
      if policy.enhanced_monitoring do
        [enforce_enhanced_monitoring(policy, agent, location) | enforcements]
      else
        enforcements
      end

    # Auto-isolate
    enforcements =
      if policy.auto_isolate do
        [enforce_isolation(policy, agent, location) | enforcements]
      else
        enforcements
      end

    # Send alert
    enforcements =
      if policy.send_alert do
        [send_policy_alert(policy, agent, location) | enforcements]
      else
        enforcements
      end

    enforcements
  end

  ## Private Functions

  defp get_agent(agent_id) do
    case Repo.get(Agent, agent_id) do
      nil -> {:error, :agent_not_found}
      agent -> {:ok, agent}
    end
  end

  defp has_region_overlap?(list1, list2) do
    MapSet.intersection(MapSet.new(list1 || []), MapSet.new(list2 || []))
    |> MapSet.size() > 0
  end

  defp get_agent_groups(agent_id) do
    # Query agent group memberships
    query =
      from m in TamanduaServer.Agents.GroupMember,
        where: m.agent_id == ^agent_id,
        select: m.group_id

    Repo.all(query)
  end

  defp check_travel_approval(agent_id, _location) do
    today = Date.utc_today()

    query =
      from t in GeoTravelRequest,
        where:
          t.agent_id == ^agent_id and
            t.status == "approved" and
            t.start_date <= ^today and
            t.end_date >= ^today

    case Repo.one(query) do
      nil -> nil
      travel -> travel
    end
  end

  defp generate_geofence_alert(agent, location, rule, result) do
    alert_attrs = %{
      organization_id: agent.organization_id,
      agent_id: agent.id,
      severity: rule.alert_severity,
      title: "Geofencing Violation: #{result.type}",
      description: result.message,
      mitre_tactics: ["TA0001"],
      # Initial Access
      mitre_techniques: ["T1078"],
      # Valid Accounts
      status: "new",
      enrichment: %{
        location: %{
          country: location.country_name,
          city: location.city,
          latitude: location.latitude,
          longitude: location.longitude,
          is_vpn: location.is_vpn,
          vpn_provider: location.vpn_provider
        },
        rule: %{
          id: rule.id,
          name: rule.name,
          violation_type: result.type
        }
      }
    }

    %Alert{}
    |> Alert.changeset(alert_attrs)
    |> Repo.insert()
  end

  defp enforce_mfa(policy, agent, location) do
    # Update agent's geo_restrictions to require MFA
    restrictions = Map.get(agent, :geo_restrictions, %{})
    new_restrictions = Map.put(restrictions, "require_mfa", true)

    agent
    |> Ecto.Changeset.change(geo_restrictions: new_restrictions)
    |> Repo.update()

    log_enforcement(policy, agent, location, "mfa_required", %{
      enabled: true
    })
  end

  defp enforce_feature_restrictions(policy, agent, location) do
    restrictions = Map.get(agent, :geo_restrictions, %{})

    new_restrictions =
      Map.put(restrictions, "disabled_features", policy.disable_features)

    agent
    |> Ecto.Changeset.change(geo_restrictions: new_restrictions)
    |> Repo.update()

    log_enforcement(policy, agent, location, "feature_disabled", %{
      features: policy.disable_features
    })
  end

  defp enforce_file_restrictions(policy, agent, location) do
    restrictions = Map.get(agent, :geo_restrictions, %{})

    new_restrictions =
      restrictions
      |> Map.put("restrict_downloads", policy.restrict_file_downloads)
      |> Map.put("restrict_uploads", policy.restrict_file_uploads)

    agent
    |> Ecto.Changeset.change(geo_restrictions: new_restrictions)
    |> Repo.update()

    log_enforcement(policy, agent, location, "file_restricted", %{
      downloads: policy.restrict_file_downloads,
      uploads: policy.restrict_file_uploads
    })
  end

  defp enforce_enhanced_monitoring(policy, agent, location) do
    # Send command to agent to increase telemetry frequency
    # TODO: Implement agent command to adjust collection rates

    log_enforcement(policy, agent, location, "monitoring_enhanced", %{
      enabled: true
    })
  end

  defp enforce_isolation(policy, agent, location) do
    attrs = %{
      agent_id: agent.id,
      command_type: "isolate_network",
      command_params: %{
        reason: "geo_policy_enforcement",
        policy_id: policy.id,
        location_id: location.id,
        source: "geofencing"
      },
      status: "pending",
      priority: 9,
      expires_at: AgentCommand.utc_now_second() |> DateTime.add(3600, :second),
      idempotency_key: "geofencing-isolate:#{policy.id}:#{agent.id}:#{location.id}"
    }

    case AgentCommand.insert_new(attrs) do
      {:ok, command} ->
        notify_agent_command_worker(agent.id)

        log_enforcement(policy, agent, location, "isolated", %{
          success: true,
          queued: true,
          command_id: command.id,
          reason: "geo_policy_enforcement"
        })

      {:existing, command} ->
        notify_agent_command_worker(agent.id)

        log_enforcement(policy, agent, location, "isolated", %{
          success: true,
          queued: true,
          existing: true,
          command_id: command.id,
          reason: "geo_policy_enforcement"
        })

      {:error, reason} ->
        log_enforcement(
          policy,
          agent,
          location,
          "isolated",
          %{
            success: false,
            error: inspect(reason)
          }
        )
    end
  end

  defp notify_agent_command_worker(agent_id) do
    case Registry.get(agent_id) do
      {:ok, %{worker_pid: pid}} when is_pid(pid) -> send(pid, :send_pending_commands)
      _ -> :ok
    end
  end

  defp send_policy_alert(policy, agent, location) do
    alert_attrs = %{
      organization_id: agent.organization_id,
      agent_id: agent.id,
      severity: policy.alert_severity,
      title: "Geo Policy Enforcement: #{policy.name}",
      description: """
      Agent #{agent.hostname} triggered geo policy "#{policy.name}".

      Location: #{location.country_name}, #{location.city}
      IP: #{location.ip_address}
      VPN: #{location.is_vpn}
      """,
      status: "new",
      enrichment: %{
        policy: %{
          id: policy.id,
          name: policy.name,
          require_mfa: policy.require_mfa,
          auto_isolate: policy.auto_isolate
        },
        location: %{
          country: location.country_name,
          city: location.city,
          is_vpn: location.is_vpn
        }
      }
    }

    %Alert{}
    |> Alert.changeset(alert_attrs)
    |> Repo.insert()

    log_enforcement(policy, agent, location, "alert_sent", %{
      severity: policy.alert_severity
    })
  end

  defp log_enforcement(policy, agent, location, enforcement_type, details) do
    attrs = %{
      organization_id: agent.organization_id,
      agent_id: agent.id,
      policy_id: policy.id,
      location_id: location.id,
      enforcement_type: enforcement_type,
      enforcement_details: details,
      success: true,
      enforced_at: DateTime.utc_now()
    }

    %GeoPolicyEnforcement{}
    |> GeoPolicyEnforcement.changeset(attrs)
    |> Repo.insert()
  end
end
