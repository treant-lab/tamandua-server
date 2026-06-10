defmodule TamanduaServer.Response.Simulator do
  @moduledoc """
  Response Action Simulator for dry-run and impact analysis.

  Provides:
  - Dry-run mode for response actions
  - Impact preview before execution
  - What-if analysis for complex playbooks
  - Risk assessment for proposed actions
  - Rollback planning

  Use this to validate response actions before they affect production systems.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Agents.Registry
  alias TamanduaServer.Response.{Playbook, DecisionEngine}
  alias TamanduaServer.Detection.{Behavioral, Correlator}

  # Simulation result types
  @type simulation_result :: %{
    simulation_id: String.t(),
    simulated: boolean(),
    dry_run: boolean(),
    status: :success | :warning | :error,
    actions: [action_simulation()],
    impact_assessment: impact_assessment(),
    risk_score: float(),
    estimated_duration_ms: integer(),
    recommendations: [String.t()],
    rollback_plan: rollback_plan()
  }

  @type action_simulation :: %{
    action: String.t(),
    simulated: boolean(),
    target: String.t(),
    would_affect: [String.t()],
    reversible: boolean(),
    estimated_duration_ms: integer(),
    dependencies: [String.t()],
    risk_level: :low | :medium | :high | :critical
  }

  @type impact_assessment :: %{
    systems_affected: integer(),
    users_affected: integer(),
    services_impacted: [String.t()],
    network_impact: String.t(),
    data_at_risk: String.t(),
    business_impact: :low | :medium | :high | :critical
  }

  @type rollback_plan :: %{
    steps: [String.t()],
    estimated_time_minutes: integer(),
    requires_manual_steps: boolean(),
    prerequisites: [String.t()]
  }

  # State
  defstruct [
    :simulation_history,
    :asset_catalog,
    :service_dependencies
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Simulate a single response action without executing it.
  Returns detailed impact analysis.
  """
  @spec simulate_action(String.t(), String.t(), map()) :: {:ok, simulation_result()} | {:error, term()}
  def simulate_action(agent_id, action_type, params \\ %{}) do
    GenServer.call(__MODULE__, {:simulate_action, agent_id, action_type, params})
  end

  @doc """
  Simulate a full playbook execution.
  """
  @spec simulate_playbook(String.t(), String.t(), map()) :: {:ok, simulation_result()} | {:error, term()}
  def simulate_playbook(playbook_id, agent_id, context \\ %{}) do
    GenServer.call(__MODULE__, {:simulate_playbook, playbook_id, agent_id, context})
  end

  @doc """
  Run what-if analysis for a proposed response strategy.
  """
  @spec what_if_analysis(map()) :: {:ok, map()} | {:error, term()}
  def what_if_analysis(scenario) do
    GenServer.call(__MODULE__, {:what_if_analysis, scenario})
  end

  @doc """
  Calculate risk score for a set of actions.
  """
  @spec calculate_risk(String.t(), [map()]) :: {:ok, float()} | {:error, term()}
  def calculate_risk(agent_id, actions) do
    GenServer.call(__MODULE__, {:calculate_risk, agent_id, actions})
  end

  @doc """
  Get impact preview for an action.
  """
  @spec impact_preview(String.t(), String.t(), map()) :: {:ok, impact_assessment()} | {:error, term()}
  def impact_preview(agent_id, action_type, params \\ %{}) do
    GenServer.call(__MODULE__, {:impact_preview, agent_id, action_type, params})
  end

  @doc """
  Generate a rollback plan for proposed actions.
  """
  @spec generate_rollback_plan(String.t(), [map()]) :: {:ok, rollback_plan()} | {:error, term()}
  def generate_rollback_plan(agent_id, actions) do
    GenServer.call(__MODULE__, {:generate_rollback_plan, agent_id, actions})
  end

  @doc """
  Get simulation history.
  """
  @spec get_simulation_history(keyword()) :: {:ok, [simulation_result()]}
  def get_simulation_history(opts \\ []) do
    GenServer.call(__MODULE__, {:get_history, opts})
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    Logger.info("Starting Response Simulator")

    state = %__MODULE__{
      simulation_history: [],
      asset_catalog: load_asset_catalog(),
      service_dependencies: load_service_dependencies()
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:simulate_action, agent_id, action_type, params}, _from, state) do
    simulation_id = generate_simulation_id()

    Logger.info("Simulating action #{action_type} on agent #{agent_id}, sim_id: #{simulation_id}")

    # Get agent info
    agent_info = get_agent_info(agent_id)

    # Simulate the action
    action_sim = simulate_single_action(action_type, params, agent_info, state)

    # Calculate impact
    impact = calculate_impact(agent_id, [action_sim], state)

    # Generate risk score
    risk = calculate_action_risk(action_type, agent_info, params)

    # Generate rollback plan
    rollback = generate_action_rollback(action_type, params, agent_info)

    result = %{
      simulation_id: simulation_id,
      simulated: true,
      dry_run: true,
      simulation_mode: "response_dry_run",
      status: determine_simulation_status(risk, impact),
      actions: [action_sim],
      impact_assessment: impact,
      risk_score: risk,
      estimated_duration_ms: action_sim.estimated_duration_ms,
      recommendations: generate_recommendations(action_type, risk, impact),
      rollback_plan: rollback,
      simulated_at: DateTime.utc_now()
    }

    # Store in history
    new_history = [result | state.simulation_history] |> Enum.take(500)

    {:reply, {:ok, result}, %{state | simulation_history: new_history}}
  end

  @impl true
  def handle_call({:simulate_playbook, playbook_id, agent_id, context}, _from, state) do
    simulation_id = generate_simulation_id()

    Logger.info("Simulating playbook #{playbook_id} on agent #{agent_id}")

    case Playbook.get_playbook(playbook_id) do
      {:ok, playbook} ->
        agent_info = get_agent_info(agent_id)

        # Simulate each step
        action_sims = playbook.steps
        |> Enum.with_index()
        |> Enum.map(fn {step, idx} ->
          action = step["action"]
          params = Map.merge(step["params"] || %{}, context)

          sim = simulate_single_action(action, params, agent_info, state)
          Map.put(sim, :step_index, idx)
        end)

        # Calculate cumulative impact
        impact = calculate_impact(agent_id, action_sims, state)

        # Calculate total risk
        total_risk = action_sims
        |> Enum.map(& &1.risk_level)
        |> Enum.map(&risk_level_to_score/1)
        |> Enum.max()

        # Calculate total duration
        total_duration = Enum.sum(Enum.map(action_sims, & &1.estimated_duration_ms))

        # Generate comprehensive rollback plan
        rollback = generate_playbook_rollback(action_sims, agent_info)

        result = %{
          simulation_id: simulation_id,
          playbook_id: playbook_id,
          playbook_name: playbook.name,
          simulated: true,
          dry_run: true,
          simulation_mode: "playbook_dry_run",
          status: determine_simulation_status(total_risk, impact),
          actions: action_sims,
          impact_assessment: impact,
          risk_score: total_risk,
          estimated_duration_ms: total_duration,
          recommendations: generate_playbook_recommendations(playbook, action_sims, impact),
          rollback_plan: rollback,
          simulated_at: DateTime.utc_now()
        }

        new_history = [result | state.simulation_history] |> Enum.take(500)

        {:reply, {:ok, result}, %{state | simulation_history: new_history}}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:what_if_analysis, scenario}, _from, state) do
    Logger.info("Running what-if analysis")

    agent_id = scenario[:agent_id]
    actions = scenario[:actions] || []
    conditions = scenario[:conditions] || %{}

    agent_info = get_agent_info(agent_id)

    # Simulate all proposed actions
    action_sims = Enum.map(actions, fn action ->
      simulate_single_action(action[:type], action[:params] || %{}, agent_info, state)
    end)

    # Calculate outcomes for different scenarios
    outcomes = [
      %{
        scenario: "best_case",
        description: "All actions succeed, minimal impact",
        probability: 0.6,
        impact: calculate_best_case_impact(action_sims),
        recovery_time_minutes: calculate_recovery_time(action_sims, :best)
      },
      %{
        scenario: "expected_case",
        description: "Most actions succeed, some require retry",
        probability: 0.3,
        impact: calculate_impact(agent_id, action_sims, state),
        recovery_time_minutes: calculate_recovery_time(action_sims, :expected)
      },
      %{
        scenario: "worst_case",
        description: "Critical failures, rollback required",
        probability: 0.1,
        impact: calculate_worst_case_impact(action_sims),
        recovery_time_minutes: calculate_recovery_time(action_sims, :worst)
      }
    ]

    # Generate decision matrix
    decision_matrix = %{
      proceed_recommendation: calculate_proceed_recommendation(outcomes),
      confidence: calculate_confidence(outcomes),
      alternative_actions: suggest_alternatives(action_sims, conditions)
    }

    result = %{
      analysis_id: generate_simulation_id(),
      simulated: true,
      dry_run: true,
      simulation_mode: "what_if_dry_run",
      agent_id: agent_id,
      proposed_actions: actions,
      simulated_actions: action_sims,
      outcomes: outcomes,
      decision_matrix: decision_matrix,
      analyzed_at: DateTime.utc_now()
    }

    {:reply, {:ok, result}, state}
  end

  @impl true
  def handle_call({:calculate_risk, agent_id, actions}, _from, state) do
    agent_info = get_agent_info(agent_id)

    risk_scores = Enum.map(actions, fn action ->
      action_type = action[:type] || action[:action]
      params = action[:params] || %{}
      calculate_action_risk(action_type, agent_info, params)
    end)

    # Use weighted maximum (highest risk has most weight)
    max_risk = Enum.max(risk_scores, fn -> 0.0 end)
    avg_risk = if length(risk_scores) > 0, do: Enum.sum(risk_scores) / length(risk_scores), else: 0.0

    combined_risk = max_risk * 0.7 + avg_risk * 0.3

    {:reply, {:ok, Float.round(combined_risk, 3)}, state}
  end

  @impl true
  def handle_call({:impact_preview, agent_id, action_type, params}, _from, state) do
    agent_info = get_agent_info(agent_id)
    action_sim = simulate_single_action(action_type, params, agent_info, state)
    impact = calculate_impact(agent_id, [action_sim], state)

    {:reply, {:ok, impact}, state}
  end

  @impl true
  def handle_call({:generate_rollback_plan, agent_id, actions}, _from, state) do
    agent_info = get_agent_info(agent_id)

    action_sims = Enum.map(actions, fn action ->
      action_type = action[:type] || action[:action]
      params = action[:params] || %{}
      simulate_single_action(action_type, params, agent_info, state)
    end)

    rollback = generate_playbook_rollback(action_sims, agent_info)

    {:reply, {:ok, rollback}, state}
  end

  @impl true
  def handle_call({:get_history, opts}, _from, state) do
    limit = Keyword.get(opts, :limit, 50)
    history = Enum.take(state.simulation_history, limit)

    {:reply, {:ok, history}, state}
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp generate_simulation_id do
    "sim_" <> Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)
  end

  defp get_agent_info(agent_id) do
    case Registry.get(agent_id) do
      {:ok, info} -> info
      _ -> %{agent_id: agent_id, hostname: "unknown", os: "unknown", criticality: :medium}
    end
  end

  defp simulate_single_action(action_type, params, agent_info, state) do
    %{
      action: action_type,
      simulated: true,
      dry_run: true,
      simulation_mode: "response_action_dry_run",
      target: agent_info[:hostname] || agent_info[:agent_id],
      would_affect: calculate_would_affect(action_type, params, agent_info, state),
      reversible: is_reversible?(action_type),
      estimated_duration_ms: estimate_duration(action_type, params),
      dependencies: get_action_dependencies(action_type),
      risk_level: determine_risk_level(action_type, agent_info),
      params: params
    }
  end

  defp calculate_would_affect(action_type, params, agent_info, state) do
    case action_type do
      "isolate_host" ->
        ["Network connectivity", "User sessions", "Running applications"]

      "isolate_network" ->
        ["Network connectivity", "User sessions", "Running applications"]

      "kill_process" ->
        pid = params[:pid]
        ["Process #{pid}", "Child processes", "Associated handles"]

      "quarantine_file" ->
        path = params[:path]
        ["File: #{path}", "Applications using the file"]

      "block_ip" ->
        ip = params[:ip]
        deps = Map.get(state.service_dependencies, ip, [])
        ["IP: #{ip}"] ++ deps

      "block_domain" ->
        domain = params[:domain]
        ["Domain: #{domain}", "DNS resolution", "Applications using domain"]

      "disable_user" ->
        ["User account", "Active sessions", "Scheduled tasks"]

      "registry_cleanup" ->
        ["Registry keys", "Dependent services", "System configuration"]

      "service_uninstallation" ->
        ["Service process", "Dependent services", "System functionality"]

      "full_remediation" ->
        ["All malware traces", "Persistence mechanisms", "Network rules"]

      _ ->
        ["Target system"]
    end
  end

  defp is_reversible?(action_type) do
    case action_type do
      "kill_process" -> false
      "isolate_host" -> true
      "isolate_network" -> true
      "quarantine_file" -> true
      "block_ip" -> true
      "block_domain" -> true
      "disable_user" -> true
      "registry_cleanup" -> true  # With backup
      "service_uninstallation" -> true  # With backup
      "full_remediation" -> true  # With rollback point
      _ -> false
    end
  end

  defp estimate_duration(action_type, _params) do
    case action_type do
      "kill_process" -> 100
      "isolate_host" -> 500
      "isolate_network" -> 500
      "quarantine_file" -> 1000
      "block_ip" -> 200
      "block_domain" -> 200
      "disable_user" -> 500
      "registry_cleanup" -> 5000
      "service_uninstallation" -> 3000
      "full_remediation" -> 30000
      "collect_forensics" -> 60000
      _ -> 1000
    end
  end

  defp get_action_dependencies(action_type) do
    case action_type do
      "full_remediation" -> ["rollback_point_created", "agent_online"]
      "registry_cleanup" -> ["backup_created", "admin_privileges"]
      "service_uninstallation" -> ["service_stopped", "backup_created"]
      "isolate_network" -> ["agent_connection_maintained"]
      _ -> []
    end
  end

  defp determine_risk_level(action_type, agent_info) do
    base_risk = case action_type do
      "collect_forensics" -> :low
      "trigger_scan" -> :low
      "block_ip" -> :low
      "block_domain" -> :low
      "kill_process" -> :medium
      "quarantine_file" -> :medium
      "isolate_host" -> :high
      "isolate_network" -> :high
      "disable_user" -> :high
      "registry_cleanup" -> :high
      "service_uninstallation" -> :high
      "full_remediation" -> :critical
      _ -> :medium
    end

    # Elevate risk for critical assets
    asset_criticality = agent_info[:criticality] || :medium

    case {base_risk, asset_criticality} do
      {:low, :critical} -> :medium
      {:medium, :critical} -> :high
      {:high, :critical} -> :critical
      _ -> base_risk
    end
  end

  defp risk_level_to_score(level) do
    case level do
      :low -> 0.2
      :medium -> 0.5
      :high -> 0.75
      :critical -> 0.95
    end
  end

  defp calculate_impact(agent_id, action_sims, state) do
    agent_info = get_agent_info(agent_id)

    systems_affected = 1 + count_related_systems(agent_info, state)
    users_affected = estimate_users_affected(agent_info, action_sims)
    services = list_impacted_services(action_sims, state)

    network_impact = if Enum.any?(action_sims, fn a -> a.action in ["isolate_host", "isolate_network", "block_ip"] end) do
      "Network connectivity will be affected"
    else
      "Minimal network impact"
    end

    data_risk = if Enum.any?(action_sims, fn a -> a.action in ["quarantine_file", "full_remediation"] end) do
      "Files may be moved or quarantined"
    else
      "No data at risk"
    end

    business_impact = calculate_business_impact(agent_info, action_sims)

    %{
      systems_affected: systems_affected,
      users_affected: users_affected,
      services_impacted: services,
      network_impact: network_impact,
      data_at_risk: data_risk,
      business_impact: business_impact
    }
  end

  defp count_related_systems(_agent_info, _state), do: 0
  defp estimate_users_affected(_agent_info, _action_sims), do: 1

  defp list_impacted_services(action_sims, _state) do
    action_sims
    |> Enum.flat_map(fn sim ->
      case sim.action do
        "service_uninstallation" -> [sim.params[:service_name] || "Unknown service"]
        "isolate_network" -> ["Network services"]
        _ -> []
      end
    end)
    |> Enum.uniq()
  end

  defp calculate_business_impact(agent_info, action_sims) do
    asset_criticality = agent_info[:criticality] || :medium
    max_risk = action_sims
    |> Enum.map(& &1.risk_level)
    |> Enum.map(&risk_level_to_score/1)
    |> Enum.max(fn -> 0.0 end)

    combined = (risk_level_to_score(asset_criticality) + max_risk) / 2

    cond do
      combined >= 0.8 -> :critical
      combined >= 0.6 -> :high
      combined >= 0.4 -> :medium
      true -> :low
    end
  end

  defp calculate_action_risk(action_type, agent_info, params) do
    base_risk = risk_level_to_score(determine_risk_level(action_type, agent_info))

    # Adjust for specific parameters
    param_adjustments = cond do
      params[:force] -> 0.1
      params[:recursive] -> 0.05
      params[:all_affected] -> 0.1
      true -> 0.0
    end

    min(base_risk + param_adjustments, 1.0)
  end

  defp generate_action_rollback(action_type, params, _agent_info) do
    steps = case action_type do
      "isolate_network" ->
        ["Remove network isolation", "Restore network connectivity", "Verify network access"]

      "isolate_host" ->
        ["Remove network isolation", "Restore network connectivity", "Verify network access"]

      "quarantine_file" ->
        ["Restore file from quarantine: #{params[:path]}", "Verify file integrity"]

      "block_ip" ->
        ["Remove IP block for: #{params[:ip]}", "Verify connectivity"]

      "block_domain" ->
        ["Remove domain block for: #{params[:domain]}", "Flush DNS cache"]

      "disable_user" ->
        ["Re-enable user account", "Restore user permissions"]

      "registry_cleanup" ->
        ["Restore registry from backup", "Verify registry integrity", "Restart affected services"]

      "service_uninstallation" ->
        ["Restore service from backup", "Start service", "Verify service functionality"]

      "full_remediation" ->
        ["Restore from VSS snapshot", "Restore registry backup", "Restart cleaned services", "Verify system integrity"]

      _ ->
        ["No automated rollback available", "Manual recovery may be required"]
    end

    %{
      steps: steps,
      estimated_time_minutes: length(steps) * 2,
      requires_manual_steps: action_type in ["kill_process", "full_remediation"],
      prerequisites: get_rollback_prerequisites(action_type)
    }
  end

  defp get_rollback_prerequisites(action_type) do
    case action_type do
      "registry_cleanup" -> ["Registry backup exists"]
      "service_uninstallation" -> ["Service backup exists"]
      "full_remediation" -> ["VSS snapshot available", "Registry backup exists"]
      _ -> []
    end
  end

  defp generate_playbook_rollback(action_sims, _agent_info) do
    all_steps = action_sims
    |> Enum.reverse()  # Rollback in reverse order
    |> Enum.flat_map(fn sim ->
      case sim.action do
        "isolate_network" -> ["Remove network isolation"]
        "isolate_host" -> ["Remove network isolation"]
        "quarantine_file" -> ["Restore quarantined file"]
        "block_ip" -> ["Remove IP block"]
        "block_domain" -> ["Remove domain block"]
        "disable_user" -> ["Re-enable user"]
        "registry_cleanup" -> ["Restore registry from backup"]
        "service_uninstallation" -> ["Restore service from backup"]
        _ -> []
      end
    end)

    requires_manual = Enum.any?(action_sims, fn sim ->
      sim.action in ["kill_process", "full_remediation"]
    end)

    %{
      steps: all_steps ++ ["Verify system integrity", "Confirm normal operation"],
      estimated_time_minutes: length(all_steps) * 2 + 5,
      requires_manual_steps: requires_manual,
      prerequisites: ["Backups available", "Admin access"]
    }
  end

  defp determine_simulation_status(risk_score, impact) do
    cond do
      risk_score >= 0.8 or impact.business_impact == :critical -> :error
      risk_score >= 0.5 or impact.business_impact in [:high, :critical] -> :warning
      true -> :success
    end
  end

  defp generate_recommendations(action_type, risk_score, impact) do
    recs = []

    recs = if risk_score >= 0.7 do
      ["Consider creating a manual backup before proceeding" | recs]
    else
      recs
    end

    recs = if impact.business_impact in [:high, :critical] do
      ["Notify stakeholders before execution" | recs]
    else
      recs
    end

    recs = if action_type in ["isolate_network", "isolate_host"] do
      ["Ensure incident response team is available" | recs]
    else
      recs
    end

    if length(recs) == 0 do
      ["Action appears safe to proceed"]
    else
      recs
    end
  end

  defp generate_playbook_recommendations(playbook, action_sims, impact) do
    recs = []

    high_risk_actions = Enum.filter(action_sims, fn a -> a.risk_level in [:high, :critical] end)

    recs = if length(high_risk_actions) > 0 do
      ["Playbook contains #{length(high_risk_actions)} high-risk action(s)" | recs]
    else
      recs
    end

    recs = if playbook.require_approval do
      ["This playbook requires approval before execution" | recs]
    else
      recs
    end

    recs = if impact.business_impact in [:high, :critical] do
      ["Consider scheduling for maintenance window" | recs]
    else
      recs
    end

    reversible_actions = Enum.filter(action_sims, & &1.reversible)
    recs = if length(reversible_actions) < length(action_sims) do
      ["Some actions are not automatically reversible" | recs]
    else
      recs
    end

    if length(recs) == 0 do
      ["Playbook simulation completed successfully"]
    else
      recs
    end
  end

  defp calculate_best_case_impact(_action_sims) do
    %{
      systems_affected: 1,
      users_affected: 0,
      services_impacted: [],
      network_impact: "None",
      data_at_risk: "None",
      business_impact: :low
    }
  end

  defp calculate_worst_case_impact(action_sims) do
    %{
      systems_affected: length(action_sims) + 5,
      users_affected: 10,
      services_impacted: ["Critical services may be affected"],
      network_impact: "Complete network isolation",
      data_at_risk: "Potential data loss without backup",
      business_impact: :critical
    }
  end

  defp calculate_recovery_time(action_sims, scenario) do
    base_time = length(action_sims) * 5

    case scenario do
      :best -> div(base_time, 2)
      :expected -> base_time
      :worst -> base_time * 3
    end
  end

  defp calculate_proceed_recommendation(outcomes) do
    # Calculate weighted probability of success
    success_prob = outcomes
    |> Enum.filter(fn o -> o.impact.business_impact in [:low, :medium] end)
    |> Enum.map(& &1.probability)
    |> Enum.sum()

    cond do
      success_prob >= 0.8 -> :proceed
      success_prob >= 0.5 -> :proceed_with_caution
      true -> :reconsider
    end
  end

  defp calculate_confidence(outcomes) do
    # Higher confidence when outcomes are more certain
    probabilities = Enum.map(outcomes, & &1.probability)
    max_prob = Enum.max(probabilities)

    if max_prob >= 0.6, do: :high, else: :medium
  end

  defp suggest_alternatives(_action_sims, _conditions) do
    [
      "Consider isolating network segment instead of full host isolation",
      "Use kill process before full remediation for faster containment",
      "Collect forensics before any destructive actions"
    ]
  end

  defp load_asset_catalog do
    # Would load from database in production
    %{}
  end

  defp load_service_dependencies do
    # Would load from CMDB or discovery in production
    %{}
  end
end
