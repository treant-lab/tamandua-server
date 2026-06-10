defmodule TamanduaServer.Response.AnalystLearning do
  @moduledoc """
  Analyst Learning Module

  Learns from analyst decisions to improve autonomous response recommendations.
  Implements a feedback loop where:
  1. System generates response recommendations
  2. Analysts approve/reject/modify recommendations
  3. System learns from these decisions
  4. Future recommendations improve based on learned patterns

  Learning dimensions:
  - Alert characteristics that lead to approval vs rejection
  - Action preferences per analyst, team, and organization
  - Timing patterns (faster approval for certain alert types)
  - Modification patterns (what actions analysts add/remove)
  - False positive patterns to reduce alert fatigue

  The module uses:
  - Historical decision analysis
  - Feature extraction from alerts
  - Simple ML model for recommendation scoring
  - A/B testing for new recommendation strategies
  """

  use GenServer
  require Logger
  import Ecto.Query

  alias TamanduaServer.Repo

  # Feature weights for recommendation scoring (learned over time)
  @default_weights %{
    severity_critical: 0.3,
    severity_high: 0.2,
    severity_medium: 0.1,
    confidence_high: 0.25,
    confidence_medium: 0.15,
    known_malware_family: 0.2,
    is_business_hours: -0.1,
    asset_critical: -0.25,
    asset_high: -0.15,
    previous_approvals_same_type: 0.3,
    analyst_approval_rate: 0.2
  }

  # Minimum decisions required before trusting learned patterns
  @min_decisions_threshold 20

  # GenServer state
  defstruct [
    :decision_history,
    :learned_weights,
    :analyst_profiles,
    :approval_patterns,
    :last_model_update
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Record an analyst's decision on a recommendation.
  Used to build the learning dataset.
  """
  @spec record_decision(map()) :: :ok
  def record_decision(decision_data) do
    GenServer.cast(__MODULE__, {:record_decision, decision_data})
  end

  @doc """
  Get ML-based recommendations for an alert.
  Returns suggested actions and confidence scores based on learned patterns.
  """
  @spec get_recommendations(map()) :: map()
  def get_recommendations(alert) do
    GenServer.call(__MODULE__, {:get_recommendations, alert})
  end

  @doc """
  Get approval probability for a specific action on an alert.
  """
  @spec approval_probability(map(), String.t()) :: float()
  def approval_probability(alert, action_type) do
    GenServer.call(__MODULE__, {:approval_probability, alert, action_type})
  end

  @doc """
  Get analyst profile (preferences, approval rate, etc.).
  """
  @spec get_analyst_profile(String.t()) :: map()
  def get_analyst_profile(analyst_id) do
    GenServer.call(__MODULE__, {:get_analyst_profile, analyst_id})
  end

  @doc """
  Get learning statistics and model performance metrics.
  """
  @spec get_learning_stats(String.t()) :: map()
  def get_learning_stats(org_id) do
    GenServer.call(__MODULE__, {:get_stats, org_id})
  end

  @doc """
  Get decision history for analysis.
  """
  @spec get_decision_history(keyword()) :: [map()]
  def get_decision_history(opts \\ []) do
    GenServer.call(__MODULE__, {:get_history, opts})
  end

  @doc """
  Get patterns learned from analyst decisions.
  """
  @spec get_learned_patterns(String.t()) :: map()
  def get_learned_patterns(org_id) do
    GenServer.call(__MODULE__, {:get_patterns, org_id})
  end

  @doc """
  Force model retraining with current decision history.
  """
  @spec retrain_model(String.t()) :: {:ok, map()} | {:error, term()}
  def retrain_model(org_id) do
    GenServer.call(__MODULE__, {:retrain, org_id})
  end

  @doc """
  Provide explicit feedback on a recommendation outcome.
  Used for post-incident analysis.
  """
  @spec provide_feedback(String.t(), map()) :: :ok
  def provide_feedback(recommendation_id, feedback) do
    GenServer.cast(__MODULE__, {:feedback, recommendation_id, feedback})
  end

  @doc """
  Get similar past decisions for reference.
  """
  @spec get_similar_decisions(map(), integer()) :: [map()]
  def get_similar_decisions(alert, limit \\ 10) do
    GenServer.call(__MODULE__, {:similar_decisions, alert, limit})
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    Logger.info("Starting Analyst Learning Module")

    state = %__MODULE__{
      decision_history: [],
      learned_weights: %{},
      analyst_profiles: %{},
      approval_patterns: %{},
      last_model_update: nil
    }

    # Load historical data asynchronously
    send(self(), :load_historical_data)

    # Schedule periodic model updates
    schedule_model_update()

    {:ok, state}
  end

  @impl true
  def handle_call({:get_recommendations, alert}, _from, state) do
    recommendations = generate_recommendations(alert, state)
    {:reply, recommendations, state}
  end

  @impl true
  def handle_call({:approval_probability, alert, action_type}, _from, state) do
    probability = calculate_approval_probability(alert, action_type, state)
    {:reply, probability, state}
  end

  @impl true
  def handle_call({:get_analyst_profile, analyst_id}, _from, state) do
    profile = Map.get(state.analyst_profiles, analyst_id, build_default_profile())
    {:reply, profile, state}
  end

  @impl true
  def handle_call({:get_stats, org_id}, _from, state) do
    stats = calculate_learning_stats(org_id, state)
    {:reply, stats, state}
  end

  @impl true
  def handle_call({:get_history, opts}, _from, state) do
    history = filter_history(state.decision_history, opts)
    {:reply, history, state}
  end

  @impl true
  def handle_call({:get_patterns, org_id}, _from, state) do
    patterns = Map.get(state.approval_patterns, org_id, %{})
    {:reply, patterns, state}
  end

  @impl true
  def handle_call({:retrain, org_id}, _from, state) do
    case retrain_model_internal(org_id, state) do
      {:ok, new_weights, metrics} ->
        new_learned = Map.put(state.learned_weights, org_id, new_weights)
        new_state = %{state |
          learned_weights: new_learned,
          last_model_update: DateTime.utc_now()
        }
        {:reply, {:ok, metrics}, new_state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:similar_decisions, alert, limit}, _from, state) do
    similar = find_similar_decisions(alert, state.decision_history, limit)
    {:reply, similar, state}
  end

  @impl true
  def handle_cast({:record_decision, decision_data}, state) do
    # Save to database
    save_decision(decision_data)

    # Update in-memory state
    new_history = [decision_data | Enum.take(state.decision_history, 9999)]

    # Update analyst profile
    analyst_id = decision_data[:user_id]
    profile = update_analyst_profile(
      Map.get(state.analyst_profiles, analyst_id, build_default_profile()),
      decision_data
    )
    new_profiles = Map.put(state.analyst_profiles, analyst_id, profile)

    # Update approval patterns
    org_id = decision_data[:organization_id]
    patterns = update_approval_patterns(
      Map.get(state.approval_patterns, org_id, %{}),
      decision_data
    )
    new_patterns = Map.put(state.approval_patterns, org_id, patterns)

    new_state = %{state |
      decision_history: new_history,
      analyst_profiles: new_profiles,
      approval_patterns: new_patterns
    }

    {:noreply, new_state}
  end

  @impl true
  def handle_cast({:feedback, recommendation_id, feedback}, state) do
    save_feedback(recommendation_id, feedback)
    {:noreply, state}
  end

  @impl true
  def handle_info(:load_historical_data, state) do
    Logger.debug("Loading historical decision data")

    history = load_decision_history()
    profiles = build_analyst_profiles(history)
    patterns = build_approval_patterns(history)
    weights = load_or_initialize_weights()

    new_state = %{state |
      decision_history: history,
      analyst_profiles: profiles,
      approval_patterns: patterns,
      learned_weights: weights
    }

    {:noreply, new_state}
  end

  @impl true
  def handle_info(:update_model, state) do
    Logger.debug("Periodic model update check")

    # Get orgs with enough new decisions
    orgs_to_update = state.decision_history
    |> Enum.group_by(& &1[:organization_id])
    |> Enum.filter(fn {_org, decisions} ->
      length(decisions) >= @min_decisions_threshold
    end)
    |> Enum.map(fn {org, _} -> org end)

    # Update models for each org
    new_weights = Enum.reduce(orgs_to_update, state.learned_weights, fn org_id, acc ->
      case retrain_model_internal(org_id, state) do
        {:ok, weights, _metrics} -> Map.put(acc, org_id, weights)
        _ -> acc
      end
    end)

    schedule_model_update()

    {:noreply, %{state | learned_weights: new_weights, last_model_update: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions - Recommendations
  # ============================================================================

  defp generate_recommendations(alert, state) do
    org_id = alert.organization_id || "default"
    weights = Map.get(state.learned_weights, org_id, @default_weights)

    # Extract features from alert
    features = extract_features(alert)

    # Calculate base confidence score
    base_confidence = calculate_confidence(features, weights)

    # Get recommended actions based on patterns
    patterns = Map.get(state.approval_patterns, org_id, %{})
    recommended_actions = recommend_actions(alert, patterns, base_confidence)

    # Find similar past decisions for context
    similar = find_similar_decisions(alert, state.decision_history, 5)
    similar_approval_rate = calculate_similar_approval_rate(similar)

    %{
      confidence: base_confidence,
      actions: recommended_actions,
      features: features,
      similar_decisions: length(similar),
      similar_approval_rate: similar_approval_rate,
      model_version: state.last_model_update,
      reasoning: build_reasoning(features, patterns, base_confidence)
    }
  end

  defp extract_features(alert) do
    %{
      severity: alert.severity,
      severity_score: severity_to_score(alert.severity),
      confidence_score: alert.threat_score || 50,
      mitre_tactics: alert.mitre_tactics || [],
      mitre_techniques: alert.mitre_techniques || [],
      has_evidence: has_evidence?(alert),
      detection_source: get_detection_source(alert),
      is_business_hours: is_business_hours?(),
      day_of_week: Date.day_of_week(Date.utc_today()),
      hour_of_day: DateTime.utc_now().hour,
      alert_type: alert.source || "unknown"
    }
  end

  defp calculate_confidence(features, weights) do
    score = 0.0

    # Severity contribution
    score = score + case features.severity do
      "critical" -> Map.get(weights, :severity_critical, 0.3)
      "high" -> Map.get(weights, :severity_high, 0.2)
      "medium" -> Map.get(weights, :severity_medium, 0.1)
      _ -> 0.0
    end

    # Confidence score contribution
    score = score + cond do
      features.confidence_score >= 90 -> Map.get(weights, :confidence_high, 0.25)
      features.confidence_score >= 70 -> Map.get(weights, :confidence_medium, 0.15)
      true -> 0.0
    end

    # Business hours penalty
    score = if features.is_business_hours do
      score + Map.get(weights, :is_business_hours, -0.1)
    else
      score
    end

    # Evidence bonus
    score = if features.has_evidence, do: score + 0.1, else: score

    # Normalize to 0-1 range
    min(max(score, 0.0), 1.0)
  end

  defp recommend_actions(alert, patterns, base_confidence) do
    severity = alert.severity

    # Get commonly approved actions for this alert type
    common_actions = Map.get(patterns, :common_approved_actions, %{})
    |> Map.get(severity, [])

    # Build action recommendations
    base_actions = case severity do
      "critical" ->
        [
          %{type: "isolate_network", confidence: base_confidence * 0.9},
          %{type: "kill_process", confidence: base_confidence * 0.95},
          %{type: "collect_forensics", confidence: base_confidence * 0.85}
        ]

      "high" ->
        [
          %{type: "kill_process", confidence: base_confidence * 0.9},
          %{type: "quarantine_file", confidence: base_confidence * 0.85},
          %{type: "collect_forensics", confidence: base_confidence * 0.8}
        ]

      "medium" ->
        [
          %{type: "quarantine_file", confidence: base_confidence * 0.7},
          %{type: "trigger_scan", confidence: base_confidence * 0.8}
        ]

      _ ->
        [
          %{type: "notify_analyst", confidence: base_confidence * 0.6}
        ]
    end

    # Adjust based on learned patterns
    Enum.map(base_actions, fn action ->
      pattern_boost = if action.type in common_actions, do: 0.1, else: 0.0
      %{action | confidence: min(action.confidence + pattern_boost, 1.0)}
    end)
    |> Enum.sort_by(& &1.confidence, :desc)
  end

  defp calculate_similar_approval_rate(similar_decisions) do
    if length(similar_decisions) == 0 do
      0.5
    else
      approved = Enum.count(similar_decisions, fn d -> d[:decision] == :approved end)
      approved / length(similar_decisions)
    end
  end

  defp build_reasoning(features, patterns, confidence) do
    reasons = []

    reasons = if features.severity_score >= 80 do
      ["High severity alert (#{features.severity})" | reasons]
    else
      reasons
    end

    reasons = if features.confidence_score >= 85 do
      ["High detection confidence (#{features.confidence_score}%)" | reasons]
    else
      reasons
    end

    reasons = if features.has_evidence do
      ["Supporting evidence available" | reasons]
    else
      reasons
    end

    reasons = if Map.get(patterns, :approval_rate, 0.5) > 0.7 do
      ["High historical approval rate for similar alerts" | reasons]
    else
      reasons
    end

    %{
      factors: Enum.reverse(reasons),
      confidence_explanation: confidence_explanation(confidence)
    }
  end

  defp confidence_explanation(confidence) when confidence >= 0.8, do: "High confidence - recommended for auto-execution"
  defp confidence_explanation(confidence) when confidence >= 0.6, do: "Moderate confidence - analyst review recommended"
  defp confidence_explanation(_), do: "Low confidence - manual investigation required"

  # ============================================================================
  # Private Functions - Learning
  # ============================================================================

  defp calculate_approval_probability(alert, action_type, state) do
    org_id = alert.organization_id || "default"
    patterns = Map.get(state.approval_patterns, org_id, %{})

    # Get action-specific approval rate
    action_rates = Map.get(patterns, :action_approval_rates, %{})
    base_rate = Map.get(action_rates, action_type, 0.5)

    # Adjust for alert severity
    severity_multiplier = case alert.severity do
      "critical" -> 1.2
      "high" -> 1.1
      "medium" -> 1.0
      _ -> 0.9
    end

    # Adjust for confidence
    confidence = alert.threat_score || 50
    confidence_multiplier = if confidence >= 85, do: 1.15, else: 1.0

    # Calculate final probability
    min(base_rate * severity_multiplier * confidence_multiplier, 1.0)
  end

  defp update_analyst_profile(profile, decision) do
    is_approved = decision[:decision] == :approved

    %{profile |
      total_decisions: profile.total_decisions + 1,
      approvals: profile.approvals + (if is_approved, do: 1, else: 0),
      rejections: profile.rejections + (if is_approved, do: 0, else: 1),
      approval_rate: (profile.approvals + (if is_approved, do: 1, else: 0)) /
                     (profile.total_decisions + 1),
      last_decision: DateTime.utc_now(),
      action_preferences: update_action_preferences(
        profile.action_preferences,
        decision[:suggested_actions],
        is_approved
      ),
      severity_preferences: update_severity_preferences(
        profile.severity_preferences,
        decision[:alert_severity],
        is_approved
      )
    }
  end

  defp update_action_preferences(prefs, actions, is_approved) when is_list(actions) do
    Enum.reduce(actions, prefs, fn action, acc ->
      action_type = action[:type] || action["type"]
      current = Map.get(acc, action_type, %{approved: 0, rejected: 0})

      updated = if is_approved do
        %{current | approved: current.approved + 1}
      else
        %{current | rejected: current.rejected + 1}
      end

      Map.put(acc, action_type, updated)
    end)
  end

  defp update_action_preferences(prefs, _, _), do: prefs

  defp update_severity_preferences(prefs, severity, is_approved) when is_binary(severity) do
    current = Map.get(prefs, severity, %{approved: 0, rejected: 0})

    updated = if is_approved do
      %{current | approved: current.approved + 1}
    else
      %{current | rejected: current.rejected + 1}
    end

    Map.put(prefs, severity, updated)
  end

  defp update_severity_preferences(prefs, _, _), do: prefs

  defp update_approval_patterns(patterns, decision) do
    is_approved = decision[:decision] == :approved
    severity = decision[:alert_severity]
    actions = decision[:suggested_actions] || []

    # Update overall approval rate
    total = Map.get(patterns, :total_decisions, 0) + 1
    approved = Map.get(patterns, :total_approvals, 0) + (if is_approved, do: 1, else: 0)

    patterns = Map.merge(patterns, %{
      total_decisions: total,
      total_approvals: approved,
      approval_rate: approved / total
    })

    # Update severity-specific rates
    severity_rates = Map.get(patterns, :severity_rates, %{})
    sev_data = Map.get(severity_rates, severity, %{total: 0, approved: 0})
    updated_sev = %{
      total: sev_data.total + 1,
      approved: sev_data.approved + (if is_approved, do: 1, else: 0)
    }
    patterns = Map.put(patterns, :severity_rates, Map.put(severity_rates, severity, updated_sev))

    # Update action-specific rates
    action_rates = Map.get(patterns, :action_approval_rates, %{})
    updated_action_rates = Enum.reduce(actions, action_rates, fn action, acc ->
      action_type = action[:type] || action["type"]
      current = Map.get(acc, action_type, %{total: 0, approved: 0})
      updated = %{
        total: current.total + 1,
        approved: current.approved + (if is_approved, do: 1, else: 0)
      }
      Map.put(acc, action_type, updated)
    end)
    patterns = Map.put(patterns, :action_approval_rates, updated_action_rates)

    # Track commonly approved actions per severity
    if is_approved do
      common_actions = Map.get(patterns, :common_approved_actions, %{})
      sev_actions = Map.get(common_actions, severity, [])
      new_action_types = Enum.map(actions, fn a -> a[:type] || a["type"] end)
      updated_sev_actions = (sev_actions ++ new_action_types) |> Enum.uniq() |> Enum.take(10)
      Map.put(patterns, :common_approved_actions, Map.put(common_actions, severity, updated_sev_actions))
    else
      patterns
    end
  end

  defp find_similar_decisions(alert, history, limit) do
    history
    |> Enum.map(fn decision ->
      score = similarity_score(alert, decision)
      {decision, score}
    end)
    |> Enum.sort_by(fn {_d, score} -> score end, :desc)
    |> Enum.take(limit)
    |> Enum.map(fn {d, _score} -> d end)
  end

  defp similarity_score(alert, decision) do
    score = 0.0

    # Same severity = +30 points
    score = if alert.severity == decision[:alert_severity], do: score + 0.3, else: score

    # Similar confidence = +20 points
    alert_conf = alert.threat_score || 50
    decision_conf = decision[:confidence_score] || 50
    score = if abs(alert_conf - decision_conf) < 15, do: score + 0.2, else: score

    # Same detection source = +20 points
    score = if alert.source == decision[:alert_type], do: score + 0.2, else: score

    # Overlapping MITRE techniques = +30 points
    alert_techniques = alert.mitre_techniques || []
    decision_techniques = decision[:mitre_techniques] || []
    overlap = length(alert_techniques -- (alert_techniques -- decision_techniques))
    score = score + min(overlap * 0.1, 0.3)

    score
  end

  defp retrain_model_internal(org_id, state) do
    # Get decisions for this org
    org_decisions = Enum.filter(state.decision_history, fn d ->
      d[:organization_id] == org_id
    end)

    if length(org_decisions) < @min_decisions_threshold do
      {:error, "Not enough decisions for retraining (need #{@min_decisions_threshold}, have #{length(org_decisions)})"}
    else
      # Simple weight adjustment based on approval patterns
      patterns = Map.get(state.approval_patterns, org_id, %{})

      # Adjust weights based on what gets approved
      new_weights = @default_weights
      |> adjust_weight(:severity_critical, patterns, "critical")
      |> adjust_weight(:severity_high, patterns, "high")
      |> adjust_weight(:confidence_high, patterns, nil)

      # Calculate metrics
      metrics = %{
        training_samples: length(org_decisions),
        approval_rate: Map.get(patterns, :approval_rate, 0.5),
        updated_at: DateTime.utc_now()
      }

      # Save weights to DB
      save_learned_weights(org_id, new_weights)

      {:ok, new_weights, metrics}
    end
  end

  defp adjust_weight(weights, key, patterns, severity) do
    severity_rates = Map.get(patterns, :severity_rates, %{})

    adjustment = if severity do
      sev_data = Map.get(severity_rates, severity, %{total: 0, approved: 0})
      if sev_data.total > 0 do
        rate = sev_data.approved / sev_data.total
        # Increase weight for high approval rate severities
        (rate - 0.5) * 0.2
      else
        0.0
      end
    else
      0.0
    end

    current = Map.get(weights, key, 0.0)
    Map.put(weights, key, max(min(current + adjustment, 1.0), -1.0))
  end

  # ============================================================================
  # Private Functions - Database
  # ============================================================================

  defp load_decision_history do
    try do
      query = from(d in "analyst_decisions",
        order_by: [desc: d.inserted_at],
        limit: 10000,
        select: %{
          id: d.id,
          recommendation_id: d.recommendation_id,
          alert_id: d.alert_id,
          agent_id: d.agent_id,
          organization_id: d.organization_id,
          user_id: d.user_id,
          decision: d.decision,
          suggested_actions: d.suggested_actions,
          alert_severity: d.alert_severity,
          confidence_score: d.confidence_score,
          criticality_level: d.criticality_level,
          mitre_techniques: d.mitre_techniques,
          inserted_at: d.inserted_at
        }
      )

      Repo.all(query)
      |> Enum.map(fn d ->
        %{d | decision: String.to_atom(d.decision || "unknown")}
      end)
    rescue
      e ->
        Logger.warning("Failed to load decision history: #{inspect(e)}")
        []
    end
  end

  defp save_decision(decision_data) do
    try do
      Repo.insert_all("analyst_decisions", [%{
        id: Ecto.UUID.generate(),
        recommendation_id: decision_data[:recommendation_id],
        alert_id: decision_data[:alert_id],
        agent_id: decision_data[:agent_id],
        organization_id: decision_data[:organization_id],
        user_id: decision_data[:user_id],
        decision: to_string(decision_data[:decision]),
        suggested_actions: decision_data[:suggested_actions],
        result: decision_data[:result],
        alert_severity: decision_data[:alert_severity],
        confidence_score: decision_data[:confidence_score],
        criticality_level: to_string(decision_data[:criticality_level]),
        mitre_techniques: decision_data[:mitre_techniques],
        inserted_at: DateTime.utc_now(),
        updated_at: DateTime.utc_now()
      }])
    rescue
      e -> Logger.error("Failed to save decision: #{inspect(e)}")
    end
  end

  defp save_feedback(recommendation_id, feedback) do
    try do
      Repo.update_all(
        from(d in "analyst_decisions", where: d.recommendation_id == ^recommendation_id),
        set: [
          feedback: feedback,
          updated_at: DateTime.utc_now()
        ]
      )
    rescue
      e -> Logger.error("Failed to save feedback: #{inspect(e)}")
    end
  end

  defp load_or_initialize_weights do
    try do
      query = from(w in "learned_weights", select: {w.organization_id, w.weights})
      Repo.all(query) |> Map.new()
    rescue
      _ -> %{}
    end
  end

  defp save_learned_weights(org_id, weights) do
    try do
      Repo.insert_all("learned_weights", [%{
        id: Ecto.UUID.generate(),
        organization_id: org_id,
        weights: weights,
        inserted_at: DateTime.utc_now(),
        updated_at: DateTime.utc_now()
      }],
      on_conflict: {:replace, [:weights, :updated_at]},
      conflict_target: :organization_id)
    rescue
      e -> Logger.error("Failed to save weights: #{inspect(e)}")
    end
  end

  defp build_analyst_profiles(history) do
    history
    |> Enum.group_by(& &1[:user_id])
    |> Enum.map(fn {user_id, decisions} ->
      profile = Enum.reduce(decisions, build_default_profile(), fn d, acc ->
        update_analyst_profile(acc, d)
      end)
      {user_id, profile}
    end)
    |> Map.new()
  end

  defp build_approval_patterns(history) do
    history
    |> Enum.group_by(& &1[:organization_id])
    |> Enum.map(fn {org_id, decisions} ->
      patterns = Enum.reduce(decisions, %{}, fn d, acc ->
        update_approval_patterns(acc, d)
      end)
      {org_id, patterns}
    end)
    |> Map.new()
  end

  defp build_default_profile do
    %{
      total_decisions: 0,
      approvals: 0,
      rejections: 0,
      approval_rate: 0.0,
      last_decision: nil,
      action_preferences: %{},
      severity_preferences: %{}
    }
  end

  defp filter_history(history, opts) do
    history
    |> filter_by_org(Keyword.get(opts, :organization_id))
    |> filter_by_user(Keyword.get(opts, :user_id))
    |> filter_by_decision(Keyword.get(opts, :decision))
    |> Enum.take(Keyword.get(opts, :limit, 100))
  end

  defp filter_by_org(history, nil), do: history
  defp filter_by_org(history, org_id), do: Enum.filter(history, & &1[:organization_id] == org_id)

  defp filter_by_user(history, nil), do: history
  defp filter_by_user(history, user_id), do: Enum.filter(history, & &1[:user_id] == user_id)

  defp filter_by_decision(history, nil), do: history
  defp filter_by_decision(history, decision), do: Enum.filter(history, & &1[:decision] == decision)

  defp calculate_learning_stats(org_id, state) do
    history = Enum.filter(state.decision_history, & &1[:organization_id] == org_id)
    patterns = Map.get(state.approval_patterns, org_id, %{})
    weights = Map.get(state.learned_weights, org_id, @default_weights)

    %{
      total_decisions: length(history),
      approval_rate: Map.get(patterns, :approval_rate, 0.0),
      model_trained: Map.has_key?(state.learned_weights, org_id),
      last_model_update: state.last_model_update,
      weight_count: map_size(weights),
      unique_analysts: history |> Enum.map(& &1[:user_id]) |> Enum.uniq() |> length(),
      decisions_by_severity: group_by_severity(history),
      decisions_by_action: group_by_action(history)
    }
  end

  defp group_by_severity(history) do
    history
    |> Enum.group_by(& &1[:alert_severity])
    |> Enum.map(fn {sev, decisions} ->
      approved = Enum.count(decisions, & &1[:decision] == :approved)
      {sev, %{total: length(decisions), approved: approved}}
    end)
    |> Map.new()
  end

  defp group_by_action(history) do
    history
    |> Enum.flat_map(fn d ->
      actions = d[:suggested_actions] || []
      Enum.map(actions, fn a ->
        {a[:type] || a["type"], d[:decision]}
      end)
    end)
    |> Enum.group_by(fn {type, _} -> type end)
    |> Enum.map(fn {type, items} ->
      approved = Enum.count(items, fn {_, decision} -> decision == :approved end)
      {type, %{total: length(items), approved: approved}}
    end)
    |> Map.new()
  end

  # ============================================================================
  # Private Functions - Helpers
  # ============================================================================

  defp severity_to_score("critical"), do: 100
  defp severity_to_score("high"), do: 80
  defp severity_to_score("medium"), do: 50
  defp severity_to_score("low"), do: 25
  defp severity_to_score("info"), do: 10
  defp severity_to_score(_), do: 0

  defp has_evidence?(alert) do
    evidence = alert.evidence || %{}
    map_size(evidence) > 0
  end

  defp get_detection_source(alert) do
    cond do
      alert.detection_metadata && alert.detection_metadata[:detection_type] ->
        alert.detection_metadata[:detection_type]
      alert.source ->
        alert.source
      true ->
        "unknown"
    end
  end

  defp is_business_hours? do
    now = DateTime.utc_now()
    hour = now.hour
    day = Date.day_of_week(DateTime.to_date(now))
    day in 1..5 and hour in 9..17
  end

  defp schedule_model_update do
    # Update model every 6 hours
    Process.send_after(self(), :update_model, :timer.hours(6))
  end
end
