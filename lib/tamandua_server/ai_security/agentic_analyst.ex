defmodule TamanduaServer.AISecurity.AgenticAnalyst do
  @moduledoc """
  Agentic Security Analyst - Autonomous AI-Powered Alert Triage and Investigation

  Inspired by SentinelOne Purple AI, this module provides autonomous security analysis:
  - Autonomous alert triage with severity assessment
  - Automated investigation workflows with state machine
  - Hypothesis generation and validation
  - Evidence collection and correlation
  - Recommended response actions with confidence scoring
  - Natural language explanations for analysts
  - Learning from analyst feedback to improve over time

  ## Architecture

  The analyst operates as a GenServer with internal state tracking:
  - Active investigations (state machine per investigation)
  - Evidence cache (correlated findings)
  - Hypothesis tree (generated and validated hypotheses)
  - Action recommendations (with confidence scores)
  - Feedback loop (analyst corrections for learning)

  ## Investigation States

      :pending -> :triaging -> :investigating -> :hypothesis_validation ->
      :evidence_collection -> :action_recommendation -> :awaiting_review ->
      :resolved | :escalated

  ## Usage

      # Start autonomous triage
      AgenticAnalyst.triage_alert(alert_id)

      # Get investigation status
      AgenticAnalyst.get_investigation(investigation_id)

      # Submit analyst feedback
      AgenticAnalyst.submit_feedback(investigation_id, feedback)
  """

  use GenServer
  require Logger

  alias TamanduaServer.Alerts
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Detection.{Correlator, Engine, Mitre}
  alias TamanduaServer.Detection.Evidence, as: DetectionEvidence
  alias TamanduaServer.Response.Executor
  alias TamanduaServer.Agents.Registry
  alias TamanduaServer.{Telemetry, ThreatIntel, Repo}

  # Investigation states
  @states ~w(pending triaging investigating hypothesis_validation evidence_collection
             action_recommendation awaiting_review resolved escalated)a

  # Confidence thresholds
  @high_confidence_threshold 0.85
  @medium_confidence_threshold 0.6
  @auto_action_threshold 0.95

  # Investigation timeout (30 minutes)
  @investigation_timeout :timer.minutes(30)

  # Evidence quality weights (direct observation > correlation > heuristic)
  @evidence_quality_weights %{
    direct_observation: 1.0,
    tool_output: 0.9,
    correlation: 0.7,
    behavioral: 0.6,
    heuristic: 0.4,
    contextual: 0.3
  }

  # MITRE technique base priors (frequency in real-world attacks)
  @technique_priors %{
    "T1059" => 0.35, "T1059.001" => 0.30,   # Command & Scripting Interpreter
    "T1003" => 0.20, "T1003.001" => 0.18,   # OS Credential Dumping
    "T1486" => 0.10,                          # Data Encrypted for Impact (Ransomware)
    "T1021" => 0.25, "T1021.001" => 0.20,   # Remote Services
    "T1021.002" => 0.22,                      # SMB/Windows Admin Shares
    "T1547" => 0.28, "T1547.001" => 0.25,   # Boot/Logon Autostart
    "T1053" => 0.22, "T1053.005" => 0.20,   # Scheduled Task
    "T1218" => 0.18, "T1218.011" => 0.15,   # Rundll32
    "T1105" => 0.30,                          # Ingress Tool Transfer
    "T1027" => 0.25                           # Obfuscated Files
  }
  @default_technique_prior 0.15

  # ETS tables for fast lookups
  @investigations_table :agentic_investigations
  @evidence_table :agentic_evidence
  @feedback_table :agentic_feedback

  defstruct [
    :stats,
    :config,
    :active_investigations
  ]

  # ============================================================================
  # Investigation State Structure
  # ============================================================================

  defmodule Investigation do
    @moduledoc "Represents an active investigation state"

    defstruct [
      :id,
      :alert_id,
      :alert,
      :state,
      :started_at,
      :updated_at,
      :triage_result,
      :hypotheses,
      :evidence,
      :correlations,
      :recommendations,
      :explanation,
      :confidence,
      :analyst_feedback,
      :resolution
    ]

    @type t :: %__MODULE__{
      id: String.t(),
      alert_id: String.t(),
      alert: map(),
      state: atom(),
      started_at: DateTime.t(),
      updated_at: DateTime.t(),
      triage_result: map() | nil,
      hypotheses: [map()],
      evidence: [map()],
      correlations: [map()],
      recommendations: [map()],
      explanation: String.t() | nil,
      confidence: float(),
      analyst_feedback: map() | nil,
      resolution: map() | nil
    }
  end

  defmodule Hypothesis do
    @moduledoc "Represents a security hypothesis to validate"

    defstruct [
      :id,
      :type,
      :description,
      :indicators,
      :mitre_technique,
      :confidence,
      :validated,
      :evidence_refs,
      :rejection_reason
    ]
  end

  defmodule Evidence do
    @moduledoc "Represents collected evidence"

    defstruct [
      :id,
      :type,
      :source,
      :timestamp,
      :data,
      :relevance_score,
      :supporting_hypotheses
    ]
  end

  defmodule Recommendation do
    @moduledoc "Represents an action recommendation"

    defstruct [
      :id,
      :action_type,
      :target,
      :parameters,
      :confidence,
      :rationale,
      :risk_level,
      :requires_approval,
      :auto_executable
    ]
  end

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Initiates autonomous triage of an alert.
  Returns an investigation ID for tracking.
  """
  @spec triage_alert(String.t()) :: {:ok, String.t()} | {:error, term()}
  def triage_alert(alert_id) do
    GenServer.call(__MODULE__, {:triage_alert, alert_id})
  end

  @doc """
  Initiates autonomous triage of multiple alerts in batch.
  """
  @spec triage_batch([String.t()]) :: {:ok, [String.t()]} | {:error, term()}
  def triage_batch(alert_ids) do
    GenServer.call(__MODULE__, {:triage_batch, alert_ids}, 60_000)
  end

  @doc """
  Gets the current state of an investigation.
  """
  @spec get_investigation(String.t()) :: {:ok, Investigation.t()} | {:error, :not_found}
  def get_investigation(investigation_id) do
    GenServer.call(__MODULE__, {:get_investigation, investigation_id})
  end

  @doc """
  Lists all active investigations.
  """
  @spec list_investigations(keyword()) :: [Investigation.t()]
  def list_investigations(opts \\ []) do
    GenServer.call(__MODULE__, {:list_investigations, opts})
  end

  @doc """
  Submits analyst feedback for an investigation.
  This feedback is used to improve future analysis.
  """
  @spec submit_feedback(String.t(), map()) :: :ok | {:error, term()}
  def submit_feedback(investigation_id, feedback) do
    GenServer.call(__MODULE__, {:submit_feedback, investigation_id, feedback})
  end

  @doc """
  Approves a recommended action for execution.
  """
  @spec approve_action(String.t(), String.t()) :: {:ok, map()} | {:error, term()}
  def approve_action(investigation_id, recommendation_id) do
    GenServer.call(__MODULE__, {:approve_action, investigation_id, recommendation_id})
  end

  @doc """
  Rejects a recommended action.
  """
  @spec reject_action(String.t(), String.t(), String.t()) :: :ok | {:error, term()}
  def reject_action(investigation_id, recommendation_id, reason) do
    GenServer.call(__MODULE__, {:reject_action, investigation_id, recommendation_id, reason})
  end

  @doc """
  Generates a natural language explanation of an investigation.
  """
  @spec explain_investigation(String.t()) :: {:ok, String.t()} | {:error, term()}
  def explain_investigation(investigation_id) do
    GenServer.call(__MODULE__, {:explain_investigation, investigation_id})
  end

  @doc """
  Gets analyst statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Forces resolution of an investigation.
  """
  @spec resolve_investigation(String.t(), map()) :: :ok | {:error, term()}
  def resolve_investigation(investigation_id, resolution) do
    GenServer.call(__MODULE__, {:resolve_investigation, investigation_id, resolution})
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    # Create ETS tables
    :ets.new(@investigations_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@evidence_table, [:named_table, :bag, :public, read_concurrency: true])
    :ets.new(@feedback_table, [:named_table, :bag, :public, read_concurrency: true])

    state = %__MODULE__{
      stats: %{
        alerts_triaged: 0,
        investigations_completed: 0,
        hypotheses_generated: 0,
        hypotheses_validated: 0,
        actions_recommended: 0,
        actions_executed: 0,
        false_positives_identified: 0,
        true_positives_confirmed: 0,
        average_confidence: 0.0,
        feedback_received: 0
      },
      config: %{
        auto_triage_enabled: true,
        auto_action_enabled: false,
        max_concurrent_investigations: 50,
        hypothesis_depth: 3
      },
      active_investigations: %{}
    }

    Logger.info("Agentic Security Analyst started")
    {:ok, state}
  end

  @impl true
  def handle_call({:triage_alert, alert_id}, _from, state) do
    case do_triage_alert(alert_id, state) do
      {:ok, investigation_id, new_state} ->
        {:reply, {:ok, investigation_id}, new_state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:triage_batch, alert_ids}, _from, state) do
    {investigation_ids, final_state} =
      Enum.map_reduce(alert_ids, state, fn alert_id, acc_state ->
        case do_triage_alert(alert_id, acc_state) do
          {:ok, inv_id, new_state} -> {inv_id, new_state}
          {:error, _} -> {nil, acc_state}
        end
      end)

    valid_ids = Enum.filter(investigation_ids, & &1)
    {:reply, {:ok, valid_ids}, final_state}
  end

  @impl true
  def handle_call({:get_investigation, investigation_id}, _from, state) do
    case :ets.lookup(@investigations_table, investigation_id) do
      [{^investigation_id, investigation}] -> {:reply, {:ok, investigation}, state}
      [] -> {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:list_investigations, opts}, _from, state) do
    investigations = :ets.tab2list(@investigations_table)
    |> Enum.map(fn {_id, inv} -> inv end)
    |> filter_investigations(opts)
    |> Enum.sort_by(& &1.updated_at, {:desc, DateTime})

    {:reply, investigations, state}
  end

  @impl true
  def handle_call({:submit_feedback, investigation_id, feedback}, _from, state) do
    case :ets.lookup(@investigations_table, investigation_id) do
      [{^investigation_id, investigation}] ->
        updated = %{investigation |
          analyst_feedback: feedback,
          updated_at: DateTime.utc_now()
        }
        :ets.insert(@investigations_table, {investigation_id, updated})
        :ets.insert(@feedback_table, {investigation_id, feedback})

        # Learn from feedback
        learn_from_feedback(investigation, feedback)

        new_stats = update_stat(state.stats, :feedback_received)
        {:reply, :ok, %{state | stats: new_stats}}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:approve_action, investigation_id, recommendation_id}, _from, state) do
    case :ets.lookup(@investigations_table, investigation_id) do
      [{^investigation_id, investigation}] ->
        case execute_recommendation(investigation, recommendation_id) do
          {:ok, result} ->
            new_stats = update_stat(state.stats, :actions_executed)
            {:reply, {:ok, result}, %{state | stats: new_stats}}

          {:error, reason} ->
            {:reply, {:error, reason}, state}
        end

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:reject_action, investigation_id, recommendation_id, reason}, _from, state) do
    case :ets.lookup(@investigations_table, investigation_id) do
      [{^investigation_id, investigation}] ->
        updated_recommendations = Enum.map(investigation.recommendations, fn rec ->
          if rec.id == recommendation_id do
            Map.put(rec, :rejected, true)
            |> Map.put(:rejection_reason, reason)
          else
            rec
          end
        end)

        updated = %{investigation |
          recommendations: updated_recommendations,
          updated_at: DateTime.utc_now()
        }
        :ets.insert(@investigations_table, {investigation_id, updated})
        {:reply, :ok, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:explain_investigation, investigation_id}, _from, state) do
    case :ets.lookup(@investigations_table, investigation_id) do
      [{^investigation_id, investigation}] ->
        explanation = generate_natural_language_explanation(investigation)
        updated = %{investigation | explanation: explanation, updated_at: DateTime.utc_now()}
        :ets.insert(@investigations_table, {investigation_id, updated})
        {:reply, {:ok, explanation}, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  @impl true
  def handle_call({:auto_triage, alert_id}, _from, state) do
    # Auto-triage uses the same logic as triage_alert but with automatic context analysis
    case do_triage_alert(alert_id, state) do
      {:ok, investigation_id, new_state} ->
        # Immediately analyze and provide triage result
        case :ets.lookup(@investigations_table, investigation_id) do
          [{^investigation_id, investigation}] ->
            triage_result = %{
              investigation_id: investigation_id,
              priority: investigation.triage_result && investigation.triage_result.priority || :medium,
              severity: investigation.alert && investigation.alert.severity || "medium",
              confidence: investigation.triage_result && investigation.triage_result.confidence || 0.5,
              recommended_actions: Enum.take(investigation.recommendations || [], 3),
              auto_triaged: true,
              triaged_at: DateTime.utc_now()
            }
            {:reply, {:ok, triage_result}, new_state}

          [] ->
            {:reply, {:error, :investigation_not_found}, state}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:get_investigation, investigation_id, opts}, _from, state) do
    case :ets.lookup(@investigations_table, investigation_id) do
      [{^investigation_id, investigation}] ->
        # Apply optional enrichments
        result = case opts do
          %{include_timeline: true} ->
            Map.put(investigation, :timeline, build_investigation_timeline(investigation))

          %{include_evidence: true} ->
            evidence = Map.get(investigation, :evidence, [])
            Map.put(investigation, :evidence_details, evidence)

          %{include_recommendations: true} ->
            recs = investigation.recommendations || []
            Map.put(investigation, :all_recommendations, recs)

          _ ->
            investigation
        end

        {:reply, {:ok, result}, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:start_investigation, params}, _from, state) when is_map(params) do
    # Start investigation from params (without requiring an existing alert)
    investigation_id = generate_investigation_id()

    investigation = %{
      id: investigation_id,
      state: :in_progress,
      created_at: DateTime.utc_now(),
      updated_at: DateTime.utc_now(),
      alert: params[:alert] || %{id: params[:alert_id], severity: params[:severity] || "medium"},
      source: params[:source] || :manual,
      triage_result: nil,
      hypotheses: [],
      evidence: [],
      recommendations: [],
      analyst_notes: params[:notes]
    }

    :ets.insert(@investigations_table, {investigation_id, investigation})

    # Start investigation process
    Process.send_after(self(), {:continue_investigation, investigation_id}, 100)

    new_stats = update_stat(state.stats, :investigations_started)
    {:reply, {:ok, investigation_id}, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:submit_feedback, params}, _from, state) when is_map(params) do
    investigation_id = params[:investigation_id]
    feedback = Map.drop(params, [:investigation_id])

    case :ets.lookup(@investigations_table, investigation_id) do
      [{^investigation_id, investigation}] ->
        updated = %{investigation |
          analyst_feedback: feedback,
          updated_at: DateTime.utc_now()
        }
        :ets.insert(@investigations_table, {investigation_id, updated})
        :ets.insert(@feedback_table, {investigation_id, feedback})

        # Learn from feedback
        learn_from_feedback(investigation, feedback)

        new_stats = update_stat(state.stats, :feedback_received)
        {:reply, :ok, %{state | stats: new_stats}}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:resolve_investigation, investigation_id, resolution}, _from, state) do
    case :ets.lookup(@investigations_table, investigation_id) do
      [{^investigation_id, investigation}] ->
        updated = %{investigation |
          state: :resolved,
          resolution: resolution,
          updated_at: DateTime.utc_now()
        }
        :ets.insert(@investigations_table, {investigation_id, updated})

        new_stats = update_stat(state.stats, :investigations_completed)
        {:reply, :ok, %{state | stats: new_stats}}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_info({:continue_investigation, investigation_id}, state) do
    case :ets.lookup(@investigations_table, investigation_id) do
      [{^investigation_id, investigation}] ->
        previous_state = investigation.state
        {updated_investigation, new_stats} = advance_investigation(investigation, state.stats)
        :ets.insert(@investigations_table, {investigation_id, updated_investigation})

        # Broadcast state transition if state changed
        if updated_investigation.state != previous_state do
          broadcast_investigation_update(investigation_id, :state_changed, %{
            from: previous_state,
            to: updated_investigation.state,
            confidence: updated_investigation.confidence
          })
        end

        # Schedule next step if not terminal state
        unless updated_investigation.state in [:resolved, :escalated, :awaiting_review] do
          Process.send_after(self(), {:continue_investigation, investigation_id}, 100)
        end

        {:noreply, %{state | stats: new_stats}}

      [] ->
        {:noreply, state}
    end
  end

  @impl true
  def handle_info({:investigation_timeout, investigation_id}, state) do
    case :ets.lookup(@investigations_table, investigation_id) do
      [{^investigation_id, investigation}] when investigation.state not in [:resolved, :escalated] ->
        Logger.warning("Investigation #{investigation_id} timed out, escalating")
        updated = %{investigation |
          state: :escalated,
          resolution: %{reason: :timeout, message: "Investigation timed out"},
          updated_at: DateTime.utc_now()
        }
        :ets.insert(@investigations_table, {investigation_id, updated})
        {:noreply, state}

      _ ->
        {:noreply, state}
    end
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Investigation State Machine
  # ============================================================================

  defp do_triage_alert(alert_id, state) do
    with {:ok, alert} <- fetch_alert(alert_id) do
      investigation_id = generate_investigation_id()
      now = DateTime.utc_now()

      investigation = %Investigation{
        id: investigation_id,
        alert_id: alert_id,
        alert: alert,
        state: :pending,
        started_at: now,
        updated_at: now,
        hypotheses: [],
        evidence: [],
        correlations: [],
        recommendations: [],
        confidence: 0.0
      }

      :ets.insert(@investigations_table, {investigation_id, investigation})

      # Schedule investigation processing
      send(self(), {:continue_investigation, investigation_id})

      # Set timeout
      Process.send_after(self(), {:investigation_timeout, investigation_id}, @investigation_timeout)

      new_stats = update_stat(state.stats, :alerts_triaged)
      {:ok, investigation_id, %{state | stats: new_stats}}
    end
  end

  defp advance_investigation(investigation, stats) do
    case investigation.state do
      :pending ->
        advance_to_triaging(investigation, stats)

      :triaging ->
        advance_to_investigating(investigation, stats)

      :investigating ->
        advance_to_hypothesis_validation(investigation, stats)

      :hypothesis_validation ->
        advance_to_evidence_collection(investigation, stats)

      :evidence_collection ->
        advance_to_action_recommendation(investigation, stats)

      :action_recommendation ->
        advance_to_awaiting_review(investigation, stats)

      terminal when terminal in [:awaiting_review, :resolved, :escalated] ->
        {investigation, stats}
    end
  end

  defp advance_to_triaging(investigation, stats) do
    Logger.debug("Investigation #{investigation.id}: Starting triage")

    triage_result = perform_triage(investigation.alert)

    updated = %{investigation |
      state: :triaging,
      triage_result: triage_result,
      confidence: triage_result.confidence,
      updated_at: DateTime.utc_now()
    }

    {updated, stats}
  end

  defp advance_to_investigating(investigation, stats) do
    Logger.debug("Investigation #{investigation.id}: Starting investigation")

    # Generate initial hypotheses based on triage
    hypotheses = generate_hypotheses(investigation)

    updated = %{investigation |
      state: :investigating,
      hypotheses: hypotheses,
      updated_at: DateTime.utc_now()
    }

    new_stats = Map.update(stats, :hypotheses_generated, length(hypotheses), &(&1 + length(hypotheses)))

    {updated, new_stats}
  end

  defp advance_to_hypothesis_validation(investigation, stats) do
    Logger.debug("Investigation #{investigation.id}: Validating hypotheses")

    # Validate each hypothesis
    validated_hypotheses = Enum.map(investigation.hypotheses, &validate_hypothesis(&1, investigation))

    # Calculate overall confidence
    confidence = calculate_hypothesis_confidence(validated_hypotheses)

    validated_count = Enum.count(validated_hypotheses, & &1.validated)

    updated = %{investigation |
      state: :hypothesis_validation,
      hypotheses: validated_hypotheses,
      confidence: confidence,
      updated_at: DateTime.utc_now()
    }

    new_stats = Map.update(stats, :hypotheses_validated, validated_count, &(&1 + validated_count))

    {updated, new_stats}
  end

  defp advance_to_evidence_collection(investigation, stats) do
    Logger.debug("Investigation #{investigation.id}: Collecting evidence")

    # Collect evidence for validated hypotheses
    evidence = collect_evidence(investigation)
    correlations = correlate_evidence(evidence, investigation)

    updated = %{investigation |
      state: :evidence_collection,
      evidence: evidence,
      correlations: correlations,
      updated_at: DateTime.utc_now()
    }

    # Store evidence in ETS for cross-investigation correlation
    Enum.each(evidence, fn ev ->
      :ets.insert(@evidence_table, {investigation.id, ev})
    end)

    {updated, stats}
  end

  defp advance_to_action_recommendation(investigation, stats) do
    Logger.debug("Investigation #{investigation.id}: Generating recommendations")

    recommendations = generate_recommendations(investigation)

    # Update confidence based on evidence
    confidence = calculate_final_confidence(investigation)

    updated = %{investigation |
      state: :action_recommendation,
      recommendations: recommendations,
      confidence: confidence,
      updated_at: DateTime.utc_now()
    }

    new_stats = Map.update(stats, :actions_recommended, length(recommendations), &(&1 + length(recommendations)))

    {updated, new_stats}
  end

  defp advance_to_awaiting_review(investigation, stats) do
    Logger.debug("Investigation #{investigation.id}: Awaiting analyst review")

    # Generate explanation
    explanation = generate_natural_language_explanation(investigation)

    # Auto-execute high-confidence actions if enabled
    {auto_executed, remaining} = maybe_auto_execute(investigation.recommendations, investigation)

    updated = %{investigation |
      state: :awaiting_review,
      recommendations: remaining,
      explanation: explanation,
      updated_at: DateTime.utc_now()
    }

    new_stats = if length(auto_executed) > 0 do
      Map.update(stats, :actions_executed, length(auto_executed), &(&1 + length(auto_executed)))
    else
      stats
    end

    {updated, new_stats}
  end

  # ============================================================================
  # Triage Engine
  # ============================================================================

  defp perform_triage(alert) do
    severity_score = triage_severity(alert)
    context_score = triage_context(alert)
    historical_score = triage_historical(alert)

    # Weighted combination
    overall_score = severity_score * 0.4 + context_score * 0.35 + historical_score * 0.25

    priority = cond do
      overall_score >= 0.9 -> :critical
      overall_score >= 0.7 -> :high
      overall_score >= 0.5 -> :medium
      overall_score >= 0.3 -> :low
      true -> :informational
    end

    %{
      priority: priority,
      confidence: overall_score,
      severity_analysis: %{
        score: severity_score,
        factors: analyze_severity_factors(alert)
      },
      context_analysis: %{
        score: context_score,
        factors: analyze_context_factors(alert)
      },
      historical_analysis: %{
        score: historical_score,
        similar_alerts: find_similar_alerts(alert)
      },
      recommended_sla: calculate_sla(priority),
      auto_investigation: overall_score >= @medium_confidence_threshold
    }
  end

  defp triage_severity(alert) do
    base_score = case alert.severity do
      "critical" -> 1.0
      "high" -> 0.8
      "medium" -> 0.5
      "low" -> 0.3
      _ -> 0.1
    end

    # Boost for specific MITRE techniques
    technique_boost = Enum.reduce(alert.mitre_techniques || [], 0.0, fn tech, acc ->
      cond do
        String.starts_with?(tech, "T1003") -> acc + 0.15  # Credential access
        String.starts_with?(tech, "T1486") -> acc + 0.2   # Ransomware
        String.starts_with?(tech, "T1059") -> acc + 0.1   # Command execution
        true -> acc
      end
    end)

    min(base_score + technique_boost, 1.0)
  end

  defp triage_context(alert) do
    factors = []

    # Check asset criticality with real score from Registry
    criticality_score = get_asset_criticality_score(alert.agent_id)
    factors = if criticality_score >= 0.7 do
      [{:critical_asset, criticality_score * 0.3} | factors]
    else
      if criticality_score >= 0.4 do
        [{:elevated_asset, criticality_score * 0.15} | factors]
      else
        factors
      end
    end

    # Check business hours
    factors = if in_business_hours?(), do: factors, else: [{:off_hours, 0.1} | factors]

    # Check for related alerts
    related_count = count_related_alerts(alert)
    factors = if related_count > 0, do: [{:related_alerts, min(related_count * 0.05, 0.2)} | factors], else: factors

    # Check agent status
    factors = case Registry.get(alert.agent_id) do
      {:ok, %{status: :isolated}} -> [{:already_isolated, 0.1} | factors]
      _ -> factors
    end

    base_score = 0.5
    boost = Enum.reduce(factors, 0.0, fn {_type, score}, acc -> acc + score end)

    min(base_score + boost, 1.0)
  end

  defp triage_historical(alert) do
    # Check if similar alerts were true positives
    similar = find_similar_alerts(alert)

    if Enum.empty?(similar) do
      0.5  # Neutral if no history
    else
      true_positive_rate = Enum.count(similar, & &1.confirmed_threat) / length(similar)
      true_positive_rate
    end
  end

  defp analyze_severity_factors(alert) do
    [
      %{factor: "Base Severity", value: alert.severity, impact: "primary"},
      %{factor: "MITRE Techniques", value: length(alert.mitre_techniques || []), impact: "high"},
      %{factor: "Event Count", value: length(alert.event_ids || []), impact: "medium"}
    ]
  end

  defp analyze_context_factors(alert) do
    criticality = get_asset_criticality(alert.agent_id)
    criticality_score = get_asset_criticality_score(alert.agent_id)

    agent_status = case Registry.get(alert.agent_id) do
      {:ok, info} -> to_string(info[:status] || "unknown")
      _ -> "unknown"
    end

    [
      %{factor: "Asset Criticality", value: criticality, score: criticality_score, impact: "high"},
      %{factor: "Agent Status", value: agent_status, impact: "medium"},
      %{factor: "Time Context", value: if(in_business_hours?(), do: "business_hours", else: "off_hours"), impact: "low"},
      %{factor: "Related Alerts", value: count_related_alerts(alert), impact: "medium"}
    ]
  end

  defp calculate_sla(priority) do
    case priority do
      :critical -> %{response_minutes: 15, resolution_hours: 4}
      :high -> %{response_minutes: 60, resolution_hours: 24}
      :medium -> %{response_minutes: 240, resolution_hours: 72}
      :low -> %{response_minutes: 1440, resolution_hours: 168}
      _ -> %{response_minutes: 2880, resolution_hours: 336}
    end
  end

  # ============================================================================
  # Hypothesis Generation and Validation
  # ============================================================================

  defp generate_hypotheses(investigation) do
    alert = investigation.alert
    triage = investigation.triage_result

    hypotheses = []

    # Generate hypotheses based on MITRE techniques
    technique_hypotheses = Enum.flat_map(alert.mitre_techniques || [], fn technique ->
      generate_technique_hypotheses(technique, alert)
    end)
    hypotheses = hypotheses ++ technique_hypotheses

    # Generate hypotheses based on alert title/description patterns
    pattern_hypotheses = generate_pattern_hypotheses(alert)
    hypotheses = hypotheses ++ pattern_hypotheses

    # Generate correlation-based hypotheses
    correlation_hypotheses = generate_correlation_hypotheses(alert)
    hypotheses = hypotheses ++ correlation_hypotheses

    # Deduplicate and rank
    hypotheses
    |> Enum.uniq_by(& &1.type)
    |> Enum.sort_by(& &1.confidence, :desc)
    |> Enum.take(10)
  end

  defp generate_technique_hypotheses(technique, alert) do
    case technique do
      t when t in ["T1059", "T1059.001"] ->
        [%Hypothesis{
          id: generate_id(),
          type: :malicious_script_execution,
          description: "Malicious script execution detected - possible initial access or lateral movement",
          indicators: ["PowerShell execution", "Encoded commands", "Bypass attempts"],
          mitre_technique: technique,
          confidence: 0.7,
          validated: false,
          evidence_refs: []
        }]

      t when t in ["T1003", "T1003.001"] ->
        [%Hypothesis{
          id: generate_id(),
          type: :credential_theft,
          description: "Credential theft attempt - LSASS memory access or SAM extraction",
          indicators: ["LSASS access", "Mimikatz signatures", "Procdump usage"],
          mitre_technique: technique,
          confidence: 0.85,
          validated: false,
          evidence_refs: []
        }]

      "T1486" ->
        [%Hypothesis{
          id: generate_id(),
          type: :ransomware_activity,
          description: "Potential ransomware activity - encryption or shadow copy deletion",
          indicators: ["Mass file encryption", "Shadow copy deletion", "Ransom note creation"],
          mitre_technique: technique,
          confidence: 0.9,
          validated: false,
          evidence_refs: []
        }]

      t when t in ["T1021", "T1021.001", "T1021.002"] ->
        [%Hypothesis{
          id: generate_id(),
          type: :lateral_movement,
          description: "Lateral movement detected - remote service execution",
          indicators: ["Remote execution tools", "PsExec/WMI usage", "RDP connections"],
          mitre_technique: technique,
          confidence: 0.75,
          validated: false,
          evidence_refs: []
        }]

      _ ->
        []
    end
  end

  defp generate_pattern_hypotheses(alert) do
    title = String.downcase(alert.title || "")
    description = String.downcase(alert.description || "")
    combined = title <> " " <> description

    hypotheses = []

    hypotheses = if String.contains?(combined, ["malware", "virus", "trojan"]) do
      [%Hypothesis{
        id: generate_id(),
        type: :malware_infection,
        description: "Malware infection detected based on alert patterns",
        indicators: extract_indicators_from_text(combined),
        mitre_technique: nil,
        confidence: 0.6,
        validated: false,
        evidence_refs: []
      } | hypotheses]
    else
      hypotheses
    end

    hypotheses = if String.contains?(combined, ["suspicious", "anomaly", "unusual"]) do
      [%Hypothesis{
        id: generate_id(),
        type: :anomalous_behavior,
        description: "Anomalous behavior detected requiring investigation",
        indicators: ["Behavioral anomaly", "Unusual pattern"],
        mitre_technique: nil,
        confidence: 0.5,
        validated: false,
        evidence_refs: []
      } | hypotheses]
    else
      hypotheses
    end

    hypotheses
  end

  defp generate_correlation_hypotheses(alert) do
    # Check for related process chains
    case Correlator.get_process_tree(alert.agent_id) do
      {:ok, _tree} ->
        [%Hypothesis{
          id: generate_id(),
          type: :attack_chain,
          description: "Part of a larger attack chain based on process correlation",
          indicators: ["Process tree correlation", "Parent-child suspicious patterns"],
          mitre_technique: nil,
          confidence: 0.65,
          validated: false,
          evidence_refs: []
        }]

      _ ->
        []
    end
  end

  @doc """
  Validates a hypothesis against available evidence using Bayesian scoring.

  Collects evidence from process trees, network flows, file operations, and
  registry changes. Each piece of evidence is weighted by quality (direct
  observation > correlation > heuristic). Returns a confidence interval
  rather than a simple true/false.
  """
  defp validate_hypothesis(hypothesis, investigation) do
    # 1. Gather all available evidence for this hypothesis
    evidence_items = gather_evidence_for_hypothesis(hypothesis, investigation)

    # 2. Calculate prior probability from MITRE technique frequency
    prior = get_technique_prior(hypothesis.mitre_technique)

    # 3. Score each piece of evidence against the hypothesis
    scored_evidence = Enum.map(evidence_items, fn ev ->
      score = score_evidence_for_hypothesis(ev, hypothesis)
      Map.put(ev, :score, score)
    end)

    # 4. Separate supporting vs contradicting evidence
    supporting = Enum.filter(scored_evidence, fn ev -> ev.score > 0.0 end)
    contradicting = Enum.filter(scored_evidence, fn ev -> ev.score < 0.0 end)

    # 5. Combine evidence scores via weighted aggregation
    likelihood = combine_evidence_scores(scored_evidence)

    # 6. Bayesian update: posterior = prior * likelihood / normalizer
    posterior = bayesian_update(prior, likelihood)

    # 7. Determine validation outcome
    validated = posterior >= @medium_confidence_threshold

    evidence_refs = Enum.map(supporting, fn ev ->
      ev[:description] || ev[:source] || "evidence"
    end)

    rejection_reason = if validated do
      nil
    else
      cond do
        Enum.empty?(evidence_items) -> "No evidence available for validation"
        length(contradicting) > length(supporting) -> "Contradicting evidence outweighs supporting evidence"
        true -> "Insufficient evidence (posterior: #{Float.round(posterior * 100, 1)}%)"
      end
    end

    %{hypothesis |
      validated: validated,
      confidence: posterior,
      evidence_refs: evidence_refs,
      rejection_reason: rejection_reason
    }
  end

  # Gather evidence from multiple sources for a specific hypothesis type
  defp gather_evidence_for_hypothesis(hypothesis, investigation) do
    alert = investigation.alert
    agent_id = alert.agent_id
    description = String.downcase(alert.description || "")
    title = String.downcase(alert.title || "")

    base_evidence = gather_text_evidence(hypothesis.type, description, title)
    process_evidence = gather_process_evidence(hypothesis.type, agent_id)
    network_evidence = gather_network_evidence(hypothesis.type, agent_id)
    file_evidence = gather_file_evidence(hypothesis.type, alert)
    registry_evidence = gather_registry_evidence(hypothesis.type, agent_id)

    base_evidence ++ process_evidence ++ network_evidence ++ file_evidence ++ registry_evidence
  end

  # Text-based evidence from alert description and title
  defp gather_text_evidence(hypothesis_type, description, title) do
    combined = description <> " " <> title
    indicators = hypothesis_text_indicators(hypothesis_type)

    Enum.flat_map(indicators, fn {pattern_list, ev_description, quality, weight} ->
      if Enum.any?(pattern_list, &String.contains?(combined, &1)) do
        [%{
          source: :alert_text,
          quality: quality,
          weight: weight,
          description: ev_description,
          direction: :supporting
        }]
      else
        []
      end
    end)
  end

  # Define text indicators by hypothesis type
  defp hypothesis_text_indicators(:malicious_script_execution) do
    [
      {["-enc", "encodedcommand", "base64"], "Encoded command pattern detected", :direct_observation, 0.9},
      {["bypass", "-ep bypass", "executionpolicy"], "Execution policy bypass", :direct_observation, 0.85},
      {["invoke-expression", "iex", "downloadstring"], "Remote code execution pattern", :direct_observation, 0.9},
      {["hidden", "-windowstyle hidden", "-w hidden"], "Hidden window execution", :behavioral, 0.7}
    ]
  end

  defp hypothesis_text_indicators(:credential_theft) do
    [
      {["lsass", "mimikatz"], "Direct LSASS/Mimikatz indicator", :direct_observation, 0.95},
      {["credential", "procdump"], "Credential dumping tool", :direct_observation, 0.85},
      {["sam", "ntds", "secrets"], "Registry/database credential target", :tool_output, 0.8},
      {["sekurlsa", "logonpasswords", "kerberos::"], "Mimikatz module invocation", :direct_observation, 0.95},
      {["hashdump", "lsadump"], "Hash extraction pattern", :direct_observation, 0.9}
    ]
  end

  defp hypothesis_text_indicators(:ransomware_activity) do
    [
      {["vssadmin", "shadow", "wmic shadowcopy"], "Shadow copy deletion", :direct_observation, 0.95},
      {["encrypt", ".locked", ".crypt", ".enc"], "File encryption pattern", :behavioral, 0.85},
      {["ransom", "decrypt", "bitcoin", "wallet"], "Ransom note indicators", :direct_observation, 0.9},
      {["bcdedit", "recoveryenabled no"], "Boot recovery disabled", :direct_observation, 0.9}
    ]
  end

  defp hypothesis_text_indicators(:lateral_movement) do
    [
      {["psexec", "psexesvc"], "PsExec lateral movement", :direct_observation, 0.85},
      {["wmi", "wmic", "wmiprvse"], "WMI-based execution", :tool_output, 0.8},
      {["remote", "lateral"], "Remote access pattern", :heuristic, 0.5},
      {["smbexec", "atexec", "dcomexec"], "Impacket-style lateral movement", :direct_observation, 0.9},
      {["winrm", "invoke-command", "enter-pssession"], "PowerShell remoting", :direct_observation, 0.85}
    ]
  end

  defp hypothesis_text_indicators(:malware_infection) do
    [
      {["malware", "virus", "trojan"], "Malware keyword indicator", :heuristic, 0.5},
      {["detected", "quarantine", "threat"], "AV detection indicator", :tool_output, 0.7},
      {["packed", "obfuscated", "suspicious"], "Obfuscation indicator", :behavioral, 0.6}
    ]
  end

  defp hypothesis_text_indicators(:attack_chain) do
    [
      {["chain", "sequence", "multi-stage"], "Attack chain indicator", :heuristic, 0.5},
      {["parent", "child", "spawn"], "Process lineage indicator", :correlation, 0.6}
    ]
  end

  defp hypothesis_text_indicators(:anomalous_behavior) do
    [
      {["anomaly", "unusual", "abnormal"], "Anomaly indicator", :heuristic, 0.4},
      {["deviation", "baseline", "outlier"], "Baseline deviation indicator", :behavioral, 0.5}
    ]
  end

  defp hypothesis_text_indicators(_), do: []

  # Process tree evidence: walk parent chain, identify suspicious lineage
  defp gather_process_evidence(hypothesis_type, agent_id) do
    case Correlator.get_process_tree(agent_id) do
      {:ok, tree} ->
        vertex_count = Graph.num_vertices(tree)
        edge_count = Graph.num_edges(tree)

        evidence = []

        # Deep process tree suggests complex activity
        evidence = if vertex_count > 5 do
          [%{
            source: :process_tree,
            quality: :correlation,
            weight: 0.6,
            description: "Complex process tree (#{vertex_count} processes, #{edge_count} edges)",
            direction: :supporting,
            data: %{vertex_count: vertex_count, edge_count: edge_count}
          } | evidence]
        else
          evidence
        end

        # Check for suspicious chain patterns via correlator
        chain_evidence = case hypothesis_type do
          type when type in [:malicious_script_execution, :credential_theft, :lateral_movement, :attack_chain] ->
            # Analyze chains for all leaf nodes
            leaf_pids = Graph.vertices(tree)
            |> Enum.filter(fn v -> Graph.out_neighbors(tree, v) == [] end)
            |> Enum.take(5)

            Enum.flat_map(leaf_pids, fn pid ->
              case Correlator.analyze_chain(agent_id, pid) do
                {:ok, detections} when detections != [] ->
                  Enum.map(detections, fn det ->
                    %{
                      source: :process_chain_analysis,
                      quality: :direct_observation,
                      weight: 0.85,
                      description: det[:description] || "Suspicious process chain detected",
                      direction: :supporting,
                      data: det
                    }
                  end)
                _ -> []
              end
            end)

          _ -> []
        end

        evidence ++ chain_evidence

      _ -> []
    end
  rescue
    e ->
      Logger.warning("[AgenticAnalyst] Process evidence gathering failed: #{Exception.message(e)}")
      []
  end

  # Network evidence: query recent connections, identify C2 beaconing
  defp gather_network_evidence(hypothesis_type, agent_id) do
    evidence = []

    # Query recent network events from telemetry
    network_events = try do
      Telemetry.list_events_for_agent(agent_id, 50)
      |> Enum.filter(fn e ->
        event_type = to_string(e.event_type || "")
        event_type in ["network_connect", "network", "dns_query", "connection"]
      end)
    rescue
      e ->
        Logger.warning("[AgenticAnalyst] Network event query failed: #{Exception.message(e)}")
        []
    end

    # Check for suspicious outbound connections
    evidence = if length(network_events) > 0 do
      external_connections = Enum.filter(network_events, fn e ->
        payload = e.payload || %{}
        ip = payload["remote_ip"] || payload[:remote_ip] || ""
        not String.starts_with?(ip, ["10.", "172.16.", "192.168.", "127."])
      end)

      if length(external_connections) > 3 do
        [%{
          source: :network_analysis,
          quality: :behavioral,
          weight: 0.6,
          description: "#{length(external_connections)} external connections detected",
          direction: if(hypothesis_type in [:lateral_movement, :malware_infection, :attack_chain], do: :supporting, else: :neutral),
          data: %{external_connection_count: length(external_connections)}
        } | evidence]
      else
        evidence
      end
    else
      evidence
    end

    # Check for beaconing patterns (relevant for C2-related hypotheses)
    evidence = if hypothesis_type in [:malware_infection, :attack_chain] do
      try do
        correlation_result = Correlator.correlate_events(agent_id, time_window_ms: :timer.minutes(10), limit: 50)
        case correlation_result do
          {:ok, %{correlations: correlations}} when length(correlations) > 3 ->
            [%{
              source: :correlation_engine,
              quality: :correlation,
              weight: 0.7,
              description: "#{length(correlations)} event correlations found in 10-minute window",
              direction: :supporting,
              data: %{correlation_count: length(correlations)}
            } | evidence]
          _ -> evidence
        end
      rescue
        e ->
          Logger.warning("[AgenticAnalyst] Network correlation failed: #{Exception.message(e)}")
          evidence
      end
    else
      evidence
    end

    evidence
  end

  # File evidence: check hashes against threat intel, signing status
  defp gather_file_evidence(_hypothesis_type, alert) do
    evidence = []

    # Extract file hashes from alert event IDs
    event_ids = alert.event_ids || []
    file_hashes = Enum.flat_map(event_ids, fn event_id ->
      try do
        case Telemetry.get_event(event_id) do
          nil -> []
          event ->
            extracted = DetectionEvidence.extract_file_hashes(event.payload || %{})
            extracted
        end
      rescue
        e ->
          Logger.warning("[AgenticAnalyst] File hash extraction failed for event #{event_id}: #{Exception.message(e)}")
          []
      end
    end)

    # Check hashes against threat intel
    evidence = Enum.reduce(file_hashes, evidence, fn hash_info, acc ->
      sha256 = hash_info[:sha256]
      if sha256 do
        case check_threat_intel_hash(sha256) do
          {:ok, :malicious, details} ->
            [%{
              source: :threat_intel,
              quality: :tool_output,
              weight: 0.9,
              description: "File hash #{String.slice(sha256, 0, 12)}... flagged as malicious: #{details}",
              direction: :supporting,
              data: %{sha256: sha256, threat_intel_match: true}
            } | acc]
          {:ok, :clean} ->
            [%{
              source: :threat_intel,
              quality: :tool_output,
              weight: 0.5,
              description: "File hash #{String.slice(sha256, 0, 12)}... clean in threat intel",
              direction: :contradicting,
              data: %{sha256: sha256, threat_intel_match: false}
            } | acc]
          _ -> acc
        end
      else
        acc
      end
    end)

    evidence
  end

  # Check hash against threat intelligence
  defp check_threat_intel_hash(sha256) do
    case ThreatIntel.lookup(:hash_sha256, sha256) do
      {:ok, ioc} ->
        severity = ioc[:severity] || "unknown"
        {:ok, :malicious, "severity: #{severity}, source: #{ioc[:source] || "unknown"}"}
      :not_found ->
        {:ok, :clean}
      _ ->
        {:error, :lookup_failed}
    end
  rescue
    e ->
      Logger.warning("[AgenticAnalyst] Threat intel lookup failed for hash #{String.slice(sha256 || "", 0, 12)}: #{Exception.message(e)}")
      {:error, :lookup_failed}
  end

  # Registry evidence: check for persistence indicators
  defp gather_registry_evidence(hypothesis_type, agent_id) when hypothesis_type in [:malware_infection, :attack_chain, :malicious_script_execution] do
    try do
      events = Telemetry.list_events_for_agent(agent_id, 30)
      registry_events = Enum.filter(events, fn e ->
        event_type = to_string(e.event_type || "")
        event_type in ["registry_modify", "registry_create", "registry"]
      end)

      persistence_keys = ["run", "runonce", "currentversion\\run", "services",
                          "winlogon", "shell", "userinit", "startup"]

      suspicious_reg = Enum.filter(registry_events, fn e ->
        payload = e.payload || %{}
        key_path = String.downcase(to_string(payload["key_path"] || payload[:key_path] || ""))
        Enum.any?(persistence_keys, &String.contains?(key_path, &1))
      end)

      if length(suspicious_reg) > 0 do
        [%{
          source: :registry_analysis,
          quality: :direct_observation,
          weight: 0.85,
          description: "#{length(suspicious_reg)} suspicious registry modifications (persistence indicators)",
          direction: :supporting,
          data: %{suspicious_registry_count: length(suspicious_reg)}
        }]
      else
        []
      end
    rescue
      _ -> []
    end
  end

  defp gather_registry_evidence(_, _), do: []

  # Get the prior probability for a MITRE technique
  defp get_technique_prior(nil), do: @default_technique_prior
  defp get_technique_prior(technique_id) do
    # Check exact match first, then parent technique
    case Map.get(@technique_priors, technique_id) do
      nil ->
        # Try parent technique (e.g., T1059.001 -> T1059)
        parent = String.split(technique_id, ".") |> List.first()
        Map.get(@technique_priors, parent, @default_technique_prior)
      prior -> prior
    end
  end

  # Score a single piece of evidence for a hypothesis
  defp score_evidence_for_hypothesis(evidence, _hypothesis) do
    quality_weight = Map.get(@evidence_quality_weights, evidence.quality, 0.5)
    base_weight = evidence.weight || 0.5

    direction_multiplier = case evidence[:direction] do
      :supporting -> 1.0
      :contradicting -> -0.5
      :neutral -> 0.0
      _ -> 0.3
    end

    quality_weight * base_weight * direction_multiplier
  end

  # Combine multiple evidence scores into a single likelihood
  defp combine_evidence_scores([]), do: 0.5
  defp combine_evidence_scores(scored_evidence) do
    total_weight = scored_evidence
    |> Enum.map(fn ev ->
      quality_weight = Map.get(@evidence_quality_weights, ev.quality, 0.5)
      abs(ev[:score] || 0.0) * quality_weight
    end)
    |> Enum.sum()

    if total_weight == 0.0 do
      0.5
    else
      weighted_sum = scored_evidence
      |> Enum.map(fn ev ->
        quality_weight = Map.get(@evidence_quality_weights, ev.quality, 0.5)
        score = ev[:score] || 0.0
        # Normalize score to 0..1 range (from -0.5..1.0)
        normalized = (score + 0.5) / 1.5
        normalized * quality_weight * abs(score)
      end)
      |> Enum.sum()

      # Clamp to 0.05..0.95
      min(max(weighted_sum / total_weight, 0.05), 0.95)
    end
  end

  # Bayesian update: P(H|E) = P(E|H) * P(H) / P(E)
  defp bayesian_update(prior, likelihood) do
    # P(E) = P(E|H)*P(H) + P(E|~H)*P(~H)
    complement_likelihood = 1.0 - likelihood
    p_evidence = (likelihood * prior) + (complement_likelihood * (1.0 - prior))

    posterior = if p_evidence > 0.0 do
      (likelihood * prior) / p_evidence
    else
      prior
    end

    # Clamp to valid range
    min(max(posterior, 0.01), 0.99)
  end

  # ============================================================================
  # Evidence Collection
  # ============================================================================

  @doc """
  Collects evidence from multiple sources for an investigation.

  Gathers:
  - Alert data and associated events
  - Process tree with parent chain analysis for suspicious lineage
  - Network connections with C2 beaconing pattern detection
  - File hashes cross-referenced against threat intelligence
  - Registry modifications checked for persistence indicators
  """
  defp collect_evidence(investigation) do
    alert = investigation.alert
    agent_id = alert.agent_id
    validated_hypotheses = Enum.filter(investigation.hypotheses, & &1.validated)

    evidence = []

    # 1. Collect alert-based evidence (always present)
    alert_evidence = %Evidence{
      id: generate_id(),
      type: :alert_data,
      source: :detection_engine,
      timestamp: DateTime.utc_now(),
      data: %{
        alert_id: investigation.alert_id,
        severity: alert.severity,
        mitre_techniques: alert.mitre_techniques,
        event_ids: alert.event_ids,
        title: alert.title,
        description: alert.description
      },
      relevance_score: 1.0,
      supporting_hypotheses: Enum.map(investigation.hypotheses, & &1.id)
    }
    evidence = [alert_evidence | evidence]

    # 2. Process tree evidence: walk parent chain, detect suspicious lineage
    evidence = collect_process_tree_evidence(agent_id, validated_hypotheses, evidence)

    # 3. Network evidence: recent connections, C2 beaconing patterns
    evidence = collect_network_evidence(agent_id, evidence)

    # 4. File evidence: hashes checked against threat intel, entropy, signing
    evidence = collect_file_evidence(alert, evidence)

    # 5. Registry evidence: persistence indicator detection
    evidence = collect_registry_evidence(agent_id, evidence)

    # 6. Correlated event evidence: temporal/behavioral patterns
    evidence = collect_correlated_event_evidence(agent_id, evidence)

    evidence
  end

  # Collect process tree evidence with chain analysis
  defp collect_process_tree_evidence(agent_id, validated_hypotheses, evidence) do
    case Correlator.get_process_tree(agent_id) do
      {:ok, tree} ->
        vertex_count = Graph.num_vertices(tree)
        edge_count = Graph.num_edges(tree)

        # Basic tree structure evidence
        tree_evidence = %Evidence{
          id: generate_id(),
          type: :process_tree,
          source: :correlator,
          timestamp: DateTime.utc_now(),
          data: %{
            vertex_count: vertex_count,
            edge_count: edge_count,
            depth: estimate_tree_depth(tree)
          },
          relevance_score: if(vertex_count > 5, do: 0.9, else: 0.6),
          supporting_hypotheses: Enum.filter(validated_hypotheses, fn h ->
            h.type in [:attack_chain, :malicious_script_execution, :credential_theft, :lateral_movement]
          end) |> Enum.map(& &1.id)
        }
        evidence = [tree_evidence | evidence]

        # Analyze suspicious process chains (leaf nodes)
        leaf_pids = Graph.vertices(tree)
        |> Enum.filter(fn v -> Graph.out_neighbors(tree, v) == [] end)
        |> Enum.take(10)

        chain_evidence = Enum.flat_map(leaf_pids, fn pid ->
          case Correlator.analyze_chain(agent_id, pid) do
            {:ok, detections} when detections != [] ->
              [%Evidence{
                id: generate_id(),
                type: :suspicious_chain,
                source: :correlator,
                timestamp: DateTime.utc_now(),
                data: %{
                  pid: pid,
                  detections: Enum.map(detections, fn d ->
                    %{description: d[:description], techniques: d[:techniques] || [], tactics: d[:tactics] || []}
                  end),
                  detection_count: length(detections)
                },
                relevance_score: 0.9,
                supporting_hypotheses: Enum.filter(validated_hypotheses, fn h ->
                  h.type in [:attack_chain, :malicious_script_execution]
                end) |> Enum.map(& &1.id)
              }]
            _ -> []
          end
        end)

        evidence ++ chain_evidence

      _ ->
        evidence
    end
  rescue
    _ -> evidence
  end

  # Collect network-related evidence
  defp collect_network_evidence(agent_id, evidence) do
    try do
      events = Telemetry.list_events_for_agent(agent_id, 100)
      network_events = Enum.filter(events, fn e ->
        event_type = to_string(e.event_type || "")
        event_type in ["network_connect", "network", "dns_query", "connection"]
      end)

      if length(network_events) > 0 do
        # Classify connections
        external = Enum.filter(network_events, fn e ->
          payload = e.payload || %{}
          ip = to_string(payload["remote_ip"] || payload[:remote_ip] || "")
          ip != "" and not String.starts_with?(ip, ["10.", "172.16.", "192.168.", "127.", "0.0.0.0"])
        end)

        # Extract unique remote IPs
        remote_ips = external
        |> Enum.map(fn e ->
          payload = e.payload || %{}
          to_string(payload["remote_ip"] || payload[:remote_ip] || "")
        end)
        |> Enum.uniq()

        # Check each IP against threat intel
        malicious_ips = Enum.filter(remote_ips, fn ip ->
          case ThreatIntel.lookup(:ip, ip) do
            {:ok, _ioc} -> true
            _ -> false
          end
        end)

        # Build network evidence
        net_evidence = %Evidence{
          id: generate_id(),
          type: :network_connections,
          source: :telemetry,
          timestamp: DateTime.utc_now(),
          data: %{
            total_connections: length(network_events),
            external_connections: length(external),
            unique_remote_ips: length(remote_ips),
            malicious_ips: malicious_ips,
            has_threat_intel_hits: length(malicious_ips) > 0
          },
          relevance_score: cond do
            length(malicious_ips) > 0 -> 0.95
            length(external) > 10 -> 0.8
            length(external) > 3 -> 0.6
            true -> 0.4
          end,
          supporting_hypotheses: []
        }

        [net_evidence | evidence]
      else
        evidence
      end
    rescue
      _ -> evidence
    end
  end

  # Collect file evidence with hash checking
  defp collect_file_evidence(alert, evidence) do
    event_ids = alert.event_ids || []

    file_results = Enum.flat_map(event_ids, fn event_id ->
      try do
        case Telemetry.get_event(event_id) do
          nil -> []
          event ->
            payload = event.payload || %{}
            hashes = DetectionEvidence.extract_file_hashes(payload)
            network = DetectionEvidence.extract_network_indicators(payload)
            process_info = DetectionEvidence.extract_process_info(payload)

            # Check each hash against threat intel
            hash_results = Enum.map(hashes, fn h ->
              sha256 = h[:sha256]
              ti_result = if sha256 do
                case check_threat_intel_hash(sha256) do
                  {:ok, :malicious, details} -> %{match: true, details: details}
                  {:ok, :clean} -> %{match: false, details: "clean"}
                  _ -> %{match: :unknown, details: "lookup failed"}
                end
              else
                %{match: :no_hash, details: "no SHA256"}
              end

              Map.merge(h, %{threat_intel: ti_result})
            end)

            [{event_id, %{hashes: hash_results, network: network, process: process_info}}]
        end
      rescue
        _ -> []
      end
    end)

    if length(file_results) > 0 do
      malicious_count = file_results
      |> Enum.flat_map(fn {_, data} -> data.hashes end)
      |> Enum.count(fn h -> h[:threat_intel] && h.threat_intel[:match] == true end)

      file_ev = %Evidence{
        id: generate_id(),
        type: :file_analysis,
        source: :threat_intel,
        timestamp: DateTime.utc_now(),
        data: %{
          events_analyzed: length(file_results),
          file_details: Enum.map(file_results, fn {eid, data} ->
            %{event_id: eid, hashes: data.hashes, process: data.process}
          end),
          malicious_hash_count: malicious_count
        },
        relevance_score: if(malicious_count > 0, do: 0.95, else: 0.5),
        supporting_hypotheses: []
      }

      [file_ev | evidence]
    else
      evidence
    end
  end

  # Collect registry evidence for persistence
  defp collect_registry_evidence(agent_id, evidence) do
    try do
      events = Telemetry.list_events_for_agent(agent_id, 50)
      registry_events = Enum.filter(events, fn e ->
        event_type = to_string(e.event_type || "")
        event_type in ["registry_modify", "registry_create", "registry"]
      end)

      persistence_keys = ["run", "runonce", "currentversion\\run", "services",
                          "winlogon", "shell", "userinit", "startup",
                          "explorer\\shellserviceobjects", "image file execution"]

      suspicious = Enum.filter(registry_events, fn e ->
        payload = e.payload || %{}
        key_path = String.downcase(to_string(payload["key_path"] || payload[:key_path] || ""))
        Enum.any?(persistence_keys, &String.contains?(key_path, &1))
      end)

      if length(registry_events) > 0 do
        reg_ev = %Evidence{
          id: generate_id(),
          type: :registry_analysis,
          source: :telemetry,
          timestamp: DateTime.utc_now(),
          data: %{
            total_registry_events: length(registry_events),
            suspicious_persistence_count: length(suspicious),
            suspicious_keys: Enum.map(suspicious, fn e ->
              payload = e.payload || %{}
              to_string(payload["key_path"] || payload[:key_path] || "")
            end) |> Enum.take(10)
          },
          relevance_score: if(length(suspicious) > 0, do: 0.85, else: 0.3),
          supporting_hypotheses: []
        }

        [reg_ev | evidence]
      else
        evidence
      end
    rescue
      _ -> evidence
    end
  end

  # Collect correlated event evidence
  defp collect_correlated_event_evidence(agent_id, evidence) do
    try do
      case Correlator.correlate_events(agent_id, time_window_ms: :timer.minutes(15), limit: 100) do
        {:ok, %{correlations: correlations, total_events: total}} when length(correlations) > 0 ->
          corr_ev = %Evidence{
            id: generate_id(),
            type: :event_correlations,
            source: :correlator,
            timestamp: DateTime.utc_now(),
            data: %{
              total_events_analyzed: total,
              correlation_count: length(correlations),
              correlation_types: correlations
                |> Enum.map(& &1[:correlation_type])
                |> Enum.frequencies(),
              strongest_correlations: correlations
                |> Enum.sort_by(fn c -> c[:strength] || 0 end, :desc)
                |> Enum.take(5)
                |> Enum.map(fn c -> %{type: c[:correlation_type], strength: c[:strength], description: c[:description]} end)
            },
            relevance_score: min(0.5 + length(correlations) * 0.05, 0.95),
            supporting_hypotheses: []
          }

          [corr_ev | evidence]

        _ -> evidence
      end
    rescue
      _ -> evidence
    end
  end

  # Estimate the depth of the process tree
  defp estimate_tree_depth(tree) do
    roots = Graph.vertices(tree)
    |> Enum.filter(fn v -> Graph.in_neighbors(tree, v) == [] end)

    case roots do
      [] -> 0
      [root | _] -> do_estimate_depth(tree, root, 0)
    end
  rescue
    _ -> 0
  end

  defp do_estimate_depth(tree, vertex, current_depth) do
    children = Graph.out_neighbors(tree, vertex)
    if Enum.empty?(children) do
      current_depth
    else
      children
      |> Enum.map(fn child -> do_estimate_depth(tree, child, current_depth + 1) end)
      |> Enum.max(fn -> current_depth end)
    end
  end

  defp correlate_evidence(evidence, investigation) do
    # Cross-reference evidence with other investigations
    related_evidence = :ets.tab2list(@evidence_table)
    |> Enum.filter(fn {inv_id, _ev} -> inv_id != investigation.id end)
    |> Enum.map(fn {inv_id, ev} -> {inv_id, ev} end)

    # Find correlations
    Enum.flat_map(evidence, fn ev ->
      find_evidence_correlations(ev, related_evidence)
    end)
  end

  defp find_evidence_correlations(evidence, related_evidence) do
    Enum.flat_map(related_evidence, fn {inv_id, related_ev} ->
      if evidence_matches?(evidence, related_ev) do
        [%{
          source_evidence_id: evidence.id,
          related_investigation_id: inv_id,
          related_evidence_id: related_ev.id,
          correlation_type: determine_correlation_type(evidence, related_ev),
          confidence: calculate_correlation_confidence(evidence, related_ev)
        }]
      else
        []
      end
    end)
  end

  defp evidence_matches?(ev1, ev2) do
    ev1.type == ev2.type
  end

  defp determine_correlation_type(ev1, ev2) do
    cond do
      ev1.type == :process_tree and ev2.type == :process_tree -> :behavioral_similarity
      ev1.type == :alert_data and ev2.type == :alert_data -> :alert_pattern
      true -> :general
    end
  end

  defp calculate_correlation_confidence(ev1, ev2) do
    (ev1.relevance_score + ev2.relevance_score) / 2
  end

  # ============================================================================
  # Recommendation Engine
  # ============================================================================

  defp generate_recommendations(investigation) do
    recommendations = []

    # Generate based on validated hypotheses
    hypothesis_recommendations = investigation.hypotheses
    |> Enum.filter(& &1.validated)
    |> Enum.flat_map(&generate_hypothesis_recommendations/1)

    recommendations = recommendations ++ hypothesis_recommendations

    # Generate based on triage priority
    priority_recommendations = generate_priority_recommendations(investigation)
    recommendations = recommendations ++ priority_recommendations

    # Deduplicate and rank
    recommendations
    |> Enum.uniq_by(& &1.action_type)
    |> Enum.sort_by(& &1.confidence, :desc)
  end

  defp generate_hypothesis_recommendations(hypothesis) do
    case hypothesis.type do
      :credential_theft ->
        [
          %Recommendation{
            id: generate_id(),
            action_type: :isolate_network,
            target: :affected_host,
            parameters: %{duration_seconds: 3600},
            confidence: 0.9,
            rationale: "Isolate host to prevent credential use for lateral movement",
            risk_level: :medium,
            requires_approval: true,
            auto_executable: false
          },
          %Recommendation{
            id: generate_id(),
            action_type: :force_password_reset,
            target: :affected_user,
            parameters: %{},
            confidence: 0.85,
            rationale: "Reset credentials that may have been compromised",
            risk_level: :low,
            requires_approval: true,
            auto_executable: false
          }
        ]

      :ransomware_activity ->
        [
          %Recommendation{
            id: generate_id(),
            action_type: :isolate_network,
            target: :affected_host,
            parameters: %{duration_seconds: 86400},
            confidence: 0.95,
            rationale: "Immediately isolate to prevent ransomware spread",
            risk_level: :high,
            requires_approval: false,
            auto_executable: true
          },
          %Recommendation{
            id: generate_id(),
            action_type: :kill_process,
            target: :malicious_process,
            parameters: %{force: true},
            confidence: 0.9,
            rationale: "Terminate ransomware process immediately",
            risk_level: :medium,
            requires_approval: false,
            auto_executable: true
          }
        ]

      :malicious_script_execution ->
        [
          %Recommendation{
            id: generate_id(),
            action_type: :kill_process,
            target: :script_process,
            parameters: %{force: true},
            confidence: 0.8,
            rationale: "Terminate suspicious script execution",
            risk_level: :medium,
            requires_approval: true,
            auto_executable: false
          }
        ]

      :lateral_movement ->
        [
          %Recommendation{
            id: generate_id(),
            action_type: :block_remote_access,
            target: :source_host,
            parameters: %{},
            confidence: 0.85,
            rationale: "Block remote access from compromised source",
            risk_level: :medium,
            requires_approval: true,
            auto_executable: false
          }
        ]

      _ ->
        []
    end
  end

  defp generate_priority_recommendations(investigation) do
    case investigation.triage_result.priority do
      :critical ->
        [%Recommendation{
          id: generate_id(),
          action_type: :escalate_to_soc,
          target: :investigation,
          parameters: %{priority: :critical},
          confidence: 1.0,
          rationale: "Critical priority requires immediate SOC attention",
          risk_level: :low,
          requires_approval: false,
          auto_executable: true
        }]

      _ ->
        []
    end
  end

  defp maybe_auto_execute(recommendations, investigation) do
    {auto_exec, manual} = Enum.split_with(recommendations, fn rec ->
      rec.auto_executable and rec.confidence >= @auto_action_threshold
    end)

    # Execute auto-executable recommendations
    Enum.each(auto_exec, fn rec ->
      Logger.info("Auto-executing recommendation #{rec.id}: #{rec.action_type}")
      execute_recommendation(investigation, rec.id)
    end)

    {auto_exec, manual}
  end

  @doc """
  Executes a recommended response action with pre-execution validation.

  Performs the following steps:
  1. Looks up the recommendation by ID
  2. Validates pre-conditions (agent online, target accessible)
  3. Extracts PID/path from collected investigation evidence
  4. Executes via TamanduaServer.Response.Executor
  5. Records execution results in the investigation timeline
  6. Broadcasts update via PubSub
  """
  defp execute_recommendation(investigation, recommendation_id) do
    recommendation = Enum.find(investigation.recommendations, & &1.id == recommendation_id)

    unless recommendation do
      {:error, :recommendation_not_found}
    else
      agent_id = investigation.alert.agent_id

      # Pre-execution validation: check agent is online
      case validate_agent_online(agent_id) do
        :ok ->
          result = execute_action_by_type(recommendation, investigation)

          # Record execution in investigation timeline
          record_execution_in_timeline(investigation, recommendation, result)

          # Broadcast investigation update
          broadcast_investigation_update(investigation.id, :action_executed, %{
            recommendation_id: recommendation_id,
            action_type: recommendation.action_type,
            result: result
          })

          result

        {:error, reason} ->
          Logger.warning("Pre-execution validation failed for #{recommendation.action_type}: #{inspect(reason)}")
          {:error, reason}
      end
    end
  end

  # Validate that the target agent is online and reachable
  defp validate_agent_online(agent_id) do
    case Registry.get(agent_id) do
      {:ok, %{status: :online}} -> :ok
      {:ok, %{status: :isolated}} -> :ok  # Isolated agents can still receive commands
      {:ok, %{status: status}} -> {:error, {:agent_not_available, status}}
      {:error, :not_found} -> {:error, :agent_not_found}
    end
  rescue
    _ -> {:error, :registry_unavailable}
  end

  # Execute action based on recommendation type, extracting parameters from evidence
  defp execute_action_by_type(recommendation, investigation) do
    agent_id = investigation.alert.agent_id

    case recommendation.action_type do
      :isolate_network ->
        duration = recommendation.parameters[:duration_seconds] || 3600
        Logger.info("Executing network isolation on #{agent_id} for #{duration}s")
        Executor.isolate_network(agent_id, duration: duration)

      :kill_process ->
        # Extract PID from investigation evidence
        pid = extract_pid_from_evidence(investigation)
        if pid do
          Logger.info("Executing kill_process on #{agent_id}, PID: #{pid}")
          Executor.kill_process(agent_id, pid, force: recommendation.parameters[:force] || true)
        else
          # Fall back to process name-based kill if we have it
          case extract_process_name_from_evidence(investigation) do
            nil ->
              Logger.warning("No PID or process name found in evidence for kill_process on #{agent_id}")
              {:error, :no_target_pid}
            process_name ->
              Logger.info("Executing kill_process by name on #{agent_id}: #{process_name}")
              Executor.execute_action(agent_id, "kill_process", %{
                process_name: process_name,
                force: recommendation.parameters[:force] || true
              })
          end
        end

      :quarantine_file ->
        # Extract file path from recommendation params or evidence
        path = recommendation.parameters[:path] || extract_file_path_from_evidence(investigation)
        if path do
          Logger.info("Executing quarantine_file on #{agent_id}: #{path}")
          Executor.quarantine_file(agent_id, path)
        else
          Logger.warning("No file path found for quarantine on #{agent_id}")
          {:error, :no_file_path}
        end

      :block_remote_access ->
        # Block remote access from source
        Logger.info("Executing block_remote_access on #{agent_id}")
        Executor.execute_action(agent_id, "block_remote_access", %{
          duration_seconds: recommendation.parameters[:duration_seconds] || 3600
        })

      :force_password_reset ->
        Logger.info("Executing force_password_reset for investigation #{investigation.id}")
        Executor.execute_action(agent_id, "force_password_reset", %{
          reason: recommendation.rationale
        })

      :escalate_to_soc ->
        Logger.info("Escalating investigation #{investigation.id} to SOC")
        broadcast_investigation_update(investigation.id, :escalated_to_soc, %{
          priority: recommendation.parameters[:priority] || :high,
          rationale: recommendation.rationale
        })
        {:ok, %{status: :escalated, escalated_at: DateTime.utc_now()}}

      :collect_forensics ->
        Logger.info("Collecting forensics from #{agent_id}")
        Executor.collect_forensics(agent_id, recommendation.parameters || %{})

      other ->
        Logger.info("Executing generic action #{other} on #{agent_id}")
        Executor.execute_action(agent_id, to_string(other), recommendation.parameters || %{})
    end
  end

  # Extract PID from collected investigation evidence
  defp extract_pid_from_evidence(investigation) do
    # Check evidence for process information
    investigation.evidence
    |> Enum.find_value(fn ev ->
      case ev do
        %{type: :alert_data, data: data} ->
          # Check event payloads for PID
          event_ids = data[:event_ids] || []
          Enum.find_value(event_ids, fn event_id ->
            try do
              case Telemetry.get_event(event_id) do
                nil -> nil
                event ->
                  payload = event.payload || %{}
                  payload["pid"] || payload[:pid]
              end
            rescue
              _ -> nil
            end
          end)

        %{type: :suspicious_chain, data: %{pid: pid}} ->
          pid

        %{type: :file_analysis, data: %{file_details: details}} ->
          Enum.find_value(details, fn d ->
            process_info = d[:process] || %{}
            process_info[:pid]
          end)

        _ -> nil
      end
    end)
  end

  # Extract process name from evidence
  defp extract_process_name_from_evidence(investigation) do
    investigation.evidence
    |> Enum.find_value(fn ev ->
      case ev do
        %{type: :alert_data, data: data} ->
          event_ids = data[:event_ids] || []
          Enum.find_value(event_ids, fn event_id ->
            try do
              case Telemetry.get_event(event_id) do
                nil -> nil
                event ->
                  payload = event.payload || %{}
                  payload["name"] || payload[:name] || payload["process_name"] || payload[:process_name]
              end
            rescue
              _ -> nil
            end
          end)

        %{type: :file_analysis, data: %{file_details: details}} ->
          Enum.find_value(details, fn d ->
            process_info = d[:process] || %{}
            process_info[:name] || process_info[:process_name]
          end)

        _ -> nil
      end
    end)
  end

  # Extract file path from evidence
  defp extract_file_path_from_evidence(investigation) do
    investigation.evidence
    |> Enum.find_value(fn ev ->
      case ev do
        %{type: :file_analysis, data: %{file_details: details}} ->
          Enum.find_value(details, fn d ->
            hashes = d[:hashes] || []
            Enum.find_value(hashes, fn h -> h[:path] end)
          end)

        %{type: :alert_data, data: data} ->
          event_ids = data[:event_ids] || []
          Enum.find_value(event_ids, fn event_id ->
            try do
              case Telemetry.get_event(event_id) do
                nil -> nil
                event ->
                  payload = event.payload || %{}
                  payload["path"] || payload[:path] || payload["file_path"] || payload[:file_path]
              end
            rescue
              _ -> nil
            end
          end)

        _ -> nil
      end
    end)
  end

  # Record execution result in investigation timeline
  defp record_execution_in_timeline(investigation, recommendation, result) do
    status = case result do
      {:ok, _} -> :success
      {:error, _} -> :failed
      _ -> :unknown
    end

    timeline_entry = %{
      timestamp: DateTime.utc_now(),
      action: :action_executed,
      details: "#{recommendation.action_type} execution: #{status}",
      data: %{
        recommendation_id: recommendation.id,
        action_type: recommendation.action_type,
        status: status,
        result: inspect(result)
      }
    }

    # Update investigation with timeline entry
    case :ets.lookup(@investigations_table, investigation.id) do
      [{id, inv}] ->
        existing_timeline = Map.get(inv, :timeline, [])
        updated = Map.put(inv, :timeline, existing_timeline ++ [timeline_entry])
        :ets.insert(@investigations_table, {id, updated})
      _ -> :ok
    end
  end

  # Broadcast investigation updates via PubSub
  defp broadcast_investigation_update(investigation_id, event_type, payload) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "investigations:#{investigation_id}",
      {:investigation_update, event_type, payload}
    )

    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "investigations:all",
      {:investigation_update, investigation_id, event_type, payload}
    )
  rescue
    _ -> :ok
  end

  # ============================================================================
  # Natural Language Explanation
  # ============================================================================

  defp generate_natural_language_explanation(investigation) do
    alert = investigation.alert
    triage = investigation.triage_result
    hypotheses = investigation.hypotheses
    recommendations = investigation.recommendations

    validated_hypotheses = Enum.filter(hypotheses, & &1.validated)
    high_conf_recommendations = Enum.filter(recommendations, & &1.confidence >= @high_confidence_threshold)

    """
    ## Investigation Summary

    **Alert:** #{alert.title}
    **Severity:** #{alert.severity}
    **Investigation Confidence:** #{Float.round(investigation.confidence * 100, 1)}%

    ### Triage Assessment

    This alert was classified as **#{triage.priority}** priority with #{Float.round(triage.confidence * 100, 1)}% confidence.
    #{if triage.priority in [:critical, :high], do: "Immediate attention is recommended.", else: "Standard investigation procedures apply."}

    ### Analysis Findings

    #{if Enum.empty?(validated_hypotheses) do
      "No hypotheses were validated during the investigation. This may indicate a false positive or require manual analysis."
    else
      """
      The following threat hypotheses were validated:

      #{Enum.map_join(validated_hypotheses, "\n", fn h ->
        "- **#{format_hypothesis_type(h.type)}**: #{h.description} (#{Float.round(h.confidence * 100, 1)}% confidence)"
      end)}
      """
    end}

    ### Recommended Actions

    #{if Enum.empty?(recommendations) do
      "No automated actions are recommended. Manual review is suggested."
    else
      """
      #{Enum.map_join(high_conf_recommendations, "\n", fn r ->
        "- **#{format_action_type(r.action_type)}**: #{r.rationale}"
      end)}
      """
    end}

    ### Evidence Collected

    #{length(investigation.evidence)} pieces of evidence were collected.
    #{length(investigation.correlations)} correlations with other investigations were found.

    ---
    *Generated by Tamandua Agentic Security Analyst*
    """
  end

  defp format_hypothesis_type(type) do
    type
    |> Atom.to_string()
    |> String.replace("_", " ")
    |> String.split()
    |> Enum.map(&String.capitalize/1)
    |> Enum.join(" ")
  end

  defp format_action_type(type) do
    type
    |> Atom.to_string()
    |> String.replace("_", " ")
    |> String.split()
    |> Enum.map(&String.capitalize/1)
    |> Enum.join(" ")
  end

  # ============================================================================
  # Feedback Learning
  # ============================================================================

  defp learn_from_feedback(investigation, feedback) do
    Logger.info("Learning from feedback for investigation #{investigation.id}")

    case feedback do
      %{verdict: :true_positive} ->
        # Boost confidence for similar patterns
        store_learning(%{
          type: :true_positive,
          alert_patterns: extract_alert_patterns(investigation.alert),
          hypotheses: investigation.hypotheses,
          timestamp: DateTime.utc_now()
        })

      %{verdict: :false_positive, reason: reason} ->
        # Store false positive pattern for future filtering
        store_learning(%{
          type: :false_positive,
          alert_patterns: extract_alert_patterns(investigation.alert),
          reason: reason,
          timestamp: DateTime.utc_now()
        })

      %{corrected_severity: severity} ->
        # Adjust severity calibration
        store_learning(%{
          type: :severity_correction,
          original_severity: investigation.alert.severity,
          corrected_severity: severity,
          alert_patterns: extract_alert_patterns(investigation.alert),
          timestamp: DateTime.utc_now()
        })

      _ ->
        :ok
    end
  end

  defp store_learning(learning_data) do
    # In production, this would persist to database and update ML models
    Logger.debug("Stored learning data: #{inspect(learning_data)}")
  end

  defp extract_alert_patterns(alert) do
    %{
      severity: alert.severity,
      mitre_techniques: alert.mitre_techniques,
      title_keywords: extract_keywords(alert.title),
      description_keywords: extract_keywords(alert.description)
    }
  end

  defp extract_keywords(nil), do: []
  defp extract_keywords(text) do
    text
    |> String.downcase()
    |> String.split(~r/\W+/)
    |> Enum.filter(&(String.length(&1) > 3))
    |> Enum.uniq()
  end

  # ============================================================================
  # Helper Functions
  # ============================================================================

  defp fetch_alert(alert_id) do
    case Repo.get(Alert, alert_id) do
      nil -> {:error, :not_found}
      alert -> {:ok, Map.from_struct(alert)}
    end
  rescue
    _ -> {:error, :database_error}
  end

  defp generate_investigation_id do
    "inv_" <> Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)
  end

  defp generate_id do
    Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)
  end

  defp filter_investigations(investigations, opts) do
    investigations
    |> filter_by_state(opts[:state])
    |> filter_by_priority(opts[:priority])
    |> maybe_limit(opts[:limit])
  end

  defp filter_by_state(investigations, nil), do: investigations
  defp filter_by_state(investigations, state) do
    Enum.filter(investigations, & &1.state == state)
  end

  defp filter_by_priority(investigations, nil), do: investigations
  defp filter_by_priority(investigations, priority) do
    Enum.filter(investigations, & &1.triage_result && &1.triage_result.priority == priority)
  end

  defp maybe_limit(investigations, nil), do: investigations
  defp maybe_limit(investigations, limit), do: Enum.take(investigations, limit)

  defp calculate_hypothesis_confidence(hypotheses) do
    validated = Enum.filter(hypotheses, & &1.validated)

    if Enum.empty?(validated) do
      0.3
    else
      Enum.reduce(validated, 0.0, & &1.confidence + &2) / length(validated)
    end
  end

  defp calculate_final_confidence(investigation) do
    weights = [
      {investigation.triage_result.confidence, 0.3},
      {calculate_hypothesis_confidence(investigation.hypotheses), 0.4},
      {if(length(investigation.evidence) > 0, do: 0.8, else: 0.4), 0.3}
    ]

    Enum.reduce(weights, 0.0, fn {score, weight}, acc ->
      acc + (score * weight)
    end)
  end

  defp update_stat(stats, key) do
    Map.update(stats, key, 1, &(&1 + 1))
  end

  @doc """
  Checks whether an agent represents a critical asset.

  Queries the Agents.Registry for agent metadata (hostname, OS, status),
  and uses naming heuristics to determine criticality. Agents with
  hostnames matching patterns for domain controllers, database servers,
  certificate authorities, or executive workstations are considered critical.
  """
  defp is_critical_asset?(agent_id) do
    case get_asset_criticality_score(agent_id) do
      score when score >= 0.7 -> true
      _ -> false
    end
  end

  defp in_business_hours? do
    hour = DateTime.utc_now().hour
    hour >= 9 and hour < 17
  end

  defp count_related_alerts(alert) do
    # Count alerts from same agent in last hour
    Alerts.list_alerts(%{agent_id: alert.agent_id})
    |> Enum.count()
  rescue
    _ -> 0
  end

  defp find_similar_alerts(alert) do
    # Find alerts with similar patterns
    Alerts.list_alerts(%{})
    |> Enum.filter(fn a ->
      a.id != alert.id and
      (a.severity == alert.severity or
       Enum.any?(a.mitre_techniques || [], &(&1 in (alert.mitre_techniques || []))))
    end)
    |> Enum.map(fn a ->
      %{
        id: a.id,
        severity: a.severity,
        confirmed_threat: a.status == "resolved" and a.resolution_notes && String.contains?(String.downcase(a.resolution_notes || ""), "confirmed")
      }
    end)
    |> Enum.take(10)
  rescue
    _ -> []
  end

  @doc """
  Returns the asset criticality label for an agent.

  Queries the agent registry for metadata and computes a criticality
  classification based on hostname patterns, OS type, and agent status.
  """
  defp get_asset_criticality(agent_id) do
    score = get_asset_criticality_score(agent_id)
    cond do
      score >= 0.9 -> "critical"
      score >= 0.7 -> "high"
      score >= 0.4 -> "medium"
      true -> "standard"
    end
  end

  @doc """
  Computes a numeric asset criticality score (0.0 - 1.0) for an agent.

  Uses the Agents.Registry for live agent metadata and computes criticality
  based on:
  - Hostname patterns (domain controllers, DB servers, CA, exec workstations)
  - OS type (server OS higher than workstation)
  - Agent status (online agents prioritized for response actions)
  """
  defp get_asset_criticality_score(agent_id) do
    # Query agent registry for metadata
    agent_info = case Registry.get(agent_id) do
      {:ok, info} -> info
      _ -> %{}
    end

    hostname = String.downcase(to_string(agent_info[:hostname] || ""))
    os_type = String.downcase(to_string(agent_info[:os_type] || ""))
    status = agent_info[:status]

    base_score = 0.3

    # Hostname-based criticality patterns
    hostname_boost = cond do
      # Domain controllers
      Regex.match?(~r/(^dc|domain.?controller|^ad[0-9]|^pdc|^bdc)/i, hostname) -> 0.5
      # Database servers
      Regex.match?(~r/(^db|^sql|^mysql|^postgres|^oracle|^mongo|database)/i, hostname) -> 0.4
      # Certificate authority / PKI
      Regex.match?(~r/(^ca|^pki|cert.?auth|root.?ca)/i, hostname) -> 0.45
      # Exchange / mail servers
      Regex.match?(~r/(^mail|^mx|^exchange|^smtp)/i, hostname) -> 0.35
      # Web / application servers
      Regex.match?(~r/(^web|^app|^api|^proxy|^lb)/i, hostname) -> 0.3
      # Executive / VIP workstations
      Regex.match?(~r/(^exec|^ceo|^cfo|^cto|^vip|^c-suite)/i, hostname) -> 0.4
      # Build / CI-CD
      Regex.match?(~r/(^build|^jenkins|^ci|^cd|^deploy)/i, hostname) -> 0.25
      # File servers
      Regex.match?(~r/(^file|^nas|^share|^backup)/i, hostname) -> 0.3
      true -> 0.0
    end

    # OS-type boost (servers are more critical)
    os_boost = cond do
      String.contains?(os_type, "server") -> 0.15
      String.contains?(os_type, "windows") and String.contains?(hostname, "srv") -> 0.10
      String.contains?(os_type, "linux") -> 0.05
      true -> 0.0
    end

    # Status factor (online agents can be responded to)
    status_factor = case status do
      :online -> 1.0
      :isolated -> 0.9
      :offline -> 0.7
      _ -> 0.8
    end

    # Compute final score, clamped to 0..1
    raw_score = (base_score + hostname_boost + os_boost) * status_factor
    min(max(raw_score, 0.0), 1.0)
  rescue
    _ -> 0.3
  end

  defp extract_indicators_from_text(text) do
    # Extract potential indicators from text
    indicators = []

    indicators = if String.contains?(text, "powershell"), do: ["PowerShell" | indicators], else: indicators
    indicators = if String.contains?(text, "malware"), do: ["Malware" | indicators], else: indicators
    indicators = if String.contains?(text, "suspicious"), do: ["Suspicious behavior" | indicators], else: indicators

    indicators
  end

  defp build_investigation_timeline(investigation) do
    timeline = [
      %{
        timestamp: investigation.created_at,
        action: :investigation_started,
        details: "Investigation initiated"
      }
    ]

    # Add triage result to timeline
    timeline = if investigation.triage_result do
      timeline ++ [%{
        timestamp: investigation.triage_result[:timestamp] || investigation.created_at,
        action: :triage_completed,
        details: "Triage completed with priority: #{investigation.triage_result.priority}"
      }]
    else
      timeline
    end

    # Add hypothesis generation to timeline
    timeline = if length(investigation.hypotheses || []) > 0 do
      timeline ++ [%{
        timestamp: investigation.updated_at,
        action: :hypotheses_generated,
        details: "Generated #{length(investigation.hypotheses)} hypotheses"
      }]
    else
      timeline
    end

    # Add evidence gathering to timeline
    timeline = if length(investigation.evidence || []) > 0 do
      timeline ++ [%{
        timestamp: investigation.updated_at,
        action: :evidence_gathered,
        details: "Gathered #{length(investigation.evidence)} pieces of evidence"
      }]
    else
      timeline
    end

    Enum.sort_by(timeline, & &1.timestamp)
  end

  # ============================================================================
  # Public API Wrapper Functions
  # ============================================================================

  @doc """
  Auto-triage an alert using AI analysis.
  """
  def auto_triage(alert_id) do
    GenServer.call(__MODULE__, {:auto_triage, alert_id}, 30_000)
  end

  @doc """
  Get an investigation by ID with optional filters.
  """
  def get_investigation(investigation_id, opts \\ %{}) do
    GenServer.call(__MODULE__, {:get_investigation, investigation_id, opts})
  end

  @doc """
  Start a new investigation.
  """
  def start_investigation(params) when is_map(params) do
    GenServer.call(__MODULE__, {:start_investigation, params}, 30_000)
  end

  @doc """
  Submit feedback for an investigation or triage decision.
  """
  def submit_feedback(params) when is_map(params) do
    GenServer.call(__MODULE__, {:submit_feedback, params})
  end

  # ETS table for chat history
  @chat_history_table :agentic_chat_history

  @doc """
  Get chat history for the analyst interface.
  Retrieves stored chat messages from ETS, ordered by timestamp.
  """
  @spec get_chat_history() :: {:ok, [map()]}
  def get_chat_history do
    GenServer.call(__MODULE__, :get_chat_history)
  end

  @doc """
  Get chat history for a specific investigation.
  """
  @spec get_chat_history(String.t()) :: {:ok, [map()]}
  def get_chat_history(investigation_id) do
    GenServer.call(__MODULE__, {:get_chat_history, investigation_id})
  end

  @doc """
  Add a message to chat history.
  """
  @spec add_chat_message(String.t() | nil, map()) :: :ok
  def add_chat_message(investigation_id, message) do
    GenServer.cast(__MODULE__, {:add_chat_message, investigation_id, message})
  end

  @doc """
  Get AI-generated insights from recent analysis.
  Returns aggregated insights based on recent investigations, alerts, and patterns.
  """
  @spec get_insights() :: {:ok, [map()]}
  def get_insights do
    GenServer.call(__MODULE__, :get_insights)
  end

  @doc """
  Get insights for a specific investigation.
  """
  @spec get_insights(String.t()) :: {:ok, [map()]}
  def get_insights(investigation_id) do
    GenServer.call(__MODULE__, {:get_insights, investigation_id})
  end

  # Handle get_chat_history
  @impl true
  def handle_call(:get_chat_history, _from, state) do
    messages = get_all_chat_messages()
    {:reply, {:ok, messages}, state}
  end

  @impl true
  def handle_call({:get_chat_history, investigation_id}, _from, state) do
    messages = get_chat_messages_for_investigation(investigation_id)
    {:reply, {:ok, messages}, state}
  end

  # Handle get_insights
  @impl true
  def handle_call(:get_insights, _from, state) do
    insights = generate_insights_from_state(state)
    {:reply, {:ok, insights}, state}
  end

  @impl true
  def handle_call({:get_insights, investigation_id}, _from, state) do
    insights = generate_insights_for_investigation(investigation_id, state)
    {:reply, {:ok, insights}, state}
  end

  # Handle add_chat_message
  @impl true
  def handle_cast({:add_chat_message, investigation_id, message}, state) do
    store_chat_message(investigation_id, message)
    {:noreply, state}
  end

  # ============================================================================
  # Chat History Implementation
  # ============================================================================

  defp ensure_chat_history_table do
    if :ets.whereis(@chat_history_table) == :undefined do
      :ets.new(@chat_history_table, [:named_table, :bag, :public, read_concurrency: true])
    end
  end

  defp store_chat_message(investigation_id, message) do
    ensure_chat_history_table()

    entry = %{
      id: generate_id(),
      investigation_id: investigation_id,
      role: message[:role] || "user",
      content: message[:content] || "",
      timestamp: DateTime.utc_now(),
      metadata: message[:metadata] || %{}
    }

    key = investigation_id || :global
    :ets.insert(@chat_history_table, {key, entry})
  end

  defp get_all_chat_messages do
    ensure_chat_history_table()

    :ets.tab2list(@chat_history_table)
    |> Enum.map(fn {_key, msg} -> msg end)
    |> Enum.sort_by(& &1.timestamp, {:asc, DateTime})
    |> Enum.take(100)
  end

  defp get_chat_messages_for_investigation(investigation_id) do
    ensure_chat_history_table()

    :ets.lookup(@chat_history_table, investigation_id)
    |> Enum.map(fn {_key, msg} -> msg end)
    |> Enum.sort_by(& &1.timestamp, {:asc, DateTime})
  end

  # ============================================================================
  # Insights Generation Implementation
  # ============================================================================

  defp generate_insights_from_state(state) do
    insights = []

    # Insight 1: Investigation activity summary
    total_investigations = map_size(state.active_investigations)
    investigations_list = :ets.tab2list(@investigations_table)

    completed = Enum.count(investigations_list, fn {_id, inv} ->
      inv.state == :resolved
    end)

    pending = Enum.count(investigations_list, fn {_id, inv} ->
      inv.state in [:pending, :triaging, :investigating]
    end)

    insights = if total_investigations > 0 do
      [%{
        id: generate_id(),
        type: :activity_summary,
        title: "Investigation Activity",
        description: "#{total_investigations} active investigations: #{completed} resolved, #{pending} in progress",
        priority: if(pending > 5, do: :high, else: :medium),
        timestamp: DateTime.utc_now(),
        data: %{
          total: total_investigations,
          completed: completed,
          pending: pending
        }
      } | insights]
    else
      insights
    end

    # Insight 2: Hypothesis validation rate
    validated_count = state.stats[:hypotheses_validated] || 0
    generated_count = state.stats[:hypotheses_generated] || 0

    validation_rate = if generated_count > 0 do
      Float.round(validated_count / generated_count * 100, 1)
    else
      0.0
    end

    insights = if generated_count > 10 do
      priority = cond do
        validation_rate > 70 -> :low
        validation_rate > 40 -> :medium
        true -> :high
      end

      [%{
        id: generate_id(),
        type: :validation_rate,
        title: "Hypothesis Validation Rate",
        description: "#{validation_rate}% of generated hypotheses have been validated (#{validated_count}/#{generated_count})",
        priority: priority,
        timestamp: DateTime.utc_now(),
        data: %{
          validated: validated_count,
          generated: generated_count,
          rate: validation_rate
        }
      } | insights]
    else
      insights
    end

    # Insight 3: Recent alert patterns
    recent_alerts = try do
      Alerts.list_recent(limit: 50)
    rescue
      _ -> []
    end

    severity_distribution = recent_alerts
    |> Enum.group_by(& &1.severity)
    |> Enum.map(fn {sev, alerts} -> {sev, length(alerts)} end)
    |> Map.new()

    critical_count = severity_distribution["critical"] || 0
    high_count = severity_distribution["high"] || 0

    insights = if length(recent_alerts) > 0 do
      priority = cond do
        critical_count > 3 -> :high
        high_count > 5 -> :medium
        true -> :low
      end

      [%{
        id: generate_id(),
        type: :alert_pattern,
        title: "Recent Alert Distribution",
        description: "#{length(recent_alerts)} recent alerts: #{critical_count} critical, #{high_count} high severity",
        priority: priority,
        timestamp: DateTime.utc_now(),
        data: %{
          total: length(recent_alerts),
          distribution: severity_distribution
        }
      } | insights]
    else
      insights
    end

    # Insight 4: Common MITRE techniques
    mitre_counts = recent_alerts
    |> Enum.flat_map(fn alert ->
      alert.mitre_techniques || []
    end)
    |> Enum.frequencies()
    |> Enum.sort_by(fn {_tech, count} -> count end, :desc)
    |> Enum.take(5)

    insights = if length(mitre_counts) > 0 do
      top_techniques = Enum.map(mitre_counts, fn {tech, count} -> "#{tech} (#{count})" end)

      [%{
        id: generate_id(),
        type: :mitre_trends,
        title: "Common Attack Techniques",
        description: "Top MITRE techniques: #{Enum.join(top_techniques, ", ")}",
        priority: :medium,
        timestamp: DateTime.utc_now(),
        data: %{
          techniques: mitre_counts
        }
      } | insights]
    else
      insights
    end

    # Insight 5: Feedback loop status
    feedback_count = state.stats[:feedback_received] || 0
    false_positives = state.stats[:false_positives_identified] || 0
    true_positives = state.stats[:true_positives_confirmed] || 0

    insights = if feedback_count > 0 do
      [%{
        id: generate_id(),
        type: :feedback_summary,
        title: "Analyst Feedback Summary",
        description: "#{feedback_count} feedback entries: #{true_positives} true positives, #{false_positives} false positives",
        priority: :low,
        timestamp: DateTime.utc_now(),
        data: %{
          total_feedback: feedback_count,
          true_positives: true_positives,
          false_positives: false_positives
        }
      } | insights]
    else
      insights
    end

    Enum.reverse(insights)
  end

  defp generate_insights_for_investigation(investigation_id, _state) do
    case :ets.lookup(@investigations_table, investigation_id) do
      [{^investigation_id, investigation}] ->
        insights = []

        # Insight 1: Investigation status
        insights = [%{
          id: generate_id(),
          type: :investigation_status,
          title: "Investigation Status",
          description: "Current state: #{investigation.state}, Confidence: #{Float.round(investigation.confidence * 100, 1)}%",
          priority: if(investigation.state == :awaiting_review, do: :high, else: :medium),
          timestamp: DateTime.utc_now(),
          data: %{
            state: investigation.state,
            confidence: investigation.confidence
          }
        } | insights]

        # Insight 2: Validated hypotheses
        validated_hypotheses = Enum.filter(investigation.hypotheses || [], & &1.validated)

        insights = if length(validated_hypotheses) > 0 do
          hypothesis_types = Enum.map(validated_hypotheses, & &1.type)

          [%{
            id: generate_id(),
            type: :validated_hypotheses,
            title: "Validated Threat Hypotheses",
            description: "#{length(validated_hypotheses)} hypotheses validated: #{Enum.join(hypothesis_types, ", ")}",
            priority: :high,
            timestamp: DateTime.utc_now(),
            data: %{
              count: length(validated_hypotheses),
              types: hypothesis_types
            }
          } | insights]
        else
          insights
        end

        # Insight 3: Evidence collected
        evidence_count = length(investigation.evidence || [])

        insights = if evidence_count > 0 do
          [%{
            id: generate_id(),
            type: :evidence_collected,
            title: "Evidence Collection",
            description: "#{evidence_count} pieces of evidence collected",
            priority: :medium,
            timestamp: DateTime.utc_now(),
            data: %{
              count: evidence_count
            }
          } | insights]
        else
          insights
        end

        # Insight 4: Recommended actions
        recommendations = investigation.recommendations || []
        high_conf_recommendations = Enum.filter(recommendations, & &1.confidence >= 0.8)

        insights = if length(recommendations) > 0 do
          [%{
            id: generate_id(),
            type: :recommendations,
            title: "Response Recommendations",
            description: "#{length(recommendations)} actions recommended, #{length(high_conf_recommendations)} high-confidence",
            priority: if(length(high_conf_recommendations) > 0, do: :high, else: :medium),
            timestamp: DateTime.utc_now(),
            data: %{
              total: length(recommendations),
              high_confidence: length(high_conf_recommendations),
              actions: Enum.map(recommendations, & &1.action_type)
            }
          } | insights]
        else
          insights
        end

        Enum.reverse(insights)

      [] ->
        []
    end
  end
end
