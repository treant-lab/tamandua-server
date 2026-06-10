defmodule TamanduaServer.Agentic.LearningLoop do
  @moduledoc """
  Self-Improving Detection Loop

  Tracks agent performance over time and uses analyst feedback to continuously
  improve agent effectiveness. Monitors key metrics per agent and adjusts
  confidence thresholds, proposes detection rule refinements, and generates
  weekly performance reports.

  ## Metrics Tracked Per Agent

  - True positives (confirmed threats)
  - False positives (analyst marked as benign)
  - Mean time to resolution
  - Actions taken per execution
  - Analyst satisfaction (approval vs rejection rate)

  ## Self-Improvement Mechanisms

  1. **Confidence Adjustment**: When FP rate exceeds threshold, automatically
     raise the confidence threshold for triggering (reducing noise).

  2. **Rule Refinement Proposals**: Analyzes FP patterns and proposes filter
     additions or condition modifications to reduce false positives.

  3. **Action Optimization**: Tracks which action sequences are most effective
     and suggests reordering or removing unnecessary steps.

  4. **Weekly Reports**: Generates per-agent performance summaries with
     trends and recommendations.
  """

  use GenServer
  require Logger

  # ETS tables
  @metrics_table :learning_loop_metrics
  @feedback_table :learning_loop_feedback
  @adjustments_table :learning_loop_adjustments
  @reports_table :learning_loop_reports

  # Thresholds
  @fp_rate_threshold 0.3        # 30% FP rate triggers adjustment
  @min_samples_for_adjustment 10 # Minimum executions before adjusting
  @confidence_increment 0.05    # How much to raise threshold per adjustment
  @max_confidence_threshold 0.95 # Maximum threshold (don't make agents useless)

  # Report schedule (weekly)
  @report_interval_ms 7 * 24 * 3_600_000

  # ============================================================================
  # Types
  # ============================================================================

  defmodule AgentMetrics do
    @moduledoc "Performance metrics for a single agent"
    defstruct [
      :agent_id,
      :agent_name,
      true_positives: 0,
      false_positives: 0,
      true_negatives: 0,
      false_negatives: 0,
      total_executions: 0,
      total_actions: 0,
      total_resolution_time_ms: 0,
      analyst_approvals: 0,
      analyst_rejections: 0,
      analyst_modifications: 0,
      confidence_threshold: 0.5,
      last_adjustment_at: nil,
      adjustment_count: 0,
      created_at: nil,
      updated_at: nil
    ]

    @type t :: %__MODULE__{
      agent_id: String.t(),
      agent_name: String.t(),
      true_positives: non_neg_integer(),
      false_positives: non_neg_integer(),
      true_negatives: non_neg_integer(),
      false_negatives: non_neg_integer(),
      total_executions: non_neg_integer(),
      total_actions: non_neg_integer(),
      total_resolution_time_ms: non_neg_integer(),
      analyst_approvals: non_neg_integer(),
      analyst_rejections: non_neg_integer(),
      analyst_modifications: non_neg_integer(),
      confidence_threshold: float(),
      last_adjustment_at: DateTime.t() | nil,
      adjustment_count: non_neg_integer(),
      created_at: DateTime.t() | nil,
      updated_at: DateTime.t() | nil
    }
  end

  defmodule FeedbackEntry do
    @moduledoc "A single analyst feedback record"
    defstruct [
      :id,
      :agent_id,
      :execution_id,
      :feedback_type,
      :verdict,
      :notes,
      :analyst_id,
      :timestamp
    ]
  end

  defmodule RuleRefinement do
    @moduledoc "A proposed refinement to an agent's detection rules"
    defstruct [
      :id,
      :agent_id,
      :type,
      :description,
      :current_value,
      :proposed_value,
      :rationale,
      :confidence,
      :status,
      :created_at
    ]
  end

  # ============================================================================
  # GenServer State
  # ============================================================================

  defstruct [
    :stats,
    :last_report_at
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Record analyst feedback for an agent execution.

  ## Feedback types
  - `:true_positive` - Confirmed threat, agent was correct
  - `:false_positive` - Benign activity, agent was wrong
  - `:approved` - Analyst approved the agent's actions
  - `:rejected` - Analyst rejected the agent's actions
  - `:modified` - Analyst modified the agent's actions
  """
  @spec record_feedback(map()) :: :ok
  def record_feedback(feedback) do
    GenServer.cast(__MODULE__, {:record_feedback, feedback})
  end

  @doc """
  Record an agent execution for metric tracking.
  """
  @spec record_execution(String.t(), String.t(), :success | :failure, non_neg_integer(), non_neg_integer()) :: :ok
  def record_execution(agent_id, agent_name, outcome, actions_taken, duration_ms) do
    GenServer.cast(__MODULE__, {:record_execution, agent_id, agent_name, outcome, actions_taken, duration_ms})
  end

  @doc """
  Get performance metrics for a specific agent.
  """
  @spec get_agent_metrics(String.t()) :: {:ok, AgentMetrics.t()} | {:error, :not_found}
  def get_agent_metrics(agent_id) do
    case :ets.lookup(@metrics_table, agent_id) do
      [{^agent_id, metrics}] -> {:ok, metrics}
      [] -> {:error, :not_found}
    end
  end

  @doc """
  Get performance metrics for all agents.
  """
  @spec get_all_metrics() :: [AgentMetrics.t()]
  def get_all_metrics do
    :ets.tab2list(@metrics_table)
    |> Enum.map(fn {_id, metrics} -> metrics end)
    |> Enum.sort_by(& &1.total_executions, :desc)
  end

  @doc """
  Get pending rule refinement proposals.
  """
  @spec get_refinement_proposals(keyword()) :: [RuleRefinement.t()]
  def get_refinement_proposals(opts \\ []) do
    status = Keyword.get(opts, :status, :proposed)

    :ets.tab2list(@adjustments_table)
    |> Enum.map(fn {_id, refinement} -> refinement end)
    |> Enum.filter(&(&1.status == status))
    |> Enum.sort_by(& &1.created_at, {:desc, DateTime})
  end

  @doc """
  Approve a rule refinement proposal, applying the change.
  """
  @spec approve_refinement(String.t()) :: :ok | {:error, term()}
  def approve_refinement(refinement_id) do
    GenServer.call(__MODULE__, {:approve_refinement, refinement_id})
  end

  @doc """
  Reject a rule refinement proposal.
  """
  @spec reject_refinement(String.t(), String.t()) :: :ok | {:error, term()}
  def reject_refinement(refinement_id, reason) do
    GenServer.call(__MODULE__, {:reject_refinement, refinement_id, reason})
  end

  @doc """
  Get the most recent performance report.
  """
  @spec get_latest_report() :: {:ok, map()} | {:error, :not_found}
  def get_latest_report do
    reports = :ets.tab2list(@reports_table)
    |> Enum.map(fn {_id, report} -> report end)
    |> Enum.sort_by(& &1.generated_at, {:desc, DateTime})

    case reports do
      [latest | _] -> {:ok, latest}
      [] -> {:error, :not_found}
    end
  end

  @doc """
  Force generation of a performance report.
  """
  @spec generate_report() :: {:ok, map()}
  def generate_report do
    GenServer.call(__MODULE__, :generate_report, 30_000)
  end

  @doc """
  Get learning loop statistics.
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
    Logger.info("[LearningLoop] Starting Self-Improving Detection Loop")

    :ets.new(@metrics_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@feedback_table, [:named_table, :bag, :public, read_concurrency: true])
    :ets.new(@adjustments_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@reports_table, [:named_table, :set, :public, read_concurrency: true])

    # Subscribe to agent events
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "agentic:orchestrator")

    # Schedule periodic analysis
    Process.send_after(self(), :analyze_performance, 300_000)  # Every 5 minutes
    Process.send_after(self(), :generate_weekly_report, @report_interval_ms)

    state = %__MODULE__{
      stats: %{
        feedback_received: 0,
        executions_tracked: 0,
        adjustments_proposed: 0,
        adjustments_applied: 0,
        reports_generated: 0
      },
      last_report_at: nil
    }

    {:ok, state}
  end

  # Track completed executions
  @impl true
  def handle_info({:execution_completed, _exec_id, agent_id, status, context}, state) do
    agent_name = context[:agent_name] || "Unknown"
    actions_taken = context[:actions_taken] || 0
    duration_ms = context[:duration_ms] || 0

    outcome = if status == :completed, do: :success, else: :failure
    do_record_execution(agent_id, agent_name, outcome, actions_taken, duration_ms)

    new_stats = Map.update!(state.stats, :executions_tracked, &(&1 + 1))
    {:noreply, %{state | stats: new_stats}}
  end

  # Periodic performance analysis
  @impl true
  def handle_info(:analyze_performance, state) do
    new_state = analyze_all_agents(state)
    Process.send_after(self(), :analyze_performance, 300_000)
    {:noreply, new_state}
  end

  # Weekly report generation
  @impl true
  def handle_info(:generate_weekly_report, state) do
    report = do_generate_report()
    :ets.insert(@reports_table, {report.id, report})

    new_stats = Map.update!(state.stats, :reports_generated, &(&1 + 1))
    new_state = %{state | stats: new_stats, last_report_at: DateTime.utc_now()}

    Logger.info("[LearningLoop] Generated weekly performance report #{report.id}")

    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "agentic:reports",
      {:weekly_report_generated, report.id}
    )

    Process.send_after(self(), :generate_weekly_report, @report_interval_ms)
    {:noreply, new_state}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  @impl true
  def handle_cast({:record_feedback, feedback}, state) do
    agent_id = feedback[:agent_id]
    feedback_type = feedback[:feedback_type] || feedback[:type]

    entry = %FeedbackEntry{
      id: Ecto.UUID.generate(),
      agent_id: agent_id,
      execution_id: feedback[:execution_id],
      feedback_type: feedback_type,
      verdict: feedback[:verdict],
      notes: feedback[:notes],
      analyst_id: feedback[:analyst_id],
      timestamp: DateTime.utc_now()
    }

    :ets.insert(@feedback_table, {agent_id, entry})

    # Update metrics based on feedback type
    update_metrics_from_feedback(agent_id, feedback_type)

    new_stats = Map.update!(state.stats, :feedback_received, &(&1 + 1))
    {:noreply, %{state | stats: new_stats}}
  end

  @impl true
  def handle_cast({:record_execution, agent_id, agent_name, outcome, actions_taken, duration_ms}, state) do
    do_record_execution(agent_id, agent_name, outcome, actions_taken, duration_ms)
    new_stats = Map.update!(state.stats, :executions_tracked, &(&1 + 1))
    {:noreply, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:approve_refinement, refinement_id}, _from, state) do
    case :ets.lookup(@adjustments_table, refinement_id) do
      [{^refinement_id, refinement}] ->
        # Apply the refinement
        apply_refinement(refinement)

        updated = %{refinement | status: :applied}
        :ets.insert(@adjustments_table, {refinement_id, updated})

        new_stats = Map.update!(state.stats, :adjustments_applied, &(&1 + 1))
        {:reply, :ok, %{state | stats: new_stats}}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:reject_refinement, refinement_id, reason}, _from, state) do
    case :ets.lookup(@adjustments_table, refinement_id) do
      [{^refinement_id, refinement}] ->
        updated = %{refinement | status: :rejected}
        :ets.insert(@adjustments_table, {refinement_id, updated})
        {:reply, :ok, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call(:generate_report, _from, state) do
    report = do_generate_report()
    :ets.insert(@reports_table, {report.id, report})

    new_stats = Map.update!(state.stats, :reports_generated, &(&1 + 1))
    {:reply, {:ok, report}, %{state | stats: new_stats, last_report_at: DateTime.utc_now()}}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  # ============================================================================
  # Execution & Feedback Recording
  # ============================================================================

  defp do_record_execution(agent_id, agent_name, outcome, actions_taken, duration_ms) do
    now = DateTime.utc_now()

    metrics = case :ets.lookup(@metrics_table, agent_id) do
      [{^agent_id, existing}] -> existing
      [] -> %AgentMetrics{agent_id: agent_id, agent_name: agent_name, created_at: now}
    end

    updated = %{metrics |
      total_executions: metrics.total_executions + 1,
      total_actions: metrics.total_actions + actions_taken,
      total_resolution_time_ms: metrics.total_resolution_time_ms + duration_ms,
      updated_at: now
    }

    :ets.insert(@metrics_table, {agent_id, updated})
  end

  defp update_metrics_from_feedback(agent_id, feedback_type) do
    case :ets.lookup(@metrics_table, agent_id) do
      [{^agent_id, metrics}] ->
        updated = case feedback_type do
          :true_positive ->
            %{metrics | true_positives: metrics.true_positives + 1}
          :false_positive ->
            %{metrics | false_positives: metrics.false_positives + 1}
          :true_negative ->
            %{metrics | true_negatives: metrics.true_negatives + 1}
          :false_negative ->
            %{metrics | false_negatives: metrics.false_negatives + 1}
          :approved ->
            %{metrics | analyst_approvals: metrics.analyst_approvals + 1}
          :rejected ->
            %{metrics | analyst_rejections: metrics.analyst_rejections + 1}
          :modified ->
            %{metrics | analyst_modifications: metrics.analyst_modifications + 1}
          _ ->
            metrics
        end

        :ets.insert(@metrics_table, {agent_id, %{updated | updated_at: DateTime.utc_now()}})

      [] ->
        :ok
    end
  end

  # ============================================================================
  # Performance Analysis
  # ============================================================================

  defp analyze_all_agents(state) do
    all_metrics = :ets.tab2list(@metrics_table)
    |> Enum.map(fn {_id, metrics} -> metrics end)

    Enum.reduce(all_metrics, state, fn metrics, acc_state ->
      analyze_agent(metrics, acc_state)
    end)
  end

  defp analyze_agent(metrics, state) do
    # Only analyze agents with enough data
    if metrics.total_executions < @min_samples_for_adjustment do
      state
    else
      state = check_fp_rate(metrics, state)
      state = check_action_efficiency(metrics, state)
      state
    end
  end

  defp check_fp_rate(metrics, state) do
    total_verdicts = metrics.true_positives + metrics.false_positives

    if total_verdicts >= @min_samples_for_adjustment do
      fp_rate = metrics.false_positives / max(total_verdicts, 1)

      if fp_rate > @fp_rate_threshold do
        # Propose confidence threshold increase
        new_threshold = min(
          metrics.confidence_threshold + @confidence_increment,
          @max_confidence_threshold
        )

        refinement = %RuleRefinement{
          id: Ecto.UUID.generate(),
          agent_id: metrics.agent_id,
          type: :confidence_threshold_increase,
          description: "False positive rate (#{Float.round(fp_rate * 100, 1)}%) exceeds threshold " <>
                       "(#{Float.round(@fp_rate_threshold * 100, 1)}%). Proposing confidence " <>
                       "threshold increase from #{metrics.confidence_threshold} to #{new_threshold}.",
          current_value: metrics.confidence_threshold,
          proposed_value: new_threshold,
          rationale: "Based on #{total_verdicts} verdict samples with #{metrics.false_positives} false positives",
          confidence: min(0.5 + total_verdicts * 0.01, 0.95),
          status: :proposed,
          created_at: DateTime.utc_now()
        }

        # Only propose if we haven't recently proposed the same thing
        unless has_recent_proposal?(metrics.agent_id, :confidence_threshold_increase) do
          :ets.insert(@adjustments_table, {refinement.id, refinement})

          Logger.info(
            "[LearningLoop] Proposed confidence threshold increase for agent '#{metrics.agent_name}' " <>
            "(FP rate: #{Float.round(fp_rate * 100, 1)}%)"
          )

          new_stats = Map.update!(state.stats, :adjustments_proposed, &(&1 + 1))
          %{state | stats: new_stats}
        else
          state
        end
      else
        state
      end
    else
      state
    end
  end

  defp check_action_efficiency(metrics, state) do
    # Check if agent is taking too many actions per execution
    if metrics.total_executions > 0 do
      avg_actions = metrics.total_actions / metrics.total_executions

      if avg_actions > 10 do
        refinement = %RuleRefinement{
          id: Ecto.UUID.generate(),
          agent_id: metrics.agent_id,
          type: :action_reduction,
          description: "Agent takes an average of #{Float.round(avg_actions, 1)} actions per execution. " <>
                       "Consider optimizing the reasoning chain to reduce unnecessary steps.",
          current_value: avg_actions,
          proposed_value: max(avg_actions * 0.7, 3),
          rationale: "Based on #{metrics.total_executions} executions",
          confidence: 0.6,
          status: :proposed,
          created_at: DateTime.utc_now()
        }

        unless has_recent_proposal?(metrics.agent_id, :action_reduction) do
          :ets.insert(@adjustments_table, {refinement.id, refinement})

          new_stats = Map.update!(state.stats, :adjustments_proposed, &(&1 + 1))
          %{state | stats: new_stats}
        else
          state
        end
      else
        state
      end
    else
      state
    end
  end

  defp has_recent_proposal?(agent_id, type) do
    cutoff = DateTime.add(DateTime.utc_now(), -86400, :second)  # 24 hours

    :ets.tab2list(@adjustments_table)
    |> Enum.any?(fn {_id, r} ->
      r.agent_id == agent_id and
        r.type == type and
        r.status == :proposed and
        DateTime.compare(r.created_at, cutoff) == :gt
    end)
  end

  # ============================================================================
  # Refinement Application
  # ============================================================================

  defp apply_refinement(refinement) do
    case refinement.type do
      :confidence_threshold_increase ->
        # Update the metrics confidence threshold
        case :ets.lookup(@metrics_table, refinement.agent_id) do
          [{agent_id, metrics}] ->
            updated = %{metrics |
              confidence_threshold: refinement.proposed_value,
              last_adjustment_at: DateTime.utc_now(),
              adjustment_count: metrics.adjustment_count + 1
            }
            :ets.insert(@metrics_table, {agent_id, updated})

          [] ->
            :ok
        end

      _ ->
        Logger.info("[LearningLoop] Applied refinement #{refinement.id} of type #{refinement.type}")
    end
  end

  # ============================================================================
  # Report Generation
  # ============================================================================

  defp do_generate_report do
    all_metrics = :ets.tab2list(@metrics_table)
    |> Enum.map(fn {_id, m} -> m end)

    agent_reports = Enum.map(all_metrics, fn metrics ->
      total_verdicts = metrics.true_positives + metrics.false_positives
      fp_rate = if total_verdicts > 0, do: metrics.false_positives / total_verdicts, else: 0.0
      tp_rate = if total_verdicts > 0, do: metrics.true_positives / total_verdicts, else: 0.0

      avg_resolution_time = if metrics.total_executions > 0 do
        metrics.total_resolution_time_ms / metrics.total_executions
      else
        0
      end

      avg_actions = if metrics.total_executions > 0 do
        metrics.total_actions / metrics.total_executions
      else
        0
      end

      analyst_total = metrics.analyst_approvals + metrics.analyst_rejections + metrics.analyst_modifications
      approval_rate = if analyst_total > 0, do: metrics.analyst_approvals / analyst_total, else: 0.0

      %{
        agent_id: metrics.agent_id,
        agent_name: metrics.agent_name,
        total_executions: metrics.total_executions,
        true_positives: metrics.true_positives,
        false_positives: metrics.false_positives,
        false_positive_rate: Float.round(fp_rate * 100, 1),
        true_positive_rate: Float.round(tp_rate * 100, 1),
        mean_resolution_time_ms: Float.round(avg_resolution_time, 0),
        mean_actions_per_execution: Float.round(avg_actions * 1.0, 1),
        analyst_approval_rate: Float.round(approval_rate * 100, 1),
        confidence_threshold: metrics.confidence_threshold,
        adjustments_applied: metrics.adjustment_count,
        health: agent_health(fp_rate, approval_rate, metrics.total_executions)
      }
    end)

    # Summary statistics
    total_executions = Enum.sum(Enum.map(all_metrics, & &1.total_executions))
    total_tp = Enum.sum(Enum.map(all_metrics, & &1.true_positives))
    total_fp = Enum.sum(Enum.map(all_metrics, & &1.false_positives))

    overall_fp_rate = if (total_tp + total_fp) > 0 do
      Float.round(total_fp / (total_tp + total_fp) * 100, 1)
    else
      0.0
    end

    pending_refinements = :ets.tab2list(@adjustments_table)
    |> Enum.count(fn {_id, r} -> r.status == :proposed end)

    %{
      id: Ecto.UUID.generate(),
      generated_at: DateTime.utc_now(),
      period: :weekly,
      summary: %{
        total_agents: length(all_metrics),
        active_agents: Enum.count(all_metrics, &(&1.total_executions > 0)),
        total_executions: total_executions,
        total_true_positives: total_tp,
        total_false_positives: total_fp,
        overall_false_positive_rate: overall_fp_rate,
        pending_refinements: pending_refinements
      },
      agent_reports: Enum.sort_by(agent_reports, & &1.total_executions, :desc),
      recommendations: generate_recommendations(agent_reports),
      trends: calculate_trends()
    }
  end

  defp agent_health(fp_rate, approval_rate, total_executions) do
    cond do
      total_executions < @min_samples_for_adjustment -> :insufficient_data
      fp_rate > 0.5 -> :critical
      fp_rate > @fp_rate_threshold -> :degraded
      approval_rate < 0.5 and total_executions > 20 -> :degraded
      fp_rate < 0.1 and approval_rate > 0.8 -> :excellent
      true -> :healthy
    end
  end

  defp generate_recommendations(agent_reports) do
    recommendations = []

    # Find agents with high FP rates
    high_fp = Enum.filter(agent_reports, fn r -> r.false_positive_rate > 30 end)
    recommendations = if high_fp != [] do
      agents = Enum.map(high_fp, & &1.agent_name) |> Enum.join(", ")
      [%{
        type: :fp_reduction,
        severity: :high,
        message: "Agents with high false positive rates (>30%): #{agents}. " <>
                 "Consider reviewing trigger conditions and confidence thresholds."
      } | recommendations]
    else
      recommendations
    end

    # Find agents with low approval rates
    low_approval = Enum.filter(agent_reports, fn r ->
      r.analyst_approval_rate < 50 and r.total_executions > 10
    end)
    recommendations = if low_approval != [] do
      agents = Enum.map(low_approval, & &1.agent_name) |> Enum.join(", ")
      [%{
        type: :approval_improvement,
        severity: :medium,
        message: "Agents with low analyst approval rates (<50%): #{agents}. " <>
                 "Consider adjusting allowed actions or adding approval requirements."
      } | recommendations]
    else
      recommendations
    end

    # Find agents with excessive actions
    high_actions = Enum.filter(agent_reports, fn r -> r.mean_actions_per_execution > 10 end)
    recommendations = if high_actions != [] do
      agents = Enum.map(high_actions, & &1.agent_name) |> Enum.join(", ")
      [%{
        type: :action_optimization,
        severity: :low,
        message: "Agents with high action counts (>10 per execution): #{agents}. " <>
                 "Consider streamlining reasoning chains."
      } | recommendations]
    else
      recommendations
    end

    Enum.reverse(recommendations)
  end

  defp calculate_trends do
    # Trends would normally compare against previous report period
    # For now, provide current snapshot
    %{
      direction: :stable,
      fp_trend: :stable,
      execution_trend: :stable,
      note: "Trend analysis requires multiple report periods"
    }
  end
end
