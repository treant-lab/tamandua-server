defmodule TamanduaServer.Agentic.WorkflowGenerator do
  @moduledoc """
  Investigation-to-Workflow Generator

  Observes completed investigations from the AgenticAnalyst and automatically
  generates reusable workflow templates by:

  1. Extracting investigation steps (triage -> hypothesis -> evidence -> action)
  2. Generalizing steps into parameterizable workflow templates
  3. Identifying fields that should become variables (IPs, hashes, process names)
  4. Generating DAG definitions compatible with the DAG engine
  5. Proposing workflows for analyst approval

  ## Workflow Lifecycle

      Investigation Completes ->
        Extract Steps ->
        Generalize ->
        Parameterize ->
        De-duplicate ->
        Propose to Analyst ->
        Analyst Approves/Modifies/Rejects ->
        Track Effectiveness

  ## Learning

  The generator tracks workflow effectiveness over time and auto-refines
  based on analyst feedback (accepted, modified, rejected).
  """

  use GenServer
  require Logger

  alias TamanduaServer.Playbooks.DAGEngine

  # ETS tables
  @workflows_table :workflow_generator_workflows
  @proposals_table :workflow_generator_proposals
  @effectiveness_table :workflow_generator_effectiveness

  # Investigation state to observe
  @terminal_states [:resolved, :escalated, :awaiting_review]

  # Patterns that indicate parameterizable values
  @ip_pattern ~r/\b(?:\d{1,3}\.){3}\d{1,3}\b/
  @hash_pattern ~r/\b[a-fA-F0-9]{32,64}\b/
  @domain_pattern ~r/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/i

  # ============================================================================
  # Types
  # ============================================================================

  defmodule WorkflowProposal do
    @moduledoc "A proposed workflow generated from investigation analysis"
    defstruct [
      :id,
      :name,
      :description,
      :source_investigation_id,
      :source_alert_type,
      :dag_definition,
      :parameters,
      :confidence,
      :status,
      :analyst_feedback,
      :created_at,
      :similarity_hash
    ]

    @type t :: %__MODULE__{
      id: String.t(),
      name: String.t(),
      description: String.t(),
      source_investigation_id: String.t(),
      source_alert_type: String.t() | nil,
      dag_definition: map(),
      parameters: [map()],
      confidence: float(),
      status: :proposed | :approved | :modified | :rejected,
      analyst_feedback: map() | nil,
      created_at: DateTime.t(),
      similarity_hash: String.t()
    }
  end

  defmodule EffectivenessMetrics do
    @moduledoc "Tracks workflow effectiveness over time"
    defstruct [
      :workflow_id,
      times_executed: 0,
      times_successful: 0,
      times_failed: 0,
      analyst_approvals: 0,
      analyst_rejections: 0,
      analyst_modifications: 0,
      mean_execution_time_ms: 0.0,
      false_positive_rate: 0.0,
      last_executed_at: nil,
      refinement_count: 0
    ]
  end

  # ============================================================================
  # GenServer State
  # ============================================================================

  defstruct [
    :stats
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Manually trigger workflow generation from a completed investigation.
  """
  @spec generate_from_investigation(String.t()) :: {:ok, WorkflowProposal.t()} | {:error, term()}
  def generate_from_investigation(investigation_id) do
    GenServer.call(__MODULE__, {:generate_from_investigation, investigation_id}, 30_000)
  end

  @doc """
  List pending workflow proposals awaiting analyst review.
  """
  @spec list_proposals(keyword()) :: [WorkflowProposal.t()]
  def list_proposals(opts \\ []) do
    status = Keyword.get(opts, :status, :proposed)

    :ets.tab2list(@proposals_table)
    |> Enum.map(fn {_id, proposal} -> proposal end)
    |> Enum.filter(fn p -> p.status == status end)
    |> Enum.sort_by(& &1.created_at, {:desc, DateTime})
  end

  @doc """
  Get a specific proposal by ID.
  """
  @spec get_proposal(String.t()) :: {:ok, WorkflowProposal.t()} | {:error, :not_found}
  def get_proposal(proposal_id) do
    case :ets.lookup(@proposals_table, proposal_id) do
      [{^proposal_id, proposal}] -> {:ok, proposal}
      [] -> {:error, :not_found}
    end
  end

  @doc """
  Analyst approves a proposed workflow. Creates it in the DAG engine.
  """
  @spec approve_proposal(String.t(), String.t()) :: {:ok, String.t()} | {:error, term()}
  def approve_proposal(proposal_id, analyst_id) do
    GenServer.call(__MODULE__, {:approve_proposal, proposal_id, analyst_id})
  end

  @doc """
  Analyst modifies and approves a proposed workflow.
  """
  @spec modify_and_approve(String.t(), map(), String.t()) :: {:ok, String.t()} | {:error, term()}
  def modify_and_approve(proposal_id, modifications, analyst_id) do
    GenServer.call(__MODULE__, {:modify_and_approve, proposal_id, modifications, analyst_id})
  end

  @doc """
  Analyst rejects a proposed workflow.
  """
  @spec reject_proposal(String.t(), String.t(), String.t()) :: :ok | {:error, term()}
  def reject_proposal(proposal_id, analyst_id, reason) do
    GenServer.call(__MODULE__, {:reject_proposal, proposal_id, analyst_id, reason})
  end

  @doc """
  Record execution outcome for effectiveness tracking.
  """
  @spec record_execution(String.t(), :success | :failure, non_neg_integer()) :: :ok
  def record_execution(workflow_id, outcome, duration_ms) do
    GenServer.cast(__MODULE__, {:record_execution, workflow_id, outcome, duration_ms})
  end

  @doc """
  Get effectiveness metrics for a workflow.
  """
  @spec get_effectiveness(String.t()) :: {:ok, EffectivenessMetrics.t()} | {:error, :not_found}
  def get_effectiveness(workflow_id) do
    case :ets.lookup(@effectiveness_table, workflow_id) do
      [{^workflow_id, metrics}] -> {:ok, metrics}
      [] -> {:error, :not_found}
    end
  end

  @doc """
  Get workflow generation statistics.
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
    Logger.info("[WorkflowGenerator] Starting Investigation-to-Workflow Generator")

    :ets.new(@workflows_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@proposals_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@effectiveness_table, [:named_table, :set, :public, read_concurrency: true])

    # Subscribe to investigation updates
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "agentic:orchestrator")

    state = %__MODULE__{
      stats: %{
        investigations_observed: 0,
        workflows_generated: 0,
        workflows_approved: 0,
        workflows_rejected: 0,
        workflows_modified: 0,
        duplicates_detected: 0
      }
    }

    {:ok, state}
  end

  # Listen for completed agent executions that came from investigations
  @impl true
  def handle_info({:execution_completed, execution_id, _agent_id, :completed, context}, state) do
    # Auto-generate workflow from completed execution context
    if Map.get(context, :investigation_id) do
      case do_generate_from_context(context) do
        {:ok, proposal} ->
          Logger.info("[WorkflowGenerator] Generated workflow proposal '#{proposal.name}' from execution #{execution_id}")
          new_stats = Map.update!(state.stats, :workflows_generated, &(&1 + 1))
          {:noreply, %{state | stats: new_stats}}

        {:error, :duplicate} ->
          new_stats = Map.update!(state.stats, :duplicates_detected, &(&1 + 1))
          {:noreply, %{state | stats: new_stats}}

        {:error, _reason} ->
          {:noreply, state}
      end
    else
      {:noreply, state}
    end
  end

  # Listen for investigation state changes
  @impl true
  def handle_info({:investigation_update, :state_changed, %{to: terminal_state} = payload}, state)
      when terminal_state in @terminal_states do
    investigation_id = payload[:investigation_id]

    if investigation_id do
      new_stats = Map.update!(state.stats, :investigations_observed, &(&1 + 1))

      # Only generate for resolved (successful) investigations
      if terminal_state == :resolved do
        Task.start(fn ->
          case do_generate_from_investigation(investigation_id) do
            {:ok, _proposal} -> :ok
            {:error, _} -> :ok
          end
        end)
      end

      {:noreply, %{state | stats: new_stats}}
    else
      {:noreply, state}
    end
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  @impl true
  def handle_call({:generate_from_investigation, investigation_id}, _from, state) do
    case do_generate_from_investigation(investigation_id) do
      {:ok, proposal} ->
        new_stats = Map.update!(state.stats, :workflows_generated, &(&1 + 1))
        {:reply, {:ok, proposal}, %{state | stats: new_stats}}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:approve_proposal, proposal_id, analyst_id}, _from, state) do
    case :ets.lookup(@proposals_table, proposal_id) do
      [{^proposal_id, proposal}] ->
        # Create DAG playbook from the proposal
        dag = proposal.dag_definition

        case DAGEngine.execute(dag, "system", user: analyst_id) do
          {:ok, execution_id} ->
            updated = %{proposal |
              status: :approved,
              analyst_feedback: %{approved_by: analyst_id, approved_at: DateTime.utc_now()}
            }
            :ets.insert(@proposals_table, {proposal_id, updated})

            # Initialize effectiveness tracking
            :ets.insert(@effectiveness_table, {proposal_id, %EffectivenessMetrics{
              workflow_id: proposal_id
            }})

            new_stats = Map.update!(state.stats, :workflows_approved, &(&1 + 1))
            {:reply, {:ok, execution_id}, %{state | stats: new_stats}}

          {:error, reason} ->
            # Still mark as approved even if initial execution has issues
            updated = %{proposal |
              status: :approved,
              analyst_feedback: %{approved_by: analyst_id, approved_at: DateTime.utc_now()}
            }
            :ets.insert(@proposals_table, {proposal_id, updated})

            new_stats = Map.update!(state.stats, :workflows_approved, &(&1 + 1))
            {:reply, {:ok, proposal_id}, %{state | stats: new_stats}}
        end

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:modify_and_approve, proposal_id, modifications, analyst_id}, _from, state) do
    case :ets.lookup(@proposals_table, proposal_id) do
      [{^proposal_id, proposal}] ->
        # Apply modifications
        modified_dag = apply_modifications(proposal.dag_definition, modifications)

        updated = %{proposal |
          status: :modified,
          dag_definition: modified_dag,
          analyst_feedback: %{
            modified_by: analyst_id,
            modified_at: DateTime.utc_now(),
            modifications: modifications
          }
        }
        :ets.insert(@proposals_table, {proposal_id, updated})

        # Initialize effectiveness tracking
        :ets.insert(@effectiveness_table, {proposal_id, %EffectivenessMetrics{
          workflow_id: proposal_id
        }})

        new_stats = Map.update!(state.stats, :workflows_modified, &(&1 + 1))
        {:reply, {:ok, proposal_id}, %{state | stats: new_stats}}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:reject_proposal, proposal_id, analyst_id, reason}, _from, state) do
    case :ets.lookup(@proposals_table, proposal_id) do
      [{^proposal_id, proposal}] ->
        updated = %{proposal |
          status: :rejected,
          analyst_feedback: %{
            rejected_by: analyst_id,
            rejected_at: DateTime.utc_now(),
            reason: reason
          }
        }
        :ets.insert(@proposals_table, {proposal_id, updated})

        new_stats = Map.update!(state.stats, :workflows_rejected, &(&1 + 1))
        {:reply, :ok, %{state | stats: new_stats}}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  @impl true
  def handle_cast({:record_execution, workflow_id, outcome, duration_ms}, state) do
    case :ets.lookup(@effectiveness_table, workflow_id) do
      [{^workflow_id, metrics}] ->
        updated = %{metrics |
          times_executed: metrics.times_executed + 1,
          times_successful: metrics.times_successful + if(outcome == :success, do: 1, else: 0),
          times_failed: metrics.times_failed + if(outcome == :failure, do: 1, else: 0),
          mean_execution_time_ms: running_average(
            metrics.mean_execution_time_ms,
            duration_ms,
            metrics.times_executed
          ),
          last_executed_at: DateTime.utc_now()
        }
        :ets.insert(@effectiveness_table, {workflow_id, updated})

      [] ->
        :ok
    end

    {:noreply, state}
  end

  # ============================================================================
  # Workflow Generation Logic
  # ============================================================================

  defp do_generate_from_investigation(investigation_id) do
    # Fetch investigation from AgenticAnalyst ETS
    case :ets.lookup(:agentic_investigations, investigation_id) do
      [{^investigation_id, investigation}] ->
        do_generate_from_investigation_data(investigation)

      [] ->
        {:error, :investigation_not_found}
    end
  rescue
    e -> {:error, {:lookup_failed, Exception.message(e)}}
  end

  defp do_generate_from_context(context) do
    # Build a pseudo-investigation from execution context
    steps = context[:completed_steps] || []
    trigger = context[:trigger] || %{}

    if length(steps) >= 2 do
      investigation_data = %{
        id: context[:investigation_id] || Ecto.UUID.generate(),
        alert: %{
          severity: trigger[:severity] || "medium",
          detection_type: trigger[:detection_type]
        },
        triage_result: %{
          priority: severity_to_priority(trigger[:severity]),
          confidence: 0.7
        },
        evidence: [],
        recommendations: steps |> Enum.map(fn s ->
          %{action_type: s[:action], parameters: s[:params] || %{}}
        end),
        state: :resolved,
        hypotheses: []
      }

      do_generate_from_investigation_data(investigation_data)
    else
      {:error, :insufficient_steps}
    end
  end

  defp do_generate_from_investigation_data(investigation) do
    # 1. Extract investigation steps
    steps = extract_investigation_steps(investigation)

    if length(steps) < 2 do
      {:error, :insufficient_steps}
    else
      # 2. Generalize steps into workflow template
      generalized = generalize_steps(steps)

      # 3. Identify parameterizable fields
      {parameterized_steps, parameters} = parameterize_steps(generalized)

      # 4. Generate DAG definition
      dag = build_dag_definition(parameterized_steps, investigation)

      # 5. Compute similarity hash for dedup
      sim_hash = compute_similarity_hash(parameterized_steps)

      # 6. Check for duplicates
      if is_duplicate?(sim_hash) do
        {:error, :duplicate}
      else
        # 7. Create proposal
        proposal = %WorkflowProposal{
          id: Ecto.UUID.generate(),
          name: generate_workflow_name(investigation),
          description: generate_workflow_description(investigation, parameterized_steps),
          source_investigation_id: investigation[:id] || investigation.id,
          source_alert_type: get_in_safe(investigation, [:alert, :detection_type]),
          dag_definition: dag,
          parameters: parameters,
          confidence: calculate_confidence(investigation, steps),
          status: :proposed,
          created_at: DateTime.utc_now(),
          similarity_hash: sim_hash
        }

        :ets.insert(@proposals_table, {proposal.id, proposal})

        # Broadcast proposal for UI
        Phoenix.PubSub.broadcast(
          TamanduaServer.PubSub,
          "agentic:workflows",
          {:workflow_proposed, proposal.id, proposal.name}
        )

        {:ok, proposal}
      end
    end
  end

  # ============================================================================
  # Step Extraction
  # ============================================================================

  defp extract_investigation_steps(investigation) do
    steps = []

    # Extract from triage result
    steps = case get_in_safe(investigation, [:triage_result]) do
      nil -> steps
      triage ->
        [%{
          type: :triage,
          action: :assess_severity,
          params: %{
            priority: triage[:priority] || triage["priority"],
            confidence: triage[:confidence] || triage["confidence"]
          }
        } | steps]
    end

    # Extract from hypotheses
    hypotheses = get_in_safe(investigation, [:hypotheses]) || []
    steps = Enum.reduce(hypotheses, steps, fn hyp, acc ->
      [%{
        type: :hypothesis,
        action: :validate_hypothesis,
        params: %{
          type: hyp[:type] || hyp["type"],
          mitre_technique: hyp[:mitre_technique] || hyp["mitre_technique"]
        }
      } | acc]
    end)

    # Extract from evidence collection
    evidence = get_in_safe(investigation, [:evidence]) || []
    steps = Enum.reduce(evidence, steps, fn ev, acc ->
      [%{
        type: :evidence,
        action: evidence_type_to_action(ev[:type] || ev["type"]),
        params: %{
          source: ev[:source] || ev["source"],
          type: ev[:type] || ev["type"]
        }
      } | acc]
    end)

    # Extract from recommendations/actions
    recommendations = get_in_safe(investigation, [:recommendations]) || []
    steps = Enum.reduce(recommendations, steps, fn rec, acc ->
      action_type = rec[:action_type] || rec["action_type"]
      params = rec[:parameters] || rec["parameters"] || %{}

      if action_type do
        [%{
          type: :action,
          action: safe_to_atom(action_type),
          params: params
        } | acc]
      else
        acc
      end
    end)

    Enum.reverse(steps)
  end

  # ============================================================================
  # Generalization
  # ============================================================================

  defp generalize_steps(steps) do
    Enum.map(steps, fn step ->
      %{step |
        params: generalize_params(step.params)
      }
    end)
  end

  defp generalize_params(params) when is_map(params) do
    Map.new(params, fn {key, value} ->
      {key, generalize_value(key, value)}
    end)
  end

  defp generalize_params(other), do: other

  defp generalize_value(_key, value) when is_binary(value) do
    cond do
      Regex.match?(@ip_pattern, value) -> "{{ip_address}}"
      Regex.match?(@hash_pattern, value) -> "{{file_hash}}"
      Regex.match?(@domain_pattern, value) -> "{{domain}}"
      String.length(value) > 100 -> "{{long_text}}"
      true -> value
    end
  end

  defp generalize_value(_key, value), do: value

  # ============================================================================
  # Parameterization
  # ============================================================================

  defp parameterize_steps(steps) do
    {parameterized, params} = Enum.map_reduce(steps, [], fn step, acc_params ->
      {new_params, new_acc} = extract_parameters(step.params, acc_params)
      {%{step | params: new_params}, new_acc}
    end)

    {parameterized, Enum.uniq_by(params, & &1.name)}
  end

  defp extract_parameters(params, acc) when is_map(params) do
    Enum.reduce(params, {%{}, acc}, fn {key, value}, {param_map, param_acc} ->
      case value do
        "{{" <> _ = template ->
          param_name = String.trim(template, "{{") |> String.trim("}}")
          param_def = %{
            name: param_name,
            type: infer_param_type(param_name),
            description: "Auto-detected parameter: #{param_name}",
            required: true,
            default: nil
          }
          {Map.put(param_map, key, template), [param_def | param_acc]}

        _ ->
          {Map.put(param_map, key, value), param_acc}
      end
    end)
  end

  defp extract_parameters(other, acc), do: {other, acc}

  defp infer_param_type(name) do
    cond do
      String.contains?(name, "ip") -> :ip_address
      String.contains?(name, "hash") -> :file_hash
      String.contains?(name, "domain") -> :domain
      String.contains?(name, "path") -> :file_path
      String.contains?(name, "pid") -> :integer
      String.contains?(name, "agent") -> :agent_id
      true -> :string
    end
  end

  # ============================================================================
  # DAG Generation
  # ============================================================================

  defp build_dag_definition(steps, investigation) do
    dag_steps = steps
    |> Enum.with_index()
    |> Enum.map(fn {step, idx} ->
      step_id = "step_#{idx}_#{step.action}"
      depends_on = if idx > 0, do: ["step_#{idx - 1}_#{Enum.at(steps, idx - 1).action}"], else: []

      %{
        id: step_id,
        action: step.action,
        params: step.params || %{},
        depends_on: depends_on,
        timeout: step_timeout(step.action)
      }
    end)

    severity = get_in_safe(investigation, [:alert, :severity]) || "medium"

    %{
      name: generate_workflow_name(investigation),
      steps: dag_steps,
      on_failure: if(severity in ["critical", "high"], do: :rollback, else: :abort),
      metadata: %{
        generated_from: :investigation,
        source_investigation: investigation[:id],
        generated_at: DateTime.utc_now() |> DateTime.to_iso8601()
      }
    }
  end

  defp step_timeout(action) do
    case action do
      a when a in [:isolate_host, :collect_evidence, :collect_memory] -> 120_000
      a when a in [:scan_yara, :full_scan] -> 300_000
      a when a in [:enrich_hash, :enrich_ip, :threat_intel_lookup] -> 30_000
      _ -> 60_000
    end
  end

  # ============================================================================
  # De-duplication
  # ============================================================================

  defp compute_similarity_hash(steps) do
    # Hash based on step actions and types (ignoring params)
    signature = steps
    |> Enum.map(fn step -> "#{step.type}:#{step.action}" end)
    |> Enum.join("|")

    :crypto.hash(:sha256, signature) |> Base.encode16(case: :lower) |> String.slice(0, 16)
  end

  defp is_duplicate?(sim_hash) do
    :ets.tab2list(@proposals_table)
    |> Enum.any?(fn {_id, proposal} ->
      proposal.similarity_hash == sim_hash and proposal.status in [:proposed, :approved, :modified]
    end)
  end

  # ============================================================================
  # Naming & Description
  # ============================================================================

  defp generate_workflow_name(investigation) do
    alert_type = get_in_safe(investigation, [:alert, :detection_type]) || "security"
    severity = get_in_safe(investigation, [:alert, :severity]) || "medium"

    "Auto: #{String.capitalize(to_string(alert_type))} Response (#{severity})"
  end

  defp generate_workflow_description(investigation, steps) do
    action_summary = steps
    |> Enum.map(fn step -> to_string(step.action) end)
    |> Enum.join(" -> ")

    alert_type = get_in_safe(investigation, [:alert, :detection_type]) || "security incident"

    "Automatically generated workflow for #{alert_type} response. " <>
    "Steps: #{action_summary}. " <>
    "Generated from investigation #{investigation[:id] || "unknown"}."
  end

  defp calculate_confidence(investigation, steps) do
    base_confidence = case get_in_safe(investigation, [:triage_result, :confidence]) do
      c when is_number(c) -> c
      _ -> 0.5
    end

    # More steps = more complete = higher confidence
    step_bonus = min(length(steps) * 0.05, 0.2)

    # Has evidence = higher confidence
    evidence_bonus = case get_in_safe(investigation, [:evidence]) do
      ev when is_list(ev) and length(ev) > 0 -> 0.1
      _ -> 0.0
    end

    min(base_confidence + step_bonus + evidence_bonus, 1.0)
  end

  # ============================================================================
  # Modification
  # ============================================================================

  defp apply_modifications(dag, modifications) do
    dag = case Map.get(modifications, :add_steps) do
      steps when is_list(steps) ->
        Map.update(dag, :steps, [], fn existing -> existing ++ steps end)
      _ -> dag
    end

    dag = case Map.get(modifications, :remove_step_ids) do
      ids when is_list(ids) ->
        Map.update(dag, :steps, [], fn existing ->
          Enum.reject(existing, fn s -> s[:id] in ids end)
        end)
      _ -> dag
    end

    dag = case Map.get(modifications, :name) do
      name when is_binary(name) -> Map.put(dag, :name, name)
      _ -> dag
    end

    dag = case Map.get(modifications, :on_failure) do
      policy when policy in [:abort, :continue, :rollback] -> Map.put(dag, :on_failure, policy)
      _ -> dag
    end

    dag
  end

  # ============================================================================
  # Helpers
  # ============================================================================

  defp evidence_type_to_action(type) do
    case to_string(type) do
      "direct_observation" -> :enrich_context
      "tool_output" -> :collect_evidence
      "correlation" -> :correlate_events
      "behavioral" -> :behavioral_analysis
      "heuristic" -> :heuristic_check
      _ -> :collect_evidence
    end
  end

  defp severity_to_priority(severity) do
    case to_string(severity) do
      "critical" -> :p1
      "high" -> :p2
      "medium" -> :p3
      "low" -> :p4
      _ -> :p3
    end
  end

  # Safe atom conversion - returns :unknown for strings not already in atom table
  # This prevents atom table exhaustion from external input
  defp safe_to_atom(val) when is_atom(val), do: val
  defp safe_to_atom(val) when is_binary(val) do
    String.to_existing_atom(val)
  rescue
    ArgumentError -> :unknown
  end
  defp safe_to_atom(_), do: :unknown

  defp get_in_safe(data, keys) when is_map(data) do
    Enum.reduce_while(keys, data, fn key, acc ->
      case acc do
        %{^key => value} -> {:cont, value}
        _ ->
          str_key = to_string(key)
          case acc do
            %{^str_key => value} -> {:cont, value}
            _ -> {:halt, nil}
          end
      end
    end)
  end

  defp get_in_safe(_, _), do: nil

  defp running_average(current_avg, new_value, count) when count > 0 do
    (current_avg * count + new_value) / (count + 1)
  end

  defp running_average(_current_avg, new_value, _count), do: new_value / 1.0
end
