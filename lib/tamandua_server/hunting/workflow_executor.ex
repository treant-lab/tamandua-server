defmodule TamanduaServer.Hunting.WorkflowExecutor do
  @moduledoc """
  Executes hunting workflows step-by-step.

  Responsibilities:
  - Execute workflow steps in sequence
  - Handle decision trees and branching
  - Collect and store findings
  - Track hypothesis status
  - Generate final reports
  - Integrate with NL Hunter for queries
  - Export IOCs to MISP/OpenCTI
  """

  use GenServer
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Hunting.{
    Workflow,
    WorkflowExecution,
    WorkflowStepResult,
    WorkflowFinding,
    NLHunter
  }
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Integrations.MISP

  import Ecto.Query

  defstruct [
    :executions
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Start a workflow execution.
  """
  def start_workflow(workflow_id, user_id, organization_id, opts \\ []) do
    GenServer.call(__MODULE__, {:start_workflow, workflow_id, user_id, organization_id, opts})
  end

  @doc """
  Execute the next step in a workflow.
  """
  def execute_next_step(execution_id) do
    GenServer.call(__MODULE__, {:execute_next_step, execution_id}, 120_000)
  end

  @doc """
  Execute a specific step (for re-running or manual execution).
  """
  def execute_step(execution_id, step_index, opts \\ []) do
    GenServer.call(__MODULE__, {:execute_step, execution_id, step_index, opts}, 120_000)
  end

  @doc """
  Make a decision for a decision step.
  """
  def make_decision(execution_id, step_index, decision) do
    GenServer.call(__MODULE__, {:make_decision, execution_id, step_index, decision})
  end

  @doc """
  Add an annotation to a step.
  """
  def add_annotation(execution_id, step_index, annotation, user_id) do
    GenServer.call(__MODULE__, {:add_annotation, execution_id, step_index, annotation, user_id})
  end

  @doc """
  Update hypothesis status.
  """
  def update_hypothesis(execution_id, hypothesis_key, status) do
    GenServer.call(__MODULE__, {:update_hypothesis, execution_id, hypothesis_key, status})
  end

  @doc """
  Pause a workflow execution.
  """
  def pause_execution(execution_id) do
    GenServer.call(__MODULE__, {:pause_execution, execution_id})
  end

  @doc """
  Resume a paused workflow execution.
  """
  def resume_execution(execution_id) do
    GenServer.call(__MODULE__, {:resume_execution, execution_id})
  end

  @doc """
  Generate final report for a workflow execution.
  """
  def generate_report(execution_id, format \\ :html) do
    GenServer.call(__MODULE__, {:generate_report, execution_id, format})
  end

  @doc """
  Get execution status and current state.
  """
  def get_execution(execution_id) do
    GenServer.call(__MODULE__, {:get_execution, execution_id})
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    state = %__MODULE__{
      executions: %{}
    }

    Logger.info("Workflow Executor started")
    {:ok, state}
  end

  @impl true
  def handle_call({:start_workflow, workflow_id, user_id, organization_id, _opts}, _from, state) do
    case Repo.get(Workflow, workflow_id) do
      nil ->
        {:reply, {:error, :workflow_not_found}, state}

      workflow ->
        start_workflow_execution(workflow, user_id, organization_id, state)
    end
  end

  defp start_workflow_execution(workflow, user_id, organization_id, state) do
    changeset = WorkflowExecution.new_from_workflow(workflow, user_id, organization_id)

    case Repo.insert(changeset) do
      {:ok, execution} ->
        execution = execution
        |> Ecto.Changeset.change(%{
          status: "in_progress",
          started_at: DateTime.utc_now()
        })
        |> Repo.update!()

        {:reply, {:ok, execution}, state}

      {:error, changeset} ->
        {:reply, {:error, changeset}, state}
    end
  end

  @impl true
  def handle_call({:execute_next_step, execution_id}, _from, state) do
    case Repo.get(WorkflowExecution, execution_id) do
      nil -> {:reply, {:error, :execution_not_found}, state}
      execution -> do_execute_next_step(Repo.preload(execution, :workflow), state)
    end
  end

  defp do_execute_next_step(execution, state) do
    if execution.status != "in_progress" do
      {:reply, {:error, :not_in_progress}, state}
    else
      step_index = execution.current_step_index
      steps = execution.workflow.steps

      if step_index >= length(steps) do
        # All steps completed
        execution = complete_execution(execution)
        {:reply, {:ok, execution}, state}
      else
        step = Enum.at(steps, step_index)
        result = execute_step_impl(execution, step, step_index)

        case result do
          {:ok, step_result, next_step_index} ->
            # Update execution
            execution = execution
            |> Ecto.Changeset.change(%{
              current_step_index: next_step_index,
              progress_percentage: calculate_progress(next_step_index, length(steps))
            })
            |> Repo.update!()

            {:reply, {:ok, %{execution: execution, step_result: step_result}}, state}

          {:error, reason} ->
            # Mark execution as failed
            execution
            |> Ecto.Changeset.change(%{
              status: "failed",
              error_message: inspect(reason)
            })
            |> Repo.update!()

            {:reply, {:error, reason}, state}

          {:wait_for_decision, step_result} ->
            # Waiting for manual decision
            {:reply, {:ok, %{execution: execution, step_result: step_result, waiting_for: :decision}}, state}

          {:wait_for_review, step_result} ->
            # Waiting for manual review
            {:reply, {:ok, %{execution: execution, step_result: step_result, waiting_for: :review}}, state}
        end
      end
    end
  end

  @impl true
  def handle_call({:execute_step, execution_id, step_index, _opts}, _from, state) do
    case Repo.get(WorkflowExecution, execution_id) do
      nil -> {:reply, {:error, :execution_not_found}, state}
      execution -> do_execute_step(Repo.preload(execution, :workflow), step_index, state)
    end
  end

  defp do_execute_step(execution, step_index, state) do
    steps = execution.workflow.steps
    step = Enum.at(steps, step_index)

    result = execute_step_impl(execution, step, step_index)

    case result do
      {:ok, step_result, _next_step} ->
        {:reply, {:ok, step_result}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}

      {:wait_for_decision, step_result} ->
        {:reply, {:ok, step_result}, state}

      {:wait_for_review, step_result} ->
        {:reply, {:ok, step_result}, state}
    end
  end

  @impl true
  def handle_call({:make_decision, execution_id, step_index, decision}, _from, state) do
    case Repo.get(WorkflowExecution, execution_id) do
      nil ->
        {:reply, {:error, :execution_not_found}, state}

      execution ->
        do_make_decision(Repo.preload(execution, :workflow), execution_id, step_index, decision, state)
    end
  end

  defp do_make_decision(execution, execution_id, step_index, decision, state) do
    # Find the step result
    step_result_query =
      from sr in WorkflowStepResult,
      where: sr.execution_id == ^execution_id and sr.step_index == ^step_index

    case Repo.one(step_result_query) do
      nil ->
        {:reply, {:error, :step_result_not_found}, state}

      step_result ->
        # Update step result with decision
        step_result
        |> Ecto.Changeset.change(%{
          decision: decision,
          status: "completed",
          completed_at: DateTime.utc_now()
        })
        |> Repo.update!()

        # Determine next step based on decision
        step = Enum.at(execution.workflow.steps, step_index)
        next_step_index = get_next_step_from_decision(step, decision, step_index)

        # Update execution
        execution = execution
        |> Ecto.Changeset.change(%{
          current_step_index: next_step_index,
          progress_percentage: calculate_progress(next_step_index, length(execution.workflow.steps))
        })
        |> Repo.update!()

        {:reply, {:ok, execution}, state}
    end
  end

  @impl true
  def handle_call({:add_annotation, execution_id, step_index, annotation, user_id}, _from, state) do
    case Repo.get(WorkflowExecution, execution_id) do
      nil ->
        {:reply, {:error, :execution_not_found}, state}

      execution ->
        annotation_entry = %{
          step_index: step_index,
          annotation: annotation,
          user_id: user_id,
          timestamp: DateTime.utc_now()
        }

        execution = execution
        |> Ecto.Changeset.change(%{
          annotations: execution.annotations ++ [annotation_entry]
        })
        |> Repo.update!()

        {:reply, {:ok, execution}, state}
    end
  end

  @impl true
  def handle_call({:update_hypothesis, execution_id, hypothesis_key, status}, _from, state) do
    case Repo.get(WorkflowExecution, execution_id) do
      nil ->
        {:reply, {:error, :execution_not_found}, state}

      execution ->
        hypothesis_status = Map.put(execution.hypothesis_status, hypothesis_key, %{
          status: status,
          updated_at: DateTime.utc_now()
        })

        execution = execution
        |> Ecto.Changeset.change(%{hypothesis_status: hypothesis_status})
        |> Repo.update!()

        {:reply, {:ok, execution}, state}
    end
  end

  @impl true
  def handle_call({:pause_execution, execution_id}, _from, state) do
    case Repo.get(WorkflowExecution, execution_id) do
      nil ->
        {:reply, {:error, :execution_not_found}, state}

      execution ->
        execution = execution
        |> Ecto.Changeset.change(%{status: "paused"})
        |> Repo.update!()

        {:reply, {:ok, execution}, state}
    end
  end

  @impl true
  def handle_call({:resume_execution, execution_id}, _from, state) do
    case Repo.get(WorkflowExecution, execution_id) do
      nil ->
        {:reply, {:error, :execution_not_found}, state}

      execution ->
        execution = execution
        |> Ecto.Changeset.change(%{status: "in_progress"})
        |> Repo.update!()

        {:reply, {:ok, execution}, state}
    end
  end

  @impl true
  def handle_call({:generate_report, execution_id, format}, _from, state) do
    case Repo.get(WorkflowExecution, execution_id) do
      nil ->
        {:reply, {:error, :execution_not_found}, state}

      execution ->
        execution = Repo.preload(execution, [:workflow, :step_results, :workflow_findings])

        report = build_final_report(execution)

        execution
        |> Ecto.Changeset.change(%{final_report: report})
        |> Repo.update!()

        formatted_report = format_report(report, format)

        {:reply, {:ok, formatted_report}, state}
    end
  end

  @impl true
  def handle_call({:get_execution, execution_id}, _from, state) do
    execution = Repo.get(WorkflowExecution, execution_id)
    |> Repo.preload([:workflow, :step_results, :workflow_findings])

    case execution do
      nil -> {:reply, {:error, :not_found}, state}
      exec -> {:reply, {:ok, exec}, state}
    end
  end

  # ============================================================================
  # Step Execution Logic
  # ============================================================================

  defp execute_step_impl(execution, step, step_index) do
    started_at = DateTime.utc_now()

    # Create step result record
    step_result = %WorkflowStepResult{
      execution_id: execution.id,
      step_index: step_index,
      step_type: step["type"],
      status: "running",
      started_at: started_at
    }
    |> Repo.insert!()

    try do
      result = case step["type"] do
        "query" -> execute_query_step(execution, step, step_result)
        "decision" -> execute_decision_step(execution, step, step_result)
        "manual_review" -> execute_manual_review_step(execution, step, step_result)
        "collect_evidence" -> execute_collect_evidence_step(execution, step, step_result)
        "notify" -> execute_notify_step(execution, step, step_result)
        "export_iocs" -> execute_export_iocs_step(execution, step, step_result)
        "create_alert" -> execute_create_alert_step(execution, step, step_result)
        _ -> {:error, :unknown_step_type}
      end

      case result do
        {:ok, updated_step_result} ->
          completed_at = DateTime.utc_now()
          duration_ms = DateTime.diff(completed_at, started_at, :millisecond)

          updated_step_result = updated_step_result
          |> Ecto.Changeset.change(%{
            status: "completed",
            completed_at: completed_at,
            duration_ms: duration_ms
          })
          |> Repo.update!()

          next_step = determine_next_step(step, updated_step_result, step_index)
          {:ok, updated_step_result, next_step}

        {:wait_for_decision, updated_step_result} ->
          {:wait_for_decision, updated_step_result}

        {:wait_for_review, updated_step_result} ->
          {:wait_for_review, updated_step_result}

        {:error, reason} ->
          step_result
          |> Ecto.Changeset.change(%{
            status: "failed",
            completed_at: DateTime.utc_now()
          })
          |> Repo.update!()

          {:error, reason}
      end
    rescue
      e ->
        Logger.error("Step execution failed: #{inspect(e)}")

        step_result
        |> Ecto.Changeset.change(%{
          status: "failed",
          completed_at: DateTime.utc_now()
        })
        |> Repo.update!()

        {:error, e}
    end
  end

  defp execute_query_step(execution, step, step_result) do
    query_template = step["query_template"]

    # Interpolate variables from previous findings
    query = interpolate_query(query_template, execution)

    # Use NL Hunter to execute query
    case NLHunter.execute_query(nil, query) do
      {:ok, response} ->
        results = response.results
        result_count = response.result_count

        # Store results in step_result
        step_result = step_result
        |> Ecto.Changeset.change(%{
          query: query,
          results: results,
          result_count: result_count
        })
        |> Repo.update!()

        # Create findings from results if significant
        if result_count > 0 do
          create_findings_from_results(execution, step, step_result, results)
        end

        {:ok, step_result}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp execute_decision_step(_execution, step, step_result) do
    # Decision steps require manual input
    step_result = step_result
    |> Ecto.Changeset.change(%{
      query: "Manual decision required: #{inspect(step["decision_criteria"])}"
    })
    |> Repo.update!()

    {:wait_for_decision, step_result}
  end

  defp execute_manual_review_step(_execution, step, step_result) do
    # Manual review steps require analyst input
    step_result = step_result
    |> Ecto.Changeset.change(%{
      query: "Manual review required: #{inspect(step["review_checklist"])}"
    })
    |> Repo.update!()

    {:wait_for_review, step_result}
  end

  defp execute_collect_evidence_step(execution, step, step_result) do
    evidence_queries = step["evidence_queries"] || []

    # Execute each evidence query
    all_evidence = Enum.map(evidence_queries, fn query_name ->
      query = build_evidence_query(query_name, execution)

      case NLHunter.execute_query(nil, query) do
        {:ok, response} ->
          %{
            query_name: query_name,
            results: response.results,
            count: response.result_count
          }

        {:error, _} ->
          %{
            query_name: query_name,
            results: [],
            count: 0
          }
      end
    end)

    step_result = step_result
    |> Ecto.Changeset.change(%{
      results: all_evidence,
      result_count: Enum.sum(Enum.map(all_evidence, & &1.count))
    })
    |> Repo.update!()

    {:ok, step_result}
  end

  defp execute_notify_step(_execution, step, step_result) do
    notification_config = step["notification_config"] || %{}

    # TODO: Integrate with notification system
    Logger.info("Notification: #{inspect(notification_config)}")

    step_result = step_result
    |> Ecto.Changeset.change(%{
      results: [%{notification_sent: true, config: notification_config}],
      result_count: 1
    })
    |> Repo.update!()

    {:ok, step_result}
  end

  defp execute_export_iocs_step(execution, step, step_result) do
    export_types = step["export_types"] || []

    # Collect IOCs from all findings
    iocs = collect_iocs_from_execution(execution, export_types)

    # Export to MISP if configured
    exported = if Application.get_env(:tamandua_server, :misp_enabled) do
      case MISP.export_iocs(iocs) do
        {:ok, _} -> true
        {:error, _} -> false
      end
    else
      false
    end

    # Mark findings as exported
    if exported do
      Repo.update_all(
        from(f in WorkflowFinding, where: f.execution_id == ^execution.id),
        set: [exported_to_misp: true, exported_at: DateTime.utc_now()]
      )
    end

    step_result = step_result
    |> Ecto.Changeset.change(%{
      results: [%{iocs: iocs, exported: exported}],
      result_count: length(iocs)
    })
    |> Repo.update!()

    {:ok, step_result}
  end

  defp execute_create_alert_step(execution, step, step_result) do
    alert_config = step["alert_config"] || %{}

    # Create alert from workflow findings
    alert_params = %{
      title: alert_config["title"] || "Workflow Alert",
      severity: alert_config["severity"] || "medium",
      description: "Alert generated from workflow: #{execution.workflow.name}",
      metadata: %{
        workflow_execution_id: execution.id,
        workflow_id: execution.workflow_id,
        recommended_actions: alert_config["recommended_actions"] || []
      },
      organization_id: execution.organization_id,
      status: "new"
    }

    case Repo.insert(%Alert{} |> Alert.changeset(alert_params)) do
      {:ok, alert} ->
        # Link findings to alert
        Repo.update_all(
          from(f in WorkflowFinding, where: f.execution_id == ^execution.id),
          set: [linked_alert_id: alert.id]
        )

        step_result = step_result
        |> Ecto.Changeset.change(%{
          results: [%{alert_id: alert.id, alert_title: alert.title}],
          result_count: 1
        })
        |> Repo.update!()

        {:ok, step_result}

      {:error, _changeset} ->
        {:error, :alert_creation_failed}
    end
  end

  # ============================================================================
  # Helper Functions
  # ============================================================================

  defp interpolate_query(query_template, execution) do
    # Replace placeholders like [evidence.earliest] with actual values
    # This is simplified - in production would have more sophisticated interpolation
    query_template
    |> String.replace("[c2_ips]", extract_c2_ips(execution))
    |> String.replace("[compromised_hashes]", extract_compromised_hashes(execution))
    |> String.replace("[compromised_files]", extract_compromised_files(execution))
  end

  defp extract_c2_ips(execution) do
    findings = Repo.all(from f in WorkflowFinding, where: f.execution_id == ^execution.id)

    findings
    |> Enum.flat_map(fn f ->
      case f.data["ip_addresses"] do
        nil -> []
        ips when is_list(ips) -> ips
        _ -> []
      end
    end)
    |> Enum.join(",")
  end

  defp extract_compromised_hashes(execution) do
    findings = Repo.all(from f in WorkflowFinding, where: f.execution_id == ^execution.id)

    findings
    |> Enum.flat_map(fn f ->
      case f.data["file_hashes"] do
        nil -> []
        hashes when is_list(hashes) -> hashes
        _ -> []
      end
    end)
    |> Enum.join(",")
  end

  defp extract_compromised_files(execution) do
    findings = Repo.all(from f in WorkflowFinding, where: f.execution_id == ^execution.id)

    findings
    |> Enum.flat_map(fn f ->
      case f.data["file_names"] do
        nil -> []
        names when is_list(names) -> names
        _ -> []
      end
    end)
    |> Enum.join(",")
  end

  defp build_evidence_query(query_name, _execution) do
    # Map query names to actual queries
    case query_name do
      "parent_process_chain" -> "event_type:process_create AND pid:[parent_pid]"
      "network_connections_same_timeframe" -> "event_type:network_connect AND timestamp:[timeframe]"
      "authentication_events" -> "event_type:authentication"
      _ -> "event_type:*"
    end
  end

  defp create_findings_from_results(execution, step, step_result, results) do
    # Create findings based on step results
    findings = Enum.take(results, 10) |> Enum.map(fn result ->
      %WorkflowFinding{
        execution_id: execution.id,
        step_index: step_result.step_index,
        finding_type: "suspicious_activity",
        severity: determine_severity(result),
        title: "Finding from: #{step["name"]}",
        description: step["description"],
        data: result
      }
      |> Repo.insert!()
    end)

    findings
  end

  defp determine_severity(_result) do
    # Simple severity determination - could be more sophisticated
    "medium"
  end

  defp determine_next_step(step, step_result, current_index) do
    next_actions = step["next_actions"]

    cond do
      is_nil(next_actions) ->
        current_index + 1

      step["type"] == "decision" && step_result.decision ->
        Map.get(next_actions, step_result.decision, current_index + 1)

      step["type"] == "query" ->
        if step_result.result_count > 0 do
          Map.get(next_actions, "found", current_index + 1)
        else
          Map.get(next_actions, "not_found", current_index + 1)
        end

      true ->
        current_index + 1
    end
  end

  defp get_next_step_from_decision(step, decision, current_index) do
    next_actions = step["next_actions"]

    if next_actions do
      Map.get(next_actions, decision, current_index + 1)
    else
      current_index + 1
    end
  end

  defp complete_execution(execution) do
    execution
    |> Ecto.Changeset.change(%{
      status: "completed",
      completed_at: DateTime.utc_now(),
      progress_percentage: 100
    })
    |> Repo.update!()
  end

  defp calculate_progress(current_step, total_steps) do
    if total_steps == 0 do
      0
    else
      min(100, div(current_step * 100, total_steps))
    end
  end

  defp collect_iocs_from_execution(execution, export_types) do
    findings = Repo.all(from f in WorkflowFinding, where: f.execution_id == ^execution.id)

    iocs = %{
      ip_addresses: [],
      file_hashes: [],
      domains: [],
      urls: []
    }

    findings
    |> Enum.reduce(iocs, fn finding, acc ->
      Enum.reduce(export_types, acc, fn type, inner_acc ->
        case finding.data[to_string(type)] do
          nil -> inner_acc
          values when is_list(values) ->
            Map.update(inner_acc, String.to_atom(type), [], &(&1 ++ values))
          value ->
            Map.update(inner_acc, String.to_atom(type), [], &(&1 ++ [value]))
        end
      end)
    end)
  end

  defp build_final_report(execution) do
    %{
      workflow: %{
        id: execution.workflow.id,
        name: execution.workflow.name,
        category: execution.workflow.category
      },
      execution: %{
        id: execution.id,
        started_at: execution.started_at,
        completed_at: execution.completed_at,
        duration_seconds: calculate_duration(execution.started_at, execution.completed_at),
        status: execution.status
      },
      summary: %{
        total_steps: length(execution.workflow.steps),
        completed_steps: execution.current_step_index,
        total_findings: length(execution.workflow_findings),
        findings_by_severity: group_findings_by_severity(execution.workflow_findings),
        hypothesis_status: execution.hypothesis_status
      },
      steps: Enum.map(execution.step_results, &format_step_result/1),
      findings: Enum.map(execution.workflow_findings, &format_finding/1),
      annotations: execution.annotations,
      recommendations: generate_recommendations(execution)
    }
  end

  defp calculate_duration(nil, _), do: 0
  defp calculate_duration(_, nil), do: 0
  defp calculate_duration(started, completed) do
    DateTime.diff(completed, started, :second)
  end

  defp group_findings_by_severity(findings) do
    findings
    |> Enum.group_by(& &1.severity)
    |> Enum.map(fn {severity, items} -> {severity, length(items)} end)
    |> Map.new()
  end

  defp format_step_result(step_result) do
    %{
      step_index: step_result.step_index,
      step_type: step_result.step_type,
      status: step_result.status,
      result_count: step_result.result_count,
      decision: step_result.decision,
      annotations: step_result.annotations,
      duration_ms: step_result.duration_ms
    }
  end

  defp format_finding(finding) do
    %{
      id: finding.id,
      step_index: finding.step_index,
      finding_type: finding.finding_type,
      severity: finding.severity,
      title: finding.title,
      description: finding.description,
      data: finding.data
    }
  end

  defp generate_recommendations(execution) do
    critical_findings = Enum.filter(execution.workflow_findings, &(&1.severity == "critical"))
    high_findings = Enum.filter(execution.workflow_findings, &(&1.severity == "high"))

    recommendations = []

    recommendations = if length(critical_findings) > 0 do
      recommendations ++ ["Immediate response required for #{length(critical_findings)} critical findings"]
    else
      recommendations
    end

    recommendations = if length(high_findings) > 0 do
      recommendations ++ ["Investigate #{length(high_findings)} high-severity findings"]
    else
      recommendations
    end

    recommendations ++ [
      "Review all findings for false positives",
      "Document investigation in case management system",
      "Update detection rules based on findings"
    ]
  end

  defp format_report(report, :html) do
    # TODO: Implement HTML report generation
    # For now, return JSON
    Jason.encode!(report, pretty: true)
  end

  defp format_report(report, :json) do
    Jason.encode!(report, pretty: true)
  end

  defp format_report(report, _) do
    inspect(report, pretty: true)
  end
end
