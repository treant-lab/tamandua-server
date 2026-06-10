defmodule TamanduaServer.Remediation.PolicyEngine do
  @moduledoc """
  GenServer that evaluates alerts against remediation policies.

  Subscribes to PubSub alert events and evaluates each new alert against
  active policies. When a policy matches, creates a remediation workflow
  and enqueues the appropriate Oban job.

  ## Policy Matching

  1. Get all active policies ordered by priority
  2. For each policy, check if conditions match the alert
  3. First matching policy wins
  4. Determine execution mode based on threat_score vs thresholds

  ## Execution Modes

  - `auto` - threat_score >= auto_threshold and below manual_threshold
  - `pending_approval` - threat_score >= manual_threshold, wait for human
  - `queued` - below auto_threshold, queue/recommend only
  """

  use GenServer
  require Logger

  alias TamanduaServer.Remediation.{Policy, Workflow}
  alias TamanduaServer.Workers.RemediationWorker
  alias Phoenix.PubSub

  @pubsub TamanduaServer.PubSub
  @topic "alerts:created"

  # === Client API ===

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc "Evaluate an alert against active policies"
  def evaluate(alert) do
    GenServer.call(__MODULE__, {:evaluate, alert})
  end

  @doc "Force reload policies from database"
  def reload_policies do
    GenServer.call(__MODULE__, :reload_policies)
  end

  @doc "Get cached policies (for debugging)"
  def get_policies do
    GenServer.call(__MODULE__, :get_policies)
  end

  @doc "Approve a pending workflow and enqueue for execution"
  def approve_workflow(workflow_id, user_id, notes \\ nil) do
    with {:ok, workflow} <- Workflow.get_workflow(workflow_id),
         :ok <- validate_pending_approval(workflow),
         {:ok, workflow} <- update_approval(workflow, user_id, notes) do
      enqueue_job(workflow)
    end
  end

  # === Server Callbacks ===

  @impl true
  def init(_opts) do
    # Subscribe to alert creation events
    PubSub.subscribe(@pubsub, @topic)

    # Load policies into state
    policies = Policy.list_active_policies()
    Logger.info("[PolicyEngine] Started with #{length(policies)} active policies")

    {:ok, %{policies: policies}}
  end

  @impl true
  def handle_call({:evaluate, alert}, _from, state) do
    result = do_evaluate(alert, state.policies)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:reload_policies, _from, _state) do
    policies = Policy.list_active_policies()
    Logger.info("[PolicyEngine] Reloaded #{length(policies)} active policies")
    {:reply, :ok, %{policies: policies}}
  end

  @impl true
  def handle_call(:get_policies, _from, state) do
    {:reply, state.policies, state}
  end

  @impl true
  def handle_info({:alert_created, alert}, state) do
    # Auto-evaluate new alerts
    case do_evaluate(alert, state.policies) do
      {:ok, workflow} ->
        Logger.info("[PolicyEngine] Created workflow #{workflow.id} for alert #{alert.id}")
      {:no_match, _} ->
        Logger.debug("[PolicyEngine] No policy matched alert #{alert.id}")
      {:error, reason} ->
        Logger.warning("[PolicyEngine] Failed to evaluate alert #{alert.id}: #{inspect(reason)}")
    end

    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # === Private Functions ===

  defp do_evaluate(alert, policies) do
    case find_matching_policy(alert, policies) do
      nil ->
        {:no_match, :no_policy_matched}

      policy ->
        execution_mode = determine_execution_mode(alert, policy)
        create_workflow_and_enqueue(alert, policy, execution_mode)
    end
  end

  defp find_matching_policy(alert, policies) do
    Enum.find(policies, fn policy ->
      matches_conditions?(alert, policy)
    end)
  end

  defp matches_conditions?(alert, policy) do
    conditions = policy.conditions || %{}

    # All specified conditions must match
    Enum.all?(conditions, fn {key, value} ->
      match_condition?(alert, key, value)
    end)
  end

  defp match_condition?(alert, "severity", allowed_severities) when is_list(allowed_severities) do
    alert.severity in allowed_severities
  end

  defp match_condition?(alert, "mitre_tactics", required_tactics) when is_list(required_tactics) do
    alert_tactics = alert.mitre_tactics || []
    Enum.any?(required_tactics, fn tactic -> tactic in alert_tactics end)
  end

  defp match_condition?(alert, "min_threat_score", min_score) when is_number(min_score) do
    (alert.threat_score || 0.0) >= min_score
  end

  defp match_condition?(_alert, _key, _value) do
    # Unknown conditions are ignored (permissive)
    true
  end

  defp determine_execution_mode(alert, policy) do
    score = alert.threat_score || 0.5
    auto_threshold = policy.auto_threshold || 0.3
    manual_threshold = policy.manual_threshold || 0.7

    cond do
      score >= manual_threshold -> :pending_approval
      score >= auto_threshold -> :auto
      true -> :queued
    end
  end

  defp create_workflow_and_enqueue(alert, policy, execution_mode) do
    # Create workflow record
    workflow_attrs = %{
      alert_id: alert.id,
      policy_id: policy.id,
      organization_id: alert.organization_id,
      execution_mode: Atom.to_string(execution_mode),
      action_type: policy.action_type,
      action_config: policy.action_config
    }

    with {:ok, workflow} <- Workflow.create_workflow(workflow_attrs) do
      # For auto and queued modes, enqueue job immediately
      # For pending_approval mode, wait for approval
      case execution_mode do
        :auto ->
          enqueue_job(workflow)

        :queued ->
          # Enqueue with delay based on action_config timeout
          timeout_minutes = get_in(policy.action_config, ["auto_execute_timeout_minutes"]) || 60
          enqueue_job(workflow, schedule_in: timeout_minutes * 60)

        :pending_approval ->
          # Don't enqueue - wait for manual approval
          Logger.info("[PolicyEngine] Workflow #{workflow.id} awaiting approval")
          {:ok, workflow}
      end
    end
  end

  defp enqueue_job(workflow, opts \\ []) do
    job_args = %{
      "workflow_id" => workflow.id,
      "alert_id" => workflow.alert_id,
      "action_type" => workflow.action_type
    }

    job =
      job_args
      |> RemediationWorker.new(opts)
      |> Oban.insert()

    case job do
      {:ok, %Oban.Job{id: job_id}} ->
        Workflow.set_oban_job_id(workflow, job_id)
        {:ok, workflow}

      {:error, reason} ->
        Logger.error("[PolicyEngine] Failed to enqueue job for workflow #{workflow.id}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp validate_pending_approval(%Workflow{state: "pending", execution_mode: "pending_approval"}), do: :ok
  defp validate_pending_approval(_), do: {:error, :not_pending_approval}

  defp update_approval(workflow, user_id, notes) do
    workflow
    |> Workflow.changeset(%{
      approved_at: DateTime.utc_now(),
      approved_by_id: user_id,
      approval_notes: notes
    })
    |> TamanduaServer.Repo.update()
  end
end
