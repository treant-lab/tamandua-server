defmodule TamanduaServer.Remediation.KillSwitchPolicy do
  @moduledoc """
  Policy module for kill switch remediation actions.

  Defines rules for when to auto-trigger kill switch and what
  approval workflows are required for different threat levels.

  ## Rules

  - `ks_auto_critical` - Auto-isolate on critical threat (no approval needed)
  - `ks_auto_high` - Isolate on high threat (approval required)
  - `ks_manual` - Manual kill switch trigger (audit required)

  ## Usage

      # Evaluate an alert against kill switch policies
      {:ok, action} = KillSwitchPolicy.evaluate(alert, context)

      # Execute the recommended action
      {:ok, result} = KillSwitchPolicy.execute(action, context)
  """

  require Logger

  alias TamanduaServer.Runtime.{KillSwitch, ModelIsolation}
  alias TamanduaServer.Remediation.{Workflow, AuditTrail}

  @behaviour TamanduaServer.Remediation.PolicyBehaviour

  # ── Policy Definition ──────────────────────────────────────────────

  @doc "Return the policy name"
  @impl true
  def name, do: "kill_switch"

  @doc "Return the policy description"
  @impl true
  def description, do: "Model isolation and kill switch policies"

  @doc """
  Return the default rules for kill switch policies.

  These rules define the automated response behavior based on
  threat levels and trigger types.
  """
  @impl true
  def default_rules do
    [
      %{
        id: "ks_auto_critical",
        name: "Auto-isolate on critical threat",
        condition: %{risk_level: :critical},
        action: :isolate,
        mode: :full,
        requires_approval: false,
        auto_release_hours: 24
      },
      %{
        id: "ks_auto_high",
        name: "Isolate on high threat (approval required)",
        condition: %{risk_level: :high},
        action: :isolate,
        mode: :network,
        requires_approval: true,
        approval_timeout_hours: 4
      },
      %{
        id: "ks_manual",
        name: "Manual kill switch trigger",
        condition: %{trigger_type: :manual},
        action: :isolate,
        mode: :full,
        requires_approval: false,
        audit_required: true
      },
      %{
        id: "ks_prompt_injection_critical",
        name: "Auto-isolate on critical prompt injection",
        condition: %{category: :prompt_injection, severity: :critical},
        action: :isolate,
        mode: :full,
        requires_approval: false,
        auto_release_hours: 12
      },
      %{
        id: "ks_pii_exfil",
        name: "Isolate on PII exfiltration (approval required)",
        condition: %{category: :pii_detected, pii_count_gte: 5},
        action: :isolate,
        mode: :network,
        requires_approval: true,
        approval_timeout_hours: 2
      }
    ]
  end

  # ── Policy Evaluation ──────────────────────────────────────────────

  @doc """
  Evaluate an alert against kill switch policies.

  Returns a recommended action based on matching rules.

  ## Parameters

  - `alert` - Alert map with `:severity`, `:category`, `:threat_score`, etc.
  - `context` - Execution context with `:triggered_by`, `:model_id`, etc.

  ## Returns

  - `{:ok, action}` - Recommended action map
  - `{:no_match, reason}` - No matching rule found
  """
  @impl true
  def evaluate(alert, context) do
    rules = get_active_rules()

    case find_matching_rule(alert, context, rules) do
      {:ok, rule} ->
        action = build_action(rule, alert, context)
        {:ok, action}

      :no_match ->
        {:no_match, "No kill switch rule matched the alert conditions"}
    end
  end

  defp get_active_rules do
    # Get custom rules from config, fallback to defaults
    Application.get_env(:tamandua_server, :kill_switch_rules, default_rules())
  end

  defp find_matching_rule(alert, context, rules) do
    matched =
      Enum.find(rules, fn rule ->
        matches_conditions?(rule.condition, alert, context)
      end)

    case matched do
      nil -> :no_match
      rule -> {:ok, rule}
    end
  end

  defp matches_conditions?(conditions, alert, context) do
    Enum.all?(conditions, fn {key, expected} ->
      case key do
        :risk_level ->
          normalize_risk_level(alert[:severity] || alert[:overall_risk]) == expected

        :category ->
          normalize_atom(alert[:category]) == expected

        :severity ->
          normalize_atom(alert[:severity]) == expected

        :trigger_type ->
          context[:trigger_type] == expected

        :pii_count_gte ->
          pii_count = get_in(alert, [:pii, :pii_count]) || get_in(alert, [:detection_metadata, "pii_count"]) || 0
          pii_count >= expected

        :threat_score_gte ->
          (alert[:threat_score] || 0.0) >= expected

        _ ->
          false
      end
    end)
  end

  defp normalize_risk_level(level) when is_atom(level), do: level
  defp normalize_risk_level("critical"), do: :critical
  defp normalize_risk_level("high"), do: :high
  defp normalize_risk_level("medium"), do: :medium
  defp normalize_risk_level("low"), do: :low
  defp normalize_risk_level(_), do: :unknown

  defp normalize_atom(value) when is_atom(value), do: value
  defp normalize_atom(value) when is_binary(value), do: String.to_existing_atom(value)
  defp normalize_atom(_), do: :unknown

  defp build_action(rule, alert, context) do
    model_id = context[:model_id] || extract_model_id(alert)
    agent_id = context[:agent_id] || alert[:agent_id]

    %{
      rule_id: rule.id,
      rule_name: rule.name,
      action: rule.action,
      mode: rule.mode,
      model_id: model_id,
      agent_id: agent_id,
      requires_approval: Map.get(rule, :requires_approval, false),
      approval_timeout_hours: Map.get(rule, :approval_timeout_hours),
      auto_release_hours: Map.get(rule, :auto_release_hours),
      audit_required: Map.get(rule, :audit_required, true),
      reason: build_reason(alert, rule),
      triggered_by: context[:triggered_by] || "policy_engine"
    }
  end

  defp extract_model_id(alert) do
    cond do
      alert[:model_id] -> alert[:model_id]
      session_id = get_in(alert, [:detection_metadata, "session_id"]) -> "session:#{session_id}"
      alert[:agent_id] -> "agent:#{alert[:agent_id]}"
      true -> "unknown"
    end
  end

  defp build_reason(alert, rule) do
    "#{rule.name}: #{alert[:title] || alert[:description] || "Alert triggered"}"
  end

  # ── Policy Execution ───────────────────────────────────────────────

  @doc """
  Execute a kill switch action.

  Handles approval workflows for actions that require approval,
  or executes immediately for auto-approved actions.

  ## Parameters

  - `action` - Action map from `evaluate/2`
  - `context` - Execution context with additional metadata

  ## Returns

  - `{:ok, result}` - Action executed or workflow created
  - `{:error, reason}` - Execution failed
  """
  @impl true
  def execute(action, context) do
    if action.requires_approval do
      create_approval_workflow(action, context)
    else
      execute_immediately(action, context)
    end
  end

  defp execute_immediately(action, context) do
    result =
      case action.action do
        :isolate ->
          opts = [
            mode: action.mode,
            reason: action.reason,
            triggered_by: action.triggered_by
          ]

          opts =
            if action.auto_release_hours do
              Keyword.put(opts, :duration_seconds, action.auto_release_hours * 3600)
            else
              opts
            end

          KillSwitch.trigger(action.model_id, action.reason, opts)

        :release ->
          KillSwitch.release(action.model_id)

        :kill ->
          ModelIsolation.kill(action.model_id, action.agent_id)
      end

    # Audit log
    if action.audit_required do
      audit_log(action, context, result)
    end

    case result do
      {:ok, _} = success ->
        Logger.info("[KillSwitchPolicy] Executed #{action.action} for model #{action.model_id}")
        success

      {:error, _} = error ->
        Logger.warning("[KillSwitchPolicy] Execution failed: #{inspect(error)}")
        error
    end
  end

  defp create_approval_workflow(action, context) do
    expires_at =
      if action.approval_timeout_hours do
        DateTime.add(DateTime.utc_now(), action.approval_timeout_hours * 3600, :second)
      else
        DateTime.add(DateTime.utc_now(), 4 * 3600, :second)
      end

    workflow_attrs = %{
      action_type: "kill_switch_#{action.action}",
      execution_mode: "pending_approval",
      action_config: %{
        "model_id" => action.model_id,
        "agent_id" => action.agent_id,
        "mode" => to_string(action.mode),
        "rule_id" => action.rule_id,
        "reason" => action.reason
      },
      organization_id: context[:organization_id],
      alert_id: context[:alert_id]
    }

    case Workflow.create_workflow(workflow_attrs) do
      {:ok, workflow} ->
        Logger.info(
          "[KillSwitchPolicy] Created approval workflow #{workflow.id} for model #{action.model_id}"
        )

        {:ok, %{workflow_id: workflow.id, status: :pending_approval, expires_at: expires_at}}

      {:error, _} = error ->
        error
    end
  end

  # ── Approval Handling ──────────────────────────────────────────────

  @doc """
  Approve a pending kill switch workflow.

  ## Parameters

  - `workflow_id` - Workflow UUID
  - `approver` - User ID or identifier of the approver
  - `notes` - Optional approval notes

  ## Returns

  - `{:ok, result}` - Workflow approved and action executed
  - `{:error, reason}` - Approval failed
  """
  def approve_isolation(workflow_id, approver, notes \\ nil) do
    with {:ok, workflow} <- Workflow.get_workflow(workflow_id),
         :ok <- validate_pending_approval(workflow) do
      # Update workflow to approved
      case Workflow.transition_state(workflow, "in_progress", %{
             approved_by_id: approver,
             approval_notes: notes,
             actor: approver
           }) do
        {:ok, updated_workflow} ->
          # Execute the action
          action_config = updated_workflow.action_config

          result =
            KillSwitch.trigger(
              action_config["model_id"],
              action_config["reason"],
              mode: String.to_existing_atom(action_config["mode"]),
              triggered_by: "workflow:#{workflow_id}"
            )

          # Update workflow based on result
          case result do
            {:ok, trigger_result} ->
              Workflow.transition_state(updated_workflow, "completed", %{
                result: trigger_result,
                actor: approver
              })

              Logger.info("[KillSwitchPolicy] Workflow #{workflow_id} approved and executed by #{approver}")
              {:ok, %{workflow_id: workflow_id, status: :completed, result: trigger_result}}

            {:error, reason} ->
              Workflow.transition_state(updated_workflow, "failed", %{
                error_message: inspect(reason),
                actor: approver
              })

              {:error, reason}
          end

        {:error, _} = error ->
          error
      end
    end
  end

  @doc """
  Reject a pending kill switch workflow.

  ## Parameters

  - `workflow_id` - Workflow UUID
  - `rejector` - User ID or identifier of the rejector
  - `reason` - Rejection reason

  ## Returns

  - `{:ok, result}` - Workflow rejected
  - `{:error, reason}` - Rejection failed
  """
  def reject_isolation(workflow_id, rejector, reason) do
    with {:ok, workflow} <- Workflow.get_workflow(workflow_id),
         :ok <- validate_pending_approval(workflow) do
      case Workflow.reject_workflow(workflow_id, rejector, reason) do
        {:ok, updated_workflow} ->
          Logger.info("[KillSwitchPolicy] Workflow #{workflow_id} rejected by #{rejector}: #{reason}")
          {:ok, %{workflow_id: workflow_id, status: :rejected}}

        {:error, _} = error ->
          error
      end
    end
  end

  defp validate_pending_approval(%Workflow{state: "pending", execution_mode: "pending_approval"}),
    do: :ok

  defp validate_pending_approval(_), do: {:error, :not_pending_approval}

  # ── Audit Logging ──────────────────────────────────────────────────

  defp audit_log(action, context, result) do
    Task.start(fn ->
      try do
        event = %{
          action: "kill_switch:#{action.action}",
          model_id: action.model_id,
          agent_id: action.agent_id,
          rule_id: action.rule_id,
          triggered_by: context[:triggered_by] || action.triggered_by,
          reason: action.reason,
          mode: to_string(action.mode),
          result: inspect(result),
          timestamp: DateTime.utc_now()
        }

        # Use AuditTrail if available
        if function_exported?(AuditTrail, :log_event, 4) do
          # Create a minimal struct-like map for audit
          workflow_like = %{
            id: action.model_id,
            action_type: "kill_switch_#{action.action}"
          }

          AuditTrail.log_event(workflow_like, :executed, context[:triggered_by] || "system", event)
        end

        # Also try TamanduaServer.Audit
        try do
          TamanduaServer.Audit.log(event)
        rescue
          _ -> :ok
        end
      rescue
        e ->
          Logger.warning("[KillSwitchPolicy] Audit log failed: #{Exception.message(e)}")
      end
    end)
  end

  # ── Policy Registration ────────────────────────────────────────────

  @doc """
  Register this policy with the policy registry.

  Should be called on application startup.
  """
  def register do
    try do
      TamanduaServer.Remediation.PolicyRegistry.register(__MODULE__)
      Logger.info("[KillSwitchPolicy] Registered with policy registry")
      :ok
    rescue
      _ ->
        Logger.debug("[KillSwitchPolicy] Policy registry not available")
        :ok
    end
  end
end
