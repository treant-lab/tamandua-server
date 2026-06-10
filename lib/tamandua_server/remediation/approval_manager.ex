defmodule TamanduaServer.Remediation.ApprovalManager do
  @moduledoc """
  Manages approval workflows for remediation playbook executions.

  Features:
  - Multi-tier approval system (analyst, senior analyst, manager, security director)
  - Approval timeout handling
  - Approval delegation
  - Approval history and audit trail
  - Notification integration for pending approvals
  - Auto-deny on timeout
  """

  use GenServer
  require Logger

  alias TamanduaServer.Remediation.{Execution, Executor}
  alias TamanduaServer.{Accounts, Notifications}

  @check_timeout_interval 60_000 # Check every minute for timeouts
  @approval_notification_reminder_interval 300_000 # Remind every 5 minutes

  defstruct [
    :pending_approvals,
    :approval_history,
    :notification_tracker
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Request approval for an execution.
  """
  @spec request_approval(Execution.t()) :: :ok
  def request_approval(execution) do
    GenServer.cast(__MODULE__, {:request_approval, execution})
  end

  @doc """
  Approve a pending execution.
  """
  @spec approve(String.t(), String.t(), String.t() | nil) ::
          {:ok, Execution.t()} | {:error, term()}
  def approve(execution_id, approver_id, comments \\ nil) do
    GenServer.call(__MODULE__, {:approve, execution_id, approver_id, comments})
  end

  @doc """
  Reject a pending execution.
  """
  @spec reject(String.t(), String.t(), String.t()) :: {:ok, Execution.t()} | {:error, term()}
  def reject(execution_id, approver_id, reason) do
    GenServer.call(__MODULE__, {:reject, execution_id, approver_id, reason})
  end

  @doc """
  Delegate approval to another user.
  """
  @spec delegate(String.t(), String.t(), String.t(), String.t() | nil) ::
          {:ok, map()} | {:error, term()}
  def delegate(execution_id, from_user_id, to_user_id, reason \\ nil) do
    GenServer.call(__MODULE__, {:delegate, execution_id, from_user_id, to_user_id, reason})
  end

  @doc """
  List pending approvals for a specific approver or approval tier.
  """
  @spec list_pending_approvals(keyword()) :: {:ok, [map()]}
  def list_pending_approvals(filters \\ []) do
    GenServer.call(__MODULE__, {:list_pending_approvals, filters})
  end

  @doc """
  Get approval history for an execution.
  """
  @spec get_approval_history(String.t()) :: {:ok, [map()]}
  def get_approval_history(execution_id) do
    GenServer.call(__MODULE__, {:get_approval_history, execution_id})
  end

  @doc """
  Check if a user has permission to approve an execution.
  """
  @spec can_approve?(String.t(), String.t()) :: boolean()
  def can_approve?(execution_id, user_id) do
    GenServer.call(__MODULE__, {:can_approve, execution_id, user_id})
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    Logger.info("Starting ApprovalManager")

    # Schedule periodic timeout checks
    schedule_timeout_check()
    schedule_reminder_check()

    state = %__MODULE__{
      pending_approvals: %{},
      approval_history: %{},
      notification_tracker: %{}
    }

    # Load pending approvals from database
    {:ok, load_pending_approvals(state)}
  end

  @impl true
  def handle_cast({:request_approval, execution}, state) do
    Logger.info("Approval requested for execution #{execution.id} (tier: #{execution.approval_tier})")

    # Add to pending approvals
    approval_request = %{
      execution_id: execution.id,
      execution: execution,
      requested_at: DateTime.utc_now(),
      timeout_at: calculate_timeout(execution),
      tier: execution.approval_tier,
      status: :pending,
      reminders_sent: 0
    }

    new_pending = Map.put(state.pending_approvals, execution.id, approval_request)

    # Send notification to approvers
    send_approval_notification(execution, approval_request)

    # Track notification
    new_tracker =
      Map.put(state.notification_tracker, execution.id, %{
        last_notified: DateTime.utc_now(),
        notification_count: 1
      })

    {:noreply, %{state | pending_approvals: new_pending, notification_tracker: new_tracker}}
  end

  @impl true
  def handle_call({:approve, execution_id, approver_id, comments}, _from, state) do
    case Map.get(state.pending_approvals, execution_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      approval_request ->
        # Validate approver has permission
        case validate_approver(approval_request, approver_id) do
          :ok ->
            # Execute the approval
            result = Executor.approve_execution(execution_id, approver_id, comments)

            # Record approval history
            history_entry = %{
              execution_id: execution_id,
              action: :approved,
              approver_id: approver_id,
              comments: comments,
              timestamp: DateTime.utc_now()
            }

            new_history =
              Map.update(
                state.approval_history,
                execution_id,
                [history_entry],
                &[history_entry | &1]
              )

            # Remove from pending
            new_pending = Map.delete(state.pending_approvals, execution_id)

            # Send notification
            send_approval_decision_notification(approval_request.execution, :approved, approver_id)

            {:reply, result,
             %{state | pending_approvals: new_pending, approval_history: new_history}}

          {:error, reason} ->
            {:reply, {:error, reason}, state}
        end
    end
  end

  @impl true
  def handle_call({:reject, execution_id, approver_id, reason}, _from, state) do
    case Map.get(state.pending_approvals, execution_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      approval_request ->
        # Validate approver has permission
        case validate_approver(approval_request, approver_id) do
          :ok ->
            # Execute the rejection
            result = Executor.reject_execution(execution_id, approver_id, reason)

            # Record rejection history
            history_entry = %{
              execution_id: execution_id,
              action: :rejected,
              approver_id: approver_id,
              reason: reason,
              timestamp: DateTime.utc_now()
            }

            new_history =
              Map.update(
                state.approval_history,
                execution_id,
                [history_entry],
                &[history_entry | &1]
              )

            # Remove from pending
            new_pending = Map.delete(state.pending_approvals, execution_id)

            # Send notification
            send_approval_decision_notification(approval_request.execution, :rejected, approver_id)

            {:reply, result,
             %{state | pending_approvals: new_pending, approval_history: new_history}}

          {:error, reason} ->
            {:reply, {:error, reason}, state}
        end
    end
  end

  @impl true
  def handle_call({:delegate, execution_id, from_user_id, to_user_id, reason}, _from, state) do
    case Map.get(state.pending_approvals, execution_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      approval_request ->
        # Validate delegator has permission
        case validate_approver(approval_request, from_user_id) do
          :ok ->
            # Record delegation history
            history_entry = %{
              execution_id: execution_id,
              action: :delegated,
              from_user_id: from_user_id,
              to_user_id: to_user_id,
              reason: reason,
              timestamp: DateTime.utc_now()
            }

            new_history =
              Map.update(
                state.approval_history,
                execution_id,
                [history_entry],
                &[history_entry | &1]
              )

            # Send notification to delegatee
            send_delegation_notification(approval_request.execution, from_user_id, to_user_id)

            {:reply, {:ok, history_entry},
             %{state | approval_history: new_history}}

          {:error, reason} ->
            {:reply, {:error, reason}, state}
        end
    end
  end

  @impl true
  def handle_call({:list_pending_approvals, filters}, _from, state) do
    approvals =
      state.pending_approvals
      |> Map.values()
      |> filter_approvals(filters)
      |> Enum.sort_by(& &1.requested_at, {:asc, DateTime})

    {:reply, {:ok, approvals}, state}
  end

  @impl true
  def handle_call({:get_approval_history, execution_id}, _from, state) do
    history = Map.get(state.approval_history, execution_id, [])
    {:reply, {:ok, history}, state}
  end

  @impl true
  def handle_call({:can_approve, execution_id, user_id}, _from, state) do
    result =
      case Map.get(state.pending_approvals, execution_id) do
        nil ->
          false

        approval_request ->
          case validate_approver(approval_request, user_id) do
            :ok -> true
            _ -> false
          end
      end

    {:reply, result, state}
  end

  @impl true
  def handle_info(:check_timeouts, state) do
    now = DateTime.utc_now()

    # Find timed out approvals
    {timed_out, remaining} =
      Enum.split_with(state.pending_approvals, fn {_id, approval} ->
        DateTime.compare(now, approval.timeout_at) == :gt
      end)

    # Process timeouts
    Enum.each(timed_out, fn {execution_id, approval} ->
      Logger.warning("Approval timeout for execution #{execution_id}")

      # Auto-deny the execution
      Executor.reject_execution(
        execution_id,
        "system",
        "Approval timeout exceeded (#{approval.tier})"
      )

      # Send timeout notification
      send_timeout_notification(approval.execution)

      # Record timeout in history
      history_entry = %{
        execution_id: execution_id,
        action: :timeout,
        timestamp: DateTime.utc_now(),
        tier: approval.tier
      }

      state =
        %{
          state
          | approval_history:
              Map.update(
                state.approval_history,
                execution_id,
                [history_entry],
                &[history_entry | &1]
              )
        }
    end)

    new_pending = Map.new(remaining)

    # Schedule next check
    schedule_timeout_check()

    {:noreply, %{state | pending_approvals: new_pending}}
  end

  @impl true
  def handle_info(:send_reminders, state) do
    now = DateTime.utc_now()

    # Send reminders for pending approvals that haven't been reminded recently
    Enum.each(state.pending_approvals, fn {execution_id, approval} ->
      notification_info = Map.get(state.notification_tracker, execution_id, %{})
      last_notified = Map.get(notification_info, :last_notified)

      should_remind =
        if last_notified do
          DateTime.diff(now, last_notified, :second) > 300
        else
          true
        end

      if should_remind do
        send_approval_reminder(approval.execution, approval)

        # Update notification tracker
        Map.put(state.notification_tracker, execution_id, %{
          last_notified: now,
          notification_count: Map.get(notification_info, :notification_count, 0) + 1
        })
      end
    end)

    # Schedule next reminder check
    schedule_reminder_check()

    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp load_pending_approvals(state) do
    pending = Execution.list_pending_approvals()

    pending_map =
      pending
      |> Enum.map(fn execution ->
        approval_request = %{
          execution_id: execution.id,
          execution: execution,
          requested_at: execution.inserted_at,
          timeout_at: calculate_timeout(execution),
          tier: execution.approval_tier,
          status: :pending,
          reminders_sent: 0
        }

        {execution.id, approval_request}
      end)
      |> Map.new()

    %{state | pending_approvals: pending_map}
  end

  defp calculate_timeout(execution) do
    timeout_minutes = execution.approval_timeout_minutes || 30

    DateTime.add(
      execution.inserted_at || DateTime.utc_now(),
      timeout_minutes * 60,
      :second
    )
  end

  defp validate_approver(approval_request, user_id) do
    # Check if user has the required tier permission
    required_tier = approval_request.tier

    case get_user_tier(user_id) do
      nil ->
        {:error, :user_not_found}

      user_tier ->
        if has_required_tier?(user_tier, required_tier) do
          :ok
        else
          {:error, :insufficient_permissions}
        end
    end
  end

  defp get_user_tier(user_id) do
    # This would integrate with your user management system
    # For now, return a default tier based on user ID pattern
    try do
      case Accounts.get_user(user_id) do
        %{role: role} when role in ["security_director", "admin"] -> "security_director"
        %{role: role} when role in ["manager"] -> "manager"
        %{role: role} when role in ["senior_analyst"] -> "senior_analyst"
        %{role: role} when role in ["analyst"] -> "analyst"
        _ -> "analyst"
      end
    rescue
      _ -> "analyst"
    end
  end

  defp has_required_tier?(user_tier, required_tier) do
    tier_hierarchy = %{
      "analyst" => 1,
      "senior_analyst" => 2,
      "manager" => 3,
      "security_director" => 4
    }

    user_level = Map.get(tier_hierarchy, user_tier, 0)
    required_level = Map.get(tier_hierarchy, required_tier, 0)

    user_level >= required_level
  end

  defp filter_approvals(approvals, filters) do
    Enum.filter(approvals, fn approval ->
      Enum.all?(filters, fn
        {:tier, tier} -> approval.tier == tier
        {:approver, user_id} -> can_user_approve?(approval, user_id)
        _ -> true
      end)
    end)
  end

  defp can_user_approve?(approval, user_id) do
    case validate_approver(approval, user_id) do
      :ok -> true
      _ -> false
    end
  end

  defp send_approval_notification(execution, approval_request) do
    Logger.info(
      "Sending approval notification for execution #{execution.id} to #{approval_request.tier}"
    )

    # This would integrate with your notification system
    # For now, just log the notification
    try do
      Notifications.send(%{
        type: "approval_required",
        title: "Remediation Approval Required",
        message: "Playbook #{execution.playbook_name} requires #{approval_request.tier} approval",
        priority: "high",
        recipients: get_tier_users(approval_request.tier),
        metadata: %{
          execution_id: execution.id,
          playbook_name: execution.playbook_name,
          tier: approval_request.tier,
          timeout_at: approval_request.timeout_at
        }
      })
    rescue
      e ->
        Logger.error("Failed to send approval notification: #{inspect(e)}")
    end
  end

  defp send_approval_decision_notification(execution, decision, approver_id) do
    Logger.info("Sending #{decision} notification for execution #{execution.id}")

    try do
      Notifications.send(%{
        type: "approval_decision",
        title: "Remediation #{String.capitalize(to_string(decision))}",
        message:
          "Playbook #{execution.playbook_name} has been #{decision} by #{approver_id}",
        priority: "medium",
        recipients: [execution.triggered_by],
        metadata: %{
          execution_id: execution.id,
          playbook_name: execution.playbook_name,
          decision: decision,
          approver_id: approver_id
        }
      })
    rescue
      e ->
        Logger.error("Failed to send approval decision notification: #{inspect(e)}")
    end
  end

  defp send_timeout_notification(execution) do
    Logger.info("Sending timeout notification for execution #{execution.id}")

    try do
      Notifications.send(%{
        type: "approval_timeout",
        title: "Remediation Approval Timeout",
        message:
          "Playbook #{execution.playbook_name} approval timed out and was auto-denied",
        priority: "high",
        recipients: [execution.triggered_by],
        metadata: %{
          execution_id: execution.id,
          playbook_name: execution.playbook_name,
          tier: execution.approval_tier
        }
      })
    rescue
      e ->
        Logger.error("Failed to send timeout notification: #{inspect(e)}")
    end
  end

  defp send_approval_reminder(execution, approval_request) do
    Logger.info("Sending approval reminder for execution #{execution.id}")

    try do
      Notifications.send(%{
        type: "approval_reminder",
        title: "Remediation Approval Reminder",
        message:
          "Playbook #{execution.playbook_name} still requires #{approval_request.tier} approval",
        priority: "high",
        recipients: get_tier_users(approval_request.tier),
        metadata: %{
          execution_id: execution.id,
          playbook_name: execution.playbook_name,
          tier: approval_request.tier,
          timeout_at: approval_request.timeout_at,
          reminders_sent: approval_request.reminders_sent + 1
        }
      })
    rescue
      e ->
        Logger.error("Failed to send approval reminder: #{inspect(e)}")
    end
  end

  defp send_delegation_notification(execution, from_user_id, to_user_id) do
    Logger.info(
      "Sending delegation notification for execution #{execution.id} from #{from_user_id} to #{to_user_id}"
    )

    try do
      Notifications.send(%{
        type: "approval_delegated",
        title: "Remediation Approval Delegated",
        message: "Playbook #{execution.playbook_name} approval has been delegated to you",
        priority: "high",
        recipients: [to_user_id],
        metadata: %{
          execution_id: execution.id,
          playbook_name: execution.playbook_name,
          from_user_id: from_user_id
        }
      })
    rescue
      e ->
        Logger.error("Failed to send delegation notification: #{inspect(e)}")
    end
  end

  defp get_tier_users(tier) do
    # This would query your user management system for users with the given tier/role
    # For now, return an empty list
    try do
      Accounts.list_users_by_role(tier_to_role(tier))
      |> Enum.map(& &1.id)
    rescue
      _ -> []
    end
  end

  defp tier_to_role(tier) do
    case tier do
      "analyst" -> "analyst"
      "senior_analyst" -> "senior_analyst"
      "manager" -> "manager"
      "security_director" -> "security_director"
      _ -> "analyst"
    end
  end

  defp schedule_timeout_check do
    Process.send_after(self(), :check_timeouts, @check_timeout_interval)
  end

  defp schedule_reminder_check do
    Process.send_after(self(), :send_reminders, @approval_notification_reminder_interval)
  end
end
