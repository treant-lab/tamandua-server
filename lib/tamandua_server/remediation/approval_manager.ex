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
  import Ecto.Query

  alias TamanduaServer.Accounts.User
  alias TamanduaServer.Remediation.{ApprovalRestore, Execution, Executor}
  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant
  alias TamanduaServer.{Accounts, Notifications}

  # Check every minute for timeouts
  @check_timeout_interval 60_000
  # Remind every 5 minutes
  @approval_notification_reminder_interval 300_000

  defstruct [
    :pending_approvals,
    :approval_history,
    :notification_tracker,
    :restore_status
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
  @spec request_approval(Execution.t()) :: :ok | {:error, :tenant_required}
  def request_approval(%Execution{organization_id: organization_id} = execution)
      when is_binary(organization_id) and organization_id != "" do
    GenServer.cast(__MODULE__, {:request_approval, execution})
  end

  def request_approval(_execution), do: {:error, :tenant_required}

  @doc """
  Approve a pending execution.
  """
  @spec approve(String.t(), String.t(), String.t() | nil, term()) ::
          {:ok, Execution.t()} | {:error, term()}
  def approve(execution_id, approver_id, comments \\ nil, scope \\ nil) do
    GenServer.call(__MODULE__, {:approve, execution_id, approver_id, comments, scope})
  end

  @doc """
  Reject a pending execution.
  """
  @spec reject(String.t(), String.t(), String.t(), term()) ::
          {:ok, Execution.t()} | {:error, term()}
  def reject(execution_id, approver_id, reason, scope \\ nil) do
    GenServer.call(__MODULE__, {:reject, execution_id, approver_id, reason, scope})
  end

  @doc """
  Delegate approval to another user.
  """
  @spec delegate(String.t(), String.t(), String.t(), String.t() | nil, term()) ::
          {:ok, map()} | {:error, term()}
  def delegate(execution_id, from_user_id, to_user_id, reason \\ nil, scope \\ nil) do
    GenServer.call(__MODULE__, {:delegate, execution_id, from_user_id, to_user_id, reason, scope})
  end

  @doc """
  List pending approvals for a specific approver or approval tier.
  """
  @spec list_pending_approvals(keyword(), term()) :: {:ok, [map()]} | {:error, term()}
  def list_pending_approvals(filters \\ [], scope \\ nil) do
    GenServer.call(__MODULE__, {:list_pending_approvals, filters, scope})
  end

  @doc """
  Get approval history for an execution.
  """
  @spec get_approval_history(String.t(), term()) :: {:ok, [map()]} | {:error, term()}
  def get_approval_history(execution_id, scope \\ nil) do
    GenServer.call(__MODULE__, {:get_approval_history, execution_id, scope})
  end

  @doc """
  Check if a user has permission to approve an execution.
  """
  @spec can_approve?(String.t(), String.t(), term()) :: boolean()
  def can_approve?(execution_id, user_id, scope \\ nil) do
    GenServer.call(__MODULE__, {:can_approve, execution_id, user_id, scope})
  end

  @doc "Returns the explicit startup restore state: disabled, ready, or degraded."
  @spec restore_status() :: :disabled | :ready | :degraded
  def restore_status, do: GenServer.call(__MODULE__, :restore_status)

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
      notification_tracker: %{},
      restore_status: :disabled
    }

    # Load pending approvals from database
    {:ok, load_pending_approvals(state)}
  end

  @impl true
  def handle_cast({:request_approval, execution}, state) do
    Logger.info(
      "Approval requested for execution #{execution.id} (tier: #{execution.approval_tier})"
    )

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
  def handle_call({:approve, execution_id, approver_id, comments, scope}, _from, state) do
    case approval_for_scope(state, execution_id, scope) do
      nil ->
        {:reply, {:error, :not_found}, state}

      approval_request ->
        # Validate approver has permission
        with :ok <- validate_approver(approval_request, approver_id),
             {:ok, _execution} = result <-
               Executor.approve_execution(execution_id, approver_id, comments, scope) do
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
              {scope, execution_id},
              [history_entry],
              &[history_entry | &1]
            )

          # Remove from pending
          new_pending = Map.delete(state.pending_approvals, execution_id)

          # Send notification
          send_approval_decision_notification(approval_request.execution, :approved, approver_id)

          {:reply, result,
           %{state | pending_approvals: new_pending, approval_history: new_history}}
        else
          {:error, reason} ->
            {:reply, {:error, reason}, state}
        end
    end
  end

  @impl true
  def handle_call({:reject, execution_id, approver_id, reason, scope}, _from, state) do
    case approval_for_scope(state, execution_id, scope) do
      nil ->
        {:reply, {:error, :not_found}, state}

      approval_request ->
        # Validate approver has permission
        with :ok <- validate_approver(approval_request, approver_id),
             {:ok, _execution} = result <-
               Executor.reject_execution(execution_id, approver_id, reason, scope) do
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
              {scope, execution_id},
              [history_entry],
              &[history_entry | &1]
            )

          # Remove from pending
          new_pending = Map.delete(state.pending_approvals, execution_id)

          # Send notification
          send_approval_decision_notification(approval_request.execution, :rejected, approver_id)

          {:reply, result,
           %{state | pending_approvals: new_pending, approval_history: new_history}}
        else
          {:error, reason} ->
            {:reply, {:error, reason}, state}
        end
    end
  end

  @impl true
  def handle_call(
        {:delegate, execution_id, from_user_id, to_user_id, reason, scope},
        _from,
        state
      ) do
    case approval_for_scope(state, execution_id, scope) do
      nil ->
        {:reply, {:error, :not_found}, state}

      approval_request ->
        # Validate delegator has permission
        with :ok <- validate_approver(approval_request, from_user_id),
             :ok <-
               validate_user_organization(
                 to_user_id,
                 approval_request.execution.organization_id
               ) do
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
              {scope, execution_id},
              [history_entry],
              &[history_entry | &1]
            )

          # Send notification to delegatee
          send_delegation_notification(approval_request.execution, from_user_id, to_user_id)

          {:reply, {:ok, history_entry}, %{state | approval_history: new_history}}
        else
          {:error, failure} ->
            {:reply, {:error, failure}, state}
        end
    end
  end

  @impl true
  def handle_call({:list_pending_approvals, filters, scope}, _from, state) do
    case organization_from_scope(scope) do
      {:ok, organization_id} ->
        approvals =
          state.pending_approvals
          |> Map.values()
          |> Enum.filter(&(&1.execution.organization_id == organization_id))
          |> filter_approvals(filters)
          |> Enum.sort_by(& &1.requested_at, {:asc, DateTime})

        {:reply, {:ok, approvals}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:get_approval_history, execution_id, scope}, _from, state) do
    case organization_from_scope(scope) do
      {:ok, _organization_id} ->
        history = Map.get(state.approval_history, {scope, execution_id}, [])
        {:reply, {:ok, history}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:can_approve, execution_id, user_id, scope}, _from, state) do
    result =
      case approval_for_scope(state, execution_id, scope) do
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

  def handle_call(:restore_status, _from, state), do: {:reply, state.restore_status, state}

  @impl true
  def handle_info(:check_timeouts, state) do
    now = DateTime.utc_now()

    # Find timed out approvals
    {timed_out, remaining} =
      Enum.split_with(state.pending_approvals, fn {_id, approval} ->
        DateTime.compare(now, approval.timeout_at) == :gt
      end)

    # Process timeouts and retain the audit history in state.
    {updated_history, failed_timeouts} =
      Enum.reduce(timed_out, {state.approval_history, %{}}, fn
        {execution_id, approval}, {history, failed} ->
          Logger.warning("Approval timeout for execution #{execution_id}")

          case Executor.expire_approval(execution_id, execution_scope(approval.execution)) do
            {:ok, _execution} ->
              send_timeout_notification(approval.execution)

              history_entry = %{
                execution_id: execution_id,
                action: :timeout,
                timestamp: DateTime.utc_now(),
                tier: approval.tier
              }

              updated =
                Map.update(
                  history,
                  {execution_scope(approval.execution), execution_id},
                  [history_entry],
                  &[history_entry | &1]
                )

              {updated, failed}

            {:error, reason} ->
              Logger.error("Failed to expire approval #{execution_id}: #{inspect(reason)}")
              {history, Map.put(failed, execution_id, approval)}
          end
      end)

    new_pending = remaining |> Map.new() |> Map.merge(failed_timeouts)

    # Schedule next check
    schedule_timeout_check()

    {:noreply, %{state | pending_approvals: new_pending, approval_history: updated_history}}
  end

  @impl true
  def handle_info(:send_reminders, state) do
    now = DateTime.utc_now()

    # Send reminders and persist their counters in the GenServer state.
    notification_tracker =
      Enum.reduce(state.pending_approvals, state.notification_tracker, fn
        {execution_id, approval}, tracker ->
          notification_info = Map.get(tracker, execution_id, %{})
          last_notified = Map.get(notification_info, :last_notified)

          should_remind =
            if last_notified do
              DateTime.diff(now, last_notified, :second) > 300
            else
              true
            end

          if should_remind do
            send_approval_reminder(approval.execution, approval)

            Map.put(tracker, execution_id, %{
              last_notified: now,
              notification_count: Map.get(notification_info, :notification_count, 0) + 1
            })
          else
            tracker
          end
      end)

    # Schedule next reminder check
    schedule_reminder_check()

    {:noreply, %{state | notification_tracker: notification_tracker}}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp load_pending_approvals(state) do
    if Application.get_env(:tamandua_server, :remediation_approval_authority_repo_enabled, false) do
      case ApprovalRestore.restore() do
        {:ok, pending} ->
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

          %{state | pending_approvals: pending_map, restore_status: :ready}

        {:error, reason} ->
          Logger.error("Approval restore degraded: #{inspect(reason)}")
          %{state | restore_status: :degraded}
      end
    else
      %{state | restore_status: :disabled}
    end
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
    required_tier = approval_request.tier
    organization_id = approval_request.execution.organization_id

    case get_user_tier(user_id, organization_id) do
      {:ok, user_tier} ->
        if has_required_tier?(user_tier, required_tier),
          do: :ok,
          else: {:error, :insufficient_permissions}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp get_user_tier(user_id, organization_id) do
    user =
      MultiTenant.with_organization(organization_id, fn ->
        Accounts.get_user(user_id)
      end)

    case user do
      %{organization_id: ^organization_id, role: role}
      when role in ["security_director", "admin"] ->
        {:ok, "security_director"}

      %{organization_id: ^organization_id, role: role}
      when role in ["manager", "senior_analyst", "analyst"] ->
        {:ok, role}

      %{organization_id: _other_organization} ->
        {:error, :organization_mismatch}

      nil ->
        {:error, :user_not_found}

      _ ->
        {:error, :insufficient_permissions}
    end
  rescue
    _ -> {:error, :user_lookup_failed}
  end

  defp validate_user_organization(user_id, organization_id) do
    user =
      MultiTenant.with_organization(organization_id, fn ->
        Accounts.get_user(user_id)
      end)

    case user do
      %{organization_id: ^organization_id} -> :ok
      %{organization_id: _other} -> {:error, :organization_mismatch}
      nil -> {:error, :user_not_found}
      _ -> {:error, :user_lookup_failed}
    end
  rescue
    _ -> {:error, :user_lookup_failed}
  end

  defp approval_for_scope(state, execution_id, scope) do
    with {:ok, organization_id} <- organization_from_scope(scope),
         %{execution: %{organization_id: ^organization_id}} = approval <-
           Map.get(state.pending_approvals, execution_id) do
      approval
    else
      _ -> nil
    end
  end

  defp organization_from_scope({:organization, organization_id})
       when is_binary(organization_id) and organization_id != "",
       do: {:ok, organization_id}

  defp organization_from_scope(_scope), do: {:error, :tenant_required}

  defp execution_scope(%Execution{organization_id: organization_id})
       when is_binary(organization_id) and organization_id != "",
       do: {:organization, organization_id}

  defp execution_scope(_execution), do: nil

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
        recipients: get_tier_users(approval_request.tier, execution.organization_id),
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
        message: "Playbook #{execution.playbook_name} has been #{decision} by #{approver_id}",
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
        message: "Playbook #{execution.playbook_name} approval timed out and was auto-denied",
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
        recipients: get_tier_users(approval_request.tier, execution.organization_id),
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

  defp get_tier_users(tier, organization_id)
       when is_binary(organization_id) and organization_id != "" do
    role = tier_to_role(tier)

    MultiTenant.with_organization(organization_id, fn ->
      User
      |> where([user], user.organization_id == ^organization_id and user.role == ^role)
      |> select([user], user.id)
      |> Repo.all()
    end)
  rescue
    error ->
      Logger.error("Failed to resolve tenant approval recipients: #{inspect(error)}")
      []
  end

  defp get_tier_users(_tier, _organization_id), do: []

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
