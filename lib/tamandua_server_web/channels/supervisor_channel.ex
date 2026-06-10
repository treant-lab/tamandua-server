defmodule TamanduaServerWeb.SupervisorChannel do
  @moduledoc """
  Phoenix Channel for supervisor approval workflow.

  Supervisors join this channel to receive and respond to approval requests
  for sensitive commands in live response sessions.

  ## Features
  - Real-time approval requests
  - Approve/reject commands
  - View pending approvals
  - Audit logging of all decisions

  ## Security
  - Requires supervisor role
  - All decisions are logged
  - Notifications to session owners
  """

  use TamanduaServerWeb, :channel

  require Logger

  @impl true
  def join("supervisors:approvals", _params, socket) do
    user = socket.assigns[:current_user]

    if has_supervisor_permission?(user) do
      # Send list of pending approvals on join
      send(self(), :send_pending_approvals)
      {:ok, socket}
    else
      {:error, %{reason: "Supervisor role required"}}
    end
  end

  @impl true
  def handle_info(:send_pending_approvals, socket) do
    # Get pending approvals from ETS or database
    approvals = get_pending_approvals()
    push(socket, "pending_approvals", %{approvals: approvals})
    {:noreply, socket}
  end

  @impl true
  def handle_info(_, socket), do: {:noreply, socket}

  @impl true
  def handle_in("approve", %{"command_id" => command_id, "session_id" => session_id}, socket) do
    user = socket.assigns.current_user

    # Log the approval
    audit_log(:supervisor_approved, socket, %{
      command_id: command_id,
      session_id: session_id
    })

    # Notify the live response channel
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "live_response:approvals:#{session_id}",
      {:supervisor_decision, command_id, :approved, user.id}
    )

    # Broadcast removal to other supervisors
    broadcast!(socket, "approval_resolved", %{
      command_id: command_id,
      decision: "approved",
      approved_by: user.email
    })

    {:reply, {:ok, %{command_id: command_id, decision: "approved"}}, socket}
  end

  @impl true
  def handle_in("reject", %{"command_id" => command_id, "session_id" => session_id, "reason" => reason}, socket) do
    user = socket.assigns.current_user

    # Log the rejection
    audit_log(:supervisor_rejected, socket, %{
      command_id: command_id,
      session_id: session_id,
      reason: reason
    })

    # Notify the live response channel
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "live_response:approvals:#{session_id}",
      {:supervisor_decision, command_id, :rejected, user.id}
    )

    # Broadcast removal to other supervisors
    broadcast!(socket, "approval_resolved", %{
      command_id: command_id,
      decision: "rejected",
      rejected_by: user.email,
      reason: reason
    })

    {:reply, {:ok, %{command_id: command_id, decision: "rejected"}}, socket}
  end

  @impl true
  def handle_in("get_pending", _params, socket) do
    approvals = get_pending_approvals()
    {:reply, {:ok, %{approvals: approvals}}, socket}
  end

  # Private functions

  defp has_supervisor_permission?(nil), do: false

  defp has_supervisor_permission?(user) do
    # Check RBAC permission or fallback to role-based check
    if TamanduaServer.Authorization.RBAC.can?(user, :supervisor_approvals) do
      true
    else
      # Fallback: check user role directly
      role = user.role || user[:role]
      role in [:admin, :supervisor, "admin", "supervisor"]
    end
  end

  defp get_pending_approvals do
    # In production, this would fetch from a shared store (ETS, Redis, or DB)
    # For now, return empty list - pending approvals are tracked in individual channel states
    []
  end

  defp audit_log(action, socket, extra) do
    user = socket.assigns.current_user

    log_entry = %{
      action: action,
      user_id: user.id,
      user_email: user.email,
      timestamp: DateTime.utc_now(),
      extra: extra
    }

    Logger.info("Supervisor Audit: #{inspect(log_entry)}")

    TamanduaServer.AuditLog.log(%{
      action: "supervisor:#{action}",
      action_type: "supervisor",
      user_id: user.id,
      user_email: user.email,
      resource_type: "approval",
      resource_id: extra[:command_id],
      severity: :info,
      details: log_entry,
      ip_address: socket.assigns[:client_ip],
      user_agent: socket.assigns[:user_agent],
      organization_id: user[:organization_id]
    })
  rescue
    e ->
      Logger.error("Failed to write audit log: #{inspect(e)}")
  end
end
