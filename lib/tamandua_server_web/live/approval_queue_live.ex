defmodule TamanduaServerWeb.ApprovalQueueLive do
  @moduledoc """
  LiveView for the remediation approval queue.

  Displays pending approval workflows and allows security analysts to
  approve or reject high-risk remediation actions.
  """

  use TamanduaServerWeb, :live_view

  alias TamanduaServer.Remediation.{Workflow, PolicyEngine, Notifier}
  alias TamanduaServer.Repo
  alias Phoenix.PubSub

  import Ecto.Query

  @pubsub TamanduaServer.PubSub

  @impl true
  def mount(_params, _session, socket) do
    user = socket.assigns.current_user
    org_id = user.organization_id

    if connected?(socket) do
      # Subscribe to approval-related events
      PubSub.subscribe(@pubsub, "remediation:approvals:#{org_id}")
      PubSub.subscribe(@pubsub, "remediation:#{org_id}")
    end

    workflows = load_pending_approvals(org_id)

    {:ok,
     socket
     |> assign(:page_title, "Pending Approvals")
     |> assign(:workflows, workflows)
     |> assign(:show_modal, nil)
     |> assign(:selected_workflow, nil)
     |> assign(:comment, "")
     |> assign(:comment_error, nil)}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="container mx-auto px-4 py-6">
      <div class="flex items-center justify-between mb-6">
        <div class="flex items-center gap-3">
          <h1 class="text-2xl font-bold text-gray-900 dark:text-white">Pending Approvals</h1>
          <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200">
            <%= length(@workflows) %>
          </span>
        </div>
      </div>

      <%= if Enum.empty?(@workflows) do %>
        <div class="text-center py-12">
          <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
          <h3 class="mt-2 text-sm font-medium text-gray-900 dark:text-white">No pending approvals</h3>
          <p class="mt-1 text-sm text-gray-500 dark:text-gray-400">
            All remediation actions are either approved or below the manual threshold.
          </p>
        </div>
      <% else %>
        <div class="grid gap-4">
          <%= for workflow <- @workflows do %>
            <.approval_card workflow={workflow} />
          <% end %>
        </div>
      <% end %>

      <!-- Approve Modal -->
      <%= if @show_modal == :approve and @selected_workflow do %>
        <div class="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50" phx-click="close_modal">
          <div class="relative top-20 mx-auto p-5 border w-full max-w-md shadow-lg rounded-md bg-white dark:bg-gray-800" phx-click-away="close_modal">
            <div class="mt-3">
              <div class="flex items-center justify-center h-12 w-12 rounded-full bg-green-100 mx-auto">
                <svg class="h-6 w-6 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <h3 class="text-lg font-medium text-gray-900 dark:text-white text-center mt-4">
                Approve this action?
              </h3>
              <div class="mt-4 px-2">
                <div class="bg-gray-50 dark:bg-gray-700 rounded-lg p-3 mb-4">
                  <p class="text-sm text-gray-600 dark:text-gray-300">
                    <strong>Action:</strong> <%= format_action_type(@selected_workflow.action_type) %>
                  </p>
                  <p class="text-sm text-gray-600 dark:text-gray-300">
                    <strong>Alert:</strong> <%= get_alert_title(@selected_workflow) %>
                  </p>
                  <p class="text-sm text-gray-600 dark:text-gray-300">
                    <strong>Threat Score:</strong> <%= format_threat_score(@selected_workflow) %>
                  </p>
                </div>
                <form phx-submit="submit_approval">
                  <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Comment (optional)
                  </label>
                  <textarea
                    name="comment"
                    rows="3"
                    class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-green-500 focus:border-green-500 dark:bg-gray-700 dark:text-white"
                    placeholder="Add a comment..."
                    phx-change="update_comment"
                  ><%= @comment %></textarea>
                  <div class="flex justify-end gap-3 mt-4">
                    <button
                      type="button"
                      phx-click="close_modal"
                      class="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 dark:bg-gray-600 dark:text-white dark:border-gray-500"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      class="px-4 py-2 text-sm font-medium text-white bg-green-600 border border-transparent rounded-md hover:bg-green-700 focus:ring-2 focus:ring-offset-2 focus:ring-green-500"
                    >
                      Approve
                    </button>
                  </div>
                </form>
              </div>
            </div>
          </div>
        </div>
      <% end %>

      <!-- Reject Modal -->
      <%= if @show_modal == :reject and @selected_workflow do %>
        <div class="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50" phx-click="close_modal">
          <div class="relative top-20 mx-auto p-5 border w-full max-w-md shadow-lg rounded-md bg-white dark:bg-gray-800" phx-click-away="close_modal">
            <div class="mt-3">
              <div class="flex items-center justify-center h-12 w-12 rounded-full bg-red-100 mx-auto">
                <svg class="h-6 w-6 text-red-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </div>
              <h3 class="text-lg font-medium text-gray-900 dark:text-white text-center mt-4">
                Reject this action?
              </h3>
              <div class="mt-4 px-2">
                <div class="bg-gray-50 dark:bg-gray-700 rounded-lg p-3 mb-4">
                  <p class="text-sm text-gray-600 dark:text-gray-300">
                    <strong>Action:</strong> <%= format_action_type(@selected_workflow.action_type) %>
                  </p>
                  <p class="text-sm text-gray-600 dark:text-gray-300">
                    <strong>Alert:</strong> <%= get_alert_title(@selected_workflow) %>
                  </p>
                  <p class="text-sm text-gray-600 dark:text-gray-300">
                    <strong>Threat Score:</strong> <%= format_threat_score(@selected_workflow) %>
                  </p>
                </div>
                <form phx-submit="submit_rejection">
                  <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Reason for rejection <span class="text-red-500">*</span>
                  </label>
                  <textarea
                    name="comment"
                    rows="3"
                    required
                    class={"w-full px-3 py-2 border rounded-md shadow-sm focus:ring-red-500 focus:border-red-500 dark:bg-gray-700 dark:text-white #{if @comment_error, do: "border-red-500", else: "border-gray-300 dark:border-gray-600"}"}
                    placeholder="Explain why this action should not be taken..."
                    phx-change="update_comment"
                  ><%= @comment %></textarea>
                  <%= if @comment_error do %>
                    <p class="mt-1 text-sm text-red-600"><%= @comment_error %></p>
                  <% end %>
                  <div class="flex justify-end gap-3 mt-4">
                    <button
                      type="button"
                      phx-click="close_modal"
                      class="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 dark:bg-gray-600 dark:text-white dark:border-gray-500"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      class="px-4 py-2 text-sm font-medium text-white bg-red-600 border border-transparent rounded-md hover:bg-red-700 focus:ring-2 focus:ring-offset-2 focus:ring-red-500"
                    >
                      Reject
                    </button>
                  </div>
                </form>
              </div>
            </div>
          </div>
        </div>
      <% end %>
    </div>
    """
  end

  # Approval card component
  defp approval_card(assigns) do
    ~H"""
    <div class="bg-white dark:bg-gray-800 shadow rounded-lg p-4 border-l-4 border-amber-500">
      <div class="flex items-start justify-between">
        <div class="flex-1">
          <div class="flex items-center gap-2 mb-2">
            <span class={"inline-flex items-center px-2 py-1 rounded text-xs font-medium #{severity_class(@workflow)}"}>
              <%= get_alert_severity(@workflow) %>
            </span>
            <span class="inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200">
              <%= format_action_type(@workflow.action_type) %>
            </span>
          </div>

          <h3 class="text-lg font-semibold text-gray-900 dark:text-white">
            <%= get_alert_title(@workflow) %>
          </h3>

          <div class="mt-2 grid grid-cols-2 gap-4 text-sm text-gray-600 dark:text-gray-400">
            <div>
              <span class="font-medium">Threat Score:</span>
              <span class={"ml-1 #{threat_score_class(@workflow)}"}>
                <%= format_threat_score(@workflow) %>
              </span>
            </div>
            <div>
              <span class="font-medium">Policy:</span>
              <span class="ml-1"><%= get_policy_name(@workflow) %></span>
            </div>
            <div>
              <span class="font-medium">Waiting:</span>
              <span class="ml-1"><%= format_waiting_time(@workflow) %></span>
            </div>
            <div>
              <span class="font-medium">Agent:</span>
              <span class="ml-1"><%= get_agent_info(@workflow) %></span>
            </div>
          </div>
        </div>

        <div class="flex flex-col gap-2 ml-4">
          <button
            phx-click="show_approve_modal"
            phx-value-id={@workflow.id}
            class="inline-flex items-center px-3 py-2 text-sm font-medium text-white bg-green-600 rounded-md hover:bg-green-700 focus:ring-2 focus:ring-offset-2 focus:ring-green-500"
          >
            <svg class="w-4 h-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
            </svg>
            Approve
          </button>
          <button
            phx-click="show_reject_modal"
            phx-value-id={@workflow.id}
            class="inline-flex items-center px-3 py-2 text-sm font-medium text-white bg-red-600 rounded-md hover:bg-red-700 focus:ring-2 focus:ring-offset-2 focus:ring-red-500"
          >
            <svg class="w-4 h-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
            Reject
          </button>
        </div>
      </div>
    </div>
    """
  end

  # Event Handlers

  @impl true
  def handle_event("show_approve_modal", %{"id" => id}, socket) do
    workflow = find_workflow(socket.assigns.workflows, id)

    {:noreply,
     socket
     |> assign(:show_modal, :approve)
     |> assign(:selected_workflow, workflow)
     |> assign(:comment, "")
     |> assign(:comment_error, nil)}
  end

  @impl true
  def handle_event("show_reject_modal", %{"id" => id}, socket) do
    workflow = find_workflow(socket.assigns.workflows, id)

    {:noreply,
     socket
     |> assign(:show_modal, :reject)
     |> assign(:selected_workflow, workflow)
     |> assign(:comment, "")
     |> assign(:comment_error, nil)}
  end

  @impl true
  def handle_event("close_modal", _params, socket) do
    {:noreply,
     socket
     |> assign(:show_modal, nil)
     |> assign(:selected_workflow, nil)
     |> assign(:comment, "")
     |> assign(:comment_error, nil)}
  end

  @impl true
  def handle_event("update_comment", %{"comment" => comment}, socket) do
    {:noreply, assign(socket, :comment, comment)}
  end

  @impl true
  def handle_event("submit_approval", %{"comment" => comment}, socket) do
    workflow = socket.assigns.selected_workflow
    user = socket.assigns.current_user

    case PolicyEngine.approve_workflow(workflow.id, user.id, comment) do
      {:ok, _updated_workflow} ->
        # Notify about approval
        Task.start(fn ->
          try do
            preloaded = Repo.preload(workflow, [:alert, :policy, :organization, :approved_by])
            Notifier.notify_workflow_approved(preloaded)
          rescue
            _ -> :ok
          end
        end)

        # Remove from list
        workflows = Enum.reject(socket.assigns.workflows, &(&1.id == workflow.id))

        {:noreply,
         socket
         |> assign(:workflows, workflows)
         |> assign(:show_modal, nil)
         |> assign(:selected_workflow, nil)
         |> assign(:comment, "")
         |> put_flash(:info, "Workflow approved successfully")}

      {:error, reason} ->
        {:noreply,
         socket
         |> put_flash(:error, "Failed to approve workflow: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("submit_rejection", %{"comment" => comment}, socket) do
    if String.trim(comment) == "" do
      {:noreply, assign(socket, :comment_error, "A reason is required when rejecting a workflow")}
    else
      workflow = socket.assigns.selected_workflow
      user = socket.assigns.current_user

      case reject_workflow(workflow, user.id, comment) do
        {:ok, _updated_workflow} ->
          # Remove from list
          workflows = Enum.reject(socket.assigns.workflows, &(&1.id == workflow.id))

          {:noreply,
           socket
           |> assign(:workflows, workflows)
           |> assign(:show_modal, nil)
           |> assign(:selected_workflow, nil)
           |> assign(:comment, "")
           |> assign(:comment_error, nil)
           |> put_flash(:info, "Workflow rejected")}

        {:error, reason} ->
          {:noreply,
           socket
           |> put_flash(:error, "Failed to reject workflow: #{inspect(reason)}")}
      end
    end
  end

  # PubSub handlers for real-time updates
  @impl true
  def handle_info({:approval_requested, workflow}, socket) do
    org_id = socket.assigns.current_user.organization_id

    if workflow.organization_id == org_id do
      workflows = [preload_workflow(workflow) | socket.assigns.workflows]
      {:noreply, assign(socket, :workflows, workflows)}
    else
      {:noreply, socket}
    end
  end

  @impl true
  def handle_info({:workflow_approved, workflow_id}, socket) do
    workflows = Enum.reject(socket.assigns.workflows, &(&1.id == workflow_id))
    {:noreply, assign(socket, :workflows, workflows)}
  end

  @impl true
  def handle_info({:workflow_rejected, workflow_id}, socket) do
    workflows = Enum.reject(socket.assigns.workflows, &(&1.id == workflow_id))
    {:noreply, assign(socket, :workflows, workflows)}
  end

  @impl true
  def handle_info(_msg, socket) do
    {:noreply, socket}
  end

  # Private functions

  defp load_pending_approvals(organization_id) do
    Workflow.list_pending_approval(organization_id: organization_id)
    |> Enum.map(&preload_workflow/1)
  end

  defp preload_workflow(workflow) do
    Repo.preload(workflow, [:alert, :policy])
  end

  defp find_workflow(workflows, id) do
    Enum.find(workflows, &(&1.id == id))
  end

  defp reject_workflow(workflow, user_id, reason) do
    workflow
    |> Workflow.transition_changeset("cancelled", %{
      approval_notes: reason,
      approved_by_id: user_id
    })
    |> Repo.update()
    |> case do
      {:ok, updated} = result ->
        # Send rejection notification
        Task.start(fn ->
          try do
            preloaded = Repo.preload(updated, [:alert, :policy, :organization, :approved_by])
            Notifier.notify_workflow_rejected(preloaded)
          rescue
            _ -> :ok
          end
        end)
        result

      error ->
        error
    end
  end

  # Formatting helpers

  defp get_alert_title(workflow) do
    case workflow.alert do
      nil -> "Unknown Alert"
      alert -> alert.title || "Untitled Alert"
    end
  end

  defp get_alert_severity(workflow) do
    case workflow.alert do
      nil -> "unknown"
      alert -> alert.severity || "medium"
    end
  end

  defp get_policy_name(workflow) do
    case workflow.policy do
      nil -> "Unknown Policy"
      policy -> policy.name || "Unnamed Policy"
    end
  end

  defp get_agent_info(workflow) do
    case workflow.alert do
      nil -> "Unknown"
      alert -> alert.agent_id |> String.slice(0..7) |> then(&("#{&1}..."))
    end
  rescue
    _ -> "Unknown"
  end

  defp format_action_type(action_type) do
    action_type
    |> to_string()
    |> String.split("_")
    |> Enum.map(&String.capitalize/1)
    |> Enum.join(" ")
  end

  defp format_threat_score(workflow) do
    score = case workflow.alert do
      nil -> 0.0
      alert -> alert.threat_score || 0.0
    end

    "#{Float.round(score * 100, 1)}%"
  end

  defp format_waiting_time(workflow) do
    diff = DateTime.diff(DateTime.utc_now(), workflow.inserted_at, :second)

    cond do
      diff < 60 -> "#{diff}s"
      diff < 3600 -> "#{div(diff, 60)}m"
      diff < 86400 -> "#{div(diff, 3600)}h #{rem(div(diff, 60), 60)}m"
      true -> "#{div(diff, 86400)}d #{rem(div(diff, 3600), 24)}h"
    end
  end

  defp severity_class(workflow) do
    case get_alert_severity(workflow) do
      "critical" -> "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
      "high" -> "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200"
      "medium" -> "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200"
      "low" -> "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
      _ -> "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200"
    end
  end

  defp threat_score_class(workflow) do
    score = case workflow.alert do
      nil -> 0.0
      alert -> alert.threat_score || 0.0
    end

    cond do
      score >= 0.9 -> "text-red-600 font-bold"
      score >= 0.7 -> "text-orange-600 font-semibold"
      score >= 0.5 -> "text-yellow-600"
      true -> "text-green-600"
    end
  end
end
