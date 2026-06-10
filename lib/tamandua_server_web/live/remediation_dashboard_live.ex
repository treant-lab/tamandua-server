defmodule TamanduaServerWeb.RemediationDashboardLive do
  @moduledoc """
  LiveView dashboard for monitoring remediation pipeline status.

  Displays workflow counts by state, pending approvals count,
  recent workflow activity, and workflow timeline details.
  """

  use TamanduaServerWeb, :live_view

  alias TamanduaServer.Remediation.{Workflow, AuditTrail}
  alias Phoenix.PubSub

  @pubsub TamanduaServer.PubSub

  @impl true
  def mount(_params, _session, socket) do
    user = socket.assigns.current_user
    org_id = user.organization_id

    if connected?(socket) do
      # Subscribe to workflow events
      PubSub.subscribe(@pubsub, "remediation:#{org_id}")
    end

    {:ok,
     socket
     |> assign(:page_title, "Remediation Dashboard")
     |> assign(:organization_id, org_id)
     |> assign(:state_counts, load_state_counts(org_id))
     |> assign(:pending_approvals, load_pending_approvals_count(org_id))
     |> assign(:recent_workflows, load_recent_workflows(org_id))
     |> assign(:selected_workflow, nil)
     |> assign(:workflow_timeline, [])}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="container mx-auto px-4 py-6">
      <div class="mb-6">
        <h1 class="text-2xl font-bold text-gray-900 dark:text-white">Remediation Dashboard</h1>
        <p class="text-gray-500 dark:text-gray-400 mt-1">Monitor automated response pipeline status</p>
      </div>

      <!-- Stats Cards -->
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4 mb-8">
        <.stat_card
          title="Pending"
          count={Map.get(@state_counts, "pending", 0)}
          color="yellow"
          icon="clock"
        />
        <.stat_card
          title="In Progress"
          count={Map.get(@state_counts, "in_progress", 0)}
          color="blue"
          icon="refresh"
        />
        <.stat_card
          title="Completed"
          count={Map.get(@state_counts, "completed", 0)}
          color="green"
          icon="check"
        />
        <.stat_card
          title="Failed"
          count={Map.get(@state_counts, "failed", 0)}
          color="red"
          icon="x"
        />
        <.stat_card
          title="Cancelled"
          count={Map.get(@state_counts, "cancelled", 0)}
          color="gray"
          icon="ban"
        />
      </div>

      <!-- Pending Approvals Card -->
      <div class="bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg p-4 mb-8">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-3">
            <div class="p-2 bg-amber-100 dark:bg-amber-800 rounded-lg">
              <svg class="w-6 h-6 text-amber-600 dark:text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
            <div>
              <h3 class="text-lg font-semibold text-amber-800 dark:text-amber-200">Pending Approvals</h3>
              <p class="text-sm text-amber-600 dark:text-amber-400">
                <%= @pending_approvals %> workflow(s) waiting for approval
              </p>
            </div>
          </div>
          <a
            href={~p"/live/remediation/approvals"}
            class="inline-flex items-center px-4 py-2 text-sm font-medium text-white bg-amber-600 rounded-md hover:bg-amber-700"
          >
            Review Queue
            <svg class="w-4 h-4 ml-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" />
            </svg>
          </a>
        </div>
      </div>

      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- Activity Feed -->
        <div class="lg:col-span-2 bg-white dark:bg-gray-800 rounded-lg shadow">
          <div class="px-4 py-3 border-b border-gray-200 dark:border-gray-700">
            <h2 class="text-lg font-semibold text-gray-900 dark:text-white">Recent Activity</h2>
          </div>
          <div class="divide-y divide-gray-200 dark:divide-gray-700 max-h-[500px] overflow-y-auto">
            <%= if Enum.empty?(@recent_workflows) do %>
              <div class="p-8 text-center text-gray-500 dark:text-gray-400">
                <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                </svg>
                <p class="mt-2">No recent workflow activity</p>
              </div>
            <% else %>
              <%= for workflow <- @recent_workflows do %>
                <.activity_row
                  workflow={workflow}
                  selected={@selected_workflow && @selected_workflow.id == workflow.id}
                />
              <% end %>
            <% end %>
          </div>
        </div>

        <!-- Workflow Timeline Panel -->
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow">
          <div class="px-4 py-3 border-b border-gray-200 dark:border-gray-700">
            <h2 class="text-lg font-semibold text-gray-900 dark:text-white">Workflow Timeline</h2>
          </div>
          <div class="p-4">
            <%= if @selected_workflow do %>
              <.workflow_timeline workflow={@selected_workflow} events={@workflow_timeline} />
            <% else %>
              <div class="text-center py-8 text-gray-500 dark:text-gray-400">
                <svg class="mx-auto h-10 w-10 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 15l-2 5L9 9l11 4-5 2zm0 0l5 5M7.188 2.239l.777 2.897M5.136 7.965l-2.898-.777M13.95 4.05l-2.122 2.122m-5.657 5.656l-2.12 2.122" />
                </svg>
                <p class="mt-2">Select a workflow to view timeline</p>
              </div>
            <% end %>
          </div>
        </div>
      </div>
    </div>
    """
  end

  # Stat card component
  defp stat_card(assigns) do
    color_classes = %{
      "yellow" => "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400",
      "blue" => "bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400",
      "green" => "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400",
      "red" => "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400",
      "gray" => "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300"
    }

    ~H"""
    <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
      <div class="flex items-center justify-between">
        <div>
          <p class="text-sm font-medium text-gray-500 dark:text-gray-400"><%= @title %></p>
          <p class="text-2xl font-bold text-gray-900 dark:text-white mt-1"><%= @count %></p>
        </div>
        <div class={"p-3 rounded-lg #{color_classes[@color]}"}>
          <.status_icon name={@icon} />
        </div>
      </div>
    </div>
    """
  end

  defp status_icon(%{name: "clock"} = assigns) do
    ~H"""
    <svg class="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
    """
  end

  defp status_icon(%{name: "refresh"} = assigns) do
    ~H"""
    <svg class="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
    </svg>
    """
  end

  defp status_icon(%{name: "check"} = assigns) do
    ~H"""
    <svg class="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
    </svg>
    """
  end

  defp status_icon(%{name: "x"} = assigns) do
    ~H"""
    <svg class="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
    </svg>
    """
  end

  defp status_icon(%{name: "ban"} = assigns) do
    ~H"""
    <svg class="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
    </svg>
    """
  end

  defp status_icon(assigns) do
    ~H"""
    <svg class="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
    """
  end

  # Activity row component
  defp activity_row(assigns) do
    ~H"""
    <div
      class={"px-4 py-3 hover:bg-gray-50 dark:hover:bg-gray-700 cursor-pointer #{if @selected, do: "bg-blue-50 dark:bg-blue-900/20", else: ""}"}
      phx-click="select_workflow"
      phx-value-id={@workflow.id}
    >
      <div class="flex items-center justify-between">
        <div class="flex items-center gap-3">
          <.state_badge state={@workflow.state} />
          <div>
            <p class="text-sm font-medium text-gray-900 dark:text-white">
              <%= get_alert_title(@workflow) %>
            </p>
            <p class="text-xs text-gray-500 dark:text-gray-400">
              <%= format_action_type(@workflow.action_type) %> - <%= format_time(@workflow.updated_at) %>
            </p>
          </div>
        </div>
        <svg class="w-5 h-5 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" />
        </svg>
      </div>
    </div>
    """
  end

  defp state_badge(assigns) do
    classes = case assigns.state do
      "pending" -> "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400"
      "in_progress" -> "bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400"
      "completed" -> "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400"
      "failed" -> "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400"
      "cancelled" -> "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300"
      _ -> "bg-gray-100 text-gray-800"
    end

    ~H"""
    <span class={"inline-flex items-center px-2 py-1 rounded text-xs font-medium #{classes}"}>
      <%= String.replace(@state, "_", " ") %>
    </span>
    """
  end

  # Workflow timeline component
  defp workflow_timeline(assigns) do
    ~H"""
    <div>
      <div class="mb-4">
        <h3 class="font-semibold text-gray-900 dark:text-white">
          <%= get_alert_title(@workflow) %>
        </h3>
        <p class="text-sm text-gray-500 dark:text-gray-400">
          <%= format_action_type(@workflow.action_type) %>
        </p>
      </div>

      <ol class="relative border-l border-gray-200 dark:border-gray-700 ml-3">
        <%= for event <- @events do %>
          <li class="mb-6 ml-4">
            <div class={"absolute w-3 h-3 rounded-full -left-1.5 border border-white dark:border-gray-800 #{event_color(event.event_type)}"}>
            </div>
            <div class="ml-2">
              <time class="text-xs text-gray-500 dark:text-gray-400">
                <%= event.formatted_time %>
              </time>
              <p class="text-sm font-medium text-gray-900 dark:text-white">
                <%= format_event_type(event.event_type) %>
              </p>
              <p class="text-xs text-gray-500 dark:text-gray-400">
                by <%= event.actor_email || "System" %>
              </p>
              <%= if event.details["notes"] || event.details["reason"] do %>
                <p class="mt-1 text-xs text-gray-600 dark:text-gray-300 italic">
                  "<%= event.details["notes"] || event.details["reason"] %>"
                </p>
              <% end %>
            </div>
          </li>
        <% end %>
      </ol>
    </div>
    """
  end

  # Event handlers

  @impl true
  def handle_event("select_workflow", %{"id" => id}, socket) do
    workflow = Enum.find(socket.assigns.recent_workflows, &(&1.id == id))
    timeline = if workflow, do: AuditTrail.get_workflow_history(id), else: []

    {:noreply,
     socket
     |> assign(:selected_workflow, workflow)
     |> assign(:workflow_timeline, timeline)}
  end

  # PubSub handlers for real-time updates
  @impl true
  def handle_info({:workflow_created, _workflow}, socket) do
    refresh_data(socket)
  end

  @impl true
  def handle_info({:workflow_updated, _workflow}, socket) do
    refresh_data(socket)
  end

  @impl true
  def handle_info({:workflow_approved, _workflow_id}, socket) do
    refresh_data(socket)
  end

  @impl true
  def handle_info({:workflow_rejected, _workflow_id}, socket) do
    refresh_data(socket)
  end

  @impl true
  def handle_info(_msg, socket) do
    {:noreply, socket}
  end

  defp refresh_data(socket) do
    org_id = socket.assigns.organization_id

    {:noreply,
     socket
     |> assign(:state_counts, load_state_counts(org_id))
     |> assign(:pending_approvals, load_pending_approvals_count(org_id))
     |> assign(:recent_workflows, load_recent_workflows(org_id))}
  end

  # Data loading helpers

  defp load_state_counts(organization_id) do
    Workflow.count_by_state(organization_id)
  end

  defp load_pending_approvals_count(organization_id) do
    Workflow.count_pending_approvals(organization_id) || 0
  end

  defp load_recent_workflows(organization_id) do
    Workflow.list_recent(organization_id, 20)
  end

  # Formatting helpers

  defp get_alert_title(workflow) do
    case workflow.alert do
      nil -> "Unknown Alert"
      alert -> alert.title || "Untitled Alert"
    end
  end

  defp format_action_type(action_type) do
    action_type
    |> to_string()
    |> String.split("_")
    |> Enum.map(&String.capitalize/1)
    |> Enum.join(" ")
  end

  defp format_time(nil), do: "N/A"
  defp format_time(%DateTime{} = dt) do
    now = DateTime.utc_now()
    diff = DateTime.diff(now, dt, :second)

    cond do
      diff < 60 -> "#{diff}s ago"
      diff < 3600 -> "#{div(diff, 60)}m ago"
      diff < 86400 -> "#{div(diff, 3600)}h ago"
      true -> "#{div(diff, 86400)}d ago"
    end
  end

  defp format_event_type(event_type) do
    event_type
    |> to_string()
    |> String.split("_")
    |> Enum.map(&String.capitalize/1)
    |> Enum.join(" ")
  end

  defp event_color("created"), do: "bg-blue-500"
  defp event_color("approved"), do: "bg-green-500"
  defp event_color("rejected"), do: "bg-red-500"
  defp event_color("started"), do: "bg-blue-400"
  defp event_color("completed"), do: "bg-green-600"
  defp event_color("failed"), do: "bg-red-600"
  defp event_color("cancelled"), do: "bg-gray-500"
  defp event_color("escalated"), do: "bg-orange-500"
  defp event_color(_), do: "bg-gray-400"
end
