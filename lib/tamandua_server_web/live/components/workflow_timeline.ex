defmodule TamanduaServerWeb.Live.Components.WorkflowTimeline do
  @moduledoc """
  Component for displaying a workflow's audit event timeline.

  Shows chronological audit events with timestamps, actors,
  and event details in a vertical timeline format.
  """

  use Phoenix.Component

  @doc """
  Renders a timeline of audit events for a workflow.

  ## Attributes

  * `events` - List of formatted timeline events from AuditTrail.get_workflow_history/1

  ## Examples

      <.render events={@events} />
  """
  def render(assigns) do
    ~H"""
    <div class="workflow-timeline">
      <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">Workflow History</h3>

      <%= if Enum.empty?(@events) do %>
        <p class="text-sm text-gray-500 dark:text-gray-400 text-center py-4">
          No events recorded yet
        </p>
      <% else %>
        <ol class="relative border-l border-gray-200 dark:border-gray-700 ml-3">
          <%= for event <- @events do %>
            <li class="mb-6 ml-6">
              <span class={"absolute flex items-center justify-center w-6 h-6 rounded-full -left-3 ring-8 ring-white dark:ring-gray-800 #{event_bg_class(event.event_type)}"}>
                <.event_icon event_type={event.event_type} />
              </span>
              <div class="p-3 bg-white dark:bg-gray-700 rounded-lg border border-gray-200 dark:border-gray-600 shadow-sm">
                <div class="flex items-center justify-between mb-1">
                  <span class={"text-sm font-semibold #{event_text_class(event.event_type)}"}>
                    <%= format_event_type(event.event_type) %>
                  </span>
                  <time class="text-xs text-gray-500 dark:text-gray-400">
                    <%= event.formatted_time %>
                  </time>
                </div>

                <div class="text-xs text-gray-600 dark:text-gray-400">
                  <span class="font-medium">Actor:</span> <%= event.actor_email || "System" %>
                </div>

                <%= if event.previous_state && event.new_state do %>
                  <div class="text-xs text-gray-600 dark:text-gray-400 mt-1">
                    <span class="font-medium">State:</span>
                    <%= event.previous_state %> -> <%= event.new_state %>
                  </div>
                <% end %>

                <%= if has_details?(event.details) do %>
                  <div class="mt-2 pt-2 border-t border-gray-100 dark:border-gray-600">
                    <.event_details details={event.details} />
                  </div>
                <% end %>
              </div>
            </li>
          <% end %>
        </ol>
      <% end %>
    </div>
    """
  end

  defp event_icon(%{event_type: "created"} = assigns) do
    ~H"""
    <svg class="w-3 h-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
    </svg>
    """
  end

  defp event_icon(%{event_type: "approved"} = assigns) do
    ~H"""
    <svg class="w-3 h-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
    </svg>
    """
  end

  defp event_icon(%{event_type: "rejected"} = assigns) do
    ~H"""
    <svg class="w-3 h-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
    </svg>
    """
  end

  defp event_icon(%{event_type: "started"} = assigns) do
    ~H"""
    <svg class="w-3 h-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
    </svg>
    """
  end

  defp event_icon(%{event_type: "completed"} = assigns) do
    ~H"""
    <svg class="w-3 h-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
    """
  end

  defp event_icon(%{event_type: "failed"} = assigns) do
    ~H"""
    <svg class="w-3 h-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
    """
  end

  defp event_icon(%{event_type: "cancelled"} = assigns) do
    ~H"""
    <svg class="w-3 h-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
    </svg>
    """
  end

  defp event_icon(%{event_type: "escalated"} = assigns) do
    ~H"""
    <svg class="w-3 h-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 10l7-7m0 0l7 7m-7-7v18" />
    </svg>
    """
  end

  defp event_icon(assigns) do
    ~H"""
    <svg class="w-3 h-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
    """
  end

  defp event_details(assigns) do
    ~H"""
    <dl class="text-xs space-y-1">
      <%= if @details["notes"] do %>
        <div>
          <dt class="inline font-medium text-gray-600 dark:text-gray-400">Notes:</dt>
          <dd class="inline text-gray-700 dark:text-gray-300 ml-1"><%= @details["notes"] %></dd>
        </div>
      <% end %>
      <%= if @details["reason"] do %>
        <div>
          <dt class="inline font-medium text-gray-600 dark:text-gray-400">Reason:</dt>
          <dd class="inline text-gray-700 dark:text-gray-300 ml-1"><%= @details["reason"] %></dd>
        </div>
      <% end %>
      <%= if @details["error"] do %>
        <div>
          <dt class="inline font-medium text-red-600 dark:text-red-400">Error:</dt>
          <dd class="inline text-red-700 dark:text-red-300 ml-1"><%= @details["error"] %></dd>
        </div>
      <% end %>
      <%= if @details["result"] do %>
        <div>
          <dt class="inline font-medium text-gray-600 dark:text-gray-400">Result:</dt>
          <dd class="inline text-gray-700 dark:text-gray-300 ml-1"><%= @details["result"] %></dd>
        </div>
      <% end %>
      <%= if @details["from_tier"] && @details["to_tier"] do %>
        <div>
          <dt class="inline font-medium text-orange-600 dark:text-orange-400">Escalation:</dt>
          <dd class="inline text-orange-700 dark:text-orange-300 ml-1">
            <%= @details["from_tier"] %> -> <%= @details["to_tier"] %>
          </dd>
        </div>
      <% end %>
    </dl>
    """
  end

  defp event_bg_class("created"), do: "bg-blue-500"
  defp event_bg_class("approved"), do: "bg-green-500"
  defp event_bg_class("rejected"), do: "bg-red-500"
  defp event_bg_class("started"), do: "bg-blue-400"
  defp event_bg_class("completed"), do: "bg-green-600"
  defp event_bg_class("failed"), do: "bg-red-600"
  defp event_bg_class("cancelled"), do: "bg-gray-500"
  defp event_bg_class("escalated"), do: "bg-orange-500"
  defp event_bg_class("auto_rejected"), do: "bg-red-700"
  defp event_bg_class("retried"), do: "bg-yellow-500"
  defp event_bg_class(_), do: "bg-gray-400"

  defp event_text_class("created"), do: "text-blue-600 dark:text-blue-400"
  defp event_text_class("approved"), do: "text-green-600 dark:text-green-400"
  defp event_text_class("rejected"), do: "text-red-600 dark:text-red-400"
  defp event_text_class("started"), do: "text-blue-500 dark:text-blue-300"
  defp event_text_class("completed"), do: "text-green-700 dark:text-green-300"
  defp event_text_class("failed"), do: "text-red-700 dark:text-red-300"
  defp event_text_class("cancelled"), do: "text-gray-600 dark:text-gray-400"
  defp event_text_class("escalated"), do: "text-orange-600 dark:text-orange-400"
  defp event_text_class("auto_rejected"), do: "text-red-700 dark:text-red-300"
  defp event_text_class("retried"), do: "text-yellow-600 dark:text-yellow-400"
  defp event_text_class(_), do: "text-gray-600 dark:text-gray-400"

  defp format_event_type(event_type) do
    event_type
    |> to_string()
    |> String.split("_")
    |> Enum.map(&String.capitalize/1)
    |> Enum.join(" ")
  end

  defp has_details?(nil), do: false
  defp has_details?(details) when is_map(details) do
    Enum.any?(~w(notes reason error result from_tier), &Map.has_key?(details, &1))
  end
  defp has_details?(_), do: false
end
