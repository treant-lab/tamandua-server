defmodule TamanduaServerWeb.Live.Components.ApprovalCard do
  @moduledoc """
  Component for displaying a pending approval workflow card.

  Displays workflow details including alert title, severity, threat score,
  action type, policy name, and waiting time. Provides Approve and Reject
  action buttons.
  """

  use Phoenix.Component

  @doc """
  Renders an approval card for a pending workflow.

  ## Attributes

  * `workflow` - The workflow struct with preloaded alert and policy associations

  ## Examples

      <.render workflow={@workflow} />
  """
  def render(assigns) do
    ~H"""
    <div class="bg-white dark:bg-gray-800 shadow rounded-lg p-4 border-l-4 border-amber-500">
      <div class="flex items-start justify-between">
        <div class="flex-1">
          <!-- Severity and Action Type Badges -->
          <div class="flex items-center gap-2 mb-2">
            <span class={"inline-flex items-center px-2 py-1 rounded text-xs font-medium #{severity_class(@workflow)}"}>
              <%= get_alert_severity(@workflow) %>
            </span>
            <span class="inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200">
              <%= format_action_type(@workflow.action_type) %>
            </span>
          </div>

          <!-- Alert Title -->
          <h3 class="text-lg font-semibold text-gray-900 dark:text-white">
            <%= get_alert_title(@workflow) %>
          </h3>

          <!-- Details Grid -->
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

        <!-- Action Buttons -->
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

  # Helper functions

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
      alert ->
        agent_id = alert.agent_id
        if agent_id && String.length(agent_id) > 8 do
          String.slice(agent_id, 0..7) <> "..."
        else
          agent_id || "Unknown"
        end
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
