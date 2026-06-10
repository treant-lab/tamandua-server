defmodule TamanduaServerWeb.Components.SimilarAlertsComponent do
  @moduledoc """
  Component to display similar alerts on the alert detail page.

  Features:
  - Shows N most similar alerts
  - Similarity score badge
  - Quick navigation to similar alerts
  - "View all similar" link to similarity graph
  """

  use TamanduaServerWeb, :live_component

  alias TamanduaServer.Alerts.SimilarityDetector

  require Logger

  @impl true
  def update(assigns, socket) do
    if assigns[:alert] && is_nil(socket.assigns[:similar_alerts]) do
      # Load similar alerts
      send(self(), {:load_similar_alerts, assigns.alert})
    end

    {:ok,
     socket
     |> assign(assigns)
     |> assign_new(:similar_alerts, fn -> nil end)
     |> assign_new(:loading, fn -> true end)
     |> assign_new(:error, fn -> nil end)}
  end

  @impl true
  def handle_event("load_similar", _params, socket) do
    send(self(), {:load_similar_alerts, socket.assigns.alert})
    {:noreply, assign(socket, loading: true)}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="similar-alerts-component bg-white rounded-lg shadow p-6">
      <div class="flex justify-between items-center mb-4">
        <h3 class="text-lg font-semibold text-gray-900">Similar Alerts</h3>

        <%= if @similar_alerts && length(@similar_alerts) > 0 do %>
          <.link
            navigate={~p"/alerts/similarity?highlight=#{@alert.id}"}
            class="text-sm text-indigo-600 hover:text-indigo-800"
          >
            View Similarity Graph →
          </.link>
        <% end %>
      </div>

      <!-- Loading State -->
      <%= if @loading do %>
        <div class="flex items-center justify-center py-8">
          <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-600"></div>
          <span class="ml-3 text-gray-600">Finding similar alerts...</span>
        </div>
      <% end %>

      <!-- Error State -->
      <%= if @error do %>
        <div class="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
          <p class="text-sm text-yellow-800"><%= @error %></p>
          <button
            phx-click="load_similar"
            phx-target={@myself}
            class="mt-2 text-sm text-yellow-900 underline"
          >
            Try again
          </button>
        </div>
      <% end %>

      <!-- Similar Alerts List -->
      <%= if @similar_alerts && length(@similar_alerts) > 0 do %>
        <div class="space-y-3">
          <%= for similar <- Enum.take(@similar_alerts, 10) do %>
            <div class="similar-alert-item border rounded-lg p-4 hover:bg-gray-50 transition">
              <div class="flex justify-between items-start">
                <div class="flex-1">
                  <div class="flex items-center gap-2 mb-2">
                    <.link
                      navigate={~p"/alerts/#{similar["alert_id"]}"}
                      class="text-sm font-medium text-gray-900 hover:text-indigo-600"
                    >
                      <%= similar["alert"]["title"] %>
                    </.link>

                    <span class={"similarity-badge badge-similarity-#{similarity_level(similar["similarity"])}"}>
                      <%= format_similarity(similar["similarity"]) %>
                    </span>
                  </div>

                  <div class="flex items-center gap-3 text-xs text-gray-600">
                    <span class={"badge badge-#{similar["alert"]["severity"]}"}>
                      <%= String.upcase(similar["alert"]["severity"]) %>
                    </span>

                    <span>
                      <%= format_relative_time(similar["alert"]["inserted_at"]) %>
                    </span>

                    <%= if similar["alert"]["agent_id"] do %>
                      <span>
                        Agent: <%= String.slice(similar["alert"]["agent_id"], 0..7) %>...
                      </span>
                    <% end %>
                  </div>

                  <%= if similar["alert"]["mitre_techniques"] && length(similar["alert"]["mitre_techniques"]) > 0 do %>
                    <div class="mt-2 flex flex-wrap gap-1">
                      <%= for technique <- Enum.take(similar["alert"]["mitre_techniques"], 3) do %>
                        <span class="text-xs bg-blue-100 text-blue-800 px-2 py-1 rounded">
                          <%= technique %>
                        </span>
                      <% end %>
                    </div>
                  <% end %>
                </div>

                <div class="ml-4">
                  <.link
                    navigate={~p"/alerts/#{similar["alert_id"]}"}
                    class="text-indigo-600 hover:text-indigo-800"
                  >
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path
                        stroke-linecap="round"
                        stroke-linejoin="round"
                        stroke-width="2"
                        d="M9 5l7 7-7 7"
                      />
                    </svg>
                  </.link>
                </div>
              </div>
            </div>
          <% end %>
        </div>

        <%= if length(@similar_alerts) > 10 do %>
          <div class="mt-4 text-center">
            <.link
              navigate={~p"/alerts/similarity?highlight=#{@alert.id}"}
              class="text-sm text-indigo-600 hover:text-indigo-800 font-medium"
            >
              View all <%= length(@similar_alerts) %> similar alerts →
            </.link>
          </div>
        <% end %>
      <% end %>

      <!-- No Similar Alerts -->
      <%= if !@loading && !@error && @similar_alerts && length(@similar_alerts) == 0 do %>
        <div class="text-center py-8">
          <svg
            class="mx-auto h-12 w-12 text-gray-400"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              stroke-width="2"
              d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
            />
          </svg>
          <p class="mt-2 text-sm text-gray-600">No similar alerts found</p>
        </div>
      <% end %>
    </div>
    """
  end

  # ==================== Helper Functions ====================

  defp format_similarity(similarity) when is_float(similarity) do
    "#{round(similarity * 100)}% similar"
  end

  defp format_similarity(_), do: "N/A"

  defp similarity_level(similarity) when similarity >= 0.95, do: "high"
  defp similarity_level(similarity) when similarity >= 0.85, do: "medium"
  defp similarity_level(_), do: "low"

  defp format_relative_time(timestamp_str) when is_binary(timestamp_str) do
    case DateTime.from_iso8601(timestamp_str) do
      {:ok, dt, _} -> format_relative_time(dt)
      _ -> "Unknown time"
    end
  end

  defp format_relative_time(%DateTime{} = dt) do
    diff_seconds = DateTime.diff(DateTime.utc_now(), dt)

    cond do
      diff_seconds < 60 ->
        "Just now"

      diff_seconds < 3600 ->
        minutes = div(diff_seconds, 60)
        "#{minutes}m ago"

      diff_seconds < 86400 ->
        hours = div(diff_seconds, 3600)
        "#{hours}h ago"

      diff_seconds < 604800 ->
        days = div(diff_seconds, 86400)
        "#{days}d ago"

      true ->
        Calendar.strftime(dt, "%Y-%m-%d")
    end
  end

  defp format_relative_time(_), do: "Unknown time"
end
