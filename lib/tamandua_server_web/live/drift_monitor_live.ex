defmodule TamanduaServerWeb.DriftMonitorLive do
  @moduledoc """
  LiveView dashboard for LLM output drift monitoring.

  Displays:
  - Time-series drift scores with threshold bands
  - Per-model drift status
  - Active alerts feed
  - Baseline statistics
  """

  use TamanduaServerWeb, :live_view
  alias Phoenix.PubSub
  alias TamanduaServer.Detection.LLMDriftDetector
  alias TamanduaServer.Detection.ML.DriftClient

  @refresh_interval_ms 30_000

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      PubSub.subscribe(TamanduaServer.PubSub, "drift:detected")
      :timer.send_interval(@refresh_interval_ms, self(), :refresh)
    end

    {:ok, assign(socket,
      page_title: "Drift Monitor",
      drift_scores: [],
      model_status: %{},
      active_alerts: [],
      statistics: %{},
      loading: true
    ) |> load_initial_data()}
  end

  @impl true
  def handle_info(:refresh, socket) do
    {:noreply, load_data(socket)}
  end

  @impl true
  def handle_info({:drift_detected, event}, socket) do
    # Add to drift scores
    new_score = %{
      model_id: event.model_id,
      score: event.drift_score,
      timestamp: event.timestamp
    }

    drift_scores = [new_score | socket.assigns.drift_scores] |> Enum.take(100)

    {:noreply, assign(socket, drift_scores: drift_scores) |> load_alerts()}
  end

  @impl true
  def handle_info(_msg, socket) do
    {:noreply, socket}
  end

  @impl true
  def handle_event("force_check", %{"model_id" => model_id}, socket) do
    Task.start(fn ->
      LLMDriftDetector.check_drift("manual", model_id)
    end)

    {:noreply, put_flash(socket, :info, "Drift check initiated for #{model_id}")}
  end

  @impl true
  def handle_event("refresh_data", _params, socket) do
    {:noreply, load_data(socket) |> put_flash(:info, "Data refreshed")}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="drift-monitor p-6">
      <header class="mb-6 flex justify-between items-center">
        <div>
          <h1 class="text-2xl font-bold text-gray-900 dark:text-white">
            LLM Drift Monitor
          </h1>
          <p class="text-sm text-gray-500 dark:text-gray-400">
            Monitor output distribution drift across models
          </p>
        </div>
        <button
          phx-click="refresh_data"
          class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
        >
          Refresh
        </button>
      </header>

      <!-- Statistics Cards -->
      <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
          <h3 class="text-sm font-medium text-gray-500 dark:text-gray-400">Samples Collected</h3>
          <p class="text-2xl font-bold text-gray-900 dark:text-white">
            <%= @statistics["total_samples"] || @statistics[:total_samples] || 0 %>
          </p>
        </div>
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
          <h3 class="text-sm font-medium text-gray-500 dark:text-gray-400">Drift Checks</h3>
          <p class="text-2xl font-bold text-gray-900 dark:text-white">
            <%= @statistics["total_checks"] || @statistics[:total_checks] || 0 %>
          </p>
        </div>
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
          <h3 class="text-sm font-medium text-gray-500 dark:text-gray-400">Drift Detected</h3>
          <p class="text-2xl font-bold text-red-600 dark:text-red-400">
            <%= @statistics["total_drift_detected"] || @statistics[:total_drift_detected] || 0 %>
          </p>
        </div>
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
          <h3 class="text-sm font-medium text-gray-500 dark:text-gray-400">Active Alerts</h3>
          <p class="text-2xl font-bold text-amber-600 dark:text-amber-400">
            <%= length(@active_alerts) %>
          </p>
        </div>
      </div>

      <!-- Drift Scores Chart -->
      <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6 mb-6">
        <h2 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Drift Scores Over Time
        </h2>
        <div id="drift-chart" phx-hook="DriftChart" data-scores={Jason.encode!(@drift_scores)}>
          <%= if Enum.empty?(@drift_scores) do %>
            <div class="text-center text-gray-500 py-12">
              <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
              </svg>
              <p class="mt-2">No drift data collected yet.</p>
              <p class="text-sm">Samples will appear as LLM inference occurs.</p>
            </div>
          <% else %>
            <div class="h-64">
              <!-- Chart rendered by JS hook -->
              <div class="space-y-2">
                <%= for score <- Enum.take(@drift_scores, 10) do %>
                  <div class="flex items-center justify-between text-sm">
                    <span class="text-gray-600 dark:text-gray-400"><%= score.model_id %></span>
                    <div class="flex items-center gap-2">
                      <div class="w-32 bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                        <div
                          class={"h-2 rounded-full #{score_color(score.score)}"}
                          style={"width: #{min(score.score * 100, 100)}%"}
                        >
                        </div>
                      </div>
                      <span class="text-gray-900 dark:text-white font-medium">
                        <%= Float.round(score.score * 100, 1) %>%
                      </span>
                    </div>
                  </div>
                <% end %>
              </div>
            </div>
          <% end %>
        </div>
      </div>

      <!-- Model Status Table -->
      <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6 mb-6">
        <h2 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Model Status
        </h2>
        <%= if map_size(@model_status) == 0 do %>
          <p class="text-gray-500 dark:text-gray-400 text-center py-4">
            No models tracked yet. Samples will appear as LLM inference occurs.
          </p>
        <% else %>
          <div class="overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead>
                <tr>
                  <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Model</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Samples</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Last Check</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Drift Score</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
                <%= for {model_id, status} <- @model_status do %>
                  <tr class="hover:bg-gray-50 dark:hover:bg-gray-700">
                    <td class="px-4 py-3 text-sm text-gray-900 dark:text-white font-medium">
                      <%= model_id %>
                    </td>
                    <td class="px-4 py-3 text-sm text-gray-500">
                      <%= status.samples_collected %>
                    </td>
                    <td class="px-4 py-3 text-sm text-gray-500">
                      <%= if status.last_check, do: format_datetime(status.last_check), else: "Never" %>
                    </td>
                    <td class="px-4 py-3 text-sm">
                      <span class={"font-medium #{drift_score_class(status.drift_score)}"}>
                        <%= Float.round((status.drift_score || 0.0) * 100, 1) %>%
                      </span>
                    </td>
                    <td class="px-4 py-3">
                      <%= if status.drift_detected do %>
                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200">
                          Drift Detected
                        </span>
                      <% else %>
                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
                          Normal
                        </span>
                      <% end %>
                    </td>
                    <td class="px-4 py-3">
                      <button
                        phx-click="force_check"
                        phx-value-model_id={model_id}
                        class="text-sm text-blue-600 hover:text-blue-800 dark:text-blue-400 hover:underline"
                      >
                        Check Now
                      </button>
                    </td>
                  </tr>
                <% end %>
              </tbody>
            </table>
          </div>
        <% end %>
      </div>

      <!-- Active Alerts -->
      <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <h2 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Active Alerts
        </h2>
        <%= if Enum.empty?(@active_alerts) do %>
          <div class="text-center py-8">
            <svg class="mx-auto h-12 w-12 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <p class="mt-2 text-gray-500 dark:text-gray-400">
              No active drift alerts
            </p>
          </div>
        <% else %>
          <div class="space-y-3">
            <%= for alert <- @active_alerts do %>
              <div class={"p-4 rounded-lg border-l-4 #{alert_class(alert)}"}>
                <div class="flex justify-between items-start">
                  <div>
                    <h3 class="font-medium text-gray-900 dark:text-white">
                      <%= alert["title"] || alert[:title] || "Drift Alert" %>
                    </h3>
                    <p class="text-sm text-gray-500 dark:text-gray-400 mt-1">
                      <%= alert["message"] || alert[:message] || "Drift detected" %>
                    </p>
                  </div>
                  <span class={"px-2 py-1 text-xs rounded #{severity_class(alert)}"}>
                    <%= alert["level"] || alert[:level] || "medium" %>
                  </span>
                </div>
              </div>
            <% end %>
          </div>
        <% end %>
      </div>
    </div>
    """
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp load_initial_data(socket) do
    load_data(assign(socket, loading: false))
  end

  defp load_data(socket) do
    socket
    |> load_statistics()
    |> load_model_status()
    |> load_alerts()
  end

  defp load_statistics(socket) do
    stats = LLMDriftDetector.get_statistics()
    assign(socket, statistics: stats)
  rescue
    _ ->
      case DriftClient.get_statistics() do
        {:ok, stats} -> assign(socket, statistics: stats)
        {:error, _} -> socket
      end
  end

  defp load_model_status(socket) do
    models = LLMDriftDetector.list_models()

    model_status = Enum.reduce(models, %{}, fn {model_id, sample_count}, acc ->
      case LLMDriftDetector.get_status(model_id) do
        {:ok, status} -> Map.put(acc, model_id, status)
        {:error, _} -> Map.put(acc, model_id, %{
          samples_collected: sample_count,
          last_check: nil,
          drift_detected: false,
          drift_score: 0.0,
          alerts: []
        })
      end
    end)

    assign(socket, model_status: model_status)
  rescue
    _ -> socket
  end

  defp load_alerts(socket) do
    case DriftClient.get_active_alerts() do
      {:ok, alerts} -> assign(socket, active_alerts: alerts)
      {:error, _} -> socket
    end
  end

  defp format_datetime(nil), do: "Never"
  defp format_datetime(datetime) do
    Calendar.strftime(datetime, "%Y-%m-%d %H:%M:%S")
  end

  defp score_color(score) when score >= 0.5, do: "bg-red-500"
  defp score_color(score) when score >= 0.25, do: "bg-yellow-500"
  defp score_color(_score), do: "bg-green-500"

  defp drift_score_class(score) when score >= 0.5, do: "text-red-600 dark:text-red-400"
  defp drift_score_class(score) when score >= 0.25, do: "text-yellow-600 dark:text-yellow-400"
  defp drift_score_class(_score), do: "text-green-600 dark:text-green-400"

  defp alert_class(alert) do
    level = alert["level"] || alert[:level] || "low"
    case level do
      "critical" -> "border-red-500 bg-red-50 dark:bg-red-900/20"
      "high" -> "border-orange-500 bg-orange-50 dark:bg-orange-900/20"
      "medium" -> "border-yellow-500 bg-yellow-50 dark:bg-yellow-900/20"
      _ -> "border-blue-500 bg-blue-50 dark:bg-blue-900/20"
    end
  end

  defp severity_class(alert) do
    level = alert["level"] || alert[:level] || "low"
    case level do
      "critical" -> "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
      "high" -> "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200"
      "medium" -> "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200"
      _ -> "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200"
    end
  end
end
