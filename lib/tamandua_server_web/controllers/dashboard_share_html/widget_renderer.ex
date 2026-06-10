defmodule TamanduaServerWeb.DashboardShareHTML.WidgetRenderer do
  @moduledoc """
  Helper functions for rendering widget content in shared dashboards.
  """

  use Phoenix.Component
  import TamanduaServerWeb.CoreComponents

  @doc """
  Renders widget content based on widget type and data.
  """
  def render_widget_content(%{widget_type: "threat_level_gauge"} = widget, data) do
    assigns = %{widget: widget, data: data}

    ~H"""
    <div class="flex flex-col items-center justify-center h-full">
      <%= if @data && @data["threat_level"] do %>
        <div class={"text-6xl font-bold mb-2 #{threat_level_color(@data["threat_level"])}"}>
          <%= String.upcase(@data["threat_level"]) %>
        </div>
        <div class="text-sm text-gray-500 dark:text-gray-400">
          <%= @data["alert_count"] || 0 %> active alerts
        </div>
      <% else %>
        <div class="text-gray-400">No threat data</div>
      <% end %>
    </div>
    """
  end

  def render_widget_content(%{widget_type: "recent_alerts"} = widget, data) do
    assigns = %{widget: widget, data: data}

    ~H"""
    <div class="space-y-2">
      <%= if @data && @data["alerts"] do %>
        <%= for alert <- Enum.take(@data["alerts"], 10) do %>
          <div class="flex items-center justify-between p-2 bg-gray-50 dark:bg-gray-700 rounded">
            <div class="flex-1 min-w-0">
              <div class="text-sm font-medium text-gray-900 dark:text-white truncate">
                <%= alert["title"] %>
              </div>
              <div class="text-xs text-gray-500 dark:text-gray-400">
                <%= format_timestamp(alert["timestamp"]) %>
              </div>
            </div>
            <span class={"px-2 py-1 text-xs rounded #{severity_badge_color(alert["severity"])}"}>
              <%= alert["severity"] %>
            </span>
          </div>
        <% end %>
      <% else %>
        <div class="text-center text-gray-400 py-8">No recent alerts</div>
      <% end %>
    </div>
    """
  end

  def render_widget_content(%{widget_type: "agent_status_overview"} = widget, data) do
    assigns = %{widget: widget, data: data}

    ~H"""
    <div class="space-y-4">
      <%= if @data && @data["agents"] do %>
        <div class="grid grid-cols-3 gap-4 text-center">
          <div>
            <div class="text-2xl font-bold text-green-600"><%= @data["online_count"] || 0 %></div>
            <div class="text-xs text-gray-500">Online</div>
          </div>
          <div>
            <div class="text-2xl font-bold text-gray-600"><%= @data["offline_count"] || 0 %></div>
            <div class="text-xs text-gray-500">Offline</div>
          </div>
          <div>
            <div class="text-2xl font-bold text-red-600"><%= @data["isolated_count"] || 0 %></div>
            <div class="text-xs text-gray-500">Isolated</div>
          </div>
        </div>
      <% else %>
        <div class="text-center text-gray-400 py-8">No agent data</div>
      <% end %>
    </div>
    """
  end

  def render_widget_content(%{widget_type: "top_detections"} = widget, data) do
    assigns = %{widget: widget, data: data}

    ~H"""
    <div class="space-y-2">
      <%= if @data && @data["detections"] do %>
        <%= for {detection, idx} <- Enum.with_index(@data["detections"], 1) do %>
          <div class="flex items-center gap-3 p-2 bg-gray-50 dark:bg-gray-700 rounded">
            <div class="flex-shrink-0 w-6 h-6 flex items-center justify-center bg-blue-100 dark:bg-blue-900 rounded-full text-xs font-bold text-blue-600 dark:text-blue-300">
              <%= idx %>
            </div>
            <div class="flex-1 min-w-0">
              <div class="text-sm font-medium text-gray-900 dark:text-white truncate">
                <%= detection["name"] %>
              </div>
              <%= if detection["mitre_id"] do %>
                <div class="text-xs text-gray-500 dark:text-gray-400">
                  <%= detection["mitre_id"] %>
                </div>
              <% end %>
            </div>
            <div class="text-sm font-bold text-gray-700 dark:text-gray-300">
              <%= detection["count"] %>
            </div>
          </div>
        <% end %>
      <% else %>
        <div class="text-center text-gray-400 py-8">No detection data</div>
      <% end %>
    </div>
    """
  end

  def render_widget_content(%{widget_type: "alert_trend"} = widget, data) do
    assigns = %{widget: widget, data: data}

    ~H"""
    <div>
      <%= if @data && @data["dataPoints"] do %>
        <div class="mb-4 grid grid-cols-4 gap-2 text-center">
          <div>
            <div class="text-xs text-gray-500">Critical</div>
            <div class="text-lg font-bold text-red-600"><%= @data["totalCritical"] || 0 %></div>
          </div>
          <div>
            <div class="text-xs text-gray-500">High</div>
            <div class="text-lg font-bold text-orange-600"><%= @data["totalHigh"] || 0 %></div>
          </div>
          <div>
            <div class="text-xs text-gray-500">Medium</div>
            <div class="text-lg font-bold text-yellow-600"><%= @data["totalMedium"] || 0 %></div>
          </div>
          <div>
            <div class="text-xs text-gray-500">Low</div>
            <div class="text-lg font-bold text-blue-600"><%= @data["totalLow"] || 0 %></div>
          </div>
        </div>
        <div class="text-center text-sm text-gray-500">
          <%= @data["change"] %>% change from previous period
        </div>
      <% else %>
        <div class="text-center text-gray-400 py-8">No trend data</div>
      <% end %>
    </div>
    """
  end

  def render_widget_content(%{widget_type: "detection_performance"} = widget, data) do
    assigns = %{widget: widget, data: data}

    ~H"""
    <div class="space-y-4">
      <%= if @data do %>
        <div class="grid grid-cols-3 gap-4">
          <div class="text-center">
            <div class="text-2xl font-bold text-blue-600"><%= Float.round(@data["precision"] || 0.0, 2) %>%</div>
            <div class="text-xs text-gray-500">Precision</div>
          </div>
          <div class="text-center">
            <div class="text-2xl font-bold text-green-600"><%= Float.round(@data["recall"] || 0.0, 2) %>%</div>
            <div class="text-xs text-gray-500">Recall</div>
          </div>
          <div class="text-center">
            <div class="text-2xl font-bold text-purple-600"><%= Float.round(@data["f1_score"] || 0.0, 2) %>%</div>
            <div class="text-xs text-gray-500">F1 Score</div>
          </div>
        </div>
      <% else %>
        <div class="text-center text-gray-400 py-8">No performance data</div>
      <% end %>
    </div>
    """
  end

  def render_widget_content(%{widget_type: "system_health"} = widget, data) do
    assigns = %{widget: widget, data: data}

    ~H"""
    <div class="space-y-3">
      <%= if @data do %>
        <div>
          <div class="flex items-center justify-between text-sm mb-1">
            <span class="text-gray-700 dark:text-gray-300">CPU Usage</span>
            <span class="font-medium"><%= Float.round(@data["cpu_usage"] || 0.0, 1) %>%</span>
          </div>
          <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
            <div
              class={"h-2 rounded-full #{usage_color(@data["cpu_usage"] || 0)}"}
              style={"width: #{@data["cpu_usage"] || 0}%"}
            >
            </div>
          </div>
        </div>
        <div>
          <div class="flex items-center justify-between text-sm mb-1">
            <span class="text-gray-700 dark:text-gray-300">Memory Usage</span>
            <span class="font-medium"><%= Float.round(@data["memory_usage"] || 0.0, 1) %>%</span>
          </div>
          <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
            <div
              class={"h-2 rounded-full #{usage_color(@data["memory_usage"] || 0)}"}
              style={"width: #{@data["memory_usage"] || 0}%"}
            >
            </div>
          </div>
        </div>
        <div>
          <div class="flex items-center justify-between text-sm mb-1">
            <span class="text-gray-700 dark:text-gray-300">Latency</span>
            <span class="font-medium"><%= @data["latency_ms"] || 0 %>ms</span>
          </div>
        </div>
      <% else %>
        <div class="text-center text-gray-400 py-8">No health data</div>
      <% end %>
    </div>
    """
  end

  def render_widget_content(_widget, _data) do
    assigns = %{}

    ~H"""
    <div class="flex items-center justify-center h-full text-gray-400">
      <div class="text-center">
        <.icon name="hero-chart-bar" class="w-12 h-12 mx-auto mb-2" />
        <div class="text-sm">Widget data not available</div>
      </div>
    </div>
    """
  end

  # Helper functions

  defp threat_level_color("critical"), do: "text-red-600"
  defp threat_level_color("high"), do: "text-orange-600"
  defp threat_level_color("medium"), do: "text-yellow-600"
  defp threat_level_color("low"), do: "text-green-600"
  defp threat_level_color(_), do: "text-gray-600"

  defp severity_badge_color("critical"), do: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
  defp severity_badge_color("high"), do: "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200"
  defp severity_badge_color("medium"), do: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200"
  defp severity_badge_color("low"), do: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200"
  defp severity_badge_color(_), do: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200"

  defp usage_color(usage) when usage > 90, do: "bg-red-500"
  defp usage_color(usage) when usage > 75, do: "bg-yellow-500"
  defp usage_color(_), do: "bg-green-500"

  defp format_timestamp(nil), do: "N/A"

  defp format_timestamp(timestamp) when is_integer(timestamp) do
    timestamp
    |> DateTime.from_unix!(:millisecond)
    |> Calendar.strftime("%b %d, %H:%M")
  end

  defp format_timestamp(%DateTime{} = dt) do
    Calendar.strftime(dt, "%b %d, %H:%M")
  end

  defp format_timestamp(_), do: "N/A"
end
