defmodule TamanduaServerWeb.Live.Components.DashboardWidgets do
  @moduledoc """
  Reusable widget components for the custom dashboard.

  This module provides Phoenix LiveView components for rendering various
  widget types with consistent styling and behavior.
  """

  use Phoenix.Component
  import TamanduaServerWeb.CoreComponents

  @doc """
  Renders a threat level gauge widget showing alert counts by severity.
  """
  attr :data, :map, required: true
  attr :config, :map, default: %{}

  def threat_level_gauge(assigns) do
    ~H"""
    <div class="threat-gauge">
      <div class="threat-gauge-item">
        <div class="threat-gauge-value text-red-600"><%= @data[:critical] || 0 %></div>
        <div class="threat-gauge-label">Critical</div>
        <%= if @config["show_percentage"] && @data[:total] && @data[:total] > 0 do %>
          <div class="text-xs text-gray-400 mt-1">
            <%= Float.round((@data[:critical] || 0) / @data[:total] * 100, 1) %>%
          </div>
        <% end %>
      </div>

      <div class="threat-gauge-item">
        <div class="threat-gauge-value text-orange-600"><%= @data[:high] || 0 %></div>
        <div class="threat-gauge-label">High</div>
        <%= if @config["show_percentage"] && @data[:total] && @data[:total] > 0 do %>
          <div class="text-xs text-gray-400 mt-1">
            <%= Float.round((@data[:high] || 0) / @data[:total] * 100, 1) %>%
          </div>
        <% end %>
      </div>

      <div class="threat-gauge-item">
        <div class="threat-gauge-value text-yellow-600"><%= @data[:medium] || 0 %></div>
        <div class="threat-gauge-label">Medium</div>
        <%= if @config["show_percentage"] && @data[:total] && @data[:total] > 0 do %>
          <div class="text-xs text-gray-400 mt-1">
            <%= Float.round((@data[:medium] || 0) / @data[:total] * 100, 1) %>%
          </div>
        <% end %>
      </div>

      <div class="threat-gauge-item">
        <div class="threat-gauge-value text-blue-600"><%= @data[:low] || 0 %></div>
        <div class="threat-gauge-label">Low</div>
        <%= if @config["show_percentage"] && @data[:total] && @data[:total] > 0 do %>
          <div class="text-xs text-gray-400 mt-1">
            <%= Float.round((@data[:low] || 0) / @data[:total] * 100, 1) %>%
          </div>
        <% end %>
      </div>
    </div>
    """
  end

  @doc """
  Renders an agent status overview widget.
  """
  attr :data, :map, required: true
  attr :config, :map, default: %{}

  def agent_status_overview(assigns) do
    ~H"""
    <div class="flex items-center justify-around h-full">
      <div class="text-center">
        <div class="text-3xl font-bold text-gray-900 dark:text-gray-100">
          <%= @data[:total] || 0 %>
        </div>
        <div class="text-sm text-gray-500">Total</div>
      </div>

      <div class="text-center">
        <div class="text-3xl font-bold text-green-600"><%= @data[:online] || 0 %></div>
        <div class="text-sm text-gray-500">Online</div>
        <%= if @config["show_version_info"] do %>
          <div class="text-xs text-gray-400 mt-1">Healthy</div>
        <% end %>
      </div>

      <div class="text-center">
        <div class="text-3xl font-bold text-gray-600"><%= @data[:offline] || 0 %></div>
        <div class="text-sm text-gray-500">Offline</div>
      </div>

      <div class="text-center">
        <div class="text-3xl font-bold text-red-600"><%= @data[:error] || 0 %></div>
        <div class="text-sm text-gray-500">Error</div>
      </div>
    </div>
    """
  end

  @doc """
  Renders a list of top detections.
  """
  attr :data, :map, required: true
  attr :config, :map, default: %{}

  def top_detections(assigns) do
    ~H"""
    <div class="widget-scrollable space-y-2 h-full">
      <%= if Enum.empty?(@data[:detections] || []) do %>
        <div class="widget-empty">
          <.icon name="hero-shield-check" class="icon" />
          <p class="text-sm">No detections in the selected time range</p>
        </div>
      <% else %>
        <%= for {detection, index} <- Enum.with_index(@data[:detections] || [], 1) do %>
          <div class="flex items-center justify-between p-2 bg-gray-50 dark:bg-gray-700 rounded hover:bg-gray-100 dark:hover:bg-gray-600 transition-colors">
            <div class="flex items-center gap-2 flex-1 min-w-0">
              <span class="flex-shrink-0 w-6 h-6 flex items-center justify-center bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 rounded-full text-xs font-semibold">
                <%= index %>
              </span>
              <span class="text-sm text-gray-900 dark:text-gray-100 widget-truncate">
                <%= detection.technique %>
              </span>
            </div>
            <span class="flex-shrink-0 ml-2 px-2 py-1 bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 rounded text-sm font-semibold">
              <%= detection.count %>
            </span>
          </div>
        <% end %>
      <% end %>
    </div>
    """
  end

  @doc """
  Renders a list of recent alerts.
  """
  attr :data, :map, required: true
  attr :config, :map, default: %{}

  def recent_alerts(assigns) do
    ~H"""
    <div class="alert-list">
      <%= if Enum.empty?(@data[:alerts] || []) do %>
        <div class="widget-empty">
          <.icon name="hero-bell-slash" class="icon" />
          <p class="text-sm">No recent alerts</p>
        </div>
      <% else %>
        <%= for alert <- @data[:alerts] || [] do %>
          <div class="alert-list-item">
            <div class="flex items-center justify-between mb-1">
              <span class="text-sm font-semibold text-gray-900 dark:text-gray-100 widget-truncate flex-1">
                <%= alert.title %>
              </span>
              <span class={"ml-2 widget-badge widget-badge-#{alert.severity}"}>
                <%= String.upcase(alert.severity) %>
              </span>
            </div>

            <%= if alert.mitre_technique do %>
              <div class="text-xs text-gray-500 dark:text-gray-400">
                MITRE: <%= alert.mitre_technique %>
              </div>
            <% end %>

            <div class="flex items-center justify-between mt-2 text-xs text-gray-400">
              <span>
                <%= Calendar.strftime(alert.inserted_at, "%Y-%m-%d %H:%M:%S") %>
              </span>
              <%= if alert.agent_id do %>
                <span class="font-mono">
                  <%= String.slice(alert.agent_id, 0..7) %>
                </span>
              <% end %>
            </div>
          </div>
        <% end %>
      <% end %>
    </div>
    """
  end

  @doc """
  Renders a timeline chart widget.
  """
  attr :data, :map, required: true
  attr :config, :map, default: %{}

  def timeline(assigns) do
    ~H"""
    <div class="widget-chart">
      <%= if @data[:timeline] && length(@data[:timeline]) > 0 do %>
        <div id="timeline-chart" phx-hook="TimelineChart" data-timeline={Jason.encode!(@data)}>
          <!-- Chart will be rendered by JavaScript hook -->
          <div class="widget-loading">
            <div class="spinner"></div>
          </div>
        </div>
      <% else %>
        <div class="widget-empty">
          <.icon name="hero-chart-bar" class="icon" />
          <p class="text-sm">No timeline data available</p>
        </div>
      <% end %>
    </div>
    """
  end

  @doc """
  Renders a system health metrics widget.
  """
  attr :data, :map, required: true
  attr :config, :map, default: %{}

  def system_health(assigns) do
    ~H"""
    <div class="space-y-4 p-4">
      <%= for {metric, info} <- @data do %>
        <%= if is_map(info) && Map.has_key?(info, :current) do %>
          <div>
            <div class="flex items-center justify-between mb-2">
              <span class="text-sm font-medium text-gray-700 dark:text-gray-300">
                <%= metric |> to_string() |> String.upcase() %>
              </span>
              <span class={metric_status_class(info[:status])}>
                <%= info[:current] %><%= metric_unit(metric) %>
              </span>
            </div>

            <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
              <div
                class={metric_bar_class(info[:status])}
                style={"width: #{min(info[:current] / info[:max] * 100, 100)}%"}
              >
              </div>
            </div>

            <%= if @config["show_alerts"] && info[:current] > info[:threshold] do %>
              <div class="text-xs text-red-600 dark:text-red-400 mt-1">
                <.icon name="hero-exclamation-triangle" class="w-3 h-3 inline mr-1" />
                Above threshold (<%= info[:threshold] %><%= metric_unit(metric) %>)
              </div>
            <% end %>
          </div>
        <% end %>
      <% end %>
    </div>
    """
  end

  @doc """
  Renders a detection performance metrics widget.
  """
  attr :data, :map, required: true
  attr :config, :map, default: %{}

  def detection_performance(assigns) do
    ~H"""
    <div class="grid grid-cols-3 gap-4 p-4">
      <div class="text-center">
        <div class="text-2xl font-bold text-blue-600">
          <%= Float.round(@data[:precision] || 0.0, 2) %>
        </div>
        <div class="text-xs text-gray-500 uppercase mt-1">Precision</div>
        <div class="text-xs text-gray-400 mt-1">
          <%= performance_indicator(@data[:precision]) %>
        </div>
      </div>

      <div class="text-center">
        <div class="text-2xl font-bold text-green-600">
          <%= Float.round(@data[:recall] || 0.0, 2) %>
        </div>
        <div class="text-xs text-gray-500 uppercase mt-1">Recall</div>
        <div class="text-xs text-gray-400 mt-1">
          <%= performance_indicator(@data[:recall]) %>
        </div>
      </div>

      <div class="text-center">
        <div class="text-2xl font-bold text-purple-600">
          <%= Float.round(@data[:f1_score] || 0.0, 2) %>
        </div>
        <div class="text-xs text-gray-500 uppercase mt-1">F1 Score</div>
        <div class="text-xs text-gray-400 mt-1">
          <%= performance_indicator(@data[:f1_score]) %>
        </div>
      </div>

      <%= if @config["show_trend"] && @data[:trend] do %>
        <div class="col-span-3 mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
          <div class="text-xs font-semibold text-gray-700 dark:text-gray-300 mb-2">
            Trend (Last 7 Days)
          </div>
          <div class="space-y-1">
            <%= for day <- Enum.take(@data[:trend], -3) do %>
              <div class="flex items-center justify-between text-xs">
                <span class="text-gray-500"><%= day.date %></span>
                <div class="flex items-center gap-2">
                  <span class="text-blue-600">P: <%= Float.round(day.precision, 2) %></span>
                  <span class="text-green-600">R: <%= Float.round(day.recall, 2) %></span>
                </div>
              </div>
            <% end %>
          </div>
        </div>
      <% end %>
    </div>
    """
  end

  # Helper functions

  defp metric_status_class("ok"), do: "text-sm font-semibold text-green-600"
  defp metric_status_class("warning"), do: "text-sm font-semibold text-yellow-600"
  defp metric_status_class("critical"), do: "text-sm font-semibold text-red-600"
  defp metric_status_class(_), do: "text-sm font-semibold text-gray-600"

  defp metric_bar_class("ok"), do: "h-2 rounded-full bg-green-500 transition-all duration-300"
  defp metric_bar_class("warning"), do: "h-2 rounded-full bg-yellow-500 transition-all duration-300"
  defp metric_bar_class("critical"), do: "h-2 rounded-full bg-red-500 transition-all duration-300"
  defp metric_bar_class(_), do: "h-2 rounded-full bg-gray-500 transition-all duration-300"

  defp metric_unit(:cpu), do: "%"
  defp metric_unit(:memory), do: "%"
  defp metric_unit(:latency), do: "ms"
  defp metric_unit(_), do: ""

  defp performance_indicator(value) when value >= 0.9, do: "Excellent"
  defp performance_indicator(value) when value >= 0.8, do: "Good"
  defp performance_indicator(value) when value >= 0.7, do: "Fair"
  defp performance_indicator(_), do: "Needs Improvement"

  @doc """
  Renders a supply chain security alerts widget.

  Shows real-time supply chain threats including malicious packages,
  typosquatting attempts, and anomalous install behaviors.
  """
  attr :data, :map, required: true
  attr :config, :map, default: %{}

  def supply_chain_alerts(assigns) do
    ~H"""
    <div class="supply-chain-alerts h-full">
      <div class="flex items-center justify-between px-4 py-2 border-b border-gray-200 dark:border-gray-700">
        <div class="flex items-center gap-2">
          <.icon name="hero-cube" class="w-5 h-5 text-purple-600" />
          <span class="text-sm font-semibold text-gray-900 dark:text-gray-100">Supply Chain Threats</span>
        </div>
        <div class="flex items-center gap-3 text-xs">
          <span class="flex items-center gap-1">
            <span class="w-2 h-2 rounded-full bg-red-500"></span>
            <span class="text-gray-600 dark:text-gray-400"><%= @data[:critical_count] || 0 %> critical</span>
          </span>
          <span class="flex items-center gap-1">
            <span class="w-2 h-2 rounded-full bg-yellow-500"></span>
            <span class="text-gray-600 dark:text-gray-400"><%= @data[:high_count] || 0 %> high</span>
          </span>
        </div>
      </div>

      <div class="divide-y divide-gray-200 dark:divide-gray-700 max-h-[400px] overflow-y-auto">
        <%= if Enum.empty?(@data[:alerts] || []) do %>
          <div class="px-6 py-12 text-center">
            <.icon name="hero-shield-check" class="w-12 h-12 mx-auto mb-3 text-green-500" />
            <p class="text-sm text-gray-500 dark:text-gray-400">No supply chain threats detected</p>
            <p class="text-xs text-gray-400 dark:text-gray-500 mt-1">Monitoring npm, pip, cargo, gem, and go packages</p>
          </div>
        <% else %>
          <%= for alert <- @data[:alerts] || [] do %>
            <div class="px-4 py-3 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
              <div class="flex items-start justify-between gap-2">
                <div class="flex-1 min-w-0">
                  <div class="flex items-center gap-2 mb-1">
                    <%= supply_chain_risk_icon(alert.enrichment["risk_type"]) %>
                    <span class="text-sm font-medium text-gray-900 dark:text-white truncate">
                      <%= alert.enrichment["package_name"] %>@<%= alert.enrichment["package_version"] %>
                    </span>
                    <span class={"px-2 py-0.5 rounded text-xs font-medium #{ecosystem_badge_class(alert.enrichment["ecosystem"])}"}>
                      <%= alert.enrichment["ecosystem_display"] || alert.enrichment["ecosystem"] %>
                    </span>
                  </div>
                  <p class="text-xs text-gray-600 dark:text-gray-400 line-clamp-2">
                    <%= alert.enrichment["severity_reason"] || alert.description %>
                  </p>
                  <div class="flex items-center gap-3 mt-2 text-xs text-gray-500 dark:text-gray-400">
                    <span class={"px-2 py-0.5 rounded #{severity_badge_class(alert.severity)}"}>
                      <%= String.upcase(alert.severity) %>
                    </span>
                    <span><%= format_time(alert.inserted_at) %></span>
                    <%= if alert.agent_id do %>
                      <span class="font-mono"><%= String.slice(alert.agent_id, 0..7) %></span>
                    <% end %>
                  </div>
                </div>
              </div>
            </div>
          <% end %>
        <% end %>
      </div>
    </div>
    """
  end

  defp supply_chain_risk_icon("known_malicious") do
    assigns = %{}
    ~H"""
    <span class="flex-shrink-0 w-5 h-5 flex items-center justify-center rounded-full bg-red-100 dark:bg-red-900">
      <.icon name="hero-exclamation-triangle" class="w-3 h-3 text-red-600 dark:text-red-400" />
    </span>
    """
  end

  defp supply_chain_risk_icon("typosquatting") do
    assigns = %{}
    ~H"""
    <span class="flex-shrink-0 w-5 h-5 flex items-center justify-center rounded-full bg-orange-100 dark:bg-orange-900">
      <.icon name="hero-eye" class="w-3 h-3 text-orange-600 dark:text-orange-400" />
    </span>
    """
  end

  defp supply_chain_risk_icon("malicious_script") do
    assigns = %{}
    ~H"""
    <span class="flex-shrink-0 w-5 h-5 flex items-center justify-center rounded-full bg-yellow-100 dark:bg-yellow-900">
      <.icon name="hero-code-bracket" class="w-3 h-3 text-yellow-600 dark:text-yellow-400" />
    </span>
    """
  end

  defp supply_chain_risk_icon("anomalous_behavior") do
    assigns = %{}
    ~H"""
    <span class="flex-shrink-0 w-5 h-5 flex items-center justify-center rounded-full bg-purple-100 dark:bg-purple-900">
      <.icon name="hero-signal" class="w-3 h-3 text-purple-600 dark:text-purple-400" />
    </span>
    """
  end

  defp supply_chain_risk_icon(_) do
    assigns = %{}
    ~H"""
    <span class="flex-shrink-0 w-5 h-5 flex items-center justify-center rounded-full bg-gray-100 dark:bg-gray-700">
      <.icon name="hero-cube" class="w-3 h-3 text-gray-600 dark:text-gray-400" />
    </span>
    """
  end

  defp ecosystem_badge_class("npm"), do: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
  defp ecosystem_badge_class("pypi"), do: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200"
  defp ecosystem_badge_class("cargo"), do: "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200"
  defp ecosystem_badge_class("gem"), do: "bg-pink-100 text-pink-800 dark:bg-pink-900 dark:text-pink-200"
  defp ecosystem_badge_class("go"), do: "bg-cyan-100 text-cyan-800 dark:bg-cyan-900 dark:text-cyan-200"
  defp ecosystem_badge_class(_), do: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200"

  defp severity_badge_class("critical"), do: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
  defp severity_badge_class("high"), do: "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200"
  defp severity_badge_class("medium"), do: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200"
  defp severity_badge_class("low"), do: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200"
  defp severity_badge_class(_), do: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200"

  defp format_time(nil), do: ""
  defp format_time(%DateTime{} = dt), do: Calendar.strftime(dt, "%H:%M:%S")
  defp format_time(%NaiveDateTime{} = dt), do: Calendar.strftime(dt, "%H:%M:%S")
  defp format_time(_), do: ""
end
