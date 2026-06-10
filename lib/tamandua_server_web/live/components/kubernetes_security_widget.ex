defmodule TamanduaServerWeb.Live.Components.KubernetesSecurityWidget do
  @moduledoc """
  Kubernetes security posture widget for the dashboard.

  Displays:
  - Per-node security posture (alerts grouped by node)
  - Per-namespace security posture (alerts grouped by namespace)
  - Real-time updates via PubSub

  ## Usage

      <KubernetesSecurityWidget.kubernetes_security data={@k8s_security_data} />
  """

  use Phoenix.Component
  import TamanduaServerWeb.CoreComponents

  @doc """
  Renders the Kubernetes security widget.

  ## Assigns

  - `:data` - Map with `:alerts`, `:by_node`, `:by_namespace` keys
  - `:config` - Optional configuration map
  """
  attr :data, :map, required: true
  attr :config, :map, default: %{}

  def kubernetes_security(assigns) do
    ~H"""
    <div class="kubernetes-security-widget h-full">
      <div class="flex items-center justify-between px-4 py-2 border-b border-gray-200 dark:border-gray-700">
        <div class="flex items-center gap-2">
          <.icon name="hero-server-stack" class="w-5 h-5 text-cyan-600" />
          <span class="text-sm font-semibold text-gray-900 dark:text-gray-100">
            Kubernetes Security Posture
          </span>
        </div>
        <div class="flex items-center gap-3 text-xs">
          <span class="flex items-center gap-1">
            <span class="w-2 h-2 rounded-full bg-red-500"></span>
            <span class="text-gray-600 dark:text-gray-400"><%= @data[:total_critical] || 0 %> critical</span>
          </span>
          <span class="flex items-center gap-1">
            <span class="w-2 h-2 rounded-full bg-orange-500"></span>
            <span class="text-gray-600 dark:text-gray-400"><%= @data[:total_high] || 0 %> high</span>
          </span>
        </div>
      </div>

      <div class="p-4">
        <!-- View Toggle -->
        <div class="flex gap-2 mb-4">
          <button
            phx-click="k8s_toggle_view"
            phx-value-mode="by_node"
            class={"px-3 py-1 text-sm rounded #{if @data[:view_mode] == :by_node, do: "bg-cyan-600 text-white", else: "bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300"}"}>
            By Node
          </button>
          <button
            phx-click="k8s_toggle_view"
            phx-value-mode="by_namespace"
            class={"px-3 py-1 text-sm rounded #{if @data[:view_mode] == :by_namespace, do: "bg-cyan-600 text-white", else: "bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300"}"}>
            By Namespace
          </button>
        </div>

        <!-- Grouped Data -->
        <div class="space-y-2 max-h-[350px] overflow-y-auto">
          <%= if Enum.empty?(@data[:grouped_data] || []) do %>
            <div class="text-center py-8">
              <.icon name="hero-shield-check" class="w-12 h-12 mx-auto mb-3 text-green-500" />
              <p class="text-sm text-gray-500 dark:text-gray-400">No Kubernetes alerts in selected time range</p>
              <p class="text-xs text-gray-400 dark:text-gray-500 mt-1">Monitoring runtime security on all nodes</p>
            </div>
          <% else %>
            <%= for group <- @data[:grouped_data] || [] do %>
              <div class="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-600 transition-colors">
                <div class="flex items-center gap-3">
                  <.group_icon view_mode={@data[:view_mode]} />
                  <div>
                    <div class="text-sm font-medium text-gray-900 dark:text-gray-100">
                      <%= group.name %>
                    </div>
                    <div class="text-xs text-gray-500 dark:text-gray-400">
                      <%= group.total %> alerts
                    </div>
                  </div>
                </div>
                <div class="flex items-center gap-2">
                  <%= if group.critical > 0 do %>
                    <span class="px-2 py-0.5 bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200 rounded text-xs font-medium">
                      <%= group.critical %>
                    </span>
                  <% end %>
                  <%= if group.high > 0 do %>
                    <span class="px-2 py-0.5 bg-orange-100 dark:bg-orange-900 text-orange-800 dark:text-orange-200 rounded text-xs font-medium">
                      <%= group.high %>
                    </span>
                  <% end %>
                  <%= if group.medium > 0 do %>
                    <span class="px-2 py-0.5 bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-200 rounded text-xs font-medium">
                      <%= group.medium %>
                    </span>
                  <% end %>
                  <%= if group.low > 0 do %>
                    <span class="px-2 py-0.5 bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 rounded text-xs font-medium">
                      <%= group.low %>
                    </span>
                  <% end %>
                </div>
              </div>
            <% end %>
          <% end %>
        </div>

        <!-- Cluster Summary -->
        <%= if @data[:cluster_name] do %>
          <div class="mt-4 pt-3 border-t border-gray-200 dark:border-gray-700">
            <div class="flex items-center justify-between text-xs text-gray-500 dark:text-gray-400">
              <span>Cluster: <%= @data[:cluster_name] %></span>
              <span><%= @data[:node_count] || 0 %> nodes monitored</span>
            </div>
          </div>
        <% end %>
      </div>
    </div>
    """
  end

  # Helper component for group icon
  defp group_icon(%{view_mode: :by_node} = assigns) do
    ~H"""
    <span class="flex-shrink-0 w-8 h-8 flex items-center justify-center rounded-full bg-cyan-100 dark:bg-cyan-900">
      <.icon name="hero-server" class="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
    </span>
    """
  end

  defp group_icon(%{view_mode: :by_namespace} = assigns) do
    ~H"""
    <span class="flex-shrink-0 w-8 h-8 flex items-center justify-center rounded-full bg-purple-100 dark:bg-purple-900">
      <.icon name="hero-folder" class="w-4 h-4 text-purple-600 dark:text-purple-400" />
    </span>
    """
  end

  defp group_icon(assigns) do
    ~H"""
    <span class="flex-shrink-0 w-8 h-8 flex items-center justify-center rounded-full bg-gray-100 dark:bg-gray-700">
      <.icon name="hero-cube" class="w-4 h-4 text-gray-600 dark:text-gray-400" />
    </span>
    """
  end
end
