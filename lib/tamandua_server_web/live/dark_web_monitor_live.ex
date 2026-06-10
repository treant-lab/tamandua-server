defmodule TamanduaServerWeb.DarkWebMonitorLive do
  @moduledoc """
  LiveView for dark web monitoring dashboard.

  Displays:
  - Compromised credentials overview
  - Recent breaches
  - Dark web intelligence findings
  - Threat actor activity
  - Response workflow status
  """

  use TamanduaServerWeb, :live_view

  alias TamanduaServer.DarkWeb
  alias TamanduaServer.DarkWeb.MonitoringService
  alias Phoenix.PubSub

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      # Subscribe to dark web updates
      PubSub.subscribe(TamanduaServer.PubSub, "dark_web:updates")
    end

    socket =
      socket
      |> assign(:page_title, "Dark Web Monitoring")
      |> assign(:active_tab, "overview")
      |> load_overview_data()

    {:ok, socket}
  end

  @impl true
  def handle_params(params, _url, socket) do
    tab = params["tab"] || "overview"

    socket =
      socket
      |> assign(:active_tab, tab)
      |> maybe_load_tab_data(tab)

    {:noreply, socket}
  end

  @impl true
  def handle_event("change_tab", %{"tab" => tab}, socket) do
    {:noreply, push_patch(socket, to: ~p"/dark-web?tab=#{tab}")}
  end

  @impl true
  def handle_event("sync_feeds", _params, socket) do
    MonitoringService.sync_all_feeds()

    {:noreply,
     socket
     |> put_flash(:info, "Feed synchronization started")
     |> assign(:syncing, true)}
  end

  @impl true
  def handle_event("update_credential_status", %{"id" => id, "status" => status}, socket) do
    credential = DarkWeb.get_credential!(id)

    case DarkWeb.update_credential(credential, %{status: status}) do
      {:ok, _credential} ->
        {:noreply,
         socket
         |> put_flash(:info, "Credential status updated")
         |> load_overview_data()}

      {:error, _changeset} ->
        {:noreply, put_flash(socket, :error, "Failed to update credential")}
    end
  end

  @impl true
  def handle_info({:dark_web_update, _data}, socket) do
    {:noreply, load_overview_data(socket)}
  end

  @impl true
  def handle_info(_msg, socket), do: {:noreply, socket}

  @impl true
  def render(assigns) do
    ~H"""
    <div class="p-6 max-w-7xl mx-auto">
      <!-- Header -->
      <div class="flex items-center justify-between mb-6">
        <div>
          <h1 class="text-2xl font-bold text-gray-900 dark:text-white">Dark Web Monitoring</h1>
          <p class="text-sm text-gray-600 dark:text-gray-400 mt-1">
            Monitor dark web for compromised credentials and threat intelligence
          </p>
        </div>

        <button
          phx-click="sync_feeds"
          class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg flex items-center gap-2"
        >
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              stroke-width="2"
              d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
            />
          </svg>
          Sync Feeds
        </button>
      </div>

      <!-- Stats Cards -->
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div class="flex items-center justify-between">
            <div>
              <p class="text-sm text-gray-600 dark:text-gray-400">Total Breaches</p>
              <p class="text-2xl font-bold text-gray-900 dark:text-white mt-1">
                <%= @stats.total_breaches %>
              </p>
            </div>
            <div class="p-3 bg-red-100 dark:bg-red-900/30 rounded-lg">
              <svg class="w-6 h-6 text-red-600 dark:text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                />
              </svg>
            </div>
          </div>
        </div>

        <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div class="flex items-center justify-between">
            <div>
              <p class="text-sm text-gray-600 dark:text-gray-400">Compromised Credentials</p>
              <p class="text-2xl font-bold text-gray-900 dark:text-white mt-1">
                <%= @stats.total_credentials %>
              </p>
            </div>
            <div class="p-3 bg-orange-100 dark:bg-orange-900/30 rounded-lg">
              <svg class="w-6 h-6 text-orange-600 dark:text-orange-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"
                />
              </svg>
            </div>
          </div>
        </div>

        <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div class="flex items-center justify-between">
            <div>
              <p class="text-sm text-gray-600 dark:text-gray-400">Matched Users</p>
              <p class="text-2xl font-bold text-gray-900 dark:text-white mt-1">
                <%= @stats.matched_users %>
              </p>
            </div>
            <div class="p-3 bg-yellow-100 dark:bg-yellow-900/30 rounded-lg">
              <svg class="w-6 h-6 text-yellow-600 dark:text-yellow-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"
                />
              </svg>
            </div>
          </div>
        </div>

        <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div class="flex items-center justify-between">
            <div>
              <p class="text-sm text-gray-600 dark:text-gray-400">Intelligence Findings</p>
              <p class="text-2xl font-bold text-gray-900 dark:text-white mt-1">
                <%= @stats.total_intelligence %>
              </p>
            </div>
            <div class="p-3 bg-purple-100 dark:bg-purple-900/30 rounded-lg">
              <svg class="w-6 h-6 text-purple-600 dark:text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
                />
              </svg>
            </div>
          </div>
        </div>
      </div>

      <!-- Tabs -->
      <div class="border-b border-gray-200 dark:border-gray-700 mb-6">
        <nav class="flex gap-4">
          <%!-- Note: Only showing overview tab until other tabs are fully implemented --%>
          <%= for {tab_id, tab_name} <- [
            {"overview", "Overview"}
          ] do %>
            <button
              phx-click="change_tab"
              phx-value-tab={tab_id}
              class={[
                "px-4 py-2 border-b-2 font-medium text-sm transition-colors",
                if(@active_tab == tab_id,
                  do: "border-blue-600 text-blue-600 dark:text-blue-400",
                  else: "border-transparent text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white"
                )
              ]}
            >
              <%= tab_name %>
            </button>
          <% end %>
        </nav>
      </div>

      <!-- Tab Content -->
      <%= case @active_tab do %>
        <% "overview" -> %>
          <.render_overview assigns={assigns} />
        <% "credentials" -> %>
          <.render_credentials assigns={assigns} />
        <% "breaches" -> %>
          <.render_breaches assigns={assigns} />
        <% "intelligence" -> %>
          <.render_intelligence assigns={assigns} />
        <% "threat_actors" -> %>
          <.render_threat_actors assigns={assigns} />
      <% end %>
    </div>
    """
  end

  # ============================================================================
  # Tab Renderers
  # ============================================================================

  defp render_overview(assigns) do
    ~H"""
    <div class="space-y-6">
      <!-- Recent Compromised Credentials -->
      <div class="bg-white dark:bg-gray-800 rounded-lg shadow">
        <div class="p-6 border-b border-gray-200 dark:border-gray-700">
          <h3 class="text-lg font-semibold text-gray-900 dark:text-white">
            Recent Compromised Credentials
          </h3>
        </div>
        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
            <thead class="bg-gray-50 dark:bg-gray-900">
              <tr>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                  Email
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                  Breach
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                  Severity
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                  Status
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                  First Seen
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
              <%= for credential <- @recent_credentials do %>
                <tr class="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                  <td class="px-6 py-4 whitespace-nowrap">
                    <div class="flex items-center">
                      <div class="text-sm font-medium text-gray-900 dark:text-white">
                        <%= credential.email %>
                      </div>
                    </div>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap">
                    <div class="text-sm text-gray-900 dark:text-white">
                      <%= credential.breach && credential.breach.breach_name %>
                    </div>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap">
                    <span class={[
                      "px-2 py-1 text-xs font-semibold rounded-full",
                      severity_badge_class(credential.severity)
                    ]}>
                      <%= String.upcase(credential.severity) %>
                    </span>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap">
                    <span class={[
                      "px-2 py-1 text-xs font-semibold rounded-full",
                      status_badge_class(credential.status)
                    ]}>
                      <%= format_status(credential.status) %>
                    </span>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                    <%= format_datetime(credential.first_seen) %>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm">
                    <.link
                      navigate={~p"/dark-web/credentials/#{credential.id}"}
                      class="text-blue-600 hover:text-blue-800 dark:text-blue-400"
                    >
                      View
                    </.link>
                  </td>
                </tr>
              <% end %>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Recent Intelligence -->
      <div class="bg-white dark:bg-gray-800 rounded-lg shadow">
        <div class="p-6 border-b border-gray-200 dark:border-gray-700">
          <h3 class="text-lg font-semibold text-gray-900 dark:text-white">
            Recent Intelligence Findings
          </h3>
        </div>
        <div class="p-6 space-y-4">
          <%= for intel <- @recent_intelligence do %>
            <div class="border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:bg-gray-50 dark:hover:bg-gray-700/50">
              <div class="flex items-start justify-between">
                <div class="flex-1">
                  <div class="flex items-center gap-2 mb-2">
                    <span class={[
                      "px-2 py-1 text-xs font-semibold rounded-full",
                      severity_badge_class(intel.severity)
                    ]}>
                      <%= String.upcase(intel.severity) %>
                    </span>
                    <span class="px-2 py-1 text-xs font-medium bg-gray-100 dark:bg-gray-700 rounded-full">
                      <%= format_intelligence_type(intel.intelligence_type) %>
                    </span>
                  </div>
                  <h4 class="text-sm font-semibold text-gray-900 dark:text-white mb-1">
                    <%= intel.title %>
                  </h4>
                  <p class="text-sm text-gray-600 dark:text-gray-400 line-clamp-2">
                    <%= intel.description %>
                  </p>
                  <div class="text-xs text-gray-500 dark:text-gray-500 mt-2">
                    <%= format_datetime(intel.first_seen) %> • Source: <%= intel.source %>
                  </div>
                </div>
                <.link
                  navigate={~p"/dark-web/intelligence/#{intel.id}"}
                  class="ml-4 text-blue-600 hover:text-blue-800 dark:text-blue-400 text-sm"
                >
                  View
                </.link>
              </div>
            </div>
          <% end %>
        </div>
      </div>
    </div>
    """
  end

  defp render_credentials(assigns) do
    ~H"""
    <div class="bg-white dark:bg-gray-800 rounded-lg shadow">
      <div class="p-6">
        <p class="text-gray-600 dark:text-gray-400">Credentials list view (implement full table)</p>
      </div>
    </div>
    """
  end

  defp render_breaches(assigns) do
    ~H"""
    <div class="bg-white dark:bg-gray-800 rounded-lg shadow">
      <div class="p-6">
        <p class="text-gray-600 dark:text-gray-400">Breaches list view (implement full table)</p>
      </div>
    </div>
    """
  end

  defp render_intelligence(assigns) do
    ~H"""
    <div class="bg-white dark:bg-gray-800 rounded-lg shadow">
      <div class="p-6">
        <p class="text-gray-600 dark:text-gray-400">Intelligence list view (implement full table)</p>
      </div>
    </div>
    """
  end

  defp render_threat_actors(assigns) do
    ~H"""
    <div class="bg-white dark:bg-gray-800 rounded-lg shadow">
      <div class="p-6">
        <p class="text-gray-600 dark:text-gray-400">Threat actors list view (implement full table)</p>
      </div>
    </div>
    """
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp load_overview_data(socket) do
    credential_stats = DarkWeb.get_credential_stats()
    breach_stats = DarkWeb.get_breach_stats()

    socket
    |> assign(:stats, %{
      total_breaches: breach_stats.total,
      total_credentials: credential_stats.total,
      matched_users: credential_stats.matched_users,
      total_intelligence: 0 # TODO: Add intelligence stats
    })
    |> assign(:recent_credentials, DarkWeb.list_credentials(limit: 10))
    |> assign(:recent_intelligence, DarkWeb.list_intelligence(limit: 5))
    |> assign(:syncing, false)
  end

  defp maybe_load_tab_data(socket, "overview"), do: load_overview_data(socket)
  defp maybe_load_tab_data(socket, _tab), do: socket

  defp severity_badge_class("critical"), do: "bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300"
  defp severity_badge_class("high"), do: "bg-orange-100 dark:bg-orange-900/30 text-orange-800 dark:text-orange-300"
  defp severity_badge_class("medium"), do: "bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-300"
  defp severity_badge_class("low"), do: "bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300"
  defp severity_badge_class(_), do: "bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-300"

  defp status_badge_class("new"), do: "bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300"
  defp status_badge_class("investigating"), do: "bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-300"
  defp status_badge_class("resolved"), do: "bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300"
  defp status_badge_class("false_positive"), do: "bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-300"
  defp status_badge_class(_), do: "bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-300"

  defp format_status(status) do
    status
    |> String.replace("_", " ")
    |> String.capitalize()
  end

  defp format_intelligence_type(type) do
    type
    |> String.replace("_", " ")
    |> String.capitalize()
  end

  defp format_datetime(nil), do: "N/A"

  defp format_datetime(datetime) do
    Calendar.strftime(datetime, "%Y-%m-%d %H:%M")
  end
end
