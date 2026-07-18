defmodule TamanduaServerWeb.DashboardShareLive do
  @moduledoc """
  LiveView for managing dashboard shares and viewing analytics.
  """
  use TamanduaServerWeb, :live_view

  alias TamanduaServer.{Dashboard, Dashboards}
  alias TamanduaServer.Dashboard.Share

  @impl true
  def mount(_params, _session, socket) do
    user = socket.assigns.current_user

    {:ok,
     socket
     |> assign(:page_title, "Dashboard Sharing")
     |> assign(:current_user, user)
     |> assign(:selected_dashboard, nil)
     |> assign(:show_create_modal, false)
     |> assign(:show_analytics_modal, false)
     |> assign(:selected_share, nil)
     |> load_dashboards()
     |> load_shares()}
  end

  @impl true
  def handle_params(params, _url, socket) do
    {:noreply, apply_action(socket, socket.assigns.live_action, params)}
  end

  defp apply_action(socket, :index, _params) do
    socket
    |> assign(:page_title, "Dashboard Sharing")
  end

  defp apply_action(socket, :new, params) do
    dashboard_id = params["dashboard_id"]

    socket
    |> assign(:page_title, "Create Share")
    |> assign(:selected_dashboard, dashboard_id)
    |> assign(:show_create_modal, true)
  end

  defp apply_action(socket, :analytics, %{"id" => share_id}) do
    share = Dashboard.get_share(share_id)
    analytics = Dashboard.get_share_analytics(share_id, time_range: :last_30_days)

    socket
    |> assign(:page_title, "Share Analytics")
    |> assign(:selected_share, share)
    |> assign(:analytics, analytics)
    |> assign(:show_analytics_modal, true)
  end

  @impl true
  def handle_event("open_create_modal", %{"dashboard_id" => dashboard_id}, socket) do
    {:noreply,
     socket
     |> assign(:selected_dashboard, dashboard_id)
     |> assign(:show_create_modal, true)}
  end

  def handle_event("close_create_modal", _params, socket) do
    {:noreply,
     socket
     |> assign(:show_create_modal, false)
     |> assign(:selected_dashboard, nil)}
  end

  def handle_event("create_share", params, socket) do
    attrs =
      params
      |> Map.put("created_by_user_id", socket.assigns.current_user.id)
      |> Map.put("dashboard_layout_id", socket.assigns.selected_dashboard)
      |> parse_share_params()

    case Dashboard.create_share(attrs) do
      {:ok, _share} ->
        {:noreply,
         socket
         |> put_flash(:info, "Dashboard share created successfully!")
         |> assign(:show_create_modal, false)
         |> assign(:selected_dashboard, nil)
         |> load_shares()}

      {:error, changeset} ->
        {:noreply,
         socket
         |> put_flash(:error, "Failed to create share: #{inspect(changeset.errors)}")}
    end
  end

  def handle_event("toggle_active", %{"share_id" => share_id}, socket) do
    share = Dashboard.get_share(share_id)

    case Dashboard.toggle_active(share) do
      {:ok, _share} ->
        {:noreply,
         socket
         |> put_flash(:info, "Share status updated")
         |> load_shares()}

      {:error, _changeset} ->
        {:noreply, put_flash(socket, :error, "Failed to update share status")}
    end
  end

  def handle_event("revoke_share", %{"share_id" => share_id}, socket) do
    share = Dashboard.get_share(share_id)

    case Dashboard.revoke_share(share) do
      {:ok, _share} ->
        {:noreply,
         socket
         |> put_flash(:info, "Share revoked successfully")
         |> load_shares()}

      {:error, _changeset} ->
        {:noreply, put_flash(socket, :error, "Failed to revoke share")}
    end
  end

  def handle_event("delete_share", %{"share_id" => share_id}, socket) do
    share = Dashboard.get_share(share_id)

    case Dashboard.delete_share(share) do
      {:ok, _share} ->
        {:noreply,
         socket
         |> put_flash(:info, "Share deleted successfully")
         |> load_shares()}

      {:error, _changeset} ->
        {:noreply, put_flash(socket, :error, "Failed to delete share")}
    end
  end

  def handle_event("regenerate_token", %{"share_id" => share_id}, socket) do
    share = Dashboard.get_share(share_id)

    case Dashboard.regenerate_token(share) do
      {:ok, _share} ->
        {:noreply,
         socket
         |> put_flash(:info, "Share URL regenerated successfully")
         |> load_shares()}

      {:error, _changeset} ->
        {:noreply, put_flash(socket, :error, "Failed to regenerate token")}
    end
  end

  def handle_event("copy_share_url", %{"url" => url}, socket) do
    {:noreply,
     socket
     |> put_flash(:info, "Share URL copied to clipboard!")}
  end

  def handle_event("copy_embed_code", %{"code" => _code}, socket) do
    {:noreply,
     socket
     |> put_flash(:info, "Embed code copied to clipboard!")}
  end

  def handle_event("view_analytics", %{"share_id" => share_id}, socket) do
    {:noreply, push_patch(socket, to: ~p"/dashboard/shares/#{share_id}/analytics")}
  end

  def handle_event("close_analytics_modal", _params, socket) do
    {:noreply,
     socket
     |> assign(:show_analytics_modal, false)
     |> assign(:selected_share, nil)
     |> assign(:analytics, nil)
     |> push_patch(to: ~p"/dashboard/shares")}
  end

  defp load_dashboards(socket) do
    user_id = socket.assigns.current_user.id
    dashboards = Dashboards.list_user_layouts(user_id)

    assign(socket, :dashboards, dashboards)
  end

  defp load_shares(socket) do
    user_id = socket.assigns.current_user.id
    shares = Dashboard.list_shares_by_user(user_id)

    assign(socket, :shares, shares)
  end

  defp parse_share_params(params) do
    params
    |> parse_expiry()
    |> parse_widgets()
    |> parse_allowed_ips()
    |> parse_allowed_domains()
  end

  defp parse_expiry(params) do
    case params["expiry_preset"] do
      "never" -> Map.put(params, "expires_at", nil)
      "1_day" -> Map.put(params, "expires_at", DateTime.add(DateTime.utc_now(), 1, :day))
      "7_days" -> Map.put(params, "expires_at", DateTime.add(DateTime.utc_now(), 7, :day))
      "30_days" -> Map.put(params, "expires_at", DateTime.add(DateTime.utc_now(), 30, :day))
      _ -> params
    end
  end

  defp parse_widgets(params) do
    case params["widget_ids"] do
      nil ->
        params

      widget_ids when is_binary(widget_ids) ->
        ids =
          widget_ids
          |> String.split(",")
          |> Enum.map(&String.trim/1)
          |> Enum.reject(&(&1 == ""))

        Map.put(params, "widget_ids", ids)

      widget_ids when is_list(widget_ids) ->
        params
    end
  end

  defp parse_allowed_ips(params) do
    case params["allowed_ips"] do
      nil ->
        params

      ips when is_binary(ips) ->
        ip_list =
          ips
          |> String.split(",")
          |> Enum.map(&String.trim/1)
          |> Enum.reject(&(&1 == ""))

        Map.put(params, "allowed_ips", ip_list)

      ips when is_list(ips) ->
        params
    end
  end

  defp parse_allowed_domains(params) do
    case params["allowed_domains"] do
      nil ->
        params

      domains when is_binary(domains) ->
        domain_list =
          domains
          |> String.split(",")
          |> Enum.map(&String.trim/1)
          |> Enum.reject(&(&1 == ""))

        Map.put(params, "allowed_domains", domain_list)

      domains when is_list(domains) ->
        params
    end
  end

  defp share_url(share) do
    base_url = TamanduaServerWeb.Endpoint.url()
    "#{base_url}/shared/dashboard/#{share.share_token}"
  end

  defp embed_code(share) do
    base_url = TamanduaServerWeb.Endpoint.url()
    Share.generate_embed_code(share, base_url)
  end

  defp format_expiry(nil), do: "Never"

  defp format_expiry(expires_at) do
    case DateTime.compare(expires_at, DateTime.utc_now()) do
      :gt ->
        Calendar.strftime(expires_at, "%B %d, %Y at %H:%M")

      _ ->
        "Expired"
    end
  end

  defp status_badge_class(share) do
    cond do
      !is_nil(share.revoked_at) ->
        "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300"

      !share.is_active ->
        "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300"

      Share.accessible?(share) ->
        "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300"

      true ->
        "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300"
    end
  end

  defp status_text(share) do
    cond do
      !is_nil(share.revoked_at) -> "Revoked"
      !share.is_active -> "Inactive"
      Share.accessible?(share) -> "Active"
      true -> "Expired"
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="min-h-screen bg-gray-50 dark:bg-gray-900">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <!-- Header -->
        <div class="mb-8">
          <div class="flex items-center justify-between">
            <div>
              <h1 class="text-3xl font-bold text-gray-900 dark:text-white">
                Dashboard Sharing
              </h1>
              <p class="mt-2 text-sm text-gray-600 dark:text-gray-400">
                Share dashboards publicly with customizable access controls and analytics.
              </p>
            </div>
          </div>
        </div>

        <!-- Dashboards Grid -->
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
          <%= for dashboard <- @dashboards do %>
            <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
              <div class="flex items-start justify-between mb-4">
                <div class="flex-1">
                  <h3 class="text-lg font-semibold text-gray-900 dark:text-white">
                    <%= dashboard.name %>
                  </h3>
                  <%= if dashboard.description do %>
                    <p class="mt-1 text-sm text-gray-500 dark:text-gray-400">
                      <%= dashboard.description %>
                    </p>
                  <% end %>
                </div>
              </div>

              <div class="flex items-center justify-between pt-4 border-t border-gray-200 dark:border-gray-700">
                <div class="text-sm text-gray-500 dark:text-gray-400">
                  <% share_count = Enum.count(@shares, fn s -> s.dashboard_layout_id == dashboard.id end) %>
                  <%= share_count %> <%= if share_count == 1, do: "share", else: "shares" %>
                </div>
                <button
                  phx-click="open_create_modal"
                  phx-value-dashboard_id={dashboard.id}
                  class="inline-flex items-center px-3 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700"
                >
                  <.icon name="hero-share" class="w-4 h-4 mr-1" />
                  Share
                </button>
              </div>
            </div>
          <% end %>
        </div>

        <!-- Active Shares Table -->
        <%= if length(@shares) > 0 do %>
          <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700">
            <div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
              <h2 class="text-lg font-semibold text-gray-900 dark:text-white">
                Your Shared Dashboards
              </h2>
            </div>
            <div class="overflow-x-auto">
              <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                <thead class="bg-gray-50 dark:bg-gray-900">
                  <tr>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      Dashboard
                    </th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      Status
                    </th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      Expires
                    </th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      Views
                    </th>
                    <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                  <%= for share <- @shares do %>
                    <tr>
                      <td class="px-6 py-4 whitespace-nowrap">
                        <div class="flex items-center">
                          <div>
                            <div class="text-sm font-medium text-gray-900 dark:text-white">
                              <%= share.custom_title || share.dashboard_layout.name %>
                            </div>
                            <div class="text-xs text-gray-500 dark:text-gray-400">
                              <%= share.share_type |> String.replace("_", " ") |> String.capitalize() %>
                            </div>
                          </div>
                        </div>
                      </td>
                      <td class="px-6 py-4 whitespace-nowrap">
                        <span class={"inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium #{status_badge_class(share)}"}>
                          <%= status_text(share) %>
                        </span>
                      </td>
                      <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                        <%= format_expiry(share.expires_at) %>
                      </td>
                      <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                        <button
                          phx-click="view_analytics"
                          phx-value-share_id={share.id}
                          class="text-blue-600 hover:text-blue-700 dark:text-blue-400"
                        >
                          View analytics →
                        </button>
                      </td>
                      <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                        <div class="flex items-center justify-end gap-2">
                          <button
                            phx-click={JS.dispatch("copy-to-clipboard", detail: %{text: share_url(share)})}
                            phx-click="copy_share_url"
                            phx-value-url={share_url(share)}
                            class="text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-white"
                            title="Copy share URL"
                          >
                            <.icon name="hero-link" class="w-5 h-5" />
                          </button>
                          <button
                            phx-click="toggle_active"
                            phx-value-share_id={share.id}
                            class="text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-white"
                            title={if share.is_active, do: "Deactivate", else: "Activate"}
                          >
                            <.icon
                              name={if share.is_active, do: "hero-pause", else: "hero-play"}
                              class="w-5 h-5"
                            />
                          </button>
                          <button
                            phx-click="delete_share"
                            phx-value-share_id={share.id}
                            data-confirm="Are you sure you want to delete this share?"
                            class="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300"
                            title="Delete"
                          >
                            <.icon name="hero-trash" class="w-5 h-5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  <% end %>
                </tbody>
              </table>
            </div>
          </div>
        <% else %>
          <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-12 text-center">
            <.icon name="hero-share" class="mx-auto h-12 w-12 text-gray-400" />
            <h3 class="mt-2 text-sm font-medium text-gray-900 dark:text-white">
              No shared dashboards
            </h3>
            <p class="mt-1 text-sm text-gray-500 dark:text-gray-400">
              Get started by sharing a dashboard from the grid above.
            </p>
          </div>
        <% end %>
      </div>

      <!-- Create Share Modal -->
      <%= if @show_create_modal do %>
        <div class="fixed inset-0 z-50 overflow-y-auto" aria-labelledby="modal-title" role="dialog" aria-modal="true">
          <div class="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
            <div class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" phx-click="close_create_modal">
            </div>

            <div class="inline-block align-bottom bg-white dark:bg-gray-800 rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-2xl sm:w-full">
              <.form :let={_f} for={%{}} phx-submit="create_share">
                <div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                  <h3 class="text-lg font-semibold text-gray-900 dark:text-white">
                    Create Dashboard Share
                  </h3>
                </div>

                <div class="px-6 py-4 space-y-4">
                  <!-- Share Type -->
                  <div>
                    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">
                      Share Type
                    </label>
                    <select
                      name="share_type"
                      required
                      class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                    >
                      <option value="full_dashboard">Full Dashboard</option>
                      <option value="specific_widgets">Specific Widgets</option>
                    </select>
                  </div>

                  <!-- Custom Title -->
                  <div>
                    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">
                      Custom Title (Optional)
                    </label>
                    <input
                      type="text"
                      name="custom_title"
                      class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                    />
                  </div>

                  <!-- Password Protection -->
                  <div>
                    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">
                      Password (Optional)
                    </label>
                    <input
                      type="password"
                      name="password"
                      autocomplete="new-password"
                      class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                    />
                  </div>

                  <!-- Expiry -->
                  <div>
                    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">
                      Expires
                    </label>
                    <select
                      name="expiry_preset"
                      class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                    >
                      <option value="never">Never</option>
                      <option value="1_day">1 Day</option>
                      <option value="7_days" selected>7 Days</option>
                      <option value="30_days">30 Days</option>
                    </select>
                  </div>

                  <!-- Display Options -->
                  <div class="space-y-2">
                    <label class="flex items-center">
                      <input
                        type="checkbox"
                        name="show_header"
                        class="rounded border-gray-300 text-blue-600 focus:ring-blue-500 dark:bg-gray-700 dark:border-gray-600"
                      />
                      <span class="ml-2 text-sm text-gray-700 dark:text-gray-300">Show header</span>
                    </label>
                    <label class="flex items-center">
                      <input
                        type="checkbox"
                        name="show_footer"
                        checked
                        class="rounded border-gray-300 text-blue-600 focus:ring-blue-500 dark:bg-gray-700 dark:border-gray-600"
                      />
                      <span class="ml-2 text-sm text-gray-700 dark:text-gray-300">Show footer</span>
                    </label>
                    <label class="flex items-center">
                      <input
                        type="checkbox"
                        name="show_watermark"
                        checked
                        class="rounded border-gray-300 text-blue-600 focus:ring-blue-500 dark:bg-gray-700 dark:border-gray-600"
                      />
                      <span class="ml-2 text-sm text-gray-700 dark:text-gray-300">Show watermark</span>
                    </label>
                  </div>
                </div>

                <div class="px-6 py-4 bg-gray-50 dark:bg-gray-900 flex justify-end gap-3">
                  <button
                    type="button"
                    phx-click="close_create_modal"
                    class="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md hover:bg-gray-50 dark:hover:bg-gray-700"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    class="px-4 py-2 text-sm font-medium text-white bg-blue-600 border border-transparent rounded-md hover:bg-blue-700"
                  >
                    Create Share
                  </button>
                </div>
              </.form>
            </div>
          </div>
        </div>
      <% end %>

      <!-- Analytics Modal -->
      <%= if @show_analytics_modal && @selected_share && @analytics do %>
        <div class="fixed inset-0 z-50 overflow-y-auto" aria-labelledby="modal-title" role="dialog" aria-modal="true">
          <div class="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
            <div class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" phx-click="close_analytics_modal">
            </div>

            <div class="inline-block align-bottom bg-white dark:bg-gray-800 rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-4xl sm:w-full">
              <div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                <h3 class="text-lg font-semibold text-gray-900 dark:text-white">
                  Share Analytics: <%= @selected_share.custom_title || @selected_share.dashboard_layout.name %>
                </h3>
              </div>

              <div class="px-6 py-4">
                <!-- KPI Grid -->
                <div class="grid grid-cols-3 gap-4 mb-6">
                  <div class="bg-blue-50 dark:bg-blue-900/20 rounded-lg p-4">
                    <div class="text-sm font-medium text-blue-600 dark:text-blue-400">Total Views</div>
                    <div class="mt-1 text-2xl font-bold text-gray-900 dark:text-white">
                      <%= @analytics.total_views %>
                    </div>
                  </div>
                  <div class="bg-green-50 dark:bg-green-900/20 rounded-lg p-4">
                    <div class="text-sm font-medium text-green-600 dark:text-green-400">
                      Unique Visitors
                    </div>
                    <div class="mt-1 text-2xl font-bold text-gray-900 dark:text-white">
                      <%= @analytics.unique_visitors %>
                    </div>
                  </div>
                  <div class="bg-purple-50 dark:bg-purple-900/20 rounded-lg p-4">
                    <div class="text-sm font-medium text-purple-600 dark:text-purple-400">
                      Avg. Duration
                    </div>
                    <div class="mt-1 text-2xl font-bold text-gray-900 dark:text-white">
                      <%= if @analytics.avg_duration_seconds do %>
                        <%= trunc(@analytics.avg_duration_seconds) %>s
                      <% else %>
                        N/A
                      <% end %>
                    </div>
                  </div>
                </div>

                <!-- Top Referrers -->
                <%= if length(@analytics.top_referrers) > 0 do %>
                  <div class="mb-6">
                    <h4 class="text-sm font-semibold text-gray-900 dark:text-white mb-2">Top Referrers</h4>
                    <div class="space-y-2">
                      <%= for ref <- @analytics.top_referrers do %>
                        <div class="flex items-center justify-between text-sm">
                          <span class="text-gray-700 dark:text-gray-300 truncate"><%= ref.referrer %></span>
                          <span class="text-gray-500 dark:text-gray-400"><%= ref.count %> views</span>
                        </div>
                      <% end %>
                    </div>
                  </div>
                <% end %>

                <!-- Share URL -->
                <div class="border-t border-gray-200 dark:border-gray-700 pt-4">
                  <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Share URL
                  </label>
                  <div class="flex gap-2">
                    <input
                      type="text"
                      readonly
                      value={share_url(@selected_share)}
                      class="flex-1 rounded-md border-gray-300 bg-gray-50 dark:bg-gray-700 dark:border-gray-600 dark:text-white text-sm"
                    />
                    <button
                      phx-click={JS.dispatch("copy-to-clipboard", detail: %{text: share_url(@selected_share)})}
                      phx-click="copy_share_url"
                      phx-value-url={share_url(@selected_share)}
                      class="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700"
                    >
                      Copy
                    </button>
                  </div>
                </div>

                <!-- Embed Code -->
                <div class="mt-4">
                  <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Embed Code
                  </label>
                  <div class="flex gap-2">
                    <textarea
                      readonly
                      rows="4"
                      class="flex-1 rounded-md border-gray-300 bg-gray-50 dark:bg-gray-700 dark:border-gray-600 dark:text-white text-xs font-mono"
                    ><%= embed_code(@selected_share) %></textarea>
                    <button
                      phx-click={JS.dispatch("copy-to-clipboard", detail: %{text: embed_code(@selected_share)})}
                      phx-click="copy_embed_code"
                      phx-value-code={embed_code(@selected_share)}
                      class="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700"
                    >
                      Copy
                    </button>
                  </div>
                </div>
              </div>

              <div class="px-6 py-4 bg-gray-50 dark:bg-gray-900 flex justify-end">
                <button
                  type="button"
                  phx-click="close_analytics_modal"
                  class="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md hover:bg-gray-50 dark:hover:bg-gray-700"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      <% end %>
    </div>

    <script>
      // Copy to clipboard functionality
      window.addEventListener("copy-to-clipboard", (event) => {
        const text = event.detail.text;
        navigator.clipboard.writeText(text);
      });
    </script>
    """
  end
end
