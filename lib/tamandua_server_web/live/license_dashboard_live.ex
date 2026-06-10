defmodule TamanduaServerWeb.LicenseDashboardLive do
  @moduledoc """
  LiveView dashboard for license management.

  Displays:
  - License status (active, expiring, expired)
  - Seat usage (used vs total)
  - Feature availability
  - Usage metrics (events, threats, storage)
  - Renewal information
  """

  use TamanduaServerWeb, :live_view

  alias TamanduaServer.Licensing.LicenseManager

  @refresh_interval 60_000  # 1 minute

  @impl true
  def mount(_params, session, socket) do
    organization_id = session["organization_id"]

    if connected?(socket) do
      :timer.send_interval(@refresh_interval, :refresh)
    end

    socket =
      socket
      |> assign(:organization_id, organization_id)
      |> assign(:page_title, "License Dashboard")
      |> load_license_data()

    {:ok, socket}
  end

  @impl true
  def handle_info(:refresh, socket) do
    {:noreply, load_license_data(socket)}
  end

  @impl true
  def handle_info(_msg, socket), do: {:noreply, socket}

  defp load_license_data(socket) do
    org_id = socket.assigns.organization_id

    license_info = case LicenseManager.get_license_info(org_id) do
      {:ok, info} -> info
      {:error, _} -> nil
    end

    usage_metrics = case LicenseManager.get_usage_metrics(org_id) do
      {:ok, metrics} -> metrics
      {:error, _} -> %{}
    end

    socket
    |> assign(:license_info, license_info)
    |> assign(:usage_metrics, usage_metrics)
    |> assign(:status_class, status_class(license_info))
  end

  defp status_class(nil), do: "bg-gray-100 text-gray-800"
  defp status_class(%{status: :active, days_remaining: days}) when days > 30, do: "bg-green-100 text-green-800"
  defp status_class(%{status: :active, days_remaining: days}) when days > 7, do: "bg-yellow-100 text-yellow-800"
  defp status_class(%{status: :active}), do: "bg-red-100 text-red-800"
  defp status_class(%{in_grace_period: true}), do: "bg-red-100 text-red-800"
  defp status_class(_), do: "bg-gray-100 text-gray-800"

  @impl true
  def render(assigns) do
    ~H"""
    <div class="p-6 space-y-6">
      <div class="flex justify-between items-center">
        <h1 class="text-2xl font-bold text-gray-900">License Dashboard</h1>
        <span class={"px-3 py-1 rounded-full text-sm font-medium #{@status_class}"}>
          <%= license_status_text(@license_info) %>
        </span>
      </div>

      <%= if @license_info do %>
        <!-- License Overview Card -->
        <div class="bg-white rounded-lg shadow p-6">
          <h2 class="text-lg font-semibold text-gray-900 mb-4">License Overview</h2>
          <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div class="bg-gray-50 rounded-lg p-4">
              <p class="text-sm text-gray-500">License Type</p>
              <p class="text-xl font-bold text-gray-900 capitalize"><%= @license_info.license_type %></p>
            </div>
            <div class="bg-gray-50 rounded-lg p-4">
              <p class="text-sm text-gray-500">License Key</p>
              <p class="text-xl font-bold text-gray-900 font-mono"><%= @license_info.license_key_masked %></p>
            </div>
            <div class="bg-gray-50 rounded-lg p-4">
              <p class="text-sm text-gray-500">Expires</p>
              <p class="text-xl font-bold text-gray-900"><%= format_date(@license_info.expires_at) %></p>
              <p class="text-sm text-gray-500"><%= @license_info.days_remaining %> days remaining</p>
            </div>
            <div class="bg-gray-50 rounded-lg p-4">
              <p class="text-sm text-gray-500">Auto-Renew</p>
              <p class="text-xl font-bold text-gray-900"><%= if @license_info.auto_renew, do: "Enabled", else: "Disabled" %></p>
            </div>
          </div>
        </div>

        <!-- Seat Usage Card -->
        <div class="bg-white rounded-lg shadow p-6">
          <h2 class="text-lg font-semibold text-gray-900 mb-4">Seat Usage</h2>
          <div class="flex items-center space-x-4">
            <div class="flex-1">
              <div class="flex justify-between mb-2">
                <span class="text-sm text-gray-500">Agents Connected</span>
                <span class="text-sm font-medium text-gray-900">
                  <%= @license_info.seats_used %> / <%= @license_info.seats_total %>
                </span>
              </div>
              <div class="w-full bg-gray-200 rounded-full h-4">
                <div
                  class={"h-4 rounded-full #{seat_usage_color(@license_info.seats_used, @license_info.seats_total)}"}
                  style={"width: #{seat_usage_percentage(@license_info.seats_used, @license_info.seats_total)}%"}
                ></div>
              </div>
            </div>
            <div class="text-right">
              <p class="text-2xl font-bold text-gray-900">
                <%= remaining_seats(@license_info.seats_total, @license_info.seats_used) %>
              </p>
              <p class="text-sm text-gray-500">available</p>
            </div>
          </div>
        </div>

        <!-- Features Card -->
        <div class="bg-white rounded-lg shadow p-6">
          <h2 class="text-lg font-semibold text-gray-900 mb-4">Included Features</h2>
          <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
            <%= for feature <- @license_info.features || [] do %>
              <div class="flex items-center space-x-2">
                <svg class="w-5 h-5 text-green-500" fill="currentColor" viewBox="0 0 20 20">
                  <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
                </svg>
                <span class="text-sm text-gray-700"><%= feature_name(feature) %></span>
              </div>
            <% end %>
          </div>
        </div>

        <!-- Usage Metrics Card -->
        <div class="bg-white rounded-lg shadow p-6">
          <h2 class="text-lg font-semibold text-gray-900 mb-4">Usage Metrics</h2>
          <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div class="bg-blue-50 rounded-lg p-4">
              <p class="text-sm text-blue-600">Endpoints Protected</p>
              <p class="text-2xl font-bold text-blue-900"><%= @usage_metrics[:endpoints_protected] || 0 %></p>
            </div>
            <div class="bg-green-50 rounded-lg p-4">
              <p class="text-sm text-green-600">Events (24h)</p>
              <p class="text-2xl font-bold text-green-900"><%= format_number(@usage_metrics[:events_processed_24h] || 0) %></p>
            </div>
            <div class="bg-red-50 rounded-lg p-4">
              <p class="text-sm text-red-600">Threats Blocked (24h)</p>
              <p class="text-2xl font-bold text-red-900"><%= @usage_metrics[:threats_blocked_24h] || 0 %></p>
            </div>
            <div class="bg-purple-50 rounded-lg p-4">
              <p class="text-sm text-purple-600">Storage Used</p>
              <p class="text-2xl font-bold text-purple-900">
                <%= Float.round(@usage_metrics[:storage_used_gb] || 0.0, 1) %> GB
              </p>
            </div>
          </div>
        </div>

      <% else %>
        <!-- No License State -->
        <div class="bg-yellow-50 border border-yellow-200 rounded-lg p-6 text-center">
          <h2 class="text-lg font-semibold text-yellow-800 mb-2">No Active License</h2>
          <p class="text-yellow-700 mb-4">
            Contact sales to activate a license for your organization.
          </p>
          <a href="mailto:contato@treantlab.org" class="inline-block px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700">
            Contact Sales
          </a>
        </div>
      <% end %>
    </div>
    """
  end

  # Helper functions
  defp license_status_text(nil), do: "No License"
  defp license_status_text(%{in_grace_period: true}), do: "Grace Period"
  defp license_status_text(%{status: :active, days_remaining: days}) when days <= 7, do: "Expiring Soon"
  defp license_status_text(%{status: :active}), do: "Active"
  defp license_status_text(%{status: status}), do: status |> to_string() |> String.capitalize()

  defp format_date(nil), do: "-"
  defp format_date(datetime), do: Calendar.strftime(datetime, "%b %d, %Y")

  defp format_number(n) when n >= 1_000_000, do: "#{Float.round(n / 1_000_000, 1)}M"
  defp format_number(n) when n >= 1_000, do: "#{Float.round(n / 1_000, 1)}K"
  defp format_number(n), do: to_string(n)

  defp seat_usage_percentage(used, total) when total > 0, do: min(100, round(used / total * 100))
  defp seat_usage_percentage(_, _), do: 0

  defp seat_usage_color(used, total) when total > 0 do
    percentage = used / total * 100
    cond do
      percentage >= 90 -> "bg-red-500"
      percentage >= 70 -> "bg-yellow-500"
      true -> "bg-green-500"
    end
  end
  defp seat_usage_color(_, _), do: "bg-gray-300"

  defp remaining_seats(total, used), do: max(0, total - used)

  defp feature_name(feature) when is_binary(feature), do: feature
  defp feature_name(feature) when is_map(feature), do: Map.get(feature, :description) || Map.get(feature, :name) || "Unknown"
  defp feature_name(feature) when is_atom(feature), do: feature |> to_string() |> String.replace("_", " ") |> String.capitalize()
  defp feature_name(_), do: "Unknown"
end
