defmodule TamanduaServerWeb.OnChainIncidentsLive do
  @moduledoc """
  LiveView for displaying on-chain incident attestations.

  Shows all incidents that have been attested on the Solana blockchain,
  with links to Solscan for verification.

  Key features:
  - Real-time updates when new attestations are created
  - Filter by severity, date range, bounty status
  - Show total bounties paid
  - Link to Solscan for each transaction
  """

  use TamanduaServerWeb, :live_view

  alias TamanduaServer.Alerts
  alias TamanduaServer.Solana.{Attestation, Bounty, Client}

  @impl true
  def mount(_params, session, socket) do
    if connected?(socket) do
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "alerts:attested")
    end

    organization_id = session["organization_id"]

    socket =
      socket
      |> assign(:page_title, "On-Chain Incidents")
      |> assign(:organization_id, organization_id)
      |> assign(:incidents, [])
      |> assign(:stats, %{
        total_attested: 0,
        total_bounties: 0,
        total_bounty_sol: 0.0
      })
      |> assign(:filter, %{
        severity: nil,
        bounty_only: false,
        date_range: "7d"
      })
      |> load_incidents()

    {:ok, socket}
  end

  @impl true
  def handle_params(params, _uri, socket) do
    filter = %{
      severity: params["severity"],
      bounty_only: params["bounty_only"] == "true",
      date_range: params["date_range"] || "7d"
    }

    {:noreply, socket |> assign(:filter, filter) |> load_incidents()}
  end

  @impl true
  def handle_info({:alert_attested, alert}, socket) do
    # Reload incidents when a new attestation is created
    {:noreply, load_incidents(socket)}
  end

  @impl true
  def handle_info(_msg, socket), do: {:noreply, socket}

  @impl true
  def render(assigns) do
    ~H"""
    <div class="container mx-auto px-4 py-8">
      <!-- Header -->
      <div class="mb-8">
        <h1 class="text-3xl font-bold text-gray-900 dark:text-white flex items-center gap-3">
          <svg class="w-8 h-8 text-purple-600" viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
          </svg>
          On-Chain Incidents
        </h1>
        <p class="mt-2 text-gray-600 dark:text-gray-400">
          Tamper-evident incident attestations verified on Solana blockchain
        </p>
      </div>

      <!-- Stats Cards -->
      <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div class="flex items-center">
            <div class="p-3 rounded-full bg-purple-100 dark:bg-purple-900">
              <svg class="w-6 h-6 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                      d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
              </svg>
            </div>
            <div class="ml-4">
              <p class="text-sm font-medium text-gray-500 dark:text-gray-400">Total Attested</p>
              <p class="text-2xl font-semibold text-gray-900 dark:text-white">
                <%= @stats.total_attested %>
              </p>
            </div>
          </div>
        </div>

        <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div class="flex items-center">
            <div class="p-3 rounded-full bg-green-100 dark:bg-green-900">
              <svg class="w-6 h-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                      d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
              </svg>
            </div>
            <div class="ml-4">
              <p class="text-sm font-medium text-gray-500 dark:text-gray-400">Bounties Paid</p>
              <p class="text-2xl font-semibold text-gray-900 dark:text-white">
                <%= @stats.total_bounties %>
              </p>
            </div>
          </div>
        </div>

        <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div class="flex items-center">
            <div class="p-3 rounded-full bg-yellow-100 dark:bg-yellow-900">
              <svg class="w-6 h-6 text-yellow-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                      d="M17 9V7a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2m2 4h10a2 2 0 002-2v-6a2 2 0 00-2-2H9a2 2 0 00-2 2v6a2 2 0 002 2zm7-5a2 2 0 11-4 0 2 2 0 014 0z"/>
              </svg>
            </div>
            <div class="ml-4">
              <p class="text-sm font-medium text-gray-500 dark:text-gray-400">Total SOL Paid</p>
              <p class="text-2xl font-semibold text-gray-900 dark:text-white">
                <%= :erlang.float_to_binary(@stats.total_bounty_sol, decimals: 3) %> SOL
              </p>
            </div>
          </div>
        </div>
      </div>

      <!-- Filters -->
      <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-4 mb-6">
        <div class="flex flex-wrap gap-4 items-center">
          <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">Severity</label>
            <select phx-change="filter"
                    name="severity"
                    class="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 dark:bg-gray-700">
              <option value="">All</option>
              <option value="critical" selected={@filter.severity == "critical"}>Critical</option>
              <option value="high" selected={@filter.severity == "high"}>High</option>
              <option value="medium" selected={@filter.severity == "medium"}>Medium</option>
              <option value="low" selected={@filter.severity == "low"}>Low</option>
            </select>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">Time Range</label>
            <select phx-change="filter"
                    name="date_range"
                    class="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 dark:bg-gray-700">
              <option value="24h" selected={@filter.date_range == "24h"}>Last 24 hours</option>
              <option value="7d" selected={@filter.date_range == "7d"}>Last 7 days</option>
              <option value="30d" selected={@filter.date_range == "30d"}>Last 30 days</option>
              <option value="all" selected={@filter.date_range == "all"}>All time</option>
            </select>
          </div>

          <div class="flex items-center mt-6">
            <input type="checkbox"
                   id="bounty_only"
                   name="bounty_only"
                   value="true"
                   checked={@filter.bounty_only}
                   phx-change="filter"
                   class="rounded border-gray-300 dark:border-gray-600"/>
            <label for="bounty_only" class="ml-2 text-sm text-gray-700 dark:text-gray-300">
              Show bounty incidents only
            </label>
          </div>
        </div>
      </div>

      <!-- Incidents Table -->
      <div class="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
        <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead class="bg-gray-50 dark:bg-gray-700">
            <tr>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                Incident
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                Severity
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                MITRE Technique
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                Attested
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                Bounty
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                Verify
              </th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
            <%= for incident <- @incidents do %>
              <tr class="hover:bg-gray-50 dark:hover:bg-gray-700">
                <td class="px-6 py-4">
                  <div class="text-sm font-medium text-gray-900 dark:text-white">
                    <%= incident.title %>
                  </div>
                  <div class="text-sm text-gray-500 dark:text-gray-400 mb-2">
                    ID: <%= String.slice(incident.id, 0, 8) %>...
                  </div>
                  <!-- Badges -->
                  <div class="flex flex-wrap gap-1">
                    <%= if incident.blockchain_tx_id do %>
                      <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200">
                        <svg class="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 24 24">
                          <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
                        </svg>
                        Verified
                      </span>
                    <% end %>
                    <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
                      <svg class="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clip-rule="evenodd"/>
                      </svg>
                      Privacy Safe
                    </span>
                    <%= if incident.bounty_tx_id do %>
                      <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200">
                        <svg class="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                          <path d="M8.433 7.418c.155-.103.346-.196.567-.267v1.698a2.305 2.305 0 01-.567-.267C8.07 8.34 8 8.114 8 8c0-.114.07-.34.433-.582zM11 12.849v-1.698c.22.071.412.164.567.267.364.243.433.468.433.582 0 .114-.07.34-.433.582a2.305 2.305 0 01-.567.267z"/>
                          <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-13a1 1 0 10-2 0v.092a4.535 4.535 0 00-1.676.662C6.602 6.234 6 7.009 6 8c0 .99.602 1.765 1.324 2.246.48.32 1.054.545 1.676.662v1.941c-.391-.127-.68-.317-.843-.504a1 1 0 10-1.51 1.31c.562.649 1.413 1.076 2.353 1.253V15a1 1 0 102 0v-.092a4.535 4.535 0 001.676-.662C13.398 13.766 14 12.991 14 12c0-.99-.602-1.765-1.324-2.246A4.535 4.535 0 0011 9.092V7.151c.391.127.68.317.843.504a1 1 0 101.511-1.31c-.563-.649-1.413-1.076-2.354-1.253V5z" clip-rule="evenodd"/>
                        </svg>
                        Bounty Paid
                      </span>
                    <% else %>
                      <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300">
                        Bounty Eligible
                      </span>
                    <% end %>
                  </div>
                </td>
                <td class="px-6 py-4">
                  <span class={"px-2 py-1 text-xs font-semibold rounded-full #{severity_class(incident.severity)}"}>
                    <%= String.upcase(incident.severity) %>
                  </span>
                </td>
                <td class="px-6 py-4 text-sm text-gray-900 dark:text-white">
                  <%= List.first(incident.mitre_techniques) || "N/A" %>
                </td>
                <td class="px-6 py-4 text-sm text-gray-500 dark:text-gray-400">
                  <%= format_datetime(incident.blockchain_attested_at) %>
                </td>
                <td class="px-6 py-4">
                  <%= if incident.bounty_tx_id do %>
                    <div class="flex items-center text-green-600">
                      <svg class="w-4 h-4 mr-1" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
                      </svg>
                      <span class="text-sm font-medium">
                        <%= format_bounty(incident.bounty_amount_lamports) %>
                      </span>
                    </div>
                  <% else %>
                    <span class="text-sm text-gray-400">-</span>
                  <% end %>
                </td>
                <td class="px-6 py-4">
                  <a href={Client.solscan_url(incident.blockchain_tx_id)}
                     target="_blank"
                     class="inline-flex items-center px-3 py-1 border border-purple-600 text-purple-600 rounded-md hover:bg-purple-50 dark:hover:bg-purple-900 text-sm">
                    <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                            d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/>
                    </svg>
                    Solscan
                  </a>
                </td>
              </tr>
            <% end %>

            <%= if Enum.empty?(@incidents) do %>
              <tr>
                <td colspan="6" class="px-6 py-16 text-center">
                  <svg class="mx-auto h-16 w-16 text-gray-300 dark:text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5"
                          d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
                  </svg>
                  <h3 class="mt-4 text-lg font-medium text-gray-900 dark:text-white">No On-Chain Incidents Yet</h3>
                  <p class="mt-2 text-sm text-gray-500 dark:text-gray-400 max-w-md mx-auto">
                    When threats are detected and attested on Solana, they will appear here with tamper-evident proof.
                  </p>
                  <p class="mt-2 text-xs text-gray-400 dark:text-gray-500">
                    Only medium, high, and critical severity incidents are automatically attested.
                  </p>
                  <div class="mt-6 flex justify-center gap-3">
                    <span class="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200">
                      <svg class="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 24 24">
                        <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
                      </svg>
                      Verified on Solana
                    </span>
                    <span class="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
                      <svg class="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clip-rule="evenodd"/>
                      </svg>
                      Privacy Safe
                    </span>
                  </div>
                </td>
              </tr>
            <% end %>
          </tbody>
        </table>
      </div>

      <!-- Info Banner -->
      <div class="mt-8 bg-purple-50 dark:bg-purple-900/20 border border-purple-200 dark:border-purple-800 rounded-lg p-4">
        <div class="flex">
          <div class="flex-shrink-0">
            <svg class="h-5 w-5 text-purple-400" fill="currentColor" viewBox="0 0 20 20">
              <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"/>
            </svg>
          </div>
          <div class="ml-3">
            <h3 class="text-sm font-medium text-purple-800 dark:text-purple-200">
              Private Telemetry, Public Proof
            </h3>
            <p class="mt-1 text-sm text-purple-700 dark:text-purple-300">
              Only cryptographic hashes of redacted incident data are stored on-chain.
              No sensitive telemetry or PII is ever exposed on the blockchain.
              Click "Solscan" to independently verify any attestation on Solana Devnet.
            </p>
          </div>
        </div>
      </div>
    </div>
    """
  end

  @impl true
  def handle_event("filter", params, socket) do
    filter = %{
      severity: params["severity"] |> empty_to_nil(),
      bounty_only: params["bounty_only"] == "true",
      date_range: params["date_range"] || "7d"
    }

    {:noreply, socket |> assign(:filter, filter) |> load_incidents()}
  end

  # Private functions

  defp load_incidents(socket) do
    org_id = socket.assigns.organization_id
    filter = socket.assigns.filter

    # Build query for attested alerts
    incidents =
      Alerts.list_attested_alerts(org_id,
        severity: filter.severity,
        bounty_only: filter.bounty_only,
        date_range: filter.date_range
      )

    # Calculate stats
    stats = %{
      total_attested: length(incidents),
      total_bounties: Enum.count(incidents, & &1.bounty_tx_id),
      total_bounty_sol: incidents
        |> Enum.map(& (&1.bounty_amount_lamports || 0))
        |> Enum.sum()
        |> Kernel./(1_000_000_000)
    }

    socket
    |> assign(:incidents, incidents)
    |> assign(:stats, stats)
  end

  defp severity_class("critical"), do: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
  defp severity_class("high"), do: "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200"
  defp severity_class("medium"), do: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200"
  defp severity_class("low"), do: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200"
  defp severity_class(_), do: "bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200"

  defp format_datetime(nil), do: "N/A"
  defp format_datetime(dt) do
    Calendar.strftime(dt, "%Y-%m-%d %H:%M")
  end

  defp format_bounty(nil), do: "0 SOL"
  defp format_bounty(lamports) do
    sol = lamports / 1_000_000_000
    "#{:erlang.float_to_binary(sol, decimals: 2)} SOL"
  end

  defp empty_to_nil(""), do: nil
  defp empty_to_nil(value), do: value
end
