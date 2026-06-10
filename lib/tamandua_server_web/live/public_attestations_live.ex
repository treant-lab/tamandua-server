defmodule TamanduaServerWeb.PublicAttestationsLive do
  @moduledoc """
  Public page for viewing blockchain-attested incidents.

  **No authentication required** - this is a public audit page.

  Shows only privacy-safe data:
  - Severity level
  - MITRE technique IDs
  - IOC counts (not values)
  - Threat classification
  - Blockchain transaction IDs
  - Attestation timestamps

  Does NOT show:
  - Organization or agent identifiers
  - Hostnames, usernames, file paths
  - Actual IOC values
  - Internal IP addresses
  - Any PII
  """

  use TamanduaServerWeb, :live_view
  # Use public layout (no sidebar) for this unauthenticated page
  use Phoenix.LiveView, layout: {TamanduaServerWeb.Layouts, :public}

  alias TamanduaServer.Alerts
  alias TamanduaServer.Solana.Client

  @impl true
  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(:page_title, "Public Attestations")
      |> assign(:filter, %{
        severity: nil,
        mitre_technique: nil,
        date_range: "7d"
      })
      |> assign(:attestations, [])
      |> assign(:stats, %{total_attested: 0, total_bounties: 0, total_bounty_sol: 0.0})
      |> load_data()

    {:ok, socket}
  end

  @impl true
  def handle_params(params, _uri, socket) do
    filter = %{
      severity: params["severity"] |> empty_to_nil(),
      mitre_technique: params["mitre"] |> empty_to_nil(),
      date_range: params["range"] || "7d"
    }

    {:noreply, socket |> assign(:filter, filter) |> load_data()}
  end

  @impl true
  def handle_event("filter", params, socket) do
    filter = %{
      severity: params["severity"] |> empty_to_nil(),
      mitre_technique: params["mitre"] |> empty_to_nil(),
      date_range: params["range"] || "7d"
    }

    {:noreply, socket |> assign(:filter, filter) |> load_data()}
  end

  defp load_data(socket) do
    filter = socket.assigns.filter

    opts = [
      severity: filter.severity,
      mitre_technique: filter.mitre_technique,
      date_range: filter.date_range,
      limit: 100
    ]
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)

    attestations = Alerts.list_public_attestations(opts)
    stats = Alerts.public_attestation_stats()

    socket
    |> assign(:attestations, attestations)
    |> assign(:stats, stats)
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="min-h-screen bg-gray-50 dark:bg-gray-900">
      <!-- Header -->
      <header class="bg-white dark:bg-gray-800 shadow">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div class="flex items-center justify-between">
            <div class="flex items-center space-x-3">
              <svg class="w-10 h-10 text-purple-600" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
              </svg>
              <div>
                <h1 class="text-2xl font-bold text-gray-900 dark:text-white">
                  Public Attestations
                </h1>
                <p class="text-sm text-gray-500 dark:text-gray-400">
                  Tamandua EDR - Blockchain-verified incident proofs
                </p>
              </div>
            </div>
            <a href="https://solscan.io" target="_blank"
               class="inline-flex items-center px-4 py-2 border border-purple-600 text-purple-600 rounded-lg hover:bg-purple-50 dark:hover:bg-purple-900/30 transition">
              <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                      d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/>
              </svg>
              Solscan
            </a>
          </div>
        </div>
      </header>

      <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <!-- Stats -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <div class="bg-white dark:bg-gray-800 rounded-xl shadow p-6">
            <div class="flex items-center">
              <div class="p-3 bg-purple-100 dark:bg-purple-900/30 rounded-full">
                <svg class="w-6 h-6 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                        d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                </svg>
              </div>
              <div class="ml-4">
                <p class="text-sm font-medium text-gray-500 dark:text-gray-400">Attestations</p>
                <p class="text-2xl font-bold text-gray-900 dark:text-white"><%= @stats.total_attested %></p>
              </div>
            </div>
          </div>

          <div class="bg-white dark:bg-gray-800 rounded-xl shadow p-6">
            <div class="flex items-center">
              <div class="p-3 bg-green-100 dark:bg-green-900/30 rounded-full">
                <svg class="w-6 h-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                        d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                </svg>
              </div>
              <div class="ml-4">
                <p class="text-sm font-medium text-gray-500 dark:text-gray-400">Bounties Paid</p>
                <p class="text-2xl font-bold text-gray-900 dark:text-white"><%= @stats.total_bounties %></p>
              </div>
            </div>
          </div>

          <div class="bg-white dark:bg-gray-800 rounded-xl shadow p-6">
            <div class="flex items-center">
              <div class="p-3 bg-yellow-100 dark:bg-yellow-900/30 rounded-full">
                <svg class="w-6 h-6 text-yellow-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                        d="M17 9V7a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2m2 4h10a2 2 0 002-2v-6a2 2 0 00-2-2H9a2 2 0 00-2 2v6a2 2 0 002 2zm7-5a2 2 0 11-4 0 2 2 0 014 0z"/>
                </svg>
              </div>
              <div class="ml-4">
                <p class="text-sm font-medium text-gray-500 dark:text-gray-400">Total SOL Paid</p>
                <p class="text-2xl font-bold text-gray-900 dark:text-white">
                  <%= :erlang.float_to_binary(@stats.total_bounty_sol, decimals: 3) %> SOL
                </p>
              </div>
            </div>
          </div>
        </div>

        <!-- Filters -->
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow p-4 mb-6">
          <form phx-change="filter" class="flex flex-wrap gap-4 items-end">
            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Severity</label>
              <select name="severity"
                      class="rounded-lg border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white">
                <option value="">All</option>
                <option value="critical" selected={@filter.severity == "critical"}>Critical</option>
                <option value="high" selected={@filter.severity == "high"}>High</option>
                <option value="medium" selected={@filter.severity == "medium"}>Medium</option>
                <option value="low" selected={@filter.severity == "low"}>Low</option>
              </select>
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Time Range</label>
              <select name="range"
                      class="rounded-lg border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white">
                <option value="24h" selected={@filter.date_range == "24h"}>Last 24h</option>
                <option value="7d" selected={@filter.date_range == "7d"}>Last 7 days</option>
                <option value="30d" selected={@filter.date_range == "30d"}>Last 30 days</option>
                <option value="all" selected={@filter.date_range == "all"}>All time</option>
              </select>
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">MITRE Technique</label>
              <input type="text" name="mitre" value={@filter.mitre_technique}
                     placeholder="e.g., T1555.003"
                     class="rounded-lg border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white w-36"/>
            </div>
          </form>
        </div>

        <!-- Attestations Table -->
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow overflow-hidden">
          <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
            <thead class="bg-gray-50 dark:bg-gray-700">
              <tr>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Severity
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  MITRE Technique
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Threat Class
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
              <%= for attestation <- @attestations do %>
                <tr class="hover:bg-gray-50 dark:hover:bg-gray-700/50 transition">
                  <td class="px-6 py-4">
                    <span class={"px-2.5 py-1 text-xs font-semibold rounded-full #{severity_class(attestation.severity)}"}>
                      <%= String.upcase(attestation.severity || "unknown") %>
                    </span>
                  </td>
                  <td class="px-6 py-4 text-sm text-gray-900 dark:text-white font-mono">
                    <%= List.first(attestation.mitre_techniques || []) || "N/A" %>
                  </td>
                  <td class="px-6 py-4 text-sm text-gray-600 dark:text-gray-300">
                    <%= get_threat_class(attestation) %>
                  </td>
                  <td class="px-6 py-4 text-sm text-gray-500 dark:text-gray-400">
                    <%= format_datetime(attestation.blockchain_attested_at) %>
                  </td>
                  <td class="px-6 py-4">
                    <%= if attestation.bounty_tx_id do %>
                      <div class="flex items-center text-green-600">
                        <svg class="w-4 h-4 mr-1" fill="currentColor" viewBox="0 0 20 20">
                          <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
                        </svg>
                        <span class="text-sm font-medium"><%= format_bounty(attestation.bounty_amount_lamports) %></span>
                      </div>
                    <% else %>
                      <span class="text-gray-400">-</span>
                    <% end %>
                  </td>
                  <td class="px-6 py-4">
                    <div class="flex space-x-2">
                      <.link navigate={~p"/public/attestations/#{attestation.blockchain_tx_id}"}
                             class="inline-flex items-center px-2.5 py-1.5 text-sm text-purple-600 hover:text-purple-800 dark:hover:text-purple-400">
                        Details
                      </.link>
                      <a href={Client.solscan_url(attestation.blockchain_tx_id)}
                         target="_blank"
                         class="inline-flex items-center px-2.5 py-1.5 text-sm border border-purple-600 text-purple-600 rounded hover:bg-purple-50 dark:hover:bg-purple-900/30">
                        <svg class="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/>
                        </svg>
                        Solscan
                      </a>
                    </div>
                  </td>
                </tr>
              <% end %>

              <%= if Enum.empty?(@attestations) do %>
                <tr>
                  <td colspan="6" class="px-6 py-12 text-center">
                    <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                            d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
                    </svg>
                    <p class="mt-2 text-sm text-gray-500 dark:text-gray-400">No attestations found</p>
                    <p class="mt-1 text-xs text-gray-400">Try adjusting your filters or check back later</p>
                  </td>
                </tr>
              <% end %>
            </tbody>
          </table>
        </div>

        <!-- Privacy Explainer -->
        <div class="mt-8 bg-purple-50 dark:bg-purple-900/20 border border-purple-200 dark:border-purple-800 rounded-xl p-6">
          <h3 class="text-lg font-semibold text-purple-800 dark:text-purple-200 mb-3 flex items-center">
            <svg class="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
              <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"/>
            </svg>
            Private Telemetry, Public Proof
          </h3>
          <div class="text-sm text-purple-700 dark:text-purple-300 space-y-2">
            <p>
              <strong>What IS on-chain:</strong> Cryptographic hashes (incident_hash, manifest_hash, rule_hash),
              severity level, MITRE technique IDs, IOC counts (not values), timestamps, and pseudonymized identifiers.
            </p>
            <p>
              <strong>What is NEVER on-chain:</strong> Hostnames, usernames, file paths, command lines,
              internal IP addresses, actual IOC values, or any personally identifiable information (PII).
            </p>
            <p class="text-xs text-purple-600 dark:text-purple-400">
              Each attestation can be independently verified on Solana Devnet via Solscan.
            </p>
          </div>
        </div>
      </main>

      <!-- Footer -->
      <footer class="bg-white dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700 mt-12">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div class="flex items-center justify-between">
            <p class="text-sm text-gray-500 dark:text-gray-400">
              Tamandua EDR - Private endpoint detection, public threat proof
            </p>
            <a href="https://github.com/treant-lab" target="_blank"
               class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">
              <svg class="w-6 h-6" fill="currentColor" viewBox="0 0 24 24">
                <path fill-rule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clip-rule="evenodd"/>
              </svg>
            </a>
          </div>
        </div>
      </footer>
    </div>
    """
  end

  # Helpers

  defp severity_class("critical"), do: "bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-200"
  defp severity_class("high"), do: "bg-orange-100 text-orange-800 dark:bg-orange-900/50 dark:text-orange-200"
  defp severity_class("medium"), do: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/50 dark:text-yellow-200"
  defp severity_class("low"), do: "bg-blue-100 text-blue-800 dark:bg-blue-900/50 dark:text-blue-200"
  defp severity_class(_), do: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200"

  defp get_threat_class(%{detection_metadata: metadata}) when is_map(metadata) do
    metadata[:threat_class] || metadata["threat_class"] || "endpoint_threat"
  end
  defp get_threat_class(_), do: "endpoint_threat"

  defp format_datetime(nil), do: "N/A"
  defp format_datetime(dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M UTC")

  defp format_bounty(nil), do: "0 SOL"
  defp format_bounty(lamports), do: "#{:erlang.float_to_binary(lamports / 1_000_000_000, decimals: 2)} SOL"

  defp empty_to_nil(""), do: nil
  defp empty_to_nil(value), do: value
end
