defmodule TamanduaServerWeb.PublicAttestationDetailLive do
  @moduledoc """
  Public page for viewing a single blockchain attestation in detail.

  **No authentication required** - this is a public audit page.

  Shows:
  - Full attestation metadata (hashes, timestamps)
  - Verification instructions
  - Solscan link for on-chain verification
  - Privacy guarantees explanation
  """

  use TamanduaServerWeb, :live_view
  # Use public layout (no sidebar) for this unauthenticated page
  use Phoenix.LiveView, layout: {TamanduaServerWeb.Layouts, :public}

  alias TamanduaServer.Alerts
  alias TamanduaServer.Solana.Client

  @impl true
  def mount(%{"tx_id" => tx_id}, _session, socket) do
    case Alerts.get_public_attestation_by_tx(tx_id) do
      nil ->
        socket =
          socket
          |> assign(:page_title, "Attestation Not Found")
          |> assign(:attestation, nil)
          |> assign(:tx_id, tx_id)

        {:ok, socket}

      attestation ->
        socket =
          socket
          |> assign(:page_title, "Attestation Details")
          |> assign(:attestation, attestation)
          |> assign(:tx_id, tx_id)
          |> assign(:solscan_url, Client.solscan_url(tx_id))

        {:ok, socket}
    end
  end

  @impl true
  def render(%{attestation: nil} = assigns) do
    ~H"""
    <div class="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center">
      <div class="text-center">
        <svg class="mx-auto h-16 w-16 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                d="M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
        </svg>
        <h2 class="mt-4 text-xl font-semibold text-gray-900 dark:text-white">Attestation Not Found</h2>
        <p class="mt-2 text-gray-500 dark:text-gray-400">
          No attestation found for transaction ID:<br/>
          <code class="text-sm font-mono"><%= @tx_id %></code>
        </p>
        <div class="mt-6">
          <.link navigate={~p"/public/attestations"}
                 class="inline-flex items-center px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition">
            <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/>
            </svg>
            Back to Attestations
          </.link>
        </div>
      </div>
    </div>
    """
  end

  def render(assigns) do
    ~H"""
    <div class="min-h-screen bg-gray-50 dark:bg-gray-900">
      <!-- Header -->
      <header class="bg-white dark:bg-gray-800 shadow">
        <div class="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div class="flex items-center justify-between">
            <div>
              <.link navigate={~p"/public/attestations"}
                     class="text-sm text-purple-600 hover:text-purple-800 dark:text-purple-400 flex items-center mb-2">
                <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/>
                </svg>
                Back to Attestations
              </.link>
              <h1 class="text-2xl font-bold text-gray-900 dark:text-white">
                Attestation Details
              </h1>
            </div>
            <a href={@solscan_url} target="_blank"
               class="inline-flex items-center px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition">
              <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                      d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/>
              </svg>
              Verify on Solscan
            </a>
          </div>
        </div>
      </header>

      <main class="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <!-- Severity Badge -->
        <div class="flex items-center space-x-4 mb-6">
          <span class={"px-4 py-2 text-sm font-semibold rounded-full #{severity_class(@attestation.severity)}"}>
            <%= String.upcase(@attestation.severity || "unknown") %> SEVERITY
          </span>
          <%= if @attestation.bounty_tx_id do %>
            <span class="px-4 py-2 text-sm font-semibold rounded-full bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-200">
              BOUNTY PAID: <%= format_bounty(@attestation.bounty_amount_lamports) %>
            </span>
          <% end %>
        </div>

        <!-- Main Content Grid -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          <!-- Attestation Data -->
          <div class="bg-white dark:bg-gray-800 rounded-xl shadow p-6">
            <h2 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">
              Attestation Data
            </h2>
            <dl class="space-y-4">
              <div>
                <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Transaction ID</dt>
                <dd class="mt-1 text-sm font-mono text-gray-900 dark:text-white break-all">
                  <%= @attestation.blockchain_tx_id %>
                </dd>
              </div>

              <div>
                <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Attested At</dt>
                <dd class="mt-1 text-sm text-gray-900 dark:text-white">
                  <%= format_datetime(@attestation.blockchain_attested_at) %>
                </dd>
              </div>

              <div>
                <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">MITRE Technique</dt>
                <dd class="mt-1 text-sm font-mono text-gray-900 dark:text-white">
                  <%= mitre_link(List.first(@attestation.mitre_techniques || [])) %>
                </dd>
              </div>

              <div>
                <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">MITRE Tactic</dt>
                <dd class="mt-1 text-sm text-gray-900 dark:text-white">
                  <%= List.first(@attestation.mitre_tactics || []) || "N/A" %>
                </dd>
              </div>

              <div>
                <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Threat Class</dt>
                <dd class="mt-1 text-sm text-gray-900 dark:text-white">
                  <%= get_threat_class(@attestation) %>
                </dd>
              </div>

              <div>
                <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Detection Source</dt>
                <dd class="mt-1 text-sm text-gray-900 dark:text-white">
                  <%= get_detection_source(@attestation) %>
                </dd>
              </div>

              <div>
                <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Threat Score</dt>
                <dd class="mt-1 text-sm text-gray-900 dark:text-white">
                  <%= if @attestation.threat_score, do: :erlang.float_to_binary(@attestation.threat_score, decimals: 1), else: "N/A" %>
                </dd>
              </div>
            </dl>
          </div>

          <!-- Bounty Information -->
          <div class="bg-white dark:bg-gray-800 rounded-xl shadow p-6">
            <h2 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">
              Bounty Information
            </h2>
            <%= if @attestation.bounty_tx_id do %>
              <dl class="space-y-4">
                <div>
                  <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Bounty Status</dt>
                  <dd class="mt-1 flex items-center text-green-600">
                    <svg class="w-5 h-5 mr-1" fill="currentColor" viewBox="0 0 20 20">
                      <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
                    </svg>
                    PAID
                  </dd>
                </div>

                <div>
                  <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Amount</dt>
                  <dd class="mt-1 text-2xl font-bold text-gray-900 dark:text-white">
                    <%= format_bounty(@attestation.bounty_amount_lamports) %>
                  </dd>
                </div>

                <div>
                  <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Payment Transaction</dt>
                  <dd class="mt-1 text-sm font-mono text-gray-900 dark:text-white break-all">
                    <a href={Client.solscan_url(@attestation.bounty_tx_id)}
                       target="_blank"
                       class="text-purple-600 hover:underline">
                      <%= @attestation.bounty_tx_id %>
                    </a>
                  </dd>
                </div>

                <div>
                  <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Paid At</dt>
                  <dd class="mt-1 text-sm text-gray-900 dark:text-white">
                    <%= format_datetime(@attestation.bounty_paid_at) %>
                  </dd>
                </div>
              </dl>
            <% else %>
              <div class="text-center py-8">
                <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                        d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                </svg>
                <p class="mt-2 text-sm text-gray-500 dark:text-gray-400">
                  No bounty payment for this attestation
                </p>
              </div>
            <% end %>
          </div>
        </div>

        <!-- How to Verify -->
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow p-6 mb-8">
          <h2 class="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center">
            <svg class="w-5 h-5 mr-2 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                    d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
            </svg>
            How to Verify This Attestation
          </h2>
          <ol class="space-y-4 text-sm text-gray-600 dark:text-gray-300">
            <li class="flex">
              <span class="flex-shrink-0 w-6 h-6 bg-purple-100 dark:bg-purple-900/30 text-purple-600 rounded-full flex items-center justify-center text-xs font-bold mr-3">1</span>
              <div>
                <strong class="text-gray-900 dark:text-white">Click the "Verify on Solscan" button</strong>
                <p class="mt-1">This opens the transaction on Solana's block explorer.</p>
              </div>
            </li>
            <li class="flex">
              <span class="flex-shrink-0 w-6 h-6 bg-purple-100 dark:bg-purple-900/30 text-purple-600 rounded-full flex items-center justify-center text-xs font-bold mr-3">2</span>
              <div>
                <strong class="text-gray-900 dark:text-white">View the transaction details</strong>
                <p class="mt-1">Confirm the transaction is finalized on the Solana blockchain.</p>
              </div>
            </li>
            <li class="flex">
              <span class="flex-shrink-0 w-6 h-6 bg-purple-100 dark:bg-purple-900/30 text-purple-600 rounded-full flex items-center justify-center text-xs font-bold mr-3">3</span>
              <div>
                <strong class="text-gray-900 dark:text-white">Check the memo data</strong>
                <p class="mt-1">The transaction memo contains the attestation JSON with incident_hash, severity, MITRE technique, and timestamps.</p>
              </div>
            </li>
            <li class="flex">
              <span class="flex-shrink-0 w-6 h-6 bg-purple-100 dark:bg-purple-900/30 text-purple-600 rounded-full flex items-center justify-center text-xs font-bold mr-3">4</span>
              <div>
                <strong class="text-gray-900 dark:text-white">Verify tamper-evidence</strong>
                <p class="mt-1">Once on-chain, the attestation cannot be modified or deleted. The blockchain provides immutable proof.</p>
              </div>
            </li>
          </ol>
        </div>

        <!-- Privacy Guarantees -->
        <div class="bg-purple-50 dark:bg-purple-900/20 border border-purple-200 dark:border-purple-800 rounded-xl p-6">
          <h3 class="text-lg font-semibold text-purple-800 dark:text-purple-200 mb-4 flex items-center">
            <svg class="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
              <path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clip-rule="evenodd"/>
            </svg>
            Privacy Guarantees
          </h3>
          <div class="grid grid-cols-1 md:grid-cols-2 gap-6 text-sm">
            <div>
              <h4 class="font-semibold text-green-700 dark:text-green-400 mb-2">What IS on-chain:</h4>
              <ul class="space-y-1 text-gray-600 dark:text-gray-300">
                <li class="flex items-center">
                  <svg class="w-4 h-4 mr-2 text-green-500" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
                  </svg>
                  Incident hash (SHA256)
                </li>
                <li class="flex items-center">
                  <svg class="w-4 h-4 mr-2 text-green-500" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
                  </svg>
                  Severity level
                </li>
                <li class="flex items-center">
                  <svg class="w-4 h-4 mr-2 text-green-500" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
                  </svg>
                  MITRE ATT&CK technique
                </li>
                <li class="flex items-center">
                  <svg class="w-4 h-4 mr-2 text-green-500" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
                  </svg>
                  IOC counts (not values)
                </li>
                <li class="flex items-center">
                  <svg class="w-4 h-4 mr-2 text-green-500" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
                  </svg>
                  Pseudonymized identifiers
                </li>
              </ul>
            </div>
            <div>
              <h4 class="font-semibold text-red-700 dark:text-red-400 mb-2">What is NEVER on-chain:</h4>
              <ul class="space-y-1 text-gray-600 dark:text-gray-300">
                <li class="flex items-center">
                  <svg class="w-4 h-4 mr-2 text-red-500" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/>
                  </svg>
                  Hostnames / IP addresses
                </li>
                <li class="flex items-center">
                  <svg class="w-4 h-4 mr-2 text-red-500" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/>
                  </svg>
                  Usernames
                </li>
                <li class="flex items-center">
                  <svg class="w-4 h-4 mr-2 text-red-500" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/>
                  </svg>
                  File paths / command lines
                </li>
                <li class="flex items-center">
                  <svg class="w-4 h-4 mr-2 text-red-500" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/>
                  </svg>
                  Actual IOC values
                </li>
                <li class="flex items-center">
                  <svg class="w-4 h-4 mr-2 text-red-500" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/>
                  </svg>
                  Organization identifiers
                </li>
              </ul>
            </div>
          </div>
        </div>
      </main>
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

  defp get_detection_source(%{detection_metadata: metadata}) when is_map(metadata) do
    metadata[:detection_source] || metadata["detection_source"] || "tamandua"
  end
  defp get_detection_source(_), do: "tamandua"

  defp format_datetime(nil), do: "N/A"
  defp format_datetime(dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S UTC")

  defp format_bounty(nil), do: "0 SOL"
  defp format_bounty(lamports), do: "#{:erlang.float_to_binary(lamports / 1_000_000_000, decimals: 4)} SOL"

  defp mitre_link(nil), do: "N/A"
  defp mitre_link(technique) do
    assigns = %{technique: technique}
    ~H"""
    <a href={"https://attack.mitre.org/techniques/#{String.replace(@technique, ".", "/")}/"}
       target="_blank"
       class="text-purple-600 hover:underline">
      <%= @technique %>
    </a>
    """
  end
end
