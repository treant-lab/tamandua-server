defmodule TamanduaServerWeb.PublicProofsLive do
  @moduledoc """
  Public Security Oracle demo page for Tamandua EDR hackathon.

  **No authentication required** - this is a public demonstration page.

  Showcases the three types of on-chain proofs:
  1. Proof of Incident - Attested security incidents
  2. Proof of Health - Fleet health attestations
  3. Proof of Remediation - Response action attestations

  Tells the "Private security, public proofs" story for:
  - Treasury auditors
  - Insurance providers
  - Compliance teams
  - Security researchers
  """

  use TamanduaServerWeb, :live_view
  # Use public layout (no sidebar) for this unauthenticated page
  use Phoenix.LiveView, layout: {TamanduaServerWeb.Layouts, :public}

  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts
  alias TamanduaServer.Solana.Client
  alias TamanduaServer.Solana.HealthAttestation
  import Ecto.Query

  @impl true
  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(:page_title, "Security Oracle - Public Proofs")
      |> assign(:active_tab, "incident")
      |> assign(:incident_proofs, [])
      |> assign(:health_proofs, [])
      |> assign(:remediation_proofs, [])
      |> assign(:stats, %{
        total_incidents: 0,
        total_health: 0,
        total_remediations: 0,
        total_bounties_sol: 0.0
      })
      |> load_all_data()

    {:ok, socket}
  end

  @impl true
  def handle_params(params, _uri, socket) do
    tab = params["tab"] || "incident"
    {:noreply, assign(socket, :active_tab, tab)}
  end

  @impl true
  def handle_event("switch_tab", %{"tab" => tab}, socket) do
    {:noreply, push_patch(socket, to: ~p"/public/proofs?tab=#{tab}")}
  end

  defp load_all_data(socket) do
    # Load incident proofs (from alerts with blockchain_tx_id)
    incident_proofs = load_incident_proofs()

    # Load health proofs (from health_attestations table)
    health_proofs = load_health_proofs()

    # Load remediation proofs (alerts with remediation_tx_id or from detection_metadata)
    remediation_proofs = load_remediation_proofs()

    # Calculate stats
    stats = %{
      total_incidents: length(incident_proofs),
      total_health: length(health_proofs),
      total_remediations: length(remediation_proofs),
      total_bounties_sol: Alerts.public_attestation_stats().total_bounty_sol
    }

    socket
    |> assign(:incident_proofs, incident_proofs)
    |> assign(:health_proofs, health_proofs)
    |> assign(:remediation_proofs, remediation_proofs)
    |> assign(:stats, stats)
  end

  defp load_incident_proofs do
    Alerts.list_public_attestations(limit: 20, date_range: "all")
  end

  defp load_health_proofs do
    try do
      HealthAttestation
      |> where([h], not is_nil(h.solana_signature))
      |> order_by([h], [desc: h.attested_at])
      |> limit(20)
      |> select([h], %{
        id: h.id,
        agent_pseudonym: h.agent_pseudonym,
        window_hours: h.window_hours,
        critical_alerts: h.critical_alerts,
        high_alerts: h.high_alerts,
        medium_alerts: h.medium_alerts,
        low_alerts: h.low_alerts,
        policy_profile: h.policy_profile,
        solana_signature: h.solana_signature,
        attested_at: h.attested_at
      })
      |> Repo.all()
    rescue
      _ -> []
    end
  end

  defp load_remediation_proofs do
    # For now, extract remediation proofs from alerts that have remediation metadata
    # In production, this would query a dedicated remediation_attestations table
    try do
      TamanduaServer.Alerts.Alert
      |> where([a], not is_nil(a.blockchain_tx_id))
      |> where([a], a.status == "resolved")
      |> where([a], not is_nil(a.resolved_at))
      |> order_by([a], [desc: a.resolved_at])
      |> limit(20)
      |> select([a], %{
        id: a.id,
        severity: a.severity,
        mitre_techniques: a.mitre_techniques,
        blockchain_tx_id: a.blockchain_tx_id,
        resolved_at: a.resolved_at,
        detection_metadata: a.detection_metadata
      })
      |> Repo.all()
    rescue
      _ -> []
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="min-h-screen bg-gradient-to-br from-gray-900 via-purple-900 to-gray-900">
      <!-- Hero Header -->
      <header class="relative overflow-hidden">
        <!-- Background decoration -->
        <div class="absolute inset-0 overflow-hidden">
          <div class="absolute -top-40 -right-40 w-80 h-80 bg-purple-500/20 rounded-full blur-3xl"></div>
          <div class="absolute -bottom-40 -left-40 w-80 h-80 bg-indigo-500/20 rounded-full blur-3xl"></div>
        </div>

        <div class="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
          <div class="text-center">
            <!-- Logo -->
            <div class="flex justify-center mb-6">
              <div class="p-4 bg-purple-500/20 rounded-2xl backdrop-blur-sm border border-purple-500/30">
                <svg class="w-16 h-16 text-purple-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                  <path d="M12 2L2 7l10 5 10-5-10-5z"/>
                  <path d="M2 17l10 5 10-5"/>
                  <path d="M2 12l10 5 10-5"/>
                </svg>
              </div>
            </div>

            <h1 class="text-4xl md:text-6xl font-bold text-white mb-4">
              Security <span class="text-transparent bg-clip-text bg-gradient-to-r from-purple-400 to-pink-400">Oracle</span>
            </h1>

            <p class="text-xl md:text-2xl text-purple-200 mb-2">
              Private Security, Public Proofs
            </p>

            <p class="text-gray-400 max-w-2xl mx-auto mb-8">
              Tamandua EDR creates tamper-evident attestations on the Solana blockchain.
              Your security data stays private. Your proof stays public.
            </p>

            <!-- Quick Stats -->
            <div class="grid grid-cols-2 md:grid-cols-4 gap-4 max-w-4xl mx-auto">
              <div class="bg-white/5 backdrop-blur-sm rounded-xl p-4 border border-white/10">
                <div class="text-3xl font-bold text-white"><%= @stats.total_incidents %></div>
                <div class="text-sm text-purple-300">Incident Proofs</div>
              </div>
              <div class="bg-white/5 backdrop-blur-sm rounded-xl p-4 border border-white/10">
                <div class="text-3xl font-bold text-white"><%= @stats.total_health %></div>
                <div class="text-sm text-green-300">Health Proofs</div>
              </div>
              <div class="bg-white/5 backdrop-blur-sm rounded-xl p-4 border border-white/10">
                <div class="text-3xl font-bold text-white"><%= @stats.total_remediations %></div>
                <div class="text-sm text-blue-300">Remediation Proofs</div>
              </div>
              <div class="bg-white/5 backdrop-blur-sm rounded-xl p-4 border border-white/10">
                <div class="text-3xl font-bold text-white">
                  <%= :erlang.float_to_binary(@stats.total_bounties_sol, decimals: 2) %>
                </div>
                <div class="text-sm text-yellow-300">SOL in Bounties</div>
              </div>
            </div>
          </div>
        </div>
      </header>

      <!-- Value Proposition Cards -->
      <section class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
          <!-- For Treasuries -->
          <div class="bg-white/5 backdrop-blur-sm rounded-2xl p-6 border border-white/10 hover:border-purple-500/50 transition">
            <div class="w-12 h-12 bg-purple-500/20 rounded-xl flex items-center justify-center mb-4">
              <svg class="w-6 h-6 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"/>
              </svg>
            </div>
            <h3 class="text-xl font-semibold text-white mb-2">For Treasuries</h3>
            <p class="text-gray-400">
              Prove to stakeholders that your treasury infrastructure is monitored.
              Immutable evidence of security posture without exposing internal systems.
            </p>
          </div>

          <!-- For Auditors -->
          <div class="bg-white/5 backdrop-blur-sm rounded-2xl p-6 border border-white/10 hover:border-green-500/50 transition">
            <div class="w-12 h-12 bg-green-500/20 rounded-xl flex items-center justify-center mb-4">
              <svg class="w-6 h-6 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
              </svg>
            </div>
            <h3 class="text-xl font-semibold text-white mb-2">For Auditors</h3>
            <p class="text-gray-400">
              Verify security claims independently. Each attestation links to Solana Explorer
              for cryptographic verification. No trust required, just math.
            </p>
          </div>

          <!-- For Insurance -->
          <div class="bg-white/5 backdrop-blur-sm rounded-2xl p-6 border border-white/10 hover:border-blue-500/50 transition">
            <div class="w-12 h-12 bg-blue-500/20 rounded-xl flex items-center justify-center mb-4">
              <svg class="w-6 h-6 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
              </svg>
            </div>
            <h3 class="text-xl font-semibold text-white mb-2">For Insurance</h3>
            <p class="text-gray-400">
              Timestamped proof of incident detection and remediation.
              Build cyber insurance products with verifiable security histories.
            </p>
          </div>
        </div>
      </section>

      <!-- Proof Types Tabs -->
      <section class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div class="bg-white/5 backdrop-blur-sm rounded-2xl border border-white/10 overflow-hidden">
          <!-- Tab Headers -->
          <div class="flex border-b border-white/10">
            <button
              phx-click="switch_tab"
              phx-value-tab="incident"
              class={"flex-1 px-6 py-4 text-center font-medium transition #{if @active_tab == "incident", do: "bg-purple-500/20 text-purple-300 border-b-2 border-purple-500", else: "text-gray-400 hover:text-white hover:bg-white/5"}"}
            >
              <svg class="w-5 h-5 inline-block mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
              </svg>
              Proof of Incident
            </button>
            <button
              phx-click="switch_tab"
              phx-value-tab="health"
              class={"flex-1 px-6 py-4 text-center font-medium transition #{if @active_tab == "health", do: "bg-green-500/20 text-green-300 border-b-2 border-green-500", else: "text-gray-400 hover:text-white hover:bg-white/5"}"}
            >
              <svg class="w-5 h-5 inline-block mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
              </svg>
              Proof of Health
            </button>
            <button
              phx-click="switch_tab"
              phx-value-tab="remediation"
              class={"flex-1 px-6 py-4 text-center font-medium transition #{if @active_tab == "remediation", do: "bg-blue-500/20 text-blue-300 border-b-2 border-blue-500", else: "text-gray-400 hover:text-white hover:bg-white/5"}"}
            >
              <svg class="w-5 h-5 inline-block mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
              </svg>
              Proof of Remediation
            </button>
          </div>

          <!-- Tab Content -->
          <div class="p-6">
            <%= case @active_tab do %>
              <% "incident" -> %>
                <.incident_tab proofs={@incident_proofs} />
              <% "health" -> %>
                <.health_tab proofs={@health_proofs} />
              <% "remediation" -> %>
                <.remediation_tab proofs={@remediation_proofs} />
              <% _ -> %>
                <.incident_tab proofs={@incident_proofs} />
            <% end %>
          </div>
        </div>
      </section>

      <!-- How It Works -->
      <section class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <h2 class="text-2xl font-bold text-white text-center mb-8">How Security Oracle Works</h2>

        <div class="grid grid-cols-1 md:grid-cols-4 gap-6">
          <div class="text-center">
            <div class="w-16 h-16 bg-purple-500/20 rounded-full flex items-center justify-center mx-auto mb-4 border-2 border-purple-500/50">
              <span class="text-2xl font-bold text-purple-400">1</span>
            </div>
            <h3 class="text-lg font-semibold text-white mb-2">Detect</h3>
            <p class="text-sm text-gray-400">Tamandua agents detect security events on endpoints in real-time</p>
          </div>

          <div class="text-center">
            <div class="w-16 h-16 bg-purple-500/20 rounded-full flex items-center justify-center mx-auto mb-4 border-2 border-purple-500/50">
              <span class="text-2xl font-bold text-purple-400">2</span>
            </div>
            <h3 class="text-lg font-semibold text-white mb-2">Redact</h3>
            <p class="text-sm text-gray-400">Sensitive data (hostnames, paths, IPs) is stripped. Only hashes remain</p>
          </div>

          <div class="text-center">
            <div class="w-16 h-16 bg-purple-500/20 rounded-full flex items-center justify-center mx-auto mb-4 border-2 border-purple-500/50">
              <span class="text-2xl font-bold text-purple-400">3</span>
            </div>
            <h3 class="text-lg font-semibold text-white mb-2">Attest</h3>
            <p class="text-sm text-gray-400">Privacy-safe proofs are written to Solana via Memo transactions</p>
          </div>

          <div class="text-center">
            <div class="w-16 h-16 bg-purple-500/20 rounded-full flex items-center justify-center mx-auto mb-4 border-2 border-purple-500/50">
              <span class="text-2xl font-bold text-purple-400">4</span>
            </div>
            <h3 class="text-lg font-semibold text-white mb-2">Verify</h3>
            <p class="text-sm text-gray-400">Anyone can verify attestations on Solana Explorer. No trust required</p>
          </div>
        </div>
      </section>

      <!-- Privacy Explainer -->
      <section class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div class="bg-gradient-to-r from-purple-500/10 to-pink-500/10 rounded-2xl p-8 border border-purple-500/20">
          <div class="flex items-start space-x-4">
            <div class="flex-shrink-0">
              <svg class="w-8 h-8 text-purple-400" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clip-rule="evenodd"/>
              </svg>
            </div>
            <div>
              <h3 class="text-xl font-semibold text-white mb-4">Privacy by Design</h3>
              <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
                <div>
                  <h4 class="font-medium text-green-400 mb-2">What IS on-chain:</h4>
                  <ul class="space-y-1 text-sm text-gray-300">
                    <li class="flex items-center">
                      <svg class="w-4 h-4 mr-2 text-green-500" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
                      </svg>
                      Cryptographic hashes (incident, manifest, rule)
                    </li>
                    <li class="flex items-center">
                      <svg class="w-4 h-4 mr-2 text-green-500" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
                      </svg>
                      Severity levels and MITRE technique IDs
                    </li>
                    <li class="flex items-center">
                      <svg class="w-4 h-4 mr-2 text-green-500" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
                      </svg>
                      IOC counts (not values) and timestamps
                    </li>
                    <li class="flex items-center">
                      <svg class="w-4 h-4 mr-2 text-green-500" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
                      </svg>
                      Pseudonymized org/agent identifiers (SHA256)
                    </li>
                  </ul>
                </div>
                <div>
                  <h4 class="font-medium text-red-400 mb-2">What is NEVER on-chain:</h4>
                  <ul class="space-y-1 text-sm text-gray-300">
                    <li class="flex items-center">
                      <svg class="w-4 h-4 mr-2 text-red-500" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/>
                      </svg>
                      Hostnames, usernames, or employee names
                    </li>
                    <li class="flex items-center">
                      <svg class="w-4 h-4 mr-2 text-red-500" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/>
                      </svg>
                      File paths, command lines, or process names
                    </li>
                    <li class="flex items-center">
                      <svg class="w-4 h-4 mr-2 text-red-500" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/>
                      </svg>
                      Internal IP addresses or private domains
                    </li>
                    <li class="flex items-center">
                      <svg class="w-4 h-4 mr-2 text-red-500" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/>
                      </svg>
                      Organization names or customer data
                    </li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <!-- Footer -->
      <footer class="border-t border-white/10 mt-12">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div class="flex flex-col md:flex-row items-center justify-between space-y-4 md:space-y-0">
            <div class="flex items-center space-x-2">
              <svg class="w-6 h-6 text-purple-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M12 2L2 7l10 5 10-5-10-5z"/>
                <path d="M2 17l10 5 10-5"/>
                <path d="M2 12l10 5 10-5"/>
              </svg>
              <span class="text-gray-400">Tamandua EDR - Security Oracle</span>
            </div>
            <div class="flex items-center space-x-6">
              <.link navigate={~p"/public/attestations"} class="text-gray-400 hover:text-white transition">
                Full Attestations List
              </.link>
              <a href="https://solscan.io" target="_blank" class="text-gray-400 hover:text-white transition flex items-center">
                <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/>
                </svg>
                Solscan
              </a>
            </div>
          </div>
          <div class="mt-6 text-center text-sm text-gray-500">
            All attestations are recorded on Solana Devnet. Verify independently.
          </div>
        </div>
      </footer>
    </div>
    """
  end

  # Component: Incident Tab
  defp incident_tab(assigns) do
    ~H"""
    <div>
      <div class="mb-6">
        <h3 class="text-lg font-semibold text-white mb-2">Proof of Incident</h3>
        <p class="text-gray-400 text-sm">
          Tamper-evident proof that a security incident was detected. Each attestation includes
          severity, MITRE ATT&CK mapping, and a cryptographic hash of the incident details.
          The actual incident data remains private.
        </p>
      </div>

      <%= if Enum.empty?(@proofs) do %>
        <.empty_state type="incident" />
      <% else %>
        <div class="space-y-4">
          <%= for proof <- @proofs do %>
            <div class="bg-white/5 rounded-xl p-4 border border-white/10 hover:border-purple-500/30 transition">
              <div class="flex items-center justify-between">
                <div class="flex items-center space-x-4">
                  <span class={"px-2.5 py-1 text-xs font-semibold rounded-full #{severity_class(proof.severity)}"}>
                    <%= String.upcase(proof.severity || "unknown") %>
                  </span>
                  <span class="text-sm font-mono text-purple-300">
                    <%= List.first(proof.mitre_techniques || []) || "N/A" %>
                  </span>
                  <span class="text-sm text-gray-400">
                    <%= format_datetime(proof.blockchain_attested_at) %>
                  </span>
                </div>
                <div class="flex items-center space-x-3">
                  <%= if proof.bounty_amount_lamports && proof.bounty_amount_lamports > 0 do %>
                    <span class="text-sm text-green-400 flex items-center">
                      <svg class="w-4 h-4 mr-1" fill="currentColor" viewBox="0 0 20 20">
                        <path d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"/>
                      </svg>
                      <%= format_bounty(proof.bounty_amount_lamports) %>
                    </span>
                  <% end %>
                  <a href={Client.solscan_url(proof.blockchain_tx_id)}
                     target="_blank"
                     class="inline-flex items-center px-3 py-1.5 text-sm border border-purple-500/50 text-purple-400 rounded-lg hover:bg-purple-500/20 transition">
                    <svg class="w-3.5 h-3.5 mr-1.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/>
                    </svg>
                    Verify
                  </a>
                </div>
              </div>
              <div class="mt-3 text-xs font-mono text-gray-500 truncate">
                TX: <%= proof.blockchain_tx_id %>
              </div>
            </div>
          <% end %>
        </div>
      <% end %>
    </div>
    """
  end

  # Component: Health Tab
  defp health_tab(assigns) do
    ~H"""
    <div>
      <div class="mb-6">
        <h3 class="text-lg font-semibold text-white mb-2">Proof of Health</h3>
        <p class="text-gray-400 text-sm">
          Attestations that endpoints were actively monitored for a time window. Shows aggregate
          alert counts by severity without exposing what endpoints were monitored or what was detected.
          Perfect for proving security monitoring to auditors.
        </p>
      </div>

      <%= if Enum.empty?(@proofs) do %>
        <.empty_state type="health" />
      <% else %>
        <div class="space-y-4">
          <%= for proof <- @proofs do %>
            <div class="bg-white/5 rounded-xl p-4 border border-white/10 hover:border-green-500/30 transition">
              <div class="flex items-center justify-between">
                <div class="flex items-center space-x-4">
                  <div class="flex items-center space-x-2">
                    <.health_status_badge critical={proof.critical_alerts} high={proof.high_alerts} />
                    <span class="text-sm text-gray-400">
                      <%= proof.window_hours %>h window
                    </span>
                  </div>
                  <div class="flex items-center space-x-2 text-xs">
                    <%= if proof.critical_alerts > 0 do %>
                      <span class="px-2 py-0.5 bg-red-500/20 text-red-300 rounded">
                        <%= proof.critical_alerts %> critical
                      </span>
                    <% end %>
                    <%= if proof.high_alerts > 0 do %>
                      <span class="px-2 py-0.5 bg-orange-500/20 text-orange-300 rounded">
                        <%= proof.high_alerts %> high
                      </span>
                    <% end %>
                    <%= if proof.critical_alerts == 0 && proof.high_alerts == 0 do %>
                      <span class="px-2 py-0.5 bg-green-500/20 text-green-300 rounded">
                        No critical/high alerts
                      </span>
                    <% end %>
                  </div>
                </div>
                <div class="flex items-center space-x-3">
                  <span class="text-xs text-gray-500">
                    <%= format_datetime(proof.attested_at) %>
                  </span>
                  <a href={Client.solscan_url(proof.solana_signature)}
                     target="_blank"
                     class="inline-flex items-center px-3 py-1.5 text-sm border border-green-500/50 text-green-400 rounded-lg hover:bg-green-500/20 transition">
                    <svg class="w-3.5 h-3.5 mr-1.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/>
                    </svg>
                    Verify
                  </a>
                </div>
              </div>
              <div class="mt-3 flex items-center justify-between text-xs">
                <span class="font-mono text-gray-500">Agent: <%= String.slice(proof.agent_pseudonym || "", 0, 12) %>...</span>
                <span class="text-gray-500">Policy: <%= proof.policy_profile %></span>
              </div>
            </div>
          <% end %>
        </div>
      <% end %>
    </div>
    """
  end

  # Component: Remediation Tab
  defp remediation_tab(assigns) do
    ~H"""
    <div>
      <div class="mb-6">
        <h3 class="text-lg font-semibold text-white mb-2">Proof of Remediation</h3>
        <p class="text-gray-400 text-sm">
          Evidence that response actions were taken after incident detection. Links to the original
          incident attestation, proving the complete detection-to-remediation cycle. Essential for
          demonstrating active security response to insurance providers.
        </p>
      </div>

      <%= if Enum.empty?(@proofs) do %>
        <.empty_state type="remediation" />
      <% else %>
        <div class="space-y-4">
          <%= for proof <- @proofs do %>
            <div class="bg-white/5 rounded-xl p-4 border border-white/10 hover:border-blue-500/30 transition">
              <div class="flex items-center justify-between">
                <div class="flex items-center space-x-4">
                  <span class="px-2.5 py-1 text-xs font-semibold rounded-full bg-blue-500/20 text-blue-300 border border-blue-500/30">
                    RESOLVED
                  </span>
                  <span class={"px-2 py-0.5 text-xs rounded #{severity_class(proof.severity)}"}>
                    <%= String.upcase(proof.severity || "unknown") %>
                  </span>
                  <span class="text-sm font-mono text-blue-300">
                    <%= List.first(proof.mitre_techniques || []) || "N/A" %>
                  </span>
                </div>
                <div class="flex items-center space-x-3">
                  <span class="text-xs text-gray-500">
                    <%= format_datetime(proof.resolved_at) %>
                  </span>
                  <a href={Client.solscan_url(proof.blockchain_tx_id)}
                     target="_blank"
                     class="inline-flex items-center px-3 py-1.5 text-sm border border-blue-500/50 text-blue-400 rounded-lg hover:bg-blue-500/20 transition">
                    <svg class="w-3.5 h-3.5 mr-1.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/>
                    </svg>
                    Verify
                  </a>
                </div>
              </div>
              <div class="mt-3 text-xs font-mono text-gray-500 truncate">
                Incident TX: <%= proof.blockchain_tx_id %>
              </div>
            </div>
          <% end %>
        </div>
      <% end %>
    </div>
    """
  end

  # Component: Health Status Badge
  defp health_status_badge(assigns) do
    ~H"""
    <span class={[
      "px-2.5 py-1 text-xs font-semibold rounded-full",
      cond do
        @critical > 0 -> "bg-red-500/20 text-red-300 border border-red-500/30"
        @high > 0 -> "bg-orange-500/20 text-orange-300 border border-orange-500/30"
        true -> "bg-green-500/20 text-green-300 border border-green-500/30"
      end
    ]}>
      <%= cond do %>
        <% @critical > 0 -> %>CRITICAL
        <% @high > 0 -> %>AT RISK
        <% true -> %>MONITORED
      <% end %>
    </span>
    """
  end

  # Component: Empty State
  defp empty_state(assigns) do
    ~H"""
    <div class="text-center py-12">
      <div class="w-16 h-16 mx-auto mb-4 rounded-full bg-white/5 flex items-center justify-center">
        <%= case @type do %>
          <% "incident" -> %>
            <svg class="w-8 h-8 text-purple-400/50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
            </svg>
          <% "health" -> %>
            <svg class="w-8 h-8 text-green-400/50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
            </svg>
          <% "remediation" -> %>
            <svg class="w-8 h-8 text-blue-400/50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
            </svg>
          <% _ -> %>
            <svg class="w-8 h-8 text-gray-400/50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
            </svg>
        <% end %>
      </div>
      <p class="text-gray-400 mb-2">No <%= @type %> proofs yet</p>
      <p class="text-sm text-gray-500">
        <%= case @type do %>
          <% "incident" -> %>
            When incidents are detected, they'll be attested here.
          <% "health" -> %>
            Health attestations will appear as agents report their status.
          <% "remediation" -> %>
            Remediation proofs will show when response actions are taken.
          <% _ -> %>
            Check back later for new attestations.
        <% end %>
      </p>
    </div>
    """
  end

  # Helpers

  defp severity_class("critical"), do: "bg-red-500/20 text-red-300 border border-red-500/30"
  defp severity_class("high"), do: "bg-orange-500/20 text-orange-300 border border-orange-500/30"
  defp severity_class("medium"), do: "bg-yellow-500/20 text-yellow-300 border border-yellow-500/30"
  defp severity_class("low"), do: "bg-blue-500/20 text-blue-300 border border-blue-500/30"
  defp severity_class(_), do: "bg-gray-500/20 text-gray-300 border border-gray-500/30"

  defp format_datetime(nil), do: "N/A"
  defp format_datetime(dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M UTC")

  defp format_bounty(nil), do: "0 SOL"
  defp format_bounty(lamports) when is_integer(lamports) do
    "#{:erlang.float_to_binary(lamports / 1_000_000_000, decimals: 3)} SOL"
  end
  defp format_bounty(_), do: "0 SOL"
end
