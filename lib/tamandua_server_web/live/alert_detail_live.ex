defmodule TamanduaServerWeb.AlertDetailLive do
  @moduledoc """
  LiveView for displaying alert details with embedded remediation actions.

  Features:
  - Full alert information display
  - Detection type, MITRE techniques, and evidence
  - Embedded remediation actions component
  - Remediation history showing previous actions taken
  - Real-time updates via PubSub
  """
  use TamanduaServerWeb, :live_view

  alias TamanduaServer.Alerts
  alias TamanduaServer.Response
  alias Phoenix.PubSub

  @impl true
  def mount(%{"id" => alert_id}, session, socket) do
    organization_id = session["organization_id"] || get_default_org_id()

    if connected?(socket) do
      # Subscribe to alert updates
      PubSub.subscribe(TamanduaServer.PubSub, "alert:#{alert_id}")
    end

    # Use tenant-scoped lookup to prevent BOLA/IDOR
    case Alerts.get_alert_with_evidence_for_org(organization_id, alert_id) do
      {:ok, alert} ->
        actions = Response.list_actions(%{alert_id: alert_id, organization_id: organization_id})

        {:ok,
         socket
         |> assign(:organization_id, organization_id)
         |> assign(:page_title, "Alert Details")
         |> assign(:alert, alert)
         |> assign(:alert_id, alert_id)
         |> assign(:actions, actions)
         |> assign(:show_evidence_details, false)
         |> assign(:show_verdict_modal, false)
         |> assign(:pending_verdict, nil)
         |> assign(:verdict_notes, "")
         |> assign(:create_suppression_rule, true)
         |> assign(:suppression_ttl_days, 30)}

      {:error, :not_found} ->
        {:ok,
         socket
         |> put_flash(:error, "Alert not found")
         |> redirect(to: ~p"/alerts")}
    end
  end

  defp get_default_org_id, do: nil

  @impl true
  def handle_params(_params, _url, socket) do
    {:noreply, socket}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="p-6 max-w-7xl mx-auto">
      <!-- Header -->
      <div class="flex items-center justify-between mb-6">
        <div class="flex items-center gap-4">
          <.link navigate={~p"/alerts"} class="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white">
            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7" />
            </svg>
          </.link>
          <h1 class="text-2xl font-bold text-gray-900 dark:text-white">Alert Details</h1>
        </div>

        <div class="flex gap-2">
          <span class={"px-3 py-1 text-sm font-semibold rounded-full #{severity_badge_color(@alert.severity)}"}>
            <%= String.upcase(@alert.severity) %>
          </span>
          <span class={"px-3 py-1 text-sm font-semibold rounded-full #{status_badge_color(@alert.status)}"}>
            <%= format_status(@alert.status) %>
          </span>
          <%= if @alert.verdict && @alert.verdict != "unconfirmed" do %>
            <span
              class={"px-3 py-1 text-sm font-semibold rounded-full #{verdict_badge_color(@alert.verdict)}"}
              title="Analyst verdict (set via Mark as ... buttons below)"
            >
              <%= format_verdict(@alert.verdict) %>
            </span>
          <% end %>
        </div>
      </div>

      <%= if severity_adjusted?(@alert) do %>
        <div class="mb-6 rounded-lg border border-amber-300 dark:border-amber-700 bg-amber-50 dark:bg-amber-900/20 p-4">
          <div class="flex items-start gap-3">
            <svg class="w-5 h-5 text-amber-600 dark:text-amber-400 mt-0.5 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
              <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/>
            </svg>
            <div class="flex-1">
              <h3 class="text-sm font-semibold text-amber-800 dark:text-amber-200">
                Severity auto-adjusted — likely false positive
              </h3>
              <p class="mt-1 text-sm text-amber-700 dark:text-amber-300">
                This alert was automatically downgraded from
                <span class="font-semibold uppercase"><%= @alert.original_severity %></span>
                to <span class="font-semibold uppercase"><%= @alert.severity %></span>
                by the false-positive classifier<%= if fp_reason(@alert), do: ":", else: "." %>
                <%= if fp_reason(@alert) do %>
                  <span class="font-mono"><%= fp_reason(@alert) %></span>.
                <% end %>
              </p>
              <%= if @alert.severity_adjusted_at do %>
                <p class="mt-1 text-xs text-amber-600 dark:text-amber-400">
                  Adjusted <%= format_datetime(@alert.severity_adjusted_at) %>
                </p>
              <% end %>
            </div>
          </div>
        </div>
      <% end %>

      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- Main Content -->
        <div class="lg:col-span-2 space-y-6">
          <!-- Alert Information Card -->
          <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
            <h2 class="text-xl font-bold mb-4 text-gray-900 dark:text-white"><%= @alert.title %></h2>

            <%= if @alert.description do %>
              <p class="text-gray-700 dark:text-gray-300 mb-6 whitespace-pre-wrap"><%= @alert.description %></p>
            <% end %>

            <div class="grid grid-cols-2 gap-4 border-t border-gray-200 dark:border-gray-700 pt-4">
              <div>
                <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Created At</dt>
                <dd class="mt-1 text-sm text-gray-900 dark:text-white">
                  <%= format_datetime(@alert.inserted_at) %>
                </dd>
              </div>

              <%= if @alert.threat_score do %>
                <div>
                  <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Threat Score</dt>
                  <dd class="mt-1 text-sm text-gray-900 dark:text-white">
                    <%= round(@alert.threat_score * 100) %> / 100
                  </dd>
                </div>
              <% end %>

              <%= if @alert.agent_id do %>
                <div>
                  <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Agent ID</dt>
                  <dd class="mt-1 text-sm font-mono text-gray-900 dark:text-white truncate">
                    <%= @alert.agent_id %>
                  </dd>
                </div>
              <% end %>

              <%= if @alert.occurrence_count && @alert.occurrence_count > 1 do %>
                <div>
                  <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Occurrence Count</dt>
                  <dd class="mt-1 text-sm text-gray-900 dark:text-white">
                    <%= @alert.occurrence_count %> times
                  </dd>
                </div>
              <% end %>
            </div>
          </div>

          <!-- Blockchain Attestation -->
          <%= if @alert.blockchain_tx_id do %>
            <div class="bg-green-50 dark:bg-green-900/20 rounded-lg shadow p-6">
              <div class="flex items-center gap-2 mb-3">
                <svg class="w-5 h-5 text-green-600 dark:text-green-400" fill="currentColor" viewBox="0 0 20 20">
                  <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
                </svg>
                <h3 class="text-lg font-semibold text-green-800 dark:text-green-200">Verified on Solana</h3>
              </div>

              <p class="text-sm text-green-700 dark:text-green-300 mb-4">
                This alert has been cryptographically attested and stored on the Solana blockchain, ensuring tamper-proof evidence for audit and compliance.
              </p>

              <div class="space-y-3">
                <div>
                  <dt class="text-xs font-medium text-green-600 dark:text-green-400 mb-1">Transaction ID</dt>
                  <dd class="text-xs font-mono text-green-900 dark:text-green-100 bg-green-100 dark:bg-green-800/50 px-3 py-2 rounded break-all">
                    <%= @alert.blockchain_tx_id %>
                  </dd>
                </div>

                <%= if @alert.blockchain_attested_at do %>
                  <div>
                    <dt class="text-xs font-medium text-green-600 dark:text-green-400 mb-1">Attested At</dt>
                    <dd class="text-sm text-green-900 dark:text-green-100">
                      <%= format_datetime(@alert.blockchain_attested_at) %>
                    </dd>
                  </div>
                <% end %>

                <a href={TamanduaServer.Solana.Client.solscan_url(@alert.blockchain_tx_id)}
                   target="_blank"
                   rel="noopener noreferrer"
                   class="inline-flex items-center gap-2 px-4 py-2 bg-green-600 hover:bg-green-700 text-white text-sm font-medium rounded-lg transition-colors">
                  <span>View on Solscan</span>
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/>
                  </svg>
                </a>
              </div>
            </div>
          <% end %>

          <!-- MITRE ATT&CK Information -->
          <%= if has_mitre_info?(@alert) do %>
            <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
              <h3 class="text-lg font-semibold mb-4 text-gray-900 dark:text-white">MITRE ATT&CK</h3>

              <%= if @alert.mitre_tactics && length(@alert.mitre_tactics) > 0 do %>
                <div class="mb-4">
                  <h4 class="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Tactics</h4>
                  <div class="flex flex-wrap gap-2">
                    <%= for tactic <- @alert.mitre_tactics do %>
                      <span class="px-3 py-1 bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300 text-sm rounded-full">
                        <%= tactic %>
                      </span>
                    <% end %>
                  </div>
                </div>
              <% end %>

              <%= if @alert.mitre_techniques && length(@alert.mitre_techniques) > 0 do %>
                <div>
                  <h4 class="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Techniques</h4>
                  <div class="flex flex-wrap gap-2">
                    <%= for technique <- @alert.mitre_techniques do %>
                      <span class="px-3 py-1 bg-purple-100 dark:bg-purple-900/30 text-purple-800 dark:text-purple-300 text-sm font-mono rounded-full">
                        <%= technique %>
                      </span>
                    <% end %>
                  </div>
                </div>
              <% end %>
            </div>
          <% end %>

          <!-- Evidence Card -->
          <%= if has_evidence?(@alert) do %>
            <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
              <div class="flex items-center justify-between mb-4">
                <h3 class="text-lg font-semibold text-gray-900 dark:text-white">Evidence</h3>
                <button
                  phx-click="toggle_evidence_details"
                  class="text-sm text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300"
                >
                  <%= if @show_evidence_details, do: "Hide Details", else: "Show Details" %>
                </button>
              </div>

              <%= render_evidence(@alert.evidence, @show_evidence_details) %>
            </div>
          <% end %>

          <!-- Detection Information -->
          <%= if @alert.detection_metadata && map_size(@alert.detection_metadata) > 0 do %>
            <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
              <h3 class="text-lg font-semibold mb-4 text-gray-900 dark:text-white">Detection Information</h3>
              <dl class="space-y-2">
                <%= for {key, value} <- @alert.detection_metadata do %>
                  <div class="flex">
                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 w-1/3"><%= format_key(key) %></dt>
                    <dd class="text-sm text-gray-900 dark:text-white w-2/3"><%= format_value(value) %></dd>
                  </div>
                <% end %>
              </dl>
            </div>
          <% end %>

          <!-- ETW Tampering Details -->
          <%= if has_etw_tampering_info?(@alert) do %>
            <%= render_etw_tampering_details(assigns) %>
          <% end %>

          <!-- Memory / Injection Context (ntdll_write detections) -->
          <%= if ntdll_write_detection?(@alert) do %>
            <%= render_memory_injection_context(assigns) %>
          <% end %>
        </div>

        <!-- Sidebar -->
        <div class="lg:col-span-1 space-y-6">
          <!-- Remediation Actions Component -->
          <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
            <.live_component
              module={TamanduaServerWeb.Components.RemediationActions}
              id="remediation-actions"
              alert={@alert}
            />
          </div>

          <!-- Remediation History -->
          <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
            <h3 class="text-lg font-semibold mb-4 text-gray-900 dark:text-white">Remediation History</h3>

            <%= if length(@actions) > 0 do %>
              <div class="space-y-3">
                <%= for action <- @actions do %>
                  <div class={"border-l-4 pl-3 py-2 #{action_border_color(action.status)}"}>
                    <div class="flex items-start justify-between">
                      <div class="flex-1">
                        <p class="text-sm font-medium text-gray-900 dark:text-white">
                          <%= format_action_type(action.action_type) %>
                        </p>
                        <p class="text-xs text-gray-500 dark:text-gray-400 mt-1">
                          <%= format_datetime(action.inserted_at) %>
                        </p>
                      </div>
                      <span class={"px-2 py-1 text-xs font-semibold rounded #{action_status_badge(action.status)}"}>
                        <%= String.upcase(action.status) %>
                      </span>
                    </div>

                    <%= if action.error_message do %>
                      <p class="text-xs text-red-600 dark:text-red-400 mt-2">
                        Error: <%= action.error_message %>
                      </p>
                    <% end %>
                  </div>
                <% end %>
              </div>
            <% else %>
              <p class="text-sm text-gray-500 dark:text-gray-400 italic">No remediation actions taken yet</p>
            <% end %>
          </div>

          <!-- Quick Actions -->
          <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
            <h3 class="text-lg font-semibold mb-4 text-gray-900 dark:text-white">Quick Actions</h3>
            <div class="space-y-2">
              <button
                phx-click="update_status"
                phx-value-status="investigating"
                class="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors"
              >
                Mark as Investigating
              </button>
              <button
                phx-click="update_status"
                phx-value-status="resolved"
                class="w-full px-4 py-2 text-sm bg-green-600 text-white rounded hover:bg-green-700 transition-colors"
              >
                Mark as Resolved
              </button>
              <button
                phx-click="open_verdict_modal"
                phx-value-verdict="false_positive"
                class="w-full px-4 py-2 text-sm bg-gray-600 text-white rounded hover:bg-gray-700 transition-colors"
                title="Records analyst feedback, updates the agent baseline, and (by default) creates a 30-day suppression rule."
              >
                Mark as False Positive
              </button>
              <p class="text-xs text-gray-500 dark:text-gray-400 mt-1">
                False-positive marking writes to the verdict feedback log, weakens the baseline match, and optionally creates a suppression rule.
              </p>
              <button
                phx-click="open_verdict_modal"
                phx-value-verdict="true_positive"
                class="w-full px-4 py-2 text-sm bg-red-700 text-white rounded hover:bg-red-800 transition-colors"
                title="Confirms a real threat. Strengthens the baseline so similar future events are more likely to alert. Suppression rule is off by default but can be enabled in the modal."
              >
                Mark as True Positive
              </button>
              <p class="text-xs text-gray-500 dark:text-gray-400 mt-1">
                Confirms threat; strengthens baseline so similar future events are more likely to alert.
              </p>
              <button
                phx-click="open_verdict_modal"
                phx-value-verdict="benign"
                class="w-full px-4 py-2 text-sm bg-green-600 text-white rounded hover:bg-green-700 transition-colors"
                title="Marks the event as harmless. Weakens the baseline and (by default) creates a suppression rule so similar future events are auto-suppressed."
              >
                Mark as Benign
              </button>
              <p class="text-xs text-gray-500 dark:text-gray-400 mt-1">
                Marks event as harmless; weakens baseline, optionally creates suppression rule.
              </p>
            </div>
          </div>
        </div>
      </div>

      <%= if @show_verdict_modal do %>
        <%= render_verdict_modal(assigns) %>
      <% end %>
    </div>
    """
  end

  defp render_verdict_modal(assigns) do
    ~H"""
    <div
      class="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
      phx-window-keydown="cancel_verdict_modal"
      phx-key="escape"
    >
      <div
        class="bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-lg w-full mx-4 p-6"
        phx-click-away="cancel_verdict_modal"
      >
        <h3 class="text-lg font-semibold mb-2 text-gray-900 dark:text-white">
          Mark as <%= format_verdict(@pending_verdict) %>
        </h3>
        <p class="text-sm text-gray-600 dark:text-gray-400 mb-4">
          This will record your verdict in the audit log, update the agent baseline,
          and optionally create a suppression rule so similar future events are
          auto-suppressed.
        </p>

        <form phx-submit="confirm_verdict" phx-change="update_verdict_form">
          <input type="hidden" name="verdict" value={@pending_verdict} />

          <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
            Analyst notes (rationale)
          </label>
          <textarea
            name="notes"
            rows="4"
            class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-900 text-gray-900 dark:text-white"
            placeholder="Why is this a false positive? (e.g., known admin tool, scheduled job, etc.)"
          ><%= @verdict_notes %></textarea>

          <div class="mt-4 flex items-center gap-2">
            <input
              type="checkbox"
              id="create_suppression_rule"
              name="create_suppression_rule"
              value="true"
              checked={@create_suppression_rule}
              class="rounded border-gray-300 dark:border-gray-600"
            />
            <label for="create_suppression_rule" class="text-sm text-gray-700 dark:text-gray-300">
              Also create a suppression rule
            </label>
          </div>

          <div class="mt-3 flex items-center gap-2">
            <label for="suppression_ttl_days" class="text-sm text-gray-700 dark:text-gray-300">
              Suppression TTL (days):
            </label>
            <input
              type="number"
              id="suppression_ttl_days"
              name="suppression_ttl_days"
              value={@suppression_ttl_days}
              min="1"
              max="365"
              class="w-20 px-2 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-900 text-gray-900 dark:text-white"
            />
          </div>
          <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">
            Typical TTLs: 7d for temporary admin activity, 30d for recurring benign events,
            365d for permanent exceptions. The rule matches future events with the same rule name,
            payload pattern, and process chain on this agent.
          </p>

          <div class="mt-6 flex justify-end gap-2">
            <button
              type="button"
              phx-click="cancel_verdict_modal"
              class="px-4 py-2 text-sm bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              class="px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors"
            >
              Confirm verdict
            </button>
          </div>
        </form>
      </div>
    </div>
    """
  end

  defp format_verdict("false_positive"), do: "False Positive"
  defp format_verdict("true_positive"), do: "True Positive"
  defp format_verdict("benign"), do: "Benign"
  defp format_verdict("suspicious"), do: "Suspicious"
  defp format_verdict(other) when is_binary(other), do: format_status(other)
  defp format_verdict(_), do: "Verdict"

  @impl true
  def handle_event("toggle_evidence_details", _params, socket) do
    {:noreply, assign(socket, :show_evidence_details, !socket.assigns.show_evidence_details)}
  end

  @impl true
  def handle_event("update_status", %{"status" => new_status}, socket) do
    alert = socket.assigns.alert

    case Alerts.update_alert(alert, %{status: new_status}) do
      {:ok, updated_alert} ->
        {:noreply,
         socket
         |> assign(:alert, updated_alert)
         |> put_flash(:info, "Alert status updated to #{new_status}")}

      {:error, _changeset} ->
        {:noreply, put_flash(socket, :error, "Failed to update alert status")}
    end
  end

  # ---------------------------------------------------------------------------
  # Analyst verdict flow
  #
  # `verdict` is the analyst's judgement (true_positive / false_positive /
  # benign / suspicious) and is distinct from `status` (the workflow stage:
  # new / investigating / resolved / false_positive). Setting a verdict goes
  # through Alerts.set_verdict/4 which is transactional: it writes a
  # VerdictFeedbackLog row, updates the agent baseline, and optionally
  # creates a suppression rule that auto-suppresses similar future events.
  # The existing "update_status" handler intentionally remains for the
  # workflow-only path (e.g., "investigating"/"resolved" without a verdict).
  # ---------------------------------------------------------------------------

  @impl true
  def handle_event("open_verdict_modal", %{"verdict" => verdict}, socket) do
    # True-positive = confirmed real threat; do NOT auto-suggest a suppression
    # rule (it would mute future real detections). Analyst can still opt in via
    # the checkbox. All other verdicts default to creating a suppression rule.
    default_create_suppression = verdict != "true_positive"

    {:noreply,
     socket
     |> assign(:show_verdict_modal, true)
     |> assign(:pending_verdict, verdict)
     |> assign(:verdict_notes, "")
     |> assign(:create_suppression_rule, default_create_suppression)
     |> assign(:suppression_ttl_days, 30)}
  end

  @impl true
  def handle_event("cancel_verdict_modal", _params, socket) do
    {:noreply,
     socket
     |> assign(:show_verdict_modal, false)
     |> assign(:pending_verdict, nil)
     |> assign(:verdict_notes, "")}
  end

  @impl true
  def handle_event("update_verdict_form", params, socket) do
    notes = Map.get(params, "notes", "")
    create_rule = Map.get(params, "create_suppression_rule") == "true"
    ttl = parse_ttl(Map.get(params, "suppression_ttl_days"))

    {:noreply,
     socket
     |> assign(:verdict_notes, notes)
     |> assign(:create_suppression_rule, create_rule)
     |> assign(:suppression_ttl_days, ttl)}
  end

  @impl true
  def handle_event("confirm_verdict", params, socket) do
    alert = socket.assigns.alert
    verdict = Map.get(params, "verdict") || socket.assigns.pending_verdict
    notes = Map.get(params, "notes", socket.assigns.verdict_notes)
    create_rule = Map.get(params, "create_suppression_rule") == "true"

    ttl =
      params
      |> Map.get("suppression_ttl_days")
      |> parse_ttl(socket.assigns.suppression_ttl_days)

    user_id =
      case socket.assigns[:current_user] do
        %{id: id} -> id
        _ -> nil
      end

    opts = [
      notes: notes,
      create_suppression_rule: create_rule,
      suppression_ttl_days: ttl
    ]

    case Alerts.set_verdict(alert.id, verdict, user_id, opts) do
      {:ok, %{alert: updated_alert, suppression_rule: rule}} ->
        flash_msg =
          if rule do
            "Verdict recorded: #{format_verdict(verdict)} (suppression rule created, TTL #{ttl}d)"
          else
            "Verdict recorded: #{format_verdict(verdict)}"
          end

        {:noreply,
         socket
         |> assign(:alert, updated_alert)
         |> assign(:show_verdict_modal, false)
         |> assign(:pending_verdict, nil)
         |> assign(:verdict_notes, "")
         |> put_flash(:info, flash_msg)}

      {:error, :invalid_verdict} ->
        {:noreply, put_flash(socket, :error, "Invalid verdict value")}

      {:error, :not_found} ->
        {:noreply, put_flash(socket, :error, "Alert not found")}

      {:error, reason} ->
        {:noreply,
         put_flash(socket, :error, "Failed to set verdict: #{inspect(reason)}")}
    end
  end

  defp parse_ttl(value, default \\ 30)
  defp parse_ttl(value, _default) when is_integer(value) and value > 0, do: value

  defp parse_ttl(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} when int > 0 -> int
      _ -> default
    end
  end

  defp parse_ttl(_, default), do: default

  @impl true
  def handle_info({:action_completed, _action_type}, socket) do
    # Refresh action history when a remediation action completes
    org_id = socket.assigns.organization_id
    actions = Response.list_actions(%{alert_id: socket.assigns.alert_id, organization_id: org_id})

    # Use tenant-scoped lookup to prevent BOLA/IDOR
    case Alerts.get_alert_for_org(org_id, socket.assigns.alert_id) do
      {:ok, alert} ->
        {:noreply,
         socket
         |> assign(:actions, actions)
         |> assign(:alert, alert)}

      {:error, :not_found} ->
        # Alert was deleted or moved to different tenant
        {:noreply, socket}
    end
  end

  @impl true
  def handle_info({:alert_updated, updated_alert}, socket) do
    # Handle real-time alert updates via PubSub
    {:noreply, assign(socket, :alert, updated_alert)}
  end

  @impl true
  def handle_info(_msg, socket), do: {:noreply, socket}

  # Private helper functions

  defp has_mitre_info?(alert) do
    (alert.mitre_tactics && length(alert.mitre_tactics) > 0) ||
      (alert.mitre_techniques && length(alert.mitre_techniques) > 0)
  end

  defp has_evidence?(alert) do
    alert.evidence && map_size(alert.evidence) > 0
  end

  defp has_etw_tampering_info?(alert) do
    alert.target_function || alert.patch_pattern || alert.target_region
  end

  # True when this alert originates from an ntdll_write_* detection rule.
  # Matches on the detection name (detection_metadata) or the alert title so the
  # memory/injection context card renders for the right detections only. This is
  # additive triage context and never gates or suppresses any event.
  defp ntdll_write_detection?(alert) do
    name = ntdll_detection_name(alert)
    title = alert.title || ""

    String.starts_with?(name, "ntdll_write_") or
      String.contains?(name, "ntdll_write") or
      String.contains?(String.downcase(title), "ntdll_write")
  end

  defp ntdll_detection_name(alert) do
    meta = alert.detection_metadata || %{}

    nested_get(meta, ["rule_name", "detection_name", "detection_type", "rule"], "")
    |> to_string()
    |> String.downcase()
  end

  defp render_etw_tampering_details(assigns) do
    ~H"""
    <div class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg shadow p-6">
      <div class="flex items-center gap-2 mb-4">
        <svg class="w-6 h-6 text-red-600 dark:text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
        <h3 class="text-lg font-semibold text-red-800 dark:text-red-200">ETW Tampering Detection</h3>
        <span class="ml-auto px-2 py-1 text-xs font-semibold bg-red-100 dark:bg-red-800 text-red-800 dark:text-red-200 rounded">
          MITRE T1562.006
        </span>
      </div>

      <p class="text-sm text-red-700 dark:text-red-300 mb-4">
        A process has attempted to patch critical Windows ETW functions to evade EDR telemetry collection.
        This is a critical defense evasion technique commonly used by advanced malware.
      </p>

      <dl class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <%= if @alert.target_function do %>
          <div>
            <dt class="text-sm font-medium text-red-600 dark:text-red-400">Target Function</dt>
            <dd class="mt-1 text-sm font-mono text-red-900 dark:text-red-100 bg-red-100 dark:bg-red-800/50 px-2 py-1 rounded">
              <%= @alert.target_function %>
            </dd>
          </div>
        <% end %>

        <%= if @alert.patch_pattern do %>
          <div>
            <dt class="text-sm font-medium text-red-600 dark:text-red-400">Patch Pattern</dt>
            <dd class="mt-1">
              <span class={"px-2 py-1 text-xs font-semibold rounded #{patch_pattern_badge_color(@alert.patch_pattern)}"}>
                <%= format_patch_pattern(@alert.patch_pattern) %>
              </span>
            </dd>
          </div>
        <% end %>

        <%= if @alert.target_region do %>
          <div>
            <dt class="text-sm font-medium text-red-600 dark:text-red-400">Target Region</dt>
            <dd class="mt-1 text-sm text-red-900 dark:text-red-100">
              <%= format_target_region(@alert.target_region) %>
            </dd>
          </div>
        <% end %>

        <%= if @alert.original_bytes do %>
          <div class="md:col-span-2">
            <dt class="text-sm font-medium text-red-600 dark:text-red-400">Original Bytes</dt>
            <dd class="mt-1 text-xs font-mono text-red-900 dark:text-red-100 bg-red-100 dark:bg-red-800/50 px-2 py-1 rounded overflow-x-auto">
              <%= format_hex_bytes(@alert.original_bytes) %>
            </dd>
          </div>
        <% end %>

        <%= if @alert.patched_bytes do %>
          <div class="md:col-span-2">
            <dt class="text-sm font-medium text-red-600 dark:text-red-400">Patched Bytes</dt>
            <dd class="mt-1 text-xs font-mono text-red-900 dark:text-red-100 bg-red-100 dark:bg-red-800/50 px-2 py-1 rounded overflow-x-auto">
              <%= format_hex_bytes(@alert.patched_bytes) %>
            </dd>
          </div>
        <% end %>
      </dl>

      <div class="mt-4 pt-4 border-t border-red-200 dark:border-red-700">
        <h4 class="text-sm font-medium text-red-700 dark:text-red-300 mb-2">Recommended Actions</h4>
        <ul class="text-sm text-red-600 dark:text-red-400 list-disc list-inside space-y-1">
          <li>Immediately investigate the process that performed the tampering</li>
          <li>Consider isolating the affected endpoint</li>
          <li>Check for other indicators of compromise on the system</li>
          <li>Review process chain and parent processes</li>
        </ul>
      </div>
    </div>
    """
  end

  defp render_memory_injection_context(assigns) do
    meta = ntdll_meta(assigns.alert)

    assigns =
      assigns
      |> assign(:nw_source_pid, meta.source_pid)
      |> assign(:nw_source_process, meta.source_process)
      |> assign(:nw_source_is_signed, meta.source_is_signed)
      |> assign(:nw_source_signer, meta.source_signer)
      |> assign(:nw_cross_process, meta.cross_process)
      |> assign(:nw_target_pid, meta.target_pid)
      |> assign(:nw_target_process, meta.target_process)
      |> assign(:nw_target_address, meta.target_address)
      |> assign(:nw_target_function, meta.target_function)
      |> assign(:nw_region_class, meta.region_class)
      |> assign(:nw_old_protection, meta.old_protection)
      |> assign(:nw_new_protection, meta.new_protection)

    ~H"""
    <div class="bg-indigo-50 dark:bg-indigo-900/20 border border-indigo-200 dark:border-indigo-800 rounded-lg shadow p-6">
      <div class="flex items-center gap-2 mb-4">
        <svg class="w-6 h-6 text-indigo-600 dark:text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z" />
        </svg>
        <h3 class="text-lg font-semibold text-indigo-800 dark:text-indigo-200">Memory / Injection Context</h3>
        <span class="ml-auto px-2 py-1 text-xs font-semibold bg-indigo-100 dark:bg-indigo-800 text-indigo-800 dark:text-indigo-200 rounded">
          ntdll write
        </span>
      </div>

      <p class="text-sm text-indigo-700 dark:text-indigo-300 mb-4">
        Triage context for a write into another process's memory via the ntdll syscall surface.
        Use the source signature and cross-process indicators below to distinguish benign tooling
        from injection. This context is for analyst triage only and does not suppress any event.
      </p>

      <!-- Source -->
      <h4 class="text-sm font-semibold text-indigo-700 dark:text-indigo-300 mb-2">Source</h4>
      <dl class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
        <div>
          <dt class="text-sm font-medium text-indigo-600 dark:text-indigo-400">Source PID</dt>
          <dd class="mt-1 text-sm font-mono text-indigo-900 dark:text-indigo-100"><%= @nw_source_pid %></dd>
        </div>
        <div>
          <dt class="text-sm font-medium text-indigo-600 dark:text-indigo-400">Source Process</dt>
          <dd class="mt-1 text-sm font-mono text-indigo-900 dark:text-indigo-100 break-all"><%= @nw_source_process %></dd>
        </div>
        <div>
          <dt class="text-sm font-medium text-indigo-600 dark:text-indigo-400">Source Signed</dt>
          <dd class="mt-1">
            <span class={"px-2 py-1 text-xs font-semibold rounded #{signature_badge_color(@nw_source_is_signed)}"}>
              <%= format_signature_status(@nw_source_is_signed) %>
            </span>
          </dd>
        </div>
        <div>
          <dt class="text-sm font-medium text-indigo-600 dark:text-indigo-400">Source Signer</dt>
          <dd class="mt-1 text-sm text-indigo-900 dark:text-indigo-100 break-all"><%= @nw_source_signer %></dd>
        </div>
      </dl>

      <!-- Cross-process flag -->
      <div class="mb-4">
        <dt class="text-sm font-medium text-indigo-600 dark:text-indigo-400">Cross-Process</dt>
        <dd class="mt-1">
          <span class={"px-2 py-1 text-xs font-semibold rounded #{cross_process_badge_color(@nw_cross_process)}"}>
            <%= format_cross_process(@nw_cross_process) %>
          </span>
        </dd>
      </div>

      <!-- Target -->
      <h4 class="text-sm font-semibold text-indigo-700 dark:text-indigo-300 mb-2">Target</h4>
      <dl class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
        <div>
          <dt class="text-sm font-medium text-indigo-600 dark:text-indigo-400">Target PID</dt>
          <dd class="mt-1 text-sm font-mono text-indigo-900 dark:text-indigo-100"><%= @nw_target_pid %></dd>
        </div>
        <div>
          <dt class="text-sm font-medium text-indigo-600 dark:text-indigo-400">Target Process</dt>
          <dd class="mt-1 text-sm font-mono text-indigo-900 dark:text-indigo-100 break-all"><%= @nw_target_process %></dd>
        </div>
        <div>
          <dt class="text-sm font-medium text-indigo-600 dark:text-indigo-400">Target Address</dt>
          <dd class="mt-1 text-sm font-mono text-indigo-900 dark:text-indigo-100 break-all"><%= @nw_target_address %></dd>
        </div>
        <div>
          <dt class="text-sm font-medium text-indigo-600 dark:text-indigo-400">Target Function</dt>
          <dd class="mt-1 text-sm font-mono text-indigo-900 dark:text-indigo-100 break-all"><%= @nw_target_function %></dd>
        </div>
        <div>
          <dt class="text-sm font-medium text-indigo-600 dark:text-indigo-400">Region Class</dt>
          <dd class="mt-1 text-sm text-indigo-900 dark:text-indigo-100"><%= @nw_region_class %></dd>
        </div>
      </dl>

      <!-- Protection transition -->
      <h4 class="text-sm font-semibold text-indigo-700 dark:text-indigo-300 mb-2">Protection Transition</h4>
      <div class="flex items-center gap-2">
        <span class="px-2 py-1 text-xs font-mono font-semibold rounded bg-indigo-100 dark:bg-indigo-800/50 text-indigo-900 dark:text-indigo-100">
          <%= @nw_old_protection %>
        </span>
        <svg class="w-4 h-4 text-indigo-500 dark:text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14 5l7 7m0 0l-7 7m7-7H3" />
        </svg>
        <span class="px-2 py-1 text-xs font-mono font-semibold rounded bg-indigo-100 dark:bg-indigo-800/50 text-indigo-900 dark:text-indigo-100">
          <%= @nw_new_protection %>
        </span>
      </div>
    </div>
    """
  end

  defp render_evidence(evidence, show_details) do
    assigns = %{evidence_entries: evidence_entries(evidence), show_details: show_details}

    ~H"""
    <div class="space-y-4">
      <%= for {category, data} <- @evidence_entries do %>
        <div class="border-l-2 border-blue-500 pl-3">
          <h4 class="text-sm font-semibold text-gray-900 dark:text-white capitalize mb-2">
            <%= format_key(category) %>
          </h4>

          <%= if @show_details do %>
            <dl class="space-y-1">
              <%= for {key, value} <- evidence_detail_rows(data) do %>
                <div class="flex text-xs">
                  <dt class="text-gray-500 dark:text-gray-400 w-1/3"><%= format_key(key) %></dt>
                  <dd class="text-gray-900 dark:text-white w-2/3 font-mono break-all"><%= format_value(value) %></dd>
                </div>
              <% end %>
            </dl>
          <% else %>
            <p class="text-xs text-gray-600 dark:text-gray-400">
              <%= summary_for_category(category, data) %>
            </p>
          <% end %>
        </div>
      <% end %>
    </div>
    """
  end

  defp evidence_entries(evidence) when is_map(evidence), do: evidence
  defp evidence_entries(_), do: []

  defp evidence_detail_rows(data) when is_map(data), do: data

  defp evidence_detail_rows(data) when is_list(data) do
    data
    |> Enum.with_index(1)
    |> Enum.map(fn {value, index} -> {"item_#{index}", value} end)
  end

  defp evidence_detail_rows(nil), do: []
  defp evidence_detail_rows(data), do: [{"value", data}]

  defp summary_for_category("process", data) do
    name = data["name"] || data[:name] || "unknown"
    path = data["path"] || data[:path]
    if path, do: "#{name} (#{path})", else: name
  end

  defp summary_for_category("file", data) do
    path = data["path"] || data[:path] || "unknown"
    sha256 = data["sha256"] || data[:sha256]
    if sha256, do: "#{path} (SHA256: #{String.slice(sha256, 0..15)}...)", else: path
  end

  defp summary_for_category("network", data) do
    ip = data["value"] || data[:value] || data["remote_ip"] || data[:remote_ip]
    port = data["port"] || data[:port] || data["remote_port"] || data[:remote_port]
    if port, do: "#{ip}:#{port}", else: ip || "unknown"
  end

  defp summary_for_category(_category, data) when is_map(data) do
    count = map_size(data)
    "#{count} #{if count == 1, do: "field", else: "fields"}"
  end

  defp summary_for_category(_category, data) when is_list(data) do
    count = length(data)
    "#{count} #{if count == 1, do: "item", else: "items"}"
  end

  defp summary_for_category(_category, _data), do: "Details available"

  defp format_key(key) when is_atom(key), do: key |> to_string() |> format_key()

  defp format_key(key) when is_binary(key) do
    key
    |> String.replace("_", " ")
    |> String.split(" ")
    |> Enum.map(&String.capitalize/1)
    |> Enum.join(" ")
  end

  defp format_value(value) when is_list(value) do
    if Enum.all?(value, &(is_binary(&1) or is_number(&1) or is_boolean(&1))) do
      Enum.join(value, ", ")
    else
      inspect(value, pretty: true, limit: 20)
    end
  end

  defp format_value(value) when is_map(value), do: inspect(value, pretty: true, limit: 5)
  defp format_value(value) when is_binary(value), do: value
  defp format_value(value), do: to_string(value)

  defp format_status(status) do
    status
    |> String.replace("_", " ")
    |> String.split(" ")
    |> Enum.map(&String.capitalize/1)
    |> Enum.join(" ")
  end

  defp format_action_type(type) do
    type
    |> String.replace("_", " ")
    |> String.split(" ")
    |> Enum.map(&String.capitalize/1)
    |> Enum.join(" ")
  end

  defp format_datetime(%NaiveDateTime{} = dt) do
    dt
    |> NaiveDateTime.to_string()
    |> String.replace("T", " ")
    |> String.slice(0..18)
  end

  defp format_datetime(%DateTime{} = dt) do
    dt
    |> DateTime.to_string()
    |> String.replace("T", " ")
    |> String.slice(0..18)
  end

  defp format_datetime(_), do: "N/A"

  # True when the FP classifier downgraded this alert's severity.
  defp severity_adjusted?(%{severity_adjusted: true}), do: true

  defp severity_adjusted?(%{original_severity: orig, severity: sev})
       when is_binary(orig) and is_binary(sev),
       do: orig != sev

  defp severity_adjusted?(_), do: false

  # The reason recorded by the FP classifier (false_positive_notes), falling
  # back to detection_metadata["fp_reason"] for older alerts.
  defp fp_reason(%{false_positive_notes: notes}) when is_binary(notes) and notes != "",
    do: notes

  defp fp_reason(%{detection_metadata: %{"fp_reason" => reason}})
       when is_binary(reason) and reason != "",
       do: reason

  defp fp_reason(_), do: nil

  # Build a normalized struct of memory/injection context for ntdll_write
  # detections. Values are pulled from detection_metadata first, then the raw
  # event, then evidence, with "N/A" / "unknown" fallbacks so the card never
  # crashes on missing fields. The agent populates source_is_signed/source_signer
  # in parallel; absence is shown as "unknown" rather than an error.
  defp ntdll_meta(alert) do
    meta = alert.detection_metadata || %{}
    raw = alert.raw_event || %{}
    evidence = alert.evidence || %{}

    source_pid = first_present([meta, raw], ["source_pid", "src_pid", "pid"])
    target_pid = first_present([meta, raw], ["target_pid", "dest_pid", "dst_pid"])

    cross_process =
      case nested_get([meta, raw], ["cross_process"], :unset) do
        :unset -> derive_cross_process(source_pid, target_pid)
        value -> value
      end

    %{
      source_pid: blank_to_na(source_pid),
      source_process:
        blank_to_na(
          first_present([meta, raw, evidence], [
            "source_process",
            "source_name",
            "process_name",
            "source_path"
          ])
        ),
      source_is_signed: nested_get([meta, raw], ["source_is_signed"], :unknown),
      source_signer:
        signer_or_unknown(first_present([meta, raw], ["source_signer", "source_signer_name"])),
      cross_process: cross_process,
      target_pid: blank_to_na(target_pid),
      target_process:
        blank_to_na(
          first_present([meta, raw, evidence], ["target_process", "target_name", "target_path"])
        ),
      target_address:
        blank_to_na(first_present([meta, raw], ["target_address", "address", "write_address"])),
      target_function:
        blank_to_na(
          first_present([meta, raw], ["target_function", "function"]) || alert.target_function
        ),
      region_class: blank_to_na(first_present([meta, raw], ["region_class", "region"])),
      old_protection:
        blank_to_na(first_present([meta, raw], ["old_protection", "old_protection_str"])),
      new_protection:
        blank_to_na(first_present([meta, raw], ["new_protection", "new_protection_str"]))
    }
  end

  # Cross-process is derivable when both PIDs are present and differ.
  defp derive_cross_process(source_pid, target_pid)
       when not is_nil(source_pid) and not is_nil(target_pid) do
    to_string(source_pid) != to_string(target_pid)
  end

  defp derive_cross_process(_source_pid, _target_pid), do: :unknown

  # Return the first non-blank value found by probing each map in order for any
  # of the candidate keys (string or atom). nil when nothing matches.
  defp first_present(maps, keys) do
    Enum.find_value(maps, fn map -> nested_get(map, keys, nil) |> presence() end)
  end

  # Safely read the first present key (string or atom) from one map or a list of
  # maps. Returns `default` when none of the keys resolve to a non-nil value.
  defp nested_get(maps, keys, default) when is_list(maps) do
    Enum.find_value(maps, default, fn map ->
      case nested_get(map, keys, :__miss__) do
        :__miss__ -> nil
        value -> value
      end
    end)
  end

  defp nested_get(map, keys, default) when is_map(map) and is_list(keys) do
    Enum.find_value(keys, default, fn key ->
      case Map.get(map, key) do
        nil -> if is_binary(key), do: Map.get(map, safe_atom(key)), else: nil
        value -> value
      end
    end)
  end

  defp nested_get(_map, _keys, default), do: default

  # Only resolve already-existing atoms to avoid atom-table exhaustion from
  # attacker-controlled metadata keys.
  defp safe_atom(key) when is_binary(key) do
    String.to_existing_atom(key)
  rescue
    ArgumentError -> nil
  end

  defp presence(nil), do: nil
  defp presence(""), do: nil
  defp presence(value), do: value

  defp blank_to_na(nil), do: "N/A"
  defp blank_to_na(""), do: "N/A"
  defp blank_to_na(value) when is_binary(value), do: value
  defp blank_to_na(value), do: to_string(value)

  defp signer_or_unknown(nil), do: "unknown"
  defp signer_or_unknown(""), do: "unknown"
  defp signer_or_unknown(value) when is_binary(value), do: value
  defp signer_or_unknown(value), do: to_string(value)

  defp format_signature_status(true), do: "Signed"
  defp format_signature_status("true"), do: "Signed"
  defp format_signature_status(false), do: "Unsigned"
  defp format_signature_status("false"), do: "Unsigned"
  defp format_signature_status(_), do: "Unknown"

  defp signature_badge_color(true),
    do: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"

  defp signature_badge_color("true"),
    do: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"

  defp signature_badge_color(false),
    do: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"

  defp signature_badge_color("false"),
    do: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"

  defp signature_badge_color(_),
    do: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200"

  defp format_cross_process(true), do: "Yes"
  defp format_cross_process("true"), do: "Yes"
  defp format_cross_process(false), do: "No"
  defp format_cross_process("false"), do: "No"
  defp format_cross_process(_), do: "Unknown"

  defp cross_process_badge_color(true),
    do: "bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200"

  defp cross_process_badge_color("true"),
    do: "bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200"

  defp cross_process_badge_color(false),
    do: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200"

  defp cross_process_badge_color("false"),
    do: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200"

  defp cross_process_badge_color(_),
    do: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200"

  defp severity_badge_color("critical"),
    do: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"

  defp severity_badge_color("high"),
    do: "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200"

  defp severity_badge_color("medium"),
    do: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200"

  defp severity_badge_color("low"),
    do: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200"

  defp severity_badge_color(_),
    do: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200"

  defp status_badge_color("new"), do: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"

  defp status_badge_color("investigating"),
    do: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200"

  defp status_badge_color("resolved"),
    do: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"

  defp status_badge_color("false_positive"),
    do: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200"

  defp status_badge_color(_), do: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200"

  defp verdict_badge_color("true_positive"),
    do: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"

  defp verdict_badge_color("false_positive"),
    do: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200"

  defp verdict_badge_color("benign"),
    do: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"

  defp verdict_badge_color("suspicious"),
    do: "bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200"

  defp verdict_badge_color(_),
    do: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200"

  defp action_border_color("success"), do: "border-green-500"
  defp action_border_color("failed"), do: "border-red-500"
  defp action_border_color("pending"), do: "border-yellow-500"
  defp action_border_color("executing"), do: "border-blue-500"
  defp action_border_color(_), do: "border-gray-300 dark:border-gray-600"

  defp action_status_badge("success"),
    do: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"

  defp action_status_badge("failed"),
    do: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"

  defp action_status_badge("pending"),
    do: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200"

  defp action_status_badge("executing"),
    do: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200"

  defp action_status_badge(_), do: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200"

  # ETW tampering helper functions

  defp format_hex_bytes(nil), do: "N/A"

  defp format_hex_bytes(bytes) when is_binary(bytes) do
    bytes
    |> :binary.bin_to_list()
    |> Enum.map(&Integer.to_string(&1, 16))
    |> Enum.map(&String.pad_leading(&1, 2, "0"))
    |> Enum.join(" ")
  end

  defp format_patch_pattern("ret"), do: "RET (0xC3)"
  defp format_patch_pattern("xor_eax_ret"), do: "XOR EAX, EAX; RET"
  defp format_patch_pattern("jmp_rel32"), do: "JMP rel32"
  defp format_patch_pattern("jmp_abs"), do: "JMP absolute"
  defp format_patch_pattern("nop_sled"), do: "NOP sled"
  defp format_patch_pattern("int3_trap"), do: "INT3 trap"
  defp format_patch_pattern("ud2"), do: "UD2 (undefined)"
  defp format_patch_pattern(pattern), do: String.upcase(pattern || "unknown")

  defp format_target_region("syscall_stub"), do: "NTDLL Syscall Stub"
  defp format_target_region("etw_function"), do: "ETW Function"
  defp format_target_region("ntdll_text"), do: "NTDLL .text Section"
  defp format_target_region("kernel32_text"), do: "Kernel32 .text Section"
  defp format_target_region("amsi_function"), do: "AMSI Function"
  defp format_target_region(region), do: String.capitalize(region || "unknown")

  defp patch_pattern_badge_color("ret"),
    do: "bg-red-200 text-red-800 dark:bg-red-700 dark:text-red-100"

  defp patch_pattern_badge_color("xor_eax_ret"),
    do: "bg-red-200 text-red-800 dark:bg-red-700 dark:text-red-100"

  defp patch_pattern_badge_color("jmp_rel32"),
    do: "bg-orange-200 text-orange-800 dark:bg-orange-700 dark:text-orange-100"

  defp patch_pattern_badge_color("jmp_abs"),
    do: "bg-orange-200 text-orange-800 dark:bg-orange-700 dark:text-orange-100"

  defp patch_pattern_badge_color(_),
    do: "bg-yellow-200 text-yellow-800 dark:bg-yellow-700 dark:text-yellow-100"
end
