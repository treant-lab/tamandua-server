defmodule TamanduaServerWeb.AIRuntimeLive do
  @moduledoc """
  Unified AI Runtime Security Dashboard.

  Main entry point for AI/ML runtime security monitoring. Provides:

  - Real-time threat feed (prompt injection, token anomalies, output blocks)
  - Active inference sessions overview
  - Kill switch status and quick controls
  - Combined detection view with filtering

  ## Tabs

  - **Overview**: Real-time threat feed with quick actions
  - **Sessions**: Active inference sessions with drill-down
  - **Detections**: Combined view of all AI security detections
  - **Kill Switch**: Quick access to model isolation controls

  ## PubSub Subscriptions

  - `inference:all` - Session updates
  - `detection:prompt_injection` - Prompt injection alerts
  - `detection:token_anomaly` - Token anomaly alerts
  - `detection:output_validation` - Output validation blocks
  - `kill_switch:all` - Kill switch state changes
  """

  use TamanduaServerWeb, :live_view

  alias TamanduaServer.Runtime.KillSwitch
  alias Phoenix.PubSub

  # Note: InferenceTracker, PromptInjectionClassifier, TokenAnomalyDetector, OutputValidator
  # are accessed via direct ETS lookups for performance and fault tolerance

  @refresh_interval_ms 30_000
  @max_threat_feed_items 10
  @max_detection_items 50

  @impl true
  def mount(params, _session, socket) do
    if connected?(socket) do
      # Subscribe to all relevant PubSub topics
      PubSub.subscribe(TamanduaServer.PubSub, "inference:all")
      PubSub.subscribe(TamanduaServer.PubSub, "detection:prompt_injection")
      PubSub.subscribe(TamanduaServer.PubSub, "detection:token_anomaly")
      PubSub.subscribe(TamanduaServer.PubSub, "detection:output_validation")
      PubSub.subscribe(TamanduaServer.PubSub, "kill_switch:all")

      :timer.send_interval(@refresh_interval_ms, self(), :refresh)
    end

    # Parse tab from URL params
    active_tab = parse_tab(params["tab"])

    {:ok,
     socket
     |> assign(:page_title, "AI Runtime Security")
     |> assign(:active_tab, active_tab)
     |> assign(:loading, true)
     |> assign(:stats, default_stats())
     |> assign(:threat_feed, [])
     |> assign(:sessions, [])
     |> assign(:detections, [])
     |> assign(:detection_filter, %{type: nil, severity: nil, time_range: "24h"})
     |> assign(:expanded_session, nil)
     |> load_data()}
  end

  @impl true
  def handle_params(params, _uri, socket) do
    active_tab = parse_tab(params["tab"])
    {:noreply, assign(socket, :active_tab, active_tab)}
  end

  @impl true
  def handle_info(:refresh, socket) do
    {:noreply, load_data(socket)}
  end

  @impl true
  def handle_info({:kill_switch, _model_id, _event}, socket) do
    # Reload stats on kill switch changes
    {:noreply, load_stats(socket)}
  end

  @impl true
  def handle_info({:inference_request, session}, socket) do
    sessions = [session | socket.assigns.sessions] |> Enum.take(50)
    {:noreply, assign(socket, :sessions, sessions) |> update_session_count()}
  end

  @impl true
  def handle_info({:inference_complete, session}, socket) do
    sessions =
      Enum.map(socket.assigns.sessions, fn s ->
        if s.session_id == session.session_id, do: session, else: s
      end)

    {:noreply, assign(socket, :sessions, sessions)}
  end

  @impl true
  def handle_info({:detection, type, detection}, socket) do
    # Add to threat feed
    threat_item = %{
      id: generate_id(),
      type: type,
      detection: detection,
      timestamp: DateTime.utc_now()
    }

    threat_feed = [threat_item | socket.assigns.threat_feed] |> Enum.take(@max_threat_feed_items)

    # Add to detections list
    detections = [threat_item | socket.assigns.detections] |> Enum.take(@max_detection_items)

    {:noreply,
     socket
     |> assign(:threat_feed, threat_feed)
     |> assign(:detections, detections)
     |> update_threat_count()}
  end

  @impl true
  def handle_info(_msg, socket) do
    {:noreply, socket}
  end

  @impl true
  def handle_event("switch_tab", %{"tab" => tab}, socket) do
    {:noreply, push_patch(socket, to: ~p"/live/ai/runtime?tab=#{tab}")}
  end

  @impl true
  def handle_event("refresh_data", _params, socket) do
    {:noreply, load_data(socket) |> put_flash(:info, "Data refreshed")}
  end

  @impl true
  def handle_event("arm_all", _params, socket) do
    # Arm all tracked models
    Task.start(fn ->
      try do
        :ets.tab2list(:model_isolation_state)
        |> Enum.each(fn {_id, state} ->
          KillSwitch.arm(state.model_id)
        end)
      rescue
        _ -> :ok
      end
    end)

    {:noreply, put_flash(socket, :info, "Arming all kill switches...") |> load_stats()}
  end

  @impl true
  def handle_event("filter_detections", params, socket) do
    filter = %{
      type: parse_detection_type(params["type"]),
      severity: parse_detection_severity(params["severity"]),
      time_range: parse_time_range(params["time_range"])
    }

    {:noreply, assign(socket, :detection_filter, filter) |> load_detections()}
  end

  @impl true
  def handle_event("expand_session", %{"session_id" => session_id}, socket) do
    expanded = if socket.assigns.expanded_session == session_id, do: nil, else: session_id
    {:noreply, assign(socket, :expanded_session, expanded)}
  end

  # ============================================================================
  # Render
  # ============================================================================

  @impl true
  def render(assigns) do
    ~H"""
    <div class="ai-runtime-dashboard p-6 space-y-6">
      <!-- Header -->
      <header class="flex justify-between items-center">
        <div>
          <h1 class="text-2xl font-bold text-[var(--color-foreground)]">
            AI Runtime Security
          </h1>
          <p class="text-sm text-[var(--color-muted)]">
            Unified monitoring for AI/ML runtime protection
          </p>
        </div>
        <button
          phx-click="refresh_data"
          class="px-4 py-2 text-sm font-medium text-white bg-[var(--color-primary-600)] hover:bg-[var(--color-primary-700)] rounded-lg transition-colors"
        >
          Refresh
        </button>
      </header>

      <!-- Stats Cards -->
      <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div class="bg-[var(--color-background)] border border-[var(--color-border)] rounded-lg p-4">
          <h3 class="text-sm font-medium text-[var(--color-muted)]">Active Sessions</h3>
          <p class="text-2xl font-bold text-[var(--color-primary-600)]">
            <%= @stats.active_sessions %>
          </p>
        </div>
        <div class="bg-[var(--color-background)] border border-[var(--color-border)] rounded-lg p-4">
          <h3 class="text-sm font-medium text-[var(--color-muted)]">Kill Switch Armed</h3>
          <p class="text-2xl font-bold text-[var(--color-warning-500)]">
            <%= @stats.armed_count %>/<%= @stats.total_models %>
          </p>
        </div>
        <div class="bg-[var(--color-background)] border border-[var(--color-border)] rounded-lg p-4">
          <h3 class="text-sm font-medium text-[var(--color-muted)]">Blocked Outputs</h3>
          <p class="text-2xl font-bold text-[var(--color-error-500)]">
            <%= @stats.blocked_outputs %>
          </p>
        </div>
        <div class="bg-[var(--color-background)] border border-[var(--color-border)] rounded-lg p-4">
          <h3 class="text-sm font-medium text-[var(--color-muted)]">Threats Today</h3>
          <p class="text-2xl font-bold text-[var(--color-error-500)]">
            <%= @stats.threats_today %>
          </p>
        </div>
      </div>

      <!-- Tabs -->
      <div class="border-b border-[var(--color-border)]">
        <nav class="flex space-x-8" aria-label="Tabs">
          <button
            phx-click="switch_tab"
            phx-value-tab="overview"
            class={"border-b-2 py-4 px-1 text-sm font-medium #{if @active_tab == :overview, do: "border-[var(--color-primary-500)] text-[var(--color-primary-600)]", else: "border-transparent text-[var(--color-muted)] hover:text-[var(--color-foreground)] hover:border-[var(--color-border)]"}"}
          >
            Overview
          </button>
          <button
            phx-click="switch_tab"
            phx-value-tab="sessions"
            class={"border-b-2 py-4 px-1 text-sm font-medium #{if @active_tab == :sessions, do: "border-[var(--color-primary-500)] text-[var(--color-primary-600)]", else: "border-transparent text-[var(--color-muted)] hover:text-[var(--color-foreground)] hover:border-[var(--color-border)]"}"}
          >
            Sessions
          </button>
          <button
            phx-click="switch_tab"
            phx-value-tab="detections"
            class={"border-b-2 py-4 px-1 text-sm font-medium #{if @active_tab == :detections, do: "border-[var(--color-primary-500)] text-[var(--color-primary-600)]", else: "border-transparent text-[var(--color-muted)] hover:text-[var(--color-foreground)] hover:border-[var(--color-border)]"}"}
          >
            Detections
          </button>
          <button
            phx-click="switch_tab"
            phx-value-tab="kill_switch"
            class={"border-b-2 py-4 px-1 text-sm font-medium #{if @active_tab == :kill_switch, do: "border-[var(--color-primary-500)] text-[var(--color-primary-600)]", else: "border-transparent text-[var(--color-muted)] hover:text-[var(--color-foreground)] hover:border-[var(--color-border)]"}"}
          >
            Kill Switch
          </button>
        </nav>
      </div>

      <!-- Tab Content -->
      <div class="tab-content">
        <%= case @active_tab do %>
          <% :overview -> %>
            <%= render_overview_tab(assigns) %>
          <% :sessions -> %>
            <%= render_sessions_tab(assigns) %>
          <% :detections -> %>
            <%= render_detections_tab(assigns) %>
          <% :kill_switch -> %>
            <%= render_kill_switch_tab(assigns) %>
        <% end %>
      </div>
    </div>
    """
  end

  # ============================================================================
  # Tab Renders
  # ============================================================================

  defp render_overview_tab(assigns) do
    ~H"""
    <div class="space-y-6">
      <!-- Quick Actions -->
      <div class="flex gap-4">
        <button
          phx-click="arm_all"
          class="px-4 py-2 text-sm font-medium text-[var(--color-warning-700)] bg-[var(--color-warning-100)] hover:bg-[var(--color-warning-200)] dark:text-[var(--color-warning-300)] dark:bg-[var(--color-warning-900)]/30 dark:hover:bg-[var(--color-warning-900)]/50 rounded-lg transition-colors"
        >
          Arm All Kill Switches
        </button>
        <.link
          navigate={~p"/live/runtime/kill-switch"}
          class="px-4 py-2 text-sm font-medium text-[var(--color-foreground)] bg-[var(--color-neutral-100)] hover:bg-[var(--color-neutral-200)] dark:bg-[var(--color-neutral-800)] dark:hover:bg-[var(--color-neutral-700)] rounded-lg transition-colors"
        >
          View Isolated Models
        </.link>
      </div>

      <!-- Status Summary Cards -->
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div class="bg-[var(--color-background)] border border-[var(--color-border)] rounded-lg p-4">
          <div class="flex items-center justify-between">
            <div>
              <h3 class="text-sm font-medium text-[var(--color-muted)]">Prompt Injection</h3>
              <p class="text-xl font-bold text-[var(--color-error-500)]">
                <%= count_by_type(@detections, :prompt_injection) %>
              </p>
            </div>
            <div class="w-10 h-10 rounded-full bg-[var(--color-error-100)] dark:bg-[var(--color-error-900)]/30 flex items-center justify-center">
              <svg class="w-5 h-5 text-[var(--color-error-500)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
          </div>
        </div>

        <div class="bg-[var(--color-background)] border border-[var(--color-border)] rounded-lg p-4">
          <div class="flex items-center justify-between">
            <div>
              <h3 class="text-sm font-medium text-[var(--color-muted)]">Token Anomalies</h3>
              <p class="text-xl font-bold text-[var(--color-warning-500)]">
                <%= count_by_type(@detections, :token_anomaly) %>
              </p>
            </div>
            <div class="w-10 h-10 rounded-full bg-[var(--color-warning-100)] dark:bg-[var(--color-warning-900)]/30 flex items-center justify-center">
              <svg class="w-5 h-5 text-[var(--color-warning-500)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" />
              </svg>
            </div>
          </div>
        </div>

        <div class="bg-[var(--color-background)] border border-[var(--color-border)] rounded-lg p-4">
          <div class="flex items-center justify-between">
            <div>
              <h3 class="text-sm font-medium text-[var(--color-muted)]">Output Blocks</h3>
              <p class="text-xl font-bold text-[var(--color-error-500)]">
                <%= count_by_type(@detections, :output_validation) %>
              </p>
            </div>
            <div class="w-10 h-10 rounded-full bg-[var(--color-error-100)] dark:bg-[var(--color-error-900)]/30 flex items-center justify-center">
              <svg class="w-5 h-5 text-[var(--color-error-500)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
              </svg>
            </div>
          </div>
        </div>
      </div>

      <!-- Real-time Threat Feed -->
      <div class="bg-[var(--color-background)] border border-[var(--color-border)] rounded-lg overflow-hidden">
        <div class="px-4 py-3 border-b border-[var(--color-border)]">
          <h2 class="text-lg font-semibold text-[var(--color-foreground)]">Real-time Threat Feed</h2>
          <p class="text-sm text-[var(--color-muted)]">Last 10 detections across all categories</p>
        </div>

        <%= if Enum.empty?(@threat_feed) do %>
          <div class="p-8 text-center text-[var(--color-muted)]">
            <svg class="mx-auto h-12 w-12 text-[var(--color-success-500)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <p class="mt-2">No threats detected recently</p>
            <p class="text-sm">AI runtime is operating normally</p>
          </div>
        <% else %>
          <div class="divide-y divide-[var(--color-border)]">
            <%= for item <- @threat_feed do %>
              <div class="px-4 py-3 hover:bg-[var(--color-neutral-50)] dark:hover:bg-[var(--color-neutral-900)]/50">
                <div class="flex items-center justify-between">
                  <div class="flex items-center gap-3">
                    <%= threat_type_icon(item.type) %>
                    <div>
                      <p class="text-sm font-medium text-[var(--color-foreground)]">
                        <%= threat_type_label(item.type) %>
                      </p>
                      <p class="text-xs text-[var(--color-muted)]">
                        <%= threat_summary(item) %>
                      </p>
                    </div>
                  </div>
                  <div class="flex items-center gap-3">
                    <%= severity_badge(item) %>
                    <span class="text-xs text-[var(--color-muted)]">
                      <%= format_relative_time(item.timestamp) %>
                    </span>
                  </div>
                </div>
              </div>
            <% end %>
          </div>
        <% end %>
      </div>
    </div>
    """
  end

  defp render_sessions_tab(assigns) do
    ~H"""
    <div class="space-y-4">
      <div class="bg-[var(--color-background)] border border-[var(--color-border)] rounded-lg overflow-hidden">
        <div class="px-4 py-3 border-b border-[var(--color-border)]">
          <h2 class="text-lg font-semibold text-[var(--color-foreground)]">Active Inference Sessions</h2>
        </div>

        <%= if Enum.empty?(@sessions) do %>
          <div class="p-8 text-center text-[var(--color-muted)]">
            <svg class="mx-auto h-12 w-12 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
            </svg>
            <p class="mt-2">No active inference sessions</p>
            <p class="text-sm">Sessions will appear here when LLM inference is detected</p>
          </div>
        <% else %>
          <div class="overflow-x-auto">
            <table class="w-full">
              <thead class="bg-[var(--color-neutral-50)] dark:bg-[var(--color-neutral-900)]">
                <tr>
                  <th class="px-4 py-3 text-left text-xs font-medium text-[var(--color-muted)] uppercase tracking-wider">Session ID</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-[var(--color-muted)] uppercase tracking-wider">Model</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-[var(--color-muted)] uppercase tracking-wider">Agent</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-[var(--color-muted)] uppercase tracking-wider">Started</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-[var(--color-muted)] uppercase tracking-wider">Requests</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-[var(--color-muted)] uppercase tracking-wider">Status</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-[var(--color-border)]">
                <%= for session <- @sessions do %>
                  <tr
                    class="hover:bg-[var(--color-neutral-50)] dark:hover:bg-[var(--color-neutral-900)]/50 cursor-pointer"
                    phx-click="expand_session"
                    phx-value-session_id={session.session_id}
                  >
                    <td class="px-4 py-3 text-sm font-mono text-[var(--color-foreground)]">
                      <%= truncate_id(session.session_id) %>
                    </td>
                    <td class="px-4 py-3 text-sm text-[var(--color-muted)]">
                      <%= get_model(session) || "Unknown" %>
                    </td>
                    <td class="px-4 py-3 text-sm text-[var(--color-muted)]">
                      <%= session.agent_id %>
                    </td>
                    <td class="px-4 py-3 text-sm text-[var(--color-muted)]">
                      <%= format_timestamp(session.created_at) %>
                    </td>
                    <td class="px-4 py-3 text-sm text-[var(--color-muted)]">
                      <%= get_request_count(session) %>
                    </td>
                    <td class="px-4 py-3">
                      <%= session_status_badge(session.status) %>
                    </td>
                  </tr>
                  <%= if @expanded_session == session.session_id do %>
                    <tr class="bg-[var(--color-neutral-50)] dark:bg-[var(--color-neutral-900)]/30">
                      <td colspan="6" class="px-4 py-4">
                        <div class="space-y-3">
                          <div>
                            <h4 class="text-sm font-medium text-[var(--color-foreground)]">Request Details</h4>
                            <div class="mt-2 grid grid-cols-2 gap-4 text-sm">
                              <div>
                                <span class="text-[var(--color-muted)]">Process:</span>
                                <span class="ml-2 font-mono"><%= get_process_name(session) %></span>
                              </div>
                              <div>
                                <span class="text-[var(--color-muted)]">Provider:</span>
                                <span class="ml-2"><%= get_provider(session) %></span>
                              </div>
                              <div>
                                <span class="text-[var(--color-muted)]">Latency:</span>
                                <span class="ml-2"><%= get_latency(session) %></span>
                              </div>
                              <div>
                                <span class="text-[var(--color-muted)]">Tokens:</span>
                                <span class="ml-2"><%= get_token_count(session) %></span>
                              </div>
                            </div>
                          </div>
                          <%= if session.request && session.request[:prompt_preview] do %>
                            <div>
                              <h4 class="text-sm font-medium text-[var(--color-foreground)]">Prompt Preview</h4>
                              <p class="mt-1 text-sm text-[var(--color-muted)] font-mono bg-[var(--color-neutral-100)] dark:bg-[var(--color-neutral-800)] p-2 rounded truncate">
                                <%= session.request[:prompt_preview] %>
                              </p>
                            </div>
                          <% end %>
                        </div>
                      </td>
                    </tr>
                  <% end %>
                <% end %>
              </tbody>
            </table>
          </div>
        <% end %>
      </div>
    </div>
    """
  end

  defp render_detections_tab(assigns) do
    ~H"""
    <div class="space-y-4">
      <!-- Filters -->
      <div class="flex gap-4 items-end">
        <div>
          <label class="block text-sm font-medium text-[var(--color-muted)] mb-1">Type</label>
          <select
            phx-change="filter_detections"
            name="type"
            class="px-3 py-2 bg-[var(--color-background)] border border-[var(--color-border)] rounded-lg text-sm text-[var(--color-foreground)]"
          >
            <option value="" selected={is_nil(@detection_filter.type)}>All Types</option>
            <option value="prompt_injection" selected={@detection_filter.type == :prompt_injection}>Prompt Injection</option>
            <option value="token_anomaly" selected={@detection_filter.type == :token_anomaly}>Token Anomaly</option>
            <option value="output_validation" selected={@detection_filter.type == :output_validation}>Output Validation</option>
          </select>
        </div>
        <div>
          <label class="block text-sm font-medium text-[var(--color-muted)] mb-1">Severity</label>
          <select
            phx-change="filter_detections"
            name="severity"
            class="px-3 py-2 bg-[var(--color-background)] border border-[var(--color-border)] rounded-lg text-sm text-[var(--color-foreground)]"
          >
            <option value="" selected={is_nil(@detection_filter.severity)}>All Severities</option>
            <option value="critical" selected={@detection_filter.severity == :critical}>Critical</option>
            <option value="high" selected={@detection_filter.severity == :high}>High</option>
            <option value="medium" selected={@detection_filter.severity == :medium}>Medium</option>
            <option value="low" selected={@detection_filter.severity == :low}>Low</option>
          </select>
        </div>
        <div>
          <label class="block text-sm font-medium text-[var(--color-muted)] mb-1">Time Range</label>
          <select
            phx-change="filter_detections"
            name="time_range"
            class="px-3 py-2 bg-[var(--color-background)] border border-[var(--color-border)] rounded-lg text-sm text-[var(--color-foreground)]"
          >
            <option value="1h" selected={@detection_filter.time_range == "1h"}>Last Hour</option>
            <option value="24h" selected={@detection_filter.time_range == "24h"}>Last 24 Hours</option>
            <option value="7d" selected={@detection_filter.time_range == "7d"}>Last 7 Days</option>
          </select>
        </div>
      </div>

      <!-- Detections Table -->
      <div class="bg-[var(--color-background)] border border-[var(--color-border)] rounded-lg overflow-hidden">
        <div class="px-4 py-3 border-b border-[var(--color-border)]">
          <h2 class="text-lg font-semibold text-[var(--color-foreground)]">AI Security Detections</h2>
        </div>

        <%= if Enum.empty?(filter_detections(@detections, @detection_filter)) do %>
          <div class="p-8 text-center text-[var(--color-muted)]">
            <svg class="mx-auto h-12 w-12 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <p class="mt-2">No detections match the current filters</p>
          </div>
        <% else %>
          <div class="overflow-x-auto">
            <table class="w-full">
              <thead class="bg-[var(--color-neutral-50)] dark:bg-[var(--color-neutral-900)]">
                <tr>
                  <th class="px-4 py-3 text-left text-xs font-medium text-[var(--color-muted)] uppercase tracking-wider">Time</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-[var(--color-muted)] uppercase tracking-wider">Type</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-[var(--color-muted)] uppercase tracking-wider">Details</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-[var(--color-muted)] uppercase tracking-wider">Confidence</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-[var(--color-muted)] uppercase tracking-wider">Severity</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-[var(--color-border)]">
                <%= for detection <- filter_detections(@detections, @detection_filter) do %>
                  <tr class="hover:bg-[var(--color-neutral-50)] dark:hover:bg-[var(--color-neutral-900)]/50">
                    <td class="px-4 py-3 text-sm text-[var(--color-muted)]">
                      <%= format_timestamp(detection.timestamp) %>
                    </td>
                    <td class="px-4 py-3">
                      <%= detection_type_badge(detection.type) %>
                    </td>
                    <td class="px-4 py-3 text-sm text-[var(--color-foreground)] max-w-xs truncate">
                      <%= detection_details(detection) %>
                    </td>
                    <td class="px-4 py-3 text-sm">
                      <%= confidence_display(detection) %>
                    </td>
                    <td class="px-4 py-3">
                      <%= severity_badge(detection) %>
                    </td>
                  </tr>
                <% end %>
              </tbody>
            </table>
          </div>
        <% end %>
      </div>
    </div>
    """
  end

  defp render_kill_switch_tab(assigns) do
    ~H"""
    <div class="space-y-4">
      <div class="bg-[var(--color-background)] border border-[var(--color-border)] rounded-lg p-6">
        <div class="flex items-center justify-between mb-4">
          <div>
            <h2 class="text-lg font-semibold text-[var(--color-foreground)]">Kill Switch Status</h2>
            <p class="text-sm text-[var(--color-muted)]">
              <%= @stats.armed_count %> of <%= @stats.total_models %> models armed
            </p>
          </div>
          <.link
            navigate={~p"/live/runtime/kill-switch"}
            class="px-4 py-2 text-sm font-medium text-white bg-[var(--color-primary-600)] hover:bg-[var(--color-primary-700)] rounded-lg transition-colors"
          >
            Open Full Dashboard
          </.link>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div class="p-4 bg-[var(--color-success-100)] dark:bg-[var(--color-success-900)]/20 rounded-lg">
            <h3 class="text-sm font-medium text-[var(--color-success-700)] dark:text-[var(--color-success-300)]">Active (Safe)</h3>
            <p class="text-2xl font-bold text-[var(--color-success-600)]">
              <%= @stats.active_safe %>
            </p>
          </div>
          <div class="p-4 bg-[var(--color-warning-100)] dark:bg-[var(--color-warning-900)]/20 rounded-lg">
            <h3 class="text-sm font-medium text-[var(--color-warning-700)] dark:text-[var(--color-warning-300)]">Armed</h3>
            <p class="text-2xl font-bold text-[var(--color-warning-600)]">
              <%= @stats.armed_count %>
            </p>
          </div>
          <div class="p-4 bg-[var(--color-error-100)] dark:bg-[var(--color-error-900)]/20 rounded-lg">
            <h3 class="text-sm font-medium text-[var(--color-error-700)] dark:text-[var(--color-error-300)]">Triggered (Isolated)</h3>
            <p class="text-2xl font-bold text-[var(--color-error-600)]">
              <%= @stats.triggered_count %>
            </p>
          </div>
        </div>

        <div class="mt-6 flex gap-4">
          <button
            phx-click="arm_all"
            class="px-4 py-2 text-sm font-medium text-[var(--color-warning-700)] bg-[var(--color-warning-100)] hover:bg-[var(--color-warning-200)] dark:text-[var(--color-warning-300)] dark:bg-[var(--color-warning-900)]/30 dark:hover:bg-[var(--color-warning-900)]/50 rounded-lg transition-colors"
          >
            Arm All Kill Switches
          </button>
        </div>
      </div>
    </div>
    """
  end

  # ============================================================================
  # Data Loading
  # ============================================================================

  defp load_data(socket) do
    socket
    |> load_stats()
    |> load_sessions()
    |> load_detections()
    |> assign(:loading, false)
  end

  defp load_stats(socket) do
    stats = %{
      active_sessions: safe_count_sessions(),
      armed_count: safe_count_armed(),
      total_models: safe_count_models(),
      blocked_outputs: safe_count_blocked(),
      threats_today: safe_count_threats_today(),
      active_safe: safe_count_active_safe(),
      triggered_count: safe_count_triggered()
    }

    assign(socket, :stats, stats)
  end

  defp load_sessions(socket) do
    sessions = safe_load_sessions()
    assign(socket, :sessions, sessions)
  end

  defp load_detections(socket) do
    # Detections are primarily populated via PubSub
    # This loads any persisted detections if available
    socket
  end

  defp update_session_count(socket) do
    stats = Map.put(socket.assigns.stats, :active_sessions, length(socket.assigns.sessions))
    assign(socket, :stats, stats)
  end

  defp update_threat_count(socket) do
    stats = Map.put(socket.assigns.stats, :threats_today, length(socket.assigns.threat_feed))
    assign(socket, :stats, stats)
  end

  # ============================================================================
  # Safe Data Access Functions
  # ============================================================================

  defp safe_count_sessions do
    try do
      :ets.info(:inference_tracker, :size) || 0
    rescue
      _ -> 0
    end
  end

  defp safe_count_armed do
    try do
      :ets.tab2list(:kill_switch_state)
      |> Enum.count(fn {_id, state} -> is_map(state) and Map.get(state, :armed, false) end)
    rescue
      _ -> 0
    end
  end

  defp safe_count_models do
    try do
      :ets.tab2list(:model_isolation_state)
      |> length()
    rescue
      _ -> 0
    end
  end

  defp safe_count_blocked do
    # Count output validation blocks from today
    try do
      # This would query from database or ETS if available
      0
    rescue
      _ -> 0
    end
  end

  defp safe_count_threats_today do
    # Count all detections from today
    0
  end

  defp safe_count_active_safe do
    try do
      :ets.tab2list(:model_isolation_state)
      |> Enum.count(fn {_id, state} ->
        is_map(state) and not Map.get(state, :triggered, false) and not safe_is_armed?(state.model_id)
      end)
    rescue
      _ -> 0
    end
  end

  defp safe_is_armed?(model_id) do
    try do
      case :ets.lookup(:kill_switch_state, model_id) do
        [{^model_id, state}] -> Map.get(state, :armed, false)
        _ -> false
      end
    rescue
      _ -> false
    end
  end

  defp safe_count_triggered do
    try do
      :ets.tab2list(:kill_switch_state)
      |> Enum.count(fn {_id, state} -> is_map(state) and Map.get(state, :triggered, false) end)
    rescue
      _ -> 0
    end
  end

  defp safe_load_sessions do
    try do
      :ets.tab2list(:inference_tracker)
      |> Enum.map(fn {_key, session} -> session end)
      |> Enum.filter(&is_map/1)
      |> Enum.sort_by(& &1.created_at, {:desc, DateTime})
      |> Enum.take(50)
    rescue
      _ -> []
    end
  end

  # ============================================================================
  # Helpers
  # ============================================================================

  defp default_stats do
    %{
      active_sessions: 0,
      armed_count: 0,
      total_models: 0,
      blocked_outputs: 0,
      threats_today: 0,
      active_safe: 0,
      triggered_count: 0
    }
  end

  defp parse_tab("sessions"), do: :sessions
  defp parse_tab("detections"), do: :detections
  defp parse_tab("kill_switch"), do: :kill_switch
  defp parse_tab(_), do: :overview

  defp parse_detection_type(nil), do: nil
  defp parse_detection_type(""), do: nil
  defp parse_detection_type("prompt_injection"), do: :prompt_injection
  defp parse_detection_type("token_anomaly"), do: :token_anomaly
  defp parse_detection_type("output_validation"), do: :output_validation
  defp parse_detection_type(:prompt_injection), do: :prompt_injection
  defp parse_detection_type(:token_anomaly), do: :token_anomaly
  defp parse_detection_type(:output_validation), do: :output_validation
  defp parse_detection_type(_), do: nil

  defp parse_detection_severity(nil), do: nil
  defp parse_detection_severity(""), do: nil
  defp parse_detection_severity("critical"), do: :critical
  defp parse_detection_severity("high"), do: :high
  defp parse_detection_severity("medium"), do: :medium
  defp parse_detection_severity("low"), do: :low
  defp parse_detection_severity(:critical), do: :critical
  defp parse_detection_severity(:high), do: :high
  defp parse_detection_severity(:medium), do: :medium
  defp parse_detection_severity(:low), do: :low
  defp parse_detection_severity(_), do: nil

  defp parse_time_range("1h"), do: "1h"
  defp parse_time_range("24h"), do: "24h"
  defp parse_time_range("7d"), do: "7d"
  defp parse_time_range(_), do: "24h"

  defp generate_id, do: :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)

  defp truncate_id(id) when is_binary(id) and byte_size(id) > 16 do
    String.slice(id, 0, 8) <> "..."
  end

  defp truncate_id(id), do: id

  defp format_timestamp(nil), do: "-"

  defp format_timestamp(%DateTime{} = dt) do
    Calendar.strftime(dt, "%H:%M:%S")
  end

  defp format_timestamp(_), do: "-"

  defp format_relative_time(%DateTime{} = dt) do
    diff = DateTime.diff(DateTime.utc_now(), dt, :second)

    cond do
      diff < 60 -> "#{diff}s ago"
      diff < 3600 -> "#{div(diff, 60)}m ago"
      diff < 86400 -> "#{div(diff, 3600)}h ago"
      true -> Calendar.strftime(dt, "%b %d")
    end
  end

  defp format_relative_time(_), do: "-"

  defp count_by_type(detections, type) do
    Enum.count(detections, fn d -> d.type == type end)
  end

  defp filter_detections(detections, %{type: type, severity: severity}) do
    detections
    |> Enum.filter(fn d ->
      (is_nil(type) or d.type == type) and
        (is_nil(severity) or get_severity(d) == severity)
    end)
  end

  defp get_severity(%{detection: d}) when is_map(d) do
    d[:severity] || d["severity"] || d[:overall_risk] || d["overall_risk"] || :medium
  end

  defp get_severity(_), do: :medium

  defp get_model(%{request: %{model: model}}) when not is_nil(model), do: model
  defp get_model(%{request: request}) when is_map(request), do: request[:model] || request["model"]
  defp get_model(_), do: nil

  defp get_process_name(%{request: %{process_name: name}}) when not is_nil(name), do: name
  defp get_process_name(%{request: request}) when is_map(request), do: request[:process_name] || "Unknown"
  defp get_process_name(_), do: "Unknown"

  defp get_provider(%{request: %{api_provider: provider}}) when not is_nil(provider), do: to_string(provider)
  defp get_provider(%{request: request}) when is_map(request), do: request[:api_provider] || "Unknown"
  defp get_provider(_), do: "Unknown"

  defp get_latency(%{metrics: %{latency_ms: ms}}) when not is_nil(ms), do: "#{ms}ms"
  defp get_latency(_), do: "-"

  defp get_token_count(%{metrics: %{token_count: tc}}) when is_map(tc) do
    "#{tc[:total_tokens] || tc["total_tokens"] || 0}"
  end

  defp get_token_count(_), do: "-"

  defp get_request_count(%{metrics: %{request_count: c}}) when not is_nil(c), do: c
  defp get_request_count(_), do: 1

  # ============================================================================
  # Component Helpers
  # ============================================================================

  defp threat_type_icon(:prompt_injection) do
    Phoenix.HTML.raw("""
    <div class="w-8 h-8 rounded-full bg-red-100 dark:bg-red-900/30 flex items-center justify-center">
      <svg class="w-4 h-4 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
      </svg>
    </div>
    """)
  end

  defp threat_type_icon(:token_anomaly) do
    Phoenix.HTML.raw("""
    <div class="w-8 h-8 rounded-full bg-yellow-100 dark:bg-yellow-900/30 flex items-center justify-center">
      <svg class="w-4 h-4 text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" />
      </svg>
    </div>
    """)
  end

  defp threat_type_icon(:output_validation) do
    Phoenix.HTML.raw("""
    <div class="w-8 h-8 rounded-full bg-red-100 dark:bg-red-900/30 flex items-center justify-center">
      <svg class="w-4 h-4 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
      </svg>
    </div>
    """)
  end

  defp threat_type_icon(_) do
    Phoenix.HTML.raw("""
    <div class="w-8 h-8 rounded-full bg-gray-100 dark:bg-gray-800 flex items-center justify-center">
      <svg class="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
      </svg>
    </div>
    """)
  end

  defp threat_type_label(:prompt_injection), do: "Prompt Injection Detected"
  defp threat_type_label(:token_anomaly), do: "Token Anomaly Detected"
  defp threat_type_label(:output_validation), do: "Output Blocked"
  defp threat_type_label(_), do: "Detection"

  defp threat_summary(%{detection: d}) when is_map(d) do
    cond do
      d[:injection_type] -> "Type: #{d[:injection_type]}"
      d[:anomaly_type] -> "Anomaly: #{d[:anomaly_type]}"
      d[:overall_risk] -> "Risk level: #{d[:overall_risk]}"
      d[:violations] && is_list(d[:violations]) -> Enum.join(d[:violations], ", ")
      true -> "Detection triggered"
    end
  end

  defp threat_summary(_), do: "Detection triggered"

  defp severity_badge(%{detection: d}) when is_map(d) do
    severity = d[:severity] || d[:overall_risk] || :medium
    severity_badge_html(severity)
  end

  defp severity_badge(_), do: severity_badge_html(:medium)

  defp severity_badge_html(:critical) do
    Phoenix.HTML.raw("""
    <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300">
      Critical
    </span>
    """)
  end

  defp severity_badge_html(:high) do
    Phoenix.HTML.raw("""
    <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300">
      High
    </span>
    """)
  end

  defp severity_badge_html(:medium) do
    Phoenix.HTML.raw("""
    <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300">
      Medium
    </span>
    """)
  end

  defp severity_badge_html(_) do
    Phoenix.HTML.raw("""
    <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300">
      Low
    </span>
    """)
  end

  defp session_status_badge(:pending) do
    Phoenix.HTML.raw("""
    <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300">
      <span class="w-1.5 h-1.5 mr-1 rounded-full bg-yellow-500 animate-pulse"></span>
      Pending
    </span>
    """)
  end

  defp session_status_badge(:complete) do
    Phoenix.HTML.raw("""
    <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300">
      Complete
    </span>
    """)
  end

  defp session_status_badge(:error) do
    Phoenix.HTML.raw("""
    <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300">
      Error
    </span>
    """)
  end

  defp session_status_badge(:timeout) do
    Phoenix.HTML.raw("""
    <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-300">
      Timeout
    </span>
    """)
  end

  defp session_status_badge(_) do
    Phoenix.HTML.raw("""
    <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-300">
      Unknown
    </span>
    """)
  end

  defp detection_type_badge(:prompt_injection) do
    Phoenix.HTML.raw("""
    <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300">
      Prompt Injection
    </span>
    """)
  end

  defp detection_type_badge(:token_anomaly) do
    Phoenix.HTML.raw("""
    <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300">
      Token Anomaly
    </span>
    """)
  end

  defp detection_type_badge(:output_validation) do
    Phoenix.HTML.raw("""
    <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300">
      Output Validation
    </span>
    """)
  end

  defp detection_type_badge(_) do
    Phoenix.HTML.raw("""
    <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-300">
      Unknown
    </span>
    """)
  end

  defp detection_details(%{type: :prompt_injection, detection: d}) when is_map(d) do
    d[:injection_type] || d[:pattern_matched] || "Injection pattern detected"
  end

  defp detection_details(%{type: :token_anomaly, detection: d}) when is_map(d) do
    type = d[:anomaly_type] || "anomaly"
    score = d[:anomaly_score]

    if score, do: "#{type} (score: #{Float.round(score * 100, 1)}%)", else: to_string(type)
  end

  defp detection_details(%{type: :output_validation, detection: d}) when is_map(d) do
    violations = d[:violations] || []

    if Enum.empty?(violations) do
      "Risk: #{d[:overall_risk] || "unknown"}"
    else
      Enum.join(violations, ", ")
    end
  end

  defp detection_details(_), do: "Detection triggered"

  defp confidence_display(%{detection: d}) when is_map(d) do
    confidence = d[:confidence] || d[:anomaly_score]

    if confidence do
      pct = Float.round(confidence * 100, 1)

      color =
        cond do
          pct >= 80 -> "text-red-600"
          pct >= 50 -> "text-yellow-600"
          true -> "text-green-600"
        end

      Phoenix.HTML.raw(~s(<span class="#{color} font-medium">#{pct}%</span>))
    else
      Phoenix.HTML.raw(~s(<span class="text-gray-400">-</span>))
    end
  end

  defp confidence_display(_), do: Phoenix.HTML.raw(~s(<span class="text-gray-400">-</span>))
end
