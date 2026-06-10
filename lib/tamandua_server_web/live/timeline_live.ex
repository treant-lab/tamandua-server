defmodule TamanduaServerWeb.TimelineLive do
  @moduledoc """
  LiveView component for Attack Timeline visualization.

  Provides an interactive view of attack progression:
  - Process tree visualization
  - Kill chain phase progression
  - Event timeline
  - Network/file correlation
  - Real-time updates

  This is similar to SentinelOne Storyline but built with Phoenix LiveView.
  """

  use TamanduaServerWeb, :live_view

  alias TamanduaServer.Detection.Timeline
  alias TamanduaServer.Alerts

  @impl true
  def mount(%{"id" => alert_id}, session, socket) do
    organization_id = session["organization_id"] || get_default_org_id()

    if connected?(socket) do
      # Subscribe to updates for this alert
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "alert:#{alert_id}")
    end

    # Use tenant-scoped lookup to prevent BOLA/IDOR
    case Alerts.get_alert_for_org(organization_id, alert_id) do
      {:ok, alert} ->
        timeline_data = Timeline.build_timeline(alert_id)

        {:ok,
         socket
         |> assign(:organization_id, organization_id)
         |> assign(:alert, alert)
         |> assign(:timeline, timeline_data)
         |> assign(:view_mode, :timeline)
         |> assign(:selected_event, nil)
         |> assign(:expanded_nodes, MapSet.new())
         |> assign(:filter, %{event_type: nil, severity: nil})}

      {:error, :not_found} ->
        {:ok,
         socket
         |> put_flash(:error, "Alert not found")
         |> redirect(to: ~p"/alerts")}
    end
  end

  defp get_default_org_id, do: nil

  @impl true
  def handle_params(params, _url, socket) do
    {:noreply, apply_action(socket, socket.assigns.live_action, params)}
  end

  defp apply_action(socket, :show, _params) do
    socket
  end

  defp apply_action(socket, :process_tree, _params) do
    assign(socket, :view_mode, :process_tree)
  end

  defp apply_action(socket, :mitre, _params) do
    assign(socket, :view_mode, :mitre)
  end

  @impl true
  def handle_event("toggle_node", %{"pid" => pid}, socket) do
    pid = String.to_integer(pid)
    expanded = socket.assigns.expanded_nodes

    expanded = if MapSet.member?(expanded, pid) do
      MapSet.delete(expanded, pid)
    else
      MapSet.put(expanded, pid)
    end

    {:noreply, assign(socket, :expanded_nodes, expanded)}
  end

  @impl true
  def handle_event("select_event", %{"index" => index}, socket) do
    index = String.to_integer(index)
    events = socket.assigns.timeline.timeline || []
    event = Enum.at(events, index)

    {:noreply, assign(socket, :selected_event, event)}
  end

  @impl true
  def handle_event("switch_view", %{"mode" => mode}, socket) do
    mode = String.to_existing_atom(mode)
    {:noreply, assign(socket, :view_mode, mode)}
  end

  @impl true
  def handle_event("filter", %{"type" => type}, socket) do
    filter = socket.assigns.filter
    type = if type == "", do: nil, else: type
    {:noreply, assign(socket, :filter, %{filter | event_type: type})}
  end

  @impl true
  def handle_info({:alert_updated, alert}, socket) do
    timeline_data = Timeline.build_timeline(alert.id)
    {:noreply,
     socket
     |> assign(:alert, alert)
     |> assign(:timeline, timeline_data)}
  end

  @impl true
  def handle_info(_msg, socket), do: {:noreply, socket}

  @impl true
  def render(assigns) do
    ~H"""
    <div class="attack-timeline-container">
      <header class="mb-6">
        <div class="flex items-center justify-between">
          <div>
            <div class="flex items-center gap-4">
              <span class="text-xl font-bold">Attack Timeline</span>
              <.severity_badge severity={@alert.severity} />
            </div>
            <p class="text-gray-600 mt-1">
              Alert: <%= @alert.title %>
              <span class="text-gray-500 ml-4">
                Duration: <%= format_duration(@timeline.metrics.duration_seconds) %>
              </span>
            </p>
          </div>
          <div>
            <.view_switcher current={@view_mode} />
          </div>
        </div>
      </header>

      <!-- Attack Metrics Summary -->
      <div class="grid grid-cols-4 gap-4 mt-6 mb-6">
        <.metric_card
          label="Events"
          value={@timeline.metrics.total_events}
          icon="activity"
        />
        <.metric_card
          label="Processes"
          value={@timeline.metrics.unique_processes}
          icon="cpu"
        />
        <.metric_card
          label="Network"
          value={@timeline.metrics.network_connections}
          icon="globe"
        />
        <.metric_card
          label="MITRE Techniques"
          value={@timeline.metrics.mitre_techniques_count}
          icon="shield"
        />
      </div>

      <!-- MITRE Kill Chain Progression -->
      <div class="mb-6">
        <h3 class="text-lg font-semibold mb-3">Kill Chain Progression</h3>
        <.kill_chain_progress phases={@timeline.mitre_progression} />
      </div>

      <!-- Main Content Area -->
      <div class="grid grid-cols-3 gap-6">
        <!-- Timeline/Tree View (2/3) -->
        <div class="col-span-2">
          <%= case @view_mode do %>
            <% :timeline -> %>
              <.timeline_view
                events={filter_events(@timeline, @filter)}
                selected={@selected_event}
              />
            <% :process_tree -> %>
              <.process_tree_view
                tree={@timeline.process_tree}
                expanded={@expanded_nodes}
              />
            <% :mitre -> %>
              <.mitre_view
                progression={@timeline.mitre_progression}
                events={@timeline}
              />
          <% end %>
        </div>

        <!-- Event Details Panel (1/3) -->
        <div class="col-span-1">
          <.event_details event={@selected_event} />
        </div>
      </div>

      <!-- Attack Summary -->
      <div class="mt-6 p-4 bg-gray-50 rounded-lg">
        <h3 class="text-lg font-semibold mb-2">Attack Summary</h3>
        <p class="text-gray-700"><%= @timeline.summary %></p>
      </div>
    </div>
    """
  end

  # ============================================================================
  # Components
  # ============================================================================

  attr :severity, :string, required: true
  defp severity_badge(assigns) do
    color = case assigns.severity do
      "critical" -> "bg-red-600"
      "high" -> "bg-orange-500"
      "medium" -> "bg-yellow-500"
      "low" -> "bg-blue-500"
      _ -> "bg-gray-500"
    end

    assigns = assign(assigns, :color, color)

    ~H"""
    <span class={"px-2 py-1 rounded text-white text-sm font-medium #{@color}"}>
      <%= String.upcase(@severity) %>
    </span>
    """
  end

  attr :current, :atom, required: true
  defp view_switcher(assigns) do
    ~H"""
    <div class="flex gap-2">
      <button
        phx-click="switch_view"
        phx-value-mode="timeline"
        class={"px-3 py-1 rounded #{if @current == :timeline, do: "bg-blue-600 text-white", else: "bg-gray-200"}"}
      >
        Timeline
      </button>
      <button
        phx-click="switch_view"
        phx-value-mode="process_tree"
        class={"px-3 py-1 rounded #{if @current == :process_tree, do: "bg-blue-600 text-white", else: "bg-gray-200"}"}
      >
        Process Tree
      </button>
      <button
        phx-click="switch_view"
        phx-value-mode="mitre"
        class={"px-3 py-1 rounded #{if @current == :mitre, do: "bg-blue-600 text-white", else: "bg-gray-200"}"}
      >
        MITRE View
      </button>
    </div>
    """
  end

  attr :label, :string, required: true
  attr :value, :any, required: true
  attr :icon, :string, required: true
  defp metric_card(assigns) do
    ~H"""
    <div class="bg-white p-4 rounded-lg shadow">
      <div class="flex items-center justify-between">
        <span class="text-gray-600"><%= @label %></span>
        <.timeline_icon name={@icon} class="w-5 h-5 text-gray-400" />
      </div>
      <div class="text-2xl font-bold mt-2"><%= @value %></div>
    </div>
    """
  end

  attr :phases, :list, required: true
  defp kill_chain_progress(assigns) do
    all_phases = [
      {"initial_access", "Initial Access"},
      {"execution", "Execution"},
      {"persistence", "Persistence"},
      {"privilege_escalation", "Priv Esc"},
      {"defense_evasion", "Defense Evasion"},
      {"credential_access", "Cred Access"},
      {"discovery", "Discovery"},
      {"lateral_movement", "Lateral Move"},
      {"collection", "Collection"},
      {"c2", "C2"},
      {"exfiltration", "Exfiltration"},
      {"impact", "Impact"}
    ]

    active_phases = assigns.phases |> Enum.map(& &1.phase) |> MapSet.new()
    assigns = assign(assigns, :all_phases, all_phases)
    assigns = assign(assigns, :active_phases, active_phases)

    ~H"""
    <div class="flex gap-1 overflow-x-auto">
      <%= for {phase_id, phase_name} <- @all_phases do %>
        <div class={
          "flex-shrink-0 px-3 py-2 rounded text-sm text-center min-w-[80px] " <>
          if MapSet.member?(@active_phases, phase_id), do: "bg-red-600 text-white", else: "bg-gray-200 text-gray-600"
        }>
          <%= phase_name %>
        </div>
      <% end %>
    </div>
    """
  end

  attr :events, :list, required: true
  attr :selected, :map, default: nil
  defp timeline_view(assigns) do
    ~H"""
    <div class="bg-white rounded-lg shadow p-4">
      <h3 class="text-lg font-semibold mb-4">Event Timeline</h3>
      <div class="relative">
        <!-- Timeline line -->
        <div class="absolute left-6 top-0 bottom-0 w-0.5 bg-gray-200"></div>

        <!-- Events -->
        <div class="space-y-4">
          <%= for {event, idx} <- Enum.with_index(@events || []) do %>
            <div
              phx-click="select_event"
              phx-value-index={idx}
              class={
                "relative pl-14 cursor-pointer p-3 rounded-lg transition " <>
                if @selected && @selected.timestamp == event.timestamp, do: "bg-blue-50 ring-2 ring-blue-500", else: "hover:bg-gray-50"
              }
            >
              <!-- Event icon -->
              <div class={
                "absolute left-4 w-5 h-5 rounded-full flex items-center justify-center " <>
                severity_color(event.severity)
              }>
                <.timeline_icon name={event.icon || "activity"} class="w-3 h-3 text-white" />
              </div>

              <!-- Event content -->
              <div class="flex justify-between items-start">
                <div>
                  <div class="font-medium"><%= event.description %></div>
                  <div class="text-sm text-gray-500">
                    <%= format_timestamp(event.timestamp) %>
                  </div>
                </div>
                <.severity_badge severity={event.severity || "info"} />
              </div>
            </div>
          <% end %>
        </div>
      </div>
    </div>
    """
  end

  attr :tree, :list, required: true
  attr :expanded, MapSet, required: true
  defp process_tree_view(assigns) do
    ~H"""
    <div class="bg-white rounded-lg shadow p-4">
      <h3 class="text-lg font-semibold mb-4">Process Tree</h3>
      <div class="font-mono text-sm">
        <%= for root <- @tree || [] do %>
          <.process_node node={root} depth={0} expanded={@expanded} />
        <% end %>
      </div>
    </div>
    """
  end

  attr :node, :map, required: true
  attr :depth, :integer, required: true
  attr :expanded, MapSet, required: true
  defp process_node(assigns) do
    has_children = length(assigns.node.children || []) > 0
    is_expanded = MapSet.member?(assigns.expanded, assigns.node.pid)
    assigns = assign(assigns, :has_children, has_children)
    assigns = assign(assigns, :is_expanded, is_expanded)

    ~H"""
    <div class="process-node">
      <div
        class="flex items-center gap-2 py-1 hover:bg-gray-100 rounded cursor-pointer"
        style={"padding-left: #{@depth * 20}px"}
        phx-click="toggle_node"
        phx-value-pid={@node.pid}
      >
        <!-- Expand/collapse icon -->
        <%= if @has_children do %>
          <span class="text-gray-400">
            <%= if @is_expanded, do: "[-]", else: "[+]" %>
          </span>
        <% else %>
          <span class="text-gray-400 w-5"></span>
        <% end %>

        <!-- Process icon -->
        <.timeline_icon name="cpu" class="w-4 h-4 text-gray-500" />

        <!-- Process name -->
        <span class={if @node.detections && length(@node.detections) > 0, do: "text-red-600 font-bold", else: ""}>
          <%= @node.name || "unknown" %>
        </span>

        <!-- PID -->
        <span class="text-gray-400 text-xs">(PID: <%= @node.pid %>)</span>

        <!-- Detection indicator -->
        <%= if @node.detections && length(@node.detections) > 0 do %>
          <span class="bg-red-100 text-red-600 text-xs px-1 rounded">
            <%= length(@node.detections) %> detection(s)
          </span>
        <% end %>
      </div>

      <!-- Children -->
      <%= if @is_expanded && @has_children do %>
        <%= for child <- @node.children || [] do %>
          <.process_node node={child} depth={@depth + 1} expanded={@expanded} />
        <% end %>
      <% end %>
    </div>
    """
  end

  attr :progression, :list, required: true
  attr :events, :map, required: true
  defp mitre_view(assigns) do
    ~H"""
    <div class="bg-white rounded-lg shadow p-4">
      <h3 class="text-lg font-semibold mb-4">MITRE ATT&CK Mapping</h3>
      <div class="space-y-4">
        <%= for phase <- @progression do %>
          <div class="border-l-4 border-red-500 pl-4">
            <div class="flex items-center justify-between">
              <span class="font-medium"><%= phase.human_name %></span>
              <span class="text-sm text-gray-500">
                First seen: <%= format_timestamp(phase.first_seen) %>
              </span>
            </div>
            <div class="text-sm text-gray-600 mt-1">
              Phase <%= phase.phase_index + 1 %> of 14 in kill chain
            </div>
          </div>
        <% end %>
      </div>
    </div>
    """
  end

  attr :event, :map, default: nil
  defp event_details(assigns) do
    ~H"""
    <div class="bg-white rounded-lg shadow p-4 sticky top-4">
      <h3 class="text-lg font-semibold mb-4">Event Details</h3>
      <%= if @event do %>
        <div class="space-y-4">
          <div>
            <label class="text-sm text-gray-500">Type</label>
            <div class="font-medium"><%= @event.event_type %></div>
          </div>
          <div>
            <label class="text-sm text-gray-500">Timestamp</label>
            <div class="font-medium"><%= format_timestamp(@event.timestamp) %></div>
          </div>
          <div>
            <label class="text-sm text-gray-500">Severity</label>
            <div><.severity_badge severity={@event.severity || "info"} /></div>
          </div>
          <div>
            <label class="text-sm text-gray-500">Details</label>
            <pre class="mt-1 p-2 bg-gray-50 rounded text-xs overflow-auto max-h-64"><%= Jason.encode!(@event.details || %{}, pretty: true) %></pre>
          </div>
        </div>
      <% else %>
        <div class="text-gray-500 text-center py-8">
          Select an event to view details
        </div>
      <% end %>
    </div>
    """
  end

  # ============================================================================
  # Helpers
  # ============================================================================

  defp filter_events(timeline, %{event_type: nil}), do: timeline.timeline
  defp filter_events(timeline, %{event_type: type}) do
    (timeline.timeline || [])
    |> Enum.filter(fn event -> event.event_type == type end)
  end

  defp format_duration(seconds) when is_number(seconds) do
    cond do
      seconds < 60 -> "#{seconds}s"
      seconds < 3600 -> "#{div(seconds, 60)}m #{rem(seconds, 60)}s"
      true -> "#{div(seconds, 3600)}h #{div(rem(seconds, 3600), 60)}m"
    end
  end
  defp format_duration(_), do: "N/A"

  defp format_timestamp(nil), do: "N/A"
  defp format_timestamp(%DateTime{} = dt) do
    Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S UTC")
  end
  defp format_timestamp(dt) when is_binary(dt), do: dt
  defp format_timestamp(_), do: "N/A"

  defp severity_color("critical"), do: "bg-red-600"
  defp severity_color("high"), do: "bg-orange-500"
  defp severity_color("medium"), do: "bg-yellow-500"
  defp severity_color("low"), do: "bg-blue-500"
  defp severity_color(_), do: "bg-gray-500"

  # Icon component - simplified version
  attr :name, :string, required: true
  attr :class, :string, default: ""
  defp timeline_icon(assigns) do
    ~H"""
    <svg class={@class} fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <%= case @name do %>
        <% "activity" -> %>
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
        <% "cpu" -> %>
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z" />
        <% "globe" -> %>
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        <% "file" -> %>
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
        <% "shield" -> %>
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        <% "server" -> %>
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
        <% "settings" -> %>
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
        <% "alert-triangle" -> %>
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        <% _ -> %>
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
      <% end %>
    </svg>
    """
  end
end
