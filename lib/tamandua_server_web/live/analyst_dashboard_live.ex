defmodule TamanduaServerWeb.AnalystDashboardLive do
  @moduledoc """
  Analyst-centric dashboard showing assigned alerts, workload, and SLA metrics.

  Features:
  - My assigned alerts (grouped by state)
  - Team workload overview
  - SLA compliance metrics
  - Activity feed
  - Quick actions (acknowledge, transition, escalate)
  """

  use TamanduaServerWeb, :live_view

  alias TamanduaServer.Alerts
  alias TamanduaServer.Alerts.{Assignment, SLATracker, Workflow}

  @impl true
  def mount(_params, session, socket) do
    user = get_current_user(session)

    if connected?(socket) and user.id && user.organization_id do
      # Subscribe to real-time updates
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "alerts:#{user.organization_id}")
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "analyst:#{user.id}")
    end

    socket =
      socket
      |> assign(:user, user)
      |> assign(:page_title, "My Dashboard")
      |> assign(:active_tab, "assigned")
      |> assign(:show_action_modal, false)
      |> assign(:selected_alert, nil)
      |> maybe_load_dashboard_data()

    {:ok, socket}
  end

  @impl true
  def handle_params(params, _url, socket) do
    tab = params["tab"] || "assigned"

    socket =
      socket
      |> assign(:active_tab, tab)
      |> load_dashboard_data()

    {:noreply, socket}
  end

  @impl true
  def handle_event("change_tab", %{"tab" => tab}, socket) do
    {:noreply, push_patch(socket, to: ~p"/dashboard/analyst?tab=#{tab}")}
  end

  @impl true
  def handle_event("acknowledge_alert", %{"id" => alert_id}, socket) do
    user = socket.assigns.user
    org_id = user.organization_id

    case Alerts.get_alert_for_org(org_id, alert_id) do
      {:ok, alert} ->
        case SLATracker.mark_acknowledged(alert, user.id) do
          {:ok, _updated_alert} ->
            {:noreply,
             socket
             |> put_flash(:info, "Alert acknowledged")
             |> load_dashboard_data()}

          {:error, _reason} ->
            {:noreply, put_flash(socket, :error, "Failed to acknowledge alert")}
        end

      {:error, :not_found} ->
        {:noreply, put_flash(socket, :error, "Alert not found")}
    end
  end

  @impl true
  def handle_event("open_action_modal", %{"id" => alert_id}, socket) do
    org_id = socket.assigns.user.organization_id

    case Alerts.get_alert_for_org(org_id, alert_id) do
      {:ok, alert} ->
        {:noreply,
         socket
         |> assign(:show_action_modal, true)
         |> assign(:selected_alert, alert)}

      {:error, :not_found} ->
        {:noreply, put_flash(socket, :error, "Alert not found")}
    end
  end

  @impl true
  def handle_event("close_action_modal", _params, socket) do
    {:noreply,
     socket
     |> assign(:show_action_modal, false)
     |> assign(:selected_alert, nil)}
  end

  @impl true
  def handle_event("transition_state", %{"alert_id" => alert_id, "state" => new_state}, socket) do
    user = socket.assigns.user
    org_id = user.organization_id

    case Alerts.get_alert_for_org(org_id, alert_id) do
      {:ok, alert} ->
        case Workflow.transition_state(alert, new_state, user_id: user.id) do
          {:ok, _updated_alert} ->
            {:noreply,
             socket
             |> put_flash(:info, "Alert transitioned to #{new_state}")
             |> assign(:show_action_modal, false)
             |> load_dashboard_data()}

          {:error, :invalid_transition} ->
            {:noreply, put_flash(socket, :error, "Invalid state transition")}

          {:error, _reason} ->
            {:noreply, put_flash(socket, :error, "Failed to transition alert")}
        end

      {:error, :not_found} ->
        {:noreply, put_flash(socket, :error, "Alert not found")}
    end
  end

  @impl true
  def handle_event("set_availability", %{"available" => available}, socket) do
    user = socket.assigns.user
    is_available = available == "true"

    case Assignment.set_analyst_availability(user.id, is_available, user.organization_id) do
      {:ok, _workload} ->
        {:noreply,
         socket
         |> put_flash(:info, "Availability updated")
         |> load_dashboard_data()}

      {:error, _reason} ->
        {:noreply, put_flash(socket, :error, "Failed to update availability")}
    end
  end

  # PubSub event handlers
  @impl true
  def handle_info({:alert_assigned, alert}, socket) do
    if alert.assigned_to_id == socket.assigns.user.id do
      {:noreply,
       socket
       |> put_flash(:info, "New alert assigned: #{alert.title}")
       |> load_dashboard_data()}
    else
      {:noreply, socket}
    end
  end

  @impl true
  def handle_info({:alert_updated, _alert}, socket) do
    {:noreply, load_dashboard_data(socket)}
  end

  @impl true
  def handle_info({:sla_warning, alert}, socket) do
    if alert.assigned_to_id == socket.assigns.user.id do
      {:noreply, put_flash(socket, :warning, "SLA deadline approaching for alert: #{alert.title}")}
    else
      {:noreply, socket}
    end
  end

  @impl true
  def handle_info(_msg, socket), do: {:noreply, socket}

  # Private helpers

  defp maybe_load_dashboard_data(%{assigns: %{user: %{id: nil}}} = socket), do: assign_empty_dashboard(socket)
  defp maybe_load_dashboard_data(%{assigns: %{user: %{organization_id: nil}}} = socket), do: assign_empty_dashboard(socket)
  defp maybe_load_dashboard_data(socket), do: load_dashboard_data(socket)

  defp assign_empty_dashboard(socket) do
    socket
    |> assign(:assigned_alerts, [])
    |> assign(:alerts_by_state, %{})
    |> assign(:my_workload, nil)
    |> assign(:team_workload, [])
    |> assign(:my_sla_metrics, %{})
    |> assign(:approaching_sla, [])
    |> assign(:recent_activity, [])
    |> assign(:verdict_stats, %{
      total_alerts: 0,
      by_verdict: %{},
      false_positive_rate: 0.0,
      reviewed_count: 0,
      unreviewed_count: 0,
      top_fp_rules: [],
      active_suppression_rules: 0,
      total_suppressed: 0,
      days: 30
    })
  end

  defp load_dashboard_data(socket) do
    user = socket.assigns.user

    # Load assigned alerts
    assigned_alerts = Assignment.get_assigned_alerts(user.id,
      organization_id: user.organization_id,
      states: ["assigned", "investigating", "pending_info"]
    )

    # Group alerts by state
    alerts_by_state = Enum.group_by(assigned_alerts, & &1.workflow_state)

    # Load workload
    my_workload = Assignment.get_analyst_workload(user.id, user.organization_id)

    # Load team workload (for comparison)
    team_workload = Assignment.list_analyst_workloads(user.organization_id)

    # Load SLA metrics
    my_sla_metrics = SLATracker.get_sla_metrics(
      analyst_id: user.id,
      organization_id: user.organization_id,
      days: 30
    )

    # Get alerts approaching SLA deadline
    approaching_sla = get_alerts_approaching_sla(assigned_alerts)

    # Get recent activity (state transitions)
    recent_activity = get_recent_activity(user.id)

    # Verdict statistics (FP rate, unreviewed count, top FP rules) — last 30 days
    verdict_stats = Alerts.get_verdict_stats(organization_id: user.organization_id, days: 30)

    socket
    |> assign(:assigned_alerts, assigned_alerts)
    |> assign(:alerts_by_state, alerts_by_state)
    |> assign(:my_workload, my_workload)
    |> assign(:team_workload, team_workload)
    |> assign(:my_sla_metrics, my_sla_metrics)
    |> assign(:approaching_sla, approaching_sla)
    |> assign(:recent_activity, recent_activity)
    |> assign(:verdict_stats, verdict_stats)
  end

  defp get_alerts_approaching_sla(alerts) do
    now = DateTime.utc_now()
    warning_threshold = DateTime.add(now, 30 * 60, :second) # 30 minutes

    Enum.filter(alerts, fn alert ->
      (alert.sla_acknowledge_deadline && is_nil(alert.acknowledged_at) &&
        DateTime.compare(alert.sla_acknowledge_deadline, warning_threshold) == :lt) ||
      (alert.sla_resolve_deadline && is_nil(alert.resolved_at) &&
        DateTime.compare(alert.sla_resolve_deadline, warning_threshold) == :lt)
    end)
    |> Enum.sort_by(fn alert ->
      alert.sla_acknowledge_deadline || alert.sla_resolve_deadline
    end, DateTime)
  end

  defp get_recent_activity(user_id) do
    # Get recent state transitions made by this user
    import Ecto.Query

    from(t in TamanduaServer.Alerts.StateTransition,
      where: t.transitioned_by_id == ^user_id,
      order_by: [desc: t.inserted_at],
      limit: 20,
      preload: [:alert]
    )
    |> TamanduaServer.Repo.all()
  end

  defp get_current_user(session) do
    case {session["user_id"], session["organization_id"]} do
      {user_id, organization_id} when is_binary(user_id) and is_binary(organization_id) ->
        %{
          id: user_id,
          name: session["name"] || session["email"] || "Analyst",
          email: session["email"],
          organization_id: organization_id
        }

      _ ->
        %{id: nil, name: nil, email: nil, organization_id: nil}
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="analyst-dashboard">
      <div class="dashboard-header">
        <h1>My Dashboard</h1>
        <div class="availability-toggle">
          <label>
            <span>Available</span>
            <input
              type="checkbox"
              checked={@my_workload.is_available}
              phx-click="set_availability"
              phx-value-available={!@my_workload.is_available}
            />
          </label>
        </div>
      </div>

      <!-- Workload Summary -->
      <div class="workload-summary">
        <div class="metric-card">
          <h3>My Workload</h3>
          <div class="metric-value"><%= @my_workload.assigned_count %></div>
          <div class="metric-label">Assigned Alerts</div>
          <div class="severity-breakdown">
            <span class="severity critical">Critical: <%= @my_workload.critical_count %></span>
            <span class="severity high">High: <%= @my_workload.high_count %></span>
            <span class="severity medium">Medium: <%= @my_workload.medium_count %></span>
            <span class="severity low">Low: <%= @my_workload.low_count %></span>
          </div>
        </div>

        <div class="metric-card">
          <h3>SLA Compliance</h3>
          <div class="metric-value">
            <%= Float.round(@my_sla_metrics.acknowledge_compliance_rate * 100, 1) %>%
          </div>
          <div class="metric-label">Acknowledge (30d)</div>
          <div class="sla-details">
            <div>Resolve: <%= Float.round(@my_sla_metrics.resolve_compliance_rate * 100, 1) %>%</div>
            <div>Avg Ack: <%= Float.round(@my_sla_metrics.avg_time_to_acknowledge_minutes, 1) %>m</div>
            <div>Avg Resolve: <%= Float.round(@my_sla_metrics.avg_time_to_resolve_minutes / 60, 1) %>h</div>
          </div>
        </div>

        <div class="metric-card">
          <h3>Team Position</h3>
          <div class="metric-value">
            <%= get_team_rank(@my_workload, @team_workload) %> / <%= length(@team_workload) %>
          </div>
          <div class="metric-label">By Workload</div>
          <div class="team-avg">
            Avg: <%= get_team_avg_workload(@team_workload) %>
          </div>
        </div>

        <div class="metric-card alert" :if={length(@approaching_sla) > 0}>
          <h3>SLA Warnings</h3>
          <div class="metric-value critical"><%= length(@approaching_sla) %></div>
          <div class="metric-label">Approaching Deadline</div>
        </div>

        <div class="metric-card">
          <h3>False Positive Review</h3>
          <%= if @verdict_stats.total_alerts == 0 do %>
            <div class="metric-value">—</div>
            <div class="metric-label">No alerts in last 30 days</div>
          <% else %>
            <div class="metric-value"><%= @verdict_stats.false_positive_rate %>%</div>
            <div class="metric-label">False positive rate</div>
            <div class="sla-details">
              <div>
                <.link navigate={~p"/alerts?verdict=unconfirmed"}>Unreviewed: <%= @verdict_stats.unreviewed_count %></.link>
              </div>
              <div>Reviewed: <%= @verdict_stats.reviewed_count %></div>
              <div>Active suppressions: <%= @verdict_stats.active_suppression_rules %></div>
            </div>
            <%= if length(@verdict_stats.top_fp_rules) > 0 do %>
              <ul class="sla-details">
                <li :for={rule <- Enum.take(@verdict_stats.top_fp_rules, 5)}>
                  <%= rule.rule_name || "(unnamed rule)" %> · <%= rule.fp_count %>
                </li>
              </ul>
            <% end %>
            <div class="metric-label">Last 30 days · FP rate from analyst verdicts only</div>
          <% end %>
        </div>
      </div>

      <!-- Tabs -->
      <div class="tabs">
        <button
          class={if @active_tab == "assigned", do: "active", else: ""}
          phx-click="change_tab"
          phx-value-tab="assigned"
        >
          Assigned (<%= length(@assigned_alerts) %>)
        </button>
        <button
          class={if @active_tab == "team", do: "active", else: ""}
          phx-click="change_tab"
          phx-value-tab="team"
        >
          Team Workload
        </button>
        <button
          class={if @active_tab == "activity", do: "active", else: ""}
          phx-click="change_tab"
          phx-value-tab="activity"
        >
          Activity Feed
        </button>
      </div>

      <!-- Tab Content -->
      <div class="tab-content">
        <%= if @active_tab == "assigned" do %>
          <%= render_assigned_alerts(assigns) %>
        <% end %>

        <%= if @active_tab == "team" do %>
          <%= render_team_workload(assigns) %>
        <% end %>

        <%= if @active_tab == "activity" do %>
          <%= render_activity_feed(assigns) %>
        <% end %>
      </div>

      <!-- Action Modal -->
      <%= if @show_action_modal && @selected_alert do %>
        <%= render_action_modal(assigns) %>
      <% end %>
    </div>
    """
  end

  defp render_assigned_alerts(assigns) do
    ~H"""
    <div class="assigned-alerts">
      <!-- SLA Warnings Section -->
      <div :if={length(@approaching_sla) > 0} class="sla-warnings">
        <h3 class="warning">Approaching SLA Deadline</h3>
        <div class="alert-list">
          <div :for={alert <- @approaching_sla} class="alert-card sla-warning">
            <%= render_alert_card(alert, assigns) %>
          </div>
        </div>
      </div>

      <!-- Alerts by State -->
      <div class="alerts-by-state">
        <%= for state <- ["assigned", "investigating", "pending_info"] do %>
          <% alerts = Map.get(@alerts_by_state, state, []) %>
          <%= if length(alerts) > 0 do %>
            <div class="state-section">
              <h3><%= humanize_state(state) %> (<%= length(alerts) %>)</h3>
              <div class="alert-list">
                <div :for={alert <- alerts} class="alert-card">
                  <%= render_alert_card(alert, assigns) %>
                </div>
              </div>
            </div>
          <% end %>
        <% end %>
      </div>

      <!-- Empty State -->
      <div :if={length(@assigned_alerts) == 0} class="empty-state">
        <p>No alerts assigned to you</p>
      </div>
    </div>
    """
  end

  defp render_alert_card(alert, assigns) do
    assigns = assign(assigns, :alert, alert)

    ~H"""
    <div class="alert-info">
      <div class="alert-header">
        <span class={"severity-badge #{@alert.severity}"}><%= @alert.severity %></span>
        <span class="alert-title"><%= @alert.title %></span>
      </div>
      <div class="alert-meta">
        <span>Agent: <%= (@alert.agent && @alert.agent.hostname) || "Unknown" %></span>
        <span>Created: <%= format_relative_time(@alert.inserted_at) %></span>
      </div>
      <%= if @alert.sla_acknowledge_deadline && is_nil(@alert.acknowledged_at) do %>
        <div class="sla-info">
          <span>Ack by: <%= format_deadline(@alert.sla_acknowledge_deadline) %></span>
        </div>
      <% end %>
      <%= if @alert.sla_resolve_deadline && is_nil(@alert.resolved_at) do %>
        <div class="sla-info">
          <span>Resolve by: <%= format_deadline(@alert.sla_resolve_deadline) %></span>
        </div>
      <% end %>
    </div>
    <div class="alert-actions">
      <%= if is_nil(@alert.acknowledged_at) do %>
        <button
          phx-click="acknowledge_alert"
          phx-value-id={@alert.id}
          class="btn-small btn-primary"
        >
          Acknowledge
        </button>
      <% end %>
      <button
        phx-click="open_action_modal"
        phx-value-id={@alert.id}
        class="btn-small btn-secondary"
      >
        Actions
      </button>
      <.link navigate={~p"/alerts/detail/#{@alert.id}"} class="btn-small">
        View Details
      </.link>
    </div>
    """
  end

  defp render_team_workload(assigns) do
    ~H"""
    <div class="team-workload">
      <h3>Team Workload Overview</h3>
      <table class="workload-table">
        <thead>
          <tr>
            <th>Analyst</th>
            <th>Status</th>
            <th>Total</th>
            <th>Critical</th>
            <th>High</th>
            <th>Medium</th>
            <th>Low</th>
            <th>Score</th>
          </tr>
        </thead>
        <tbody>
          <tr :for={workload <- @team_workload} class={if workload.user_id == @user.id, do: "current-user", else: ""}>
            <td><%= (workload.user && workload.user.name) || "Unknown" %></td>
            <td>
              <span class={if workload.is_available, do: "status-available", else: "status-unavailable"}>
                <%= if workload.is_available, do: "Available", else: "Unavailable" %>
              </span>
            </td>
            <td><%= workload.assigned_count %></td>
            <td><%= workload.critical_count %></td>
            <td><%= workload.high_count %></td>
            <td><%= workload.medium_count %></td>
            <td><%= workload.low_count %></td>
            <td><%= Float.round(workload.total_workload_score, 1) %></td>
          </tr>
        </tbody>
      </table>
    </div>
    """
  end

  defp render_activity_feed(assigns) do
    ~H"""
    <div class="activity-feed">
      <h3>Recent Activity</h3>
      <div class="activity-list">
        <div :for={activity <- @recent_activity} class="activity-item">
          <div class="activity-icon">
            <%= state_transition_icon(activity.from_state, activity.to_state) %>
          </div>
          <div class="activity-content">
            <div class="activity-title">
              Transitioned alert from <strong><%= activity.from_state %></strong> to <strong><%= activity.to_state %></strong>
            </div>
            <div class="activity-meta">
              <%= format_relative_time(activity.inserted_at) %>
              <%= if activity.transition_reason do %>
                · <%= activity.transition_reason %>
              <% end %>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
  end

  defp render_action_modal(assigns) do
    alert = assigns.selected_alert
    current_state = alert.workflow_state || "new"
    valid_next_states = Workflow.valid_next_states(current_state)

    assigns = assign(assigns, :valid_next_states, valid_next_states)

    ~H"""
    <div class="modal-overlay" phx-click="close_action_modal">
      <div class="modal-content" phx-click={JS.exec("phx-remove", to: ".modal-overlay")}>
        <div class="modal-header">
          <h3>Alert Actions</h3>
          <button phx-click="close_action_modal" class="close-btn">&times;</button>
        </div>
        <div class="modal-body">
          <h4><%= @selected_alert.title %></h4>
          <p>Current State: <strong><%= humanize_state(@selected_alert.workflow_state || "new") %></strong></p>

          <div class="state-transitions">
            <h5>Transition to:</h5>
            <div class="transition-buttons">
              <%= for state <- @valid_next_states do %>
                <button
                  phx-click="transition_state"
                  phx-value-alert_id={@selected_alert.id}
                  phx-value-state={state}
                  class="btn-transition"
                >
                  <%= humanize_state(state) %>
                </button>
              <% end %>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
  end

  # Helper functions

  defp humanize_state("new"), do: "New"
  defp humanize_state("assigned"), do: "Assigned"
  defp humanize_state("investigating"), do: "Investigating"
  defp humanize_state("pending_info"), do: "Pending Info"
  defp humanize_state("resolved"), do: "Resolved"
  defp humanize_state("false_positive"), do: "False Positive"
  defp humanize_state("escalated"), do: "Escalated"
  defp humanize_state("closed"), do: "Closed"
  defp humanize_state(state), do: String.capitalize(state)

  defp format_relative_time(datetime) do
    seconds = DateTime.diff(DateTime.utc_now(), datetime)
    cond do
      seconds < 60 -> "#{seconds}s ago"
      seconds < 3600 -> "#{div(seconds, 60)}m ago"
      seconds < 86400 -> "#{div(seconds, 3600)}h ago"
      true -> "#{div(seconds, 86400)}d ago"
    end
  end

  defp format_deadline(deadline) do
    diff = DateTime.diff(deadline, DateTime.utc_now())
    cond do
      diff < 0 -> "OVERDUE"
      diff < 60 -> "#{diff}s"
      diff < 3600 -> "#{div(diff, 60)}m"
      diff < 86400 -> "#{div(diff, 3600)}h"
      true -> "#{div(diff, 86400)}d"
    end
  end

  defp get_team_rank(my_workload, team_workload) do
    sorted = Enum.sort_by(team_workload, & &1.total_workload_score)
    Enum.find_index(sorted, fn w -> w.user_id == my_workload.user_id end) + 1
  end

  defp get_team_avg_workload(team_workload) do
    if length(team_workload) > 0 do
      avg = Enum.sum(Enum.map(team_workload, & &1.assigned_count)) / length(team_workload)
      Float.round(avg, 1)
    else
      0
    end
  end

  defp state_transition_icon(_from, _to), do: "→"
end
