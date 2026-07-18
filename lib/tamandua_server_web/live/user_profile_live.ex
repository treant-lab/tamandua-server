defmodule TamanduaServerWeb.UserProfileLive do
  @moduledoc """
  LiveView for individual user behavior profile.

  Shows:
  - User risk score and factors
  - Behavior baselines
  - Anomaly history
  - Behavior timeline
  """

  use TamanduaServerWeb, :live_view
  require Logger

  alias TamanduaServer.UBA.{RiskScorer, BehaviorTracker, AnomalyDetector}
  alias TamanduaServer.Repo
  alias TamanduaServer.Accounts.User

  import Ecto.Query

  @impl true
  def mount(%{"user_id" => user_id}, _session, socket) do
    if connected?(socket) do
      # Subscribe to updates for this user
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "uba:user:#{user_id}")
    end

    socket =
      socket
      |> assign(:user_id, user_id)
      |> assign(:loading, true)
      |> assign(:time_range, "7d")
      |> load_user_profile()

    {:ok, socket}
  end

  @impl true
  def handle_params(params, _uri, socket) do
    time_range = params["time_range"] || "7d"

    socket =
      socket
      |> assign(:time_range, time_range)
      |> load_user_profile()

    {:noreply, socket}
  end

  @impl true
  def handle_event("change_time_range", %{"time_range" => time_range}, socket) do
    user_id = socket.assigns.user_id
    {:noreply, push_patch(socket, to: ~p"/uba/users/#{user_id}?time_range=#{time_range}")}
  end

  @impl true
  def handle_event("acknowledge_anomaly", %{"id" => anomaly_id}, socket) do
    current_user_id = socket.assigns[:current_user_id]

    case AnomalyDetector.acknowledge_anomaly(anomaly_id, current_user_id) do
      {:ok, _anomaly} ->
        socket =
          socket
          |> put_flash(:info, "Anomaly acknowledged")
          |> load_user_profile()

        {:noreply, socket}

      {:error, _} ->
        {:noreply, put_flash(socket, :error, "Failed to acknowledge anomaly")}
    end
  end

  @impl true
  def handle_info({:uba_update, _data}, socket) do
    {:noreply, load_user_profile(socket)}
  end

  @impl true
  def handle_info(_msg, socket), do: {:noreply, socket}

  defp load_user_profile(socket) do
    user_id = socket.assigns.user_id
    days = parse_time_range(socket.assigns.time_range)

    # Get user info
    user = Repo.get(User, user_id)

    # Get risk score
    risk_score = RiskScorer.get_risk_score(user_id)

    # Get baselines
    baselines = get_user_baselines(user_id)

    # Get anomalies
    anomalies = AnomalyDetector.get_user_anomalies(user_id, days: days)

    # Get behavior stats
    behavior_stats = get_behavior_stats(user_id, days)

    # Get behavior timeline
    behavior_timeline = get_behavior_timeline(user_id, days)

    socket
    |> assign(:loading, false)
    |> assign(:user, user)
    |> assign(:risk_score, risk_score)
    |> assign(:baselines, baselines)
    |> assign(:anomalies, anomalies)
    |> assign(:behavior_stats, behavior_stats)
    |> assign(:behavior_timeline, behavior_timeline)
  end

  defp parse_time_range("24h"), do: 1
  defp parse_time_range("7d"), do: 7
  defp parse_time_range("30d"), do: 30
  defp parse_time_range(_), do: 7

  defp get_user_baselines(user_id) do
    alias TamanduaServer.UBA.UserBaseline

    from(b in UserBaseline,
      where: b.user_id == ^user_id,
      where: b.is_complete == true
    )
    |> Repo.all()
  end

  defp get_behavior_stats(user_id, days) do
    [
      {"login", BehaviorTracker.get_behavior_stats(user_id, "login", days)},
      {"file_access", BehaviorTracker.get_behavior_stats(user_id, "file_access", days)},
      {"data_download", BehaviorTracker.get_behavior_stats(user_id, "data_download", days)},
      {"sudo_usage", BehaviorTracker.get_behavior_stats(user_id, "sudo_usage", days)},
      {"app_launch", BehaviorTracker.get_behavior_stats(user_id, "app_launch", days)}
    ]
    |> Enum.into(%{})
  end

  defp get_behavior_timeline(user_id, days) do
    alias TamanduaServer.UBA.UserBehavior

    cutoff = DateTime.utc_now() |> DateTime.add(-days * 24 * 3600, :second)

    from(b in UserBehavior,
      where: b.user_id == ^user_id,
      where: b.timestamp >= ^cutoff,
      order_by: [desc: b.timestamp],
      limit: 50
    )
    |> Repo.all()
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="user-profile">
      <div class="page-header">
        <div>
          <h1>User Behavior Profile</h1>
          <%= if @user do %>
            <p class="user-email"><%= @user.email %></p>
          <% end %>
        </div>
        <div class="controls">
          <select name="time_range" phx-change="change_time_range">
            <option value="24h" selected={@time_range == "24h"}>Last 24 Hours</option>
            <option value="7d" selected={@time_range == "7d"}>Last 7 Days</option>
            <option value="30d" selected={@time_range == "30d"}>Last 30 Days</option>
          </select>
        </div>
      </div>

      <%= if @loading do %>
        <div class="loading">Loading user profile...</div>
      <% else %>
        <div class="profile-grid">
          <!-- Risk Score Card -->
          <div class="card risk-card">
            <h2>Risk Score</h2>
            <%= if @risk_score do %>
              <div class={"risk-score-display #{@risk_score.risk_level}"}>
                <div class="score"><%= @risk_score.risk_score %></div>
                <div class="level"><%= String.upcase(@risk_score.risk_level) %></div>
              </div>

              <div class="risk-factors">
                <h3>Risk Factors</h3>
                <div class="factor">
                  <span class="label">Off-hours Activity</span>
                  <span class="value"><%= @risk_score.off_hours_activity %></span>
                </div>
                <div class="factor">
                  <span class="label">New Location</span>
                  <span class="value"><%= @risk_score.new_location %></span>
                </div>
                <div class="factor">
                  <span class="label">Excessive Data Access</span>
                  <span class="value"><%= @risk_score.excessive_data_access %></span>
                </div>
                <div class="factor">
                  <span class="label">Privilege Escalation</span>
                  <span class="value"><%= @risk_score.privilege_escalation %></span>
                </div>
                <div class="factor">
                  <span class="label">Failed Logins</span>
                  <span class="value"><%= @risk_score.failed_logins %></span>
                </div>
              </div>
            <% else %>
              <p>No risk score available. Baseline learning may still be in progress.</p>
            <% end %>
          </div>

          <!-- Behavior Stats -->
          <div class="card">
            <h2>Behavior Statistics</h2>
            <div class="stats-grid">
              <%= for {behavior, stats} <- @behavior_stats do %>
                <div class="stat-card">
                  <h4><%= format_behavior_type(behavior) %></h4>
                  <div class="stat-row">
                    <span class="label">Count:</span>
                    <span class="value"><%= stats.count %></span>
                  </div>
                  <%= if stats.avg > 0 do %>
                    <div class="stat-row">
                      <span class="label">Average:</span>
                      <span class="value"><%= Float.round(stats.avg, 2) %></span>
                    </div>
                    <div class="stat-row">
                      <span class="label">Max:</span>
                      <span class="value"><%= Float.round(stats.max, 2) %></span>
                    </div>
                  <% end %>
                </div>
              <% end %>
            </div>
          </div>

          <!-- Baselines -->
          <div class="card full-width">
            <h2>Behavioral Baselines</h2>
            <div class="baselines-table">
              <table>
                <thead>
                  <tr>
                    <th>Behavior</th>
                    <th>Mean</th>
                    <th>Std Dev</th>
                    <th>95th Percentile</th>
                    <th>Count</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  <%= for baseline <- @baselines do %>
                    <tr>
                      <td><%= format_behavior_type(baseline.behavior_type) %></td>
                      <td><%= Float.round(baseline.mean || 0, 2) %></td>
                      <td><%= Float.round(baseline.stddev || 0, 2) %></td>
                      <td><%= Float.round(baseline.p95 || 0, 2) %></td>
                      <td><%= baseline.count %></td>
                      <td>
                        <%= if baseline.is_complete do %>
                          <span class="status-badge complete">Complete</span>
                        <% else %>
                          <span class="status-badge learning">Learning</span>
                        <% end %>
                      </td>
                    </tr>
                  <% end %>
                </tbody>
              </table>
            </div>
          </div>

          <!-- Anomalies -->
          <div class="card full-width">
            <h2>Anomaly History</h2>
            <div class="anomalies-table">
              <table>
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Behavior</th>
                    <th>Anomaly Type</th>
                    <th>Severity</th>
                    <th>Score</th>
                    <th>Baseline</th>
                    <th>Observed</th>
                    <th>Status</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  <%= for anomaly <- @anomalies do %>
                    <tr class={"anomaly-row #{anomaly.severity}"}>
                      <td><%= format_timestamp(anomaly.timestamp) %></td>
                      <td><%= format_behavior_type(anomaly.behavior_type) %></td>
                      <td><%= format_anomaly_type(anomaly.anomaly_type) %></td>
                      <td>
                        <span class={"severity-badge #{anomaly.severity}"}>
                          <%= String.upcase(anomaly.severity) %>
                        </span>
                      </td>
                      <td><%= Float.round(anomaly.score || 0, 2) %></td>
                      <td><%= Float.round(anomaly.baseline_value || 0, 2) %></td>
                      <td><%= Float.round(anomaly.observed_value || 0, 2) %></td>
                      <td>
                        <%= if anomaly.is_acknowledged do %>
                          <span class="status-badge ack">Acknowledged</span>
                        <% else %>
                          <span class="status-badge pending">Pending</span>
                        <% end %>
                      </td>
                      <td>
                        <%= unless anomaly.is_acknowledged do %>
                          <button phx-click="acknowledge_anomaly" phx-value-id={anomaly.id}>
                            Acknowledge
                          </button>
                        <% end %>
                      </td>
                    </tr>
                  <% end %>
                </tbody>
              </table>
            </div>
          </div>

          <!-- Behavior Timeline -->
          <div class="card full-width">
            <h2>Recent Activity Timeline</h2>
            <div class="timeline">
              <%= for event <- @behavior_timeline do %>
                <div class="timeline-event">
                  <span class="timestamp"><%= format_timestamp(event.timestamp) %></span>
                  <span class="behavior-type"><%= format_behavior_type(event.behavior_type) %></span>
                  <%= if event.location do %>
                    <span class="location">from <%= event.location %></span>
                  <% end %>
                  <%= if event.value do %>
                    <span class="value">(<%= Float.round(event.value, 2) %>)</span>
                  <% end %>
                </div>
              <% end %>
            </div>
          </div>
        </div>
      <% end %>
    </div>

    <style>
      .user-profile {
        padding: 2rem;
      }

      .page-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 2rem;
      }

      .user-email {
        color: #666;
        font-size: 1.1rem;
        margin-top: 0.5rem;
      }

      .profile-grid {
        display: grid;
        grid-template-columns: repeat(2, 1fr);
        gap: 1.5rem;
      }

      .card {
        background: white;
        border-radius: 8px;
        padding: 1.5rem;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      }

      .card.full-width {
        grid-column: 1 / -1;
      }

      .risk-score-display {
        text-align: center;
        padding: 2rem;
        border-radius: 8px;
        margin-bottom: 1.5rem;
      }

      .risk-score-display.critical { background: #ffcdd2; }
      .risk-score-display.high { background: #ffe0b2; }
      .risk-score-display.medium { background: #fff9c4; }
      .risk-score-display.low { background: #c8e6c9; }

      .risk-score-display .score {
        font-size: 3rem;
        font-weight: bold;
      }

      .risk-score-display .level {
        font-size: 1.5rem;
        font-weight: 600;
        margin-top: 0.5rem;
      }

      .risk-factors .factor {
        display: flex;
        justify-content: space-between;
        padding: 0.5rem 0;
        border-bottom: 1px solid #eee;
      }

      .stats-grid {
        display: grid;
        grid-template-columns: repeat(2, 1fr);
        gap: 1rem;
      }

      .stat-card {
        padding: 1rem;
        background: #f5f5f5;
        border-radius: 4px;
      }

      .stat-row {
        display: flex;
        justify-content: space-between;
        margin-top: 0.5rem;
      }

      .baselines-table table,
      .anomalies-table table {
        width: 100%;
        border-collapse: collapse;
      }

      .baselines-table th,
      .anomalies-table th {
        text-align: left;
        padding: 0.75rem;
        background: #f5f5f5;
        font-weight: 600;
      }

      .baselines-table td,
      .anomalies-table td {
        padding: 0.75rem;
        border-bottom: 1px solid #eee;
      }

      .status-badge {
        padding: 0.25rem 0.5rem;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 600;
      }

      .status-badge.complete { background: #c8e6c9; color: #1b5e20; }
      .status-badge.learning { background: #fff9c4; color: #f57f17; }
      .status-badge.ack { background: #e0e0e0; color: #424242; }
      .status-badge.pending { background: #ffe0b2; color: #e65100; }

      .severity-badge {
        padding: 0.25rem 0.5rem;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 600;
      }

      .severity-badge.critical { background: #ffcdd2; color: #b71c1c; }
      .severity-badge.high { background: #ffe0b2; color: #e65100; }
      .severity-badge.medium { background: #fff9c4; color: #f57f17; }
      .severity-badge.low { background: #c8e6c9; color: #1b5e20; }

      .timeline {
        max-height: 400px;
        overflow-y: auto;
      }

      .timeline-event {
        padding: 0.75rem;
        border-left: 3px solid #2196f3;
        margin-bottom: 1rem;
        background: #f5f5f5;
      }

      .timeline-event .timestamp {
        color: #666;
        font-size: 0.875rem;
        margin-right: 1rem;
      }

      .timeline-event .behavior-type {
        font-weight: 600;
        margin-right: 0.5rem;
      }
    </style>
    """
  end

  defp format_timestamp(timestamp) do
    Calendar.strftime(timestamp, "%Y-%m-%d %H:%M:%S")
  end

  defp format_behavior_type(type) do
    type
    |> String.replace("_", " ")
    |> String.capitalize()
  end

  defp format_anomaly_type(type) do
    type
    |> String.replace("_", " ")
    |> String.capitalize()
  end
end
