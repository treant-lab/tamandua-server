defmodule TamanduaServerWeb.UBADashboardLive do
  @moduledoc """
  LiveView for User Behavior Analytics dashboard.

  Shows:
  - Top risky users
  - Risk score distribution
  - Recent anomalies
  - Behavior trends
  """

  use TamanduaServerWeb, :live_view
  require Logger

  alias TamanduaServer.UBA.{RiskScorer, AnomalyDetector}
  alias TamanduaServer.Repo

  import Ecto.Query

  @impl true
  def mount(_params, session, socket) do
    organization_id = get_organization_id(session)

    if connected?(socket) do
      # Subscribe to UBA updates
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "uba:#{organization_id}")
    end

    socket =
      socket
      |> assign(:organization_id, organization_id)
      |> assign(:loading, true)
      |> assign(:time_range, "7d")
      |> load_dashboard_data()

    {:ok, socket}
  end

  @impl true
  def handle_params(params, _uri, socket) do
    time_range = params["time_range"] || "7d"

    socket =
      socket
      |> assign(:time_range, time_range)
      |> load_dashboard_data()

    {:noreply, socket}
  end

  @impl true
  def handle_event("change_time_range", %{"time_range" => time_range}, socket) do
    {:noreply, push_patch(socket, to: ~p"/uba?time_range=#{time_range}")}
  end

  @impl true
  def handle_event("acknowledge_anomaly", %{"id" => anomaly_id}, socket) do
    current_user_id = socket.assigns[:current_user_id]

    case AnomalyDetector.acknowledge_anomaly(anomaly_id, current_user_id) do
      {:ok, _anomaly} ->
        socket =
          socket
          |> put_flash(:info, "Anomaly acknowledged")
          |> load_dashboard_data()

        {:noreply, socket}

      {:error, _} ->
        {:noreply, put_flash(socket, :error, "Failed to acknowledge anomaly")}
    end
  end

  @impl true
  def handle_info({:uba_update, _data}, socket) do
    {:noreply, load_dashboard_data(socket)}
  end

  @impl true
  def handle_info(_msg, socket), do: {:noreply, socket}

  defp load_dashboard_data(socket) do
    organization_id = socket.assigns.organization_id
    days = parse_time_range(socket.assigns.time_range)

    # Get top risky users
    top_risky_users = RiskScorer.get_top_risky_users(organization_id, 10)

    # Get risk distribution
    risk_distribution = get_risk_distribution(organization_id)

    # Get recent anomalies
    recent_anomalies = get_recent_anomalies(organization_id, days)

    # Get anomaly trends
    anomaly_trends = get_anomaly_trends(organization_id, days)

    # Get alert stats
    alert_stats = get_alert_stats(organization_id)

    socket
    |> assign(:loading, false)
    |> assign(:top_risky_users, top_risky_users)
    |> assign(:risk_distribution, risk_distribution)
    |> assign(:recent_anomalies, recent_anomalies)
    |> assign(:anomaly_trends, anomaly_trends)
    |> assign(:alert_stats, alert_stats)
  end

  defp parse_time_range("24h"), do: 1
  defp parse_time_range("7d"), do: 7
  defp parse_time_range("30d"), do: 30
  defp parse_time_range(_), do: 7

  defp get_risk_distribution(organization_id) do
    alias TamanduaServer.UBA.UserRiskScore

    from(r in UserRiskScore,
      where: r.organization_id == ^organization_id,
      select: %{risk_level: r.risk_level, count: count(r.id)},
      group_by: r.risk_level
    )
    |> Repo.all()
    |> Enum.map(fn %{risk_level: level, count: count} ->
      {level, count}
    end)
    |> Map.new()
  end

  defp get_recent_anomalies(organization_id, days) do
    alias TamanduaServer.UBA.UserAnomaly

    cutoff = DateTime.utc_now() |> DateTime.add(-days * 24 * 3600, :second)

    from(a in UserAnomaly,
      where: a.organization_id == ^organization_id,
      where: a.timestamp >= ^cutoff,
      where: a.is_acknowledged == false,
      order_by: [desc: a.timestamp],
      limit: 20,
      preload: [:user]
    )
    |> Repo.all()
  end

  defp get_anomaly_trends(organization_id, days) do
    alias TamanduaServer.UBA.UserAnomaly

    cutoff = DateTime.utc_now() |> DateTime.add(-days * 24 * 3600, :second)

    from(a in UserAnomaly,
      where: a.organization_id == ^organization_id,
      where: a.timestamp >= ^cutoff,
      select: %{
        date: fragment("DATE(?)", a.timestamp),
        count: count(a.id)
      },
      group_by: fragment("DATE(?)", a.timestamp),
      order_by: fragment("DATE(?)", a.timestamp)
    )
    |> Repo.all()
  end

  defp get_alert_stats(organization_id) do
    alias TamanduaServer.UBA.UBAAlert

    from(a in UBAAlert,
      where: a.organization_id == ^organization_id,
      select: %{
        status: a.status,
        severity: a.severity,
        count: count(a.id)
      },
      group_by: [a.status, a.severity]
    )
    |> Repo.all()
    |> Enum.reduce(%{total: 0, by_status: %{}, by_severity: %{}}, fn stat, acc ->
      %{
        total: acc.total + stat.count,
        by_status: Map.update(acc.by_status, stat.status, stat.count, &(&1 + stat.count)),
        by_severity: Map.update(acc.by_severity, stat.severity, stat.count, &(&1 + stat.count))
      }
    end)
  end

  defp get_organization_id(session) do
    # Get from session or current user
    session["organization_id"] || Ecto.UUID.generate()
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="uba-dashboard">
      <div class="page-header">
        <h1>User Behavior Analytics</h1>
        <div class="controls">
          <select name="time_range" phx-change="change_time_range">
            <option value="24h" selected={@time_range == "24h"}>Last 24 Hours</option>
            <option value="7d" selected={@time_range == "7d"}>Last 7 Days</option>
            <option value="30d" selected={@time_range == "30d"}>Last 30 Days</option>
          </select>
        </div>
      </div>

      <%= if @loading do %>
        <div class="loading">Loading UBA data...</div>
      <% else %>
        <div class="dashboard-grid">
          <!-- Risk Distribution -->
          <div class="card">
            <h2>Risk Distribution</h2>
            <div class="risk-chart">
              <div class="risk-bar critical">
                <span class="label">Critical</span>
                <div class="bar" style={"width: #{get_percentage(@risk_distribution, "critical", total_users(@risk_distribution))}%"}>
                  <span class="count"><%= Map.get(@risk_distribution, "critical", 0) %></span>
                </div>
              </div>
              <div class="risk-bar high">
                <span class="label">High</span>
                <div class="bar" style={"width: #{get_percentage(@risk_distribution, "high", total_users(@risk_distribution))}%"}>
                  <span class="count"><%= Map.get(@risk_distribution, "high", 0) %></span>
                </div>
              </div>
              <div class="risk-bar medium">
                <span class="label">Medium</span>
                <div class="bar" style={"width: #{get_percentage(@risk_distribution, "medium", total_users(@risk_distribution))}%"}>
                  <span class="count"><%= Map.get(@risk_distribution, "medium", 0) %></span>
                </div>
              </div>
              <div class="risk-bar low">
                <span class="label">Low</span>
                <div class="bar" style={"width: #{get_percentage(@risk_distribution, "low", total_users(@risk_distribution))}%"}>
                  <span class="count"><%= Map.get(@risk_distribution, "low", 0) %></span>
                </div>
              </div>
            </div>
          </div>

          <!-- Top Risky Users -->
          <div class="card">
            <h2>Top Risky Users</h2>
            <div class="risky-users-list">
              <%= for risk_score <- @top_risky_users do %>
                <div class={"risky-user #{risk_score.risk_level}"}>
                  <div class="user-info">
                    <a href={~p"/uba/users/#{risk_score.user_id}"}>
                      <%= risk_score.user.email %>
                    </a>
                    <span class="risk-score"><%= risk_score.risk_score %></span>
                  </div>
                  <div class={"risk-level-badge #{risk_score.risk_level}"}>
                    <%= String.upcase(risk_score.risk_level) %>
                  </div>
                </div>
              <% end %>
            </div>
          </div>

          <!-- Recent Anomalies -->
          <div class="card full-width">
            <h2>Recent Anomalies</h2>
            <div class="anomalies-table">
              <table>
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>User</th>
                    <th>Behavior</th>
                    <th>Anomaly Type</th>
                    <th>Severity</th>
                    <th>Score</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  <%= for anomaly <- @recent_anomalies do %>
                    <tr class={"anomaly-row #{anomaly.severity}"}>
                      <td><%= format_timestamp(anomaly.timestamp) %></td>
                      <td>
                        <a href={~p"/uba/users/#{anomaly.user_id}"}>
                          <%= anomaly.user.email %>
                        </a>
                      </td>
                      <td><%= format_behavior_type(anomaly.behavior_type) %></td>
                      <td><%= format_anomaly_type(anomaly.anomaly_type) %></td>
                      <td>
                        <span class={"severity-badge #{anomaly.severity}"}>
                          <%= String.upcase(anomaly.severity) %>
                        </span>
                      </td>
                      <td><%= Float.round(anomaly.score || 0, 2) %></td>
                      <td>
                        <button phx-click="acknowledge_anomaly" phx-value-id={anomaly.id}>
                          Acknowledge
                        </button>
                      </td>
                    </tr>
                  <% end %>
                </tbody>
              </table>
            </div>
          </div>

          <!-- Anomaly Trends -->
          <div class="card">
            <h2>Anomaly Trends</h2>
            <div class="trend-chart">
              <%= for trend <- @anomaly_trends do %>
                <div class="trend-bar">
                  <span class="date"><%= trend.date %></span>
                  <div class="bar" style={"height: #{trend.count * 5}px"}>
                    <span class="count"><%= trend.count %></span>
                  </div>
                </div>
              <% end %>
            </div>
          </div>

          <!-- Alert Stats -->
          <div class="card">
            <h2>Alert Statistics</h2>
            <div class="alert-stats">
              <div class="stat">
                <span class="label">Total Alerts</span>
                <span class="value"><%= @alert_stats.total %></span>
              </div>
              <div class="stat">
                <span class="label">Open</span>
                <span class="value"><%= Map.get(@alert_stats.by_status, "open", 0) %></span>
              </div>
              <div class="stat">
                <span class="label">Investigating</span>
                <span class="value"><%= Map.get(@alert_stats.by_status, "investigating", 0) %></span>
              </div>
              <div class="stat">
                <span class="label">Critical</span>
                <span class="value critical"><%= Map.get(@alert_stats.by_severity, "critical", 0) %></span>
              </div>
            </div>
          </div>
        </div>
      <% end %>
    </div>

    <style>
      .uba-dashboard {
        padding: 2rem;
      }

      .page-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 2rem;
      }

      .dashboard-grid {
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

      .risk-chart .risk-bar {
        margin-bottom: 1rem;
      }

      .risk-bar .label {
        display: inline-block;
        width: 80px;
        font-weight: 600;
      }

      .risk-bar .bar {
        display: inline-block;
        height: 30px;
        background: #e0e0e0;
        border-radius: 4px;
        position: relative;
        min-width: 40px;
      }

      .risk-bar.critical .bar { background: #d32f2f; }
      .risk-bar.high .bar { background: #f57c00; }
      .risk-bar.medium .bar { background: #fbc02d; }
      .risk-bar.low .bar { background: #388e3c; }

      .risky-user {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 0.75rem;
        border-bottom: 1px solid #eee;
      }

      .risk-level-badge {
        padding: 0.25rem 0.5rem;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.75rem;
      }

      .risk-level-badge.critical { background: #ffcdd2; color: #b71c1c; }
      .risk-level-badge.high { background: #ffe0b2; color: #e65100; }
      .risk-level-badge.medium { background: #fff9c4; color: #f57f17; }
      .risk-level-badge.low { background: #c8e6c9; color: #1b5e20; }

      .anomalies-table table {
        width: 100%;
        border-collapse: collapse;
      }

      .anomalies-table th {
        text-align: left;
        padding: 0.75rem;
        background: #f5f5f5;
        font-weight: 600;
      }

      .anomalies-table td {
        padding: 0.75rem;
        border-bottom: 1px solid #eee;
      }

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
    </style>
    """
  end

  defp total_users(distribution) do
    distribution
    |> Map.values()
    |> Enum.sum()
    |> max(1)
  end

  defp get_percentage(distribution, level, total) do
    count = Map.get(distribution, level, 0)
    (count / total * 100) |> Float.round(1)
  end

  defp format_timestamp(timestamp) do
    Calendar.strftime(timestamp, "%Y-%m-%d %H:%M")
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
