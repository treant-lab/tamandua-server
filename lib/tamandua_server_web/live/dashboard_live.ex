defmodule TamanduaServerWeb.DashboardLive do
  use TamanduaServerWeb, :live_view

  alias TamanduaServer.Agents
  alias TamanduaServer.Alerts
  alias TamanduaServerWeb.Live.Components.DashboardWidgets
  alias TamanduaServerWeb.Live.Components.KubernetesSecurityWidget

  @refresh_interval 5000

  @impl true
  def mount(_params, _session, socket) do
    # Extract organization_id from the authenticated current_user for multi-tenant isolation
    organization_id = socket.assigns.current_user.organization_id

    if connected?(socket) do
      # Subscribe to real-time alerts (org-scoped topic)
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "alerts:feed:#{organization_id}")
      # Subscribe to agent status changes (org-scoped topic)
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "agents:status:#{organization_id}")
      # Subscribe to supply chain alerts (org-scoped topic)
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "alerts:supply_chain:#{organization_id}")
      # Subscribe to Kubernetes alerts (org-scoped topic)
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "alerts:kubernetes:#{organization_id}")
      # Also subscribe to global topics for backwards compatibility
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "alerts:feed")
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "agents:status")
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "alerts:supply_chain")
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "alerts:kubernetes")
      # Schedule periodic refresh for KPIs
      :timer.send_interval(@refresh_interval, :refresh_dashboard)
    end

    {:ok,
     socket
     |> assign(:organization_id, organization_id)
     |> assign_page_title()
     |> assign_kpis()
     |> assign_threat_feed()
     |> assign_agent_status()
     |> assign_chart_period("24h")
     |> assign_alert_trend()
     |> assign_supply_chain_alerts()
     |> assign_kubernetes_security()}
  end

  @impl true
  def handle_info(:refresh_dashboard, socket) do
    {:noreply,
     socket
     |> assign_kpis()
     |> assign_agent_status()
     |> assign_alert_trend()}
  end

  # Handle new alert from PubSub
  def handle_info(%{topic: topic, event: "new_alert", payload: alert_payload}, socket) do
    unless topic == "alerts:feed" or String.starts_with?(topic, "alerts:feed:") do
      {:noreply, socket}
    else
    # Verify alert belongs to current organization (multi-tenant isolation)
    org_id = socket.assigns.organization_id
    alert_org_id = alert_payload.organization_id || alert_payload["organization_id"]

    # Only process alerts that belong to this organization
    if is_nil(alert_org_id) or alert_org_id == org_id do
      # Prepend new alert to threat feed
      new_alert = %{
        id: alert_payload.id || alert_payload["id"],
        title: alert_payload.title || alert_payload["title"],
        severity: alert_payload.severity || alert_payload["severity"],
        agent_id: alert_payload.agentId || alert_payload["agentId"] || alert_payload.agent_id,
        timestamp: alert_payload.timestamp || System.system_time(:millisecond),
        status: alert_payload.status || alert_payload["status"] || "new"
      }

      threat_feed = [new_alert | socket.assigns.threat_feed] |> Enum.take(20)

      {:noreply,
       socket
       |> assign(threat_feed: threat_feed)
       |> assign_kpis()
       |> assign_alert_trend()}
    else
      # Alert belongs to different organization, ignore
      {:noreply, socket}
    end
    end
  end

  # Handle alert updates
  def handle_info(%{topic: "alerts:feed", event: "alert_updated", payload: _payload}, socket) do
    {:noreply, assign_kpis(socket)}
  end

  # Handle agent status changes
  def handle_info({:agent_status_changed, _agent_id, _status}, socket) do
    {:noreply, assign_agent_status(socket)}
  end

  # Handle new supply chain alert from PubSub
  def handle_info(%{event: "new_alert", payload: alert}, socket) do
    # Verify alert belongs to current organization (multi-tenant isolation)
    org_id = socket.assigns.organization_id
    alert_org_id = if is_map(alert), do: alert[:organization_id] || alert["organization_id"], else: nil

    # Only process alerts that belong to this organization
    if (is_nil(alert_org_id) or alert_org_id == org_id) and
       is_map(alert) and is_map(alert.enrichment) and alert.enrichment["ecosystem"] do
      supply_chain_data = socket.assigns.supply_chain_data
      alerts = [alert | supply_chain_data.alerts] |> Enum.take(20)

      critical_count =
        Enum.count(alerts, fn a -> a.severity == "critical" end)

      high_count =
        Enum.count(alerts, fn a -> a.severity == "high" end)

      updated_data = %{
        supply_chain_data
        | alerts: alerts,
          critical_count: critical_count,
          high_count: high_count
      }

      {:noreply, assign(socket, supply_chain_data: updated_data)}
    else
      {:noreply, socket}
    end
  end

  # Handle new Kubernetes alert from PubSub
  def handle_info({:k8s_alert, alert}, socket) do
    # Update K8s security data with new alert
    socket = assign_kubernetes_security(socket)
    {:noreply, socket}
  end

  def handle_info(_, socket), do: {:noreply, socket}

  @impl true
  def handle_event("change_chart_period", %{"period" => period}, socket) do
    {:noreply,
     socket
     |> assign_chart_period(period)
     |> assign_alert_trend()}
  end

  def handle_event("navigate_to_alerts", params, socket) do
    # Build query params for alert filtering
    query_params = build_alert_filter_params(params)
    path = "/alerts?" <> URI.encode_query(query_params)

    {:noreply, push_navigate(socket, to: path)}
  end

  def handle_event("k8s_toggle_view", %{"mode" => mode}, socket) do
    view_mode = String.to_atom(mode)

    grouped_data = case view_mode do
      :by_node -> socket.assigns.k8s_security_data.by_node
      :by_namespace -> socket.assigns.k8s_security_data.by_namespace
      _ -> socket.assigns.k8s_security_data.by_node
    end

    updated_data = socket.assigns.k8s_security_data
      |> Map.put(:view_mode, view_mode)
      |> Map.put(:grouped_data, grouped_data)

    {:noreply, assign(socket, k8s_security_data: updated_data)}
  end

  # Private functions

  defp assign_page_title(socket) do
    assign(socket, page_title: "Dashboard")
  end

  defp assign_kpis(socket) do
    now = System.system_time(:millisecond)
    one_hour_ago = now - (60 * 60 * 1000)
    org_id = socket.assigns.organization_id

    # Get active alerts for KPIs (org-scoped for multi-tenant isolation)
    active_alerts = Alerts.list_recent_for_org(org_id, limit: 1000)
    recent_alerts = Enum.filter(active_alerts, fn alert ->
      timestamp = alert.inserted_at
      |> NaiveDateTime.to_gregorian_seconds()
      |> elem(0)
      |> Kernel.*(1000)

      timestamp >= one_hour_ago
    end)

    detections_per_hour = length(recent_alerts)

    # Calculate MTTR (Mean Time to Respond)
    # MTTR = average time from alert creation to status change (investigating/resolved)
    mttr_minutes = calculate_mttr(active_alerts)

    # Calculate block rate (resolved/false_positive alerts as % of total)
    total_count = length(active_alerts)
    blocked_count = Enum.count(active_alerts, fn alert ->
      alert.status in ["resolved", "false_positive"]
    end)
    block_rate = if total_count > 0, do: Float.round(blocked_count / total_count * 100, 1), else: 0.0

    # Active threats count
    active_threats = Enum.count(active_alerts, fn alert ->
      alert.status not in ["resolved", "false_positive"]
    end)

    assign(socket,
      detections_per_hour: detections_per_hour,
      mttr_minutes: mttr_minutes,
      block_rate: block_rate,
      active_threats: active_threats
    )
  end

  defp assign_threat_feed(socket) do
    org_id = socket.assigns.organization_id

    # Get recent alerts (last 20) - org-scoped for multi-tenant isolation
    recent_alerts = Alerts.list_recent_for_org(org_id, limit: 20)

    threat_feed = Enum.map(recent_alerts, fn alert ->
      %{
        id: alert.id,
        title: alert.title,
        severity: alert.severity,
        agent_id: alert.agent_id,
        timestamp: alert.inserted_at |> naive_to_unix_ms(),
        status: alert.status
      }
    end)

    assign(socket, threat_feed: threat_feed)
  end

  defp assign_agent_status(socket) do
    org_id = socket.assigns.organization_id

    # Get agents for this organization only (org-scoped for multi-tenant isolation)
    agents = Agents.Registry.list_for_org(org_id)

    agent_status = Enum.map(agents, fn agent ->
      health = case Agents.Registry.get_health(agent.agent_id) do
        {:ok, health_data} -> health_data
        _ -> %{}
      end

      health_status = Agents.Registry.get_agent_health_status(agent.agent_id)

      %{
        id: agent.agent_id,
        hostname: agent.hostname,
        status: agent.status,
        health_status: health_status,
        os_type: agent.os_type,
        last_seen_at: agent.last_seen_at,
        cpu_usage: agent[:cpu_usage] || health[:cpu_usage] || 0,
        memory_usage: agent[:memory_usage] || health[:memory_usage] || 0,
        disk_usage: agent[:disk_usage] || health[:disk_usage] || 0
      }
    end)

    # Count by status
    online_count = Enum.count(agent_status, &(&1.status == :online))
    offline_count = Enum.count(agent_status, &(&1.status == :offline))
    isolated_count = Enum.count(agent_status, &(&1.status == :isolated))

    assign(socket,
      agent_status: agent_status,
      online_count: online_count,
      offline_count: offline_count,
      isolated_count: isolated_count
    )
  end

  defp assign_supply_chain_alerts(socket) do
    org_id = socket.assigns.organization_id

    # Get recent supply chain alerts (those with ecosystem enrichment) - org-scoped for multi-tenant isolation
    all_alerts = Alerts.list_recent_for_org(org_id, limit: 100)

    supply_chain_alerts =
      all_alerts
      |> Enum.filter(fn alert ->
        is_map(alert.enrichment) and alert.enrichment["ecosystem"] != nil
      end)
      |> Enum.take(20)

    critical_count = Enum.count(supply_chain_alerts, &(&1.severity == "critical"))
    high_count = Enum.count(supply_chain_alerts, &(&1.severity == "high"))

    assign(socket,
      supply_chain_data: %{
        alerts: supply_chain_alerts,
        critical_count: critical_count,
        high_count: high_count
      }
    )
  end

  defp assign_kubernetes_security(socket) do
    org_id = socket.assigns.organization_id

    # Get recent alerts that have k8s_context - org-scoped for multi-tenant isolation
    all_alerts = Alerts.list_recent_for_org(org_id, limit: 200)

    k8s_alerts =
      all_alerts
      |> Enum.filter(fn alert ->
        alert.k8s_context != nil ||
          (alert.metadata && Map.get(alert.metadata, "container_id")) ||
          (alert.enrichment && Map.get(alert.enrichment, "container_id"))
      end)
      |> Enum.take(100)

    # Group by node
    by_node = k8s_alerts
      |> Enum.group_by(fn alert ->
        get_in(alert.k8s_context || %{}, [:node_name]) ||
          get_in(alert.metadata || %{}, ["node_name"]) ||
          "unknown"
      end)
      |> Enum.map(fn {node, alerts} ->
        %{
          name: node,
          total: length(alerts),
          critical: count_severity(alerts, "critical"),
          high: count_severity(alerts, "high"),
          medium: count_severity(alerts, "medium"),
          low: count_severity(alerts, "low")
        }
      end)
      |> Enum.sort_by(& &1.critical, :desc)

    # Group by namespace
    by_namespace = k8s_alerts
      |> Enum.group_by(fn alert ->
        get_in(alert.k8s_context || %{}, [:namespace]) ||
          get_in(alert.metadata || %{}, ["namespace"]) ||
          "unknown"
      end)
      |> Enum.map(fn {namespace, alerts} ->
        %{
          name: namespace,
          total: length(alerts),
          critical: count_severity(alerts, "critical"),
          high: count_severity(alerts, "high"),
          medium: count_severity(alerts, "medium"),
          low: count_severity(alerts, "low")
        }
      end)
      |> Enum.sort_by(& &1.critical, :desc)

    total_critical = count_severity(k8s_alerts, "critical")
    total_high = count_severity(k8s_alerts, "high")

    # Default view mode
    view_mode = :by_node

    assign(socket,
      k8s_security_data: %{
        alerts: k8s_alerts,
        by_node: by_node,
        by_namespace: by_namespace,
        grouped_data: by_node,  # Default to by_node
        view_mode: view_mode,
        total_critical: total_critical,
        total_high: total_high,
        node_count: length(by_node),
        cluster_name: "default"  # Could be configurable
      }
    )
  end

  defp count_severity(alerts, severity) do
    Enum.count(alerts, &(&1.severity == severity))
  end

  defp calculate_mttr(alerts) do
    # Calculate mean time to respond (in minutes)
    # Time from alert creation to first status change (investigating/resolved)
    times = Enum.filter_map(
      alerts,
      fn alert ->
        alert.status in ["investigating", "resolved", "false_positive"] &&
          alert.inserted_at != nil &&
          alert.updated_at != nil
      end,
      fn alert ->
        inserted_seconds = alert.inserted_at |> NaiveDateTime.to_gregorian_seconds() |> elem(0)
        updated_seconds = alert.updated_at |> NaiveDateTime.to_gregorian_seconds() |> elem(0)
        (updated_seconds - inserted_seconds) / 60
      end
    )

    if length(times) > 0 do
      Enum.sum(times) / length(times) |> Float.round(1)
    else
      0.0
    end
  end

  defp naive_to_unix_ms(%NaiveDateTime{} = ndt) do
    ndt
    |> DateTime.from_naive!("Etc/UTC")
    |> DateTime.to_unix(:millisecond)
  end
  defp naive_to_unix_ms(_), do: 0

  defp format_timestamp(nil), do: "N/A"
  defp format_timestamp(timestamp) when is_integer(timestamp) do
    timestamp
    |> DateTime.from_unix!(:millisecond)
    |> Calendar.strftime("%H:%M:%S")
  end
  defp format_timestamp(%NaiveDateTime{} = ts) do
    Calendar.strftime(ts, "%H:%M:%S")
  end
  defp format_timestamp(timestamp) when is_number(timestamp) do
    timestamp
    |> trunc()
    |> DateTime.from_unix!(:millisecond)
    |> Calendar.strftime("%H:%M:%S")
  end
  defp format_timestamp(_), do: "N/A"

  defp severity_color(severity) do
    case severity do
      "critical" -> "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300"
      "high" -> "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-300"
      "medium" -> "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300"
      "low" -> "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300"
      "info" -> "bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-300"
      _ -> "bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-300"
    end
  end

  defp status_badge_color(status) do
    case status do
      :online -> "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300"
      :offline -> "bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-300"
      :isolated -> "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300"
      _ -> "bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-300"
    end
  end

  defp health_status_icon(health_status) do
    case health_status do
      :healthy -> {"hero-check-circle", "text-green-500"}
      :degraded -> {"hero-exclamation-triangle", "text-yellow-500"}
      :critical -> {"hero-x-circle", "text-red-500"}
      _ -> {"hero-question-mark-circle", "text-gray-400"}
    end
  end

  defp time_ago(nil), do: "Never"
  defp time_ago(timestamp) when is_integer(timestamp) do
    now = System.system_time(:millisecond)
    diff_seconds = div(now - timestamp, 1000)

    cond do
      diff_seconds < 60 -> "#{diff_seconds}s ago"
      diff_seconds < 3600 -> "#{div(diff_seconds, 60)}m ago"
      diff_seconds < 86400 -> "#{div(diff_seconds, 3600)}h ago"
      true -> "#{div(diff_seconds, 86400)}d ago"
    end
  end
  defp time_ago(%NaiveDateTime{} = ts) do
    ts
    |> naive_to_unix_ms()
    |> time_ago()
  end
  defp time_ago(_), do: "Unknown"

  defp assign_chart_period(socket, period) when period in ["24h", "7d", "30d"] do
    assign(socket, chart_period: period)
  end
  defp assign_chart_period(socket, _), do: assign(socket, chart_period: "24h")

  defp assign_alert_trend(socket) do
    period = socket.assigns[:chart_period] || "24h"
    org_id = socket.assigns.organization_id

    # Get alert trend data with severity breakdown - org-scoped for multi-tenant isolation
    trend_data = Alerts.get_alert_trend(period: period, organization_id: org_id)

    # Transform data for chart rendering
    chart_data = %{
      labels: Enum.map(trend_data.dataPoints, fn point ->
        format_chart_timestamp(point.timestamp, period)
      end),
      datasets: [
        %{
          label: "Critical",
          data: Enum.map(trend_data.dataPoints, & &1.critical),
          color: "#ef4444"
        },
        %{
          label: "High",
          data: Enum.map(trend_data.dataPoints, & &1.high),
          color: "#f97316"
        },
        %{
          label: "Medium",
          data: Enum.map(trend_data.dataPoints, & &1.medium),
          color: "#eab308"
        },
        %{
          label: "Low",
          data: Enum.map(trend_data.dataPoints, & &1.low),
          color: "#3b82f6"
        }
      ],
      total_data: Enum.map(trend_data.dataPoints, & &1.total)
    }

    # Count severity totals for the period
    severity_counts = Enum.reduce(trend_data.dataPoints, %{critical: 0, high: 0, medium: 0, low: 0}, fn point, acc ->
      %{
        critical: acc.critical + point.critical,
        high: acc.high + point.high,
        medium: acc.medium + point.medium,
        low: acc.low + point.low
      }
    end)

    assign(socket,
      chart_data: chart_data,
      trend_stats: trend_data,
      severity_counts: severity_counts
    )
  end

  defp format_chart_timestamp(timestamp, period) do
    datetime = DateTime.from_unix!(timestamp, :millisecond)

    case period do
      "24h" ->
        # Show hour (e.g., "14:00")
        Calendar.strftime(datetime, "%H:%M")

      "7d" ->
        # Show day and month (e.g., "Feb 20")
        Calendar.strftime(datetime, "%b %d")

      "30d" ->
        # Show day and month (e.g., "Feb 20")
        Calendar.strftime(datetime, "%b %d")

      _ ->
        Calendar.strftime(datetime, "%H:%M")
    end
  end

  defp build_alert_filter_params(params) do
    case params do
      %{"filter" => "last_hour"} ->
        now = DateTime.utc_now()
        one_hour_ago = DateTime.add(now, -3600, :second)
        %{
          "date_from" => DateTime.to_iso8601(one_hour_ago),
          "date_to" => DateTime.to_iso8601(now)
        }

      %{"filter" => "resolved"} ->
        %{"status" => "resolved"}

      %{"filter" => "severity", "value" => severity} ->
        %{"severity" => severity}

      _ ->
        %{}
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="min-h-screen bg-gray-50 dark:bg-gray-900">
      <!-- Header -->
      <div class="bg-white dark:bg-gray-800 shadow">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div class="flex items-center justify-between">
            <h1 class="text-3xl font-bold text-gray-900 dark:text-white">
              Security Operations Center
            </h1>
            <div class="flex items-center gap-2 text-sm text-gray-500 dark:text-gray-400">
              <.icon name="hero-arrow-path" class="w-4 h-4 animate-spin" />
              <span>Auto-refreshing every 5s</span>
            </div>
          </div>
        </div>
      </div>

      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <!-- KPI Cards -->
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <!-- Detections per Hour -->
          <div
            class="bg-white dark:bg-gray-800 rounded-lg shadow p-6 cursor-pointer hover:shadow-lg transition-shadow"
            phx-click="navigate_to_alerts"
            phx-value-filter="last_hour"
          >
            <div class="flex items-center justify-between">
              <div>
                <p class="text-sm font-medium text-gray-600 dark:text-gray-400">
                  Detections/Hour
                </p>
                <p class="text-3xl font-bold text-gray-900 dark:text-white mt-2">
                  <%= @detections_per_hour %>
                </p>
                <p class="text-xs text-gray-500 dark:text-gray-500 mt-1">
                  Click to view alerts
                </p>
              </div>
              <div class="p-3 bg-blue-100 dark:bg-blue-900 rounded-full">
                <.icon name="hero-shield-exclamation" class="w-8 h-8 text-blue-600 dark:text-blue-300" />
              </div>
            </div>
          </div>

          <!-- MTTR -->
          <div
            class="bg-white dark:bg-gray-800 rounded-lg shadow p-6 cursor-pointer hover:shadow-lg transition-shadow"
            phx-click="navigate_to_alerts"
            phx-value-filter="resolved"
          >
            <div class="flex items-center justify-between">
              <div>
                <p class="text-sm font-medium text-gray-600 dark:text-gray-400">
                  MTTR (minutes)
                </p>
                <p class="text-3xl font-bold text-gray-900 dark:text-white mt-2">
                  <%= @mttr_minutes %>
                </p>
                <p class="text-xs text-gray-500 dark:text-gray-500 mt-1">
                  View resolved alerts
                </p>
              </div>
              <div class="p-3 bg-purple-100 dark:bg-purple-900 rounded-full">
                <.icon name="hero-clock" class="w-8 h-8 text-purple-600 dark:text-purple-300" />
              </div>
            </div>
          </div>

          <!-- Block Rate -->
          <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
            <div class="flex items-center justify-between">
              <div>
                <p class="text-sm font-medium text-gray-600 dark:text-gray-400">
                  Block Rate
                </p>
                <p class="text-3xl font-bold text-gray-900 dark:text-white mt-2">
                  <%= @block_rate %>%
                </p>
              </div>
              <div class="p-3 bg-green-100 dark:bg-green-900 rounded-full">
                <.icon name="hero-shield-check" class="w-8 h-8 text-green-600 dark:text-green-300" />
              </div>
            </div>
          </div>

          <!-- Active Threats -->
          <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
            <div class="flex items-center justify-between">
              <div>
                <p class="text-sm font-medium text-gray-600 dark:text-gray-400">
                  Active Threats
                </p>
                <p class="text-3xl font-bold text-gray-900 dark:text-white mt-2">
                  <%= @active_threats %>
                </p>
              </div>
              <div class="p-3 bg-red-100 dark:bg-red-900 rounded-full">
                <.icon name="hero-fire" class="w-8 h-8 text-red-600 dark:text-red-300" />
              </div>
            </div>
          </div>
        </div>

        <!-- Alert Trend Chart -->
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow mb-8">
          <div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
            <div class="flex items-center justify-between">
              <h2 class="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                <.icon name="hero-chart-bar" class="w-5 h-5" />
                Alert Trend
              </h2>
              <div class="flex gap-2">
                <button
                  phx-click="change_chart_period"
                  phx-value-period="24h"
                  class={"px-3 py-1 rounded text-sm font-medium #{if @chart_period == "24h", do: "bg-blue-600 text-white", else: "bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300"}"}
                >
                  24h
                </button>
                <button
                  phx-click="change_chart_period"
                  phx-value-period="7d"
                  class={"px-3 py-1 rounded text-sm font-medium #{if @chart_period == "7d", do: "bg-blue-600 text-white", else: "bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300"}"}
                >
                  7d
                </button>
                <button
                  phx-click="change_chart_period"
                  phx-value-period="30d"
                  class={"px-3 py-1 rounded text-sm font-medium #{if @chart_period == "30d", do: "bg-blue-600 text-white", else: "bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300"}"}
                >
                  30d
                </button>
              </div>
            </div>
          </div>
          <div class="p-6">
            <!-- Severity Legend and Stats -->
            <div class="grid grid-cols-4 gap-4 mb-6">
              <div
                class="p-3 border-l-4 border-red-500 bg-red-50 dark:bg-red-900/20 rounded cursor-pointer hover:bg-red-100 dark:hover:bg-red-900/30"
                phx-click="navigate_to_alerts"
                phx-value-filter="severity"
                phx-value-value="critical"
              >
                <p class="text-xs font-medium text-gray-600 dark:text-gray-400">Critical</p>
                <p class="text-2xl font-bold text-gray-900 dark:text-white"><%= @severity_counts.critical %></p>
              </div>
              <div
                class="p-3 border-l-4 border-orange-500 bg-orange-50 dark:bg-orange-900/20 rounded cursor-pointer hover:bg-orange-100 dark:hover:bg-orange-900/30"
                phx-click="navigate_to_alerts"
                phx-value-filter="severity"
                phx-value-value="high"
              >
                <p class="text-xs font-medium text-gray-600 dark:text-gray-400">High</p>
                <p class="text-2xl font-bold text-gray-900 dark:text-white"><%= @severity_counts.high %></p>
              </div>
              <div
                class="p-3 border-l-4 border-yellow-500 bg-yellow-50 dark:bg-yellow-900/20 rounded cursor-pointer hover:bg-yellow-100 dark:hover:bg-yellow-900/30"
                phx-click="navigate_to_alerts"
                phx-value-filter="severity"
                phx-value-value="medium"
              >
                <p class="text-xs font-medium text-gray-600 dark:text-gray-400">Medium</p>
                <p class="text-2xl font-bold text-gray-900 dark:text-white"><%= @severity_counts.medium %></p>
              </div>
              <div
                class="p-3 border-l-4 border-blue-500 bg-blue-50 dark:bg-blue-900/20 rounded cursor-pointer hover:bg-blue-100 dark:hover:bg-blue-900/30"
                phx-click="navigate_to_alerts"
                phx-value-filter="severity"
                phx-value-value="low"
              >
                <p class="text-xs font-medium text-gray-600 dark:text-gray-400">Low</p>
                <p class="text-2xl font-bold text-gray-900 dark:text-white"><%= @severity_counts.low %></p>
              </div>
            </div>

            <!-- Chart Area -->
            <div class="h-80" id="alert-trend-chart" phx-hook="AlertTrendChart" data-chart={Jason.encode!(@chart_data)}>
              <!-- Server-side SVG fallback when JavaScript is disabled -->
              <svg viewBox="0 0 800 320" class="w-full h-full">
                <!-- Grid lines -->
                <%= for i <- 0..4 do %>
                  <line
                    x1="40"
                    y1={80 * i}
                    x2="800"
                    y2={80 * i}
                    stroke="#e5e7eb"
                    stroke-width="1"
                  />
                <% end %>

                <!-- Render data as stacked area chart -->
                <%= if @chart_data && length(@chart_data.labels) > 0 do %>
                  <% max_value = Enum.max(@chart_data.total_data ++ [1]) %>
                  <% x_step = 760 / max(length(@chart_data.labels) - 1, 1) %>

                  <!-- Critical area (bottom layer - red) -->
                  <% critical_points = @chart_data.datasets |> Enum.find(fn d -> d.label == "Critical" end) |> Map.get(:data) %>
                  <% critical_path = Enum.with_index(critical_points) |> Enum.map(fn {val, idx} ->
                    x = 40 + idx * x_step
                    y = 320 - (val / max_value * 300)
                    "#{if idx == 0, do: "M", else: "L"}#{x},#{y}"
                  end) |> Enum.join(" ") %>
                  <path d={"#{critical_path} L800,320 L40,320 Z"} fill="#ef4444" opacity="0.6" />

                  <!-- High area -->
                  <% high_points = @chart_data.datasets |> Enum.find(fn d -> d.label == "High" end) |> Map.get(:data) %>
                  <% high_cumulative = Enum.zip(critical_points, high_points) |> Enum.map(fn {c, h} -> c + h end) %>
                  <% high_path = Enum.with_index(high_cumulative) |> Enum.map(fn {val, idx} ->
                    x = 40 + idx * x_step
                    y = 320 - (val / max_value * 300)
                    "#{if idx == 0, do: "M", else: "L"}#{x},#{y}"
                  end) |> Enum.join(" ") %>
                  <% critical_base_path = Enum.with_index(critical_points) |> Enum.reverse() |> Enum.map(fn {val, idx} ->
                    x = 40 + idx * x_step
                    y = 320 - (val / max_value * 300)
                    "L#{x},#{y}"
                  end) |> Enum.join(" ") %>
                  <path d={"#{high_path} #{critical_base_path} Z"} fill="#f97316" opacity="0.6" />

                  <!-- X-axis labels -->
                  <%= for {label, idx} <- Enum.with_index(@chart_data.labels) do %>
                    <%= if rem(idx, max(div(length(@chart_data.labels), 8), 1)) == 0 do %>
                      <text
                        x={40 + idx * x_step}
                        y="340"
                        text-anchor="middle"
                        class="text-xs fill-gray-600 dark:fill-gray-400"
                      >
                        <%= label %>
                      </text>
                    <% end %>
                  <% end %>
                <% end %>
              </svg>
            </div>

            <!-- Trend Statistics -->
            <div class="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
              <div class="grid grid-cols-3 gap-4 text-center">
                <div>
                  <p class="text-xs text-gray-600 dark:text-gray-400">Total Detections</p>
                  <p class="text-lg font-bold text-gray-900 dark:text-white"><%= @trend_stats.totalDetections %></p>
                </div>
                <div>
                  <p class="text-xs text-gray-600 dark:text-gray-400">Trend</p>
                  <p class={"text-lg font-bold #{if @trend_stats.change > 0, do: "text-red-600", else: if @trend_stats.change < 0, do: "text-green-600", else: "text-gray-600"}"}>
                    <%= if @trend_stats.change > 0, do: "↑", else: if @trend_stats.change < 0, do: "↓", else: "→" %>
                    <%= abs(@trend_stats.change) %>%
                  </p>
                </div>
                <div>
                  <p class="text-xs text-gray-600 dark:text-gray-400">Avg/Day</p>
                  <p class="text-lg font-bold text-gray-900 dark:text-white"><%= @trend_stats.averagePerDay %></p>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Main Dashboard Grid -->
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <!-- Threat Feed (Left - 2/3 width) -->
          <div class="lg:col-span-2">
            <div class="bg-white dark:bg-gray-800 rounded-lg shadow">
              <div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                <h2 class="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                  <.icon name="hero-bell-alert" class="w-5 h-5" />
                  Live Threat Feed
                </h2>
              </div>
              <div class="divide-y divide-gray-200 dark:divide-gray-700 max-h-[600px] overflow-y-auto">
                <%= if Enum.empty?(@threat_feed) do %>
                  <div class="px-6 py-12 text-center text-gray-500 dark:text-gray-400">
                    <.icon name="hero-shield-check" class="w-12 h-12 mx-auto mb-3 text-gray-400" />
                    <p class="text-sm">No threats detected. System is clean.</p>
                  </div>
                <% else %>
                  <%= for alert <- @threat_feed do %>
                    <div class="px-6 py-4 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                      <div class="flex items-start justify-between gap-4">
                        <div class="flex-1 min-w-0">
                          <div class="flex items-center gap-2 mb-1">
                            <span class={"inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium #{severity_color(alert.severity)}"}>
                              <%= String.upcase(alert.severity) %>
                            </span>
                            <span class="text-xs text-gray-500 dark:text-gray-400">
                              <%= format_timestamp(alert.timestamp) %>
                            </span>
                          </div>
                          <p class="text-sm font-medium text-gray-900 dark:text-white truncate">
                            <%= alert.title %>
                          </p>
                          <%= if alert.agent_id do %>
                            <p class="text-xs text-gray-500 dark:text-gray-400 mt-1">
                              Agent: <%= alert.agent_id |> String.slice(0..7) %>
                            </p>
                          <% end %>
                        </div>
                        <div class="flex-shrink-0">
                          <a
                            href={"/alerts/#{alert.id}"}
                            class="inline-flex items-center px-3 py-1 border border-gray-300 dark:border-gray-600 rounded-md text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700"
                          >
                            View
                          </a>
                        </div>
                      </div>
                    </div>
                  <% end %>
                <% end %>
              </div>
            </div>
          </div>

          <!-- Agent Status (Right - 1/3 width) -->
          <div class="lg:col-span-1">
            <div class="bg-white dark:bg-gray-800 rounded-lg shadow">
              <div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                <h2 class="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                  <.icon name="hero-cpu-chip" class="w-5 h-5" />
                  Agent Status
                </h2>
                <div class="flex items-center gap-4 mt-2 text-sm">
                  <span class="text-green-600 dark:text-green-400">
                    <.icon name="hero-check-circle" class="w-4 h-4 inline mr-1" />
                    <%= @online_count %> online
                  </span>
                  <span class="text-gray-500 dark:text-gray-400">
                    <.icon name="hero-x-circle" class="w-4 h-4 inline mr-1" />
                    <%= @offline_count %> offline
                  </span>
                  <%= if @isolated_count > 0 do %>
                    <span class="text-red-600 dark:text-red-400">
                      <.icon name="hero-shield-exclamation" class="w-4 h-4 inline mr-1" />
                      <%= @isolated_count %> isolated
                    </span>
                  <% end %>
                </div>
              </div>
              <div class="divide-y divide-gray-200 dark:divide-gray-700 max-h-[600px] overflow-y-auto">
                <%= if Enum.empty?(@agent_status) do %>
                  <div class="px-6 py-12 text-center text-gray-500 dark:text-gray-400">
                    <.icon name="hero-server" class="w-12 h-12 mx-auto mb-3 text-gray-400" />
                    <p class="text-sm">No agents registered</p>
                  </div>
                <% else %>
                  <%= for agent <- @agent_status do %>
                    <div class="px-6 py-4 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                      <div class="flex items-start justify-between gap-3">
                        <div class="flex-1 min-w-0">
                          <div class="flex items-center gap-2 mb-1">
                            <% {icon, icon_color} = health_status_icon(agent.health_status) %>
                            <.icon name={icon} class={"w-4 h-4 #{icon_color}"} />
                            <p class="text-sm font-medium text-gray-900 dark:text-white truncate">
                              <%= agent.hostname %>
                            </p>
                          </div>
                          <div class="flex items-center gap-2 text-xs text-gray-500 dark:text-gray-400">
                            <span class={"inline-flex items-center px-2 py-0.5 rounded text-xs font-medium #{status_badge_color(agent.status)}"}>
                              <%= agent.status %>
                            </span>
                            <span><%= agent.os_type %></span>
                          </div>

                          <!-- Health Metrics -->
                          <div class="mt-2 space-y-1">
                            <!-- CPU Usage -->
                            <div>
                              <div class="flex items-center justify-between text-xs text-gray-600 dark:text-gray-400 mb-0.5">
                                <span>CPU</span>
                                <span><%= Float.round(agent.cpu_usage, 1) %>%</span>
                              </div>
                              <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-1.5">
                                <div
                                  class={"h-1.5 rounded-full #{if agent.cpu_usage > 90, do: "bg-red-500", else: if agent.cpu_usage > 70, do: "bg-yellow-500", else: "bg-green-500"}"}
                                  style={"width: #{min(agent.cpu_usage, 100)}%"}
                                >
                                </div>
                              </div>
                            </div>

                            <!-- Memory Usage -->
                            <div>
                              <div class="flex items-center justify-between text-xs text-gray-600 dark:text-gray-400 mb-0.5">
                                <span>Memory</span>
                                <span><%= Float.round(agent.memory_usage, 1) %>%</span>
                              </div>
                              <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-1.5">
                                <div
                                  class={"h-1.5 rounded-full #{if agent.memory_usage > 95, do: "bg-red-500", else: if agent.memory_usage > 80, do: "bg-yellow-500", else: "bg-blue-500"}"}
                                  style={"width: #{min(agent.memory_usage, 100)}%"}
                                >
                                </div>
                              </div>
                            </div>

                            <!-- Disk Usage -->
                            <div>
                              <div class="flex items-center justify-between text-xs text-gray-600 dark:text-gray-400 mb-0.5">
                                <span>Disk</span>
                                <span><%= Float.round(agent.disk_usage, 1) %>%</span>
                              </div>
                              <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-1.5">
                                <div
                                  class={"h-1.5 rounded-full #{if agent.disk_usage > 90, do: "bg-red-500", else: if agent.disk_usage > 75, do: "bg-yellow-500", else: "bg-purple-500"}"}
                                  style={"width: #{min(agent.disk_usage, 100)}%"}
                                >
                                </div>
                              </div>
                            </div>
                          </div>

                          <p class="text-xs text-gray-500 dark:text-gray-400 mt-2">
                            Last seen: <%= time_ago(agent.last_seen_at) %>
                          </p>
                        </div>
                      </div>
                    </div>
                  <% end %>
                <% end %>
              </div>
            </div>
          </div>
        </div>

        <!-- Supply Chain Security Widget -->
        <div class="mt-6">
          <div class="bg-white dark:bg-gray-800 rounded-lg shadow">
            <DashboardWidgets.supply_chain_alerts data={@supply_chain_data} />
          </div>
        </div>

        <!-- Kubernetes Security Widget -->
        <div class="mt-6">
          <div class="bg-white dark:bg-gray-800 rounded-lg shadow">
            <KubernetesSecurityWidget.kubernetes_security data={@k8s_security_data} />
          </div>
        </div>
      </div>
    </div>
    """
  end
end
