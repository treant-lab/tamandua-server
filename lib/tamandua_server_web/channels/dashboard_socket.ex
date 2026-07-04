defmodule TamanduaServerWeb.DashboardSocket do
  @moduledoc """
  Socket for dashboard real-time updates.

  This socket handles browser connections for the dashboard UI,
  providing real-time updates for alerts, agents, and events.

  ## Features

  - JWT-based authentication via Guardian
  - Connection audit logging for compliance
  - Client IP and User-Agent tracking
  - Channel join/leave audit trail
  - Development mode fallback with mock user
  """
  use Phoenix.Socket, log: false
  require Logger

  alias TamanduaServer.AuditLog

  # Channels
  channel "dashboard:*", TamanduaServerWeb.DashboardChannel
  channel "alerts:*", TamanduaServerWeb.AlertChannel
  channel "agents:*", TamanduaServerWeb.AgentStatusChannel
  channel "events:*", TamanduaServerWeb.EventsChannel
  channel "geo:*", TamanduaServerWeb.GeoChannel
  channel "shell:*", TamanduaServerWeb.ShellChannel
  channel "live_response:*", TamanduaServerWeb.LiveResponseChannel
  channel "supervisors:*", TamanduaServerWeb.SupervisorChannel

  @impl true
  def connect(%{"token" => token}, socket, connect_info) do
    # Extract connection metadata
    ip_address = extract_ip(connect_info)
    user_agent = extract_user_agent(connect_info)

    case TamanduaServer.Guardian.decode_and_verify(token) do
      {:ok, claims} ->
        user_id = claims["sub"]

        # Fetch the full user for shell channel permission checks
        user = TamanduaServer.Accounts.get_user(user_id)

        if user do
          socket =
            socket
            |> assign(:user_id, user_id)
            |> assign(:current_user, user)
            |> assign(:ip_address, ip_address)
            |> assign(:user_agent, user_agent)
            |> assign(:connected_at, System.system_time(:millisecond))

          # Audit log the connection
          log_socket_connect(user, ip_address, user_agent)

          {:ok, socket}
        else
          # User not found in database
          log_auth_failure("user_not_found", user_id, ip_address, user_agent)
          :error
        end

      {:error, reason} ->
        case authenticate_api_token(token, socket, ip_address, user_agent) do
          {:ok, socket} ->
            {:ok, socket}

          :error ->
            case maybe_allow_lab_light_socket(socket, connect_info) do
              {:ok, socket} ->
                Logger.debug("[DashboardSocket] Lab light socket fallback after token error #{inspect(reason)} from #{ip_address}")
                {:ok, socket}

              :error ->
                log_auth_failure(reason, nil, ip_address, user_agent)
                :error
            end
        end
    end
  end

  defp authenticate_api_token(token, socket, ip_address, user_agent) do
    with {:error, _} <- TamanduaServer.CLIAuth.verify_token(token),
         nil <- TamanduaServer.Accounts.get_user_by_api_token(token) do
      :error
    else
      {:ok, user} ->
        socket =
          socket
          |> assign(:user_id, user.id)
          |> assign(:current_user, user)
          |> assign(:ip_address, ip_address)
          |> assign(:user_agent, user_agent)
          |> assign(:connected_at, System.system_time(:millisecond))

        log_socket_connect(user, ip_address, user_agent)
        {:ok, socket}

      user ->
        socket =
          socket
          |> assign(:user_id, user.id)
          |> assign(:current_user, user)
          |> assign(:ip_address, ip_address)
          |> assign(:user_agent, user_agent)
          |> assign(:connected_at, System.system_time(:millisecond))

        log_socket_connect(user, ip_address, user_agent)
        {:ok, socket}
    end
  end

  def connect(_params, socket, connect_info) do
    case maybe_allow_lab_light_socket(socket, connect_info) do
          {:ok, socket} ->
            {:ok, socket}

          :error ->
            # Allow anonymous connections in development only
            if Application.get_env(:tamandua_server, :env) == :dev do
              ip_address = extract_ip(connect_info)
              user_agent = extract_user_agent(connect_info)

              # Create a mock dev user for development
              dev_user = %{
                id: "dev-user",
                email: "dev@tamandua.local",
                role: "admin",
                organization_id: nil,
                permissions: ["shell:access", "response:execute", "forensics:collect"]
              }

              socket =
                socket
                |> assign(:user_id, "dev-user")
                |> assign(:current_user, dev_user)
                |> assign(:ip_address, ip_address)
                |> assign(:user_agent, user_agent)
                |> assign(:connected_at, System.system_time(:millisecond))

              Logger.debug("[DashboardSocket] Dev mode connection from #{ip_address}")

              {:ok, socket}
            else
              ip_address = extract_ip(connect_info)
              user_agent = extract_user_agent(connect_info)
              log_auth_failure("missing_token", nil, ip_address, user_agent)
              :error
            end
        end
  end

  @impl true
  def id(socket), do: "dashboard:#{socket.assigns[:user_id] || "anon"}"

  # ===========================================================================
  # Connection Info Extraction
  # ===========================================================================

  defp extract_ip(connect_info) do
    # Try x_forwarded_for first (for load balancers/proxies)
    x_forwarded = get_in(connect_info, [:x_headers, "x-forwarded-for"])

    cond do
      is_binary(x_forwarded) && x_forwarded != "" ->
        # Take first IP from comma-separated list
        x_forwarded |> String.split(",") |> List.first() |> String.trim()

      # Fall back to peer_data
      peer_data = connect_info[:peer_data] ->
        case peer_data do
          %{address: address} when is_tuple(address) ->
            address |> :inet.ntoa() |> to_string()
          _ ->
            "unknown"
        end

      true ->
        "unknown"
    end
  end

  defp extract_user_agent(connect_info) do
    case get_in(connect_info, [:x_headers, "user-agent"]) do
      ua when is_binary(ua) -> ua
      _ -> "unknown"
    end
  end

  defp maybe_allow_lab_light_socket(socket, connect_info) do
    cond do
      # SECURITY: Only allow LAB_LIGHT mode in dev/test environments
      Application.get_env(:tamandua_server, :env) not in [:dev, :test] ->
        :error

      # Require explicit LAB_LIGHT flag
      System.get_env("TAMANDUA_LAB_LIGHT", "false") != "true" ->
        :error

      # SECURITY: Only allow from loopback addresses to prevent remote exploitation
      not is_loopback_connection?(connect_info) ->
        ip_address = extract_ip(connect_info)
        Logger.warning("[DashboardSocket] LAB_LIGHT rejected: non-loopback connection attempt from #{ip_address}")
        :error

      true ->
        ip_address = extract_ip(connect_info)
        user_agent = extract_user_agent(connect_info)

        case TamanduaServer.Accounts.get_user_by_email("admin@tamandua.local") do
          nil ->
            Logger.warning("[DashboardSocket] LAB_LIGHT rejected: admin@tamandua.local user not found")
            :error

          user ->
            Logger.warning("[DashboardSocket] LAB_LIGHT mode: authenticated as admin from loopback (#{ip_address})")

            {:ok,
             socket
             |> assign(:user_id, user.id)
             |> assign(:current_user, user)
             |> assign(:ip_address, ip_address)
             |> assign(:user_agent, user_agent)
             |> assign(:connected_at, System.system_time(:millisecond))}
        end
    end
  rescue
    e ->
      Logger.warning("[DashboardSocket] LAB_LIGHT error: #{inspect(e)}")
      :error
  end

  # Check if connection originates from loopback address (127.x.x.x or ::1)
  defp is_loopback_connection?(connect_info) do
    peer_data = connect_info[:peer_data] || %{}
    address = peer_data[:address]

    case address do
      # IPv4 loopback (127.0.0.0/8)
      {127, _, _, _} -> true
      # IPv6 loopback (::1)
      {0, 0, 0, 0, 0, 0, 0, 1} -> true
      # String representations (shouldn't normally happen, but handle anyway)
      "127.0.0.1" -> true
      "::1" -> true
      # Also handle localhost binding (0.0.0.0 binds to all, but if peer is localhost)
      _ -> false
    end
  end

  # ===========================================================================
  # Audit Logging
  # ===========================================================================

  defp log_socket_connect(user, ip_address, user_agent) do
    Task.start(fn ->
      AuditLog.log(%{
        user_id: user.id,
        action: "dashboard.socket_connect",
        action_type: "data_access",
        resource_type: "dashboard_socket",
        severity: :info,
        category: "data_access",
        metadata: %{
          channel: "dashboard",
          transport: "websocket"
        },
        ip_address: ip_address,
        user_agent: user_agent,
        organization_id: user.organization_id
      })
    end)
  end

  defp log_auth_failure(reason, user_id, ip_address, user_agent) do
    # Don't log in dev mode to reduce noise
    unless Application.get_env(:tamandua_server, :env) == :dev do
      Logger.warning("[DashboardSocket] Auth failed: #{inspect(reason)} from #{ip_address}")

      Task.start(fn ->
        AuditLog.log(%{
          user_id: user_id,
          action: "dashboard.socket_auth_failed",
          action_type: "authentication",
          resource_type: "dashboard_socket",
          severity: :warning,
          category: "authentication",
          success: false,
          error_message: to_string(reason),
          metadata: %{
            failure_reason: to_string(reason)
          },
          ip_address: ip_address,
          user_agent: user_agent,
          organization_id: nil
        })
      end)
    end
  end

  @doc """
  Log a channel join event. Called from individual channels.
  """
  def log_channel_join(socket, channel_topic) do
    user = socket.assigns[:current_user]

    if user && user.id != "dev-user" do
      Task.start(fn ->
        AuditLog.log(%{
          user_id: user.id,
          action: "dashboard.channel_join",
          action_type: "data_access",
          resource_type: "dashboard_channel",
          resource_id: channel_topic,
          severity: :info,
          category: "data_access",
          metadata: %{
            channel: channel_topic,
            transport: "websocket"
          },
          ip_address: socket.assigns[:ip_address],
          user_agent: socket.assigns[:user_agent],
          organization_id: get_user_organization_id(user)
        })
      end)
    end

    :ok
  end

  @doc """
  Log a channel action event (acknowledge alert, send command, etc).
  """
  def log_channel_action(socket, action, resource_type, resource_id, metadata \\ %{}) do
    user = socket.assigns[:current_user]

    if user && user.id != "dev-user" do
      Task.start(fn ->
        AuditLog.log(%{
          user_id: user.id,
          action: "dashboard.#{action}",
          action_type: "data_access",
          resource_type: resource_type,
          resource_id: resource_id,
          severity: :info,
          category: "data_access",
          metadata: metadata,
          ip_address: socket.assigns[:ip_address],
          user_agent: socket.assigns[:user_agent],
          organization_id: get_user_organization_id(user)
        })
      end)
    end

    :ok
  end

  defp get_user_organization_id(%{organization_id: organization_id}), do: organization_id
  defp get_user_organization_id(_), do: nil
end

defmodule TamanduaServerWeb.DashboardChannel do
  @moduledoc """
  Channel for general dashboard updates.

  Supports:
  - stats_update: Real-time dashboard statistics
  - new_alert: New alerts as they are created
  - alert_updated: Updates to existing alerts
  - agent_status: Agent connection/status changes
  """
  use TamanduaServerWeb, :channel
  require Logger

  alias TamanduaServerWeb.DashboardSocket

  # Alert broadcasts go out on the global "dashboard:lobby" topic; intercept them
  # so handle_out can drop any alert that does not belong to this socket's org.
  intercept ["new_alert", "alert_updated"]

  @impl true
  def join("dashboard:lobby", _params, socket) do
    # Log channel join for audit
    DashboardSocket.log_channel_join(socket, "dashboard:lobby")

    # Capture the org for outbound cross-tenant filtering (handle_out).
    socket = assign(socket, :org_id, get_user_org_id(socket))

    # Send initial stats upon join
    send(self(), :send_initial_stats)
    {:ok, socket}
  end

  @impl true
  def handle_out("new_alert", payload, socket) do
    push_if_allowed(socket, "new_alert", payload, payload)

    {:noreply, socket}
  end

  def handle_out("alert_updated", %{alert: alert} = payload, socket) do
    push_if_allowed(socket, "alert_updated", payload, alert)

    {:noreply, socket}
  end

  def handle_out(event, payload, socket) do
    push(socket, event, payload)
    {:noreply, socket}
  end

  # Only deliver when the alert's org matches the subscriber's org. Handles both
  # the serialized payload (organizationId) and a raw Ecto struct
  # (organization_id). Fail closed if either side is missing an org.
  defp push_if_allowed(socket, event, payload, tenant_payload) do
    if cross_tenant_allowed?(tenant_payload, socket) do
      push(socket, event, payload)
    end
  rescue
    error ->
      Logger.warning("[DashboardChannel] Dropped #{event} broadcast: #{Exception.message(error)}")
      :ok
  end

  defp cross_tenant_allowed?(payload, socket) do
    org = payload_org_id(payload)
    socket_org = socket.assigns[:org_id]
    not is_nil(socket_org) and not is_nil(org) and to_string(socket_org) == to_string(org)
  end

  defp payload_org_id(%{organizationId: org}) when not is_nil(org), do: org
  defp payload_org_id(%{"organizationId" => org}) when not is_nil(org), do: org
  defp payload_org_id(%{organization_id: org}), do: org
  defp payload_org_id(%{"organization_id" => org}), do: org
  defp payload_org_id(_), do: nil

  @impl true
  def handle_info(:send_initial_stats, socket) do
    org_id = get_user_org_id(socket)
    stats = get_dashboard_stats(org_id)
    push(socket, "stats_update", stats)
    {:noreply, socket}
  end

  def handle_info(_msg, socket), do: {:noreply, socket}

  @impl true
  def handle_in("ping", _params, socket) do
    {:reply, {:ok, %{message: "pong"}}, socket}
  end

  @impl true
  def handle_in("refresh_stats", _params, socket) do
    org_id = get_user_org_id(socket)
    stats = get_dashboard_stats(org_id)
    {:reply, {:ok, stats}, socket}
  end

  defp get_user_org_id(socket) do
    case socket.assigns[:current_user] do
      %{organization_id: org_id} -> org_id
      user when is_map(user) -> user[:organization_id]
      _ -> nil
    end
  end

  defp get_dashboard_stats(org_id) do
    alias TamanduaServer.{Agents, Alerts, Telemetry, Detection}

    # Get counts with individual error handling to avoid all-or-nothing failures
    # Multi-tenant scoped: all counts are filtered by organization_id
    total_agents = try do
      Agents.count_agents_for_org(org_id)
    rescue
      e ->
        Logger.warning("[DashboardChannel] Failed to count agents: #{inspect(e)}")
        nil
    end

    online_agents = try do
      Agents.count_online_for_org(org_id)
    rescue
      e ->
        Logger.warning("[DashboardChannel] Failed to count online agents: #{inspect(e)}")
        nil
    end

    # Get agent status breakdown from Registry (org-scoped)
    status_counts = try do
      TamanduaServer.Agents.Registry.count_by_status_for_org(org_id)
    rescue
      e ->
        Logger.warning("[DashboardChannel] Failed to get agent status counts: #{inspect(e)}")
        %{}
    end

    open_alerts = try do
      Alerts.count_active_for_org(org_id)
    rescue
      e ->
        Logger.warning("[DashboardChannel] Failed to count open alerts: #{inspect(e)}")
        nil
    end

    critical_alerts = try do
      Alerts.count_by_severity_for_org(org_id, :critical)
    rescue
      e ->
        Logger.warning("[DashboardChannel] Failed to count critical alerts: #{inspect(e)}")
        nil
    end

    high_alerts = try do
      Alerts.count_by_severity_for_org(org_id, :high)
    rescue
      e ->
        Logger.warning("[DashboardChannel] Failed to count high alerts: #{inspect(e)}")
        nil
    end

    events_today = try do
      Telemetry.count_events_today_for_org(org_id)
    rescue
      e ->
        Logger.warning("[DashboardChannel] Failed to count today's events: #{inspect(e)}")
        nil
    end

    detections_today = try do
      Detection.count_detections_today_for_org(org_id)
    rescue
      e ->
        Logger.warning("[DashboardChannel] Failed to count today's detections: #{inspect(e)}")
        nil
    end

    %{
      totalAgents: total_agents,
      onlineAgents: online_agents,
      offlineAgents: Map.get(status_counts, :offline, 0),
      degradedAgents: Map.get(status_counts, :degraded, 0),
      openAlerts: open_alerts,
      criticalAlerts: critical_alerts,
      highAlerts: high_alerts,
      eventsToday: events_today,
      detectionsToday: detections_today,
      timestamp: System.system_time(:millisecond)
    }
  end
end

defmodule TamanduaServerWeb.AlertChannel do
  @moduledoc """
  Channel for real-time alert updates.
  """
  use TamanduaServerWeb, :channel
  require Logger

  alias TamanduaServerWeb.DashboardSocket
  alias TamanduaServer.Alerts

  # Alerts broadcast on the global "alerts:feed" topic; intercept so handle_out
  # can drop any alert that does not belong to this socket's org.
  intercept ["new_alert", "alert_updated"]

  @impl true
  def join("alerts:feed", _params, socket) do
    DashboardSocket.log_channel_join(socket, "alerts:feed")
    {:ok, assign(socket, :org_id, get_user_org_id(socket))}
  end

  def join("alerts:" <> alert_id, _params, socket) do
    # Validate tenant ownership before allowing join
    org_id = get_user_org_id(socket)

    case Alerts.get_alert_for_org(org_id, alert_id) do
      {:ok, alert} ->
        DashboardSocket.log_channel_join(socket, "alerts:#{alert_id}")

        {:ok,
         socket
         |> assign(:alert_id, alert_id)
         |> assign(:alert, alert)
         |> assign(:org_id, org_id)}

      {:error, :not_found} ->
        {:error, %{reason: "unauthorized"}}
    end
  end

  @impl true
  def handle_out("new_alert", payload, socket) do
    push_if_allowed(socket, "new_alert", payload, payload)

    {:noreply, socket}
  end

  def handle_out("alert_updated", %{alert: alert} = payload, socket) do
    push_if_allowed(socket, "alert_updated", payload, alert)

    {:noreply, socket}
  end

  def handle_out(event, payload, socket) do
    push(socket, event, payload)
    {:noreply, socket}
  end

  # Only deliver when the alert's org matches the subscriber's org. Handles both
  # the serialized payload (organizationId) and a raw Ecto struct
  # (organization_id, used by the acknowledge broadcast). Fail closed.
  defp push_if_allowed(socket, event, payload, tenant_payload) do
    if cross_tenant_allowed?(tenant_payload, socket) do
      push(socket, event, payload)
    end
  rescue
    error ->
      Logger.warning("[AlertChannel] Dropped #{event} broadcast: #{Exception.message(error)}")
      :ok
  end

  defp cross_tenant_allowed?(payload, socket) do
    org = payload_org_id(payload)
    socket_org = socket.assigns[:org_id]
    not is_nil(socket_org) and not is_nil(org) and to_string(socket_org) == to_string(org)
  end

  defp payload_org_id(%{organizationId: org}) when not is_nil(org), do: org
  defp payload_org_id(%{"organizationId" => org}) when not is_nil(org), do: org
  defp payload_org_id(%{organization_id: org}), do: org
  defp payload_org_id(%{"organization_id" => org}), do: org
  defp payload_org_id(_), do: nil

  defp get_user_org_id(socket) do
    case socket.assigns[:current_user] do
      %{organization_id: org_id} -> org_id
      user when is_map(user) -> user[:organization_id]
      _ -> nil
    end
  end

  @impl true
  def handle_in("acknowledge", %{"alert_id" => alert_id}, socket) do
    org_id = get_user_org_id(socket)

    # Validate tenant ownership before acknowledging
    case Alerts.get_alert_for_org(org_id, alert_id) do
      {:ok, alert} ->
        attrs = %{
          status: :acknowledged,
          acknowledged_by: socket.assigns[:user_id],
          acknowledged_at: DateTime.utc_now()
        }

        case Alerts.update_alert(alert, attrs) do
          {:ok, updated_alert} ->
            # Audit log the acknowledgment
            DashboardSocket.log_channel_action(
              socket,
              "alert_acknowledged",
              "alert",
              alert_id,
              %{previous_status: to_string(alert.status)}
            )

            broadcast!(socket, "alert_updated", %{alert: updated_alert})
            {:reply, {:ok, %{alert: updated_alert}}, socket}

          {:error, reason} ->
            {:reply, {:error, %{reason: inspect(reason)}}, socket}
        end

      {:error, :not_found} ->
        {:reply, {:error, %{reason: "Alert not found"}}, socket}
    end
  end
end

defmodule TamanduaServerWeb.AgentStatusChannel do
  @moduledoc """
  Channel for real-time agent status updates (for dashboard).
  """
  use TamanduaServerWeb, :channel

  alias TamanduaServerWeb.DashboardSocket
  alias TamanduaServer.Agents

  @impl true
  def join("agents:status", _params, socket) do
    DashboardSocket.log_channel_join(socket, "agents:status")
    {:ok, socket}
  end

  def join("agents:" <> agent_id, _params, socket) do
    # Validate tenant ownership before allowing join
    org_id = get_user_org_id(socket)

    case Agents.get_agent_for_org(org_id, agent_id) do
      {:ok, agent} ->
        DashboardSocket.log_channel_join(socket, "agents:#{agent_id}")
        {:ok, assign(socket, :agent_id, agent_id) |> assign(:agent, agent)}

      {:error, :not_found} ->
        {:error, %{reason: "unauthorized"}}
    end
  end

  defp get_user_org_id(socket) do
    case socket.assigns[:current_user] do
      %{organization_id: org_id} -> org_id
      user when is_map(user) -> user[:organization_id]
      _ -> nil
    end
  end

  @impl true
  def handle_in("get_status", %{"agent_id" => agent_id}, socket) do
    org_id = get_user_org_id(socket)

    # Validate tenant ownership before returning status
    case Agents.get_agent_for_org(org_id, agent_id) do
      {:ok, _agent} ->
        case Agents.Registry.get(agent_id) do
          {:ok, agent_info} ->
            {:reply, {:ok, %{agent: agent_info}}, socket}

          _ ->
            {:reply, {:error, %{reason: "Agent not found"}}, socket}
        end

      {:error, :not_found} ->
        {:reply, {:error, %{reason: "Agent not found"}}, socket}
    end
  end
end

defmodule TamanduaServerWeb.EventsChannel do
  @moduledoc """
  Channel for real-time event streaming.

  Topics:
  - events:all - All events from all agents (org-scoped via filter)
  - events:{agent_id} - Events from a specific agent
  """
  use TamanduaServerWeb, :channel
  require Logger

  alias TamanduaServerWeb.DashboardSocket
  alias TamanduaServer.Agents

  @impl true
  def join("events:all", _params, socket) do
    # Org-scoped: only subscribe to this tenant's event stream. The ingestor
    # broadcasts per-org on "dashboard:events:#{org_id}" to prevent cross-tenant
    # leakage. A socket with no resolvable org is rejected (fail closed).
    case get_user_org_id(socket) do
      nil ->
        {:error, %{reason: "unauthorized"}}

      org_id ->
        DashboardSocket.log_channel_join(socket, "events:all")
        Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "dashboard:events:#{org_id}")
        {:ok, socket}
    end
  end

  def join("events:" <> agent_id, _params, socket) do
    # Validate tenant ownership before allowing join
    org_id = get_user_org_id(socket)

    case Agents.get_agent_for_org(org_id, agent_id) do
      {:ok, agent} ->
        DashboardSocket.log_channel_join(socket, "events:#{agent_id}")
        Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "agent:#{agent_id}:events")
        {:ok, assign(socket, :agent_id, agent_id) |> assign(:agent, agent)}

      {:error, :not_found} ->
        {:error, %{reason: "unauthorized"}}
    end
  end

  defp get_user_org_id(socket) do
    case socket.assigns[:current_user] do
      %{organization_id: org_id} -> org_id
      user when is_map(user) -> user[:organization_id]
      _ -> nil
    end
  end

  @impl true
  def handle_in("subscribe", %{"filters" => filters}, socket) do
    socket = assign(socket, :filters, filters)
    {:reply, {:ok, %{subscribed: true}}, socket}
  end

  @impl true
  def handle_in("unsubscribe", _params, socket) do
    socket = assign(socket, :filters, nil)
    {:reply, {:ok, %{subscribed: false}}, socket}
  end

  @impl true
  def handle_info({:new_events, events}, socket) do
    filters = socket.assigns[:filters]

    serialized =
      events
      |> Enum.map(&serialize_event/1)
      |> apply_filters(filters)

    if length(serialized) > 0 do
      push(socket, "events_batch", %{events: serialized})
    end

    {:noreply, socket}
  end

  def handle_info(_msg, socket), do: {:noreply, socket}

  defp serialize_event(event) do
    event_type = to_string(event[:event_type] || event["event_type"] || "unknown")
    payload = event[:payload] || event["payload"] || %{}

    %{
      id: event[:event_id] || event["event_id"] || Ecto.UUID.generate(),
      eventType: event_type,
      agentId: to_string(event[:agent_id] || event["agent_id"] || ""),
      timestamp: event[:timestamp] || event["timestamp"] || System.system_time(:millisecond),
      severity: to_string(event[:severity] || event["severity"] || derive_severity(event_type, payload)),
      summary: build_summary(event_type, payload),
      payload: normalize_payload(payload)
    }
  end

  defp derive_severity(event_type, _payload) do
    case event_type do
      t when t in ["alert", "detection"] -> "high"
      "dns_query" -> "info"
      "process_create" -> "info"
      "file_create" -> "info"
      "network_connection" -> "info"
      _ -> "info"
    end
  end

  defp build_summary(event_type, payload) do
    case event_type do
      "dns_query" ->
        domain = payload[:domain] || payload["domain"] || payload[:query] || payload["query"] || ""
        "DNS query: #{domain}"

      "process_create" ->
        name = payload[:name] || payload["name"] || ""
        pid = payload[:pid] || payload["pid"] || ""
        "Process created: #{name} (PID #{pid})"

      "file_create" ->
        path = payload[:path] || payload["path"] || ""
        "File created: #{path}"

      "network_connection" ->
        dest = payload[:dest_ip] || payload["dest_ip"] || payload[:remote_ip] || payload["remote_ip"] || ""
        port = payload[:dest_port] || payload["dest_port"] || payload[:remote_port] || payload["remote_port"] || ""
        "Connection to #{dest}:#{port}"

      _ ->
        event_type
    end
  end

  defp normalize_payload(payload) when is_map(payload) do
    payload
    |> Enum.map(fn {k, v} -> {to_string(k), v} end)
    |> Map.new()
  end
  defp normalize_payload(_), do: %{}

  defp apply_filters(events, nil), do: events
  defp apply_filters(events, filters) when is_map(filters) do
    event_types = filters["event_types"] || filters[:event_types]

    if event_types && is_list(event_types) && length(event_types) > 0 do
      Enum.filter(events, fn e -> e.eventType in event_types end)
    else
      events
    end
  end
  defp apply_filters(events, _), do: events
end

# ==============================================================================
# Geo Channel - Real-time threat map updates
# ==============================================================================

defmodule TamanduaServerWeb.GeoChannel do
  @moduledoc """
  Channel for real-time threat map updates.

  Topics:
  - geo:map - All geo data (threats, agents, flows, summary)

  Provides:
  - Initial map data on join
  - Real-time updates when new threats/alerts arrive
  - Periodic refresh of threat data
  """
  use TamanduaServerWeb, :channel

  alias TamanduaServer.Enrichment.GeoStats
  alias TamanduaServerWeb.DashboardSocket

  @impl true
  def join("geo:map", params, socket) do
    DashboardSocket.log_channel_join(socket, "geo:map")

    timeframe = params["timeframe"] || "24h"
    socket = assign(socket, :timeframe, timeframe)

    # Subscribe to geo updates
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "geo:updates")

    # Send initial data
    send(self(), :send_initial_data)

    {:ok, socket}
  end

  @impl true
  def handle_info(:send_initial_data, socket) do
    timeframe = socket.assigns[:timeframe] || "24h"
    data = get_map_data(timeframe)
    push(socket, "map_data", data)
    {:noreply, socket}
  end

  @impl true
  def handle_info({:geo_update, data}, socket) do
    push(socket, "map_update", data)
    {:noreply, socket}
  end

  @impl true
  def handle_info(_, socket), do: {:noreply, socket}

  @impl true
  def handle_in("refresh", params, socket) do
    timeframe = params["timeframe"] || socket.assigns[:timeframe] || "24h"
    socket = assign(socket, :timeframe, timeframe)
    data = get_map_data(timeframe)
    {:reply, {:ok, data}, socket}
  end

  @impl true
  def handle_in("set_timeframe", %{"timeframe" => timeframe}, socket) do
    socket = assign(socket, :timeframe, timeframe)
    data = get_map_data(timeframe)
    push(socket, "map_data", data)
    {:reply, {:ok, %{timeframe: timeframe}}, socket}
  end

  defp get_map_data(timeframe) do
    threats = GeoStats.get_threat_origins(timeframe)
    agents = GeoStats.get_agent_locations()
    flows = GeoStats.get_threat_flows(timeframe)
    summary = GeoStats.get_summary(timeframe)

    %{
      threats: serialize_threats(threats),
      agents: serialize_agents(agents),
      flows: serialize_flows(flows),
      summary: serialize_summary(summary),
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
    }
  end

  defp serialize_threats(threats) do
    Enum.map(threats, fn threat ->
      %{
        source_lat: threat.source_lat,
        source_lon: threat.source_lon,
        source_country: threat.source_country,
        source_country_name: threat[:source_country_name] || threat.source_country,
        threat_type: threat.threat_type,
        count: threat.count,
        severity: threat.severity,
        last_seen: format_datetime(threat[:last_seen])
      }
    end)
  end

  defp serialize_agents(agents) do
    Enum.map(agents, fn agent ->
      %{
        agent_id: agent.agent_id,
        lat: agent.lat,
        lon: agent.lon,
        hostname: agent.hostname,
        status: agent.status,
        country_code: agent[:country_code],
        city: agent[:city],
        os_type: agent[:os_type],
        last_seen: format_datetime(agent[:last_seen])
      }
    end)
  end

  defp serialize_flows(flows) do
    Enum.map(flows, fn flow ->
      %{
        id: flow.id,
        source: flow.source,
        target: flow.target,
        threat_type: flow.threat_type,
        severity: flow.severity,
        count: flow.count
      }
    end)
  end

  defp serialize_summary(summary) do
    %{
      top_countries: summary.top_countries,
      total_threats: summary.total_threats,
      unique_sources: summary.unique_sources,
      unique_threat_types: summary[:unique_threat_types] || 0,
      agents_online: summary[:agents_online] || 0,
      agents_total: summary[:agents_total] || 0,
      severity_counts: summary[:severity_counts] || %{},
      timeframe: summary[:timeframe] || "24h"
    }
  end

  defp format_datetime(nil), do: nil
  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp format_datetime(%NaiveDateTime{} = dt), do: NaiveDateTime.to_iso8601(dt)
  defp format_datetime(other), do: other
end

# ==============================================================================
# Broadcaster Module - Push updates to connected clients
# ==============================================================================

defmodule TamanduaServerWeb.Broadcaster do
  @moduledoc """
  Centralized module for broadcasting events to WebSocket channels.

  Usage:
    TamanduaServerWeb.Broadcaster.broadcast_new_alert(alert)
    TamanduaServerWeb.Broadcaster.broadcast_event(event)
    TamanduaServerWeb.Broadcaster.broadcast_agent_status(agent_id, status)
    TamanduaServerWeb.Broadcaster.broadcast_stats_update()
  """

  require Logger

  alias TamanduaServerWeb.Endpoint

  @doc "Broadcast a new alert to all connected dashboard clients"
  def broadcast_new_alert(alert) do
    payload = serialize_alert(alert)
    Endpoint.broadcast("dashboard:lobby", "new_alert", payload)
    Endpoint.broadcast("alerts:feed", "new_alert", payload)

    # Also broadcast to PubSub for long-polling consumers
    Phoenix.PubSub.broadcast(TamanduaServer.PubSub, "alerts:new", {:new_alert, alert})

    # Broadcast to external streaming consumers
    try do
      TamanduaServer.Streaming.StreamManager.broadcast_alert(alert)
    rescue
      _ -> :ok
    catch
      _, _ -> :ok
    end
  end

  @doc "Broadcast an alert update to all connected dashboard clients"
  def broadcast_alert_updated(alert) do
    payload = %{alert: serialize_alert(alert)}
    Endpoint.broadcast("dashboard:lobby", "alert_updated", payload)
    Endpoint.broadcast("alerts:feed", "alert_updated", payload)
    Endpoint.broadcast("alerts:#{alert.id}", "alert_updated", payload)
  end

  @doc "Broadcast agent status change"
  def broadcast_agent_status(agent_id, status) do
    payload = %{
      agentId: agent_id,
      status: status.status,
      hostname: status.hostname,
      lastSeen: status.last_seen,
      cpuUsage: status[:cpu_usage],
      memoryUsage: status[:memory_usage],
      eventsPerMinute: status[:events_per_minute]
    }

    Endpoint.broadcast("dashboard:lobby", "agent_status", payload)
    Endpoint.broadcast("agents:status", "status_update", payload)
    Endpoint.broadcast("agents:#{agent_id}", "status_update", payload)
  end

  @doc "Broadcast a telemetry event to event streams"
  def broadcast_event(event, agent_id) do
    payload = serialize_event(event)
    Endpoint.broadcast("events:all", "event", payload)
    Endpoint.broadcast("events:#{agent_id}", "event", payload)
  end

  @doc "Broadcast a batch of events"
  def broadcast_events_batch(events, agent_id) do
    payload = %{events: Enum.map(events, &serialize_event/1)}
    Endpoint.broadcast("events:all", "events_batch", payload)
    Endpoint.broadcast("events:#{agent_id}", "events_batch", payload)
  end

  @doc """
  Broadcast updated dashboard stats.

  SECURITY NOTE: This broadcasts a refresh notification, not actual stats.
  Stats are fetched per-user/per-org in the channel handler (handle_in/refresh_stats)
  to maintain multi-tenant isolation. This function only triggers clients to
  refresh their data.
  """
  def broadcast_stats_update do
    # Broadcast a refresh notification - clients will request their org-scoped stats
    Endpoint.broadcast("dashboard:lobby", "stats_refresh", %{timestamp: System.system_time(:millisecond)})
  end

  @doc "Broadcast geo/threat map update notification"
  def broadcast_geo_update do
    # Notify geo channel subscribers to refresh their data
    # The actual data fetch happens in the channel handler
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "geo:updates",
      {:geo_update, %{type: "refresh", timestamp: System.system_time(:millisecond)}}
    )

    # Also invalidate the cache so fresh data is computed
    try do
      TamanduaServer.Enrichment.GeoStats.invalidate_cache()
    rescue
      e ->
        Logger.warning("[Broadcaster] Failed to invalidate geo cache: #{inspect(e)}")
        :ok
    end
  end

  @doc "Broadcast new threat origin to geo channel"
  def broadcast_new_threat_origin(threat_data) do
    Endpoint.broadcast("geo:map", "new_threat", threat_data)
  end

  # Private helpers

  defp serialize_alert(alert) do
    %{
      id: to_string(alert.id),
      organizationId: to_string(alert.organization_id),
      agentId: to_string(alert.agent_id),
      severity: stringify(alert.severity),
      title: alert.title,
      description: alert.description,
      status: stringify(alert.status),
      threatScore: json_number(alert.threat_score),
      mitreTactics: alert.mitre_tactics || [],
      mitreTechniques: alert.mitre_techniques || [],
      createdAt: format_datetime(alert.inserted_at),
      updatedAt: format_datetime(alert.updated_at),
      acknowledgedBy: stringify(alert.acknowledged_by_id),
      acknowledgedAt: format_datetime(alert.acknowledged_at)
    }
  end

  defp serialize_event(event) do
    %{
      id: event.id || event[:event_id],
      eventType: event.event_type,
      agentId: event.agent_id,
      timestamp: event.timestamp,
      severity: event[:severity] || "info",
      summary: event[:summary] || generate_event_summary(event),
      payload: event.payload || %{},
      detections: serialize_detections(event[:detections] || [])
    }
  end

  defp serialize_detections(detections) when is_list(detections) do
    Enum.map(detections, fn d ->
      %{
        type: d[:type] || d["type"],
        ruleName: d[:rule_name] || d["rule_name"],
        confidence: d[:confidence] || d["confidence"],
        description: d[:description] || d["description"],
        mitreTactics: d[:mitre_tactics] || d["mitre_tactics"] || [],
        mitreTechniques: d[:mitre_techniques] || d["mitre_techniques"] || []
      }
    end)
  end
  defp serialize_detections(_), do: []

  defp stringify(nil), do: nil
  defp stringify(value) when is_atom(value), do: Atom.to_string(value)
  defp stringify(value), do: to_string(value)

  defp json_number(nil), do: nil
  defp json_number(%Decimal{} = value), do: Decimal.to_float(value)
  defp json_number(value) when is_number(value), do: value
  defp json_number(value) when is_binary(value) do
    case Float.parse(value) do
      {number, ""} -> number
      _ -> nil
    end
  end
  defp json_number(_value), do: nil

  defp generate_event_summary(event) do
    case event.event_type do
      "process_start" ->
        "Process started: #{event.payload["name"] || "unknown"}"
      "process_end" ->
        "Process ended: #{event.payload["name"] || "unknown"}"
      "file_create" ->
        "File created: #{event.payload["path"] || "unknown"}"
      "file_modify" ->
        "File modified: #{event.payload["path"] || "unknown"}"
      "file_delete" ->
        "File deleted: #{event.payload["path"] || "unknown"}"
      "network_connect" ->
        "Network connection: #{event.payload["remote_ip"]}:#{event.payload["remote_port"]}"
      "dns_query" ->
        "DNS query: #{event.payload["domain"] || "unknown"}"
      "registry_write" ->
        "Registry modified: #{event.payload["path"] || "unknown"}"
      _ ->
        "#{event.event_type} event"
    end
  end

  defp format_datetime(nil), do: nil
  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp format_datetime(%NaiveDateTime{} = dt), do: NaiveDateTime.to_iso8601(dt)

  # NOTE: Dashboard stats are now fetched per-org in DashboardChannel.get_dashboard_stats/1
  # to maintain multi-tenant isolation. broadcast_stats_update/0 only sends refresh notifications.
end
