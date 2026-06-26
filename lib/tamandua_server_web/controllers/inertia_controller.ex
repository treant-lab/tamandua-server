defmodule TamanduaServerWeb.InertiaController do
  @moduledoc """
  Controller for Inertia.js pages (React frontend).
  """
  use TamanduaServerWeb, :controller
  require Logger

  alias TamanduaServer.Agents
  alias TamanduaServer.Alerts
  alias TamanduaServer.Bounties
  alias TamanduaServer.Response
  alias TamanduaServer.Detection
  alias TamanduaServer.Forensics.Collector, as: ForensicsCollector
  alias TamanduaServer.ThreatIntel
  alias TamanduaServer.Inventory.AssetManager

  alias TamanduaServer.AISecurity.{
    AIGateway,
    AIInventory,
    AttackSurface,
    AgentPosture,
    AgenticAnalyst,
    PredictiveShield
  }

  alias TamanduaServer.Detection.DynamicHunter
  alias TamanduaServer.Hunting.NLHunter
  alias TamanduaServer.Integrations.{AISIEM, MCPServer}
  alias TamanduaServer.Detection.PhishingTriage
  alias TamanduaServer.AI.QueryInterface
  alias TamanduaServer.AI.DependencyGraph

  def dashboard(conn, _params) do
    alias TamanduaServer.Telemetry
    alias TamanduaServer.Repo
    import Ecto.Query

    current_user = conn.assigns[:current_user]
    org_id = current_user && current_user.organization_id

    {total_agents, online_agents, degraded_agents, offline_agents, isolated_agents} =
      dashboard_agent_counts(org_id, Repo)

    # Get alert counts with error handling (multi-tenant scoped)
    open_alerts =
      try do
        Alerts.count_active_for_org(org_id)
      rescue
        e ->
          Logger.warning("Failed to count open alerts: #{Exception.message(e)}")
          0
      end

    critical_alerts =
      try do
        Alerts.count_by_severity_for_org(org_id, :critical)
      rescue
        e ->
          Logger.warning("Failed to count critical alerts: #{Exception.message(e)}")
          0
      end

    # Get event/detection counts with error handling (multi-tenant scoped)
    events_today =
      try do
        Telemetry.count_events_today_for_org(org_id)
      rescue
        e ->
          Logger.warning("Failed to count events today: #{Exception.message(e)}")
          0
      end

    detections_today =
      try do
        Detection.count_detections_today_for_org(org_id)
      rescue
        e ->
          Logger.warning("Failed to count detections today: #{Exception.message(e)}")
          0
      end

    stats = %{
      totalAgents: total_agents,
      onlineAgents: online_agents,
      openAlerts: open_alerts,
      criticalAlerts: critical_alerts,
      eventsToday: events_today,
      detectionsToday: detections_today
    }

    Logger.debug("Dashboard stats: #{inspect(stats)}")

    recent_alerts =
      try do
        Alerts.list_recent_for_org(org_id, limit: 5)
        |> Enum.map(&serialize_alert/1)
      rescue
        e ->
          Logger.warning("Failed to fetch recent alerts: #{Exception.message(e)}")
          []
      end

    top_threats =
      try do
        Detection.get_top_techniques_for_org(org_id, limit: 5)
        |> Enum.map(fn {technique, name, count} ->
          %{technique: technique, name: name, count: count}
        end)
      rescue
        e ->
          Logger.warning("Failed to fetch top threats: #{Exception.message(e)}")
          []
      end

    render_inertia(conn, "Dashboard", %{
      stats: stats,
      agentsByStatus: %{
        online: online_agents,
        offline: offline_agents,
        isolated: isolated_agents,
        degraded: degraded_agents
      },
      recentAlerts: recent_alerts,
      topThreats: top_threats
    })
  end

  def process_tree(conn, params) do
    require Logger

    current_user = conn.assigns[:current_user]
    org_id = current_user && current_user.organization_id

    agents =
      list_agents_for_dashboard(org_id)
      |> Enum.map(&serialize_agent/1)

    agent_id = params["agent_id"]
    Logger.debug("Process tree request for agent_id: #{inspect(agent_id)}")

    agent = if agent_id, do: get_agent_for_org(org_id, agent_id), else: nil
    Logger.debug("Agent found: #{inspect(agent != nil)}, agent: #{inspect(agent)}")

    {process_tree, tree_meta} =
      if agent do
        case Agents.get_process_tree(agent) do
          {:ok, tree} ->
            Logger.debug("Process tree count: #{length(tree)}")
            {tree |> Enum.map(&serialize_process_node/1), %{truncated: false, error: nil}}

          {:ok, tree, %{truncated: true, total_processes: total}} ->
            Logger.debug(
              "Process tree truncated: #{total} total processes, returning top-level only"
            )

            serialized = tree |> Enum.map(&serialize_process_node/1)
            {serialized, %{truncated: true, total_processes: total, error: nil}}

          {:error, :timeout} ->
            Logger.warning("Process tree timed out for agent #{inspect(agent_id)}")

            {[],
             %{
               truncated: false,
               error: "timeout",
               error_message:
                 "Process tree loading timed out. The agent has too many processes to load at once. Use the expand controls to load processes on demand."
             }}

          {:error, :build_failed} ->
            Logger.error("Process tree build failed for agent #{inspect(agent_id)}")

            {[],
             %{
               truncated: false,
               error: "build_failed",
               error_message: "Failed to build the process tree. Please try refreshing."
             }}

          _ ->
            {[], %{truncated: false, error: nil}}
        end
      else
        Logger.debug("No agent found, returning empty tree")
        {[], %{truncated: false, error: nil}}
      end

    render_inertia(conn, "ProcessTree", %{
      agents: agents,
      selectedAgent: serialize_agent(agent),
      processTree: process_tree,
      treeMeta: tree_meta
    })
  end

  def agents(conn, _params) do
    current_user = conn.assigns[:current_user]
    org_id = current_user && current_user.organization_id

    agents =
      list_agents_for_dashboard(org_id)
      |> Enum.map(&serialize_agent/1)

    render_inertia(conn, "Agents", %{
      agents: agents,
      # The React page refreshes data-source coverage asynchronously via
      # /api/v1/agents/data-sources/health. Keeping the initial Inertia payload
      # lean prevents the Agents page from blocking on telemetry aggregation.
      dataSourceHealth: %{}
    })
  end

  def deploy_agent(conn, _params) do
    current_user = conn.assigns[:current_user]
    org_id = current_user && current_user.organization_id
    agent_server_url = public_agent_socket_url(conn)
    web_base_url = public_web_url(conn)
    binary_base_url = public_binary_base_url(conn)

    recent_agents =
      if org_id do
        list_agents_for_dashboard(org_id)
        |> Enum.take(10)
        |> Enum.map(&serialize_agent/1)
      else
        []
      end

    render_inertia(conn, "DeployAgent", %{
      organizationId: org_id,
      agentServerUrl: agent_server_url,
      enrollmentUrl: web_base_url,
      downloadUrls: %{
        windowsMsi:
          binary_download_url_if_present(binary_base_url, "tamandua-agent-windows-x64.msi"),
        windowsExe:
          binary_download_url_if_present(binary_base_url, "tamandua-agent-windows-x64.exe"),
        linuxX64: binary_download_url_if_present(binary_base_url, "tamandua-agent-linux-x64"),
        macosUniversal: nil
      },
      recentAgents: recent_agents
    })
  end

  def security_status(conn, _params) do
    current_user = conn.assigns[:current_user]
    org_id = current_user && current_user.organization_id

    agents =
      list_agents_for_dashboard(org_id)
      |> Enum.map(&serialize_agent/1)

    render_inertia(conn, "SecurityStatus", %{
      agents: agents,
      solanaEnabled: TamanduaServer.Solana.Client.enabled?()
    })
  end

  @doc """
  Public Proofs page - Privacy-safe attestations anchored to Solana.

  Shows a list of on-chain attestations with filters for type (incident,
  health, remediation), severity, and time range. Includes information
  about what data goes on-chain and what stays private.
  """
  def public_proofs(conn, _params) do
    proofs =
      try do
        Alerts.list_public_attestations(limit: 50, date_range: "30d")
        |> Enum.map(&serialize_public_proof/1)
      rescue
        e in [DBConnection.ConnectionError, Postgrex.Error] ->
          Logger.warning("Public proofs attestation list failed: #{Exception.message(e)}")
          []

        e ->
          Logger.warning("Public proofs attestation list failed: #{Exception.message(e)}")
          []
      catch
        :exit, reason ->
          Logger.warning("Public proofs attestation list failed: exit #{inspect(reason)}")
          []
      end

    stats = %{
      total_attested: length(proofs),
      total_bounties: 0,
      total_bounty_sol: 0
    }

    conn
    |> assign(:page_title, "Public Proofs")
    |> render_inertia("PublicProofs", %{
      attestations: proofs,
      counts: %{
        all: stats.total_attested,
        incident: stats.total_attested,
        health: 0,
        remediation: 0,
        bounties: stats.total_bounties,
        bounty_sol: stats.total_bounty_sol
      }
    })
  end

  @doc """
  Policy Gate page.

  Web3 endpoint security verification for DeFi protocols.
  Hidden from navigation until the health attestation API is wired end-to-end.
  """
  def policy_gate(conn, _params) do
    render_inertia(conn, "PolicyGate", %{
      coming_soon: true,
      feature_name: "Policy Gate",
      description:
        "Web3 endpoint security verification for DeFi protocols. Verify signer endpoint health before approving multi-sig transactions."
    })
  end

  def agent_detail_page(conn, %{"id" => agent_id}) do
    current_user = conn.assigns[:current_user]
    org_id = current_user && current_user.organization_id

    result =
      if org_id do
        Agents.get_agent_for_org(org_id, agent_id)
      else
        {:error, :not_found}
      end

    case result do
      {:error, :not_found} ->
        conn
        |> put_flash(:error, "Agent not found")
        |> redirect(to: "/app/agents")

      {:ok, agent} ->
        # Merge live ETS status if the agent is currently connected
        live_info = TamanduaServer.Agents.Registry.get(agent_id)

        live_status =
          case live_info do
            {:ok, info} -> to_string(info[:status] || :online)
            _ -> to_string(agent.status)
          end

        serialized_agent =
          serialize_agent(agent)
          |> Map.put(:status, live_status)
          |> Map.put(:ip_address, Map.get(agent, :ip_address, ""))

        # Fetch recent events for this agent
        events =
          try do
            TamanduaServer.Telemetry.list_events_for_agent(agent_id, 50)
            |> Enum.map(fn e ->
              %{
                id: e.id || Ecto.UUID.generate(),
                event_type: e.event_type,
                timestamp: format_datetime(e.timestamp || e.inserted_at),
                severity: Map.get(e, :severity, "info"),
                summary: Map.get(e, :summary, "#{e.event_type} event"),
                payload: Map.get(e, :payload, %{})
              }
            end)
          rescue
            e ->
              Logger.warning(
                "Failed to fetch events for agent #{agent_id}: #{Exception.message(e)}"
              )

              []
          end

        # Fetch recent alerts for this agent
        alerts =
          try do
            Alerts.list_alerts(%{agent_id: agent_id, organization_id: org_id})
            |> Enum.take(20)
            |> Enum.map(&serialize_alert/1)
          rescue
            e ->
              Logger.warning(
                "Failed to fetch alerts for agent #{agent_id}: #{Exception.message(e)}"
              )

              []
          end

        # Derive collector info from recent events
        collectors =
          try do
            agent_events = TamanduaServer.Telemetry.list_events_for_agent(agent_id, 500)
            derive_collectors(agent_events, Map.get(agent, :config) || %{})
          rescue
            e ->
              Logger.warning(
                "Failed to derive collectors for agent #{agent_id}: #{Exception.message(e)}"
              )

              derive_collectors([], Map.get(agent, :config) || %{})
          end

        # Health metrics from the dedicated health ETS table (populated by agent
        # system_health telemetry events).  Falls back to basic info from the
        # agent registry entry when no health events have been received yet.
        health =
          case TamanduaServer.Agents.Registry.get_health(agent_id) do
            {:ok, h} ->
              %{
                cpu_usage: h.cpu_usage,
                memory_usage: h.memory_usage,
                disk_usage: h.disk_usage,
                cpu_history: h.cpu_history,
                memory_history: h.memory_history,
                uptime_seconds: h.uptime_seconds
              }

            {:error, :not_found} ->
              case live_info do
                {:ok, info} ->
                  %{
                    cpu_usage: Map.get(info, :cpu_usage, 0),
                    memory_usage: Map.get(info, :memory_usage, 0),
                    disk_usage: Map.get(info, :disk_usage, 0),
                    cpu_history: [],
                    memory_history: [],
                    uptime_seconds:
                      div(
                        System.system_time(:millisecond) -
                          Map.get(info, :connected_at, System.system_time(:millisecond)),
                        1000
                      )
                  }

                _ ->
                  nil
              end
          end

        # Get agent config from DB or live registry
        config =
          case live_info do
            {:ok, info} -> Map.get(info, :config, agent.config || %{})
            _ -> agent.config || %{}
          end

        render_inertia(conn, "AgentDetail", %{
          agent: serialized_agent,
          collectors: collectors,
          health: health,
          events: events,
          alerts: alerts,
          config: config
        })
    end
  end

  defp derive_collectors(events, config) do
    event_collectors =
      events
      |> Enum.group_by(&to_string(&1.event_type))
      |> Enum.map(fn {event_type, evts} ->
        latest = List.first(evts)

        %{
          name: event_type,
          status: "running",
          events_collected: length(evts),
          last_event_at: format_datetime(latest.timestamp || latest.inserted_at),
          error_message: nil
        }
      end)

    config_collectors =
      config
      |> Map.get("collectors", %{})
      |> Enum.flat_map(fn
        {name, enabled} when is_boolean(enabled) ->
          [
            %{
              name: normalize_collector_name(name),
              status: if(enabled, do: "running", else: "stopped"),
              events_collected: 0,
              last_event_at: nil,
              error_message: nil
            }
          ]

        {_name, _value} ->
          []
      end)

    (event_collectors ++ config_collectors)
    |> Enum.reduce(%{}, fn collector, acc ->
      Map.update(acc, collector.name, collector, fn existing ->
        %{
          name: collector.name,
          status: existing.status,
          events_collected: max(existing.events_collected || 0, collector.events_collected || 0),
          last_event_at: existing.last_event_at || collector.last_event_at,
          error_message: existing.error_message || collector.error_message
        }
      end)
    end)
    |> Map.values()
    |> Enum.sort_by(&{-(&1.events_collected || 0), &1.name})
  end

  defp normalize_collector_name(name) when is_binary(name) do
    name
    |> String.trim()
    |> String.replace_suffix("_enabled", "")
  end

  defp normalize_collector_name(name), do: to_string(name)

  def alerts(conn, _params) do
    current_user = conn.assigns[:current_user]
    org_id = current_user && current_user.organization_id

    alerts =
      try do
        # CRITICAL: Filter alerts by organization to prevent cross-tenant data leakage
        if org_id do
          Alerts.list_alerts_for_org(org_id, limit: 100)
          |> Enum.map(&serialize_alert/1)
        else
          Logger.warning("No organization_id for user - returning empty alerts")
          []
        end
      rescue
        e ->
          Logger.warning("Failed to load alerts page data: #{Exception.message(e)}")
          []
      catch
        _kind, _reason ->
          Logger.warning("Failed to load alerts page data due to unavailable runtime dependency")
          []
      end

    render_inertia(conn, "Alerts", %{
      alerts: alerts
    })
  end

  def alert_detail(conn, %{"id" => alert_id}) do
    current_user = conn.assigns[:current_user]
    org_id = current_user && current_user.organization_id

    # CRITICAL: Use get_alert_for_org to prevent cross-tenant data leakage
    result =
      if org_id do
        Alerts.get_alert_for_org(org_id, alert_id)
      else
        {:error, :not_found}
      end

    case result do
      {:error, :not_found} ->
        conn
        |> put_flash(:error, "Alert not found")
        |> redirect(to: "/app/alerts")

      {:ok, alert} ->
        # Get the agent if available
        agent =
          case alert.agent_id do
            nil ->
              nil

            agent_id ->
              case Agents.get_agent_for_org(org_id, agent_id) do
                {:ok, a} -> serialize_agent(a)
                _ -> nil
              end
          end

        # Get related events from the time window around the alert
        time_window_minutes = 60
        related_events = get_alert_related_events(alert, time_window_minutes)

        # Get related alerts (same agent, similar time window, or same MITRE technique)
        related_alerts = get_related_alerts_for_detail(alert)

        # Build graph data
        graph_data = build_alert_graph_data(alert, related_events)

        # Build timeline
        timeline = build_alert_timeline(alert, related_events)
        response_actions = get_alert_response_actions(org_id, alert.id)

        render_inertia(conn, "AlertDetail", %{
          alert: serialize_alert(alert),
          agent: agent,
          relatedEvents: related_events,
          relatedAlerts: related_alerts,
          responseActions: response_actions,
          graphData: graph_data,
          timeline: timeline
        })
    end
  end

  defp get_alert_related_events(alert, time_window_minutes) do
    # Get correlated events with correlation scores and reasons
    # The Correlator.get_related_events function now properly handles fallback internally
    try do
      Detection.Correlator.get_related_events(
        alert.agent_id,
        alert.source_event_id,
        time_window_minutes
      )
      |> Enum.map(fn event ->
        payload = event[:payload] || event.payload || %{}

        %{
          id: event[:id] || event[:event_id] || UUID.uuid4(),
          event_type: event[:event_type] || event.event_type || "unknown",
          timestamp: format_alert_timestamp(event[:timestamp] || event.timestamp),
          summary: build_event_summary(event),
          pid: payload["pid"] || payload[:pid] || payload["process_id"],
          process_name: payload["name"] || payload[:name] || payload["process_name"],
          severity: event[:severity] || event.severity || "info",
          payload: payload,
          correlation_score: event[:correlation_score] || 0,
          correlation_reason: event[:correlation_reason] || "",
          correlation_kind: related_event_kind(event),
          score_explanation: related_event_score_explanation(event)
        }
      end)
    rescue
      e ->
        Logger.warning(
          "Failed to get correlated events for alert #{alert.id}: #{Exception.message(e)}"
        )

        # Fallback: get recent events from same agent
        if alert.agent_id do
          try do
            TamanduaServer.Telemetry.list_events_for_agent(alert.agent_id, 20)
            |> Enum.map(fn event ->
              payload = event.payload || %{}

              %{
                id: event.id,
                event_type: event.event_type || "unknown",
                timestamp: format_alert_timestamp(event.timestamp),
                summary: build_event_summary(event.event_type, payload),
                pid: payload["pid"] || payload["process_id"],
                process_name: payload["name"] || payload["process_name"],
                severity: to_string(Map.get(event, :severity, "info")),
                payload: payload,
                correlation_score: 0,
                correlation_reason: "Fallback: recent event from same agent",
                correlation_kind: "fallback",
                score_explanation: "No engine score; shown as recent same-agent context"
              }
            end)
          rescue
            e ->
              Logger.warning("Failed to serialize related events: #{Exception.message(e)}")
              []
          end
        else
          []
        end
    end
  end

  defp related_event_kind(event) do
    score = event[:correlation_score] || 0
    reason = event[:correlation_reason] || ""

    cond do
      is_binary(reason) and String.starts_with?(reason, "Fallback:") -> "fallback"
      score > 0 -> "engine"
      true -> "context_only"
    end
  end

  defp related_event_score_explanation(event) do
    case related_event_kind(event) do
      "engine" -> "Score from correlator criteria"
      "fallback" -> "No engine score; shown as recent same-agent context"
      _ -> "No engine score; shown as nearby endpoint context"
    end
  end

  defp get_related_alerts_for_detail(alert) do
    try do
      Alerts.get_related_alerts(alert.id)
      |> Enum.map(&serialize_alert/1)
    rescue
      e ->
        Logger.warning("Failed to get related alerts for #{alert.id}: #{Exception.message(e)}")
        []
    end
  end

  defp build_alert_graph_data(alert, related_events) do
    # Build nodes and edges from the alert and related events
    process_events =
      Enum.filter(related_events, fn e ->
        t = e.event_type || ""

        String.contains?(t, "process") or
          t in ~w(proc_create proc_spawn image_load module_load injection)
      end)

    network_events =
      Enum.filter(related_events, fn e ->
        t = e.event_type || ""

        String.contains?(t, "network") or String.contains?(t, "conn") or
          t in ~w(tcp udp http https socket)
      end)

    file_events =
      Enum.filter(related_events, fn e ->
        t = e.event_type || ""
        String.contains?(t, "file") or t in ~w(write read rename delete)
      end)

    dns_events =
      Enum.filter(related_events, fn e ->
        t = e.event_type || ""
        String.contains?(t, "dns") or t in ~w(dns_resolve name_resolution)
      end)

    registry_events =
      Enum.filter(related_events, fn e ->
        t = e.event_type || ""

        String.contains?(t, "registry") or
          t in ~w(reg_write reg_set reg_create reg_delete)
      end)

    # Add process nodes
    {process_nodes, process_edges} = build_process_nodes_for_alert(process_events, alert)

    # Add network nodes with enriched data
    network_nodes =
      Enum.map(network_events, fn event ->
        payload = event.payload || %{}
        remote_ip = get_payload_value(payload, "remote_ip") || "unknown"
        remote_port = get_payload_value(payload, "remote_port") || "?"
        local_port = get_payload_value(payload, "local_port")
        protocol = get_payload_value(payload, "protocol") || "TCP"
        direction = get_payload_value(payload, "direction") || "outbound"

        bytes_sent =
          get_payload_value(payload, "bytes_sent") || get_payload_value(payload, "sent_bytes") ||
            0

        bytes_received =
          get_payload_value(payload, "bytes_received") || get_payload_value(payload, "recv_bytes") ||
            0

        process_name =
          event.process_name || get_payload_value(payload, "name") ||
            get_payload_value(payload, "process_name")

        # Build a descriptive label showing the connection flow
        label =
          cond do
            process_name && direction == "inbound" ->
              "#{remote_ip}:#{remote_port} -> #{process_name}"

            process_name ->
              "#{process_name} -> #{remote_ip}:#{remote_port}"

            true ->
              "#{remote_ip}:#{remote_port}"
          end

        total_bytes = safe_to_int(bytes_sent) + safe_to_int(bytes_received)

        label_with_volume =
          if total_bytes > 0 do
            "#{label} (#{format_bytes(total_bytes)})"
          else
            label
          end

        %{
          id: "network-#{event.id}",
          type: "network",
          label: label_with_volume,
          data:
            Map.merge(payload, %{
              "remote_ip" => remote_ip,
              "remote_port" => remote_port,
              "local_port" => local_port,
              "protocol" => protocol,
              "direction" => direction,
              "bytes_sent" => bytes_sent,
              "bytes_received" => bytes_received,
              "total_bytes" => total_bytes,
              "process_name" => process_name,
              "timestamp" => event.timestamp
            }),
          severity: event.severity || "info",
          pid: event.pid,
          timestamp: event.timestamp
        }
      end)

    # Add file nodes
    file_nodes =
      Enum.map(file_events, fn event ->
        path = get_in(event.payload || %{}, ["path"]) || "unknown"

        %{
          id: "file-#{event.id}",
          type: "file",
          label: Path.basename(path),
          data: event.payload || %{},
          severity: event.severity || "info",
          pid: event.pid
        }
      end)

    # Add DNS nodes
    dns_nodes =
      Enum.map(dns_events, fn event ->
        query =
          get_in(event.payload || %{}, ["query"]) || get_in(event.payload || %{}, ["domain"]) ||
            "unknown"

        %{
          id: "dns-#{event.id}",
          type: "dns",
          label: query,
          data: event.payload || %{},
          severity: event.severity || "info",
          pid: event.pid
        }
      end)

    # Add registry nodes
    registry_nodes =
      Enum.map(registry_events, fn event ->
        key = get_in(event.payload || %{}, ["key"]) || "unknown"

        %{
          id: "registry-#{event.id}",
          type: "registry",
          label: key |> String.split("\\") |> List.last() || key,
          data: event.payload || %{},
          severity: event.severity || "info",
          pid: event.pid
        }
      end)

    all_nodes = process_nodes ++ network_nodes ++ file_nodes ++ dns_nodes ++ registry_nodes

    # Fallback: build graph from alert's process_chain/evidence when events produce no nodes
    if all_nodes == [] do
      build_graph_from_alert_metadata(alert)
    else
      # Build edges connecting processes to their network/file/dns/registry activities
      network_edges =
        Enum.flat_map(network_nodes, fn node ->
          case find_process_node_by_pid(process_nodes, node.pid) do
            nil ->
              []

            proc_node ->
              direction = node.data["direction"] || "outbound"
              bytes_sent = node.data["bytes_sent"] || 0
              bytes_received = node.data["bytes_received"] || 0
              total_bytes = safe_to_int(bytes_sent) + safe_to_int(bytes_received)
              protocol = node.data["protocol"] || "TCP"

              edge_label =
                cond do
                  total_bytes > 0 ->
                    "#{protocol} #{format_bytes(total_bytes)}"

                  true ->
                    "#{protocol} connection"
                end

              {src, tgt} =
                if direction == "inbound",
                  do: {node.id, proc_node.id},
                  else: {proc_node.id, node.id}

              [
                %{
                  source: src,
                  target: tgt,
                  type: "connection",
                  label: edge_label,
                  bytes_sent: safe_to_int(bytes_sent),
                  bytes_received: safe_to_int(bytes_received),
                  protocol: protocol,
                  direction: direction,
                  timestamp: node[:timestamp] || node.data["timestamp"],
                  process_name: proc_node[:label]
                }
              ]
          end
        end)

      file_edges =
        Enum.flat_map(file_nodes, fn node ->
          case find_process_node_by_pid(process_nodes, node.pid) do
            nil ->
              []

            proc_node ->
              [%{source: proc_node.id, target: node.id, type: "file_access", label: "accesses"}]
          end
        end)

      dns_edges =
        Enum.flat_map(dns_nodes, fn node ->
          case find_process_node_by_pid(process_nodes, node.pid) do
            nil ->
              []

            proc_node ->
              [%{source: proc_node.id, target: node.id, type: "dns_query", label: "queries"}]
          end
        end)

      registry_edges =
        Enum.flat_map(registry_nodes, fn node ->
          case find_process_node_by_pid(process_nodes, node.pid) do
            nil ->
              []

            proc_node ->
              [
                %{
                  source: proc_node.id,
                  target: node.id,
                  type: "registry_access",
                  label: "modifies"
                }
              ]
          end
        end)

      all_edges = process_edges ++ network_edges ++ file_edges ++ dns_edges ++ registry_edges

      %{
        nodes: all_nodes,
        edges: all_edges,
        stats: %{
          process_count: length(process_nodes),
          network_count: length(network_nodes),
          file_count: length(file_nodes),
          dns_count: length(dns_nodes)
        }
      }
    end
  end

  defp build_graph_from_alert_metadata(alert) do
    process_chain = alert.process_chain || []
    evidence = alert.evidence || %{}
    techniques = alert.mitre_techniques || []
    chain_length = length(process_chain)

    # Build process nodes from the alert's attack chain
    process_nodes =
      process_chain
      |> Enum.with_index()
      |> Enum.map(fn {proc, idx} ->
        name = proc["name"] || proc["process_name"] || "Process #{idx}"
        pid = proc["pid"]
        is_last = idx == chain_length - 1

        %{
          id: "proc-chain-#{idx}",
          type: "process",
          label: name,
          pid: pid,
          data: %{
            "pid" => pid,
            "ppid" => proc["ppid"],
            "path" => proc["path"] || proc["image_path"],
            "cmdline" => proc["cmdline"] || proc["command_line"],
            "user" => proc["user"],
            "mitre_techniques" => if(is_last, do: techniques, else: [])
          },
          severity: if(is_last, do: to_string(alert.severity), else: "info"),
          highlighted: is_last,
          detections:
            if(is_last, do: [%{ruleName: alert.title, description: alert.description}], else: nil)
        }
      end)

    # Build parent→child spawn edges
    process_edges =
      if chain_length > 1 do
        0..(chain_length - 2)
        |> Enum.map(fn idx ->
          %{
            source: "proc-chain-#{idx}",
            target: "proc-chain-#{idx + 1}",
            type: "spawn",
            label: "spawns"
          }
        end)
      else
        []
      end

    # Build file nodes from evidence
    files = Map.get(evidence, "files", []) ++ Map.get(evidence, :files, [])
    file_hashes = Map.get(evidence, "file_hashes", []) ++ Map.get(evidence, :file_hashes, [])
    all_files = (files ++ file_hashes) |> Enum.uniq()

    file_nodes =
      all_files
      |> Enum.with_index()
      |> Enum.map(fn {file, idx} ->
        path = file["path"] || file[:path] || ""

        %{
          id: "evidence-file-#{idx}",
          type: "file",
          label: Path.basename(to_string(path)),
          data: file,
          severity: "info",
          pid: nil
        }
      end)

    # Build network nodes from evidence
    network = Map.get(evidence, "network", []) ++ Map.get(evidence, :network, [])

    network_nodes =
      network
      |> Enum.with_index()
      |> Enum.map(fn {conn, idx} ->
        addr =
          conn["remote_addr"] || conn["destination"] || conn["value"] ||
            conn[:remote_addr] || conn[:destination] || "unknown"

        port = conn["remote_port"] || conn[:remote_port]
        label = if port, do: "#{addr}:#{port}", else: to_string(addr)

        %{
          id: "evidence-net-#{idx}",
          type: "network",
          label: label,
          data: conn,
          severity: "info",
          pid: nil
        }
      end)

    # Connect evidence to the last process in the chain (the detected one)
    last_proc_id = if chain_length > 0, do: "proc-chain-#{chain_length - 1}"

    evidence_edges =
      if last_proc_id do
        file_edges =
          Enum.map(file_nodes, fn n ->
            %{source: last_proc_id, target: n.id, type: "file_access", label: "accesses"}
          end)

        net_edges =
          Enum.map(network_nodes, fn n ->
            %{source: last_proc_id, target: n.id, type: "connection", label: "connects"}
          end)

        file_edges ++ net_edges
      else
        []
      end

    all_nodes = process_nodes ++ file_nodes ++ network_nodes
    all_edges = process_edges ++ evidence_edges

    %{
      nodes: all_nodes,
      edges: all_edges,
      stats: %{
        process_count: length(process_nodes),
        network_count: length(network_nodes),
        file_count: length(file_nodes),
        dns_count: 0
      }
    }
  end

  defp build_process_nodes_for_alert(process_events, alert) do
    # Group by PID and create parent-child relationships
    nodes =
      Enum.map(process_events, fn event ->
        pid = event.pid || get_in(event.payload || %{}, ["pid"])
        name = event.process_name || get_in(event.payload || %{}, ["name"]) || "unknown"

        # Check if this is the alert source
        is_alert_source = alert.source_event_id == event.id

        %{
          id: "process-#{pid || event.id}",
          type: "process",
          label: name,
          pid: pid,
          data: event.payload || %{},
          severity: if(is_alert_source, do: alert.severity, else: event.severity || "info"),
          highlighted: is_alert_source,
          detections:
            if(is_alert_source,
              do: [%{ruleName: alert.title, description: alert.description}],
              else: nil
            )
        }
      end)
      |> Enum.uniq_by(& &1.id)

    # Build parent-child edges
    edges =
      Enum.flat_map(process_events, fn event ->
        pid = event.pid || get_in(event.payload || %{}, ["pid"])

        ppid =
          get_in(event.payload || %{}, ["ppid"]) || get_in(event.payload || %{}, ["parent_pid"])

        if ppid && pid do
          parent_node = Enum.find(nodes, &(&1.pid == ppid))

          if parent_node do
            [%{source: parent_node.id, target: "process-#{pid}", type: "spawn", label: "spawns"}]
          else
            []
          end
        else
          []
        end
      end)

    {nodes, edges}
  end

  defp find_process_node_by_pid(_process_nodes, nil), do: nil

  defp find_process_node_by_pid(process_nodes, pid) do
    Enum.find(process_nodes, &(&1.pid == pid))
  end

  defp build_alert_timeline(alert, related_events) do
    try do
      builder_entries =
        alert
        |> TamanduaServer.Alerts.TimelineBuilder.build_timeline(limit: 200)
        |> Enum.map(&serialize_timeline_builder_event/1)

      related_entries = related_event_timeline_entries(related_events)

      (builder_entries ++ related_entries)
      |> Enum.uniq_by(& &1.id)
      |> Enum.sort_by(&(&1.timestamp || ""))
    rescue
      e ->
        Logger.warning("TimelineBuilder failed for alert #{alert.id}: #{Exception.message(e)}")
        build_basic_alert_timeline(alert, related_events)
    end
  end

  defp build_basic_alert_timeline(alert, related_events) do
    # Convert events to timeline entries
    event_entries = related_event_timeline_entries(related_events)

    # Add the alert as a timeline entry
    alert_entry = %{
      id: "alert-#{alert.id}",
      timestamp: format_alert_timestamp(alert.inserted_at),
      event_type: "alert",
      severity: alert.severity,
      summary: alert.title,
      pid: nil,
      detections: [%{ruleName: alert.title, description: alert.description}]
    }

    [alert_entry | event_entries]
    |> Enum.sort_by(& &1.timestamp)
  end

  defp serialize_timeline_builder_event(event) do
    %{
      id: event.id,
      timestamp: format_alert_timestamp(event.timestamp),
      event_type: event.group || event.type || "system",
      severity: event.severity || "info",
      summary: event.title || event.content || "Timeline event",
      pid: get_in(event.metadata || %{}, [:pid]) || get_in(event.metadata || %{}, ["pid"]),
      detections: timeline_event_detections(event),
      payload: event.metadata || %{},
      content: event.content,
      subtype: event.subtype,
      user_name: event.user_name
    }
  end

  defp timeline_event_detections(%{type: "detection"} = event) do
    [%{ruleName: event.title || "Detection", description: event.content || ""}]
  end

  defp timeline_event_detections(_event), do: []

  defp related_event_timeline_entries(related_events) do
    Enum.map(related_events, fn event ->
      %{
        id: event.id,
        timestamp: event.timestamp,
        event_type: event.event_type,
        severity: event.severity || "info",
        summary: event.summary,
        pid: event.pid,
        detections: [],
        payload: event.payload || %{},
        content: event.correlation_reason
      }
    end)
  end

  defp build_event_summary(event) do
    # Handle both struct access (event.field) and map access (event[:field])
    event_type = event[:event_type] || Map.get(event, :event_type)
    payload = event[:payload] || Map.get(event, :payload) || %{}

    case event_type do
      "process_create" ->
        name = get_payload_value(payload, "name") || "unknown"
        "Process created: #{name}"

      "process_terminate" ->
        name = get_payload_value(payload, "name") || "unknown"
        "Process terminated: #{name}"

      "network_connect" ->
        ip = get_payload_value(payload, "remote_ip") || "unknown"
        port = get_payload_value(payload, "remote_port") || "?"
        process = get_payload_value(payload, "name") || get_payload_value(payload, "process_name")
        protocol = get_payload_value(payload, "protocol") || "TCP"

        bytes_sent =
          safe_to_int(
            get_payload_value(payload, "bytes_sent") || get_payload_value(payload, "sent_bytes") ||
              0
          )

        bytes_received =
          safe_to_int(
            get_payload_value(payload, "bytes_received") ||
              get_payload_value(payload, "recv_bytes") || 0
          )

        total = bytes_sent + bytes_received

        base = if process, do: "#{process} -> #{ip}:#{port}", else: "Connection to #{ip}:#{port}"

        volume =
          if total > 0, do: " [#{format_bytes(total)} via #{protocol}]", else: " [#{protocol}]"

        base <> volume

      "file_create" ->
        path = get_payload_value(payload, "path") || "unknown"
        "File created: #{Path.basename(path)}"

      "file_modify" ->
        path = get_payload_value(payload, "path") || "unknown"
        "File modified: #{Path.basename(path)}"

      "dns_query" ->
        query = get_payload_value(payload, "query") || "unknown"
        "DNS query: #{query}"

      "registry_modify" ->
        key = get_payload_value(payload, "key") || "unknown"
        "Registry modified: #{key}"

      _ ->
        event_type || "Unknown event"
    end
  end

  # Helper to get payload values with both string and atom key support
  defp get_payload_value(payload, key) when is_binary(key) do
    payload[key] ||
      try do
        payload[String.to_existing_atom(key)]
      rescue
        ArgumentError -> nil
      end
  end

  defp format_alert_timestamp(nil), do: nil
  defp format_alert_timestamp(datetime) when is_binary(datetime), do: datetime
  defp format_alert_timestamp(%DateTime{} = datetime), do: DateTime.to_iso8601(datetime)
  defp format_alert_timestamp(%NaiveDateTime{} = datetime), do: NaiveDateTime.to_iso8601(datetime)

  defp safe_to_int(val) when is_integer(val), do: val
  defp safe_to_int(val) when is_float(val), do: round(val)

  defp safe_to_int(val) when is_binary(val) do
    case Integer.parse(val) do
      {n, _} -> n
      :error -> 0
    end
  end

  defp safe_to_int(_), do: 0

  defp format_bytes(bytes) when is_number(bytes) and bytes >= 1_073_741_824,
    do: "#{Float.round(bytes / 1_073_741_824, 1)} GB"

  defp format_bytes(bytes) when is_number(bytes) and bytes >= 1_048_576,
    do: "#{Float.round(bytes / 1_048_576, 1)} MB"

  defp format_bytes(bytes) when is_number(bytes) and bytes >= 1024,
    do: "#{Float.round(bytes / 1024, 1)} KB"

  defp format_bytes(bytes) when is_number(bytes), do: "#{bytes} B"
  defp format_bytes(_), do: "0 B"

  def mitre(conn, params) do
    include_coverage? = params["include_coverage"] in ["true", true]

    coverage =
      if include_coverage? do
        try do
          Detection.Mitre.get_coverage()
        rescue
          e ->
            Logger.warning("Detection.Mitre.get_coverage failed: #{Exception.message(e)}")
            %{}
        catch
          :exit, reason ->
            Logger.warning("Detection.Mitre.get_coverage failed: exit #{inspect(reason)}")
            %{}
        end
      else
        %{}
      end

    technique_limit = params["limit"] |> safe_parse_int(75) |> max(25) |> min(300)

    techniques =
      try do
        Detection.Mitre.list_techniques()
        |> Enum.take(technique_limit)
      rescue
        e ->
          Logger.warning("Detection.Mitre.list_techniques failed: #{Exception.message(e)}")
          []
      catch
        :exit, reason ->
          Logger.warning("Detection.Mitre.list_techniques failed: exit #{inspect(reason)}")
          []
      end

    render_inertia(conn, "Mitre", %{
      coverage: coverage,
      techniques: techniques,
      techniqueLimit: technique_limit,
      techniquesTruncated: length(techniques) >= technique_limit,
      coverageDeferred: not include_coverage?
    })
  end

  def hunt(conn, _params) do
    saved_queries =
      try do
        NLHunter.get_hunt_suggestions()
        |> Enum.map(fn suggestion ->
          %{
            id: UUID.uuid4(),
            query: suggestion[:query],
            reason: suggestion[:reason],
            priority: suggestion[:priority],
            category: infer_hunt_category(suggestion[:query])
          }
        end)
      catch
        kind, reason ->
          Logger.warning("NLHunter.get_hunt_suggestions failed: #{kind} #{inspect(reason)}")
          []
      end

    session_queries =
      try do
        case NLHunter.list_sessions(%{status: :completed}) do
          {:ok, sessions} ->
            sessions
            |> Enum.take(10)
            |> Enum.map(fn session ->
              %{
                id: session[:id],
                query: session[:original_query],
                reason: "Previous hunt session",
                priority: :medium,
                category: to_string(session[:parsed_query][:intent] || :general_hunt),
                createdAt: format_datetime(session[:created_at]),
                resultCount: session[:result_count] || 0
              }
            end)

          _ ->
            []
        end
      catch
        kind, reason ->
          Logger.warning("NLHunter.list_sessions failed: #{kind} #{inspect(reason)}")
          []
      end

    all_queries =
      (session_queries ++ saved_queries)
      |> Enum.uniq_by(& &1[:query])
      |> Enum.take(20)

    render_inertia(conn, "Hunt", %{
      savedQueries: all_queries
    })
  end

  defp infer_hunt_category(query) when is_binary(query) do
    query_lower = String.downcase(query)

    cond do
      String.contains?(query_lower, ["powershell", "encoded", "script"]) ->
        "execution"

      String.contains?(query_lower, ["lateral", "psexec", "wmi", "remote"]) ->
        "lateral_movement"

      String.contains?(query_lower, ["credential", "lsass", "mimikatz", "password"]) ->
        "credential_access"

      String.contains?(query_lower, ["persist", "startup", "registry", "scheduled"]) ->
        "persistence"

      String.contains?(query_lower, ["exfil", "upload", "transfer"]) ->
        "exfiltration"

      String.contains?(query_lower, ["c2", "beacon", "callback"]) ->
        "command_control"

      true ->
        "general"
    end
  end

  defp infer_hunt_category(_), do: "general"

  def network(conn, _params) do
    alias TamanduaServer.Telemetry

    current_user = conn.assigns[:current_user]
    org_id = current_user && current_user.organization_id

    agents =
      list_agents_for_dashboard(org_id)
      |> Enum.map(fn a ->
        %{id: Map.get(a, :id) || Map.get(a, :agent_id), hostname: a.hostname}
      end)

    # Get recent network connection events from telemetry
    network_events = Telemetry.list_events(%{event_type: "network_connect", limit: 500})

    # Serialize network connections for frontend
    # Handle both atom and string keys in payload (database uses string keys from JSON)
    connections =
      Enum.map(network_events, fn event ->
        payload = event.payload || %{}

        # Helper to get value with both atom and string key fallbacks
        get_val = fn keys, default ->
          Enum.find_value(keys, default, fn key ->
            payload[key] || payload[to_string(key)]
          end)
        end

        %{
          id: event.id,
          agentId: event.agent_id,
          timestamp: format_datetime(event.timestamp),
          sourceIp: get_val.([:local_ip, :source_ip, "local_ip", "source_ip"], nil),
          sourcePort: get_val.([:local_port, :source_port, "local_port", "source_port"], 0),
          destIp:
            get_val.(
              [:remote_ip, :dest_ip, :destination_ip, "remote_ip", "dest_ip", "destination_ip"],
              nil
            ),
          destPort:
            get_val.(
              [
                :remote_port,
                :dest_port,
                :destination_port,
                "remote_port",
                "dest_port",
                "destination_port"
              ],
              0
            ),
          protocol: get_val.([:protocol, "protocol"], "tcp"),
          processName: get_val.([:process_name, :name, "process_name", "name"], "unknown"),
          processPid: get_val.([:pid, "pid"], 0),
          direction: get_val.([:direction, "direction"], "outbound"),
          status: get_val.([:status, "status"], "established")
        }
      end)

    # Calculate stats from actual connection data
    unique_destinations =
      connections
      |> Enum.map(& &1.destIp)
      |> Enum.uniq()
      |> length()

    active_connections = Enum.count(connections, fn c -> c.status == "established" end)
    blocked_connections = Enum.count(connections, fn c -> c.status == "blocked" end)

    render_inertia(conn, "Network", %{
      agents: agents,
      connections: connections,
      stats: %{
        totalConnections: length(connections),
        activeConnections: active_connections,
        blockedConnections: blocked_connections,
        uniqueDestinations: unique_destinations
      }
    })
  end

  def dns(conn, _params) do
    current_user = conn.assigns[:current_user]
    org_id = current_user && current_user.organization_id

    agents =
      list_agents_for_dashboard(org_id)
      |> Enum.map(fn a ->
        %{id: Map.get(a, :id) || Map.get(a, :agent_id), hostname: a.hostname}
      end)

    # Keep the Inertia render cheap. The DNS table hydrates through the
    # paginated /api/v1/dns/queries endpoint after mount; doing the broad
    # payload-shape query here can time out on large telemetry tables.
    dns_events = []

    queries =
      Enum.map(dns_events, fn event ->
        payload = event.payload || %{}
        process_payload = payload["process"] || payload[:process] || %{}
        dns_payload = payload["dns"] || payload[:dns] || %{}

        get_val = fn keys, default ->
          Enum.find_value(keys, default, fn key ->
            payload[key] || payload[to_string(key)]
          end)
        end

        nested_val = fn source, keys, default ->
          Enum.find_value(keys, default, fn key ->
            source[key] || source[to_string(key)]
          end)
        end

        domain =
          first_present(
            [
              get_val.(
                [
                  :query,
                  :query_name,
                  :domain,
                  :dns_query,
                  :"dns.domain",
                  :host,
                  :hostname,
                  "query",
                  "query_name",
                  "domain",
                  "dns_query",
                  "dns.domain",
                  "host",
                  "hostname"
                ],
                nil
              ),
              nested_val.(
                dns_payload,
                [:query, :query_name, :domain, "query", "query_name", "domain"],
                nil
              )
            ],
            "unknown"
          )

        blocked = get_val.([:blocked, "blocked"], false)
        suspicious = get_val.([:suspicious, "suspicious"], false)

        status =
          cond do
            blocked -> "blocked"
            suspicious -> "suspicious"
            event.severity in ["critical", "high"] -> "suspicious"
            true -> "allowed"
          end

        %{
          id: event.id,
          timestamp: format_datetime(event.timestamp),
          domain: domain,
          queryType:
            first_present(
              [
                get_val.(
                  [
                    :query_type,
                    :record_type,
                    :type,
                    :"dns.query_type",
                    :"dns.record_type",
                    "query_type",
                    "record_type",
                    "type",
                    "dns.query_type",
                    "dns.record_type"
                  ],
                  nil
                ),
                nested_val.(
                  dns_payload,
                  [:query_type, :record_type, :type, "query_type", "record_type", "type"],
                  nil
                )
              ],
              "A"
            ),
          response:
            first_present(
              [
                get_val.(
                  [
                    :response,
                    :resolved_ip,
                    :answer,
                    :response_data,
                    :dns_response,
                    :"dns.response",
                    "response",
                    "resolved_ip",
                    "answer",
                    "response_data",
                    "dns_response",
                    "dns.response"
                  ],
                  nil
                ),
                nested_val.(
                  dns_payload,
                  [:response, :response_data, "response", "response_data"],
                  nil
                ),
                format_response_list(payload[:responses] || payload["responses"]),
                format_response_list(payload[:resolved_ips] || payload["resolved_ips"]),
                format_response_list(payload[:response_data] || payload["response_data"]),
                format_response_list(dns_payload[:responses] || dns_payload["responses"]),
                format_response_list(dns_payload[:resolved_ips] || dns_payload["resolved_ips"]),
                format_response_list(dns_payload[:response_data] || dns_payload["response_data"])
              ],
              ""
            ),
          processName:
            first_present(
              [
                get_val.([:process_name, :name, "process_name", "name"], nil),
                nested_val.(process_payload, [:process_name, :name, "process_name", "name"], nil)
              ],
              "unknown"
            ),
          processPid:
            safe_to_int(
              first_present(
                [
                  get_val.([:pid, "pid"], nil),
                  nested_val.(process_payload, [:pid, "pid"], nil)
                ],
                0
              )
            ),
          processPath:
            first_present([
              get_val.([:process_path, :path, "process_path", "path"], nil),
              nested_val.(process_payload, [:process_path, :path, "process_path", "path"], nil)
            ]),
          agentId: event.agent_id,
          agentHostname:
            Enum.find_value(agents, event.agent_id, fn a ->
              if a.id == event.agent_id, do: a.hostname
            end),
          severity: to_string(event.severity || "info"),
          status: status,
          detections: []
        }
      end)

    # Calculate stats
    unique_domains = queries |> Enum.map(& &1.domain) |> Enum.uniq() |> length()
    blocked_count = Enum.count(queries, fn q -> q.status == "blocked" end)
    suspicious_count = Enum.count(queries, fn q -> q.status == "suspicious" end)

    render_inertia(conn, "DNS", %{
      stats: %{
        totalQueries: length(queries),
        uniqueDomains: unique_domains,
        blockedQueries: blocked_count,
        suspiciousQueries: suspicious_count
      },
      queries: queries,
      topDomains:
        queries
        |> Enum.group_by(& &1.domain)
        |> Enum.map(fn {domain, items} -> %{domain: domain, count: length(items)} end)
        |> Enum.sort_by(& &1.count, :desc)
        |> Enum.take(20),
      blocklist:
        try do
          case TamanduaServer.Detection.DNSAnalyzer.get_blocklist(org_id) do
            list when is_list(list) -> list
            _ -> []
          end
        catch
          kind, reason ->
            Logger.warning("DnsAnalyzer.get_blocklist failed: #{kind} #{inspect(reason)}")
            []
        end,
      alerts:
        try do
          Alerts.list_alerts(%{})
          |> Enum.filter(fn alert ->
            title = String.downcase(alert.title || "")
            String.contains?(title, ["dns", "domain"])
          end)
          |> Enum.take(20)
          |> Enum.map(&serialize_alert/1)
        rescue
          e ->
            Logger.warning("Failed to fetch DNS-related alerts: #{Exception.message(e)}")
            []
        end,
      agents: agents,
      pagination: %{page: 1, perPage: 50, total: length(queries)}
    })
  end

  defp first_present(values, default \\ nil) do
    Enum.find_value(values, default, fn
      nil -> nil
      "" -> nil
      [] -> nil
      value -> value
    end)
  end

  defp format_response_list(nil), do: nil
  defp format_response_list([]), do: nil
  defp format_response_list(values) when is_list(values), do: Enum.join(values, ", ")
  defp format_response_list(value), do: value

  def events(conn, params) do
    alias TamanduaServer.Telemetry
    import Ecto.Query

    current_user = conn.assigns[:current_user]
    org_id = current_user && current_user.organization_id

    # Parse pagination params
    page = params["page"] |> safe_parse_int(1) |> max(1)
    per_page = params["per_page"] |> safe_parse_int(25) |> max(1) |> min(50)
    offset = (page - 1) * per_page
    include_payloads? = params["include_payloads"] in ["true", true]

    # Build filter options
    filters = %{limit: per_page + 1, offset: offset, skip_agent_lookup: true}

    filters =
      if org_id, do: Map.put(filters, :organization_id, org_id), else: filters

    filters =
      if params["event_type"] && params["event_type"] != "",
        do: Map.put(filters, :event_type, params["event_type"]),
        else: filters

    filters =
      if params["agent_id"] && params["agent_id"] != "",
        do: Map.put(filters, :agent_id, params["agent_id"]),
        else: filters

    filters =
      if params["severity"] && params["severity"] != "",
        do: Map.put(filters, :severity, params["severity"]),
        else: filters

    # Time range filter
    filters =
      case params["time_range"] do
        "1h" -> Map.put(filters, :since, DateTime.add(DateTime.utc_now(), -1, :hour))
        "6h" -> Map.put(filters, :since, DateTime.add(DateTime.utc_now(), -6, :hour))
        "24h" -> Map.put(filters, :since, DateTime.add(DateTime.utc_now(), -24, :hour))
        "7d" -> Map.put(filters, :since, DateTime.add(DateTime.utc_now(), -7 * 24, :hour))
        "30d" -> Map.put(filters, :since, DateTime.add(DateTime.utc_now(), -30 * 24, :hour))
        _ -> filters
      end

    # Get events from telemetry. Pull one extra row so large tables do not need
    # an expensive COUNT(*) just to render the first page.
    {events_rows, events_error} =
      try do
        {Telemetry.list_events(filters), nil}
      rescue
        e in [DBConnection.ConnectionError, Postgrex.Error] ->
          Logger.warning("Telemetry.list_events failed for Events page: #{Exception.message(e)}")
          {[], Exception.message(e)}
      catch
        :exit, reason ->
          Logger.warning("Telemetry.list_events failed for Events page: exit #{inspect(reason)}")
          {[], "exit #{inspect(reason)}"}
      end

    has_more = length(events_rows) > per_page
    events_data = Enum.take(events_rows, per_page)
    total_count = offset + length(events_data) + if(has_more, do: 1, else: 0)

    # Build agent hostname lookup
    all_agents = list_agents_for_dashboard(org_id)

    agent_hostname_map =
      all_agents
      |> Enum.map(fn a -> {Map.get(a, :id) || Map.get(a, :agent_id), a.hostname} end)
      |> Map.new()

    # Serialize events for frontend
    events =
      Enum.map(events_data, fn event ->
        payload = event.payload || %{}

        %{
          id: event.id,
          agentId: event.agent_id,
          eventType: event.event_type,
          timestamp: format_datetime(event.timestamp),
          severity: event.severity || infer_severity(event.event_type),
          hostname: Map.get(agent_hostname_map, event.agent_id, "Unknown"),
          payload: if(include_payloads?, do: json_safe(payload), else: %{}),
          enrichment: if(include_payloads?, do: json_safe(event.enrichment || %{}), else: %{}),
          summary: build_event_summary(event.event_type, payload)
        }
      end)

    agents =
      all_agents
      |> Enum.map(fn a ->
        %{id: Map.get(a, :id) || Map.get(a, :agent_id), hostname: a.hostname}
      end)

    # Keep initial render cheap. Dynamic facets can be requested explicitly once
    # the UI is mounted; querying distinct values on a large telemetry table is
    # too expensive for every page load.
    event_types =
      if params["include_facets"] in ["true", true] do
        try do
          case Telemetry.get_distinct_event_types() do
            [] -> default_event_types()
            db_types when is_list(db_types) -> db_types
            _ -> default_event_types()
          end
        rescue
          e ->
            Logger.warning("Telemetry.get_distinct_event_types failed: #{Exception.message(e)}")
            default_event_types()
        catch
          :exit, reason ->
            Logger.warning("Telemetry.get_distinct_event_types failed: exit #{inspect(reason)}")
            default_event_types()
        end
      else
        default_event_types()
      end

    # Event stats by type
    type_counts =
      events_data
      |> Enum.frequencies_by(& &1.event_type)

    # Event stats by severity
    severity_counts =
      events_data
      |> Enum.frequencies_by(&(&1.severity || infer_severity(&1.event_type)))

    render_inertia(conn, "Events", %{
      events: events,
      filters: %{
        types: event_types,
        agents: agents
      },
      pagination: %{
        page: page,
        perPage: per_page,
        total: total_count,
        totalPages: max(1, ceil(total_count / per_page)),
        hasMore: has_more,
        totalIsEstimate: true
      },
      stats: %{
        byType: type_counts,
        bySeverity: severity_counts,
        total: total_count
      },
      activeFilters: %{
        eventType: params["event_type"] || "",
        agentId: params["agent_id"] || "",
        severity: params["severity"] || "",
        timeRange: params["time_range"] || ""
      },
      eventsUnavailable: not is_nil(events_error),
      eventsError: events_error
    })
  end

  defp default_event_types do
    [
      "process_create",
      "process_terminate",
      "file_create",
      "file_modify",
      "file_delete",
      "network_connect",
      "dns_query",
      "registry_modify"
    ]
  end

  # Build a human-readable summary for an event
  defp build_event_summary(event_type, payload) do
    case event_type do
      "process_create" ->
        name = payload["name"] || payload["process_name"] || "Unknown"
        "Process started: #{name}"

      "process_terminate" ->
        name = payload["name"] || payload["process_name"] || "Unknown"
        "Process terminated: #{name}"

      "file_create" ->
        path = payload["path"] || payload["file_path"] || "Unknown"
        "File created: #{Path.basename(path)}"

      "file_modify" ->
        path = payload["path"] || payload["file_path"] || "Unknown"
        "File modified: #{Path.basename(path)}"

      "file_delete" ->
        path = payload["path"] || payload["file_path"] || "Unknown"
        "File deleted: #{Path.basename(path)}"

      "network_connect" ->
        dest = payload["remote_ip"] || payload["dest_ip"] || "Unknown"
        port = payload["remote_port"] || payload["dest_port"] || ""
        "Network connection to #{dest}:#{port}"

      "dns_query" ->
        domain = payload["domain"] || payload["query"] || "Unknown"
        "DNS query: #{domain}"

      "registry_modify" ->
        key = payload["key"] || payload["registry_key"] || "Unknown"
        "Registry modified: #{key}"

      _ ->
        "Event: #{event_type}"
    end
  end

  defp infer_severity(event_type) do
    case event_type do
      t
      when t in [
             "injection_detected",
             "process_hollowing",
             "lsass_access",
             "ransomware_canary",
             "exploit_attempt"
           ] ->
        "critical"

      t
      when t in [
             "credential_access",
             "defense_evasion",
             "lateral_movement",
             "honeyfile_access",
             "input_capture"
           ] ->
        "high"

      t when t in ["persistence", "amsi_scan", "scheduled_task", "wmi_event"] ->
        "medium"

      _ ->
        "low"
    end
  end

  def prevention_policies(conn, _params) do
    alias TamanduaServer.Detection.PreventionPolicy

    current_user = conn.assigns[:current_user]
    org_id = current_user && current_user.organization_id

    policies =
      try do
        PreventionPolicy.list_policies()
        |> Enum.map(fn policy ->
          %{
            id: policy.id,
            name: policy.name,
            description: policy.description,
            isDefault: policy.is_default,
            isEnabled: policy.is_enabled,
            globalMode: policy.global_mode,
            globalAggressiveness: policy.global_aggressiveness,
            categorySettings: policy.category_settings || %{},
            assignedGroups: policy.assigned_groups || [],
            assignedAgents: policy.assigned_agents || [],
            excludedPaths: policy.excluded_paths || [],
            excludedProcesses: policy.excluded_processes || [],
            excludedHashes: policy.excluded_hashes || [],
            excludedUsers: policy.excluded_users || [],
            createdAt: format_datetime(policy.inserted_at),
            updatedAt: format_datetime(policy.updated_at)
          }
        end)
      rescue
        e ->
          Logger.warning("PreventionPolicy.list_policies failed: #{Exception.message(e)}")
          []
      end

    agents =
      list_agents_for_dashboard(org_id)
      |> Enum.map(fn a ->
        %{
          id: Map.get(a, :id) || Map.get(a, :agent_id),
          hostname: a.hostname,
          status: to_string(a.status)
        }
      end)

    threat_categories =
      try do
        PreventionPolicy.threat_categories()
        |> Enum.map(fn cat ->
          %{key: to_string(cat.key), label: cat.label, description: cat.description}
        end)
      rescue
        e ->
          Logger.warning("PreventionPolicy.threat_categories failed: #{Exception.message(e)}")
          []
      end

    aggressiveness_levels =
      try do
        PreventionPolicy.aggressiveness_summary()
        |> Enum.map(fn level ->
          %{
            level: to_string(level.level),
            label: level.label,
            description: level.description,
            alertThreshold: level.alert_threshold,
            blockThreshold: level.block_threshold
          }
        end)
      rescue
        e ->
          Logger.warning(
            "PreventionPolicy.aggressiveness_summary failed: #{Exception.message(e)}"
          )

          []
      end

    render_inertia(conn, "PreventionPolicies", %{
      page_title: "Prevention Policies",
      policies: policies,
      agents: agents,
      threatCategories: threat_categories,
      aggressivenessLevels: aggressiveness_levels
    })
  end

  def settings(conn, _params) do
    # Get current user from session for user-specific preferences
    current_user = conn.assigns[:current_user]

    # Get current configuration
    config = Application.get_all_env(:tamandua_server)

    detection_config = %{
      mlEnabled: Keyword.get(config, :ml_enabled, true),
      mlConfidenceThreshold: Keyword.get(config, :ml_confidence_threshold, 0.7),
      sigmaEnabled: Keyword.get(config, :sigma_enabled, true),
      yaraEnabled: Keyword.get(config, :yara_enabled, true),
      autoResponseEnabled: Keyword.get(config, :auto_response_enabled, false),
      isolateOnCritical: Keyword.get(config, :isolate_on_critical, false),
      quarantineOnMalware: Keyword.get(config, :quarantine_on_malware, false)
    }

    # Get notification configuration from application config, scoped to user when available
    notifications_config = Keyword.get(config, :notifications, [])

    # Use current user email as default recipient when available
    default_recipients =
      if current_user && current_user.email do
        [current_user.email]
      else
        Keyword.get(notifications_config, :email_recipients, [])
      end

    notification_config = %{
      emailEnabled: Keyword.get(notifications_config, :email_enabled, false),
      emailRecipients: default_recipients,
      slackEnabled: Keyword.get(notifications_config, :slack_enabled, false),
      slackWebhook:
        if(Keyword.get(notifications_config, :slack_webhook), do: "***configured***", else: nil),
      webhookEnabled: Keyword.get(notifications_config, :webhook_enabled, false),
      webhookUrl:
        if(Keyword.get(notifications_config, :webhook_url), do: "***configured***", else: nil),
      criticalAlerts: Keyword.get(notifications_config, :critical_alerts, true),
      highAlerts: Keyword.get(notifications_config, :high_alerts, false),
      mediumAlerts: Keyword.get(notifications_config, :medium_alerts, false)
    }

    # Get SIEM integrations from the SIEM module
    alias TamanduaServer.Integrations.SIEM

    siem_integrations =
      try do
        case SIEM.list_integrations() do
          {:ok, list} ->
            Enum.map(list, fn integration ->
              %{
                id: integration.id,
                name: integration.name,
                type: to_string(integration.type),
                enabled: integration.enabled,
                status: determine_siem_integration_status(integration)
              }
            end)

          _ ->
            []
        end
      catch
        kind, reason ->
          Logger.warning("SIEM.list_integrations failed: #{kind} #{inspect(reason)}")
          []
      end

    # Build default integration list with actual SIEM integrations merged in
    default_integrations = [
      %{
        id: "virustotal",
        name: "VirusTotal",
        type: "threat_intel",
        enabled: false,
        status: "disconnected"
      },
      %{id: "misp", name: "MISP", type: "threat_intel", enabled: false, status: "disconnected"},
      %{
        id: "otx",
        name: "AlienVault OTX",
        type: "threat_intel",
        enabled: false,
        status: "disconnected"
      }
    ]

    # Merge SIEM integrations with defaults
    integrations = default_integrations ++ siem_integrations

    # System stats
    {:ok, hostname} = :inet.gethostname()
    memory = :erlang.memory()

    system_stats = %{
      version: Application.spec(:tamandua_server, :vsn) |> to_string(),
      uptime: :erlang.statistics(:wall_clock) |> elem(0) |> div(1000),
      hostname: to_string(hostname),
      erlangVersion: :erlang.system_info(:otp_release) |> to_string(),
      memoryUsed: div(memory[:total], 1024 * 1024),
      processCount: :erlang.system_info(:process_count)
    }

    # Include user info for user-specific settings display
    user_info =
      if current_user do
        %{
          id: current_user.id,
          email: current_user.email,
          name: current_user.name,
          role: current_user.role
        }
      else
        nil
      end

    render_inertia(conn, "Settings", %{
      config: detection_config,
      notifications: notification_config,
      integrations: integrations,
      system: system_stats,
      user: user_info
    })
  end

  def tenant_settings(conn, _params) do
    current_user = conn.assigns[:current_user]
    org_id = current_user && current_user.organization_id

    # Get tenant info from organization
    tenant =
      if org_id do
        case TamanduaServer.Repo.get(TamanduaServer.Organizations.Organization, org_id) do
          nil ->
            default_tenant()

          org ->
            %{
              id: org.id,
              name: org.name,
              slug: org.slug || String.downcase(String.replace(org.name, ~r/\s+/, "-")),
              domain: org.domain,
              status: org.status || "active",
              plan: org.plan || "free",
              logo_url: org.logo_url,
              primary_color: org.primary_color,
              created_at: org.inserted_at,
              updated_at: org.updated_at,
              agent_count: 0,
              user_count: 0,
              event_count_30d: 0,
              storage_used_mb: 0
            }
        end
      else
        default_tenant()
      end

    # Get tenant settings (from organization or defaults)
    settings = %{
      logo_url: tenant[:logo_url],
      primary_color: tenant[:primary_color] || "#6366f1",
      secondary_color: "#10b981",
      favicon_url: nil,
      custom_css: nil,
      sso_enabled: false,
      sso_provider: nil,
      sso_config: nil,
      mfa_required: false,
      max_agents: 100,
      max_users: 50,
      max_events_per_day: 1_000_000,
      retention_days: 90,
      admin_email: current_user && current_user.email,
      support_email: nil,
      billing_email: nil
    }

    # Get API keys for this tenant
    api_keys = []

    # Get license info
    license = %{
      tenant_id: tenant[:id],
      plan: tenant[:plan] || "free",
      status: "active",
      started_at: tenant[:created_at] || DateTime.utc_now(),
      expires_at: DateTime.add(DateTime.utc_now(), 365, :day),
      auto_renew: true,
      limits: %{
        max_agents: 100,
        max_users: 50,
        max_events_per_day: 1_000_000,
        retention_days: 90,
        features: ["basic_detection", "alerts", "dashboard"]
      },
      usage: %{
        agents: 0,
        users: 1,
        events_today: 0
      }
    }

    # Available SSO providers
    available_sso_providers = ["saml", "oidc", "azure_ad", "okta", "google"]

    render_inertia(conn, "TenantSettings", %{
      tenant: tenant,
      settings: settings,
      api_keys: api_keys,
      license: license,
      available_sso_providers: available_sso_providers
    })
  end

  defp default_tenant do
    %{
      id: "default",
      name: "Default Tenant",
      slug: "default",
      domain: nil,
      status: "active",
      plan: "free",
      logo_url: nil,
      primary_color: "#6366f1",
      created_at: DateTime.utc_now(),
      updated_at: DateTime.utc_now(),
      agent_count: 0,
      user_count: 0,
      event_count_30d: 0,
      storage_used_mb: 0
    }
  end

  def response(conn, _params) do
    current_user = conn.assigns[:current_user]
    org_id = current_user && current_user.organization_id

    agents =
      list_agents_for_dashboard(org_id)
      |> Enum.map(fn a ->
        %{
          id: Map.get(a, :id) || Map.get(a, :agent_id),
          hostname: a.hostname,
          status: a.status
        }
      end)

    recent_actions =
      TamanduaServer.Response.list_actions(%{})
      |> Enum.take(20)
      |> Enum.map(&serialize_response_action/1)

    render_inertia(conn, "Response", %{
      agents: agents,
      recentActions: recent_actions
    })
  end

  # Timeline / Attack Storyline
  def timeline(conn, params) do
    current_user = conn.assigns[:current_user]
    org_id = current_user && current_user.organization_id
    include_payloads? = params["include_payloads"] in ["true", true]

    # Get time range from params (default 24h)
    time_window_minutes =
      case params["time_range"] do
        "1h" -> 60
        "6h" -> 360
        "12h" -> 720
        "24h" -> 1440
        "7d" -> 10080
        "30d" -> 43200
        # default 24h
        _ -> 1440
      end

    # Keep the initial page load cheap. Expensive correlation is available via
    # /api/v1/timeline and /api/v1/timeline/correlate after the UI mounts.
    incidents =
      if params["include_incidents"] in ["true", true] do
        clusters =
          if is_nil(org_id) do
            []
          else
            Detection.Timeline.auto_correlate_alerts(org_id,
              time_window_minutes: time_window_minutes,
              limit: 25
            )
          end

        case clusters do
          clusters when is_list(clusters) ->
            clusters
            |> Enum.take(10)
            |> Enum.flat_map(fn alert_cluster ->
              try do
                alert_ids = Enum.map(alert_cluster, & &1.id)
                incident = Detection.Timeline.build_incident(alert_ids)
                [serialize_incident(incident, alert_cluster)]
              rescue
                e ->
                  Logger.warning("Timeline incident serialization failed: #{Exception.message(e)}")
                  []
              catch
                :exit, reason ->
                  Logger.warning("Timeline incident serialization failed: exit #{inspect(reason)}")
                  []
              end
            end)

          _ ->
            []
        end
      else
        []
      end

    # Build filters
    agents = list_agents_for_dashboard(org_id) |> Enum.map(&serialize_agent/1)

    agent_hostnames =
      agents
      |> Enum.map(fn agent -> {agent.id, agent.hostname} end)
      |> Map.new()

    filters = %{
      eventTypes: ["process", "file", "network", "registry", "alert", "dns"],
      agents: agents,
      severities: ["critical", "high", "medium", "low", "info"]
    }

    # Get recent events for timeline display
    timeline_events =
      try do
        alias TamanduaServer.Telemetry

        timeline_filters = %{limit: 25, skip_agent_lookup: true}
        timeline_filters = if org_id, do: Map.put(timeline_filters, :organization_id, org_id), else: timeline_filters

        Telemetry.list_events(timeline_filters)
        |> Enum.map(fn event ->
          payload = event.payload || %{}

          %{
            id: event.id,
            agentId: event.agent_id,
            eventType: event.event_type,
            timestamp: format_datetime(event.timestamp),
            severity: to_string(Map.get(event, :severity, "info")),
            summary: build_event_summary(event.event_type, payload),
            hostname: Map.get(agent_hostnames, event.agent_id, "Unknown"),
            payload: if(include_payloads?, do: json_safe(payload), else: %{})
          }
        end)
      rescue
        e ->
          Logger.warning("Failed to build timeline events: #{Exception.message(e)}")
          []
      catch
        :exit, reason ->
          Logger.warning("Failed to build timeline events: exit #{inspect(reason)}")
          []
      end

    render_inertia(conn, "Timeline", %{
      page_title: "Attack Timeline",
      events: timeline_events,
      incidents: incidents,
      filters: filters
    })
  end

  def timeline_detail(conn, %{"incident_id" => incident_id}) do
    # incident_id could be a single alert ID or comma-separated list of alert IDs
    alert_ids =
      String.split(incident_id, ",")
      |> Enum.map(&String.trim/1)
      |> Enum.reject(&(&1 == ""))

    case alert_ids do
      [] ->
        render_inertia(conn, "TimelineDetail", %{
          page_title: "Incident Timeline",
          incidentId: incident_id,
          incident: nil,
          events: [],
          timeline: [],
          error: "No alert IDs provided"
        })

      [single_alert_id] ->
        # Build timeline from a single alert
        try do
          timeline_data = Detection.Timeline.build_timeline(single_alert_id)

          render_inertia(conn, "TimelineDetail", %{
            page_title: "Incident Timeline",
            incidentId: incident_id,
            incident: %{
              alertId: single_alert_id,
              agentId: timeline_data[:agent_id],
              timestampStart: format_datetime(timeline_data[:timestamp_start]),
              timestampEnd: format_datetime(timeline_data[:timestamp_end]),
              summary: timeline_data[:summary],
              metrics: timeline_data[:metrics]
            },
            events: serialize_timeline_events(timeline_data),
            timeline: %{
              processTree: serialize_timeline_process_tree(timeline_data[:process_tree] || []),
              networkTimeline:
                Enum.map(
                  timeline_data[:network_timeline] || [],
                  &serialize_timeline_network_event/1
                ),
              fileTimeline:
                Enum.map(timeline_data[:file_timeline] || [], &serialize_timeline_file_event/1),
              mitreProgression: timeline_data[:mitre_progression] || []
            },
            error: nil
          })
        rescue
          e ->
            render_inertia(conn, "TimelineDetail", %{
              page_title: "Incident Timeline",
              incidentId: incident_id,
              incident: nil,
              events: [],
              timeline: [],
              error: "Failed to build timeline: #{Exception.message(e)}"
            })
        end

      multiple_alert_ids ->
        # Build incident from multiple correlated alerts
        try do
          incident = Detection.Timeline.build_incident(multiple_alert_ids)

          render_inertia(conn, "TimelineDetail", %{
            page_title: "Incident Timeline",
            incidentId: incident_id,
            incident: %{
              alertIds: incident[:alert_ids],
              severity: incident[:severity],
              eventCount: incident[:event_count],
              affectedAssets: incident[:affected_assets] || [],
              mitreCoverage: incident[:mitre_coverage] || %{},
              rootCause: serialize_root_cause(incident[:root_cause]),
              attackChain:
                Enum.map(incident[:attack_chain] || [], &serialize_attack_chain_entry/1),
              recommendations: incident[:recommended_actions] || []
            },
            events:
              Enum.map(incident[:timeline] || [], fn event ->
                %{
                  timestamp: format_datetime(event[:timestamp]),
                  eventType: event[:event_type],
                  agentId: event[:agent_id],
                  summary: event[:summary],
                  payload: event[:payload]
                }
              end),
            timeline: incident[:timeline] || [],
            error: nil
          })
        rescue
          e ->
            render_inertia(conn, "TimelineDetail", %{
              page_title: "Incident Timeline",
              incidentId: incident_id,
              incident: nil,
              events: [],
              timeline: [],
              error: "Failed to build incident: #{Exception.message(e)}"
            })
        end
    end
  end

  # Timeline serialization helpers
  defp serialize_timeline_events(timeline_data) do
    process_events =
      Enum.map(timeline_data[:process_tree] || [], fn node ->
        %{
          type: "process",
          timestamp: format_datetime(node[:start_time]),
          data: serialize_timeline_process_node(node)
        }
      end)

    network_events =
      Enum.map(timeline_data[:network_timeline] || [], fn event ->
        %{
          type: "network",
          timestamp: format_datetime(event[:timestamp]),
          data: serialize_timeline_network_event(event)
        }
      end)

    file_events =
      Enum.map(timeline_data[:file_timeline] || [], fn event ->
        %{
          type: "file",
          timestamp: format_datetime(event[:timestamp]),
          data: serialize_timeline_file_event(event)
        }
      end)

    (process_events ++ network_events ++ file_events) |> Enum.sort_by(& &1.timestamp)
  end

  defp serialize_timeline_process_tree(nodes) when is_list(nodes),
    do: Enum.map(nodes, &serialize_timeline_process_node/1)

  defp serialize_timeline_process_tree(_), do: []

  defp serialize_timeline_process_node(node) when is_map(node) do
    %{
      pid: node[:pid],
      ppid: node[:ppid],
      name: node[:name],
      path: node[:path],
      cmdline: node[:cmdline],
      user: node[:user],
      startTime: format_datetime(node[:start_time]),
      sha256: node[:sha256],
      isElevated: node[:is_elevated],
      isSigned: node[:is_signed],
      signer: node[:signer],
      children: serialize_timeline_process_tree(node[:children] || [])
    }
  end

  defp serialize_timeline_process_node(_), do: nil

  defp serialize_timeline_network_event(event) when is_map(event) do
    %{
      timestamp: format_datetime(event[:timestamp]),
      pid: event[:pid],
      processName: event[:process_name],
      localIp: event[:local_ip],
      localPort: event[:local_port],
      remoteIp: event[:remote_ip],
      remotePort: event[:remote_port],
      protocol: event[:protocol],
      direction: event[:direction],
      bytesIn: event[:bytes_in],
      bytesOut: event[:bytes_out]
    }
  end

  defp serialize_timeline_network_event(_), do: nil

  defp serialize_timeline_file_event(event) when is_map(event) do
    %{
      timestamp: format_datetime(event[:timestamp]),
      pid: event[:pid],
      processName: event[:process_name],
      eventType: event[:event_type],
      path: event[:path],
      sha256: event[:sha256],
      size: event[:size]
    }
  end

  defp serialize_timeline_file_event(_), do: nil

  # Storyline - SentinelOne-style attack visualization
  def storyline(conn, %{"alert_id" => alert_id} = params) do
    layout = Map.get(params, "layout", "timeline")

    alias TamanduaServer.Storyline.Engine

    case safe_storyline_result(fn -> Engine.generate_for_alert(alert_id, layout: layout) end) do
      {:ok, storyline} ->
        analysis = safe_storyline_analysis(storyline)

        render_inertia(conn, "Storyline", %{
          page_title: "Attack Storyline",
          alert_id: alert_id,
          storyline: serialize_storyline_for_inertia(storyline),
          analysis: serialize_storyline_analysis(analysis),
          layout: layout,
          error: nil
        })

      {:error, :alert_not_found} ->
        render_inertia(conn, "Storyline", %{
          page_title: "Attack Storyline",
          alert_id: alert_id,
          storyline: nil,
          analysis: nil,
          layout: layout,
          error: "Alert not found"
        })

      {:error, reason} ->
        render_inertia(conn, "Storyline", %{
          page_title: "Attack Storyline",
          alert_id: alert_id,
          storyline: nil,
          analysis: nil,
          layout: layout,
          error: "Failed to generate storyline: #{inspect(reason)}"
        })
    end
  end

  def storyline_process(conn, %{"agent_id" => agent_id, "pid" => pid_str} = params) do
    layout = Map.get(params, "layout", "timeline")
    parsed_pid = parse_positive_integer(pid_str)

    if is_nil(parsed_pid) do
      render_inertia(conn, "Storyline", %{
        page_title: "Process Investigation",
        alert_id: nil,
        agent_id: agent_id,
        pid: pid_str,
        storyline: nil,
        analysis: nil,
        layout: layout,
        error: "Invalid process id: #{pid_str}"
      })
    else
      pid = parsed_pid
      time_window = parse_positive_integer(Map.get(params, "time_window_minutes") || Map.get(params, "time_window")) || 60

      alias TamanduaServer.Storyline.Engine

      case safe_storyline_result(fn ->
             Engine.generate_from_process(agent_id, pid,
               time_window_minutes: time_window,
               layout: layout
             )
           end) do
        {:ok, storyline} ->
          analysis = safe_storyline_analysis(storyline)

          render_inertia(conn, "Storyline", %{
            page_title: "Process Investigation",
            alert_id: nil,
            agent_id: agent_id,
            pid: pid,
            storyline: serialize_storyline_for_inertia(storyline),
            analysis: serialize_storyline_analysis(analysis),
            layout: layout,
            error: nil
          })

        {:error, reason} ->
          render_inertia(conn, "Storyline", %{
            page_title: "Process Investigation",
            alert_id: nil,
            agent_id: agent_id,
            pid: pid,
            storyline: nil,
            analysis: nil,
            layout: layout,
            error: "Failed to generate storyline: #{inspect(reason)}"
          })
      end
    end
  end

  defp parse_positive_integer(value) when is_integer(value) and value > 0, do: value

  defp parse_positive_integer(value) when is_binary(value) do
    case Integer.parse(value) do
      {int, ""} when int > 0 -> int
      {int, _rest} when int > 0 -> int
      _ -> nil
    end
  end

  defp parse_positive_integer(_), do: nil

  defp safe_storyline_result(fun) when is_function(fun, 0) do
    fun.()
  rescue
    e ->
      Logger.warning("Failed to generate storyline: #{Exception.message(e)}")
      {:error, Exception.message(e)}
  catch
    kind, reason ->
      Logger.warning("Failed to generate storyline: #{inspect({kind, reason})}")
      {:error, reason}
  end

  defp safe_storyline_analysis(storyline) do
    alias TamanduaServer.Storyline.Engine

    case Engine.analyze_storyline(storyline) do
      {:ok, analysis} -> analysis
      {:error, reason} -> fallback_storyline_analysis(storyline, reason)
      other -> fallback_storyline_analysis(storyline, other)
    end
  rescue
    e ->
      Logger.warning("Failed to analyze storyline: #{Exception.message(e)}")
      fallback_storyline_analysis(storyline, Exception.message(e))
  catch
    kind, reason ->
      Logger.warning("Failed to analyze storyline: #{inspect({kind, reason})}")
      fallback_storyline_analysis(storyline, reason)
  end

  defp fallback_storyline_analysis(storyline, reason) do
    %{
      threat_assessment: %{
        severity: Map.get(storyline, :severity, "unknown"),
        confidence: Map.get(storyline, :confidence_score, 0),
        reason: "Automated storyline analysis unavailable: #{inspect(reason)}"
      },
      attack_techniques:
        (Map.get(storyline, :mitre_techniques, []) || [])
        |> Enum.map(fn
          value when is_binary(value) ->
            %{id: value, name: value, tactic: "unknown", description: "Technique observed in storyline telemetry"}

          value when is_map(value) ->
            value

          value ->
            %{id: to_string(value), name: to_string(value), tactic: "unknown", description: ""}
        end),
      recommended_actions: [
        %{
          priority: "medium",
          action:
            "Review correlated events, evidence, and response actions from the alert detail view",
          reason: "The storyline graph was generated, but deeper analysis did not complete"
        }
      ],
      confidence: Map.get(storyline, :confidence_score, 0),
      attack_narrative:
        Map.get(storyline, :summary, "Storyline generated from correlated endpoint telemetry.")
    }
  end

  defp serialize_storyline_for_inertia(storyline) do
    %{
      id: Map.get(storyline, :id),
      alert_id: Map.get(storyline, :alert_id),
      agent_id: Map.get(storyline, :agent_id),
      title: Map.get(storyline, :title),
      summary: Map.get(storyline, :summary),
      severity: Map.get(storyline, :severity),
      root_cause: Map.get(storyline, :root_cause),
      nodes: Map.get(storyline, :nodes, []),
      edges: Map.get(storyline, :edges, []),
      timeline: Map.get(storyline, :timeline, []),
      threat_indicators: Map.get(storyline, :threat_indicators, []),
      mitre_techniques: Map.get(storyline, :mitre_techniques, []),
      attack_phase: Map.get(storyline, :attack_phase),
      confidence_score: Map.get(storyline, :confidence_score),
      generated_at: format_datetime(Map.get(storyline, :generated_at)),
      time_range: serialize_storyline_time_range(Map.get(storyline, :time_range))
    }
  end

  defp serialize_storyline_analysis(analysis) do
    %{
      threat_assessment: Map.get(analysis, :threat_assessment),
      attack_techniques: Map.get(analysis, :attack_techniques, []),
      recommended_actions: Map.get(analysis, :recommended_actions, []),
      confidence: Map.get(analysis, :confidence, 0),
      attack_narrative: Map.get(analysis, :attack_narrative)
    }
  end

  defp serialize_storyline_time_range(%{start: start_time, end: end_time}) do
    %{start: format_datetime(start_time), end: format_datetime(end_time)}
  end

  defp serialize_storyline_time_range(%{"start" => start_time, "end" => end_time}) do
    %{start: format_datetime(start_time), end: format_datetime(end_time)}
  end

  defp serialize_storyline_time_range(_), do: %{start: nil, end: nil}

  # AI Assistant
  def ai_assistant(conn, _params) do
    current_user = conn.assigns[:current_user]
    org_id = current_user && current_user.organization_id

    # Get hunting suggestions from QueryInterface
    suggestions = QueryInterface.get_hunting_suggestions(nil)

    # Format suggested queries based on threat hunting templates
    suggested_queries = [
      "What are the most critical alerts from today?",
      "Show me suspicious process executions",
      "Analyze the latest malware detection",
      "Generate a threat hunt query for lateral movement",
      "Find processes connecting to external IPs after business hours",
      "Search for encoded PowerShell commands",
      "Show credential access attempts in the last 24 hours"
    ]

    # Add dynamic suggestions from QueryInterface
    dynamic_suggestions =
      case suggestions do
        {:ok, sugg_list} when is_list(sugg_list) ->
          Enum.map(sugg_list, fn s -> s[:query] || s[:text] || s end)
          |> Enum.take(5)

        _ when is_list(suggestions) ->
          Enum.map(suggestions, fn s -> s[:query] || s[:text] || s end)
          |> Enum.take(5)

        _ ->
          []
      end

    all_suggestions =
      (dynamic_suggestions ++ suggested_queries)
      |> Enum.uniq()
      |> Enum.take(10)

    # Get conversations from session (stored as a list of conversation maps)
    # Each conversation has: id, title, messages, created_at, updated_at
    conversations = get_session(conn, :ai_conversations) || []

    # Build real environment context from system state
    active_agents =
      try do
        list_agents_for_dashboard(org_id)
        |> Enum.count(fn a -> to_string(a.status) == "online" end)
      rescue
        e ->
          Logger.warning("Failed to count active agents: \#{Exception.message(e)}")
          0
      end

    open_alerts =
      try do
        Alerts.count_active_for_org(org_id)
      rescue
        e ->
          Logger.warning("Failed to count open alerts: \#{Exception.message(e)}")
          0
      end

    events_today =
      try do
        TamanduaServer.Telemetry.count_events_today_for_org(org_id)
      rescue
        e ->
          Logger.warning("Failed to count events today: \#{Exception.message(e)}")
          0
      end

    environment_context = %{
      activeAgents: active_agents,
      openAlerts: open_alerts,
      activeInvestigations: 0,
      eventsToday: events_today
    }

    render_inertia(conn, "AIAssistant", %{
      page_title: "AI Assistant",
      conversations: conversations,
      suggestedQueries: all_suggestions,
      environmentContext: environment_context,
      capabilities: [
        %{
          id: "query",
          name: "Natural Language Queries",
          description: "Ask questions about your security data in plain English"
        },
        %{
          id: "summarize",
          name: "Alert Summarization",
          description: "Get AI-generated summaries of alerts and incidents"
        },
        %{
          id: "hunt",
          name: "Hunt Query Generation",
          description: "Generate threat hunting queries from descriptions"
        },
        %{
          id: "ioc",
          name: "IOC Extraction",
          description: "Extract indicators of compromise from text"
        },
        %{
          id: "mitre",
          name: "MITRE Mapping",
          description: "Map descriptions to MITRE ATT&CK techniques"
        }
      ]
    })
  end

  # Playbooks
  def playbooks(conn, _params) do
    alias TamanduaServer.Response.Playbook

    playbooks =
      try do
        case Playbook.list_playbooks() do
          {:ok, list} when is_list(list) -> Enum.map(list, &serialize_playbook/1)
          _ -> []
        end
      catch
        kind, reason ->
          Logger.warning("Playbook.list_playbooks failed: \#{kind} \#{inspect(reason)}")
          []
      end

    templates =
      try do
        [
          TamanduaServer.Response.Playbook.Templates.ransomware_response(),
          TamanduaServer.Response.Playbook.Templates.lateral_movement_response(),
          TamanduaServer.Response.Playbook.Templates.credential_theft_response()
        ]
        |> Enum.map(fn t ->
          %{
            id: t[:id] || t.id || UUID.uuid4(),
            name: t[:name] || t.name || "Template",
            description: t[:description] || t.description || "",
            triggerType: t[:trigger_type] || t.trigger_type || "manual",
            steps: t[:steps] || t.steps || []
          }
        end)
      catch
        kind, reason ->
          Logger.warning("Failed to load playbook templates: \#{kind} \#{inspect(reason)}")
          []
      end

    # Frontend expects executions as an array of PlaybookExecution objects
    executions =
      try do
        case Playbook.list_recent_executions(limit: 20) do
          {:ok, list} when is_list(list) -> Enum.map(list, &serialize_playbook_execution/1)
          _ -> []
        end
      catch
        kind, reason ->
          Logger.warning("Playbook.list_recent_executions failed: \#{kind} \#{inspect(reason)}")
          []
      end

    render_inertia(conn, "Playbooks", %{
      page_title: "Automated Playbooks",
      playbooks: playbooks,
      templates: templates,
      executions: executions
    })
  end

  def playbook_detail(conn, %{"id" => id}) do
    alias TamanduaServer.Response.Playbook

    case Playbook.get_playbook(id) do
      {:ok, playbook} ->
        # Get execution history for this playbook
        execution_history =
          case Playbook.get_execution_history(id) do
            {:ok, history} -> Enum.map(history, &serialize_playbook_execution/1)
            _ -> []
          end

        render_inertia(conn, "PlaybookDetail", %{
          page_title: playbook.name || "Playbook Details",
          playbookId: id,
          playbook: serialize_playbook(playbook),
          executionHistory: execution_history
        })

      {:error, :not_found} ->
        render_inertia(conn, "PlaybookDetail", %{
          page_title: "Playbook Not Found",
          playbookId: id,
          playbook: nil,
          executionHistory: [],
          error: "Playbook not found"
        })

      {:error, reason} ->
        render_inertia(conn, "PlaybookDetail", %{
          page_title: "Playbook Details",
          playbookId: id,
          playbook: nil,
          executionHistory: [],
          error: "Failed to load playbook: #{inspect(reason)}"
        })
    end
  end

  defp serialize_playbook_execution(execution) do
    %{
      id: execution[:id] || execution.id,
      playbookId: execution[:playbook_id] || execution.playbook_id,
      triggeredBy: execution[:triggered_by] || execution.triggered_by,
      alertId: execution[:alert_id] || execution.alert_id,
      status: execution[:status] || execution.status,
      startedAt: format_datetime(execution[:started_at] || execution.started_at),
      completedAt: format_datetime(execution[:completed_at] || execution.completed_at),
      stepResults: execution[:step_results] || execution.step_results || [],
      error: execution[:error] || execution.error
    }
  end

  # Assets
  def assets(conn, _params) do
    # Get all assets from the AssetManager module
    all_assets =
      try do
        case AssetManager.list_assets(%{}) do
          {:ok, assets} -> assets
          _ -> []
        end
      catch
        kind, reason ->
          Logger.warning("AssetManager.list_assets failed: #{kind} #{inspect(reason)}")
          []
      end

    # Serialize assets for frontend
    assets = Enum.map(all_assets, &serialize_asset/1)

    # Get vulnerability summary for stats
    vuln_summary =
      try do
        case AssetManager.get_vulnerability_summary() do
          {:ok, summary} -> summary
          _ -> %{assets: %{affected: 0}, average_risk_score: 0}
        end
      catch
        kind, reason ->
          Logger.warning(
            "AssetManager.get_vulnerability_summary failed: #{kind} #{inspect(reason)}"
          )

          %{assets: %{affected: 0}, average_risk_score: 0}
      end

    # Calculate stats
    affected_assets =
      vuln_summary
      |> get_any([:assets, "assets"])
      |> get_any([:affected, "affected"]) || 0

    stats = %{
      totalAssets: length(all_assets),
      managedAssets: Enum.count(all_assets, &asset_managed?/1),
      unmanagedAssets: Enum.count(all_assets, &(not asset_managed?(&1))),
      criticalAssets: Enum.count(all_assets, &(asset_value(&1, :criticality) == "critical")),
      vulnerableAssets: affected_assets,
      averageRiskScore: get_any(vuln_summary, [:average_risk_score, "average_risk_score"]) || 0
    }

    render_inertia(conn, "Assets", %{
      page_title: "Asset Inventory",
      assets: assets,
      stats: stats
    })
  end

  def asset_detail(conn, %{"id" => id}) do
    case AssetManager.get_asset(id) do
      {:ok, asset} ->
        # Get vulnerabilities for this asset
        vulnerabilities =
          case AssetManager.list_vulnerabilities(id) do
            {:ok, vulns} -> Enum.map(vulns, &serialize_asset_vulnerability/1)
            _ -> []
          end

        # Get risk report for this asset
        risk_report =
          case AssetManager.get_risk_report(id) do
            {:ok, report} -> report
            _ -> %{score: asset.risk_score || 0, factors: [], recommendations: []}
          end

        render_inertia(conn, "AssetDetail", %{
          page_title: asset.hostname || "Asset Details",
          assetId: id,
          asset: serialize_asset(asset),
          vulnerabilities: vulnerabilities,
          riskScore: risk_report[:score] || asset.risk_score || 0,
          riskFactors: risk_report[:factors] || [],
          recommendations: risk_report[:recommendations] || [],
          securityPosture: asset.security_posture || %{}
        })

      {:error, :not_found} ->
        render_inertia(conn, "AssetDetail", %{
          page_title: "Asset Not Found",
          assetId: id,
          asset: nil,
          vulnerabilities: [],
          riskScore: 0,
          error: "Asset not found"
        })

      {:error, reason} ->
        render_inertia(conn, "AssetDetail", %{
          page_title: "Asset Details",
          assetId: id,
          asset: nil,
          vulnerabilities: [],
          riskScore: 0,
          error: "Failed to load asset: #{inspect(reason)}"
        })
    end
  end

  defp serialize_asset_vulnerability(vuln) do
    %{
      id: vuln[:id] || vuln.id,
      cveId: vuln[:cve_id] || vuln.cve_id,
      title: vuln[:title] || vuln.title,
      description: vuln[:description] || vuln.description,
      severity: vuln[:severity] || vuln.severity,
      cvssScore: vuln[:cvss_score] || vuln.cvss_score,
      status: vuln[:status] || vuln.status,
      discoveredAt: format_datetime(vuln[:discovered_at] || vuln.discovered_at),
      remediation: vuln[:remediation] || vuln.remediation,
      affectedComponent: vuln[:affected_component] || vuln.affected_component
    }
  end

  # Forensics
  def forensics(conn, _params) do
    # Scope collections to the caller's organization to prevent cross-tenant
    # exposure on the dashboard.
    current_user = conn.assigns[:current_user]
    org_id = current_user && current_user.organization_id

    all_collections =
      try do
        case ForensicsCollector.list_collections(%{organization_id: org_id}) do
          {:ok, list} -> list
          _ -> []
        end
      catch
        kind, reason ->
          Logger.warning(
            "ForensicsCollector.list_collections failed: \#{kind} \#{inspect(reason)}"
          )

          []
      end

    pending_collections =
      try do
        case ForensicsCollector.list_collections(%{organization_id: org_id, status: "pending"}) do
          {:ok, list} -> list
          _ -> []
        end
      catch
        kind, reason ->
          Logger.warning(
            "ForensicsCollector.list_collections(pending) failed: \#{kind} \#{inspect(reason)}"
          )

          []
      end

    # Serialize collections for frontend
    collections = Enum.map(all_collections, &serialize_forensic_collection/1)
    pending = Enum.map(pending_collections, &serialize_forensic_collection/1)

    # Calculate stats
    stats = %{
      totalCollections: length(all_collections),
      pendingCollections: length(pending_collections),
      completedCollections: Enum.count(all_collections, &(&1.status == "completed")),
      totalArtifacts:
        all_collections
        |> Enum.flat_map(&(&1.artifacts_collected || []))
        |> length()
    }

    render_inertia(conn, "Forensics", %{
      page_title: "Forensics Collections",
      collections: collections,
      pendingCollections: pending,
      stats: stats
    })
  end

  def forensics_detail(conn, %{"collection_id" => collection_id}) do
    collection_result =
      try do
        case ForensicsCollector.get_collection(collection_id) do
          {:ok, data} -> {:ok, data}
          {:error, reason} -> {:error, reason}
          other -> {:ok, other}
        end
      catch
        kind, reason ->
          Logger.warning("ForensicsCollector.get_collection failed: \#{kind} \#{inspect(reason)}")
          {:error, :service_unavailable}
      end

    case collection_result do
      {:ok, collection} ->
        # Get artifacts for this collection
        artifacts =
          Enum.map(collection.artifacts_collected || [], fn artifact ->
            artifact_id = artifact[:id] || artifact["id"]
            # Optionally fetch full artifact details
            artifact_result =
              try do
                case ForensicsCollector.get_artifact(collection_id, artifact_id) do
                  {:ok, full_artifact} -> serialize_forensic_artifact(full_artifact)
                  _ -> serialize_forensic_artifact(artifact)
                end
              catch
                kind, reason ->
                  Logger.warning(
                    "ForensicsCollector.get_artifact failed: \#{kind} \#{inspect(reason)}"
                  )

                  serialize_forensic_artifact(artifact)
              end

            artifact_result
          end)

        evidence_chain =
          Enum.map(collection.evidence_chain || [], fn entry ->
            %{
              action: entry.action,
              timestamp: format_datetime(entry.timestamp),
              user: entry.user,
              notes: entry.notes
            }
          end)

        render_inertia(conn, "ForensicsDetail", %{
          page_title: "Collection: #{collection.id}",
          collectionId: collection_id,
          collection: serialize_forensic_collection(collection),
          artifacts: artifacts,
          # Analysis results would come from ForensicsCollector.start_analysis results
          analysisResults: [],
          evidenceChain: evidence_chain
        })

      {:error, :not_found} ->
        render_inertia(conn, "ForensicsDetail", %{
          page_title: "Collection Not Found",
          collectionId: collection_id,
          collection: nil,
          artifacts: [],
          analysisResults: [],
          evidenceChain: [],
          error: "Forensic collection not found"
        })

      {:error, reason} ->
        render_inertia(conn, "ForensicsDetail", %{
          page_title: "Forensics Collection",
          collectionId: collection_id,
          collection: nil,
          artifacts: [],
          analysisResults: [],
          evidenceChain: [],
          error: "Failed to load collection: #{inspect(reason)}"
        })
    end
  end

  defp serialize_forensic_artifact(artifact) do
    %{
      id: artifact[:id] || artifact["id"],
      type: artifact[:type] || artifact["type"],
      name: artifact[:name] || artifact["name"],
      path: artifact[:path] || artifact["path"],
      size: artifact[:size] || artifact["size"],
      hash: artifact[:hash] || artifact["hash"],
      sha256: artifact[:sha256] || artifact["sha256"],
      md5: artifact[:md5] || artifact["md5"],
      collectedAt: format_datetime(artifact[:collected_at] || artifact["collected_at"]),
      metadata: artifact[:metadata] || artifact["metadata"] || %{}
    }
  end

  # Live Response Shell
  def live_response(conn, _params) do
    current_user = conn.assigns[:current_user]
    org_id = current_user && current_user.organization_id

    # Get list of agents for the agent picker (online shown as selectable, offline shown but disabled)
    agents =
      try do
        list_agents_for_dashboard(org_id)
        |> Enum.map(fn a ->
          %{
            id: a[:agent_id] || a[:id] || "",
            hostname: a[:hostname] || "Unknown",
            ip_address: a[:ip_address] || "",
            os_type: to_string(a[:os_type] || ""),
            agent_version: to_string(a[:agent_version] || ""),
            status: to_string(a[:status] || "unknown"),
            last_seen: format_datetime(a[:last_seen_at])
          }
        end)
      rescue
        e ->
          Logger.warning("Failed to get agents for live response: #{Exception.message(e)}")
          []
      end

    # Get recent shell sessions from the durable shell session table. The UI
    # expects the ShellSession shape, not audit-log metadata.
    recentSessions =
      try do
        list_recent_shell_sessions()
      rescue
        _ -> []
      end

    render_inertia(conn, "LiveResponse", %{
      page_title: "Live Response",
      agents: agents,
      recentSessions: recentSessions,
      builtinCommands: get_builtin_commands()
    })
  end

  def live_response_agent(conn, %{"agent_id" => agent_id}) do
    # Get the specific agent
    agent =
      try do
        case Agents.get_agent(agent_id) do
          {:ok, a} ->
            %{
              id: a.id,
              hostname: a.hostname || "Unknown",
              ip_address: a.ip_address || "",
              os_type: to_string(a.os_type || ""),
              agent_version: a.agent_version || "",
              status: to_string(a.status || "unknown"),
              last_seen: format_datetime(a.last_seen_at)
            }

          {:error, :not_found} ->
            nil

          nil ->
            nil
        end
      rescue
        e ->
          Logger.warning("Failed to get agent #{agent_id}: #{Exception.message(e)}")
          nil
      end

    if agent do
      render_inertia(conn, "LiveResponse", %{
        page_title: "Live Response - #{agent.hostname}",
        selectedAgent: agent,
        agentId: agent_id,
        # Just the selected agent
        agents: [agent],
        recentSessions: list_recent_shell_sessions(agent_id: agent_id),
        builtinCommands: get_builtin_commands()
      })
    else
      render_inertia(conn, "LiveResponse", %{
        page_title: "Live Response - Agent Not Found",
        selectedAgent: nil,
        agentId: agent_id,
        agents: [],
        recentSessions: [],
        builtinCommands: get_builtin_commands(),
        error: "Agent not found or offline"
      })
    end
  end

  defp list_recent_shell_sessions(opts \\ []) do
    TamanduaServer.ShellSessions.list_sessions(Keyword.put_new(opts, :limit, 10))
    |> Enum.map(fn session ->
      %{
        id: session.id,
        session_id: session.session_id,
        agent_id: session.agent_id,
        agent_hostname: session.agent_hostname || "Unknown",
        user_id: session.user_id,
        started_at: iso8601_or_nil(session.started_at),
        ended_at: iso8601_or_nil(session.ended_at),
        status: session.status |> to_string(),
        has_recording: shell_recording_available?(session)
      }
    end)
  rescue
    e ->
      Logger.warning("Failed to list recent shell sessions: #{Exception.message(e)}")
      []
  end

  defp iso8601_or_nil(nil), do: nil
  defp iso8601_or_nil(%DateTime{} = value), do: DateTime.to_iso8601(value)

  defp iso8601_or_nil(%NaiveDateTime{} = value),
    do: value |> DateTime.from_naive!("Etc/UTC") |> DateTime.to_iso8601()

  defp iso8601_or_nil(value), do: to_string(value)

  defp shell_recording_available?(%{session_id: session_id, has_recording: true}) do
    case TamanduaServer.ShellSessions.get_recording_path(session_id) do
      {:ok, path} -> File.exists?(path)
      _ -> false
    end
  rescue
    _ -> false
  end

  defp shell_recording_available?(_), do: false

  defp get_builtin_commands do
    [
      %{
        name: "ps",
        description: "List running processes",
        usage: "ps [options]",
        examples: ["ps", "ps -a", "ps --tree"]
      },
      %{
        name: "netstat",
        description: "List network connections",
        usage: "netstat [options]",
        examples: ["netstat", "netstat -l", "netstat --established"]
      },
      %{
        name: "ls",
        description: "List directory contents",
        usage: "ls <path>",
        examples: ["ls /tmp", "ls C:\\Windows\\Temp"]
      },
      %{
        name: "cat",
        description: "Display file contents",
        usage: "cat <path>",
        examples: ["cat /etc/passwd", "cat C:\\Windows\\System32\\config\\SAM"]
      },
      %{
        name: "hash",
        description: "Calculate file hash (MD5, SHA256)",
        usage: "hash <path>",
        examples: ["hash /bin/bash", "hash C:\\Windows\\System32\\cmd.exe"]
      },
      %{
        name: "reg",
        description: "Query Windows registry",
        usage: "reg query <key>",
        examples: ["reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"]
      },
      %{
        name: "memdump",
        description: "Dump process memory",
        usage: "memdump <pid>",
        examples: ["memdump 1234"]
      },
      %{
        name: "collect",
        description: "Collect forensic artifact",
        usage: "collect <path>",
        examples: [
          "collect /var/log/auth.log",
          "collect C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        ]
      },
      %{
        name: "yara",
        description: "Run YARA scan on file",
        usage: "yara <path>",
        examples: ["yara /tmp/suspicious.exe"]
      },
      %{
        name: "strings",
        description: "Extract strings from file or process memory",
        usage: "strings <path|pid>",
        examples: ["strings /tmp/malware.bin", "strings 1234"]
      }
    ]
  end

  # Behavioral Analytics
  def behavioral_analytics(conn, _params) do
    # Phase 3 tenant-scoping: prefer the assigns set by SetOrganizationContext,
    # fall back to current_user.organization_id, and finally render an honest
    # zero-state if neither is present (Inertia hydrators must be resilient and
    # never crash the page on missing org context).
    org_id =
      conn.assigns[:current_organization_id] ||
        (conn.assigns[:current_user] && conn.assigns[:current_user].organization_id)

    if is_nil(org_id) do
      render_inertia(conn, "BehavioralAnalytics", %{
        page_title: "Behavioral Analytics",
        entities: [],
        anomalies: [],
        baselines: %{
          updateInterval: "1 hour",
          lastUpdate: format_datetime(DateTime.utc_now()),
          profileCount: 0
        },
        stats: %{
          totalEntities: 0,
          highRiskEntities: 0,
          anomaliesDetected: 0,
          riskScoreThreshold: 75
        }
      })
    else
      # The Behavioral module uses a GenServer for state
      # We can get profiles through its API
      # Since there's no list_entities, we build entity list from agents
      agents = list_agents_for_dashboard(org_id)

      entities =
        Enum.map(agents, fn agent ->
          # Try to get risk score for each agent/user
          user_risk = safe_behavioral_risk_score(org_id, :user, agent.hostname)
          host_risk = safe_behavioral_risk_score(org_id, :host, agent.hostname)

          %{
            id: Map.get(agent, :id) || Map.get(agent, :agent_id),
            name: agent.hostname,
            type: "host",
            userRiskScore: user_risk,
            hostRiskScore: host_risk,
            lastSeen: format_datetime(Map.get(agent, :last_seen_at) || Map.get(agent, :updated_at))
          }
        end)

      # Get behavioral anomaly alerts from the Alerts system, org-scoped.
      # Behavioral anomalies create alerts when detected - filter by behavioral patterns.
      anomalies =
        safe_behavioral_alerts(org_id)
        |> Enum.filter(fn alert ->
          title = String.downcase(alert.title || "")

          String.contains?(title, ["behavioral", "anomaly", "unusual"]) or
            Enum.any?(alert.mitre_techniques || [], &String.starts_with?(&1, "T1078"))
        end)
        |> Enum.take(50)
        |> Enum.map(fn alert ->
          %{
            id: alert.id,
            type: detect_anomaly_type(alert),
            entityId: alert.agent_id,
            entityType: "host",
            description: alert.description,
            riskScore: severity_to_risk_score(alert.severity),
            deviationScore: 0.0,
            baselineValue: nil,
            observedValue: nil,
            mitreTechniques: alert.mitre_techniques || [],
            detectedAt: format_datetime(alert.inserted_at)
          }
        end)

      render_inertia(conn, "BehavioralAnalytics", %{
        page_title: "Behavioral Analytics",
        entities: entities,
        anomalies: anomalies,
        baselines: %{
          updateInterval: "1 hour",
          lastUpdate: format_datetime(DateTime.utc_now()),
          profileCount: length(agents)
        },
        stats: %{
          totalEntities: length(entities),
          highRiskEntities:
            Enum.count(entities, fn e -> (e.userRiskScore || 0) + (e.hostRiskScore || 0) > 50 end),
          anomaliesDetected: length(anomalies),
          riskScoreThreshold: 75
        }
      })
    end
  end

  defp safe_behavioral_risk_score(org_id, entity_type, entity_id) do
    try do
      case Detection.Behavioral.get_risk_score(org_id, entity_type, entity_id) do
        {:ok, score} when is_number(score) -> score
        _ -> 0
      end
    catch
      :exit, _ -> 0
    rescue
      _ -> 0
    end
  end

  defp safe_behavioral_alerts(org_id) do
    try do
      Alerts.list_alerts_for_org(org_id, limit: 75)
    catch
      :exit, _ -> []
    rescue
      _ -> []
    end
  end

  defp safe_threat_intel_alerts(nil), do: []

  defp safe_threat_intel_alerts(org_id) do
    try do
      Alerts.list_alerts_for_org(org_id, limit: 100)
    rescue
      e in [DBConnection.ConnectionError, Postgrex.Error] ->
        Logger.warning("ThreatIntel alert list failed: #{Exception.message(e)}")
        []

      e ->
        Logger.warning("ThreatIntel alert list failed: #{Exception.message(e)}")
        []
    catch
      :exit, reason ->
        Logger.warning("ThreatIntel alert list failed: exit #{inspect(reason)}")
        []
    end
  end

  defp detect_anomaly_type(alert) do
    title = String.downcase(alert.title || "")

    cond do
      String.contains?(title, "login") -> "unusual_login_time"
      String.contains?(title, "process") -> "unusual_process_for_user"
      String.contains?(title, "network") -> "unusual_network_port"
      String.contains?(title, "parent") -> "unusual_parent_process"
      String.contains?(title, "encoded") -> "encoded_command"
      String.contains?(title, "transfer") -> "large_data_transfer"
      true -> "behavioral_anomaly"
    end
  end

  defp severity_to_risk_score(severity) do
    case severity do
      "critical" -> 95
      "high" -> 80
      "medium" -> 50
      "low" -> 25
      _ -> 10
    end
  end

  # Cloud Workloads
  def cloud_workloads(conn, _params) do
    # Get cloud-related assets from AssetManager
    all_assets =
      try do
        case AssetManager.list_assets(%{}) do
          {:ok, assets} -> assets
          _ -> []
        end
      catch
        kind, reason ->
          Logger.warning("AssetManager.list_assets(cloud) failed: #{kind} #{inspect(reason)}")
          []
      end

    # Filter to cloud workloads (assets with cloud provider set)
    cloud_assets =
      Enum.filter(all_assets, fn asset ->
        asset.cloud_provider != nil and asset.cloud_provider != ""
      end)

    # Build workloads list from cloud assets
    workloads =
      Enum.map(cloud_assets, fn asset ->
        %{
          id: asset.id,
          name: asset.hostname,
          type: determine_workload_type(asset),
          provider: asset.cloud_provider,
          region: asset.cloud_region,
          status: if(asset.agent_id, do: "monitored", else: "discovered"),
          agentId: asset.agent_id,
          tags: asset.cloud_tags || asset.tags || %{},
          securityScore: 100 - (asset.risk_score || 0),
          lastScanned: format_datetime(asset.last_seen)
        }
      end)

    # Group by type for containers
    containers =
      workloads
      |> Enum.filter(fn w -> w.type == "container" end)
      |> Enum.map(fn w ->
        %{
          id: w.id,
          name: w.name,
          image: w.tags["image"] || "unknown",
          runtime: w.tags["runtime"] || "docker",
          status: "running",
          hostAgentId: w.agentId,
          security: %{
            privileged: false,
            readOnlyRootfs: true
          }
        }
      end)

    # Build kubernetes info
    kubernetes = %{
      clusters:
        Enum.filter(workloads, fn w -> w.type == "kubernetes" end)
        |> Enum.map(fn w -> %{id: w.id, name: w.name, provider: w.provider, region: w.region} end),
      pods: []
    }

    # Calculate security posture
    security_posture = %{
      overallScore:
        if length(workloads) > 0 do
          (Enum.reduce(workloads, 0, fn w, acc -> acc + (w.securityScore || 0) end) /
             length(workloads))
          |> Float.round(1)
        else
          0
        end,
      byProvider:
        workloads
        |> Enum.group_by(& &1.provider)
        |> Enum.map(fn {provider, ws} ->
          {provider,
           %{
             count: length(ws),
             avgScore:
               Enum.reduce(ws, 0, fn w, acc -> acc + (w.securityScore || 0) end) / length(ws)
           }}
        end)
        |> Enum.into(%{})
    }

    render_inertia(conn, "CloudWorkloads", %{
      page_title: "Cloud Workloads",
      workloads: workloads,
      containers: containers,
      kubernetes: kubernetes,
      securityPosture: security_posture,
      stats: %{
        totalWorkloads: length(workloads),
        byProvider:
          workloads
          |> Enum.group_by(& &1.provider)
          |> Enum.map(fn {k, v} -> {k, length(v)} end)
          |> Enum.into(%{}),
        byType:
          workloads
          |> Enum.group_by(& &1.type)
          |> Enum.map(fn {k, v} -> {k, length(v)} end)
          |> Enum.into(%{}),
        monitored: Enum.count(workloads, fn w -> w.status == "monitored" end)
      }
    })
  end

  defp determine_workload_type(asset) do
    cond do
      asset.is_virtual == true and String.contains?(asset.hostname || "", "k8s") ->
        "kubernetes"

      asset.is_virtual == true and String.contains?(asset.hostname || "", "container") ->
        "container"

      asset.cloud_instance_type != nil and
          String.contains?(asset.cloud_instance_type || "", "lambda") ->
        "serverless"

      asset.is_virtual == true ->
        "vm"

      true ->
        "compute"
    end
  end

  # Cloud Security (CSPM)
  def cloud_security(conn, _params) do
    alias TamanduaServer.Cloud.{CloudAccount, Finding, PolicyEngine}

    # Initialize policy engine if not already done
    PolicyEngine.init()

    # Fetch accounts
    accounts =
      try do
        CloudAccount.list(%{})
        |> Enum.map(fn account ->
          %{
            id: account.id,
            name: account.name,
            provider: account.provider,
            account_id: account.account_id,
            alias: account.alias,
            status: account.status,
            connection_status: account.connection_status,
            compliance_score: account.compliance_score || 100.0,
            findings_count: account.findings_count || 0,
            critical_findings_count: account.critical_findings_count || 0,
            resources_count: account.resources_count || 0,
            last_scan_at: format_datetime(account.last_scan_at)
          }
        end)
      rescue
        _ -> []
      end

    # Fetch recent critical findings
    findings =
      try do
        Finding.list_findings(%{
          severity: ["critical", "high"],
          status: "open",
          limit: 20
        })
        |> Enum.map(fn f ->
          %{
            id: f.id,
            provider: f.provider,
            account_id: f.account_id,
            resource_id: f.resource_id,
            resource_name: f.resource_name,
            resource_type: f.resource_type,
            region: f.region,
            category: f.category,
            severity: f.severity,
            title: f.title,
            description: f.description,
            recommendation: f.recommendation,
            compliance: f.compliance || [],
            status: f.status,
            first_seen_at: format_datetime(f.first_seen_at),
            last_seen_at: format_datetime(f.last_seen_at)
          }
        end)
      rescue
        _ -> []
      end

    # Fetch policies
    policies =
      try do
        PolicyEngine.list_policies(%{})
        |> Enum.take(50)
        |> Enum.map(fn p ->
          %{
            id: p.id,
            name: p.name,
            description: p.description,
            provider: p.provider,
            resource_type: p.resource_type,
            severity: p.severity,
            category: p.category,
            enabled: p.enabled,
            compliance: p.compliance || [],
            source: p.source
          }
        end)
      rescue
        _ -> []
      end

    # Calculate stats
    stats =
      try do
        global_finding_stats = Finding.global_statistics()
        policy_stats = PolicyEngine.statistics()

        total_resources =
          Enum.reduce(accounts, 0, fn a, acc -> acc + (a.resources_count || 0) end)

        total_findings = Enum.reduce(accounts, 0, fn a, acc -> acc + (a.findings_count || 0) end)

        critical_findings =
          Enum.reduce(accounts, 0, fn a, acc -> acc + (a.critical_findings_count || 0) end)

        avg_compliance =
          if length(accounts) > 0 do
            (Enum.reduce(accounts, 0, fn a, acc -> acc + (a.compliance_score || 100) end) /
               length(accounts))
            |> Float.round(1)
          else
            100.0
          end

        %{
          total_accounts: length(accounts),
          connected_accounts:
            Enum.count(accounts, fn a -> a.connection_status == "connected" end),
          total_resources: total_resources,
          total_findings: total_findings,
          open_findings: global_finding_stats[:open_findings] || total_findings,
          critical_findings: critical_findings,
          high_findings: global_finding_stats[:high_findings] || 0,
          average_compliance_score: avg_compliance
        }
      rescue
        _ ->
          %{
            total_accounts: length(accounts),
            connected_accounts:
              Enum.count(accounts, fn a -> a.connection_status == "connected" end),
            total_resources: 0,
            total_findings: 0,
            open_findings: 0,
            critical_findings: 0,
            high_findings: 0,
            average_compliance_score: 100.0
          }
      end

    render_inertia(conn, "CloudSecurity", %{
      page_title: "Cloud Security (CSPM)",
      accounts: accounts,
      findings: findings,
      policies: policies,
      stats: stats
    })
  end

  # Serverless Security
  def serverless(conn, _params) do
    alias TamanduaServer.Serverless.{Lambda, AzureFunctions, CloudFunctions}
    alias TamanduaServer.Serverless.{SecurityAnalyzer, BehavioralBaseline}

    # Get functions from all providers
    aws_functions =
      try do
        Lambda.list_functions(%{})
        |> Enum.map(fn f ->
          f
          |> Map.from_struct()
          |> Map.put(:provider, "aws")
          |> serialize_serverless_function()
        end)
      rescue
        _ -> []
      end

    azure_functions =
      try do
        AzureFunctions.list_functions(%{})
        |> Enum.map(fn f ->
          f
          |> Map.from_struct()
          |> Map.put(:provider, "azure")
          |> serialize_serverless_function()
        end)
      rescue
        _ -> []
      end

    gcp_functions =
      try do
        CloudFunctions.list_functions(%{})
        |> Enum.map(fn f ->
          f
          |> Map.from_struct()
          |> Map.put(:provider, "gcp")
          |> serialize_serverless_function()
        end)
      rescue
        _ -> []
      end

    functions = aws_functions ++ azure_functions ++ gcp_functions

    # Get security statistics
    security_stats =
      try do
        SecurityAnalyzer.get_statistics()
      rescue
        _ -> %{}
      end

    # Get baseline statistics
    baseline_stats =
      try do
        BehavioralBaseline.get_statistics()
      rescue
        _ -> %{}
      end

    # Get recent findings (critical/high severity)
    findings =
      try do
        (SecurityAnalyzer.get_findings_by_severity(:critical) ++
           SecurityAnalyzer.get_findings_by_severity(:high))
        |> Enum.take(50)
        |> Enum.map(&serialize_serverless_finding/1)
      rescue
        _ -> []
      end

    # Get recent anomalies
    anomalies =
      try do
        BehavioralBaseline.get_recent_anomalies(50)
        |> Enum.map(&serialize_serverless_anomaly/1)
      rescue
        _ -> []
      end

    # Build stats
    stats = %{
      summary: %{
        total_functions: length(functions),
        total_invocations_24h:
          Enum.reduce(functions, 0, fn f, acc -> acc + (f[:invocation_count_24h] || 0) end),
        total_errors_24h:
          Enum.reduce(functions, 0, fn f, acc -> acc + (f[:error_count_24h] || 0) end),
        average_security_score:
          if(length(functions) > 0,
            do:
              round(
                Enum.reduce(functions, 0, fn f, acc -> acc + (f[:security_score] || 100) end) /
                  length(functions)
              ),
            else: 100
          ),
        open_findings: security_stats[:open_findings] || length(findings),
        critical_findings:
          security_stats[:critical_findings] ||
            Enum.count(findings, fn f -> f[:severity] == :critical end),
        anomalies_24h: baseline_stats[:total_anomalies_24h] || length(anomalies)
      },
      by_provider: %{
        aws: %{total_functions: length(aws_functions)},
        azure: %{total_functions: length(azure_functions)},
        gcp: %{total_functions: length(gcp_functions)}
      },
      security: security_stats,
      baselines: baseline_stats
    }

    render_inertia(conn, "Serverless", %{
      page_title: "Serverless Security",
      functions: functions,
      findings: findings,
      anomalies: anomalies,
      stats: stats
    })
  end

  defp serialize_serverless_function(func) do
    %{
      id: func[:function_id] || func[:function_arn] || func[:id] || func[:name],
      name: func[:function_name] || func[:name],
      provider: func[:provider],
      runtime: func[:runtime] || func[:runtime_version],
      region: func[:region],
      status: func[:status] || func[:state] || "unknown",
      memory_size: func[:memory_size] || func[:available_memory_mb],
      timeout: func[:timeout],
      security_score: func[:security_score] || 100,
      findings_count: length(func[:findings] || []),
      invocation_count_24h: func[:invocation_count_24h] || 0,
      error_count_24h: func[:error_count_24h] || 0,
      last_invoked: format_datetime(func[:last_invoked] || func[:last_execution])
    }
  end

  defp serialize_serverless_finding(finding) when is_struct(finding) do
    serialize_serverless_finding(Map.from_struct(finding))
  end

  defp serialize_serverless_finding(finding) when is_map(finding) do
    %{
      id: finding[:id],
      function_id: finding[:function_id],
      provider: finding[:provider],
      category: finding[:category],
      severity: finding[:severity],
      title: finding[:title],
      description: finding[:description],
      evidence: finding[:evidence],
      remediation: finding[:remediation],
      status: finding[:status],
      detected_at: format_datetime(finding[:detected_at])
    }
  end

  defp serialize_serverless_anomaly(anomaly) when is_struct(anomaly) do
    serialize_serverless_anomaly(Map.from_struct(anomaly))
  end

  defp serialize_serverless_anomaly(anomaly) when is_map(anomaly) do
    %{
      id: anomaly[:id],
      function_id: anomaly[:function_id],
      provider: anomaly[:provider],
      anomaly_type: anomaly[:anomaly_type],
      severity: anomaly[:severity],
      description: anomaly[:description],
      z_score: anomaly[:z_score] || 0.0,
      confidence: anomaly[:confidence] || 0.0,
      detected_at: format_datetime(anomaly[:detected_at]),
      acknowledged: anomaly[:acknowledged] || false
    }
  end

  # Threat Intelligence
  def threat_intel(conn, _params) do
    org_id =
      conn.assigns[:current_organization_id] ||
        (conn.assigns[:current_user] && conn.assigns[:current_user].organization_id)

    # Get IOCs from ThreatIntel module
    iocs =
      try do
        ThreatIntel.list_active_iocs(limit: 75)
      catch
        kind, reason ->
          Logger.warning("ThreatIntel.list_active_iocs failed: #{kind} #{inspect(reason)}")
          []
      end

    # Get feed status
    feeds =
      try do
        ThreatIntel.get_feed_status()
        |> Enum.map(fn feed ->
          %{
            id: feed.name,
            name: feed.name,
            enabled: feed.enabled,
            status: feed.status,
            lastUpdate: format_datetime(feed.last_update),
            iocCount: feed.ioc_count
          }
        end)
      catch
        kind, reason ->
          Logger.warning("ThreatIntel.get_feed_status failed: #{kind} #{inspect(reason)}")
          []
      end

    # Get stats
    stats =
      try do
        ThreatIntel.get_stats()
      catch
        kind, reason ->
          Logger.warning("ThreatIntel.get_stats failed: #{kind} #{inspect(reason)}")
          %{total_iocs: 0, by_type: %{}, by_source: %{}, last_update: nil, feeds_active: 0}
      end

    # Serialize IOCs for frontend
    indicators =
      Enum.map(iocs, fn ioc ->
        %{
          id: "#{ioc.type}_#{ioc.value}",
          type: ioc.type,
          value: ioc.value,
          source: ioc.source,
          severity: ioc.severity,
          description: ioc.description,
          tags: ioc.tags || [],
          createdAt: format_datetime(ioc.inserted_at),
          expiresAt: format_datetime(ioc.expires_at)
        }
      end)

    recent_alerts = safe_threat_intel_alerts(org_id)

    # Get recent IOC matches from bounded, org-scoped alerts that have threat intel matches
    recent_matches =
      recent_alerts
      |> Enum.filter(fn alert ->
        title = String.downcase(alert.title || "")
        description = String.downcase(alert.description || "")

        String.contains?(title, ["ioc", "indicator", "threat intel", "malicious"]) or
          String.contains?(description, ["matched", "known malicious", "threat intelligence"])
      end)
      |> Enum.take(20)
      |> Enum.map(fn alert ->
        %{
          id: alert.id,
          iocType: extract_ioc_type_from_alert(alert),
          iocValue: extract_ioc_value_from_alert(alert),
          source: "detection_engine",
          agentId: alert.agent_id,
          severity: alert.severity,
          matchedAt: format_datetime(alert.inserted_at),
          context: alert.description
        }
      end)

    # Derive threat actors from IOC tags and sources
    actors =
      iocs
      |> Enum.flat_map(fn ioc ->
        tags = ioc.tags || []
        # Extract actor names from tags (tags like "APT28", "Lazarus", etc.)
        actor_tags =
          Enum.filter(tags, fn tag ->
            String.match?(tag, ~r/^(APT|FIN|UNC|TA)\d+$/i) or
              String.downcase(tag) in ~w(lazarus cozy_bear fancy_bear equation_group turla hafnium)
          end)

        Enum.map(actor_tags, fn tag -> {String.upcase(tag), ioc} end)
      end)
      |> Enum.group_by(fn {actor, _} -> actor end, fn {_, ioc} -> ioc end)
      |> Enum.map(fn {name, actor_iocs} ->
        %{
          id: "actor_#{String.downcase(name)}",
          name: name,
          iocCount: length(actor_iocs),
          lastSeen:
            actor_iocs
            |> Enum.map(& &1.inserted_at)
            |> Enum.max(DateTime, fn -> nil end)
            |> format_datetime(),
          severity:
            actor_iocs
            |> Enum.map(& &1.severity)
            |> Enum.min_by(
              fn s ->
                case s do
                  "critical" -> 0
                  "high" -> 1
                  "medium" -> 2
                  "low" -> 3
                  _ -> 4
                end
              end,
              fn -> "medium" end
            ),
          iocTypes: actor_iocs |> Enum.map(& &1.type) |> Enum.uniq(),
          sources: actor_iocs |> Enum.map(& &1.source) |> Enum.uniq()
        }
      end)

    # Derive campaigns from alert clusters with MITRE techniques
    campaigns =
      try do
        recent_alerts
        |> Enum.filter(fn a -> length(a.mitre_techniques || []) >= 2 end)
        |> Enum.group_by(fn a ->
          techniques = Enum.sort(a.mitre_techniques || [])
          # Group by overlapping technique sets
          Enum.take(techniques, 3) |> Enum.join(",")
        end)
        |> Enum.filter(fn {_key, alerts} -> length(alerts) >= 2 end)
        |> Enum.with_index()
        |> Enum.map(fn {{_key, campaign_alerts}, idx} ->
          %{
            id: "campaign_#{idx + 1}",
            name: "Campaign #{idx + 1}: #{hd(campaign_alerts).title |> String.slice(0..40)}",
            alertCount: length(campaign_alerts),
            mitreTechniques:
              campaign_alerts |> Enum.flat_map(&(&1.mitre_techniques || [])) |> Enum.uniq(),
            severity:
              campaign_alerts
              |> Enum.map(& &1.severity)
              |> Enum.min_by(
                fn s ->
                  case s do
                    "critical" -> 0
                    "high" -> 1
                    "medium" -> 2
                    "low" -> 3
                    _ -> 4
                  end
                end,
                fn -> "medium" end
              ),
            firstSeen:
              campaign_alerts
              |> Enum.map(& &1.inserted_at)
              |> Enum.min(DateTime, fn -> nil end)
              |> format_datetime(),
            lastSeen:
              campaign_alerts
              |> Enum.map(& &1.inserted_at)
              |> Enum.max(DateTime, fn -> nil end)
              |> format_datetime(),
            agents:
              campaign_alerts |> Enum.map(& &1.agent_id) |> Enum.uniq() |> Enum.reject(&is_nil/1)
          }
        end)
      rescue
        e ->
          Logger.warning("Failed to build threat intel campaigns: #{Exception.message(e)}")
          []
      end

    render_inertia(conn, "ThreatIntel", %{
      page_title: "Threat Intelligence",
      feeds: feeds,
      indicators: indicators,
      recentMatches: recent_matches,
      actors: actors,
      campaigns: campaigns,
      stats: %{
        totalIOCs: stats.total_iocs,
        byType: stats.by_type,
        bySource: stats.by_source,
        lastUpdate: format_datetime(stats.last_update),
        feedsActive: stats.feeds_active
      }
    })
  end

  defp extract_ioc_type_from_alert(alert) do
    title = String.downcase(alert.title || "")

    cond do
      String.contains?(title, ["ip", "address"]) -> "ip"
      String.contains?(title, ["domain", "dns"]) -> "domain"
      String.contains?(title, ["hash", "sha256", "md5"]) -> "hash"
      String.contains?(title, ["url"]) -> "url"
      String.contains?(title, ["email"]) -> "email"
      true -> "unknown"
    end
  end

  defp extract_ioc_value_from_alert(alert) do
    description = alert.description || ""

    # IPv4 with proper octet validation (0-255)
    ipv4_regex =
      ~r/\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b/

    # Hash patterns with exact length matching
    sha256_regex = ~r/\b[a-fA-F0-9]{64}\b/
    sha1_regex = ~r/\b[a-fA-F0-9]{40}\b/
    md5_regex = ~r/\b[a-fA-F0-9]{32}\b/

    cond do
      Regex.match?(ipv4_regex, description) ->
        [match | _] = Regex.run(ipv4_regex, description)
        match

      Regex.match?(sha256_regex, description) ->
        [match | _] = Regex.run(sha256_regex, description)
        match

      Regex.match?(sha1_regex, description) ->
        [match | _] = Regex.run(sha1_regex, description)
        match

      Regex.match?(md5_regex, description) ->
        [match | _] = Regex.run(md5_regex, description)
        match

      true ->
        "N/A"
    end
  end

  # AI Security Features
  def ai_attack_surface(conn, _params) do
    # Call AttackSurface.analyze/1 to get comprehensive analysis
    analysis =
      try do
        case AttackSurface.analyze(%{}) do
          {:ok, result} -> result
          _ -> %{}
        end
      catch
        :exit, reason ->
          Logger.warning("AttackSurface.analyze failed: exit #{inspect(reason)}")
          %{}

        kind, reason ->
          Logger.warning("AttackSurface.analyze failed: #{kind} #{inspect(reason)}")
          %{}
      end

    # Build assets list from agent activity
    agent_activity = analysis[:agent_activity] || %{}
    assets = build_ai_assets(agent_activity)

    # Build attack vectors from injection threats
    injection_threats = analysis[:injection_threats] || %{}
    attack_vectors = build_attack_vectors(injection_threats)

    # Build assessments list
    assessments_data = analysis[:assessments] || []
    assessments = build_vulnerability_assessments(analysis)

    # Flag if we're showing example data
    is_example_data =
      Enum.empty?(agent_activity) and Enum.empty?(injection_threats) and
        Enum.empty?(assessments_data)

    attack_surface = %{
      assets: assets,
      attackVectors: attack_vectors,
      assessments: assessments,
      isExampleData: is_example_data
    }

    recommendations = build_recommendations(analysis[:recommendations] || [])

    render_inertia(conn, "AIAttackSurface", %{
      page_title: "AI Attack Surface",
      attackSurface: attack_surface,
      recommendations: recommendations
    })
  end

  defp build_ai_assets(agent_activity) when is_map(agent_activity) do
    # Convert agent activity to AI assets format
    assets_from_activity =
      Enum.map(agent_activity, fn {id, activity} ->
        %{
          id: to_string(id),
          name: activity[:name] || "AI Asset #{id}",
          type: activity[:type] || "llm",
          status: calculate_asset_status(activity),
          riskScore: activity[:risk_score] || 0,
          owner: activity[:owner] || "Security Team",
          department: activity[:department] || "Engineering",
          lastAssessed: format_datetime(activity[:last_assessed] || DateTime.utc_now()),
          vulnerabilities: activity[:vulnerabilities] || 0
        }
      end)

    # Return real assets, or demo data if DEMO_MODE enabled, or empty list
    if Enum.empty?(assets_from_activity) do
      if Application.get_env(:tamandua_server, :demo_mode, false) do
        [
          %{
            id: "llm-gpt-prod",
            name: "Production LLM Gateway",
            type: "llm",
            status: "healthy",
            riskScore: 35,
            owner: "ML Team",
            department: "Engineering",
            lastAssessed: format_datetime(DateTime.utc_now()),
            vulnerabilities: 2,
            _demo: true
          },
          %{
            id: "vector-db-main",
            name: "Vector Database Cluster",
            type: "vector_db",
            status: "at_risk",
            riskScore: 65,
            owner: "Data Team",
            department: "Data Science",
            lastAssessed: format_datetime(DateTime.add(DateTime.utc_now(), -86400, :second)),
            vulnerabilities: 5,
            _demo: true
          },
          %{
            id: "agent-customer-support",
            name: "Customer Support Agent",
            type: "ai_agent",
            status: "healthy",
            riskScore: 42,
            owner: "Support Team",
            department: "Customer Success",
            lastAssessed: format_datetime(DateTime.add(DateTime.utc_now(), -172_800, :second)),
            vulnerabilities: 1,
            _demo: true
          }
        ]
      else
        # Return empty - no AI assets detected
        []
      end
    else
      assets_from_activity
    end
  end

  defp build_ai_assets(_), do: build_ai_assets(%{})

  defp calculate_asset_status(activity) do
    risk = activity[:risk_score] || 0

    cond do
      risk > 70 -> "compromised"
      risk > 40 -> "at_risk"
      true -> "healthy"
    end
  end

  defp build_attack_vectors(injection_threats) when is_map(injection_threats) do
    vectors_from_threats =
      Enum.map(injection_threats, fn {id, threat} ->
        %{
          id: to_string(id),
          name: threat[:name] || "Attack Vector #{id}",
          category: threat[:category] || "prompt_injection",
          severity: threat[:severity] || "medium",
          affectedAssets: threat[:affected_assets] || 1,
          mitigationStatus: threat[:mitigation_status] || "partial",
          description: threat[:description] || "Potential security vulnerability detected"
        }
      end)

    if Enum.empty?(vectors_from_threats) do
      if Application.get_env(:tamandua_server, :demo_mode, false) do
        [
          %{
            id: "vec-1",
            name: "Prompt Injection Attack",
            category: "prompt_injection",
            severity: "high",
            affectedAssets: 3,
            mitigationStatus: "partial",
            description: "Malicious prompts attempting to bypass system instructions",
            _demo: true
          },
          %{
            id: "vec-2",
            name: "Model Exfiltration Attempt",
            category: "model_theft",
            severity: "critical",
            affectedAssets: 1,
            mitigationStatus: "mitigated",
            description: "Attempts to extract model weights or architecture",
            _demo: true
          },
          %{
            id: "vec-3",
            name: "Jailbreak Patterns",
            category: "jailbreak",
            severity: "medium",
            affectedAssets: 2,
            mitigationStatus: "unmitigated",
            description: "Techniques to bypass safety guardrails",
            _demo: true
          }
        ]
      else
        # Return empty - no attack vectors detected
        []
      end
    else
      vectors_from_threats
    end
  end

  defp build_attack_vectors(_), do: build_attack_vectors(%{})

  defp build_vulnerability_assessments(analysis) do
    assessments_data = analysis[:assessments] || []

    if Enum.empty?(assessments_data) do
      if Application.get_env(:tamandua_server, :demo_mode, false) do
        [
          %{
            id: "assess-1",
            assetName: "Production LLM Gateway",
            assessmentDate: format_datetime(DateTime.add(DateTime.utc_now(), -86400, :second)),
            status: "completed",
            findings: 8,
            criticalFindings: 1,
            _demo: true
          },
          %{
            id: "assess-2",
            assetName: "Vector Database Cluster",
            assessmentDate: format_datetime(DateTime.utc_now()),
            status: "in_progress",
            findings: 3,
            criticalFindings: 0,
            _demo: true
          },
          %{
            id: "assess-3",
            assetName: "Customer Support Agent",
            assessmentDate: format_datetime(DateTime.add(DateTime.utc_now(), 86400, :second)),
            status: "scheduled",
            findings: 0,
            criticalFindings: 0,
            _demo: true
          }
        ]
      else
        # Return empty - no assessments available
        []
      end
    else
      Enum.map(assessments_data, fn a ->
        %{
          id: a[:id] || UUID.uuid4(),
          assetName: a[:asset_name] || "Unknown Asset",
          assessmentDate: format_datetime(a[:assessment_date] || DateTime.utc_now()),
          status: a[:status] || "scheduled",
          findings: a[:findings] || 0,
          criticalFindings: a[:critical_findings] || 0
        }
      end)
    end
  end

  defp build_recommendations(recommendations) when is_list(recommendations) do
    if Enum.empty?(recommendations) do
      if Application.get_env(:tamandua_server, :demo_mode, false) do
        [
          %{
            id: "rec-1",
            title: "Implement Input Validation",
            description:
              "Add robust input validation for all LLM prompts to prevent injection attacks",
            priority: "high",
            _demo: true
          },
          %{
            id: "rec-2",
            title: "Enable Model Access Logging",
            description: "Implement comprehensive logging for all model inference requests",
            priority: "medium",
            _demo: true
          }
        ]
      else
        # Return empty - no recommendations available
        []
      end
    else
      Enum.map(recommendations, fn r ->
        %{
          id: r[:id] || UUID.uuid4(),
          title: r[:title] || "Recommendation",
          description: r[:description] || "",
          priority: r[:priority] || "medium"
        }
      end)
    end
  end

  defp build_recommendations(_), do: build_recommendations([])

  def shadow_ai(conn, _params) do
    # Get shadow AI detections from AttackSurface module
    shadow_ai_detections =
      try do
        case AttackSurface.get_shadow_ai_detections(limit: 100) do
          list when is_list(list) -> list
          _ -> []
        end
      catch
        kind, reason ->
          Logger.warning(
            "AttackSurface.get_shadow_ai_detections failed: #{kind} #{inspect(reason)}"
          )

          []
      end

    inventory_components =
      try do
        case AIInventory.list_inventory(limit: 250) do
          {:ok, list} when is_list(list) -> list
          _ -> []
        end
      catch
        kind, reason ->
          Logger.warning("AIInventory.list_inventory failed: #{kind} #{inspect(reason)}")
          []
      end

    ai_usage_events =
      try do
        case AttackSurface.get_recent_events(limit: 250) do
          list when is_list(list) -> list
          _ -> []
        end
      catch
        kind, reason ->
          Logger.warning("AttackSurface.get_recent_events failed: #{kind} #{inspect(reason)}")
          []
      end

    gateway_usage_events =
      try do
        case AIGateway.list_usage(limit: 250) do
          {:ok, list} when is_list(list) -> list
          _ -> []
        end
      catch
        kind, reason ->
          Logger.warning("AIGateway.list_usage failed: #{kind} #{inspect(reason)}")
          []
      end

    gateway_health =
      try do
        AIGateway.health()
      catch
        kind, reason ->
          Logger.warning("AIGateway.health failed: #{kind} #{inspect(reason)}")
          %{status: "unsupported", event_count: 0, last_seen: nil}
      end

    gateway_policy =
      try do
        AIGateway.get_policy()
      catch
        kind, reason ->
          Logger.warning("AIGateway.get_policy failed: #{kind} #{inspect(reason)}")
          %{}
      end

    # Map detections to frontend format - discoveredServices array
    shadow_services =
      Enum.map(shadow_ai_detections, fn detection ->
        %{
          id: detection[:id] || detection[:timestamp] || UUID.uuid4(),
          name: detection[:name] || detection[:domain] || "Unknown AI Service",
          domain: detection[:domain],
          category: detection[:category] || "generative_ai",
          riskLevel: detection[:risk_level] || "medium",
          agentId: detection[:agent_id],
          processInfo: detection[:process_info],
          firstSeen: format_datetime(detection[:first_seen] || detection[:detected_at]),
          lastSeen: format_datetime(detection[:last_seen] || detection[:detected_at]),
          requestCount: detection[:request_count] || 1,
          dataVolume: detection[:data_volume] || 0
        }
      end)

    inventory_services =
      Enum.map(inventory_components, fn component ->
        %{
          id: component[:id],
          name: component[:name] || "Unknown AI component",
          domain: nil,
          category: component[:component_type] || "ai_component",
          riskLevel: component[:risk_level] || "medium",
          agentId: component[:agent_id],
          processInfo: %{
            pid: component[:process_id],
            path: component[:install_path]
          },
          firstSeen: format_datetime(component[:discovered_at]),
          lastSeen: format_datetime(component[:last_seen_at]),
          requestCount: 0,
          dataVolume: 0,
          source: "ai_discovery",
          policyStatus: component[:policy_status] |> to_string()
        }
      end)

    usage_services =
      ai_usage_events
      |> Enum.group_by(fn event -> {event[:agent_id], event[:domain] || event[:remote_domain]} end)
      |> Enum.map(fn {{agent_id, domain}, events} ->
        latest =
          Enum.reduce(events, %{}, fn event, acc ->
            if (event[:timestamp] || 0) > (acc[:timestamp] || 0), do: event, else: acc
          end)

        total_bytes =
          Enum.reduce(events, 0, fn event, acc ->
            acc + (event[:bytes_sent] || 0) + (event[:bytes_received] || 0)
          end)

        %{
          id: "usage_#{agent_id}_#{domain}",
          name: domain || "Unknown AI service",
          domain: domain,
          category: "ai_usage",
          riskLevel: if(total_bytes > 1_000_000, do: "medium", else: "low"),
          agentId: agent_id,
          processInfo: latest[:process_info],
          firstSeen: nil,
          lastSeen: format_datetime_from_unix_ms(latest[:timestamp]),
          requestCount: length(events),
          dataVolume: total_bytes,
          source: "dns_network_usage",
          policyStatus: "unknown"
        }
      end)

    gateway_services =
      gateway_usage_events
      |> Enum.group_by(fn event ->
        {event[:user_id] || event[:agent_id] || event[:tenant_id],
         event[:provider] || event[:domain]}
      end)
      |> Enum.map(fn {{entity_id, provider}, events} ->
        latest =
          Enum.reduce(events, %{}, fn event, acc ->
            if (event[:timestamp_ms] || 0) > (acc[:timestamp_ms] || 0), do: event, else: acc
          end)

        %{
          id: "gateway_#{entity_id}_#{provider}",
          name: provider || latest[:domain] || "Unknown AI gateway service",
          domain: latest[:domain],
          category: "ai_gateway",
          riskLevel: latest[:risk_level] || "low",
          agentId: latest[:agent_id],
          processInfo: %{
            name: latest[:process_name],
            path: latest[:process_path],
            pid: latest[:pid]
          },
          firstSeen: nil,
          lastSeen: latest[:observed_at],
          requestCount:
            Enum.reduce(events, 0, fn event, acc -> acc + (event[:request_count] || 1) end),
          dataVolume:
            Enum.reduce(events, 0, fn event, acc ->
              acc + (event[:bytes_sent] || 0) + (event[:bytes_received] || 0)
            end),
          source: "ai_gateway",
          policyStatus: latest[:policy_decision] || "monitor"
        }
      end)

    discovered_services =
      (shadow_services ++ usage_services ++ gateway_services ++ inventory_services)
      |> Enum.uniq_by(fn service ->
        "#{service[:agentId]}:#{service[:domain] || service[:name]}:#{service[:source] || "shadow"}"
      end)

    # Frontend expects unapprovedModels as array of UnapprovedModel objects (not just strings)
    unapproved_models =
      shadow_ai_detections
      |> Enum.filter(fn d -> d[:domain] != nil end)
      |> Enum.group_by(fn d -> d[:domain] end)
      |> Enum.map(fn {domain, detections} ->
        %{
          id: domain,
          name: domain,
          vendor: infer_vendor_from_domain(domain),
          type: "llm",
          riskScore: Enum.reduce(detections, 0, fn d, acc -> max(acc, d[:risk_score] || 50) end),
          usageCount: length(detections),
          lastUsed:
            format_datetime(
              Enum.max_by(detections, fn d -> d[:detected_at] || DateTime.utc_now() end)[
                :detected_at
              ]
            ),
          status: "unapproved"
        }
      end)

    # Get attack surface analysis for data flow risks
    analysis =
      try do
        case AttackSurface.analyze(%{include_data_flows: true}) do
          {:ok, result} -> result
          _ -> %{}
        end
      catch
        kind, reason ->
          Logger.warning("AttackSurface.analyze(data_flows) failed: #{kind} #{inspect(reason)}")
          %{}
      end

    stats_raw =
      try do
        case AttackSurface.get_stats() do
          s when is_map(s) -> s
          _ -> %{}
        end
      catch
        kind, reason ->
          Logger.warning("AttackSurface.get_stats failed: #{kind} #{inspect(reason)}")
          %{}
      end

    # Get data exfiltration risks from high-risk data flows in the analysis
    data_flows_info = analysis[:data_flows] || %{}
    high_risk_flow_count = data_flows_info[:high_risk_flows] || 0

    # Get alerts related to data exfiltration
    data_exfiltration_risks =
      try do
        Alerts.list_alerts(%{})
        |> Enum.filter(fn alert ->
          title = String.downcase(alert.title || "")
          description = String.downcase(alert.description || "")

          String.contains?(title, ["exfil", "data flow", "sensitive", "pii"]) or
            String.contains?(description, [
              "exfiltration",
              "sensitive data",
              "data leak",
              "ai service"
            ])
        end)
        |> Enum.take(20)
        |> Enum.map(fn alert ->
          %{
            id: alert.id,
            type: "data_flow",
            severity: alert.severity,
            description: alert.description,
            agentId: alert.agent_id,
            detectedAt: format_datetime(alert.inserted_at),
            mitreTechniques: alert.mitre_techniques || []
          }
        end)
      catch
        kind, reason ->
          Logger.warning("Failed to fetch data exfiltration alerts: #{kind} #{inspect(reason)}")
          []
      end

    # Add synthetic risk entries based on high-risk flow count if no alerts exist
    data_exfiltration_risks =
      if Enum.empty?(data_exfiltration_risks) and high_risk_flow_count > 0 do
        [
          %{
            id: "high_risk_flows",
            type: "aggregate",
            severity: "high",
            description: "#{high_risk_flow_count} high-risk data flows detected to AI services",
            agentId: nil,
            detectedAt: format_datetime(DateTime.utc_now()),
            mitreTechniques: ["T1020", "T1567"]
          }
        ]
      else
        data_exfiltration_risks
      end

    # Frontend expects usage as array of ShadowAIUsage objects
    gateway_usage =
      gateway_usage_events
      |> Enum.map(fn event ->
        %{
          id: event[:id],
          agentId: event[:agent_id] || event[:user_id] || event[:tenant_id],
          service: event[:provider] || event[:domain] || "AI gateway",
          requestCount: event[:request_count] || 1,
          dataTransferred: (event[:bytes_sent] || 0) + (event[:bytes_received] || 0),
          lastActivity: event[:observed_at],
          accessMethod: event[:access_method] || "gateway",
          dataTypesShared: event[:data_categories] || [],
          policyStatus: event[:policy_decision] || "unknown",
          policyReasons: event[:policy_reasons] || [],
          policyEnforced: event[:policy_enforced] == true,
          effectiveRiskScore: event[:effective_risk_score] || event[:risk_score] || 0,
          provider: event[:provider],
          domain: event[:domain],
          processName: event[:process_name],
          hostname: event[:hostname],
          userName: event[:username] || event[:user_id] || event[:agent_id],
          department: event[:department] || "Unassigned"
        }
      end)

    usage =
      ((shadow_ai_detections ++ ai_usage_events)
       |> Enum.group_by(fn d -> {d[:agent_id], d[:domain] || d[:remote_domain]} end)
       |> Enum.map(fn {{agent_id, domain}, detections} ->
         %{
           id: "#{agent_id}_#{domain}",
           agentId: agent_id,
           service: domain,
           requestCount: length(detections),
           dataTransferred:
             Enum.reduce(detections, 0, fn d, acc ->
               acc + (d[:data_volume] || 0) + (d[:bytes_sent] || 0) + (d[:bytes_received] || 0)
             end),
           lastActivity: latest_ai_activity(detections),
           accessMethod: "network",
           dataTypesShared: []
         }
       end)) ++ gateway_usage

    # Frontend expects violations as array of PolicyViolation objects
    violations =
      data_exfiltration_risks
      |> Enum.map(fn risk ->
        %{
          id: risk.id,
          type: risk.type,
          severity: risk.severity,
          description: risk.description,
          agentId: risk.agentId,
          timestamp: risk.detectedAt,
          status: "open"
        }
      end)

    # Build stats with dataExfiltrationByCategory as an array
    data_exfil_by_category = [
      %{category: "pii", count: stats_raw[:pii_exfiltration] || 0, percentage: 0},
      %{category: "credentials", count: stats_raw[:credential_exfiltration] || 0, percentage: 0},
      %{category: "source_code", count: stats_raw[:source_code_exfiltration] || 0, percentage: 0},
      %{
        category: "business_data",
        count: stats_raw[:business_data_exfiltration] || 0,
        percentage: 0
      }
    ]

    total_exfil = Enum.reduce(data_exfil_by_category, 0, fn c, acc -> acc + c.count end)

    data_exfil_by_category =
      if total_exfil > 0 do
        Enum.map(data_exfil_by_category, fn c ->
          %{c | percentage: Float.round(c.count / total_exfil * 100, 1)}
        end)
      else
        data_exfil_by_category
      end

    render_inertia(conn, "ShadowAI", %{
      page_title: "Shadow AI Discovery",
      discoveredServices: discovered_services,
      unapprovedModels: unapproved_models,
      usage: usage,
      violations: violations,
      dataExfiltrationRisks: data_exfiltration_risks,
      remediation: [
        "Review and authorize or block detected shadow AI services",
        "Implement network policies to control AI service access",
        "Enable DLP monitoring for sensitive data flows to AI services"
      ],
      stats: %{
        totalServices: length(discovered_services),
        unapprovedCount: length(unapproved_models),
        highRiskCount: Enum.count(discovered_services, fn s -> s.riskLevel == "high" end),
        dataExfiltrationByCategory: data_exfil_by_category
      },
      dataSourceHealth: %{
        aiDiscovery: %{
          status: if(Enum.empty?(inventory_components), do: "no_data", else: "active"),
          componentCount: length(inventory_components),
          lastSeen: latest_inventory_seen(inventory_components),
          coverage: "local processes, packages, IDE extensions, model files, MCP/config artifacts"
        },
        aiUsage: %{
          status: if(Enum.empty?(ai_usage_events), do: "no_data", else: "active"),
          eventCount: length(ai_usage_events),
          lastSeen: latest_usage_seen(ai_usage_events),
          coverage: "DNS/network domain visibility only; prompt contents are not captured"
        },
        aiGateway: %{
          status: gateway_health[:status] || "no_data",
          eventCount: gateway_health[:event_count] || length(gateway_usage_events),
          lastSeen: gateway_health[:last_seen],
          coverage:
            "Gateway/browser/proxy metadata; prompts and responses are rejected by the API",
          persistenceStatus: get_in(gateway_health, [:persistence, :status]),
          persistenceRetention: get_in(gateway_health, [:persistence, :retention]),
          enforcementAvailable: get_in(gateway_health, [:enforcement, :available]) == true,
          enforcementMode: get_in(gateway_health, [:enforcement, :mode]),
          enforcementNote: get_in(gateway_health, [:enforcement, :note]),
          inlineProxy: gateway_health[:inline_proxy] == true
        },
        llmInterception: %{
          status: "unsupported",
          coverage:
            "Passive prompt/API interception is not implemented for Windows/macOS endpoint agents yet"
        }
      },
      gatewayPolicy: gateway_policy
    })
  end

  defp latest_ai_activity([]), do: nil

  defp latest_ai_activity(detections) do
    latest =
      Enum.max_by(detections, fn detection ->
        cond do
          is_integer(detection[:timestamp]) ->
            detection[:timestamp]

          match?(%DateTime{}, detection[:detected_at]) ->
            DateTime.to_unix(detection[:detected_at], :millisecond)

          true ->
            0
        end
      end)

    case latest[:detected_at] do
      %DateTime{} = dt -> format_datetime(dt)
      _ -> format_datetime_from_unix_ms(latest[:timestamp])
    end
  end

  defp latest_inventory_seen([]), do: nil

  defp latest_inventory_seen(components) do
    components
    |> Enum.map(& &1[:last_seen_at])
    |> Enum.filter(&match?(%DateTime{}, &1))
    |> Enum.reduce(nil, fn
      dt, nil -> dt
      dt, acc -> if DateTime.compare(dt, acc) == :gt, do: dt, else: acc
    end)
    |> format_datetime()
  end

  defp latest_usage_seen([]), do: nil

  defp latest_usage_seen(events) do
    events
    |> Enum.map(& &1[:timestamp])
    |> Enum.filter(&is_integer/1)
    |> Enum.max(fn -> nil end)
    |> format_datetime_from_unix_ms()
  end

  defp format_datetime_from_unix_ms(timestamp) when is_integer(timestamp) do
    timestamp
    |> DateTime.from_unix!(:millisecond)
    |> format_datetime()
  rescue
    _ -> nil
  end

  defp format_datetime_from_unix_ms(_), do: nil

  defp infer_vendor_from_domain(domain) when is_binary(domain) do
    domain_lower = String.downcase(domain)

    cond do
      String.contains?(domain_lower, "openai") ->
        "OpenAI"

      String.contains?(domain_lower, "anthropic") ->
        "Anthropic"

      String.contains?(domain_lower, "google") or String.contains?(domain_lower, "bard") ->
        "Google"

      String.contains?(domain_lower, "microsoft") or String.contains?(domain_lower, "copilot") ->
        "Microsoft"

      String.contains?(domain_lower, "huggingface") ->
        "Hugging Face"

      String.contains?(domain_lower, "cohere") ->
        "Cohere"

      String.contains?(domain_lower, "stability") ->
        "Stability AI"

      true ->
        "Unknown"
    end
  end

  defp infer_vendor_from_domain(_), do: "Unknown"

  def ai_posture(conn, _params) do
    # Get AI agents from AgentPosture module
    agents_raw =
      try do
        case AgentPosture.list_agents() do
          list when is_list(list) -> list
          _ -> []
        end
      catch
        kind, reason ->
          Logger.warning("AgentPosture.list_agents failed (registry): #{kind} #{inspect(reason)}")
          []
      end

    agents =
      Enum.map(agents_raw, fn agent ->
        %{
          id: agent[:id],
          name: agent[:name],
          type: agent[:type],
          vendor: agent[:vendor],
          status: agent[:status],
          riskScore: agent[:risk_score],
          approved: agent[:approved],
          lastSeenAt: format_datetime(agent[:last_seen_at])
        }
      end)

    # Get dashboard metrics for organization score and compliance
    metrics =
      try do
        case AgentPosture.get_dashboard_metrics() do
          m when is_map(m) -> m
          _ -> %{}
        end
      catch
        kind, reason ->
          Logger.warning(
            "AgentPosture.get_dashboard_metrics failed (registry): #{kind} #{inspect(reason)}"
          )

          %{}
      end

    # Frontend expects complianceStatus with frameworks and controls as arrays
    compliance_raw = metrics[:compliance_summary] || %{}

    compliance_status = %{
      overallScore: compliance_raw[:overall_score] || compliance_raw["overall_score"] || 0,
      frameworks:
        build_compliance_frameworks(
          compliance_raw[:frameworks] || compliance_raw["frameworks"] || []
        ),
      controls:
        build_security_controls(compliance_raw[:controls] || compliance_raw["controls"] || [])
    }

    risk_score = metrics[:organization_score] || 0

    # Aggregate data flows across all AI agents
    data_flows =
      agents_raw
      |> Enum.flat_map(fn agent ->
        try do
          case AgentPosture.get_data_flows(agent[:id]) do
            {:ok, flows} when is_list(flows) ->
              Enum.map(flows, fn flow ->
                %{
                  id: flow[:id] || UUID.uuid4(),
                  agentId: agent[:id],
                  agentName: agent[:name],
                  direction: flow[:direction] || "outbound",
                  dataType: flow[:data_type],
                  destination: flow[:destination],
                  riskScore: flow[:risk_score] || 0,
                  timestamp: format_datetime(flow[:timestamp])
                }
              end)

            _ ->
              []
          end
        catch
          kind, reason ->
            Logger.warning("AgentPosture.get_data_flows failed: #{kind} #{inspect(reason)}")
            []
        end
      end)
      |> Enum.sort_by(& &1.timestamp, :desc)
      |> Enum.take(50)

    # Frontend expects recommendations as an array
    recommendations =
      try do
        case AgentPosture.get_recommendations() do
          {:ok, recs} when is_list(recs) ->
            Enum.map(recs, fn rec ->
              %{
                id: rec[:id] || UUID.uuid4(),
                title: rec[:title] || "Security Recommendation",
                description: rec[:description] || "",
                priority: rec[:priority] || "medium",
                category: rec[:category] || "general",
                status: rec[:status] || "pending"
              }
            end)

          _ ->
            []
        end
      catch
        kind, reason ->
          Logger.warning("AgentPosture.get_recommendations failed: #{kind} #{inspect(reason)}")
          []
      end

    render_inertia(conn, "AIPosture", %{
      page_title: "AI Posture Management",
      agents: agents,
      complianceStatus: compliance_status,
      dataFlows: data_flows,
      riskScore: risk_score,
      recommendations: recommendations,
      metrics: %{
        totalAgents: metrics[:total_agents] || 0,
        approvedAgents: metrics[:approved_agents] || 0,
        unapprovedAgents: metrics[:unapproved_agents] || 0,
        shadowAIAlerts: metrics[:shadow_ai_alerts] || 0,
        riskDistribution: metrics[:risk_distribution] || %{}
      }
    })
  end

  defp build_compliance_frameworks(frameworks) when is_list(frameworks) do
    Enum.map(frameworks, fn fw ->
      %{
        id: fw[:id] || fw["id"] || UUID.uuid4(),
        name: fw[:name] || fw["name"] || "Unknown Framework",
        score: fw[:score] || fw["score"] || 0,
        status: fw[:status] || fw["status"] || "incomplete",
        controlsTotal: fw[:controls_total] || fw["controls_total"] || 0,
        controlsPassed: fw[:controls_passed] || fw["controls_passed"] || 0
      }
    end)
  end

  defp build_compliance_frameworks(_), do: []

  defp build_security_controls(controls) when is_list(controls) do
    Enum.map(controls, fn ctrl ->
      %{
        id: ctrl[:id] || ctrl["id"] || UUID.uuid4(),
        name: ctrl[:name] || ctrl["name"] || "Unknown Control",
        category: ctrl[:category] || ctrl["category"] || "general",
        status: ctrl[:status] || ctrl["status"] || "not_implemented",
        severity: ctrl[:severity] || ctrl["severity"] || "medium",
        description: ctrl[:description] || ctrl["description"] || ""
      }
    end)
  end

  defp build_security_controls(_), do: []

  # Agentic Analyst (Purple AI)
  def agentic_analyst(conn, _params) do
    # Get investigations from AgenticAnalyst module (keep raw for extracting recommendations)
    investigations_raw =
      try do
        case AgenticAnalyst.list_investigations(limit: 50) do
          list when is_list(list) -> list
          _ -> []
        end
      catch
        kind, reason ->
          Logger.warning("AgenticAnalyst.list_investigations failed: #{kind} #{inspect(reason)}")
          []
      end

    investigations =
      Enum.map(investigations_raw, fn inv ->
        %{
          id: inv.id,
          alertId: inv.alert_id,
          state: inv.state,
          startedAt: format_datetime(inv.started_at),
          updatedAt: format_datetime(inv.updated_at),
          confidence: inv.confidence,
          triageResult: inv.triage_result,
          hypothesesCount: length(inv.hypotheses || []),
          recommendationsCount: length(inv.recommendations || [])
        }
      end)

    # Get stats for triage queue info
    stats =
      try do
        case AgenticAnalyst.get_stats() do
          s when is_map(s) -> s
          _ -> %{}
        end
      catch
        kind, reason ->
          Logger.warning("AgenticAnalyst.get_stats failed: #{kind} #{inspect(reason)}")
          %{}
      end

    # Build triage queue from pending/triaging investigations
    triage_queue =
      investigations
      |> Enum.filter(fn inv -> inv.state in [:pending, :triaging, :awaiting_review] end)
      |> Enum.sort_by(fn inv -> inv.startedAt end, :desc)

    # Get active investigation (most recent in_progress)
    active_investigation =
      investigations
      |> Enum.find(fn inv ->
        inv.state in [
          :investigating,
          :hypothesis_validation,
          :evidence_collection,
          :action_recommendation
        ]
      end)

    # Extract suggested actions from active/pending investigations with recommendations
    suggested_actions =
      investigations_raw
      |> Enum.filter(fn inv ->
        inv.state in [:action_recommendation, :awaiting_review, :investigating] and
          length(inv.recommendations || []) > 0
      end)
      |> Enum.flat_map(fn inv ->
        (inv.recommendations || [])
        |> Enum.map(fn rec ->
          rec_map = if is_struct(rec), do: Map.from_struct(rec), else: rec

          %{
            id: rec_map[:id] || UUID.uuid4(),
            investigationId: inv.id,
            alertId: inv.alert_id,
            actionType: rec_map[:action_type],
            target: rec_map[:target],
            parameters: rec_map[:parameters] || %{},
            confidence: rec_map[:confidence] || 0.0,
            rationale: rec_map[:rationale],
            riskLevel: rec_map[:risk_level],
            requiresApproval: rec_map[:requires_approval] || true,
            autoExecutable: rec_map[:auto_executable] || false
          }
        end)
      end)
      |> Enum.sort_by(fn a -> a.confidence end, :desc)
      |> Enum.take(20)

    # Frontend expects insights as an array of AIInsight objects
    insights =
      try do
        case AgenticAnalyst.get_insights() do
          {:ok, list} when is_list(list) ->
            Enum.map(list, fn insight ->
              %{
                id: insight[:id] || UUID.uuid4(),
                type: insight[:type] || "observation",
                title: insight[:title] || "Insight",
                description: insight[:description] || "",
                severity: insight[:severity] || "info",
                confidence: insight[:confidence] || 0.0,
                relatedInvestigations: insight[:related_investigations] || [],
                createdAt: format_datetime(insight[:created_at])
              }
            end)

          _ ->
            []
        end
      catch
        kind, reason ->
          Logger.warning("AgenticAnalyst.get_insights failed: #{kind} #{inspect(reason)}")
          []
      end

    # Frontend expects chatHistory as an array of ChatMessage objects
    chat_history =
      try do
        case AgenticAnalyst.get_chat_history() do
          {:ok, list} when is_list(list) ->
            Enum.map(list, fn msg ->
              %{
                id: msg[:id] || UUID.uuid4(),
                role: msg[:role] || "assistant",
                content: msg[:content] || "",
                timestamp: format_datetime(msg[:timestamp]),
                investigationId: msg[:investigation_id]
              }
            end)

          _ ->
            []
        end
      catch
        kind, reason ->
          Logger.warning("AgenticAnalyst.get_chat_history failed: #{kind} #{inspect(reason)}")
          []
      end

    render_inertia(conn, "AgenticAnalyst", %{
      page_title: "Agentic Analyst",
      investigations: investigations,
      activeInvestigation: active_investigation,
      suggestedActions: suggested_actions,
      triageQueue: triage_queue,
      insights: insights,
      chatHistory: chat_history,
      stats: %{
        alertsTriaged: stats[:alerts_triaged] || 0,
        investigationsCompleted: stats[:investigations_completed] || 0,
        hypothesesGenerated: stats[:hypotheses_generated] || 0,
        hypothesesValidated: stats[:hypotheses_validated] || 0,
        actionsRecommended: stats[:actions_recommended] || 0,
        actionsExecuted: stats[:actions_executed] || 0,
        averageConfidence: stats[:average_confidence] || 0.0
      }
    })
  end

  def investigation_detail(conn, %{"id" => id}) do
    case AgenticAnalyst.get_investigation(id) do
      {:ok, investigation} ->
        # Get explanation for this investigation
        explanation =
          case AgenticAnalyst.explain_investigation(id) do
            {:ok, exp} -> exp
            _ -> nil
          end

        # Serialize findings from hypotheses and evidence
        findings =
          Enum.map(investigation.hypotheses || [], fn hyp ->
            %{
              id: hyp[:id] || UUID.uuid4(),
              type: "hypothesis",
              title: hyp[:description],
              status: hyp[:status],
              confidence: hyp[:confidence],
              evidence: hyp[:evidence] || [],
              mitreTechniques: hyp[:mitre_techniques] || []
            }
          end)

        # Build investigation timeline from state transitions and evidence
        investigation_timeline = [
          %{
            timestamp: format_datetime(investigation.started_at),
            event: "Investigation started",
            state: "started"
          },
          %{
            timestamp: format_datetime(investigation.updated_at),
            event: "Last updated",
            state: to_string(investigation.state)
          }
        ]

        render_inertia(conn, "InvestigationDetail", %{
          page_title: "Investigation: #{investigation.id}",
          investigationId: id,
          investigation: %{
            id: investigation.id,
            alertId: investigation.alert_id,
            state: investigation.state,
            confidence: investigation.confidence,
            triageResult: investigation.triage_result,
            startedAt: format_datetime(investigation.started_at),
            updatedAt: format_datetime(investigation.updated_at),
            hypotheses: investigation.hypotheses || [],
            evidence: investigation.evidence || [],
            correlations: investigation.correlations || [],
            explanation: explanation
          },
          findings: findings,
          timeline: investigation_timeline,
          recommendations:
            Enum.map(investigation.recommendations || [], fn rec ->
              %{
                id: rec[:id] || UUID.uuid4(),
                action: rec[:action],
                priority: rec[:priority],
                rationale: rec[:rationale],
                parameters: rec[:parameters] || %{}
              }
            end)
        })

      {:error, :not_found} ->
        render_inertia(conn, "InvestigationDetail", %{
          page_title: "Investigation Not Found",
          investigationId: id,
          investigation: nil,
          findings: [],
          timeline: [],
          recommendations: [],
          error: "Investigation not found"
        })

      {:error, reason} ->
        render_inertia(conn, "InvestigationDetail", %{
          page_title: "Investigation Details",
          investigationId: id,
          investigation: nil,
          findings: [],
          timeline: [],
          recommendations: [],
          error: "Failed to load investigation: #{inspect(reason)}"
        })
    end
  end

  # Dynamic Detection
  def dynamic_detection(conn, _params) do
    # Get real status from DynamicHunter
    hunter_status =
      try do
        case DynamicHunter.status() do
          {:ok, s} when is_map(s) -> s
          _ -> %{}
        end
      catch
        kind, reason ->
          Logger.warning("DynamicHunter.status failed: #{kind} #{inspect(reason)}")
          %{}
      end

    # Get real blind spots analysis
    blind_spots_analysis =
      try do
        case DynamicHunter.analyze_blind_spots(%{}) do
          {:ok, a} when is_map(a) -> a
          _ -> %{}
        end
      catch
        kind, reason ->
          Logger.warning("DynamicHunter.analyze_blind_spots failed: #{kind} #{inspect(reason)}")
          %{}
      end

    # Get real findings
    recent_findings =
      try do
        case DynamicHunter.get_recent_findings(limit: 20) do
          list when is_list(list) -> list
          _ -> []
        end
      catch
        kind, reason ->
          Logger.warning("DynamicHunter.get_recent_findings failed: #{kind} #{inspect(reason)}")
          []
      end

    # Format detection feed - matching DetectionEvent interface
    detection_feed =
      try do
        case DynamicHunter.get_detection_feed() do
          {:ok, list} when is_list(list) ->
            Enum.map(list, fn event ->
              %{
                id: event[:id] || UUID.uuid4(),
                timestamp: format_datetime(event[:timestamp]),
                ruleName: event[:rule_name] || "Unknown",
                ruleType: event[:rule_type] || "static",
                severity: event[:severity] || "medium",
                agentId: event[:agent_id] || "",
                hostname: event[:hostname] || "",
                description: event[:description] || "",
                confidence: event[:confidence] || 0.0,
                mitreTechniques: event[:mitre_techniques] || []
              }
            end)

          _ ->
            []
        end
      catch
        kind, reason ->
          Logger.warning("DynamicHunter.get_detection_feed failed: #{kind} #{inspect(reason)}")
          []
      end

    # Format dynamic rules - matching DynamicRule interface
    dynamic_rules =
      try do
        case DynamicHunter.list_dynamic_rules() do
          {:ok, list} when is_list(list) ->
            Enum.map(list, fn rule ->
              %{
                id: rule[:id] || UUID.uuid4(),
                name: rule[:name] || "Unknown",
                status: rule[:status] || "disabled",
                generatedAt: format_datetime(rule[:generated_at] || rule[:created_at]),
                triggeredCount: rule[:triggered_count] || rule[:match_count] || 0,
                falsePositiveRate: rule[:false_positive_rate] || 0.0,
                basedOn: rule[:based_on] || "",
                description: rule[:description] || ""
              }
            end)

          _ ->
            []
        end
      catch
        kind, reason ->
          Logger.warning("DynamicHunter.list_dynamic_rules failed: #{kind} #{inspect(reason)}")
          []
      end

    # Format emerging threats - matching EmergingThreat interface
    emerging_threats =
      try do
        case DynamicHunter.get_emerging_threats() do
          {:ok, list} when is_list(list) ->
            Enum.map(list, fn threat ->
              %{
                id: threat[:id] || UUID.uuid4(),
                name: threat[:name] || "Unknown",
                firstSeen: format_datetime(threat[:first_seen]),
                occurrences: threat[:occurrences] || 0,
                affectedHosts: threat[:affected_hosts] || 0,
                riskLevel: threat[:risk_level] || threat[:severity] || "medium",
                mitreMapping: threat[:mitre_mapping] || threat[:mitre_techniques] || [],
                indicators: threat[:indicators] || []
              }
            end)

          _ ->
            []
        end
      catch
        kind, reason ->
          Logger.warning("DynamicHunter.get_emerging_threats failed: #{kind} #{inspect(reason)}")
          []
      end

    # Format proactive hunts from findings
    proactive_hunts =
      Enum.map(recent_findings, fn finding ->
        %{
          id: finding[:id] || UUID.uuid4(),
          name: finding[:type] || finding[:name] || "Hunt",
          status: finding[:status] || "completed",
          lastRun: format_datetime(finding[:timestamp]),
          findings: finding[:finding_count] || 0
        }
      end)

    # Format blind spots - matching BlindSpot interface
    blind_spots =
      (blind_spots_analysis[:blind_spots] || [])
      |> Enum.map(fn bs ->
        %{
          id: bs[:id] || UUID.uuid4(),
          area: to_string(bs[:tactic] || bs[:area] || "Unknown"),
          risk:
            cond do
              (bs[:coverage_score] || 100) < 30 -> "high"
              (bs[:coverage_score] || 100) < 60 -> "medium"
              true -> "low"
            end,
          recommendation: bs[:recommendation] || "Improve detection coverage"
        }
      end)

    # Format recommendations - matching Recommendation interface
    # Handle both string recommendations and map recommendations
    recommendations =
      (blind_spots_analysis[:recommendations] || [])
      |> Enum.with_index()
      |> Enum.map(fn {rec, idx} ->
        cond do
          is_binary(rec) ->
            %{
              id: "rec-#{idx + 1}",
              title: rec,
              priority: "medium",
              description: rec
            }

          is_map(rec) ->
            %{
              id: rec[:id] || rec["id"] || "rec-#{idx + 1}",
              title: rec[:title] || rec["title"] || "Recommendation",
              priority: rec[:priority] || rec["priority"] || "medium",
              description: rec[:description] || rec["description"] || ""
            }

          true ->
            %{
              id: "rec-#{idx + 1}",
              title: "Recommendation",
              priority: "medium",
              description: to_string(rec)
            }
        end
      end)

    # ML metrics from hunter status
    hunter_stats = hunter_status[:stats] || %{}

    ml_metrics = %{
      modelName: "Malware-SMELL",
      version: "1.0.0",
      accuracy: hunter_stats[:model_accuracy] || 0.0,
      precision: hunter_stats[:model_precision] || 0.0,
      recall: hunter_stats[:model_recall] || 0.0,
      f1Score: hunter_stats[:model_f1] || 0.0,
      lastTrained: format_datetime(hunter_stats[:last_trained]),
      samplesProcessed: hunter_stats[:samples_processed] || 0,
      inferenceLatency: hunter_stats[:inference_latency] || 0
    }

    render_inertia(conn, "DynamicDetection", %{
      page_title: "Dynamic Detection",
      status: %{
        detectionFeed: detection_feed,
        dynamicRules: dynamic_rules,
        mlMetrics: ml_metrics,
        emergingThreats: emerging_threats
      },
      proactiveHunts: proactive_hunts,
      blindSpots: blind_spots,
      recommendations: recommendations,
      coverage: %{
        total: blind_spots_analysis[:total_tactics] || 0,
        covered: blind_spots_analysis[:covered_tactics] || 0,
        percentage: blind_spots_analysis[:coverage_percentage] || 0
      }
    })
  end

  # Predictive Shielding
  def predictive_shielding(conn, _params) do
    # Get real stats from PredictiveShield
    stats =
      try do
        case PredictiveShield.get_stats() do
          s when is_map(s) -> s
          _ -> %{}
        end
      catch
        kind, reason ->
          Logger.warning("PredictiveShield.get_stats failed: #{kind} #{inspect(reason)}")
          %{}
      end

    # Get real risk rankings
    risk_rankings =
      try do
        case PredictiveShield.get_risk_rankings() do
          {:ok, list} when is_list(list) -> list
          _ -> []
        end
      catch
        kind, reason ->
          Logger.warning("PredictiveShield.get_risk_rankings failed: #{kind} #{inspect(reason)}")
          []
      end

    # Calculate organization risk from real rankings
    org_risk =
      if Enum.empty?(risk_rankings) do
        %{score: 0.0, risk_level: "minimal", factors: []}
      else
        avg_score =
          Enum.reduce(risk_rankings, 0, fn r, acc ->
            acc + (r.risk_score || r[:risk_score] || 0)
          end) / length(risk_rankings)

        high_risk_count =
          Enum.count(risk_rankings, fn r -> (r.risk_score || r[:risk_score] || 0) >= 70 end)

        critical_count =
          Enum.count(risk_rankings, fn r -> (r.risk_score || r[:risk_score] || 0) >= 85 end)

        factors = []

        factors =
          if high_risk_count > 0,
            do: ["#{high_risk_count} high-risk agents" | factors],
            else: factors

        factors =
          if critical_count > 0,
            do: ["#{critical_count} critical-risk agents" | factors],
            else: factors

        %{
          score: Float.round(avg_score * 1.0, 1),
          risk_level:
            cond do
              avg_score >= 85 -> "critical"
              avg_score >= 70 -> "high"
              avg_score >= 50 -> "medium"
              avg_score >= 25 -> "low"
              true -> "minimal"
            end,
          factors: factors
        }
      end

    # Get real attack paths analysis
    attack_paths_result =
      try do
        case PredictiveShield.analyze_attack_paths(%{}) do
          {:ok, result} when is_map(result) -> result
          _ -> %{}
        end
      catch
        kind, reason ->
          Logger.warning(
            "PredictiveShield.analyze_attack_paths failed: #{kind} #{inspect(reason)}"
          )

          %{}
      end

    # Get real hardening recommendations
    hardening_recommendations =
      try do
        case PredictiveShield.generate_hardening_recommendations(%{}) do
          {:ok, result} when is_map(result) -> result
          _ -> %{}
        end
      catch
        kind, reason ->
          Logger.warning(
            "PredictiveShield.generate_hardening_recommendations failed: #{kind} #{inspect(reason)}"
          )

          %{}
      end

    # Format real riskForecast - matching AttackForecast interface
    # Interface: { category, currentRisk, predictedRisk, timeline, factors[] }
    risk_forecast =
      (attack_paths_result[:risk_forecast] || [])
      |> Enum.map(fn rf ->
        %{
          category: rf[:category] || rf[:name] || "Unknown",
          currentRisk: rf[:current_risk] || rf[:score] || 0,
          predictedRisk: rf[:predicted_risk] || rf[:score] || 0,
          timeline: rf[:timeline] || "7 days",
          factors: rf[:factors] || []
        }
      end)

    # Format real attack paths - matching AttackPath interface
    # Interface: { id, name, likelihood, impact, stages[] }
    attack_paths =
      (attack_paths_result[:paths] || [])
      |> Enum.map(fn path ->
        %{
          id: path[:id] || UUID.uuid4(),
          name: path[:name] || "Unknown Path",
          likelihood: path[:likelihood] || 0.0,
          impact: path[:impact] || path[:severity] || "medium",
          stages: path[:steps] || path[:stages] || []
        }
      end)

    # Format real recommendations - matching DefenseRecommendation interface
    # Interface: { id, title, priority, status, description, expectedRiskReduction, relatedThreats[], implementationSteps[] }
    recommendations =
      (hardening_recommendations[:recommendations] || [])
      |> Enum.map(fn rec ->
        %{
          id: rec[:id] || UUID.uuid4(),
          title: rec[:title] || "Recommendation",
          priority: rec[:priority] || "medium",
          status: rec[:status] || "pending",
          description: rec[:description] || "",
          expectedRiskReduction: rec[:expected_risk_reduction] || rec[:impact_score] || 0,
          relatedThreats: rec[:related_threats] || [],
          implementationSteps: rec[:implementation_steps] || rec[:steps] || []
        }
      end)

    # Get real predictions - matching ThreatPrediction interface
    # Interface: { id, vector, description, probability, trend, timeframe, affectedAssets[], mitreTechniques[], lastUpdated }
    predictions =
      try do
        case PredictiveShield.get_predictions() do
          {:ok, list} when is_list(list) ->
            Enum.map(list, fn pred ->
              %{
                id: pred[:id] || UUID.uuid4(),
                vector: pred[:threat_type] || pred[:vector] || "Unknown",
                description: pred[:description] || "",
                probability: pred[:probability] || 0,
                trend: pred[:trend] || "stable",
                timeframe: pred[:timeframe] || "24h",
                affectedAssets: pred[:target_assets] || pred[:affected_assets] || [],
                mitreTechniques: pred[:mitre_techniques] || [],
                lastUpdated: format_datetime(pred[:created_at] || pred[:updated_at])
              }
            end)

          _ ->
            []
        end
      catch
        kind, reason ->
          Logger.warning("PredictiveShield.get_predictions failed: #{kind} #{inspect(reason)}")
          []
      end

    # Get real accuracy history - matching AccuracyMetric interface
    # Interface: { period, predictions, accurate, falsePositives, falseNegatives, accuracy }
    accuracy_history =
      try do
        case PredictiveShield.get_accuracy_history() do
          {:ok, list} when is_list(list) ->
            Enum.map(list, fn metric ->
              %{
                period: metric[:period] || format_datetime(metric[:date]),
                predictions: metric[:predictions] || metric[:total] || 0,
                accurate: metric[:accurate] || metric[:true_positives] || 0,
                falsePositives: metric[:false_positives] || 0,
                falseNegatives: metric[:false_negatives] || 0,
                accuracy: (metric[:accuracy] || 0.0) * 1.0
              }
            end)

          _ ->
            []
        end
      catch
        kind, reason ->
          Logger.warning(
            "PredictiveShield.get_accuracy_history failed: #{kind} #{inspect(reason)}"
          )

          []
      end

    # Build stats matching PredictiveStats interface
    # Interface: { highRiskPredictions, defensesImplemented, predictionAccuracy, risingThreats }
    predictive_stats = %{
      highRiskPredictions:
        stats[:high_risk_predictions] || Enum.count(predictions, fn p -> p.probability >= 70 end),
      defensesImplemented: Enum.count(recommendations, fn r -> r.status == "implemented" end),
      predictionAccuracy: (stats[:accuracy] || 0.0) * 1.0,
      risingThreats:
        stats[:rising_threats] || Enum.count(predictions, fn p -> p.trend == "increasing" end)
    }

    render_inertia(conn, "PredictiveShielding", %{
      page_title: "Predictive Shielding",
      riskForecast: risk_forecast,
      attackPaths: attack_paths,
      recommendations: recommendations,
      predictions: predictions,
      accuracyHistory: accuracy_history,
      simulationHistory: [],
      stats: predictive_stats
    })
  end

  # Detection Rule Builder
  def detection_builder(conn, _params) do
    render_inertia(conn, "DetectionBuilder", %{
      page_title: "Detection Rule Builder"
    })
  end

  # Detection Analytics
  def detection_analytics(conn, _params) do
    alias TamanduaServer.Detection.{Analytics, EffectiveCoverage, PrecisionMetrics}

    # Get overview metrics from the Analytics GenServer
    overview =
      try do
        Analytics.get_overview()
      rescue
        _ ->
          %{
            total_rules: 0,
            active_rules: 0,
            total_detections: 0,
            avg_effectiveness: 0.0,
            false_positive_rate: 0.0,
            true_positive_rate: 0.0,
            detection_rate: 0.0,
            total_events_processed: 0,
            avg_pipeline_latency_ms: 0.0,
            total_recommendations: 0,
            total_blind_spots: 0
          }
      catch
        :exit, _ ->
          %{
            total_rules: 0,
            active_rules: 0,
            total_detections: 0,
            avg_effectiveness: 0.0,
            false_positive_rate: 0.0,
            true_positive_rate: 0.0,
            detection_rate: 0.0,
            total_events_processed: 0,
            avg_pipeline_latency_ms: 0.0,
            total_recommendations: 0,
            total_blind_spots: 0
          }
      end

    # Get per-rule metrics
    rule_metrics =
      try do
        Analytics.get_rule_metrics(sort_by: :effectiveness_score, sort_order: :desc)
        |> Enum.map(fn m ->
          %{
            ruleId: m.rule_id,
            ruleName: m.rule_name,
            ruleType: m.rule_type,
            totalHits: m.total_hits,
            truePositives: m.true_positives,
            falsePositives: m.false_positives,
            benignCount: m.benign_count,
            avgConfidence: m.avg_confidence,
            fpRate: m.fp_rate,
            tpRate: m.tp_rate,
            effectivenessScore: m.effectiveness_score,
            meanTriageSeconds: m.mean_triage_seconds,
            detectionToAlertRatio: m.detection_to_alert_ratio,
            mitreTechniques: m.mitre_techniques,
            firstHitAt: m.first_hit_at,
            lastHitAt: m.last_hit_at
          }
        end)
      rescue
        _ -> []
      catch
        :exit, _ -> []
      end

    # Get pipeline performance
    pipeline =
      try do
        pipeline_data = Analytics.get_pipeline_metrics()

        Enum.map(pipeline_data.stages_summary, fn s ->
          %{
            stage: s.stage,
            totalEvents: s.total_events,
            avgLatencyMs: s.avg_latency_ms,
            p95LatencyMs: s.p95_latency_ms,
            errorCount: s.error_count,
            errorRate: s.error_rate
          }
        end)
      rescue
        _ -> []
      catch
        :exit, _ -> []
      end

    # Get blind spots
    blind_spots =
      try do
        spots = Analytics.get_blind_spots()
        mitre = spots.mitre_gaps || %{}
        event_types = spots.event_type_gaps || %{}
        time_gaps = spots.time_of_day_gaps || %{}

        %{
          mitre: %{
            totalTechniques: mitre[:total_techniques] || 0,
            coveredTechniques: mitre[:covered_techniques] || 0,
            coveragePercent: mitre[:coverage_percent] || 0.0,
            uncoveredTechniques: Enum.take(mitre[:uncovered_techniques] || [], 30)
          },
          eventTypes: %{
            totalEventTypes: event_types[:total_event_types] || 0,
            coveredEventTypes: event_types[:covered_event_types] || 0,
            uncoveredEventTypes: event_types[:uncovered_event_types] || []
          },
          timeOfDay: %{
            hourlyDistribution:
              Enum.map(time_gaps[:hourly_distribution] || [], fn h ->
                %{hour: h.hour, count: h.count}
              end),
            gapHours: time_gaps[:gap_hours] || []
          }
        }
      rescue
        _ -> %{mitre: %{}, eventTypes: %{}, timeOfDay: %{}}
      catch
        :exit, _ -> %{mitre: %{}, eventTypes: %{}, timeOfDay: %{}}
      end

    # Get recommendations
    recommendations =
      try do
        Analytics.get_recommendations()
        |> Enum.map(fn r ->
          %{
            id: r.id,
            type: r.type,
            priority: r.priority,
            ruleId: r[:rule_id],
            ruleName: r[:rule_name],
            title: r.title,
            description: r.description,
            impact: r[:impact],
            action: r[:action],
            metrics: r[:metrics] || %{}
          }
        end)
      rescue
        _ -> []
      catch
        :exit, _ -> []
      end

    # Get trends
    trends =
      try do
        t = Analytics.get_trends("7d")

        %{
          alertTrend: t.alert_trend,
          fpTrend: t.fp_trend,
          severityTrend: t.severity_trend
        }
      rescue
        _ -> %{alertTrend: [], fpTrend: [], severityTrend: []}
      catch
        :exit, _ -> %{alertTrend: [], fpTrend: [], severityTrend: []}
      end

    precision_metrics =
      try do
        PrecisionMetrics.summary(%{})
      rescue
        _ -> %{}
      catch
        :exit, _ -> %{}
      end

    effective_coverage =
      try do
        EffectiveCoverage.summary(%{})
      rescue
        _ -> %{}
      catch
        :exit, _ -> %{}
      end

    summary = %{
      totalRules: overview.total_rules,
      activeRules: overview.active_rules,
      totalDetections: overview.total_detections,
      avgEffectiveness: overview.avg_effectiveness,
      falsePositiveRate: overview.false_positive_rate,
      truePositiveRate: overview.true_positive_rate,
      detectionRate: overview.detection_rate,
      totalEventsProcessed: overview.total_events_processed,
      avgPipelineLatencyMs: overview.avg_pipeline_latency_ms,
      totalRecommendations: overview.total_recommendations,
      totalBlindSpots: overview.total_blind_spots
    }

    render_inertia(conn, "DetectionAnalytics", %{
      page_title: "Detection Analytics & Tuning",
      summary: summary,
      ruleMetrics: rule_metrics,
      pipeline: pipeline,
      blindSpots: blind_spots,
      recommendations: recommendations,
      trends: trends,
      precisionMetrics: precision_metrics,
      effectiveCoverage: effective_coverage
    })
  end

  # Hyperautomation
  def hyperautomation(conn, _params) do
    alias TamanduaServer.Automation.Hyperautomation

    workflows =
      try do
        case Hyperautomation.list_workflows() do
          {:ok, list} when is_list(list) -> Enum.map(list, &serialize_workflow/1)
          _ -> []
        end
      catch
        kind, reason ->
          Logger.warning("Hyperautomation.list_workflows failed: #{kind} #{inspect(reason)}")
          []
      end

    actions =
      try do
        case Hyperautomation.list_available_actions() do
          {:ok, list} when is_list(list) ->
            list

          actions when is_map(actions) ->
            Enum.map(actions, fn {name, _config} ->
              %{action: to_string(name), total: 0, successful: 0, failed: 0, avgDuration: 0}
            end)

          _ ->
            []
        end
      catch
        kind, reason ->
          Logger.warning(
            "Hyperautomation.list_available_actions failed: #{kind} #{inspect(reason)}"
          )

          []
      end

    templates =
      try do
        case Hyperautomation.list_templates() do
          {:ok, list} when is_list(list) ->
            Enum.map(list, fn t ->
              %{
                id: t[:id] || t["id"] || UUID.uuid4(),
                name: t[:name] || t["name"] || "Template",
                description: t[:description] || t["description"] || ""
              }
            end)

          _ ->
            []
        end
      catch
        kind, reason ->
          Logger.warning("Hyperautomation.list_templates failed: #{kind} #{inspect(reason)}")
          []
      end

    stats =
      try do
        case Hyperautomation.get_execution_stats() do
          {:ok, s} when is_map(s) -> s
          _ -> %{total_executions: 0, success_rate: 0, avg_response_time_ms: 0}
        end
      catch
        kind, reason ->
          Logger.warning("Hyperautomation.get_execution_stats failed: #{kind} #{inspect(reason)}")
          %{total_executions: 0, success_rate: 0, avg_response_time_ms: 0}
      end

    # Frontend expects recentExecutions as an array of WorkflowExecution objects
    recent_executions =
      try do
        case Hyperautomation.list_recent_executions(limit: 20) do
          {:ok, list} when is_list(list) ->
            Enum.map(list, &serialize_workflow_execution/1)

          _ ->
            []
        end
      catch
        kind, reason ->
          Logger.warning(
            "Hyperautomation.list_recent_executions failed: #{kind} #{inspect(reason)}"
          )

          []
      end

    render_inertia(conn, "Hyperautomation", %{
      page_title: "Hyperautomation",
      workflows: workflows,
      availableActions: actions,
      templates: templates,
      recentExecutions: recent_executions,
      executionStats: %{
        totalWorkflows: length(workflows),
        enabledWorkflows: Enum.count(workflows, & &1.isEnabled),
        totalExecutions: stats[:total_executions] || 0,
        totalSuccessful: stats[:successful] || stats[:total_successful] || 0,
        runningNow: stats[:running_now] || 0
      }
    })
  end

  def workflow_detail(conn, %{"id" => id}) do
    alias TamanduaServer.Automation.Hyperautomation

    case Hyperautomation.get_workflow(id) do
      {:ok, workflow} ->
        # Get execution history for this workflow
        execution_history =
          case Hyperautomation.get_workflow_executions(id) do
            {:ok, history} -> Enum.map(history, &serialize_workflow_execution/1)
            _ -> []
          end

        # Get available actions for editing
        available_actions =
          case Hyperautomation.list_available_actions() do
            {:ok, actions} -> actions
            _ -> []
          end

        render_inertia(conn, "WorkflowDetail", %{
          page_title: workflow.name || "Workflow Details",
          workflowId: id,
          workflow: serialize_workflow(workflow),
          executionHistory: execution_history,
          availableActions: available_actions
        })

      {:error, :not_found} ->
        render_inertia(conn, "WorkflowDetail", %{
          page_title: "Workflow Not Found",
          workflowId: id,
          workflow: nil,
          executionHistory: [],
          availableActions: [],
          error: "Workflow not found"
        })

      {:error, reason} ->
        render_inertia(conn, "WorkflowDetail", %{
          page_title: "Workflow Details",
          workflowId: id,
          workflow: nil,
          executionHistory: [],
          availableActions: [],
          error: "Failed to load workflow: #{inspect(reason)}"
        })
    end
  end

  defp serialize_workflow_execution(execution) do
    %{
      id: execution[:id] || execution.id,
      workflowId: execution[:workflow_id] || execution.workflow_id,
      triggeredBy: execution[:triggered_by] || execution.triggered_by,
      triggerData: execution[:trigger_data] || execution.trigger_data || %{},
      status: execution[:status] || execution.status,
      startedAt: format_datetime(execution[:started_at] || execution.started_at),
      completedAt: format_datetime(execution[:completed_at] || execution.completed_at),
      stepResults: execution[:step_results] || execution.step_results || [],
      error: execution[:error] || execution.error,
      duration_ms: execution[:duration_ms] || execution.duration_ms
    }
  end

  # Exposure Management
  def exposure_management(conn, _params) do
    alias TamanduaServer.AISecurity.ExposureAgent

    # Get real attack surface data
    attack_surface_raw =
      try do
        case ExposureAgent.get_attack_surface_map() do
          {:ok, map} when is_map(map) -> map
          _ -> %{}
        end
      catch
        kind, reason ->
          Logger.warning(
            "ExposureAgent.get_attack_surface_map failed: #{kind} #{inspect(reason)}"
          )

          %{}
      end

    # Format assets - matching AttackSurfaceAsset interface
    assets =
      cond do
        is_list(attack_surface_raw[:assets]) ->
          Enum.map(attack_surface_raw[:assets], fn a ->
            %{
              id: a[:id] || UUID.uuid4(),
              name: a[:name] || "Unknown",
              type: a[:type] || "endpoint",
              riskScore: a[:risk_score] || a[:exposure_score] || 0,
              exposures: a[:exposures] || a[:vulnerability_count] || 0
            }
          end)

        is_map(attack_surface_raw[:assets]) ->
          Enum.map(attack_surface_raw[:assets], fn {_k, a} ->
            %{
              id: a[:id] || UUID.uuid4(),
              name: a[:name] || "Unknown",
              type: a[:type] || "endpoint",
              riskScore: a[:risk_score] || a[:exposure_score] || 0,
              exposures: a[:exposures] || a[:vulnerability_count] || 0
            }
          end)

        true ->
          []
      end

    attack_surface_map = %{
      assets: assets,
      totalRiskScore:
        attack_surface_raw[:total_risk_score] ||
          if(length(assets) > 0,
            do: Enum.reduce(assets, 0, fn a, acc -> acc + a.riskScore end) |> div(length(assets)),
            else: 0
          ),
      exposedAssets:
        attack_surface_raw[:exposed_assets] || Enum.count(assets, fn a -> a.exposures > 0 end)
    }

    # Get real services - matching ExposedService interface
    services =
      try do
        case ExposureAgent.get_exposed_services() do
          {:ok, list} when is_list(list) ->
            Enum.map(list, fn s ->
              %{
                id: s[:id] || UUID.uuid4(),
                host: s[:host] || s[:name] || "Unknown",
                port: s[:port] || 0,
                protocol: s[:protocol] || "tcp",
                service: s[:service] || s[:name] || "Unknown",
                version: s[:version] || "",
                severity: s[:severity] || "low",
                exposure: s[:exposure] || if(s[:is_public], do: "internet", else: "internal"),
                vulnerabilities: s[:vulnerabilities] || 0,
                lastScanned: format_datetime(s[:last_scanned] || s[:last_seen]),
                findings: s[:findings] || []
              }
            end)

          _ ->
            []
        end
      catch
        kind, reason ->
          Logger.warning("ExposureAgent.get_exposed_services failed: #{kind} #{inspect(reason)}")
          []
      end

    # Get real trends - matching ExposureTrend interface
    trends =
      try do
        case ExposureAgent.get_exposure_trends() do
          {:ok, list} when is_list(list) ->
            Enum.map(list, fn t ->
              %{
                date: t[:date] || format_datetime(t[:timestamp]),
                critical: t[:critical] || 0,
                high: t[:high] || 0,
                medium: t[:medium] || 0,
                low: t[:low] || 0
              }
            end)

          _ ->
            []
        end
      catch
        kind, reason ->
          Logger.warning("ExposureAgent.get_exposure_trends failed: #{kind} #{inspect(reason)}")
          []
      end

    # Get real crown jewels - matching CrownJewel interface
    crown_jewels =
      try do
        case ExposureAgent.get_crown_jewels() do
          {:ok, list} when is_list(list) ->
            Enum.map(list, fn cj ->
              %{
                id: cj[:id] || UUID.uuid4(),
                name: cj[:name] || "Unknown",
                type: cj[:type] || "Unknown",
                criticality: cj[:criticality] || "medium",
                protectionStatus: cj[:protection_status] || "unknown",
                lastAssessed: format_datetime(cj[:last_assessed])
              }
            end)

          _ ->
            []
        end
      catch
        kind, reason ->
          Logger.warning("ExposureAgent.get_crown_jewels failed: #{kind} #{inspect(reason)}")
          []
      end

    # Get real vulnerabilities - matching VulnerabilityItem interface
    vulnerabilities =
      try do
        case ExposureAgent.get_prioritized_vulnerabilities() do
          {:ok, list} when is_list(list) ->
            Enum.map(list, fn v ->
              %{
                id: v[:id] || UUID.uuid4(),
                cve: v[:cve] || v[:id] || "Unknown",
                title: v[:title] || v[:name] || "Unknown Vulnerability",
                severity: v[:severity] || "medium",
                cvss: v[:cvss] || v[:cvss_score] || 0.0,
                affectedAssets: v[:affected_assets] || 0,
                exploitable: v[:exploitable] || false,
                patchAvailable: v[:patch_available] || false,
                firstSeen: format_datetime(v[:first_seen]),
                recommendation: v[:recommendation] || ""
              }
            end)

          _ ->
            []
        end
      catch
        kind, reason ->
          Logger.warning(
            "ExposureAgent.get_prioritized_vulnerabilities failed: #{kind} #{inspect(reason)}"
          )

          []
      end

    # Get real recommendations - matching Recommendation interface
    recommendations =
      try do
        case ExposureAgent.get_recommendations() do
          {:ok, list} when is_list(list) ->
            Enum.map(list, fn r ->
              %{
                id: r[:id] || UUID.uuid4(),
                priority: r[:priority] || "medium",
                title: r[:title] || "Recommendation",
                description: r[:description] || "",
                impact: r[:impact] || "",
                effort: r[:effort] || "medium",
                affectedAssets: r[:affected_assets] || 0,
                status: r[:status] || "open"
              }
            end)

          _ ->
            []
        end
      catch
        kind, reason ->
          Logger.warning("ExposureAgent.get_recommendations failed: #{kind} #{inspect(reason)}")
          []
      end

    # Build stats - matching ExposureStats interface
    critical_count = Enum.count(vulnerabilities, fn v -> v.severity == "critical" end)

    stats = %{
      totalExposures:
        length(vulnerabilities) + Enum.sum(Enum.map(services, fn s -> s.vulnerabilities end)),
      criticalExposures:
        critical_count + Enum.count(services, fn s -> s.severity == "critical" end),
      exposedServices: Enum.count(services, fn s -> s.exposure == "internet" end),
      attackSurface: length(services),
      riskScore: attack_surface_map.totalRiskScore,
      trend:
        if(length(trends) >= 2,
          do:
            if(Enum.at(trends, -1)[:critical] > Enum.at(trends, -2)[:critical],
              do: "up",
              else: "down"
            ),
          else: "stable"
        ),
      trendValue: 0
    }

    render_inertia(conn, "ExposureManagement", %{
      page_title: "Exposure Management",
      attackSurfaceMap: attack_surface_map,
      prioritizedVulnerabilities: vulnerabilities,
      crownJewels: crown_jewels,
      services: services,
      trends: trends,
      recommendations: recommendations,
      stats: stats
    })
  end

  def attack_paths(conn, _params) do
    # Get attack paths analysis from PredictiveShield
    attack_paths_result =
      try do
        case PredictiveShield.analyze_attack_paths(%{}) do
          {:ok, result} when is_map(result) ->
            result

          other ->
            Logger.warning("PredictiveShield.analyze_attack_paths returned #{inspect(other)}")
            %{paths: []}
        end
      catch
        kind, reason ->
          Logger.warning("PredictiveShield.analyze_attack_paths failed: #{kind} #{inspect(reason)}")
          %{paths: []}
      end

    # Format all attack paths
    paths =
      (attack_paths_result[:paths] || [])
      |> Enum.map(fn path ->
        %{
          id: path[:id],
          name: path[:name],
          severity: path[:severity],
          likelihood: path[:likelihood],
          impactScore: path[:impact_score],
          steps: path[:steps] || [],
          affectedAssets: path[:affected_assets] || [],
          mitigations: path[:mitigations] || [],
          entryPoints: path[:entry_points] || [],
          targetAssets: path[:target_assets] || []
        }
      end)

    # Filter critical paths (severity is critical or high with high likelihood)
    critical_paths =
      paths
      |> Enum.filter(fn path ->
        path.severity in [:critical, "critical"] or
          (path.severity in [:high, "high"] and
             path.likelihood in [:high, "high", :very_high, "very_high"])
      end)

    # Get hardening recommendations
    hardening_result =
      try do
        case PredictiveShield.generate_hardening_recommendations(%{}) do
          {:ok, result} when is_map(result) ->
            result

          other ->
            Logger.warning("PredictiveShield.generate_hardening_recommendations returned #{inspect(other)}")
            %{recommendations: []}
        end
      catch
        kind, reason ->
          Logger.warning("PredictiveShield.generate_hardening_recommendations failed: #{kind} #{inspect(reason)}")
          %{recommendations: []}
      end

    # Format recommendations
    recommendations =
      (hardening_result[:recommendations] || [])
      |> Enum.map(fn rec ->
        %{
          id: rec[:id],
          priority: rec[:priority],
          category: rec[:category],
          title: rec[:title],
          description: rec[:description],
          effort: rec[:effort],
          impact: rec[:impact],
          status: rec[:status] || "pending",
          relatedPaths: rec[:related_paths] || []
        }
      end)

    render_inertia(conn, "AttackPaths", %{
      page_title: "Attack Paths",
      paths: paths,
      criticalPaths: critical_paths,
      recommendations: recommendations,
      stats: %{
        totalPaths: length(paths),
        criticalPaths: length(critical_paths),
        pendingRecommendations: Enum.count(recommendations, fn r -> r.status == "pending" end)
      }
    })
  end

  # Collaboration Security
  def collaboration_security(conn, _params) do
    alias TamanduaServer.Integrations.CollaborationSecurity

    events =
      try do
        case CollaborationSecurity.list_events(%{limit: 100}) do
          {:ok, list} when is_list(list) -> Enum.map(list, &serialize_collab_event/1)
          _ -> []
        end
      catch
        kind, reason ->
          Logger.warning("CollaborationSecurity.list_events failed: #{kind} #{inspect(reason)}")
          []
      end

    # Frontend expects risks as an array of SharingRisk objects
    risks =
      try do
        case CollaborationSecurity.analyze_risks(%{}) do
          {:ok, analysis} when is_map(analysis) ->
            # Convert risk analysis map to array of risk objects
            risk_items = analysis[:risks] || analysis["risks"] || []

            if is_list(risk_items) do
              Enum.map(risk_items, fn risk ->
                %{
                  id: risk[:id] || risk["id"] || UUID.uuid4(),
                  type: risk[:type] || risk["type"] || "unknown",
                  severity: risk[:severity] || risk["severity"] || "medium",
                  description: risk[:description] || risk["description"] || "",
                  affectedUsers: risk[:affected_users] || risk["affected_users"] || 0,
                  detectedAt: format_datetime(risk[:detected_at] || risk["detected_at"])
                }
              end)
            else
              []
            end

          {:ok, list} when is_list(list) ->
            Enum.map(list, fn risk ->
              %{
                id: risk[:id] || risk["id"] || UUID.uuid4(),
                type: risk[:type] || risk["type"] || "unknown",
                severity: risk[:severity] || risk["severity"] || "medium",
                description: risk[:description] || risk["description"] || "",
                affectedUsers: risk[:affected_users] || risk["affected_users"] || 0,
                detectedAt: format_datetime(risk[:detected_at] || risk["detected_at"])
              }
            end)

          _ ->
            []
        end
      catch
        kind, reason ->
          Logger.warning("CollaborationSecurity.analyze_risks failed: #{kind} #{inspect(reason)}")
          []
      end

    # Frontend expects externalSharing as an array of ExternalSharing objects
    external_sharing =
      try do
        case CollaborationSecurity.analyze_external_sharing(%{}) do
          {:ok, analysis} when is_map(analysis) ->
            # Convert external sharing analysis to array
            shares = analysis[:shares] || analysis["shares"] || analysis[:external_shares] || []

            if is_list(shares) do
              Enum.map(shares, fn share ->
                %{
                  id: share[:id] || share["id"] || UUID.uuid4(),
                  resourceType: share[:resource_type] || share["resource_type"] || "file",
                  resourceName: share[:resource_name] || share["resource_name"] || "Unknown",
                  sharedWith: share[:shared_with] || share["shared_with"] || "",
                  sharedBy: share[:shared_by] || share["shared_by"] || "",
                  permissions: share[:permissions] || share["permissions"] || "view",
                  expiresAt: format_datetime(share[:expires_at] || share["expires_at"]),
                  createdAt: format_datetime(share[:created_at] || share["created_at"])
                }
              end)
            else
              []
            end

          {:ok, list} when is_list(list) ->
            Enum.map(list, fn share ->
              %{
                id: share[:id] || share["id"] || UUID.uuid4(),
                resourceType: share[:resource_type] || share["resource_type"] || "file",
                resourceName: share[:resource_name] || share["resource_name"] || "Unknown",
                sharedWith: share[:shared_with] || share["shared_with"] || "",
                sharedBy: share[:shared_by] || share["shared_by"] || "",
                permissions: share[:permissions] || share["permissions"] || "view",
                expiresAt: format_datetime(share[:expires_at] || share["expires_at"]),
                createdAt: format_datetime(share[:created_at] || share["created_at"])
              }
            end)

          _ ->
            []
        end
      catch
        kind, reason ->
          Logger.warning(
            "CollaborationSecurity.analyze_external_sharing failed: #{kind} #{inspect(reason)}"
          )

          []
      end

    policies =
      try do
        case CollaborationSecurity.get_policies() do
          {:ok, list} when is_list(list) -> Enum.map(list, &serialize_collab_policy/1)
          _ -> []
        end
      catch
        kind, reason ->
          Logger.warning("CollaborationSecurity.get_policies failed: #{kind} #{inspect(reason)}")
          []
      end

    # Frontend expects alerts as an array of DLPAlert objects
    alerts =
      try do
        case CollaborationSecurity.list_alerts(%{limit: 50}) do
          {:ok, list} when is_list(list) ->
            Enum.map(list, fn alert ->
              %{
                id: alert[:id] || alert["id"] || UUID.uuid4(),
                type: alert[:type] || alert["type"] || "dlp_violation",
                severity: alert[:severity] || alert["severity"] || "medium",
                message: alert[:message] || alert["message"] || "",
                userId: alert[:user_id] || alert["user_id"],
                resourceId: alert[:resource_id] || alert["resource_id"],
                action: alert[:action] || alert["action"] || "blocked",
                timestamp: format_datetime(alert[:timestamp] || alert["timestamp"])
              }
            end)

          _ ->
            []
        end
      catch
        kind, reason ->
          Logger.warning("CollaborationSecurity.list_alerts failed: #{kind} #{inspect(reason)}")
          []
      end

    render_inertia(conn, "CollaborationSecurity", %{
      page_title: "Collaboration Security",
      events: events,
      risks: risks,
      externalSharing: external_sharing,
      policies: policies,
      alerts: alerts
    })
  end

  # Natural Language Hunting
  def nl_hunting(conn, _params) do
    # Get hunt sessions from NLHunter module
    sessions_data =
      try do
        case NLHunter.list_sessions(%{}) do
          {:ok, list} when is_list(list) -> list
          _ -> []
        end
      catch
        kind, reason ->
          Logger.warning("NLHunter.list_sessions failed: #{kind} #{inspect(reason)}")
          []
      end

    sessions =
      Enum.map(sessions_data, fn session ->
        %{
          id: session[:id],
          name: session[:name] || "Hunt Session",
          status: session[:status],
          queryCount: session[:query_count] || 0,
          findingsCount: session[:findings_count] || 0,
          createdAt: format_datetime(session[:created_at]),
          updatedAt: format_datetime(session[:updated_at])
        }
      end)

    # Get query suggestions for hypotheses
    suggestions =
      try do
        case NLHunter.query_suggestions(%{}) do
          {:ok, s} when is_map(s) -> s
          _ -> %{}
        end
      catch
        kind, reason ->
          Logger.warning("NLHunter.query_suggestions failed: #{kind} #{inspect(reason)}")
          %{}
      end

    suggested_hypotheses =
      Enum.map(suggestions[:hypotheses] || [], fn hyp ->
        %{
          id: hyp[:id] || UUID.uuid4(),
          hypothesis: hyp[:text] || hyp[:hypothesis],
          category: hyp[:category],
          confidence: hyp[:confidence],
          mitreTechniques: hyp[:mitre_techniques] || []
        }
      end)

    # Ensure savedQueries is always an array
    saved_queries =
      cond do
        is_list(suggestions[:saved_queries]) ->
          Enum.map(suggestions[:saved_queries], fn q ->
            %{
              id: q[:id] || UUID.uuid4(),
              name: q[:name] || "Saved Query",
              query: q[:query] || "",
              createdAt: format_datetime(q[:created_at])
            }
          end)

        true ->
          []
      end

    render_inertia(conn, "NLHunting", %{
      page_title: "Natural Language Hunting",
      sessions: sessions,
      savedQueries: saved_queries,
      suggestedHypotheses: suggested_hypotheses
    })
  end

  def nl_hunt_session(conn, %{"id" => id}) do
    case NLHunter.get_session(id) do
      {:ok, session} ->
        # Get queries and results for this session
        queries =
          Enum.map(session[:queries] || [], fn query ->
            %{
              id: query[:id] || UUID.uuid4(),
              originalQuery: query[:original_query],
              parsedQuery: query[:parsed_query],
              generatedSql: query[:generated_sql],
              executedAt: format_datetime(query[:executed_at]),
              resultCount: query[:result_count] || 0
            }
          end)

        # Get results (latest query results)
        results = session[:latest_results] || []

        # Get findings
        findings =
          Enum.map(session[:findings] || [], fn finding ->
            %{
              id: finding[:id] || UUID.uuid4(),
              type: finding[:type],
              severity: finding[:severity],
              description: finding[:description],
              evidence: finding[:evidence] || [],
              mitreTechniques: finding[:mitre_techniques] || [],
              discoveredAt: format_datetime(finding[:discovered_at])
            }
          end)

        render_inertia(conn, "NLHuntSession", %{
          page_title: session[:name] || "Hunt Session",
          sessionId: id,
          session: %{
            id: session[:id],
            name: session[:name],
            status: session[:status],
            createdAt: format_datetime(session[:created_at]),
            updatedAt: format_datetime(session[:updated_at]),
            queryCount: length(queries),
            findingsCount: length(findings)
          },
          queries: queries,
          results: results,
          findings: findings
        })

      {:error, :not_found} ->
        render_inertia(conn, "NLHuntSession", %{
          page_title: "Session Not Found",
          sessionId: id,
          session: nil,
          queries: [],
          results: [],
          findings: [],
          error: "Hunt session not found"
        })

      {:error, reason} ->
        render_inertia(conn, "NLHuntSession", %{
          page_title: "Hunt Session",
          sessionId: id,
          session: nil,
          queries: [],
          results: [],
          findings: [],
          error: "Failed to load session: #{inspect(reason)}"
        })
    end
  end

  # AI SIEM
  def ai_siem(conn, _params) do
    # Get discovered patterns from AI SIEM module
    patterns_data =
      try do
        case AISIEM.discovered_patterns(%{}) do
          {:ok, data} when is_list(data) -> data
          _ -> []
        end
      catch
        kind, reason ->
          Logger.warning("AISIEM.discovered_patterns failed: #{kind} #{inspect(reason)}")
          []
      end

    discovered_patterns =
      Enum.map(patterns_data || [], fn pattern ->
        %{
          id: pattern[:id],
          type: pattern[:type],
          name: pattern[:name],
          description: pattern[:description],
          frequency: pattern[:frequency],
          confidence: pattern[:confidence],
          isNoise: pattern[:is_noise],
          mitreMappings: pattern[:mitre_mapping] || [],
          firstSeen: format_datetime(pattern[:first_seen]),
          lastSeen: format_datetime(pattern[:last_seen])
        }
      end)

    # Get alert correlations
    correlations_data =
      try do
        case AISIEM.alert_correlations(%{}) do
          {:ok, data} when is_list(data) -> data
          _ -> []
        end
      catch
        kind, reason ->
          Logger.warning("AISIEM.alert_correlations failed: #{kind} #{inspect(reason)}")
          []
      end

    alert_correlations =
      Enum.map(correlations_data || [], fn corr ->
        %{
          id: corr[:id],
          rootAlertId: corr[:root_alert_id],
          alertIds: corr[:alert_ids] || [],
          correlationType: corr[:correlation_type],
          confidence: corr[:confidence],
          attackNarrative: corr[:attack_narrative],
          recommendedActions: corr[:recommended_actions] || [],
          createdAt: format_datetime(corr[:created_at])
        }
      end)

    # Get noise metrics
    noise_data =
      try do
        case AISIEM.noise_metrics(%{}) do
          {:ok, data} when is_map(data) -> data
          _ -> %{}
        end
      catch
        kind, reason ->
          Logger.warning("AISIEM.noise_metrics failed: #{kind} #{inspect(reason)}")
          %{}
      end

    noise_metrics = %{
      totalAlerts: noise_data[:total_alerts] || 0,
      filteredNoise: noise_data[:suppressed_count] || 0,
      noiseReductionRate: noise_data[:noise_reduction_rate] || 0,
      avgNoiseScore: noise_data[:avg_noise_score] || 0
    }

    # Get dashboard data for intelligent alerts
    dashboard_data =
      try do
        case AISIEM.get_dashboard_data() do
          {:ok, data} when is_map(data) -> data
          _ -> %{}
        end
      catch
        kind, reason ->
          Logger.warning("AISIEM.get_dashboard_data failed: #{kind} #{inspect(reason)}")
          %{}
      end

    intelligent_alerts =
      Enum.map(dashboard_data[:recent_high_value_alerts] || [], fn alert ->
        %{
          id: alert[:id],
          title: alert[:title],
          severity: alert[:severity],
          noiseScore: alert[:noise_score],
          correlationGroup: alert[:correlation_group],
          timestamp: format_datetime(alert[:timestamp])
        }
      end)

    # Frontend expects connections as an array of SIEMConnection objects
    connections =
      try do
        case AISIEM.list_connections() do
          {:ok, list} when is_list(list) ->
            Enum.map(list, fn conn_item ->
              %{
                id: conn_item[:id] || UUID.uuid4(),
                name: conn_item[:name] || "SIEM Connection",
                type: conn_item[:type] || "splunk",
                status: conn_item[:status] || "disconnected",
                lastSync: format_datetime(conn_item[:last_sync]),
                eventsIngested: conn_item[:events_ingested] || 0
              }
            end)

          _ ->
            []
        end
      catch
        kind, reason ->
          Logger.warning("AISIEM.list_connections failed: #{kind} #{inspect(reason)}")
          []
      end

    # Frontend expects correlationRules as an array of CorrelationRule objects
    correlation_rules =
      try do
        case AISIEM.list_correlation_rules() do
          {:ok, list} when is_list(list) ->
            Enum.map(list, fn rule ->
              %{
                id: rule[:id] || UUID.uuid4(),
                name: rule[:name] || "Correlation Rule",
                description: rule[:description] || "",
                enabled: rule[:enabled] || false,
                conditions: rule[:conditions] || [],
                actions: rule[:actions] || [],
                matchCount: rule[:match_count] || 0
              }
            end)

          _ ->
            []
        end
      catch
        kind, reason ->
          Logger.warning("AISIEM.list_correlation_rules failed: #{kind} #{inspect(reason)}")
          []
      end

    # Frontend expects enrichmentSources as an array of EnrichmentSource objects
    enrichment_sources =
      try do
        case AISIEM.list_enrichment_sources() do
          {:ok, list} when is_list(list) ->
            Enum.map(list, fn source ->
              %{
                id: source[:id] || UUID.uuid4(),
                name: source[:name] || "Enrichment Source",
                type: source[:type] || "threat_intel",
                status: source[:status] || "inactive",
                lastUpdate: format_datetime(source[:last_update]),
                recordCount: source[:record_count] || 0
              }
            end)

          _ ->
            []
        end
      catch
        kind, reason ->
          Logger.warning("AISIEM.list_enrichment_sources failed: #{kind} #{inspect(reason)}")
          []
      end

    render_inertia(conn, "AISIEM", %{
      page_title: "AI SIEM",
      discoveredPatterns: discovered_patterns,
      alertCorrelations: alert_correlations,
      noiseMetrics: noise_metrics,
      intelligentAlerts: intelligent_alerts,
      connections: connections,
      correlationRules: correlation_rules,
      enrichmentSources: enrichment_sources
    })
  end

  # Deception Technology
  def deception(conn, _params) do
    alias TamanduaServer.Deception.{Breadcrumbs, Analytics}

    current_user = conn.assigns[:current_user]
    org_id = current_user && current_user.organization_id

    # Get stats
    breadcrumb_stats =
      try do
        case Breadcrumbs.get_stats() do
          {:ok, stats} -> stats
          _ -> %{}
        end
      rescue
        _ -> %{}
      end

    analytics_stats =
      try do
        case Analytics.get_stats() do
          {:ok, stats} -> stats
          _ -> %{}
        end
      rescue
        _ -> %{}
      end

    stats = %{
      totalDecoys: Map.get(breadcrumb_stats, :total_breadcrumbs, 0),
      activeDecoys: Map.get(breadcrumb_stats, :active_breadcrumbs, 0),
      accessedDecoys: Map.get(breadcrumb_stats, :accessed_breadcrumbs, 0),
      uniqueAttackers: Map.get(analytics_stats, :attacker_profiles, 0),
      totalInteractions: Map.get(analytics_stats, :total_interactions, 0),
      interactionsToday: 0,
      ttpsExtracted: Map.get(analytics_stats, :ttps_extracted, 0),
      indicatorsGenerated: Map.get(analytics_stats, :total_indicators, 0),
      agentsWithDecoys: Map.get(breadcrumb_stats, :agents_with_breadcrumbs, 0),
      detectionRate: calculate_deception_detection_rate(breadcrumb_stats)
    }

    # Get breadcrumbs
    breadcrumbs =
      try do
        case Breadcrumbs.list_breadcrumbs(limit: 50) do
          {:ok, bcs} -> Enum.map(bcs, &serialize_breadcrumb/1)
          _ -> []
        end
      rescue
        _ -> []
      end

    # Get attacker profiles
    attackers =
      try do
        case Analytics.list_attacker_profiles(limit: 20) do
          {:ok, atks} -> Enum.map(atks, &serialize_attacker_profile/1)
          _ -> []
        end
      rescue
        _ -> []
      end

    # Get indicators
    indicators =
      try do
        case Analytics.get_indicators(limit: 50) do
          {:ok, inds} -> Enum.map(inds, &serialize_deception_indicator/1)
          _ -> []
        end
      rescue
        _ -> []
      end

    # Get deployment profiles
    profiles =
      try do
        case Breadcrumbs.list_profiles() do
          {:ok, profs} -> Enum.map(profs, &serialize_deployment_profile/1)
          _ -> []
        end
      rescue
        _ -> []
      end

    # Get timeline
    timeline =
      try do
        case Analytics.get_timeline(limit: 20) do
          {:ok, events} -> Enum.map(events, &serialize_deception_timeline_event/1)
          _ -> []
        end
      rescue
        _ -> []
      end

    # Get decoy services from deployed breadcrumbs
    decoy_services =
      try do
        case Breadcrumbs.list_breadcrumbs(status: :active) do
          {:ok, bcs} ->
            bcs
            |> Enum.group_by(& &1.type)
            |> Enum.map(fn {type, items} ->
              latest = items |> Enum.max_by(& &1.deployed_at, DateTime, fn -> nil end)

              %{
                type: to_string(type),
                count: length(items),
                status: "active",
                connections: Enum.sum(Enum.map(items, & &1.access_count)),
                lastActivity: if(latest, do: format_datetime(latest.deployed_at), else: nil)
              }
            end)

          _ ->
            []
        end
      rescue
        _ -> []
      end

    # Generate recommendations
    recommendations = generate_deception_recommendations(org_id, breadcrumbs, attackers, stats)

    render_inertia(conn, "Deception", %{
      page_title: "Deception Technology",
      stats: stats,
      breadcrumbs: breadcrumbs,
      attackers: attackers,
      indicators: indicators,
      profiles: profiles,
      recommendations: recommendations,
      timeline: timeline,
      decoyServices: decoy_services
    })
  end

  defp calculate_deception_detection_rate(stats) do
    total = Map.get(stats, :total_breadcrumbs, 0)
    accessed = Map.get(stats, :accessed_breadcrumbs, 0)

    if total > 0 do
      Float.round(accessed / total * 100, 1)
    else
      0.0
    end
  end

  defp serialize_breadcrumb(bc) do
    agent_hostname =
      case Agents.get_agent(bc.agent_id) do
        {:ok, agent} -> agent.hostname
        _ -> "Unknown"
      end

    %{
      id: bc.id,
      type: to_string(bc.type),
      agentId: bc.agent_id,
      agentHostname: agent_hostname,
      path: bc.path,
      canaryToken: bc.canary_token,
      status: to_string(bc.status),
      deployedAt: format_datetime(bc.deployed_at),
      lastRotatedAt: format_datetime(bc.last_rotated_at),
      accessCount: bc.access_count
    }
  end

  defp serialize_attacker_profile(attacker) do
    %{
      id: attacker.id,
      riskScore: attacker.risk_score,
      firstSeen: format_datetime(attacker.first_seen),
      lastSeen: format_datetime(attacker.last_seen),
      sourceIps: attacker.source_ips,
      agentsTargeted: attacker.agents_targeted,
      interactions: attacker.decoy_interactions,
      ttps:
        Enum.map(attacker.ttps, fn ttp ->
          %{
            tactic: ttp.tactic,
            techniqueId: ttp.technique_id,
            techniqueName: ttp.technique_name,
            evidenceCount: ttp.evidence_count
          }
        end),
      status: to_string(attacker.status)
    }
  end

  defp serialize_deception_indicator(ind) do
    %{
      type: to_string(ind.type),
      value: ind.value,
      confidence: ind.confidence,
      firstSeen: format_datetime(ind.first_seen),
      context: ind.context
    }
  end

  defp serialize_deployment_profile(profile) do
    %{
      id: profile.id,
      name: profile.name,
      description: profile.description,
      decoyTypes: Enum.map(profile.decoy_types, &to_string/1),
      osTypes: Enum.map(profile.os_types, &to_string/1),
      density: to_string(profile.density),
      enabled: profile.enabled
    }
  end

  defp serialize_deception_timeline_event(event) do
    agent_hostname =
      case Agents.get_agent(event.agent_id) do
        {:ok, agent} -> agent.hostname
        _ -> "Unknown"
      end

    %{
      timestamp: format_datetime(event.timestamp),
      eventType: event.event_type,
      agentId: event.agent_id,
      agentHostname: agent_hostname,
      decoyType: to_string(event.decoy_type),
      sourceIp: event.source_ip,
      mitreTechnique: event.mitre_technique
    }
  end

  defp generate_deception_recommendations(org_id, breadcrumbs, attackers, _stats) do
    recommendations = []

    # Check for high-risk attackers
    high_risk = Enum.filter(attackers, &(&1.riskScore >= 80))

    recommendations =
      if length(high_risk) > 0 do
        [
          %{
            type: "investigate",
            priority: "critical",
            title: "#{length(high_risk)} High-Risk Attackers Detected",
            description: "Immediate investigation recommended"
          }
          | recommendations
        ]
      else
        recommendations
      end

    # Check for agents without decoys
    agents_with_decoys =
      breadcrumbs
      |> Enum.map(& &1.agentId)
      |> Enum.uniq()
      |> MapSet.new()

    all_agents = list_agents_for_dashboard(org_id)
    agents_without = Enum.reject(all_agents, &MapSet.member?(agents_with_decoys, &1.id))

    recommendations =
      if length(agents_without) > 0 do
        [
          %{
            type: "add_decoy",
            priority: "medium",
            title: "#{length(agents_without)} Agents Without Decoys",
            description: "Deploy breadcrumbs to improve coverage"
          }
          | recommendations
        ]
      else
        recommendations
      end

    recommendations
  end

  # AI Agent Registry
  def ai_agent_registry(conn, _params) do
    # Get AI agents from AgentPosture module
    agents_raw =
      try do
        case AgentPosture.list_agents() do
          list when is_list(list) -> list
          _ -> []
        end
      catch
        kind, reason ->
          Logger.warning(
            "AgentPosture.list_agents failed (ai_agent_registry): #{kind} #{inspect(reason)}"
          )

          []
      end

    ai_agents =
      Enum.map(agents_raw, fn agent ->
        # Get permissions for each agent
        agent_permissions =
          try do
            case AgentPosture.get_permissions(agent[:id]) do
              {:ok, perms} when is_map(perms) -> perms
              _ -> %{}
            end
          catch
            kind, reason ->
              Logger.warning("AgentPosture.get_permissions failed: #{kind} #{inspect(reason)}")
              %{}
          end

        %{
          id: agent[:id],
          name: agent[:name],
          type: agent[:type],
          vendor: agent[:vendor],
          status: agent[:status],
          riskScore: agent[:risk_score],
          approved: agent[:approved],
          permissions: %{
            dataAccess: agent_permissions[:data_access] || [],
            toolAccess: agent_permissions[:tool_access] || [],
            apiScopes: agent_permissions[:api_scopes] || []
          },
          lastSeenAt: format_datetime(agent[:last_seen_at]),
          registeredAt: format_datetime(agent[:registered_at])
        }
      end)

    # Get dashboard metrics for activity summary
    metrics =
      try do
        case AgentPosture.get_dashboard_metrics() do
          m when is_map(m) -> m
          _ -> %{}
        end
      catch
        kind, reason ->
          Logger.warning(
            "AgentPosture.get_dashboard_metrics failed (ai_agent_registry): #{kind} #{inspect(reason)}"
          )

          %{}
      end

    # Build activity logs from recent data flows (if available)
    activity_logs =
      Enum.flat_map(ai_agents, fn agent ->
        try do
          case AgentPosture.get_data_flows(agent.id) do
            {:ok, flows} when is_list(flows) ->
              Enum.take(flows, 5)
              |> Enum.map(fn flow ->
                %{
                  id: flow[:id] || UUID.uuid4(),
                  agentId: agent.id,
                  agentName: agent.name,
                  action: flow[:action],
                  resource: flow[:resource],
                  timestamp: format_datetime(flow[:timestamp]),
                  status: flow[:status]
                }
              end)

            _ ->
              []
          end
        catch
          kind, reason ->
            Logger.warning(
              "AgentPosture.get_data_flows failed (activity logs): #{kind} #{inspect(reason)}"
            )

            []
        end
      end)
      |> Enum.sort_by(& &1.timestamp, :desc)
      |> Enum.take(50)

    # Frontend expects permissions as an array of Permission objects (distinct from agent permissions)
    # Build permissions list from all unique permissions across agents
    permissions_list =
      ai_agents
      |> Enum.flat_map(fn agent ->
        data_perms =
          Enum.map(agent.permissions.dataAccess || [], fn da ->
            %{
              id: "data_#{agent.id}_#{da}",
              agentId: agent.id,
              type: "data_access",
              resource: da,
              granted: true,
              grantedAt: agent.registeredAt
            }
          end)

        tool_perms =
          Enum.map(agent.permissions.toolAccess || [], fn ta ->
            %{
              id: "tool_#{agent.id}_#{ta}",
              agentId: agent.id,
              type: "tool_access",
              resource: ta,
              granted: true,
              grantedAt: agent.registeredAt
            }
          end)

        api_perms =
          Enum.map(agent.permissions.apiScopes || [], fn scope ->
            %{
              id: "api_#{agent.id}_#{scope}",
              agentId: agent.id,
              type: "api_scope",
              resource: scope,
              granted: true,
              grantedAt: agent.registeredAt
            }
          end)

        data_perms ++ tool_perms ++ api_perms
      end)

    render_inertia(conn, "AIAgentRegistry", %{
      page_title: "AI Agent Registry",
      agents: ai_agents,
      permissions: permissions_list,
      activityLogs: activity_logs,
      stats: %{
        totalAgents: metrics[:total_agents] || length(ai_agents),
        approvedAgents: metrics[:approved_agents] || Enum.count(ai_agents, & &1.approved),
        unapprovedAgents:
          metrics[:unapproved_agents] || Enum.count(ai_agents, &(not &1.approved)),
        riskDistribution: metrics[:risk_distribution] || %{}
      }
    })
  end

  # AI Model Dependency Graph
  def ai_dependency_graph(conn, _params) do
    current_user = conn.assigns[:current_user]
    org_id = current_user && current_user.organization_id

    # Get graph stats
    stats =
      try do
        DependencyGraph.stats()
      catch
        kind, reason ->
          Logger.warning("DependencyGraph.stats failed: #{kind} #{inspect(reason)}")
          %{node_count: 0, edge_count: 0, model_count: 0, process_count: 0}
      end

    # Get critical models
    critical_models =
      try do
        DependencyGraph.find_critical_models(limit: 10, min_dependents: 2)
      catch
        kind, reason ->
          Logger.warning(
            "DependencyGraph.find_critical_models failed: #{kind} #{inspect(reason)}"
          )

          []
      end

    # Get unusual chains / anomalies
    anomalies =
      try do
        DependencyGraph.detect_unusual_chains()
      catch
        kind, reason ->
          Logger.warning(
            "DependencyGraph.detect_unusual_chains failed: #{kind} #{inspect(reason)}"
          )

          []
      end

    # Get agents list for filtering
    agents =
      list_agents_for_dashboard(org_id)
      |> Enum.map(fn a ->
        %{
          id: Map.get(a, :id) || Map.get(a, :agent_id),
          hostname: a.hostname,
          status: to_string(a.status || "unknown")
        }
      end)

    render_inertia(conn, "AIDependencyGraph", %{
      page_title: "AI Model Dependency Graph",
      stats: %{
        nodeCount: stats[:node_count] || 0,
        edgeCount: stats[:edge_count] || 0,
        modelCount: stats[:model_count] || 0,
        processCount: stats[:process_count] || 0
      },
      criticalModels:
        Enum.map(critical_models, fn m ->
          %{
            id: m[:id] || m.id,
            name: m[:id] || m.id,
            totalDependents: m[:total_dependents] || m.total_dependents || 0,
            directDependents: m[:direct_dependents] || m.direct_dependents || 0,
            indirectDependents: m[:indirect_dependents] || m.indirect_dependents || 0,
            criticalityScore: m[:criticality_score] || m.criticality_score || 0.0
          }
        end),
      anomalies:
        Enum.map(anomalies, fn a ->
          %{
            id: a[:id] || UUID.uuid4(),
            type: to_string(a[:type] || a.type),
            severity: to_string(a[:severity] || a.severity),
            description: a[:description] || a.description,
            modelId: a[:model_id] || a.model_id,
            details: a[:details] || %{}
          }
        end),
      agents: agents
    })
  end

  # AI Artifact Inventory
  def ai_artifacts(conn, _params) do
    current_user = conn.assigns[:current_user]
    org_id = current_user && current_user.organization_id

    artifacts = list_ai_artifact_inventory(org_id)
    stats = build_ai_artifact_stats(artifacts)

    render_inertia(conn, "AIArtifactInventory", %{
      page_title: "AI Artifact Inventory",
      artifacts: artifacts,
      stats: stats,
      dataSource: %{
        table: "ai_inventory",
        collector: "ai_discovery",
        emptyState: Enum.empty?(artifacts)
      }
    })
  end

  defp list_ai_artifact_inventory(org_id) do
    alias TamanduaServer.Repo

    {where_org, params} =
      if org_id do
        {"ai.organization_id = $1 AND", [org_id]}
      else
        {"", []}
      end

    sql = """
    SELECT
      ai.id,
      ai.name,
      ai.component_type,
      ai.version,
      ai.install_path,
      ai.risk_score,
      ai.risk_level,
      ai.policy_status,
      ai.is_shadow,
      ai.agent_id,
      ai.organization_id,
      ai.data,
      ai.inserted_at,
      ai.updated_at,
      agents.hostname,
      organizations.name AS organization_name
    FROM ai_inventory ai
    LEFT JOIN agents ON agents.id = ai.agent_id
    LEFT JOIN organizations ON organizations.id = ai.organization_id
    WHERE #{where_org}
      (
        ai.data ? 'artifact_type'
        OR ai.data ? 'file_hash'
        OR ai.component_type IN ('dev_tool', 'prompt_artifact', 'skill_artifact', 'mcp_server', 'model_file')
        OR lower(coalesce(ai.name, '') || ' ' || coalesce(ai.install_path, '') || ' ' || coalesce(ai.data::text, '')) ~
          '(codex|claude|cursor|windsurf|mcp|skill)'
      )
    ORDER BY ai.updated_at DESC NULLS LAST, ai.inserted_at DESC NULLS LAST
    LIMIT 500
    """

    case Ecto.Adapters.SQL.query(Repo, sql, params) do
      {:ok, result} ->
        result.rows
        |> Enum.map(fn row -> result.columns |> Enum.zip(row) |> Map.new() end)
        |> Enum.map(&serialize_ai_artifact_row/1)

      {:error, error} ->
        Logger.warning("Failed to load AI artifact inventory: #{inspect(error)}")
        []
    end
  rescue
    error ->
      Logger.warning("AI artifact inventory query failed: #{Exception.message(error)}")
      []
  end

  defp serialize_ai_artifact_row(row) do
    data = Map.get(row, "data") || %{}
    matched_patterns = artifact_field(data, "matched_patterns", [])
    risk_score = Map.get(row, "risk_score") || 0
    risk_level = Map.get(row, "risk_level") || risk_level_from_score(risk_score)

    %{
      id: Map.get(row, "id"),
      source: infer_ai_artifact_source(row, data),
      name: Map.get(row, "name") || "AI artifact",
      component_type: Map.get(row, "component_type"),
      artifact_type: artifact_field(data, "artifact_type", Map.get(row, "component_type")),
      file_hash: artifact_field(data, "file_hash", nil),
      redacted_preview: artifact_field(data, "redacted_preview", nil),
      matched_patterns: matched_patterns,
      risk_score: risk_score,
      risk_level: risk_level,
      severity: ai_artifact_severity(risk_level, matched_patterns),
      policy_status: to_string(Map.get(row, "policy_status") || "unknown"),
      is_shadow: Map.get(row, "is_shadow") || false,
      agent_id: Map.get(row, "agent_id"),
      agent_hostname: Map.get(row, "hostname") || artifact_field(data, "hostname", nil),
      organization_id: Map.get(row, "organization_id"),
      organization_name: Map.get(row, "organization_name"),
      version: Map.get(row, "version"),
      install_path: Map.get(row, "install_path"),
      config_path: artifact_field(data, "config_path", nil),
      discovered_at: format_datetime(artifact_field(data, "discovered_at", nil)),
      inserted_at: format_datetime(Map.get(row, "inserted_at")),
      updated_at: format_datetime(Map.get(row, "updated_at"))
    }
  end

  defp artifact_field(data, key, default) when is_map(data) do
    safe_string_or_atom_field(data, key, default)
  end

  defp artifact_field(_, _, default), do: default

  defp infer_ai_artifact_source(row, data) do
    haystack =
      [
        Map.get(row, "name"),
        Map.get(row, "component_type"),
        Map.get(row, "install_path"),
        artifact_field(data, "artifact_type", nil),
        artifact_field(data, "config_path", nil)
      ]
      |> Enum.reject(&is_nil/1)
      |> Enum.join(" ")
      |> String.downcase()

    cond do
      String.contains?(haystack, "codex") -> "Codex"
      String.contains?(haystack, "claude") -> "Claude"
      String.contains?(haystack, "cursor") -> "Cursor"
      String.contains?(haystack, "windsurf") -> "Windsurf"
      String.contains?(haystack, "mcp") -> "MCP"
      String.contains?(haystack, "skill") -> "Skills"
      true -> "AI"
    end
  end

  defp ai_artifact_severity("critical", _), do: "critical"
  defp ai_artifact_severity("high", _), do: "high"

  defp ai_artifact_severity(_, patterns) when is_list(patterns) do
    cond do
      Enum.any?(
        patterns,
        &(&1 in ["secret_exfiltration", "network_exfiltration", "approval_bypass"])
      ) and length(patterns) >= 2 ->
        "critical"

      Enum.any?(patterns, &(&1 in ["secret_exfiltration", "approval_bypass", "git_tampering"])) ->
        "high"

      length(patterns) > 0 ->
        "medium"

      true ->
        "low"
    end
  end

  defp ai_artifact_severity(_, _), do: "low"

  defp risk_level_from_score(score) when score >= 75, do: "critical"
  defp risk_level_from_score(score) when score >= 50, do: "high"
  defp risk_level_from_score(score) when score >= 25, do: "medium"
  defp risk_level_from_score(_), do: "low"

  defp build_ai_artifact_stats(artifacts) do
    by_source =
      artifacts
      |> Enum.group_by(& &1.source)
      |> Enum.map(fn {source, entries} -> %{source: source, count: length(entries)} end)

    %{
      total: length(artifacts),
      with_hash: Enum.count(artifacts, & &1.file_hash),
      high_or_critical: Enum.count(artifacts, &(&1.severity in ["high", "critical"])),
      matched_patterns:
        artifacts |> Enum.flat_map(& &1.matched_patterns) |> Enum.uniq() |> length(),
      by_source: by_source
    }
  end

  # MCP Servers
  def mcp_servers(conn, _params) do
    mcp_alive? = Process.whereis(MCPServer) != nil
    catalog_tools = MCPServer.tool_catalog()
    catalog_providers = MCPServer.context_provider_catalog()

    # Get available tools from MCPServer module
    {tools_data, tools_error} =
      mcp_safe_call("list_tools", catalog_tools, fn ->
        MCPServer.list_tools()
      end)

    tools = normalize_mcp_tools(tools_data || [])
    tools = if tools == [] and catalog_tools != [], do: normalize_mcp_tools(catalog_tools), else: tools

    # Get context providers
    {providers_data, providers_error} =
      mcp_safe_call("list_context_providers", catalog_providers, fn ->
        MCPServer.list_context_providers()
      end)

    context_providers = normalize_mcp_context_providers(providers_data || [])

    context_providers =
      if context_providers == [] and catalog_providers != [] do
        normalize_mcp_context_providers(catalog_providers)
      else
        context_providers
      end

    # Get server stats
    {stats, stats_error} =
      mcp_safe_call("get_stats", %{}, fn ->
        MCPServer.get_stats()
      end)

    # Get audit log for connection logs
    {audit_entries, audit_error} =
      mcp_safe_call("get_audit_log", [], fn ->
        MCPServer.get_audit_log(limit: 50)
      end)

    connection_logs =
      Enum.map(audit_entries || [], fn entry ->
        %{
          id: entry[:id],
          clientId: entry[:client_id],
          method: entry[:method],
          status: entry[:result_status],
          durationMs: entry[:duration_ms],
          ipAddress: entry[:ip_address],
          timestamp: format_datetime(entry[:timestamp])
        }
      end)

    total_requests = stats[:total_requests] || 0
    successful_requests = stats[:successful_requests] || 0
    failed_requests = stats[:failed_requests] || 0
    actions_executed = stats[:actions_executed] || 0
    health_errors = Enum.reject([tools_error, providers_error, stats_error, audit_error], &is_nil/1)

    mcp_status =
      cond do
        mcp_alive? and health_errors == [] -> "active"
        tools != [] -> "disconnected"
        true -> "error"
      end

    health_message =
      cond do
        not mcp_alive? and tools != [] -> "MCPServer process is not running; showing static tool catalog"
        not mcp_alive? -> "MCPServer process is not running in this boot profile"
        health_errors != [] -> Enum.join(health_errors, "; ")
        true -> "MCP server is running"
      end

    # Build server info (MCP is a single server endpoint)
    servers = [
      %{
        id: "tamandua-mcp",
        name: "Tamandua MCP Server",
        endpoint: "/api/v1/mcp/rpc",
        status: mcp_status,
        healthMessage: health_message,
        tools: tools,
        toolCount: length(tools),
        contextProviderCount: length(context_providers),
        totalRequests: total_requests,
        successRate:
          if total_requests > 0 do
            Float.round(successful_requests / total_requests * 100, 1)
          else
            if mcp_status == "active", do: 100.0, else: 0.0
          end,
        errorsToday:
          if mcp_status == "active" do
            failed_requests
          else
            max(failed_requests, 1)
          end,
        startedAt: format_datetime(stats[:started_at])
      }
    ]

    render_inertia(conn, "MCPServers", %{
      page_title: "MCP Servers",
      servers: servers,
      tools: tools,
      contextProviders: context_providers,
      connectionLogs: connection_logs,
      stats: %{
        totalServers: 1,
        connectedServers: if(mcp_status == "active", do: 1, else: 0),
        totalTools: length(tools),
        requestsToday: total_requests,
        totalRequests: total_requests,
        successfulRequests: successful_requests,
        failedRequests: failed_requests,
        actionsExecuted: actions_executed,
        mcpAlive: mcp_alive?,
        healthMessage: health_message
      }
    })
  end

  defp mcp_field(map, key, default \\ nil)
  defp mcp_field(map, key, default) when is_map(map) and is_atom(key) do
    Map.get(map, key) || Map.get(map, Atom.to_string(key)) || default
  end

  defp mcp_field(_map, _key, default), do: default

  defp normalize_mcp_tools(tools_data) do
    tools_data
    |> Enum.map(fn tool ->
      %{
        name: mcp_field(tool, :name),
        description: mcp_field(tool, :description, ""),
        inputSchema: mcp_field(tool, :input_schema) || mcp_field(tool, :inputSchema) || %{},
        requiredPermissions:
          mcp_field(tool, :required_permissions) || mcp_field(tool, :requiredPermissions) || []
      }
    end)
    |> Enum.reject(&is_nil(&1.name))
  end

  defp normalize_mcp_context_providers(providers_data) do
    providers_data
    |> Enum.map(fn provider ->
      %{
        name: mcp_field(provider, :name),
        description: mcp_field(provider, :description),
        type: mcp_field(provider, :type),
        status: mcp_field(provider, :status),
        resourceCount: mcp_field(provider, :resource_count) || mcp_field(provider, :resourceCount),
        parameters: mcp_field(provider, :parameters, %{})
      }
    end)
    |> Enum.reject(&is_nil(&1.name))
  end

  defp mcp_safe_call(operation, fallback, fun) when is_function(fun, 0) do
    case fun.() do
      {:ok, data} ->
        {data, nil}

      other ->
        {fallback, "#{operation} returned #{inspect(other)}"}
    end
  rescue
    exception ->
      Logger.warning("MCPServer.#{operation} failed: #{Exception.message(exception)}")
      {fallback, "#{operation} failed: #{Exception.message(exception)}"}
  catch
    kind, reason ->
      Logger.warning("MCPServer.#{operation} failed: #{kind} #{inspect(reason)}")
      {fallback, "#{operation} failed: #{inspect(kind)} #{inspect(reason)}"}
  end

  # Phishing Triage
  def phishing_triage(conn, _params) do
    # Get stats from PhishingTriage module
    stats =
      try do
        case PhishingTriage.get_stats() do
          s when is_map(s) -> s
          _ -> %{}
        end
      catch
        kind, reason ->
          Logger.warning("PhishingTriage.get_stats failed: #{kind} #{inspect(reason)}")
          %{}
      end

    # Build verdict history from stats - as array of VerdictHistory objects
    verdict_history = [
      %{
        id: "malicious",
        verdict: "malicious",
        count: stats[:malicious_detected] || 0,
        percentage: calculate_percentage(stats[:malicious_detected], stats[:total_analyzed])
      },
      %{
        id: "suspicious",
        verdict: "suspicious",
        count: stats[:suspicious_detected] || 0,
        percentage: calculate_percentage(stats[:suspicious_detected], stats[:total_analyzed])
      },
      %{
        id: "benign",
        verdict: "benign",
        count: stats[:benign_resolved] || 0,
        percentage: calculate_percentage(stats[:benign_resolved], stats[:total_analyzed])
      }
    ]

    # Frontend expects reporterStats as an array of ReporterStats objects
    reporter_stats = [
      %{
        id: "overall",
        reporterId: "all_reporters",
        totalReported: stats[:total_analyzed] || 0,
        falsePositives: stats[:false_positives] || 0,
        falseNegatives: stats[:false_negatives] || 0,
        avgConfidence: stats[:avg_confidence] || 0.0,
        accuracyRate: calculate_accuracy_rate(stats)
      }
    ]

    # Frontend expects reportedEmails as an array of ReportedEmail objects
    reported_emails =
      try do
        case PhishingTriage.list_reported_emails(limit: 50) do
          {:ok, list} when is_list(list) ->
            Enum.map(list, fn email ->
              %{
                id: email[:id] || UUID.uuid4(),
                subject: email[:subject] || "No Subject",
                sender: email[:sender] || "unknown@example.com",
                recipient: email[:recipient] || "",
                reportedBy: email[:reported_by] || "",
                reportedAt: format_datetime(email[:reported_at]),
                status: email[:status] || "pending",
                verdict: email[:verdict]
              }
            end)

          _ ->
            []
        end
      catch
        kind, reason ->
          Logger.warning("PhishingTriage.list_reported_emails failed: #{kind} #{inspect(reason)}")
          []
      end

    # Frontend expects classifications as an array of AIClassification objects
    classifications =
      try do
        case PhishingTriage.list_classifications(limit: 50) do
          {:ok, list} when is_list(list) ->
            Enum.map(list, fn cls ->
              %{
                id: cls[:id] || UUID.uuid4(),
                emailId: cls[:email_id],
                verdict: cls[:verdict] || "unknown",
                confidence: cls[:confidence] || 0.0,
                indicators: cls[:indicators] || [],
                analysisDetails: cls[:analysis_details] || %{},
                classifiedAt: format_datetime(cls[:classified_at])
              }
            end)

          _ ->
            []
        end
      catch
        kind, reason ->
          Logger.warning("PhishingTriage.list_classifications failed: #{kind} #{inspect(reason)}")
          []
      end

    render_inertia(conn, "PhishingTriage", %{
      page_title: "Phishing Triage",
      reportedEmails: reported_emails,
      classifications: classifications,
      verdictHistory: verdict_history,
      reporterStats: reporter_stats,
      stats: %{
        totalAnalyzed: stats[:total_analyzed] || 0,
        maliciousDetected: stats[:malicious_detected] || 0,
        suspiciousDetected: stats[:suspicious_detected] || 0,
        benignResolved: stats[:benign_resolved] || 0,
        avgConfidence: Float.round((stats[:avg_confidence] || 0.0) * 100, 1)
      }
    })
  end

  defp calculate_percentage(_count, 0), do: 0.0
  defp calculate_percentage(nil, _total), do: 0.0

  defp calculate_percentage(count, total) when is_number(count) and is_number(total) do
    Float.round(count / total * 100, 1)
  end

  def email_security(conn, _params) do
    alias TamanduaServer.EmailSecurity.{Microsoft365, GoogleWorkspace, EmailCorrelator}

    # Get integration statuses
    m365_status =
      try do
        case Microsoft365.get_status() do
          {:ok, status} -> status
          _ -> %{connected: false, enabled: false}
        end
      rescue
        _ -> %{connected: false, enabled: false}
      end

    google_status =
      try do
        case GoogleWorkspace.get_status() do
          {:ok, status} -> status
          _ -> %{connected: false, enabled: false}
        end
      rescue
        _ -> %{connected: false, enabled: false}
      end

    # Get correlator stats
    correlator_stats =
      try do
        EmailCorrelator.get_stats()
      rescue
        _ -> %{}
      end

    # Get triage stats
    triage_stats =
      try do
        case PhishingTriage.get_stats() do
          s when is_map(s) -> s
          _ -> %{}
        end
      rescue
        _ -> %{}
      end

    # Get recent attack chains
    attack_chains =
      try do
        case EmailCorrelator.list_attack_chains(limit: 10, min_severity: :medium) do
          {:ok, chains} -> Enum.map(chains, &serialize_attack_chain/1)
          _ -> []
        end
      rescue
        _ -> []
      end

    render_inertia(conn, "EmailSecurity", %{
      page_title: "Email Security",
      integrations: %{
        microsoft365: %{
          connected: m365_status[:connected] || false,
          enabled: m365_status[:enabled] || false,
          tenantId: m365_status[:tenant_id],
          lastPoll: format_datetime(m365_status[:last_poll]),
          stats: m365_status[:stats] || %{}
        },
        googleWorkspace: %{
          connected: google_status[:connected] || false,
          enabled: google_status[:enabled] || false,
          adminEmail: google_status[:admin_email],
          lastPoll: format_datetime(google_status[:last_poll]),
          stats: google_status[:stats] || %{}
        }
      },
      stats: %{
        emailsAnalyzed: triage_stats[:total_analyzed] || 0,
        phishingDetected: triage_stats[:malicious_detected] || 0,
        suspiciousFlagged: triage_stats[:suspicious_detected] || 0,
        attackChainsBuilt: correlator_stats[:chains_built] || 0,
        attachmentsTracked: correlator_stats[:attachments_tracked] || 0,
        payloadsExecuted: correlator_stats[:processes_correlated] || 0
      },
      attackChains: attack_chains
    })
  end

  defp serialize_attack_chain(chain) do
    %{
      id: chain[:id] || chain.id,
      emailId: chain[:email_id] || chain.email_id,
      email: %{
        sender: get_in(chain, [:email, :sender]) || get_in(chain, ["email", "sender"]),
        recipient: get_in(chain, [:email, :recipient]) || get_in(chain, ["email", "recipient"]),
        subject: get_in(chain, [:email, :subject]) || get_in(chain, ["email", "subject"]),
        timestamp:
          format_datetime(
            get_in(chain, [:email, :timestamp]) || get_in(chain, ["email", "timestamp"])
          ),
        verdict: get_in(chain, [:email, :verdict]) || get_in(chain, ["email", "verdict"]),
        threatType:
          get_in(chain, [:email, :threat_type]) || get_in(chain, ["email", "threat_type"])
      },
      stagesCompleted: chain[:stages_completed] || chain.stages_completed,
      riskScore: chain[:risk_score] || chain.risk_score,
      severity: chain[:severity] || chain.severity,
      builtAt: format_datetime(chain[:built_at] || chain.built_at),
      timeline:
        Enum.map(chain[:timeline] || chain.timeline || [], fn event ->
          %{
            stage: event[:stage] || event.stage,
            timestamp: format_datetime(event[:timestamp] || event.timestamp),
            description: event[:description] || event.description
          }
        end)
    }
  end

  defp calculate_accuracy_rate(stats) do
    total = stats[:total_analyzed] || 0
    false_positives = stats[:false_positives] || 0
    false_negatives = stats[:false_negatives] || 0

    if total > 0 do
      Float.round((total - false_positives - false_negatives) / total * 100, 1)
    else
      100.0
    end
  end

  # Determine the status of a SIEM integration based on circuit breaker state
  defp determine_siem_integration_status(integration) do
    cond do
      not integration.enabled -> "disabled"
      integration.circuit_breaker && integration.circuit_breaker.state == :open -> "error"
      integration.circuit_breaker && integration.circuit_breaker.failure_count > 0 -> "warning"
      true -> "connected"
    end
  end

  # Serializers

  defp serialize_agent(nil), do: nil

  defp serialize_agent(agent) when is_map(agent) do
    # Handle both database Agent structs and Registry maps
    id = Map.get(agent, :id) || Map.get(agent, :agent_id)
    last_seen = Map.get(agent, :last_seen_at) || Map.get(agent, :updated_at)
    # Status can be atom from ETS (:online) or string from DB ("offline")
    status =
      case normalize_dashboard_agent_status(agent) do
        :online -> "online"
        :offline -> "offline"
        :isolated -> "isolated"
        :degraded -> "degraded"
      end

    health_status =
      id
      |> agent_health_status_for_display(status)
      |> serialize_agent_health_status()

    %{
      id: id,
      hostname: agent.hostname,
      ip_address: Map.get(agent, :ip_address, ""),
      os_type: agent.os_type,
      os_version: agent.os_version,
      agent_version: agent.agent_version,
      status: status,
      health_status: health_status,
      isolated: Map.get(agent, :isolated, false) || status == "isolated",
      certificate_fingerprint: Map.get(agent, :certificate_fingerprint),
      certificate_subject: Map.get(agent, :certificate_subject),
      certificate_valid_until: format_datetime(Map.get(agent, :certificate_valid_until)),
      last_seen: format_datetime(last_seen)
    }
  end

  defp serialize_agent_health_status(%{} = detail) do
    %{
      status: detail |> Map.get(:status, :unknown) |> to_string(),
      reasons: detail |> Map.get(:reasons, []) |> Enum.map(&to_string/1),
      metrics: Map.get(detail, :metrics, %{})
    }
  end

  defp serialize_agent_health_status(_), do: %{status: "unknown", reasons: [], metrics: %{}}

  defp agent_health_status_for_display(_agent_id, status) when status in ["offline", :offline] do
    %{status: :unknown, reasons: [:offline], metrics: %{}}
  end

  defp agent_health_status_for_display(agent_id, _status),
    do: TamanduaServer.Agents.Registry.get_agent_health_status_detail(agent_id)

  defp get_alert_response_actions(nil, _alert_id), do: []

  defp get_alert_response_actions(org_id, alert_id) do
    Response.list_actions(%{organization_id: org_id, alert_id: alert_id})
    |> Enum.map(&serialize_response_action/1)
  rescue
    e ->
      Logger.warning(
        "Failed to list response actions for alert #{alert_id}: #{Exception.message(e)}"
      )

      []
  end

  defp serialize_response_action(action) do
    %{
      id: action.id,
      action_type: action.action_type,
      status: action.status,
      parameters: action.parameters || %{},
      result: action.result || %{},
      error_message: action.error_message,
      executed_at: format_datetime(action.executed_at),
      created_at: format_datetime(action.inserted_at),
      executed_by_id: action.executed_by_id
    }
  end

  # SECURITY: Return empty list if no org_id to prevent data leakage
  # In production, all routes should require authentication with org_id
  defp list_agents_for_dashboard(nil), do: []

  defp list_agents_for_dashboard(org_id) do
    Agents.list_all_for_org(org_id)
  rescue
    e in [DBConnection.ConnectionError, Postgrex.Error] ->
      Logger.warning("Failed to list agents for dashboard: #{Exception.message(e)}")
      []
  catch
    :exit, reason ->
      Logger.warning("Failed to list agents for dashboard: exit #{inspect(reason)}")
      []
  end

  defp get_data_source_health_for_agents(agents) do
    agents
    |> Enum.map(& &1.id)
    |> TamanduaServer.Telemetry.data_source_health_for_agents()
  rescue
    e ->
      Logger.warning("Failed to calculate agent data source health: #{Exception.message(e)}")
      %{}
  end

  # Multi-tenant scoped agent getter - returns agent only if it belongs to org
  # SECURITY: Return nil if no org_id to prevent data leakage
  defp get_agent_for_org(nil, _agent_id), do: nil

  defp get_agent_for_org(org_id, agent_id) do
    case Agents.get_agent_for_org(org_id, agent_id) do
      {:ok, agent} -> agent
      {:error, :not_found} -> nil
    end
  end

  # Multi-tenant scoped alert getter - returns alert only if it belongs to org
  # SECURITY: Return nil if no org_id to prevent data leakage
  defp get_alert_for_org(nil, _alert_id), do: nil
  defp get_alert_for_org(org_id, alert_id), do: Alerts.get_alert_for_org(org_id, alert_id)

  defp public_web_url(conn) do
    Application.get_env(:tamandua_server, :public_url) ||
      System.get_env("TAMANDUA_PUBLIC_URL") ||
      "#{conn.scheme}://#{conn.host}"
  end

  defp public_agent_socket_url(conn) do
    configured =
      Application.get_env(:tamandua_server, :agent_public_url) ||
        System.get_env("AGENT_PUBLIC_URL") ||
        System.get_env("TAMANDUA_AGENT_PUBLIC_URL")

    configured || default_agent_socket_url(conn.host)
  end

  defp public_binary_base_url(conn) do
    Application.get_env(:tamandua_server, :agent_binary_base_url) ||
      System.get_env("AGENT_BINARY_BASE_URL") ||
      System.get_env("TAMANDUA_AGENT_BINARY_BASE_URL") ||
      public_web_url(conn)
  end

  defp binary_download_url(nil, _filename), do: nil

  defp binary_download_url(base_url, filename) do
    base_url
    |> String.trim_trailing("/")
    |> Kernel.<>("/downloads/agents/#{filename}")
  end

  defp binary_download_url_if_present(base_url, filename) do
    path =
      :tamandua_server
      |> :code.priv_dir()
      |> Path.join("static/downloads/agents/#{filename}")

    if File.regular?(path), do: binary_download_url(base_url, filename), else: nil
  end

  defp default_agent_socket_url("tamandua.treantlab.org"),
    do: "wss://agents.tamandua.treantlab.org:8443/socket/agent"

  defp default_agent_socket_url("localhost"), do: "ws://localhost:4000/socket/agent"
  defp default_agent_socket_url("127.0.0.1"), do: "ws://127.0.0.1:4000/socket/agent"
  defp default_agent_socket_url(host), do: "wss://agents.#{host}:8443/socket/agent"

  # SECURITY: Return zeros if no org_id to prevent data leakage
  # In production, all routes should require authentication with org_id
  defp dashboard_agent_counts(nil, _repo) do
    {0, 0, 0, 0, 0}
  end

  defp dashboard_agent_counts(org_id, _repo) do
    try do
      agents = Agents.list_all_for_org(org_id)

      counts =
        Enum.reduce(
          agents,
          %{total: 0, online: 0, degraded: 0, offline: 0, isolated: 0},
          fn agent, acc ->
            status = normalize_dashboard_agent_status(agent)

            acc
            |> Map.update!(:total, &(&1 + 1))
            |> Map.update!(status, &(&1 + 1))
          end
        )

      {counts.total, counts.online, counts.degraded, counts.offline, counts.isolated}
    rescue
      e ->
        Logger.warning(
          "Failed to get organization agent counts for #{org_id}: #{Exception.message(e)}"
        )

        {0, 0, 0, 0, 0}
    end
  end

  defp normalize_dashboard_agent_status(agent) do
    cond do
      Map.get(agent, :status) in [:isolated, "isolated"] ->
        :isolated

      Map.get(agent, :status) in [:offline, "offline"] ->
        :offline

      degraded_agent?(agent) ->
        :degraded

      true ->
        :online
    end
  end

  defp degraded_agent?(agent) do
    agent_id = Map.get(agent, :id) || Map.get(agent, :agent_id)

    case TamanduaServer.Agents.Registry.get_agent_health_status(agent_id) do
      :degraded -> true
      :critical -> true
      _ -> false
    end
  end

  defp serialize_alert(alert) do
    detection_metadata = Map.get(alert, :detection_metadata) || %{}
    source = alert_source(alert, detection_metadata)

    %{
      id: alert.id,
      agentId: alert.agent_id,
      severity: alert.severity,
      title: alert.title,
      description: alert.description,
      status: alert.status,
      threatScore: Map.get(alert, :threat_score),
      enrichment: Map.get(alert, :enrichment, %{}),
      source: source,
      detectionMetadata: detection_metadata,
      sourceEventId: Map.get(alert, :source_event_id),
      mitreTactics: alert.mitre_tactics || [],
      mitreTechniques: alert.mitre_techniques || [],
      createdAt: format_datetime(alert.inserted_at),
      # Enhanced fields for correlation and investigation
      evidence: Map.get(alert, :evidence, %{}),
      iocs: extract_alert_iocs(alert),
      processChain: serialize_process_chain(Map.get(alert, :process_chain, []))
    }
  end

  defp alert_source(alert, detection_metadata) do
    Map.get(alert, :source) ||
      get_any(detection_metadata, [
        "source",
        :source,
        "detection_source",
        :detection_source,
        "detection_type",
        :detection_type
      ])
  end

  defp extract_alert_iocs(alert) do
    evidence = Map.get(alert, :evidence) || %{}
    manifest = Map.get(alert, :public_manifest) || %{}

    []
    |> add_manifest_iocs(manifest)
    |> add_evidence_iocs(evidence)
    |> dedupe_iocs()
  rescue
    e ->
      Logger.warning(
        "Failed to extract IOCs for alert #{inspect(Map.get(alert, :id))}: #{Exception.message(e)}"
      )

      []
  end

  defp add_manifest_iocs(iocs, manifest) when is_map(manifest) do
    manifest_iocs =
      get_any(manifest, ["iocs", :iocs, "indicators", :indicators, "public_iocs", :public_iocs]) ||
        []

    iocs ++ Enum.flat_map(List.wrap(manifest_iocs), &normalize_ioc(&1, "manifest"))
  end

  defp add_manifest_iocs(iocs, _manifest), do: iocs

  defp add_evidence_iocs(iocs, evidence) when is_map(evidence) do
    iocs
    |> add_ioc_collection(
      get_any(evidence, ["iocs", :iocs, "indicators", :indicators]),
      "evidence"
    )
    |> add_file_hash_iocs(get_any(evidence, ["file_hashes", :file_hashes]))
    |> add_network_iocs(get_any(evidence, ["network", :network]))
    |> add_process_iocs(get_any(evidence, ["process", :process]))
    |> add_file_iocs(get_any(evidence, ["file", :file]))
    |> add_dns_iocs(get_any(evidence, ["dns", :dns]))
  end

  defp add_evidence_iocs(iocs, _evidence), do: iocs

  defp add_ioc_collection(iocs, nil, _source), do: iocs

  defp add_ioc_collection(iocs, values, source) do
    iocs ++ Enum.flat_map(List.wrap(values), &normalize_ioc(&1, source))
  end

  defp add_file_hash_iocs(iocs, nil), do: iocs

  defp add_file_hash_iocs(iocs, hashes) do
    iocs ++
      Enum.flat_map(List.wrap(hashes), fn hash ->
        [
          normalize_ioc(
            %{type: "hash", value: get_any(hash, ["sha256", :sha256]), source: "sha256"},
            "evidence"
          ),
          normalize_ioc(
            %{type: "hash", value: get_any(hash, ["sha1", :sha1]), source: "sha1"},
            "evidence"
          ),
          normalize_ioc(
            %{type: "hash", value: get_any(hash, ["md5", :md5]), source: "md5"},
            "evidence"
          ),
          normalize_ioc(
            %{type: "file_path", value: get_any(hash, ["path", :path]), source: "file"},
            "evidence"
          )
        ]
        |> List.flatten()
      end)
  end

  defp add_network_iocs(iocs, nil), do: iocs

  defp add_network_iocs(iocs, values) do
    iocs ++
      Enum.flat_map(List.wrap(values), fn net ->
        [
          normalize_ioc(
            %{
              type: get_any(net, ["type", :type]) || "ip",
              value: get_any(net, ["value", :value]),
              source: get_any(net, ["direction", :direction]) || "network"
            },
            "evidence"
          ),
          normalize_ioc(
            %{
              type: "ip",
              value:
                get_any(net, [
                  "remote_ip",
                  :remote_ip,
                  "dst_ip",
                  :dst_ip,
                  "resolved_ip",
                  :resolved_ip
                ]),
              source: "network"
            },
            "evidence"
          ),
          normalize_ioc(
            %{
              type: "domain",
              value: get_any(net, ["domain", :domain, "host", :host]),
              source: "network"
            },
            "evidence"
          ),
          normalize_ioc(
            %{type: "url", value: get_any(net, ["url", :url]), source: "network"},
            "evidence"
          )
        ]
        |> List.flatten()
      end)
  end

  defp add_process_iocs(iocs, nil), do: iocs

  defp add_process_iocs(iocs, process) do
    (iocs ++
       [
         normalize_ioc(
           %{
             type: "hash",
             value: get_any(process, ["sha256", :sha256, "hash", :hash]),
             source: "process"
           },
           "evidence"
         ),
         normalize_ioc(
           %{
             type: "file_path",
             value: get_any(process, ["path", :path, "image_path", :image_path]),
             source: "process"
           },
           "evidence"
         )
       ])
    |> List.flatten()
  end

  defp add_file_iocs(iocs, nil), do: iocs

  defp add_file_iocs(iocs, file) do
    (iocs ++
       [
         normalize_ioc(
           %{type: "file_path", value: get_any(file, ["path", :path]), source: "file"},
           "evidence"
         ),
         normalize_ioc(
           %{
             type: "hash",
             value: get_any(file, ["sha256", :sha256, "hash", :hash]),
             source: "file"
           },
           "evidence"
         )
       ])
    |> List.flatten()
  end

  defp add_dns_iocs(iocs, nil), do: iocs

  defp add_dns_iocs(iocs, dns) do
    iocs ++
      Enum.flat_map(List.wrap(dns), fn entry ->
        [
          normalize_ioc(
            %{
              type: "domain",
              value: get_any(entry, ["query", :query, "domain", :domain, "name", :name]),
              source: "dns"
            },
            "evidence"
          ),
          normalize_ioc(
            %{
              type: "ip",
              value: get_any(entry, ["resolved_ip", :resolved_ip, "answer", :answer]),
              source: "dns"
            },
            "evidence"
          )
        ]
        |> List.flatten()
      end)
  end

  defp normalize_ioc(nil, _fallback_source), do: []

  defp normalize_ioc(value, fallback_source) when is_binary(value) do
    normalize_ioc(%{value: value}, fallback_source)
  end

  defp normalize_ioc(value, fallback_source) when is_map(value) do
    raw_value =
      get_any(value, ["value", :value, "ioc", :ioc, "indicator", :indicator, "hash", :hash])

    type = normalize_ioc_type(get_any(value, ["type", :type, "ioc_type", :ioc_type]), raw_value)

    case normalize_ioc_value(raw_value) do
      nil ->
        []

      ioc_value ->
        [
          %{
            type: type,
            value: ioc_value,
            source: get_any(value, ["source", :source]) || fallback_source,
            confidence: get_any(value, ["confidence", :confidence]),
            tlp: get_any(value, ["tlp", :tlp]) || "clear",
            blockable: type in ["ip", "domain"],
            redacted: get_any(value, ["redacted", :redacted]) || false
          }
        ]
    end
  end

  defp normalize_ioc(_value, _fallback_source), do: []

  defp get_any(nil, _keys), do: nil

  defp get_any(map, keys) when is_map(map) do
    Enum.find_value(keys, fn key -> Map.get(map, key) end)
  end

  defp get_any(_value, _keys), do: nil

  defp normalize_ioc_value(nil), do: nil

  defp normalize_ioc_value(value) when is_binary(value) do
    value = String.trim(value)
    if value == "" or value in ["unknown", "n/a", "-"], do: nil, else: value
  end

  defp normalize_ioc_value(value), do: value |> to_string() |> normalize_ioc_value()

  defp normalize_ioc_type(type, value) do
    normalized =
      type
      |> to_string()
      |> String.downcase()
      |> String.replace("-", "_")

    cond do
      normalized in ["ip", "ipv4", "ipv6", "remote_ip", "dst_ip"] ->
        "ip"

      normalized in ["domain", "dns", "hostname", "host"] ->
        "domain"

      normalized in ["url", "uri"] ->
        "url"

      normalized in ["email", "mail"] ->
        "email"

      normalized in ["path", "file", "file_path", "filepath"] ->
        "file_path"

      normalized in ["hash", "sha256", "sha1", "md5"] ->
        "hash"

      is_binary(value) and String.starts_with?(value, ["http://", "https://"]) ->
        "url"

      is_binary(value) and Regex.match?(~r/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i, value) ->
        "hash"

      is_binary(value) and Regex.match?(~r/^\d{1,3}(\.\d{1,3}){3}$/, value) ->
        "ip"

      is_binary(value) and String.contains?(value, ".") ->
        "domain"

      true ->
        "file_path"
    end
  end

  defp dedupe_iocs(iocs) do
    iocs
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq_by(fn ioc -> {ioc.type, String.downcase(to_string(ioc.value))} end)
  end

  defp serialize_public_proof(proof) when is_map(proof) do
    metadata = proof[:detection_metadata] || %{}
    mitre = proof[:mitre_techniques] || []

    %{
      id: proof[:id],
      type:
        Map.get(metadata, "attestation_type") || Map.get(metadata, :attestation_type) ||
          "incident",
      severity: proof[:severity],
      manifest_hash: Map.get(metadata, "manifest_hash") || Map.get(metadata, :manifest_hash),
      mitre_id: List.first(mitre),
      mitre_techniques: mitre,
      family: Map.get(metadata, "malware_family") || Map.get(metadata, :malware_family),
      ioc_count: Map.get(metadata, "ioc_count") || Map.get(metadata, :ioc_count) || 0,
      slot: Map.get(metadata, "slot") || Map.get(metadata, :slot),
      tx_hash: proof[:blockchain_tx_id],
      status: "verified",
      timestamp: datetime_to_unix_ms(proof[:blockchain_attested_at]),
      solscan_url: solscan_url(proof[:blockchain_tx_id])
    }
  end

  defp serialize_bounty_submission(submission) do
    %{
      id: submission.id,
      type: normalize_contribution_type(submission),
      ruleName: submission.title || submission.description || submission.type,
      status: normalize_contribution_status(submission.status),
      solReward: 0,
      rank: nil,
      submittedAt: datetime_to_unix_ms(submission.inserted_at),
      contributor_wallet: submission.contributor_wallet,
      bounty_eligibility: submission.bounty_eligibility,
      benchmark_testable: Map.get(submission, :benchmark_testable),
      validation_results: Map.get(submission, :validation_results) || %{},
      techniques_covered: Map.get(submission, :techniques_covered) || [],
      inserted_at: format_datetime(submission.inserted_at),
      updated_at: format_datetime(submission.updated_at)
    }
  end

  defp serialize_bounty_leaderboard_entry(entry) do
    lamports = entry[:total_lamports] || 0

    %{
      rank: entry[:rank],
      wallet: entry[:wallet],
      submissions: entry[:submission_count] || 0,
      accepted: entry[:submission_count] || 0,
      totalEarned: lamports / 1_000_000_000,
      total_lamports: lamports,
      total_sol: lamports / 1_000_000_000,
      submission_count: entry[:submission_count] || 0,
      last_payment: format_datetime(entry[:last_payment])
    }
  end

  defp submission_to_available_bounty(submission) do
    validation = submission.validation_results || %{}

    %{
      id: submission.id,
      category: submission.type,
      tier: "paid",
      solAmount: 0,
      title: submission.ruleName,
      description: "Validated contribution eligible for bounty review",
      author: submission.contributor_wallet || "unknown",
      coverageTags: submission.techniques_covered || [],
      fpRisk:
        Map.get(validation, "false_positive_rate") || Map.get(validation, :false_positive_rate) ||
          0,
      validationScore: Map.get(validation, "score") || Map.get(validation, :score) || 0
    }
  end

  defp solscan_url(nil), do: nil
  defp solscan_url(tx_id), do: "https://solscan.io/tx/#{tx_id}?cluster=devnet"

  defp normalize_contribution_type(submission) do
    payload = Map.get(submission, :payload) || %{}

    case submission.type do
      type when type in ["sigma", "yara", "config"] -> type
      "rule" -> Map.get(payload, "rule_type") || Map.get(payload, :rule_type) || "sigma"
      "ioc" -> "config"
      _ -> "config"
    end
  end

  defp normalize_contribution_status("validated"), do: "accepted"
  defp normalize_contribution_status("accepted"), do: "accepted"
  defp normalize_contribution_status("rejected"), do: "rejected"
  defp normalize_contribution_status(_), do: "in_review"

  defp datetime_to_unix_ms(nil), do: nil
  defp datetime_to_unix_ms(%DateTime{} = dt), do: DateTime.to_unix(dt, :millisecond)

  defp datetime_to_unix_ms(%NaiveDateTime{} = dt) do
    dt
    |> DateTime.from_naive!("Etc/UTC")
    |> DateTime.to_unix(:millisecond)
  end

  defp serialize_process_chain(nil), do: []

  defp serialize_process_chain(chain) when is_list(chain) do
    chain
    |> Enum.with_index()
    |> Enum.map(fn {process, idx} ->
      %{
        pid: process_value(process, [:pid, "pid", :process_id, "process_id"]),
        ppid: process_value(process, [:ppid, "ppid", :parent_pid, "parent_pid"]),
        name: process_value(process, [:name, "name", :process_name, "process_name"]),
        path: process_value(process, [:path, "path", :image_path, "image_path", :process_path, "process_path"]),
        cmdline:
          process_value(process, [
            :cmdline,
            "cmdline",
            :command_line,
            "command_line",
            :command,
            "command",
            :process_command_line,
            "process_command_line"
          ]),
        sha256: process[:sha256] || process["sha256"],
        is_signed: process[:is_signed] || process["is_signed"],
        signer: process[:signer] || process["signer"],
        is_elevated: process[:is_elevated] || process["is_elevated"],
        user: process[:user] || process["user"],
        start_time: format_datetime(process[:start_time] || process["start_time"]),
        level: idx,
        is_malicious: process[:is_malicious] || process["is_malicious"] || false
      }
    end)
  end

  defp serialize_process_chain(_), do: []

  defp process_value(process, keys) when is_map(process) do
    Enum.find_value(keys, fn key -> Map.get(process, key) end)
  end

  defp process_value(_, _), do: nil

  defp format_datetime(nil), do: nil
  defp format_datetime(dt) when is_binary(dt), do: dt
  defp format_datetime(%NaiveDateTime{} = dt), do: NaiveDateTime.to_iso8601(dt)
  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)

  defp format_datetime(unix_ms) when is_integer(unix_ms) do
    case DateTime.from_unix(unix_ms, :millisecond) do
      {:ok, datetime} -> DateTime.to_iso8601(datetime)
      {:error, _} -> nil
    end
  end

  defp format_datetime(_), do: nil

  defp json_safe(value), do: json_safe(value, 0)

  defp json_safe(_value, depth) when depth > 6, do: nil
  defp json_safe(nil, _depth), do: nil
  defp json_safe(value, _depth) when is_boolean(value) or is_number(value), do: value

  defp json_safe(value, _depth) when is_binary(value) do
    if String.length(value) > 4_096 do
      String.slice(value, 0, 4_096) <> "...[truncated]"
    else
      value
    end
  end

  defp json_safe(%DateTime{} = value, _depth), do: DateTime.to_iso8601(value)
  defp json_safe(%NaiveDateTime{} = value, _depth), do: NaiveDateTime.to_iso8601(value)
  defp json_safe(%Decimal{} = value, _depth), do: Decimal.to_string(value)

  defp json_safe(value, depth) when is_list(value) do
    value
    |> Enum.take(100)
    |> Enum.map(&json_safe(&1, depth + 1))
  end

  defp json_safe(value, depth) when is_map(value) do
    value
    |> Enum.take(100)
    |> Enum.reduce(%{}, fn {key, item}, acc ->
      Map.put(acc, json_key(key), json_safe(item, depth + 1))
    end)
  end

  defp json_safe(value, _depth) when is_atom(value), do: Atom.to_string(value)
  defp json_safe(value, _depth), do: inspect(value, limit: 20)

  defp json_key(key) when is_atom(key), do: Atom.to_string(key)
  defp json_key(key) when is_binary(key), do: key
  defp json_key(key), do: to_string(key)

  defp serialize_process_node(node) do
    %{
      pid: node.pid,
      ppid: node.ppid,
      name: node.name,
      path: node.path,
      cmdline: node.cmdline,
      user: node.user,
      startTime: node.start_time,
      sha256: node.sha256,
      isElevated: node.is_elevated,
      isSigned: node.is_signed,
      signer: node.signer,
      childCount: node[:child_count] || length(node.children || []),
      children: Enum.map(node.children || [], &serialize_process_node/1),
      detections: Enum.map(node.detections || [], &serialize_detection/1),
      cpuUsage: node[:cpu_usage],
      memoryBytes: node[:memory_bytes],
      companyName: node[:company_name],
      fileDescription: node[:file_description],
      productName: node[:product_name],
      fileVersion: node[:file_version],
      entropy: node[:entropy]
    }
  end

  defp serialize_detection(detection) do
    %{
      type: detection.type,
      ruleName: detection.rule_name,
      confidence: detection.confidence,
      description: detection.description,
      mitreTactics: detection.mitre_tactics || [],
      mitreTechniques: detection.mitre_techniques || []
    }
  end

  defp serialize_response_action(action) do
    %{
      id: action.id,
      agentId: action.agent_id,
      actionType: action.action_type,
      parameters: action.parameters || %{},
      status: action.status,
      result: action.result,
      errorMessage: action.error_message,
      executedAt: format_datetime(action.executed_at),
      createdAt: format_datetime(action.inserted_at)
    }
  end

  defp serialize_incident(incident, alert_cluster) do
    %{
      id: incident[:alert_ids] |> List.first() |> to_string(),
      alertIds: incident[:alert_ids] || [],
      eventCount: incident[:event_count] || 0,
      severity: incident[:severity] || "medium",
      rootCause: serialize_root_cause(incident[:root_cause]),
      attackChain: Enum.map(incident[:attack_chain] || [], &serialize_attack_chain_entry/1),
      timeline: incident[:timeline] || [],
      mitreCoverage: incident[:mitre_coverage] || %{},
      affectedAssets: incident[:affected_assets] || [],
      recommendations: incident[:recommended_actions] || [],
      alerts: Enum.map(alert_cluster, &serialize_alert/1),
      createdAt: format_datetime(DateTime.utc_now())
    }
  end

  defp serialize_root_cause(nil), do: nil

  defp serialize_root_cause(event) do
    %{
      eventType: event[:event_type],
      timestamp: format_datetime(event[:timestamp]),
      summary: event[:payload]["name"] || event[:payload][:name] || "Unknown",
      agentId: event[:agent_id]
    }
  end

  defp serialize_attack_chain_entry(entry) do
    %{
      timestamp: format_datetime(entry.timestamp),
      eventType: entry.event_type,
      summary: entry.summary,
      mitreTactics: entry.mitre_tactics || [],
      mitreTechniques: entry.mitre_techniques || [],
      severity: entry.severity
    }
  end

  defp serialize_forensic_collection(collection) do
    %{
      id: collection.id,
      agentId: collection.agent_id,
      type: collection.type,
      status: collection.status,
      artifacts: collection.artifacts || [],
      artifactsCollected:
        Enum.map(collection.artifacts_collected || [], fn artifact ->
          %{
            id: artifact[:id] || artifact["id"],
            type: artifact[:type] || artifact["type"],
            name: artifact[:name] || artifact["name"],
            size: artifact[:size] || artifact["size"],
            hash: artifact[:hash] || artifact["hash"]
          }
        end),
      evidenceChain:
        Enum.map(collection.evidence_chain || [], fn entry ->
          %{
            action: entry.action,
            timestamp: format_datetime(entry.timestamp),
            user: entry.user,
            notes: entry.notes
          }
        end),
      createdAt: format_datetime(collection.created_at),
      createdBy: collection.created_by
    }
  end

  defp serialize_asset(asset) do
    critical_vuln_count = asset_value(asset, :critical_vuln_count) || 0
    vulnerability_count = asset_value(asset, :vulnerability_count) || 0
    agent_id = asset_value(asset, :agent_id)

    %{
      id: asset_value(asset, :id),
      agentId: agent_id,
      hostname: asset_value(asset, :hostname),
      type: normalize_asset_type(asset_value(asset, :asset_type)),
      os:
        Enum.reject([asset_value(asset, :os_type), asset_value(asset, :os_version)], &is_nil/1)
        |> Enum.join(" "),
      ip: List.first(asset_value(asset, :ip_addresses) || []) || "-",
      fqdn: asset_value(asset, :fqdn),
      osType: asset_value(asset, :os_type),
      osVersion: asset_value(asset, :os_version),
      architecture: asset_value(asset, :architecture),
      ipAddresses: asset_value(asset, :ip_addresses) || [],
      macAddresses: asset_value(asset, :mac_addresses) || [],
      domain: asset_value(asset, :domain),
      lastSeen: format_datetime(asset_value(asset, :last_seen)),
      firstSeen: format_datetime(asset_value(asset, :first_seen)),
      riskScore: asset_value(asset, :risk_score),
      criticality: asset_value(asset, :criticality),
      securityPosture: asset_value(asset, :security_posture) || %{},
      vulnerabilityCount: vulnerability_count,
      criticalVulnCount: critical_vuln_count,
      vulnerabilities: %{
        critical: critical_vuln_count,
        high: max(vulnerability_count - critical_vuln_count, 0),
        medium: 0,
        low: 0
      },
      tags: asset_value(asset, :tags) || [],
      businessUnit: asset_value(asset, :business_unit),
      owner: asset_value(asset, :owner) || asset_value(asset, :business_unit) || "-",
      department: asset_value(asset, :business_unit) || "-",
      location: asset_value(asset, :cloud_region) || "-",
      discoveryStatus: if(asset_managed?(asset), do: "managed", else: "discovered"),
      agentStatus: if(agent_id, do: "installed", else: "not_installed"),
      environment: asset_value(asset, :environment),
      assetType: asset_value(asset, :asset_type),
      cpuModel: asset_value(asset, :cpu_model),
      cpuCores: asset_value(asset, :cpu_cores),
      memoryGb: asset_value(asset, :memory_gb),
      isVirtual: asset_value(asset, :is_virtual),
      cloudProvider: asset_value(asset, :cloud_provider),
      cloudRegion: asset_value(asset, :cloud_region)
    }
  end

  defp asset_managed?(asset), do: not is_nil(asset_value(asset, :agent_id))

  defp asset_value(asset, key) do
    get_any(asset, [key, Atom.to_string(key)])
  end

  defp normalize_asset_type(nil), do: "server"

  defp normalize_asset_type(type)
       when type in ["server", "workstation", "laptop", "network", "cloud", "database"],
       do: type

  defp normalize_asset_type(_type), do: "server"

  defp serialize_playbook(playbook) do
    execution_count = playbook.execution_count || 0
    success_count = playbook.success_count || 0
    trigger_conditions = playbook.trigger_conditions || %{}

    status =
      cond do
        not playbook.enabled -> "disabled"
        execution_count == 0 -> "draft"
        true -> "active"
      end

    success_rate =
      if execution_count > 0 do
        Float.round(success_count / execution_count * 100, 1)
      else
        0.0
      end

    %{
      id: playbook.id,
      name: playbook.name,
      description: playbook.description || "",
      category: Map.get(trigger_conditions, "category", "custom"),
      status: status,
      triggerType: playbook.trigger_type,
      trigger_type: playbook.trigger_type,
      triggerConditions: Map.keys(trigger_conditions),
      trigger: %{
        type: playbook.trigger_type || "manual",
        conditions: Enum.map(trigger_conditions, fn {key, value} -> %{field: key, value: value} end)
      },
      steps: playbook.steps || [],
      enabled: playbook.enabled,
      executionCount: execution_count,
      successRate: success_rate,
      lastExecuted: format_datetime(playbook.last_executed_at),
      createdAt: format_datetime(playbook.inserted_at),
      updatedAt: format_datetime(playbook.updated_at),
      createdBy: playbook.created_by || "system"
    }
  end

  defp serialize_workflow(workflow) do
    execution_count = workflow.execution_count || 0
    success_count = workflow.success_count || 0

    %{
      id: workflow.id,
      name: workflow.name,
      description: workflow.description || "",
      triggerType: workflow.trigger_type,
      triggerConditions: workflow.trigger_config |> workflow_trigger_conditions(),
      steps: workflow.steps || [],
      isEnabled: workflow.enabled,
      enabled: workflow.enabled,
      executions: %{
        total: execution_count,
        successful: success_count,
        failed: max(execution_count - success_count, 0),
        avgDuration: workflow.avg_duration_seconds || 0
      },
      lastExecuted: format_datetime(workflow.last_executed_at),
      createdAt: format_datetime(workflow.inserted_at),
      updatedAt: format_datetime(workflow.updated_at),
      createdBy: workflow.created_by || "system"
    }
  end

  defp workflow_trigger_conditions(%{"conditions" => conditions}) when is_list(conditions), do: conditions
  defp workflow_trigger_conditions(config) when is_map(config), do: Enum.map(config, fn {key, value} -> "#{key}: #{inspect(value)}" end)
  defp workflow_trigger_conditions(_), do: []

  defp serialize_vulnerability(vuln) do
    %{
      id: vuln[:id],
      cveId: vuln[:cve_id],
      title: vuln[:title],
      severity: vuln[:severity],
      cvssScore: vuln[:cvss_score],
      affectedAssets: vuln[:affected_assets] || [],
      exploitability: vuln[:exploitability],
      remediationPriority: vuln[:remediation_priority]
    }
  end

  defp serialize_crown_jewel(jewel) do
    %{
      id: jewel[:id],
      name: jewel[:name],
      type: jewel[:type],
      criticality: jewel[:criticality],
      riskScore: jewel[:risk_score],
      attackPaths: jewel[:attack_paths] || []
    }
  end

  defp serialize_collab_event(event) do
    %{
      id: event.id,
      platform: event.platform,
      eventType: event.event_type,
      timestamp: format_datetime(event.timestamp),
      userId: event.user_id,
      userEmail: event.user_email,
      userName: event.user_name,
      channelId: event.channel_id,
      channelName: event.channel_name,
      riskScore: event.risk_score,
      riskFactors: event.risk_factors || []
    }
  end

  defp serialize_collab_policy(policy) do
    %{
      id: policy.id,
      name: policy.name,
      enabled: policy.enabled,
      allowedDomains: policy.allowed_domains || [],
      blockedDomains: policy.blocked_domains || [],
      allowExternalUsers: policy.allow_external_users,
      allowGuestAccess: policy.allow_guest_access,
      requireApproval: policy.require_approval,
      maxExternalSharesPerDay: policy.max_external_shares_per_day,
      blockSensitiveFiles: policy.block_sensitive_files,
      notifyOnExternalShare: policy.notify_on_external_share
    }
  end

  # =============================================================================
  # EDR Validation & Benchmark
  # =============================================================================

  def validation_dashboard(conn, _params) do
    alias TamanduaServer.Validation.EDRTester
    alias TamanduaServer.Agents.Registry

    # Get available tests
    tests =
      try do
        case EDRTester.get_available_tests() do
          {:ok, list} when is_list(list) ->
            list

          other ->
            Logger.warning("EDRTester.get_available_tests returned unexpected: #{inspect(other)}")
            []
        end
      catch
        kind, reason ->
          Logger.warning("EDRTester.get_available_tests failed: #{kind} #{inspect(reason)}")
          []
      end

    # Get stats
    stats =
      try do
        case EDRTester.get_stats() do
          {:ok, s} when is_map(s) ->
            s

          other ->
            Logger.warning("EDRTester.get_stats returned unexpected: #{inspect(other)}")
            %{}
        end
      catch
        kind, reason ->
          Logger.warning("EDRTester.get_stats failed: #{kind} #{inspect(reason)}")
          %{}
      end

    # Get connected agents
    agents =
      try do
        case Registry.list_all() do
          list when is_list(list) ->
            Enum.map(list, fn a ->
              %{
                id: a.agent_id,
                hostname: a.hostname,
                status: a.status,
                os: a[:os_type],
                lastSeen: format_datetime(a[:last_seen_at] || a[:last_seen])
              }
            end)

          other ->
            Logger.warning("Registry.list_all returned unexpected: #{inspect(other)}")
            []
        end
      catch
        kind, reason ->
          Logger.warning("Registry.list_all failed: #{kind} #{inspect(reason)}")
          []
      end

    # Group tests by category
    tests_by_category =
      tests
      |> Enum.group_by(& &1.category)
      |> Enum.map(fn {cat, items} ->
        %{
          category: cat,
          categoryName: category_display_name(cat),
          tests: items,
          count: length(items)
        }
      end)

    render_inertia(conn, "ValidationDashboard", %{
      page_title: "EDR Validation",
      tests: tests,
      testsByCategory: tests_by_category,
      agents: agents,
      stats: %{
        totalTestsRun: stats[:total_tests_run] || 0,
        totalDetections: stats[:total_detections] || 0,
        agentsTested: stats[:agents_tested_count] || 0,
        detectionRate: stats[:detection_rate] || 0.0,
        techniquesAvailable: stats[:techniques_available] || 0,
        lastTestRun: format_datetime(stats[:last_test_run])
      },
      priorityLevels: [
        %{id: "critical", name: "Critical", color: "#ef4444"},
        %{id: "high", name: "High", color: "#f97316"},
        %{id: "medium", name: "Medium", color: "#eab308"},
        %{id: "low", name: "Low", color: "#22c55e"}
      ]
    })
  end

  def validation_benchmark(conn, _params) do
    alias TamanduaServer.Validation.EDRTester

    # Get benchmark comparison
    comparison =
      try do
        case EDRTester.get_benchmark_comparison() do
          {:ok, c} when is_map(c) ->
            c

          other ->
            Logger.warning(
              "EDRTester.get_benchmark_comparison returned unexpected: #{inspect(other)}"
            )

            %{}
        end
      catch
        kind, reason ->
          Logger.warning("EDRTester.get_benchmark_comparison failed: #{kind} #{inspect(reason)}")
          %{}
      end

    competitors =
      try do
        case EDRTester.get_industry_baselines() do
          {:ok, baselines} when is_list(baselines) and length(baselines) > 0 -> baselines
          _ -> []
        end
      catch
        kind, reason ->
          Logger.warning("EDRTester.get_industry_baselines failed: #{kind} #{inspect(reason)}")
          []
      end

    # Tamandua's current rates (from testing)
    tamandua_rates = comparison[:tamandua] || %{}

    tamandua = %{
      id: "tamandua",
      name: "Tamandua EDR",
      overall: calculate_overall_rate(tamandua_rates),
      categories:
        Enum.map(tamandua_rates, fn {k, v} -> {k, Float.round(v * 100, 1)} end) |> Enum.into(%{})
    }

    render_inertia(conn, "ValidationBenchmark", %{
      page_title: "Detection Benchmark",
      tamandua: tamandua,
      competitors: competitors,
      strengths: comparison[:strengths] || [],
      weaknesses: comparison[:weaknesses] || [],
      recommendations: comparison[:recommendations] || [],
      categories: [
        %{id: "execution", name: "Execution", mitreTacticId: "TA0002"},
        %{id: "persistence", name: "Persistence", mitreTacticId: "TA0003"},
        %{id: "defense_evasion", name: "Defense Evasion", mitreTacticId: "TA0005"},
        %{id: "credential_access", name: "Credential Access", mitreTacticId: "TA0006"},
        %{id: "discovery", name: "Discovery", mitreTacticId: "TA0007"},
        %{id: "lateral_movement", name: "Lateral Movement", mitreTacticId: "TA0008"},
        %{id: "collection", name: "Collection", mitreTacticId: "TA0009"},
        %{id: "command_control", name: "Command & Control", mitreTacticId: "TA0011"},
        %{id: "exfiltration", name: "Exfiltration", mitreTacticId: "TA0010"},
        %{id: "impact", name: "Impact", mitreTacticId: "TA0040"}
      ]
    })
  end

  defp category_display_name(:execution), do: "Execution"
  defp category_display_name(:persistence), do: "Persistence"
  defp category_display_name(:privilege_escalation), do: "Privilege Escalation"
  defp category_display_name(:defense_evasion), do: "Defense Evasion"
  defp category_display_name(:credential_access), do: "Credential Access"
  defp category_display_name(:discovery), do: "Discovery"
  defp category_display_name(:lateral_movement), do: "Lateral Movement"
  defp category_display_name(:collection), do: "Collection"
  defp category_display_name(:command_control), do: "Command & Control"
  defp category_display_name(:exfiltration), do: "Exfiltration"
  defp category_display_name(:impact), do: "Impact"
  defp category_display_name(other), do: to_string(other) |> String.capitalize()

  defp calculate_overall_rate(rates) when map_size(rates) == 0, do: 0.0

  defp calculate_overall_rate(rates) do
    values = Map.values(rates)

    if length(values) > 0 do
      Float.round(Enum.sum(values) / length(values) * 100, 1)
    else
      0.0
    end
  end

  # Case Investigations Hub (for manual investigation cases)
  def investigation_hub(conn, params) do
    alias TamanduaServer.Investigations
    alias TamanduaServer.Accounts

    # Get filters from params
    status_filter = params["status"]
    severity_filter = params["severity"]
    assignee_filter = params["assigned_to"]
    search_query = params["search"]

    opts =
      [
        status: status_filter,
        severity: severity_filter,
        assigned_to: assignee_filter,
        search: search_query,
        limit: 50
      ]
      |> Enum.reject(fn {_k, v} -> is_nil(v) || v == "" end)

    # Get investigations
    investigations = Investigations.list_investigations(opts)
    stats = Investigations.get_stats()

    # Get users for assignee dropdown
    users =
      try do
        current_user = conn.assigns[:current_user]
        org_id = current_user && current_user.organization_id

        if org_id do
          Accounts.list_users(org_id)
          |> Enum.map(fn user ->
            %{
              id: user.id,
              name: user.name || user.email,
              email: user.email
            }
          end)
        else
          []
        end
      rescue
        _ -> []
      end

    render_inertia(conn, "InvestigationHub", %{
      page_title: "Investigations",
      investigations: Enum.map(investigations, &serialize_case_investigation/1),
      stats: stats,
      users: users,
      filters: %{
        status: status_filter,
        severity: severity_filter,
        assigned_to: assignee_filter,
        search: search_query
      },
      statuses: ["open", "in_progress", "closed", "archived"],
      severities: ["critical", "high", "medium", "low", "info"]
    })
  end

  def investigation_case_detail(conn, %{"id" => id}) do
    alias TamanduaServer.Investigations
    alias TamanduaServer.Accounts

    current_user = conn.assigns[:current_user]
    org_id = current_user && current_user.organization_id

    case Investigations.get_investigation(id) do
      {:ok, investigation} ->
        # Get linked alerts (org-scoped)
        linked_alerts =
          if investigation.alert_ids && length(investigation.alert_ids) > 0 do
            investigation.alert_ids
            |> Enum.map(fn alert_id ->
              case get_alert_for_org(org_id, alert_id) do
                {:ok, alert} -> serialize_alert(alert)
                _ -> nil
              end
            end)
            |> Enum.filter(& &1)
          else
            []
          end

        # Get users for assignment
        users =
          try do
            if org_id do
              Accounts.list_users(org_id)
              |> Enum.map(fn user ->
                %{
                  id: user.id,
                  name: user.name || user.email,
                  email: user.email
                }
              end)
            else
              []
            end
          rescue
            _ -> []
          end

        render_inertia(conn, "InvestigationCaseDetail", %{
          page_title: investigation.title,
          investigation: serialize_case_investigation(investigation),
          linkedAlerts: linked_alerts,
          users: users,
          statuses: ["open", "in_progress", "closed", "archived"],
          severities: ["critical", "high", "medium", "low", "info"]
        })

      {:error, :not_found} ->
        render_inertia(conn, "NotFound", %{
          page_title: "Investigation Not Found",
          message: "The investigation you're looking for could not be found."
        })
    end
  end

  defp serialize_case_investigation(investigation) do
    %{
      id: investigation.id,
      title: investigation.title,
      description: investigation.description,
      status: investigation.status,
      severity: investigation.severity,
      assignedTo: investigation.assigned_to,
      assignedUser:
        if(investigation.assigned_user,
          do: %{
            id: investigation.assigned_user.id,
            name: investigation.assigned_user.name || investigation.assigned_user.email,
            email: investigation.assigned_user.email
          },
          else: nil
        ),
      createdBy: investigation.created_by,
      creator:
        if(investigation.creator,
          do: %{
            id: investigation.creator.id,
            name: investigation.creator.name || investigation.creator.email,
            email: investigation.creator.email
          },
          else: nil
        ),
      alertIds: investigation.alert_ids || [],
      eventIds: investigation.event_ids || [],
      notes: investigation.notes,
      findings: investigation.findings,
      timeline: investigation.timeline || %{},
      tags: investigation.tags || [],
      mitreTactics: investigation.mitre_tactics || [],
      mitreTechniques: investigation.mitre_techniques || [],
      insertedAt: investigation.inserted_at,
      updatedAt: investigation.updated_at
    }
  end

  # Investigation Graph Hub (for D3.js visualization)
  def investigation_graph(conn, params) do
    alias TamanduaServer.Detection.Correlator

    current_user = conn.assigns[:current_user]
    org_id = current_user && current_user.organization_id

    agents = list_agents_for_dashboard(org_id) |> Enum.map(&serialize_agent/1)

    # Get recent alerts for investigation (multi-tenant scoped)
    recent_alerts = Alerts.list_recent_for_org(org_id, limit: 20) |> Enum.map(&serialize_alert/1)

    # Get agent_id from params or use first online agent
    agent_id =
      params["agent_id"] ||
        case Enum.find(agents, fn a -> a.status == "online" end) do
          nil -> nil
          agent -> agent.id
        end

    # Get recent processes for this agent
    recent_processes =
      if agent_id do
        case Correlator.get_process_tree(agent_id) do
          {:ok, graph} ->
            Graph.vertices(graph)
            |> Enum.map(fn pid ->
              labels = Graph.vertex_labels(graph, pid)
              info = List.first(labels) || %{}

              %{
                pid: pid,
                name: info[:name] || "PID #{pid}",
                path: info[:path],
                cmdline: info[:cmdline]
              }
            end)
            |> Enum.take(50)

          _ ->
            []
        end
      else
        []
      end

    render_inertia(conn, "InvestigationHub", %{
      page_title: "Investigation Hub",
      agents: agents,
      selectedAgentId: agent_id,
      recentAlerts: recent_alerts,
      recentProcesses: recent_processes,
      filters: %{
        timeRanges: ["1h", "6h", "24h", "7d"],
        entityTypes: ["process", "network", "file", "dns", "registry"]
      }
    })
  end

  def investigation_graph_detail(conn, %{"id" => id} = params) do
    current_user = conn.assigns[:current_user]
    org_id = current_user && current_user.organization_id

    # Determine what type of ID this is (alert, event, or process)
    start_type = params["type"] || "alert"
    time_window = parse_investigation_time_window(params["time_range"])

    case start_type do
      "alert" ->
        case get_alert_for_org(org_id, id) do
          {:error, :not_found} ->
            render_investigation_error(conn, id, "Alert not found")

          {:ok, alert} ->
            render_investigation_for_alert(conn, org_id, alert, time_window)
        end

      "process" ->
        agent_id = params["agent_id"]
        pid = parse_int_param(id)

        if agent_id && pid do
          render_investigation_for_process(conn, org_id, agent_id, pid, time_window)
        else
          render_investigation_error(conn, id, "Missing agent_id or invalid pid")
        end

      "event" ->
        render_investigation_for_event(conn, id, time_window)

      _ ->
        render_investigation_error(conn, id, "Unknown investigation type")
    end
  end

  defp render_investigation_for_alert(conn, org_id, alert, time_window) do
    agent = if alert.agent_id, do: get_agent_for_org(org_id, alert.agent_id), else: nil

    render_inertia(conn, "InvestigationGraph", %{
      page_title: "Investigation: #{alert.title}",
      investigationType: "alert",
      investigationId: alert.id,
      alert: serialize_alert(alert),
      agent: serialize_agent(agent),
      timeWindow: time_window,
      apiEndpoint: "/api/v1/investigation/#{alert.id}"
    })
  end

  defp render_investigation_for_process(conn, org_id, agent_id, pid, time_window) do
    agent = get_agent_for_org(org_id, agent_id)

    render_inertia(conn, "InvestigationGraph", %{
      page_title: "Investigation: Process #{pid}",
      investigationType: "process",
      investigationId: "#{agent_id}_#{pid}",
      alert: nil,
      agent: serialize_agent(agent),
      processId: pid,
      agentId: agent_id,
      timeWindow: time_window,
      apiEndpoint: "/api/v1/investigation/process"
    })
  end

  defp render_investigation_for_event(conn, event_id, time_window) do
    render_inertia(conn, "InvestigationGraph", %{
      page_title: "Investigation: Event",
      investigationType: "event",
      investigationId: event_id,
      alert: nil,
      agent: nil,
      eventId: event_id,
      timeWindow: time_window,
      apiEndpoint: "/api/v1/investigation/event"
    })
  end

  defp render_investigation_error(conn, id, error) do
    render_inertia(conn, "InvestigationGraph", %{
      page_title: "Investigation",
      investigationType: "error",
      investigationId: id,
      alert: nil,
      agent: nil,
      error: error
    })
  end

  defp parse_investigation_time_window(nil), do: 60
  defp parse_investigation_time_window("1h"), do: 60
  defp parse_investigation_time_window("6h"), do: 360
  defp parse_investigation_time_window("24h"), do: 1440
  defp parse_investigation_time_window("7d"), do: 10080

  defp parse_investigation_time_window(val) when is_binary(val) do
    case Integer.parse(val) do
      {int, _} -> int
      :error -> 60
    end
  end

  defp parse_investigation_time_window(_), do: 60

  defp parse_int_param(val) when is_integer(val), do: val

  defp parse_int_param(val) when is_binary(val) do
    case Integer.parse(val) do
      {int, _} -> int
      :error -> nil
    end
  end

  defp parse_int_param(_), do: nil

  defp safe_parse_int(nil, default), do: default
  defp safe_parse_int(value, _default) when is_integer(value), do: value

  defp safe_parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> default
    end
  end

  defp safe_parse_int(_, default), do: default

  # Provenance Graph (causal analysis visualization)
  def provenance_graph(conn, _params) do
    current_user = conn.assigns[:current_user]
    org_id = current_user && current_user.organization_id

    agents =
      list_agents_for_dashboard(org_id)
      |> Enum.map(fn a ->
        %{
          id: Map.get(a, :id) || Map.get(a, :agent_id),
          hostname: a.hostname,
          status: to_string(a.status || "unknown")
        }
      end)

    render_inertia(conn, "ProvenanceGraph", %{
      page_title: "Provenance Graph",
      agents: agents
    })
  end

  # Device Control Pages
  def device_control(conn, _params) do
    render_inertia(conn, "DeviceControl", %{
      page_title: "Device Control"
    })
  end

  def device_control_policies(conn, _params) do
    render_inertia(conn, "DeviceControlPolicies", %{
      page_title: "Device Control Policies"
    })
  end

  # RBAC Management Pages
  def rbac_roles(conn, _params) do
    alias TamanduaServer.Authorization.RBAC
    alias TamanduaServer.Accounts.{Role, Permission}
    alias TamanduaServer.Repo

    import Ecto.Query

    org_id = conn.assigns[:current_user].organization_id

    roles =
      from(r in Role,
        where: is_nil(r.organization_id) or r.organization_id == ^org_id,
        order_by: [desc: r.priority, asc: r.name]
      )
      |> Repo.all()
      |> Enum.map(fn role ->
        user_count =
          from(ur in TamanduaServer.Accounts.UserRole,
            where: ur.role_id == ^role.id,
            select: count()
          )
          |> Repo.one()

        %{
          id: role.id,
          name: role.name,
          slug: role.slug,
          description: role.description,
          builtin: role.builtin,
          priority: role.priority,
          color: Map.get(role, :color, "#6366f1"),
          userCount: user_count
        }
      end)

    permission_categories =
      Permission.definitions()
      |> Enum.map(fn {category, perms} ->
        %{
          category: category,
          permissions:
            Enum.map(perms, fn {slug, desc, _cat} ->
              %{slug: slug, description: desc}
            end)
        }
      end)

    # Get role templates and hierarchy
    templates = Role.list_templates()
    hierarchy = Role.role_hierarchy()

    render_inertia(conn, "RBACRoles", %{
      page_title: "Role Management",
      roles: roles,
      permissionCategories: permission_categories,
      builtinRoles: Role.builtin_roles(),
      templates: templates,
      hierarchy: hierarchy
    })
  end

  def rbac_role_detail(conn, %{"id" => role_id}) do
    alias TamanduaServer.Accounts.{Role, Permission, UserRole}
    alias TamanduaServer.Repo

    import Ecto.Query

    org_id = conn.assigns[:current_user].organization_id

    role =
      from(r in Role,
        where: r.id == ^role_id,
        where: is_nil(r.organization_id) or r.organization_id == ^org_id
      )
      |> Repo.one()

    case role do
      nil ->
        conn
        |> put_status(:not_found)
        |> render_inertia("NotFound", %{message: "Role not found"})

      role ->
        permissions =
          if role.builtin do
            role.slug |> String.to_existing_atom() |> Role.default_permissions()
          else
            from(rp in TamanduaServer.Accounts.RolePermission,
              join: p in Permission,
              on: p.id == rp.permission_id,
              where: rp.role_id == ^role.id,
              select: p.slug
            )
            |> Repo.all()
            |> Enum.map(&String.to_existing_atom/1)
          end

        user_count =
          from(ur in UserRole, where: ur.role_id == ^role.id, select: count())
          |> Repo.one()

        render_inertia(conn, "RBACRoleDetail", %{
          page_title: "Role: #{role.name}",
          role: %{
            id: role.id,
            name: role.name,
            slug: role.slug,
            description: role.description,
            builtin: role.builtin,
            priority: role.priority,
            color: Map.get(role, :color, "#6366f1")
          },
          permissions: permissions,
          userCount: user_count,
          allPermissions: Permission.definitions()
        })
    end
  end

  def user_management(conn, _params) do
    alias TamanduaServer.Accounts
    alias TamanduaServer.Accounts.Role
    alias TamanduaServer.Repo
    import Ecto.Query

    org_id = conn.assigns[:current_user].organization_id

    users =
      Accounts.list_users(org_id)
      |> Enum.map(fn user ->
        # Get user_roles to check for expires_at
        user_roles =
          from(ur in TamanduaServer.Accounts.UserRole,
            where: ur.user_id == ^user.id,
            preload: [:role]
          )
          |> Repo.all()

        role_data =
          Enum.map(user_roles, fn ur ->
            %{
              id: ur.role.id,
              slug: ur.role.slug,
              name: ur.role.name,
              expiresAt: ur.expires_at,
              grantedBy: ur.granted_by
            }
          end)

        %{
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
          mfaEnabled: user.mfa_enabled,
          isActive: Map.get(user, :is_active, true),
          lastLoginAt: user.last_login_at,
          roles: role_data
        }
      end)

    # Get all available roles for the organization
    available_roles =
      from(r in Role,
        where: is_nil(r.organization_id) or r.organization_id == ^org_id,
        order_by: [desc: r.priority, asc: r.name]
      )
      |> Repo.all()
      |> Enum.map(fn r ->
        %{
          id: r.id,
          name: r.name,
          slug: r.slug,
          priority: r.priority,
          color: Map.get(r, :color, "#6366f1")
        }
      end)

    render_inertia(conn, "UserManagement", %{
      page_title: "User Management",
      users: users,
      availableRoles: available_roles
    })
  end

  # Admin Tenant Management Pages

  @doc """
  Admin Tenants list page.
  Shows all tenants in the system with stats and filtering.
  Requires system_settings permission.
  """
  def admin_tenants(conn, _params) do
    render_inertia(conn, "admin/Tenants", %{
      page_title: "Tenant Management"
    })
  end

  @doc """
  Admin Tenant creation page.
  Form to create a new tenant/organization.
  Requires system_settings permission.
  """
  def admin_tenant_create(conn, _params) do
    render_inertia(conn, "admin/TenantCreate", %{
      page_title: "Create Tenant"
    })
  end

  @doc """
  Admin Tenant detail page.
  Shows detailed information about a specific tenant including users, API keys, usage stats.
  Requires system_settings permission.
  """
  def admin_tenant_detail(conn, %{"id" => _tenant_id}) do
    render_inertia(conn, "admin/TenantDetail", %{
      page_title: "Tenant Details"
    })
  end

  @doc """
  ML Malware Detection dashboard.
  Shows model status, prediction statistics, and training controls.
  """
  def ml_dashboard(conn, _params) do
    org_id =
      conn.assigns[:current_organization_id] ||
        (conn.assigns[:current_user] && conn.assigns[:current_user].organization_id)

    ml_client_alive? = Process.whereis(TamanduaServer.Detection.ML.Client) != nil
    healthy = ml_client_alive? and safe_ml_service_healthy?()
    model_info = if ml_client_alive?, do: safe_ml_model_info(), else: nil

    # Get detection statistics
    stats = safe_detection_engine_stats()

    # Get recent ML-triggered alerts
    recent_alerts = get_recent_ml_alerts(org_id, 10)

    render_inertia(conn, "MLDashboard", %{
      page_title: "ML Malware Detection",
      service: %{
        healthy: healthy,
        url: System.get_env("ML_SERVICE_URL", "http://localhost:8000")
      },
      model:
        if model_info do
          %{
            version: model_info["model_version"],
            encoder: model_info["encoder"],
            latent_dim: model_info["latent_dim"],
            similarity_markers: model_info["similarity_markers"],
            dissimilarity_markers: model_info["dissimilarity_markers"],
            training_samples: model_info["training_samples"],
            accuracy: model_info["accuracy"],
            zsl_recall: model_info["zsl_recall"],
            device: model_info["device"],
            trained: (model_info["training_samples"] || 0) > 0
          }
        else
          nil
        end,
      statistics: %{
        total_predictions: Map.get(stats, :ml_predictions, 0),
        total_detections: Map.get(stats, :detections, 0),
        alerts_created: Map.get(stats, :alerts_created, 0)
      },
      recent_alerts: recent_alerts,
      recent_predictions: get_recent_ml_predictions(recent_alerts),
      training: %{
        available_datasets: ["synthetic", "telemetry"],
        default_epochs: 50,
        default_batch_size: 32
      }
    })
  end

  defp safe_ml_service_healthy? do
    TamanduaServer.Detection.ML.Client.healthy?()
  rescue
    e ->
      Logger.warning("ML service health check failed: #{Exception.message(e)}")
      false
  catch
    kind, reason ->
      Logger.warning("ML service health check failed: #{inspect(kind)} #{inspect(reason)}")
      false
  end

  defp safe_ml_model_info do
    case TamanduaServer.Detection.ML.Client.model_info() do
      {:ok, info} when is_map(info) ->
        info

      {:ok, _} ->
        nil

      {:error, reason} ->
        Logger.debug("ML model info unavailable: #{inspect(reason)}")
        nil
    end
  rescue
    e ->
      Logger.warning("ML model info failed: #{Exception.message(e)}")
      nil
  catch
    kind, reason ->
      Logger.warning("ML model info failed: #{inspect(kind)} #{inspect(reason)}")
      nil
  end

  defp safe_detection_engine_stats do
    case TamanduaServer.Detection.Engine.get_stats() do
      stats when is_map(stats) -> stats
      _ -> %{}
    end
  rescue
    e ->
      Logger.warning("Detection engine stats failed for ML dashboard: #{Exception.message(e)}")
      %{}
  catch
    kind, reason ->
      Logger.warning(
        "Detection engine stats failed for ML dashboard: #{inspect(kind)} #{inspect(reason)}"
      )

      %{}
  end

  defp get_recent_ml_alerts(nil, _limit), do: []

  defp get_recent_ml_alerts(org_id, limit) do
    import Ecto.Query

    from(a in TamanduaServer.Alerts.Alert,
      where:
        a.organization_id == ^org_id and
          (like(a.title, "ML Detection:%") or
          like(a.title, "Malware detected:%") or
          like(a.title, "Agent detection: OFFLINE_ML%") or
          fragment("?->>'detection_type' = ?", a.detection_metadata, "ml") or
          fragment("?->>'source' = ?", a.detection_metadata, "ml") or
          fragment("?->>'detection_source' = ?", a.detection_metadata, "ml")),
      order_by: [desc: a.inserted_at],
      limit: ^limit
    )
    |> TamanduaServer.Repo.all()
    |> Enum.map(fn alert ->
      %{
        id: alert.id,
        title: alert.title,
        severity: alert.severity,
        agent_id: alert.agent_id,
        threat_score: alert.threat_score,
        detection_metadata: alert.detection_metadata || %{},
        created_at: alert.inserted_at
      }
    end)
  rescue
    e ->
      Logger.warning("get_recent_ml_alerts failed: #{Exception.message(e)}")
      []
  end

  defp get_recent_ml_predictions(alerts) do
    Enum.map(alerts, fn alert ->
      metadata = alert[:detection_metadata] || alert["detection_metadata"] || %{}
      title = alert[:title] || alert["title"] || ""

      %{
        id: alert[:id] || alert["id"],
        alert_id: alert[:id] || alert["id"],
        agent_id: alert[:agent_id] || alert["agent_id"],
        prediction: metadata_field(metadata, "prediction") || prediction_from_ml_title(title),
        malware_family: metadata_field(metadata, "malware_family"),
        model_version: metadata_field(metadata, "model_version") || metadata_field(metadata, "onnx_model_version"),
        confidence: metadata_field(metadata, "confidence"),
        threat_score: alert[:threat_score] || alert["threat_score"],
        timestamp: alert[:created_at] || alert["created_at"] || alert[:inserted_at] || alert["inserted_at"]
      }
    end)
  end

  defp metadata_field(metadata, key) when is_map(metadata) do
    safe_string_or_atom_field(metadata, key, nil)
  end

  defp metadata_field(_metadata, _key), do: nil

  defp safe_string_or_atom_field(map, key, default) when is_map(map) and is_binary(key) do
    cond do
      Map.has_key?(map, key) ->
        Map.get(map, key)

      true ->
        Enum.find_value(map, default, fn
          {map_key, value} when is_atom(map_key) ->
            if Atom.to_string(map_key) == key, do: value, else: false

          _ ->
            false
        end)
    end
  end

  defp safe_string_or_atom_field(map, key, default) when is_map(map) do
    Map.get(map, key, default)
  end

  defp prediction_from_ml_title(title) when is_binary(title) do
    cond do
      String.contains?(String.downcase(title), "malicious") -> "malicious"
      String.contains?(String.downcase(title), "benign") -> "benign"
      true -> "ml_detection"
    end
  end

  defp prediction_from_ml_title(_), do: "ml_detection"

  # ===========================================================================
  # Reports
  # ===========================================================================

  def reports(conn, _params) do
    current_user = conn.assigns[:current_user]
    org_id = current_user && current_user.organization_id

    # Gather real data for the reports page
    templates = [
      %{
        id: "executive_summary",
        name: "Executive Summary",
        description:
          "High-level overview of security posture, key metrics, and critical incidents for leadership review.",
        sections: [
          "Security Score",
          "Critical Incidents",
          "Agent Coverage",
          "Top Threats",
          "Recommendations"
        ]
      },
      %{
        id: "incident_report",
        name: "Incident Report",
        description:
          "Detailed breakdown of security incidents, response actions taken, and resolution timeline.",
        sections: [
          "Incident Timeline",
          "Affected Assets",
          "MITRE ATT&CK Mapping",
          "Response Actions",
          "Lessons Learned"
        ]
      },
      %{
        id: "threat_landscape",
        name: "Threat Landscape",
        description:
          "Analysis of detected threats, attack patterns, and threat actor activity observed in the environment.",
        sections: [
          "Threat Overview",
          "Attack Vectors",
          "IOC Summary",
          "Threat Actor Activity",
          "Trend Analysis"
        ]
      },
      %{
        id: "agent_health",
        name: "Agent Health",
        description:
          "Status and health metrics for all deployed agents, including uptime, version, and coverage gaps.",
        sections: [
          "Agent Status",
          "Version Distribution",
          "Coverage Gaps",
          "Performance Metrics",
          "Offline Agents"
        ]
      },
      %{
        id: "compliance_summary",
        name: "Compliance Summary",
        description:
          "Compliance status against security policies, detection coverage, and audit trail summary.",
        sections: [
          "Policy Compliance",
          "Detection Coverage",
          "Audit Events",
          "Configuration Status",
          "Remediation Items"
        ]
      }
    ]

    # Fetch report history from the API or fallback to empty
    reports =
      try do
        TamanduaServer.Reports.list_history()
      rescue
        e ->
          Logger.warning("Failed to fetch report history: #{Exception.message(e)}")
          []
      catch
        kind, reason ->
          Logger.warning("Failed to fetch report history: #{inspect(kind)} #{inspect(reason)}")
          []
      end

    # Build stats from real modules (multi-tenant scoped)
    total_agents =
      try do
        Agents.count_agents_for_org(org_id)
      rescue
        e ->
          Logger.warning("Failed to count agents for reports page: #{Exception.message(e)}")
          0
      catch
        kind, reason ->
          Logger.warning(
            "Failed to count agents for reports page: #{inspect(kind)} #{inspect(reason)}"
          )

          0
      end

    open_alerts =
      try do
        Alerts.count_active_for_org(org_id)
      rescue
        e ->
          Logger.warning("Failed to count open alerts for reports page: #{Exception.message(e)}")
          0
      catch
        kind, reason ->
          Logger.warning(
            "Failed to count open alerts for reports page: #{inspect(kind)} #{inspect(reason)}"
          )

          0
      end

    total_events =
      try do
        TamanduaServer.Telemetry.count_events_today_for_org(org_id)
      rescue
        e ->
          Logger.warning("Failed to count events for reports page: #{Exception.message(e)}")
          0
      catch
        kind, reason ->
          Logger.warning(
            "Failed to count events for reports page: #{inspect(kind)} #{inspect(reason)}"
          )

          0
      end

    stats = %{
      total_agents: total_agents,
      open_alerts: open_alerts,
      events_today: total_events
    }

    conn
    |> assign(:page_title, "Reports")
    |> render_inertia("Reports", %{
      templates: templates,
      reports: reports,
      stats: stats
    })
  end

  # ===========================================================================
  # Audit Log
  # ===========================================================================

  def audit_log(conn, params) do
    page = params["page"] |> safe_parse_int(1) |> max(1)
    per_page = params["per_page"] |> safe_parse_int(50) |> max(1) |> min(100)

    # Try fetching from audit log service, fallback to empty
    {entries, pagination} =
      try do
        audit_entries =
          TamanduaServer.AuditLog.list_entries(
            page: page,
            per_page: per_page,
            search: Map.get(params, "search"),
            action_type: Map.get(params, "action_type"),
            user: Map.get(params, "user"),
            date_from: Map.get(params, "date_from"),
            date_to: Map.get(params, "date_to")
          )

        entries =
          Enum.map(audit_entries.entries, fn e ->
            %{
              id: e.id,
              timestamp: e.inserted_at,
              user: e.user,
              action: e.action,
              action_type: e.action_type,
              target: e.target || "",
              details: e.details || "",
              ip_address: e.ip_address || ""
            }
          end)

        pagination = %{
          page: audit_entries.page,
          per_page: audit_entries.per_page,
          total: audit_entries.total,
          total_pages: audit_entries.total_pages
        }

        {entries, pagination}
      rescue
        e ->
          Logger.warning("AuditLog.list_entries failed: #{Exception.message(e)}")
          {[], %{page: 1, per_page: 50, total: 0, total_pages: 1}}
      catch
        kind, reason ->
          Logger.warning("AuditLog.list_entries crashed: #{kind} #{inspect(reason)}")
          {[], %{page: 1, per_page: 50, total: 0, total_pages: 1}}
      end

    conn
    |> assign(:page_title, "Audit Log")
    |> render_inertia("AuditLog", %{
      entries: entries,
      pagination: pagination
    })
  end

  # ===========================================================================
  # Identity Protection
  # ===========================================================================

  def identity(conn, _params) do
    alias TamanduaServer.Identity.RiskScoring
    alias TamanduaServer.Identity.AzureAD

    stats_result = safe_identity_call("Identity risk statistics", fn -> RiskScoring.get_statistics() end)

    stats =
      case stats_result do
        {:ok, result} ->
          case result do
            {:ok, s} ->
              %{
                totalUsers: s.total_users,
                highRiskUsers: s.critical_risk + s.high_risk,
                mediumRiskUsers: s.medium_risk,
                riskySignInsToday: 0,
                privilegeChangesToday: 0,
                serviceAccounts: 0,
                averageRiskScore: s.average_score,
                impossibleTravelDetected: 0
              }

            _ ->
              default_identity_stats()
          end

        {:error, _reason} ->
          default_identity_stats()
      end

    high_risk_result =
      safe_identity_call("Identity high risk users", fn ->
        RiskScoring.get_high_risk_users(min_score: 30, limit: 50)
      end)

    high_risk_users =
      case high_risk_result do
        {:ok, result} ->
          case result do
            {:ok, users} ->
              Enum.map(users, fn user ->
                user_id = identity_text(identity_field(user, :user_id), "unknown-user")
                risk_level = normalize_identity_risk_level(identity_field(user, :level, :low))

                %{
                  userId: user_id,
                  userPrincipalName: user_id,
                  displayName: identity_text(identity_field(user, :display_name), user_id),
                  department: identity_field(user, :department),
                  score: identity_number(identity_field(user, :score), 0),
                  level: risk_level,
                  factors:
                    Enum.map(identity_field(user, :factors, []), fn factor ->
                      %{
                        name: identity_text(identity_field(factor, :name), "Risk factor"),
                        contribution: identity_number(identity_field(factor, :contribution), 0),
                        details: identity_text(identity_field(factor, :details), "")
                      }
                    end),
                  trend: normalize_identity_trend(identity_field(user, :trend, :stable)),
                  lastUpdated: format_datetime(identity_field(user, :last_updated)),
                  azureAdRiskLevel:
                    user
                    |> identity_field(:external_signals, %{})
                    |> identity_field(:azure_ad_risk_level),
                  azureAdRiskState:
                    user
                    |> identity_field(:external_signals, %{})
                    |> identity_field(:azure_ad_risk_state)
                }
              end)

            _ ->
              []
          end

        {:error, _reason} ->
          []
      end

    azure_status_result = safe_identity_call("Azure AD status", fn -> AzureAD.status() end)

    # Get risky sign-ins (from Azure AD if configured)
    risky_sign_ins_result =
      case azure_status_result do
        {:ok, %{enabled: true}} ->
          safe_identity_call("Azure AD risky sign-ins", fn ->
            AzureAD.get_sign_ins(limit: 50, status: "failure")
          end)

        {:ok, _status} ->
          {:disabled, []}

        {:error, reason} ->
          {:error, reason}
      end

    risky_sign_ins =
      case risky_sign_ins_result do
        {:ok, result} ->
          case result do
            {:ok, sign_ins} -> Enum.map(sign_ins, &serialize_azure_ad_sign_in/1)
            _ -> []
          end

        _ ->
          []
      end

    # Get privilege changes (from Azure AD if configured)
    privilege_changes_result =
      case azure_status_result do
        {:ok, %{enabled: true}} ->
          safe_identity_call("Azure AD directory audits", fn ->
            AzureAD.get_directory_audits(limit: 20)
          end)

        {:ok, _status} ->
          {:disabled, []}

        {:error, reason} ->
          {:error, reason}
      end

    privilege_changes =
      case privilege_changes_result do
        {:ok, result} ->
          case result do
            {:ok, audits} -> Enum.map(audits, &serialize_azure_ad_audit/1)
            _ -> []
          end

        _ ->
          []
      end

    # Get service accounts (from Azure AD if configured)
    service_accounts_result =
      case azure_status_result do
        {:ok, %{enabled: true}} ->
          safe_identity_call("Azure AD service principals", fn ->
            AzureAD.get_service_principals(limit: 50)
          end)

        {:ok, _status} ->
          {:disabled, []}

        {:error, reason} ->
          {:error, reason}
      end

    service_accounts =
      case service_accounts_result do
        {:ok, result} ->
          case result do
            {:ok, principals} -> Enum.map(principals, &serialize_service_principal/1)
            _ -> []
          end

        _ ->
          []
      end

    stats =
      stats
      |> Map.put(
        :riskySignInsToday,
        identity_count_or_default(risky_sign_ins_result, risky_sign_ins, stats.riskySignInsToday)
      )
      |> Map.put(
        :privilegeChangesToday,
        identity_count_or_default(
          privilege_changes_result,
          privilege_changes,
          stats.privilegeChangesToday
        )
      )
      |> Map.put(
        :serviceAccounts,
        identity_count_or_default(service_accounts_result, service_accounts, stats.serviceAccounts)
      )

    identity_availability = %{
      riskScoring: identity_result_status(stats_result),
      highRiskUsers: identity_result_status(high_risk_result),
      azureAd: azure_status(azure_status_result),
      riskySignIns: identity_result_status(risky_sign_ins_result),
      privilegeChanges: identity_result_status(privilege_changes_result),
      serviceAccounts: identity_result_status(service_accounts_result)
    }

    render_inertia(conn, "Identity", %{
      page_title: "Identity Protection",
      stats: stats,
      highRiskUsers: high_risk_users,
      riskySignIns: risky_sign_ins,
      privilegeChanges: privilege_changes,
      serviceAccounts: service_accounts,
      identityAvailability: identity_availability
    })
  end

  defp safe_identity_call(label, fun) when is_function(fun, 0) do
    {:ok, fun.()}
  rescue
    error ->
      Logger.warning("#{label} failed: #{Exception.message(error)}")
      {:error, Exception.message(error)}
  catch
    :exit, reason ->
      Logger.warning("#{label} failed: exit #{inspect(reason)}")
      {:error, "exit #{inspect(reason)}"}
  end

  defp identity_result_status({:ok, {:ok, _value}}), do: "available"
  defp identity_result_status({:ok, {:error, _reason}}), do: "unavailable"
  defp identity_result_status({:ok, _value}), do: "available"
  defp identity_result_status({:disabled, _value}), do: "disabled"
  defp identity_result_status({:error, _reason}), do: "unavailable"
  defp identity_result_status(_), do: "unavailable"

  defp identity_count_or_default({:ok, {:ok, _value}}, items, _default), do: length(items)
  defp identity_count_or_default({:disabled, _value}, _items, _default), do: 0
  defp identity_count_or_default(_result, _items, default), do: default

  defp azure_status({:ok, %{enabled: true}}), do: "available"
  defp azure_status({:ok, _status}), do: "disabled"
  defp azure_status({:error, _reason}), do: "unavailable"

  defp default_identity_stats do
    %{
      totalUsers: 0,
      highRiskUsers: 0,
      mediumRiskUsers: 0,
      riskySignInsToday: 0,
      privilegeChangesToday: 0,
      serviceAccounts: 0,
      averageRiskScore: 0,
      impossibleTravelDetected: 0
    }
  end

  defp identity_field(value, key, default \\ nil)
  defp identity_field(value, key, default) when is_map(value) and is_atom(key) do
    Map.get(value, key) || Map.get(value, Atom.to_string(key)) || default
  end

  defp identity_field(_value, _key, default), do: default

  defp identity_text(value, default \\ "")
  defp identity_text(value, _default) when is_binary(value), do: value
  defp identity_text(value, _default) when is_atom(value), do: Atom.to_string(value)
  defp identity_text(value, _default) when is_number(value), do: to_string(value)
  defp identity_text(%{} = value, default), do: if(map_size(value) == 0, do: default, else: inspect(value))
  defp identity_text(nil, default), do: default
  defp identity_text(value, _default), do: inspect(value)

  defp identity_number(value, default \\ 0)
  defp identity_number(value, _default) when is_number(value), do: value

  defp identity_number(value, default) when is_binary(value) do
    case Float.parse(value) do
      {number, _rest} -> number
      :error -> default
    end
  end

  defp identity_number(_value, default), do: default

  defp identity_list_length(value) when is_list(value), do: length(value)
  defp identity_list_length(_value), do: 0

  defp normalize_identity_risk_level(value) do
    case value |> identity_text("low") |> String.downcase() do
      level when level in ["critical", "high", "medium", "low", "none"] -> level
      _ -> "low"
    end
  end

  defp normalize_identity_trend(value) do
    case value |> identity_text("stable") |> String.downcase() do
      trend when trend in ["increasing", "decreasing", "stable"] -> trend
      _ -> "stable"
    end
  end

  defp serialize_azure_ad_sign_in(sign_in) do
    status_error_code = get_in(sign_in, ["status", "errorCode"]) || 0

    %{
      id: identity_text(sign_in["id"], "azure-signin-#{System.unique_integer([:positive])}"),
      userPrincipalName: identity_text(sign_in["userPrincipalName"], "unknown-user"),
      userId: identity_text(sign_in["userId"], "unknown-user"),
      timestamp: identity_text(sign_in["createdDateTime"], DateTime.utc_now() |> DateTime.to_iso8601()),
      ipAddress: identity_text(sign_in["ipAddress"], "unknown"),
      location: %{
        city: identity_text(get_in(sign_in, ["location", "city"]), nil),
        state: identity_text(get_in(sign_in, ["location", "state"]), nil),
        country: identity_text(get_in(sign_in, ["location", "countryOrRegion"]), "Unknown")
      },
      appDisplayName: identity_text(sign_in["appDisplayName"], "Unknown application"),
      clientAppUsed: identity_text(sign_in["clientAppUsed"], "unknown"),
      riskLevelDuringSignIn: normalize_identity_risk_level(sign_in["riskLevelDuringSignIn"] || "none"),
      riskState: identity_text(sign_in["riskState"], "unknown"),
      riskDetail: identity_text(sign_in["riskDetail"], nil),
      statusErrorCode: identity_number(status_error_code, 0),
      statusFailureReason: identity_text(get_in(sign_in, ["status", "failureReason"]), nil),
      deviceDetail: %{
        browser: identity_text(get_in(sign_in, ["deviceDetail", "browser"]), "Unknown"),
        operatingSystem: identity_text(get_in(sign_in, ["deviceDetail", "operatingSystem"]), "Unknown"),
        deviceId: identity_text(get_in(sign_in, ["deviceDetail", "deviceId"]), nil)
      },
      conditionalAccessStatus: identity_text(sign_in["conditionalAccessStatus"], "unknown"),
      isInteractive: sign_in["isInteractive"] == true
    }
  end

  defp serialize_azure_ad_audit(audit) do
    %{
      id: identity_text(audit["id"], "azure-audit-#{System.unique_integer([:positive])}"),
      timestamp: identity_text(audit["activityDateTime"], DateTime.utc_now() |> DateTime.to_iso8601()),
      activity: identity_text(audit["activityDisplayName"], "Directory audit event"),
      category: identity_text(audit["category"], "unknown"),
      initiatedBy: %{
        user: normalize_identity_actor(get_in(audit, ["initiatedBy", "user"])),
        app: normalize_identity_actor(get_in(audit, ["initiatedBy", "app"]))
      },
      targetResources: normalize_identity_targets(audit["targetResources"]),
      result: identity_text(audit["result"], "unknown")
    }
  end

  defp serialize_service_principal(principal) do
    %{
      id: identity_text(principal["id"], "service-principal-#{System.unique_integer([:positive])}"),
      displayName: identity_text(principal["displayName"], "Unnamed service principal"),
      appId: identity_text(principal["appId"], "unknown"),
      servicePrincipalType: identity_text(principal["servicePrincipalType"], "unknown"),
      accountEnabled: principal["accountEnabled"] == true,
      createdDateTime: identity_text(principal["createdDateTime"], DateTime.utc_now() |> DateTime.to_iso8601()),
      signInActivity: normalize_service_principal_sign_in(principal["signInActivity"]),
      riskLevel: nil,
      permissionGrantsCount: identity_list_length(principal["oauth2PermissionGrants"])
    }
  end

  defp normalize_identity_actor(actor) when is_map(actor) do
    %{
      "displayName" => identity_text(actor["displayName"], actor[:displayName] || "Unknown"),
      "userPrincipalName" => identity_text(actor["userPrincipalName"], actor[:userPrincipalName] || nil)
    }
  end

  defp normalize_identity_actor(_actor), do: nil

  defp normalize_identity_targets(targets) when is_list(targets) do
    Enum.map(targets, fn target ->
      %{
        "displayName" => identity_text(identity_field(target, :displayName) || identity_field(target, :display_name), "Unknown"),
        "type" => identity_text(identity_field(target, :type), "unknown"),
        "userPrincipalName" => identity_text(identity_field(target, :userPrincipalName) || identity_field(target, :user_principal_name), nil)
      }
    end)
  end

  defp normalize_identity_targets(_targets), do: []

  defp normalize_service_principal_sign_in(activity) when is_map(activity) do
    %{
      "lastSignInDateTime" =>
        identity_text(
          activity["lastSignInDateTime"] || activity[:lastSignInDateTime] ||
            activity["last_sign_in_date_time"] || activity[:last_sign_in_date_time],
          nil
        ),
      "lastSignInRequestId" =>
        identity_text(
          activity["lastSignInRequestId"] || activity[:lastSignInRequestId] ||
            activity["last_sign_in_request_id"] || activity[:last_sign_in_request_id],
          nil
        )
    }
  end

  defp normalize_service_principal_sign_in(_activity), do: %{}

  # ===========================================================================
  # Vulnerability Management
  # ===========================================================================

  def vulnerabilities(conn, _params) do
    render_inertia(conn, "Vulnerabilities", %{
      page_title: "Vulnerability Management"
    })
  end

  def vulnerability_detail(conn, %{"cve_id" => cve_id}) do
    render_inertia(conn, "VulnerabilityDetail", %{
      page_title: cve_id,
      cve_id: cve_id
    })
  end

  # ============================================================================
  # Integrations
  # ============================================================================

  def integrations(conn, _params) do
    alias TamanduaServer.Integrations.Config, as: IntegrationConfig

    # Get available integration types
    integration_types = IntegrationConfig.available_types()

    render_inertia(conn, "Integrations", %{
      page_title: "Integrations",
      integration_types: integration_types
    })
  end

  # ============================================================================
  # XDR (Extended Detection & Response)
  # ============================================================================

  def xdr(conn, _params) do
    alias TamanduaServer.XDR.{Correlator, NormalizedEvent}
    import Ecto.Query

    # Get correlation statistics
    stats =
      try do
        correlator_stats = Correlator.get_stats()

        %{
          correlationsDetected: correlator_stats[:events_correlated] || 0,
          killChainsDetected: correlator_stats[:kill_chains_detected] || 0,
          alertsGenerated: correlator_stats[:alerts_generated] || 0,
          patternsDetected: correlator_stats[:patterns_detected] || 0
        }
      catch
        _kind, _reason ->
          %{
            correlationsDetected: 0,
            killChainsDetected: 0,
            alertsGenerated: 0,
            patternsDetected: 0
          }
      end

    # Get recent XDR events
    events =
      try do
        now = DateTime.utc_now()
        yesterday = DateTime.add(now, -86400, :second)

        from(e in NormalizedEvent,
          where: e.timestamp >= ^yesterday,
          order_by: [desc: e.timestamp],
          limit: 100
        )
        |> TamanduaServer.Repo.all()
        |> Enum.map(fn e ->
          %{
            id: e.id,
            timestamp: DateTime.to_iso8601(e.timestamp),
            sourceType: e.source_type,
            sourceId: e.source_id,
            severity: e.severity || "info",
            category: e.category,
            action: e.action,
            outcome: e.outcome,
            sourceIp: e.source_ip,
            destIp: e.dest_ip,
            user: e.user,
            domain: e.domain,
            url: e.url,
            fileName: e.file_name,
            fileHash: e.file_hash,
            threatName: e.threat_name,
            threatCategory: e.threat_category,
            mitreTechniques: e.mitre_techniques || []
          }
        end)
      rescue
        _ -> []
      end

    # Get XDR sources
    sources =
      try do
        TamanduaServer.Repo.all(TamanduaServer.XDR.Source)
        |> Enum.map(fn s ->
          %{
            id: s.id,
            name: s.name,
            sourceType: s.source_type,
            vendor: s.vendor,
            status: s.status || "unknown",
            lastEventAt: format_datetime(s.last_event_at),
            eventsLastHour: 0,
            eventsLastDay: s.event_count || 0,
            errorCount: s.error_count || 0
          }
        end)
      rescue
        _ -> []
      end

    # Compute aggregated stats
    events_by_source = events |> Enum.frequencies_by(& &1[:sourceType])
    events_by_severity = events |> Enum.frequencies_by(& &1[:severity])

    full_stats =
      Map.merge(stats, %{
        totalSources: length(sources),
        healthySources: Enum.count(sources, &(&1[:status] == "healthy")),
        eventsLast24h: length(events),
        bySourceType: events_by_source,
        bySeverity: events_by_severity
      })

    render_inertia(conn, "XDR", %{
      page_title: "XDR - Extended Detection & Response",
      sources: sources,
      events: events,
      stats: full_stats
    })
  end

  # ============================================================================
  # NDR (Network Detection & Response)
  # ============================================================================

  def ndr(conn, params) do
    alias TamanduaServer.NDR.{FlowAnalyzer, ProtocolAnalyzer, LateralDetector, EncryptedTraffic}

    include_details? = params["include_details"] in ["true", true]

    # Get overall NDR statistics
    stats =
      if include_details? do
        try do
          flow_stats = FlowAnalyzer.get_stats()
          protocol_stats = ProtocolAnalyzer.get_stats()
          lateral_stats = LateralDetector.get_stats()
          encrypted_stats = EncryptedTraffic.get_stats()

          %{
            flow_analyzer: flow_stats,
            protocol_analyzer: protocol_stats,
            lateral_detector: lateral_stats,
            encrypted_traffic: encrypted_stats,
            summary: %{
              total_flows_processed: flow_stats[:flows_processed] || 0,
              total_events_analyzed:
                (protocol_stats[:events_analyzed] || 0) +
                  (lateral_stats[:events_analyzed] || 0) +
                  (encrypted_stats[:events_analyzed] || 0),
              total_anomalies:
                (flow_stats[:anomalies_detected] || 0) +
                  (lateral_stats[:lateral_movements_detected] || 0),
              total_alerts:
                (flow_stats[:alerts_created] || 0) +
                  (protocol_stats[:alerts_created] || 0) +
                  (lateral_stats[:alerts_created] || 0) +
                  (encrypted_stats[:alerts_created] || 0)
            }
          }
        catch
          kind, reason ->
            Logger.warning("NDR stats failed: #{kind} #{inspect(reason)}")
            default_ndr_stats()
        rescue
          e ->
            Logger.warning("NDR stats failed: #{Exception.message(e)}")
            default_ndr_stats()
        end
      else
        default_ndr_stats()
      end

    # Get flow statistics
    flow_stats =
      if include_details? do
        try do
          FlowAnalyzer.get_flow_stats(time_range: :hour)
        catch
          _kind, _reason -> %{}
        rescue
          _ -> %{}
        end
      else
        %{}
      end

    # Get top talkers
    top_talkers =
      if include_details? do
        try do
          FlowAnalyzer.get_top_talkers(limit: 10)
          |> Enum.map(fn t ->
            %{
              ip: t[:ip],
              agent_id: t[:agent_id],
              bytes_sent: t[:bytes_sent] || 0,
              bytes_received: t[:bytes_received] || 0,
              total_bytes: t[:total_bytes] || 0,
              connection_count: t[:connection_count] || 0
            }
          end)
        catch
          _kind, _reason -> []
        rescue
          _ -> []
        end
      else
        []
      end

    # Get protocol distribution
    protocols =
      if include_details? do
        try do
          FlowAnalyzer.get_protocol_distribution([])
        catch
          _kind, _reason -> []
        rescue
          _ -> []
        end
      else
        []
      end

    # Get recent lateral movements
    lateral_movements =
      if include_details? do
        try do
          LateralDetector.get_lateral_movement(limit: 20)
          |> Enum.map(fn m ->
            %{
              type: m[:type],
              src_ip: m[:src_ip],
              dst_ip: m[:dst_ip],
              port: m[:port],
              ports_scanned: m[:ports_scanned],
              hosts_scanned: m[:hosts_scanned],
              username: m[:username],
              timestamp: format_datetime(m[:timestamp])
            }
          end)
        catch
          _kind, _reason -> []
        rescue
          _ -> []
        end
      else
        []
      end

    # Get JA3 stats
    ja3_stats =
      if include_details? do
        try do
          EncryptedTraffic.get_ja3_stats(limit: 20)
          |> Enum.map(fn s ->
            %{
              ja3_hash: s[:ja3_hash],
              occurrence_count: s[:occurrence_count] || 0,
              unique_agents: s[:unique_agents] || 0,
              unique_destinations: s[:unique_destinations] || 0,
              is_malicious: s[:is_malicious] || false,
              malware_info: s[:malware_info],
              first_seen: format_datetime(s[:first_seen]),
              last_seen: format_datetime(s[:last_seen])
            }
          end)
        catch
          _kind, _reason -> []
        rescue
          _ -> []
        end
      else
        []
      end

    # Get network topology
    topology =
      if include_details? do
        try do
          FlowAnalyzer.get_topology([])
        catch
          _kind, _reason -> %{nodes: [], edges: [], summary: %{}}
        rescue
          _ -> %{nodes: [], edges: [], summary: %{}}
        end
      else
        %{nodes: [], edges: [], summary: %{}}
      end

    render_inertia(conn, "NDR", %{
      page_title: "NDR - Network Detection & Response",
      stats: stats,
      flow_stats: flow_stats,
      top_talkers: top_talkers,
      protocols: protocols,
      lateral_movements: lateral_movements,
      ja3_stats: ja3_stats,
      topology: topology
    })
  end

  defp default_ndr_stats do
    %{
      flow_analyzer: %{},
      protocol_analyzer: %{},
      lateral_detector: %{},
      encrypted_traffic: %{},
      summary: %{
        total_flows_processed: 0,
        total_events_analyzed: 0,
        total_anomalies: 0,
        total_alerts: 0
      }
    }
  end

  # ============================================================================
  # Attack Surface Management (ASM)
  # ============================================================================

  def attack_surface(conn, _params) do
    alias TamanduaServer.ASM.{Discovery, Exposure, RiskScoring, Monitor}

    # Get dashboard summary
    dashboard =
      try do
        Discovery.get_dashboard()
      rescue
        _ ->
          %{
            total_assets: 0,
            total_domains: 0,
            discovery_in_progress: false,
            last_discovery: nil
          }
      catch
        _kind, _reason ->
          %{
            total_assets: 0,
            total_domains: 0,
            discovery_in_progress: false,
            last_discovery: nil
          }
      end

    # Get all discovered assets
    assets =
      try do
        Discovery.list_assets([])
        |> Enum.map(fn asset ->
          risk = RiskScoring.calculate_risk(asset[:id] || asset.id)
          exposures = Exposure.get_asset_exposures(asset[:id] || asset.id)

          %{
            id: asset[:id] || asset.id,
            type: asset[:type] || asset.type,
            name: asset[:name] || asset.name,
            domain: asset[:domain] || asset.domain,
            ip: asset[:ip] || asset.ip,
            discovered_at: format_datetime(asset[:discovered_at] || asset.discovered_at),
            last_seen: format_datetime(asset[:last_seen] || asset.last_seen),
            source: asset[:source] || asset.source,
            metadata: asset[:metadata] || asset.metadata || %{},
            risk_score: risk[:score] || 0,
            risk_level: risk[:level] || "unknown",
            exposure_count: length(exposures[:exposures] || []),
            open_ports: length(exposures[:open_ports] || [])
          }
        end)
      rescue
        _ -> []
      catch
        _kind, _reason -> []
      end

    # Get tracked domains
    domains =
      try do
        Discovery.list_domains()
        |> Enum.map(fn domain ->
          %{
            name: domain[:name] || domain.name,
            added_at: format_datetime(domain[:added_at] || domain.added_at),
            asset_count: domain[:asset_count] || 0,
            status: domain[:status] || "active"
          }
        end)
      rescue
        _ -> []
      catch
        _kind, _reason -> []
      end

    # Get top risks
    top_risks =
      try do
        RiskScoring.get_top_risks(limit: 10)
        |> Enum.map(fn risk ->
          %{
            asset_id: risk[:asset_id],
            asset_name: risk[:asset_name],
            score: risk[:score],
            level: risk[:level],
            factors: risk[:factors] || []
          }
        end)
      rescue
        _ -> []
      catch
        _kind, _reason -> []
      end

    # Get risk distribution
    risk_distribution =
      try do
        RiskScoring.get_risk_distribution()
      rescue
        _ -> %{critical: 0, high: 0, medium: 0, low: 0}
      catch
        _kind, _reason -> %{critical: 0, high: 0, medium: 0, low: 0}
      end

    # Get aggregate risk
    aggregate_risk =
      try do
        RiskScoring.get_aggregate_risk()
      rescue
        _ -> %{score: 0, level: "unknown", trend: "stable"}
      catch
        _kind, _reason -> %{score: 0, level: "unknown", trend: "stable"}
      end

    # Get recent changes
    recent_changes =
      try do
        Monitor.get_changes(days: 7, limit: 20)
        |> Enum.map(fn change ->
          %{
            id: change[:id],
            asset_id: change[:asset_id],
            asset_name: change[:asset_name],
            change_type: change[:change_type],
            field: change[:field],
            old_value: change[:old_value],
            new_value: change[:new_value],
            detected_at: format_datetime(change[:detected_at]),
            severity: change[:severity]
          }
        end)
      rescue
        _ -> []
      catch
        _kind, _reason -> []
      end

    # Get alert rules
    alert_rules =
      try do
        Monitor.list_alert_rules()
        |> Enum.map(fn rule ->
          %{
            id: rule[:id],
            name: rule[:name],
            description: rule[:description],
            change_type: rule[:change_type],
            severity: rule[:severity],
            enabled: rule[:enabled]
          }
        end)
      rescue
        _ -> []
      catch
        _kind, _reason -> []
      end

    # Get statistics
    stats =
      try do
        %{
          total_assets: length(assets),
          total_domains: length(domains),
          critical_risks: risk_distribution[:critical] || 0,
          high_risks: risk_distribution[:high] || 0,
          changes_this_week: length(recent_changes),
          aggregate_risk_score: aggregate_risk[:score] || 0
        }
      rescue
        _ ->
          %{
            total_assets: 0,
            total_domains: 0,
            critical_risks: 0,
            high_risks: 0,
            changes_this_week: 0,
            aggregate_risk_score: 0
          }
      end

    render_inertia(conn, "AttackSurface", %{
      page_title: "Attack Surface Management",
      dashboard: dashboard,
      assets: assets,
      domains: domains,
      topRisks: top_risks,
      riskDistribution: risk_distribution,
      aggregateRisk: aggregate_risk,
      recentChanges: recent_changes,
      alertRules: alert_rules,
      stats: stats
    })
  end

  # Mobile Security foundation. The app route remains hidden until mobile telemetry is production-ready.
  def mobile(conn, _params) do
    # Mobile agent support is in foundation phase
    # This page shows the architecture overview and setup guide

    render_inertia(conn, "Mobile", %{
      page_title: "Mobile Security"
    })
  end

  # Executive Dashboard - High-level security posture overview
  def executive_dashboard(conn, _params) do
    current_user = conn.assigns[:current_user]
    org_id = current_user && current_user.organization_id

    # Fetch executive summary data
    now = DateTime.utc_now()
    thirty_days_ago = DateTime.add(now, -30, :day)

    # Get high-level metrics (multi-tenant scoped)
    total_agents =
      try do
        TamanduaServer.Agents.count_agents_for_org(org_id)
      rescue
        _ -> 0
      end

    online_agents =
      try do
        TamanduaServer.Agents.count_online_for_org(org_id)
      rescue
        _ -> 0
      end

    total_alerts =
      try do
        TamanduaServer.Alerts.count_active_for_org(org_id)
      rescue
        _ -> 0
      end

    critical_alerts =
      try do
        TamanduaServer.Alerts.count_by_severity_for_org(org_id, "critical")
      rescue
        _ -> 0
      end

    high_alerts =
      try do
        TamanduaServer.Alerts.count_by_severity_for_org(org_id, "high")
      rescue
        _ -> 0
      end

    # Calculate compliance score from the Compliance framework
    compliance_score =
      try do
        posture = TamanduaServer.Compliance.get_overall_posture_for_org(org_id)
        posture.overall_score
      catch
        _kind, _reason -> nil
      end

    # Get recent threat trends (multi-tenant scoped)
    alert_trend =
      try do
        TamanduaServer.Alerts.get_trend_for_org(org_id, "30d")
      rescue
        _ -> []
      catch
        _kind, _reason -> []
      end

    detection_trend =
      try do
        TamanduaServer.Detection.get_trend_for_org(org_id, "30d")
      rescue
        _ -> []
      catch
        _kind, _reason -> []
      end

    # MTTD and MTTR calculations from resolved alerts (multi-tenant scoped)
    # MTTD: approximate as time from source event insertion to alert creation (inserted_at).
    # Since detection_metadata may contain source event timestamps, but the alert's
    # own inserted_at is effectively the detection time, MTTD is derived from the
    # detection_metadata when available.
    # MTTR: time from alert creation (inserted_at) to resolution (updated_at for resolved alerts).
    {mttd_minutes, mttr_minutes} =
      try do
        import Ecto.Query
        alias TamanduaServer.Repo
        alias TamanduaServer.Alerts.Alert

        # Base query with org_id scope for multi-tenant isolation
        base_query =
          from(a in Alert,
            where: a.status == "resolved",
            where:
              a.inserted_at >= ^NaiveDateTime.add(NaiveDateTime.utc_now(), -30 * 86400, :second),
            select: %{
              inserted_at: a.inserted_at,
              updated_at: a.updated_at,
              detection_metadata: a.detection_metadata
            },
            order_by: [desc: a.updated_at],
            limit: 200
          )

        resolved_alerts =
          if org_id do
            base_query |> where([a], a.organization_id == ^org_id) |> Repo.all()
          else
            base_query |> Repo.all()
          end

        # MTTR: difference between updated_at (resolution) and inserted_at (creation)
        mttr_samples =
          resolved_alerts
          |> Enum.map(fn a ->
            NaiveDateTime.diff(a.updated_at, a.inserted_at, :second) / 60.0
          end)
          |> Enum.filter(&(&1 > 0))

        computed_mttr =
          if mttr_samples != [] do
            Float.round(Enum.sum(mttr_samples) / length(mttr_samples), 1)
          else
            nil
          end

        # MTTD: if detection_metadata contains a source_event_time, use that;
        # otherwise MTTD is not computable from alert data alone.
        mttd_samples =
          resolved_alerts
          |> Enum.flat_map(fn a ->
            case a.detection_metadata do
              %{"source_event_time" => ts_str} when is_binary(ts_str) ->
                case NaiveDateTime.from_iso8601(ts_str) do
                  {:ok, source_time} ->
                    diff = NaiveDateTime.diff(a.inserted_at, source_time, :second) / 60.0
                    if diff > 0, do: [diff], else: []

                  _ ->
                    []
                end

              _ ->
                []
            end
          end)

        computed_mttd =
          if mttd_samples != [] do
            Float.round(Enum.sum(mttd_samples) / length(mttd_samples), 1)
          else
            nil
          end

        {computed_mttd, computed_mttr}
      rescue
        _ -> {nil, nil}
      end

    # Risk score calculation
    risk_score =
      calculate_executive_risk_score(critical_alerts, high_alerts, total_agents, online_agents)

    # Get top threats by severity and type (multi-tenant scoped)
    top_threats =
      try do
        TamanduaServer.Alerts.list_recent_for_org(org_id, limit: 10)
        |> Enum.filter(fn alert -> alert.severity in ["critical", "high"] end)
        |> Enum.take(5)
        |> Enum.map(fn alert ->
          %{
            id: alert.id,
            title: alert.title,
            severity: alert.severity,
            timestamp: alert.inserted_at,
            mitre_tactic: Map.get(alert, :mitre_tactic),
            mitre_technique: Map.get(alert, :mitre_technique)
          }
        end)
      rescue
        _ -> []
      catch
        _kind, _reason -> []
      end

    # Get MITRE coverage summary
    mitre_coverage =
      try do
        TamanduaServer.Detection.Mitre.get_coverage()
      rescue
        _ -> %{}
      catch
        _kind, _reason -> %{}
      end

    # Industry benchmarks computed from real data where possible, nil otherwise.
    # No external benchmark source is integrated, so return nil instead of fake data.
    industry_benchmarks = %{
      mttd_avg: nil,
      mttr_avg: nil,
      risk_score_avg: nil,
      compliance_avg: nil
    }

    render_inertia(conn, "ExecutiveDashboard", %{
      page_title: "Executive Dashboard",
      metrics: %{
        totalAgents: total_agents,
        onlineAgents: online_agents,
        totalAlerts: total_alerts,
        criticalAlerts: critical_alerts,
        highAlerts: high_alerts,
        complianceScore: compliance_score,
        riskScore: risk_score,
        mttdMinutes: mttd_minutes,
        mttrMinutes: mttr_minutes
      },
      trends: %{
        alerts: alert_trend,
        detections: detection_trend
      },
      topThreats: top_threats,
      mitreCoverage: mitre_coverage,
      industryBenchmarks: industry_benchmarks
    })
  end

  # Detection Rules page (Sigma + YARA management)
  def detection_rules(conn, _params) do
    conn
    |> assign(:page_title, "Detection Rules")
    |> render_inertia("DetectionRules", %{})
  end

  # Detection Packs marketplace
  def detection_packs(conn, _params) do
    alias TamanduaServer.Detection.Packs

    organization_id = conn.assigns[:current_organization_id]
    installed_packs = if organization_id, do: Packs.list_installed(organization_id), else: []
    stats = if organization_id, do: Packs.get_stats(organization_id), else: Packs.get_stats(nil)

    conn
    |> assign(:page_title, "Detection Packs")
    |> render_inertia("DetectionPacks", %{
      availablePacks: Packs.list_available(),
      installedPacks: installed_packs,
      stats: stats
    })
  end

  @doc """
  Contributions page - Community bounty submissions and leaderboard.

  Displays user submissions for detection rules, IOCs, and threat intelligence,
  along with available bounties and the contributor leaderboard.
  """
  def contributions(conn, _params) do
    current_user = conn.assigns[:current_user]
    org_id = current_user && current_user.organization_id

    submissions =
      if org_id do
        Bounties.list_submissions(organization_id: org_id)
        |> Enum.map(&serialize_bounty_submission/1)
      else
        []
      end

    leaderboard =
      Bounties.leaderboard_stats(limit: 20)
      |> Enum.with_index(1)
      |> Enum.map(fn {entry, rank} -> Map.put(entry, :rank, rank) end)
      |> Enum.map(&serialize_bounty_leaderboard_entry/1)

    bounties =
      submissions
      |> Enum.filter(fn submission -> submission.bounty_eligibility == "eligible" end)
      |> Enum.map(&submission_to_available_bounty/1)

    conn
    |> assign(:page_title, "Contributions")
    |> render_inertia("Contributions", %{
      submissions: submissions,
      bounties: bounties,
      leaderboard: leaderboard,
      stats: %{
        your_submissions: length(submissions),
        accepted: Enum.count(submissions, fn submission -> submission.status == "accepted" end),
        total_earned: Enum.reduce(leaderboard, 0, fn entry, acc -> acc + entry.total_sol end)
      }
    })
  end

  def not_found(conn, params) do
    path =
      params
      |> Map.get("path", [])
      |> case do
        [] -> "/app"
        segments when is_list(segments) -> "/app/" <> Enum.join(segments, "/")
        segment when is_binary(segment) -> "/app/" <> segment
      end

    conn
    |> put_status(:not_found)
    |> assign(:page_title, "Page not found")
    |> render_inertia("NotFound", %{
      status: 404,
      path: path,
      message: "That Tamandua workspace page does not exist or is no longer available."
    })
  end

  # Helper function to calculate executive risk score
  defp calculate_executive_risk_score(critical, high, total_agents, online_agents) do
    base_score = 100

    # Deduct for critical alerts
    critical_penalty = min(critical * 10, 40)

    # Deduct for high alerts
    high_penalty = min(high * 3, 20)

    # Deduct for offline agents
    offline_ratio =
      if total_agents > 0, do: (total_agents - online_agents) / total_agents, else: 0

    offline_penalty = round(offline_ratio * 20)

    max(0, base_score - critical_penalty - high_penalty - offline_penalty)
  end
end
