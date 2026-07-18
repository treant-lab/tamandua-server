defmodule TamanduaServerWeb.API.V1.AgentController do
  use TamanduaServerWeb, :controller

  require Logger
  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Agents
  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.Agents.ModelScanRuntime
  alias TamanduaServer.Agents.PlatformCapabilities
  alias TamanduaServer.Agents.PlatformVisibility
  alias TamanduaServer.LiveResponse.ScreenCapturePolicy
  alias TamanduaServer.Authorization.RBAC
  alias TamanduaServer.AuditLog
  alias TamanduaServer.Alerts
  alias TamanduaServer.Response
  alias TamanduaServer.Response.ResponseActor
  alias TamanduaServer.Telemetry
  alias TamanduaServer.Telemetry.Event

  @live_presence_stale_after_ms :timer.seconds(120)
  @mobile_presence_stale_after_ms :timer.hours(24)

  # Pagination defaults for index/2 to prevent unbounded responses.
  # @default_per_page mirrors the existing list-endpoint convention across
  # AlertController; @max_per_page is the hard ceiling for clients.
  @default_per_page 50
  @max_per_page 200

  action_fallback(TamanduaServerWeb.FallbackController)

  # RBAC on destructive/state-changing agent actions. Org membership alone is
  # not sufficient: a viewer/analyst must not be able to isolate, restart, or
  # reconfigure endpoints. The plug fails closed (403) when the user lacks the
  # permission or is unauthenticated.
  plug(TamanduaServerWeb.Plugs.Authorize, :agents_command when action in [:restart_agent])
  plug(TamanduaServerWeb.Plugs.Authorize, :agents_policy when action in [:update_config])
  plug(TamanduaServerWeb.Plugs.Authorize, :agents_update when action in [:update])
  plug(TamanduaServerWeb.Plugs.Authorize, :agents_delete when action in [:delete])

  # Helper to authorize agent access within the current organization
  defp authorize_agent!(conn, agent_id) do
    org_id = conn.assigns[:current_organization_id]
    Agents.get_agent_for_org!(org_id, agent_id)
  end

  def index(conn, params) do
    org_id = conn.assigns[:current_organization_id]

    filtered =
      org_id
      |> Agents.list_all_for_org()
      |> filter_agents(params)

    total = length(filtered)
    {limit, offset} = pagination_params(params)
    page = filtered |> Enum.drop(offset) |> Enum.take(limit)

    json(conn, %{
      data: Enum.map(page, &serialize/1),
      meta: %{total: total, limit: limit, offset: offset}
    })
  end

  def data_sources_health(conn, params) do
    org_id = conn.assigns[:current_organization_id]
    window_hours = parse_int(params["hours"], 24)
    cutoff = DateTime.utc_now() |> DateTime.add(-window_hours * 3600, :second)
    agents = Agents.list_all_for_org(org_id)

    source_health_by_agent =
      agents
      |> Enum.map(&agent_field(&1, :id))
      |> Enum.reject(&is_nil/1)
      |> Telemetry.data_source_health_for_agents(window_hours: window_hours)

    stats =
      from(e in Event,
        where: e.organization_id == ^org_id and e.timestamp >= ^cutoff,
        group_by: e.agent_id,
        select: %{
          agent_id: e.agent_id,
          last_seen: max(e.timestamp),
          process: fragment("COUNT(*) FILTER (WHERE ? LIKE 'process%')", e.event_type),
          file: fragment("COUNT(*) FILTER (WHERE ? LIKE 'file%')", e.event_type),
          network: fragment("COUNT(*) FILTER (WHERE ? LIKE 'network%')", e.event_type),
          dns: fragment("COUNT(*) FILTER (WHERE ? LIKE 'dns%')", e.event_type),
          registry: fragment("COUNT(*) FILTER (WHERE ? LIKE 'registry%')", e.event_type),
          driver:
            fragment(
              """
              COUNT(*) FILTER (
                WHERE ? LIKE 'driver%'
                   OR ? LIKE 'etw%'
                   OR ?->>'source' = 'kernel_driver'
                   OR ?->'metadata'->>'source' = 'kernel_driver'
                   OR ?->>'source' = 'kernel_driver'
                   OR ?->'event_contract'->>'category' = 'driver'
                   OR ?->'metadata'->>'source' = 'kernel_driver'
              )
              """,
              e.event_type,
              e.event_type,
              e.enrichment,
              e.enrichment,
              e.payload,
              e.enrichment,
              e.enrichment
            )
        }
      )
      |> Repo.all()
      |> Map.new(&{&1.agent_id, &1})

    data =
      Enum.map(agents, fn agent ->
        agent_id = agent_field(agent, :id)
        agent_config = agent_field(agent, :config) || %{}
        agent_stats = Map.get(stats, agent_id, %{last_seen: nil})
        live_info = live_agent_info(agent_id)
        health = live_agent_health(agent_id)
        health_status = TamanduaServer.Agents.Registry.get_agent_health_status_detail(agent_id)
        driver_status = normalize_driver_status(live_health_value(health, :driver_status))
        platform_status = live_health_value(health, :platform_status) || []
        agent_health_visibility = live_health_value(health, :platform_visibility)
        source_contracts = get_in(source_health_by_agent, [agent_id, :sources]) || %{}

        sources =
          [:process, :file, :dns, :network, :registry, :driver, :ai, :ndr]
          |> Enum.map(fn source ->
            source_name = Atom.to_string(source)
            contract = Map.get(source_contracts, source_name, %{})
            count = Map.get(contract, "count") || Map.get(agent_stats, source, 0) || 0
            status = Map.get(contract, "status") || if(count > 0, do: "healthy", else: "missing")

            %{
              name: source,
              source: source_name,
              status: status,
              eventCount: count,
              count: count,
              lastSeen: Map.get(contract, "last_seen"),
              last_seen: Map.get(contract, "last_seen"),
              missingReason: Map.get(contract, "missing_reason"),
              missing_reason: Map.get(contract, "missing_reason")
            }
          end)

        platform_capabilities =
          PlatformCapabilities.for_agent(agent,
            status: heartbeat_state(live_info, agent),
            config: agent_config,
            health:
              Map.merge(health_status || %{}, %{
                driver_status: driver_status,
                platform_status: platform_status
              }),
            data_sources: source_counts(sources),
            screen_capture_policy: ScreenCapturePolicy.resolve(agent_field(agent, :id))
          )

        platform_visibility =
          PlatformVisibility.summarize(agent,
            capabilities: platform_capabilities,
            agent_health_visibility: agent_health_visibility,
            last_telemetry_at: agent_stats.last_seen,
            last_heartbeat_at:
              live_health_value(live_info, :last_seen_at) || agent_field(agent, :last_seen_at)
          )

        %{
          agentId: agent_id,
          hostname: agent_field(agent, :hostname),
          osType: agent_field(agent, :os_type),
          windowHours: window_hours,
          lastTelemetryAt: format_datetime(agent_stats.last_seen),
          lastHeartbeatAt:
            format_heartbeat_at(
              live_health_value(live_info, :last_seen_at) || agent_field(agent, :last_seen_at)
            ),
          heartbeatState: heartbeat_state(live_info, agent),
          healthStatus: serialize_health_status_detail(health_status),
          driverStatus: driver_status,
          platformStatus: platform_status,
          agentHealthPlatformVisibility: agent_health_visibility,
          platformCapabilities: platform_capabilities,
          platformVisibility: platform_visibility,
          dropCounters: driver_drop_counters(driver_status),
          sources: sources,
          missingSources:
            sources
            |> Enum.filter(&(&1.status in ["missing", "stale"]))
            |> Enum.map(& &1.name),
          receivingSources:
            sources
            |> Enum.filter(&(&1.status == "healthy"))
            |> Enum.map(& &1.name)
        }
      end)

    json(conn, %{data: data})
  end

  defp agent_field(%{} = agent, :id),
    do:
      Map.get(agent, :id) || Map.get(agent, "id") || Map.get(agent, :agent_id) ||
        Map.get(agent, "agent_id")

  defp agent_field(%{} = agent, key),
    do: Map.get(agent, key) || Map.get(agent, Atom.to_string(key))

  defp agent_field(agent, key), do: Map.get(agent, key)

  def show(conn, %{"id" => id}) do
    agent = authorize_agent!(conn, id)
    live_info = TamanduaServer.Agents.Registry.get(id)

    health =
      case TamanduaServer.Agents.Registry.get_health(id) do
        {:ok, h} ->
          %{
            cpu_usage: h.cpu_usage,
            memory_usage: h.memory_usage,
            disk_usage: h.disk_usage,
            cpu_history: h.cpu_history,
            memory_history: h.memory_history,
            uptime_seconds: h.uptime_seconds,
            collector_status: Map.get(h, :collector_status),
            platform_status: Map.get(h, :platform_status, []),
            platform_visibility: Map.get(h, :platform_visibility),
            driver_status: normalize_driver_status(Map.get(h, :driver_status))
          }

        {:error, :not_found} ->
          case live_info do
            {:ok, info} ->
              %{
                cpu_usage: Map.get(info, :cpu_usage, 0),
                memory_usage: Map.get(info, :memory_usage, 0),
                disk_usage: Map.get(info, :disk_usage, 0),
                collector_status: Map.get(info, :collector_status),
                platform_status: Map.get(info, :platform_status, []),
                platform_visibility: Map.get(info, :platform_visibility),
                driver_status: normalize_driver_status(Map.get(info, :driver_status)),
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

    config =
      case live_info do
        {:ok, info} -> Map.merge(agent.config || %{}, Map.get(info, :config, %{}))
        _ -> agent.config || %{}
      end

    {agent_events, events_partial_reason} =
      safe_list_events_for_agent(id, 20, "agent_detail_recent_events")

    events = Enum.map(agent_events, &serialize_event/1)

    model_scan_event =
      safe_latest_ai_discovery_event(conn.assigns[:current_organization_id], id)

    model_scan_runtime =
      ModelScanRuntime.summarize(if(model_scan_event, do: [model_scan_event], else: agent_events))

    alerts =
      try do
        Alerts.list_alerts(%{
          agent_id: id,
          organization_id: conn.assigns[:current_organization_id]
        })
        |> Enum.take(10)
        |> Enum.map(fn alert ->
          %{
            id: alert.id,
            title: alert.title,
            severity: alert.severity,
            status: alert.status,
            created_at: format_datetime(alert.inserted_at || alert.created_at)
          }
        end)
      rescue
        _ -> []
      end

    {collector_events, collectors_partial_reason} =
      safe_list_events_for_agent(id, 500, "agent_detail_collectors")

    collectors = derive_collectors(collector_events, config)
    capabilities = derive_capabilities(config, collectors)
    data_source_health = get_data_source_health(id)
    live_status_info = live_agent_info(id)

    platform_capabilities =
      PlatformCapabilities.for_agent(agent,
        status:
          effective_agent_status(
            persisted_status_for_display(agent.status, agent.last_seen_at, mobile_agent?(agent)),
            live_status_info
          ),
        health:
          Map.merge(
            TamanduaServer.Agents.Registry.get_agent_health_status_detail(id) || %{},
            health || %{}
          ),
        config: config,
        collectors: collectors,
        data_sources: data_source_counts(data_source_health),
        screen_capture_policy: ScreenCapturePolicy.resolve(id)
      )

    platform_visibility =
      PlatformVisibility.summarize(agent,
        capabilities: platform_capabilities,
        agent_health_visibility: Map.get(health || %{}, :platform_visibility),
        last_telemetry_at: latest_source_seen_at(data_source_health),
        last_heartbeat_at:
          live_health_value(live_status_info, :last_seen_at) || agent.last_seen_at
      )

    json(conn, %{
      data:
        serialize(agent)
        |> Map.put(:health, health)
        |> Map.put(
          :health_status,
          serialize_health_status_detail(
            TamanduaServer.Agents.Registry.get_agent_health_status_detail(id)
          )
        )
        |> Map.put(:collectors, collectors)
        |> Map.put(:capabilities, capabilities)
        |> Map.put(:platform_capabilities, platform_capabilities)
        |> Map.put(:platformCapabilities, platform_capabilities)
        |> Map.put(:platform_visibility, platform_visibility)
        |> Map.put(:platformVisibility, platform_visibility)
        |> Map.put(:dataSourceHealth, data_source_health)
        |> Map.put(:events, events)
        |> Map.put(:model_scan_runtime, model_scan_runtime)
        |> Map.put(:modelScanRuntime, model_scan_runtime)
        |> Map.put(:events_partial, not is_nil(events_partial_reason))
        |> Map.put(:events_partial_reason, events_partial_reason)
        |> Map.put(:collectors_partial, not is_nil(collectors_partial_reason))
        |> Map.put(:collectors_partial_reason, collectors_partial_reason)
        |> Map.put(:alerts, alerts)
        |> Map.put(:config, config)
    })
  end

  def update(conn, %{"id" => id} = params) do
    agent = authorize_agent!(conn, id)

    with {:ok, %Agent{} = agent} <-
           agent
           |> Agent.public_update_changeset(params)
           |> Repo.update() do
      json(conn, %{data: serialize(agent)})
    end
  end

  def delete(conn, %{"id" => id}) do
    agent = authorize_agent!(conn, id)

    with {:ok, %Agent{}} <- Agents.delete_agent(agent) do
      send_resp(conn, :no_content, "")
    end
  end

  def isolate(conn, %{"id" => id} = params) do
    with :ok <- authorize_response_isolate(conn) do
      user = conn.assigns[:current_user]
      agent = authorize_agent!(conn, id)

      if mobile_agent?(agent) do
        unsupported_mobile_host_action(conn, "network isolation")
      else
        with {:ok, actor} <-
               ResponseActor.from_user_scope(user, current_organization_id(conn)) do
          allowed_ips = Map.get(params, "allowed_ips", [])

          case TamanduaServer.Response.Executor.isolate_network(id,
                 allowed_ips: allowed_ips,
                 actor: actor
               ) do
            {:ok, response} ->
              # The Executor already updated the agent's isolation_status and
              # broadcast the PubSub event, so just log and respond.
              AuditLog.log_agent_action(
                user,
                "isolate_agent",
                id,
                %{
                  hostname: agent.hostname,
                  allowed_ips: allowed_ips,
                  result: "success",
                  isolation_state: get_in(response, ["result_data", "state"]) || "unknown"
                },
                request_metadata(conn)
              )

              record_response_action(
                conn,
                user,
                "isolate_network",
                id,
                params,
                "success",
                response
              )

              # Re-read agent to get updated isolation_status
              updated_agent = authorize_agent!(conn, id)

              json(conn, %{
                data: serialize(updated_agent),
                message: "Agent isolation command executed",
                isolation_status: updated_agent.isolation_status
              })

            {:error, reason} ->
              AuditLog.log_agent_action(
                user,
                "isolate_agent",
                id,
                %{
                  hostname: agent.hostname,
                  result: "failed",
                  error: inspect(reason)
                },
                request_metadata(conn)
              )

              record_response_action(
                conn,
                user,
                "isolate_network",
                id,
                params,
                "failed",
                nil,
                inspect(reason)
              )

              conn
              |> put_status(400)
              |> json(%{success: false, error: inspect(reason)})
          end
        end
      end
    else
      {:error, conn} -> conn
    end
  end

  def unisolate(conn, %{"id" => id}) do
    with :ok <- authorize_response_isolate(conn) do
      user = conn.assigns[:current_user]
      agent = authorize_agent!(conn, id)

      if mobile_agent?(agent) do
        unsupported_mobile_host_action(conn, "network isolation removal")
      else
        with {:ok, actor} <-
               ResponseActor.from_user_scope(user, current_organization_id(conn)) do
          case TamanduaServer.Response.Executor.unisolate_network(id, actor: actor) do
            {:ok, response} ->
              AuditLog.log_agent_action(
                user,
                "unisolate_agent",
                id,
                %{
                  hostname: agent.hostname,
                  result: "success",
                  isolation_state: get_in(response, ["result_data", "state"]) || "disabled"
                },
                request_metadata(conn)
              )

              updated_agent = authorize_agent!(conn, id)

              json(conn, %{
                data: serialize(updated_agent),
                message: "Agent de-isolation command executed",
                isolation_status: updated_agent.isolation_status
              })

            {:error, reason} ->
              AuditLog.log_agent_action(
                user,
                "unisolate_agent",
                id,
                %{
                  hostname: agent.hostname,
                  result: "failed",
                  error: inspect(reason)
                },
                request_metadata(conn)
              )

              conn
              |> put_status(400)
              |> json(%{success: false, error: inspect(reason)})
          end
        end
      end
    else
      {:error, conn} -> conn
    end
  end

  @doc """
  GET /api/v1/agents/:id/isolation

  Returns the current detailed isolation status for an agent, including
  applied rules, allowlisted connections, connectivity test results,
  and timestamps.
  """
  def isolation_status(conn, %{"id" => id}) do
    # First verify the agent belongs to the current organization
    _agent = authorize_agent!(conn, id)

    case Agents.get_isolation_status(id) do
      {:ok, status} ->
        json(conn, %{
          success: true,
          agent_id: id,
          isolation_status: status
        })

      {:error, :not_found} ->
        conn
        |> put_status(404)
        |> json(%{success: false, error: "Agent not found"})

      {:error, reason} ->
        conn
        |> put_status(400)
        |> json(%{success: false, error: inspect(reason)})
    end
  end

  def restart_agent(conn, %{"id" => id}) do
    user = conn.assigns[:current_user]

    # First verify the agent belongs to the current organization
    _agent = authorize_agent!(conn, id)

    case TamanduaServer.Agents.Registry.get(id) do
      {:ok, _info} ->
        # Send restart command via the agent's WebSocket channel
        TamanduaServerWeb.Endpoint.broadcast("agent:#{id}", "command", %{
          type: "restart_agent",
          params: %{}
        })

        # Log restart action
        AuditLog.log_agent_action(
          user,
          "restart_agent",
          id,
          %{
            result: "command_sent"
          },
          request_metadata(conn)
        )

        json(conn, %{success: true, message: "Restart command sent to agent"})

      {:error, :not_found} ->
        conn
        |> put_status(404)
        |> json(%{success: false, error: "Agent is not connected"})
    end
  end

  def events(conn, %{"id" => id} = params) do
    _agent = authorize_agent!(conn, id)

    filters = %{
      limit: parse_int(params["limit"], 100),
      offset: parse_int(params["offset"], 0),
      event_type: params["event_type"],
      severity: params["severity"],
      from: params["from"],
      to: params["to"]
    }

    {events, total, partial_reason} = safe_list_agent_events(id, filters, "agent_events")

    json(conn, %{
      data: Enum.map(events, &serialize_event/1),
      meta: %{
        total: total,
        limit: filters.limit,
        offset: filters.offset,
        partial: not is_nil(partial_reason),
        partial_reason: partial_reason
      }
    })
  end

  defp safe_list_events_for_agent(agent_id, limit, label) do
    {Telemetry.list_events_for_agent(agent_id, limit), nil}
  rescue
    exception ->
      Logger.warning(
        "[AgentController] #{label} failed for #{agent_id}: #{Exception.message(exception)}"
      )

      {[], "event_query_failed"}
  catch
    :exit, reason ->
      Logger.warning("[AgentController] #{label} failed for #{agent_id}: exit #{inspect(reason)}")
      {[], "event_query_exit"}
  end

  defp safe_latest_ai_discovery_event(organization_id, agent_id) do
    Telemetry.latest_ai_discovery_event_for_agent(organization_id, agent_id)
  rescue
    exception ->
      Logger.warning(
        "[AgentController] agent_detail_model_runtime failed for #{agent_id}: #{Exception.message(exception)}"
      )

      nil
  catch
    :exit, reason ->
      Logger.warning(
        "[AgentController] agent_detail_model_runtime failed for #{agent_id}: exit #{inspect(reason)}"
      )

      nil
  end

  defp safe_list_agent_events(agent_id, filters, label) do
    {events, total} = Telemetry.list_agent_events(agent_id, filters)
    {events, total, nil}
  rescue
    exception ->
      Logger.warning(
        "[AgentController] #{label} failed for #{agent_id}: #{Exception.message(exception)}"
      )

      {[], 0, "event_query_failed"}
  catch
    :exit, reason ->
      Logger.warning("[AgentController] #{label} failed for #{agent_id}: exit #{inspect(reason)}")
      {[], 0, "event_query_exit"}
  end

  defp serialize_event(event) do
    %{
      id: event.id,
      agent_id: event.agent_id,
      event_type: event.event_type,
      severity: event.severity,
      timestamp: format_datetime(event.timestamp),
      payload: event.payload || %{}
    }
  end

  defp get_data_source_health(agent_id) do
    Telemetry.data_source_health_for_agents([agent_id])
    |> Map.get(agent_id)
  rescue
    e ->
      Logger.warning(
        "[AgentController] failed to calculate data source health for #{agent_id}: #{Exception.message(e)}"
      )

      nil
  end

  defp parse_int(nil, default), do: default

  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> default
    end
  end

  defp parse_int(value, _default) when is_integer(value), do: value

  def processes(conn, %{"id" => id} = params) do
    agent = authorize_agent!(conn, id)

    case params do
      %{"page" => _} ->
        # Paginated flat list
        page = parse_int(params["page"], 1) |> max(1)
        per_page = parse_int(params["per_page"], 100) |> min(500) |> max(1)
        offset = (page - 1) * per_page

        case Agents.list_processes(agent.id, limit: per_page, offset: offset) do
          {:ok, result} ->
            total_pages = ceil(result.total / per_page)

            json(conn, %{
              data: Enum.map(result.processes, &serialize_flat_process/1),
              meta: %{
                total: result.total,
                page: page,
                per_page: per_page,
                total_pages: total_pages
              }
            })
        end

      _ ->
        # Full tree (legacy behavior, with new error handling)
        case Agents.get_process_tree(agent) do
          {:ok, tree} ->
            json(conn, %{data: tree, meta: %{truncated: false}})

          {:ok, tree, %{truncated: true, total_processes: total}} ->
            json(conn, %{
              data: tree,
              meta: %{truncated: true, total_processes: total}
            })

          {:error, :timeout} ->
            conn
            |> put_status(504)
            |> json(%{
              error: "timeout",
              message:
                "Process tree loading timed out. Use paginated endpoints for large process lists."
            })

          {:error, :build_failed} ->
            conn
            |> put_status(500)
            |> json(%{error: "build_failed", message: "Failed to build the process tree."})
        end
    end
  end

  def process_children(conn, %{"id" => id, "pid" => pid_str} = params) do
    _agent = authorize_agent!(conn, id)

    pid = parse_int(pid_str, 0)
    limit = parse_int(params["limit"], 200)
    offset = parse_int(params["offset"], 0)

    case Agents.get_process_children(id, pid, limit: limit, offset: offset) do
      {:ok, result} ->
        json(conn, %{
          data: Enum.map(result.children, &serialize_flat_process/1),
          meta: %{
            total: result.total,
            parent_pid: result.parent_pid
          }
        })

      {:error, :not_found} ->
        conn
        |> put_status(404)
        |> json(%{error: "not_found", message: "Process #{pid} not found on this agent"})
    end
  end

  def process_ancestors(conn, %{"id" => id, "pid" => pid_str}) do
    _agent = authorize_agent!(conn, id)

    pid = parse_int(pid_str, 0)

    case Agents.get_process_ancestors(id, pid) do
      {:ok, ancestors} ->
        json(conn, %{
          data: Enum.map(ancestors, &serialize_flat_process/1),
          meta: %{
            target_pid: pid,
            depth: length(ancestors)
          }
        })

      {:error, :not_found} ->
        conn
        |> put_status(404)
        |> json(%{error: "not_found", message: "Process #{pid} not found on this agent"})
    end
  end

  def process_context(conn, %{"id" => id, "pid" => pid_str}) do
    _agent = authorize_agent!(conn, id)

    pid = parse_int(pid_str, 0)

    case Agents.get_process_context(id, pid) do
      {:ok, context} ->
        json(conn, %{
          data: %{
            process: serialize_flat_process(context.process),
            ancestors: Enum.map(context.ancestors, &serialize_flat_process/1),
            chain: Enum.map(context.chain, &serialize_flat_process/1)
          },
          meta: %{
            target_pid: pid,
            depth: length(context.ancestors),
            claim_boundary:
              "Process context is correlated from process telemetry already held by the server; sparse network events may still lack binary/hash data if process telemetry was not collected."
          }
        })

      {:error, :not_found} ->
        conn
        |> put_status(404)
        |> json(%{
          error: "not_found",
          message: "Process #{pid} context was not found for this agent"
        })
    end
  end

  defp serialize_flat_process(node) do
    %{
      pid: node.pid,
      ppid: node.ppid,
      name: node.name,
      path: node.path,
      cmdline: node.cmdline,
      user: node.user,
      startTime: node[:start_time],
      sha256: node[:sha256],
      isElevated: node[:is_elevated] || false,
      isSigned: node[:is_signed] || false,
      signer: node[:signer],
      childCount: node[:child_count] || 0,
      children: [],
      detections: [],
      cpuUsage: node[:cpu_usage],
      memoryBytes: node[:memory_bytes],
      companyName: node[:company_name],
      fileDescription: node[:file_description],
      productName: node[:product_name],
      fileVersion: node[:file_version],
      entropy: node[:entropy]
    }
  end

  def update_config(conn, %{"id" => id} = params) do
    user = conn.assigns[:current_user]

    # First verify the agent belongs to the current organization
    _agent = authorize_agent!(conn, id)

    case TamanduaServer.Agents.Registry.get(id) do
      {:ok, info} ->
        config_update = params["config"] || %{}

        # Send config update via WebSocket
        TamanduaServerWeb.Endpoint.broadcast("agent:#{id}", "config_update", config_update)

        # Also update config in database
        try do
          agent = authorize_agent!(conn, id)
          merged_config = Map.merge(agent.config || %{}, config_update)
          Agents.update_agent(agent, %{config: merged_config})
        rescue
          e ->
            Logger.warning("[AgentController] update_config failed: #{Exception.message(e)}")
            :ok
        end

        # Log audit
        AuditLog.log_config_change(
          user,
          "agent_performance_profile",
          %{
            agent_id: id,
            hostname: info[:hostname],
            changes: config_update
          },
          request_metadata(conn)
        )

        json(conn, %{success: true, message: "Configuration update sent to agent"})

      {:error, :not_found} ->
        conn
        |> put_status(404)
        |> json(%{success: false, error: "Agent is not connected"})
    end
  end

  defp serialize(%Agent{} = agent) do
    live_info = live_agent_info(agent.id)

    persisted_status =
      persisted_status_for_display(agent.status, agent.last_seen_at, mobile_agent?(agent))

    status = effective_agent_status(persisted_status, live_info)
    last_seen_at = live_health_value(live_info, :last_seen_at) || agent.last_seen_at
    health_status = agent_health_status_for_display(agent.id, status)

    platform_capabilities =
      PlatformCapabilities.for_agent(agent,
        status: status,
        health: health_status,
        config: agent.config || %{},
        screen_capture_policy: ScreenCapturePolicy.resolve(agent.id)
      )

    platform_visibility =
      PlatformVisibility.summarize(agent,
        capabilities: platform_capabilities,
        last_heartbeat_at: last_seen_at
      )

    %{
      id: agent.id,
      hostname: agent.hostname,
      os_type: agent.os_type,
      os_version: agent.os_version,
      agent_version: agent.agent_version,
      status: status,
      health_status: serialize_health_status_detail(health_status),
      isolated: status == "isolated",
      isolation_status: agent.isolation_status,
      capabilities: derive_capabilities(agent.config || %{}, []),
      platform_capabilities: platform_capabilities,
      platformCapabilities: platform_capabilities,
      platform_visibility: platform_visibility,
      platformVisibility: platform_visibility,
      last_seen: format_datetime(last_seen_at),
      created_at: format_datetime(agent.inserted_at)
    }
  end

  defp serialize(agent) when is_map(agent) do
    status =
      persisted_status_for_display(
        agent[:status] || agent["status"] || :offline,
        agent[:last_seen_at] || agent["last_seen_at"],
        mobile_agent?(agent)
      )

    id = agent[:agent_id] || agent["agent_id"] || agent[:id] || agent["id"]
    live_info = live_agent_info(id)
    status = effective_agent_status(status, live_info)

    last_seen_at =
      live_health_value(live_info, :last_seen_at) || agent[:last_seen_at] || agent["last_seen_at"]

    health_status = agent_health_status_for_display(id, status)

    platform_capabilities =
      agent[:platform_capabilities] ||
        agent["platform_capabilities"] ||
        agent[:platformCapabilities] ||
        agent["platformCapabilities"] ||
        PlatformCapabilities.for_agent(agent,
          status: status,
          health: health_status,
          config: agent[:config] || agent["config"] || %{},
          screen_capture_policy: ScreenCapturePolicy.resolve(id)
        )

    platform_visibility =
      agent[:platform_visibility] ||
        agent["platform_visibility"] ||
        agent[:platformVisibility] ||
        agent["platformVisibility"] ||
        PlatformVisibility.summarize(agent,
          capabilities: platform_capabilities,
          last_heartbeat_at: last_seen_at
        )

    %{
      id: id,
      hostname: agent[:hostname] || agent["hostname"],
      ip_address: agent[:ip_address] || agent["ip_address"],
      machine_id: searchable_agent_value(agent[:machine_id] || agent["machine_id"]),
      os_type: agent[:os_type] || agent["os_type"],
      os_version: agent[:os_version] || agent["os_version"],
      agent_version: agent[:agent_version] || agent["agent_version"],
      status: to_string(status),
      health_status: serialize_health_status_detail(health_status),
      isolated: status in [:isolated, "isolated"],
      isolation_status: agent[:isolation_status] || agent["isolation_status"],
      capabilities: agent[:capabilities] || agent["capabilities"] || [],
      platform_capabilities: platform_capabilities,
      platformCapabilities: platform_capabilities,
      platform_visibility: platform_visibility,
      platformVisibility: platform_visibility,
      last_seen: format_datetime(last_seen_at),
      created_at: format_datetime(agent[:inserted_at] || agent["inserted_at"])
    }
  end

  defp effective_agent_status(persisted_status, live_info) when is_map(live_info) do
    cond do
      live_worker_connected?(live_info) and live_status?(live_info, :isolated) and
          recent_live_presence?(live_info) ->
        "isolated"

      live_worker_connected?(live_info) and live_status?(live_info, :online) and
          recent_live_presence?(live_info) ->
        "online"

      true ->
        to_string(persisted_status || "offline")
    end
  end

  defp effective_agent_status(persisted_status, _live_info)
       when persisted_status in [:online, "online", :isolated, "isolated"] do
    # Dashboard and mTLS ingestion may run in separate runtimes. When there is
    # no local Registry entry, a recent persisted heartbeat from the ingestion
    # runtime is still valid live presence for API/GUI display.
    to_string(persisted_status)
  end

  defp effective_agent_status(persisted_status, _live_info),
    do: to_string(persisted_status || "offline")

  defp persisted_status_for_display(status, last_seen_at, mobile?)
       when status in [:online, "online", :isolated, "isolated"] do
    if recent_persisted_presence?(last_seen_at, mobile?), do: status, else: :offline
  end

  defp persisted_status_for_display(status, _last_seen_at, _mobile?), do: status || :offline

  defp agent_health_status_for_display(_agent_id, status) when status in [:offline, "offline"] do
    %{status: :unknown, reasons: [:offline], metrics: %{}}
  end

  defp agent_health_status_for_display(agent_id, _status),
    do: TamanduaServer.Agents.Registry.get_agent_health_status_detail(agent_id)

  defp filter_agents(agents, params) do
    agents
    |> filter_by_status(params["status"])
    |> filter_by_search(params["search"])
  end

  defp filter_by_status(agents, status) when status in [nil, "", "all"], do: agents

  defp filter_by_status(agents, status) do
    Enum.filter(agents, fn agent ->
      agent_status = agent[:status] || agent["status"] || :offline
      to_string(agent_status) == to_string(status)
    end)
  end

  defp filter_by_search(agents, search) when search in [nil, ""], do: agents

  defp filter_by_search(agents, search) do
    query = String.downcase(to_string(search))

    Enum.filter(agents, fn agent ->
      [
        agent[:agent_id] || agent["agent_id"] || agent[:id] || agent["id"],
        agent[:hostname] || agent["hostname"],
        agent[:ip_address] || agent["ip_address"],
        agent[:machine_id] || agent["machine_id"],
        get_in(agent, [:config, "mobile_device_external_id"]) ||
          get_in(agent, ["config", "mobile_device_external_id"]),
        get_in(agent, [:config, "mobile_device_v2_id"]) ||
          get_in(agent, ["config", "mobile_device_v2_id"]),
        get_in(agent, [:config, "mobile_device_id"]) ||
          get_in(agent, ["config", "mobile_device_id"]),
        agent[:os_type] || agent["os_type"]
      ]
      |> Enum.any?(fn value ->
        case searchable_agent_value(value) do
          nil -> false
          text -> String.contains?(String.downcase(text), query)
        end
      end)
    end)
  end

  defp searchable_agent_value(nil), do: nil

  defp searchable_agent_value(value) when is_binary(value) do
    if String.valid?(value), do: value, else: Base.encode16(value, case: :lower)
  end

  defp searchable_agent_value(value), do: to_string(value)

  # Clamps client-supplied limit/offset so /agents cannot return an unbounded
  # response. Defaults each page to @default_per_page; absolute ceiling is
  # @max_per_page.
  defp pagination_params(params) do
    limit =
      params["limit"]
      |> parse_int(@default_per_page)
      |> max(1)
      |> min(@max_per_page)

    offset = params["offset"] |> parse_int(0) |> max(0)
    {limit, offset}
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

  defp derive_capabilities(config, collectors) do
    config = config || %{}
    reported = Map.get(config, "reported_capabilities") || []
    reported_collectors = Map.get(config, "reported_collectors") || %{}
    runtime = Map.get(config, "reported_runtime") || %{}

    %{
      reported: reported,
      collectors: collectors,
      reported_collectors: reported_collectors,
      runtime: runtime,
      summary: %{
        capability_count: capability_count(reported),
        collector_count: length(collectors)
      }
    }
  end

  defp capability_count(reported) when is_list(reported), do: length(reported)
  defp capability_count(reported) when is_map(reported), do: map_size(reported)
  defp capability_count(_reported), do: 0

  defp source_counts(sources) when is_list(sources) do
    Map.new(sources, fn source ->
      {source[:source] || source[:name] || source["source"] || source["name"],
       source[:count] || source[:eventCount] || source["count"] || source["eventCount"] || 0}
    end)
  end

  defp source_counts(_sources), do: %{}

  defp data_source_counts(%{sources: sources}), do: source_counts(sources)
  defp data_source_counts(%{"sources" => sources}), do: source_counts(sources)
  defp data_source_counts(_), do: %{}

  defp latest_source_seen_at(%{sources: sources}), do: latest_source_seen_at(sources)
  defp latest_source_seen_at(%{"sources" => sources}), do: latest_source_seen_at(sources)

  defp latest_source_seen_at(sources) when is_list(sources) do
    sources
    |> Enum.map(&(Map.get(&1, :last_seen) || Map.get(&1, "last_seen")))
    |> Enum.reject(&is_nil/1)
    |> Enum.max(fn -> nil end)
  end

  defp latest_source_seen_at(_), do: nil

  defp format_datetime(nil), do: nil
  defp format_datetime(%NaiveDateTime{} = dt), do: NaiveDateTime.to_iso8601(dt)
  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)

  defp format_datetime(timestamp) when is_integer(timestamp) do
    unit = if timestamp > 10_000_000_000, do: :millisecond, else: :second

    case DateTime.from_unix(timestamp, unit) do
      {:ok, dt} -> DateTime.to_iso8601(dt)
      _ -> nil
    end
  end

  defp format_datetime(timestamp) when is_float(timestamp),
    do: timestamp |> trunc() |> format_datetime()

  defp format_datetime(timestamp) when is_binary(timestamp), do: timestamp
  defp format_datetime(_), do: nil

  defp format_epoch_millis(ms) when is_integer(ms) do
    case DateTime.from_unix(ms, :millisecond) do
      {:ok, dt} -> DateTime.to_iso8601(dt)
      _ -> nil
    end
  end

  defp format_epoch_millis(_), do: nil

  defp live_agent_info(agent_id) do
    case TamanduaServer.Agents.Registry.get(agent_id) do
      {:ok, info} -> merge_live_heartbeat(info, agent_id)
      _ -> nil
    end
  end

  defp merge_live_heartbeat(info, agent_id) when is_map(info) do
    detail = TamanduaServer.Agents.Registry.get_agent_health_status_detail(agent_id)
    metrics = if is_map(detail), do: Map.get(detail, :metrics, %{}), else: %{}
    last_seen_at = Map.get(metrics, :last_seen_at) || Map.get(metrics, "last_seen_at")

    if is_integer(last_seen_at) and is_nil(live_health_value(info, :last_seen_at)) do
      Map.put(info, :last_seen_at, last_seen_at)
    else
      info
    end
  end

  defp merge_live_heartbeat(info, _agent_id), do: info

  defp live_agent_health(agent_id) do
    case TamanduaServer.Agents.Registry.get_health(agent_id) do
      {:ok, health} -> health
      _ -> nil
    end
  end

  defp live_health_value(nil, _key), do: nil

  defp live_health_value(map, key) when is_map(map),
    do: Map.get(map, key) || Map.get(map, Atom.to_string(key))

  defp heartbeat_state(nil), do: "offline"

  defp heartbeat_state(info) when is_map(info) do
    if live_status?(info, :online) and recent_live_presence?(info), do: "online", else: "offline"
  end

  defp heartbeat_state(live_info, agent) do
    case heartbeat_state(live_info) do
      "online" -> "online"
      _ -> persisted_heartbeat_state(agent)
    end
  end

  defp persisted_heartbeat_state(_agent), do: "offline"

  defp format_heartbeat_at(value) when is_integer(value), do: format_epoch_millis(value)
  defp format_heartbeat_at(value), do: format_datetime(value)

  defp live_status?(info, expected) when is_map(info) do
    expected_string = Atom.to_string(expected)
    status = live_health_value(info, :status)
    status == expected or status == expected_string
  end

  defp live_worker_connected?(info) when is_map(info) do
    case live_health_value(info, :worker_pid) do
      pid when is_pid(pid) -> Process.alive?(pid)
      _ -> false
    end
  end

  defp recent_live_presence?(info) when is_map(info) do
    info
    |> live_health_value(:last_seen_at)
    |> recent_presence_value?()
  end

  defp recent_persisted_presence?(value, mobile?),
    do: recent_presence_value?(value, persisted_presence_stale_after_ms(mobile?))

  defp persisted_presence_stale_after_ms(true), do: @mobile_presence_stale_after_ms
  defp persisted_presence_stale_after_ms(_), do: @live_presence_stale_after_ms

  defp recent_presence_value?(value),
    do: recent_presence_value?(value, @live_presence_stale_after_ms)

  defp recent_presence_value?(nil, _stale_after_ms), do: false

  defp recent_presence_value?(value, stale_after_ms) when is_integer(value) do
    System.system_time(:millisecond) - value <= stale_after_ms
  end

  defp recent_presence_value?(%NaiveDateTime{} = value, stale_after_ms) do
    value
    |> DateTime.from_naive!("Etc/UTC")
    |> recent_presence_value?(stale_after_ms)
  end

  defp recent_presence_value?(%DateTime{} = value, stale_after_ms) do
    DateTime.diff(DateTime.utc_now(), value, :millisecond) <= stale_after_ms
  end

  defp recent_presence_value?(_, _stale_after_ms), do: false

  defp normalize_driver_status(nil), do: nil

  defp normalize_driver_status(status) when is_map(status) do
    supported = truthy?(Map.get(status, "supported") || Map.get(status, :supported))
    loaded = truthy?(Map.get(status, "loaded") || Map.get(status, :loaded))
    connected = truthy?(Map.get(status, "connected") || Map.get(status, :connected))

    status
    |> stringify_keys()
    |> Map.put_new("supported", supported)
    |> Map.put_new("loaded", loaded)
    |> Map.put_new("connected", connected)
    |> Map.put_new("state", driver_state(supported, loaded, connected))
  end

  defp normalize_driver_status(_), do: nil

  defp serialize_health_status_detail(%{} = detail) do
    %{
      status: detail |> Map.get(:status, :unknown) |> to_string(),
      reasons: detail |> Map.get(:reasons, []) |> Enum.map(&to_string/1),
      metrics: Map.get(detail, :metrics, %{})
    }
  end

  defp serialize_health_status_detail(_), do: %{status: "unknown", reasons: [], metrics: %{}}

  defp driver_drop_counters(nil), do: %{}

  defp driver_drop_counters(status) when is_map(status) do
    %{
      eventsDropped: Map.get(status, "events_dropped"),
      channelDrops: Map.get(status, "channel_drops"),
      kernelEventsDropped: Map.get(status, "kernel_events_dropped")
    }
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
    |> Map.new()
  end

  defp driver_state(false, _loaded, _connected), do: "unsupported"
  defp driver_state(_supported, _loaded, true), do: "loaded"
  defp driver_state(_supported, true, false), do: "loaded_no_telemetry"
  defp driver_state(_supported, false, false), do: "not_loaded"

  defp truthy?(value) when value in [true, "true", 1, "1"], do: true
  defp truthy?(_), do: false

  defp stringify_keys(map) when is_map(map) do
    Map.new(map, fn
      {key, value} when is_atom(key) -> {Atom.to_string(key), value}
      {key, value} -> {key, value}
    end)
  end

  defp request_metadata(conn) do
    [
      ip_address: get_client_ip(conn),
      user_agent: get_user_agent(conn)
    ]
  end

  defp record_response_action(
         conn,
         user,
         action_type,
         agent_id,
         params,
         status,
         result,
         error_message \\ nil
       ) do
    attrs = %{
      agent_id: agent_id,
      action_type: action_type,
      alert_id: Map.get(params, "alert_id"),
      executed_by_id: user && user.id,
      organization_id: current_organization_id(conn),
      parameters: Map.drop(params, ["id"]),
      status: status,
      result: normalize_response_result(result),
      error_message: error_message,
      executed_at: DateTime.utc_now()
    }

    case Response.create_action(attrs) do
      {:ok, _action} ->
        :ok

      {:error, changeset} ->
        Logger.warning(
          "Failed to persist response action #{action_type}: #{inspect(changeset.errors)}"
        )

        :error
    end
  end

  defp normalize_response_result(nil), do: %{}
  defp normalize_response_result(result) when is_map(result), do: result
  defp normalize_response_result(result), do: %{"value" => inspect(result)}

  defp current_organization_id(conn) do
    conn.assigns[:current_organization_id] ||
      (conn.assigns[:current_user] && conn.assigns[:current_user].organization_id)
  end

  defp mobile_agent?(%Agent{os_type: os_type, config: config, tags: tags}) do
    os = String.downcase(to_string(os_type || ""))
    source = config |> stringify_keys() |> Map.get("source") |> to_string()
    tags = tags || []

    String.contains?(os, "android") or String.contains?(os, "ios") or
      String.contains?(os, "iphone") or String.contains?(os, "ipad") or
      mobile_source?(source) or mobile_tags?(tags)
  end

  defp mobile_agent?(%{} = agent) do
    os =
      (agent[:os_type] || agent["os_type"] || "")
      |> to_string()
      |> String.downcase()

    source =
      (agent[:config] || agent["config"] || %{})
      |> stringify_keys()
      |> Map.get("source")
      |> to_string()

    tags = agent[:tags] || agent["tags"] || []

    String.contains?(os, "android") or String.contains?(os, "ios") or
      String.contains?(os, "iphone") or String.contains?(os, "ipad") or
      mobile_source?(source) or mobile_tags?(tags)
  end

  defp mobile_agent?(_), do: false

  defp mobile_source?(source) do
    normalized =
      source
      |> to_string()
      |> String.downcase()

    normalized in ["tamandua_mobile", "tamandua_mobile_v2"]
  end

  defp mobile_tags?(tags) when is_list(tags) do
    tags
    |> Enum.map(&(to_string(&1) |> String.downcase()))
    |> Enum.any?(&(&1 in ["mobile", "mobile-v2", "mobile_endpoint"]))
  end

  defp mobile_tags?(_), do: false

  defp unsupported_mobile_host_action(conn, action) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{
      success: false,
      error: "#{action} is not available for mobile endpoints",
      platform: "mobile",
      supported_surface: "mobile endpoint commands"
    })
  end

  defp authorize_response_isolate(conn) do
    if RBAC.can?(conn.assigns[:current_user], :response_isolate, nil) do
      :ok
    else
      conn =
        conn
        |> put_status(:forbidden)
        |> put_view(json: TamanduaServerWeb.ErrorJSON)
        |> render(:error, %{
          error: "forbidden",
          message: "You don't have permission to perform this action",
          required_permission: :response_isolate
        })

      {:error, conn}
    end
  end

  defp get_client_ip(conn) do
    case get_req_header(conn, "x-forwarded-for") do
      [forwarded | _] ->
        forwarded
        |> String.split(",")
        |> List.first()
        |> String.trim()

      [] ->
        conn.remote_ip
        |> :inet.ntoa()
        |> to_string()
    end
  end

  defp get_user_agent(conn) do
    case get_req_header(conn, "user-agent") do
      [ua | _] -> ua
      [] -> nil
    end
  end
end
