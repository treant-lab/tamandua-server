defmodule TamanduaServerWeb.API.V1.DNSController do
  @moduledoc """
  API controller for DNS-related queries, statistics, and blocklist management.

  Provides endpoints to:
  - View DNS query statistics and top domains
  - Search and filter DNS query events
  - Manage the DNS blocklist (add, remove, import, list)
  - Broadcast block/unblock commands to agents via WebSocket
  """

  use TamanduaServerWeb, :controller
  require Logger

  import Ecto.Query, warn: false

  alias TamanduaServer.Repo
  alias TamanduaServer.Telemetry.Event
  alias TamanduaServer.Detection.DNSAnalyzer
  alias TamanduaServer.AuditLog

  action_fallback TamanduaServerWeb.FallbackController

  # ==========================================================================
  # GET /api/v1/dns/stats
  # ==========================================================================

  @doc """
  Return aggregate DNS statistics for the current day.

  Response:
    {
      "data": {
        "total_queries_today": 12345,
        "unique_domains": 987,
        "blocked_count": 42,
        "suspicious_count": 15
      }
    }
  """
  def stats(conn, _params) do
    today_start =
      DateTime.utc_now()
      |> Map.put(:hour, 0)
      |> Map.put(:minute, 0)
      |> Map.put(:second, 0)
      |> Map.put(:microsecond, {0, 0})
      |> DateTime.truncate(:second)

    base_query =
      from(e in Event,
        where: e.event_type == "dns_query",
        where: e.timestamp >= ^today_start
      )

    total_queries_today = Repo.aggregate(base_query, :count, :id)

    unique_domains =
      from(e in Event,
        where: e.event_type == "dns_query",
        where: e.timestamp >= ^today_start,
        select: fragment("COUNT(DISTINCT ?->>'query')", e.payload)
      )
      |> Repo.one() || 0

    # Blocked count: DNS events that matched a blocklist detection
    blocked_count =
      from(e in Event,
        where: e.event_type == "dns_query",
        where: e.timestamp >= ^today_start,
        where: fragment("?->>'blocked' = 'true'", e.payload)
      )
      |> Repo.aggregate(:count, :id)

    # Suspicious count: events with severity above info
    suspicious_count =
      from(e in Event,
        where: e.event_type == "dns_query",
        where: e.timestamp >= ^today_start,
        where: e.severity in ["medium", "high", "critical"]
      )
      |> Repo.aggregate(:count, :id)

    json(conn, %{
      data: %{
        total_queries_today: total_queries_today,
        unique_domains: unique_domains,
        blocked_count: blocked_count,
        suspicious_count: suspicious_count
      }
    })
  end

  # ==========================================================================
  # GET /api/v1/dns/queries
  # ==========================================================================

  @doc """
  Return paginated DNS query events with optional filters.

  Query parameters:
    - domain:     partial match on the queried domain name
    - query_type: DNS record type (A, AAAA, TXT, MX, etc.)
    - agent_id:   filter by specific agent
    - severity:   info | medium | high | critical
    - from:       ISO 8601 start time
    - to:         ISO 8601 end time
    - limit:      max results (default 100)
    - offset:     pagination offset (default 0)
  """
  def queries(conn, params) do
    # Support both limit/offset and page/per_page pagination styles
    {limit, offset} =
      case {params["page"], params["per_page"]} do
        {page, per_page} when not is_nil(page) ->
          p = parse_int(page, 1) |> max(1)
          pp = parse_int(per_page, 50) |> min(200)
          {pp, (p - 1) * pp}

        _ ->
          {parse_int(params["limit"], 100), parse_int(params["offset"], 0)}
      end

    base =
      from(e in Event,
        where: e.event_type == "dns_query",
        order_by: [desc: e.timestamp]
      )

    # Domain search (ILIKE on payload->>'query')
    base =
      case params["domain"] do
        nil -> base
        "" -> base
        domain ->
          pattern = "%#{domain}%"
          where(base, [e], fragment("?->>'query' ILIKE ?", e.payload, ^pattern))
      end

    # Query type filter
    base =
      case params["query_type"] do
        nil -> base
        "" -> base
        qt ->
          where(base, [e], fragment("?->>'query_type' = ?", e.payload, ^qt))
      end

    # Agent filter
    base =
      case params["agent_id"] do
        nil -> base
        "" -> base
        agent_id -> where(base, [e], e.agent_id == ^agent_id)
      end

    # Severity filter
    base =
      case params["severity"] do
        nil -> base
        "" -> base
        severity -> where(base, [e], e.severity == ^severity)
      end

    # Time range filters
    base = apply_time_filter(base, params["from"], :gte)
    base = apply_time_filter(base, params["to"], :lte)

    total = Repo.aggregate(base, :count, :id)

    events =
      base
      |> limit(^limit)
      |> offset(^offset)
      |> Repo.all()
      |> Enum.map(&serialize_dns_event/1)

    json(conn, %{
      data: events,
      meta: %{
        total: total,
        limit: limit,
        offset: offset
      }
    })
  end

  # ==========================================================================
  # GET /api/v1/dns/top-domains
  # ==========================================================================

  @doc """
  Return the top 20 most queried domains with counts.

  Query parameters:
    - time_range: "1h" | "24h" | "7d" (default "24h")
  """
  def top_domains(conn, params) do
    time_range = params["time_range"] || "24h"
    start_time = parse_time_range(time_range)

    results =
      from(e in Event,
        where: e.event_type == "dns_query",
        where: e.timestamp >= ^start_time,
        group_by: fragment("?->>'query'", e.payload),
        select: %{
          domain: fragment("?->>'query'", e.payload),
          count: count(e.id)
        },
        order_by: [desc: count(e.id)],
        limit: 20
      )
      |> Repo.all()

    json(conn, %{
      data: results,
      meta: %{time_range: time_range}
    })
  end

  # ==========================================================================
  # GET /api/v1/dns/blocklist
  # ==========================================================================

  @doc """
  Return the current DNS blocklist.

  Each entry contains:
    - domain
    - blocked_at (ISO 8601)
    - blocked_by
    - reason
  """
  def blocklist_index(conn, _params) do
    with {:ok, organization_id} <- current_organization_id(conn) do
      entries =
        organization_id
        |> DNSAnalyzer.get_blocklist()
        |> Enum.map(fn entry ->
          %{
            domain: entry[:domain],
            blocked_at: format_datetime(entry[:blocked_at]),
            blocked_by: entry[:blocked_by],
            reason: entry[:reason],
            source: entry[:source]
          }
        end)

      json(conn, %{data: entries})
    else
      {:error, :missing_organization} -> missing_organization_response(conn)
    end
  end

  # ==========================================================================
  # POST /api/v1/dns/blocklist
  # ==========================================================================

  @doc """
  Add one or more domains to the blocklist.

  Body:
    {
      "domains": ["evil.com", "bad.net"],
      "reason": "Malicious C2"
    }

  Broadcasts a dns_block command to all connected agents.
  """
  def blocklist_create(conn, %{"domains" => domains} = params) when is_list(domains) do
    reason = params["reason"] || "Manual block"
    blocked_by = get_current_user(conn)

    with {:ok, organization_id} <- current_organization_id(conn),
         {:ok, count} <- DNSAnalyzer.add_to_blocklist(domains, reason, blocked_by, organization_id) do
      # Broadcast block command to all agents
      broadcast_dns_command(:block, domains, reason, organization_id)
      log_dns_blocklist_change(conn, "add", domains, %{added: count, reason: reason})

      conn
      |> put_status(:created)
      |> json(%{
        data: %{
          added: count,
          domains: domains,
          reason: reason
        }
      })
    else
      {:error, :missing_organization} ->
        missing_organization_response(conn)

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Failed to update DNS blocklist", reason: inspect(reason)})
    end
  end

  def blocklist_create(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required field 'domains' (array of strings)"})
  end

  # ==========================================================================
  # DELETE /api/v1/dns/blocklist/:domain
  # ==========================================================================

  @doc """
  Remove a domain from the blocklist.

  Broadcasts a dns_unblock command to all connected agents.
  """
  def blocklist_delete(conn, %{"domain" => domain}) do
    with {:ok, organization_id} <- current_organization_id(conn) do
      case DNSAnalyzer.remove_from_blocklist(domain, organization_id) do
      :ok ->
        broadcast_dns_command(:unblock, [domain], "Removed from blocklist", organization_id)
        log_dns_blocklist_change(conn, "remove", [domain], %{reason: "Removed from blocklist"})
        send_resp(conn, :no_content, "")

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Domain '#{domain}' not found in blocklist"})
      end
    else
      {:error, :missing_organization} -> missing_organization_response(conn)
    end
  end

  # ==========================================================================
  # GET /api/v1/dns/alerts
  # ==========================================================================

  @doc """
  Return DNS-specific alerts (DGA detection, tunneling, malicious domain queries, etc.).

  Query parameters:
    - severity:   critical | high | medium | low
    - limit:      max results (default 50)
    - offset:     pagination offset (default 0)

  Response:
    {
      "data": [
        {
          "id": "uuid",
          "domain": "suspicious.example.com",
          "detectionType": "dga",
          "severity": "high",
          "timestamp": "2026-01-28T10:30:00Z",
          "agentId": "uuid",
          "agentHostname": "workstation-01",
          "description": "Possible DGA-generated domain detected",
          "alertId": "uuid"
        }
      ]
    }
  """
  def alerts(conn, params) do
    alias TamanduaServer.Alerts.Alert
    alias TamanduaServer.Agents.Agent

    limit = parse_int(params["limit"], 50)
    offset = parse_int(params["offset"], 0)

    # Query alerts that are DNS-related based on title, description, or detection metadata
    base_query =
      from(a in Alert,
        left_join: agent in Agent,
        on: a.agent_id == agent.id,
        where:
          ilike(a.title, ^"%DNS%") or
            ilike(a.title, ^"%DGA%") or
            ilike(a.title, ^"%domain%") or
            ilike(a.title, ^"%tunneling%") or
            ilike(a.title, ^"%exfiltration%") or
            ilike(a.description, ^"%DNS%") or
            ilike(a.description, ^"%DGA%") or
            ilike(a.description, ^"%domain%") or
            fragment("?->>'detection_type' ILIKE ?", a.detection_metadata, "%dns%") or
            fragment("?->>'detection_type' ILIKE ?", a.detection_metadata, "%dga%") or
            fragment("?->>'event_type' = ?", a.detection_metadata, "dns_query"),
        order_by: [desc: a.inserted_at],
        select: %{
          id: a.id,
          alert_id: a.id,
          title: a.title,
          description: a.description,
          severity: a.severity,
          status: a.status,
          timestamp: a.inserted_at,
          agent_id: a.agent_id,
          agent_hostname: agent.hostname,
          detection_metadata: a.detection_metadata,
          evidence: a.evidence,
          raw_event: a.raw_event
        }
      )

    # Apply severity filter if provided
    base_query =
      case params["severity"] do
        nil -> base_query
        "" -> base_query
        severity -> where(base_query, [a], a.severity == ^severity)
      end

    total = Repo.aggregate(base_query, :count)

    alerts =
      base_query
      |> limit(^limit)
      |> offset(^offset)
      |> Repo.all()
      |> Enum.map(&serialize_dns_alert/1)

    json(conn, %{
      data: alerts,
      alerts: alerts,
      meta: %{
        total: total,
        limit: limit,
        offset: offset
      }
    })
  end

  # ==========================================================================
  # POST /api/v1/dns/blocklist/import
  # ==========================================================================

  @doc """
  Bulk import domains from a text body (one domain per line).

  Body:
    {
      "text": "evil.com\\nbad.net\\nmalware.org",
      "reason": "Threat feed import"
    }
  """
  def blocklist_import(conn, %{"text" => text} = params) when is_binary(text) do
    reason = params["reason"] || "Bulk import"

    domains =
      text
      |> String.split(~r/[\r\n]+/)
      |> Enum.map(&String.trim/1)
      |> Enum.reject(&(&1 == "" or String.starts_with?(&1, "#")))

    with {:ok, organization_id} <- current_organization_id(conn),
         {:ok, count} <- DNSAnalyzer.import_blocklist(domains, reason, organization_id) do
      # Broadcast block commands for imported domains
      if count > 0 do
        broadcast_dns_command(:block, domains, reason, organization_id)
      end

      log_dns_blocklist_change(conn, "import", domains, %{
        imported: count,
        total_lines: length(domains),
        reason: reason
      })

      conn
      |> put_status(:created)
      |> json(%{
        data: %{
          imported: count,
          total_lines: length(domains),
          reason: reason
        }
      })
    else
      {:error, :missing_organization} ->
        missing_organization_response(conn)

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Failed to import DNS blocklist", reason: inspect(reason)})
    end
  end

  def blocklist_import(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required field 'text' (newline-separated domain list)"})
  end

  # ==========================================================================
  # Private Helpers
  # ==========================================================================

  defp serialize_dns_event(event) do
    payload = event.payload || %{}
    process_payload = payload["process"] || payload[:process] || %{}
    dns_payload = payload["dns"] || payload[:dns] || %{}

    %{
      id: event.id,
      agent_id: event.agent_id,
      timestamp: format_timestamp(event.timestamp),
      severity: event.severity,
      domain: first_present([
        payload["query"],
        payload[:query],
        payload["query_name"],
        payload[:query_name],
        payload["domain"],
        payload[:domain],
        dns_payload["query"],
        dns_payload[:query],
        dns_payload["query_name"],
        dns_payload[:query_name]
      ]),
      query_type: first_present([
        payload["query_type"],
        payload[:query_type],
        payload["record_type"],
        payload[:record_type],
        payload["type"],
        payload[:type],
        dns_payload["query_type"],
        dns_payload[:query_type],
        dns_payload["record_type"],
        dns_payload[:record_type]
      ], "A"),
      response: first_present([
        payload["response"],
        payload[:response],
        payload["resolved_ip"],
        payload[:resolved_ip],
        payload["answer"],
        payload[:answer],
        format_responses(payload["responses"] || payload[:responses]),
        format_responses(dns_payload["responses"] || dns_payload[:responses]),
        format_responses(payload["resolved_ips"] || payload[:resolved_ips]),
        format_responses(dns_payload["resolved_ips"] || dns_payload[:resolved_ips])
      ], ""),
      response_code: first_present([
        payload["response_code"],
        payload[:response_code],
        payload["rcode"],
        payload[:rcode],
        dns_payload["response_code"],
        dns_payload[:response_code],
        dns_payload["rcode"],
        dns_payload[:rcode]
      ]),
      pid: safe_int(first_present([
        payload["pid"],
        payload[:pid],
        process_payload["pid"],
        process_payload[:pid]
      ]), 0),
      process_name: first_present([
        payload["process_name"],
        payload[:process_name],
        payload["name"],
        payload[:name],
        process_payload["name"],
        process_payload[:name]
      ], "Unknown"),
      process_path: first_present([
        payload["process_path"],
        payload[:process_path],
        payload["path"],
        payload[:path],
        process_payload["path"],
        process_payload[:path],
        process_payload["process_path"],
        process_payload[:process_path]
      ]),
      blocked: payload["blocked"] || payload[:blocked] || false,
      payload: payload
    }
  end

  defp first_present(values, default \\ nil) do
    Enum.find_value(values, default, fn
      nil -> nil
      "" -> nil
      [] -> nil
      value -> value
    end)
  end

  defp format_responses(nil), do: nil
  defp format_responses([]), do: nil
  defp format_responses(responses) when is_list(responses), do: Enum.join(responses, ", ")
  defp format_responses(response), do: response

  defp safe_int(nil, default), do: default
  defp safe_int(value, _default) when is_integer(value), do: value
  defp safe_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> default
    end
  end
  defp safe_int(_, default), do: default

  defp serialize_dns_alert(alert) do
    detection_metadata = alert.detection_metadata || %{}
    evidence = alert.evidence || %{}
    raw_event = alert.raw_event || %{}

    # Try to extract domain from various sources
    domain =
      detection_metadata["domain"] ||
        detection_metadata[:domain] ||
        evidence["domain"] ||
        evidence[:domain] ||
        raw_event["query"] ||
        raw_event[:query] ||
        raw_event["domain"] ||
        raw_event[:domain] ||
        extract_domain_from_title(alert.title) ||
        "Unknown"

    # Determine detection type from metadata or title
    detection_type =
      detection_metadata["detection_type"] ||
        detection_metadata[:detection_type] ||
        infer_detection_type(alert.title, alert.description)

    %{
      id: alert.id,
      alertId: alert.alert_id,
      domain: domain,
      detectionType: detection_type,
      severity: alert.severity,
      timestamp: format_timestamp(alert.timestamp),
      agentId: alert.agent_id,
      agentHostname: alert.agent_hostname || "Unknown",
      description: alert.description || alert.title
    }
  end

  defp extract_domain_from_title(nil), do: nil

  defp extract_domain_from_title(title) do
    # Try to extract a domain-like pattern from the title
    case Regex.run(~r/([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}/, title) do
      [domain | _] -> domain
      _ -> nil
    end
  end

  defp infer_detection_type(title, description) do
    text = String.downcase("#{title} #{description}")

    cond do
      String.contains?(text, "dga") -> "dga"
      String.contains?(text, "tunnel") -> "tunneling"
      String.contains?(text, "exfiltration") -> "exfiltration"
      String.contains?(text, "c2") or String.contains?(text, "command and control") -> "ioc_match"
      String.contains?(text, "malicious") -> "ioc_match"
      String.contains?(text, "suspicious") -> "suspicious_domain"
      String.contains?(text, "dns") -> "suspicious_domain"
      true -> "suspicious_domain"
    end
  end

  defp apply_time_filter(query, nil, _direction), do: query
  defp apply_time_filter(query, "", _direction), do: query

  defp apply_time_filter(query, time_str, direction) when is_binary(time_str) do
    case parse_datetime(time_str) do
      {:ok, dt} ->
        case direction do
          :gte -> where(query, [e], e.timestamp >= ^dt)
          :lte -> where(query, [e], e.timestamp <= ^dt)
        end

      :error ->
        query
    end
  end

  defp parse_datetime(str) do
    case DateTime.from_iso8601(str) do
      {:ok, dt, _offset} ->
        {:ok, dt}

      {:error, _} ->
        case NaiveDateTime.from_iso8601(str) do
          {:ok, ndt} ->
            {:ok, DateTime.from_naive!(ndt, "Etc/UTC")}

          {:error, _} ->
            case Date.from_iso8601(str) do
              {:ok, date} ->
                {:ok, DateTime.new!(date, ~T[00:00:00], "Etc/UTC")}

              {:error, _} ->
                :error
            end
        end
    end
  end

  defp parse_time_range("1h"), do: DateTime.utc_now() |> DateTime.add(-1, :hour)
  defp parse_time_range("24h"), do: DateTime.utc_now() |> DateTime.add(-24, :hour)
  defp parse_time_range("7d"), do: DateTime.utc_now() |> DateTime.add(-7, :day)
  defp parse_time_range(_), do: DateTime.utc_now() |> DateTime.add(-24, :hour)

  defp format_timestamp(%NaiveDateTime{} = ts), do: NaiveDateTime.to_iso8601(ts)
  defp format_timestamp(%DateTime{} = ts), do: DateTime.to_iso8601(ts)
  defp format_timestamp(ts) when is_binary(ts), do: ts
  defp format_timestamp(_), do: nil

  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp format_datetime(nil), do: nil
  defp format_datetime(other), do: inspect(other)

  defp parse_int(nil, default), do: default

  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> default
    end
  end

  defp parse_int(value, _default) when is_integer(value), do: value

  defp get_current_user(conn) do
    case conn.assigns[:current_user] do
      nil -> "api"
      user -> user.email || user.username || "api"
    end
  end

  defp log_dns_blocklist_change(conn, action, domains, details) do
    user = conn.assigns[:current_user]

    AuditLog.log_rule_change(
      user,
      "dns_blocklist",
      action,
      Enum.join(Enum.take(domains, 5), ","),
      Map.merge(details, %{
        domains: domains,
        domain_count: length(domains)
      }),
      request_metadata(conn)
    )
  rescue
    e ->
      Logger.warning("Failed to audit DNS blocklist change: #{inspect(e)}")
      :ok
  end

  defp request_metadata(conn) do
    [
      ip_address: get_client_ip(conn),
      user_agent: get_user_agent(conn)
    ]
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

  defp current_organization_id(conn) do
    organization_id =
      conn.assigns[:current_organization_id] ||
        (conn.assigns[:current_user] && conn.assigns[:current_user].organization_id)

    if organization_id, do: {:ok, organization_id}, else: {:error, :missing_organization}
  end

  defp missing_organization_response(conn) do
    conn
    |> put_status(:forbidden)
    |> json(%{error: "Missing organization context"})
  end

  defp broadcast_dns_command(action, domains, reason, organization_id) do
    command_type =
      case action do
        :block -> "block_domain"
        :unblock -> "unblock_domain"
      end

    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "agents:commands:#{organization_id}",
      {:broadcast_command,
       %{type: command_type, domains: domains, reason: reason, organization_id: organization_id}}
    )

    # Also broadcast to each connected agent's channel
    case TamanduaServer.Agents.Registry.list() do
      agents when is_list(agents) ->
        Enum.each(agents, fn agent ->
          agent_id = if is_map(agent), do: agent.id || agent[:agent_id], else: agent

          if agent_id && agent_belongs_to_org?(agent_id, organization_id) do
            Enum.each(domains, fn domain ->
              Phoenix.PubSub.broadcast(
                TamanduaServer.PubSub,
                "agent:#{agent_id}",
                {:send_command,
                 %{
                   command_id: Ecto.UUID.generate(),
                   command_type: command_type,
                   timestamp: System.system_time(:millisecond),
                   payload: %{
                     domain: domain,
                     reason: reason
                   }
                 }}
              )
            end)
          end
        end)

      _ ->
        :ok
    end
  rescue
    e ->
      Logger.warning("Failed to broadcast DNS command: #{inspect(e)}")
      :ok
  end

  defp agent_belongs_to_org?(agent_id, organization_id) do
    TamanduaServer.Agents.OrgLookup.get_org_id(agent_id) == organization_id
  rescue
    _ -> false
  end
end
