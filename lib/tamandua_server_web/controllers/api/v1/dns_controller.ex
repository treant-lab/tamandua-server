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
  alias TamanduaServer.Detection.DNSBlocklist
  alias TamanduaServer.AuditLog

  action_fallback TamanduaServerWeb.FallbackController

  def action(conn, _opts) do
    apply(__MODULE__, action_name(conn), [conn, conn.params])
  rescue
    exception ->
      Logger.warning("DNS API action #{action_name(conn)} failed: #{Exception.message(exception)}")

      conn
      |> put_status(:service_unavailable)
      |> json(%{
        error: "dns_service_unavailable",
        message: "DNS service is unavailable",
        detail: Exception.message(exception)
      })
  catch
    :exit, {:noproc, _} ->
      conn
      |> put_status(:service_unavailable)
      |> json(%{
        error: "dns_service_unavailable",
        message: "DNS analyzer is not running in this boot profile"
      })

    :exit, {:timeout, _} ->
      conn
      |> put_status(:gateway_timeout)
      |> json(%{error: "dns_service_timeout", message: "DNS service timed out"})

    kind, reason ->
      Logger.warning("DNS API action #{action_name(conn)} failed: #{inspect(kind)} #{inspect(reason)}")

      conn
      |> put_status(:service_unavailable)
      |> json(%{error: "dns_service_unavailable", message: "DNS service is unavailable"})
  end

  @default_query_limit 50
  @max_query_limit 100
  @top_domain_sample_limit 200
  @default_query_window_hours 24
  @dns_event_types ["dns_query", "dns", "dns_response", "name_resolution", "domain_lookup"]
  @dns_transport_ports ["53", "5353"]
  @dot_ports ["853"]
  @doh_ports ["443", "8443"]
  @known_doh_ips [
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
    "94.140.14.14",
    "94.140.15.15",
    "76.76.2.0",
    "76.76.10.0",
    "185.228.168.9",
    "185.228.169.9"
  ]
  @known_doh_domains [
    "cloudflare-dns.com",
    "dns.google",
    "dns.quad9.net",
    "dns.adguard.com",
    "doh.opendns.com",
    "dns.nextdns.io",
    "dns.cleanbrowsing.org"
  ]
  @default_dns_feed_names [
    "abusech_feodo",
    "abusech_urlhaus",
    "abusech_threatfox",
    "abusech_malware_bazaar",
    "abusech_ssl_blacklist",
    "emergingthreats",
    "tor_exit_nodes",
    "phishtank",
    "openphish",
    "spamhaus_drop",
    "firehol_level1",
    "c2_intel_feeds"
  ]

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
    with {:ok, organization_id} <- current_organization_id(conn) do
      stats_for_org(conn, organization_id)
    else
      {:error, :missing_organization} -> missing_organization_response(conn)
    end
  end

  defp stats_for_org(conn, organization_id) do
    now = DateTime.utc_now()

    today_start =
      now
      |> Map.put(:hour, 0)
      |> Map.put(:minute, 0)
      |> Map.put(:second, 0)
      |> Map.put(:microsecond, {0, 0})
      |> DateTime.truncate(:second)

    base_query =
      Event
      |> dns_events_query()
      |> scope_event_org(organization_id)
      |> where([e], e.timestamp >= ^today_start)
      |> where([e], e.timestamp <= ^now)

    {total_queries_today, total_queries_error} =
      safe_repo_value_with_meta("DNS stats total queries", 0, fn ->
        Repo.aggregate(base_query, :count, :id)
      end)

    {unique_domains, unique_domains_error} =
      Event
      |> dns_events_query()
      |> scope_event_org(organization_id)
      |> where([e], e.timestamp >= ^today_start)
      |> where([e], e.timestamp <= ^now)
      |> select([e],
        fragment(
          "COUNT(DISTINCT COALESCE(?->>'query', ?->>'query_name', ?->>'domain', ?->>'dns_query', ?->>'dns.domain', ?->>'host', ?->>'hostname', ?->'dns'->>'query', ?->'dns'->>'query_name', ?->'dns'->>'domain'))",
          e.payload,
          e.payload,
          e.payload,
          e.payload,
          e.payload,
          e.payload,
          e.payload,
          e.payload,
          e.payload,
          e.payload
        )
      )
      |> then(fn query ->
        safe_repo_value_with_meta("DNS stats unique domains", 0, fn -> Repo.one(query) || 0 end)
      end)

    # Blocked count: DNS events that matched a blocklist detection
    {blocked_count, blocked_count_error} =
      Event
      |> dns_events_query()
      |> scope_event_org(organization_id)
      |> where([e], e.timestamp >= ^today_start)
      |> where([e], e.timestamp <= ^now)
      |> where([e], fragment("?->>'blocked' = 'true'", e.payload))
      |> then(fn query ->
        safe_repo_value_with_meta("DNS stats blocked count", 0, fn -> Repo.aggregate(query, :count, :id) end)
      end)

    # Suspicious count: events with severity above info
    {suspicious_count, suspicious_count_error} =
      Event
      |> dns_events_query()
      |> scope_event_org(organization_id)
      |> where([e], e.timestamp >= ^today_start)
      |> where([e], e.timestamp <= ^now)
      |> where([e], e.severity in ["medium", "high", "critical"])
      |> then(fn query ->
        safe_repo_value_with_meta("DNS stats suspicious count", 0, fn -> Repo.aggregate(query, :count, :id) end)
      end)

    meta =
      dns_partial_meta([
        total_queries_error,
        unique_domains_error,
        blocked_count_error,
        suspicious_count_error
      ])

    json(conn, %{
      data: %{
        total_queries_today: total_queries_today,
        unique_domains: unique_domains,
        blocked_count: blocked_count,
        suspicious_count: suspicious_count
      },
      meta: Map.put(meta, :scope, "organization_dns_telemetry")
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
    - time_range:  24h | 7d | 30d | all (default 24h)
    - from:       ISO 8601 start time
    - to:         ISO 8601 end time
    - limit:      max results (default 100)
    - offset:     pagination offset (default 0)
  """
  def queries(conn, params) do
    with {:ok, organization_id} <- current_organization_id(conn) do
      queries_for_org(conn, params, organization_id)
    else
      {:error, :missing_organization} -> missing_organization_response(conn)
    end
  end

  defp queries_for_org(conn, params, organization_id) do
    now = DateTime.utc_now()

    # Support both limit/offset and page/per_page pagination styles
    {limit, offset} =
      case {params["page"], params["per_page"]} do
        {page, per_page} when not is_nil(page) ->
          p = parse_int(page, 1) |> max(1)
          pp = bounded_limit(per_page, @default_query_limit, @max_query_limit)
          {pp, (p - 1) * pp}

        _ ->
          {bounded_limit(params["limit"], @default_query_limit, @max_query_limit), bounded_offset(params["offset"])}
      end

    base =
      Event
      |> dns_events_query(params)
      |> scope_event_org(organization_id)
      |> where([e], e.timestamp <= ^now)
      |> apply_query_window(params, now)
      |> order_by([e], desc: e.timestamp)

    # Domain search (ILIKE on known DNS domain fields)
    base =
      case params["domain"] do
        nil -> base
        "" -> base
        domain ->
          pattern = "%#{domain}%"
          where(
            base,
            [e],
            fragment(
              "COALESCE(?->>'query', ?->>'query_name', ?->>'domain', ?->>'dns_query', ?->>'dns.domain', ?->>'host', ?->>'hostname', ?->'dns'->>'query', ?->'dns'->>'query_name', ?->'dns'->>'domain') ILIKE ?",
              e.payload,
              e.payload,
              e.payload,
              e.payload,
              e.payload,
              e.payload,
              e.payload,
              e.payload,
              e.payload,
              e.payload,
              ^pattern
            )
          )
      end

    # Process filter
    base =
      case params["process"] do
        nil ->
          base

        "" ->
          base

        process ->
          pattern = "%#{process}%"

          where(
            base,
            [e],
            fragment(
              "COALESCE(?->>'process_name', ?->>'processName', ?->>'process_path', ?->>'processPath', ?->>'pid', ?->>'process_pid', ?->'process'->>'name', ?->'process'->>'path', ?->'process'->>'pid') ILIKE ?",
              e.payload,
              e.payload,
              e.payload,
              e.payload,
              e.payload,
              e.payload,
              e.payload,
              e.payload,
              e.payload,
              ^pattern
            )
          )
      end

    # Query type filter
    base =
      case params["query_type"] do
        nil -> base
        "" -> base
        "TRANSPORT" -> where(base, ^dns_transport_dynamic())
        "DOH" -> where(base, ^doh_dynamic())
        "DOT" -> where(base, ^dot_dynamic())
        qt ->
          where(
            base,
            [e],
            fragment(
              "COALESCE(?->>'query_type', ?->>'record_type', ?->>'dns.query_type', ?->>'dns.record_type', ?->'dns'->>'query_type', ?->'dns'->>'record_type') = ?",
              e.payload,
              e.payload,
              e.payload,
              e.payload,
              e.payload,
              e.payload,
              ^qt
            )
          )
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

    {rows, query_error} =
      base
      |> limit(^(limit + 1))
      |> offset(^offset)
      |> safe_repo_all_with_meta("DNS query feed")

    has_more = length(rows) > limit

    events =
      rows
      |> Enum.take(limit)
      |> Enum.map(&serialize_dns_event/1)

    total = offset + length(events) + if(has_more, do: 1, else: 0)

    json(conn, %{
      data: events,
      meta: Map.merge(%{
        total: total,
        limit: limit,
        offset: offset,
        has_more: has_more,
        total_is_estimate: true,
        default_window_hours: default_query_window_hours(params),
        time_range: dns_time_range(params),
        scope: "organization_dns_telemetry"
      }, dns_partial_meta([query_error]))
    })
  end

  # ==========================================================================
  # GET /api/v1/dns/top-domains
  # ==========================================================================

  @doc """
  Return the top 20 most queried domains with counts.

  Query parameters:
    - time_range: "1h" | "24h" | "7d" | "30d" | "all" (default "24h")
  """
  def top_domains(conn, params) do
    with {:ok, organization_id} <- current_organization_id(conn) do
      top_domains_for_org(conn, params, organization_id)
    else
      {:error, :missing_organization} -> missing_organization_response(conn)
    end
  end

  defp top_domains_for_org(conn, params, organization_id) do
    time_range = dns_time_range(params)
    start_time = parse_time_range(time_range)
    now = DateTime.utc_now()

    base_query =
      Event
      |> dns_events_query(params)
      |> scope_event_org(organization_id)
      |> where([e], e.timestamp <= ^now)

    base_query =
      if start_time do
        where(base_query, [e], e.timestamp >= ^start_time)
      else
        base_query
      end

    {rows, top_domains_error} =
      base_query
      |> apply_top_domain_sample_order(time_range)
      |> limit(@top_domain_sample_limit)
      |> safe_repo_all_with_meta("DNS top domains")

    results =
      rows
      |> Enum.map(&serialize_dns_event/1)
      |> Enum.map(&Map.get(&1, :domain))
      |> Enum.filter(&(is_binary(&1) and String.trim(&1) != ""))
      |> Enum.frequencies()
      |> Enum.map(fn {domain, count} -> %{domain: domain, count: count} end)
      |> Enum.sort_by(fn item -> {-item.count, item.domain} end)
      |> Enum.take(20)

    json(conn, %{
      data: results,
      meta:
        Map.merge(
          %{
            time_range: time_range,
            scope: "organization_dns_telemetry",
            sampled: true,
            sample_limit: @top_domain_sample_limit,
            sample_order: top_domain_sample_order(time_range),
            sampled_events: length(rows)
          },
          dns_partial_meta([top_domains_error])
        )
    })
  end

  # The agent has emitted DNS telemetry under a few historical shapes. Keep the
  # dashboard query inclusive so live and retained events do not disappear.
  defp dns_events_query(queryable, params \\ %{}) do
    where(queryable, ^dns_event_dynamic(dns_time_range(params)))
  end

  defp scope_event_org(queryable, organization_id) do
    where(queryable, [e], e.organization_id == ^organization_id)
  end

  defp apply_query_window(queryable, params, now) do
    cond do
      not blank_param?(params["from"]) or not blank_param?(params["to"]) ->
        queryable

      dns_time_range(params) == "all" ->
        queryable

      true ->
        from = parse_time_range(dns_time_range(params), now)
        where(queryable, [e], e.timestamp >= ^from)
    end
  end

  defp default_query_window_hours(params) do
    if blank_param?(params["from"]) and blank_param?(params["to"]) and dns_time_range(params) == "24h" do
      @default_query_window_hours
    else
      nil
    end
  end

  defp dns_time_range(%{"time_range" => value}) when value in ["1h", "24h", "7d", "30d", "all"], do: value
  defp dns_time_range(_params), do: "24h"

  defp blank_param?(nil), do: true
  defp blank_param?(""), do: true
  defp blank_param?(_), do: false

  defp apply_top_domain_sample_order(query, _time_range) do
    order_by(query, [e], desc: e.timestamp)
  end

  defp top_domain_sample_order(_time_range), do: "latest_first"

  defp safe_repo_all_with_meta(query, label) do
    {Repo.all(query, timeout: 8_000), nil}
  rescue
    error in [DBConnection.ConnectionError, Postgrex.Error] ->
      Logger.warning("#{label} failed: #{Exception.message(error)}")
      {[], "#{label}: #{Exception.message(error)}"}
  catch
    :exit, reason ->
      Logger.warning("#{label} failed: exit #{inspect(reason)}")
      {[], "#{label}: exit #{inspect(reason)}"}
  end

  defp safe_repo_value_with_meta(label, default, fun) when is_function(fun, 0) do
    {fun.(), nil}
  rescue
    error in [DBConnection.ConnectionError, Postgrex.Error] ->
      Logger.warning("#{label} failed: #{Exception.message(error)}")
      {default, "#{label}: #{Exception.message(error)}"}
  catch
    :exit, reason ->
      Logger.warning("#{label} failed: exit #{inspect(reason)}")
      {default, "#{label}: exit #{inspect(reason)}"}
  end

  defp safe_dns_analyzer_call(label, fun) when is_function(fun, 0) do
    {:ok, fun.()}
  rescue
    error ->
      message = "#{label}: #{Exception.message(error)}"
      Logger.warning("#{label} failed: #{Exception.message(error)}")
      {:error, message}
  catch
    :exit, {:noproc, _} ->
      message = "#{label}: DNS analyzer is not running"
      Logger.warning(message)
      {:error, message}

    :exit, {:timeout, _} ->
      message = "#{label}: DNS analyzer timed out"
      Logger.warning(message)
      {:error, message}

    :exit, reason ->
      message = "#{label}: exit #{inspect(reason)}"
      Logger.warning(message)
      {:error, message}
  end

  defp dns_analyzer_unavailable_response(conn, reason) do
    conn
    |> put_status(:service_unavailable)
    |> json(%{
      error: "dns_service_unavailable",
      message: "DNS analyzer is unavailable",
      detail: reason
    })
  end

  defp list_dns_blocklist_entries(organization_id) do
    case safe_dns_analyzer_call("DNS blocklist overrides", fn ->
           DNSAnalyzer.get_blocklist(organization_id)
         end) do
      {:ok, entries} when is_list(entries) ->
        {entries, nil}

      {:ok, _unexpected} ->
        {[], "DNS blocklist overrides returned an unexpected payload"}

      {:error, reason} ->
        entries =
          organization_id
          |> DNSBlocklist.list_entries()
          |> Enum.map(fn entry ->
            %{
              domain: entry.normalized_domain || entry.domain,
              blocked_at: entry.updated_at || entry.inserted_at,
              blocked_by: entry.blocked_by,
              reason: entry.reason,
              source: entry.source
            }
          end)

        {entries, reason}
    end
  rescue
    error ->
      message = "DNS blocklist overrides fallback: #{Exception.message(error)}"
      Logger.warning(message)
      {[], message}
  end

  defp dns_partial_meta(errors) do
    unavailable =
      errors
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()

    %{
      partial: unavailable != [],
      unavailable: unavailable,
      message:
        if unavailable == [] do
          nil
        else
          "DNS telemetry is partially unavailable; zero values may be fallback values."
        end
    }
  end

  defp dns_event_dynamic(time_range) when time_range in ["24h", "1h"] do
    dynamic([e], ^dns_explicit_event_dynamic() or ^dns_transport_dynamic() or ^doh_dynamic() or ^dot_dynamic())
  end

  defp dns_event_dynamic(_time_range), do: dns_explicit_event_dynamic()

  defp dns_explicit_event_dynamic do
    dynamic([e], e.event_type in ^@dns_event_types or like(e.event_type, "dns%"))
  end

  defp dns_transport_dynamic do
    dynamic(
      [e],
      e.event_type in ["network_connect", "network_connection"] and
        ^network_port_dynamic(@dns_transport_ports) and
        ^useful_remote_endpoint_dynamic()
    )
  end

  defp dot_dynamic do
    dynamic(
      [e],
      e.event_type in ["network_connect", "network_connection"] and
        ^network_port_dynamic(@dot_ports) and
        ^useful_remote_endpoint_dynamic()
    )
  end

  defp doh_dynamic do
    dynamic(
      [e],
      e.event_type in ["network_connect", "network_connection"] and
        ^network_port_dynamic(@doh_ports) and
        (fragment("?->>'remote_ip' = ANY(?::text[])", e.payload, ^@known_doh_ips) or
           fragment(
             "lower(COALESCE(?->>'domain', ?->>'remote_domain', ?->>'sni', ?->>'tls_sni', ?->>'host', ?->>'hostname')) = ANY(?::text[])",
             e.payload,
             e.payload,
             e.payload,
             e.payload,
             e.payload,
             e.payload,
             ^@known_doh_domains
           ))
    )
  end

  defp network_port_dynamic(ports) do
    dynamic(
      [e],
      fragment(
        "COALESCE(?->>'remote_port', ?->>'destination_port', ?->>'dst_port', ?->>'port') = ANY(?::text[])",
        e.payload,
        e.payload,
        e.payload,
        e.payload,
        ^ports
      ) or
        (fragment("lower(COALESCE(?->>'protocol', ?->>'transport'))", e.payload, e.payload) == "udp" and
           fragment(
             "COALESCE(?->>'local_port', ?->>'source_port', ?->>'src_port') = ANY(?::text[])",
             e.payload,
             e.payload,
             e.payload,
             ^ports
           ))
    )
  end

  defp useful_remote_endpoint_dynamic do
    dynamic(
      [e],
      fragment(
        "NULLIF(COALESCE(?->>'remote_ip', ?->>'remoteIp', ?->>'dst_ip', ?->>'destination_ip'), '') IS NOT NULL",
        e.payload,
        e.payload,
        e.payload,
        e.payload
      ) and
        fragment(
          "COALESCE(?->>'remote_ip', ?->>'remoteIp', ?->>'dst_ip', ?->>'destination_ip') NOT IN ('0.0.0.0', '::', '::0', '[::]')",
          e.payload,
          e.payload,
          e.payload,
          e.payload
        ) and
        fragment(
          "COALESCE(?->>'remote_port', ?->>'remotePort', ?->>'destination_port', ?->>'destinationPort', ?->>'dst_port', ?->>'dstPort', ?->>'port') NOT IN ('', '0')",
          e.payload,
          e.payload,
          e.payload,
          e.payload,
          e.payload,
          e.payload,
          e.payload
        )
    )
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
      {entries, blocklist_error} = list_dns_blocklist_entries(organization_id)

      entries =
        Enum.map(entries, fn entry ->
          %{
            domain: entry[:domain],
            blocked_at: format_datetime(entry[:blocked_at]),
            blocked_by: entry[:blocked_by],
            reason: entry[:reason],
            source: entry[:source]
          }
        end)

      json(conn, %{
        data: entries,
        meta: Map.merge(%{
          explicit_overrides: length(entries),
          default_feed_count: length(@default_dns_feed_names),
          default_feeds_loaded: false,
          default_feeds: default_dns_feed_summaries(),
          default_feed_source: "threat_intel_feed_status",
          default_feed_note:
            "Default feed names are configured references, not tenant DNS blocklist entries. Use feed_status_endpoint for live IOC counts and health.",
          feed_status_endpoint: "/api/v1/threat-intel/feed-status",
          scope: "tenant_dns_blocklist_overrides"
        }, dns_partial_meta([blocklist_error]))
      })
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
         {:ok, {:ok, count}} <-
           safe_dns_analyzer_call("DNS blocklist add", fn ->
             DNSAnalyzer.add_to_blocklist(domains, reason, blocked_by, organization_id)
           end) do
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

      {:error, reason} when is_binary(reason) ->
        dns_analyzer_unavailable_response(conn, reason)

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Failed to update DNS blocklist", reason: inspect(reason)})

      {:ok, {:error, reason}} ->
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
      case safe_dns_analyzer_call("DNS blocklist remove", fn ->
             DNSAnalyzer.remove_from_blocklist(domain, organization_id)
           end) do
        {:ok, :ok} ->
          broadcast_dns_command(:unblock, [domain], "Removed from blocklist", organization_id)
          log_dns_blocklist_change(conn, "remove", [domain], %{reason: "Removed from blocklist"})
          send_resp(conn, :no_content, "")

        {:ok, {:error, :not_found}} ->
          conn
          |> put_status(:not_found)
          |> json(%{error: "Domain '#{domain}' not found in blocklist"})

        {:ok, {:error, reason}} ->
          conn
          |> put_status(:unprocessable_entity)
          |> json(%{error: "Failed to update DNS blocklist", reason: inspect(reason)})

        {:error, reason} ->
          dns_analyzer_unavailable_response(conn, reason)
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
    with {:ok, organization_id} <- current_organization_id(conn) do
      alerts_for_org(conn, params, organization_id)
    else
      {:error, :missing_organization} -> missing_organization_response(conn)
    end
  end

  defp alerts_for_org(conn, params, organization_id) do
    alias TamanduaServer.Alerts.Alert
    alias TamanduaServer.Agents.Agent

    limit = bounded_limit(params["limit"], 50, @max_query_limit)
    offset = bounded_offset(params["offset"])

    # Query alerts with explicit DNS-related signals. Broad "domain" text matches
    # pollute the DNS view with script/process alerts, so final row validation below
    # also requires a DNS marker or a valid domain-bearing C2/IOC signal.
    base_query =
      from(a in Alert,
        left_join: agent in Agent,
        on: a.agent_id == agent.id,
        where: a.organization_id == ^organization_id,
        where:
          ilike(a.title, ^"%DNS%") or
            ilike(a.title, ^"%DGA%") or
            ilike(a.title, ^"%tunneling%") or
            ilike(a.title, ^"%DoH%") or
            ilike(a.title, ^"%DoT%") or
            ilike(a.title, ^"%command and control%") or
            ilike(a.title, ^"%C2%") or
            ilike(a.title, ^"%exfiltration%") or
            ilike(a.description, ^"%DNS%") or
            ilike(a.description, ^"%DGA%") or
            ilike(a.description, ^"%DoH%") or
            ilike(a.description, ^"%DoT%") or
            ilike(a.description, ^"%domain generation%") or
            fragment("?->>'detection_type' ILIKE ?", a.detection_metadata, "%dns%") or
            fragment("?->>'detection_type' ILIKE ?", a.detection_metadata, "%dga%") or
            fragment("?->>'detection_type' ILIKE ?", a.detection_metadata, "%doh%") or
            fragment("?->>'detection_type' ILIKE ?", a.detection_metadata, "%dot%") or
            fragment("?->>'detection_type' ILIKE ?", a.detection_metadata, "%tunnel%") or
            fragment("?->>'detection_type' ILIKE ?", a.detection_metadata, "%exfil%") or
            fragment("?->>'event_type' ILIKE ?", a.detection_metadata, "dns%") or
            fragment("?->>'event_type' ILIKE ?", a.raw_event, "dns%"),
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

    {rows, alerts_error} =
      base_query
      |> limit(^(min(limit * 5, @max_query_limit * 5) + 1))
      |> offset(^offset)
      |> safe_repo_all_with_meta("DNS-related alerts")

    alerts =
      rows
      |> Enum.filter(&dns_alert_row?/1)
      |> Enum.take(limit)
      |> Enum.map(&serialize_dns_alert/1)
      |> Enum.reject(&unknown_dns_alert_domain?/1)
      |> Enum.reject(&trusted_dns_alert_domain?/1)

    has_more = length(rows) > length(alerts) and length(rows) > limit

    json(conn, %{
      data: alerts,
      alerts: alerts,
      meta: Map.merge(%{
        total: offset + length(alerts) + if(has_more, do: 1, else: 0),
        limit: limit,
        offset: offset,
        has_more: has_more,
        total_is_estimate: true,
        scope: "organization_dns_alerts"
      }, dns_partial_meta([alerts_error]))
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
         {:ok, {:ok, count}} <-
           safe_dns_analyzer_call("DNS blocklist import", fn ->
             DNSAnalyzer.import_blocklist(domains, reason, organization_id)
           end) do
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

      {:error, reason} when is_binary(reason) ->
        dns_analyzer_unavailable_response(conn, reason)

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Failed to import DNS blocklist", reason: inspect(reason)})

      {:ok, {:error, reason}} ->
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
    classification = classify_dns_event(event.event_type, payload)
    remote_ip = payload["remote_ip"] || payload[:remote_ip]
    remote_port =
      first_present([
        payload["remote_port"],
        payload[:remote_port],
        payload["destination_port"],
        payload[:destination_port],
        payload["dst_port"],
        payload[:dst_port],
        payload["port"],
        payload[:port],
        payload["local_port"],
        payload[:local_port]
      ])

    transport_target = format_transport_target(remote_ip, remote_port, classification)

    %{
      id: event.id,
      agent_id: event.agent_id,
      timestamp: format_timestamp(event.timestamp),
      severity: dns_event_severity(event.severity, classification),
      domain: first_present([
        payload["query"],
        payload[:query],
        payload["query_name"],
        payload[:query_name],
        payload["domain"],
        payload[:domain],
        payload["dns_query"],
        payload[:dns_query],
        payload["dns.domain"],
        payload[:"dns.domain"],
        payload["host"],
        payload[:host],
        payload["hostname"],
        payload[:hostname],
        dns_payload["query"],
        dns_payload[:query],
        dns_payload["query_name"],
        dns_payload[:query_name],
        dns_payload["domain"],
        dns_payload[:domain],
        payload["sni"],
        payload[:sni],
        payload["tls_sni"],
        payload[:tls_sni],
        transport_target
      ]),
      query_type: first_present([
        dns_classification_query_type(classification),
        payload["query_type"],
        payload[:query_type],
        payload["record_type"],
        payload[:record_type],
        payload["type"],
        payload[:type],
        payload["dns.query_type"],
        payload[:"dns.query_type"],
        payload["dns.record_type"],
        payload[:"dns.record_type"],
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
        payload["response_data"],
        payload[:response_data],
        payload["dns_response"],
        payload[:dns_response],
        payload["dns.response"],
        payload[:"dns.response"],
        dns_payload["response"],
        dns_payload[:response],
        dns_payload["response_data"],
        dns_payload[:response_data],
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
      status: dns_event_status(payload, classification),
      transport: classification,
      payload: payload
    }
  end

  defp classify_dns_event(event_type, payload) do
    cond do
      event_type in @dns_event_types or String.starts_with?(to_string(event_type), "dns") ->
        "query"

      payload_port?(payload, @dot_ports) ->
        "dot"

      payload_port?(payload, @doh_ports) and known_doh_target?(payload) ->
        "doh"

      payload_port?(payload, @dns_transport_ports) ->
        "transport"

      true ->
        "query"
    end
  end

  defp payload_port?(payload, ports) do
    [
      payload["remote_port"],
      payload[:remote_port],
      payload["destination_port"],
      payload[:destination_port],
      payload["dst_port"],
      payload[:dst_port],
      payload["port"],
      payload[:port],
      payload["local_port"],
      payload[:local_port],
      payload["source_port"],
      payload[:source_port],
      payload["src_port"],
      payload[:src_port]
    ]
    |> Enum.any?(&(to_string(&1 || "") in ports))
  end

  defp known_doh_target?(payload) do
    remote_ip = to_string(payload["remote_ip"] || payload[:remote_ip] || "")

    domain =
      first_present([
        payload["domain"],
        payload[:domain],
        payload["remote_domain"],
        payload[:remote_domain],
        payload["sni"],
        payload[:sni],
        payload["tls_sni"],
        payload[:tls_sni],
        payload["host"],
        payload[:host],
        payload["hostname"],
        payload[:hostname]
      ])
      |> to_string()
      |> String.downcase()

    remote_ip in @known_doh_ips or domain in @known_doh_domains
  end

  defp format_transport_target(nil, nil, _classification), do: nil
  defp format_transport_target(nil, "", _classification), do: nil
  defp format_transport_target("", nil, _classification), do: nil

  defp format_transport_target(remote_ip, remote_port, classification) do
    label =
      case classification do
        "doh" -> "DoH resolver"
        "dot" -> "DoT resolver"
        "transport" -> "DNS resolver"
        _ -> "Resolver"
      end

    port = if remote_port in [nil, ""], do: "", else: ":#{remote_port}"
    "#{label} #{remote_ip}#{port}"
  end

  defp dns_classification_query_type("doh"), do: "DOH"
  defp dns_classification_query_type("dot"), do: "DOT"
  defp dns_classification_query_type("transport"), do: "TRANSPORT"
  defp dns_classification_query_type(_), do: nil

  defp dns_event_status(payload, classification) do
    cond do
      payload["blocked"] == true or payload[:blocked] == true -> "blocked"
      classification in ["doh", "dot"] -> "suspicious"
      true -> "allowed"
    end
  end

  defp dns_event_severity(severity, classification) when classification in ["doh", "dot"] do
    case severity do
      s when s in ["high", "critical"] -> s
      _ -> "medium"
    end
  end

  defp dns_event_severity(severity, _classification), do: severity || "info"

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

    domain =
      [
        map_get_any(detection_metadata, "domain"),
        map_get_any(detection_metadata, "query"),
        map_get_any(evidence, "domain"),
        map_get_any(evidence, "query"),
        map_get_any(raw_event, "query"),
        map_get_any(raw_event, "query_name"),
        map_get_any(raw_event, "domain"),
        extract_domain_from_title(alert.title)
      ]
      |> Enum.find_value(&normalize_dns_domain/1)

    domain = domain || "Unknown"

    detection_type =
      map_get_any(detection_metadata, "detection_type") ||
        map_get_any(raw_event, "detection_type") ||
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

  defp unknown_dns_alert_domain?(%{domain: domain}), do: domain in [nil, "", "Unknown", "unknown"]
  defp unknown_dns_alert_domain?(_), do: true

  defp trusted_dns_alert_domain?(%{domain: domain}) do
    domain = normalize_dns_domain(domain)

    domain != nil and domain in trusted_dns_alert_domains()
  end

  defp trusted_dns_alert_domain?(_), do: false

  defp trusted_dns_alert_domains do
    env_domains =
      "TAMANDUA_DNS_ALERT_TRUSTED_DOMAINS"
      |> System.get_env("")
      |> String.split(",", trim: true)

    [
      "agents.tamandua.treantlab.org",
      "docs.treantlab.org",
      "relay.tamandua.treantlab.org",
      "tamandua.treantlab.org"
      | env_domains
    ]
    |> Enum.map(&normalize_dns_domain/1)
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
  end

  defp extract_domain_from_title(nil), do: nil

  defp extract_domain_from_title(title) do
    case Regex.run(~r/([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}/, title) do
      [domain | _] -> domain
      _ -> nil
    end
  end

  defp dns_alert_row?(alert) do
    detection_metadata = alert.detection_metadata || %{}
    evidence = alert.evidence || %{}
    raw_event = alert.raw_event || %{}

    detection_type =
      map_get_any(detection_metadata, "detection_type") ||
        map_get_any(raw_event, "detection_type") ||
        ""

    event_type =
      map_get_any(detection_metadata, "event_type") ||
        map_get_any(raw_event, "event_type") ||
        ""

    domain =
      [
        map_get_any(detection_metadata, "domain"),
        map_get_any(detection_metadata, "query"),
        map_get_any(evidence, "domain"),
        map_get_any(evidence, "query"),
        map_get_any(raw_event, "query"),
        map_get_any(raw_event, "query_name"),
        map_get_any(raw_event, "domain"),
        extract_domain_from_title(alert.title)
      ]
      |> Enum.find_value(&normalize_dns_domain/1)

    dns_alert_marker?(detection_type, event_type, alert.title, alert.description) or
      (domain != nil and c2_or_ioc_marker?(detection_type, alert.title, alert.description))
  end

  defp dns_alert_marker?(detection_type, event_type, title, description) do
    detection_text = String.downcase("#{detection_type} #{event_type}")
    display_text = "#{title} #{description}"

    String.starts_with?(String.downcase(to_string(event_type)), "dns") or
      String.contains?(detection_text, "dns") or
      String.contains?(detection_text, "dga") or
      String.contains?(detection_text, "doh") or
      String.contains?(detection_text, "dot") or
      String.contains?(detection_text, "tunnel") or
      String.contains?(detection_text, "exfil") or
      Regex.match?(~r/\b(dns|dga|doh|dot|dns-over-https|dns-over-tls|tunnel(?:ing)?|exfil(?:tration)?)\b/i, display_text)
  end

  defp c2_or_ioc_marker?(detection_type, title, description) do
    text = String.downcase("#{detection_type} #{title} #{description}")

    String.contains?(text, "command_and_control") or
      String.contains?(text, "command and control") or
      String.contains?(text, "c2") or
      String.contains?(text, "ioc") or
      String.contains?(text, "malicious domain") or
      String.contains?(text, "suspicious domain")
  end

  defp normalize_dns_domain(value) when is_binary(value) do
    domain =
      value
      |> String.trim()
      |> String.trim_trailing(".")
      |> String.downcase()

    if valid_dns_domain?(domain), do: domain, else: nil
  end

  defp normalize_dns_domain(_), do: nil

  defp valid_dns_domain?(domain) when is_binary(domain) do
    blocked_file_like_tlds = ~w(exe dll sys scr bat cmd ps1 msi lnk tmp log json localmachine)

    Regex.match?(~r/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/, domain) and
      not String.contains?(domain, [" ", "/", "\\", ":", "@"]) and
      List.last(String.split(domain, ".")) not in blocked_file_like_tlds and
      domain not in ["unknown", "localhost"]
  end

  defp valid_dns_domain?(_), do: false

  defp map_get_any(map, key) when is_map(map) do
    Map.get(map, key) || Map.get(map, String.to_atom(key))
  end

  defp map_get_any(_, _), do: nil

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

  defp parse_time_range(range), do: parse_time_range(range, DateTime.utc_now())
  defp parse_time_range("1h", now), do: DateTime.add(now, -60 * 60, :second)
  defp parse_time_range("24h", now), do: DateTime.add(now, -24 * 60 * 60, :second)
  defp parse_time_range("7d", now), do: DateTime.add(now, -7 * 24 * 60 * 60, :second)
  defp parse_time_range("30d", now), do: DateTime.add(now, -30 * 24 * 60 * 60, :second)
  defp parse_time_range("all", _now), do: nil
  defp parse_time_range(_, now), do: DateTime.add(now, -24 * 60 * 60, :second)

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
  defp parse_int(_, default), do: default

  defp bounded_limit(value, default, max_limit) do
    value
    |> parse_int(default)
    |> max(1)
    |> min(max_limit)
  end

  defp bounded_offset(value) do
    value
    |> parse_int(0)
    |> max(0)
  end

  defp default_dns_feed_summaries do
    Enum.map(@default_dns_feed_names, fn name ->
      %{
        name: name,
        enabled: true,
        health: "validation_pending",
        ioc_count: 0,
        inserted: 0,
        loaded: false,
        source: "threat_intel_feed_status",
        description:
          "Configured DNS feed reference; live IOC counts and health are reported by the threat-intel feed-status endpoint."
      }
    end)
  end

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
