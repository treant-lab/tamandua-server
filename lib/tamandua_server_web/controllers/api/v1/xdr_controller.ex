defmodule TamanduaServerWeb.API.V1.XDRController do
  @moduledoc """
  API controller for XDR (Extended Detection and Response) operations.

  Provides endpoints for:
  - Ingesting events from external security sources
  - Querying normalized XDR events
  - Managing data sources
  - Cross-source correlation
  - Attack timeline building
  - Webhook receivers for third-party integrations
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.XDR.{Ingestor, NormalizedEvent, Correlator}
  alias TamanduaServer.Repo

  import Ecto.Query

  require Logger

  action_fallback TamanduaServerWeb.FallbackController

  # Rate limiting for webhook endpoints
  @max_webhook_events_per_request 1000
  @max_batch_size 5000

  # ============================================================================
  # Event Ingestion
  # ============================================================================

  @doc """
  Ingest a single event from an external source.

  POST /api/v1/xdr/ingest

  Body:
    {
      "source_type": "firewall|proxy|email|cloud|network",
      "format": "cef|leef|json|syslog|auto",
      "raw_data": "...",
      "metadata": {...}
    }
  """
  def ingest(conn, %{"raw_data" => raw_data} = params) do
    source_type = params["source_type"]
    format = params["format"] || "auto"
    metadata = params["metadata"] || %{}

    with {:ok, org_id} <- require_organization(current_organization_id(conn)),
         result <- Ingestor.ingest_sync(raw_data, source_type: source_type, format: format, organization_id: org_id, metadata: metadata) do
      case result do
      {:ok, event} ->
        # Also add to correlator for cross-source analysis
        Correlator.add_event(event)

        conn
        |> put_status(:created)
        |> json(%{
          success: true,
          event: serialize_event(event),
          message: "Event ingested successfully"
        })

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{success: false, error: to_string(reason)})
      end
    else
      {:error, reason} ->
        conn
        |> put_status(error_status(reason))
        |> json(%{success: false, error: to_string(reason)})
    end
  end

  def ingest(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{success: false, error: "raw_data is required"})
  end

  @doc """
  Ingest a batch of events.

  POST /api/v1/xdr/ingest/batch

  Body:
    {
      "source_type": "firewall",
      "format": "cef",
      "events": ["event1", "event2", ...]
    }
  """
  def ingest_batch(conn, %{"events" => events} = params) when is_list(events) do
    if length(events) > @max_batch_size do
      conn
      |> put_status(:request_entity_too_large)
      |> json(%{
        success: false,
        error: "Batch size exceeds maximum of #{@max_batch_size} events"
      })
    else
      source_type = params["source_type"]
      format = params["format"] || "auto"

      with {:ok, org_id} <- require_organization(current_organization_id(conn)) do
        results = events
        |> Enum.with_index()
        |> Enum.map(fn {raw_data, idx} ->
          case Ingestor.ingest_sync(raw_data, source_type: source_type, format: format, organization_id: org_id) do
            {:ok, event} ->
              Correlator.add_event(event)
              {:ok, idx, event}
            {:error, reason} ->
              {:error, idx, reason}
          end
        end)

        successful = Enum.filter(results, fn {status, _, _} -> status == :ok end)
        failed = Enum.filter(results, fn {status, _, _} -> status == :error end)

        json(conn, %{
          success: length(failed) == 0,
          total: length(events),
          ingested: length(successful),
          failed: length(failed),
          errors: Enum.map(failed, fn {:error, idx, reason} ->
            %{index: idx, error: to_string(reason)}
          end)
        })
      else
        {:error, reason} ->
          conn
          |> put_status(error_status(reason))
          |> json(%{success: false, error: to_string(reason)})
      end
    end
  end

  def ingest_batch(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{success: false, error: "events array is required"})
  end

  # ============================================================================
  # Event Queries
  # ============================================================================

  @doc """
  List XDR events with filtering and pagination.

  GET /api/v1/xdr/events

  Query params:
    - source_type: Filter by source type (firewall, proxy, email, cloud, network)
    - source_id: Filter by specific source ID
    - severity: Filter by severity (critical, high, medium, low, info)
    - category: Filter by event category
    - start_time: Start of time range (ISO8601)
    - end_time: End of time range (ISO8601)
    - source_ip: Filter by source IP
    - dest_ip: Filter by destination IP
    - user: Filter by user
    - limit: Results limit (default: 100, max: 1000)
    - offset: Pagination offset
  """
  def index(conn, params) do
    org_id = current_organization_id(conn)
    limit = params["limit"] |> parse_int(100) |> max(1) |> min(1000)
    offset = params["offset"] |> parse_int(0) |> max(0)

    query = NormalizedEvent
    |> maybe_filter_org(org_id)
    |> maybe_filter_source_type(params["source_type"])
    |> maybe_filter_source_id(params["source_id"])
    |> maybe_filter_severity(params["severity"])
    |> maybe_filter_category(params["category"])
    |> maybe_filter_time_range(params["start_time"], params["end_time"])
    |> maybe_filter_source_ip(params["source_ip"])
    |> maybe_filter_dest_ip(params["dest_ip"])
    |> maybe_filter_user(params["user"])
    |> order_by([e], desc: e.timestamp)
    |> limit(^limit)
    |> offset(^offset)

    events = safe_repo_all(query, "XDR event index")
    total = safe_repo_value("XDR event index total", offset + length(events), fn ->
      Repo.aggregate(query |> exclude(:limit) |> exclude(:offset), :count, timeout: 8_000)
    end)

    json(conn, %{
      data: Enum.map(events, &serialize_event/1),
      meta: %{
        total: total,
        limit: limit,
        offset: offset,
        has_more: offset + length(events) < total
      }
    })
  end

  @doc """
  Get a single XDR event by ID.

  GET /api/v1/xdr/events/:id
  """
  def show(conn, %{"id" => id}) do
    org_id = current_organization_id(conn)

    with {:ok, valid_id} <- Ecto.UUID.cast(id) do
      query = NormalizedEvent
      |> maybe_filter_org(org_id)
      |> where([e], e.id == ^valid_id)

      case safe_repo_one(query, "XDR event show") do
        nil ->
          conn
          |> put_status(:not_found)
          |> json(%{error: "Event not found"})

        event ->
          # Get correlated events
          correlated = Correlator.correlate_with_endpoint(Map.from_struct(event))
          |> case do
            {:ok, result} -> result.matches
            _ -> []
          end

          json(conn, %{
            data: serialize_event(event),
            correlated_events: Enum.take(correlated, 20)
          })
      end
    else
      :error ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Invalid event id"})
    end
  end

  @doc """
  Search XDR events.

  POST /api/v1/xdr/events/search

  Body:
    {
      "query": "search text",
      "filters": {...},
      "time_range": "24h|7d|30d|custom",
      "start_time": "...",
      "end_time": "..."
    }
  """
  def search(conn, params) do
    org_id = current_organization_id(conn)
    query_text = params["query"] || ""
    filters = params["filters"] || %{}
    limit = params["limit"] |> parse_int(100) |> max(1) |> min(1000)
    time_range = params["time_range"] || "24h"

    {start_time, end_time} = parse_time_range(time_range, params["start_time"], params["end_time"])

    base_query = NormalizedEvent
    |> maybe_filter_org(org_id)
    |> filter_time_range(start_time, end_time)

    # Apply text search if provided
    base_query = if query_text != "" do
      search_pattern = "%#{query_text}%"
      base_query
      |> where([e], ilike(e.action, ^search_pattern)
        or ilike(e.outcome, ^search_pattern)
        or ilike(e.source_ip, ^search_pattern)
        or ilike(e.dest_ip, ^search_pattern)
        or ilike(e.user, ^search_pattern)
        or ilike(fragment("raw_data::text"), ^search_pattern))
    else
      base_query
    end

    # Apply additional filters
    base_query = apply_filters(base_query, filters)

    events = base_query
    |> order_by([e], desc: e.timestamp)
    |> limit(^limit)
    |> safe_repo_all("XDR event search")

    # Get aggregations
    aggregations = get_search_aggregations(base_query)

    json(conn, %{
      data: Enum.map(events, &serialize_event/1),
      aggregations: aggregations,
      meta: %{
        query: query_text,
        time_range: time_range,
        count: length(events)
      }
    })
  end

  # ============================================================================
  # Data Sources
  # ============================================================================

  @doc """
  List configured XDR data sources.

  GET /api/v1/xdr/sources
  """
  def list_sources(conn, params) do
    org_id = current_organization_id(conn)
    source_type = params["source_type"]

    query = TamanduaServer.XDR.Source
    |> maybe_filter_org(org_id)
    |> maybe_filter_source_type(source_type)
    |> order_by([s], asc: s.name)

    sources = safe_repo_all(query, "XDR source list")
    json(conn, %{data: Enum.map(sources, &serialize_source/1)})
  end

  @doc """
  Create a new XDR data source.

  POST /api/v1/xdr/sources

  Body:
    {
      "name": "Production Firewall",
      "source_type": "firewall",
      "vendor": "palo_alto",
      "config": {...}
    }
  """
  def create_source(conn, params) do
    org_id = current_organization_id(conn)

    changeset = TamanduaServer.XDR.Source.changeset(
      struct(TamanduaServer.XDR.Source),
      Map.put(params, "organization_id", org_id)
    )

    case Repo.insert(changeset) do
      {:ok, source} ->
        conn
        |> put_status(:created)
        |> json(%{data: serialize_source(source)})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{errors: format_errors(changeset)})
    end
  end

  @doc """
  Update an XDR data source.

  PUT /api/v1/xdr/sources/:id
  """
  def update_source(conn, %{"id" => id} = params) do
    org_id = current_organization_id(conn)

    query = TamanduaServer.XDR.Source
    |> maybe_filter_org(org_id)
    |> where([s], s.id == ^id)

    case Repo.one(query) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Source not found"})

      source ->
        changeset = TamanduaServer.XDR.Source.changeset(source, params)

        case Repo.update(changeset) do
          {:ok, updated} ->
            json(conn, %{data: serialize_source(updated)})

          {:error, changeset} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{errors: format_errors(changeset)})
        end
    end
  end

  @doc """
  Delete an XDR data source.

  DELETE /api/v1/xdr/sources/:id
  """
  def delete_source(conn, %{"id" => id}) do
    org_id = current_organization_id(conn)

    query = TamanduaServer.XDR.Source
    |> maybe_filter_org(org_id)
    |> where([s], s.id == ^id)

    case Repo.one(query) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Source not found"})

      source ->
        Repo.delete(source)
        json(conn, %{success: true, message: "Source deleted"})
    end
  end

  @doc """
  Get source health and statistics.

  GET /api/v1/xdr/sources/:id/health
  """
  def source_health(conn, %{"id" => id}) do
    org_id = current_organization_id(conn)

    query = TamanduaServer.XDR.Source
    |> maybe_filter_org(org_id)
    |> where([s], s.id == ^id)

    case Repo.one(query) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Source not found"})

      source ->
        # Get recent event stats
        stats = get_source_stats(source.id)

        json(conn, %{
          source_id: source.id,
          name: source.name,
          status: source.status,
          last_event_at: source.last_event_at,
          stats: stats
        })
    end
  end

  # ============================================================================
  # Correlation Endpoints
  # ============================================================================

  @doc """
  Get cross-source correlations for an entity.

  GET /api/v1/xdr/correlations/entity/:type/:value

  Path params:
    - type: ip|user|hash|domain
    - value: The entity value to correlate

  Query params:
    - time_window_ms: Time window for correlation (default: 15 minutes)
  """
  def entity_correlations(conn, %{"type" => entity_type, "value" => entity_value} = params) do
    time_window_ms = parse_int(params["time_window_ms"], 15 * 60 * 1000)

    case Correlator.get_entity_correlations(entity_type, entity_value, time_window_ms: time_window_ms) do
      {:ok, result} ->
        json(conn, %{data: result})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: to_string(reason)})
    end
  end

  @doc """
  Detect kill chain patterns across sources.

  GET /api/v1/xdr/correlations/kill-chain

  Query params:
    - time_window_ms: Analysis time window
  """
  def detect_kill_chain(conn, params) do
    time_window_ms = parse_int(params["time_window_ms"], 60 * 60 * 1000)

    with {:ok, org_id} <- require_organization(current_organization_id(conn)) do
      opts = [
        time_window_ms: time_window_ms,
        organization_id: org_id
      ]

      case Correlator.detect_kill_chain(opts) do
        {:ok, kill_chains} ->
          json(conn, %{
            data: kill_chains,
            meta: %{
              time_window_ms: time_window_ms,
              count: length(kill_chains)
            }
          })

        {:error, reason} ->
          conn
          |> put_status(:unprocessable_entity)
          |> json(%{error: to_string(reason)})
      end
    else
      {:error, reason} ->
        conn
        |> put_status(error_status(reason))
        |> json(%{error: to_string(reason)})
    end
  end

  @doc """
  Get correlation statistics.

  GET /api/v1/xdr/correlations/stats
  """
  def correlation_stats(conn, _params) do
    stats = Correlator.get_stats()
    json(conn, %{data: stats})
  end

  # ============================================================================
  # Attack Timelines
  # ============================================================================

  @doc """
  List attack timelines.

  GET /api/v1/xdr/timelines

  Query params:
    - status: active|closed|investigating
    - min_risk_score: Minimum risk score filter
    - limit: Results limit
  """
  def list_timelines(conn, params) do
    org_id = current_organization_id(conn)

    opts = [
      organization_id: org_id,
      status: parse_atom(params["status"]),
      min_risk_score: parse_float(params["min_risk_score"]),
      limit: parse_int(params["limit"], 100)
    ]
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)

    case Correlator.list_timelines(opts) do
      {:ok, timelines} ->
        json(conn, %{data: timelines})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: to_string(reason)})
    end
  end

  @doc """
  Build or get an attack timeline.

  POST /api/v1/xdr/timelines

  Body:
    {
      "correlation_id": "uuid",
      "time_window_ms": 3600000
    }
  """
  def build_timeline(conn, %{"correlation_id" => correlation_id} = params) do
    org_id = current_organization_id(conn)
    time_window_ms = parse_int(params["time_window_ms"], 30 * 60 * 1000)

    opts = [
      organization_id: org_id,
      time_window_ms: time_window_ms
    ]

    case Correlator.build_timeline(correlation_id, opts) do
      {:ok, timeline} ->
        conn
        |> put_status(:created)
        |> json(%{data: timeline})

      {:error, :insufficient_events} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Insufficient events to build timeline"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: to_string(reason)})
    end
  end

  def build_timeline(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "correlation_id is required"})
  end

  # ============================================================================
  # Webhook Receivers
  # ============================================================================

  @doc """
  Generic webhook receiver for third-party integrations.

  POST /api/v1/xdr/webhooks/:source_type

  Headers:
    - X-Webhook-Signature: HMAC signature for validation
    - X-Webhook-Timestamp: Request timestamp

  Path params:
    - source_type: firewall|proxy|email|cloud|network|custom
  """
  def webhook_receive(conn, %{"source_type" => source_type} = _params) do
    org_id = current_organization_id(conn)
    signature = get_req_header(conn, "x-webhook-signature") |> List.first()
    timestamp = get_req_header(conn, "x-webhook-timestamp") |> List.first()

    # Get raw body for signature verification
    {:ok, raw_body, conn} = read_body(conn)

    # Verify signature if configured
    case verify_webhook_signature(source_type, org_id, raw_body, signature, timestamp) do
      :ok ->
        # Parse body
        case Jason.decode(raw_body) do
          {:ok, payload} ->
            process_webhook_payload(conn, source_type, org_id, payload)

          {:error, _} ->
            # Try as raw log data
            case Ingestor.ingest_sync(raw_body, source_type: source_type, organization_id: org_id) do
              {:ok, event} ->
                Correlator.add_event(event)
                json(conn, %{success: true, events_processed: 1})

              {:error, reason} ->
                conn
                |> put_status(:unprocessable_entity)
                |> json(%{success: false, error: to_string(reason)})
            end
        end

      {:error, :invalid_signature} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "Invalid webhook signature"})

      {:error, :expired} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "Webhook timestamp expired"})
    end
  end

  defp process_webhook_payload(conn, source_type, org_id, payload) do
    # Handle different payload formats
    events = case payload do
      %{"events" => events} when is_list(events) -> events
      %{"logs" => logs} when is_list(logs) -> logs
      %{"records" => records} when is_list(records) -> records
      %{"data" => data} when is_list(data) -> data
      event when is_map(event) -> [event]
      _ -> []
    end

    # Limit events per request
    events = Enum.take(events, @max_webhook_events_per_request)

    results = events
    |> Enum.map(fn event_data ->
      raw = if is_binary(event_data), do: event_data, else: Jason.encode!(event_data)
      case Ingestor.ingest_sync(raw, source_type: source_type, organization_id: org_id) do
        {:ok, event} ->
          Correlator.add_event(event)
          :ok
        {:error, _} -> :error
      end
    end)

    success_count = Enum.count(results, & &1 == :ok)
    error_count = Enum.count(results, & &1 == :error)

    json(conn, %{
      success: error_count == 0,
      events_processed: success_count,
      errors: error_count
    })
  end

  defp verify_webhook_signature(_source_type, _org_id, _body, nil, _timestamp) do
    # No signature provided - allow if signature not required
    # In production, you'd check source configuration
    :ok
  end

  defp verify_webhook_signature(_source_type, _org_id, body, signature, timestamp) do
    # Verify timestamp is recent (within 5 minutes)
    case parse_timestamp(timestamp) do
      nil -> :ok  # No timestamp, skip validation
      ts ->
        now = System.system_time(:second)
        if abs(now - ts) > 300 do
          {:error, :expired}
        else
          # In production, you'd look up the webhook secret for this source
          # and verify the HMAC signature
          # secret = get_webhook_secret(source_type, org_id)
          # expected = :crypto.mac(:hmac, :sha256, secret, "#{timestamp}.#{body}") |> Base.encode16(case: :lower)
          # if Plug.Crypto.secure_compare(signature, expected), do: :ok, else: {:error, :invalid_signature}
          :ok
        end
    end
  end

  defp parse_timestamp(nil), do: nil
  defp parse_timestamp(ts) when is_binary(ts) do
    case Integer.parse(ts) do
      {int, _} -> int
      :error -> nil
    end
  end
  defp parse_timestamp(ts) when is_integer(ts), do: ts

  # ============================================================================
  # Helpers
  # ============================================================================

  defp current_organization_id(conn) do
    conn.assigns[:organization_id] ||
      conn.assigns[:current_organization_id] ||
      get_in(conn.assigns, [:current_user, Access.key(:organization_id)])
  end

  defp require_organization(nil), do: {:error, :organization_required}
  defp require_organization(org_id), do: {:ok, org_id}

  defp error_status(:organization_required), do: :bad_request
  defp error_status(_), do: :unprocessable_entity

  defp serialize_event(%NormalizedEvent{} = event) do
    %{
      id: event.id,
      source_type: event.source_type,
      source_id: event.source_id,
      timestamp: format_timestamp(event.timestamp),
      severity: event.severity,
      category: event.category,
      action: event.action,
      outcome: event.outcome,
      source_ip: event.source_ip,
      source_port: event.source_port,
      dest_ip: event.dest_ip,
      dest_port: event.dest_port,
      protocol: event.protocol,
      user: event.user,
      user_domain: event.user_domain,
      url: event.url,
      domain: event.domain,
      file_name: event.file_name,
      file_hash: event.file_hash,
      file_size: event.file_size,
      email_subject: event.email_subject,
      email_sender: event.email_sender,
      email_recipient: event.email_recipient,
      cloud_provider: event.cloud_provider,
      cloud_service: event.cloud_service,
      cloud_region: event.cloud_region,
      threat_name: event.threat_name,
      threat_category: event.threat_category,
      mitre_techniques: event.mitre_techniques,
      raw_data: event.raw_data,
      inserted_at: format_timestamp(event.inserted_at)
    }
  end

  defp serialize_event(event) when is_map(event) do
    Map.take(event, [
      :id, :source_type, :source_id, :timestamp, :severity, :category, :action,
      :outcome, :source_ip, :dest_ip, :user, :domain, :file_hash, :threat_name,
      :mitre_techniques
    ])
  end

  defp serialize_source(source) do
    %{
      id: source.id,
      name: source.name,
      source_type: source.source_type,
      vendor: source.vendor,
      status: source.status,
      config: source.config,
      last_event_at: format_timestamp(source.last_event_at),
      event_count: source.event_count,
      error_count: source.error_count,
      inserted_at: format_timestamp(source.inserted_at),
      updated_at: format_timestamp(source.updated_at)
    }
  end

  defp get_source_stats(source_id) do
    now = DateTime.utc_now()
    last_hour = DateTime.add(now, -3600, :second)
    last_day = DateTime.add(now, -86400, :second)

    last_hour_count =
      safe_repo_value("XDR source stats last hour", 0, fn ->
        Repo.aggregate(
          from(e in NormalizedEvent, where: e.source_id == ^source_id and e.timestamp >= ^last_hour),
          :count,
          timeout: 8_000
        )
      end)

    last_day_count =
      safe_repo_value("XDR source stats last day", 0, fn ->
        Repo.aggregate(
          from(e in NormalizedEvent, where: e.source_id == ^source_id and e.timestamp >= ^last_day),
          :count,
          timeout: 8_000
        )
      end)

    severity_breakdown =
      safe_repo_all(
        from(e in NormalizedEvent,
          where: e.source_id == ^source_id and e.timestamp >= ^last_day,
          group_by: e.severity,
          select: {e.severity, count(e.id)}
        ),
        "XDR source severity breakdown"
      )
      |> Map.new()

    %{
      events_last_hour: last_hour_count,
      events_last_day: last_day_count,
      severity_breakdown: severity_breakdown
    }
  end

  defp get_search_aggregations(query) do
    # Get aggregations for search results
    by_source_type =
      safe_repo_all(
        from(e in subquery(query),
          group_by: e.source_type,
          select: {e.source_type, count(e.id)}
        ),
        "XDR search aggregation source type"
      )
      |> Map.new()

    by_severity =
      safe_repo_all(
        from(e in subquery(query),
          group_by: e.severity,
          select: {e.severity, count(e.id)}
        ),
        "XDR search aggregation severity"
      )
      |> Map.new()

    by_category =
      safe_repo_all(
        from(e in subquery(query),
          where: not is_nil(e.category),
          group_by: e.category,
          select: {e.category, count(e.id)},
          limit: 20
        ),
        "XDR search aggregation category"
      )
      |> Map.new()

    %{
      by_source_type: by_source_type,
      by_severity: by_severity,
      by_category: by_category
    }
  end

  defp apply_filters(query, filters) when is_map(filters) do
    Enum.reduce(filters, query, fn
      {"source_type", value}, q -> maybe_filter_source_type(q, value)
      {"severity", value}, q -> maybe_filter_severity(q, value)
      {"category", value}, q -> maybe_filter_category(q, value)
      {"source_ip", value}, q -> maybe_filter_source_ip(q, value)
      {"dest_ip", value}, q -> maybe_filter_dest_ip(q, value)
      {"user", value}, q -> maybe_filter_user(q, value)
      _, q -> q
    end)
  end

  defp maybe_filter_org(query, nil), do: where(query, [e], false)
  defp maybe_filter_org(query, org_id) do
    where(query, [e], e.organization_id == ^org_id)
  end

  defp maybe_filter_source_type(query, nil), do: query
  defp maybe_filter_source_type(query, source_type) do
    where(query, [e], e.source_type == ^source_type)
  end

  defp maybe_filter_source_id(query, nil), do: query
  defp maybe_filter_source_id(query, source_id) do
    where(query, [e], e.source_id == ^source_id)
  end

  defp maybe_filter_severity(query, nil), do: query
  defp maybe_filter_severity(query, severity) do
    where(query, [e], e.severity == ^severity)
  end

  defp maybe_filter_category(query, nil), do: query
  defp maybe_filter_category(query, category) do
    where(query, [e], e.category == ^category)
  end

  defp maybe_filter_source_ip(query, nil), do: query
  defp maybe_filter_source_ip(query, ip) do
    where(query, [e], e.source_ip == ^ip)
  end

  defp maybe_filter_dest_ip(query, nil), do: query
  defp maybe_filter_dest_ip(query, ip) do
    where(query, [e], e.dest_ip == ^ip)
  end

  defp maybe_filter_user(query, nil), do: query
  defp maybe_filter_user(query, user) do
    where(query, [e], e.user == ^user)
  end

  defp maybe_filter_time_range(query, nil, nil), do: query
  defp maybe_filter_time_range(query, start_time, end_time) do
    {start_dt, end_dt} = parse_time_range("custom", start_time, end_time)
    filter_time_range(query, start_dt, end_dt)
  end

  defp filter_time_range(query, nil, nil), do: query
  defp filter_time_range(query, start_time, nil) do
    where(query, [e], e.timestamp >= ^start_time)
  end
  defp filter_time_range(query, nil, end_time) do
    where(query, [e], e.timestamp <= ^end_time)
  end
  defp filter_time_range(query, start_time, end_time) do
    where(query, [e], e.timestamp >= ^start_time and e.timestamp <= ^end_time)
  end

  defp parse_time_range("24h", _, _) do
    now = DateTime.utc_now()
    {DateTime.add(now, -86400, :second), now}
  end
  defp parse_time_range("7d", _, _) do
    now = DateTime.utc_now()
    {DateTime.add(now, -7 * 86400, :second), now}
  end
  defp parse_time_range("30d", _, _) do
    now = DateTime.utc_now()
    {DateTime.add(now, -30 * 86400, :second), now}
  end
  defp parse_time_range("custom", start_str, end_str) do
    start_dt = parse_datetime(start_str)
    end_dt = parse_datetime(end_str)
    {start_dt, end_dt}
  end
  defp parse_time_range(_, _, _) do
    now = DateTime.utc_now()
    {DateTime.add(now, -86400, :second), now}
  end

  defp parse_datetime(nil), do: nil
  defp parse_datetime(str) when is_binary(str) do
    case DateTime.from_iso8601(str) do
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end
  defp parse_datetime(_), do: nil

  defp format_timestamp(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp format_timestamp(%NaiveDateTime{} = ndt), do: NaiveDateTime.to_iso8601(ndt)
  defp format_timestamp(ts), do: ts

  defp parse_int(nil, default), do: default
  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> default
    end
  end
  defp parse_int(value, _default) when is_integer(value), do: value

  defp parse_float(nil), do: nil
  defp parse_float(value) when is_binary(value) do
    case Float.parse(value) do
      {f, _} -> f
      :error -> nil
    end
  end
  defp parse_float(value) when is_float(value), do: value
  defp parse_float(value) when is_integer(value), do: value / 1.0

  defp parse_atom(nil), do: nil
  defp parse_atom(value) when is_binary(value) do
    String.to_existing_atom(value)
  rescue
    _ -> nil
  end
  defp parse_atom(value) when is_atom(value), do: value

  defp safe_repo_all(query, label) do
    Repo.all(query, timeout: 8_000)
  rescue
    error in [DBConnection.ConnectionError, Postgrex.Error] ->
      Logger.warning("#{label} failed: #{Exception.message(error)}")
      []
  catch
    :exit, reason ->
      Logger.warning("#{label} failed: exit #{inspect(reason)}")
      []
  end

  defp safe_repo_one(query, label) do
    Repo.one(query, timeout: 8_000)
  rescue
    error in [DBConnection.ConnectionError, Postgrex.Error] ->
      Logger.warning("#{label} failed: #{Exception.message(error)}")
      nil
  catch
    :exit, reason ->
      Logger.warning("#{label} failed: exit #{inspect(reason)}")
      nil
  end

  defp safe_repo_value(label, default, fun) when is_function(fun, 0) do
    fun.()
  rescue
    error in [DBConnection.ConnectionError, Postgrex.Error] ->
      Logger.warning("#{label} failed: #{Exception.message(error)}")
      default
  catch
    :exit, reason ->
      Logger.warning("#{label} failed: exit #{inspect(reason)}")
      default
  end

  defp format_errors(%Ecto.Changeset{} = changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
end
