defmodule TamanduaServerWeb.API.V1.AlertController do
  use TamanduaServerWeb, :controller

  import Ecto.Query, warn: false
  require Logger

  alias TamanduaServer.Alerts
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Alerts.EvidenceQuality
  alias TamanduaServer.Alerts.TriageAgent
  alias TamanduaServer.Agents.AgentCommand
  alias TamanduaServer.AuditLog
  alias TamanduaServer.Detection.Exclusions
  alias TamanduaServer.Mobile.MDMCommand
  alias TamanduaServer.Accounts
  alias TamanduaServer.Repo
  alias TamanduaServer.Solana.Attestation
  alias TamanduaServer.Telemetry.Event

  action_fallback TamanduaServerWeb.FallbackController

  # Helper to authorize alert access within the current organization
  defp authorize_alert!(conn, alert_id) do
    org_id = conn.assigns[:current_organization_id]
    Alerts.get_alert_for_org!(org_id, alert_id)
  end

  # ===========================================================================
  # Standard CRUD Operations
  # ===========================================================================

  @max_per_page 200

  def index(conn, params) do
    case resolve_organization_id(conn, params) do
      nil -> tenant_context_required(conn)
      org_id -> list_alerts(conn, params, org_id)
    end
  end

  defp list_alerts(conn, params, org_id) do
    page = parse_int(params["page"], 1) |> max(1)
    per_page = parse_int(params["per_page"] || params["limit"], 25) |> max(1) |> min(@max_per_page)
    offset = parse_int(params["offset"], (page - 1) * per_page) |> max(0)
    status = normalize_status_filter(params["status"])

    filters = [
      severity: params["severity"],
      status: status,
      agent_id: params["agent_id"] || params["agent"],
      assigned_to_id: params["assigned_to_id"],
      source: params["source"],
      category: params["category"],
      validation: params["validation"] || params["include_validation"] || "include",
      mitre_technique: params["mitre_technique"] || params["mitre_technique_id"],
      inserted_from: params["from"] || params["date_from"],
      inserted_to: params["to"] || params["date_to"],
      sort_by: parse_sort_field(params["sort"] || params["sort_by"]),
      sort_order: parse_sort_order(params["order"] || params["sort_order"]),
      limit: per_page + 1,
      offset: offset,
      summary: true
    ]

    alerts = list_alert_summary_rows(org_id, filters)
    returned_alerts = Enum.take(alerts, per_page)
    returned = length(returned_alerts)
    has_more = length(alerts) > per_page

    total =
      if include_total?(params) do
        Alerts.count_alerts_for_org(org_id, Keyword.drop(filters, [:limit, :offset]))
      end

    total_pages = if total && total > 0, do: ceil(total / per_page), else: nil

    applied_filters =
      %{
        severity: params["severity"],
        status: status,
        agent_id: params["agent_id"] || params["agent"],
        assigned_to_id: params["assigned_to_id"],
        source: params["source"],
        category: params["category"],
        validation: params["validation"] || params["include_validation"],
        mitre_technique: params["mitre_technique"] || params["mitre_technique_id"],
        inserted_from: params["from"] || params["date_from"],
        inserted_to: params["to"] || params["date_to"]
      }
      |> compact_applied_filters()

    json(conn, %{
      data: Enum.map(returned_alerts, &serialize/1),
      meta: %{
        page: div(offset, per_page) + 1,
        per_page: per_page,
        offset: offset,
        total: total,
        total_pages: total_pages,
        returned: returned,
        truncated: has_more,
        has_more: has_more,
        applied_filters: applied_filters
      }
    })
  end

  def show(conn, %{"id" => id}) do
    alert = authorize_alert!(conn, id) |> Repo.preload(:agent)
    json(conn, %{data: serialize(alert)})
  end

  def recompute_triage(conn, %{"id" => id}) do
    alert = authorize_alert!(conn, id) |> Repo.preload(:agent)

    case build_triage_contract(alert) do
      {:ok, triage} ->
        enrichment = alert.enrichment || %{}

        case Alerts.update_alert(alert, %{enrichment: Map.put(enrichment, "triage", triage)}) do
          {:ok, updated_alert} ->
            json(conn, %{
              data: %{
                alert_id: updated_alert.id,
                triage_agent: triage,
                triageAgent: camelize_triage_agent(triage)
              }
            })

          {:error, changeset} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: format_changeset_errors(changeset)})
        end

      {:error, triage} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{error: "triage agent unavailable", data: %{triage_agent: triage, triageAgent: camelize_triage_agent(triage)}})
    end
  end

  def agent_commands(conn, %{"id" => id}) do
    alert = authorize_alert!(conn, id)
    command_ids = investigation_command_ids(alert)
    desktop_command_ids = command_ids_by_runtime(alert, [nil, "desktop_agent"])
    mobile_command_ids = command_ids_by_runtime(alert, ["mobile_mdm"])

    desktop_commands = alert_desktop_commands(alert, desktop_command_ids)
    mobile_commands = alert_mobile_commands(alert, mobile_command_ids)

    json(conn, %{
      data: Enum.map(desktop_commands, &serialize_agent_command/1) ++ Enum.map(mobile_commands, &serialize_mdm_command/1),
      meta: %{
        alert_id: alert.id,
        agent_id: alert.agent_id,
        requested_command_ids: command_ids,
        desktop_command_ids: desktop_command_ids,
        mobile_command_ids: mobile_command_ids,
 discovered_by_alert_id: alert.id,
 discovered_command_counts: %{
 desktop: Enum.count(desktop_commands, &(not (&1.id in desktop_command_ids))),
 mobile: Enum.count(mobile_commands, &(not (&1.id in mobile_command_ids)))
 },
        returned: length(desktop_commands) + length(mobile_commands)
      }
    })
  end

  def incident(conn, %{"id" => id}) do
    alert = authorize_alert!(conn, id)
    events = load_incident_events(alert)

    json(conn, %{
      data: %{
        id: alert.id,
        alert: serialize(alert),
        timeline: incident_timeline(alert, events),
        evidence: alert.evidence || %{},
        process_chain: alert.process_chain || [],
        detections: alert.detection_metadata || %{},
        contributing_events: alert.contributing_events || [],
        proof: proof_details(alert),
        response: %{
          status: alert.status,
          assigned_to_id: alert.assigned_to_id,
          resolved_at: format_datetime(alert.resolved_at),
          resolution_notes: alert.resolution_notes
        }
      }
    })
  end

  def update(conn, %{"id" => id} = params) do
    alert = authorize_alert!(conn, id)

    with {:ok, %Alert{} = alert} <- Alerts.update_alert(alert, params) do
      user = conn.assigns[:current_user]
      AuditLog.log_alert_action(user, "update_alert", id, %{
        changes: Map.drop(params, ["id"])
      }, request_metadata(conn))

      json(conn, %{data: serialize(alert)})
    end
  end

  def assign(conn, %{"id" => id, "user_id" => user_id}) do
    alert = authorize_alert!(conn, id)

    with {:ok, %Alert{} = alert} <- Alerts.update_alert(alert, %{assigned_to_id: user_id, status: "investigating"}) do
      user = conn.assigns[:current_user]
      AuditLog.log_alert_action(user, "assign_alert", id, %{
        assigned_to_id: user_id
      }, request_metadata(conn))

      json(conn, %{data: serialize(alert), message: "Alert assigned successfully"})
    end
  end

  def resolve(conn, %{"id" => id} = params) do
    alert = authorize_alert!(conn, id)
    resolution_notes = Map.get(params, "notes", "")

    with {:ok, %Alert{} = alert} <- Alerts.update_alert(alert, %{status: "resolved", resolution_notes: resolution_notes}) do
      user = conn.assigns[:current_user]
      AuditLog.log_alert_action(user, "resolve_alert", id, %{
        resolution_notes: resolution_notes
      }, request_metadata(conn))

      json(conn, %{data: serialize(alert), message: "Alert resolved successfully"})
    end
  end

  def false_positive(conn, %{"id" => id} = params) do
    alert = authorize_alert!(conn, id)
    notes = Map.get(params, "notes", "")

    with {:ok, %Alert{} = alert} <- Alerts.update_alert(alert, %{status: "false_positive", resolution_notes: notes}) do
      user = conn.assigns[:current_user]
      AuditLog.log_alert_action(user, "false_positive", id, %{
        notes: notes
      }, request_metadata(conn))

      json(conn, %{data: serialize(alert), message: "Alert marked as false positive"})
    end
  end

  def update_status(conn, %{"id" => id, "status" => new_status}) do
    valid_statuses = ["open", "new", "investigating", "resolved", "false_positive"]

    if new_status in valid_statuses do
      alert = authorize_alert!(conn, id)

      with {:ok, %Alert{} = alert} <- Alerts.update_alert(alert, %{status: new_status}) do
        user = conn.assigns[:current_user]
        AuditLog.log_alert_action(user, "update_status", id, %{
          new_status: new_status
        }, request_metadata(conn))

        json(conn, %{data: serialize(alert), message: "Status updated to #{new_status}"})
      end
    else
      conn
      |> put_status(:bad_request)
      |> json(%{error: "Invalid status. Must be one of: #{Enum.join(valid_statuses, ", ")}"})
    end
  end

  # ===========================================================================
  # Bulk Operations
  # ===========================================================================

  @doc """
  Bulk update multiple alerts at once.

  POST /api/v1/alerts/bulk
  Body: { "alert_ids": [...], "action": "status|assign|resolve|false_positive", ... }
  """
  def bulk_update(conn, %{"alert_ids" => alert_ids, "action" => action} = params) when is_list(alert_ids) do
    organization_id = conn.assigns[:current_organization_id]
    opts = if organization_id, do: [organization_id: organization_id], else: []

    result = case action do
      "status" ->
        new_status = params["status"] || params["new_status"]
        Alerts.bulk_update_status(alert_ids, new_status, opts)

      "assign" ->
        user_id = params["user_id"] || params["assigned_to_id"]
        Alerts.bulk_assign(alert_ids, user_id, opts)

      "resolve" ->
        notes = params["notes"] || params["resolution_notes"]
        Alerts.bulk_resolve(alert_ids, notes, opts)

      "false_positive" ->
        notes = params["notes"] || params["resolution_notes"]
        Alerts.bulk_false_positive(alert_ids, notes, opts)

      "acknowledge" ->
        Alerts.bulk_update(alert_ids, %{status: "acknowledged"}, opts)

      "close" ->
        Alerts.bulk_update(alert_ids, %{status: "closed"}, opts)

      _ ->
        {:error, :invalid_action}
    end

    case result do
      {:ok, count} ->
        user = conn.assigns[:current_user]
        AuditLog.log_alert_action(user, "bulk_#{action}", nil, %{
          alert_ids: alert_ids,
          action: action,
          updated_count: count
        }, request_metadata(conn))

        json(conn, %{
          success: true,
          message: "Successfully updated #{count} alert(s)",
          updated_count: count
        })

      {:error, :invalid_status} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Invalid status value"})

      {:error, :invalid_action} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Invalid action. Must be one of: status, assign, resolve, false_positive, acknowledge, close"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Failed to update alerts: #{inspect(reason)}"})
    end
  end

  def bulk_update(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required parameters: alert_ids (array), action"})
  end

  @doc """
  Add alerts to an investigation.

  POST /api/v1/alerts/bulk/add-to-investigation
  """
  def bulk_add_to_investigation(conn, %{"alert_ids" => alert_ids, "investigation_id" => investigation_id}) do
    organization_id = conn.assigns[:current_organization_id]

    case TamanduaServer.Investigations.add_alerts_to_investigation(
           investigation_id,
           alert_ids,
           organization_id: organization_id
         ) do
      {:ok, investigation} ->
        json(conn, %{
          success: true,
          message: "Added #{length(alert_ids)} alert(s) to investigation",
          investigation_id: investigation.id
        })

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Investigation not found"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Failed to add alerts: #{inspect(reason)}"})
    end
  end

  # ===========================================================================
  # Advanced Search
  # ===========================================================================

  @doc """
  Search alerts with advanced filtering.

  POST /api/v1/alerts/search
  """
  def search(conn, params) do
    case resolve_organization_id(conn, params) do
      nil -> tenant_context_required(conn)
      organization_id -> search_alerts(conn, params, organization_id)
    end
  end

  defp search_alerts(conn, params, organization_id) do
    limit = parse_int(params["limit"], 100) |> max(1) |> min(@max_per_page)
    offset = parse_int(params["offset"], 0) |> max(0)
    filters = search_filters(params) |> Map.put_new("validation", "include")

    opts = [
      organization_id: organization_id,
      limit: limit + 1,
      offset: offset,
      sort_by: parse_sort_field(params["sort_by"]),
      sort_order: parse_sort_order(params["sort_order"]),
      summary: true
    ]

    alerts = Alerts.search_alerts(filters, opts)
    page = div(offset, limit) + 1
    returned_alerts = Enum.take(alerts, limit)
    returned = length(returned_alerts)
    has_more = length(alerts) > limit

    json(conn, %{
      data: Enum.map(returned_alerts, &serialize/1),
      meta: %{
        total: nil,
        limit: limit,
        per_page: limit,
        offset: offset,
        page: page,
        total_pages: nil,
        max_per_page: @max_per_page,
        returned: returned,
        truncated: has_more,
        has_more: has_more,
        applied_filters: compact_applied_filters(filters)
      }
    })
  end

  @search_filter_keys ~w(
    search query severity status agent_id assigned_to_id source category
    mitre_techniques mitre_tactics mitre_technique date_from date_to
    threat_score_min threat_score_max has_evidence validation include_validation
  )

  defp search_filters(params) do
    nested_filters =
      params
      |> param_value("filters")
      |> stringify_filter_keys()
      |> Map.take(@search_filter_keys)

    top_level_filters =
      params
      |> stringify_filter_keys()
      |> Map.take(@search_filter_keys)

    nested_filters
    |> Map.merge(top_level_filters)
    |> normalize_search_aliases()
  end

  defp include_total?(params) do
    value = params["include_total"] || params["includeTotal"]
    value in [true, "true", "1", 1]
  end

  defp list_alert_summary_rows(org_id, filters) do
    sort_by = Keyword.get(filters, :sort_by, :inserted_at)
    sort_order = Keyword.get(filters, :sort_order, :desc)
    limit_value = Keyword.get(filters, :limit, 26)
    offset_value = Keyword.get(filters, :offset, 0)

    Alert
    |> where([a], a.organization_id == ^org_id)
    |> apply_alert_summary_filter(:severity, Keyword.get(filters, :severity))
    |> apply_alert_summary_filter(:status, Keyword.get(filters, :status))
    |> apply_alert_summary_filter(:agent_id, Keyword.get(filters, :agent_id))
    |> apply_alert_summary_filter(:assigned_to_id, Keyword.get(filters, :assigned_to_id))
    |> apply_alert_summary_filter(:mitre_technique, Keyword.get(filters, :mitre_technique))
    |> apply_alert_summary_filter(:inserted_from, Keyword.get(filters, :inserted_from))
    |> apply_alert_summary_filter(:inserted_to, Keyword.get(filters, :inserted_to))
    |> apply_alert_summary_order(sort_by, sort_order)
    |> limit(^limit_value)
    |> offset(^offset_value)
    |> select([a], %{
      __alert_summary__: true,
      id: a.id,
      agent_id: a.agent_id,
      severity: a.severity,
      title: a.title,
      description: a.description,
      status: a.status,
      threat_score: a.threat_score,
      mitre_tactics: a.mitre_tactics,
      mitre_techniques: a.mitre_techniques,
      assigned_to_id: a.assigned_to_id,
      source_event_id: a.source_event_id,
      detection_metadata: a.detection_metadata,
      occurrence_count: a.occurrence_count,
      last_seen_at: a.last_seen_at,
      rule_version: a.rule_version,
      recommended_response: a.recommended_response,
      verdict: a.verdict,
      verdict_by_id: a.verdict_by_id,
      verdict_at: a.verdict_at,
      verdict_notes: a.verdict_notes,
      suppression_rule_id: a.suppression_rule_id,
      blockchain_tx_id: a.blockchain_tx_id,
      blockchain_attested_at: a.blockchain_attested_at,
      bounty_tx_id: a.bounty_tx_id,
      bounty_amount_lamports: a.bounty_amount_lamports,
      bounty_paid_at: a.bounty_paid_at,
      rule_author_pubkey: a.rule_author_pubkey,
      incident_hash: a.incident_hash,
      manifest_hash: a.manifest_hash,
      attestation_tlp: a.attestation_tlp,
      attestation_ioc_count: a.attestation_ioc_count,
      attestation_ioc_types: a.attestation_ioc_types,
      attestation_redacted_ioc_count: a.attestation_redacted_ioc_count,
      attestation_confidence: a.attestation_confidence,
      attestation_threat_class: a.attestation_threat_class,
      attestation_malware_family: a.attestation_malware_family,
      inserted_at: a.inserted_at,
      updated_at: a.updated_at
    })
    |> Repo.all()
  end

  defp apply_alert_summary_filter(query, _field, nil), do: query
  defp apply_alert_summary_filter(query, _field, ""), do: query
  defp apply_alert_summary_filter(query, _field, []), do: query

  defp apply_alert_summary_filter(query, :severity, values) when is_list(values) do
    from(a in query, where: a.severity in ^values)
  end

  defp apply_alert_summary_filter(query, :severity, value) do
    from(a in query, where: a.severity == ^value)
  end

  defp apply_alert_summary_filter(query, :status, values) when is_list(values) do
    from(a in query, where: a.status in ^values)
  end

  defp apply_alert_summary_filter(query, :status, value) do
    from(a in query, where: a.status == ^value)
  end

  defp apply_alert_summary_filter(query, :agent_id, value) do
    from(a in query, where: a.agent_id == ^value)
  end

  defp apply_alert_summary_filter(query, :assigned_to_id, value) do
    from(a in query, where: a.assigned_to_id == ^value)
  end

  defp apply_alert_summary_filter(query, :mitre_technique, value) do
    from(a in query, where: ^value in a.mitre_techniques)
  end

  defp apply_alert_summary_filter(query, :inserted_from, value) do
    case DateTime.from_iso8601(value) do
      {:ok, datetime, _} -> from(a in query, where: a.inserted_at >= ^datetime)
      _ -> query
    end
  end

  defp apply_alert_summary_filter(query, :inserted_to, value) do
    case DateTime.from_iso8601(value) do
      {:ok, datetime, _} -> from(a in query, where: a.inserted_at <= ^datetime)
      _ -> query
    end
  end

  defp apply_alert_summary_filter(query, _field, _value), do: query

  defp apply_alert_summary_order(query, :severity, :asc), do: from(a in query, order_by: [asc: a.severity, desc: a.inserted_at])
  defp apply_alert_summary_order(query, :severity, _), do: from(a in query, order_by: [desc: a.severity, desc: a.inserted_at])
  defp apply_alert_summary_order(query, :threat_score, :asc), do: from(a in query, order_by: [asc: a.threat_score, desc: a.inserted_at])
  defp apply_alert_summary_order(query, :threat_score, _), do: from(a in query, order_by: [desc: a.threat_score, desc: a.inserted_at])
  defp apply_alert_summary_order(query, :status, :asc), do: from(a in query, order_by: [asc: a.status, desc: a.inserted_at])
  defp apply_alert_summary_order(query, :status, _), do: from(a in query, order_by: [desc: a.status, desc: a.inserted_at])
  defp apply_alert_summary_order(query, :title, :asc), do: from(a in query, order_by: [asc: a.title, desc: a.inserted_at])
  defp apply_alert_summary_order(query, :title, _), do: from(a in query, order_by: [desc: a.title, desc: a.inserted_at])
  defp apply_alert_summary_order(query, _field, :asc), do: from(a in query, order_by: [asc: a.inserted_at])
  defp apply_alert_summary_order(query, _field, _), do: from(a in query, order_by: [desc: a.inserted_at])

  defp stringify_filter_keys(value) when is_map(value) do
    Map.new(value, fn {key, filter_value} -> {to_string(key), filter_value} end)
  end

  defp stringify_filter_keys(_value), do: %{}

  defp normalize_search_aliases(filters) do
    case {Map.get(filters, "search"), Map.get(filters, "query")} do
      {nil, query} when query not in [nil, ""] -> Map.put(filters, "search", query)
      {"", query} when query not in [nil, ""] -> Map.put(filters, "search", query)
      _ -> filters
    end
    |> Map.delete("query")
    |> normalize_search_status_alias()
  end

  defp normalize_search_status_alias(%{"status" => status} = filters) do
    Map.put(filters, "status", normalize_status_filter(status))
  end

  defp normalize_search_status_alias(filters), do: filters

  defp compact_applied_filters(filters) when is_list(filters) do
    filters
    |> Map.new()
    |> compact_applied_filters()
  end

  defp compact_applied_filters(filters) when is_map(filters) do
    Map.reject(filters, fn {_key, value} -> value in [nil, "", []] end)
  end

  defp param_value(params, _key) when is_map(params) do
    Map.get(params, "filters") || Map.get(params, :filters)
  end

  defp param_value(_params, _key), do: nil

  defp parse_int(nil, default), do: default
  defp parse_int(val, _default) when is_integer(val), do: val
  defp parse_int(val, default) when is_binary(val) do
    case Integer.parse(val) do
      {int, _} -> int
      :error -> default
    end
  end

  defp normalize_status_filter(nil), do: nil
  defp normalize_status_filter(""), do: nil
  defp normalize_status_filter("active"), do: ["new", "open", "acknowledged", "triaged", "investigating"]
  defp normalize_status_filter("dismissed"), do: ["resolved", "false_positive", "closed"]
  defp normalize_status_filter("closed"), do: ["resolved", "closed"]
  defp normalize_status_filter(status), do: status

  defp parse_sort_field(nil), do: :inserted_at
  defp parse_sort_field("created_at"), do: :inserted_at
  defp parse_sort_field("severity"), do: :severity
  defp parse_sort_field("threat_score"), do: :threat_score
  defp parse_sort_field("status"), do: :status
  defp parse_sort_field("title"), do: :title
  defp parse_sort_field(_), do: :inserted_at

  defp parse_sort_order(nil), do: :desc
  defp parse_sort_order("asc"), do: :asc
  defp parse_sort_order("desc"), do: :desc
  defp parse_sort_order(_), do: :desc

  # ===========================================================================
  # Statistics & Analytics
  # ===========================================================================

  @doc """
  Get alert summary for the dashboard ThreatSummary widget.

  Returns severity distribution, threat level, active threat score, and top threats.
  Supports `range` query param: 24h, 7d, 30d (default 7d).

  GET /api/v1/alerts/summary?range=7d
  """
  def summary(conn, params) do
    organization_id = conn.assigns[:organization_id]
    range = params["range"] || "7d"

    summary_data = Alerts.get_alert_summary(organization_id: organization_id, range: range)

    json(conn, %{data: summary_data})
  end

  @doc """
  Get alert trend data for the dashboard DetectionTrend widget.

  Returns time-series data points with severity breakdowns, trend direction,
  category breakdowns, and peak-hour analysis.
  Supports `period` query param: 24h, 7d, 30d (default 7d).

  GET /api/v1/alerts/trend?period=7d
  """
  def trend(conn, params) do
    organization_id = conn.assigns[:organization_id]
    period = params["period"] || "7d"

    trend_data = Alerts.get_alert_trend(organization_id: organization_id, period: period)

    json(conn, %{data: trend_data})
  end

  @doc """
  Get alert statistics.

  GET /api/v1/alerts/stats
  """
  def stats(conn, params) do
    organization_id = conn.assigns[:organization_id]
    time_range = params["time_range"] || "7d"

    stats = Alerts.get_alert_stats(organization_id: organization_id, time_range: time_range)

    json(conn, %{data: stats})
  end

  @doc """
  Get historical occurrence count for an alert.

  GET /api/v1/alerts/:id/history
  """
  def history(conn, %{"id" => id} = params) do
    alert = authorize_alert!(conn, id)
    days_back = parse_int(params["days_back"], 30)

    history = Alerts.get_historical_count(alert, days_back: days_back)

    json(conn, %{data: history})
  end

  @doc """
  Get related alerts for grouping.

  GET /api/v1/alerts/:id/related
  """
  def related(conn, %{"id" => id}) do
    # First verify the alert belongs to the current organization
    _alert = authorize_alert!(conn, id)

    related_alerts = Alerts.get_related_alerts(id, organization_id: conn.assigns[:current_organization_id])

    json(conn, %{data: Enum.map(related_alerts, &serialize/1)})
  end

  # ===========================================================================
  # Exclusion Rules
  # ===========================================================================

  @doc """
  List exclusion rules.

  GET /api/v1/alerts/exclusions
  """
  def list_exclusions(conn, params) do
    organization_id = resolve_organization_id(conn, params)

    opts = [
      enabled_only: params["enabled_only"] == "true",
      rule_type: params["rule_type"]
    ]

    rules =
      if organization_id do
        Exclusions.list_rules(organization_id, opts)
      else
        []
      end

    json(conn, %{data: Enum.map(rules, &serialize_exclusion_rule/1)})
  end

  @doc """
  Get exclusion rule statistics.

  GET /api/v1/alerts/exclusions/stats
  """
  def exclusion_stats(conn, _params) do
    organization_id = resolve_organization_id(conn, %{})

    stats =
      if organization_id do
        Exclusions.get_stats(organization_id)
      else
        %{
          total_rules: 0,
          active_rules: 0,
          expired_rules: 0,
          total_matches: 0,
          by_type: %{}
        }
      end

    json(conn, %{data: stats})
  end

  @doc """
  Create an exclusion rule.

  POST /api/v1/alerts/exclusions
  """
  def create_exclusion(conn, params) do
    organization_id = resolve_organization_id(conn, params)
    user_id = conn.assigns[:current_user] && conn.assigns[:current_user].id

    attrs = params
    |> Map.take([
      "name", "description", "rule_type", "enabled",
      "criteria", "hash_patterns", "path_patterns", "cmdline_patterns",
      "ip_patterns", "domain_patterns", "rule_name_patterns",
      "source_agent_ids", "source_hostnames",
      "time_based", "active_start", "active_end", "active_days",
      "expires_at", "adjust_severity"
    ])
    |> atomize_keys()
    |> Map.put(:organization_id, organization_id)
    |> Map.put(:created_by_id, user_id)

    case Exclusions.create_rule(attrs) do
      {:ok, rule} ->
        conn
        |> put_status(:created)
        |> json(%{data: serialize_exclusion_rule(rule), message: "Exclusion rule created"})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: format_changeset_errors(changeset)})
    end
  end

  @doc """
  Create an exclusion rule from an alert.

  POST /api/v1/alerts/:id/create-exclusion
  """
  def create_exclusion_from_alert(conn, %{"id" => alert_id} = params) do
    alert = authorize_alert!(conn, alert_id)
    user_id = conn.assigns[:current_user] && conn.assigns[:current_user].id

    opts = [
      rule_type: params["rule_type"] || "suppress",
      name: params["name"],
      created_by_id: user_id,
      expires_in_days: parse_int(params["expires_in_days"], nil),
      adjust_severity: params["adjust_severity"],
      match_fields: parse_match_fields(params["match_fields"])
    ]

    case Exclusions.create_rule_from_alert(alert, opts) do
      {:ok, rule} ->
        conn
        |> put_status(:created)
        |> json(%{data: serialize_exclusion_rule(rule), message: "Exclusion rule created from alert"})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: format_changeset_errors(changeset)})
    end
  end

  @allowed_match_fields ~w(rule_name agent_id hostname severity process_name file_path hash cmdline ip domain)

  defp parse_match_fields(nil), do: [:rule_name, :agent_id]
  defp parse_match_fields(fields) when is_list(fields) do
    fields
    |> Enum.map(fn f ->
      if is_binary(f), do: safe_to_atom(f, @allowed_match_fields), else: f
    end)
    |> Enum.reject(&is_nil/1)
    |> case do
      [] -> [:rule_name, :agent_id]
      valid_fields -> valid_fields
    end
  end
  defp parse_match_fields(_), do: [:rule_name, :agent_id]

  defp safe_to_atom(str, allowed) when is_binary(str) do
    if str in allowed do
      String.to_existing_atom(str)
    else
      nil
    end
  rescue
    ArgumentError -> nil
  end

  defp resolve_organization_id(conn, _params) do
    valid_organization_id(conn.assigns[:current_organization_id]) ||
      valid_organization_id(conn.assigns[:organization_id]) ||
      valid_organization_id(resolve_user_organization_id(conn.assigns[:current_user]))
  end

  defp resolve_user_organization_id(%{organization_id: organization_id}), do: organization_id
  defp resolve_user_organization_id(_), do: nil

  defp valid_organization_id(value) when is_binary(value) do
    case Ecto.UUID.cast(String.trim(value)) do
      {:ok, uuid} -> uuid
      :error -> nil
    end
  end

  defp valid_organization_id(_value), do: nil

  defp tenant_context_required(conn) do
    conn
    |> put_status(:forbidden)
    |> json(%{error: "tenant_context_required"})
  end

  @doc """
  Update an exclusion rule.

  PUT /api/v1/alerts/exclusions/:id
  """
  def update_exclusion(conn, %{"id" => id} = params) do
    org_id = conn.assigns[:current_organization_id]
    case Exclusions.get_rule_for_org(org_id, id) do
      {:ok, rule} ->
        attrs = params
        |> Map.take([
          "name", "description", "enabled",
          "criteria", "hash_patterns", "path_patterns", "cmdline_patterns",
          "ip_patterns", "domain_patterns", "rule_name_patterns",
          "source_agent_ids", "source_hostnames",
          "time_based", "active_start", "active_end", "active_days",
          "expires_at", "adjust_severity"
        ])
        |> atomize_keys()

        case Exclusions.update_rule(rule, attrs) do
          {:ok, updated_rule} ->
            json(conn, %{data: serialize_exclusion_rule(updated_rule), message: "Exclusion rule updated"})

          {:error, changeset} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: format_changeset_errors(changeset)})
        end

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Exclusion rule not found"})
    end
  end

  @doc """
  Delete an exclusion rule.

  DELETE /api/v1/alerts/exclusions/:id
  """
  def delete_exclusion(conn, %{"id" => id}) do
    org_id = conn.assigns[:current_organization_id]
    case Exclusions.get_rule_for_org(org_id, id) do
      {:ok, rule} ->
        case Exclusions.delete_rule(rule) do
          {:ok, _} ->
            json(conn, %{success: true, message: "Exclusion rule deleted"})

          {:error, _} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "Failed to delete exclusion rule"})
        end

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Exclusion rule not found"})
    end
  end

  @doc """
  Toggle an exclusion rule's enabled status.

  POST /api/v1/alerts/exclusions/:id/toggle
  """
  def toggle_exclusion(conn, %{"id" => id}) do
    org_id = conn.assigns[:current_organization_id]
    case Exclusions.get_rule_for_org(org_id, id) do
      {:ok, rule} ->
        case Exclusions.toggle_rule(rule) do
          {:ok, updated_rule} ->
            status = if updated_rule.enabled, do: "enabled", else: "disabled"
            json(conn, %{data: serialize_exclusion_rule(updated_rule), message: "Exclusion rule #{status}"})

          {:error, _} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "Failed to toggle exclusion rule"})
        end

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Exclusion rule not found"})
    end
  end

  # ===========================================================================
  # Analyst Verdict / Feedback Loop
  # ===========================================================================

  @doc """
  Set the analyst verdict on an alert.

  POST /api/v1/alerts/:id/verdict
  Body: { "verdict": "true_positive|false_positive|benign|suspicious", "notes": "...", "create_suppression_rule": true }
  """
  def set_verdict(conn, %{"id" => id} = params) do
    verdict = params["verdict"]
    notes = params["notes"]
    create_suppression = params["create_suppression_rule"] == true || params["create_suppression_rule"] == "true"
    suppression_ttl = parse_int(params["suppression_ttl_days"], 30)
    suppression_action = params["suppression_action"] || "suppress"

    user = conn.assigns[:current_user]
    user_id = user && user.id

    opts = [
      notes: notes,
      create_suppression_rule: create_suppression,
      suppression_ttl_days: suppression_ttl,
      suppression_action: suppression_action
    ]

    case Alerts.set_verdict(id, verdict, user_id, opts) do
      {:ok, result} ->
        AuditLog.log_alert_action(user, "set_verdict", id, %{
          verdict: verdict,
          notes: notes,
          create_suppression_rule: create_suppression,
          suppression_rule_id: result.suppression_rule && result.suppression_rule.id
        }, request_metadata(conn))

        json(conn, %{
          data: serialize(result.alert),
          suppression_rule: result.suppression_rule && serialize_suppression_rule(result.suppression_rule),
          feedback_log: serialize_feedback_log(result.feedback_log),
          message: "Verdict set to #{verdict}"
        })

      {:error, :invalid_verdict} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Invalid verdict. Must be one of: unconfirmed, true_positive, false_positive, benign, suspicious"})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Alert not found"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Failed to set verdict: #{inspect(reason)}"})
    end
  end

  @doc """
  Bulk set verdict on multiple alerts.

  POST /api/v1/alerts/bulk_verdict
  Body: { "alert_ids": [...], "verdict": "...", "notes": "..." }
  """
  def bulk_verdict(conn, %{"alert_ids" => alert_ids, "verdict" => verdict} = params) when is_list(alert_ids) do
    notes = params["notes"]
    create_suppression = params["create_suppression_rule"] == true || params["create_suppression_rule"] == "true"

    user = conn.assigns[:current_user]
    user_id = user && user.id

    opts = [
      notes: notes,
      create_suppression_rule: create_suppression,
      suppression_ttl_days: parse_int(params["suppression_ttl_days"], 30),
      suppression_action: params["suppression_action"] || "suppress"
    ]

    case Alerts.bulk_set_verdict(alert_ids, verdict, user_id, opts) do
      {:ok, result} ->
        AuditLog.log_alert_action(user, "bulk_set_verdict", nil, %{
          alert_ids: alert_ids,
          verdict: verdict,
          updated: result.updated,
          errors: result.errors,
          suppression_rules_created: result.suppression_rules_created
        }, request_metadata(conn))

        json(conn, %{
          success: true,
          message: "Verdict set on #{result.updated} alert(s)",
          updated: result.updated,
          errors: result.errors,
          suppression_rules_created: result.suppression_rules_created
        })

      {:error, :invalid_verdict} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Invalid verdict. Must be one of: unconfirmed, true_positive, false_positive, benign, suspicious"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Failed to set verdict: #{inspect(reason)}"})
    end
  end

  def bulk_verdict(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required parameters: alert_ids (array), verdict"})
  end

  @doc """
  Get verdict statistics and FP rate analytics.

  GET /api/v1/alerts/verdict-stats
  """
  def verdict_stats(conn, params) do
    organization_id = conn.assigns[:organization_id]
    days = parse_int(params["days"], 30)

    stats = Alerts.get_verdict_stats(organization_id: organization_id, days: days)

    json(conn, %{data: stats})
  end

  @doc """
  Get feedback log for an alert.

  GET /api/v1/alerts/:id/feedback-log
  """
  def feedback_log(conn, %{"id" => id}) do
    logs = Alerts.get_feedback_log(id)

    data = Enum.map(logs, &serialize_feedback_log/1)

    json(conn, %{data: data})
  end

  @doc """
  List suppression rules.

  GET /api/v1/alerts/suppression-rules
  """
  def list_suppression_rules(conn, params) do
    # Tenant scope comes only from the authenticated context; never trust a
    # client-supplied organization_id (would allow cross-tenant access / writes).
    organization_id = conn.assigns[:organization_id]
    enabled_only = params["enabled_only"] == "true"

    rules = Alerts.list_suppression_rules(
      organization_id: organization_id,
      enabled_only: enabled_only
    )

    json(conn, %{data: Enum.map(rules, &serialize_suppression_rule/1)})
  end

  @doc """
  Create a suppression rule manually.

  POST /api/v1/alerts/suppression-rules
  """
  def create_suppression_rule(conn, params) do
    # Tenant scope comes only from the authenticated context; never trust a
    # client-supplied organization_id (would allow cross-tenant access / writes).
    organization_id = conn.assigns[:organization_id]
    user_id = conn.assigns[:current_user] && conn.assigns[:current_user].id

    attrs = params
    |> Map.take([
      "name", "description", "enabled",
      "rule_name_pattern", "agent_id", "process_name_pattern",
      "parent_process_pattern", "file_path_pattern", "title_pattern",
      "severity", "mitre_techniques", "criteria",
      "expires_at", "max_matches",
      "action", "reduce_to_severity"
    ])
    |> atomize_keys()
    |> Map.put(:organization_id, organization_id)
    |> Map.put(:created_by_id, user_id)

    case Alerts.create_suppression_rule(attrs) do
      {:ok, rule} ->
        conn
        |> put_status(:created)
        |> json(%{data: serialize_suppression_rule(rule), message: "Suppression rule created"})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: format_changeset_errors(changeset)})
    end
  end

  @doc """
  Update a suppression rule.

  PUT /api/v1/alerts/suppression-rules/:id
  """
  def update_suppression_rule(conn, %{"id" => id} = params) do
    org_id = conn.assigns[:current_organization_id]
    case Alerts.get_suppression_rule_for_org(org_id, id) do
      {:ok, rule} ->
        attrs = params
        |> Map.take([
          "name", "description", "enabled",
          "rule_name_pattern", "process_name_pattern",
          "parent_process_pattern", "file_path_pattern", "title_pattern",
          "severity", "mitre_techniques", "criteria",
          "expires_at", "max_matches",
          "action", "reduce_to_severity"
        ])
        |> atomize_keys()

        case Alerts.update_suppression_rule(rule, attrs) do
          {:ok, updated} ->
            json(conn, %{data: serialize_suppression_rule(updated), message: "Suppression rule updated"})

          {:error, changeset} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: format_changeset_errors(changeset)})
        end

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Suppression rule not found"})
    end
  end

  @doc """
  Delete a suppression rule.

  DELETE /api/v1/alerts/suppression-rules/:id
  """
  def delete_suppression_rule(conn, %{"id" => id}) do
    org_id = conn.assigns[:current_organization_id]
    case Alerts.get_suppression_rule_for_org(org_id, id) do
      {:ok, rule} ->
        case Alerts.delete_suppression_rule(rule) do
          {:ok, _} ->
            json(conn, %{success: true, message: "Suppression rule deleted"})
          {:error, _} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "Failed to delete suppression rule"})
        end

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Suppression rule not found"})
    end
  end

  @doc """
  Toggle a suppression rule's enabled status.

  POST /api/v1/alerts/suppression-rules/:id/toggle
  """
  def toggle_suppression_rule(conn, %{"id" => id}) do
    org_id = conn.assigns[:current_organization_id]
    case Alerts.get_suppression_rule_for_org(org_id, id) do
      {:ok, rule} ->
        case Alerts.toggle_suppression_rule(rule) do
          {:ok, updated} ->
            status_str = if updated.enabled, do: "enabled", else: "disabled"
            json(conn, %{data: serialize_suppression_rule(updated), message: "Suppression rule #{status_str}"})
          {:error, _} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "Failed to toggle suppression rule"})
        end

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Suppression rule not found"})
    end
  end

  @doc """
  Get suppression engine stats.

  GET /api/v1/alerts/suppression-stats
  """
  def suppression_stats(conn, _params) do
    alias TamanduaServer.Alerts.Suppression

    stats = Suppression.get_stats()
    json(conn, %{data: stats})
  end

  # ===========================================================================
  # Saved Filter Presets
  # ===========================================================================

  @doc """
  List saved filter presets for the current user.

  GET /api/v1/alerts/filter-presets
  """
  def list_filter_presets(conn, _params) do
    user_id = conn.assigns[:current_user] && conn.assigns[:current_user].id

    # For now, return from user preferences or a dedicated table
    # This could be expanded to use a dedicated filter_presets table
    presets = get_user_filter_presets(user_id)

    json(conn, %{data: presets})
  end

  @doc """
  Save a filter preset.

  POST /api/v1/alerts/filter-presets
  """
  def save_filter_preset(conn, %{"name" => name, "filters" => filters}) do
    _user_id = conn.assigns[:current_user] && conn.assigns[:current_user].id

    preset = %{
      id: Ecto.UUID.generate(),
      name: name,
      filters: filters,
      created_at: DateTime.utc_now() |> DateTime.to_iso8601()
    }

    # In production, save to database
    # For now, return the preset as if saved
    json(conn, %{data: preset, message: "Filter preset saved"})
  end

  defp get_user_filter_presets(_user_id) do
    # Return default presets
    [
      %{id: "critical-open", name: "Critical Open", filters: %{severity: "critical", status: "open"}},
      %{id: "high-unassigned", name: "High Unassigned", filters: %{severity: ["critical", "high"], assigned_to_id: "unassigned"}},
      %{id: "my-alerts", name: "My Alerts", filters: %{assigned_to_id: "current_user"}},
      %{id: "recent-24h", name: "Last 24 Hours", filters: %{date_from: "today-1d"}},
      %{id: "false-positives", name: "False Positives", filters: %{status: "false_positive"}}
    ]
  end

  # ===========================================================================
  # Export
  # ===========================================================================

  @doc """
  Export alerts with enrichment data.

  POST /api/v1/alerts/export
  """
  def export(conn, params) do
    organization_id = conn.assigns[:organization_id]
    format = params["format"] || "json"

    # Get alert IDs or use filters
    alerts = case params["alert_ids"] do
      ids when is_list(ids) and length(ids) > 0 ->
        Alerts.get_alerts_by_ids(ids, organization_id: organization_id)

      _ ->
        filters = Map.take(params, [
          "search", "severity", "status", "agent_id", "assigned_to_id", "source", "category",
          "mitre_techniques", "mitre_tactics", "date_from", "date_to",
          "threat_score_min", "threat_score_max", "has_evidence"
        ])
        Alerts.search_alerts(filters, organization_id: organization_id, limit: 5_000)
    end

    include_enrichment = params["include_enrichment"] == true || params["include_enrichment"] == "true"

    data = Enum.map(alerts, fn alert ->
      base = serialize(alert)

      if include_enrichment do
        # Add historical count
        history = Alerts.get_historical_count(alert, days_back: 30)
        Map.put(base, :historical_occurrences, history.count)
      else
        base
      end
    end)

    case format do
      "csv" ->
        csv_content = alerts_to_csv(data)
        conn
        |> put_resp_content_type("text/csv")
        |> put_resp_header("content-disposition", "attachment; filename=\"alerts-export.csv\"")
        |> send_resp(200, csv_content)

      "json" ->
        json(conn, %{data: data, meta: %{count: length(data), exported_at: DateTime.utc_now()}})

      _ ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Invalid format. Use 'json' or 'csv'"})
    end
  end

  defp alerts_to_csv(alerts) do
    headers = ["id", "title", "severity", "status", "agent_id", "source", "threat_score", "created_at", "mitre_techniques"]

    rows = Enum.map(alerts, fn alert ->
      [
        alert[:id],
        alert[:title],
        alert[:severity],
        alert[:status],
        alert[:agent_id],
        alert[:source],
        alert[:threat_score] || "",
        alert[:created_at],
        (alert[:mitre_techniques] || []) |> Enum.join("; ")
      ]
    end)

    [headers | rows]
    |> Enum.map(fn row -> row |> Enum.map(&csv_escape/1) |> Enum.join(",") end)
    |> Enum.join("\n")
  end

  defp csv_escape(nil), do: ""
  defp csv_escape(value) do
    text = to_string(value)

    if String.contains?(text, [",", "\"", "\n", "\r"]) do
      "\"#{String.replace(text, "\"", "\"\"")}\""
    else
      text
    end
  end

  # ===========================================================================
  # Users for Assignment
  # ===========================================================================

  @doc """
  Get list of users available for alert assignment.

  GET /api/v1/alerts/assignable-users
  """
  def assignable_users(conn, _params) do
    organization_id = conn.assigns[:organization_id]

    users = if organization_id do
      Accounts.list_users(organization_id)
    else
      Accounts.list_all_users()
    end

    data = Enum.map(users, fn user ->
      %{
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    end)

    json(conn, %{data: data})
  end

  # ===========================================================================
  # Helpers
  # ===========================================================================

  defp serialize(%{__alert_summary__: true} = alert) do
    metadata = Map.get(alert, :detection_metadata) || %{}
    rule_name = summary_rule_name(metadata)

    %{
      id: alert.id,
      agent_id: alert.agent_id,
      agent_hostname: nil,
      agent_name: nil,
      agent: nil,
      severity: alert.severity,
      title: alert.title,
      description: alert.description,
      source: summary_source(metadata),
      status: alert.status,
      threat_score: alert.threat_score,
      mitre_tactics: alert.mitre_tactics || [],
      mitre_techniques: alert.mitre_techniques || [],
      assigned_to_id: alert.assigned_to_id,
      resolution_notes: nil,
      source_event_id: alert.source_event_id,
      sourceEventId: alert.source_event_id,
      eventIds: [],
      event_ids: [],
      evidence: %{},
      evidence_quality: "missing",
      evidenceQuality: "missing",
      operational_triage: %{"level" => "needs_review", "reasons" => ["summary_projection"]},
      operationalTriage: %{"level" => "needs_review", "reasons" => ["summary_projection"]},
      triage_agent: nil,
      triageAgent: nil,
      process_chain: [],
      raw_event: %{},
      rawEvent: %{},
      detection_metadata: metadata,
      detectionMetadata: metadata,
      enrichment: %{},
      auto_investigation: nil,
      autoInvestigation: nil,
      rule_name: rule_name,
      detection_rule: rule_name,
      contributing_events: [],
      contributingEvents: [],
      processChain: [],
      mitreTactics: alert.mitre_tactics || [],
      mitreTechniques: alert.mitre_techniques || [],
      mitre_technique: List.first(alert.mitre_techniques || []),
      technique_id: List.first(alert.mitre_techniques || []),
      occurrence_count: alert.occurrence_count,
      occurrenceCount: alert.occurrence_count,
      last_seen_at: format_datetime(alert.last_seen_at),
      lastSeenAt: format_datetime(alert.last_seen_at),
      rule_version: alert.rule_version,
      recommended_response: alert.recommended_response,
      recommendedResponse: alert.recommended_response,
      recommended_actions: [],
      recommendedActions: [],
      verdict: alert.verdict || "unconfirmed",
      verdict_by_id: alert.verdict_by_id,
      verdict_at: format_datetime(alert.verdict_at),
      verdict_notes: alert.verdict_notes,
      suppression_rule_id: alert.suppression_rule_id,
      blockchain_tx_id: alert.blockchain_tx_id,
      blockchain_attested_at: format_datetime(alert.blockchain_attested_at),
      bounty_tx_id: alert.bounty_tx_id,
      bounty_amount_lamports: alert.bounty_amount_lamports,
      bounty_amount_sol:
        if(alert.bounty_amount_lamports, do: alert.bounty_amount_lamports / 1_000_000_000, else: nil),
      bounty_paid_at: format_datetime(alert.bounty_paid_at),
      rule_author_pubkey: alert.rule_author_pubkey,
      incident_hash: alert.incident_hash,
      manifest_hash: alert.manifest_hash,
      attestation_tlp: alert.attestation_tlp,
      attestation_ioc_count: alert.attestation_ioc_count,
      attestation_ioc_types: alert.attestation_ioc_types || [],
      attestation_redacted_ioc_count: alert.attestation_redacted_ioc_count,
      attestation_confidence: alert.attestation_confidence,
      proof: summary_proof_details(alert),
      validation_alert: false,
      validationAlert: false,
      validation_kind: nil,
      validationKind: nil,
      created_at: format_datetime(alert.inserted_at),
      updated_at: format_datetime(alert.updated_at)
    }
  end

  defp serialize(%Alert{} = alert) do
    agent = loaded_agent(alert)
    evidence_quality = EvidenceQuality.classify(alert)
    evidence_quality_camel = camelize_evidence_quality(evidence_quality)
    operational_triage = operational_triage(alert, evidence_quality)
    triage_agent = triage_contract_for(alert)

    %{
      id: alert.id,
      agent_id: alert.agent_id,
      agent_hostname: agent && agent.hostname,
      agent_name: agent && agent.hostname,
      agent: serialize_agent_summary(agent),
      severity: alert.severity,
      title: alert.title,
      description: alert.description,
      source: alert_source(alert),
      status: alert.status,
      threat_score: alert.threat_score,
      mitre_tactics: alert.mitre_tactics || [],
      mitre_techniques: alert.mitre_techniques || [],
      assigned_to_id: alert.assigned_to_id,
      resolution_notes: alert.resolution_notes,
      # Forensics & correlation fields
      source_event_id: alert.source_event_id,
      sourceEventId: alert.source_event_id,
      eventIds: alert.event_ids || [],
      event_ids: alert.event_ids || [],
      evidence: alert.evidence || %{},
      evidence_quality: evidence_quality,
      evidenceQuality: evidence_quality_camel,
      operational_triage: operational_triage,
      operationalTriage: camelize_operational_triage(operational_triage),
      triage_agent: triage_agent,
      triageAgent: camelize_triage_agent(triage_agent),
      process_chain: alert.process_chain || [],
      raw_event: alert.raw_event || %{},
      rawEvent: alert.raw_event || %{},
      detection_metadata: alert.detection_metadata || %{},
      detectionMetadata: alert.detection_metadata || %{},
      enrichment: alert.enrichment || %{},
      auto_investigation: get_in(alert.enrichment || %{}, ["auto_investigation"]),
      autoInvestigation: get_in(alert.enrichment || %{}, ["auto_investigation"]),
      rule_name: alert_rule_name(alert),
      detection_rule: alert_rule_name(alert),
      contributing_events: alert.contributing_events || [],
      contributingEvents: alert.contributing_events || [],
      processChain: alert.process_chain || [],
      mitreTactics: alert.mitre_tactics || [],
      mitreTechniques: alert.mitre_techniques || [],
      mitre_technique: List.first(alert.mitre_techniques || []),
      technique_id: List.first(alert.mitre_techniques || []),
      occurrence_count: alert.occurrence_count,
      occurrenceCount: alert.occurrence_count,
      last_seen_at: format_datetime(alert.last_seen_at),
      lastSeenAt: format_datetime(alert.last_seen_at),
      rule_version: alert.rule_version,
      recommended_response: alert.recommended_response,
      recommendedResponse: alert.recommended_response,
      recommended_actions: recommended_actions(alert),
      recommendedActions: recommended_actions(alert),
      # Analyst verdict fields
      verdict: alert.verdict || "unconfirmed",
      verdict_by_id: alert.verdict_by_id,
      verdict_at: format_datetime(alert.verdict_at),
      verdict_notes: alert.verdict_notes,
      suppression_rule_id: alert.suppression_rule_id,
      blockchain_tx_id: alert.blockchain_tx_id,
      blockchain_attested_at: format_datetime(alert.blockchain_attested_at),
      bounty_tx_id: alert.bounty_tx_id,
      bounty_amount_lamports: alert.bounty_amount_lamports,
      bounty_amount_sol:
        if(alert.bounty_amount_lamports, do: alert.bounty_amount_lamports / 1_000_000_000, else: nil),
      bounty_paid_at: format_datetime(alert.bounty_paid_at),
      rule_author_pubkey: alert.rule_author_pubkey,
      incident_hash: alert.incident_hash,
      manifest_hash: alert.manifest_hash,
      attestation_tlp: alert.attestation_tlp,
      attestation_ioc_count: alert.attestation_ioc_count,
      attestation_ioc_types: alert.attestation_ioc_types || [],
      attestation_redacted_ioc_count: alert.attestation_redacted_ioc_count,
      attestation_confidence: alert.attestation_confidence,
      proof: proof_details(alert),
      validation_alert: validation_alert?(alert),
      validationAlert: validation_alert?(alert),
      validation_kind: validation_kind(alert),
      validationKind: validation_kind(alert),
      created_at: format_datetime(alert.inserted_at),
      updated_at: format_datetime(alert.updated_at)
    }
  end

  defp summary_source(metadata) do
    metadata["source"] ||
      metadata["detection_source"] ||
      metadata["alert_source"] ||
      metadata["detection_type"] ||
      "tamandua"
  end

  defp summary_rule_name(metadata) do
    metadata["rule_name"] ||
      metadata["rule"] ||
      metadata["sigma_rule"] ||
      metadata["detection_rule"]
  end

  defp summary_proof_details(alert) do
    %{
      blockchain_tx_id: alert.blockchain_tx_id,
      blockchain_attested_at: format_datetime(alert.blockchain_attested_at),
      incident_hash: alert.incident_hash,
      manifest_hash: alert.manifest_hash,
      tlp: alert.attestation_tlp,
      ioc_count: alert.attestation_ioc_count,
      redacted_ioc_count: alert.attestation_redacted_ioc_count,
      confidence: alert.attestation_confidence
    }
  end

  defp operational_triage(%Alert{} = alert, evidence_quality) do
    metadata = alert.detection_metadata || %{}
    status = to_string(alert.status || "new")
    quality = to_string(Map.get(evidence_quality, :quality) || "missing")
    claimable? = Map.get(evidence_quality, :claimable) == true
    missing = Map.get(evidence_quality, :missing) || []
    threat_score = normalize_score(alert.threat_score)

    fp_review? =
      truthy?(metadata["fp_review_required"] || metadata[:fp_review_required]) ||
        truthy?(metadata["fpReviewRequired"] || metadata[:fpReviewRequired])

    claim_strength =
      to_string(
        metadata["alert_claim_strength"] ||
          metadata[:alert_claim_strength] ||
          metadata["alertClaimStrength"] ||
          metadata[:alertClaimStrength] ||
          ""
      )

    has_response_plan? =
      not is_nil(alert.recommended_response) ||
        Enum.any?(recommended_actions(alert)) ||
        status in ["investigating", "triaged"]

    weak_evidence? = quality in ["missing", "synthetic"] or not claimable?
    explicit_fp_candidate? = fp_review? or claim_strength in ["triage_only", "weak"]

    {state, label, priority, next_action, reasons} =
      cond do
        status == "false_positive" ->
          {"false_positive_candidate", "False positive candidate", "review", "Confirm tuning or keep suppression evidence attached", ["marked false positive"]}

        explicit_fp_candidate? and weak_evidence? and threat_score < 50 ->
          {"false_positive_candidate", "False positive candidate", "review", "Review source telemetry before response", fp_reasons(fp_review?, claim_strength, quality, missing)}

        weak_evidence? and status in ["new", "open", "acknowledged", "triaged", "investigating"] ->
          {"needs_evidence", "Needs evidence", "high", "Collect missing telemetry before making a strong claim", evidence_reasons(quality, missing)}

        has_response_plan? and status in ["triaged", "investigating"] ->
          {"ready_for_response", "Ready for response", "high", "Review recommended response and execute containment if approved", ["triage started", "response path available"]}

        status in ["resolved", "closed"] ->
          {"triaged", "Triaged", "normal", "No queue action required", ["alert closed"]}

        status in ["triaged", "investigating"] ->
          {"triaged", "Triaged", "normal", "Continue investigation or response review", ["triage started"]}

        true ->
          {"needs_triage", "Needs triage", "normal", "Assign an analyst and validate evidence", ["new or unassigned alert"]}
      end

    %{
      state: state,
      label: label,
      priority: priority,
      queue: state,
      next_action: next_action,
      reasons: Enum.uniq(reasons),
      evidence_quality: quality,
      claimable: claimable?,
      terminal: status in ["resolved", "closed", "false_positive"]
    }
  end

  defp triage_contract_for(%Alert{} = alert) do
    case build_triage_contract(alert, :persisted_or_build) do
      {:ok, triage} -> triage
      {:error, fallback} -> fallback
    end
  end

  defp build_triage_contract(%Alert{} = alert, mode \\ :build) do
    triage =
      case mode do
        :persisted_or_build -> TriageAgent.contract_for(alert)
        _ -> TriageAgent.build(alert)
      end

    {:ok, triage}
  rescue
    error ->
      Logger.warn("alert triage agent degraded for alert=#{Map.get(alert, :id)} reason=#{Exception.message(error)}")
      {:error, degraded_triage_contract(alert, error)}
  end

  defp degraded_triage_contract(%Alert{} = alert, error) do
    %{
      "schema_version" => "alert-triage/v1",
      "status" => "degraded",
      "hypothesis" => "Triage agent contract could not be generated for this alert.",
      "evidence_strength" => %{
        "level" => "unknown",
        "label" => "Triage unavailable",
        "claimable" => false,
        "benchmark_eligible" => false
      },
      "gaps" => [
        %{
          "source" => "triage_agent",
          "field" => "contract_generation",
          "severity" => "high"
        }
      ],
      "false_positive_likelihood" => %{
        "score" => nil,
        "label" => "unknown",
        "basis" => ["triage_agent_degraded"]
      },
      "recommended_pivots" => [
        %{
          "action" => "inspect_alert_payload",
          "reason" => "Triage contract generation failed; inspect alert evidence, raw event and enrichment payload shape.",
          "priority" => "high"
        }
      ],
      "recommended_response" => "Do not make automated response decisions from this degraded triage contract.",
      "confidence" => 0.0,
      "generated_at" => DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601(),
      "error" => Exception.message(error),
      "alert_id" => alert.id
    }
  end

  defp normalize_score(nil), do: 0
  defp normalize_score(score) when is_number(score) and score <= 1, do: score * 100
  defp normalize_score(score) when is_number(score), do: score
  defp normalize_score(_score), do: 0

  defp truthy?(value) when value in [true, "true", "yes", "1", 1], do: true
  defp truthy?(_value), do: false

  defp fp_reasons(fp_review?, claim_strength, quality, missing) do
    []
    |> maybe_add(fp_review?, "fp review required")
    |> maybe_add(claim_strength != "", "claim strength #{claim_strength}")
    |> maybe_add(quality in ["missing", "synthetic"], "weak evidence quality")
    |> Kernel.++(Enum.take(missing, 3))
  end

  defp evidence_reasons(quality, missing) do
    ["evidence quality #{quality || "unknown"}"] ++ Enum.take(missing, 4)
  end

  defp maybe_add(list, true, value), do: list ++ [value]
  defp maybe_add(list, _condition, _value), do: list

  defp camelize_operational_triage(%{} = triage) do
    triage
    |> camelize_map_keys()
    |> Map.put("nextAction", Map.get(triage, :next_action))
    |> Map.put("evidenceQuality", Map.get(triage, :evidence_quality))
  end

  defp camelize_triage_agent(%{} = triage) do
    triage
    |> camelize_map_deep()
    |> Map.put("schemaVersion", Map.get(triage, "schema_version") || Map.get(triage, :schema_version))
    |> Map.put("evidenceStrength", camelize_map_deep(Map.get(triage, "evidence_strength") || Map.get(triage, :evidence_strength) || %{}))
    |> Map.put("falsePositiveLikelihood", camelize_map_deep(Map.get(triage, "false_positive_likelihood") || Map.get(triage, :false_positive_likelihood) || %{}))
    |> Map.put("recommendedPivots", camelize_map_deep(Map.get(triage, "recommended_pivots") || Map.get(triage, :recommended_pivots) || []))
    |> Map.put("recommendedResponse", Map.get(triage, "recommended_response") || Map.get(triage, :recommended_response))
    |> Map.put("generatedAt", Map.get(triage, "generated_at") || Map.get(triage, :generated_at))
  end

  defp camelize_triage_agent(_), do: %{}

  defp camelize_evidence_quality(%{} = evidence_quality) do
    %{
      quality: Map.get(evidence_quality, :quality),
      label: Map.get(evidence_quality, :label),
      claimable: Map.get(evidence_quality, :claimable),
      benchmarkEligible: Map.get(evidence_quality, :benchmark_eligible),
      summary: Map.get(evidence_quality, :summary),
      checks: camelize_map_keys(Map.get(evidence_quality, :checks) || %{}),
      missing: Map.get(evidence_quality, :missing),
      investigationContext:
        camelize_investigation_context(Map.get(evidence_quality, :investigation_context) || %{}),
      score: Map.get(evidence_quality, :score)
    }
  end

  defp camelize_investigation_context(%{} = context) do
    context
    |> camelize_map_keys()
    |> Map.put("fields", camelize_map_keys(Map.get(context, :fields) || %{}))
  end

  defp camelize_map_keys(%{} = map) do
    Map.new(map, fn {key, value} -> {camelize_key(key), value} end)
  end

  defp camelize_map_deep(%{} = map) do
    Map.new(map, fn {key, value} -> {camelize_key(key), camelize_map_deep(value)} end)
  end

  defp camelize_map_deep(values) when is_list(values), do: Enum.map(values, &camelize_map_deep/1)
  defp camelize_map_deep(value), do: value

  defp camelize_key(key) when is_atom(key), do: key |> Atom.to_string() |> camelize_key()
  defp camelize_key(key) when is_binary(key) do
    key
    |> String.split("_")
    |> case do
      [head | tail] -> head <> Enum.map_join(tail, "", &String.capitalize/1)
      [] -> ""
    end
  end
  defp camelize_key(key), do: key

  defp loaded_agent(%Alert{} = alert) do
    case Map.get(alert, :agent) do
      %Ecto.Association.NotLoaded{} -> nil
      nil -> nil
      agent -> agent
    end
  end

  defp serialize_agent_summary(nil), do: nil

  defp serialize_agent_summary(agent) do
    %{
      id: agent.id,
      hostname: agent.hostname,
      name: agent.hostname,
      status: Map.get(agent, :status)
    }
  end

  defp alert_desktop_commands(%Alert{agent_id: nil}, _command_ids), do: []

  defp alert_desktop_commands(%Alert{} = alert, command_ids) do
    AgentCommand
    |> where([c], c.agent_id == ^alert.agent_id)
    |> where(
      [c],
      c.id in ^command_ids or
        fragment("?->>'alert_id' = ?", c.command_params, ^alert.id) or
        fragment("?->'filters'->>'alert_id' = ?", c.command_params, ^alert.id)
    )
    |> order_by([c], asc: c.inserted_at)
    |> limit(100)
    |> Repo.all()
  end

  defp alert_mobile_commands(%Alert{} = alert, command_ids) do
    MDMCommand
    |> where([c], c.organization_id == ^alert.organization_id)
    |> where(
      [c],
      c.id in ^command_ids or
        fragment("?->>'alert_id' = ?", c.payload, ^alert.id) or
        fragment("?->'filters'->>'alert_id' = ?", c.payload, ^alert.id)
    )
    |> order_by([c], asc: c.inserted_at)
    |> limit(100)
    |> Repo.all()
  end

  defp investigation_command_ids(%Alert{} = alert) do
    alert
    |> investigation_command_entries()
    |> Enum.map(&command_id_from_map/1)
    |> Enum.filter(&is_binary/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
  end

  defp command_ids_by_runtime(%Alert{} = alert, runtimes) do
    alert
    |> investigation_command_entries()
    |> Enum.filter(fn entry ->
      runtime = Map.get(entry, "runtime") || Map.get(entry, :runtime)
      runtime in runtimes
    end)
    |> Enum.map(&command_id_from_map/1)
    |> Enum.filter(&is_binary/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
  end

  defp investigation_command_entries(%Alert{} = alert) do
    detection_investigation = map_or_empty(get_in(alert.detection_metadata || %{}, ["investigation_enrichment"]))
    enrichment_investigation = map_or_empty(get_in(alert.enrichment || %{}, ["auto_investigation"]))

    [detection_investigation, enrichment_investigation]
    |> Enum.flat_map(fn investigation ->
      queued =
        investigation
        |> Map.get("queued_commands", [])
        |> List.wrap()
        |> Enum.filter(&is_map/1)

      artifacts =
        investigation
        |> Map.get("artifact_requests", [])
        |> List.wrap()
        |> Enum.filter(&is_map/1)

      collection =
        case Map.get(investigation, "collection_command_id") do
          id when is_binary(id) -> [%{"command_id" => id, "runtime" => "desktop_agent"}]
          _ -> []
        end

      collection ++ queued ++ artifacts
    end)
  end

  defp map_or_empty(value) when is_map(value), do: value
  defp map_or_empty(_), do: %{}

  defp command_id_from_map(%{} = value) do
    Map.get(value, "command_id") || Map.get(value, :command_id) || Map.get(value, "id") || Map.get(value, :id)
  end

  defp command_id_from_map(_), do: nil

  defp serialize_agent_command(%AgentCommand{} = command) do
    command_params = redact_command_credentials(command.command_params || %{})

    %{
      id: command.id,
      runtime: "desktop_agent",
      agent_id: command.agent_id,
      command_type: command.command_type,
      commandType: command.command_type,
      command_params: command_params,
      commandParams: command_params,
      status: command.status,
      priority: command.priority,
      result: command.result || %{},
      error: command.error,
      sent_at: format_datetime(command.sent_at),
      sentAt: format_datetime(command.sent_at),
      acknowledged_at: format_datetime(command.acknowledged_at),
      acknowledgedAt: format_datetime(command.acknowledged_at),
      completed_at: format_datetime(command.completed_at),
      completedAt: format_datetime(command.completed_at),
      expires_at: format_datetime(command.expires_at),
      expiresAt: format_datetime(command.expires_at),
      dispatch_count: command.dispatch_count,
      dispatchCount: command.dispatch_count,
      last_dispatched_at: format_datetime(command.last_dispatched_at),
      lastDispatchedAt: format_datetime(command.last_dispatched_at),
      inserted_at: format_datetime(command.inserted_at),
      insertedAt: format_datetime(command.inserted_at),
      updated_at: format_datetime(command.updated_at),
      updatedAt: format_datetime(command.updated_at),
      rollback: command_rollback_summary(command.command_type, command.status)
    }
  end

  defp redact_command_credentials(params) when is_map(params) do
    params
    |> redact_nested_upload("upload")
    |> redact_nested_upload(:upload)
  end

  defp redact_command_credentials(_params), do: %{}

  defp redact_nested_upload(params, key) do
    case Map.fetch(params, key) do
      {:ok, upload} when is_map(upload) ->
        redacted =
          upload
          |> Map.delete("token")
          |> Map.delete(:token)
          |> Map.delete("authorization")
          |> Map.delete(:authorization)

        Map.put(params, key, redacted)

      _ ->
        params
    end
  end

  defp serialize_mdm_command(%MDMCommand{} = command) do
    %{
      id: command.id,
      runtime: "mobile_mdm",
      device_id: command.device_id,
      command_type: command.command_type,
      commandType: command.command_type,
      command_params: command.payload || %{},
      commandParams: command.payload || %{},
      status: command.status,
      priority: nil,
      result: command.result || %{},
      error: get_in(command.result || %{}, ["error"]),
      sent_at: format_datetime(command.sent_at),
      sentAt: format_datetime(command.sent_at),
      acknowledged_at: nil,
      acknowledgedAt: nil,
      completed_at: format_datetime(command.completed_at),
      completedAt: format_datetime(command.completed_at),
      expires_at: nil,
      expiresAt: nil,
      dispatch_count: nil,
      dispatchCount: nil,
      last_dispatched_at: nil,
      lastDispatchedAt: nil,
      inserted_at: format_datetime(command.inserted_at),
      insertedAt: format_datetime(command.inserted_at),
      updated_at: format_datetime(command.updated_at),
      updatedAt: format_datetime(command.updated_at),
      rollback: %{
        available: false,
        action_type: nil,
        actionType: nil,
        reason: "Mobile command rollback is not exposed for this investigation command."
      }
    }
  end

  defp command_rollback_summary(command_type, status) do
    reversible = command_type in ["isolate_network", "block_ip", "block_domain", "quarantine_file"]

    %{
      available: reversible and status in ["completed", "sent", "acknowledged", "pending"],
      action_type: command_rollback_action_type(command_type),
      actionType: command_rollback_action_type(command_type),
      reason:
        cond do
          not reversible -> "No automated rollback is defined for this command type."
          status == "completed" -> "Command completed; rollback can be requested if the target still applies."
          status in ["pending", "sent", "acknowledged"] -> "Command is still active; rollback should wait for final execution status."
          status == "failed" -> "Original command failed; rollback is usually not required."
          true -> "Rollback depends on final command status."
        end
    }
  end

  defp command_rollback_action_type("isolate_network"), do: "unisolate_network"
  defp command_rollback_action_type("block_ip"), do: "unblock_ip"
  defp command_rollback_action_type("block_domain"), do: "unblock_domain"
  defp command_rollback_action_type("quarantine_file"), do: "restore_quarantined_file"
  defp command_rollback_action_type(_), do: nil

  defp alert_rule_name(%Alert{} = alert) do
    metadata = alert.detection_metadata || %{}
    evidence = alert.evidence || %{}

    metadata["rule_name"] || metadata[:rule_name] || metadata["ruleName"] ||
      get_in(evidence, ["detection", "rule_name"]) ||
      get_in(evidence, [:detection, :rule_name]) ||
      alert.title
  end

  defp recommended_actions(%Alert{} = alert) do
    case alert.recommended_response do
      value when is_binary(value) and value != "" -> [value]
      _ -> []
    end
  end

  defp proof_details(%Alert{} = alert) do
    manifest = proof_manifest(alert)
    tx_id = alert.blockchain_tx_id
    bounty_amount = alert.bounty_amount_lamports

    %{
      eligible: alert.severity in ["medium", "high", "critical"],
      attested: not is_nil(tx_id),
      tx_id: tx_id,
      solscan_url: tx_id && TamanduaServer.Solana.Client.solscan_url(tx_id),
      attested_at: format_datetime(alert.blockchain_attested_at),
      incident_hash: alert.incident_hash || manifest_value(manifest, :incident_hash),
      manifest_hash:
        alert.manifest_hash ||
          (Attestation.compute_manifest_hash(manifest) |> Base.encode16(case: :lower)),
      tlp: alert.attestation_tlp || manifest_value(manifest, :tlp),
      ioc_count: alert.attestation_ioc_count || manifest_value(manifest, :ioc_count),
      ioc_types: non_empty_list(alert.attestation_ioc_types) || manifest_value(manifest, :ioc_types) || [],
      redacted_ioc_count:
        alert.attestation_redacted_ioc_count || manifest_value(manifest, :redacted_ioc_count),
      confidence: alert.attestation_confidence || manifest_value(manifest, :confidence),
      threat_class: alert.attestation_threat_class || manifest_value(manifest, :threat_class),
      malware_family: alert.attestation_malware_family || manifest_value(manifest, :malware_family),
      public_manifest: manifest,
      bounty:
        if alert.bounty_tx_id do
          %{
            tx_id: alert.bounty_tx_id,
            amount_lamports: bounty_amount,
            amount_sol: (bounty_amount || 0) / 1_000_000_000,
            paid_at: format_datetime(alert.bounty_paid_at)
          }
        else
          nil
        end
    }
  end

  defp proof_manifest(%Alert{} = alert) do
    manifest = Map.get(alert, :public_manifest)

    if is_map(manifest) and map_size(manifest) > 0 do
      manifest
    else
      Attestation.build_public_manifest(alert)
    end
  end

  defp manifest_value(manifest, key), do: Map.get(manifest, key) || Map.get(manifest, to_string(key))

  defp non_empty_list(value) when is_list(value) and value != [], do: value
  defp non_empty_list(_value), do: nil

  defp alert_source(%Alert{} = alert) do
    explicit_source =
      [
        get_in(alert.detection_metadata || %{}, ["source"]),
        get_in(alert.detection_metadata || %{}, ["detection_source"]),
        get_in(alert.raw_event || %{}, ["source"]),
        get_in(alert.raw_event || %{}, ["alert_source"]),
        get_in(alert.raw_event || %{}, ["payload", "detection_source"]),
        get_in(alert.raw_event || %{}, ["payload", "source"]),
        get_in(alert.raw_event || %{}, ["metadata", "detection_source"]),
        get_in(alert.raw_event || %{}, ["metadata", "source"]),
        get_in(alert.evidence || %{}, ["source"]),
        get_in(alert.evidence || %{}, ["detection_source"]),
        get_in(alert.evidence || %{}, ["alert_source"])
      ]
      |> Enum.find(&(is_binary(&1) and String.trim(&1) != ""))

    explicit_source
    |> normalize_alert_source(inferred_alert_source(alert))
  end

  defp normalize_alert_source(source, inferred_source) when is_binary(source) do
    normalized =
      source
      |> String.trim()
      |> String.downcase()
      |> String.replace("-", "_")

    cond do
      normalized == "" -> normalize_alert_source(inferred_source, nil)
      String.contains?(normalized, "sigma") -> "sigma"
      String.contains?(normalized, "yara") -> "yara"
      source_matches_any?(normalized, ["mobile", "android", "ios", "app_guard", "mdm", "tamandua_mobile"]) -> "mobile"
      source_matches_any?(normalized, ["ndr", "network", "dns", "flow", "packet", "zeek", "suricata", "firewall", "doh"]) -> "ndr"
      source_matches_any?(normalized, ["ml", "onnx", "model"]) -> "ml"
      source_matches_any?(normalized, ["ai_security", "ai_runtime", "llm", "prompt", "rag"]) -> "ai_security"
      source_matches_any?(normalized, ["ioc", "threat_intel", "indicator"]) -> "ioc"
      source_matches_any?(normalized, ["behavior", "baseline", "anomaly", "rule_match", "detection_engine"]) -> "behavioral"
      true -> normalized
    end
  end

  defp normalize_alert_source(_source, inferred_source) when is_binary(inferred_source),
    do: normalize_alert_source(inferred_source, nil)

  defp normalize_alert_source(_source, _inferred_source), do: "behavioral"

  defp source_matches_any?(source, aliases), do: Enum.any?(aliases, &String.contains?(source, &1))

  defp validation_alert?(%Alert{} = alert), do: not is_nil(validation_kind(alert))

  defp validation_kind(%Alert{} = alert) do
    if explicit_validation_alert?(alert) do
      "validation"
    else
      inferred_validation_kind(alert)
    end
  end

  defp inferred_validation_kind(%Alert{} = alert) do
    text =
      [
        alert.detection_metadata,
        alert.raw_event,
        alert.evidence,
        alert.source_event_id,
        alert.title
      ]
      |> Enum.map_join(" ", &validation_text/1)
      |> String.downcase()

    cond do
      String.contains?(text, "parity") -> "parity"
      String.contains?(text, "validation_run_id") or String.contains?(text, "validation_event") -> "validation"
      String.contains?(text, "synthetic") or String.contains?(text, "test_event") -> "synthetic"
      true -> nil
    end
  end

  defp explicit_validation_alert?(%Alert{} = alert) do
    [alert.detection_metadata, alert.raw_event, alert.evidence]
    |> Enum.any?(fn metadata ->
      metadata
      |> validation_value(["validation_alert", "validationAlert"])
      |> explicit_validation_value?()
    end)
  end

  defp validation_value(metadata, keys) when is_map(metadata) do
    Enum.find_value(keys, &Map.get(metadata, &1))
  end

  defp validation_value(_metadata, _keys), do: nil

  defp explicit_validation_value?(true), do: true
  defp explicit_validation_value?(value) when is_binary(value) do
    normalized =
      value
      |> String.trim()
      |> String.downcase()

    normalized in ["true", "1", "yes"]
  end
  defp explicit_validation_value?(_value), do: false

  defp validation_text(value) when is_binary(value), do: value
  defp validation_text(value) when is_map(value), do: Jason.encode!(value)
  defp validation_text(value) when is_list(value), do: Jason.encode!(value)
  defp validation_text(nil), do: ""
  defp validation_text(value), do: to_string(value)

  defp inferred_alert_source(%Alert{} = alert) do
    [
      alert.detection_metadata,
      alert.raw_event,
      get_in(alert.raw_event || %{}, ["payload"]),
      alert.evidence
    ]
    |> Enum.find_value(&inferred_map_source/1)
  end

  defp inferred_map_source(metadata) when is_map(metadata) do
    detection_type = metadata["detection_type"] || metadata[:detection_type]
    rule_type = metadata["rule_type"] || metadata[:rule_type]
    rule_name = metadata["rule_name"] || metadata[:rule_name]

    cond do
      ml_source_value?(detection_type) -> "ml"
      ml_source_value?(rule_type) -> "ml"
      is_binary(rule_name) and String.starts_with?(String.upcase(rule_name), "ML_") -> "ml"
      true -> nil
    end
  end

  defp inferred_map_source(_metadata), do: nil

  defp ml_source_value?(value) when is_binary(value), do: String.downcase(value) == "ml"
  defp ml_source_value?(_value), do: false

  defp load_incident_events(%Alert{} = alert) do
    ids =
      [alert.source_event_id | (alert.event_ids || [])]
      |> Enum.reject(&is_nil/1)
      |> Enum.map(&to_string/1)
      |> Enum.uniq()

    if ids == [] do
      []
    else
      Event
      |> where([e], e.id in ^ids)
      |> where([e], e.agent_id == ^alert.agent_id)
      |> order_by([e], asc: e.timestamp)
      |> Repo.all()
    end
  end

  defp incident_timeline(%Alert{} = alert, events) do
    event_timeline = Enum.map(events, &serialize_incident_event/1)

    if event_timeline == [] do
      raw_event_timeline(alert)
    else
      event_timeline
    end
  end

  defp raw_event_timeline(%Alert{} = alert) do
    raw_event = alert.raw_event || %{}
    nested_payload = raw_event["payload"] || raw_event[:payload] || %{}
    payload = if is_map(nested_payload) and nested_payload != %{}, do: nested_payload, else: raw_event

    if raw_event == %{} and payload == %{} do
      []
    else
      [
        %{
          id:
            raw_event["mobile_event_id"] || raw_event[:mobile_event_id] ||
              payload["event_id"] || payload[:event_id] || "alert-#{alert.id}-raw-event",
          agent_id: alert.agent_id,
          event_type:
            raw_event["event_type"] || raw_event[:event_type] ||
              payload["event_type"] || payload[:event_type] || "alert_event",
          severity: payload["severity"] || payload[:severity] || alert.severity,
          timestamp:
            payload["timestamp"] || payload[:timestamp] ||
              format_datetime(alert.inserted_at),
          title: alert.title,
          summary: raw_event_summary(alert, payload),
          payload: payload,
          enrichment: %{
            source: alert_source(alert),
            synthetic: true,
            reason: "No persisted source_event_id/event_ids were linked to this alert"
          }
        }
      ]
    end
  end

  defp raw_event_summary(%Alert{} = alert, payload) do
    risk = payload["risk"] || payload[:risk] || %{}
    app = payload["app"] || payload[:app] || %{}
    device = payload["device"] || payload[:device] || %{}

    app_name = app["display_name"] || app[:display_name] || app["package_or_bundle_id"] || app[:package_or_bundle_id]
    device_name = device["device_id"] || device[:device_id] || device["model"] || device[:model]
    decision = risk["decision"] || risk[:decision]
    score = risk["score"] || risk[:score]

    [
      alert.description || alert.title,
      app_name && "App: #{app_name}",
      device_name && "Device: #{device_name}",
      decision && "Decision: #{decision}",
      score && "Risk score: #{score}"
    ]
    |> Enum.reject(&is_nil/1)
    |> Enum.join(" | ")
  end

  defp serialize_incident_event(%Event{} = event) do
    %{
      id: event.id,
      agent_id: event.agent_id,
      event_type: event.event_type,
      severity: event.severity,
      timestamp: format_datetime(event.timestamp),
      payload: event.payload || %{},
      enrichment: event.enrichment || %{}
    }
  end

  defp serialize_exclusion_rule(rule) do
    %{
      id: rule.id,
      name: rule.name,
      description: rule.description,
      enabled: rule.enabled,
      rule_type: rule.rule_type,
      criteria: rule.criteria,
      hash_patterns: rule.hash_patterns,
      path_patterns: rule.path_patterns,
      cmdline_patterns: rule.cmdline_patterns,
      ip_patterns: rule.ip_patterns,
      domain_patterns: rule.domain_patterns,
      rule_name_patterns: rule.rule_name_patterns,
      source_agent_ids: rule.source_agent_ids,
      source_hostnames: rule.source_hostnames,
      time_based: rule.time_based,
      active_start: rule.active_start && Time.to_iso8601(rule.active_start),
      active_end: rule.active_end && Time.to_iso8601(rule.active_end),
      active_days: rule.active_days,
      expires_at: rule.expires_at && DateTime.to_iso8601(rule.expires_at),
      adjust_severity: rule.adjust_severity,
      match_count: rule.match_count,
      last_matched_at: rule.last_matched_at && DateTime.to_iso8601(rule.last_matched_at),
      created_at: format_datetime(rule.inserted_at),
      updated_at: format_datetime(rule.updated_at)
    }
  end

  defp serialize_suppression_rule(rule) do
    %{
      id: rule.id,
      name: rule.name,
      description: rule.description,
      enabled: rule.enabled,
      rule_name_pattern: rule.rule_name_pattern,
      agent_id: rule.agent_id,
      process_name_pattern: rule.process_name_pattern,
      parent_process_pattern: rule.parent_process_pattern,
      file_path_pattern: rule.file_path_pattern,
      title_pattern: rule.title_pattern,
      severity: rule.severity,
      mitre_techniques: rule.mitre_techniques,
      criteria: rule.criteria,
      expires_at: rule.expires_at && DateTime.to_iso8601(rule.expires_at),
      match_count: rule.match_count,
      last_matched_at: rule.last_matched_at && DateTime.to_iso8601(rule.last_matched_at),
      max_matches: rule.max_matches,
      action: rule.action,
      reduce_to_severity: rule.reduce_to_severity,
      source_alert_id: rule.source_alert_id,
      created_by_id: rule.created_by_id,
      organization_id: rule.organization_id,
      created_at: format_datetime(rule.inserted_at),
      updated_at: format_datetime(rule.updated_at)
    }
  end

  defp serialize_feedback_log(log) do
    %{
      id: log.id,
      alert_id: log.alert_id,
      user_id: log.user_id,
      previous_verdict: log.previous_verdict,
      new_verdict: log.new_verdict,
      notes: log.notes,
      suppression_rule_created: log.suppression_rule_created,
      baseline_updated: log.baseline_updated,
      metadata: log.metadata,
      created_at: format_datetime(log.inserted_at)
    }
  end

  # ===========================================================================
  # Solana Attestation (Proof of Incident)
  # ===========================================================================

  @doc """
  Manually trigger Solana attestation for an alert.

  Creates a tamper-evident on-chain proof of the incident.
  Only works for medium, high, or critical severity alerts.
  """
  def attest(conn, %{"id" => id}) do
    alert = authorize_alert!(conn, id)

    case Alerts.attest_alert(alert) do
      {:ok, job} ->
        json(conn, %{
          status: "queued",
          message: "Attestation job enqueued",
          job_id: job.id,
          alert_id: alert.id
        })

      {:error, :already_attested} ->
        json(conn, %{
          status: "already_attested",
          message: "Alert already has an on-chain attestation",
          tx_id: alert.blockchain_tx_id,
          solscan_url: TamanduaServer.Solana.Client.solscan_url(alert.blockchain_tx_id),
          attested_at: format_datetime(alert.blockchain_attested_at)
        })

      {:error, :severity_not_eligible} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{
          error: "severity_not_eligible",
          message: "Only medium, high, and critical severity alerts can be attested",
          severity: alert.severity
        })

      {:error, :solana_disabled} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{
          error: "solana_disabled",
          message: "Solana integration is not enabled"
        })

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{
          error: "attestation_failed",
          message: "Failed to enqueue attestation",
          details: inspect(reason)
        })
    end
  end

  @doc """
  Get attestation details for an alert.

  Returns the Solana transaction details if the alert has been attested.
  """
  def get_attestation(conn, %{"id" => id}) do
    alert = authorize_alert!(conn, id)

    if alert.blockchain_tx_id do
      json(conn, %{
        data: Map.put(proof_details(alert), :alert_id, alert.id)
      })
    else
      json(conn, %{
        data:
          alert
          |> proof_details()
          |> Map.put(:alert_id, alert.id)
          |> Map.put(:severity, alert.severity)
      })
    end
  end

  defp format_datetime(nil), do: nil
  defp format_datetime(%NaiveDateTime{} = dt), do: NaiveDateTime.to_iso8601(dt)
  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)

  defp atomize_keys(map) when is_map(map) do
    Map.new(map, fn {k, v} ->
      key = if is_binary(k), do: String.to_existing_atom(k), else: k
      {key, v}
    end)
  rescue
    ArgumentError -> map
  end

  defp format_changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end

  defp request_metadata(conn) do
    [
      ip_address: get_client_ip(conn),
      user_agent: get_user_agent(conn)
    ]
  end

  defp get_client_ip(conn) do
    case Plug.Conn.get_req_header(conn, "x-forwarded-for") do
      [forwarded | _] -> forwarded |> String.split(",") |> List.first() |> String.trim()
      [] -> conn.remote_ip |> :inet.ntoa() |> to_string()
    end
  end

  defp get_user_agent(conn) do
    case Plug.Conn.get_req_header(conn, "user-agent") do
      [ua | _] -> ua
      [] -> nil
    end
  end
end
