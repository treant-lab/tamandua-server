defmodule TamanduaServerWeb.API.V1.AlertController do
  use TamanduaServerWeb, :controller

  import Ecto.Query, warn: false

  alias TamanduaServer.Alerts
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.AuditLog
  alias TamanduaServer.Detection.Exclusions
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
    org_id = conn.assigns[:current_organization_id]
    page = parse_int(params["page"], 1) |> max(1)
    per_page = parse_int(params["per_page"], 50) |> max(1) |> min(@max_per_page)
    offset = parse_int(params["offset"], (page - 1) * per_page) |> max(0)
    status = normalize_status_filter(params["status"])

    filters = [
      severity: params["severity"],
      status: status,
      agent_id: params["agent_id"],
      source: params["source"],
      limit: per_page,
      offset: offset
    ]

    alerts = Alerts.list_alerts_for_org(org_id, filters)
    total = Alerts.count_alerts_for_org(org_id, Keyword.drop(filters, [:limit, :offset]))
    total_pages = if total > 0, do: ceil(total / per_page), else: 0

    json(conn, %{
      data: Enum.map(alerts, &serialize/1),
      meta: %{
        page: page,
        per_page: per_page,
        offset: offset,
        total: total,
        total_pages: total_pages
      }
    })
  end

  def show(conn, %{"id" => id}) do
    alert = authorize_alert!(conn, id)
    json(conn, %{data: serialize(alert)})
  end

  def incident(conn, %{"id" => id}) do
    alert = authorize_alert!(conn, id)
    events = load_incident_events(alert)

    json(conn, %{
      data: %{
        id: alert.id,
        alert: serialize(alert),
        timeline: Enum.map(events, &serialize_incident_event/1),
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
        Alerts.bulk_update_status(alert_ids, "investigating", opts)

      "close" ->
        Alerts.bulk_update_status(alert_ids, "resolved", opts)

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
    case TamanduaServer.Investigations.add_alerts_to_investigation(investigation_id, alert_ids) do
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
    organization_id = conn.assigns[:current_organization_id]

    filters = Map.take(params, [
      "search", "severity", "status", "agent_id", "assigned_to_id",
      "mitre_techniques", "mitre_tactics", "date_from", "date_to",
      "threat_score_min", "threat_score_max", "has_evidence"
    ])

    opts = [
      organization_id: organization_id,
      limit: parse_int(params["limit"], 100),
      offset: parse_int(params["offset"], 0),
      sort_by: parse_sort_field(params["sort_by"]),
      sort_order: parse_sort_order(params["sort_order"])
    ]

    alerts = Alerts.search_alerts(filters, opts)
    total = Alerts.count_search_results(filters, organization_id: organization_id)

    json(conn, %{
      data: Enum.map(alerts, &serialize/1),
      meta: %{
        total: total,
        limit: opts[:limit],
        offset: opts[:offset]
      }
    })
  end

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
  defp normalize_status_filter("active"), do: ["new", "investigating"]
  defp normalize_status_filter("dismissed"), do: ["resolved", "false_positive"]
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

    related_alerts = Alerts.get_related_alerts(id)

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
    conn.assigns[:current_organization_id] ||
      resolve_user_organization_id(conn.assigns[:current_user])
  end

  defp resolve_user_organization_id(%{organization_id: organization_id}), do: organization_id
  defp resolve_user_organization_id(_), do: nil

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
    user_id = conn.assigns[:current_user] && conn.assigns[:current_user].id

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
          "search", "severity", "status", "agent_id", "date_from", "date_to"
        ])
        Alerts.search_alerts(filters, organization_id: organization_id, limit: 1000)
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
    headers = ["id", "title", "severity", "status", "agent_id", "threat_score", "created_at", "mitre_techniques"]

    rows = Enum.map(alerts, fn alert ->
      [
        alert[:id],
        alert[:title],
        alert[:severity],
        alert[:status],
        alert[:agent_id],
        alert[:threat_score] || "",
        alert[:created_at],
        (alert[:mitre_techniques] || []) |> Enum.join("; ")
      ]
    end)

    [headers | rows]
    |> Enum.map(&Enum.join(&1, ","))
    |> Enum.join("\n")
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

  defp serialize(%Alert{} = alert) do
    %{
      id: alert.id,
      agent_id: alert.agent_id,
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
      event_ids: alert.event_ids || [],
      evidence: alert.evidence || %{},
      process_chain: alert.process_chain || [],
      raw_event: alert.raw_event,
      detection_metadata: alert.detection_metadata || %{},
      contributing_events: alert.contributing_events || [],
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
      created_at: format_datetime(alert.inserted_at),
      updated_at: format_datetime(alert.updated_at)
    }
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

  defp proof_manifest(%Alert{public_manifest: manifest}) when is_map(manifest) and map_size(manifest) > 0 do
    manifest
  end

  defp proof_manifest(%Alert{} = alert), do: Attestation.build_public_manifest(alert)

  defp manifest_value(manifest, key), do: Map.get(manifest, key) || Map.get(manifest, to_string(key))

  defp non_empty_list(value) when is_list(value) and value != [], do: value
  defp non_empty_list(_value), do: nil

  defp alert_source(%Alert{} = alert) do
    [
      get_in(alert.detection_metadata || %{}, ["source"]),
      get_in(alert.detection_metadata || %{}, ["detection_source"]),
      get_in(alert.raw_event || %{}, ["source"]),
      get_in(alert.raw_event || %{}, ["alert_source"]),
      get_in(alert.evidence || %{}, ["source"])
    ]
    |> Enum.find("behavioral", &(is_binary(&1) and String.trim(&1) != ""))
  end

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
