defmodule TamanduaServer.Alerts.TimelineBuilder do
  @moduledoc """
  Builds comprehensive timeline data for alert investigation visualization.

  Aggregates events from multiple sources:
  - Alert lifecycle events (created, updated, status changed)
  - Response actions (process killed, file quarantined, agent isolated)
  - Analyst actions (comments, assignments, verdict changes)
  - System events (enrichment, ML analysis, correlation)
  - External events (SIEM exports, ticket creation)

  Timeline events are returned in chronological order with full metadata
  for rendering in vis.js Timeline component.
  """

  require Logger

  alias TamanduaServer.Alerts.{Alert, AlertActivity, Comment, CommentManager}
  alias TamanduaServer.Alerts.Timestamp
  alias TamanduaServer.Response
  alias TamanduaServer.Repo

  import Ecto.Query

  @doc """
  Build a complete timeline for an alert.

  Returns a list of timeline events sorted by timestamp (oldest first).

  ## Options

    * `:include_comments` - Include comment events (default: true)
    * `:include_responses` - Include response action events (default: true)
    * `:include_system` - Include system events (default: true)
    * `:include_external` - Include external events (default: true)
    * `:limit` - Maximum number of events to return (default: 1000)

  ## Return Format

  Each event is a map with:

    * `:id` - Unique event identifier
    * `:type` - Event type category (detection, response, analyst, system, external)
    * `:subtype` - Specific event subtype
    * `:title` - Short event title
    * `:content` - Event description/details
    * `:timestamp` - Event timestamp (DateTime)
    * `:user_id` - Associated user ID (if any)
    * `:user_name` - Associated user name (if any)
    * `:metadata` - Additional event-specific metadata
    * `:severity` - Event severity level (critical, high, medium, low, info)
    * `:group` - Event grouping category for timeline rendering
    * `:className` - CSS class name for styling
    * `:style` - Inline CSS style overrides
  """
  @spec build_timeline(Alert.t(), keyword()) :: [map()]
  def build_timeline(%Alert{} = alert, opts \\ []) do
    include_comments = Keyword.get(opts, :include_comments, true)
    include_responses = Keyword.get(opts, :include_responses, true)
    include_system = Keyword.get(opts, :include_system, true)
    include_external = Keyword.get(opts, :include_external, true)
    limit = Keyword.get(opts, :limit, 1000)

    events = []

    # Add alert creation event
    events = [build_alert_created_event(alert) | events]

    # Add alert lifecycle events
    events = events ++ build_lifecycle_events(alert)

    # Add response action events
    events =
      if include_responses do
        events ++ build_response_events(alert)
      else
        events
      end

    # Add comment events
    events =
      if include_comments do
        events ++ build_comment_events(alert)
      else
        events
      end

    # Add system events
    events =
      if include_system do
        events ++ build_system_events(alert)
      else
        events
      end

    # Add external events
    events =
      if include_external do
        events ++ build_external_events(alert)
      else
        events
      end

    # Sort by timestamp and limit
    events
    |> Enum.map(&normalize_timeline_event/1)
    |> Enum.sort_by(&Timestamp.sort_key(&1.timestamp))
    |> Enum.take(limit)
  end

  @doc """
  Export timeline data to JSON format for vis.js.

  Returns a map with:
  - `items` - Array of timeline items
  - `groups` - Array of timeline groups
  - `options` - Recommended vis.js options
  """
  @spec export_timeline_json(Alert.t(), keyword()) :: map()
  def export_timeline_json(%Alert{} = alert, opts \\ []) do
    events = build_timeline(alert, opts)

    items =
      Enum.map(events, fn event ->
        %{
          id: event.id,
          group: event.group,
          content: event.title,
          start: Timestamp.iso8601(event.timestamp),
          className: event.className,
          title: event.content,
          type: "point",
          metadata: event.metadata
        }
      end)

    groups = [
      %{id: "detection", content: "Detection Events", className: "timeline-group-detection"},
      %{id: "response", content: "Response Actions", className: "timeline-group-response"},
      %{id: "analyst", content: "Analyst Actions", className: "timeline-group-analyst"},
      %{id: "system", content: "System Events", className: "timeline-group-system"},
      %{id: "external", content: "External Events", className: "timeline-group-external"}
    ]

    options = %{
      stack: false,
      showCurrentTime: true,
      zoomMin: 1000 * 60,
      zoomMax: 1000 * 60 * 60 * 24 * 30,
      editable: false,
      margin: %{
        item: 10,
        axis: 5
      },
      orientation: "both"
    }

    %{
      items: items,
      groups: groups,
      options: options
    }
  end

  # ---------------------------------------------------------------------------
  # Private - Event Builders
  # ---------------------------------------------------------------------------

  defp build_alert_created_event(alert) do
    %{
      id: "alert_created_#{alert.id}",
      type: "detection",
      subtype: "alert_created",
      title: "Alert Created",
      content: "Alert #{alert.title} was created with severity #{alert.severity}",
      timestamp: alert.inserted_at,
      user_id: nil,
      user_name: "System",
      metadata: %{
        alert_id: alert.id,
        agent_id: alert.agent_id,
        severity: alert.severity,
        threat_score: alert.threat_score,
        mitre_tactics: alert.mitre_tactics || [],
        mitre_techniques: alert.mitre_techniques || [],
        source_event_id: alert.source_event_id,
        evidence_summary: evidence_summary(alert.evidence || %{}),
        detection_metadata_summary: metadata_summary(alert.detection_metadata || %{})
      },
      severity: alert.severity,
      group: "detection",
      className: "timeline-event-detection timeline-event-created",
      style: "background-color: #8b5cf6;"
    }
  end

  defp build_lifecycle_events(alert) do
    events = []

    # Status changes
    if alert.status != "new" do
      events = [
        %{
          id: "alert_status_#{alert.id}",
          type: "analyst",
          subtype: "status_changed",
          title: "Status Changed",
          content: "Alert status changed to #{format_status(alert.status)}",
          timestamp: alert.state_changed_at || alert.updated_at,
          user_id: alert.state_changed_by_id,
          user_name: get_user_name(alert, :state_changed_by),
          metadata: %{
            status: alert.status,
            previous_status: alert.previous_state
          },
          severity: "info",
          group: "analyst",
          className: "timeline-event-analyst timeline-event-status",
          style: "background-color: #3b82f6;"
        }
        | events
      ]
    end

    # Assignment
    if alert.assigned_to_id do
      events = [
        %{
          id: "alert_assigned_#{alert.id}",
          type: "analyst",
          subtype: "assignment_changed",
          title: "Alert Assigned",
          content: "Assigned to #{get_user_name(alert, :assigned_to)}",
          timestamp: alert.assigned_at || alert.updated_at,
          user_id: alert.assigned_by_id,
          user_name: get_user_name(alert, :assigned_by),
          metadata: %{
            assigned_to_id: alert.assigned_to_id,
            assigned_by_id: alert.assigned_by_id,
            notes: alert.assignment_notes
          },
          severity: "info",
          group: "analyst",
          className: "timeline-event-analyst timeline-event-assignment",
          style: "background-color: #3b82f6;"
        }
        | events
      ]
    end

    # Acknowledgment
    if alert.acknowledged_at do
      events = [
        %{
          id: "alert_acknowledged_#{alert.id}",
          type: "analyst",
          subtype: "acknowledged",
          title: "Alert Acknowledged",
          content: "Alert acknowledged by #{get_user_name(alert, :acknowledged_by)}",
          timestamp: alert.acknowledged_at,
          user_id: alert.acknowledged_by_id,
          user_name: get_user_name(alert, :acknowledged_by),
          metadata: %{
            sla_breached: alert.sla_acknowledge_breached
          },
          severity: if(alert.sla_acknowledge_breached, do: "high", else: "info"),
          group: "analyst",
          className: "timeline-event-analyst timeline-event-acknowledged",
          style: "background-color: #10b981;"
        }
        | events
      ]
    end

    # Escalation
    if alert.escalated_at do
      events = [
        %{
          id: "alert_escalated_#{alert.id}",
          type: "analyst",
          subtype: "escalated",
          title: "Alert Escalated",
          content:
            "Escalated to level #{alert.escalation_level}: #{alert.escalation_reason || "No reason provided"}",
          timestamp: alert.escalated_at,
          user_id: alert.escalated_to_id,
          user_name: get_user_name(alert, :escalated_to),
          metadata: %{
            escalation_level: alert.escalation_level,
            escalation_reason: alert.escalation_reason
          },
          severity: "high",
          group: "analyst",
          className: "timeline-event-analyst timeline-event-escalated",
          style: "background-color: #f59e0b;"
        }
        | events
      ]
    end

    # Verdict
    if alert.verdict && alert.verdict != "unconfirmed" do
      events = [
        %{
          id: "alert_verdict_#{alert.id}",
          type: "analyst",
          subtype: "verdict_changed",
          title: "Verdict: #{format_verdict(alert.verdict)}",
          content: "Analyst verdict: #{format_verdict(alert.verdict)} - #{alert.verdict_notes || "No notes"}",
          timestamp: alert.verdict_at || alert.updated_at,
          user_id: alert.verdict_by_id,
          user_name: get_user_name(alert, :verdict_by),
          metadata: %{
            verdict: alert.verdict,
            notes: alert.verdict_notes
          },
          severity: verdict_severity(alert.verdict),
          group: "analyst",
          className: "timeline-event-analyst timeline-event-verdict",
          style: "background-color: #{verdict_color(alert.verdict)};"
        }
        | events
      ]
    end

    # Severity adjustment
    if alert.severity_adjusted && alert.severity_adjusted_at do
      events = [
        %{
          id: "alert_severity_adjusted_#{alert.id}",
          type: "analyst",
          subtype: "severity_adjusted",
          title: "Severity Adjusted",
          content: "Severity changed from #{alert.original_severity} to #{alert.severity}",
          timestamp: alert.severity_adjusted_at,
          user_id: alert.severity_adjusted_by_id,
          user_name: get_user_name(alert, :severity_adjusted_by),
          metadata: %{
            original_severity: alert.original_severity,
            new_severity: alert.severity
          },
          severity: alert.severity,
          group: "analyst",
          className: "timeline-event-analyst timeline-event-severity",
          style: "background-color: #8b5cf6;"
        }
        | events
      ]
    end

    # Resolution
    if alert.resolved_at do
      events = [
        %{
          id: "alert_resolved_#{alert.id}",
          type: "analyst",
          subtype: "resolved",
          title: "Alert Resolved",
          content: "Alert resolved: #{alert.resolution_notes || "No notes"}",
          timestamp: alert.resolved_at,
          user_id: alert.state_changed_by_id,
          user_name: get_user_name(alert, :state_changed_by),
          metadata: %{
            resolution_notes: alert.resolution_notes,
            sla_breached: alert.sla_resolve_breached
          },
          severity: if(alert.sla_resolve_breached, do: "high", else: "info"),
          group: "analyst",
          className: "timeline-event-analyst timeline-event-resolved",
          style: "background-color: #10b981;"
        }
        | events
      ]
    end

    events
  end

  defp build_response_events(alert) do
    # Fetch response actions from database
    actions =
      Response.Action
      |> where([a], a.alert_id == ^alert.id)
      |> order_by([a], asc: a.executed_at)
      |> Repo.all()

    Enum.map(actions, fn action ->
      %{
        id: "response_#{action.id}",
        type: "response",
        subtype: action.action_type,
        title: format_action_type(action.action_type),
        content: build_action_content(action),
        timestamp: action.executed_at || action.inserted_at,
        user_id: nil,
        user_name: if(action.status == "success", do: "Automated", else: "System"),
        metadata: %{
          action_id: action.id,
          action_type: action.action_type,
          parameters: action.parameters,
          status: action.status,
          result: action.result,
          error_message: action.error_message
        },
        severity: action_severity(action.action_type, action.status),
        group: "response",
        className: "timeline-event-response timeline-event-#{action.status}",
        style: "background-color: #{action_color(action.status)};"
      }
    end)
  end

  defp build_comment_events(alert) do
    comments = CommentManager.list_comments(alert, sort: :oldest_first)

    Enum.flat_map(comments, fn comment ->
      events = [
        %{
          id: "comment_#{comment.id}",
          type: "analyst",
          subtype: "comment_added",
          title: "Comment Added",
          content: String.slice(comment.content, 0..100) <> if(String.length(comment.content) > 100, do: "...", else: ""),
          timestamp: comment.inserted_at,
          user_id: comment.user_id,
          user_name: get_comment_user_name(comment),
          metadata: %{
            comment_id: comment.id,
            has_attachments: !Enum.empty?(comment.attachments || []),
            is_pinned: comment.is_pinned
          },
          severity: "info",
          group: "analyst",
          className: "timeline-event-analyst timeline-event-comment" <> if(comment.is_pinned, do: " timeline-event-pinned", else: ""),
          style: "background-color: #6366f1;"
        }
      ]

      # Add edit events if comment was edited
      events =
        if comment.edited_at do
          [
            %{
              id: "comment_edited_#{comment.id}",
              type: "analyst",
              subtype: "comment_edited",
              title: "Comment Edited",
              content: "Comment edited",
              timestamp: comment.edited_at,
              user_id: comment.user_id,
              user_name: get_comment_user_name(comment),
              metadata: %{
                comment_id: comment.id
              },
              severity: "info",
              group: "analyst",
              className: "timeline-event-analyst timeline-event-comment-edit",
              style: "background-color: #f59e0b;"
            }
            | events
          ]
        else
          events
        end

      events
    end)
  end

  defp build_system_events(alert) do
    events = []

    # ML analysis event (if ML metadata exists)
    if alert.detection_metadata && Map.has_key?(alert.detection_metadata, "ml_score") do
      events = [
        %{
          id: "ml_analysis_#{alert.id}",
          type: "system",
          subtype: "ml_analysis",
          title: "ML Analysis Complete",
          content: "Machine learning analysis completed with score: #{alert.detection_metadata["ml_score"]}",
          timestamp: alert.inserted_at,
          user_id: nil,
          user_name: "ML Engine",
          metadata: %{
            ml_score: alert.detection_metadata["ml_score"],
            model_version: alert.detection_metadata["model_version"]
          },
          severity: "info",
          group: "system",
          className: "timeline-event-system timeline-event-ml",
          style: "background-color: #8b5cf6;"
        }
        | events
      ]
    end

    # Enrichment event (if enrichment data exists)
    if alert.enrichment && map_size(alert.enrichment) > 0 do
      events = [
        %{
          id: "enrichment_#{alert.id}",
          type: "system",
          subtype: "enrichment_completed",
          title: "Enrichment Complete",
          content: "Alert enriched with #{map_size(alert.enrichment)} data sources",
          timestamp: alert.inserted_at,
          user_id: nil,
          user_name: "Enrichment Engine",
          metadata: %{
            enrichment_count: map_size(alert.enrichment),
            sources: Map.keys(alert.enrichment)
          },
          severity: "info",
          group: "system",
          className: "timeline-event-system timeline-event-enrichment",
          style: "background-color: #06b6d4;"
        }
        | events
      ]
    end

    # Correlation event (if part of a storyline)
    if alert.storyline_id do
      events = [
        %{
          id: "correlation_#{alert.id}",
          type: "system",
          subtype: "correlation",
          title: "Alert Correlated",
          content: "Alert correlated to storyline #{alert.storyline_id}",
          timestamp: alert.inserted_at,
          user_id: nil,
          user_name: "Correlation Engine",
          metadata: %{
            storyline_id: alert.storyline_id,
            correlation_data: alert.correlation_data,
            correlated_alert_ids: Map.get(alert.correlation_data || %{}, "alert_ids", []),
            shared_iocs: Map.get(alert.correlation_data || %{}, "shared_iocs", []),
            shared_techniques: Map.get(alert.correlation_data || %{}, "shared_techniques", [])
          },
          severity: "info",
          group: "system",
          className: "timeline-event-system timeline-event-correlation",
          style: "background-color: #14b8a6;"
        }
        | events
      ]
    end

    # Deduplication event (if alert is a duplicate)
    if alert.occurrence_count > 1 do
      events = [
        %{
          id: "deduplication_#{alert.id}",
          type: "system",
          subtype: "deduplication",
          title: "Alert Deduplicated",
          content: "Alert has occurred #{alert.occurrence_count} times (last seen: #{format_datetime(alert.last_seen_at)})",
          timestamp: alert.last_seen_at || alert.updated_at,
          user_id: nil,
          user_name: "Deduplication Engine",
          metadata: %{
            occurrence_count: alert.occurrence_count,
            dedup_key: alert.dedup_key,
            last_seen_at: alert.last_seen_at
          },
          severity: "info",
          group: "system",
          className: "timeline-event-system timeline-event-dedup",
          style: "background-color: #64748b;"
        }
        | events
      ]
    end

    events
  end

  defp build_external_events(alert) do
    # For now, return empty list. This can be extended to include:
    # - SIEM export events
    # - Ticket creation events (Jira, ServiceNow, etc.)
    # - Webhook notifications
    # - External API calls
    []
  end

  # ---------------------------------------------------------------------------
  # Private - Helpers
  # ---------------------------------------------------------------------------

  defp normalize_timeline_event(event) do
    Map.update(event, :timestamp, nil, &Timestamp.normalize/1)
  end

  defp get_user_name(%Alert{} = alert, field) do
    case Map.get(alert, field) do
      %{name: name} when is_binary(name) -> name
      %{email: email} -> email
      _ -> "Unknown"
    end
  end

  defp get_comment_user_name(comment) do
    case comment do
      %{user: %{name: name}} when is_binary(name) -> name
      %{user: %{email: email}} -> email
      _ -> "Unknown"
    end
  end

  defp format_status(status) do
    status
    |> String.replace("_", " ")
    |> String.capitalize()
  end

  defp format_verdict(verdict) do
    verdict
    |> String.replace("_", " ")
    |> String.capitalize()
  end

  defp format_action_type(action_type) do
    action_type
    |> String.replace("_", " ")
    |> String.split()
    |> Enum.map(&String.capitalize/1)
    |> Enum.join(" ")
  end

  defp build_action_content(action) do
    case action.status do
      "success" ->
        "#{format_action_type(action.action_type)} executed successfully"

      "failed" ->
        "#{format_action_type(action.action_type)} failed: #{action.error_message || "Unknown error"}"

      "pending" ->
        "#{format_action_type(action.action_type)} is pending execution"

      _ ->
        "#{format_action_type(action.action_type)} - #{action.status}"
    end
  end

  defp action_severity(action_type, status) do
    case {action_type, status} do
      {_, "failed"} -> "high"
      {"isolate_network", "success"} -> "high"
      {"kill_process", "success"} -> "medium"
      {"quarantine_file", "success"} -> "medium"
      {_, "success"} -> "info"
      _ -> "info"
    end
  end

  defp action_color("success"), do: "#10b981"
  defp action_color("failed"), do: "#ef4444"
  defp action_color("pending"), do: "#f59e0b"
  defp action_color(_), do: "#6b7280"

  defp verdict_severity("true_positive"), do: "high"
  defp verdict_severity("suspicious"), do: "medium"
  defp verdict_severity("false_positive"), do: "low"
  defp verdict_severity("benign"), do: "low"
  defp verdict_severity(_), do: "info"

  defp verdict_color("true_positive"), do: "#ef4444"
  defp verdict_color("suspicious"), do: "#f59e0b"
  defp verdict_color("false_positive"), do: "#10b981"
  defp verdict_color("benign"), do: "#10b981"
  defp verdict_color(_), do: "#6b7280"

  defp format_datetime(nil), do: "N/A"

  defp format_datetime(%DateTime{} = dt) do
    Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S UTC")
  end

  defp format_datetime(%NaiveDateTime{} = ndt) do
    ndt
    |> Timestamp.normalize()
    |> format_datetime()
  end

  defp format_datetime(value) when is_binary(value) do
    case Timestamp.normalize(value) do
      %DateTime{} = dt -> format_datetime(dt)
      nil -> value
    end
  end

  defp evidence_summary(evidence) when is_map(evidence) do
    %{
      process:
        compact_map(evidence["process"] || evidence[:process], [
          "name",
          "path",
          "pid",
          "ppid",
          "user",
          "sha256"
        ]),
      file: compact_map(evidence["file"] || evidence[:file], ["path", "sha256"]),
      network:
        compact_map(evidence["network"] || evidence[:network], [
          "remote_ip",
          "remote_port",
          "domain",
          "protocol"
        ]),
      dns: compact_map(evidence["dns"] || evidence[:dns], ["query", "resolved_ip"]),
      ioc_count: count_iocs(evidence)
    }
    |> Enum.reject(fn {_key, value} -> value in [%{}, nil, 0] end)
    |> Map.new()
  end

  defp evidence_summary(_), do: %{}

  defp metadata_summary(metadata) when is_map(metadata) do
    metadata
    |> Map.take(["rule_id", "rule_name", "detector", "sensor", "ml_score", "model_version"])
    |> Enum.reject(fn {_key, value} -> value in [nil, ""] end)
    |> Map.new()
  end

  defp metadata_summary(_), do: %{}

  defp compact_map(value, keys) when is_map(value) do
    keys
    |> Enum.reduce(%{}, fn key, acc ->
      value = Map.get(value, key) || Map.get(value, String.to_atom(key))
      if value in [nil, "", []], do: acc, else: Map.put(acc, key, value)
    end)
  rescue
    _ -> %{}
  end

  defp compact_map(_, _), do: %{}

  defp count_iocs(evidence) do
    [
      evidence["file_hashes"] || evidence[:file_hashes],
      evidence["iocs"] || evidence[:iocs],
      nested_value(evidence, "network", "remote_ip"),
      nested_value(evidence, "dns", "query")
    ]
    |> List.flatten()
    |> Enum.reject(&(&1 in [nil, "", []]))
    |> length()
  end

  defp nested_value(map, parent, child) when is_map(map) do
    case Map.get(map, parent) || Map.get(map, String.to_atom(parent)) do
      nested when is_map(nested) -> Map.get(nested, child) || Map.get(nested, String.to_atom(child))
      _ -> nil
    end
  rescue
    _ -> nil
  end

  defp nested_value(_, _, _), do: nil
end
