defmodule TamanduaServerWeb.GraphQL.Resolvers.InvestigationResolver do
  @moduledoc """
  GraphQL resolvers for Investigation queries and mutations.

  Wired to the `TamanduaServer.Investigations` context which persists
  `CaseInvestigation` records in PostgreSQL.
  """

  require Logger

  alias TamanduaServer.{Accounts, Investigations, Repo}
  alias TamanduaServer.Investigations.CaseInvestigation
  alias TamanduaServer.Alerts.Alert
  import Ecto.Query

  # ===========================================================================
  # Query resolvers
  # ===========================================================================

  def list_investigations(_parent, args, %{context: context}) do
    org_id = context[:organization_id]
    filter = Map.get(args, :filter, %{})
    pagination = Map.get(args, :pagination, %{})

    opts =
      []
      |> put_opt(:organization_id, org_id)
      |> put_opt(:status, filter[:status])
      |> put_opt(:search, filter[:search])
      |> put_opt(:assigned_to, filter[:assigned_to_id])
      |> put_opt(:severity, filter[:priority])
      |> put_opt(:limit, pagination[:limit])
      |> put_opt(:offset, pagination[:offset])

    investigations = Investigations.list_investigations(opts)

    {:ok, Enum.map(investigations, &to_graphql/1)}
  end

  def get_investigation(_parent, %{id: id}, %{context: _context}) do
    case Investigations.get_investigation(id) do
      {:ok, investigation} ->
        {:ok, to_graphql(investigation)}

      {:error, :not_found} ->
        {:error, message: "Investigation not found", code: "NOT_FOUND"}
    end
  end

  def investigation_stats(_parent, _args, %{context: context}) do
    org_id = context[:organization_id]
    stats = Investigations.get_stats(organization_id: org_id)

    {:ok, %{
      total: stats.total,
      open: stats.open,
      closed: stats.closed,
      by_status: stats.by_status,
      by_priority: stats.by_severity,
      average_resolution_hours: calculate_avg_resolution_hours(org_id),
      mttr: calculate_avg_resolution_hours(org_id)
    }}
  end

  # ===========================================================================
  # Field resolvers
  # ===========================================================================

  def alerts(%CaseInvestigation{} = investigation, _args, _resolution) do
    alert_ids = investigation.alert_ids || []
    resolve_alert_ids(alert_ids)
  end

  def alerts(investigation, _args, _resolution) when is_map(investigation) do
    alert_ids = Map.get(investigation, :alert_ids) || Map.get(investigation, "alert_ids") || []
    resolve_alert_ids(alert_ids)
  end

  defp resolve_alert_ids(alert_ids) do
    if Enum.empty?(alert_ids) do
      {:ok, []}
    else
      alerts =
        from(a in Alert,
          where: a.id in ^alert_ids,
          order_by: [desc: a.inserted_at]
        )
        |> Repo.all()

      {:ok, alerts}
    end
  end

  def notes(%CaseInvestigation{notes: notes_text}, _args, _resolution) do
    {:ok, parse_notes(notes_text)}
  end

  def notes(investigation, _args, _resolution) when is_map(investigation) do
    notes_text = Map.get(investigation, :notes) || Map.get(investigation, "notes")
    {:ok, parse_notes(notes_text)}
  end

  def timeline(%CaseInvestigation{timeline: timeline_data}, _args, _resolution) do
    {:ok, parse_timeline(timeline_data)}
  end

  def timeline(investigation, _args, _resolution) when is_map(investigation) do
    timeline_data = Map.get(investigation, :timeline) || Map.get(investigation, "timeline")
    {:ok, parse_timeline(timeline_data)}
  end

  def evidence(%CaseInvestigation{} = _investigation, _args, _resolution) do
    # Evidence items are not stored as a separate field in the current schema.
    # Alert evidence can be accessed through the linked alerts.
    {:ok, []}
  end

  def evidence(_investigation, _args, _resolution) do
    {:ok, []}
  end

  def created_by(%CaseInvestigation{} = investigation, _args, _resolution) do
    # The preloaded association is available directly
    case investigation.creator do
      %Ecto.Association.NotLoaded{} ->
        if investigation.created_by do
          {:ok, Accounts.get_user(investigation.created_by)}
        else
          {:ok, nil}
        end

      nil ->
        {:ok, nil}

      user ->
        {:ok, user}
    end
  end

  def created_by(investigation, _args, _resolution) when is_map(investigation) do
    created_by_id = Map.get(investigation, :created_by_id) || Map.get(investigation, :created_by)
    if created_by_id do
      {:ok, Accounts.get_user(created_by_id)}
    else
      {:ok, nil}
    end
  end

  def assigned_to(%CaseInvestigation{} = investigation, _args, _resolution) do
    case investigation.assigned_user do
      %Ecto.Association.NotLoaded{} ->
        if investigation.assigned_to do
          {:ok, Accounts.get_user(investigation.assigned_to)}
        else
          {:ok, nil}
        end

      nil ->
        {:ok, nil}

      user ->
        {:ok, user}
    end
  end

  def assigned_to(investigation, _args, _resolution) when is_map(investigation) do
    assigned_to_id = Map.get(investigation, :assigned_to_id) || Map.get(investigation, :assigned_to)
    if assigned_to_id do
      {:ok, Accounts.get_user(assigned_to_id)}
    else
      {:ok, nil}
    end
  end

  # ===========================================================================
  # Mutation resolvers
  # ===========================================================================

  def create_investigation(_parent, %{input: input}, %{context: context}) do
    user_id = context[:current_user_id]
    org_id = context[:organization_id]

    attrs = %{
      title: input.title,
      description: input[:description],
      severity: input[:priority] || "medium",
      created_by: user_id,
      organization_id: org_id,
      alert_ids: input[:alert_ids] || [],
      tags: input[:tags] || []
    }

    case Investigations.create_investigation(attrs) do
      {:ok, investigation} ->
        {:ok, to_graphql(investigation)}

      {:error, %Ecto.Changeset{} = changeset} ->
        {:error, message: format_changeset_errors(changeset), code: "VALIDATION_ERROR"}
    end
  end

  def update_investigation(_parent, %{id: id, input: input}, %{context: _context}) do
    case Investigations.get_investigation(id) do
      {:ok, investigation} ->
        attrs =
          %{}
          |> maybe_put(:title, input[:title])
          |> maybe_put(:description, input[:description])
          |> maybe_put(:status, input[:status])
          |> maybe_put(:severity, input[:priority])
          |> maybe_put(:assigned_to, input[:assigned_to_id])
          |> maybe_put(:findings, input[:findings])
          |> maybe_put(:tags, input[:tags])

        # Map recommendations to findings if provided (schema stores findings only)
        attrs =
          if input[:recommendations] do
            current_findings = attrs[:findings] || investigation.findings || ""
            combined =
              if current_findings == "" do
                "Recommendations: #{input[:recommendations]}"
              else
                "#{current_findings}\n\nRecommendations: #{input[:recommendations]}"
              end
            Map.put(attrs, :findings, combined)
          else
            attrs
          end

        case Investigations.update_investigation(investigation, attrs) do
          {:ok, updated} ->
            {:ok, to_graphql(updated)}

          {:error, %Ecto.Changeset{} = changeset} ->
            {:error, message: format_changeset_errors(changeset), code: "VALIDATION_ERROR"}
        end

      {:error, :not_found} ->
        {:error, message: "Investigation not found", code: "NOT_FOUND"}
    end
  end

  def add_investigation_note(_parent, %{input: input}, %{context: context}) do
    investigation_id = input.investigation_id
    content = input.content
    user_id = context[:current_user_id]

    # Resolve author name from user_id
    author_name =
      if user_id do
        case Accounts.get_user(user_id) do
          nil -> nil
          user -> user.email || user.name
        end
      else
        nil
      end

    case Investigations.add_note(investigation_id, content, author_name) do
      {:ok, _investigation} ->
        # Return the note that was just added
        note = %{
          id: Ecto.UUID.generate(),
          content: content,
          author_id: user_id,
          author_name: author_name,
          created_at: DateTime.utc_now(),
          is_internal: input[:is_internal] || false
        }

        {:ok, note}

      {:error, :not_found} ->
        {:error, message: "Investigation not found", code: "NOT_FOUND"}

      {:error, %Ecto.Changeset{} = changeset} ->
        {:error, message: format_changeset_errors(changeset), code: "VALIDATION_ERROR"}
    end
  end

  def add_alerts_to_investigation(_parent, %{investigation_id: id, alert_ids: alert_ids}, _resolution) do
    case Investigations.add_alerts_to_investigation(id, alert_ids) do
      {:ok, investigation} ->
        {:ok, to_graphql(investigation)}

      {:error, :not_found} ->
        {:error, message: "Investigation not found", code: "NOT_FOUND"}

      {:error, %Ecto.Changeset{} = changeset} ->
        {:error, message: format_changeset_errors(changeset), code: "VALIDATION_ERROR"}
    end
  end

  def close_investigation(_parent, args, _resolution) do
    id = args[:id]
    findings = args[:findings]
    recommendations = args[:recommendations]

    case Investigations.get_investigation(id) do
      {:ok, investigation} ->
        close_attrs = %{status: "closed"}

        close_attrs =
          if findings do
            Map.put(close_attrs, :findings, findings)
          else
            close_attrs
          end

        # Store recommendations alongside findings
        close_attrs =
          if recommendations do
            existing_findings = close_attrs[:findings] || investigation.findings || ""
            combined =
              if existing_findings == "" do
                "Recommendations: #{recommendations}"
              else
                "#{existing_findings}\n\nRecommendations: #{recommendations}"
              end
            Map.put(close_attrs, :findings, combined)
          else
            close_attrs
          end

        case Investigations.update_investigation(investigation, close_attrs) do
          {:ok, updated} ->
            {:ok, to_graphql(updated)}

          {:error, %Ecto.Changeset{} = changeset} ->
            {:error, message: format_changeset_errors(changeset), code: "VALIDATION_ERROR"}
        end

      {:error, :not_found} ->
        {:error, message: "Investigation not found", code: "NOT_FOUND"}
    end
  end

  # ===========================================================================
  # Investigation graph builder
  # ===========================================================================

  def build_investigation_graph(_parent, %{alert_id: alert_id}, %{context: _context}) do
    # Build investigation graph starting from an alert
    case Repo.get(Alert, alert_id) do
      nil ->
        {:error, message: "Alert not found", code: "NOT_FOUND"}

      alert ->
        graph = build_graph_from_alert(alert)
        {:ok, graph}
    end
  end

  def build_investigation_graph(_parent, %{process_id: process_id, agent_id: agent_id}, %{context: _context}) do
    # Build investigation graph starting from a process
    graph = build_graph_from_process(agent_id, process_id)
    {:ok, graph}
  end

  # ===========================================================================
  # AI Analysis
  # ===========================================================================

  def ai_analyze_investigation(_parent, %{investigation_id: id}, %{context: _context}) do
    case Investigations.get_investigation(id) do
      {:ok, investigation} ->
        # Attempt to use the AgenticAnalyst if it is running
        case analyze_with_ai(investigation) do
          {:ok, analysis} ->
            {:ok, analysis}

          {:error, :not_available} ->
            {:error,
              message: "AI analysis requires configuration. " <>
                "Ensure the AgenticAnalyst GenServer is started and " <>
                "the ML service is reachable at the configured ML_SERVICE_URL.",
              code: "AI_NOT_CONFIGURED"}
        end

      {:error, :not_found} ->
        {:error, message: "Investigation not found", code: "NOT_FOUND"}
    end
  end

  # ===========================================================================
  # Forensics
  # ===========================================================================

  def collect_forensics(_parent, %{input: input}, %{context: _context}) do
    agent_id = input.agent_id
    collection_type = input[:collection_type] || "full"

    case TamanduaServer.Response.Executor.collect_forensics(agent_id, %{type: collection_type}) do
      {:ok, collection_id} ->
        {:ok, %{
          success: true,
          collection_id: collection_id,
          agent_id: agent_id,
          status: "in_progress",
          artifacts_count: 0,
          size_bytes: 0,
          message: "Forensics collection started"
        }}

      {:error, reason} ->
        {:ok, %{
          success: false,
          collection_id: nil,
          agent_id: agent_id,
          status: "failed",
          artifacts_count: 0,
          size_bytes: 0,
          message: "Failed to start collection: #{inspect(reason)}"
        }}
    end
  end

  def get_forensic_collection(_parent, %{id: id}, %{context: _context}) do
    # Forensic collections are tracked in-memory by the Executor.
    # Query the Executor for collection status.
    case get_collection_status(id) do
      {:ok, collection} ->
        {:ok, collection}

      {:error, :not_found} ->
        {:error, message: "Forensic collection not found", code: "NOT_FOUND"}
    end
  end

  # ===========================================================================
  # Private helpers - GraphQL mapping
  # ===========================================================================

  # Convert a CaseInvestigation struct to the map shape the GraphQL schema expects.
  # The GraphQL type uses `priority` and `severity` whereas the Ecto schema
  # stores severity. We expose the same value for both fields.
  defp to_graphql(%CaseInvestigation{} = inv) do
    %{
      id: inv.id,
      title: inv.title,
      description: inv.description,
      status: inv.status,
      priority: inv.severity,
      severity: inv.severity,
      created_by_id: inv.created_by,
      assigned_to_id: inv.assigned_to,
      organization_id: inv.organization_id,
      mitre_tactics: inv.mitre_tactics || [],
      mitre_techniques: inv.mitre_techniques || [],
      tags: inv.tags || [],
      findings: inv.findings,
      recommendations: nil,
      inserted_at: inv.inserted_at,
      updated_at: inv.updated_at,
      closed_at: if(inv.status == "closed", do: inv.updated_at, else: nil),
      # Keep raw data for field resolvers
      alert_ids: inv.alert_ids || [],
      notes: inv.notes,
      timeline: inv.timeline
    }
  end

  # Fallback for maps (should not normally be reached)
  defp to_graphql(map) when is_map(map), do: map

  # ===========================================================================
  # Private helpers - Notes parsing
  # ===========================================================================

  # Notes are stored as a single text field with entries separated by double
  # newlines, each entry formatted as: [timestamp] (author): content
  # We parse them into structured objects for the GraphQL response.
  defp parse_notes(nil), do: []
  defp parse_notes(""), do: []

  defp parse_notes(notes_text) when is_binary(notes_text) do
    notes_text
    |> String.split("\n\n")
    |> Enum.with_index()
    |> Enum.map(fn {note_str, idx} ->
      {timestamp, author, content} = parse_single_note(note_str)

      %{
        id: "note_#{idx}",
        content: content,
        author_id: nil,
        author_name: author,
        created_at: timestamp,
        is_internal: false
      }
    end)
    |> Enum.reject(fn note -> note.content == "" end)
  end

  defp parse_notes(_), do: []

  defp parse_single_note(note_str) do
    case Regex.run(~r/^\[([^\]]+)\]\s*(?:\(([^)]*)\))?\s*:\s*(.*)$/s, note_str) do
      [_, timestamp_str, author, content] ->
        timestamp =
          case DateTime.from_iso8601(timestamp_str) do
            {:ok, dt, _} -> dt
            _ -> nil
          end

        {timestamp, if(author == "", do: nil, else: author), String.trim(content)}

      _ ->
        {nil, nil, String.trim(note_str)}
    end
  end

  # ===========================================================================
  # Private helpers - Timeline parsing
  # ===========================================================================

  defp parse_timeline(nil), do: []
  defp parse_timeline(data) when is_map(data) and map_size(data) == 0, do: []

  defp parse_timeline(%{"events" => events}) when is_list(events) do
    Enum.map(events, fn event ->
      %{
        timestamp: event["timestamp"],
        event_type: event["type"] || event["event_type"],
        description: event["description"] || event["summary"]
      }
    end)
  end

  defp parse_timeline(_), do: []

  # ===========================================================================
  # Private helpers - AI analysis
  # ===========================================================================

  defp analyze_with_ai(investigation) do
    # Check if the AgenticAnalyst GenServer is available
    case Process.whereis(TamanduaServer.AISecurity.AgenticAnalyst) do
      nil ->
        # AgenticAnalyst is not running, try a basic local analysis
        build_basic_analysis(investigation)

      _pid ->
        # Attempt to use the AgenticAnalyst
        try do
          alert_ids = investigation.alert_ids || []

          if Enum.empty?(alert_ids) do
            build_basic_analysis(investigation)
          else
            # Use the first alert as the primary analysis target
            primary_alert_id = List.first(alert_ids)

            case TamanduaServer.AISecurity.AgenticAnalyst.triage_alert(primary_alert_id) do
              {:ok, result} ->
                {:ok, format_ai_result(result, investigation)}

              {:error, _reason} ->
                build_basic_analysis(investigation)
            end
          end
        rescue
          _ -> {:error, :not_available}
        catch
          :exit, _ -> {:error, :not_available}
        end
    end
  end

  defp build_basic_analysis(investigation) do
    alert_ids = investigation.alert_ids || []

    alerts =
      if Enum.empty?(alert_ids) do
        []
      else
        from(a in Alert, where: a.id in ^alert_ids)
        |> Repo.all()
      end

    if Enum.empty?(alerts) do
      {:error, :not_available}
    else
      # Build a basic analysis from linked alerts
      severities = Enum.map(alerts, & &1.severity)
      techniques = alerts |> Enum.flat_map(& (&1.mitre_techniques || [])) |> Enum.uniq()
      _tactics = alerts |> Enum.flat_map(& (&1.mitre_tactics || [])) |> Enum.uniq()

      threat_level =
        cond do
          "critical" in severities -> "critical"
          "high" in severities -> "high"
          "medium" in severities -> "medium"
          true -> "low"
        end

      mitre_mapping =
        techniques
        |> Enum.map(fn tech_id ->
          %{
            tactic_id: nil,
            tactic_name: nil,
            technique_id: tech_id,
            technique_name: tech_id,
            confidence: 0.7,
            evidence: []
          }
        end)

      recommended_actions =
        alerts
        |> Enum.map(fn alert ->
          %{
            action: "Investigate alert: #{alert.title}",
            priority: alert.severity,
            description: alert.description || "Review alert details",
            playbook_id: nil,
            auto_executable: false
          }
        end)

      summary =
        "Investigation contains #{length(alerts)} linked alert(s). " <>
        "Highest severity: #{threat_level}. " <>
        if(length(techniques) > 0,
          do: "MITRE techniques: #{Enum.join(techniques, ", ")}. ",
          else: "") <>
        "Manual review recommended."

      {:ok, %{
        summary: summary,
        threat_level: threat_level,
        confidence: 0.5,
        attack_chain: [],
        recommended_actions: recommended_actions,
        iocs_extracted: [],
        mitre_mapping: mitre_mapping,
        similar_incidents: []
      }}
    end
  end

  defp format_ai_result(result, _investigation) do
    %{
      summary: result[:summary] || "Analysis complete",
      threat_level: result[:threat_level] || "unknown",
      confidence: result[:confidence] || 0.0,
      attack_chain: result[:attack_chain] || [],
      recommended_actions: result[:recommended_actions] || [],
      iocs_extracted: result[:iocs_extracted] || [],
      mitre_mapping: result[:mitre_mapping] || [],
      similar_incidents: result[:similar_incidents] || []
    }
  end

  # ===========================================================================
  # Private helpers - Forensics
  # ===========================================================================

  defp get_collection_status(collection_id) do
    # Try to get status from the Executor's in-memory state.
    # The Executor tracks active collections internally.
    try do
      case TamanduaServer.Response.Executor.get_collection_status(collection_id) do
        {:ok, status} ->
          {:ok, %{
            id: collection_id,
            agent_id: status[:agent_id],
            collection_type: status[:type] || "full",
            status: status[:status] || "unknown",
            progress: status[:progress] || 0,
            artifacts: status[:artifacts] || [],
            size_bytes: status[:size_bytes] || 0,
            started_at: status[:started_at],
            completed_at: status[:completed_at],
            error_message: status[:error_message],
            requested_by_id: status[:requested_by]
          }}

        {:error, _} ->
          {:error, :not_found}
      end
    rescue
      UndefinedFunctionError ->
        # get_collection_status/1 is not yet implemented on the Executor
        {:error, :not_found}
    catch
      :exit, _ ->
        {:error, :not_found}
    end
  end

  # ===========================================================================
  # Private helpers - Statistics
  # ===========================================================================

  defp calculate_avg_resolution_hours(org_id) do
    query =
      from(i in CaseInvestigation,
        where: i.status == "closed",
        select: avg(fragment("EXTRACT(EPOCH FROM ? - ?)", i.updated_at, i.inserted_at))
      )

    query =
      if org_id do
        from(i in query, where: i.organization_id == ^org_id)
      else
        query
      end

    case Repo.one(query) do
      nil -> 0.0
      avg_seconds when is_float(avg_seconds) -> Float.round(avg_seconds / 3600.0, 1)
      _ -> 0.0
    end
  end

  # ===========================================================================
  # Private helpers - Graph building
  # ===========================================================================

  defp build_graph_from_alert(alert) do
    nodes = []
    edges = []

    # Add alert as a node
    alert_node = %{
      id: "alert_#{alert.id}",
      type: "alert",
      label: alert.title,
      properties: %{
        severity: alert.severity,
        status: alert.status
      },
      severity: alert.severity,
      is_suspicious: true
    }

    nodes = [alert_node | nodes]

    # Add agent as a node if present
    {nodes, edges} = if alert.agent_id do
      agent_node = %{
        id: "host_#{alert.agent_id}",
        type: "host",
        label: "Agent",
        properties: %{agent_id: alert.agent_id},
        severity: nil,
        is_suspicious: false
      }

      edge = %{
        source: "alert_#{alert.id}",
        target: "host_#{alert.agent_id}",
        type: "on_host",
        label: "detected on",
        timestamp: alert.inserted_at
      }

      {[agent_node | nodes], [edge | edges]}
    else
      {nodes, edges}
    end

    # Add process chain nodes if present
    {nodes, edges} = if alert.process_chain do
      Enum.reduce(alert.process_chain, {nodes, edges}, fn process, {n, e} ->
        proc_id = "process_#{process["pid"] || "unknown"}"

        proc_node = %{
          id: proc_id,
          type: "process",
          label: process["name"] || "unknown",
          properties: process,
          severity: nil,
          is_suspicious: process["is_suspicious"] || false
        }

        {[proc_node | n], e}
      end)
    else
      {nodes, edges}
    end

    %{
      nodes: nodes,
      edges: edges,
      clusters: []
    }
  end

  defp build_graph_from_process(agent_id, process_id) do
    # Get process tree from correlator
    case TamanduaServer.Detection.Correlator.get_process_tree(agent_id) do
      {:ok, graph} ->
        # Convert libgraph to our graph format
        nodes = Graph.vertices(graph)
        |> Enum.map(fn pid ->
          labels = Graph.vertex_labels(graph, pid)
          info = List.first(labels) || %{}

          %{
            id: "process_#{pid}",
            type: "process",
            label: info[:name] || "PID #{pid}",
            properties: info,
            severity: nil,
            is_suspicious: info[:is_suspicious] || false
          }
        end)

        edges = Graph.edges(graph)
        |> Enum.map(fn edge ->
          %{
            source: "process_#{edge.v1}",
            target: "process_#{edge.v2}",
            type: "spawned",
            label: "spawned",
            timestamp: nil
          }
        end)

        %{nodes: nodes, edges: edges, clusters: []}

      {:error, _} ->
        %{nodes: [], edges: [], clusters: []}
    end
  end

  # ===========================================================================
  # Private helpers - Utilities
  # ===========================================================================

  defp put_opt(opts, _key, nil), do: opts
  defp put_opt(opts, key, value), do: Keyword.put(opts, key, value)

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp format_changeset_errors(%Ecto.Changeset{} = changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
    |> Enum.map(fn {field, errors} ->
      "#{field}: #{Enum.join(errors, ", ")}"
    end)
    |> Enum.join("; ")
  end
end
