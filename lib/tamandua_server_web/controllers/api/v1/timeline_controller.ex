defmodule TamanduaServerWeb.API.V1.TimelineController do
  @moduledoc """
  Timeline and Attack Storyline API controller.

  Provides endpoints for viewing and correlating security events
  into coherent attack timelines and storylines for incident investigation.

  Note: This controller interfaces with the Correlator module which provides:
  - Process tree analysis for agents
  - Event correlation within time windows
  - Attack storyline building for process chains
  """
  use TamanduaServerWeb, :controller

  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Telemetry.Event
  alias TamanduaServer.Telemetry.EventCorrelation
  alias TamanduaServer.Telemetry.CorrelationEvidence
  alias TamanduaServer.Telemetry.CorrelationExplorer
  alias TamanduaServer.Telemetry.EventContract
  alias TamanduaServer.Telemetry.IncidentCandidates
  alias TamanduaServer.Detection.Correlator
  alias TamanduaServer.Agents

  require Logger

  action_fallback(TamanduaServerWeb.FallbackController)

  def action(conn, _opts) do
    apply(__MODULE__, action_name(conn), [conn, conn.params])
  rescue
    exception ->
      Logger.warning("Timeline action #{action_name(conn)} failed: #{Exception.message(exception)}")

      conn
      |> put_status(:service_unavailable)
      |> json(%{
        status: "error",
        message: "Timeline service is unavailable",
        detail: Exception.message(exception)
      })
  catch
    :exit, {:timeout, _} ->
      conn
      |> put_status(:gateway_timeout)
      |> json(%{
        status: "error",
        message: "Timeline service timed out",
        partial: true
      })

    :exit, {:noproc, _} ->
      conn
      |> put_status(:service_unavailable)
      |> json(%{
        status: "error",
        message: "Timeline correlation service is not running in this boot profile",
        partial: true
      })

    kind, reason ->
      Logger.warning("Timeline action #{action_name(conn)} failed: #{inspect(kind)} #{inspect(reason)}")

      conn
      |> put_status(:service_unavailable)
      |> json(%{
        status: "error",
        message: "Timeline service is unavailable",
        partial: true
      })
  end

  @default_timeline_limit 150
  @max_timeline_limit 250
  @default_readiness_limit 1_000
  @max_readiness_limit 2_500

  @doc """
  List timeline events with time range and optional filters.

  Returns a list of events formatted for the Timeline UI, including
  derived title, description, hostname, and severity fields.

  ## Query Parameters
    - start_time: ISO 8601 start time (default: 24h ago)
    - end_time: ISO 8601 end time (default: now)
    - event_types: Comma-separated event types to filter by
    - agent_ids: Comma-separated agent IDs to filter by
    - severities: Comma-separated severities to filter by
    - limit: Max events to return (default: 500)
  """
  def index(conn, params) do
    organization_id = get_organization_id(conn)
    limit = bounded_limit(params["limit"], @default_timeline_limit, @max_timeline_limit)

    # Get agent IDs that belong to this organization for tenant isolation
    org_agent_ids = get_org_agent_ids(organization_id)

    # Build base query ordered by timestamp descending, scoped to org's agents
    query =
      from(e in Event,
        where: e.agent_id in ^org_agent_ids,
        order_by: [desc: e.timestamp],
        limit: ^limit
      )

    # Apply time range filter
    query = apply_time_range(query, params["start_time"], params["end_time"])

    # Apply event_types filter
    query =
      case params["event_types"] do
        nil ->
          query

        "" ->
          query

        types_str ->
          types =
            String.split(types_str, ",") |> Enum.map(&String.trim/1) |> Enum.reject(&(&1 == ""))

          if length(types) > 0 do
            # Map frontend type names to possible DB event_type values
            db_types = Enum.flat_map(types, &expand_event_type/1)
            where(query, [e], e.event_type in ^db_types)
          else
            query
          end
      end

    # Apply agent_ids filter (must be subset of org's agents)
    query =
      case params["agent_ids"] do
        nil ->
          query

        "" ->
          query

        ids_str ->
          ids = String.split(ids_str, ",") |> Enum.map(&String.trim/1) |> Enum.reject(&(&1 == ""))
          # Only allow filtering by agents that belong to this organization
          allowed_ids = Enum.filter(ids, &(&1 in org_agent_ids))

          if length(allowed_ids) > 0 do
            where(query, [e], e.agent_id in ^allowed_ids)
          else
            query
          end
      end

    # Apply severities filter
    query =
      case params["severities"] do
        nil ->
          query

        "" ->
          query

        sev_str ->
          sevs =
            String.split(sev_str, ",") |> Enum.map(&String.trim/1) |> Enum.reject(&(&1 == ""))

          if length(sevs) > 0 do
            where(query, [e], e.severity in ^sevs)
          else
            query
          end
      end

    events = safe_repo_all(query, "Timeline events")

    {evidence, correlation_partial_reason} =
      safe_correlate_events(events,
        threshold: 40,
        max_events: min(limit, @max_timeline_limit),
        label: "Timeline correlation"
      )

    serialized = serialize_timeline_events(events, organization_id, evidence)

    json(conn, %{
      data: serialized,
      correlationMeta: %{
        scoringPolicy: evidence.scoring_policy,
        analyzedEventCount: evidence.analyzed_event_count,
        correlationCount: length(evidence.correlations),
        partial: evidence.partial,
        partialReason: correlation_partial_reason,
        incidentCandidates: evidence.incident_candidates || [],
        campaignCandidates: evidence.campaign_candidates || [],
        entityGraph: evidence.entity_graph,
        telemetryGaps: evidence.telemetry_gaps
      }
    })
  end

  @doc """
  Get correlation statistics.

  Returns statistics about the correlation engine including
  events correlated, suspicious chains detected, and alerts generated.
  """
  def stats(conn, _params) do
    stats = Correlator.get_stats()

    json(conn, %{
      data: %{
        events_correlated: stats[:events_correlated] || 0,
        suspicious_chains: stats[:suspicious_chains] || 0,
        alerts_generated: stats[:alerts_generated] || 0
      }
    })
  end

  def correlations(conn, params) do
    organization_id = get_organization_id(conn)
    limit = bounded_limit(params["limit"], 100, 500)

    query =
      from(c in EventCorrelation,
        where: c.organization_id == ^organization_id,
        order_by: [desc: c.inserted_at],
        limit: ^limit
      )
      |> maybe_filter_correlation_event(params["event_id"])

    correlations =
      query
      |> safe_repo_all("Timeline correlations")
      |> Enum.map(&serialize_event_correlation/1)

    json(conn, %{data: correlations})
  end

  def incident_candidates(conn, params) do
    organization_id = get_organization_id(conn)
    limit = bounded_limit(params["limit"], 50, 200)

    candidates =
      organization_id
      |> IncidentCandidates.list(limit: limit, status: params["status"])
      |> Enum.map(&IncidentCandidates.serialize/1)

    json(conn, %{data: candidates})
  end

  def candidate_feedback(conn, %{"id" => id} = params) do
    organization_id = get_organization_id(conn)

    user_id =
      case conn.assigns[:current_user] do
        %{id: id} -> id
        _ -> nil
      end

    attrs = Map.put(params, "user_id", user_id)

    feedback_attrs =
      attrs
      |> Map.put("organization_id", organization_id)
      |> Map.put("target_type", "incident_candidate")
      |> Map.put("target_id", id)

    with candidate when not is_nil(candidate) <- IncidentCandidates.get(id, organization_id),
         {:ok, _feedback} <- CorrelationExplorer.record_feedback(feedback_attrs),
         updated when not is_nil(updated) <- IncidentCandidates.get(id, organization_id) do
      json(conn, %{data: IncidentCandidates.serialize(updated)})
    else
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Incident candidate not found"})

      {:ok, _feedback} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Incident candidate not found"})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Invalid feedback", details: inspect(changeset.errors)})
    end
  end

  def readiness(conn, params) do
    organization_id = get_organization_id(conn)
    org_agent_ids = get_org_agent_ids(organization_id)
    limit = bounded_limit(params["limit"], @default_readiness_limit, @max_readiness_limit)

    since =
      params["hours"]
      |> parse_int(24)
      |> max(1)
      |> min(24 * 30)
      |> then(&DateTime.add(DateTime.utc_now(), -&1 * 60 * 60, :second))

    events =
      from(e in Event,
        where: e.agent_id in ^org_agent_ids and e.timestamp >= ^since,
        order_by: [desc: e.timestamp],
        limit: ^limit
      )
      |> safe_repo_all("Timeline readiness")

    json(conn, %{
      data: build_readiness(events, organization_id),
      meta: %{
        since: format_timestamp(since),
        eventCount: length(events),
        eventLimit: limit,
        scoring: "telemetry-contract/v1"
      }
    })
  end

  @doc """
  Get process tree for an agent.

  Returns the process tree structure for a specific agent,
  showing parent-child process relationships.

  ## Parameters
    - agent_id: Required - the agent ID to get the process tree for
  """
  def show(conn, %{"incident_id" => incident_id}) do
    show(conn, %{"id" => incident_id})
  end

  def show(conn, %{"id" => agent_id}) do
    organization_id = get_organization_id(conn)

    # Verify agent belongs to user's organization
    case Agents.get_agent_for_org(organization_id, agent_id) do
      {:error, :not_found} ->
        {:error, :not_found}

      {:ok, _agent} ->
        case Correlator.get_process_tree(agent_id) do
          {:ok, graph} ->
            # Convert graph to serializable format
            vertices = Graph.vertices(graph)
            edges = Graph.edges(graph)

            process_info =
              vertices
              |> Enum.map(fn pid ->
                labels = Graph.vertex_labels(graph, pid)
                info = List.first(labels) || %{}
                Map.put(info, :pid, pid)
              end)

            edge_list =
              edges
              |> Enum.map(fn edge ->
                %{from: edge.v1, to: edge.v2}
              end)

            json(conn, %{
              data: %{
                agent_id: agent_id,
                processes: process_info,
                edges: edge_list,
                process_count: length(vertices)
              }
            })

          {:error, :not_found} ->
            {:error, :not_found}

          {:error, reason} ->
            {:error, to_string(reason)}
        end
    end
  end

  @doc """
  Correlate events for an agent.

  Finds related events based on temporal proximity and shared attributes.

  ## Parameters
    - agent_id: Required - the agent ID to correlate events for
    - time_window_ms: Time window for correlation (default: 5 minutes)
    - limit: Maximum events to analyze (default: 100)
  """
  def correlate(conn, %{"agent_id" => agent_id} = params) do
    organization_id = get_organization_id(conn)

    # Verify agent belongs to user's organization
    case Agents.get_agent_for_org(organization_id, agent_id) do
      {:error, :not_found} ->
        {:error, :not_found}

      {:ok, _agent} ->
        time_window_ms = params["time_window_ms"] |> parse_int(:timer.minutes(5)) |> max(1_000)
        limit = params["limit"] |> parse_int(100) |> max(1) |> min(@max_timeline_limit)

        opts = [time_window_ms: time_window_ms, limit: limit]

        case Correlator.correlate_events(agent_id, opts) do
          {:ok, result} ->
            json(conn, %{
              data: %{
                agent_id: result.agent_id,
                total_events: result.total_events,
                time_window_ms: result.time_window_ms,
                correlations: result.correlations,
                correlation_count: result.correlation_count,
                time_groups: result.time_groups,
                analyzed_at: result.analyzed_at
              }
            })

          {:error, reason} ->
            {:error, to_string(reason)}
        end
    end
  end

  def correlate(conn, %{"event_ids" => event_ids}) when is_list(event_ids) do
    organization_id = get_organization_id(conn)
    org_agent_ids = get_org_agent_ids(organization_id)

    event_ids =
      event_ids
      |> Enum.map(&to_string/1)
      |> Enum.reject(&(&1 == ""))
      |> Enum.filter(&(Ecto.UUID.cast(&1) != :error))
      |> Enum.uniq()
      |> Enum.take(100)

    events =
      from(e in Event,
        where: e.id in ^event_ids and e.agent_id in ^org_agent_ids,
        order_by: [asc: e.timestamp]
      )
      |> safe_repo_all("Selected timeline events")

    cond do
      length(event_ids) < 2 ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Select at least two events"})

      length(events) < 2 ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "At least two selected events were not found for this organization"})

      true ->
        {evidence, correlation_partial_reason} =
          safe_correlate_events(events,
            threshold: 40,
            max_events: 100,
            label: "Selected event correlation"
          )

        {persisted_candidates, persistence_warnings} =
          persist_selected_correlation(evidence, organization_id)

        serialized = serialize_timeline_events(events, organization_id, evidence)

        json(conn, %{
          data: %{
            id: "correlation-" <> Ecto.UUID.generate(),
            name: "Selected Event Correlation",
            events: serialized,
            startTime:
              events
              |> Enum.min_by(&DateTime.to_unix(&1.timestamp, :microsecond))
              |> Map.get(:timestamp)
              |> format_timestamp(),
            endTime:
              events
              |> Enum.max_by(&DateTime.to_unix(&1.timestamp, :microsecond))
              |> Map.get(:timestamp)
              |> format_timestamp(),
            attackChain: evidence.attack_chain,
            riskScore: evidence.risk_score,
            scoringPolicy: evidence.scoring_policy,
            correlations: evidence.correlations,
            incidentCandidates: evidence.incident_candidates || [],
            persistedIncidentCandidates: persisted_candidates,
            campaignCandidates: evidence.campaign_candidates || [],
            entityGraph: evidence.entity_graph,
            evidenceSummary: evidence.evidence_summary,
            telemetryGaps: evidence.telemetry_gaps,
            persistenceWarnings: persistence_warnings,
            partialReason: correlation_partial_reason,
            analyzedEventCount: evidence.analyzed_event_count
          }
        })
    end
  end

  def correlate(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required parameter: agent_id or event_ids"})
  end

  @doc """
  Build an attack storyline for a process.

  Creates a structured attack narrative by analyzing the process chain
  (ancestors and descendants) and correlating related events.

  ## Parameters
    - agent_id: Required - the agent ID
    - pid: Required - the process ID to build storyline for
  """
  def build(conn, %{"agent_id" => agent_id, "pid" => pid_param}) do
    organization_id = get_organization_id(conn)

    # Verify agent belongs to user's organization
    case Agents.get_agent_for_org(organization_id, agent_id) do
      {:error, :not_found} ->
        {:error, :not_found}

      {:ok, _agent} ->
        pid = parse_int(pid_param, -1)

        case pid >= 0 && Correlator.build_storyline(agent_id, pid) do
          false ->
            conn
            |> put_status(:bad_request)
            |> json(%{error: "pid must be a valid integer"})

          {:ok, storyline} ->
            json(conn, %{
              data: %{
                agent_id: storyline.agent_id,
                target_pid: storyline.target_pid,
                process_chain: storyline.process_chain,
                timeline: storyline.timeline,
                event_count: storyline.event_count,
                detections: storyline.detections,
                suspicious: storyline.suspicious,
                built_at: storyline.built_at
              }
            })

          {:error, :not_found} ->
            {:error, :not_found}

          {:error, reason} ->
            {:error, to_string(reason)}
        end
    end
  end

  def build(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required parameters: agent_id and pid"})
  end

  @doc """
  Analyze a process chain for suspicious patterns.

  Checks the process ancestry for known suspicious patterns
  (e.g., Office spawning cmd.exe, browser spawning PowerShell).

  ## Parameters
    - agent_id: Required - the agent ID
    - pid: Required - the process ID to analyze
  """
  def analyze_chain(conn, %{"agent_id" => agent_id, "pid" => pid_param}) do
    organization_id = get_organization_id(conn)

    # Verify agent belongs to user's organization
    case Agents.get_agent_for_org(organization_id, agent_id) do
      {:error, :not_found} ->
        {:error, :not_found}

      {:ok, _agent} ->
        pid = parse_int(pid_param, -1)

        case pid >= 0 && Correlator.analyze_chain(agent_id, pid) do
          false ->
            conn
            |> put_status(:bad_request)
            |> json(%{error: "pid must be a valid integer"})

          {:ok, detections} ->
            json(conn, %{
              data: %{
                agent_id: agent_id,
                pid: pid,
                detections: detections,
                suspicious: length(detections) > 0,
                detection_count: length(detections)
              }
            })

          {:error, :not_found} ->
            {:error, :not_found}

          {:error, reason} ->
            {:error, to_string(reason)}
        end
    end
  end

  def analyze_chain(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required parameters: agent_id and pid"})
  end

  @doc """
  Get events for a specific process.

  Returns all correlated events for a process identified by agent_id and pid.

  ## Parameters
    - agent_id: Required - the agent ID
    - pid: Required - the process ID
  """
  def process_events(conn, %{"agent_id" => agent_id, "pid" => pid_param}) do
    organization_id = get_organization_id(conn)

    # Verify agent belongs to user's organization
    case Agents.get_agent_for_org(organization_id, agent_id) do
      {:error, :not_found} ->
        {:error, :not_found}

      {:ok, _agent} ->
        pid = parse_int(pid_param, -1)

        if pid < 0 do
          conn
          |> put_status(:bad_request)
          |> json(%{error: "pid must be a valid integer"})
        else
          events = Correlator.get_process_events(agent_id, pid)

          json(conn, %{
            data: %{
              agent_id: agent_id,
              pid: pid,
              events: events,
              event_count: length(events)
            }
          })
        end
    end
  end

  def process_events(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required parameters: agent_id and pid"})
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  # Get organization_id from conn.assigns[:current_user]
  defp get_organization_id(conn) do
    case conn.assigns[:current_user] do
      %{organization_id: org_id} when not is_nil(org_id) -> org_id
      user when is_map(user) -> user[:organization_id]
      _ -> nil
    end
  end

  # Get list of agent IDs that belong to an organization
  defp get_org_agent_ids(nil), do: []

  defp get_org_agent_ids(organization_id) do
    Agents.list_agents_for_org(organization_id)
    |> Enum.map(& &1.id)
  rescue
    error ->
      Logger.warning("Timeline organization agent lookup failed: #{Exception.message(error)}")
      []
  catch
    :exit, reason ->
      Logger.warning("Timeline organization agent lookup failed: exit #{inspect(reason)}")
      []
  end

  defp serialize_timeline_events(events, organization_id, evidence) do
    links_by_id = evidence.event_links || %{}
    hostnames_by_agent_id = get_org_agent_hostnames(organization_id)

    Enum.map(events, fn event ->
      related = Map.get(links_by_id, event.id, [])

      event
      |> serialize_timeline_event(hostnames_by_agent_id)
      |> Map.merge(%{
        relatedEvents: Enum.map(related, & &1.id),
        correlationEvidence: related,
        entities: CorrelationEvidence.extract_entities(event),
        telemetryQuality: CorrelationEvidence.telemetry_quality(event),
        telemetryContract: EventContract.summarize(event)
      })
    end)
  end

  defp maybe_filter_correlation_event(query, nil), do: query
  defp maybe_filter_correlation_event(query, ""), do: query

  defp maybe_filter_correlation_event(query, event_id) do
    case Ecto.UUID.cast(event_id) do
      {:ok, valid_id} ->
        where(query, [c], c.source_event_id == ^valid_id or c.target_event_id == ^valid_id)

      :error ->
        query
    end
  end

  defp serialize_event_correlation(correlation) do
    %{
      id: correlation.id,
      sourceEventId: correlation.source_event_id,
      targetEventId: correlation.target_event_id,
      score: correlation.score,
      relationTypes: correlation.relation_types || [],
      reasons: correlation.reasons || [],
      sharedEntities: correlation.shared_entities || [],
      metadata: correlation.metadata || %{},
      insertedAt: format_timestamp(correlation.inserted_at)
    }
  end

  defp build_readiness(events, organization_id) do
    hostnames =
      if organization_id do
        organization_id
        |> Agents.list_agents_for_org()
        |> Map.new(&{&1.id, &1.hostname})
      else
        %{}
      end

    categories = EventContract.categories()

    events
    |> Enum.group_by(& &1.agent_id)
    |> Enum.map(fn {agent_id, agent_events} ->
      category_stats =
        categories
        |> Enum.reject(&(&1 == "unknown"))
        |> Enum.map(fn category ->
          category_events =
            Enum.filter(agent_events, fn event ->
              EventContract.category(event.event_type) == category
            end)

          qualities = Enum.map(category_events, &CorrelationEvidence.telemetry_quality/1)
          missing = qualities |> Enum.flat_map(& &1.missing) |> Enum.frequencies()

          %{
            category: category,
            eventCount: length(category_events),
            status: readiness_status(category_events, qualities),
            averageQuality: average_quality(qualities),
            missingFields:
              missing
              |> Enum.sort_by(fn {_field, count} -> count end, :desc)
              |> Enum.take(6)
              |> Enum.map(fn {field, count} -> %{field: field, count: count} end)
          }
        end)

      %{
        agentId: agent_id,
        hostname: Map.get(hostnames, agent_id, "Unknown"),
        lastSeenEventAt:
          agent_events
          |> Enum.map(& &1.timestamp)
          |> Enum.reject(&is_nil/1)
          |> Enum.max_by(&DateTime.to_unix(&1, :microsecond), fn -> nil end)
          |> format_timestamp(),
        totalEvents: length(agent_events),
        categories: category_stats
      }
    end)
    |> Enum.sort_by(& &1.hostname)
  end

  defp readiness_status([], _qualities), do: "missing"

  defp readiness_status(_events, qualities) do
    avg = average_quality(qualities)

    cond do
      avg >= 75 -> "good"
      avg >= 40 -> "partial"
      true -> "poor"
    end
  end

  defp average_quality([]), do: 0

  defp average_quality(qualities) do
    qualities
    |> Enum.map(& &1.score)
    |> Enum.sum()
    |> Kernel./(length(qualities))
    |> round()
  end

  defp persist_selected_correlation(evidence, organization_id) do
    warnings = []

    warnings =
      case CorrelationExplorer.persist_event_correlations(
             evidence.correlations || [],
             organization_id
           ) do
        {:ok, _correlations} -> warnings
        {:error, reason} -> ["event_correlations: #{inspect(reason)}" | warnings]
      end

    {persisted_candidates, warnings} =
      case CorrelationExplorer.persist_incident_candidates(
             evidence.incident_candidates || [],
             organization_id
           ) do
        {:ok, candidates} ->
          {Enum.map(candidates, &IncidentCandidates.serialize/1), warnings}

        {:error, reason} ->
          {[], ["incident_candidates: #{inspect(reason)}" | warnings]}
      end

    {persisted_candidates, Enum.reverse(warnings)}
  end

  # Serialize a Telemetry.Event into the shape the Timeline UI expects
  defp serialize_timeline_event(event, hostnames_by_agent_id) do
    payload = event.payload || %{}
    event_type = event.event_type || "unknown"
    hostname = Map.get(hostnames_by_agent_id, event.agent_id, "Unknown")

    %{
      id: event.id,
      timestamp: format_timestamp(event.timestamp),
      eventType: normalize_event_type(event_type),
      severity: event.severity || "info",
      title: build_title(event_type, payload),
      description: build_description(event_type, payload),
      agentId: event.agent_id,
      hostname: hostname,
      details: payload,
      relatedEvents: [],
      mitreTechniques: extract_mitre_techniques(payload)
    }
  end

  # Map DB event_type values to the frontend category names
  defp normalize_event_type(event_type) do
    case event_type do
      t when t in ["process_create", "process_start", "process_terminate", "process"] ->
        "process"

      t
      when t in [
             "file_create",
             "file_modify",
             "file_delete",
             "file_rename",
             "file_execute",
             "file"
           ] ->
        "file"

      t
      when t in [
             "network_connect",
             "network_listen",
             "network_close",
             "network_connection",
             "network"
           ] ->
        "network"

      t when t in ["registry_modify", "registry_create", "registry_delete", "registry"] ->
        "registry"

      t when t in ["dns_query", "dns"] ->
        "dns"

      t when t in ["alert"] ->
        "alert"

      # Default to process for unknown types
      _ ->
        "process"
    end
  end

  # Expand a frontend event type category to all possible DB event_type values
  defp expand_event_type(type) do
    case type do
      "process" ->
        ["process", "process_create", "process_start", "process_terminate"]

      "file" ->
        ["file", "file_create", "file_modify", "file_delete", "file_rename", "file_execute"]

      "network" ->
        ["network", "network_connect", "network_listen", "network_close", "network_connection"]

      "registry" ->
        ["registry", "registry_modify", "registry_create", "registry_delete"]

      "dns" ->
        ["dns", "dns_query"]

      "alert" ->
        ["alert"]

      other ->
        [other]
    end
  end

  defp build_title(event_type, payload) do
    case event_type do
      t when t in ["process_create", "process_start", "process"] ->
        name = payload["name"] || payload["process_name"] || "Unknown"
        "Process: #{name}"

      t when t in ["process_terminate"] ->
        name = payload["name"] || payload["process_name"] || "Unknown"
        "Process Terminated: #{name}"

      t when t in ["file_create"] ->
        path = payload["path"] || payload["file_path"] || "Unknown"
        "File Created: #{Path.basename(to_string(path))}"

      t when t in ["file_modify", "file"] ->
        path = payload["path"] || payload["file_path"] || "Unknown"
        "File Modified: #{Path.basename(to_string(path))}"

      t when t in ["file_delete"] ->
        path = payload["path"] || payload["file_path"] || "Unknown"
        "File Deleted: #{Path.basename(to_string(path))}"

      t when t in ["network_connect", "network_connection", "network"] ->
        ip = payload["remote_ip"] || payload["dest_ip"] || "Unknown"
        port = payload["remote_port"] || payload["dest_port"] || ""
        "Network Connection: #{ip}:#{port}"

      t when t in ["dns_query", "dns"] ->
        domain = payload["domain"] || payload["query"] || "Unknown"
        "DNS Query: #{domain}"

      t when t in ["registry_modify", "registry"] ->
        key = payload["key"] || payload["key_path"] || payload["registry_key"] || "Unknown"
        "Registry: #{key}"

      "alert" ->
        payload["title"] || payload["rule_name"] || "Alert"

      _ ->
        humanize_event_type(event_type)
    end
  end

  defp build_description(event_type, payload) do
    case event_type do
      t when t in ["process_create", "process_start", "process"] ->
        cmdline = payload["command_line"] || payload["cmdline"] || ""
        path = payload["path"] || ""
        user = payload["user"] || ""
        parts = [path, cmdline, if(user != "", do: "(#{user})", else: nil)]
        parts |> Enum.reject(&is_nil/1) |> Enum.reject(&(&1 == "")) |> Enum.join(" ")

      t when t in ["process_terminate"] ->
        "Process terminated (PID: #{payload["pid"] || "?"})"

      t
      when t in [
             "file_create",
             "file_modify",
             "file_delete",
             "file_rename",
             "file_execute",
             "file"
           ] ->
        path = payload["path"] || payload["file_path"] || ""
        op = payload["operation"] || event_type
        "#{op}: #{path}"

      t when t in ["network_connect", "network_connection", "network"] ->
        protocol = payload["protocol"] || "TCP"
        direction = payload["direction"] || ""
        local = "#{payload["local_ip"] || ""}:#{payload["local_port"] || ""}"
        remote = "#{payload["remote_ip"] || ""}:#{payload["remote_port"] || ""}"
        "#{protocol} #{direction} #{local} -> #{remote}" |> String.trim()

      t when t in ["dns_query", "dns"] ->
        qtype = payload["query_type"] || ""
        response = payload["response"] || ""

        parts = [
          if(qtype != "", do: "Type: #{qtype}", else: nil),
          if(response != "", do: "Response: #{response}", else: nil)
        ]

        parts |> Enum.reject(&is_nil/1) |> Enum.join(" | ")

      t when t in ["registry_modify", "registry"] ->
        value = payload["value_data"] || payload["value_name"] || ""
        op = payload["operation"] || "modify"
        "#{op}: #{value}"

      "alert" ->
        payload["description"] || payload["message"] || ""

      _ ->
        # Fallback: show a few payload keys
        payload
        |> Enum.take(3)
        |> Enum.map(fn {k, v} -> "#{k}: #{inspect(v)}" end)
        |> Enum.join(", ")
    end
  end

  defp humanize_event_type(event_type) do
    event_type
    |> to_string()
    |> String.replace("_", " ")
    |> String.split(" ")
    |> Enum.map(&String.capitalize/1)
    |> Enum.join(" ")
  end

  defp extract_mitre_techniques(payload) do
    cond do
      is_list(payload["mitre_techniques"]) -> payload["mitre_techniques"]
      is_list(payload["techniques"]) -> payload["techniques"]
      is_binary(payload["mitre_technique"]) -> [payload["mitre_technique"]]
      true -> []
    end
  end

  # Apply ISO 8601 time range to the query.
  # The Event schema uses :utc_datetime_usec (DateTime), so we must compare with DateTime values.
  defp apply_time_range(query, start_str, end_str) do
    start_dt = parse_iso_datetime(start_str) || DateTime.utc_now() |> DateTime.add(-24 * 60 * 60, :second)
    end_dt = parse_iso_datetime(end_str) || DateTime.utc_now()

    query
    |> where([e], e.timestamp >= ^start_dt)
    |> where([e], e.timestamp <= ^end_dt)
  end

  # Parse an ISO 8601 string into a DateTime (not NaiveDateTime).
  # Handles both "2026-01-29T12:00:00Z" and "2026-01-29T12:00:00.000Z" formats.
  defp parse_iso_datetime(nil), do: nil
  defp parse_iso_datetime(""), do: nil

  defp parse_iso_datetime(str) when is_binary(str) do
    case DateTime.from_iso8601(str) do
      {:ok, dt, _offset} ->
        dt

      _ ->
        # Try NaiveDateTime and convert to UTC DateTime
        case NaiveDateTime.from_iso8601(str) do
          {:ok, ndt} -> DateTime.from_naive!(ndt, "Etc/UTC")
          _ -> nil
        end
    end
  end

  defp get_org_agent_hostnames(nil), do: %{}

  defp get_org_agent_hostnames(organization_id) do
    organization_id
    |> Agents.list_agents_for_org()
    |> Map.new(fn agent -> {agent.id, agent.hostname || "Unknown"} end)
  rescue
    error ->
      Logger.warning("Timeline agent hostname lookup failed: #{Exception.message(error)}")
      %{}
  catch
    :exit, reason ->
      Logger.warning("Timeline agent hostname lookup failed: exit #{inspect(reason)}")
      %{}
  end

  defp format_timestamp(%DateTime{} = ts), do: DateTime.to_iso8601(ts)
  defp format_timestamp(%NaiveDateTime{} = ts), do: NaiveDateTime.to_iso8601(ts) <> "Z"
  defp format_timestamp(ts) when is_binary(ts), do: ts
  defp format_timestamp(_), do: nil

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

  defp safe_correlate_events(events, opts) do
    label = Keyword.get(opts, :label, "Timeline correlation")
    correlate_opts = Keyword.drop(opts, [:label])

    do_safe_correlate_events(events, correlate_opts, label)
  end

  defp do_safe_correlate_events(events, correlate_opts, label) do
    {CorrelationEvidence.correlate_events(events, correlate_opts), nil}
  rescue
    error ->
      Logger.warning("#{label} failed: #{Exception.message(error)}")
      {empty_correlation_evidence(length(events)), "correlation_unavailable"}
  catch
    :exit, reason ->
      Logger.warning("#{label} failed: exit #{inspect(reason)}")
      {empty_correlation_evidence(length(events)), "correlation_unavailable"}
  end

  defp empty_correlation_evidence(event_count) do
    %{
      scoring_version: "unavailable",
      scoring_policy: %{
        version: "unavailable",
        threshold: nil,
        mode: "degraded",
        requirements: []
      },
      correlations: [],
      event_links: %{},
      entity_graph: %{nodes: [], edges: []},
      incident_candidates: [],
      campaign_candidates: [],
      risk_score: 0,
      attack_chain: [],
      evidence_summary: [],
      telemetry_gaps: [],
      analyzed_event_count: event_count,
      partial: true
    }
  end
end
