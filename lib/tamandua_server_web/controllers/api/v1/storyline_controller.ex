defmodule TamanduaServerWeb.API.V1.StorylineController do
  @moduledoc """
  Storyline API Controller - SentinelOne-style attack visualization.

  Provides endpoints for generating and analyzing attack storylines,
  which are visual representations of attack chains showing how
  threats propagate through systems.

  ## Endpoints

  - `GET /api/v1/storyline/:alert_id` - Get storyline for a specific alert
  - `GET /api/v1/storyline/process/:agent_id/:pid` - Get storyline from process
  - `POST /api/v1/storyline/build` - Build storyline from event IDs
  - `POST /api/v1/storyline/analyze` - AI analysis of a storyline
  - `GET /api/v1/storyline/export/:alert_id` - Export storyline in various formats
  """

  use TamanduaServerWeb, :controller

  require Logger

  alias TamanduaServer.Storyline.Engine
  alias TamanduaServer.Storyline.Renderer
  alias TamanduaServer.Detection.Storyline, as: AutonomousStoryline
  alias TamanduaServer.Investigations.Storyline, as: InvestigationStoryline

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  Get a complete storyline for an alert.

  Returns a visualization-ready graph structure with:
  - Nodes (processes, files, network connections, etc.)
  - Edges (relationships between entities)
  - Timeline data
  - Threat indicators
  - Root cause analysis

  ## Parameters
    - `alert_id` (required): The alert ID to generate storyline for
    - `time_window_minutes` (optional): Time window to include (default: 30)
    - `layout` (optional): Layout type - "timeline", "hierarchical", or "force" (default: "timeline")
    - `highlight_malicious` (optional): Highlight malicious path (default: true)

  ## Response
  ```json
  {
    "data": {
      "id": "storyline_abc123",
      "alert_id": "uuid",
      "title": "Ransomware Attack - cmd.exe",
      "summary": "Attack storyline...",
      "severity": "critical",
      "root_cause": {...},
      "nodes": [...],
      "edges": [...],
      "timeline": [...],
      "threat_indicators": [...],
      "mitre_techniques": ["T1059.001", "T1486"],
      "attack_phase": "impact",
      "confidence_score": 0.85,
      "analysis": {...}
    }
  }
  ```
  """
  def show(conn, %{"alert_id" => alert_id} = params) do
    opts = build_opts(params)

    with {:ok, storyline} <- Engine.generate_for_alert(alert_id, opts),
         {:ok, analysis} <- Engine.analyze_storyline(storyline, opts) do

      json(conn, %{
        data: %{
          id: storyline.id,
          alert_id: storyline.alert_id,
          agent_id: storyline.agent_id,
          title: storyline.title,
          summary: storyline.summary,
          severity: storyline.severity,
          root_cause: storyline.root_cause,
          nodes: storyline.nodes,
          edges: storyline.edges,
          timeline: storyline.timeline,
          threat_indicators: storyline.threat_indicators,
          mitre_techniques: storyline.mitre_techniques,
          attack_phase: storyline.attack_phase,
          confidence_score: storyline.confidence_score,
          generated_at: storyline.generated_at,
          time_range: storyline.time_range,
          analysis: analysis
        }
      })
    end
  end

  @doc """
  Get storyline starting from a specific process.

  Useful for investigating suspicious process activity without
  an existing alert.

  ## Parameters
    - `agent_id` (required): The agent ID
    - `pid` (required): The process ID to investigate
    - `time_window_minutes` (optional): Time window (default: 60)
  """
  def from_process(conn, %{"agent_id" => agent_id, "pid" => pid_str} = params) do
    pid = parse_integer(pid_str, 0, 0, 10_000_000)
    opts = build_opts(params)

    with {:ok, storyline} <- Engine.generate_from_process(agent_id, pid, opts),
         {:ok, analysis} <- Engine.analyze_storyline(storyline, opts) do

      json(conn, %{
        data: %{
          id: storyline.id,
          alert_id: storyline.alert_id,
          agent_id: storyline.agent_id,
          title: storyline.title,
          summary: storyline.summary,
          severity: storyline.severity,
          root_cause: storyline.root_cause,
          nodes: storyline.nodes,
          edges: storyline.edges,
          timeline: storyline.timeline,
          threat_indicators: storyline.threat_indicators,
          mitre_techniques: storyline.mitre_techniques,
          attack_phase: storyline.attack_phase,
          confidence_score: storyline.confidence_score,
          generated_at: storyline.generated_at,
          time_range: storyline.time_range,
          analysis: analysis
        }
      })
    end
  end

  def from_process(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required parameters: agent_id and pid"})
  end

  @doc """
  Build a storyline from a list of event IDs.

  Allows manual storyline construction from selected events.

  ## Request Body
  ```json
  {
    "event_ids": ["event1", "event2", ...],
    "time_window_minutes": 30,
    "layout": "timeline"
  }
  ```
  """
  def build(conn, %{"event_ids" => event_ids} = params) when is_list(event_ids) do
    opts = build_opts(params)

    with {:ok, storyline} <- Engine.generate_from_events(event_ids, opts),
         {:ok, analysis} <- Engine.analyze_storyline(storyline, opts) do

      json(conn, %{
        data: %{
          id: storyline.id,
          alert_id: storyline.alert_id,
          agent_id: storyline.agent_id,
          title: storyline.title,
          summary: storyline.summary,
          severity: storyline.severity,
          root_cause: storyline.root_cause,
          nodes: storyline.nodes,
          edges: storyline.edges,
          timeline: storyline.timeline,
          threat_indicators: storyline.threat_indicators,
          mitre_techniques: storyline.mitre_techniques,
          attack_phase: storyline.attack_phase,
          confidence_score: storyline.confidence_score,
          generated_at: storyline.generated_at,
          time_range: storyline.time_range,
          analysis: analysis
        }
      })
    end
  end

  def build(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required parameter: event_ids (array)"})
  end

  @doc """
  Analyze an existing storyline with AI assistance.

  Provides enhanced analysis including:
  - Threat assessment
  - Attack technique identification
  - Recommended response actions
  - Similar incident detection
  - Human-readable narrative

  ## Request Body
  ```json
  {
    "storyline": {...},
    "use_ai": true
  }
  ```
  """
  def analyze(conn, %{"storyline" => storyline_data} = params) do
    use_ai = Map.get(params, "use_ai", false)

    # Convert string keys to atoms for the storyline
    storyline = atomize_keys(storyline_data)

    opts = [use_ai: use_ai]

    case Engine.analyze_storyline(storyline, opts) do
      {:ok, analysis} ->
        json(conn, %{
          data: %{
            threat_assessment: analysis.threat_assessment,
            attack_techniques: analysis.attack_techniques,
            recommended_actions: analysis.recommended_actions,
            confidence: analysis.confidence,
            similar_incidents: analysis.similar_incidents,
            attack_narrative: analysis.attack_narrative
          }
        })

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: to_string(reason)})
    end
  end

  def analyze(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required parameter: storyline"})
  end

  @doc """
  Export a storyline in various formats.

  ## Parameters
    - `alert_id` (required): The alert ID
    - `format` (optional): Export format - "json", "dot", "mermaid" (default: "json")

  ## Formats
    - `json`: Full JSON export (default)
    - `dot`: GraphViz DOT format for external rendering
    - `mermaid`: Mermaid diagram format for documentation
  """
  def export(conn, %{"alert_id" => alert_id} = params) do
    format = params
    |> Map.get("format", "json")
    |> String.downcase()
    |> safe_to_existing_atom(~w(json dot mermaid))
    |> Kernel.||(:json)

    opts = build_opts(params)

    with {:ok, storyline} <- Engine.generate_for_alert(alert_id, opts),
         {:ok, export_data} <- Renderer.export(%{nodes: storyline.nodes, edges: storyline.edges}, format) do

      case format do
        :json ->
          json(conn, %{
            data: %{
              format: "json",
              content: Jason.decode!(export_data)
            }
          })

        :dot ->
          conn
          |> put_resp_content_type("text/plain")
          |> send_resp(200, export_data)

        :mermaid ->
          conn
          |> put_resp_content_type("text/plain")
          |> send_resp(200, export_data)

        _ ->
          conn
          |> put_status(:bad_request)
          |> json(%{error: "Unsupported format. Use: json, dot, or mermaid"})
      end
    end
  end

  @doc """
  Get storyline statistics for an agent.

  Returns aggregate statistics about storylines generated for an agent.
  """
  def stats(conn, %{"agent_id" => agent_id} = params) do
    time_range = Map.get(params, "time_range", "24h")

    hours = case time_range do
      "1h" -> 1
      "6h" -> 6
      "24h" -> 24
      "7d" -> 24 * 7
      "30d" -> 24 * 30
      _ -> 24
    end

    cutoff = DateTime.utc_now() |> DateTime.add(-hours * 3600, :second)

    import Ecto.Query
    alias TamanduaServer.Detection.StorylineRecord
    alias TamanduaServer.Repo

    base =
      from(s in StorylineRecord,
        where: s.agent_id == ^agent_id and s.inserted_at >= ^cutoff
      )

    total = Repo.aggregate(base, :count, :id)

    avg_processes =
      case Repo.aggregate(base, :avg, :process_count) do
        nil -> 0
        val -> Float.round(val, 1)
      end

    avg_detections =
      case Repo.aggregate(base, :avg, :detection_count) do
        nil -> 0
        val -> Float.round(val, 1)
      end

    # Most common MITRE techniques across storylines
    common_techniques =
      from(s in StorylineRecord,
        where: s.agent_id == ^agent_id and s.inserted_at >= ^cutoff,
        select: s.mitre_techniques
      )
      |> Repo.all()
      |> List.flatten()
      |> Enum.frequencies()
      |> Enum.sort_by(fn {_k, v} -> v end, :desc)
      |> Enum.take(10)
      |> Enum.map(fn {technique, count} -> %{technique: technique, count: count} end)

    # Recent storylines (top 5 by score)
    recent =
      from(s in StorylineRecord,
        where: s.agent_id == ^agent_id and s.inserted_at >= ^cutoff,
        order_by: [desc: s.total_score],
        limit: 5,
        select: %{
          id: s.id,
          severity: s.severity,
          total_score: s.total_score,
          detection_count: s.detection_count,
          process_count: s.process_count,
          status: s.status,
          inserted_at: s.inserted_at
        }
      )
      |> Repo.all()

    # Severity breakdown
    severity_counts =
      from(s in StorylineRecord,
        where: s.agent_id == ^agent_id and s.inserted_at >= ^cutoff,
        group_by: s.severity,
        select: {s.severity, count(s.id)}
      )
      |> Repo.all()
      |> Map.new()

    json(conn, %{
      data: %{
        agent_id: agent_id,
        time_range: time_range,
        total_storylines: total,
        average_processes: avg_processes,
        average_detections: avg_detections,
        severity_breakdown: %{
          critical: Map.get(severity_counts, "critical", 0),
          high: Map.get(severity_counts, "high", 0),
          medium: Map.get(severity_counts, "medium", 0),
          low: Map.get(severity_counts, "low", 0)
        },
        common_techniques: common_techniques,
        recent_storylines: recent
      }
    })
  rescue
    e ->
      Logger.warning("[StorylineController] stats failed: #{Exception.message(e)}")
      # Fallback if table doesn't exist yet (migration not run)
      json(conn, %{
        data: %{
          agent_id: agent_id,
          time_range: Map.get(params, "time_range", "24h"),
          total_storylines: 0,
          average_processes: 0,
          average_detections: 0,
          severity_breakdown: %{critical: 0, high: 0, medium: 0, low: 0},
          common_techniques: [],
          recent_storylines: []
        }
      })
  end

  # ====================================================================
  # Autonomous Storyline Engine endpoints
  # ====================================================================

  @doc """
  List all active autonomous storylines across all agents.

  ## Query Parameters
    - `status` (optional): Filter by status ("active", "resolved")
    - `min_severity` (optional): Minimum severity ("low", "medium", "high", "critical")
    - `limit` (optional): Maximum results (default: 50)
  """
  def list_active(conn, params) do
    # Return all storylines across all agents by iterating ETS directly
    limit = parse_integer(Map.get(params, "limit", "50"), 50, 1, 500)
    status_filter = parse_status(Map.get(params, "status"))
    min_severity = parse_severity_atom(Map.get(params, "min_severity"))

    # Get all agent IDs that have storylines
    storylines =
      :ets.tab2list(:tamandua_storylines)
      |> Enum.map(fn {_id, s} -> s end)
      |> maybe_filter_by_status(status_filter)
      |> maybe_filter_by_severity(min_severity)
      |> Enum.sort_by(& &1.updated_at, {:desc, DateTime})
      |> Enum.take(limit)
      |> Enum.map(&serialize_autonomous_storyline/1)

    json(conn, %{data: storylines, total: length(storylines)})
  rescue
    e ->
      Logger.warning("[StorylineController] list_active failed: #{Exception.message(e)}")
      # ETS table may not exist yet
      json(conn, %{data: [], total: 0})
  end

  @doc """
  Get a single autonomous storyline by its ID.

  Returns the full storyline including process list, detections,
  MITRE coverage, and severity.
  """
  def show_autonomous(conn, %{"id" => storyline_id}) do
    case AutonomousStoryline.get_storyline(storyline_id) do
      {:ok, storyline} ->
        json(conn, %{data: storyline})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Storyline not found"})
    end
  end

  @doc """
  List autonomous storylines for a specific agent.

  ## Query Parameters
    - `status` (optional): Filter by status ("active", "resolved")
    - `min_severity` (optional): Minimum severity
    - `limit` (optional): Maximum results (default: 50)
  """
  def agent_storylines(conn, %{"agent_id" => agent_id} = params) do
    opts = [
      status: parse_status(Map.get(params, "status")),
      min_severity: parse_severity_atom(Map.get(params, "min_severity")),
      limit: parse_integer(Map.get(params, "limit", "50"), 50, 1, 500)
    ]
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)

    case AutonomousStoryline.get_agent_storylines(agent_id, opts) do
      {:ok, storylines} ->
        json(conn, %{data: storylines, total: length(storylines)})
    end
  end

  @doc """
  Merge two storylines into one.

  The second storyline is absorbed into the first. All processes,
  detections, and scores are combined.
  """
  def merge(conn, %{"id1" => id1, "id2" => id2}) do
    case AutonomousStoryline.merge_storylines(id1, id2) do
      :ok ->
        case AutonomousStoryline.get_storyline(id1) do
          {:ok, merged} ->
            json(conn, %{data: merged, message: "Storylines merged successfully"})
          {:error, :not_found} ->
            json(conn, %{data: nil, message: "Merged but could not retrieve result"})
        end

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "One or both storylines not found"})

      {:error, :same_storyline} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Cannot merge a storyline with itself"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: to_string(reason)})
    end
  end

  @doc """
  Get Storyline engine statistics (ETS table sizes, counters).
  """
  def engine_stats(conn, _params) do
    stats = AutonomousStoryline.stats()
    json(conn, %{data: stats})
  end

  # Private helpers

  defp build_opts(params) do
    [
      time_window_minutes: parse_integer(Map.get(params, "time_window_minutes", "30"), 30, 1, 24 * 60),
      layout: parse_layout(Map.get(params, "layout", "timeline")),
      highlight_malicious: parse_boolean(Map.get(params, "highlight_malicious", "true")),
      highlight_suspicious: parse_boolean(Map.get(params, "highlight_suspicious", "true")),
      limit: parse_integer(Map.get(params, "limit", "500"), 500, 1, 1_000),
      use_ai: parse_boolean(Map.get(params, "use_ai", "false"))
    ]
  end

  defp parse_integer(val, _default, min, max) when is_integer(val), do: clamp(val, min, max)
  defp parse_integer(val, default, min, max) when is_binary(val) do
    case Integer.parse(val) do
      {int, _} -> clamp(int, min, max)
      :error -> default
    end
  end
  defp parse_integer(_val, default, _min, _max), do: default

  defp clamp(value, min, _max) when value < min, do: min
  defp clamp(value, _min, max) when value > max, do: max
  defp clamp(value, _min, _max), do: value

  defp parse_boolean(val) when is_boolean(val), do: val
  defp parse_boolean("true"), do: true
  defp parse_boolean("1"), do: true
  defp parse_boolean(_), do: false

  defp parse_layout("timeline"), do: :timeline
  defp parse_layout("hierarchical"), do: :hierarchical
  defp parse_layout("force"), do: :force
  defp parse_layout(_), do: :timeline

  defp atomize_keys(map) when is_map(map) do
    map
    |> Enum.map(fn {k, v} ->
      key = if is_binary(k) do
        try do
          String.to_existing_atom(k)
        rescue
          ArgumentError -> k
        end
      else
        k
      end
      value = atomize_keys(v)
      {key, value}
    end)
    |> Map.new()
  end
  defp atomize_keys(list) when is_list(list) do
    Enum.map(list, &atomize_keys/1)
  end
  defp atomize_keys(value), do: value

  # Autonomous Storyline helpers

  defp parse_status("active"), do: :active
  defp parse_status("resolved"), do: :resolved
  defp parse_status(_), do: nil

  defp parse_severity_atom("low"), do: :low
  defp parse_severity_atom("medium"), do: :medium
  defp parse_severity_atom("high"), do: :high
  defp parse_severity_atom("critical"), do: :critical
  defp parse_severity_atom(_), do: nil

  defp maybe_filter_by_status(storylines, nil), do: storylines
  defp maybe_filter_by_status(storylines, status) do
    Enum.filter(storylines, &(&1.status == status))
  end

  defp maybe_filter_by_severity(storylines, nil), do: storylines
  defp maybe_filter_by_severity(storylines, min_severity) do
    severity_order = %{low: 0, medium: 1, high: 2, critical: 3}
    min_ord = Map.get(severity_order, min_severity, 0)
    Enum.filter(storylines, fn s ->
      Map.get(severity_order, s.severity, 0) >= min_ord
    end)
  end

  defp serialize_autonomous_storyline(s) do
    %{
      id: s.id,
      agent_id: s.agent_id,
      root_pid: s.root_pid,
      processes: MapSet.to_list(s.processes),
      detections: s.detections,
      total_score: s.total_score,
      severity: s.severity,
      status: s.status,
      alert_id: s.alert_id,
      mitre_tactics: MapSet.to_list(s.mitre_tactics),
      mitre_techniques: MapSet.to_list(s.mitre_techniques),
      created_at: s.created_at,
      updated_at: s.updated_at
    }
  end

  # ====================================================================
  # Investigation Storyline Engine endpoints
  # ====================================================================

  @doc """
  Create a new investigation story from alert IDs.

  ## Request Body
  ```json
  {
    "alert_ids": ["uuid1", "uuid2"]
  }
  ```
  """
  def create_investigation_story(conn, %{"alert_ids" => alert_ids}) when is_list(alert_ids) do
    organization_id = get_organization_id(conn)

    if is_nil(organization_id) do
      conn
      |> put_status(:unauthorized)
      |> json(%{error: "Organization context required"})
    else
      # Fetch alert data for each alert ID, scoped to organization
      alerts = Enum.flat_map(alert_ids, fn id ->
        case TamanduaServer.Alerts.get_alert_for_org(organization_id, id) do
          {:ok, alert} -> [alert_to_map(alert)]
          {:error, :not_found} -> []
        end
      end)

      if alerts == [] do
        conn
        |> put_status(:bad_request)
        |> json(%{error: "No valid alerts found for the provided IDs"})
      else
        case InvestigationStoryline.create_story(alerts) do
          {:ok, story_id} ->
            case InvestigationStoryline.get_story(story_id) do
              {:ok, story} ->
                conn
                |> put_status(:created)
                |> json(%{data: story})

              _ ->
                conn
                |> put_status(:created)
                |> json(%{data: %{id: story_id}, message: "Story created"})
            end

          {:error, reason} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: to_string(reason)})
        end
      end
    end
  end

  def create_investigation_story(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required parameter: alert_ids (array)"})
  end

  @doc """
  Get the causal graph for an investigation story (nodes + edges for visualization).
  """
  def investigation_story_graph(conn, %{"id" => story_id}) do
    case InvestigationStoryline.get_story_graph(story_id) do
      {:ok, graph} ->
        json(conn, %{data: graph})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Story not found"})
    end
  end

  @doc """
  Get the chronological event timeline for an investigation story.
  """
  def investigation_story_timeline(conn, %{"id" => story_id}) do
    case InvestigationStoryline.get_story_timeline(story_id) do
      {:ok, timeline} ->
        json(conn, %{data: timeline, total: length(timeline)})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Story not found"})
    end
  end

  @doc """
  Merge two investigation stories into one.

  ## Request Body
  ```json
  {
    "story_id_1": "id1",
    "story_id_2": "id2"
  }
  ```
  """
  def merge_investigation_stories(conn, %{"story_id_1" => id1, "story_id_2" => id2}) do
    case InvestigationStoryline.merge_stories(id1, id2) do
      {:ok, merged_id} ->
        case InvestigationStoryline.get_story(merged_id) do
          {:ok, story} ->
            json(conn, %{data: story, message: "Stories merged successfully"})

          _ ->
            json(conn, %{data: %{id: merged_id}, message: "Stories merged"})
        end

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "One or both stories not found"})

      {:error, :same_story} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Cannot merge a story with itself"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: to_string(reason)})
    end
  end

  def merge_investigation_stories(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required parameters: story_id_1, story_id_2"})
  end

  @doc """
  Resolve an investigation story with a verdict.

  ## Request Body
  ```json
  {
    "state": "resolved",
    "notes": "False alarm - authorized pentest activity"
  }
  ```
  """
  def resolve_investigation_story(conn, %{"id" => story_id} = params) do
    resolution = %{
      state: params["state"] || "resolved",
      notes: params["notes"]
    }

    case InvestigationStoryline.resolve_story(story_id, resolution) do
      :ok ->
        case InvestigationStoryline.get_story(story_id) do
          {:ok, story} ->
            json(conn, %{data: story, message: "Story resolved"})

          _ ->
            json(conn, %{message: "Story resolved"})
        end

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Story not found"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: to_string(reason)})
    end
  end

  @doc """
  Get MITRE ATT&CK kill chain coverage for an investigation story.
  """
  def investigation_kill_chain(conn, %{"id" => story_id}) do
    case InvestigationStoryline.get_kill_chain_coverage(story_id) do
      {:ok, coverage} ->
        json(conn, %{data: coverage})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Story not found"})
    end
  end

  @doc """
  List active investigation stories with optional filters.

  ## Query Parameters
    - `agent_id` (optional): Filter by agent
    - `state` (optional): Filter by state ("open", "investigating", "resolved", "false_positive")
    - `min_severity` (optional): Minimum severity ("low", "medium", "high", "critical")
    - `limit` (optional): Maximum results (default: 50)
  """
  def list_investigation_stories(conn, params) do
    filters = [
      agent_id: params["agent_id"],
      state: parse_investigation_state(params["state"]),
      min_severity: params["min_severity"],
      limit: parse_integer(Map.get(params, "limit", "50"), 50, 1, 500)
    ]
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)

    case InvestigationStoryline.get_active_stories(filters) do
      {:ok, stories} ->
        json(conn, %{data: stories, total: length(stories)})
    end
  end

  @doc """
  Get Investigation Storyline engine statistics.
  """
  def investigation_stats(conn, _params) do
    stats = InvestigationStoryline.stats()
    json(conn, %{data: stats})
  end

  # Multi-tenant helpers

  defp get_organization_id(conn) do
    case conn.assigns[:current_user] do
      %{organization_id: org_id} when not is_nil(org_id) -> org_id
      _ -> conn.assigns[:organization_id]
    end
  end

  # Investigation story helpers

  defp parse_investigation_state("open"), do: :open
  defp parse_investigation_state("investigating"), do: :investigating
  defp parse_investigation_state("resolved"), do: :resolved
  defp parse_investigation_state("false_positive"), do: :false_positive
  defp parse_investigation_state(_), do: nil

  defp alert_to_map(%{} = alert) do
    %{
      id: Map.get(alert, :id),
      title: Map.get(alert, :title),
      description: Map.get(alert, :description),
      severity: Map.get(alert, :severity),
      status: Map.get(alert, :status),
      agent_id: Map.get(alert, :agent_id),
      mitre_tactics: Map.get(alert, :mitre_tactics, []),
      mitre_techniques: Map.get(alert, :mitre_techniques, []),
      threat_score: Map.get(alert, :threat_score),
      evidence: Map.get(alert, :evidence, %{}),
      raw_event: Map.get(alert, :raw_event, %{}),
      detection_metadata: Map.get(alert, :detection_metadata, %{}),
      inserted_at: Map.get(alert, :inserted_at),
      event_type: "alert"
    }
  end
end
