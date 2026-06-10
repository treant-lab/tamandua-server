defmodule TamanduaServerWeb.API.V1.ForensicsInvestigationController do
  @moduledoc """
  Forensic Investigation API controller.

  Provides endpoints for managing full-lifecycle forensic investigations,
  including investigation creation, timeline reconstruction, artifact
  collection, evidence tracking, and report generation.

  ## Endpoints
    - POST   /api/v1/forensics/investigations                      - Create investigation
    - GET    /api/v1/forensics/investigations                      - List investigations
    - GET    /api/v1/forensics/investigations/stats                - Investigation statistics
    - GET    /api/v1/forensics/investigations/:id                  - Get investigation details
    - PUT    /api/v1/forensics/investigations/:id/state            - Transition state
    - GET    /api/v1/forensics/investigations/:id/timeline         - Get unified timeline
    - POST   /api/v1/forensics/investigations/:id/collect          - Request artifact collection
    - GET    /api/v1/forensics/investigations/:id/evidence         - List collected evidence
    - POST   /api/v1/forensics/investigations/:id/evidence         - Record new evidence
    - POST   /api/v1/forensics/investigations/:id/notes            - Add investigation note
    - POST   /api/v1/forensics/investigations/:id/report           - Generate forensic report
    - PUT    /api/v1/forensics/investigations/:id/close            - Close investigation
  """
  use TamanduaServerWeb, :controller

  alias TamanduaServer.Forensics.Engine

  action_fallback TamanduaServerWeb.FallbackController

  # ── Create Investigation ────────────────────────────────────────────

  @doc """
  Create a new forensic investigation.

  ## Parameters
    - title (required): Investigation title
    - description: Detailed description
    - alert_ids: List of alert IDs to link
    - agent_ids: List of agent IDs under investigation
    - priority: "low", "medium", "high", "critical"
    - assigned_to: User ID of lead investigator
    - tags: List of tags
  """
  def create(conn, %{"title" => _title} = params) do
    user_id = get_current_user_id(conn)
    params = Map.put(params, "created_by", user_id)

    case Engine.create_investigation(params) do
      {:ok, investigation} ->
        conn
        |> put_status(:created)
        |> json(%{data: serialize_investigation(investigation)})

      {:error, :title_required} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Title is required"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: inspect(reason)})
    end
  end

  def create(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required parameter: title"})
  end

  # ── List Investigations ─────────────────────────────────────────────

  @doc """
  List investigations with optional filters.

  ## Query Parameters
    - status: Filter by state (open, collecting, analyzing, reporting, closed)
    - priority: Filter by priority
    - assigned_to: Filter by assigned user
    - agent_id: Filter by linked agent
    - alert_id: Filter by linked alert
    - limit: Max results (default 50)
    - offset: Pagination offset
  """
  def index(conn, params) do
    filters = %{
      "status" => Map.get(params, "status"),
      "priority" => Map.get(params, "priority"),
      "assigned_to" => Map.get(params, "assigned_to"),
      "agent_id" => Map.get(params, "agent_id"),
      "alert_id" => Map.get(params, "alert_id"),
      "limit" => Map.get(params, "limit", "50"),
      "offset" => Map.get(params, "offset", "0")
    }
    |> reject_nil()

    case Engine.list_investigations(filters) do
      {:ok, investigations} ->
        json(conn, %{
          data: Enum.map(investigations, &serialize_investigation/1),
          meta: %{count: length(investigations)}
        })
    end
  end

  # ── Show Investigation ──────────────────────────────────────────────

  @doc """
  Get investigation details by ID.
  """
  def show(conn, %{"id" => id}) do
    case Engine.get_investigation(id) do
      {:ok, investigation} ->
        json(conn, %{data: serialize_investigation_detail(investigation)})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Investigation not found"})
    end
  end

  # ── Transition State ────────────────────────────────────────────────

  @doc """
  Transition an investigation to a new state.

  ## Parameters
    - state (required): Target state
    - reason: Reason for transition
  """
  def update_state(conn, %{"id" => id, "state" => new_state} = params) do
    user_id = get_current_user_id(conn)
    opts = %{
      "user_id" => user_id,
      "reason" => Map.get(params, "reason", "")
    }

    case Engine.transition_state(id, new_state, opts) do
      {:ok, investigation} ->
        json(conn, %{data: serialize_investigation(investigation)})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Investigation not found"})

      {:error, {:invalid_transition, from, to}} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Invalid state transition from '#{from}' to '#{to}'"})

      {:error, {:invalid_state, state}} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Invalid state: #{state}"})
    end
  end

  def update_state(conn, %{"id" => _id}) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required parameter: state"})
  end

  # ── Get Timeline ────────────────────────────────────────────────────

  @doc """
  Get the unified timeline for an investigation.

  Merges events from all linked agents across all telemetry sources.

  ## Query Parameters
    - from: Start time (ISO8601)
    - to: End time (ISO8601)
    - event_types: Comma-separated event types
    - process_filter: Filter by process name
    - user_filter: Filter by username
    - severity_filter: Minimum severity
    - limit: Max events (default 2000)
    - format: "json" or "csv"
  """
  def timeline(conn, %{"id" => id} = params) do
    opts = %{
      from: Map.get(params, "from"),
      to: Map.get(params, "to"),
      event_types: parse_list(Map.get(params, "event_types")),
      process_filter: Map.get(params, "process_filter"),
      user_filter: Map.get(params, "user_filter"),
      severity_filter: Map.get(params, "severity_filter"),
      limit: parse_int(Map.get(params, "limit"), 2000),
      format: Map.get(params, "format", "json")
    }

    case Engine.get_timeline(id, opts) do
      {:ok, timeline} ->
        format = Map.get(params, "format", "json")

        if format == "csv" do
          csv_data = TamanduaServer.Forensics.Timeline.export_csv(timeline.events)

          conn
          |> put_resp_content_type("text/csv")
          |> put_resp_header("content-disposition", "attachment; filename=\"timeline_#{id}.csv\"")
          |> send_resp(200, csv_data)
        else
          json(conn, %{
            data: %{
              events: timeline.events,
              total_events: timeline.total_events,
              from: format_datetime(timeline.from),
              to: format_datetime(timeline.to),
              event_type_distribution: timeline.event_type_distribution,
              agent_distribution: timeline[:agent_distribution],
              notable_events: Enum.take(timeline.notable_events, 50),
              temporal_patterns: timeline.temporal_patterns
            }
          })
        end

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Investigation not found"})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Timeline generation failed: #{inspect(reason)}"})
    end
  end

  # ── Request Artifact Collection ─────────────────────────────────────

  @doc """
  Request specific forensic artifacts from an agent.

  ## Parameters
    - agent_id (required): Target agent
    - artifact_types (required): List of artifact types
    - process_pid: For targeted process memory dump
    - paths: Specific file paths to collect
    - time_range: Time range for event logs
  """
  def collect(conn, %{"id" => id, "agent_id" => agent_id, "artifact_types" => types} = params) do
    user_id = get_current_user_id(conn)

    opts = %{
      "requested_by" => user_id,
      "process_pid" => Map.get(params, "process_pid"),
      "paths" => Map.get(params, "paths", []),
      "time_range" => Map.get(params, "time_range")
    }

    types = if is_list(types), do: types, else: [types]

    case Engine.request_artifacts(id, agent_id, types, opts) do
      {:ok, request} ->
        conn
        |> put_status(:accepted)
        |> json(%{
          data: serialize_collection_request(request),
          message: "Artifact collection initiated"
        })

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Investigation not found"})

      {:error, {:invalid_artifact_types, invalid}} ->
        conn
        |> put_status(:bad_request)
        |> json(%{
          error: "Invalid artifact types: #{Enum.join(invalid, ", ")}",
          valid_types: Engine.artifact_types()
        })

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: inspect(reason)})
    end
  end

  def collect(conn, %{"id" => _id}) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required parameters: agent_id and artifact_types"})
  end

  # ── List Evidence ───────────────────────────────────────────────────

  @doc """
  List all evidence collected for an investigation.
  """
  def list_evidence(conn, %{"id" => id}) do
    case Engine.list_evidence(id) do
      {:ok, evidence} ->
        json(conn, %{
          data: Enum.map(evidence, &serialize_evidence/1),
          meta: %{count: length(evidence)}
        })

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Investigation not found"})
    end
  end

  # ── Record Evidence ─────────────────────────────────────────────────

  @doc """
  Record new evidence for an investigation.

  ## Parameters
    - type (required): Evidence type
    - source_agent_id: Agent that provided it
    - hash_sha256: SHA-256 hash
    - hash_md5: MD5 hash
    - size_bytes: Size in bytes
    - storage_path: Where evidence is stored
    - description: Description
  """
  def record_evidence(conn, %{"id" => id} = params) do
    user_id = get_current_user_id(conn)

    evidence_data = %{
      "type" => Map.get(params, "type", "unknown"),
      "source_agent_id" => Map.get(params, "source_agent_id"),
      "hash_sha256" => Map.get(params, "hash_sha256"),
      "hash_md5" => Map.get(params, "hash_md5"),
      "size_bytes" => Map.get(params, "size_bytes"),
      "storage_path" => Map.get(params, "storage_path"),
      "description" => Map.get(params, "description"),
      "collected_by" => user_id,
      "metadata" => Map.get(params, "metadata", %{})
    }

    case Engine.record_evidence(id, evidence_data) do
      {:ok, evidence} ->
        conn
        |> put_status(:created)
        |> json(%{data: serialize_evidence(evidence)})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Investigation not found"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: inspect(reason)})
    end
  end

  # ── Add Note ────────────────────────────────────────────────────────

  @doc """
  Add a note to the investigation.

  ## Parameters
    - content (required): Note content
  """
  def add_note(conn, %{"id" => id, "content" => content}) do
    user_id = get_current_user_id(conn) || "anonymous"

    case Engine.add_note(id, user_id, content) do
      {:ok, investigation} ->
        json(conn, %{
          data: serialize_investigation(investigation),
          message: "Note added"
        })

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Investigation not found"})
    end
  end

  def add_note(conn, %{"id" => _id}) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required parameter: content"})
  end

  # ── Generate Report ─────────────────────────────────────────────────

  @doc """
  Generate a forensic report for the investigation.

  ## Parameters
    - format: Report format ("json" default)
  """
  def report(conn, %{"id" => id} = params) do
    opts = %{
      format: Map.get(params, "format", "json")
    }

    case Engine.generate_report(id, opts) do
      {:ok, report} ->
        json(conn, %{data: report})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Investigation not found"})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Report generation failed: #{inspect(reason)}"})
    end
  end

  # ── Close Investigation ─────────────────────────────────────────────

  @doc """
  Close an investigation with a final summary.

  ## Parameters
    - verdict: Final verdict
    - summary: Summary text
    - findings: List of findings
  """
  def close(conn, %{"id" => id} = params) do
    summary = %{
      verdict: Map.get(params, "verdict"),
      summary: Map.get(params, "summary"),
      findings: Map.get(params, "findings", []),
      closed_by: get_current_user_id(conn)
    }

    case Engine.close_investigation(id, summary) do
      {:ok, investigation} ->
        json(conn, %{
          data: serialize_investigation(investigation),
          message: "Investigation closed"
        })

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Investigation not found"})
    end
  end

  # ── Statistics ──────────────────────────────────────────────────────

  @doc """
  Get investigation statistics.
  """
  def stats(conn, _params) do
    stats = Engine.get_stats()
    json(conn, %{data: stats})
  end

  # ── Private: Serialization ──────────────────────────────────────────

  defp serialize_investigation(inv) do
    %{
      id: inv.id,
      title: inv.title,
      description: inv.description,
      status: inv.status,
      priority: inv.priority,
      alert_ids: inv.alert_ids,
      agent_ids: inv.agent_ids,
      assigned_to: inv.assigned_to,
      created_by: inv.created_by,
      tags: inv.tags,
      evidence_count: inv.evidence_count,
      artifact_request_count: length(inv.artifact_requests),
      created_at: format_datetime(inv.created_at),
      updated_at: format_datetime(inv.updated_at),
      closed_at: format_datetime(inv.closed_at)
    }
  end

  defp serialize_investigation_detail(inv) do
    %{
      id: inv.id,
      title: inv.title,
      description: inv.description,
      status: inv.status,
      priority: inv.priority,
      alert_ids: inv.alert_ids,
      agent_ids: inv.agent_ids,
      assigned_to: inv.assigned_to,
      created_by: inv.created_by,
      tags: inv.tags,
      notes: inv.notes,
      findings: inv.findings,
      summary: inv.summary,
      evidence_count: inv.evidence_count,
      artifact_requests: Enum.map(inv.artifact_requests, &serialize_collection_request/1),
      activity_log: inv.activity_log,
      created_at: format_datetime(inv.created_at),
      updated_at: format_datetime(inv.updated_at),
      closed_at: format_datetime(inv.closed_at)
    }
  end

  defp serialize_collection_request(req) do
    %{
      id: req.id,
      investigation_id: req.investigation_id,
      agent_id: req.agent_id,
      artifact_types: req.artifact_types,
      status: req.status,
      requested_by: req.requested_by,
      requested_at: format_datetime(req.requested_at)
    }
  end

  defp serialize_evidence(ev) do
    %{
      id: ev.id,
      investigation_id: ev.investigation_id,
      type: ev.type,
      source_agent_id: ev.source_agent_id,
      hash_sha256: ev.hash_sha256,
      hash_md5: ev.hash_md5,
      size_bytes: ev.size_bytes,
      storage_path: ev.storage_path,
      description: ev.description,
      collected_by: ev.collected_by,
      collected_at: format_datetime(ev.collected_at),
      chain_of_custody: ev.chain_of_custody,
      metadata: ev.metadata
    }
  end

  # ── Private: Helpers ────────────────────────────────────────────────

  defp get_current_user_id(conn) do
    case conn.assigns[:current_user] do
      nil -> nil
      user -> user.id
    end
  end

  defp format_datetime(nil), do: nil
  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp format_datetime(%NaiveDateTime{} = dt), do: NaiveDateTime.to_iso8601(dt)
  defp format_datetime(other), do: to_string(other)

  defp parse_list(nil), do: nil
  defp parse_list(list) when is_list(list), do: list
  defp parse_list(str) when is_binary(str) do
    str
    |> String.split(",")
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
  end

  defp parse_int(nil, default), do: default
  defp parse_int(v, _default) when is_integer(v), do: v
  defp parse_int(v, default) when is_binary(v) do
    case Integer.parse(v) do
      {n, _} -> n
      :error -> default
    end
  end
  defp parse_int(_, default), do: default

  defp reject_nil(map) do
    map
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Map.new()
  end
end
