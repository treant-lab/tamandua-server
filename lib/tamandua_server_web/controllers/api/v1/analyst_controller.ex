defmodule TamanduaServerWeb.API.V1.AnalystController do
  @moduledoc """
  Agentic Analyst (Purple AI) endpoints for autonomous security investigations,
  automated triage, and AI-assisted threat analysis.
  """
  use TamanduaServerWeb, :controller

  alias TamanduaServer.AISecurity.AgenticAnalyst

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  Start a new autonomous investigation.

  The agentic analyst will autonomously investigate the specified target,
  gathering evidence, correlating events, and building a timeline.

  ## Parameters
    - trigger: The trigger for investigation (alert_id, event_id, ioc, or custom)
    - trigger_id: ID of the triggering entity
    - investigation_type: Type of investigation (incident, threat_hunt, forensic)
    - parameters: Additional investigation parameters
  """
  def start_investigation(conn, params) do
    with {:ok, trigger} <- fetch_required(params, "trigger"),
         {:ok, trigger_id} <- fetch_required(params, "trigger_id") do
      investigation_type = Map.get(params, "investigation_type", "incident")
      investigation_params = Map.get(params, "parameters", %{})

      opts = [
        trigger: trigger,
        trigger_id: trigger_id,
        investigation_type: investigation_type,
        parameters: investigation_params
      ]

      case AgenticAnalyst.start_investigation(opts) do
        {:ok, investigation} ->
          conn
          |> put_status(:created)
          |> json(%{
            status: "success",
            data: %{
              investigation_id: investigation.id,
              status: investigation.status,
              started_at: investigation.started_at,
              estimated_completion: investigation.estimated_completion
            }
          })

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  @doc """
  List all investigations with optional filters.

  ## Parameters
    - status: Filter by status (active, completed, paused, failed)
    - investigation_type: Filter by type
    - limit: Number of results (default 50)
    - offset: Pagination offset
  """
  def list_investigations(conn, params) do
    filters = %{
      status: Map.get(params, "status"),
      investigation_type: Map.get(params, "investigation_type"),
      limit: Map.get(params, "limit", 50),
      offset: Map.get(params, "offset", 0)
    }

    with {:ok, investigations} <- AgenticAnalyst.list_investigations(filters) do
      json(conn, %{
        status: "success",
        data: %{
          investigations: investigations.items,
          total: investigations.total,
          limit: filters.limit,
          offset: filters.offset
        }
      })
    end
  end

  @doc """
  Get detailed information about a specific investigation.

  ## Parameters
    - id: The investigation ID (path parameter)
    - include_evidence: Whether to include collected evidence
    - include_timeline: Whether to include event timeline
  """
  def investigation_detail(conn, %{"id" => investigation_id} = params) do
    include_evidence = Map.get(params, "include_evidence", true)
    include_timeline = Map.get(params, "include_timeline", true)

    opts = [
      include_evidence: include_evidence,
      include_timeline: include_timeline
    ]

    with {:ok, investigation} <- AgenticAnalyst.get_investigation(investigation_id, opts) do
      json(conn, %{
        status: "success",
        data: investigation
      })
    end
  end

  def investigation_detail(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{status: "error", message: "investigation id is required"})
  end

  @doc """
  Submit analyst feedback on an investigation or its findings.

  This feedback is used to improve the agentic analyst's decision-making
  and is crucial for continuous learning.

  ## Parameters
    - investigation_id: The investigation to provide feedback on
    - feedback_type: Type of feedback (accuracy, relevance, completeness, false_positive)
    - rating: Numeric rating (1-5)
    - comments: Optional detailed comments
    - corrections: Optional corrections to findings
  """
  def analyst_feedback(conn, %{"investigation_id" => investigation_id} = params) do
    with {:ok, feedback_type} <- fetch_required(params, "feedback_type"),
         {:ok, rating} <- fetch_required(params, "rating") do
      feedback = %{
        investigation_id: investigation_id,
        feedback_type: feedback_type,
        rating: rating,
        comments: Map.get(params, "comments"),
        corrections: Map.get(params, "corrections", %{}),
        submitted_by: conn.assigns[:current_user]
      }

      case AgenticAnalyst.submit_feedback(feedback) do
        {:ok, result} ->
          json(conn, %{
            status: "success",
            data: %{
              feedback_id: result.feedback_id,
              acknowledged: true,
              impact_assessment: result.impact_assessment
            }
          })

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  def analyst_feedback(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{status: "error", message: "investigation_id is required"})
  end

  @doc """
  Trigger automatic triage on pending alerts.

  The agentic analyst will automatically classify, prioritize, and
  optionally begin investigating alerts based on severity and context.

  ## Parameters
    - alert_ids: Optional list of specific alert IDs to triage
    - auto_investigate: Whether to auto-start investigations for critical findings
    - max_alerts: Maximum number of alerts to process (default 100)
  """
  def auto_triage(conn, params) do
    alert_ids = Map.get(params, "alert_ids")
    auto_investigate = Map.get(params, "auto_investigate", false)
    max_alerts = Map.get(params, "max_alerts", 100)

    opts = [
      auto_investigate: auto_investigate,
      max_alerts: max_alerts
    ]

    opts = if alert_ids, do: Keyword.put(opts, :alert_ids, alert_ids), else: opts

    with {:ok, triage_result} <- AgenticAnalyst.auto_triage(opts) do
      json(conn, %{
        status: "success",
        data: %{
          processed_count: triage_result.processed_count,
          classifications: triage_result.classifications,
          started_investigations: triage_result.started_investigations,
          suppressed_count: triage_result.suppressed_count,
          processing_time_ms: triage_result.processing_time_ms
        }
      })
    end
  end

  # Private helpers

  defp fetch_required(params, key) do
    case Map.fetch(params, key) do
      {:ok, value} when not is_nil(value) and value != "" -> {:ok, value}
      _ -> {:error, :missing_required_param, key}
    end
  end
end
