defmodule TamanduaServerWeb.API.V1.AnalystController do
  @moduledoc """
  Agentic Analyst (Purple AI) endpoints for autonomous security investigations,
  automated triage, and AI-assisted threat analysis.
  """
  use TamanduaServerWeb, :controller

  alias TamanduaServer.AISecurity.AgenticAnalyst

  action_fallback(TamanduaServerWeb.FallbackController)

  plug(
    TamanduaServerWeb.Plugs.RBAC,
    [permission: :response_approve]
    when action in [:approve_action]
  )

  plug(
    TamanduaServerWeb.Plugs.RBAC,
    [permission: :investigations_create]
    when action in [:start_investigation, :auto_triage]
  )

  plug(
    TamanduaServerWeb.Plugs.RBAC,
    [permission: :investigations_read]
    when action in [:list_investigations, :investigation_detail]
  )

  plug(
    TamanduaServerWeb.Plugs.RBAC,
    [permission: :investigations_update]
    when action in [:analyst_feedback]
  )

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
    with {:ok, organization_id} <- current_organization_id(conn),
         {:ok, trigger} <- fetch_required(params, "trigger"),
         {:ok, trigger_id} <- fetch_required(params, "trigger_id") do
      investigation_type = Map.get(params, "investigation_type", "incident")
      investigation_params = Map.get(params, "parameters", %{})

      opts = %{
        trigger: trigger,
        trigger_id: trigger_id,
        alert_id: if(trigger in ["alert", "alert_id"], do: trigger_id),
        organization_id: organization_id,
        investigation_type: investigation_type,
        parameters: investigation_params
      }

      case AgenticAnalyst.start_investigation(opts) do
        {:ok, investigation_id} when is_binary(investigation_id) ->
          conn
          |> put_status(:created)
          |> json(%{
            status: "success",
            data: %{
              investigation_id: investigation_id,
              status: "in_progress"
            }
          })

        {:ok, investigation} ->
          conn
          |> put_status(:created)
          |> json(%{
            status: "success",
            data: %{
              investigation_id: Map.get(investigation, :id),
              status:
                investigation_status(
                  Map.get(investigation, :state) || Map.get(investigation, :status)
                ),
              started_at:
                Map.get(investigation, :started_at) || Map.get(investigation, :created_at),
              estimated_completion: Map.get(investigation, :estimated_completion)
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
    with {:ok, organization_id} <- current_organization_id(conn) do
      limit = parse_integer_param(Map.get(params, "limit"), 50)
      offset = parse_integer_param(Map.get(params, "offset"), 0)

      filters = [
        organization_id: organization_id,
        status: Map.get(params, "status"),
        investigation_type: Map.get(params, "investigation_type")
      ]

      investigations = AgenticAnalyst.list_investigations(filters)
      visible_investigations = investigations |> Enum.drop(offset) |> Enum.take(limit)

      json(conn, %{
        status: "success",
        data: %{
          investigations: Enum.map(visible_investigations, &serialize_investigation/1),
          total: length(investigations),
          limit: limit,
          offset: offset
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

    with {:ok, organization_id} <- current_organization_id(conn),
         opts = [
           organization_id: organization_id,
           include_evidence: include_evidence,
           include_timeline: include_timeline
         ],
         {:ok, investigation} <- AgenticAnalyst.get_investigation(investigation_id, opts) do
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
    with {:ok, organization_id} <- current_organization_id(conn),
         {:ok, _investigation} <-
           AgenticAnalyst.get_investigation(investigation_id,
             organization_id: organization_id
           ),
         {:ok, feedback_type} <- fetch_required(params, "feedback_type"),
         {:ok, rating} <- fetch_required(params, "rating") do
      feedback = %{
        investigation_id: investigation_id,
        feedback_type: feedback_type,
        rating: rating,
        comments: Map.get(params, "comments"),
        corrections: Map.get(params, "corrections", %{}),
        submitted_by: conn.assigns[:current_user]
      }

      case AgenticAnalyst.submit_feedback(
             investigation_id,
             Map.delete(feedback, :investigation_id),
             organization_id
           ) do
        :ok ->
          json(conn, %{
            status: "success",
            data: %{
              acknowledged: true,
              investigation_id: investigation_id
            }
          })

        {:ok, result} ->
          json(conn, %{
            status: "success",
            data: %{
              feedback_id: Map.get(result, :feedback_id),
              acknowledged: true,
              impact_assessment: Map.get(result, :impact_assessment)
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
    alert_ids = params |> Map.get("alert_ids", []) |> List.wrap()
    max_alerts =
      params
      |> Map.get("max_alerts")
      |> parse_integer_param(100)
      |> min(100)

    if alert_ids == [] do
      conn
      |> put_status(:bad_request)
      |> json(%{status: "error", message: "alert_ids is required"})
    else
      with {:ok, organization_id} <- current_organization_id(conn) do
        results =
          alert_ids
          |> Enum.take(max_alerts)
          |> Enum.map(fn alert_id ->
            {alert_id, AgenticAnalyst.auto_triage(alert_id, organization_id)}
          end)

        classifications =
          Enum.flat_map(results, fn
            {alert_id, {:ok, result}} -> [Map.put(result, :alert_id, alert_id)]
            _ -> []
          end)

        errors =
          Enum.flat_map(results, fn
            {alert_id, {:error, reason}} -> [%{alert_id: alert_id, reason: inspect(reason)}]
            _ -> []
          end)

        json(conn, %{
          status: "success",
          data: %{
            processed_count: length(results),
            classifications: classifications,
            started_investigations:
              classifications
              |> Enum.map(&Map.get(&1, :investigation_id))
              |> Enum.reject(&is_nil/1),
            suppressed_count: 0,
            errors: errors
          }
        })
      end
    end
  end

  @doc """
  Approve and execute one recommendation using the authenticated analyst identity.
  """
  def approve_action(
        conn,
        %{"id" => investigation_id, "recommendation_id" => recommendation_id}
      ) do
    with :ok <- authorize_response_approval(conn),
         {:ok, organization_id} <- current_organization_id(conn),
         {:ok, approver_id} <- current_approver_id(conn),
         {:ok, result} <-
           AgenticAnalyst.approve_action(
             investigation_id,
             recommendation_id,
             organization_id,
             approver_id
           ) do
      json(conn, %{
        status: "success",
        data: %{
          investigation_id: investigation_id,
          recommendation_id: recommendation_id,
          result: result
        }
      })
    end
  end

  def approve_action(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{status: "error", message: "recommendation_id is required"})
  end

  # Private helpers

  defp parse_integer_param(value, _default) when is_integer(value) and value >= 0, do: value
  defp parse_integer_param(value, default) when is_integer(value), do: max(value, default)

  defp parse_integer_param(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {parsed, _} when parsed >= 0 -> parsed
      _ -> default
    end
  end

  defp parse_integer_param(_value, default), do: default

  defp serialize_investigation(investigation) do
    hypotheses = Map.get(investigation, :hypotheses) || []
    evidence = Map.get(investigation, :evidence) || []
    recommendations = Map.get(investigation, :recommendations) || []
    alert = Map.get(investigation, :alert) || %{}
    state = Map.get(investigation, :state)

    %{
      id: Map.get(investigation, :id),
      alertId: Map.get(investigation, :alert_id),
      title: investigation_title(investigation, alert),
      status: investigation_status(state),
      state: state,
      severity: investigation_severity(alert),
      startedAt: Map.get(investigation, :started_at),
      updatedAt: Map.get(investigation, :updated_at),
      alertCount: if(Map.get(investigation, :alert_id), do: 1, else: 0),
      findings: length(hypotheses) + length(evidence),
      assignedAgent: "Agentic Analyst",
      confidence: Map.get(investigation, :confidence) || 0.0,
      hypothesesCount: length(hypotheses),
      recommendationsCount: length(recommendations),
      triageResult: Map.get(investigation, :triage_result)
    }
  end

  defp investigation_title(investigation, alert) do
    Map.get(alert, :title) ||
      Map.get(alert, "title") ||
      Map.get(investigation, :explanation) ||
      "Investigation #{Map.get(investigation, :id)}"
  end

  defp investigation_status(state) when state in [:awaiting_review, :action_recommendation],
    do: "pending_review"

  defp investigation_status(state) when state in [:completed, :resolved], do: "completed"
  defp investigation_status(_state), do: "active"

  defp investigation_severity(alert) do
    severity = Map.get(alert, :severity) || Map.get(alert, "severity") || "medium"
    severity = severity |> to_string() |> String.downcase()

    if severity in ["critical", "high", "medium", "low"], do: severity, else: "medium"
  end

  defp fetch_required(params, key) do
    case Map.fetch(params, key) do
      {:ok, value} when not is_nil(value) and value != "" -> {:ok, value}
      _ -> {:error, :missing_required_param, key}
    end
  end

  defp current_organization_id(conn) do
    organization_id =
      conn.assigns[:current_organization_id] ||
        current_user_organization_id(conn.assigns[:current_user])

    if is_nil(organization_id),
      do: {:error, :organization_required},
      else: {:ok, organization_id}
  end

  defp current_user_organization_id(%{organization_id: organization_id}), do: organization_id

  defp current_user_organization_id(user) when is_map(user),
    do: user[:organization_id] || user["organization_id"]

  defp current_user_organization_id(_), do: nil

  defp current_approver_id(conn) do
    approver_id =
      case conn.assigns[:current_user] do
        %{id: id} -> id
        user when is_map(user) -> user[:id] || user["id"]
        _ -> nil
      end

    if is_binary(approver_id) and approver_id != "",
      do: {:ok, approver_id},
      else: {:error, :unauthorized}
  end

  defp authorize_response_approval(conn) do
    if TamanduaServer.Accounts.user_can?(conn.assigns[:current_user], :response_approve),
      do: :ok,
      else: {:error, :unauthorized}
  rescue
    _ -> {:error, :unauthorized}
  end
end
