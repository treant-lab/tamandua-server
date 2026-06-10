defmodule TamanduaServerWeb.API.V1.DynamicDetectionController do
  @moduledoc """
  Controller for Dynamic Threat Detection API endpoints.

  Provides proactive threat hunting, blind spot analysis, and false negative detection.
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Detection.DynamicHunter

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  Get the current status of the dynamic detection system.
  """
  def status(conn, _params) do
    case DynamicHunter.status() do
      {:ok, status} ->
        json(conn, %{data: status})

      {:error, reason} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{error: %{message: "Failed to get detection status", details: reason}})
    end
  end

  @doc """
  Initiate a proactive threat hunt based on provided parameters.
  """
  def proactive_hunt(conn, params) do
    hunt_params = %{
      scope: Map.get(params, "scope", "all"),
      indicators: Map.get(params, "indicators", []),
      time_range: Map.get(params, "time_range", "24h"),
      techniques: Map.get(params, "techniques", []),
      priority: Map.get(params, "priority", "normal")
    }

    case DynamicHunter.proactive_hunt(hunt_params) do
      {:ok, hunt_result} ->
        conn
        |> put_status(:ok)
        |> json(%{
          data: %{
            hunt_id: hunt_result.id,
            status: hunt_result.status,
            findings: hunt_result.findings,
            started_at: hunt_result.started_at,
            scope: hunt_result.scope
          }
        })

      {:error, :invalid_scope} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: %{message: "Invalid hunt scope provided"}})

      {:error, :hunt_in_progress} ->
        conn
        |> put_status(:conflict)
        |> json(%{error: %{message: "A hunt is already in progress"}})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: %{message: "Failed to initiate threat hunt", details: reason}})
    end
  end

  @doc """
  Identify blind spots in the current detection coverage.
  """
  def blind_spots(conn, params) do
    options = %{
      mitre_techniques: Map.get(params, "mitre_techniques", true),
      data_sources: Map.get(params, "data_sources", true),
      time_gaps: Map.get(params, "time_gaps", true),
      agent_coverage: Map.get(params, "agent_coverage", true)
    }

    case DynamicHunter.analyze_blind_spots(options) do
      {:ok, analysis} ->
        json(conn, %{
          data: %{
            blind_spots: analysis.blind_spots,
            coverage_score: analysis.coverage_score,
            recommendations: analysis.recommendations,
            uncovered_techniques: analysis.uncovered_techniques,
            missing_data_sources: analysis.missing_data_sources,
            analyzed_at: analysis.analyzed_at
          }
        })

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: %{message: "Failed to analyze blind spots", details: reason}})
    end
  end

  @doc """
  Analyze potential false negatives in past detections.
  """
  def false_negatives(conn, params) do
    options = %{
      time_range: Map.get(params, "time_range", "7d"),
      confidence_threshold: Map.get(params, "confidence_threshold", 0.7),
      include_dismissed: Map.get(params, "include_dismissed", false),
      techniques: Map.get(params, "techniques", [])
    }

    case DynamicHunter.find_false_negatives(options) do
      {:ok, results} ->
        json(conn, %{
          data: %{
            potential_false_negatives: results.findings,
            total_count: results.total_count,
            high_confidence_count: results.high_confidence_count,
            analysis_period: results.analysis_period,
            recommendations: results.recommendations
          }
        })

      {:error, :invalid_time_range} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: %{message: "Invalid time range specified"}})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: %{message: "Failed to analyze false negatives", details: reason}})
    end
  end
end
