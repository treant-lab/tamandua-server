defmodule TamanduaServerWeb.API.V1.PredictiveController do
  @moduledoc """
  Controller for Predictive Shielding API endpoints.

  Provides risk forecasting, attack path analysis, attack simulation,
  and hardening recommendations.
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.AISecurity.PredictiveShield

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  Generate a risk forecast based on current threat landscape and asset state.
  """
  def risk_forecast(conn, params) do
    agent_id = Map.get(params, "agent_id")

    if is_nil(agent_id) do
      conn
      |> put_status(:bad_request)
      |> json(%{error: %{message: "agent_id is required"}})
    else
      # generate_risk_forecast/1 takes agent_id and returns hourly forecast data
      case PredictiveShield.generate_risk_forecast(agent_id) do
        {:ok, forecast_points} ->
          json(conn, %{
            data: %{
              agent_id: agent_id,
              forecast: Enum.map(forecast_points, fn point ->
                %{
                  hour: point.hour,
                  timestamp: point.timestamp,
                  predicted_risk: point.predicted_risk,
                  confidence: point.confidence
                }
              end),
              generated_at: DateTime.utc_now()
            }
          })

        {:error, :insufficient_data} ->
          conn
          |> put_status(:unprocessable_entity)
          |> json(%{error: %{message: "Insufficient historical data for accurate forecast"}})

        {:error, reason} ->
          conn
          |> put_status(:internal_server_error)
          |> json(%{error: %{message: "Failed to generate risk forecast", details: reason}})
      end
    end
  end

  @doc """
  Analyze potential attack paths to critical assets.
  """
  def attack_paths(conn, params) do
    agent_id = Map.get(params, "agent_id")

    if is_nil(agent_id) do
      conn
      |> put_status(:bad_request)
      |> json(%{error: %{message: "agent_id is required"}})
    else
      # predict_attack_paths/1 takes agent_id and returns list of attack paths
      case PredictiveShield.predict_attack_paths(agent_id) do
        {:ok, paths} ->
          json(conn, %{
            data: %{
              agent_id: agent_id,
              attack_paths: Enum.map(paths, fn path ->
                %{
                  tactics: path.tactics,
                  probability: path.probability,
                  techniques: path.techniques,
                  mitigations: path.mitigations,
                  severity: path.severity
                }
              end),
              total_paths: length(paths),
              analyzed_at: DateTime.utc_now()
            }
          })

        {:error, :not_found} ->
          conn
          |> put_status(:not_found)
          |> json(%{error: %{message: "Agent not found"}})

        {:error, reason} ->
          conn
          |> put_status(:internal_server_error)
          |> json(%{error: %{message: "Failed to analyze attack paths", details: reason}})
      end
    end
  end

  @doc """
  Simulate an attack scenario to test defenses.
  """
  def simulate_attack(conn, params) do
    agent_id = Map.get(params, "agent_id")

    if is_nil(agent_id) do
      conn
      |> put_status(:bad_request)
      |> json(%{error: %{message: "agent_id is required"}})
    else
      # simulate_attack/1 takes agent_id and simulates most likely attack path
      case PredictiveShield.simulate_attack(agent_id) do
        {:ok, result} ->
          json(conn, %{
            data: %{
              agent_id: result.agent_id,
              simulated_path: result.simulated_path,
              tactics_involved: result[:tactics_involved],
              probability: result[:probability],
              severity: result[:severity],
              estimated_time_to_impact: result[:estimated_time_to_impact],
              potential_impact: result[:potential_impact],
              detection_points: result[:detection_points],
              recommended_mitigations: result[:recommended_mitigations],
              message: result[:message],
              simulation_timestamp: result.simulation_timestamp
            }
          })

        {:error, :not_found} ->
          conn
          |> put_status(:not_found)
          |> json(%{error: %{message: "Agent not found"}})

        {:error, reason} ->
          conn
          |> put_status(:internal_server_error)
          |> json(%{error: %{message: "Failed to run attack simulation", details: reason}})
      end
    end
  end

  @doc """
  Generate hardening recommendations based on current security posture.
  """
  def hardening_recommendations(conn, params) do
    agent_id = Map.get(params, "agent_id")

    if is_nil(agent_id) do
      conn
      |> put_status(:bad_request)
      |> json(%{error: %{message: "agent_id is required"}})
    else
      # get_mitigation_recommendations/1 takes agent_id
      case PredictiveShield.get_mitigation_recommendations(agent_id) do
        {:ok, recommendations} ->
          json(conn, %{
            data: %{
              agent_id: agent_id,
              recommendations: Enum.map(recommendations, fn rec ->
                %{
                  id: rec.id,
                  action: rec.action,
                  priority: rec.priority,
                  automated: rec[:automated] || false
                }
              end),
              total_count: length(recommendations),
              generated_at: DateTime.utc_now()
            }
          })

        {:error, reason} ->
          conn
          |> put_status(:internal_server_error)
          |> json(%{error: %{message: "Failed to generate hardening recommendations", details: reason}})
      end
    end
  end
end
