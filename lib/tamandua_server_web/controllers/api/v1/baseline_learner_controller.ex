defmodule TamanduaServerWeb.API.V1.BaselineLearnerController do
  @moduledoc """
  API controller for the Behavioral Baseline Learning and User Risk Scoring system.

  Provides REST endpoints for:
  - Baseline learner statistics and entity baselines
  - User risk scores and risk history
  - High-risk entity listing
  - User profiles and peer group information
  """

  use TamanduaServerWeb, :controller
  require Logger

  alias TamanduaServer.Detection.BaselineLearner
  alias TamanduaServer.Identity.RiskEngine
  alias TamanduaServer.Identity.UserProfiler
  alias TamanduaServer.Identity.PeerClustering

  action_fallback TamanduaServerWeb.FallbackController

  # ============================================================================
  # Baseline Learner Endpoints
  # ============================================================================

  @doc """
  GET /api/v1/baselines/stats

  Get overall baseline learning statistics.
  """
  def baseline_stats(conn, _params) do
    stats = BaselineLearner.stats()
    json(conn, %{status: "success", data: stats})
  end

  @doc """
  GET /api/v1/baselines/:entity_type/:entity_id

  Get the learned baseline for a specific entity.
  """
  def show_baseline(conn, %{"entity_type" => entity_type_str, "entity_id" => entity_id}) do
    entity_type = parse_entity_type(entity_type_str)

    case BaselineLearner.get_baseline(entity_type, entity_id) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{status: "error", message: "No baseline found for #{entity_type_str}/#{entity_id}"})

      baseline ->
        json(conn, %{
          status: "success",
          data: serialize_baseline(baseline)
        })
    end
  end

  @doc """
  POST /api/v1/baselines/:entity_type/:entity_id/reset

  Reset the baseline for a specific entity.
  """
  def reset_baseline(conn, %{"entity_type" => entity_type_str, "entity_id" => entity_id}) do
    entity_type = parse_entity_type(entity_type_str)
    BaselineLearner.reset_baseline(entity_type, entity_id)
    json(conn, %{status: "success", message: "Baseline reset for #{entity_type_str}/#{entity_id}"})
  end

  @doc """
  POST /api/v1/baselines/:entity_type/:entity_id/mode

  Set the learning mode for an entity.
  Body: {"mode": "learning" | "active" | "frozen"}
  """
  def set_mode(conn, %{"entity_type" => entity_type_str, "entity_id" => entity_id, "mode" => mode_str}) do
    entity_type = parse_entity_type(entity_type_str)

    mode =
      safe_to_existing_atom(mode_str, ~w(learning active frozen))

    if mode do
      BaselineLearner.set_mode(entity_type, entity_id, mode)
      json(conn, %{status: "success", message: "Mode set to #{mode_str}"})
    else
      conn
      |> put_status(:bad_request)
      |> json(%{status: "error", message: "Invalid mode. Must be one of: learning, active, frozen"})
    end
  end

  def set_mode(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{status: "error", message: "Missing required 'mode' parameter"})
  end

  @doc """
  POST /api/v1/baselines/:entity_type/:entity_id/check

  Check an observation against the baseline for anomalies.
  Body: {"features": {"key": value, ...}}
  """
  def check_anomaly(conn, %{"entity_type" => entity_type_str, "entity_id" => entity_id, "features" => features})
      when is_map(features) do
    entity_type = parse_entity_type(entity_type_str)
    {status, score, details} = BaselineLearner.check_anomaly(entity_type, entity_id, features)

    json(conn, %{
      status: "success",
      data: %{
        result: to_string(status),
        anomaly_score: score,
        details: details
      }
    })
  end

  def check_anomaly(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{status: "error", message: "Missing required 'features' map in request body"})
  end

  # ============================================================================
  # Risk Engine Endpoints
  # ============================================================================

  @doc """
  GET /api/v1/identity/risk/:entity_type/:entity_id

  Get the risk score for an entity.
  """
  def get_risk(conn, %{"entity_type" => entity_type_str, "entity_id" => entity_id}) do
    entity_type = parse_entity_type(entity_type_str)
    risk = RiskEngine.calculate_risk(entity_type, entity_id)

    json(conn, %{
      status: "success",
      data: serialize_risk(risk, entity_type, entity_id)
    })
  end

  @doc """
  GET /api/v1/identity/risk/high-risk

  List all high-risk entities.
  Query params: threshold (default: 75)
  """
  def high_risk_entities(conn, params) do
    threshold = parse_int(params["threshold"], 75)
    entities = RiskEngine.get_high_risk_entities(threshold)

    json(conn, %{
      status: "success",
      data: Enum.map(entities, fn e ->
        serialize_risk(e, e.entity_type, e.entity_id)
      end),
      meta: %{threshold: threshold, count: length(entities)}
    })
  end

  @doc """
  GET /api/v1/identity/risk/:entity_type/:entity_id/history

  Get risk score history for an entity.
  Query params: hours (default: 24), limit (default: 100)
  """
  def risk_history(conn, %{"entity_type" => entity_type_str, "entity_id" => entity_id} = params) do
    entity_type = parse_entity_type(entity_type_str)
    hours = parse_int(params["hours"], 24)
    limit = parse_int(params["limit"], 100)

    history = RiskEngine.get_risk_history(entity_type, entity_id, hours: hours, limit: limit)

    json(conn, %{
      status: "success",
      data: Enum.map(history, fn entry ->
        %{
          score: entry.score,
          timestamp: format_datetime(entry.timestamp)
        }
      end),
      meta: %{
        entity_type: entity_type_str,
        entity_id: entity_id,
        hours: hours,
        count: length(history)
      }
    })
  end

  @doc """
  GET /api/v1/identity/risk/:entity_type/:entity_id/trend

  Get the risk trend for an entity.
  """
  def risk_trend(conn, %{"entity_type" => entity_type_str, "entity_id" => entity_id}) do
    entity_type = parse_entity_type(entity_type_str)
    trend = RiskEngine.get_risk_trend(entity_type, entity_id)

    json(conn, %{
      status: "success",
      data: %{
        entity_type: entity_type_str,
        entity_id: entity_id,
        trend: to_string(trend)
      }
    })
  end

  @doc """
  GET /api/v1/identity/risk/stats

  Get risk engine statistics.
  """
  def risk_stats(conn, _params) do
    stats = RiskEngine.stats()
    json(conn, %{status: "success", data: stats})
  end

  # ============================================================================
  # User Profile Endpoints
  # ============================================================================

  @doc """
  GET /api/v1/identity/users/:user_id/profile

  Get the behavioral profile for a user.
  """
  def user_profile(conn, %{"user_id" => user_id}) do
    case UserProfiler.get_profile(user_id) do
      {:ok, profile} ->
        json(conn, %{
          status: "success",
          data: serialize_profile(profile, user_id)
        })

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{status: "error", message: "No profile found for user #{user_id}"})
    end
  end

  @doc """
  GET /api/v1/identity/users/:user_id/peer-group

  Get peer group information for a user.
  """
  def peer_group(conn, %{"user_id" => user_id}) do
    case UserProfiler.get_peer_group(user_id) do
      {:ok, cluster} ->
        json(conn, %{
          status: "success",
          data: %{
            user_id: user_id,
            cluster: cluster
          }
        })

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{status: "error", message: "No peer group assigned for user #{user_id}"})
    end
  end

  @doc """
  POST /api/v1/identity/users/:user_id/assign-peer-group

  Assign a user to a peer group based on attributes.
  Body: {"department": "...", "role": "..."}
  """
  def assign_peer_group(conn, %{"user_id" => user_id} = params) do
    attributes = %{
      department: params["department"],
      role: params["role"],
      machine_type: params["machine_type"],
      organization_id: params["organization_id"]
    }

    case PeerClustering.assign_user(user_id, attributes) do
      {:ok, cluster_id} ->
        json(conn, %{
          status: "success",
          data: %{user_id: user_id, cluster_id: cluster_id}
        })

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{status: "error", message: inspect(reason)})
    end
  end

  @doc """
  GET /api/v1/identity/peer-clusters

  List all peer clusters.
  """
  def list_clusters(conn, _params) do
    clusters = PeerClustering.list_clusters()
    json(conn, %{status: "success", data: clusters})
  end

  @doc """
  GET /api/v1/identity/profiler/stats

  Get user profiler statistics.
  """
  def profiler_stats(conn, _params) do
    stats = UserProfiler.stats()
    json(conn, %{status: "success", data: stats})
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp parse_entity_type(type_str) when is_binary(type_str) do
    allowed = ~w(agent user asset process_execution network_connection file_access authentication dns_query registry_modification)

    safe_to_existing_atom(type_str, allowed) || :agent
  end

  defp serialize_baseline(baseline) do
    %{
      entity_type: to_string(baseline.entity_type),
      entity_id: baseline.entity_id,
      mode: to_string(baseline.mode),
      learning_started_at: format_datetime(baseline.learning_started_at),
      events_processed: baseline.events_processed,
      learning_days: baseline.learning_days,
      statistics: baseline.statistics,
      histograms: baseline.histograms,
      categoricals: baseline.categoricals
    }
  end

  defp serialize_risk(risk, entity_type, entity_id) do
    %{
      entity_type: to_string(entity_type),
      entity_id: entity_id,
      score: risk.score,
      tier: to_string(risk.tier),
      factors: risk.factors,
      trending: to_string(risk[:trending] || risk[:trend] || :stable),
      calculated_at: format_datetime(risk[:calculated_at])
    }
  end

  defp serialize_profile(profile, user_id) do
    login_total = Enum.sum(Map.values(profile.login_hours))

    %{
      user_id: user_id,
      login_hours: profile.login_hours,
      login_total: login_total,
      process_count: map_size(profile.process_frequency),
      top_processes:
        profile.process_frequency
        |> Enum.sort_by(fn {_k, v} -> v end, :desc)
        |> Enum.take(20)
        |> Enum.map(fn {name, count} -> %{name: name, count: count} end),
      network_destinations_count: map_size(profile.network_destinations),
      top_destinations:
        profile.network_destinations
        |> Enum.sort_by(fn {_k, v} -> v end, :desc)
        |> Enum.take(20)
        |> Enum.map(fn {dest, count} -> %{destination: dest, count: count} end),
      file_extensions: profile.file_extensions,
      auth_patterns: profile.auth_patterns,
      privilege_usage: %{
        count: profile.privilege_usage.count,
        last_at: format_datetime(profile.privilege_usage.last_at)
      }
    }
  end

  defp format_datetime(nil), do: nil
  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)

  defp parse_int(nil, default), do: default

  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> default
    end
  end

  defp parse_int(value, _default) when is_integer(value), do: value
end
