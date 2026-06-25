defmodule TamanduaServerWeb.API.V1.UBAController do
  @moduledoc """
  API endpoints for User Behavior Analytics.
  """

  use TamanduaServerWeb, :controller
  require Logger

  alias TamanduaServer.UBA

  @doc """
  GET /api/v1/uba/risk_scores
  Get risk scores for all users in organization.
  """
  def risk_scores(conn, params) do
    organization_id = conn.assigns.organization_id
    risk_level = params["risk_level"]

    users = if risk_level do
      UBA.get_users_by_risk(risk_level, organization_id)
    else
      UBA.get_top_risky_users(organization_id, 100)
    end

    json(conn, %{
      risk_scores: Enum.map(users, &format_risk_score/1)
    })
  end

  @doc """
  GET /api/v1/uba/users/:user_id/risk
  Get risk score for a specific user.
  """
  def user_risk(conn, %{"user_id" => user_id}) do
    case UBA.get_risk_score(user_id) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Risk score not found"})

      risk_score ->
        json(conn, %{risk_score: format_risk_score(risk_score)})
    end
  end

  @doc """
  GET /api/v1/uba/users/:user_id/baselines
  Get behavioral baselines for a user.
  """
  def user_baselines(conn, %{"user_id" => user_id}) do
    baselines = get_user_baselines(user_id)

    json(conn, %{
      baselines: Enum.map(baselines, &format_baseline/1)
    })
  end

  @doc """
  GET /api/v1/uba/users/:user_id/anomalies
  Get anomalies for a user.
  """
  def user_anomalies(conn, %{"user_id" => user_id} = params) do
    days = bounded_days(params["days"], 7)
    severity = params["severity"]

    opts = [days: days]
    opts = if severity, do: Keyword.put(opts, :severity, severity), else: opts

    anomalies = UBA.get_user_anomalies(user_id, opts)

    json(conn, %{
      anomalies: Enum.map(anomalies, &format_anomaly/1)
    })
  end

  @doc """
  POST /api/v1/uba/users/:user_id/anomalies/:anomaly_id/acknowledge
  Acknowledge an anomaly.
  """
  def acknowledge_anomaly(conn, %{"anomaly_id" => anomaly_id} = params) do
    current_user_id = conn.assigns.current_user.id
    notes = params["notes"]

    case UBA.acknowledge_anomaly(anomaly_id, current_user_id, notes) do
      {:ok, anomaly} ->
        json(conn, %{anomaly: format_anomaly(anomaly)})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Anomaly not found"})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{errors: format_errors(changeset)})
    end
  end

  @doc """
  GET /api/v1/uba/anomalies
  Get unacknowledged anomalies for organization.
  """
  def anomalies(conn, _params) do
    organization_id = conn.assigns.organization_id

    anomalies = UBA.get_unacknowledged_anomalies(organization_id)

    json(conn, %{
      anomalies: Enum.map(anomalies, &format_anomaly/1)
    })
  end

  @doc """
  POST /api/v1/uba/track
  Track a user behavior event.
  """
  def track_behavior(conn, params) do
    user_id = params["user_id"]
    behavior_type = params["behavior_type"]
    metadata = params["metadata"] || %{}

    UBA.track_behavior(user_id, behavior_type, metadata)

    json(conn, %{status: "tracked"})
  end

  @doc """
  POST /api/v1/uba/check_anomalies
  Trigger anomaly check for a user.
  """
  def check_anomalies(conn, %{"user_id" => user_id} = params) do
    behavior_type = params["behavior_type"]

    if behavior_type do
      UBA.check_anomalies(user_id, behavior_type)
    else
      # Check all behaviors for this user
      UBA.check_all_anomalies()
    end

    json(conn, %{status: "checking"})
  end

  @doc """
  POST /api/v1/uba/update_baseline
  Trigger baseline update for a user.
  """
  def update_baseline(conn, %{"user_id" => user_id} = params) do
    behavior_type = params["behavior_type"]

    if behavior_type do
      UBA.update_baseline(user_id, behavior_type)
      json(conn, %{status: "updating", behavior_type: behavior_type})
    else
      # Update all baselines
      UBA.calculate_all_baselines()
      json(conn, %{status: "updating", behavior_type: "all"})
    end
  end

  @doc """
  POST /api/v1/uba/update_risk_score
  Trigger risk score update for a user.
  """
  def update_risk_score(conn, %{"user_id" => user_id}) do
    UBA.update_risk_score(user_id)
    json(conn, %{status: "updating"})
  end

  @doc """
  GET /api/v1/uba/users/:user_id/behavior_stats
  Get behavior statistics for a user.
  """
  def behavior_stats(conn, %{"user_id" => user_id} = params) do
    behavior_type = params["behavior_type"]
    days = bounded_days(params["days"], 30)

    stats = UBA.get_behavior_stats(user_id, behavior_type, days)

    json(conn, %{
      behavior_type: behavior_type,
      days: days,
      stats: stats
    })
  end

  @doc """
  GET /api/v1/uba/users/:user_id/behavior_history
  Get behavior history for a user.
  """
  def behavior_history(conn, %{"user_id" => user_id} = params) do
    behavior_type = params["behavior_type"]
    days = bounded_days(params["days"], 7)
    limit = bounded_limit(params["limit"], 100, 1000)

    behaviors = UBA.get_behavior_history(user_id, behavior_type, days: days, limit: limit)

    json(conn, %{
      behavior_type: behavior_type,
      behaviors: Enum.map(behaviors, &format_behavior/1)
    })
  end

  ## Private Functions

  defp bounded_days(value, default), do: value |> parse_int(default) |> max(1) |> min(365)

  defp bounded_limit(value, default, max_limit),
    do: value |> parse_int(default) |> max(1) |> min(max_limit)

  defp parse_int(nil, default), do: default
  defp parse_int(value, _default) when is_integer(value), do: value
  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> default
    end
  end
  defp parse_int(_, default), do: default

  defp get_user_baselines(user_id) do
    alias TamanduaServer.UBA.UserBaseline
    alias TamanduaServer.Repo
    import Ecto.Query

    from(b in UserBaseline,
      where: b.user_id == ^user_id
    )
    |> Repo.all()
  end

  defp format_risk_score(risk_score) do
    %{
      id: risk_score.id,
      user_id: risk_score.user_id,
      risk_score: risk_score.risk_score,
      risk_level: risk_score.risk_level,
      risk_factors: %{
        off_hours_activity: risk_score.off_hours_activity,
        new_location: risk_score.new_location,
        excessive_data_access: risk_score.excessive_data_access,
        privilege_escalation: risk_score.privilege_escalation,
        failed_logins: risk_score.failed_logins,
        anomalous_app_usage: risk_score.anomalous_app_usage,
        peer_group_outlier: risk_score.peer_group_outlier
      },
      contributing_anomalies: risk_score.contributing_anomalies,
      last_calculated: risk_score.last_calculated
    }
  end

  defp format_baseline(baseline) do
    %{
      id: baseline.id,
      user_id: baseline.user_id,
      behavior_type: baseline.behavior_type,
      statistics: %{
        mean: baseline.mean,
        stddev: baseline.stddev,
        median: baseline.median,
        p95: baseline.p95,
        p99: baseline.p99,
        min: baseline.min,
        max: baseline.max,
        count: baseline.count
      },
      patterns: %{
        hourly: baseline.hourly_pattern,
        daily: baseline.daily_pattern,
        locations: baseline.common_locations,
        devices: baseline.common_devices
      },
      baseline_period: %{
        start: baseline.baseline_start,
        end: baseline.baseline_end
      },
      is_complete: baseline.is_complete,
      last_updated: baseline.last_updated
    }
  end

  defp format_anomaly(anomaly) do
    %{
      id: anomaly.id,
      user_id: anomaly.user_id,
      behavior_type: anomaly.behavior_type,
      timestamp: anomaly.timestamp,
      anomaly_type: anomaly.anomaly_type,
      severity: anomaly.severity,
      score: anomaly.score,
      baseline_value: anomaly.baseline_value,
      observed_value: anomaly.observed_value,
      deviation: anomaly.deviation,
      metadata: anomaly.metadata,
      is_acknowledged: anomaly.is_acknowledged,
      acknowledged_by: anomaly.acknowledged_by,
      acknowledged_at: anomaly.acknowledged_at,
      notes: anomaly.notes
    }
  end

  defp format_behavior(behavior) do
    %{
      id: behavior.id,
      user_id: behavior.user_id,
      behavior_type: behavior.behavior_type,
      timestamp: behavior.timestamp,
      value: behavior.value,
      location: behavior.location,
      device: behavior.device,
      metadata: behavior.metadata
    }
  end

  defp format_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
end
