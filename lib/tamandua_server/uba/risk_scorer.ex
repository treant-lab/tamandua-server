defmodule TamanduaServer.UBA.RiskScorer do
  @moduledoc """
  Calculates user risk scores based on behavioral anomalies and risk factors.

  Risk Factors (weighted points):
  - Off-hours activity: 10 points
  - New location: 15 points
  - Excessive data access: 20 points
  - Privilege escalation: 25 points
  - Failed logins: 10 points
  - Anomalous app usage: 10 points
  - Peer group outlier: 10 points

  Risk Levels:
  - <30: Low
  - 30-60: Medium
  - 60-80: High
  - >80: Critical
  """

  use GenServer
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.UBA.{UserAnomaly, UserRiskScore, UBAAlert}
  import Ecto.Query

  # Risk factor weights
  @risk_weights %{
    "off_hours_activity" => 10,
    "new_location" => 15,
    "excessive_data_access" => 20,
    "privilege_escalation" => 25,
    "failed_logins" => 10,
    "anomalous_app_usage" => 10,
    "peer_group_outlier" => 10
  }

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    Logger.info("RiskScorer started")

    # Schedule periodic risk score updates (every 15 minutes)
    schedule_update()

    {:ok, %{}}
  end

  ## Public API

  @doc """
  Updates risk score for a specific user.
  """
  def update_risk_score(user_id) do
    GenServer.cast(__MODULE__, {:update, user_id})
  end

  @doc """
  Updates risk scores for all users.
  """
  def update_all_risk_scores do
    GenServer.cast(__MODULE__, :update_all)
  end

  @doc """
  Gets risk score for a user.
  """
  def get_risk_score(user_id) do
    Repo.get_by(UserRiskScore, user_id: user_id)
  end

  @doc """
  Gets users by risk level.
  """
  def get_users_by_risk(risk_level, organization_id) do
    from(r in UserRiskScore,
      where: r.risk_level == ^risk_level,
      where: r.organization_id == ^organization_id,
      order_by: [desc: r.risk_score]
    )
    |> Repo.all()
  end

  @doc """
  Gets top risky users.
  """
  def get_top_risky_users(organization_id, limit \\ 10) do
    from(r in UserRiskScore,
      where: r.organization_id == ^organization_id,
      where: r.risk_score > 30,
      order_by: [desc: r.risk_score],
      limit: ^limit,
      preload: [:user]
    )
    |> Repo.all()
  end

  ## GenServer Callbacks

  @impl true
  def handle_cast({:update, user_id}, state) do
    Task.start(fn ->
      calculate_risk_score(user_id)
    end)

    {:noreply, state}
  end

  @impl true
  def handle_cast(:update_all, state) do
    Task.start(fn ->
      update_all_risk_scores_async()
    end)

    {:noreply, state}
  end

  @impl true
  def handle_info(:update, state) do
    update_all_risk_scores()
    schedule_update()
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  ## Private Functions

  defp schedule_update do
    # Update every 15 minutes
    Process.send_after(self(), :update, 15 * 60 * 1000)
  end

  defp update_all_risk_scores_async do
    Logger.info("Updating risk scores for all users...")

    # Get all users with recent anomalies
    query = from(a in UserAnomaly,
      select: a.user_id,
      distinct: true
    )

    Repo.all(query)
    |> Enum.each(fn user_id ->
      calculate_risk_score(user_id)
    end)

    Logger.info("Risk score update complete")
  end

  defp calculate_risk_score(user_id) do
    # Get recent anomalies (last 7 days)
    cutoff = DateTime.utc_now() |> DateTime.add(-7 * 24 * 3600, :second)

    anomalies = from(a in UserAnomaly,
      where: a.user_id == ^user_id,
      where: a.timestamp >= ^cutoff,
      where: a.is_acknowledged == false
    )
    |> Repo.all()

    # Calculate risk factors
    risk_factors = %{
      off_hours_activity: calculate_off_hours_risk(anomalies),
      new_location: calculate_location_risk(anomalies),
      excessive_data_access: calculate_data_access_risk(anomalies),
      privilege_escalation: calculate_privilege_risk(anomalies),
      failed_logins: calculate_failed_login_risk(anomalies),
      anomalous_app_usage: calculate_app_usage_risk(anomalies),
      peer_group_outlier: calculate_peer_outlier_risk(anomalies)
    }

    # Calculate total risk score
    risk_score = Enum.reduce(risk_factors, 0, fn {_factor, value}, acc ->
      acc + value
    end)

    # Cap at 100
    risk_score = min(risk_score, 100)

    # Determine risk level
    risk_level = cond do
      risk_score >= 80 -> "critical"
      risk_score >= 60 -> "high"
      risk_score >= 30 -> "medium"
      true -> "low"
    end

    # Get contributing anomalies
    contributing_anomalies = Enum.map(anomalies, & &1.id)

    attrs = %{
      user_id: user_id,
      organization_id: get_user_organization(user_id),
      risk_score: risk_score,
      risk_level: risk_level,
      off_hours_activity: risk_factors.off_hours_activity,
      new_location: risk_factors.new_location,
      excessive_data_access: risk_factors.excessive_data_access,
      privilege_escalation: risk_factors.privilege_escalation,
      failed_logins: risk_factors.failed_logins,
      anomalous_app_usage: risk_factors.anomalous_app_usage,
      peer_group_outlier: risk_factors.peer_group_outlier,
      contributing_anomalies: contributing_anomalies,
      last_calculated: DateTime.utc_now()
    }

    result = case Repo.get_by(UserRiskScore, user_id: user_id) do
      nil ->
        %UserRiskScore{}
        |> UserRiskScore.changeset(attrs)
        |> Repo.insert()

      risk_score_record ->
        risk_score_record
        |> UserRiskScore.changeset(attrs)
        |> Repo.update()
    end

    case result do
      {:ok, risk_score_record} ->
        Logger.info("Updated risk score for user #{user_id}: #{risk_score} (#{risk_level})")

        # Trigger alerts for high-risk users
        if risk_level in ["high", "critical"] do
          create_risk_alert(risk_score_record)
        end

        risk_score_record

      {:error, changeset} ->
        Logger.error("Failed to update risk score: #{inspect(changeset.errors)}")
        nil
    end
  end

  defp calculate_off_hours_risk(anomalies) do
    off_hours_anomalies = Enum.filter(anomalies, fn a ->
      a.anomaly_type in ["time_anomaly", "off_hours_activity"]
    end)

    count = length(off_hours_anomalies)
    max_score = @risk_weights["off_hours_activity"]

    min(count * (max_score / 5), max_score)
  end

  defp calculate_location_risk(anomalies) do
    location_anomalies = Enum.filter(anomalies, fn a ->
      a.anomaly_type in ["location_anomaly", "impossible_travel"]
    end)

    count = length(location_anomalies)
    max_score = @risk_weights["new_location"]

    # Impossible travel gets full score immediately
    if Enum.any?(location_anomalies, & &1.anomaly_type == "impossible_travel") do
      max_score
    else
      min(count * (max_score / 3), max_score)
    end
  end

  defp calculate_data_access_risk(anomalies) do
    data_anomalies = Enum.filter(anomalies, fn a ->
      a.behavior_type in ["file_access", "data_download", "data_upload"] and
      a.anomaly_type == "statistical_outlier"
    end)

    _count = length(data_anomalies)
    max_score = @risk_weights["excessive_data_access"]

    # Weight by severity
    score = Enum.reduce(data_anomalies, 0, fn a, acc ->
      weight = case a.severity do
        "critical" -> 1.0
        "high" -> 0.75
        "medium" -> 0.5
        "low" -> 0.25
        _ -> 0.25
      end
      acc + (max_score / 3) * weight
    end)

    min(score, max_score)
  end

  defp calculate_privilege_risk(anomalies) do
    privilege_anomalies = Enum.filter(anomalies, fn a ->
      a.behavior_type in ["sudo_usage", "uac_elevation", "permission_change"] and
      a.anomaly_type == "statistical_outlier"
    end)

    _count = length(privilege_anomalies)
    max_score = @risk_weights["privilege_escalation"]

    # Weight by severity
    score = Enum.reduce(privilege_anomalies, 0, fn a, acc ->
      weight = case a.severity do
        "critical" -> 1.0
        "high" -> 0.75
        "medium" -> 0.5
        "low" -> 0.25
        _ -> 0.25
      end
      acc + (max_score / 2) * weight
    end)

    min(score, max_score)
  end

  defp calculate_failed_login_risk(anomalies) do
    failed_login_anomalies = Enum.filter(anomalies, fn a ->
      a.behavior_type == "failed_auth"
    end)

    count = length(failed_login_anomalies)
    max_score = @risk_weights["failed_logins"]

    min(count * (max_score / 5), max_score)
  end

  defp calculate_app_usage_risk(anomalies) do
    app_anomalies = Enum.filter(anomalies, fn a ->
      a.behavior_type in ["app_launch", "app_switch"] and
      a.anomaly_type in ["statistical_outlier", "behavioral_drift"]
    end)

    count = length(app_anomalies)
    max_score = @risk_weights["anomalous_app_usage"]

    min(count * (max_score / 3), max_score)
  end

  defp calculate_peer_outlier_risk(anomalies) do
    # This would compare to peer group baselines (to be implemented with PeerGroupManager)
    # For now, use behavioral drift as proxy
    drift_anomalies = Enum.filter(anomalies, fn a ->
      a.anomaly_type == "behavioral_drift" and a.severity in ["high", "critical"]
    end)

    count = length(drift_anomalies)
    max_score = @risk_weights["peer_group_outlier"]

    min(count * (max_score / 2), max_score)
  end

  defp create_risk_alert(risk_score_record) do
    # Check if alert already exists for this user (last 24 hours)
    cutoff = DateTime.utc_now() |> DateTime.add(-24 * 3600, :second)

    existing = from(a in UBAAlert,
      where: a.user_id == ^risk_score_record.user_id,
      where: a.alert_type == "high_risk_user",
      where: a.inserted_at >= ^cutoff,
      limit: 1
    )
    |> Repo.one()

    if is_nil(existing) do
      attrs = %{
        user_id: risk_score_record.user_id,
        organization_id: risk_score_record.organization_id,
        alert_type: "high_risk_user",
        severity: risk_score_record.risk_level,
        status: "open",
        risk_score: risk_score_record.risk_score,
        description: "User has elevated risk score: #{risk_score_record.risk_score} (#{risk_score_record.risk_level})",
        evidence: %{
          risk_factors: %{
            off_hours_activity: risk_score_record.off_hours_activity,
            new_location: risk_score_record.new_location,
            excessive_data_access: risk_score_record.excessive_data_access,
            privilege_escalation: risk_score_record.privilege_escalation,
            failed_logins: risk_score_record.failed_logins,
            anomalous_app_usage: risk_score_record.anomalous_app_usage,
            peer_group_outlier: risk_score_record.peer_group_outlier
          },
          contributing_anomalies: risk_score_record.contributing_anomalies
        }
      }

      case UBAAlert.changeset(%UBAAlert{}, attrs) |> Repo.insert() do
        {:ok, alert} ->
          Logger.warning("UBA Alert created: High risk user #{risk_score_record.user_id} (score: #{risk_score_record.risk_score})")
          {:ok, alert}

        {:error, changeset} ->
          Logger.error("Failed to create UBA alert: #{inspect(changeset.errors)}")
          {:error, changeset}
      end
    else
      {:ok, existing}
    end
  end

  defp get_user_organization(user_id) do
    from(u in TamanduaServer.Accounts.User,
      where: u.id == ^user_id,
      select: u.organization_id
    )
    |> Repo.one()
  end
end
