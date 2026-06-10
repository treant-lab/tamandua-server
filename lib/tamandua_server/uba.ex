defmodule TamanduaServer.UBA do
  @moduledoc """
  User Behavior Analytics (UBA) main module.

  Provides comprehensive UBA functionality:
  - Behavior tracking (10+ behavior types)
  - Baseline learning (30-day statistical baselines)
  - Anomaly detection (statistical outliers, time/location anomalies)
  - Risk scoring (0-100 with weighted factors)
  - Peer group comparison
  - Automated alerting

  ## Behavior Types

  - `login` - User login events
  - `logout` - User logout events
  - `file_access` - File access events
  - `file_create` - File creation
  - `file_modify` - File modification
  - `file_delete` - File deletion
  - `data_upload` - Data upload/transfer
  - `data_download` - Data download
  - `email_sent` - Email sent
  - `sudo_usage` - Sudo/privilege escalation
  - `uac_elevation` - UAC elevation (Windows)
  - `app_launch` - Application launch
  - `app_switch` - Application switch
  - `network_connection` - Network connection
  - `failed_auth` - Failed authentication
  - `permission_change` - Permission change
  - `admin_console_access` - Admin console access
  - `off_hours_activity` - Off-hours activity

  ## Risk Factors

  - Off-hours activity: 10 points
  - New location: 15 points
  - Excessive data access: 20 points
  - Privilege escalation: 25 points
  - Failed logins: 10 points
  - Anomalous app usage: 10 points
  - Peer group outlier: 10 points

  ## Risk Levels

  - Low: <30 points
  - Medium: 30-60 points
  - High: 60-80 points
  - Critical: >80 points
  """

  alias TamanduaServer.UBA.{
    BehaviorTracker,
    BaselineLearner,
    AnomalyDetector,
    RiskScorer
  }

  # Behavior tracking

  @doc """
  Tracks a user behavior event.
  """
  defdelegate track_behavior(user_id, behavior_type, metadata \\ %{}), to: BehaviorTracker

  @doc """
  Tracks login behavior.
  """
  defdelegate track_login(user_id, ip_address, user_agent, metadata \\ %{}), to: BehaviorTracker

  @doc """
  Tracks file access.
  """
  defdelegate track_file_access(user_id, file_path, operation, agent_id \\ nil), to: BehaviorTracker

  @doc """
  Tracks data transfer.
  """
  defdelegate track_data_transfer(user_id, direction, bytes, metadata \\ %{}), to: BehaviorTracker

  @doc """
  Tracks privilege usage.
  """
  defdelegate track_privilege_usage(user_id, privilege_type, command, agent_id \\ nil), to: BehaviorTracker

  @doc """
  Tracks application usage.
  """
  defdelegate track_app_usage(user_id, app_name, duration_seconds, agent_id \\ nil), to: BehaviorTracker

  @doc """
  Tracks network connection.
  """
  defdelegate track_network_connection(user_id, dest_ip, dest_port, bytes, agent_id \\ nil), to: BehaviorTracker

  @doc """
  Tracks failed authentication.
  """
  defdelegate track_failed_auth(user_id, reason, location, metadata \\ %{}), to: BehaviorTracker

  @doc """
  Gets behavior history.
  """
  defdelegate get_behavior_history(user_id, behavior_type, opts \\ []), to: BehaviorTracker

  @doc """
  Gets behavior statistics.
  """
  defdelegate get_behavior_stats(user_id, behavior_type, days \\ 30), to: BehaviorTracker

  # Baseline learning

  @doc """
  Updates baseline for a user and behavior type.
  """
  defdelegate update_baseline(user_id, behavior_type), to: BaselineLearner

  @doc """
  Calculates baselines for all users.
  """
  defdelegate calculate_all_baselines(), to: BaselineLearner

  @doc """
  Gets baseline for a user.
  """
  defdelegate get_baseline(user_id, behavior_type), to: BaselineLearner

  @doc """
  Checks if baseline learning is complete.
  """
  defdelegate baseline_complete?(user_id, behavior_type), to: BaselineLearner

  # Anomaly detection

  @doc """
  Checks for anomalies in user behavior.
  """
  defdelegate check_anomalies(user_id, behavior_type), to: AnomalyDetector

  @doc """
  Checks all recent behaviors for anomalies.
  """
  defdelegate check_all_anomalies(), to: AnomalyDetector

  @doc """
  Gets anomalies for a user.
  """
  defdelegate get_user_anomalies(user_id, opts \\ []), to: AnomalyDetector

  @doc """
  Gets unacknowledged anomalies.
  """
  defdelegate get_unacknowledged_anomalies(organization_id), to: AnomalyDetector

  @doc """
  Acknowledges an anomaly.
  """
  defdelegate acknowledge_anomaly(anomaly_id, user_id, notes \\ nil), to: AnomalyDetector

  # Risk scoring

  @doc """
  Updates risk score for a user.
  """
  defdelegate update_risk_score(user_id), to: RiskScorer

  @doc """
  Updates risk scores for all users.
  """
  defdelegate update_all_risk_scores(), to: RiskScorer

  @doc """
  Gets risk score for a user.
  """
  defdelegate get_risk_score(user_id), to: RiskScorer

  @doc """
  Gets users by risk level.
  """
  defdelegate get_users_by_risk(risk_level, organization_id), to: RiskScorer

  @doc """
  Gets top risky users.
  """
  defdelegate get_top_risky_users(organization_id, limit \\ 10), to: RiskScorer

  @doc """
  Starts all UBA workers.
  """
  def start_workers do
    children = [
      BehaviorTracker,
      BaselineLearner,
      AnomalyDetector,
      RiskScorer
    ]

    opts = [strategy: :one_for_one, name: TamanduaServer.UBA.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
