defmodule TamanduaServer.InsiderThreat do
  @moduledoc """
  Main module for insider threat detection.
  Provides high-level API for insider threat detection, peer group management,
  and investigation workflows.
  """

  alias TamanduaServer.InsiderThreat.{
    Detector,
    RiskScorer,
    PeerGroup,
    PeerGroupMember,
    Alert,
    Investigation,
    Indicator
  }

  import Ecto.Query
  alias TamanduaServer.Repo

  # ============================================================================
  # Detection API
  # ============================================================================

  @doc """
  Analyze an event for insider threat indicators.
  """
  defdelegate analyze_event(event), to: Detector

  @doc """
  Analyze user activity over a time period.
  """
  defdelegate analyze_user(user_id, start_time, end_time), to: Detector

  @doc """
  Batch analyze all users in organization.
  """
  defdelegate analyze_organization(organization_id, start_time, end_time), to: Detector

  # ============================================================================
  # Risk Scoring API
  # ============================================================================

  @doc """
  Calculate risk score for a user.
  """
  defdelegate calculate_score(user_id, indicators, opts \\ %{}), to: RiskScorer

  @doc """
  Get risk severity from score.
  """
  defdelegate get_severity(score), to: RiskScorer

  @doc """
  Get high risk threshold.
  """
  defdelegate high_risk_threshold(), to: RiskScorer

  # ============================================================================
  # Peer Group API
  # ============================================================================

  @doc """
  Create a new peer group.
  """
  defdelegate create_peer_group(attrs), to: PeerGroup, as: :create

  @doc """
  Get peer group by ID.
  """
  defdelegate get_peer_group(id), to: PeerGroup, as: :get

  @doc """
  List peer groups for an organization.
  """
  defdelegate list_peer_groups(organization_id), to: PeerGroup, as: :list_by_organization

  @doc """
  Add user to peer group.
  """
  defdelegate add_peer_group_member(peer_group_id, user_id), to: PeerGroup, as: :add_member

  @doc """
  Remove user from peer group.
  """
  defdelegate remove_peer_group_member(peer_group_id, user_id), to: PeerGroup, as: :remove_member

  @doc """
  Calculate baseline for peer group.
  """
  defdelegate calculate_peer_group_baseline(peer_group_id, start_time, end_time),
    to: PeerGroup,
    as: :calculate_baseline

  # ============================================================================
  # Alert API
  # ============================================================================

  @doc """
  Create an insider threat alert.
  """
  defdelegate create_alert(attrs), to: Alert, as: :create

  @doc """
  Get alert by ID.
  """
  defdelegate get_alert(id), to: Alert, as: :get

  @doc """
  List alerts for an organization.
  """
  defdelegate list_alerts(organization_id, opts \\ %{}), to: Alert, as: :list_by_organization

  @doc """
  List alerts for a user.
  """
  defdelegate list_user_alerts(user_id, opts \\ %{}), to: Alert, as: :list_by_user

  @doc """
  Get top users by risk score.
  """
  defdelegate top_users_by_risk(organization_id, limit \\ 10), to: Alert

  @doc """
  Get risk score distribution.
  """
  defdelegate risk_distribution(organization_id), to: Alert

  @doc """
  Mark alert as under investigation.
  """
  defdelegate start_investigation(alert, investigator_id), to: Alert

  @doc """
  Resolve an alert.
  """
  defdelegate resolve_alert(alert, resolver_id, resolution_notes, false_positive \\ false),
    to: Alert,
    as: :resolve

  @doc """
  Suppress an alert.
  """
  defdelegate suppress_alert(alert), to: Alert, as: :suppress

  @doc """
  Get recent alerts.
  """
  defdelegate recent_alerts(organization_id, hours \\ 24), to: Alert

  @doc """
  Get alert statistics.
  """
  defdelegate alert_statistics(organization_id, start_time, end_time), to: Alert, as: :statistics

  # ============================================================================
  # Investigation API
  # ============================================================================

  @doc """
  Create a new investigation.
  """
  defdelegate create_investigation(attrs), to: Investigation, as: :create

  @doc """
  Get investigation by ID.
  """
  defdelegate get_investigation(id), to: Investigation, as: :get

  @doc """
  List investigations for an organization.
  """
  defdelegate list_investigations(organization_id, opts \\ %{}),
    to: Investigation,
    as: :list_by_organization

  @doc """
  Add evidence to investigation.
  """
  defdelegate add_evidence(investigation, evidence_item), to: Investigation

  @doc """
  Add timeline entry to investigation.
  """
  defdelegate add_timeline_entry(investigation, entry), to: Investigation

  @doc """
  Close an investigation.
  """
  defdelegate close_investigation(investigation, outcome, action_taken),
    to: Investigation,
    as: :close

  @doc """
  Get user activity timeline.
  """
  defdelegate get_user_timeline(user_id, start_time, end_time), to: Investigation

  @doc """
  Get user access log.
  """
  defdelegate get_user_access_log(user_id, start_time, end_time), to: Investigation

  @doc """
  Get user network activity.
  """
  defdelegate get_user_network_activity(user_id, start_time, end_time), to: Investigation

  @doc """
  Get user authentication log.
  """
  defdelegate get_user_auth_log(user_id, start_time, end_time), to: Investigation

  @doc """
  Generate investigation report.
  """
  defdelegate generate_investigation_report(investigation),
    to: Investigation,
    as: :generate_report

  @doc """
  Export investigation for legal hold.
  """
  defdelegate export_for_legal_hold(investigation), to: Investigation

  # ============================================================================
  # Automated Peer Group Management
  # ============================================================================

  @doc """
  Auto-create peer groups based on user roles.
  """
  @spec auto_create_role_based_peer_groups(Ecto.UUID.t()) :: {:ok, [PeerGroup.t()]}
  def auto_create_role_based_peer_groups(organization_id) do
    query =
      from(u in "users",
        where: u.organization_id == ^organization_id and u.is_active == true,
        group_by: u.role,
        select: {u.role, fragment("array_agg(?)", u.id)}
      )

    role_groups = Repo.all(query)

    peer_groups =
      Enum.map(role_groups, fn {role, user_ids} ->
        {:ok, peer_group} =
          create_peer_group(%{
            name: "#{String.capitalize(role)}s",
            description: "Auto-generated peer group for #{role} role",
            group_type: "role",
            organization_id: organization_id
          })

        # Add members
        Enum.each(user_ids, fn user_id ->
          add_peer_group_member(peer_group.id, user_id)
        end)

        peer_group
      end)

    {:ok, peer_groups}
  end

  @doc """
  Auto-calculate baselines for all peer groups in organization.
  """
  @spec auto_calculate_baselines(Ecto.UUID.t()) :: {:ok, map()}
  def auto_calculate_baselines(organization_id) do
    peer_groups = list_peer_groups(organization_id)

    # Calculate baseline for last 30 days
    end_time = DateTime.utc_now()
    start_time = DateTime.add(end_time, -30 * 24 * 3600, :second)

    results =
      Enum.map(peer_groups, fn peer_group ->
        case calculate_peer_group_baseline(peer_group.id, start_time, end_time) do
          {:ok, baseline} -> {peer_group.id, baseline}
          {:error, _} -> {peer_group.id, nil}
        end
      end)
      |> Map.new()

    {:ok, results}
  end

  # ============================================================================
  # Scheduled Analysis
  # ============================================================================

  @doc """
  Run scheduled insider threat analysis for organization.
  Should be called periodically (e.g., hourly) by scheduler.
  """
  @spec run_scheduled_analysis(Ecto.UUID.t()) :: {:ok, map()}
  def run_scheduled_analysis(organization_id) do
    # Analyze last hour of activity
    end_time = DateTime.utc_now()
    start_time = DateTime.add(end_time, -3600, :second)

    case analyze_organization(organization_id, start_time, end_time) do
      {:ok, results} ->
        # Count alerts created
        alert_count =
          results
          |> Enum.count(fn {_user_id, result} ->
            result && result.risk_score.threshold_exceeded
          end)

        {:ok,
         %{
           organization_id: organization_id,
           analyzed_at: end_time,
           users_analyzed: map_size(results),
           alerts_created: alert_count
         }}

      error ->
        error
    end
  end

  # ============================================================================
  # Dashboard Data
  # ============================================================================

  @doc """
  Get insider threat dashboard data for organization.
  """
  @spec get_dashboard_data(Ecto.UUID.t()) :: map()
  def get_dashboard_data(organization_id) do
    # Get statistics for last 30 days
    end_time = DateTime.utc_now()
    start_time = DateTime.add(end_time, -30 * 24 * 3600, :second)

    %{
      top_users: top_users_by_risk(organization_id, 10),
      risk_distribution: risk_distribution(organization_id),
      recent_alerts: recent_alerts(organization_id, 24),
      statistics: alert_statistics(organization_id, start_time, end_time),
      open_investigations:
        list_investigations(organization_id, %{status: "open"}) |> length(),
      peer_groups: list_peer_groups(organization_id) |> length()
    }
  end

  @doc """
  Get user risk profile.
  """
  @spec get_user_risk_profile(Ecto.UUID.t()) :: map()
  def get_user_risk_profile(user_id) do
    # Get alerts for last 30 days
    end_time = DateTime.utc_now()
    start_time = DateTime.add(end_time, -30 * 24 * 3600, :second)

    alerts = list_user_alerts(user_id, %{})
    recent_alerts = Enum.filter(alerts, &(DateTime.compare(&1.inserted_at, start_time) == :gt))

    current_risk_score =
      case recent_alerts do
        [] -> 0.0
        alerts -> Enum.max_by(alerts, & &1.risk_score).risk_score
      end

    %{
      user_id: user_id,
      current_risk_score: current_risk_score,
      severity: get_severity(current_risk_score),
      total_alerts: length(alerts),
      recent_alerts: length(recent_alerts),
      open_investigations:
        list_investigations(nil, %{subject_user_id: user_id, status: "open"}) |> length(),
      alert_history: alerts |> Enum.take(10)
    }
  end
end
