defmodule TamanduaServer.Alerts.SLATracker do
  @moduledoc """
  SLA (Service Level Agreement) tracking for alert response times.

  ## SLA Metrics

  - **Time to Acknowledge** - Time from alert creation to acknowledgment
  - **Time to Resolve** - Time from alert creation to resolution

  ## Severity-Based Thresholds (Default)

  - **Critical**: 15min acknowledge, 4h resolve
  - **High**: 1h acknowledge, 8h resolve
  - **Medium**: 4h acknowledge, 24h resolve
  - **Low**: 8h acknowledge, 48h resolve

  ## Business Hours

  SLA policies can optionally use business hours, which pauses SLA timers
  outside of configured working hours.
  """

  use Ecto.Schema
  import Ecto.{Changeset, Query}
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts.{Alert, SLAPolicy}

  @default_thresholds %{
    "critical" => %{acknowledge: 15, resolve: 240},
    "high" => %{acknowledge: 60, resolve: 480},
    "medium" => %{acknowledge: 240, resolve: 1440},
    "low" => %{acknowledge: 480, resolve: 2880},
    "info" => %{acknowledge: 1440, resolve: 4320}
  }

  # ===========================================================================
  # Public API - Alert SLA Tracking
  # ===========================================================================

  @doc """
  Set SLA deadlines on a newly created alert.

  Called automatically when an alert is created.
  """
  def set_sla_deadlines(%Alert{} = alert) do
    policy = get_active_policy(alert.organization_id)
    thresholds = get_thresholds_for_severity(policy, alert.severity)

    now = DateTime.utc_now()
    acknowledge_deadline = calculate_deadline(now, thresholds.acknowledge, policy)
    resolve_deadline = calculate_deadline(now, thresholds.resolve, policy)

    alert
    |> change(%{
      sla_acknowledge_deadline: acknowledge_deadline,
      sla_resolve_deadline: resolve_deadline,
      sla_acknowledge_breached: false,
      sla_resolve_breached: false
    })
    |> Repo.update()
  end

  @doc """
  Mark an alert as acknowledged.

  Updates the `acknowledged_at` timestamp and checks if SLA was breached.
  """
  def mark_acknowledged(%Alert{} = alert, user_id) do
    now = DateTime.utc_now()

    # Check if acknowledge SLA was breached
    breached = if alert.sla_acknowledge_deadline do
      DateTime.compare(now, alert.sla_acknowledge_deadline) == :gt
    else
      false
    end

    alert
    |> change(%{
      acknowledged_at: now,
      acknowledged_by_id: user_id,
      sla_acknowledge_breached: breached
    })
    |> Repo.update()
    |> case do
      {:ok, updated_alert} ->
        if breached do
          Logger.warning("[SLA] Alert #{alert.id} acknowledge SLA breached")
          send_sla_breach_notification(updated_alert, :acknowledge)
        end
        {:ok, updated_alert}

      error ->
        error
    end
  end

  @doc """
  Mark an alert as resolved.

  Updates resolution timestamp and checks if resolve SLA was breached.
  """
  def mark_resolved(%Alert{} = alert) do
    now = DateTime.utc_now()

    # Check if resolve SLA was breached
    breached = if alert.sla_resolve_deadline do
      DateTime.compare(now, alert.sla_resolve_deadline) == :gt
    else
      false
    end

    alert
    |> change(%{
      resolved_at: now,
      sla_resolve_breached: breached
    })
    |> Repo.update()
    |> case do
      {:ok, updated_alert} ->
        if breached do
          Logger.warning("[SLA] Alert #{alert.id} resolve SLA breached")
          send_sla_breach_notification(updated_alert, :resolve)
        end
        {:ok, updated_alert}

      error ->
        error
    end
  end

  @doc """
  Mark an alert as closed (final state).
  """
  def mark_closed(%Alert{} = alert) do
    # If not already resolved, mark as resolved first
    if is_nil(alert.resolved_at) do
      mark_resolved(alert)
    else
      {:ok, alert}
    end
  end

  @doc """
  Check for SLA breaches and send warnings.

  This is called periodically by a background job to check for approaching
  or breached SLA deadlines.
  """
  def check_sla_breaches(opts \\ []) do
    organization_id = Keyword.get(opts, :organization_id)
    warning_threshold_minutes = Keyword.get(opts, :warning_threshold_minutes, 15)

    now = DateTime.utc_now()
    warning_time = DateTime.add(now, warning_threshold_minutes * 60, :second)

    # Find alerts approaching acknowledge deadline
    approaching_acknowledge = get_alerts_approaching_deadline(
      :acknowledge,
      now,
      warning_time,
      organization_id
    )

    # Find alerts approaching resolve deadline
    approaching_resolve = get_alerts_approaching_deadline(
      :resolve,
      now,
      warning_time,
      organization_id
    )

    # Find alerts that have breached deadlines
    breached_acknowledge = get_breached_alerts(:acknowledge, organization_id)
    breached_resolve = get_breached_alerts(:resolve, organization_id)

    # Send warnings
    Enum.each(approaching_acknowledge, fn alert ->
      send_sla_warning_notification(alert, :acknowledge)
    end)

    Enum.each(approaching_resolve, fn alert ->
      send_sla_warning_notification(alert, :resolve)
    end)

    # Update breach flags for newly breached alerts
    Enum.each(breached_acknowledge, fn alert ->
      if not alert.sla_acknowledge_breached do
        alert
        |> change(%{sla_acknowledge_breached: true})
        |> Repo.update()

        send_sla_breach_notification(alert, :acknowledge)
      end
    end)

    Enum.each(breached_resolve, fn alert ->
      if not alert.sla_resolve_breached do
        alert
        |> change(%{sla_resolve_breached: true})
        |> Repo.update()

        send_sla_breach_notification(alert, :resolve)
      end
    end)

    %{
      approaching_acknowledge: length(approaching_acknowledge),
      approaching_resolve: length(approaching_resolve),
      breached_acknowledge: length(breached_acknowledge),
      breached_resolve: length(breached_resolve)
    }
  end

  # ===========================================================================
  # Public API - SLA Metrics & Reporting
  # ===========================================================================

  @doc """
  Get SLA compliance metrics for an organization or analyst.

  ## Options

  - `:organization_id` - Filter by organization
  - `:analyst_id` - Filter by assigned analyst
  - `:days` - Number of days to look back (default: 30)

  ## Returns

      %{
        total_alerts: 100,
        acknowledged_count: 95,
        resolved_count: 85,
        acknowledge_compliance_rate: 0.92,
        resolve_compliance_rate: 0.88,
        avg_time_to_acknowledge_minutes: 25.5,
        avg_time_to_resolve_minutes: 180.2,
        breached_acknowledge: 8,
        breached_resolve: 12
      }
  """
  def get_sla_metrics(opts \\ []) do
    organization_id = Keyword.get(opts, :organization_id)
    analyst_id = Keyword.get(opts, :analyst_id)
    days = Keyword.get(opts, :days, 30)

    since = DateTime.utc_now() |> DateTime.add(-days * 24 * 60 * 60, :second)

    query = from(a in Alert,
      where: a.inserted_at >= ^since,
      select: %{
        total: count(a.id),
        acknowledged: count(a.acknowledged_at),
        resolved: count(a.resolved_at),
        breached_acknowledge: fragment("COUNT(*) FILTER (WHERE ? = true)", a.sla_acknowledge_breached),
        breached_resolve: fragment("COUNT(*) FILTER (WHERE ? = true)", a.sla_resolve_breached),
        avg_ack_time: fragment(
          "AVG(EXTRACT(EPOCH FROM (? - ?)) / 60) FILTER (WHERE ? IS NOT NULL)",
          a.acknowledged_at,
          a.inserted_at,
          a.acknowledged_at
        ),
        avg_resolve_time: fragment(
          "AVG(EXTRACT(EPOCH FROM (? - ?)) / 60) FILTER (WHERE ? IS NOT NULL)",
          a.resolved_at,
          a.inserted_at,
          a.resolved_at
        )
      }
    )

    query = if organization_id do
      from(a in query, where: a.organization_id == ^organization_id)
    else
      query
    end

    query = if analyst_id do
      from(a in query, where: a.assigned_to_id == ^analyst_id)
    else
      query
    end

    result = Repo.one(query)

    if result do
      acknowledged_count = result.acknowledged || 0
      resolved_count = result.resolved || 0
      total = result.total || 0

      %{
        total_alerts: total,
        acknowledged_count: acknowledged_count,
        resolved_count: resolved_count,
        acknowledge_compliance_rate: calculate_compliance_rate(
          acknowledged_count - (result.breached_acknowledge || 0),
          acknowledged_count
        ),
        resolve_compliance_rate: calculate_compliance_rate(
          resolved_count - (result.breached_resolve || 0),
          resolved_count
        ),
        avg_time_to_acknowledge_minutes: result.avg_ack_time || 0.0,
        avg_time_to_resolve_minutes: result.avg_resolve_time || 0.0,
        breached_acknowledge: result.breached_acknowledge || 0,
        breached_resolve: result.breached_resolve || 0
      }
    else
      %{
        total_alerts: 0,
        acknowledged_count: 0,
        resolved_count: 0,
        acknowledge_compliance_rate: 0.0,
        resolve_compliance_rate: 0.0,
        avg_time_to_acknowledge_minutes: 0.0,
        avg_time_to_resolve_minutes: 0.0,
        breached_acknowledge: 0,
        breached_resolve: 0
      }
    end
  end

  @doc """
  Get SLA metrics grouped by severity.
  """
  def get_sla_metrics_by_severity(opts \\ []) do
    organization_id = Keyword.get(opts, :organization_id)
    days = Keyword.get(opts, :days, 30)

    since = DateTime.utc_now() |> DateTime.add(-days * 24 * 60 * 60, :second)

    query = from(a in Alert,
      where: a.inserted_at >= ^since,
      group_by: a.severity,
      select: %{
        severity: a.severity,
        total: count(a.id),
        breached_acknowledge: fragment("COUNT(*) FILTER (WHERE ? = true)", a.sla_acknowledge_breached),
        breached_resolve: fragment("COUNT(*) FILTER (WHERE ? = true)", a.sla_resolve_breached)
      }
    )

    query = if organization_id do
      from(a in query, where: a.organization_id == ^organization_id)
    else
      query
    end

    Repo.all(query)
  end

  # ===========================================================================
  # Public API - SLA Policies
  # ===========================================================================

  @doc """
  Create an SLA policy.
  """
  def create_policy(attrs) do
    %SLAPolicy{}
    |> SLAPolicy.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Update an SLA policy.
  """
  def update_policy(%SLAPolicy{} = policy, attrs) do
    policy
    |> SLAPolicy.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Delete an SLA policy.
  """
  def delete_policy(%SLAPolicy{} = policy) do
    Repo.delete(policy)
  end

  @doc """
  Get the active SLA policy for an organization.

  Returns the highest priority enabled policy, or nil if none exists.
  """
  def get_active_policy(organization_id) do
    from(p in SLAPolicy,
      where: p.organization_id == ^organization_id,
      where: p.enabled == true,
      order_by: [desc: p.priority],
      limit: 1
    )
    |> Repo.one()
  end

  @doc """
  List SLA policies.
  """
  def list_policies(opts \\ []) do
    organization_id = Keyword.get(opts, :organization_id)
    enabled_only = Keyword.get(opts, :enabled_only, false)

    query = from(p in SLAPolicy, order_by: [desc: p.priority])

    query = if organization_id do
      from(p in query, where: p.organization_id == ^organization_id)
    else
      query
    end

    query = if enabled_only do
      from(p in query, where: p.enabled == true)
    else
      query
    end

    Repo.all(query)
  end

  # ===========================================================================
  # Private Helpers
  # ===========================================================================

  defp get_thresholds_for_severity(nil, severity) do
    Map.get(@default_thresholds, severity, @default_thresholds["medium"])
  end

  defp get_thresholds_for_severity(%SLAPolicy{} = policy, severity) do
    case severity do
      "critical" ->
        %{
          acknowledge: policy.critical_acknowledge_minutes,
          resolve: policy.critical_resolve_minutes
        }

      "high" ->
        %{
          acknowledge: policy.high_acknowledge_minutes,
          resolve: policy.high_resolve_minutes
        }

      "medium" ->
        %{
          acknowledge: policy.medium_acknowledge_minutes,
          resolve: policy.medium_resolve_minutes
        }

      "low" ->
        %{
          acknowledge: policy.low_acknowledge_minutes,
          resolve: policy.low_resolve_minutes
        }

      _ ->
        %{
          acknowledge: policy.low_acknowledge_minutes,
          resolve: policy.low_resolve_minutes
        }
    end
  end

  defp calculate_deadline(start_time, threshold_minutes, nil) do
    # Simple calculation - just add minutes
    DateTime.add(start_time, threshold_minutes * 60, :second)
  end

  defp calculate_deadline(start_time, threshold_minutes, %SLAPolicy{business_hours_only: false}) do
    # Simple calculation - just add minutes
    DateTime.add(start_time, threshold_minutes * 60, :second)
  end

  defp calculate_deadline(start_time, threshold_minutes, %SLAPolicy{} = policy) do
    # Complex calculation considering business hours
    # This is a simplified version - a full implementation would need to
    # account for holidays, multi-day calculations, etc.

    _timezone = policy.timezone || "UTC"
    _business_start = policy.business_hours_start || ~T[09:00:00]
    _business_end = policy.business_hours_end || ~T[17:00:00]
    _business_days = policy.business_days || [1, 2, 3, 4, 5]

    # For now, use simple calculation
    # TODO: Implement full business hours calculation
    DateTime.add(start_time, threshold_minutes * 60, :second)
  end

  defp get_alerts_approaching_deadline(deadline_type, now, warning_time, organization_id) do
    deadline_field = if deadline_type == :acknowledge do
      :sla_acknowledge_deadline
    else
      :sla_resolve_deadline
    end

    completed_field = if deadline_type == :acknowledge do
      :acknowledged_at
    else
      :resolved_at
    end

    query = from(a in Alert,
      where: field(a, ^deadline_field) >= ^now,
      where: field(a, ^deadline_field) <= ^warning_time,
      where: is_nil(field(a, ^completed_field)),
      preload: [:assigned_to, :agent]
    )

    query = if organization_id do
      from(a in query, where: a.organization_id == ^organization_id)
    else
      query
    end

    Repo.all(query)
  end

  defp get_breached_alerts(deadline_type, organization_id) do
    deadline_field = if deadline_type == :acknowledge do
      :sla_acknowledge_deadline
    else
      :sla_resolve_deadline
    end

    completed_field = if deadline_type == :acknowledge do
      :acknowledged_at
    else
      :resolved_at
    end

    breached_field = if deadline_type == :acknowledge do
      :sla_acknowledge_breached
    else
      :sla_resolve_breached
    end

    now = DateTime.utc_now()

    query = from(a in Alert,
      where: field(a, ^deadline_field) < ^now,
      where: is_nil(field(a, ^completed_field)),
      where: field(a, ^breached_field) == false,
      preload: [:assigned_to, :agent]
    )

    query = if organization_id do
      from(a in query, where: a.organization_id == ^organization_id)
    else
      query
    end

    Repo.all(query)
  end

  defp calculate_compliance_rate(_compliant, 0), do: 0.0
  defp calculate_compliance_rate(compliant, total) do
    Float.round(compliant / total, 2)
  end

  # Notifier never exposed send_sla_warning/send_sla_breach; the real surface
  # for SLA notices is NotificationCenter.Dispatcher.dispatch/4, whose
  # Notification schema explicitly supports the "sla_warning"/"sla_breach"
  # types and routes to the alert assignee (or org admins) by resource id.
  defp send_sla_warning_notification(alert, deadline_type) do
    Logger.info("[SLA] Sending warning for alert #{alert.id} - #{deadline_type} deadline approaching")

    TamanduaServer.NotificationCenter.Dispatcher.dispatch(
      "sla_warning",
      "SLA warning: #{deadline_type} deadline approaching",
      "Alert #{alert.id} (#{alert.title}) is approaching its #{deadline_type} SLA deadline.",
      %{
        organization_id: alert.organization_id,
        related_resource_type: "alert",
        related_resource_id: alert.id,
        priority: "high"
      }
    )
  end

  defp send_sla_breach_notification(alert, deadline_type) do
    Logger.warning("[SLA] Alert #{alert.id} #{deadline_type} SLA breached")

    TamanduaServer.NotificationCenter.Dispatcher.dispatch(
      "sla_breach",
      "SLA breached: #{deadline_type}",
      "Alert #{alert.id} (#{alert.title}) has breached its #{deadline_type} SLA deadline.",
      %{
        organization_id: alert.organization_id,
        related_resource_type: "alert",
        related_resource_id: alert.id,
        priority: "critical"
      }
    )
  end
end

# Schema moved to separate file: a_sla_policy.ex (TamanduaServer.Alerts.SLAPolicy)
