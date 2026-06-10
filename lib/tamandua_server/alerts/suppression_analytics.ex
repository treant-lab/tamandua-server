defmodule TamanduaServer.Alerts.SuppressionAnalytics do
  @moduledoc """
  Analytics and metrics for alert suppression.

  Tracks:
  - Suppression rates
  - Top suppression rules
  - False positive reduction
  - Time-series metrics
  """

  import Ecto.Query
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts.{Alert, SuppressedAlert, SuppressionRule}

  @doc """
  Get suppression statistics for an organization.

  Options:
  - `:period` - Time period ("24h", "7d", "30d", "90d")
  - `:agent_id` - Filter by specific agent
  """
  def get_stats(organization_id, opts \\ []) do
    period = Keyword.get(opts, :period, "7d")
    agent_id = Keyword.get(opts, :agent_id)

    start_time = calculate_start_time(period)

    %{
      summary: get_summary(organization_id, start_time, agent_id),
      top_rules: get_top_suppression_rules(organization_id, start_time, agent_id),
      by_severity: get_suppressed_by_severity(organization_id, start_time, agent_id),
      by_type: get_suppressed_by_type(organization_id, start_time, agent_id),
      timeline: get_suppression_timeline(organization_id, start_time, agent_id),
      false_positive_reduction: calculate_fp_reduction(organization_id, start_time, agent_id)
    }
  end

  @doc """
  Get summary metrics for suppression.
  """
  def get_summary(organization_id, start_time, agent_id \\ nil) do
    # Count total alerts (including suppressed)
    total_alerts_query = from(a in Alert,
      where: a.organization_id == ^organization_id,
      where: a.inserted_at >= ^start_time
    )

    total_alerts_query = if agent_id do
      from(a in total_alerts_query, where: a.agent_id == ^agent_id)
    else
      total_alerts_query
    end

    total_alerts = Repo.aggregate(total_alerts_query, :count)

    # Count suppressed alerts
    suppressed_query = from(sa in SuppressedAlert,
      where: sa.organization_id == ^organization_id,
      where: sa.suppressed_at >= ^start_time
    )

    suppressed_query = if agent_id do
      from(sa in suppressed_query, where: sa.agent_id == ^agent_id)
    else
      suppressed_query
    end

    suppressed_count = Repo.aggregate(suppressed_query, :count)

    # Calculate rate
    total_with_suppressed = total_alerts + suppressed_count
    suppression_rate = if total_with_suppressed > 0 do
      Float.round(suppressed_count / total_with_suppressed * 100, 1)
    else
      0.0
    end

    # Get active alerts
    active_alerts = from(a in Alert,
      where: a.organization_id == ^organization_id,
      where: a.status != "resolved",
      where: a.status != "false_positive"
    )

    active_alerts = if agent_id do
      from(a in active_alerts, where: a.agent_id == ^agent_id)
    else
      active_alerts
    end

    active_count = Repo.aggregate(active_alerts, :count)

    %{
      total_alerts: total_alerts,
      suppressed_count: suppressed_count,
      suppression_rate: suppression_rate,
      active_alerts: active_count,
      period_start: start_time,
      period_end: DateTime.utc_now()
    }
  end

  @doc """
  Get top suppression rules by match count.
  """
  def get_top_suppression_rules(organization_id, start_time, agent_id \\ nil, limit \\ 10) do
    # Get rule IDs from suppressed alerts in the time period
    suppressed_query = from(sa in SuppressedAlert,
      where: sa.organization_id == ^organization_id,
      where: sa.suppressed_at >= ^start_time,
      where: not is_nil(sa.suppression_rule_id),
      group_by: sa.suppression_rule_id,
      select: {sa.suppression_rule_id, count(sa.id)}
    )

    suppressed_query = if agent_id do
      from(sa in suppressed_query, where: sa.agent_id == ^agent_id)
    else
      suppressed_query
    end

    rule_counts = Repo.all(suppressed_query)
    |> Map.new()

    # Get rule details
    rule_ids = Map.keys(rule_counts)

    rules = from(r in SuppressionRule,
      where: r.id in ^rule_ids
    )
    |> Repo.all()
    |> Enum.map(fn rule ->
      %{
        id: rule.id,
        name: rule.name,
        priority: rule.priority,
        action: rule.action,
        match_count: Map.get(rule_counts, rule.id, 0),
        enabled: rule.enabled
      }
    end)
    |> Enum.sort_by(& &1.match_count, :desc)
    |> Enum.take(limit)

    rules
  end

  @doc """
  Get suppressed alerts grouped by severity.
  """
  def get_suppressed_by_severity(organization_id, start_time, agent_id \\ nil) do
    query = from(sa in SuppressedAlert,
      where: sa.organization_id == ^organization_id,
      where: sa.suppressed_at >= ^start_time,
      group_by: sa.severity,
      select: {sa.severity, count(sa.id)}
    )

    query = if agent_id do
      from(sa in query, where: sa.agent_id == ^agent_id)
    else
      query
    end

    Repo.all(query)
    |> Map.new()
  end

  @doc """
  Get suppressed alerts grouped by suppression type.
  """
  def get_suppressed_by_type(organization_id, start_time, agent_id \\ nil) do
    query = from(sa in SuppressedAlert,
      where: sa.organization_id == ^organization_id,
      where: sa.suppressed_at >= ^start_time,
      group_by: sa.suppression_type,
      select: {sa.suppression_type, count(sa.id)}
    )

    query = if agent_id do
      from(sa in query, where: sa.agent_id == ^agent_id)
    else
      query
    end

    Repo.all(query)
    |> Map.new()
  end

  @doc """
  Get suppression timeline (hourly or daily buckets).
  """
  def get_suppression_timeline(organization_id, start_time, agent_id \\ nil) do
    # Determine bucket size based on time range
    now = DateTime.utc_now()
    diff_seconds = DateTime.diff(now, start_time)

    {trunc_format, bucket_name} = cond do
      diff_seconds <= 86400 -> {"hour", "hour"}  # 24 hours: hourly
      diff_seconds <= 604800 -> {"day", "day"}   # 7 days: daily
      true -> {"day", "day"}                      # >7 days: daily
    end

    query = from(sa in SuppressedAlert,
      where: sa.organization_id == ^organization_id,
      where: sa.suppressed_at >= ^start_time,
      group_by: fragment("date_trunc(?, ?)", ^trunc_format, sa.suppressed_at),
      select: {fragment("date_trunc(?, ?)", ^trunc_format, sa.suppressed_at), count(sa.id)},
      order_by: [asc: fragment("date_trunc(?, ?)", ^trunc_format, sa.suppressed_at)]
    )

    query = if agent_id do
      from(sa in query, where: sa.agent_id == ^agent_id)
    else
      query
    end

    Repo.all(query)
    |> Enum.map(fn {timestamp, count} ->
      %{
        timestamp: timestamp,
        count: count,
        bucket: bucket_name
      }
    end)
  end

  @doc """
  Calculate false positive reduction percentage.

  Compares suppressed alerts marked as false positives vs alerts created.
  """
  def calculate_fp_reduction(organization_id, start_time, agent_id \\ nil) do
    # Count alerts marked as false positive (not suppressed)
    fp_alerts_query = from(a in Alert,
      where: a.organization_id == ^organization_id,
      where: a.inserted_at >= ^start_time,
      where: a.status == "false_positive" or a.verdict == "false_positive"
    )

    fp_alerts_query = if agent_id do
      from(a in fp_alerts_query, where: a.agent_id == ^agent_id)
    else
      fp_alerts_query
    end

    fp_alerts_count = Repo.aggregate(fp_alerts_query, :count)

    # Count suppressed alerts (assumed to be potential FPs)
    suppressed_query = from(sa in SuppressedAlert,
      where: sa.organization_id == ^organization_id,
      where: sa.suppressed_at >= ^start_time
    )

    suppressed_query = if agent_id do
      from(sa in suppressed_query, where: sa.agent_id == ^agent_id)
    else
      suppressed_query
    end

    suppressed_count = Repo.aggregate(suppressed_query, :count)

    # Total potential FPs (suppressed + marked as FP)
    total_potential_fps = fp_alerts_count + suppressed_count

    # Reduction percentage
    reduction_pct = if total_potential_fps > 0 do
      Float.round(suppressed_count / total_potential_fps * 100, 1)
    else
      0.0
    end

    %{
      suppressed_fps: suppressed_count,
      created_fps: fp_alerts_count,
      total_fps: total_potential_fps,
      reduction_percentage: reduction_pct
    }
  end

  @doc """
  Get suppression audit log for an organization.
  """
  def get_audit_log(organization_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)
    offset = Keyword.get(opts, :offset, 0)

    from(log in "suppression_audit_log",
      where: log.organization_id == ^organization_id,
      order_by: [desc: log.occurred_at],
      limit: ^limit,
      offset: ^offset,
      select: log
    )
    |> Repo.all()
  end

  @doc """
  Record an audit log entry for suppression actions.
  """
  def log_action(action, resource_type, resource_id, organization_id, user_id, changes \\ %{}, metadata \\ %{}) do
    attrs = %{
      id: Ecto.UUID.generate(),
      action: action,
      resource_type: resource_type,
      resource_id: resource_id,
      organization_id: organization_id,
      user_id: user_id,
      changes: changes,
      metadata: metadata,
      occurred_at: DateTime.utc_now(),
      inserted_at: DateTime.utc_now()
    }

    Repo.insert_all("suppression_audit_log", [attrs])
  rescue
    e ->
      Logger.warning("Failed to log suppression action: #{inspect(e)}")
      :ok
  end

  # ---------------------------------------------------------------------------
  # Private Helpers
  # ---------------------------------------------------------------------------

  defp calculate_start_time(period) do
    now = DateTime.utc_now()

    case period do
      "1h" -> DateTime.add(now, -3600, :second)
      "24h" -> DateTime.add(now, -86400, :second)
      "7d" -> DateTime.add(now, -7 * 86400, :second)
      "30d" -> DateTime.add(now, -30 * 86400, :second)
      "90d" -> DateTime.add(now, -90 * 86400, :second)
      _ -> DateTime.add(now, -7 * 86400, :second)  # Default to 7 days
    end
  end
end
