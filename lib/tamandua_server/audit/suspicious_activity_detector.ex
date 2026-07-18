defmodule TamanduaServer.Audit.SuspiciousActivityDetector do
  @moduledoc """
  Detects suspicious activity patterns in audit logs.
  Implements real-time detection of:
  - Multiple failed logins
  - Access from new IPs/locations
  - Privilege escalation attempts
  - Bulk data access
  - Off-hours activity
  """

  import Ecto.Query
  alias TamanduaServer.Repo
  alias TamanduaServer.Audit.AuditLog
  alias TamanduaServer.Cache

  @failed_login_threshold 5
  @failed_login_window_minutes 5
  @off_hours_start 2
  @off_hours_end 6
  @bulk_access_threshold 100

  @doc """
  Analyzes an audit log entry for suspicious patterns.
  Returns {:suspicious, reason, risk_score} or :ok
  """
  def analyze(%AuditLog{} = audit_log) do
    checks = [
      &check_failed_logins/1,
      &check_new_ip/1,
      &check_privilege_escalation/1,
      &check_bulk_access/1,
      &check_off_hours/1,
      &check_unusual_location/1,
      &check_impossible_travel/1
    ]

    results = Enum.map(checks, fn check -> check.(audit_log) end)
    
    case Enum.find(results, fn r -> r != :ok end) do
      nil -> :ok
      {:suspicious, reason, score} -> {:suspicious, reason, score}
    end
  end

  # Check for multiple failed login attempts
  defp check_failed_logins(%AuditLog{action: "auth.login_failed", ip_address: ip} = _log) do
    window_start = DateTime.add(DateTime.utc_now(), -@failed_login_window_minutes * 60, :second)
    
    count = Repo.one(
      from a in AuditLog,
        where: a.action == "auth.login_failed",
        where: a.ip_address == ^ip,
        where: a.inserted_at >= ^window_start,
        select: count(a.id)
    )

    if count >= @failed_login_threshold do
      {:suspicious, "Multiple failed login attempts (#{count} in #{@failed_login_window_minutes} min)", 80}
    else
      :ok
    end
  end
  defp check_failed_logins(_), do: :ok

  # Check for access from new IP address
  defp check_new_ip(%AuditLog{action: "auth.login_success", user_id: user_id, ip_address: ip}) when not is_nil(user_id) and not is_nil(ip) do
    # Check if this IP has been seen before for this user
    cached_key = "user_ips:#{user_id}"
    known_ips = Cache.get(cached_key) || []

    if ip in known_ips do
      :ok
    else
      # Check historical data
      historical_count = Repo.one(
        from a in AuditLog,
          where: a.user_id == ^user_id,
          where: a.ip_address == ^ip,
          where: a.action == "auth.login_success",
          where: a.inserted_at < ago(24, "hour"),
          select: count(a.id)
      )

      if historical_count == 0 do
        # Cache the new IP
        Cache.put(cached_key, [ip | known_ips], ttl: :timer.hours(24))
        {:suspicious, "Login from new IP address: #{ip}", 50}
      else
        :ok
      end
    end
  end
  defp check_new_ip(_), do: :ok

  # Check for privilege escalation attempts
  defp check_privilege_escalation(%AuditLog{action: action} = log) do
    escalation_actions = [
      "authz.role_assigned",
      "user.updated",
      "security.privilege_escalation_attempt"
    ]

    if action in escalation_actions do
      metadata = log.metadata || %{}
      
      cond do
        action == "security.privilege_escalation_attempt" ->
          {:suspicious, "Privilege escalation attempt detected", 90}
          
        action == "authz.role_assigned" and metadata["new_role"] == "admin" ->
          {:suspicious, "Admin role assigned", 70}
          
        true ->
          :ok
      end
    else
      :ok
    end
  end

  # Check for bulk data access
  defp check_bulk_access(%AuditLog{category: "data_access", user_id: user_id}) when not is_nil(user_id) do
    window_start = DateTime.add(DateTime.utc_now(), -300, :second) # 5 minutes
    
    count = Repo.one(
      from a in AuditLog,
        where: a.category == "data_access",
        where: a.user_id == ^user_id,
        where: a.inserted_at >= ^window_start,
        select: count(a.id)
    )

    if count >= @bulk_access_threshold do
      {:suspicious, "Bulk data access detected (#{count} operations in 5 min)", 75}
    else
      :ok
    end
  end
  defp check_bulk_access(_), do: :ok

  # Check for off-hours activity
  defp check_off_hours(%AuditLog{inserted_at: timestamp, user_id: user_id, category: category}) 
      when not is_nil(user_id) and category in ["data_access", "configuration", "response"] do
    hour = timestamp.hour

    if hour >= @off_hours_start and hour < @off_hours_end do
      {:suspicious, "Activity during off-hours (#{hour}:00)", 40}
    else
      :ok
    end
  end
  defp check_off_hours(_), do: :ok

  # Check for unusual location (requires GeoIP)
  defp check_unusual_location(%AuditLog{action: "auth.login_success", user_id: user_id, ip_address: ip}) 
      when not is_nil(user_id) and not is_nil(ip) do
    # This would integrate with GeoIP service
    # For now, return :ok
    :ok
  end
  defp check_unusual_location(_), do: :ok

  # Check for impossible travel (login from different locations in short time)
  defp check_impossible_travel(%AuditLog{action: "auth.login_success", user_id: user_id, ip_address: current_ip}) 
      when not is_nil(user_id) do
    # Get last login location from last 1 hour
    last_login = Repo.one(
      from a in AuditLog,
        where: a.user_id == ^user_id,
        where: a.action == "auth.login_success",
        where: a.inserted_at > ago(1, "hour"),
        where: a.ip_address != ^current_ip,
        order_by: [desc: a.inserted_at],
        limit: 1
    )

    case last_login do
      nil ->
        :ok
      
      %{ip_address: previous_ip, inserted_at: previous_time} ->
        # This would calculate distance between IPs and time diff
        # If distance > physically possible travel speed, flag as suspicious
        # For now, simplified check
        time_diff_minutes = DateTime.diff(DateTime.utc_now(), previous_time, :minute)
        
        if time_diff_minutes < 30 and current_ip != previous_ip do
          {:suspicious, "Impossible travel detected (login from #{previous_ip} #{time_diff_minutes} min ago)", 85}
        else
          :ok
        end
    end
  end
  defp check_impossible_travel(_), do: :ok

  @doc """
  Gets suspicious activity summary for an organization.
  """
  def get_suspicious_summary(organization_id, days_back \\ 7) do
    start_date = DateTime.add(DateTime.utc_now(), -days_back * 24 * 3600, :second)

    query = from a in AuditLog,
      where: a.organization_id == ^organization_id,
      where: a.suspicious == true,
      where: a.inserted_at >= ^start_date,
      preload: [:user]

    suspicious_logs = Repo.all(query)

    %{
      total_count: length(suspicious_logs),
      by_reason: group_by_reason(suspicious_logs),
      by_user: group_by_user(suspicious_logs),
      high_risk: Enum.filter(suspicious_logs, &(&1.risk_score >= 70)),
      recent: Enum.take(suspicious_logs, 10)
    }
  end

  defp group_by_reason(logs) do
    Enum.group_by(logs, & &1.suspicious_reason)
    |> Enum.map(fn {reason, logs} -> {reason, length(logs)} end)
    |> Enum.sort_by(fn {_, count} -> count end, :desc)
  end

  defp group_by_user(logs) do
    Enum.group_by(logs, & &1.user_id)
    |> Enum.map(fn {user_id, logs} -> {user_id, length(logs)} end)
    |> Enum.sort_by(fn {_, count} -> count end, :desc)
  end
end
