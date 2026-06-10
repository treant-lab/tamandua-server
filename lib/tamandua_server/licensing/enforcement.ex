defmodule TamanduaServer.Licensing.Enforcement do
  @moduledoc """
  License enforcement module.

  Handles:
  - Pre-action license checks
  - Quota enforcement
  - Grace period handling
  - Violation logging
  """

  require Logger

  alias TamanduaServer.Licensing.License
  alias TamanduaServer.AuditLog

  @doc """
  Enforce license before allowing an action.

  Returns `:ok` if action is allowed, `{:error, reason}` otherwise.
  """
  def enforce(organization_id, action, opts \\ []) do
    with {:ok, _} <- check_license_active(organization_id),
         :ok <- check_feature_enabled(organization_id, action),
         :ok <- check_quota(organization_id, action, opts) do
      :ok
    else
      {:error, reason} = error ->
        log_violation(organization_id, action, reason, opts)
        error
    end
  end

  @doc """
  Check if license is active (including grace period).
  """
  def check_license_active(organization_id) do
    if License.valid_license?(organization_id) do
      {:ok, :active}
    else
      {:error, :license_inactive}
    end
  end

  @doc """
  Check if a specific feature is enabled for the action.
  """
  def check_feature_enabled(organization_id, action) do
    feature = action_to_feature(action)

    if feature == :none or License.feature_enabled?(organization_id, feature) do
      :ok
    else
      {:error, {:feature_not_licensed, feature}}
    end
  end

  @doc """
  Check if action is within quota limits.
  """
  def check_quota(organization_id, action, opts) do
    case action do
      :add_agent ->
        if License.can_add_agent?(organization_id) do
          :ok
        else
          {:error, :agent_limit_exceeded}
        end

      :add_user ->
        check_user_quota(organization_id)

      :execute_query ->
        check_query_quota(organization_id, opts)

      _ ->
        :ok
    end
  end

  @doc """
  Get enforcement status for an organization.
  """
  def get_status(organization_id) do
    usage = License.get_usage(organization_id)

    %{
      organization_id: organization_id,
      license_status: usage.license_status,
      enforced: usage.license_status in [:active, :grace_period],
      warnings: get_warnings(usage),
      blocked_actions: get_blocked_actions(usage)
    }
  end

  @doc """
  Check if an action would be allowed (without enforcing).
  """
  def would_allow?(organization_id, action, opts \\ []) do
    case enforce(organization_id, action, opts) do
      :ok -> true
      _ -> false
    end
  end

  # Private Functions

  defp action_to_feature(action) do
    mapping = %{
      # Core actions - no specific feature required
      view_dashboard: :dashboards,
      view_alerts: :alerts,
      manage_alerts: :alerts,

      # Detection
      create_rule: :detection,
      update_rule: :detection,
      delete_rule: :detection,

      # Response
      kill_process: :basic_response,
      quarantine_file: :basic_response,
      isolate_endpoint: :basic_response,

      # Advanced
      execute_hunt: :hunting,
      create_playbook: :playbooks,
      execute_playbook: :playbooks,
      view_behavioral: :behavioral_analytics,

      # Enterprise
      live_response_session: :live_response,
      collect_forensics: :advanced_forensics,
      api_request: :api_access,
      configure_sso: :sso,
      generate_compliance_report: :compliance,

      # MSSP
      view_mssp_portal: :mssp_portal,
      manage_tenants: :mssp_portal,
      configure_branding: :white_labeling,

      # Addons
      ai_query: :ai_assistant,
      threat_intel_lookup: :threat_intel_premium,

      # No specific feature
      add_agent: :none,
      add_user: :none,
      view_events: :none
    }

    Map.get(mapping, action, :none)
  end

  defp check_user_quota(organization_id) do
    usage = License.get_usage(organization_id)

    case usage.license_tier do
      :trial when usage.user_count >= 5 ->
        {:error, :user_limit_exceeded}

      :pro when usage.user_count >= 25 ->
        {:error, :user_limit_exceeded}

      _ ->
        :ok
    end
  end

  defp check_query_quota(organization_id, opts) do
    # Get daily query count
    today = Date.utc_today()
    {:ok, start_of_day} = DateTime.new(today, ~T[00:00:00], "Etc/UTC")

    metrics = License.get_usage_metrics(organization_id, date_from: start_of_day)
    query_count = Enum.find_value(metrics, 0, fn m ->
      if m.metric_type == "query_executed", do: m.total, else: nil
    end)

    usage = License.get_usage(organization_id)

    max_queries = case usage.license_tier do
      :trial -> 100
      :pro -> 10_000
      :enterprise -> :unlimited
      :mssp -> :unlimited
      _ -> 100
    end

    if max_queries == :unlimited or query_count < max_queries do
      # Record the query
      License.record_usage(organization_id, "query_executed", 1, opts[:metadata] || %{})
      :ok
    else
      {:error, :query_limit_exceeded}
    end
  end

  defp get_warnings(usage) do
    warnings = []

    warnings = if usage.agent_usage_percent > 80 do
      ["Agent usage at #{usage.agent_usage_percent}% of limit" | warnings]
    else
      warnings
    end

    warnings = if usage.days_remaining && usage.days_remaining < 30 do
      ["License expires in #{usage.days_remaining} days" | warnings]
    else
      warnings
    end

    warnings = if usage.in_grace_period do
      ["License expired - in grace period" | warnings]
    else
      warnings
    end

    warnings
  end

  defp get_blocked_actions(usage) do
    blocked = []

    blocked = if usage.license_status == :expired do
      # All non-read actions blocked when expired
      [:create_rule, :execute_playbook, :live_response_session, :collect_forensics | blocked]
    else
      blocked
    end

    blocked = if usage.agent_usage_percent >= 100 do
      [:add_agent | blocked]
    else
      blocked
    end

    blocked
  end

  defp log_violation(organization_id, action, reason, opts) do
    Logger.warning("License violation: org=#{organization_id} action=#{action} reason=#{inspect(reason)}")

    AuditLog.log(%{
      action: "license_violation",
      action_type: "system",
      resource_type: "license",
      organization_id: organization_id,
      severity: :warning,
      details: %{
        attempted_action: action,
        reason: inspect(reason),
        user_id: opts[:user_id]
      }
    })
  end
end
