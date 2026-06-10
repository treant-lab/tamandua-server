defmodule TamanduaServer.Remediation.Notifier do
  @moduledoc """
  Dispatches notifications for remediation workflow events.

  Integrates with NotificationCenter to send multi-channel notifications
  when workflows are created, approved, completed, or fail.
  """

  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.NotificationCenter.{Dispatcher, NotificationWebhook}
  alias TamanduaServer.NotificationCenter.Channels.WebhookWorker
  alias TamanduaServer.Remediation.{Workflow, Policy}
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Accounts.User

  import Ecto.Query

  # === Public API Functions ===

  @doc """
  Notify when a new remediation workflow is created.

  Called by Workflow.create_workflow/1 after successful insertion.
  """
  def notify_workflow_created(%Workflow{} = workflow) do
    workflow = preload_workflow(workflow)

    metadata = build_notification_metadata(workflow)
    users = get_notification_users(workflow, :created)
    priority = priority_from_workflow(workflow)

    dispatch_notification(
      "remediation_workflow_created",
      "Remediation Action Triggered: #{format_action_type(workflow.action_type)}",
      build_created_body(workflow),
      organization_id: workflow.organization_id,
      users: users,
      priority: priority,
      metadata: metadata,
      related_resource_type: "workflow",
      related_resource_id: workflow.id
    )
  rescue
    e ->
      Logger.error("[Remediation.Notifier] Failed to notify workflow created: #{inspect(e)}")
      :ok
  end

  @doc """
  Notify when a workflow is approved by a user.
  """
  def notify_workflow_approved(%Workflow{} = workflow) do
    workflow = preload_workflow(workflow)

    metadata = build_notification_metadata(workflow)
    users = get_notification_users(workflow, :approved)
    priority = "medium"

    dispatch_notification(
      "remediation_workflow_approved",
      "Remediation Approved: #{format_action_type(workflow.action_type)}",
      build_approved_body(workflow),
      organization_id: workflow.organization_id,
      users: users,
      priority: priority,
      metadata: metadata,
      related_resource_type: "workflow",
      related_resource_id: workflow.id
    )
  rescue
    e ->
      Logger.error("[Remediation.Notifier] Failed to notify workflow approved: #{inspect(e)}")
      :ok
  end

  @doc """
  Notify when a workflow starts execution.
  """
  def notify_workflow_started(%Workflow{} = workflow) do
    workflow = preload_workflow(workflow)

    metadata = build_notification_metadata(workflow)
    users = get_notification_users(workflow, :started)
    priority = "medium"

    dispatch_notification(
      "remediation_workflow_started",
      "Remediation Started: #{format_action_type(workflow.action_type)}",
      build_started_body(workflow),
      organization_id: workflow.organization_id,
      users: users,
      priority: priority,
      metadata: metadata,
      related_resource_type: "workflow",
      related_resource_id: workflow.id
    )
  rescue
    e ->
      Logger.error("[Remediation.Notifier] Failed to notify workflow started: #{inspect(e)}")
      :ok
  end

  @doc """
  Notify when a workflow completes successfully.
  """
  def notify_workflow_completed(%Workflow{} = workflow) do
    workflow = preload_workflow(workflow)

    metadata = build_notification_metadata(workflow)
    users = get_notification_users(workflow, :completed)
    priority = "medium"

    dispatch_notification(
      "remediation_workflow_completed",
      "Remediation Completed: #{format_action_type(workflow.action_type)}",
      build_completed_body(workflow),
      organization_id: workflow.organization_id,
      users: users,
      priority: priority,
      metadata: metadata,
      related_resource_type: "workflow",
      related_resource_id: workflow.id
    )
  rescue
    e ->
      Logger.error("[Remediation.Notifier] Failed to notify workflow completed: #{inspect(e)}")
      :ok
  end

  @doc """
  Notify when a workflow fails.
  """
  def notify_workflow_failed(%Workflow{} = workflow) do
    workflow = preload_workflow(workflow)

    metadata = build_notification_metadata(workflow)
    users = get_notification_users(workflow, :failed)
    priority = "high"

    dispatch_notification(
      "remediation_workflow_failed",
      "Remediation Failed: #{format_action_type(workflow.action_type)}",
      build_failed_body(workflow),
      organization_id: workflow.organization_id,
      users: users,
      priority: priority,
      metadata: metadata,
      related_resource_type: "workflow",
      related_resource_id: workflow.id
    )
  rescue
    e ->
      Logger.error("[Remediation.Notifier] Failed to notify workflow failed: #{inspect(e)}")
      :ok
  end

  @doc """
  Notify when a workflow is rejected by a user.
  """
  def notify_workflow_rejected(%Workflow{} = workflow) do
    workflow = preload_workflow(workflow)

    metadata = build_notification_metadata(workflow)
    users = get_notification_users(workflow, :rejected)
    priority = "medium"

    dispatch_notification(
      "remediation_workflow_rejected",
      "Remediation Rejected: #{format_action_type(workflow.action_type)}",
      build_rejected_body(workflow),
      organization_id: workflow.organization_id,
      users: users,
      priority: priority,
      metadata: metadata,
      related_resource_type: "workflow",
      related_resource_id: workflow.id
    )
  rescue
    e ->
      Logger.error("[Remediation.Notifier] Failed to notify workflow rejected: #{inspect(e)}")
      :ok
  end

  @doc """
  Notify when a workflow requires approval.

  Sent to organization admins with approval permissions.
  """
  def notify_approval_requested(%Workflow{} = workflow) do
    workflow = preload_workflow(workflow)

    metadata = build_notification_metadata(workflow)
    users = get_approval_users(workflow)
    priority = "critical"

    dispatch_notification(
      "remediation_approval_requested",
      "Approval Required: #{format_action_type(workflow.action_type)} for #{get_alert_title(workflow)}",
      build_approval_body(workflow),
      organization_id: workflow.organization_id,
      users: users,
      priority: priority,
      metadata: metadata,
      related_resource_type: "workflow",
      related_resource_id: workflow.id
    )
  rescue
    e ->
      Logger.error("[Remediation.Notifier] Failed to notify approval requested: #{inspect(e)}")
      :ok
  end

  @doc """
  Notify when a workflow is escalated to a higher approval tier.

  ## Parameters

  - `workflow` - The workflow being escalated
  - `tier` - The new approval tier (e.g., "senior_analyst", "manager", "security_director")
  """
  def notify_escalation(%Workflow{} = workflow, tier) do
    workflow = preload_workflow(workflow)

    metadata = build_notification_metadata(workflow)
    users = get_users_by_tier(workflow.organization_id, tier)
    priority = "critical"

    dispatch_notification(
      "remediation_escalation",
      "ESCALATED: #{format_action_type(workflow.action_type)} requires #{format_tier(tier)} approval",
      build_escalation_body(workflow, tier),
      organization_id: workflow.organization_id,
      users: users,
      priority: priority,
      metadata: metadata,
      related_resource_type: "workflow",
      related_resource_id: workflow.id
    )
  rescue
    e ->
      Logger.error("[Remediation.Notifier] Failed to notify escalation: #{inspect(e)}")
      :ok
  end

  # === Private Helpers ===

  defp preload_workflow(workflow) do
    Repo.preload(workflow, [:alert, :policy, :organization, :approved_by])
  end

  defp dispatch_notification(type, title, body, opts) do
    # Convert opts to map for Dispatcher.dispatch
    opts_map = Enum.into(opts, %{})

    # Dispatch to user notifications via NotificationCenter
    Dispatcher.dispatch(type, title, body, opts_map)

    # Also send to organization-level webhooks
    send_to_webhooks(type, title, body, opts_map)

    Logger.info("[Remediation.Notifier] Dispatched #{type} notification for workflow #{opts[:related_resource_id]}")
    :ok
  rescue
    e ->
      Logger.error("[Remediation.Notifier] Failed to dispatch notification: #{inspect(e)}")
      :ok
  end

  # Send to organization-level webhooks configured for this notification type
  defp send_to_webhooks(type, title, body, opts) do
    organization_id = opts[:organization_id]

    unless organization_id do
      Logger.debug("[Remediation.Notifier] No organization_id, skipping webhook dispatch")
      :ok
    else
      # Find enabled webhooks for this notification type
      webhooks =
        NotificationWebhook
        |> where([w], w.organization_id == ^organization_id)
        |> where([w], w.enabled == true)
        |> Repo.all()
        |> Enum.filter(fn webhook ->
          Enum.empty?(webhook.notification_types) or type in webhook.notification_types
        end)

      # Build webhook payload
      webhook_payload = build_webhook_payload(type, title, body, opts)

      # Enqueue webhook delivery jobs
      Enum.each(webhooks, fn webhook ->
        try do
          %{
            webhook_id: webhook.id,
            payload: webhook_payload,
            direct_delivery: true
          }
          |> WebhookWorker.new()
          |> Oban.insert()
        rescue
          e ->
            Logger.error("[Remediation.Notifier] Failed to enqueue webhook #{webhook.id}: #{inspect(e)}")
        end
      end)

      :ok
    end
  rescue
    e ->
      Logger.error("[Remediation.Notifier] Failed to send to webhooks: #{inspect(e)}")
      :ok
  end

  # Build a structured JSON payload for generic webhooks
  defp build_webhook_payload(type, title, body, opts) do
    metadata = opts[:metadata] || %{}
    alert = extract_alert_info(metadata)
    policy = extract_policy_info(metadata)
    workflow = extract_workflow_info(metadata)

    %{
      event_type: type,
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
      organization_id: opts[:organization_id],
      title: title,
      body: body,
      priority: opts[:priority] || "normal",
      workflow: workflow,
      alert: alert,
      policy: policy
    }
  end

  defp extract_workflow_info(metadata) do
    %{
      id: metadata[:workflow_id],
      state: metadata[:state],
      action_type: metadata[:action_type],
      execution_mode: metadata[:execution_mode],
      retry_count: metadata[:retry_count],
      error_message: metadata[:error_message],
      result_summary: metadata[:result_summary],
      url: metadata[:workflow_url]
    }
  end

  defp extract_alert_info(metadata) do
    %{
      id: metadata[:alert_id],
      title: metadata[:alert_title],
      severity: metadata[:alert_severity],
      threat_score: metadata[:threat_score]
    }
  end

  defp extract_policy_info(metadata) do
    %{
      id: metadata[:policy_id],
      name: metadata[:policy_name]
    }
  end

  defp build_notification_metadata(workflow) do
    alert = workflow.alert || %{title: "Unknown", severity: "unknown", threat_score: 0.0}
    policy = workflow.policy || %{name: "Unknown"}

    %{
      workflow_id: workflow.id,
      alert_id: workflow.alert_id,
      policy_id: workflow.policy_id,
      action_type: workflow.action_type,
      execution_mode: workflow.execution_mode,
      state: workflow.state,
      alert_title: get_in_or_default(alert, :title, "Unknown Alert"),
      alert_severity: get_in_or_default(alert, :severity, "unknown"),
      threat_score: format_threat_score(get_in_or_default(alert, :threat_score, 0.0)),
      policy_name: get_in_or_default(policy, :name, "Unknown Policy"),
      result_summary: extract_result_summary(workflow.result),
      error_message: workflow.error_message,
      retry_count: workflow.retry_count || 0,
      max_retries: 3,
      completed_at: format_datetime(workflow.completed_at),
      workflow_url: build_workflow_url(workflow.id),
      approval_url: build_approval_url(workflow.id),
      severity_color: severity_to_color(get_in_or_default(alert, :severity, "unknown")),
      action_details: format_action_details(workflow.action_config)
    }
  end

  defp get_in_or_default(struct, key, default) when is_struct(struct) do
    Map.get(struct, key, default)
  end

  defp get_in_or_default(map, key, default) when is_map(map) do
    Map.get(map, key, default)
  end

  defp get_in_or_default(_, _, default), do: default

  defp get_notification_users(workflow, event_type) do
    users = []

    # Get alert assignee
    users =
      if workflow.alert && workflow.alert.assigned_to_id do
        [workflow.alert.assigned_to_id | users]
      else
        users
      end

    # For critical events, include org admins
    users =
      if event_type in [:created, :failed] do
        org_admins = get_org_admins(workflow.organization_id)
        users ++ org_admins
      else
        users
      end

    # Remove duplicates
    Enum.uniq(users)
  end

  defp get_approval_users(workflow) do
    # Get organization admins who can approve
    get_org_admins(workflow.organization_id)
  end

  defp get_org_admins(organization_id) when is_binary(organization_id) do
    User
    |> where([u], u.organization_id == ^organization_id)
    |> where([u], u.role == "admin")
    |> select([u], u.id)
    |> Repo.all()
  end

  defp get_org_admins(_), do: []

  # Get users by approval tier for escalation notifications
  defp get_users_by_tier(organization_id, tier) when is_binary(organization_id) do
    # Map tier to minimum required role
    min_role = case tier do
      "analyst" -> "analyst"
      "senior_analyst" -> "senior_analyst"
      "manager" -> "manager"
      "security_director" -> "admin"
      _ -> "admin"
    end

    # Get users with this role or higher
    roles_above = roles_at_or_above(min_role)

    User
    |> where([u], u.organization_id == ^organization_id)
    |> where([u], u.role in ^roles_above)
    |> select([u], u.id)
    |> Repo.all()
  end

  defp get_users_by_tier(_, _), do: []

  defp roles_at_or_above("analyst"), do: ["analyst", "senior_analyst", "manager", "admin"]
  defp roles_at_or_above("senior_analyst"), do: ["senior_analyst", "manager", "admin"]
  defp roles_at_or_above("manager"), do: ["manager", "admin"]
  defp roles_at_or_above("admin"), do: ["admin"]
  defp roles_at_or_above(_), do: ["admin"]

  defp format_tier("analyst"), do: "Analyst"
  defp format_tier("senior_analyst"), do: "Senior Analyst"
  defp format_tier("manager"), do: "Manager"
  defp format_tier("security_director"), do: "Security Director"
  defp format_tier(tier), do: String.capitalize(tier)

  defp priority_from_workflow(workflow) do
    case workflow.execution_mode do
      "pending_approval" -> "critical"
      "auto" -> "medium"
      "queued" -> "normal"
      _ -> "normal"
    end
  end

  defp get_alert_title(workflow) do
    if workflow.alert do
      workflow.alert.title || "Untitled Alert"
    else
      "Unknown Alert"
    end
  end

  defp format_action_type(action_type) do
    action_type
    |> to_string()
    |> String.split("_")
    |> Enum.map(&String.capitalize/1)
    |> Enum.join(" ")
  end

  defp format_threat_score(score) when is_float(score), do: Float.round(score, 2)
  defp format_threat_score(score) when is_integer(score), do: score / 1
  defp format_threat_score(_), do: 0.0

  defp format_datetime(nil), do: nil
  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp format_datetime(_), do: nil

  defp extract_result_summary(nil), do: "No result available"
  defp extract_result_summary(result) when is_map(result) do
    cond do
      Map.has_key?(result, "summary") -> result["summary"]
      Map.has_key?(result, :summary) -> result[:summary]
      Map.has_key?(result, "message") -> result["message"]
      Map.has_key?(result, :message) -> result[:message]
      true -> inspect(result, limit: 100)
    end
  end
  defp extract_result_summary(result), do: inspect(result, limit: 100)

  defp format_action_details(nil), do: "No configuration specified"
  defp format_action_details(config) when is_map(config) do
    config
    |> Enum.map(fn {k, v} -> "  - #{k}: #{inspect(v)}" end)
    |> Enum.join("\n")
  end
  defp format_action_details(_), do: "No configuration specified"

  defp severity_to_color("critical"), do: "#dc2626"  # Red
  defp severity_to_color("high"), do: "#f59e0b"      # Orange
  defp severity_to_color("medium"), do: "#eab308"    # Yellow
  defp severity_to_color("low"), do: "#22c55e"       # Green
  defp severity_to_color(_), do: "#6b7280"           # Gray

  defp build_workflow_url(workflow_id) do
    "#{TamanduaServerWeb.Endpoint.url()}/app/remediation/workflows/#{workflow_id}"
  end

  defp build_approval_url(workflow_id) do
    "#{TamanduaServerWeb.Endpoint.url()}/app/remediation/workflows/#{workflow_id}/approve"
  end

  # === Body Builders ===

  defp build_created_body(workflow) do
    alert = workflow.alert || %{title: "Unknown", severity: "unknown", threat_score: 0.0}
    policy = workflow.policy || %{name: "Unknown"}

    """
    A remediation action has been triggered.

    Alert: #{get_in_or_default(alert, :title, "Unknown")}
    Severity: #{get_in_or_default(alert, :severity, "unknown")}
    Threat Score: #{format_threat_score(get_in_or_default(alert, :threat_score, 0.0))}

    Action Type: #{format_action_type(workflow.action_type)}
    Execution Mode: #{format_execution_mode(workflow.execution_mode)}
    Policy: #{get_in_or_default(policy, :name, "Unknown")}

    Workflow ID: #{workflow.id}
    """
  end

  defp build_approved_body(workflow) do
    alert = workflow.alert || %{title: "Unknown"}
    approver = if workflow.approved_by, do: workflow.approved_by.email, else: "Unknown"

    """
    A remediation action has been approved.

    Alert: #{get_in_or_default(alert, :title, "Unknown")}
    Action Type: #{format_action_type(workflow.action_type)}
    Approved by: #{approver}
    Approval Notes: #{workflow.approval_notes || "None"}

    The action will now be executed.

    Workflow ID: #{workflow.id}
    """
  end

  defp build_started_body(workflow) do
    alert = workflow.alert || %{title: "Unknown"}

    """
    A remediation action has started execution.

    Alert: #{get_in_or_default(alert, :title, "Unknown")}
    Action Type: #{format_action_type(workflow.action_type)}

    The action is now in progress.

    Workflow ID: #{workflow.id}
    """
  end

  defp build_completed_body(workflow) do
    alert = workflow.alert || %{title: "Unknown"}

    """
    A remediation action has completed successfully.

    Alert: #{get_in_or_default(alert, :title, "Unknown")}
    Action Type: #{format_action_type(workflow.action_type)}

    Result: #{extract_result_summary(workflow.result)}

    Workflow ID: #{workflow.id}
    Completed at: #{format_datetime(workflow.completed_at)}
    """
  end

  defp build_failed_body(workflow) do
    alert = workflow.alert || %{title: "Unknown"}
    retry_info = if workflow.retry_count < 3 do
      "The workflow will retry automatically."
    else
      "Maximum retries reached. Manual intervention required."
    end

    """
    A remediation action has failed.

    Alert: #{get_in_or_default(alert, :title, "Unknown")}
    Action Type: #{format_action_type(workflow.action_type)}

    Error: #{workflow.error_message || "Unknown error"}
    Retry Count: #{workflow.retry_count || 0}/3

    #{retry_info}

    Workflow ID: #{workflow.id}
    """
  end

  defp build_approval_body(workflow) do
    alert = workflow.alert || %{title: "Unknown", severity: "unknown", threat_score: 0.0}
    policy = workflow.policy || %{name: "Unknown"}

    """
    A high-risk remediation action requires your approval.

    Alert: #{get_in_or_default(alert, :title, "Unknown")}
    Severity: #{get_in_or_default(alert, :severity, "unknown")}
    Threat Score: #{format_threat_score(get_in_or_default(alert, :threat_score, 0.0))}

    Proposed Action: #{format_action_type(workflow.action_type)}
    Policy: #{get_in_or_default(policy, :name, "Unknown")}

    Action Configuration:
    #{format_action_details(workflow.action_config)}

    Review and approve at: #{build_approval_url(workflow.id)}

    Workflow ID: #{workflow.id}
    """
  end

  defp build_rejected_body(workflow) do
    alert = workflow.alert || %{title: "Unknown"}
    rejecter = if workflow.approved_by, do: workflow.approved_by.email, else: "Unknown"

    """
    A remediation action has been rejected.

    Alert: #{get_in_or_default(alert, :title, "Unknown")}
    Action Type: #{format_action_type(workflow.action_type)}
    Rejected by: #{rejecter}
    Reason: #{workflow.approval_notes || "No reason provided"}

    The action will NOT be executed.

    Workflow ID: #{workflow.id}
    """
  end

  defp build_escalation_body(workflow, tier) do
    alert = workflow.alert || %{title: "Unknown", severity: "unknown", threat_score: 0.0}
    policy = workflow.policy || %{name: "Unknown"}
    escalation_level = workflow.escalation_level || 0
    wait_time = format_wait_time(workflow.inserted_at)

    """
    ESCALATION: A remediation action requires immediate attention.

    This workflow has been escalated to #{format_tier(tier)} level due to
    approval timeout.

    Alert: #{get_in_or_default(alert, :title, "Unknown")}
    Severity: #{get_in_or_default(alert, :severity, "unknown")}
    Threat Score: #{format_threat_score(get_in_or_default(alert, :threat_score, 0.0))}

    Proposed Action: #{format_action_type(workflow.action_type)}
    Policy: #{get_in_or_default(policy, :name, "Unknown")}

    Escalation Level: #{escalation_level + 1}/4
    Time Waiting: #{wait_time}

    Action Configuration:
    #{format_action_details(workflow.action_config)}

    URGENT: Please review and approve/reject at: #{build_approval_url(workflow.id)}

    Workflow ID: #{workflow.id}
    """
  end

  defp format_wait_time(nil), do: "Unknown"
  defp format_wait_time(%DateTime{} = inserted_at) do
    diff = DateTime.diff(DateTime.utc_now(), inserted_at, :second)

    cond do
      diff < 60 -> "#{diff} seconds"
      diff < 3600 -> "#{div(diff, 60)} minutes"
      diff < 86400 -> "#{div(diff, 3600)} hours"
      true -> "#{div(diff, 86400)} days"
    end
  end

  defp format_execution_mode("auto"), do: "Automatic"
  defp format_execution_mode("queued"), do: "Queued"
  defp format_execution_mode("pending_approval"), do: "Pending Approval"
  defp format_execution_mode(mode), do: mode
end
