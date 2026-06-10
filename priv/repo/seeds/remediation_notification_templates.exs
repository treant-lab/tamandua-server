# Seed default notification templates for remediation workflows
# Run with: mix run priv/repo/seeds/remediation_notification_templates.exs
#
# This seeds 12 default templates for remediation events:
# - 4 email templates
# - 4 Slack templates
# - 4 Discord templates
#
# Templates support EEx variable substitution with workflow, alert, and policy context.

alias TamanduaServer.{Repo}
alias TamanduaServer.NotificationCenter.NotificationTemplate

IO.puts("Seeding remediation notification templates...")

# Helper to upsert templates
defmodule RemediationTemplateSeed do
  def upsert_template(attrs) do
    import Ecto.Query

    case Repo.one(
           from(t in NotificationTemplate,
             where: t.type == ^attrs.type and t.channel == ^attrs.channel and is_nil(t.organization_id)
           )
         ) do
      nil ->
        %NotificationTemplate{}
        |> NotificationTemplate.changeset(attrs)
        |> Repo.insert!()

      existing ->
        existing
        |> NotificationTemplate.changeset(attrs)
        |> Repo.update!()
    end
  end
end

# === Email Templates ===

RemediationTemplateSeed.upsert_template(%{
  type: "remediation_workflow_created",
  channel: "email",
  name: "Remediation Workflow Created",
  description: "Email sent when a new remediation workflow is triggered",
  is_default: true,
  subject_template: "[Tamandua] Remediation Action Triggered: <%= action_type %>",
  body_template: """
  A remediation action has been triggered:

  Alert: <%= alert_title %>
  Severity: <%= alert_severity %>
  Threat Score: <%= threat_score %>

  Action Type: <%= action_type %>
  Execution Mode: <%= execution_mode %>
  Policy: <%= policy_name %>

  Workflow ID: <%= workflow_id %>

  <%= if execution_mode == "pending_approval" do %>
  This action requires approval before execution.
  Visit the approval queue to review.
  <% end %>

  View workflow: <%= workflow_url %>

  ---
  Tamandua EDR - Automated Security Response
  """
})

RemediationTemplateSeed.upsert_template(%{
  type: "remediation_workflow_completed",
  channel: "email",
  name: "Remediation Workflow Completed",
  description: "Email sent when a remediation action completes successfully",
  is_default: true,
  subject_template: "[Tamandua] Remediation Completed: <%= action_type %>",
  body_template: """
  Remediation action completed successfully:

  Alert: <%= alert_title %>
  Action Type: <%= action_type %>

  Result Summary:
  <%= result_summary %>

  Workflow ID: <%= workflow_id %>
  Completed at: <%= completed_at %>

  View workflow: <%= workflow_url %>

  ---
  Tamandua EDR - Automated Security Response
  """
})

RemediationTemplateSeed.upsert_template(%{
  type: "remediation_workflow_failed",
  channel: "email",
  name: "Remediation Workflow Failed",
  description: "Email sent when a remediation action fails",
  is_default: true,
  subject_template: "[Tamandua] Remediation Failed: <%= action_type %>",
  body_template: """
  Remediation action failed:

  Alert: <%= alert_title %>
  Action Type: <%= action_type %>

  Error: <%= error_message %>
  Retry Count: <%= retry_count %>/<%= max_retries %>

  <%= if retry_count < max_retries do %>
  The workflow will retry automatically.
  <% else %>
  Maximum retries reached. Manual intervention required.
  <% end %>

  Workflow ID: <%= workflow_id %>

  View workflow: <%= workflow_url %>

  ---
  Tamandua EDR - Automated Security Response
  """
})

RemediationTemplateSeed.upsert_template(%{
  type: "remediation_approval_requested",
  channel: "email",
  name: "Remediation Approval Required",
  description: "Email sent when a high-risk action requires approval",
  is_default: true,
  subject_template: "[Tamandua] Approval Required: <%= action_type %>",
  body_template: """
  A high-risk remediation action requires your approval:

  Alert: <%= alert_title %>
  Severity: <%= alert_severity %>
  Threat Score: <%= threat_score %>

  Proposed Action: <%= action_type %>
  Policy: <%= policy_name %>

  Action Details:
  <%= action_details %>

  Workflow ID: <%= workflow_id %>

  Review and approve: <%= approval_url %>

  ---
  Tamandua EDR - Automated Security Response
  """
})

# === Slack Templates ===

RemediationTemplateSeed.upsert_template(%{
  type: "remediation_workflow_created",
  channel: "slack",
  name: "Remediation Workflow Created (Slack)",
  description: "Slack message for new remediation workflows",
  is_default: true,
  subject_template: "Remediation Action Triggered",
  body_template: """
  {
    "text": "Remediation Action Triggered: <%= action_type %>",
    "attachments": [
      {
        "color": "<%= severity_color %>",
        "fields": [
          {"title": "Alert", "value": "<%= alert_title %>", "short": true},
          {"title": "Severity", "value": "<%= alert_severity %>", "short": true},
          {"title": "Threat Score", "value": "<%= threat_score %>", "short": true},
          {"title": "Action", "value": "<%= action_type %>", "short": true},
          {"title": "Mode", "value": "<%= execution_mode %>", "short": true},
          {"title": "Policy", "value": "<%= policy_name %>", "short": false}
        ],
        "footer": "Workflow ID: <%= workflow_id %>"
      }
    ]
  }
  """
})

RemediationTemplateSeed.upsert_template(%{
  type: "remediation_workflow_completed",
  channel: "slack",
  name: "Remediation Workflow Completed (Slack)",
  description: "Slack message for successful remediation completion",
  is_default: true,
  subject_template: "Remediation Completed",
  body_template: """
  {
    "text": "Remediation Completed: <%= action_type %>",
    "attachments": [
      {
        "color": "good",
        "fields": [
          {"title": "Alert", "value": "<%= alert_title %>", "short": true},
          {"title": "Action", "value": "<%= action_type %>", "short": true},
          {"title": "Result", "value": "<%= result_summary %>", "short": false}
        ],
        "footer": "Workflow ID: <%= workflow_id %>"
      }
    ]
  }
  """
})

RemediationTemplateSeed.upsert_template(%{
  type: "remediation_workflow_failed",
  channel: "slack",
  name: "Remediation Workflow Failed (Slack)",
  description: "Slack message for failed remediation actions",
  is_default: true,
  subject_template: "Remediation Failed",
  body_template: """
  {
    "text": "Remediation Failed: <%= action_type %>",
    "attachments": [
      {
        "color": "danger",
        "fields": [
          {"title": "Alert", "value": "<%= alert_title %>", "short": true},
          {"title": "Action", "value": "<%= action_type %>", "short": true},
          {"title": "Error", "value": "<%= error_message %>", "short": false},
          {"title": "Retry Count", "value": "<%= retry_count %>/<%= max_retries %>", "short": true}
        ],
        "footer": "Workflow ID: <%= workflow_id %>"
      }
    ]
  }
  """
})

RemediationTemplateSeed.upsert_template(%{
  type: "remediation_approval_requested",
  channel: "slack",
  name: "Remediation Approval Required (Slack)",
  description: "Slack message for approval requests",
  is_default: true,
  subject_template: "Approval Required",
  body_template: """
  {
    "text": "High-Risk Action Requires Approval",
    "attachments": [
      {
        "color": "warning",
        "fields": [
          {"title": "Alert", "value": "<%= alert_title %>", "short": true},
          {"title": "Severity", "value": "<%= alert_severity %>", "short": true},
          {"title": "Threat Score", "value": "<%= threat_score %>", "short": true},
          {"title": "Proposed Action", "value": "<%= action_type %>", "short": true},
          {"title": "Policy", "value": "<%= policy_name %>", "short": false}
        ],
        "actions": [
          {
            "type": "button",
            "text": "Review & Approve",
            "url": "<%= approval_url %>"
          }
        ],
        "footer": "Workflow ID: <%= workflow_id %>"
      }
    ]
  }
  """
})

# === Discord Templates ===

RemediationTemplateSeed.upsert_template(%{
  type: "remediation_workflow_created",
  channel: "discord",
  name: "Remediation Workflow Created (Discord)",
  description: "Discord embed for new remediation workflows",
  is_default: true,
  subject_template: "Remediation Action Triggered",
  body_template: """
  A remediation action has been triggered for alert: **<%= alert_title %>**

  **Action Type:** <%= action_type %>
  **Execution Mode:** <%= execution_mode %>
  **Policy:** <%= policy_name %>

  **Alert Details:**
  - Severity: <%= alert_severity %>
  - Threat Score: <%= threat_score %>

  <%= if execution_mode == "pending_approval" do %>
  :warning: **This action requires approval before execution.**
  <% end %>

  Workflow ID: `<%= workflow_id %>`
  """
})

RemediationTemplateSeed.upsert_template(%{
  type: "remediation_workflow_completed",
  channel: "discord",
  name: "Remediation Workflow Completed (Discord)",
  description: "Discord embed for successful remediation completion",
  is_default: true,
  subject_template: "Remediation Completed",
  body_template: """
  Remediation action completed successfully.

  **Alert:** <%= alert_title %>
  **Action:** <%= action_type %>

  **Result:**
  <%= result_summary %>

  Workflow ID: `<%= workflow_id %>`
  Completed: <%= completed_at %>
  """
})

RemediationTemplateSeed.upsert_template(%{
  type: "remediation_workflow_failed",
  channel: "discord",
  name: "Remediation Workflow Failed (Discord)",
  description: "Discord embed for failed remediation actions",
  is_default: true,
  subject_template: "Remediation Failed",
  body_template: """
  Remediation action failed.

  **Alert:** <%= alert_title %>
  **Action:** <%= action_type %>

  **Error:** <%= error_message %>
  **Retry Count:** <%= retry_count %>/<%= max_retries %>

  <%= if retry_count < max_retries do %>
  The workflow will retry automatically.
  <% else %>
  :warning: **Maximum retries reached. Manual intervention required.**
  <% end %>

  Workflow ID: `<%= workflow_id %>`
  """
})

RemediationTemplateSeed.upsert_template(%{
  type: "remediation_approval_requested",
  channel: "discord",
  name: "Remediation Approval Required (Discord)",
  description: "Discord embed for approval requests",
  is_default: true,
  subject_template: "Approval Required",
  body_template: """
  A high-risk remediation action requires approval.

  **Alert:** <%= alert_title %>
  **Severity:** <%= alert_severity %>
  **Threat Score:** <%= threat_score %>

  **Proposed Action:** <%= action_type %>
  **Policy:** <%= policy_name %>

  **Action Details:**
  <%= action_details %>

  [Review and Approve](<%= approval_url %>)

  Workflow ID: `<%= workflow_id %>`
  """
})

IO.puts("Remediation notification templates seeded (12 templates: 4 email + 4 slack + 4 discord)")
