defmodule TamanduaServer.E2E.SettingsTest do
  @moduledoc """
  E2E tests for settings and configuration management.

  Tests cover:
  - User settings
  - Organization settings
  - Integration settings
  - YARA/Sigma rule management
  - Notification settings
  - API key management
  """

  use TamanduaServer.E2ECase, async: false

  alias Wallaby.Query

  setup %{session: session} do
    org = insert(:organization)
    admin = insert(:user, organization_id: org.id, role: "admin", name: "Admin User")

    session = login_user(session, admin)
    {:ok, session: session, user: admin, org: org}
  end

  describe "user settings" do
    test "can access user settings", %{session: session} do
      session
      |> visit("/settings/profile")
      |> assert_has(Query.css("[data-page='settings']"))
      |> assert_has(Query.css("[data-section='profile']"))
    end

    test "can update profile information", %{session: session, user: user} do
      session
      |> visit("/settings/profile")
      |> fill_in(Query.text_field("Name"), with: "Updated Name")
      |> fill_in(Query.text_field("Email"), with: "updated@example.com")
      |> click(Query.button("Save Changes"))
      |> assert_success("Profile updated successfully")
    end

    test "can change password", %{session: session} do
      session
      |> visit("/settings/security")
      |> fill_in(Query.text_field("Current Password"), with: "password123")
      |> fill_in(Query.text_field("New Password"), with: "NewSecure123!")
      |> fill_in(Query.text_field("Confirm Password"), with: "NewSecure123!")
      |> click(Query.button("Change Password"))
      |> assert_success("Password changed successfully")
    end

    test "password change validates current password", %{session: session} do
      session
      |> visit("/settings/security")
      |> fill_in(Query.text_field("Current Password"), with: "wrongpassword")
      |> fill_in(Query.text_field("New Password"), with: "NewSecure123!")
      |> fill_in(Query.text_field("Confirm Password"), with: "NewSecure123!")
      |> click(Query.button("Change Password"))
      |> assert_error("Current password is incorrect")
    end

    test "can enable MFA", %{session: session} do
      session
      |> visit("/settings/security")
      |> click(Query.button("Enable MFA"))
      |> assert_has(Query.css("[data-qr-code]"))
      |> fill_in(Query.text_field("Verification Code"), with: "123456")
      |> click(Query.button("Verify and Enable"))
    end

    test "shows backup codes after enabling MFA", %{session: session} do
      session
      |> visit("/settings/security")
      |> click(Query.button("Enable MFA"))
      |> fill_in(Query.text_field("Verification Code"), with: "123456")
      |> click(Query.button("Verify and Enable"))
      |> assert_has(Query.css("[data-backup-codes]"))
    end

    test "can disable MFA", %{session: session, user: user} do
      user |> Ecto.Changeset.change(%{mfa_enabled: true}) |> Repo.update!()

      session
      |> visit("/settings/security")
      |> click(Query.button("Disable MFA"))
      |> fill_in(Query.text_field("Password"), with: "password123")
      |> click(Query.button("Confirm"))
      |> assert_success("MFA disabled")
    end

    test "can set timezone", %{session: session} do
      session
      |> visit("/settings/preferences")
      |> select_by_label("Timezone", "America/New_York")
      |> click(Query.button("Save"))
      |> assert_success("Preferences saved")
    end

    test "can set language", %{session: session} do
      session
      |> visit("/settings/preferences")
      |> select_by_label("Language", "English")
      |> click(Query.button("Save"))
      |> assert_success("Preferences saved")
    end

    test "can configure notification preferences", %{session: session} do
      session
      |> visit("/settings/notifications")
      |> toggle_checkbox(Query.css("[data-notification='email_alerts']"))
      |> toggle_checkbox(Query.css("[data-notification='email_reports']"))
      |> click(Query.button("Save"))
      |> assert_success("Notification preferences saved")
    end

    test "can generate API key", %{session: session} do
      session
      |> visit("/settings/api")
      |> click(Query.button("Generate API Key"))
      |> fill_in(Query.text_field("Name"), with: "My API Key")
      |> select_by_label("Permissions", "Read Only")
      |> click(Query.button("Generate"))
      |> assert_success("API key generated")
      |> assert_has(Query.css("[data-api-key]"))
    end

    test "can revoke API key", %{session: session} do
      session
      |> visit("/settings/api")
      |> click(Query.css("[data-api-key]:first-child [data-action='revoke']"))
      |> click(Query.button("Confirm"))
      |> assert_success("API key revoked")
    end
  end

  describe "organization settings" do
    test "can access organization settings", %{session: session} do
      session
      |> visit("/settings/organization")
      |> assert_has(Query.css("[data-section='organization']"))
    end

    test "can update organization name", %{session: session} do
      session
      |> visit("/settings/organization")
      |> fill_in(Query.text_field("Organization Name"), with: "Updated Org Name")
      |> click(Query.button("Save"))
      |> assert_success("Organization updated")
    end

    test "can set retention policies", %{session: session} do
      session
      |> visit("/settings/organization/retention")
      |> fill_in(Query.text_field("Alert Retention (days)"), with: "90")
      |> fill_in(Query.text_field("Event Retention (days)"), with: "30")
      |> click(Query.button("Save"))
      |> assert_success("Retention policies updated")
    end

    test "can configure SLA settings", %{session: session} do
      session
      |> visit("/settings/organization/sla")
      |> fill_in(Query.text_field("Critical Alert Acknowledge (minutes)"), with: "15")
      |> fill_in(Query.text_field("Critical Alert Resolve (hours)"), with: "4")
      |> click(Query.button("Save"))
      |> assert_success("SLA settings saved")
    end

    test "can invite user to organization", %{session: session} do
      session
      |> visit("/settings/organization/users")
      |> click(Query.button("Invite User"))
      |> fill_in(Query.text_field("Email"), with: "newuser@example.com")
      |> select_by_label("Role", "Analyst")
      |> click(Query.button("Send Invitation"))
      |> assert_success("Invitation sent")
    end

    test "can manage user roles", %{session: session, org: org} do
      user = insert(:user, organization_id: org.id, role: "analyst")

      session
      |> visit("/settings/organization/users")
      |> click(Query.css("[data-user='#{user.id}'] [data-action='edit']"))
      |> select_by_label("Role", "Hunter")
      |> click(Query.button("Save"))
      |> assert_success("User role updated")
    end

    test "can deactivate user", %{session: session, org: org} do
      user = insert(:user, organization_id: org.id)

      session
      |> visit("/settings/organization/users")
      |> click(Query.css("[data-user='#{user.id}'] [data-action='deactivate']"))
      |> click(Query.button("Confirm"))
      |> assert_success("User deactivated")
    end

    test "shows audit log", %{session: session} do
      session
      |> visit("/settings/organization/audit")
      |> assert_has(Query.css("[data-audit-log]"))
      |> assert_has(Query.css("[data-audit-entry]", minimum: 0))
    end

    test "can filter audit log", %{session: session} do
      session
      |> visit("/settings/organization/audit")
      |> select_by_label("Action Type", "User Login")
      |> wait_for_ajax()
      |> assert_has(Query.css("[data-action-type='login']"))
    end
  end

  describe "integration settings" do
    test "displays available integrations", %{session: session} do
      session
      |> visit("/settings/integrations")
      |> assert_has(Query.css("[data-integration='slack']"))
      |> assert_has(Query.css("[data-integration='teams']"))
      |> assert_has(Query.css("[data-integration='pagerduty']"))
      |> assert_has(Query.css("[data-integration='splunk']"))
    end

    test "can configure Slack integration", %{session: session} do
      session
      |> visit("/settings/integrations")
      |> click(Query.css("[data-integration='slack'] [data-action='configure']"))
      |> fill_in(Query.text_field("Webhook URL"), with: "https://hooks.slack.com/services/TEST")
      |> fill_in(Query.text_field("Channel"), with: "#security-alerts")
      |> click(Query.button("Save"))
      |> assert_success("Slack integration configured")
    end

    test "can test integration", %{session: session} do
      session
      |> visit("/settings/integrations")
      |> click(Query.css("[data-integration='slack'] [data-action='configure']"))
      |> fill_in(Query.text_field("Webhook URL"), with: "https://hooks.slack.com/services/TEST")
      |> click(Query.button("Test Connection"))
      |> wait_for_notification("Test message sent")
    end

    test "can disable integration", %{session: session} do
      session
      |> visit("/settings/integrations")
      |> toggle_checkbox(Query.css("[data-integration='slack'] [data-enabled]"))
      |> assert_success("Integration disabled")
    end

    test "can configure SIEM integration", %{session: session} do
      session
      |> visit("/settings/integrations")
      |> click(Query.css("[data-integration='splunk'] [data-action='configure']"))
      |> fill_in(Query.text_field("HEC Endpoint"), with: "https://splunk.example.com:8088")
      |> fill_in(Query.text_field("HEC Token"), with: "token123")
      |> select_by_label("Event Types", "Alerts")
      |> click(Query.button("Save"))
      |> assert_success("SIEM integration configured")
    end

    test "can configure ticketing integration", %{session: session} do
      session
      |> visit("/settings/integrations")
      |> click(Query.css("[data-integration='jira'] [data-action='configure']"))
      |> fill_in(Query.text_field("JIRA URL"), with: "https://company.atlassian.net")
      |> fill_in(Query.text_field("API Token"), with: "token123")
      |> fill_in(Query.text_field("Project Key"), with: "SEC")
      |> click(Query.button("Save"))
      |> assert_success("JIRA integration configured")
    end

    test "shows integration usage statistics", %{session: session} do
      session
      |> visit("/settings/integrations")
      |> click(Query.css("[data-integration='slack']"))
      |> assert_has(Query.css("[data-stats]"))
      |> assert_has(Query.css("[data-stat='total_sent']"))
      |> assert_has(Query.css("[data-stat='success_rate']"))
    end
  end

  describe "YARA rule management" do
    test "displays YARA rules list", %{session: session} do
      session
      |> visit("/settings/detection/yara")
      |> assert_has(Query.css("[data-rules-list]"))
    end

    test "can upload YARA rule file", %{session: session} do
      session
      |> visit("/settings/detection/yara")
      |> click(Query.button("Upload Rules"))
      |> attach_file(Query.file_field("File"), path: "test/fixtures/test_rule.yar")
      |> click(Query.button("Upload"))
      |> assert_success("YARA rules uploaded")
    end

    test "can create YARA rule", %{session: session} do
      session
      |> visit("/settings/detection/yara")
      |> click(Query.button("Create Rule"))
      |> fill_in(Query.text_field("Rule Name"), with: "test_malware")
      |> fill_in(Query.css("[data-rule-content]"), with: """
        rule test_malware {
          strings:
            $str1 = "malware"
          condition:
            $str1
        }
        """)
      |> click(Query.button("Save"))
      |> assert_success("YARA rule created")
    end

    test "validates YARA rule syntax", %{session: session} do
      session
      |> visit("/settings/detection/yara")
      |> click(Query.button("Create Rule"))
      |> fill_in(Query.css("[data-rule-content]"), with: "invalid syntax")
      |> click(Query.button("Validate"))
      |> assert_error("Invalid YARA syntax")
    end

    test "can enable/disable YARA rule", %{session: session} do
      session
      |> visit("/settings/detection/yara")
      |> toggle_checkbox(Query.css("[data-rule]:first-child [data-enabled]"))
      |> assert_success("Rule status updated")
    end

    test "can delete YARA rule", %{session: session} do
      session
      |> visit("/settings/detection/yara")
      |> click(Query.css("[data-rule]:first-child [data-action='delete']"))
      |> click(Query.button("Confirm"))
      |> assert_success("Rule deleted")
    end

    test "shows rule match statistics", %{session: session} do
      session
      |> visit("/settings/detection/yara")
      |> click(Query.css("[data-rule]:first-child"))
      |> assert_has(Query.css("[data-stats]"))
      |> assert_has(Query.css("[data-stat='matches']"))
      |> assert_has(Query.css("[data-stat='last_match']"))
    end
  end

  describe "Sigma rule management" do
    test "displays Sigma rules list", %{session: session} do
      session
      |> visit("/settings/detection/sigma")
      |> assert_has(Query.css("[data-rules-list]"))
    end

    test "can upload Sigma rule file", %{session: session} do
      session
      |> visit("/settings/detection/sigma")
      |> click(Query.button("Upload Rules"))
      |> attach_file(Query.file_field("File"), path: "test/fixtures/test_sigma.yml")
      |> click(Query.button("Upload"))
      |> assert_success("Sigma rules uploaded")
    end

    test "can create Sigma rule", %{session: session} do
      session
      |> visit("/settings/detection/sigma")
      |> click(Query.button("Create Rule"))
      |> fill_in(Query.text_field("Title"), with: "Suspicious PowerShell")
      |> fill_in(Query.css("[data-rule-content]"), with: """
        detection:
          selection:
            EventID: 4688
            Image|endswith: 'powershell.exe'
          condition: selection
        """)
      |> click(Query.button("Save"))
      |> assert_success("Sigma rule created")
    end

    test "can test Sigma rule", %{session: session} do
      session
      |> visit("/settings/detection/sigma")
      |> click(Query.css("[data-rule]:first-child"))
      |> click(Query.button("Test Rule"))
      |> fill_in(Query.css("[data-test-event]"), with: ~s({"EventID": 4688, "Image": "powershell.exe"}))
      |> click(Query.button("Run Test"))
      |> assert_has(Query.css("[data-test-result]"))
    end

    test "can filter rules by MITRE technique", %{session: session} do
      session
      |> visit("/settings/detection/sigma")
      |> apply_filter("technique", "T1059")
      |> wait_for_ajax()
      |> assert_has(Query.css("[data-technique='T1059']"))
    end
  end

  describe "notification settings" do
    test "can configure email notifications", %{session: session} do
      session
      |> visit("/settings/notifications/email")
      |> fill_in(Query.text_field("SMTP Server"), with: "smtp.example.com")
      |> fill_in(Query.text_field("SMTP Port"), with: "587")
      |> fill_in(Query.text_field("Username"), with: "alerts@example.com")
      |> fill_in(Query.text_field("Password"), with: "password123")
      |> click(Query.button("Save"))
      |> assert_success("Email settings saved")
    end

    test "can test email configuration", %{session: session} do
      session
      |> visit("/settings/notifications/email")
      |> fill_in(Query.text_field("Test Email"), with: "test@example.com")
      |> click(Query.button("Send Test Email"))
      |> wait_for_notification("Test email sent")
    end

    test "can configure notification templates", %{session: session} do
      session
      |> visit("/settings/notifications/templates")
      |> click(Query.css("[data-template='alert_created']"))
      |> fill_in(Query.text_field("Subject"), with: "Alert: {{ alert.title }}")
      |> fill_in(Query.css("[data-body]"), with: "Severity: {{ alert.severity }}")
      |> click(Query.button("Save"))
      |> assert_success("Template saved")
    end

    test "template editor has syntax help", %{session: session} do
      session
      |> visit("/settings/notifications/templates")
      |> click(Query.css("[data-template='alert_created']"))
      |> assert_has(Query.css("[data-syntax-help]"))
      |> click(Query.button("Available Variables"))
      |> assert_has(Query.css("[data-variables-list]"))
    end

    test "can preview notification template", %{session: session} do
      session
      |> visit("/settings/notifications/templates")
      |> click(Query.css("[data-template='alert_created']"))
      |> click(Query.button("Preview"))
      |> assert_has(Query.css("[data-preview-modal]"))
    end
  end

  describe "threat intelligence feeds" do
    test "displays configured feeds", %{session: session} do
      session
      |> visit("/settings/threat-intel")
      |> assert_has(Query.css("[data-feeds-list]"))
    end

    test "can add threat intelligence feed", %{session: session} do
      session
      |> visit("/settings/threat-intel")
      |> click(Query.button("Add Feed"))
      |> select_by_label("Feed Type", "STIX/TAXII")
      |> fill_in(Query.text_field("Name"), with: "My Threat Feed")
      |> fill_in(Query.text_field("URL"), with: "https://threatfeed.example.com/taxii")
      |> fill_in(Query.text_field("API Key"), with: "key123")
      |> click(Query.button("Add"))
      |> assert_success("Feed added")
    end

    test "can sync threat intel feed", %{session: session} do
      session
      |> visit("/settings/threat-intel")
      |> click(Query.css("[data-feed]:first-child [data-action='sync']"))
      |> wait_for_notification("Sync started")
    end

    test "shows feed sync status", %{session: session} do
      session
      |> visit("/settings/threat-intel")
      |> assert_has(Query.css("[data-feed] [data-sync-status]"))
      |> assert_has(Query.css("[data-feed] [data-last-sync]"))
    end

    test "can configure auto-sync schedule", %{session: session} do
      session
      |> visit("/settings/threat-intel")
      |> click(Query.css("[data-feed]:first-child [data-action='configure']"))
      |> toggle_checkbox(Query.css("[data-auto-sync]"))
      |> select_by_label("Sync Frequency", "Every 6 hours")
      |> click(Query.button("Save"))
      |> assert_success("Feed configuration saved")
    end
  end

  describe "advanced settings" do
    test "can configure agent enrollment settings", %{session: session} do
      session
      |> visit("/settings/advanced/enrollment")
      |> toggle_checkbox(Query.css("[data-auto-approve]"))
      |> fill_in(Query.text_field("Token Expiry (hours)"), with: "24")
      |> click(Query.button("Save"))
      |> assert_success("Enrollment settings saved")
    end

    test "can manage certificate settings", %{session: session} do
      session
      |> visit("/settings/advanced/certificates")
      |> assert_has(Query.css("[data-ca-certificate]"))
      |> click(Query.button("Upload CA Certificate"))
    end

    test "can configure log settings", %{session: session} do
      session
      |> visit("/settings/advanced/logs")
      |> select_by_label("Log Level", "Debug")
      |> toggle_checkbox(Query.css("[data-export-logs]"))
      |> click(Query.button("Save"))
      |> assert_success("Log settings saved")
    end

    test "can export configuration", %{session: session} do
      session
      |> visit("/settings/advanced/backup")
      |> click(Query.button("Export Configuration"))
      |> wait_for_notification("Export started")
    end

    test "can import configuration", %{session: session} do
      session
      |> visit("/settings/advanced/backup")
      |> click(Query.button("Import Configuration"))
      |> attach_file(Query.file_field("File"), path: "test/fixtures/config_backup.json")
      |> click(Query.button("Import"))
      |> assert_success("Configuration imported")
    end
  end
end
