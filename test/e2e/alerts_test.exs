defmodule TamanduaServer.E2E.AlertsTest do
  @moduledoc """
  E2E tests for alert management functionality.

  Tests cover:
  - Alert list view and filtering
  - Alert detail view
  - Alert triage workflow
  - Alert correlation
  - Timeline visualization
  - Bulk operations
  - Alert assignment
  """

  use TamanduaServer.E2ECase, async: false

  alias Wallaby.Query

  setup %{session: session} do
    org = insert(:organization)
    user = insert(:user, organization_id: org.id, role: "analyst", name: "Test Analyst")
    agent = insert(:agent, organization_id: org.id, hostname: "test-host-001")

    # Create alerts with different severities and statuses
    critical_alert = insert(:alert,
      organization_id: org.id,
      agent: agent,
      severity: "critical",
      status: "new",
      title: "Suspected Ransomware Activity"
    )

    high_alert = insert(:alert,
      organization_id: org.id,
      agent: agent,
      severity: "high",
      status: "investigating",
      title: "Suspicious PowerShell Execution",
      assigned_to: user
    )

    resolved_alert = insert(:alert,
      organization_id: org.id,
      agent: agent,
      severity: "medium",
      status: "resolved",
      title: "Resolved Test Alert"
    )

    session = login_user(session, user)

    {:ok,
     session: session,
     user: user,
     org: org,
     agent: agent,
     critical_alert: critical_alert,
     high_alert: high_alert,
     resolved_alert: resolved_alert}
  end

  describe "alert list view" do
    test "displays all alerts in a table", %{session: session} do
      session
      |> visit("/alerts")
      |> assert_has(Query.css("[data-page='alerts']"))
      |> assert_has(Query.css("table[data-alerts-table]"))
      |> assert_has(Query.css("tbody tr", minimum: 1))
    end

    test "shows alert metadata columns", %{session: session, critical_alert: alert} do
      session
      |> visit("/alerts")
      |> assert_has(Query.css("[data-column='severity']"))
      |> assert_has(Query.css("[data-column='title']"))
      |> assert_has(Query.css("[data-column='status']"))
      |> assert_has(Query.css("[data-column='agent']"))
      |> assert_has(Query.css("[data-column='timestamp']"))
      |> assert_has(Query.text(alert.title))
    end

    test "severity is displayed with color coding", %{session: session} do
      session
      |> visit("/alerts")
      |> assert_has(Query.css("[data-severity='critical']", class: "text-red"))
      |> assert_has(Query.css("[data-severity='high']", class: "text-orange"))
    end

    test "status badges are displayed correctly", %{session: session} do
      session
      |> visit("/alerts")
      |> assert_has(Query.css("[data-status='new']"))
      |> assert_has(Query.css("[data-status='investigating']"))
      |> assert_has(Query.css("[data-status='resolved']"))
    end

    test "can sort by severity", %{session: session} do
      session
      |> visit("/alerts")
      |> sort_table_by("severity")
      |> wait_for_ajax()
      |> assert_has(Query.css("th[data-column='severity'][data-sort='desc']"))
    end

    test "can sort by timestamp", %{session: session} do
      session
      |> visit("/alerts")
      |> sort_table_by("timestamp")
      |> wait_for_ajax()
      |> assert_has(Query.css("th[data-column='timestamp'][data-sort='desc']"))
    end

    test "pagination works correctly", %{session: session, org: org, agent: agent} do
      # Create enough alerts to require pagination
      insert_list(25, :alert, organization_id: org.id, agent: agent)

      session
      |> visit("/alerts")
      |> assert_table_row_count(20)  # Default page size
      |> next_page()
      |> assert_table_row_count(8)   # Remaining alerts
    end

    test "can change page size", %{session: session, org: org, agent: agent} do
      insert_list(15, :alert, organization_id: org.id, agent: agent)

      session
      |> visit("/alerts")
      |> change_page_size(50)
      |> wait_for_ajax()
      |> assert_table_row_count(18)  # All alerts on one page
    end
  end

  describe "alert filtering" do
    test "can filter by severity", %{session: session} do
      session
      |> visit("/alerts")
      |> apply_filter("severity", "critical")
      |> wait_for_ajax()
      |> assert_has(Query.css("[data-severity='critical']"))
      |> refute_has(Query.css("[data-severity='high']"))
    end

    test "can filter by status", %{session: session} do
      session
      |> visit("/alerts")
      |> apply_filter("status", "investigating")
      |> wait_for_ajax()
      |> assert_has(Query.css("[data-status='investigating']"))
      |> refute_has(Query.css("[data-status='new']"))
    end

    test "can filter by agent", %{session: session, agent: agent} do
      session
      |> visit("/alerts")
      |> fill_in(Query.css("[data-filter='agent']"), with: agent.hostname)
      |> wait_for_search_results()
      |> click(Query.css("[data-agent-option='#{agent.id}']"))
      |> wait_for_ajax()
      |> assert_has(Query.text(agent.hostname))
    end

    test "can filter by MITRE technique", %{session: session} do
      session
      |> visit("/alerts")
      |> apply_filter("technique", "T1059.001")
      |> wait_for_ajax()
      |> assert_has(Query.css("[data-technique='T1059.001']"))
    end

    test "can combine multiple filters", %{session: session} do
      session
      |> visit("/alerts")
      |> apply_filter("severity", "critical")
      |> apply_filter("status", "new")
      |> wait_for_ajax()
      |> assert_has(Query.css("[data-severity='critical'][data-status='new']"))
    end

    test "can search alerts by text", %{session: session, critical_alert: alert} do
      session
      |> visit("/alerts")
      |> search_for(alert.title)
      |> assert_has(Query.text(alert.title))
    end

    test "can clear all filters", %{session: session} do
      session
      |> visit("/alerts")
      |> apply_filter("severity", "critical")
      |> click(Query.button("Clear Filters"))
      |> wait_for_ajax()
      |> assert_has(Query.css("[data-severity]", minimum: 2))
    end

    test "can save filter as saved search", %{session: session} do
      session
      |> visit("/alerts")
      |> apply_filter("severity", "critical")
      |> apply_filter("status", "new")
      |> click(Query.button("Save Search"))
      |> fill_in(Query.text_field("Name"), with: "Critical New Alerts")
      |> click(Query.button("Save"))
      |> assert_success("Search saved successfully")
    end

    test "can load saved search", %{session: session} do
      # Create a saved search first
      insert(:saved_search,
        user: session.user,
        name: "My Saved Search",
        filter_json: %{
          "logic" => "AND",
          "conditions" => [
            %{"field" => "severity", "operator" => "eq", "value" => "critical"}
          ]
        }
      )

      session
      |> visit("/alerts")
      |> click(Query.css("[data-action='load-search']"))
      |> click(Query.text("My Saved Search"))
      |> wait_for_ajax()
      |> assert_has(Query.css("[data-active-filter='severity:critical']"))
    end
  end

  describe "alert detail view" do
    test "clicking alert row opens detail modal", %{session: session, critical_alert: alert} do
      session
      |> visit("/alerts")
      |> click(Query.css("[data-alert-id='#{alert.id}']"))
      |> assert_has(Query.css("[data-modal='alert-detail']", visible: true))
      |> assert_has(Query.text(alert.title))
    end

    test "alert detail shows all metadata", %{session: session, critical_alert: alert} do
      session
      |> visit("/alerts/#{alert.id}")
      |> assert_has(Query.css("[data-field='title']", text: alert.title))
      |> assert_has(Query.css("[data-field='severity']", text: alert.severity))
      |> assert_has(Query.css("[data-field='status']", text: alert.status))
      |> assert_has(Query.css("[data-field='agent']"))
      |> assert_has(Query.css("[data-field='timestamp']"))
    end

    test "shows MITRE ATT&CK tactics and techniques", %{session: session, critical_alert: alert} do
      session
      |> visit("/alerts/#{alert.id}")
      |> assert_has(Query.css("[data-mitre-tactics]"))
      |> assert_has(Query.css("[data-mitre-techniques]"))
      |> assert_has(Query.text("T1059.001"))
    end

    test "displays process chain", %{session: session, critical_alert: alert} do
      # Update alert with process chain
      alert
      |> Ecto.Changeset.change(%{
        process_chain: [
          %{"pid" => 1234, "name" => "cmd.exe", "cmdline" => "cmd.exe"},
          %{"pid" => 5678, "name" => "powershell.exe", "cmdline" => "powershell.exe -enc ..."}
        ]
      })
      |> Repo.update!()

      session
      |> visit("/alerts/#{alert.id}")
      |> assert_has(Query.css("[data-process-chain]"))
      |> assert_has(Query.text("cmd.exe"))
      |> assert_has(Query.text("powershell.exe"))
    end

    test "shows evidence section", %{session: session, critical_alert: alert} do
      session
      |> visit("/alerts/#{alert.id}")
      |> assert_has(Query.css("[data-section='evidence']"))
      |> assert_has(Query.css("[data-evidence-items]"))
    end

    test "can view raw event data", %{session: session, critical_alert: alert} do
      session
      |> visit("/alerts/#{alert.id}")
      |> switch_tab("Raw Event")
      |> assert_has(Query.css("[data-raw-event]"))
      |> assert_has(Query.css("pre code"))
    end

    test "can copy alert ID", %{session: session, critical_alert: alert} do
      session
      |> visit("/alerts/#{alert.id}")
      |> click(Query.css("[data-action='copy-id']"))
      |> wait_for_notification("Alert ID copied to clipboard")
    end

    test "can export alert as JSON", %{session: session, critical_alert: alert} do
      session
      |> visit("/alerts/#{alert.id}")
      |> click(Query.css("[data-action='export']"))
      |> click(Query.css("[data-format='json']"))
      # Download would start
    end
  end

  describe "alert triage workflow" do
    test "can change alert status", %{session: session, critical_alert: alert} do
      session
      |> visit("/alerts/#{alert.id}")
      |> click(Query.css("[data-action='change-status']"))
      |> select_dropdown_option("[data-status-dropdown]", "Investigating")
      |> click(Query.button("Update Status"))
      |> assert_success("Alert status updated")
      |> assert_has(Query.css("[data-status='investigating']"))
    end

    test "can assign alert to self", %{session: session, critical_alert: alert, user: user} do
      session
      |> visit("/alerts/#{alert.id}")
      |> click(Query.button("Assign to Me"))
      |> assert_success("Alert assigned to you")
      |> assert_has(Query.text(user.name))
    end

    test "can assign alert to another user", %{session: session, critical_alert: alert, org: org} do
      other_user = insert(:user, organization_id: org.id, name: "Other Analyst")

      session
      |> visit("/alerts/#{alert.id}")
      |> click(Query.css("[data-action='assign']"))
      |> search_for(other_user.name)
      |> click(Query.css("[data-user-option='#{other_user.id}']"))
      |> click(Query.button("Assign"))
      |> assert_success("Alert assigned")
      |> assert_has(Query.text(other_user.name))
    end

    test "can add resolution notes when resolving", %{session: session, critical_alert: alert} do
      session
      |> visit("/alerts/#{alert.id}")
      |> click(Query.button("Resolve"))
      |> fill_in(Query.css("[data-resolution-notes]"), with: "False positive - whitelisted process")
      |> select_by_label("Resolution Type", "False Positive")
      |> click(Query.button("Confirm Resolution"))
      |> assert_success("Alert resolved")
      |> assert_has(Query.css("[data-status='resolved']"))
    end

    test "can escalate alert", %{session: session, critical_alert: alert, org: org} do
      senior_analyst = insert(:user, organization_id: org.id, name: "Senior Analyst", role: "admin")

      session
      |> visit("/alerts/#{alert.id}")
      |> click(Query.button("Escalate"))
      |> search_for(senior_analyst.name)
      |> click(Query.css("[data-user-option='#{senior_analyst.id}']"))
      |> fill_in(Query.text_field("Reason"), with: "Requires advanced investigation")
      |> click(Query.button("Escalate"))
      |> assert_success("Alert escalated")
    end

    test "can acknowledge alert", %{session: session, critical_alert: alert} do
      session
      |> visit("/alerts/#{alert.id}")
      |> click(Query.button("Acknowledge"))
      |> assert_success("Alert acknowledged")
      |> assert_has(Query.css("[data-acknowledged='true']"))
    end

    test "can mark as false positive", %{session: session, critical_alert: alert} do
      session
      |> visit("/alerts/#{alert.id}")
      |> click(Query.button("Mark as False Positive"))
      |> fill_in(Query.css("[data-reason]"), with: "Known good process")
      |> toggle_checkbox(Query.css("[data-create-suppression]"))
      |> click(Query.button("Confirm"))
      |> assert_success("Alert marked as false positive")
    end

    test "marking false positive creates suppression rule", %{session: session, critical_alert: alert} do
      session
      |> visit("/alerts/#{alert.id}")
      |> click(Query.button("Mark as False Positive"))
      |> toggle_checkbox(Query.css("[data-create-suppression]"))
      |> click(Query.button("Confirm"))
      |> assert_success("Suppression rule created")
    end
  end

  describe "alert comments and activity" do
    test "can add comment to alert", %{session: session, critical_alert: alert} do
      session
      |> visit("/alerts/#{alert.id}")
      |> add_alert_comment("This looks like a credential dumping attempt")
      |> assert_has(Query.css("[data-comment]", text: "This looks like a credential dumping attempt"))
    end

    test "comments show author and timestamp", %{session: session, critical_alert: alert, user: user} do
      session
      |> visit("/alerts/#{alert.id}")
      |> add_alert_comment("Test comment")
      |> assert_has(Query.css("[data-comment-author]", text: user.name))
      |> assert_has(Query.css("[data-comment-timestamp]"))
    end

    test "can edit own comment", %{session: session, critical_alert: alert} do
      session
      |> visit("/alerts/#{alert.id}")
      |> add_alert_comment("Original comment")
      |> click(Query.css("[data-comment-actions] [data-action='edit']"))
      |> fill_in(Query.css("[data-edit-comment]"), with: "Updated comment")
      |> click(Query.button("Save"))
      |> assert_has(Query.text("Updated comment"))
    end

    test "can delete own comment", %{session: session, critical_alert: alert} do
      session
      |> visit("/alerts/#{alert.id}")
      |> add_alert_comment("Comment to delete")
      |> click(Query.css("[data-comment-actions] [data-action='delete']"))
      |> click(Query.button("Confirm"))
      |> refute_has(Query.text("Comment to delete"))
    end

    test "activity timeline shows status changes", %{session: session, critical_alert: alert} do
      session
      |> visit("/alerts/#{alert.id}")
      |> switch_tab("Activity")
      |> assert_has(Query.css("[data-activity-timeline]"))
      |> assert_has(Query.css("[data-activity-type='created']"))
    end

    test "activity timeline shows assignments", %{session: session, high_alert: alert, user: user} do
      session
      |> visit("/alerts/#{alert.id}")
      |> switch_tab("Activity")
      |> assert_has(Query.css("[data-activity-type='assigned']"))
      |> assert_has(Query.text("assigned to #{user.name}"))
    end

    test "can mention users in comments", %{session: session, critical_alert: alert, org: org} do
      other_user = insert(:user, organization_id: org.id, name: "Jane Doe")

      session
      |> visit("/alerts/#{alert.id}")
      |> fill_in(Query.css("[data-comment-input]"), with: "@Jane")
      |> wait_for(Query.css("[data-mention-suggestions]"))
      |> click(Query.css("[data-mention='#{other_user.id}']"))
      |> click(Query.button("Add Comment"))
      |> assert_has(Query.css("[data-mention]", text: "@Jane Doe"))
    end
  end

  describe "alert correlation" do
    test "shows related alerts", %{session: session, critical_alert: alert, agent: agent, org: org} do
      # Create related alert
      related_alert = insert(:alert,
        organization_id: org.id,
        agent: agent,
        title: "Related Alert",
        mitre_techniques: alert.mitre_techniques
      )

      session
      |> visit("/alerts/#{alert.id}")
      |> switch_tab("Related Alerts")
      |> assert_has(Query.css("[data-related-alerts]"))
      |> assert_has(Query.text(related_alert.title))
    end

    test "shows correlation reasons", %{session: session, critical_alert: alert} do
      session
      |> visit("/alerts/#{alert.id}")
      |> switch_tab("Related Alerts")
      |> assert_has(Query.css("[data-correlation-reason]"))
    end

    test "can navigate to related alert", %{session: session, critical_alert: alert, agent: agent, org: org} do
      related_alert = insert(:alert,
        organization_id: org.id,
        agent: agent,
        title: "Related Alert"
      )

      session
      |> visit("/alerts/#{alert.id}")
      |> switch_tab("Related Alerts")
      |> click(Query.css("[data-alert-id='#{related_alert.id}']"))
      |> assert_current_path("/alerts/#{related_alert.id}")
    end

    test "can create alert correlation", %{session: session, critical_alert: alert, agent: agent, org: org} do
      other_alert = insert(:alert, organization_id: org.id, agent: agent)

      session
      |> visit("/alerts/#{alert.id}")
      |> switch_tab("Related Alerts")
      |> click(Query.button("Add Correlation"))
      |> search_for(other_alert.title)
      |> click(Query.css("[data-alert-option='#{other_alert.id}']"))
      |> select_by_label("Relationship Type", "Same Attack Chain")
      |> click(Query.button("Create Correlation"))
      |> assert_success("Alerts correlated")
    end
  end

  describe "alert timeline" do
    test "timeline shows chronological events", %{session: session, critical_alert: alert} do
      session
      |> visit("/alerts/#{alert.id}")
      |> switch_tab("Timeline")
      |> assert_has(Query.css("[data-timeline]"))
      |> assert_has(Query.css("[data-timeline-event]", minimum: 1))
    end

    test "timeline events are sorted chronologically", %{session: session, critical_alert: alert} do
      session
      |> visit("/alerts/#{alert.id}")
      |> switch_tab("Timeline")
      |> assert_has(Query.css("[data-timeline] [data-timeline-event]:first-child [data-earliest='true']"))
    end

    test "can zoom timeline", %{session: session, critical_alert: alert} do
      session
      |> visit("/alerts/#{alert.id}")
      |> switch_tab("Timeline")
      |> click(Query.css("[data-action='zoom-in']"))
      |> assert_has(Query.css("[data-zoom-level='2']"))
    end

    test "can filter timeline by event type", %{session: session, critical_alert: alert} do
      session
      |> visit("/alerts/#{alert.id}")
      |> switch_tab("Timeline")
      |> apply_filter("event_type", "process_create")
      |> assert_has(Query.css("[data-event-type='process_create']"))
      |> refute_has(Query.css("[data-event-type='network_connect']"))
    end
  end

  describe "bulk alert operations" do
    test "can select multiple alerts", %{session: session} do
      session
      |> visit("/alerts")
      |> toggle_checkbox(Query.css("tr[data-alert]:nth-child(1) [data-checkbox]"))
      |> toggle_checkbox(Query.css("tr[data-alert]:nth-child(2) [data-checkbox]"))
      |> assert_has(Query.css("[data-selected-count='2']"))
    end

    test "can select all alerts on page", %{session: session} do
      session
      |> visit("/alerts")
      |> toggle_checkbox(Query.css("[data-select-all]"))
      |> assert_has(Query.css("[data-selected-count]", minimum: 1))
    end

    test "can bulk assign alerts", %{session: session, user: user} do
      session
      |> visit("/alerts")
      |> toggle_checkbox(Query.css("[data-select-all]"))
      |> click(Query.button("Bulk Actions"))
      |> click(Query.css("[data-action='assign']"))
      |> search_for(user.name)
      |> click(Query.css("[data-user-option='#{user.id}']"))
      |> click(Query.button("Assign Selected"))
      |> assert_success("Alerts assigned successfully")
    end

    test "can bulk change status", %{session: session} do
      session
      |> visit("/alerts")
      |> toggle_checkbox(Query.css("[data-select-all]"))
      |> click(Query.button("Bulk Actions"))
      |> click(Query.css("[data-action='change-status']"))
      |> select_by_label("New Status", "Investigating")
      |> click(Query.button("Update Selected"))
      |> assert_success("Alert statuses updated")
    end

    test "can bulk export alerts", %{session: session} do
      session
      |> visit("/alerts")
      |> toggle_checkbox(Query.css("[data-select-all]"))
      |> click(Query.button("Bulk Actions"))
      |> click(Query.css("[data-action='export']"))
      |> select_by_label("Format", "CSV")
      |> click(Query.button("Export"))
      |> wait_for_notification("Export started")
    end

    test "can bulk delete alerts", %{session: session} do
      session
      |> visit("/alerts")
      |> toggle_checkbox(Query.css("tr[data-alert]:nth-child(1) [data-checkbox]"))
      |> click(Query.button("Bulk Actions"))
      |> click(Query.css("[data-action='delete']"))
      |> assert_has(Query.css("[data-confirm-modal]"))
      |> fill_in(Query.text_field("Confirmation"), with: "DELETE")
      |> click(Query.button("Confirm Delete"))
      |> assert_success("Alerts deleted")
    end
  end
end
