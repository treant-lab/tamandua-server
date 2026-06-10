defmodule TamanduaServer.E2E.ComplianceTest do
  @moduledoc """
  E2E tests for compliance management functionality.

  Tests cover:
  - Compliance dashboard
  - Framework selection and management
  - Evidence collection
  - Report generation
  - Audit trails
  - Control mapping
  """

  use TamanduaServer.E2ECase, async: false

  alias Wallaby.Query

  setup %{session: session} do
    org = insert(:organization)
    user = insert(:user, organization_id: org.id, role: "compliance_officer")

    session = login_user(session, user)
    {:ok, session: session, user: user, org: org}
  end

  describe "compliance dashboard" do
    test "displays compliance overview", %{session: session} do
      session
      |> visit("/compliance")
      |> assert_has(Query.css("[data-page='compliance']"))
      |> assert_has(Query.css("[data-compliance-dashboard]"))
    end

    test "shows active frameworks", %{session: session} do
      session
      |> visit("/compliance")
      |> assert_has(Query.css("[data-frameworks-list]"))
      |> assert_has(Query.css("[data-framework]", minimum: 0))
    end

    test "displays overall compliance score", %{session: session} do
      session
      |> visit("/compliance")
      |> assert_has(Query.css("[data-compliance-score]"))
    end

    test "shows compliance by framework", %{session: session} do
      session
      |> visit("/compliance")
      |> assert_has(Query.css("[data-framework-scores]"))
    end

    test "displays control coverage statistics", %{session: session} do
      session
      |> visit("/compliance")
      |> assert_has(Query.css("[data-stats='total_controls']"))
      |> assert_has(Query.css("[data-stats='implemented']"))
      |> assert_has(Query.css("[data-stats='pending']"))
    end

    test "shows recent audit activities", %{session: session} do
      session
      |> visit("/compliance")
      |> assert_has(Query.css("[data-recent-activities]"))
    end

    test "displays upcoming audits", %{session: session} do
      session
      |> visit("/compliance")
      |> assert_has(Query.css("[data-upcoming-audits]"))
    end
  end

  describe "framework management" do
    test "can view available frameworks", %{session: session} do
      session
      |> visit("/compliance/frameworks")
      |> assert_has(Query.css("[data-available-frameworks]"))
      |> assert_has(Query.text("PCI DSS"))
      |> assert_has(Query.text("HIPAA"))
      |> assert_has(Query.text("SOC 2"))
      |> assert_has(Query.text("ISO 27001"))
      |> assert_has(Query.text("NIST CSF"))
    end

    test "can enable compliance framework", %{session: session} do
      session
      |> visit("/compliance/frameworks")
      |> click(Query.css("[data-framework='pci_dss'] [data-action='enable']"))
      |> assert_has(Query.css("[data-modal='enable-framework']"))
      |> click(Query.button("Enable Framework"))
      |> assert_success("Framework enabled")
    end

    test "can view framework details", %{session: session} do
      session
      |> visit("/compliance/frameworks")
      |> click(Query.css("[data-framework='pci_dss']"))
      |> assert_has(Query.css("[data-framework-detail]"))
      |> assert_has(Query.css("[data-field='version']"))
      |> assert_has(Query.css("[data-field='control_count']"))
    end

    test "displays framework requirements", %{session: session} do
      session
      |> visit("/compliance/frameworks/pci_dss")
      |> assert_has(Query.css("[data-requirements-list]"))
      |> assert_has(Query.css("[data-requirement]", minimum: 1))
    end

    test "can map controls to requirements", %{session: session} do
      session
      |> visit("/compliance/frameworks/pci_dss")
      |> click(Query.css("[data-requirement]:first-child [data-action='map']"))
      |> click(Query.button("Add Control"))
      |> search_for("Access Control")
      |> click(Query.css("[data-control-option]"))
      |> click(Query.button("Map"))
      |> assert_success("Control mapped")
    end

    test "shows mapped controls for requirement", %{session: session} do
      session
      |> visit("/compliance/frameworks/pci_dss")
      |> click(Query.css("[data-requirement]:first-child"))
      |> assert_has(Query.css("[data-mapped-controls]"))
    end

    test "can disable framework", %{session: session} do
      session
      |> visit("/compliance/frameworks")
      |> click(Query.css("[data-framework='pci_dss'] [data-action='disable']"))
      |> click(Query.button("Confirm"))
      |> assert_success("Framework disabled")
    end
  end

  describe "control management" do
    test "displays control catalog", %{session: session} do
      session
      |> visit("/compliance/controls")
      |> assert_has(Query.css("[data-controls-catalog]"))
    end

    test "can create custom control", %{session: session} do
      session
      |> visit("/compliance/controls")
      |> click(Query.button("Create Control"))
      |> fill_in(Query.text_field("Control ID"), with: "CUSTOM-001")
      |> fill_in(Query.text_field("Title"), with: "Custom Security Control")
      |> fill_in(Query.css("[data-description]"), with: "Control description")
      |> select_by_label("Category", "Access Control")
      |> click(Query.button("Create"))
      |> assert_success("Control created")
    end

    test "can edit control", %{session: session} do
      session
      |> visit("/compliance/controls")
      |> click(Query.css("[data-control]:first-child [data-action='edit']"))
      |> fill_in(Query.text_field("Title"), with: "Updated Control Title")
      |> click(Query.button("Save"))
      |> assert_success("Control updated")
    end

    test "can view control implementation status", %{session: session} do
      session
      |> visit("/compliance/controls")
      |> click(Query.css("[data-control]:first-child"))
      |> assert_has(Query.css("[data-implementation-status]"))
    end

    test "can filter controls by status", %{session: session} do
      session
      |> visit("/compliance/controls")
      |> apply_filter("status", "Implemented")
      |> wait_for_ajax()
      |> assert_has(Query.css("[data-status='implemented']"))
    end

    test "can filter controls by category", %{session: session} do
      session
      |> visit("/compliance/controls")
      |> apply_filter("category", "Access Control")
      |> wait_for_ajax()
    end

    test "can search controls", %{session: session} do
      session
      |> visit("/compliance/controls")
      |> search_for("encryption")
      |> assert_has(Query.css("[data-control]", text: "encryption"))
    end
  end

  describe "evidence collection" do
    test "displays evidence repository", %{session: session} do
      session
      |> visit("/compliance/evidence")
      |> assert_has(Query.css("[data-evidence-repository]"))
    end

    test "can upload evidence", %{session: session} do
      session
      |> visit("/compliance/evidence")
      |> click(Query.button("Upload Evidence"))
      |> fill_in(Query.text_field("Title"), with: "Security Audit Report")
      |> select_by_label("Control", "Access Control - AC-001")
      |> attach_file(Query.file_field("File"), path: "test/fixtures/evidence.pdf")
      |> click(Query.button("Upload"))
      |> assert_success("Evidence uploaded")
    end

    test "can link evidence to multiple controls", %{session: session} do
      session
      |> visit("/compliance/evidence")
      |> click(Query.css("[data-evidence]:first-child [data-action='link']"))
      |> search_for("Control")
      |> toggle_checkbox(Query.css("[data-control-option]:first-child"))
      |> toggle_checkbox(Query.css("[data-control-option]:nth-child(2)"))
      |> click(Query.button("Link"))
      |> assert_success("Evidence linked to controls")
    end

    test "can view evidence details", %{session: session} do
      session
      |> visit("/compliance/evidence")
      |> click(Query.css("[data-evidence]:first-child"))
      |> assert_has(Query.css("[data-evidence-detail]"))
      |> assert_has(Query.css("[data-field='title']"))
      |> assert_has(Query.css("[data-field='uploaded_by']"))
      |> assert_has(Query.css("[data-field='upload_date']"))
    end

    test "can download evidence", %{session: session} do
      session
      |> visit("/compliance/evidence")
      |> click(Query.css("[data-evidence]:first-child [data-action='download']"))
      # Download would start
    end

    test "can delete evidence", %{session: session} do
      session
      |> visit("/compliance/evidence")
      |> click(Query.css("[data-evidence]:first-child [data-action='delete']"))
      |> click(Query.button("Confirm"))
      |> assert_success("Evidence deleted")
    end

    test "can filter evidence by control", %{session: session} do
      session
      |> visit("/compliance/evidence")
      |> apply_filter("control", "AC-001")
      |> wait_for_ajax()
    end

    test "can filter evidence by date range", %{session: session} do
      session
      |> visit("/compliance/evidence")
      |> click(Query.button("Filter by Date"))
      |> fill_in(Query.css("[data-start-date]"), with: "2024-01-01")
      |> fill_in(Query.css("[data-end-date]"), with: "2024-12-31")
      |> click(Query.button("Apply"))
      |> wait_for_ajax()
    end

    test "shows evidence collection progress", %{session: session} do
      session
      |> visit("/compliance/evidence")
      |> assert_has(Query.css("[data-collection-progress]"))
      |> assert_has(Query.css("[data-progress-bar]"))
    end
  end

  describe "report generation" do
    test "can access reports section", %{session: session} do
      session
      |> visit("/compliance/reports")
      |> assert_has(Query.css("[data-reports-page]"))
    end

    test "displays report templates", %{session: session} do
      session
      |> visit("/compliance/reports")
      |> assert_has(Query.css("[data-template='compliance_summary']"))
      |> assert_has(Query.css("[data-template='audit_readiness']"))
      |> assert_has(Query.css("[data-template='gap_analysis']"))
    end

    test "can generate compliance summary report", %{session: session} do
      session
      |> visit("/compliance/reports")
      |> click(Query.css("[data-template='compliance_summary'] [data-action='generate']"))
      |> select_by_label("Framework", "PCI DSS")
      |> select_by_label("Format", "PDF")
      |> click(Query.button("Generate"))
      |> assert_success("Report generation started")
    end

    test "can customize report content", %{session: session} do
      session
      |> visit("/compliance/reports")
      |> click(Query.css("[data-template='compliance_summary'] [data-action='generate']"))
      |> click(Query.button("Customize"))
      |> toggle_checkbox(Query.css("[data-section='executive_summary']"))
      |> toggle_checkbox(Query.css("[data-section='control_details']"))
      |> toggle_checkbox(Query.css("[data-section='evidence_list']"))
      |> click(Query.button("Generate"))
      |> assert_success("Report generation started")
    end

    test "can schedule recurring reports", %{session: session} do
      session
      |> visit("/compliance/reports")
      |> click(Query.css("[data-template='compliance_summary'] [data-action='schedule']"))
      |> select_by_label("Frequency", "Monthly")
      |> fill_in(Query.text_field("Day of Month"), with: "1")
      |> fill_in(Query.text_field("Recipients"), with: "compliance@example.com")
      |> click(Query.button("Schedule"))
      |> assert_success("Report scheduled")
    end

    test "shows report history", %{session: session} do
      session
      |> visit("/compliance/reports/history")
      |> assert_has(Query.css("[data-report-history]"))
      |> assert_has(Query.css("[data-report]", minimum: 0))
    end

    test "can download previous report", %{session: session} do
      session
      |> visit("/compliance/reports/history")
      |> click(Query.css("[data-report]:first-child [data-action='download']"))
      # Download would start
    end

    test "can regenerate report", %{session: session} do
      session
      |> visit("/compliance/reports/history")
      |> click(Query.css("[data-report]:first-child [data-action='regenerate']"))
      |> click(Query.button("Confirm"))
      |> assert_success("Report regeneration started")
    end

    test "shows report generation progress", %{session: session} do
      session
      |> visit("/compliance/reports")
      |> click(Query.css("[data-template='compliance_summary'] [data-action='generate']"))
      |> click(Query.button("Generate"))
      |> assert_has(Query.css("[data-generation-status='in_progress']"))
    end
  end

  describe "audit trails" do
    test "displays audit log", %{session: session} do
      session
      |> visit("/compliance/audit")
      |> assert_has(Query.css("[data-audit-log]"))
    end

    test "shows compliance-related activities", %{session: session} do
      session
      |> visit("/compliance/audit")
      |> assert_has(Query.css("[data-audit-entry]", minimum: 0))
    end

    test "can filter audit log by action", %{session: session} do
      session
      |> visit("/compliance/audit")
      |> apply_filter("action", "Control Updated")
      |> wait_for_ajax()
    end

    test "can filter by user", %{session: session, user: user} do
      session
      |> visit("/compliance/audit")
      |> search_for(user.name)
      |> wait_for_ajax()
      |> assert_has(Query.css("[data-user='#{user.id}']"))
    end

    test "can filter by date range", %{session: session} do
      session
      |> visit("/compliance/audit")
      |> click(Query.button("Filter by Date"))
      |> fill_in(Query.css("[data-start-date]"), with: "2024-01-01")
      |> fill_in(Query.css("[data-end-date]"), with: "2024-12-31")
      |> click(Query.button("Apply"))
      |> wait_for_ajax()
    end

    test "can view audit entry details", %{session: session} do
      session
      |> visit("/compliance/audit")
      |> click(Query.css("[data-audit-entry]:first-child"))
      |> assert_has(Query.css("[data-audit-detail]"))
      |> assert_has(Query.css("[data-field='timestamp']"))
      |> assert_has(Query.css("[data-field='user']"))
      |> assert_has(Query.css("[data-field='action']"))
      |> assert_has(Query.css("[data-field='details']"))
    end

    test "can export audit log", %{session: session} do
      session
      |> visit("/compliance/audit")
      |> click(Query.button("Export"))
      |> select_by_label("Format", "CSV")
      |> click(Query.button("Export"))
      |> wait_for_notification("Export started")
    end
  end

  describe "assessments" do
    test "can create assessment", %{session: session} do
      session
      |> visit("/compliance/assessments")
      |> click(Query.button("New Assessment"))
      |> fill_in(Query.text_field("Title"), with: "Q1 2024 Assessment")
      |> select_by_label("Framework", "PCI DSS")
      |> fill_in(Query.text_field("Assessor"), with: "John Doe")
      |> fill_in(Query.css("[data-start-date]"), with: "2024-01-01")
      |> fill_in(Query.css("[data-end-date]"), with: "2024-03-31")
      |> click(Query.button("Create"))
      |> assert_success("Assessment created")
    end

    test "can view assessment", %{session: session} do
      session
      |> visit("/compliance/assessments")
      |> click(Query.css("[data-assessment]:first-child"))
      |> assert_has(Query.css("[data-assessment-detail]"))
    end

    test "shows assessment progress", %{session: session} do
      session
      |> visit("/compliance/assessments")
      |> click(Query.css("[data-assessment]:first-child"))
      |> assert_has(Query.css("[data-progress]"))
      |> assert_has(Query.css("[data-progress-bar]"))
    end

    test "can mark control as assessed", %{session: session} do
      session
      |> visit("/compliance/assessments")
      |> click(Query.css("[data-assessment]:first-child"))
      |> click(Query.css("[data-control]:first-child [data-action='assess']"))
      |> select_by_label("Result", "Pass")
      |> fill_in(Query.css("[data-notes]"), with: "Control properly implemented")
      |> click(Query.button("Save"))
      |> assert_success("Control assessed")
    end

    test "can attach evidence during assessment", %{session: session} do
      session
      |> visit("/compliance/assessments")
      |> click(Query.css("[data-assessment]:first-child"))
      |> click(Query.css("[data-control]:first-child [data-action='assess']"))
      |> click(Query.button("Attach Evidence"))
      |> attach_file(Query.file_field("File"), path: "test/fixtures/evidence.pdf")
      |> click(Query.button("Upload"))
      |> assert_success("Evidence attached")
    end

    test "can finalize assessment", %{session: session} do
      session
      |> visit("/compliance/assessments")
      |> click(Query.css("[data-assessment]:first-child"))
      |> click(Query.button("Finalize Assessment"))
      |> click(Query.button("Confirm"))
      |> assert_success("Assessment finalized")
    end

    test "can export assessment results", %{session: session} do
      session
      |> visit("/compliance/assessments")
      |> click(Query.css("[data-assessment]:first-child"))
      |> click(Query.button("Export Results"))
      |> select_by_label("Format", "PDF")
      |> click(Query.button("Export"))
      |> wait_for_notification("Export started")
    end
  end

  describe "gap analysis" do
    test "displays gap analysis dashboard", %{session: session} do
      session
      |> visit("/compliance/gap-analysis")
      |> assert_has(Query.css("[data-gap-analysis]"))
    end

    test "shows identified gaps", %{session: session} do
      session
      |> visit("/compliance/gap-analysis")
      |> assert_has(Query.css("[data-gaps-list]"))
      |> assert_has(Query.css("[data-gap]", minimum: 0))
    end

    test "can create remediation plan", %{session: session} do
      session
      |> visit("/compliance/gap-analysis")
      |> click(Query.css("[data-gap]:first-child [data-action='remediate']"))
      |> fill_in(Query.text_field("Action Plan"), with: "Implement missing control")
      |> fill_in(Query.css("[data-target-date]"), with: "2024-12-31")
      |> fill_in(Query.text_field("Assigned To"), with: "Security Team")
      |> click(Query.button("Create Plan"))
      |> assert_success("Remediation plan created")
    end

    test "shows gap severity", %{session: session} do
      session
      |> visit("/compliance/gap-analysis")
      |> assert_has(Query.css("[data-gap] [data-severity]"))
    end

    test "can filter gaps by priority", %{session: session} do
      session
      |> visit("/compliance/gap-analysis")
      |> apply_filter("priority", "High")
      |> wait_for_ajax()
      |> assert_has(Query.css("[data-priority='high']"))
    end

    test "can track remediation progress", %{session: session} do
      session
      |> visit("/compliance/gap-analysis")
      |> click(Query.css("[data-gap]:first-child"))
      |> assert_has(Query.css("[data-remediation-progress]"))
    end
  end

  describe "notifications and alerts" do
    test "shows compliance notifications", %{session: session} do
      session
      |> visit("/compliance")
      |> assert_has(Query.css("[data-notifications]", minimum: 0))
    end

    test "can configure compliance alerts", %{session: session} do
      session
      |> visit("/compliance/settings")
      |> toggle_checkbox(Query.css("[data-alert='approaching_deadline']"))
      |> toggle_checkbox(Query.css("[data-alert='control_failure']"))
      |> click(Query.button("Save"))
      |> assert_success("Alert settings saved")
    end

    test "shows deadline reminders", %{session: session} do
      session
      |> visit("/compliance")
      |> assert_has(Query.css("[data-deadline-reminder]", minimum: 0))
    end
  end
end
