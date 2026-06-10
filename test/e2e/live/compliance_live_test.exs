defmodule TamanduaServerWeb.E2E.ComplianceLiveTest do
  use TamanduaServer.LiveViewCase, async: false
  alias TamanduaServer.Compliance

  describe "framework selection" do
    test "displays available compliance frameworks", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/compliance")

      assert has_element?(view, ".framework-card", "NIST CSF")
      assert has_element?(view, ".framework-card", "ISO 27001")
      assert has_element?(view, ".framework-card", "PCI DSS")
      assert has_element?(view, ".framework-card", "SOC 2")
      assert has_element?(view, ".framework-card", "HIPAA")
      assert has_element?(view, ".framework-card", "GDPR")
    end

    test "select compliance framework", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/compliance")

      # Select NIST CSF
      view
      |> element(".framework-card[data-framework='nist_csf']")
      |> render_click()

      assert_redirect(view, "/compliance/frameworks/nist_csf")
    end

    test "framework overview shows statistics", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      framework = insert(:compliance_framework, name: "NIST CSF", control_count: 108)

      {:ok, view, _html} = live(conn, "/compliance/frameworks/#{framework.id}")

      assert has_element?(view, ".control-count", "108")
      assert has_element?(view, ".compliance-score")
    end

    test "enable multiple frameworks", %{conn: conn} do
      user = insert(:user, role: :admin)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/compliance/settings")

      # Enable frameworks
      view
      |> element("#framework-settings")
      |> render_change(%{
        enabled: ["nist_csf", "iso_27001", "pci_dss"]
      })

      view |> element("#save-settings") |> render_click()

      assert has_element?(view, ".settings-saved")
    end
  end

  describe "control assessment" do
    test "displays framework controls", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      framework = insert(:compliance_framework, name: "NIST CSF")
      control1 = insert(:compliance_control,
        framework: framework,
        identifier: "ID.AM-1",
        title: "Physical devices and systems"
      )
      control2 = insert(:compliance_control,
        framework: framework,
        identifier: "ID.AM-2",
        title: "Software platforms"
      )

      {:ok, view, _html} = live(conn, "/compliance/frameworks/#{framework.id}")

      assert has_element?(view, "[data-control-id='#{control1.id}']", "ID.AM-1")
      assert has_element?(view, "[data-control-id='#{control2.id}']", "ID.AM-2")
    end

    test "assess control implementation", %{conn: conn} do
      user = insert(:user, role: :admin)
      conn = log_in_user(conn, user)

      framework = insert(:compliance_framework)
      control = insert(:compliance_control, framework: framework)

      {:ok, view, _html} = live(conn, "/compliance/controls/#{control.id}")

      # Submit assessment
      view
      |> element("#assessment-form")
      |> render_submit(%{
        assessment: %{
          status: "compliant",
          notes: "All requirements met",
          evidence_url: "https://docs.example.com/evidence"
        }
      })

      assert has_element?(view, ".status-compliant")
      assert render(view) =~ "All requirements met"
    end

    test "mark control as non-compliant with remediation plan", %{conn: conn} do
      user = insert(:user, role: :admin)
      conn = log_in_user(conn, user)

      framework = insert(:compliance_framework)
      control = insert(:compliance_control, framework: framework)

      {:ok, view, _html} = live(conn, "/compliance/controls/#{control.id}")

      # Submit non-compliant assessment
      view
      |> element("#assessment-form")
      |> render_submit(%{
        assessment: %{
          status: "non_compliant",
          notes: "Missing encryption controls",
          remediation_plan: "Implement TLS 1.3",
          due_date: "2024-06-30"
        }
      })

      assert has_element?(view, ".status-non-compliant")
      assert render(view) =~ "Implement TLS 1.3"
      assert has_element?(view, ".due-date", "2024-06-30")
    end

    test "mark control as partially compliant", %{conn: conn} do
      user = insert(:user, role: :admin)
      conn = log_in_user(conn, user)

      framework = insert(:compliance_framework)
      control = insert(:compliance_control, framework: framework)

      {:ok, view, _html} = live(conn, "/compliance/controls/#{control.id}")

      view
      |> element("#assessment-form")
      |> render_submit(%{
        assessment: %{
          status: "partial",
          compliance_percentage: 60,
          notes: "Some requirements met"
        }
      })

      assert has_element?(view, ".status-partial")
      assert render(view) =~ "60%"
    end

    test "assign control owner", %{conn: conn} do
      user = insert(:user, role: :admin)
      owner = insert(:user, email: "owner@example.com")
      conn = log_in_user(conn, user)

      framework = insert(:compliance_framework)
      control = insert(:compliance_control, framework: framework)

      {:ok, view, _html} = live(conn, "/compliance/controls/#{control.id}")

      # Assign owner
      view
      |> element("#assign-owner-form")
      |> render_submit(%{assignment: %{user_id: owner.id}})

      assert has_element?(view, ".control-owner", "owner@example.com")
    end

    test "set review schedule", %{conn: conn} do
      user = insert(:user, role: :admin)
      conn = log_in_user(conn, user)

      framework = insert(:compliance_framework)
      control = insert(:compliance_control, framework: framework)

      {:ok, view, _html} = live(conn, "/compliance/controls/#{control.id}")

      # Set quarterly review
      view
      |> element("#review-schedule-form")
      |> render_submit(%{
        schedule: %{
          frequency: "quarterly",
          next_review: "2024-06-01"
        }
      })

      assert has_element?(view, ".review-schedule", "Quarterly")
      assert has_element?(view, ".next-review", "2024-06-01")
    end
  end

  describe "evidence upload" do
    test "upload evidence document", %{conn: conn} do
      user = insert(:user, role: :admin)
      conn = log_in_user(conn, user)

      framework = insert(:compliance_framework)
      control = insert(:compliance_control, framework: framework)

      {:ok, view, _html} = live(conn, "/compliance/controls/#{control.id}")

      # Upload file
      file = %{
        name: "evidence.pdf",
        content: "PDF content",
        type: "application/pdf"
      }

      view
      |> element("#evidence-upload")
      |> render_upload(file)

      assert has_element?(view, ".evidence-file", "evidence.pdf")
    end

    test "upload multiple evidence files", %{conn: conn} do
      user = insert(:user, role: :admin)
      conn = log_in_user(conn, user)

      framework = insert(:compliance_framework)
      control = insert(:compliance_control, framework: framework)

      {:ok, view, _html} = live(conn, "/compliance/controls/#{control.id}")

      # Upload multiple files
      files = [
        %{name: "policy.pdf", content: "content", type: "application/pdf"},
        %{name: "scan.png", content: "content", type: "image/png"},
        %{name: "audit.xlsx", content: "content", type: "application/vnd.ms-excel"}
      ]

      for file <- files do
        view |> element("#evidence-upload") |> render_upload(file)
      end

      assert has_element?(view, ".evidence-count", "3")
    end

    test "delete evidence file", %{conn: conn} do
      user = insert(:user, role: :admin)
      conn = log_in_user(conn, user)

      framework = insert(:compliance_framework)
      control = insert(:compliance_control, framework: framework)
      evidence = insert(:evidence, control: control, filename: "old-evidence.pdf")

      {:ok, view, _html} = live(conn, "/compliance/controls/#{control.id}")

      # Delete evidence
      view
      |> element("[data-evidence-id='#{evidence.id}'] .delete-button")
      |> render_click()

      # Confirm
      view |> element("#confirm-delete") |> render_click()

      refute has_element?(view, "[data-evidence-id='#{evidence.id}']")
    end

    test "view evidence preview", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      framework = insert(:compliance_framework)
      control = insert(:compliance_control, framework: framework)
      evidence = insert(:evidence, control: control, filename: "screenshot.png", type: "image/png")

      {:ok, view, _html} = live(conn, "/compliance/controls/#{control.id}")

      # Click to preview
      view
      |> element("[data-evidence-id='#{evidence.id}'] .preview-button")
      |> render_click()

      assert has_element?(view, ".evidence-preview-modal")
      assert has_element?(view, "img[src*='screenshot.png']")
    end
  end

  describe "report generation" do
    test "generate compliance report", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      framework = insert(:compliance_framework, name: "NIST CSF")

      {:ok, view, _html} = live(conn, "/compliance/frameworks/#{framework.id}/report")

      # Generate report
      view
      |> element("#generate-report")
      |> render_click()

      assert has_element?(view, ".report-generating")
    end

    test "report includes executive summary", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      framework = insert(:compliance_framework)
      report = insert(:compliance_report, framework: framework)

      {:ok, view, _html} = live(conn, "/compliance/reports/#{report.id}")

      assert has_element?(view, ".executive-summary")
      assert has_element?(view, ".overall-compliance-score")
      assert has_element?(view, ".key-findings")
    end

    test "report shows control-by-control assessment", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      framework = insert(:compliance_framework)
      control1 = insert(:compliance_control, framework: framework, status: "compliant")
      control2 = insert(:compliance_control, framework: framework, status: "non_compliant")

      report = insert(:compliance_report, framework: framework)

      {:ok, view, _html} = live(conn, "/compliance/reports/#{report.id}")

      assert has_element?(view, "[data-control-id='#{control1.id}'] .status-compliant")
      assert has_element?(view, "[data-control-id='#{control2.id}'] .status-non-compliant")
    end

    test "export report as PDF", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      framework = insert(:compliance_framework)
      report = insert(:compliance_report, framework: framework)

      {:ok, view, _html} = live(conn, "/compliance/reports/#{report.id}")

      # Export
      view |> element("#export-pdf") |> render_click()

      assert_push_event(view, "download", %{format: "pdf"})
    end

    test "export report as DOCX", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      framework = insert(:compliance_framework)
      report = insert(:compliance_report, framework: framework)

      {:ok, view, _html} = live(conn, "/compliance/reports/#{report.id}")

      view |> element("#export-docx") |> render_click()

      assert_push_event(view, "download", %{format: "docx"})
    end

    test "schedule automated reports", %{conn: conn} do
      user = insert(:user, role: :admin)
      conn = log_in_user(conn, user)

      framework = insert(:compliance_framework)

      {:ok, view, _html} = live(conn, "/compliance/frameworks/#{framework.id}/settings")

      # Schedule monthly report
      view
      |> element("#report-schedule-form")
      |> render_submit(%{
        schedule: %{
          frequency: "monthly",
          day_of_month: 1,
          recipients: ["compliance@example.com", "audit@example.com"]
        }
      })

      assert has_element?(view, ".schedule-saved")
      assert render(view) =~ "Monthly"
    end
  end

  describe "compliance dashboard" do
    test "displays overall compliance score", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      # Create frameworks with varying compliance
      framework1 = insert(:compliance_framework, compliance_score: 95)
      framework2 = insert(:compliance_framework, compliance_score: 80)
      framework3 = insert(:compliance_framework, compliance_score: 70)

      {:ok, view, _html} = live(conn, "/compliance/dashboard")

      assert has_element?(view, ".overall-score")
      assert render(view) =~ "82" # Average
    end

    test "shows compliance trend chart", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/compliance/dashboard")

      assert has_element?(view, "#compliance-trend-chart")
    end

    test "displays upcoming reviews", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      framework = insert(:compliance_framework)
      control = insert(:compliance_control,
        framework: framework,
        next_review: Date.add(Date.utc_today(), 7)
      )

      {:ok, view, _html} = live(conn, "/compliance/dashboard")

      assert has_element?(view, ".upcoming-review", control.identifier)
    end

    test "shows overdue assessments", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      framework = insert(:compliance_framework)
      control = insert(:compliance_control,
        framework: framework,
        status: "non_compliant",
        remediation_due: Date.add(Date.utc_today(), -5)
      )

      {:ok, view, _html} = live(conn, "/compliance/dashboard")

      assert has_element?(view, ".overdue-control", control.identifier)
      assert has_element?(view, ".overdue-badge")
    end

    test "displays framework comparison", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      nist = insert(:compliance_framework, name: "NIST CSF", compliance_score: 90)
      iso = insert(:compliance_framework, name: "ISO 27001", compliance_score: 85)
      pci = insert(:compliance_framework, name: "PCI DSS", compliance_score: 75)

      {:ok, view, _html} = live(conn, "/compliance/dashboard")

      assert has_element?(view, "[data-framework='#{nist.id}'] .score", "90")
      assert has_element?(view, "[data-framework='#{iso.id}'] .score", "85")
      assert has_element?(view, "[data-framework='#{pci.id}'] .score", "75")
    end
  end

  describe "gap analysis" do
    test "identify compliance gaps", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      framework = insert(:compliance_framework)
      insert(:compliance_control, framework: framework, status: "not_assessed")
      insert(:compliance_control, framework: framework, status: "non_compliant")
      insert(:compliance_control, framework: framework, status: "compliant")

      {:ok, view, _html} = live(conn, "/compliance/frameworks/#{framework.id}/gaps")

      assert has_element?(view, ".gap-not-assessed", "1")
      assert has_element?(view, ".gap-non-compliant", "1")
    end

    test "prioritize gaps by risk", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      framework = insert(:compliance_framework)
      high_risk = insert(:compliance_control,
        framework: framework,
        status: "non_compliant",
        risk_level: "high"
      )
      low_risk = insert(:compliance_control,
        framework: framework,
        status: "non_compliant",
        risk_level: "low"
      )

      {:ok, view, _html} = live(conn, "/compliance/frameworks/#{framework.id}/gaps")

      # Sort by risk
      view
      |> element("#sort-select")
      |> render_change(%{sort: "risk_desc"})

      # High risk should appear first
      html = render(view)
      high_pos = :binary.match(html, high_risk.id) |> elem(0)
      low_pos = :binary.match(html, low_risk.id) |> elem(0)

      assert high_pos < low_pos
    end

    test "generate remediation roadmap", %{conn: conn} do
      user = insert(:user, role: :admin)
      conn = log_in_user(conn, user)

      framework = insert(:compliance_framework)

      {:ok, view, _html} = live(conn, "/compliance/frameworks/#{framework.id}/roadmap")

      # Generate roadmap
      view |> element("#generate-roadmap") |> render_click()

      assert has_element?(view, ".roadmap-timeline")
      assert has_element?(view, ".milestone")
    end
  end

  describe "audit trail" do
    test "displays compliance audit log", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      framework = insert(:compliance_framework)
      control = insert(:compliance_control, framework: framework)

      # Create audit events
      insert(:audit_event,
        control: control,
        action: "assessment_updated",
        user: user,
        timestamp: DateTime.utc_now()
      )

      {:ok, view, _html} = live(conn, "/compliance/audit")

      assert has_element?(view, ".audit-event", "assessment_updated")
      assert render(view) =~ user.email
    end

    test "filter audit log by date range", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/compliance/audit")

      # Filter to last 7 days
      view
      |> element("#date-filter")
      |> render_change(%{
        start_date: Date.add(Date.utc_today(), -7),
        end_date: Date.utc_today()
      })

      assert has_element?(view, ".date-filter-active")
    end

    test "export audit log", %{conn: conn} do
      user = insert(:user)
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/compliance/audit")

      view |> element("#export-audit-log") |> render_click()

      assert_push_event(view, "download", %{format: "csv"})
    end
  end

  describe "real-time updates" do
    test "assessment status updates in real-time", %{conn: conn} do
      user1 = insert(:user)
      user2 = insert(:user)

      framework = insert(:compliance_framework)
      control = insert(:compliance_control, framework: framework)

      conn1 = log_in_user(conn, user1)
      conn2 = log_in_user(conn, user2)

      {:ok, view1, _html} = live(conn1, "/compliance/controls/#{control.id}")
      {:ok, view2, _html} = live(conn2, "/compliance/controls/#{control.id}")

      # User1 updates assessment
      {:ok, updated_control} = Compliance.update_control(control, %{status: "compliant"})

      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "compliance:controls:#{control.id}",
        {:control_updated, updated_control}
      )

      :timer.sleep(100)

      # Both views should update
      assert has_element?(view1, ".status-compliant")
      assert has_element?(view2, ".status-compliant")
    end

    test "evidence upload appears in real-time", %{conn: conn} do
      user1 = insert(:user)
      user2 = insert(:user)

      framework = insert(:compliance_framework)
      control = insert(:compliance_control, framework: framework)

      conn1 = log_in_user(conn, user1)
      conn2 = log_in_user(conn, user2)

      {:ok, view1, _html} = live(conn1, "/compliance/controls/#{control.id}")
      {:ok, view2, _html} = live(conn2, "/compliance/controls/#{control.id}")

      # User1 uploads evidence
      evidence = insert(:evidence, control: control, filename: "new-evidence.pdf")

      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "compliance:controls:#{control.id}:evidence",
        {:evidence_added, evidence}
      )

      :timer.sleep(100)

      # Both views should show new evidence
      assert has_element?(view1, "[data-evidence-id='#{evidence.id}']")
      assert has_element?(view2, "[data-evidence-id='#{evidence.id}']")
    end
  end
end
