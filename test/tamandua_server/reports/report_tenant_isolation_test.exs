defmodule TamanduaServer.Reports.ReportTenantIsolationTest do
  @moduledoc """
  Regression tests for cross-tenant data isolation in report generation.

  Guards against the leak where reports (and their underlying alert queries)
  returned alerts from ALL organizations instead of only the requesting
  tenant's organization.
  """

  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Alerts
  alias TamanduaServer.Reports
  alias TamanduaServer.Reports.Templates.IncidentReport

  setup do
    org1 = insert(:organization)
    org2 = insert(:organization)

    agent1 = insert(:agent, organization: org1)
    agent2 = insert(:agent, organization: org2)

    alert1 =
      insert(:alert,
        organization: org1,
        agent: agent1,
        title: "ORG1-ONLY suspicious powershell",
        severity: "critical",
        status: "new"
      )

    alert2 =
      insert(:alert,
        organization: org2,
        agent: agent2,
        title: "ORG2-ONLY credential dumping",
        severity: "critical",
        status: "new"
      )

    date_from = Date.utc_today() |> Date.add(-1) |> Date.to_iso8601()
    date_to = Date.utc_today() |> Date.to_iso8601()

    %{
      org1: org1,
      org2: org2,
      alert1: alert1,
      alert2: alert2,
      date_from: date_from,
      date_to: date_to
    }
  end

  describe "Alerts.list_alerts_in_range_for_org/3" do
    test "returns only the organization's alerts", ctx do
      results = Alerts.list_alerts_in_range_for_org(ctx.org1.id, ctx.date_from, ctx.date_to)

      assert Enum.any?(results, &(&1.id == ctx.alert1.id))
      refute Enum.any?(results, &(&1.id == ctx.alert2.id))
      assert Enum.all?(results, &(&1.organization_id == ctx.org1.id))
    end

    test "raises when organization_id is nil (no unscoped fallback)", ctx do
      assert_raise ArgumentError, fn ->
        Alerts.list_alerts_in_range_for_org(nil, ctx.date_from, ctx.date_to)
      end
    end
  end

  describe "Alerts.count_by_status_for_org/2" do
    test "counts only the organization's alerts", ctx do
      assert Alerts.count_by_status_for_org(ctx.org1.id, "new") == 1
      assert Alerts.count_by_status_for_org(ctx.org2.id, "new") == 1
    end
  end

  describe "Reports.generate_report/5" do
    test "includes only the requesting organization's alerts", ctx do
      user = insert(:user, organization: ctx.org1)

      report = Reports.generate_report("incident_report", ctx.date_from, ctx.date_to, user, ctx.org1.id)
      rendered = inspect(report)

      assert rendered =~ "ORG1-ONLY"
      refute rendered =~ "ORG2-ONLY"
    end

    test "derives the organization from the user when not passed explicitly", ctx do
      user = insert(:user, organization: ctx.org2)

      report = Reports.generate_report("incident_report", ctx.date_from, ctx.date_to, user)
      rendered = inspect(report)

      assert rendered =~ "ORG2-ONLY"
      refute rendered =~ "ORG1-ONLY"
    end

    test "fails closed (no alert data) when no organization can be resolved", ctx do
      report = Reports.generate_report("incident_report", ctx.date_from, ctx.date_to)
      rendered = inspect(report)

      refute rendered =~ "ORG1-ONLY"
      refute rendered =~ "ORG2-ONLY"
    end

    test "executive summary counts are tenant-scoped", ctx do
      user = insert(:user, organization: ctx.org1)

      report = Reports.generate_report("executive_summary", ctx.date_from, ctx.date_to, user, ctx.org1.id)

      key_metrics = Enum.find(report.sections, &(&1.title == "Key Metrics"))
      critical = Enum.find(key_metrics.content, &(&1.label == "Critical Alerts"))

      # Only org1's single critical alert, not both orgs' alerts
      assert critical.value == 1
    end
  end

  describe "Engine templates (params-based scoping)" do
    test "IncidentReport.generate/3 scopes alerts by params organization_id", ctx do
      report = IncidentReport.generate(ctx.date_from, ctx.date_to, %{"organization_id" => ctx.org1.id})
      rendered = inspect(report)

      assert rendered =~ "ORG1-ONLY"
      refute rendered =~ "ORG2-ONLY"
    end

    test "IncidentReport.generate/3 fails closed without organization_id", ctx do
      report = IncidentReport.generate(ctx.date_from, ctx.date_to, %{})
      rendered = inspect(report)

      refute rendered =~ "ORG1-ONLY"
      refute rendered =~ "ORG2-ONLY"
    end
  end
end
