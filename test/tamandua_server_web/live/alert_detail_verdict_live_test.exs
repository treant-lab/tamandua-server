defmodule TamanduaServerWeb.AlertDetailVerdictLiveTest do
  @moduledoc """
  LiveView tests for the analyst verdict modal on the alert detail page
  (`/live/alerts/:id`), wired to `Alerts.set_verdict/4` on 2026-06-15.

  Covers: opening the modal from the quick actions, cancelling it, and
  confirming a verdict (with and without suppression rule creation).
  """

  use TamanduaServerWeb.ConnCase, async: false

  import Phoenix.LiveViewTest
  import TamanduaServer.AccountsFixtures
  import TamanduaServer.AlertsFixtures

  alias TamanduaServer.Accounts
  alias TamanduaServer.Alerts
  alias TamanduaServer.Alerts.{Alert, SuppressionRule}
  alias TamanduaServer.Repo

  setup %{conn: conn} do
    org = organization_fixture()
    user = user_fixture(organization_id: org.id)

    alert =
      alert_fixture(
        organization_id: org.id,
        agent_id: Ecto.UUID.generate(),
        title: "Verdict modal test alert #{System.unique_integer([:positive])}",
        severity: "high",
        status: "new",
        detection_metadata: %{"rule_name" => "modal_test_rule"},
        evidence: %{"process" => %{"name" => "modal_tool.exe"}}
      )

    conn = log_in_with_org(conn, user, org)

    %{conn: conn, org: org, user: user, alert: alert}
  end

  defp log_in_with_org(conn, user, org) do
    token = Accounts.generate_user_session_token(user)

    conn
    |> Plug.Test.init_test_session(%{})
    |> Plug.Conn.put_session(:user_token, token)
    |> Plug.Conn.put_session(:organization_id, org.id)
  end

  describe "authentication" do
    test "redirects unauthenticated users to login", %{alert: alert} do
      conn = Phoenix.ConnTest.build_conn()

      assert {:error, {:redirect, %{to: "/login"}}} =
               live(conn, "/live/alerts/#{alert.id}")
    end
  end

  describe "verdict modal flow" do
    test "open_verdict_modal shows the modal with suppression defaults", %{
      conn: conn,
      alert: alert
    } do
      {:ok, view, html} = live(conn, "/live/alerts/#{alert.id}")

      # Modal not rendered initially
      refute html =~ "Confirm verdict"

      view
      |> element("button[phx-click='open_verdict_modal'][phx-value-verdict='false_positive']")
      |> render_click()

      html = render(view)
      assert html =~ "Mark as False Positive"
      assert html =~ "Confirm verdict"
      # FP defaults to creating a suppression rule with a 30 day TTL
      assert has_element?(view, "#create_suppression_rule[checked]")
      assert has_element?(view, "#suppression_ttl_days[value='30']")
    end

    test "true_positive modal does not default to creating a suppression rule", %{
      conn: conn,
      alert: alert
    } do
      {:ok, view, _html} = live(conn, "/live/alerts/#{alert.id}")

      view
      |> element("button[phx-click='open_verdict_modal'][phx-value-verdict='true_positive']")
      |> render_click()

      assert render(view) =~ "Mark as True Positive"
      refute has_element?(view, "#create_suppression_rule[checked]")
    end

    test "cancel_verdict_modal closes the modal without setting a verdict", %{
      conn: conn,
      alert: alert
    } do
      {:ok, view, _html} = live(conn, "/live/alerts/#{alert.id}")

      view
      |> element("button[phx-click='open_verdict_modal'][phx-value-verdict='false_positive']")
      |> render_click()

      assert render(view) =~ "Confirm verdict"

      view
      |> element("button[phx-click='cancel_verdict_modal']")
      |> render_click()

      refute render(view) =~ "Confirm verdict"
      assert Repo.get!(Alert, alert.id).verdict == "unconfirmed"
    end

    test "confirm_verdict without suppression rule marks the alert FP and logs feedback", %{
      conn: conn,
      alert: alert,
      user: user
    } do
      {:ok, view, _html} = live(conn, "/live/alerts/#{alert.id}")

      view
      |> element("button[phx-click='open_verdict_modal'][phx-value-verdict='false_positive']")
      |> render_click()

      html =
        view
        |> element("form[phx-submit='confirm_verdict']")
        |> render_submit(%{
          "verdict" => "false_positive",
          "notes" => "Known noisy dev tool",
          "suppression_ttl_days" => "30"
        })

      # Flash confirms verdict without a suppression rule
      assert html =~ "Verdict recorded: False Positive"
      refute html =~ "suppression rule created"

      # Modal closed
      refute html =~ "Confirm verdict"

      updated = Repo.get!(Alert, alert.id)
      assert updated.verdict == "false_positive"
      assert updated.status == "false_positive"
      assert updated.verdict_notes == "Known noisy dev tool"
      assert updated.verdict_by_id == user.id
      assert updated.suppression_rule_id == nil

      assert [log] = Alerts.get_feedback_log(alert.id)
      assert log.new_verdict == "false_positive"
      assert log.notes == "Known noisy dev tool"
      assert log.user_id == user.id
    end

    test "confirm_verdict with suppression rule creates a TTL-bounded rule", %{
      conn: conn,
      alert: alert
    } do
      {:ok, view, _html} = live(conn, "/live/alerts/#{alert.id}")

      view
      |> element("button[phx-click='open_verdict_modal'][phx-value-verdict='false_positive']")
      |> render_click()

      html =
        view
        |> element("form[phx-submit='confirm_verdict']")
        |> render_submit(%{
          "verdict" => "false_positive",
          "notes" => "Recurring benign job",
          "create_suppression_rule" => "true",
          "suppression_ttl_days" => "7"
        })

      assert html =~ "Verdict recorded: False Positive"
      assert html =~ "suppression rule created, TTL 7d"

      updated = Repo.get!(Alert, alert.id)
      assert updated.verdict == "false_positive"
      assert updated.suppression_rule_id != nil

      rule = Repo.get!(SuppressionRule, updated.suppression_rule_id)
      assert rule.source_alert_id == alert.id
      assert rule.title_pattern == alert.title
      assert rule.rule_name_pattern == "modal_test_rule"

      ttl_seconds = DateTime.diff(rule.expires_at, DateTime.utc_now())
      assert_in_delta ttl_seconds, 7 * 24 * 60 * 60, 120
    end

    test "verdict badge is rendered after confirmation", %{conn: conn, alert: alert} do
      {:ok, view, _html} = live(conn, "/live/alerts/#{alert.id}")

      view
      |> element("button[phx-click='open_verdict_modal'][phx-value-verdict='benign']")
      |> render_click()

      html =
        view
        |> element("form[phx-submit='confirm_verdict']")
        |> render_submit(%{
          "verdict" => "benign",
          "notes" => "",
          "suppression_ttl_days" => "30"
        })

      assert html =~ "Benign"

      updated = Repo.get!(Alert, alert.id)
      assert updated.verdict == "benign"
      assert updated.status == "resolved"
    end
  end
end
