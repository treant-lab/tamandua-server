defmodule TamanduaServerWeb.ApprovalQueueLiveTest do
  use TamanduaServerWeb.ConnCase

  import Phoenix.LiveViewTest

  alias TamanduaServer.Remediation.{Workflow, Policy}
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Repo

  describe "Approval Queue Index" do
    setup %{conn: conn} do
      # Create organization and user for testing
      organization_id = Ecto.UUID.generate()
      user = %{id: Ecto.UUID.generate(), email: "test@example.com", organization_id: organization_id, role: "admin"}

      # Assign user to connection
      conn = assign(conn, :current_user, user)

      %{conn: conn, organization_id: organization_id, user: user}
    end

    test "mounts with empty list when no pending approvals", %{conn: conn} do
      {:ok, view, html} = live(conn, ~p"/live/remediation/approvals")

      assert html =~ "Pending Approvals"
      assert html =~ "No pending approvals"
    end

    test "displays pending workflows with alert details", %{conn: conn, organization_id: organization_id} do
      # Create test alert
      {:ok, alert} = create_test_alert(%{
        title: "High Risk Malware Detected",
        severity: "critical",
        threat_score: 0.85,
        organization_id: organization_id
      })

      # Create test policy
      {:ok, policy} = create_test_policy(%{
        name: "Auto Quarantine Policy",
        organization_id: organization_id
      })

      # Create pending approval workflow
      {:ok, _workflow} = create_test_workflow(%{
        alert_id: alert.id,
        policy_id: policy.id,
        organization_id: organization_id,
        execution_mode: "pending_approval",
        action_type: "quarantine",
        state: "pending"
      })

      {:ok, view, html} = live(conn, ~p"/live/remediation/approvals")

      assert html =~ "High Risk Malware Detected"
      assert html =~ "quarantine" or html =~ "Quarantine"
    end

    test "approval card shows action_type, threat_score, alert title, created timestamp", %{conn: conn, organization_id: organization_id} do
      {:ok, alert} = create_test_alert(%{
        title: "Suspicious Process Execution",
        severity: "high",
        threat_score: 0.75,
        organization_id: organization_id
      })

      {:ok, policy} = create_test_policy(%{
        name: "Process Block Policy",
        organization_id: organization_id
      })

      {:ok, workflow} = create_test_workflow(%{
        alert_id: alert.id,
        policy_id: policy.id,
        organization_id: organization_id,
        execution_mode: "pending_approval",
        action_type: "block",
        state: "pending"
      })

      {:ok, view, html} = live(conn, ~p"/live/remediation/approvals")

      assert html =~ "Suspicious Process Execution"
      assert html =~ "block" or html =~ "Block"
      assert html =~ "0.75" or html =~ "75%"
    end

    test "approval card shows Approve and Reject buttons", %{conn: conn, organization_id: organization_id} do
      {:ok, alert} = create_test_alert(%{
        title: "Test Alert",
        organization_id: organization_id
      })

      {:ok, policy} = create_test_policy(%{
        name: "Test Policy",
        organization_id: organization_id
      })

      {:ok, _workflow} = create_test_workflow(%{
        alert_id: alert.id,
        policy_id: policy.id,
        organization_id: organization_id,
        execution_mode: "pending_approval",
        action_type: "quarantine",
        state: "pending"
      })

      {:ok, view, html} = live(conn, ~p"/live/remediation/approvals")

      assert html =~ "Approve"
      assert html =~ "Reject"
    end

    test "workflows sorted by oldest first (inserted_at asc)", %{conn: conn, organization_id: organization_id} do
      # Create older workflow first
      {:ok, alert1} = create_test_alert(%{title: "Older Alert", organization_id: organization_id})
      {:ok, policy} = create_test_policy(%{name: "Policy", organization_id: organization_id})

      {:ok, workflow1} = create_test_workflow(%{
        alert_id: alert1.id,
        policy_id: policy.id,
        organization_id: organization_id,
        execution_mode: "pending_approval",
        action_type: "quarantine",
        state: "pending"
      })

      # Wait briefly to ensure different timestamps
      Process.sleep(10)

      # Create newer workflow
      {:ok, alert2} = create_test_alert(%{title: "Newer Alert", organization_id: organization_id})
      {:ok, workflow2} = create_test_workflow(%{
        alert_id: alert2.id,
        policy_id: policy.id,
        organization_id: organization_id,
        execution_mode: "pending_approval",
        action_type: "block",
        state: "pending"
      })

      {:ok, view, html} = live(conn, ~p"/live/remediation/approvals")

      # Older should appear before newer
      older_pos = :binary.match(html, "Older Alert")
      newer_pos = :binary.match(html, "Newer Alert")

      assert older_pos != :nomatch
      assert newer_pos != :nomatch

      {older_start, _} = older_pos
      {newer_start, _} = newer_pos

      assert older_start < newer_start, "Older workflow should appear first"
    end
  end

  describe "Approve/Reject flow" do
    @tag :approve_reject
    setup %{conn: conn} do
      organization_id = Ecto.UUID.generate()
      user = %{id: Ecto.UUID.generate(), email: "approver@example.com", organization_id: organization_id, role: "admin"}
      conn = assign(conn, :current_user, user)

      {:ok, alert} = create_test_alert(%{
        title: "Critical Threat",
        severity: "critical",
        threat_score: 0.9,
        organization_id: organization_id
      })

      {:ok, policy} = create_test_policy(%{
        name: "Critical Response Policy",
        organization_id: organization_id
      })

      {:ok, workflow} = create_test_workflow(%{
        alert_id: alert.id,
        policy_id: policy.id,
        organization_id: organization_id,
        execution_mode: "pending_approval",
        action_type: "quarantine",
        state: "pending"
      })

      %{conn: conn, organization_id: organization_id, user: user, workflow: workflow, alert: alert}
    end

    @tag :approve_reject
    test "clicking Approve opens modal with optional comment textarea", %{conn: conn, workflow: workflow} do
      {:ok, view, _html} = live(conn, ~p"/live/remediation/approvals")

      # Click approve button
      view
      |> element("[phx-click='show_approve_modal'][phx-value-id='#{workflow.id}']")
      |> render_click()

      html = render(view)
      assert html =~ "Approve this action"
      assert html =~ "textarea" or html =~ "comment"
    end

    @tag :approve_reject
    test "clicking Reject opens modal with required comment textarea", %{conn: conn, workflow: workflow} do
      {:ok, view, _html} = live(conn, ~p"/live/remediation/approvals")

      # Click reject button
      view
      |> element("[phx-click='show_reject_modal'][phx-value-id='#{workflow.id}']")
      |> render_click()

      html = render(view)
      assert html =~ "Reject this action"
      assert html =~ "required" or html =~ "textarea"
    end

    @tag :approve_reject
    test "submitting reject with empty comment shows validation error", %{conn: conn, workflow: workflow} do
      {:ok, view, _html} = live(conn, ~p"/live/remediation/approvals")

      # Open reject modal
      view
      |> element("[phx-click='show_reject_modal'][phx-value-id='#{workflow.id}']")
      |> render_click()

      # Submit without comment
      view
      |> element("form[phx-submit='submit_rejection']")
      |> render_submit(%{"comment" => ""})

      html = render(view)
      assert html =~ "required" or html =~ "must provide" or html =~ "cannot be empty"
    end

    @tag :approve_reject
    test "successful approval removes workflow from queue and shows flash", %{conn: conn, workflow: workflow} do
      {:ok, view, _html} = live(conn, ~p"/live/remediation/approvals")

      # Verify workflow is displayed
      assert render(view) =~ "Critical Threat"

      # Open approve modal
      view
      |> element("[phx-click='show_approve_modal'][phx-value-id='#{workflow.id}']")
      |> render_click()

      # Submit approval
      view
      |> element("form[phx-submit='submit_approval']")
      |> render_submit(%{"comment" => "Approved after investigation"})

      html = render(view)

      # Workflow should be removed from queue
      refute html =~ "Critical Threat" or html =~ "No pending approvals"

      # Should show success indication
      assert html =~ "approved" or html =~ "success" or html =~ "No pending approvals"
    end

    @tag :approve_reject
    test "successful rejection transitions workflow to cancelled state", %{conn: conn, workflow: workflow} do
      {:ok, view, _html} = live(conn, ~p"/live/remediation/approvals")

      # Open reject modal
      view
      |> element("[phx-click='show_reject_modal'][phx-value-id='#{workflow.id}']")
      |> render_click()

      # Submit rejection with required comment
      view
      |> element("form[phx-submit='submit_rejection']")
      |> render_submit(%{"comment" => "False positive - not a real threat"})

      html = render(view)

      # Workflow should be removed
      refute html =~ "Critical Threat" or html =~ "No pending approvals"

      # Verify workflow state in database
      updated_workflow = Repo.get(Workflow, workflow.id)
      assert updated_workflow.state == "cancelled"
    end

    @tag :approve_reject
    test "flash notification shows on successful approve/reject", %{conn: conn, workflow: workflow} do
      {:ok, view, _html} = live(conn, ~p"/live/remediation/approvals")

      # Open approve modal and submit
      view
      |> element("[phx-click='show_approve_modal'][phx-value-id='#{workflow.id}']")
      |> render_click()

      view
      |> element("form[phx-submit='submit_approval']")
      |> render_submit(%{"comment" => ""})

      # Flash should be set - check for success indicators in the rendered HTML
      html = render(view)
      assert html =~ "approved" or html =~ "success" or html =~ "Workflow"
    end
  end

  # Helper functions

  defp create_test_alert(attrs) do
    default_attrs = %{
      title: "Test Alert",
      description: "Test alert description",
      severity: "medium",
      status: "new",
      threat_score: 0.5,
      agent_id: Ecto.UUID.generate(),
      organization_id: Ecto.UUID.generate()
    }

    merged_attrs = Map.merge(default_attrs, attrs)

    %Alert{}
    |> Alert.changeset(merged_attrs)
    |> Repo.insert()
  end

  defp create_test_policy(attrs) do
    default_attrs = %{
      name: "Test Policy",
      description: "Test policy description",
      action_type: "quarantine",
      auto_threshold: 0.3,
      manual_threshold: 0.7,
      is_enabled: true,
      organization_id: Ecto.UUID.generate()
    }

    merged_attrs = Map.merge(default_attrs, attrs)

    %Policy{}
    |> Policy.changeset(merged_attrs)
    |> Repo.insert()
  end

  defp create_test_workflow(attrs) do
    default_attrs = %{
      state: "pending",
      execution_mode: "pending_approval",
      action_type: "quarantine",
      action_config: %{},
      organization_id: Ecto.UUID.generate()
    }

    merged_attrs = Map.merge(default_attrs, attrs)

    %Workflow{}
    |> Workflow.changeset(merged_attrs)
    |> Repo.insert()
  end
end
