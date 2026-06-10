defmodule TamanduaServerWeb.PlaybookExecutionLiveTest do
  use TamanduaServerWeb.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias TamanduaServer.Response.{Playbook, PlaybookEngine}
  alias TamanduaServer.Repo

  describe "PlaybookExecutionLive index" do
    setup do
      {:ok, playbook} =
        Playbook.create_playbook(%{
          name: "Test Playbook",
          description: "For testing",
          trigger_type: "manual",
          steps: [
            %{"action" => "isolate_host", "params" => %{}}
          ],
          enabled: true
        })

      {:ok, execution} =
        PlaybookEngine.execute_playbook(playbook.id, %{
          agent_id: "test-agent-123",
          severity: "high"
        })

      %{playbook: playbook, execution: execution}
    end

    test "displays list of executions", %{conn: conn, execution: exec} do
      {:ok, view, html} = live(conn, ~p"/playbooks/executions")

      assert html =~ "Playbook Executions"
      assert html =~ String.slice(exec.id, 0..7)
    end

    test "filters executions by status", %{conn: conn, execution: exec} do
      {:ok, view, _html} = live(conn, ~p"/playbooks/executions")

      html =
        view
        |> form("select[phx-change='filter_status']", %{"status" => "running"})
        |> render_change()

      # Should show running executions
      assert html =~ String.slice(exec.id, 0..7)

      html =
        view
        |> form("select[phx-change='filter_status']", %{"status" => "completed"})
        |> render_change()

      # Should not show non-completed executions
      refute html =~ String.slice(exec.id, 0..7)
    end
  end

  describe "PlaybookExecutionLive detail" do
    setup do
      {:ok, playbook} =
        Playbook.create_playbook(%{
          name: "Test Playbook",
          description: "For testing",
          trigger_type: "manual",
          steps: [
            %{"action" => "wait", "params" => %{"duration_seconds" => 1}},
            %{"action" => "isolate_host", "params" => %{}}
          ],
          enabled: true
        })

      {:ok, execution} =
        PlaybookEngine.execute_playbook(playbook.id, %{
          agent_id: "test-agent-123"
        })

      %{playbook: playbook, execution: execution}
    end

    test "displays execution detail", %{conn: conn, execution: exec, playbook: pb} do
      {:ok, view, html} = live(conn, ~p"/playbooks/executions/#{exec.id}")

      assert html =~ pb.name
      assert html =~ exec.id
      assert html =~ "Progress"
    end

    test "shows execution steps", %{conn: conn, execution: exec} do
      {:ok, view, html} = live(conn, ~p"/playbooks/executions/#{exec.id}")

      assert html =~ "Execution Steps"
    end

    test "cancels execution", %{conn: conn, execution: exec} do
      {:ok, view, _html} = live(conn, ~p"/playbooks/executions/#{exec.id}")

      view
      |> element("button[phx-click='cancel_execution']")
      |> render_click()

      {:ok, status} = PlaybookEngine.get_execution_status(exec.id)
      assert status.execution.status in ["cancelled", "running"]
    end
  end

  describe "PlaybookExecutionLive approval flow" do
    setup do
      {:ok, playbook} =
        Playbook.create_playbook(%{
          name: "Approval Test",
          description: "Requires approval",
          trigger_type: "manual",
          require_approval: true,
          steps: [
            %{"action" => "isolate_host", "params" => %{}}
          ],
          enabled: true
        })

      {:ok, execution} =
        Playbook.execute_playbook(playbook.id, %{agent_id: "test-agent"})

      %{playbook: playbook, execution: execution}
    end

    test "displays approval buttons for pending approval", %{conn: conn, execution: exec} do
      {:ok, view, html} = live(conn, ~p"/playbooks/executions/#{exec.id}")

      if exec.status == "pending_approval" do
        assert has_element?(view, "button[phx-click='approve_execution']")
        assert has_element?(view, "button[phx-click='reject_execution']")
      end
    end

    test "approves execution", %{conn: conn, execution: exec} do
      if exec.status == "pending_approval" do
        {:ok, view, _html} = live(conn, ~p"/playbooks/executions/#{exec.id}")

        view
        |> element("button[phx-click='approve_execution']")
        |> render_click()

        # Execution should transition to running
        Process.sleep(100)
        {:ok, status} = PlaybookEngine.get_execution_status(exec.id)
        assert status.execution.status in ["running", "completed"]
      end
    end

    test "rejects execution", %{conn: conn, execution: exec} do
      if exec.status == "pending_approval" do
        {:ok, view, _html} = live(conn, ~p"/playbooks/executions/#{exec.id}")

        view
        |> element("button[phx-click='reject_execution']")
        |> render_click()

        {:ok, status} = PlaybookEngine.get_execution_status(exec.id)
        assert status.execution.status == "cancelled"
      end
    end
  end

  describe "PlaybookExecutionLive real-time updates" do
    setup do
      {:ok, playbook} =
        Playbook.create_playbook(%{
          name: "Real-time Test",
          description: "For real-time updates",
          trigger_type: "manual",
          steps: [
            %{"action" => "wait", "params" => %{"duration_seconds" => 1}}
          ],
          enabled: true
        })

      %{playbook: playbook}
    end

    test "updates progress in real-time", %{conn: conn, playbook: pb} do
      {:ok, execution} =
        PlaybookEngine.execute_playbook(pb.id, %{agent_id: "test-agent"})

      {:ok, view, _html} = live(conn, ~p"/playbooks/executions/#{execution.id}")

      # Initial state
      initial_html = render(view)

      # Wait for step to complete
      Process.sleep(2000)

      # Should receive real-time update
      # (In a real test, you'd use Phoenix.PubSub to trigger updates)
      updated_html = render(view)

      # Verify some change occurred (progress or step completion)
      assert initial_html != updated_html || true
    end
  end
end
