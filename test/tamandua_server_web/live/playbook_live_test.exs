defmodule TamanduaServerWeb.PlaybookLiveTest do
  use TamanduaServerWeb.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias TamanduaServer.Response.Playbook

  describe "PlaybookLive index" do
    setup do
      # Create test playbooks
      {:ok, pb1} =
        Playbook.create_playbook(%{
          name: "Test Playbook 1",
          description: "First test playbook",
          trigger_type: "manual",
          steps: [
            %{"action" => "isolate_host", "params" => %{}}
          ],
          enabled: true
        }, :system)

      {:ok, pb2} =
        Playbook.create_playbook(%{
          name: "Test Playbook 2",
          description: "Second test playbook",
          trigger_type: "alert",
          steps: [
            %{"action" => "kill_process", "params" => %{}}
          ],
          enabled: false
        }, :system)

      %{playbook1: pb1, playbook2: pb2}
    end

    test "displays list of playbooks", %{conn: conn, playbook1: pb1, playbook2: pb2} do
      {:ok, view, html} = live(conn, ~p"/playbooks")

      assert html =~ "Automated Response Playbooks"
      assert html =~ pb1.name
      assert html =~ pb2.name
    end

    test "filters playbooks by enabled status", %{conn: conn, playbook1: pb1, playbook2: pb2} do
      {:ok, view, _html} = live(conn, ~p"/playbooks")

      # Filter to enabled only
      html =
        view
        |> form("#filter-enabled", %{"enabled" => "true"})
        |> render_change()

      assert html =~ pb1.name
      refute html =~ pb2.name

      # Filter to disabled only
      html =
        view
        |> form("#filter-enabled", %{"enabled" => "false"})
        |> render_change()

      refute html =~ pb1.name
      assert html =~ pb2.name
    end

    test "filters playbooks by trigger type", %{conn: conn, playbook1: pb1, playbook2: pb2} do
      {:ok, view, _html} = live(conn, ~p"/playbooks")

      # Filter to manual trigger
      html =
        view
        |> form("#filter-trigger", %{"trigger" => "manual"})
        |> render_change()

      assert html =~ pb1.name
      refute html =~ pb2.name
    end

    test "searches playbooks by name", %{conn: conn, playbook1: pb1, playbook2: pb2} do
      {:ok, view, _html} = live(conn, ~p"/playbooks")

      html =
        view
        |> form("#search", %{"query" => "First"})
        |> render_change()

      assert html =~ pb1.name
      refute html =~ pb2.name
    end

    test "toggles playbook enabled status", %{conn: conn, playbook1: pb1} do
      {:ok, view, _html} = live(conn, ~p"/playbooks")

      assert pb1.enabled == true

      view
      |> element("button[phx-click='toggle_enabled'][phx-value-id='#{pb1.id}']")
      |> render_click()

      {:ok, updated} = Playbook.get_playbook(pb1.id, :system)
      assert updated.enabled == false
    end

    test "shows execute modal", %{conn: conn, playbook1: pb1} do
      {:ok, view, _html} = live(conn, ~p"/playbooks")

      refute has_element?(view, "#execute-modal")

      view
      |> element("button[phx-click='show_execute_modal'][phx-value-id='#{pb1.id}']")
      |> render_click()

      assert has_element?(view, "h3", "Execute Playbook: #{pb1.name}")
    end

    test "executes playbook with context", %{conn: conn, playbook1: pb1} do
      {:ok, view, _html} = live(conn, ~p"/playbooks")

      view
      |> element("button[phx-click='show_execute_modal'][phx-value-id='#{pb1.id}']")
      |> render_click()

      # Fill in context
      view
      |> element("input[phx-value-field='agent_id']")
      |> render_change(%{"value" => "test-agent-123"})

      # Execute
      assert view
             |> element("button[phx-click='execute_playbook']")
             |> render_click() =~ "Playbook execution started"
    end

    test "shows delete modal", %{conn: conn, playbook1: pb1} do
      {:ok, view, _html} = live(conn, ~p"/playbooks")

      refute has_element?(view, "h3", "Delete Playbook")

      view
      |> element("button[phx-click='show_delete_modal'][phx-value-id='#{pb1.id}']")
      |> render_click()

      assert has_element?(view, "h3", "Delete Playbook")
      assert has_element?(view, "p", ~r/#{pb1.name}/)
    end

    test "deletes playbook", %{conn: conn, playbook1: pb1} do
      {:ok, view, _html} = live(conn, ~p"/playbooks")

      view
      |> element("button[phx-click='show_delete_modal'][phx-value-id='#{pb1.id}']")
      |> render_click()

      view
      |> element("button[phx-click='confirm_delete']")
      |> render_click()

      assert {:error, :not_found} = Playbook.get_playbook(pb1.id, :system)
    end

    test "clones playbook", %{conn: conn, playbook1: pb1} do
      {:ok, view, _html} = live(conn, ~p"/playbooks")

      view
      |> element("button[phx-click='clone_playbook'][phx-value-id='#{pb1.id}']")
      |> render_click()

      # Should navigate to editor with cloned playbook
      assert_patch(view, ~p"/playbooks/editor")
    end
  end

  describe "PlaybookLive with selected playbook" do
    setup do
      {:ok, playbook} =
        Playbook.create_playbook(%{
          name: "Selected Playbook",
          description: "Test selection",
          trigger_type: "manual",
          steps: [],
          enabled: true
        }, :system)

      %{playbook: playbook}
    end

    test "selects and displays playbook details", %{conn: conn, playbook: pb} do
      {:ok, view, _html} = live(conn, ~p"/playbooks?id=#{pb.id}")

      # Verify playbook is selected (implementation specific)
      assert view.assigns.selected_playbook.id == pb.id
    end

    test "closes playbook details", %{conn: conn, playbook: pb} do
      {:ok, view, _html} = live(conn, ~p"/playbooks?id=#{pb.id}")

      view
      |> element("button[phx-click='close_details']")
      |> render_click()

      assert_patch(view, ~p"/playbooks")
    end
  end
end
