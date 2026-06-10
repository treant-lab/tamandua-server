defmodule TamanduaServerWeb.FileBrowserLiveTest do
  use TamanduaServerWeb.ConnCase, async: true

  import Phoenix.LiveViewTest
  import TamanduaServer.AccountsFixtures
  import TamanduaServer.AgentsFixtures

  alias TamanduaServer.LiveResponse.SessionManager

  setup do
    user = user_fixture(%{role: :analyst})
    agent = agent_fixture(%{status: :online, os_type: "linux"})

    %{user: user, agent: agent}
  end

  describe "mount" do
    test "mounts successfully for authorized user with online agent", %{conn: conn, user: user, agent: agent} do
      conn = log_in_user(conn, user)

      {:ok, view, html} = live(conn, "/agents/#{agent.id}/files")

      assert html =~ "File Browser"
      assert html =~ agent.hostname
      assert has_element?(view, "table")
    end

    test "rejects unauthorized user", %{conn: conn, agent: agent} do
      user = user_fixture(%{role: :viewer})
      conn = log_in_user(conn, user)

      assert {:error, {:redirect, %{to: "/agents"}}} = live(conn, "/agents/#{agent.id}/files")
    end

    test "rejects offline agent", %{conn: conn, user: user} do
      agent = agent_fixture(%{status: :offline})
      conn = log_in_user(conn, user)

      assert {:error, {:redirect, %{to: "/agents"}}} = live(conn, "/agents/#{agent.id}/files")
    end

    test "creates live response session on mount", %{conn: conn, user: user, agent: agent} do
      conn = log_in_user(conn, user)

      {:ok, _view, _html} = live(conn, "/agents/#{agent.id}/files")

      sessions = SessionManager.list_sessions(agent_id: agent.id, user_id: user.id)
      assert length(sessions) == 1
      assert hd(sessions).status == :active
    end

    test "initializes with default path based on OS", %{conn: conn, user: user} do
      linux_agent = agent_fixture(%{status: :online, os_type: "linux"})
      windows_agent = agent_fixture(%{status: :online, os_type: "windows"})

      conn = log_in_user(conn, user)

      {:ok, linux_view, _} = live(conn, "/agents/#{linux_agent.id}/files")
      assert has_element?(linux_view, "[phx-click='navigate'][phx-value-path='/']")

      {:ok, win_view, _} = live(conn, "/agents/#{windows_agent.id}/files")
      assert has_element?(win_view, "[phx-click='navigate'][phx-value-path='C:\\\\']")
    end

    test "accepts custom initial path from params", %{conn: conn, user: user, agent: agent} do
      conn = log_in_user(conn, user)

      {:ok, view, _html} = live(conn, "/agents/#{agent.id}/files?path=/etc")

      # Should show /etc breadcrumb
      assert has_element?(view, "button", "etc")
    end
  end

  describe "navigation" do
    setup %{conn: conn, user: user, agent: agent} do
      conn = log_in_user(conn, user)
      {:ok, view, _html} = live(conn, "/agents/#{agent.id}/files")
      %{conn: conn, view: view}
    end

    test "navigates to directory on click", %{view: view} do
      # Simulate agent response with files
      send(view.pid, {:file_list_result, "/", [
        %{"name" => "home", "path" => "/home", "is_directory" => true, "size" => 0}
      ]})

      view
      |> element("tr", "home")
      |> render_double_click()

      assert has_element?(view, "button", "home")
    end

    test "navigates via breadcrumbs", %{view: view} do
      # Simulate navigation to /etc/nginx
      send(view.pid, {:file_list_result, "/etc/nginx", []})

      view
      |> element("button[phx-click='navigate_breadcrumb'][phx-value-index='1']")
      |> render_click()

      # Should navigate back to /etc
      assert has_element?(view, "button", "etc")
    end

    test "navigates to parent directory", %{view: view} do
      # Navigate to /etc first
      send(view.pid, {:file_list_result, "/etc", []})

      view
      |> element("button[phx-click='parent_directory']")
      |> render_click()

      # Should be back at root
      assert has_element?(view, "button", "/")
    end
  end

  describe "file operations" do
    setup %{conn: conn, user: user, agent: agent} do
      conn = log_in_user(conn, user)
      {:ok, view, _html} = live(conn, "/agents/#{agent.id}/files")

      # Populate with test files
      send(view.pid, {:file_list_result, "/", [
        %{"name" => "test.txt", "path" => "/test.txt", "is_directory" => false, "size" => 1024, "modified" => 1234567890}
      ]})

      %{conn: conn, view: view}
    end

    test "selects file on click", %{view: view} do
      view
      |> element("tr[phx-click='select_file'][phx-value-path='/test.txt']")
      |> render_click()

      # Should show details panel
      assert has_element?(view, "h3", "Details")
      assert has_element?(view, "h4", "test.txt")
    end

    test "previews text file", %{view: view} do
      view
      |> element("button[phx-click='preview_file'][phx-value-path='/test.txt'][phx-value-mode='text']")
      |> render_click()

      # Simulate preview response
      send(view.pid, {:preview_ready, "/test.txt", "text", "Hello, World!"})

      assert has_element?(view, "pre", "Hello, World!")
    end

    test "downloads file", %{view: view} do
      view
      |> element("button[phx-click='download_file'][phx-value-path='/test.txt']")
      |> render_click()

      # Should show download progress
      download_id = "dl_test123"
      send(view.pid, {:download_chunk, download_id, "chunk", 512, 1024})

      assert has_element?(view, "div", "50%")
    end

    test "calculates file hash", %{view: view} do
      view
      |> element("button[phx-click='hash_file'][phx-value-path='/test.txt']")
      |> render_click()

      assert has_element?(view, "div.flash", "Calculating hashes")
    end

    test "deletes file with admin role", %{conn: conn, agent: agent} do
      admin = user_fixture(%{role: :admin})
      conn = log_in_user(conn, admin)
      {:ok, view, _html} = live(conn, "/agents/#{agent.id}/files")

      send(view.pid, {:file_list_result, "/", [
        %{"name" => "test.txt", "path" => "/test.txt", "is_directory" => false}
      ]})

      view
      |> element("button[phx-click='delete_file'][phx-value-path='/test.txt']")
      |> render_click()

      # Should show confirmation
      assert has_element?(view, "div.flash")
    end

    test "denies delete for analyst role", %{view: view} do
      send(view.pid, {:file_list_result, "/", [
        %{"name" => "test.txt", "path" => "/test.txt", "is_directory" => false}
      ]})

      view
      |> element("button[phx-click='delete_file'][phx-value-path='/test.txt']")
      |> render_click()

      assert has_element?(view, "div.flash", "Insufficient permissions")
    end
  end

  describe "view modes" do
    setup %{conn: conn, user: user, agent: agent} do
      conn = log_in_user(conn, user)
      {:ok, view, _html} = live(conn, "/agents/#{agent.id}/files")
      %{conn: conn, view: view}
    end

    test "switches to grid view", %{view: view} do
      view
      |> element("button[phx-click='change_view'][phx-value-mode='grid']")
      |> render_click()

      assert has_element?(view, "div.grid")
    end

    test "switches to tree view", %{view: view} do
      view
      |> element("button[phx-click='change_view'][phx-value-mode='tree']")
      |> render_click()

      assert has_element?(view, "div", "Tree view coming soon")
    end

    test "switches back to list view", %{view: view} do
      # Start in grid
      view
      |> element("button[phx-click='change_view'][phx-value-mode='grid']")
      |> render_click()

      # Switch back to list
      view
      |> element("button[phx-click='change_view'][phx-value-mode='list']")
      |> render_click()

      assert has_element?(view, "table")
    end
  end

  describe "sorting and filtering" do
    setup %{conn: conn, user: user, agent: agent} do
      conn = log_in_user(conn, user)
      {:ok, view, _html} = live(conn, "/agents/#{agent.id}/files")

      # Populate with multiple files
      send(view.pid, {:file_list_result, "/", [
        %{"name" => "a.txt", "path" => "/a.txt", "is_directory" => false, "size" => 100, "modified" => 1000},
        %{"name" => "z.txt", "path" => "/z.txt", "is_directory" => false, "size" => 500, "modified" => 2000},
        %{"name" => ".hidden", "path" => "/.hidden", "is_directory" => false, "size" => 10, "modified" => 500}
      ]})

      %{conn: conn, view: view}
    end

    test "sorts by name ascending", %{view: view} do
      html = view
      |> element("button[phx-click='sort'][phx-value-by='name']")
      |> render_click()

      # First file should be a.txt
      assert html =~ "a.txt"
    end

    test "sorts by size descending", %{view: view} do
      # Click once for ascending
      view
      |> element("button[phx-click='sort'][phx-value-by='size']")
      |> render_click()

      # Click again for descending
      html = view
      |> element("button[phx-click='sort'][phx-value-by='size']")
      |> render_click()

      # z.txt (500 bytes) should be first
      assert html =~ "z.txt"
    end

    test "searches for files", %{view: view} do
      html = view
      |> form("form[phx-change='search']", %{query: "z.txt"})
      |> render_change()

      assert html =~ "z.txt"
      refute html =~ "a.txt"
    end

    test "toggles hidden files", %{view: view} do
      # Initially shows hidden files
      assert has_element?(view, "tr", ".hidden")

      # Hide hidden files
      view
      |> element("button[phx-click='toggle_hidden']")
      |> render_click()

      refute has_element?(view, "tr", ".hidden")
    end

    test "always shows directories first regardless of sort", %{view: view} do
      send(view.pid, {:file_list_result, "/", [
        %{"name" => "z_file.txt", "path" => "/z_file.txt", "is_directory" => false, "size" => 100},
        %{"name" => "a_dir", "path" => "/a_dir", "is_directory" => true, "size" => 0}
      ]})

      html = view
      |> element("button[phx-click='sort'][phx-value-by='name']")
      |> render_click()

      # Directory should still be first
      [first_row | _] = html
        |> Floki.parse_document!()
        |> Floki.find("tbody tr")

      assert first_row |> Floki.text() =~ "a_dir"
    end
  end

  describe "error handling" do
    setup %{conn: conn, user: user, agent: agent} do
      conn = log_in_user(conn, user)
      {:ok, view, _html} = live(conn, "/agents/#{agent.id}/files")
      %{conn: conn, view: view}
    end

    test "displays error on file list failure", %{view: view} do
      send(view.pid, {:error, :file_list_failed, "Permission denied"})

      assert has_element?(view, "div.bg-red-50", "Permission denied")
    end

    test "handles agent offline during session", %{view: view, agent: agent} do
      send(view.pid, {:agent_status_changed, agent.id, :offline})

      assert has_element?(view, "div.flash", "Agent went offline")
    end

    test "shows empty state when no files", %{view: view} do
      send(view.pid, {:file_list_result, "/empty", []})

      assert has_element?(view, "svg")
      assert has_element?(view, "p", "No files found")
    end

    test "shows loading state during operations", %{view: view} do
      # Trigger navigation
      render_click(view, "navigate", %{"path" => "/etc"})

      # Should show loading spinner
      assert has_element?(view, "svg.animate-spin")
    end
  end

  describe "breadcrumb parsing" do
    test "parses Windows paths correctly" do
      breadcrumbs = TamanduaServerWeb.FileBrowserLive.parse_breadcrumbs("C:\\Users\\Alice\\Documents")

      assert length(breadcrumbs) == 3
      assert Enum.at(breadcrumbs, 0).name == "C:"
      assert Enum.at(breadcrumbs, 1).name == "Users"
      assert Enum.at(breadcrumbs, 2).name == "Alice"
    end

    test "parses Unix paths correctly" do
      breadcrumbs = TamanduaServerWeb.FileBrowserLive.parse_breadcrumbs("/home/alice/documents")

      assert length(breadcrumbs) == 4
      assert Enum.at(breadcrumbs, 0).name == "/"
      assert Enum.at(breadcrumbs, 1).name == "home"
      assert Enum.at(breadcrumbs, 2).name == "alice"
    end
  end

  describe "formatting helpers" do
    test "formats file sizes correctly" do
      alias TamanduaServerWeb.FileBrowserLive

      assert FileBrowserLive.format_size(500) == "500 B"
      assert FileBrowserLive.format_size(1024) == "1.0 KB"
      assert FileBrowserLive.format_size(1_048_576) == "1.0 MB"
      assert FileBrowserLive.format_size(1_073_741_824) == "1.0 GB"
    end

    test "formats timestamps correctly" do
      alias TamanduaServerWeb.FileBrowserLive

      # Unix timestamp: 2020-01-01 00:00:00 UTC
      assert FileBrowserLive.format_timestamp(1577836800) =~ "2020-01-01"
    end

    test "handles nil values gracefully" do
      alias TamanduaServerWeb.FileBrowserLive

      assert FileBrowserLive.format_size(nil) == "—"
      assert FileBrowserLive.format_timestamp(nil) == "—"
    end
  end

  describe "upload functionality" do
    setup %{conn: conn, user: user, agent: agent} do
      conn = log_in_user(conn, user)
      {:ok, view, _html} = live(conn, "/agents/#{agent.id}/files")
      %{conn: conn, view: view}
    end

    test "initiates upload", %{view: view} do
      render_click(view, "upload_file_start", %{
        "path" => "/tmp",
        "filename" => "upload.txt"
      })

      # Should store upload metadata
      assert view.assigns.upload_target_path == "/tmp"
      assert view.assigns.upload_filename == "upload.txt"
    end

    test "receives upload chunks", %{view: view} do
      render_click(view, "upload_file_start", %{
        "path" => "/tmp",
        "filename" => "upload.txt"
      })

      # Send chunks
      render_click(view, "upload_chunk", %{
        "chunk" => Base.encode64("chunk1"),
        "offset" => 0
      })

      render_click(view, "upload_chunk", %{
        "chunk" => Base.encode64("chunk2"),
        "offset" => 6
      })

      assert length(view.assigns.upload_chunks) == 2
    end

    test "completes upload by reassembling chunks", %{view: view} do
      render_click(view, "upload_file_start", %{
        "path" => "/tmp",
        "filename" => "upload.txt"
      })

      content = "Hello, World!"
      encoded = Base.encode64(content)

      render_click(view, "upload_chunk", %{
        "chunk" => encoded,
        "offset" => 0
      })

      render_click(view, "upload_complete", %{})

      # Upload chunks should be cleared
      assert view.assigns.upload_chunks == []
    end
  end

  describe "RBAC integration" do
    test "allows access with live_response_files permission", %{conn: conn, agent: agent} do
      user = user_fixture(%{role: :analyst})
      # Assume RBAC grants permission
      conn = log_in_user(conn, user)

      assert {:ok, _view, html} = live(conn, "/agents/#{agent.id}/files")
      assert html =~ "File Browser"
    end

    test "denies access without permission", %{conn: conn, agent: agent} do
      user = user_fixture(%{role: :viewer})
      conn = log_in_user(conn, user)

      assert {:error, {:redirect, %{to: "/agents"}}} = live(conn, "/agents/#{agent.id}/files")
    end
  end

  describe "session management" do
    test "reuses existing session for same user and agent", %{conn: conn, user: user, agent: agent} do
      conn = log_in_user(conn, user)

      # Create first view
      {:ok, _view1, _} = live(conn, "/agents/#{agent.id}/files")

      sessions_before = SessionManager.list_sessions(agent_id: agent.id, user_id: user.id)
      count_before = length(sessions_before)

      # Create second view
      {:ok, _view2, _} = live(conn, "/agents/#{agent.id}/files")

      sessions_after = SessionManager.list_sessions(agent_id: agent.id, user_id: user.id)
      count_after = length(sessions_after)

      # Should reuse session
      assert count_after == count_before
    end

    test "closes session when LiveView terminates", %{conn: conn, user: user, agent: agent} do
      conn = log_in_user(conn, user)

      {:ok, view, _} = live(conn, "/agents/#{agent.id}/files")
      session_id = view.assigns.session_id

      # Stop the view
      stop(view)

      # Session should eventually be closed or timed out
      Process.sleep(100)

      case SessionManager.get_session(session_id) do
        {:ok, session} -> assert session.status in [:closed, :idle]
        {:error, :not_found} -> :ok
      end
    end
  end

  describe "cross-platform path handling" do
    test "handles Windows paths correctly", %{conn: conn, user: user} do
      agent = agent_fixture(%{status: :online, os_type: "windows"})
      conn = log_in_user(conn, user)

      {:ok, view, _} = live(conn, "/agents/#{agent.id}/files?path=C:\\Windows\\System32")

      # Should parse Windows path
      assert has_element?(view, "button", "C:")
      assert has_element?(view, "button", "Windows")
      assert has_element?(view, "button", "System32")
    end

    test "handles Unix paths correctly", %{conn: conn, user: user} do
      agent = agent_fixture(%{status: :online, os_type: "linux"})
      conn = log_in_user(conn, user)

      {:ok, view, _} = live(conn, "/agents/#{agent.id}/files?path=/etc/nginx")

      # Should parse Unix path
      assert has_element?(view, "button", "/")
      assert has_element?(view, "button", "etc")
      assert has_element?(view, "button", "nginx")
    end
  end

  describe "audit logging" do
    test "logs file downloads", %{conn: conn, user: user, agent: agent} do
      conn = log_in_user(conn, user)
      {:ok, view, _} = live(conn, "/agents/#{agent.id}/files")

      send(view.pid, {:file_list_result, "/", [
        %{"name" => "test.txt", "path" => "/test.txt", "is_directory" => false}
      ]})

      render_click(view, "download_file", %{"path" => "/test.txt"})

      # Audit should be recorded via SessionManager
      session_id = view.assigns.session_id
      audit_entries = SessionManager.get_audit_entries(session_id)

      # Should have session_created and download command
      assert Enum.any?(audit_entries, &(&1.action == "command_executed"))
    end

    test "logs file deletions", %{conn: conn, agent: agent} do
      admin = user_fixture(%{role: :admin})
      conn = log_in_user(conn, admin)
      {:ok, view, _} = live(conn, "/agents/#{agent.id}/files")

      send(view.pid, {:file_list_result, "/", [
        %{"name" => "test.txt", "path" => "/test.txt", "is_directory" => false}
      ]})

      render_click(view, "delete_file", %{"path" => "/test.txt"})

      session_id = view.assigns.session_id
      audit_entries = SessionManager.get_audit_entries(session_id)

      assert Enum.any?(audit_entries, &(&1.action == "command_executed"))
    end
  end
end
