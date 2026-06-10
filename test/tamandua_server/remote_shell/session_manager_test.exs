defmodule TamanduaServer.RemoteShell.SessionManagerTest do
  use TamanduaServer.DataCase

  alias TamanduaServer.RemoteShell.SessionManager
  alias TamanduaServer.{Accounts, Agents}

  setup do
    # Start SessionManager
    start_supervised!(SessionManager)

    # Create test user with shell permissions
    user = insert(:user)
    role = insert(:role, name: "admin")
    insert(:user_role, user: user, role: role)

    # Create test agent
    agent = insert(:agent, hostname: "test-host", os_type: "linux")

    %{user: user, agent: agent}
  end

  describe "create_session/1" do
    test "creates a new session with valid parameters", %{user: user, agent: agent} do
      opts = [
        user_id: user.id,
        agent_id: agent.id,
        client_ip: "192.168.1.100",
        user_agent: "Mozilla/5.0",
        config: %{cols: 120, rows: 40}
      ]

      assert {:ok, session} = SessionManager.create_session(opts)
      assert session.session_id
      assert session.user_id == user.id
      assert session.agent_id == agent.id
    end

    test "enforces RBAC permissions", %{user: user, agent: agent} do
      # Revoke shell permission
      Accounts.revoke_permission(user, "shell:open")

      opts = [
        user_id: user.id,
        agent_id: agent.id,
        client_ip: "127.0.0.1",
        user_agent: "test",
        config: %{}
      ]

      assert {:error, :permission_denied} = SessionManager.create_session(opts)
    end

    test "enforces session quota", %{user: user, agent: agent} do
      # Create maximum allowed sessions (5)
      for _ <- 1..5 do
        SessionManager.create_session(
          user_id: user.id,
          agent_id: agent.id,
          client_ip: "127.0.0.1",
          user_agent: "test",
          config: %{}
        )
      end

      # Attempt to create one more
      opts = [
        user_id: user.id,
        agent_id: agent.id,
        client_ip: "127.0.0.1",
        user_agent: "test",
        config: %{}
      ]

      assert {:error, :quota_exceeded} = SessionManager.create_session(opts)
    end

    test "creates recording file", %{user: user, agent: agent} do
      opts = [
        user_id: user.id,
        agent_id: agent.id,
        client_ip: "127.0.0.1",
        user_agent: "test",
        config: %{}
      ]

      assert {:ok, session} = SessionManager.create_session(opts)

      # Check recording file exists
      db_session = TamanduaServer.ShellSessions.get_session_by_session_id(session.session_id)
      assert db_session.recording_path
      assert db_session.has_recording
      assert File.exists?(db_session.recording_path)
    end
  end

  describe "get_session/1" do
    test "retrieves existing session", %{user: user, agent: agent} do
      {:ok, session} = create_test_session(user, agent)

      retrieved = SessionManager.get_session(session.session_id)
      assert retrieved
      assert retrieved.session_id == session.session_id
    end

    test "returns nil for non-existent session" do
      assert is_nil(SessionManager.get_session("nonexistent"))
    end
  end

  describe "terminate_session/2" do
    test "terminates active session", %{user: user, agent: agent} do
      {:ok, session} = create_test_session(user, agent)

      assert :ok = SessionManager.terminate_session(session.session_id, "user_requested")

      # Session should be marked as ended
      db_session = TamanduaServer.ShellSessions.get_session_by_session_id(session.session_id)
      assert db_session.status == :ended
      assert db_session.end_reason == "user_requested"

      # Should be removed from in-memory state
      refute SessionManager.get_session(session.session_id)
    end

    test "returns error for non-existent session" do
      assert {:error, :not_found} = SessionManager.terminate_session("nonexistent", "test")
    end
  end

  describe "update_stats/2" do
    test "updates session statistics", %{user: user, agent: agent} do
      {:ok, session} = create_test_session(user, agent)

      stats = %{
        command_count: 10,
        bytes_sent: 1024,
        bytes_received: 2048
      }

      SessionManager.update_stats(session.session_id, stats)

      # Wait for async update
      :timer.sleep(100)

      # Check database
      db_session = TamanduaServer.ShellSessions.get_session_by_session_id(session.session_id)
      assert db_session.command_count == 10
      assert db_session.bytes_sent == 1024
      assert db_session.bytes_received == 2048
    end
  end

  describe "list_active_sessions/0" do
    test "lists all active sessions", %{user: user, agent: agent} do
      {:ok, session1} = create_test_session(user, agent)
      {:ok, session2} = create_test_session(user, agent)

      sessions = SessionManager.list_active_sessions()
      session_ids = Enum.map(sessions, & &1.session_id)

      assert session1.session_id in session_ids
      assert session2.session_id in session_ids
    end
  end

  describe "list_user_sessions/1" do
    test "lists sessions for specific user", %{user: user, agent: agent} do
      {:ok, session} = create_test_session(user, agent)

      # Create session for different user
      other_user = insert(:user)
      create_test_session(other_user, agent)

      sessions = SessionManager.list_user_sessions(user.id)
      assert length(sessions) == 1
      assert hd(sessions).session_id == session.session_id
    end
  end

  describe "list_agent_sessions/1" do
    test "lists sessions for specific agent", %{user: user, agent: agent} do
      {:ok, session} = create_test_session(user, agent)

      # Create session for different agent
      other_agent = insert(:agent)
      create_test_session(user, other_agent)

      sessions = SessionManager.list_agent_sessions(agent.id)
      assert length(sessions) == 1
      assert hd(sessions).session_id == session.session_id
    end
  end

  describe "can_create_session?/2" do
    test "returns true when user can create session", %{user: user, agent: agent} do
      assert {:ok, true} = SessionManager.can_create_session?(user.id, agent.id)
    end

    test "returns false when user lacks permission", %{user: user, agent: agent} do
      Accounts.revoke_permission(user, "shell:open")

      assert {:ok, false, :permission_denied} =
        SessionManager.can_create_session?(user.id, agent.id)
    end

    test "returns false when quota exceeded", %{user: user, agent: agent} do
      # Create maximum sessions
      for _ <- 1..5 do
        create_test_session(user, agent)
      end

      assert {:ok, false, :quota_exceeded} =
        SessionManager.can_create_session?(user.id, agent.id)
    end
  end

  describe "session timeout" do
    test "automatically terminates expired sessions", %{user: user, agent: agent} do
      {:ok, session} = create_test_session(user, agent)

      # Simulate old session by updating started_at
      old_time = DateTime.add(DateTime.utc_now(), -3600, :second)
      db_session = TamanduaServer.ShellSessions.get_session_by_session_id(session.session_id)
      TamanduaServer.ShellSessions.update_session(db_session, %{started_at: old_time})

      # Trigger cleanup
      send(SessionManager, :cleanup_sessions)

      # Wait for cleanup
      :timer.sleep(100)

      # Session should be terminated
      refute SessionManager.get_session(session.session_id)
    end
  end

  # ============================================================================
  # Helpers
  # ============================================================================

  defp create_test_session(user, agent) do
    SessionManager.create_session(
      user_id: user.id,
      agent_id: agent.id,
      client_ip: "127.0.0.1",
      user_agent: "test",
      config: %{cols: 80, rows: 24}
    )
  end
end
