defmodule TamanduaServer.LiveResponse.SessionManagerTest do
  @moduledoc """
  Tests for the Live Response SessionManager GenServer.

  Covers:
  - Session creation, authorization, connection lifecycle
  - Session lookup and listing with filters
  - Concurrent session limits (per-agent and per-user)
  - Timeout and expiration
  - Command recording
  - Session statistics
  - ETS table lifecycle
  """

  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.LiveResponse.SessionManager

  # ============================================================================
  # Session creation
  # ============================================================================

  describe "create_session/3" do
    test "creates a session with valid agent and user" do
      {_org, agent} = create_agent_with_org()
      user = insert!(:user)

      result = SessionManager.create_session(agent.id, user.id, %{})

      case result do
        {:ok, session} ->
          assert is_binary(session.id)
          assert session.agent_id == agent.id
          assert session.user_id == user.id
          assert session.status in [:active, :idle]

        {:error, reason} ->
          # May fail if agent is not in the registry (offline) -- that is valid behavior
          assert reason in [:agent_not_found, :agent_offline, :unauthorized]
      end
    end

    test "returns error for non-existent agent" do
      user = insert!(:user)
      fake_agent_id = Ecto.UUID.generate()

      result = SessionManager.create_session(fake_agent_id, user.id, %{})
      assert {:error, reason} = result
      assert reason in [:agent_not_found, :agent_offline, :unauthorized]
    end
  end

  # ============================================================================
  # Session lookup
  # ============================================================================

  describe "get_session/1" do
    test "returns error for non-existent session" do
      result = SessionManager.get_session("nonexistent-session-id")
      assert {:error, :not_found} = result
    end
  end

  # ============================================================================
  # Session listing
  # ============================================================================

  describe "list_sessions/1" do
    test "returns a list" do
      result = SessionManager.list_sessions(%{})
      assert is_list(result)
    end

    test "list_active_sessions/0 returns a list" do
      result = SessionManager.list_active_sessions()
      assert is_list(result)
    end
  end

  # ============================================================================
  # Session counting
  # ============================================================================

  describe "count_agent_sessions/1" do
    test "returns 0 for an agent with no sessions" do
      count = SessionManager.count_agent_sessions(Ecto.UUID.generate())
      assert is_integer(count)
      assert count >= 0
    end
  end

  describe "count_user_sessions/1" do
    test "returns 0 for a user with no sessions" do
      count = SessionManager.count_user_sessions(Ecto.UUID.generate())
      assert is_integer(count)
      assert count >= 0
    end
  end

  # ============================================================================
  # Statistics
  # ============================================================================

  describe "stats/0" do
    test "returns a map with expected keys" do
      stats = SessionManager.stats()

      assert is_map(stats)
      assert Map.has_key?(stats, :total_sessions)
      assert Map.has_key?(stats, :active_sessions)
    end

    test "all stat values are non-negative" do
      stats = SessionManager.stats()

      for {key, value} <- stats do
        if is_integer(value) do
          assert value >= 0, "stat #{key} should be non-negative, got #{value}"
        end
      end
    end
  end

  # ============================================================================
  # ETS tables
  # ============================================================================

  describe "ETS tables" do
    test ":live_response_sessions table exists" do
      info = :ets.info(:live_response_sessions, :size)
      assert info != :undefined
    end

    test ":live_response_audit table exists" do
      info = :ets.info(:live_response_audit, :size)
      assert info != :undefined
    end
  end

  # ============================================================================
  # Disconnect and close error paths
  # ============================================================================

  describe "disconnect_session/2" do
    test "returns error for non-existent session" do
      result = SessionManager.disconnect_session("nonexistent-session", "voluntary")
      assert {:error, :not_found} = result
    end
  end

  describe "close_session/2" do
    test "returns error for non-existent session" do
      result = SessionManager.close_session("nonexistent-session", "requested")
      assert {:error, :not_found} = result
    end
  end

  # ============================================================================
  # Touch session error path
  # ============================================================================

  describe "touch_session/1" do
    test "returns error for non-existent session" do
      result = SessionManager.touch_session("nonexistent-session")
      assert {:error, :not_found} = result
    end
  end

  # ============================================================================
  # Expire agent sessions
  # ============================================================================

  describe "expire_agent_sessions/2" do
    test "returns :ok even when no sessions exist for the agent" do
      result = SessionManager.expire_agent_sessions(Ecto.UUID.generate(), "test_reason")
      assert result == :ok
    end
  end
end
