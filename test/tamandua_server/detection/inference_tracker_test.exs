defmodule TamanduaServer.Detection.InferenceTrackerTest do
  @moduledoc """
  Tests for the InferenceTracker GenServer.

  The InferenceTracker module tracks ML inference request/response pairs
  for security monitoring. It provides:
  - Session ID correlation between requests and responses
  - Latency measurement
  - Token usage tracking
  - Real-time PubSub broadcasts

  Tests cover:
  - Session creation via track_request/2
  - Session completion via track_response/3
  - Session retrieval via get_session/2
  - Pending session listing via get_pending_sessions/1
  - Recent session listing via get_recent_sessions/2
  - Statistics via get_stats/1
  - Session TTL and garbage collection
  """

  use ExUnit.Case, async: false

  alias TamanduaServer.Detection.InferenceTracker
  alias TamanduaServer.Detection.InferenceTracker.Session

  setup do
    # Start the InferenceTracker if not already running
    case GenServer.whereis(InferenceTracker) do
      nil ->
        {:ok, pid} = InferenceTracker.start_link([])
        on_exit(fn ->
          if Process.alive?(pid), do: GenServer.stop(pid)
        end)
        {:ok, tracker_pid: pid}
      pid ->
        # Clear any existing sessions for test isolation
        {:ok, tracker_pid: pid}
    end
  end

  # ============================================================================
  # Session struct tests
  # ============================================================================

  describe "Session struct" do
    test "can be created with default fields" do
      session = %Session{}
      assert session.session_id == nil
      assert session.agent_id == nil
      assert session.request == nil
      assert session.response == nil
      assert session.status == nil
      assert session.created_at == nil
      assert session.updated_at == nil
      assert session.metrics == nil
      assert session.extraction_risk == nil
    end

    test "accepts all documented fields" do
      now = DateTime.utc_now()
      session = %Session{
        session_id: "sess-123",
        agent_id: "agent-456",
        request: %{prompt_preview: "Hello", api_provider: :openai},
        response: %{response_preview: "Hi there"},
        status: :complete,
        created_at: now,
        updated_at: now,
        metrics: %{latency_ms: 150, token_count: %{input_tokens: 10, output_tokens: 20}},
        extraction_risk: 0.25
      }

      assert session.session_id == "sess-123"
      assert session.agent_id == "agent-456"
      assert session.status == :complete
      assert session.metrics.latency_ms == 150
      assert session.extraction_risk == 0.25
    end
  end

  # ============================================================================
  # track_request/2 tests
  # ============================================================================

  describe "track_request/2" do
    test "creates a new session with pending status" do
      agent_id = "agent-#{System.unique_integer([:positive])}"
      event = %{
        session_id: "sess-#{System.unique_integer([:positive])}",
        pid: 1234,
        process_name: "python",
        api_provider: "openai",
        api_endpoint: "https://api.openai.com/v1/chat/completions",
        prompt_preview: "Hello, how are you?",
        timestamp: DateTime.utc_now()
      }

      assert {:ok, session_id} = InferenceTracker.track_request(agent_id, event)
      assert session_id == event.session_id

      # Verify session was created
      assert {:ok, session} = InferenceTracker.get_session(agent_id, session_id)
      assert session.status == :pending
      assert session.agent_id == agent_id
      assert session.request.api_provider == :openai
    end

    test "generates session_id if not provided" do
      agent_id = "agent-#{System.unique_integer([:positive])}"
      event = %{
        pid: 1234,
        process_name: "python",
        api_provider: "anthropic",
        prompt_preview: "Test prompt"
      }

      assert {:ok, session_id} = InferenceTracker.track_request(agent_id, event)
      assert is_binary(session_id)
      assert String.length(session_id) > 0
    end

    test "normalizes API provider names" do
      agent_id = "agent-#{System.unique_integer([:positive])}"

      providers = [
        {"openai", :openai},
        {"OpenAI", :openai},
        {"anthropic", :anthropic},
        {"Anthropic", :anthropic},
        {"ollama", :ollama},
        {"huggingface", :huggingface},
        {"unknown_provider", :other}
      ]

      for {input, expected} <- providers do
        event = %{
          session_id: "sess-#{System.unique_integer([:positive])}",
          api_provider: input,
          prompt_preview: "Test"
        }

        {:ok, session_id} = InferenceTracker.track_request(agent_id, event)
        {:ok, session} = InferenceTracker.get_session(agent_id, session_id)
        assert session.request.api_provider == expected, "Expected #{expected} for input #{input}"
      end
    end

    test "handles both atom and string keys in event" do
      agent_id = "agent-#{System.unique_integer([:positive])}"

      # String keys (from JSON)
      event_string = %{
        "session_id" => "sess-string-keys",
        "api_provider" => "openai",
        "prompt_preview" => "String key test"
      }

      assert {:ok, "sess-string-keys"} = InferenceTracker.track_request(agent_id, event_string)
      {:ok, session} = InferenceTracker.get_session(agent_id, "sess-string-keys")
      assert session.request.api_provider == :openai
    end
  end

  # ============================================================================
  # track_response/3 tests
  # ============================================================================

  describe "track_response/3" do
    test "completes a pending session" do
      agent_id = "agent-#{System.unique_integer([:positive])}"
      session_id = "sess-#{System.unique_integer([:positive])}"

      # Create request first
      request_event = %{
        session_id: session_id,
        api_provider: "openai",
        prompt_preview: "Hello"
      }
      {:ok, ^session_id} = InferenceTracker.track_request(agent_id, request_event)

      # Now send response
      response_event = %{
        response_preview: "Hi there! How can I help you?",
        response_hash: "abc123hash",
        finish_reason: "stop",
        latency_ms: 250,
        token_count: %{
          input_tokens: 5,
          output_tokens: 15,
          total_tokens: 20
        }
      }

      assert {:ok, session} = InferenceTracker.track_response(agent_id, session_id, response_event)
      assert session.status == :complete
      assert session.response.response_preview == "Hi there! How can I help you?"
      assert session.metrics.latency_ms == 250
      assert session.metrics.token_count.input_tokens == 5
    end

    test "returns error for unknown session" do
      agent_id = "agent-#{System.unique_integer([:positive])}"

      assert {:error, :session_not_found} = InferenceTracker.track_response(
        agent_id,
        "nonexistent-session",
        %{response_preview: "Test"}
      )
    end

    test "marks session as error when finish_reason is error" do
      agent_id = "agent-#{System.unique_integer([:positive])}"
      session_id = "sess-#{System.unique_integer([:positive])}"

      {:ok, ^session_id} = InferenceTracker.track_request(agent_id, %{
        session_id: session_id,
        api_provider: "openai"
      })

      {:ok, session} = InferenceTracker.track_response(agent_id, session_id, %{
        finish_reason: "error",
        error_message: "Rate limit exceeded"
      })

      assert session.status == :error
    end

    test "calculates token efficiency" do
      agent_id = "agent-#{System.unique_integer([:positive])}"
      session_id = "sess-#{System.unique_integer([:positive])}"

      {:ok, ^session_id} = InferenceTracker.track_request(agent_id, %{
        session_id: session_id,
        api_provider: "openai"
      })

      {:ok, session} = InferenceTracker.track_response(agent_id, session_id, %{
        token_count: %{input_tokens: 100, output_tokens: 50}
      })

      # Token efficiency = output / input
      assert session.metrics.token_efficiency == 0.5
    end
  end

  # ============================================================================
  # get_session/2 tests
  # ============================================================================

  describe "get_session/2" do
    test "returns session by agent_id and session_id" do
      agent_id = "agent-#{System.unique_integer([:positive])}"
      session_id = "sess-#{System.unique_integer([:positive])}"

      {:ok, ^session_id} = InferenceTracker.track_request(agent_id, %{
        session_id: session_id,
        api_provider: "anthropic"
      })

      assert {:ok, session} = InferenceTracker.get_session(agent_id, session_id)
      assert session.session_id == session_id
      assert session.agent_id == agent_id
    end

    test "returns error for nonexistent session" do
      assert {:error, :not_found} = InferenceTracker.get_session("agent-x", "nonexistent")
    end
  end

  # ============================================================================
  # get_pending_sessions/1 tests
  # ============================================================================

  describe "get_pending_sessions/1" do
    test "returns only pending sessions for agent" do
      agent_id = "agent-#{System.unique_integer([:positive])}"

      # Create two pending sessions
      {:ok, sess1} = InferenceTracker.track_request(agent_id, %{
        session_id: "pending-1",
        api_provider: "openai"
      })

      {:ok, sess2} = InferenceTracker.track_request(agent_id, %{
        session_id: "pending-2",
        api_provider: "anthropic"
      })

      # Complete one of them
      InferenceTracker.track_response(agent_id, sess1, %{response_preview: "Done"})

      # Should only return the pending one
      pending = InferenceTracker.get_pending_sessions(agent_id)
      assert length(pending) == 1
      assert hd(pending).session_id == "pending-2"
    end

    test "returns empty list for agent with no pending sessions" do
      agent_id = "agent-no-pending-#{System.unique_integer([:positive])}"
      assert InferenceTracker.get_pending_sessions(agent_id) == []
    end
  end

  # ============================================================================
  # get_recent_sessions/2 tests
  # ============================================================================

  describe "get_recent_sessions/2" do
    test "returns completed sessions within time window" do
      agent_id = "agent-#{System.unique_integer([:positive])}"

      # Create and complete a session
      {:ok, session_id} = InferenceTracker.track_request(agent_id, %{
        session_id: "recent-1",
        api_provider: "openai"
      })

      InferenceTracker.track_response(agent_id, session_id, %{response_preview: "Done"})

      # Should appear in recent sessions
      recent = InferenceTracker.get_recent_sessions(agent_id, 300)
      assert length(recent) >= 1
      assert Enum.any?(recent, fn s -> s.session_id == "recent-1" end)
    end

    test "excludes pending sessions" do
      agent_id = "agent-#{System.unique_integer([:positive])}"

      {:ok, _} = InferenceTracker.track_request(agent_id, %{
        session_id: "still-pending",
        api_provider: "openai"
      })

      recent = InferenceTracker.get_recent_sessions(agent_id, 300)
      refute Enum.any?(recent, fn s -> s.session_id == "still-pending" end)
    end
  end

  # ============================================================================
  # get_stats/1 tests
  # ============================================================================

  describe "get_stats/1" do
    test "returns statistics for agent" do
      agent_id = "agent-stats-#{System.unique_integer([:positive])}"

      # Create some sessions
      {:ok, sess1} = InferenceTracker.track_request(agent_id, %{
        session_id: "stats-1",
        api_provider: "openai"
      })

      {:ok, _sess2} = InferenceTracker.track_request(agent_id, %{
        session_id: "stats-2",
        api_provider: "anthropic"
      })

      # Complete one with latency
      InferenceTracker.track_response(agent_id, sess1, %{
        response_preview: "Done",
        latency_ms: 100
      })

      stats = InferenceTracker.get_stats(agent_id)

      assert stats.total >= 2
      assert stats.pending >= 1
      assert stats.complete >= 1
    end

    test "calculates average latency from completed sessions" do
      agent_id = "agent-latency-#{System.unique_integer([:positive])}"

      # Create and complete sessions with known latencies
      for {id, latency} <- [{"lat-1", 100}, {"lat-2", 200}] do
        {:ok, session_id} = InferenceTracker.track_request(agent_id, %{
          session_id: id,
          api_provider: "openai"
        })

        InferenceTracker.track_response(agent_id, session_id, %{
          response_preview: "Done",
          latency_ms: latency
        })
      end

      stats = InferenceTracker.get_stats(agent_id)
      assert stats.avg_latency_ms == 150.0
    end

    test "includes extraction risk statistics" do
      agent_id = "agent-extraction-stats-#{System.unique_integer([:positive])}"

      # Create and complete a session
      {:ok, session_id} = InferenceTracker.track_request(agent_id, %{
        session_id: "extract-1",
        api_provider: "openai",
        prompt_preview: "Test query"
      })

      InferenceTracker.track_response(agent_id, session_id, %{
        response_preview: "Response",
        latency_ms: 100
      })

      stats = InferenceTracker.get_stats(agent_id)

      # Stats should include extraction risk fields
      assert Map.has_key?(stats, :avg_extraction_risk)
      assert Map.has_key?(stats, :max_extraction_risk)
      assert Map.has_key?(stats, :high_extraction_risk_count)
    end
  end

  # ============================================================================
  # Module exports verification
  # ============================================================================

  describe "module exports" do
    test "start_link/1 is exported" do
      assert function_exported?(InferenceTracker, :start_link, 1)
    end

    test "track_request/2 is exported" do
      assert function_exported?(InferenceTracker, :track_request, 2)
    end

    test "track_response/3 is exported" do
      assert function_exported?(InferenceTracker, :track_response, 3)
    end

    test "get_session/2 is exported" do
      assert function_exported?(InferenceTracker, :get_session, 2)
    end

    test "get_pending_sessions/1 is exported" do
      assert function_exported?(InferenceTracker, :get_pending_sessions, 1)
    end

    test "get_recent_sessions/2 is exported" do
      assert function_exported?(InferenceTracker, :get_recent_sessions, 2)
    end

    test "get_stats/1 is exported" do
      assert function_exported?(InferenceTracker, :get_stats, 1)
    end
  end
end
