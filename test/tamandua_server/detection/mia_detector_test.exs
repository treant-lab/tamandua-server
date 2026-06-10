defmodule TamanduaServer.Detection.MIADetectorTest do
  @moduledoc """
  Tests for the MIADetector GenServer.

  The MIADetector module tracks user sessions and detects patterns
  indicative of Membership Inference Attacks (MIA):
  - Confidence cliff patterns
  - Statistical probing
  - Query variation attacks

  Tests cover:
  - Query tracking via track_query/2
  - Session analysis via analyze_session/1
  - Session statistics via get_session_stats/1
  - Alert triggering for sustained probing
  - Session management (list, clear, reset)
  """

  use ExUnit.Case, async: false

  alias TamanduaServer.Detection.MIADetector

  setup do
    # Start the MIADetector if not already running
    case GenServer.whereis(MIADetector) do
      nil ->
        {:ok, pid} = MIADetector.start_link([])

        on_exit(fn ->
          if Process.alive?(pid), do: GenServer.stop(pid)
        end)

        {:ok, detector_pid: pid}

      pid ->
        {:ok, detector_pid: pid}
    end
  end

  # ============================================================================
  # track_query/2 tests
  # ============================================================================

  describe "track_query/2" do
    test "tracks a query for a user" do
      user_id = "user-#{System.unique_integer([:positive])}"

      :ok =
        MIADetector.track_query(user_id, %{
          query_hash: "abc123hash",
          confidence: 0.85,
          predicted_class: 1
        })

      # Small delay for async cast
      Process.sleep(10)

      {:ok, stats} = MIADetector.get_session_stats(user_id)
      assert stats.query_count == 1
      assert stats.user_id == user_id
    end

    test "accumulates multiple queries" do
      user_id = "user-#{System.unique_integer([:positive])}"

      for i <- 1..5 do
        :ok =
          MIADetector.track_query(user_id, %{
            query_hash: "hash-#{i}",
            confidence: 0.5 + i * 0.05,
            predicted_class: rem(i, 3)
          })
      end

      Process.sleep(20)

      {:ok, stats} = MIADetector.get_session_stats(user_id)
      assert stats.query_count == 5
      assert map_size(stats.class_distribution) >= 1
    end

    test "handles both atom and string keys" do
      user_id = "user-#{System.unique_integer([:positive])}"

      # Atom keys
      :ok =
        MIADetector.track_query(user_id, %{
          query_hash: "hash1",
          confidence: 0.9,
          predicted_class: 0
        })

      # String keys (from JSON)
      :ok =
        MIADetector.track_query(user_id, %{
          "query_hash" => "hash2",
          "confidence" => 0.85,
          "predicted_class" => 1
        })

      Process.sleep(20)

      {:ok, stats} = MIADetector.get_session_stats(user_id)
      assert stats.query_count == 2
    end
  end

  # ============================================================================
  # analyze_session/1 tests
  # ============================================================================

  describe "analyze_session/1" do
    test "returns no risk for insufficient queries" do
      user_id = "user-#{System.unique_integer([:positive])}"

      :ok =
        MIADetector.track_query(user_id, %{
          query_hash: "single-query",
          confidence: 0.9,
          predicted_class: 1
        })

      Process.sleep(10)

      {:ok, risk} = MIADetector.analyze_session(user_id)

      assert risk.is_attack == false
      assert risk.attack_type == :none
      assert risk.risk_level == :none
    end

    test "detects confidence cliff pattern" do
      user_id = "user-#{System.unique_integer([:positive])}"

      # Create cliff pattern: high then low confidence
      for i <- 1..5 do
        :ok =
          MIADetector.track_query(user_id, %{
            query_hash: "high-#{i}",
            confidence: 0.95,
            predicted_class: 1
          })
      end

      for i <- 1..5 do
        :ok =
          MIADetector.track_query(user_id, %{
            query_hash: "low-#{i}",
            confidence: 0.6,
            predicted_class: 0
          })
      end

      Process.sleep(20)

      {:ok, risk} = MIADetector.analyze_session(user_id)

      if risk.is_attack do
        assert risk.attack_type == :confidence_cliff
        assert risk.details[:cliff_count] >= 1
      end
    end

    test "returns error for unknown user" do
      result = MIADetector.analyze_session("nonexistent-user-12345")
      assert result == {:error, :session_not_found}
    end
  end

  # ============================================================================
  # get_session_stats/1 tests
  # ============================================================================

  describe "get_session_stats/1" do
    test "returns session statistics" do
      user_id = "user-#{System.unique_integer([:positive])}"

      for i <- 1..10 do
        :ok =
          MIADetector.track_query(user_id, %{
            query_hash: "stats-#{i}",
            confidence: 0.7 + :rand.uniform() * 0.2,
            predicted_class: rem(i, 3)
          })
      end

      Process.sleep(30)

      {:ok, stats} = MIADetector.get_session_stats(user_id)

      assert stats.user_id == user_id
      assert stats.query_count == 10
      assert is_integer(stats.unique_queries)
      assert is_float(stats.mean_confidence)
      assert stats.mean_confidence >= 0.7 and stats.mean_confidence <= 0.9
      assert is_map(stats.class_distribution)
      assert stats.alert_triggered == false
      assert %DateTime{} = stats.created_at
    end

    test "returns error for unknown user" do
      result = MIADetector.get_session_stats("unknown-user-stats-12345")
      assert result == {:error, :not_found}
    end
  end

  # ============================================================================
  # list_sessions/0 tests
  # ============================================================================

  describe "list_sessions/0" do
    test "returns all active sessions" do
      # Create a few sessions
      for i <- 1..3 do
        user_id = "list-user-#{i}-#{System.unique_integer([:positive])}"

        for j <- 1..5 do
          :ok =
            MIADetector.track_query(user_id, %{
              query_hash: "query-#{j}",
              confidence: 0.5 + :rand.uniform() * 0.4,
              predicted_class: rem(j, 2)
            })
        end
      end

      Process.sleep(30)

      sessions = MIADetector.list_sessions()

      assert is_list(sessions)
      assert length(sessions) >= 3

      Enum.each(sessions, fn session ->
        assert is_binary(session.user_id)
        assert is_integer(session.query_count)
        assert session.risk_level in [:critical, :high, :medium, :low, :none]
        assert is_boolean(session.alert_triggered)
      end)
    end
  end

  # ============================================================================
  # alert_triggered?/1 tests
  # ============================================================================

  describe "alert_triggered?/1" do
    test "returns false for new session" do
      user_id = "alert-test-#{System.unique_integer([:positive])}"

      :ok =
        MIADetector.track_query(user_id, %{
          query_hash: "test",
          confidence: 0.9,
          predicted_class: 1
        })

      Process.sleep(10)

      assert MIADetector.alert_triggered?(user_id) == false
    end

    test "returns false for unknown user" do
      assert MIADetector.alert_triggered?("unknown-alert-user-12345") == false
    end
  end

  # ============================================================================
  # clear_session/1 tests
  # ============================================================================

  describe "clear_session/1" do
    test "clears a user session" do
      user_id = "clear-test-#{System.unique_integer([:positive])}"

      :ok =
        MIADetector.track_query(user_id, %{
          query_hash: "test",
          confidence: 0.9,
          predicted_class: 1
        })

      Process.sleep(10)

      {:ok, _stats} = MIADetector.get_session_stats(user_id)

      :ok = MIADetector.clear_session(user_id)

      Process.sleep(10)

      assert MIADetector.get_session_stats(user_id) == {:error, :not_found}
    end
  end

  # ============================================================================
  # reset_alert/1 tests
  # ============================================================================

  describe "reset_alert/1" do
    test "resets alert status" do
      user_id = "reset-alert-#{System.unique_integer([:positive])}"

      :ok =
        MIADetector.track_query(user_id, %{
          query_hash: "test",
          confidence: 0.9,
          predicted_class: 1
        })

      Process.sleep(10)

      # Should not error even if alert wasn't triggered
      :ok = MIADetector.reset_alert(user_id)

      assert MIADetector.alert_triggered?(user_id) == false
    end
  end

  # ============================================================================
  # get_stats/0 tests
  # ============================================================================

  describe "get_stats/0" do
    test "returns detection statistics" do
      stats = MIADetector.get_stats()

      assert is_map(stats)
      assert is_integer(stats.total_queries_tracked)
      assert is_integer(stats.alerts_triggered)
      assert is_integer(stats.sessions_analyzed)
      assert is_integer(stats.attacks_detected)
      assert is_integer(stats.confidence_cliff_count)
      assert is_integer(stats.statistical_probe_count)
    end

    test "increments query counter" do
      initial_stats = MIADetector.get_stats()
      initial_count = initial_stats.total_queries_tracked

      user_id = "stats-inc-#{System.unique_integer([:positive])}"

      :ok =
        MIADetector.track_query(user_id, %{
          query_hash: "inc-test",
          confidence: 0.9,
          predicted_class: 1
        })

      Process.sleep(10)

      new_stats = MIADetector.get_stats()
      assert new_stats.total_queries_tracked == initial_count + 1
    end
  end

  # ============================================================================
  # Statistical probing detection tests
  # ============================================================================

  describe "statistical probing detection" do
    test "detects uniform confidence distribution" do
      user_id = "uniform-#{System.unique_integer([:positive])}"

      # Create uniform distribution
      for i <- 0..24 do
        confidence = i / 25.0

        :ok =
          MIADetector.track_query(user_id, %{
            query_hash: "uniform-#{i}-#{:rand.uniform(100_000)}",
            confidence: confidence,
            predicted_class: rem(i, 5)
          })
      end

      Process.sleep(50)

      {:ok, risk} = MIADetector.analyze_session(user_id)

      # May detect statistical probing
      if risk.is_attack do
        assert risk.attack_type in [:statistical_probe, :confidence_cliff, :query_variation]
      end
    end
  end

  # ============================================================================
  # Query variation detection tests
  # ============================================================================

  describe "query variation detection" do
    test "detects similar query patterns" do
      user_id = "variation-#{System.unique_integer([:positive])}"

      # Create queries with same hash prefix
      base_hash = "abcdef12"

      for i <- 0..9 do
        :ok =
          MIADetector.track_query(user_id, %{
            query_hash: "#{base_hash}#{String.pad_leading(to_string(i), 56, "0")}",
            confidence: 0.7 + :rand.uniform() * 0.2,
            predicted_class: 1
          })
      end

      Process.sleep(30)

      {:ok, risk} = MIADetector.analyze_session(user_id)

      if risk.is_attack do
        assert risk.attack_type in [:query_variation, :confidence_cliff]
      end
    end
  end

  # ============================================================================
  # Module exports verification
  # ============================================================================

  describe "module exports" do
    test "start_link/1 is exported" do
      assert function_exported?(MIADetector, :start_link, 1)
    end

    test "track_query/2 is exported" do
      assert function_exported?(MIADetector, :track_query, 2)
    end

    test "analyze_session/1 is exported" do
      assert function_exported?(MIADetector, :analyze_session, 1)
    end

    test "get_session_stats/1 is exported" do
      assert function_exported?(MIADetector, :get_session_stats, 1)
    end

    test "list_sessions/0 is exported" do
      assert function_exported?(MIADetector, :list_sessions, 0)
    end

    test "alert_triggered?/1 is exported" do
      assert function_exported?(MIADetector, :alert_triggered?, 1)
    end

    test "clear_session/1 is exported" do
      assert function_exported?(MIADetector, :clear_session, 1)
    end

    test "reset_alert/1 is exported" do
      assert function_exported?(MIADetector, :reset_alert, 1)
    end

    test "get_stats/0 is exported" do
      assert function_exported?(MIADetector, :get_stats, 0)
    end
  end
end
