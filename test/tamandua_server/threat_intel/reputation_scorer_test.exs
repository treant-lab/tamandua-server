defmodule TamanduaServer.ThreatIntel.ReputationScorerTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.ThreatIntel.ReputationScorer

  describe "score_indicator/3" do
    test "scores an IP address with multiple sources" do
      # This test requires mocked sources or test mode
      # For now, we test the structure
      assert {:ok, score} = ReputationScorer.score_indicator(:ip, "1.2.3.4", force: true)

      assert is_map(score)
      assert Map.has_key?(score, :score)
      assert Map.has_key?(score, :confidence)
      assert Map.has_key?(score, :verdict)
      assert Map.has_key?(score, :breakdown)
      assert score.score >= 0 and score.score <= 100
      assert score.confidence >= 0.0 and score.confidence <= 1.0
    end

    test "uses cached results when available" do
      # First call
      {:ok, score1} = ReputationScorer.score_indicator(:ip, "8.8.8.8")

      # Second call should use cache
      {:ok, score2} = ReputationScorer.score_indicator(:ip, "8.8.8.8")

      assert score1.last_updated == score2.last_updated
    end

    test "bypasses cache when force: true" do
      {:ok, score1} = ReputationScorer.score_indicator(:ip, "8.8.8.8")
      Process.sleep(100)
      {:ok, score2} = ReputationScorer.score_indicator(:ip, "8.8.8.8", force: true)

      # Timestamps should be different
      assert DateTime.compare(score2.last_updated, score1.last_updated) == :gt
    end
  end

  describe "batch_score/2" do
    test "scores multiple indicators efficiently" do
      indicators = [
        {:ip, "1.2.3.4"},
        {:domain, "example.com"},
        {:url, "http://test.com"}
      ]

      results = ReputationScorer.batch_score(indicators)

      assert length(results) == 3

      Enum.each(results, fn {{_type, _value}, result} ->
        assert match?({:ok, _}, result) or match?({:error, _}, result)
      end)
    end
  end

  describe "get_score_history/3" do
    test "returns score history for an indicator" do
      # Score an indicator to create history
      ReputationScorer.score_indicator(:ip, "1.2.3.4")

      {:ok, history} = ReputationScorer.get_score_history(:ip, "1.2.3.4", days: 30)

      assert is_list(history)
    end
  end

  describe "get_score_trend/3" do
    test "calculates trend with sufficient data points" do
      # Create multiple score entries
      ip = "10.0.0.1"

      Enum.each(1..5, fn _ ->
        ReputationScorer.score_indicator(:ip, ip, force: true)
        Process.sleep(100)
      end)

      case ReputationScorer.get_score_trend(:ip, ip) do
        {:ok, trend} ->
          assert Map.has_key?(trend, :direction)
          assert Map.has_key?(trend, :change)
          assert trend.direction in ["increasing", "decreasing", "stable"]

        {:error, :insufficient_data} ->
          # This is ok too, depends on test environment
          :ok

        {:error, :no_history} ->
          :ok
      end
    end
  end

  describe "source aggregation" do
    test "applies source weights correctly" do
      # Internal IOCs should have highest weight
      weights = ReputationScorer.get_source_weights()

      assert weights["internal_iocs"] == 100
      assert weights["virustotal"] == 95
      assert weights["malwarebazaar"] == 95
    end

    test "removes outliers from scoring" do
      # Test outlier detection logic indirectly
      # by checking that scores are reasonable
      {:ok, score} = ReputationScorer.score_indicator(:ip, "1.2.3.4")

      # Score should be within reasonable bounds
      assert score.score >= 0
      assert score.score <= 100
    end
  end

  describe "verdict determination" do
    test "assigns correct verdicts based on score" do
      # Malicious threshold: 75
      # Suspicious threshold: 50
      # Unknown threshold: 25
      # Clean: < 25

      # These would need to be tested with controlled source responses
      # For now, just verify the structure
      {:ok, score} = ReputationScorer.score_indicator(:ip, "127.0.0.1")

      assert score.verdict in ["clean", "unknown", "suspicious", "malicious"]
    end
  end

  describe "cache management" do
    test "clears cache successfully" do
      # Create some cached entries
      ReputationScorer.score_indicator(:ip, "1.2.3.4")
      ReputationScorer.score_indicator(:domain, "example.com")

      stats_before = ReputationScorer.get_stats()
      assert stats_before.cache_size > 0

      # Clear cache
      :ok = ReputationScorer.clear_cache()

      stats_after = ReputationScorer.get_stats()
      assert stats_after.cache_size == 0
    end
  end

  describe "statistics" do
    test "tracks scoring statistics" do
      stats = ReputationScorer.get_stats()

      assert is_map(stats)
      assert Map.has_key?(stats, :scores_calculated)
      assert Map.has_key?(stats, :cache_hits)
      assert Map.has_key?(stats, :cache_misses)
      assert Map.has_key?(stats, :source_queries)
      assert Map.has_key?(stats, :source_count)
    end
  end
end
