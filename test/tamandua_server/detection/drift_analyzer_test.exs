defmodule TamanduaServer.Detection.DriftAnalyzerTest do
  @moduledoc """
  Tests for the DriftAnalyzer GenServer.
  """

  use ExUnit.Case, async: false

  alias TamanduaServer.Detection.DriftAnalyzer

  # Note: These tests are designed to work without database or ML service
  # by using ETS-based storage.

  setup do
    # Start the DriftAnalyzer for each test
    case GenServer.whereis(DriftAnalyzer) do
      nil ->
        {:ok, pid} = DriftAnalyzer.start_link([])
        on_exit(fn ->
          if Process.alive?(pid), do: GenServer.stop(pid)
        end)
        {:ok, %{pid: pid}}

      pid ->
        # Clear existing state
        DriftAnalyzer.clear_history("test-model")
        {:ok, %{pid: pid}}
    end
  end

  describe "store_drift_result/1" do
    test "stores a drift result successfully" do
      result = %{
        model_id: "test-model",
        timestamp: DateTime.utc_now(),
        drift_detected: true,
        drift_type: "sudden",
        overall_severity: "high",
        features_drifting: 3,
        top_features: ["feature_a", "feature_b"],
        recommendations: [%{title: "Retrain model"}],
        confidence_score: 0.85
      }

      assert :ok = DriftAnalyzer.store_drift_result(result)
    end

    test "increments total_results_stored" do
      result = %{
        model_id: "test-model-2",
        timestamp: DateTime.utc_now(),
        drift_detected: false,
        drift_type: "none",
        overall_severity: "none",
        features_drifting: 0,
        top_features: [],
        recommendations: [],
        confidence_score: 0.5
      }

      stats_before = DriftAnalyzer.get_statistics()
      DriftAnalyzer.store_drift_result(result)
      stats_after = DriftAnalyzer.get_statistics()

      assert stats_after.total_results_stored == stats_before.total_results_stored + 1
    end
  end

  describe "analyze_trend/2" do
    test "returns empty trend for model with no history" do
      {:ok, trend} = DriftAnalyzer.analyze_trend("nonexistent-model")

      assert trend.model_id == "nonexistent-model"
      assert trend.total_checks == 0
      assert trend.drift_count == 0
      assert trend.drift_rate == 0.0
    end

    test "calculates trend from stored results" do
      # Store multiple results
      for i <- 1..5 do
        result = %{
          model_id: "trend-test-model",
          timestamp: DateTime.add(DateTime.utc_now(), -i * 3600),
          drift_detected: i > 2,  # 3 out of 5 have drift
          drift_type: if(i > 2, do: "gradual", else: "none"),
          overall_severity: if(i > 2, do: "medium", else: "none"),
          features_drifting: if(i > 2, do: i, else: 0),
          top_features: if(i > 2, do: ["feature_a"], else: []),
          recommendations: [],
          confidence_score: 0.7
        }
        DriftAnalyzer.store_drift_result(result)
      end

      {:ok, trend} = DriftAnalyzer.analyze_trend("trend-test-model", days: 7)

      assert trend.model_id == "trend-test-model"
      assert trend.total_checks == 5
      assert trend.drift_count == 3
      assert trend.drift_rate == 0.6
    end

    test "identifies top drifting features" do
      for i <- 1..3 do
        result = %{
          model_id: "features-test-model",
          timestamp: DateTime.add(DateTime.utc_now(), -i * 3600),
          drift_detected: true,
          drift_type: "gradual",
          overall_severity: "medium",
          features_drifting: 2,
          top_features: ["common_feature", "feature_#{i}"],
          recommendations: [],
          confidence_score: 0.7
        }
        DriftAnalyzer.store_drift_result(result)
      end

      {:ok, trend} = DriftAnalyzer.analyze_trend("features-test-model")

      # "common_feature" should be most frequent
      assert "common_feature" in trend.top_drifting_features
    end
  end

  describe "check_sustained_drift/1" do
    test "returns not sustained for model with no history" do
      {:ok, result} = DriftAnalyzer.check_sustained_drift("no-history-model")

      assert result.model_id == "no-history-model"
      assert result.sustained == false
      assert result.consecutive_count == 0
    end

    test "detects sustained drift" do
      # Store 4 consecutive drift results
      for i <- 1..4 do
        result = %{
          model_id: "sustained-test-model",
          timestamp: DateTime.add(DateTime.utc_now(), -i * 60),
          drift_detected: true,
          drift_type: "gradual",
          overall_severity: "high",
          features_drifting: 3,
          top_features: ["persistent_feature"],
          recommendations: [],
          confidence_score: 0.9
        }
        DriftAnalyzer.store_drift_result(result)
      end

      {:ok, result} = DriftAnalyzer.check_sustained_drift("sustained-test-model")

      assert result.sustained == true
      assert result.consecutive_count >= 3
      assert "persistent_feature" in result.common_features
    end

    test "returns appropriate action recommendation" do
      # Store many consecutive drift results
      for i <- 1..6 do
        result = %{
          model_id: "action-test-model",
          timestamp: DateTime.add(DateTime.utc_now(), -i * 60),
          drift_detected: true,
          drift_type: "sudden",
          overall_severity: "high",
          features_drifting: 5,
          top_features: ["critical_feature"],
          recommendations: [],
          confidence_score: 0.95
        }
        DriftAnalyzer.store_drift_result(result)
      end

      {:ok, result} = DriftAnalyzer.check_sustained_drift("action-test-model")

      assert result.recommended_action in ["immediate_retrain", "investigate_and_retrain"]
    end
  end

  describe "get_history/2" do
    test "returns empty list for model with no history" do
      {:ok, history} = DriftAnalyzer.get_history("empty-history-model")

      assert history == []
    end

    test "returns stored history" do
      for i <- 1..3 do
        result = %{
          model_id: "history-test-model",
          timestamp: DateTime.add(DateTime.utc_now(), -i * 3600),
          drift_detected: i == 2,
          drift_type: "none",
          overall_severity: "none",
          features_drifting: 0,
          top_features: [],
          recommendations: [],
          confidence_score: 0.5
        }
        DriftAnalyzer.store_drift_result(result)
      end

      {:ok, history} = DriftAnalyzer.get_history("history-test-model")

      assert length(history) == 3
    end

    test "respects limit parameter" do
      for i <- 1..10 do
        result = %{
          model_id: "limit-test-model",
          timestamp: DateTime.add(DateTime.utc_now(), -i * 3600),
          drift_detected: false,
          drift_type: "none",
          overall_severity: "none",
          features_drifting: 0,
          top_features: [],
          recommendations: [],
          confidence_score: 0.5
        }
        DriftAnalyzer.store_drift_result(result)
      end

      {:ok, history} = DriftAnalyzer.get_history("limit-test-model", limit: 5)

      assert length(history) == 5
    end
  end

  describe "get_drifting_models/0" do
    test "returns models with recent drift" do
      # Model with drift
      result1 = %{
        model_id: "drifting-model",
        timestamp: DateTime.utc_now(),
        drift_detected: true,
        drift_type: "sudden",
        overall_severity: "high",
        features_drifting: 3,
        top_features: ["feature_a"],
        recommendations: [],
        confidence_score: 0.9
      }
      DriftAnalyzer.store_drift_result(result1)

      # Model without drift
      result2 = %{
        model_id: "stable-model",
        timestamp: DateTime.utc_now(),
        drift_detected: false,
        drift_type: "none",
        overall_severity: "none",
        features_drifting: 0,
        top_features: [],
        recommendations: [],
        confidence_score: 0.5
      }
      DriftAnalyzer.store_drift_result(result2)

      models = DriftAnalyzer.get_drifting_models()

      drifting_ids = Enum.map(models, & &1.model_id)
      assert "drifting-model" in drifting_ids
      refute "stable-model" in drifting_ids
    end
  end

  describe "get_statistics/0" do
    test "returns statistics" do
      stats = DriftAnalyzer.get_statistics()

      assert is_integer(stats.total_results_stored)
      assert is_integer(stats.total_analyses)
      assert is_integer(stats.alerts_generated)
    end
  end

  describe "clear_history/1" do
    test "clears history for a model" do
      # Store some results
      for i <- 1..3 do
        result = %{
          model_id: "clear-test-model",
          timestamp: DateTime.add(DateTime.utc_now(), -i * 3600),
          drift_detected: true,
          drift_type: "gradual",
          overall_severity: "medium",
          features_drifting: 1,
          top_features: ["feature_a"],
          recommendations: [],
          confidence_score: 0.7
        }
        DriftAnalyzer.store_drift_result(result)
      end

      # Verify history exists
      {:ok, history_before} = DriftAnalyzer.get_history("clear-test-model")
      assert length(history_before) == 3

      # Clear history
      :ok = DriftAnalyzer.clear_history("clear-test-model")

      # Verify history is cleared
      {:ok, history_after} = DriftAnalyzer.get_history("clear-test-model")
      assert history_after == []
    end
  end
end
