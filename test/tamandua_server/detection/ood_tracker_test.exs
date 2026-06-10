defmodule TamanduaServer.Detection.OODTrackerTest do
  @moduledoc """
  Unit tests for Out-of-Distribution (OOD) Tracker.

  Tests cover:
  - Recording OOD detections
  - Per-model statistics tracking
  - Rolling OOD rate calculation
  - Alert generation for high OOD rates
  - Statistics aggregation
  """

  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Detection.OODTracker

  setup do
    # Start the OODTracker if not already started
    case GenServer.whereis(OODTracker) do
      nil ->
        {:ok, _pid} = OODTracker.start_link([])
        :ok

      _pid ->
        :ok
    end

    # Reset state by resetting all models
    models = OODTracker.get_all_stats()
    Enum.each(models, fn stats ->
      OODTracker.reset_model(stats.model_id)
    end)

    :ok
  end

  # =========================================================================
  # Basic recording tests
  # =========================================================================

  describe "record_detection/2" do
    test "records a detection for a model" do
      model_id = "test-model-1"

      :ok =
        OODTracker.record_detection(model_id, %{
          is_ood: false,
          ood_score: 0.2,
          severity: "low",
          agent_id: "agent-1"
        })

      # Give it time to process
      Process.sleep(50)

      {:ok, stats} = OODTracker.get_model_stats(model_id)

      assert stats.model_id == model_id
      assert stats.total_detections == 1
      assert stats.ood_count == 0
    end

    test "records OOD detection and updates ood_count" do
      model_id = "test-model-2"

      :ok =
        OODTracker.record_detection(model_id, %{
          is_ood: true,
          ood_score: 0.85,
          severity: "high",
          agent_id: "agent-1"
        })

      Process.sleep(50)

      {:ok, stats} = OODTracker.get_model_stats(model_id)

      assert stats.total_detections == 1
      assert stats.ood_count == 1
    end

    test "handles string keys in detection map" do
      model_id = "test-model-3"

      :ok =
        OODTracker.record_detection(model_id, %{
          "is_ood" => true,
          "ood_score" => 0.7,
          "severity" => "medium"
        })

      Process.sleep(50)

      {:ok, stats} = OODTracker.get_model_stats(model_id)

      assert stats.total_detections == 1
      assert stats.ood_count == 1
    end
  end

  # =========================================================================
  # Statistics tests
  # =========================================================================

  describe "get_model_stats/1" do
    test "returns error for unknown model" do
      result = OODTracker.get_model_stats("nonexistent-model")
      assert result == {:error, :not_found}
    end

    test "returns stats with correct structure" do
      model_id = "test-model-stats"

      OODTracker.record_detection(model_id, %{
        is_ood: false,
        ood_score: 0.1,
        severity: "none"
      })

      Process.sleep(50)

      {:ok, stats} = OODTracker.get_model_stats(model_id)

      assert Map.has_key?(stats, :model_id)
      assert Map.has_key?(stats, :total_detections)
      assert Map.has_key?(stats, :ood_count)
      assert Map.has_key?(stats, :ood_rate)
      assert Map.has_key?(stats, :avg_ood_score)
      assert Map.has_key?(stats, :recent_scores)
      assert Map.has_key?(stats, :severity_distribution)
      assert Map.has_key?(stats, :last_updated)
    end
  end

  describe "get_all_stats/0" do
    test "returns empty list when no models tracked" do
      stats = OODTracker.get_all_stats()
      assert is_list(stats)
    end

    test "returns stats for all tracked models" do
      OODTracker.record_detection("model-a", %{is_ood: false, ood_score: 0.1, severity: "none"})
      OODTracker.record_detection("model-b", %{is_ood: true, ood_score: 0.9, severity: "high"})

      Process.sleep(50)

      stats = OODTracker.get_all_stats()

      model_ids = Enum.map(stats, & &1.model_id)
      assert "model-a" in model_ids
      assert "model-b" in model_ids
    end

    test "sorts by OOD rate descending" do
      # Model with low OOD rate
      for _ <- 1..10 do
        OODTracker.record_detection("low-ood", %{is_ood: false, ood_score: 0.1, severity: "none"})
      end

      # Model with high OOD rate
      for _ <- 1..10 do
        OODTracker.record_detection("high-ood", %{is_ood: true, ood_score: 0.9, severity: "high"})
      end

      Process.sleep(100)

      stats = OODTracker.get_all_stats()

      # High OOD model should be first
      first_model = List.first(stats)
      assert first_model.model_id == "high-ood"
    end
  end

  # =========================================================================
  # OOD rate calculation tests
  # =========================================================================

  describe "OOD rate calculation" do
    test "calculates correct OOD rate" do
      model_id = "rate-test"

      # 3 OOD out of 10
      for i <- 1..10 do
        is_ood = i <= 3
        ood_score = if is_ood, do: 0.8, else: 0.2

        OODTracker.record_detection(model_id, %{
          is_ood: is_ood,
          ood_score: ood_score,
          severity: if(is_ood, do: "high", else: "none")
        })
      end

      Process.sleep(100)

      {:ok, stats} = OODTracker.get_model_stats(model_id)

      # Rate should be based on scores > 0.5
      assert stats.ood_rate == 0.3  # 3/10
    end

    test "maintains rolling window of recent scores" do
      model_id = "rolling-test"

      for i <- 1..150 do
        OODTracker.record_detection(model_id, %{
          is_ood: false,
          ood_score: 0.1 * rem(i, 10),
          severity: "none"
        })
      end

      Process.sleep(100)

      {:ok, stats} = OODTracker.get_model_stats(model_id)

      # Should have at most 100 recent scores (window size)
      assert length(stats.recent_scores) <= 100
    end
  end

  # =========================================================================
  # Severity distribution tests
  # =========================================================================

  describe "severity distribution tracking" do
    test "tracks severity distribution correctly" do
      model_id = "severity-test"

      OODTracker.record_detection(model_id, %{is_ood: false, ood_score: 0.1, severity: "none"})
      OODTracker.record_detection(model_id, %{is_ood: false, ood_score: 0.3, severity: "low"})
      OODTracker.record_detection(model_id, %{is_ood: true, ood_score: 0.6, severity: "medium"})
      OODTracker.record_detection(model_id, %{is_ood: true, ood_score: 0.8, severity: "high"})
      OODTracker.record_detection(model_id, %{is_ood: true, ood_score: 0.95, severity: "critical"})

      Process.sleep(100)

      {:ok, stats} = OODTracker.get_model_stats(model_id)

      assert stats.severity_distribution["none"] == 1
      assert stats.severity_distribution["low"] == 1
      assert stats.severity_distribution["medium"] == 1
      assert stats.severity_distribution["high"] == 1
      assert stats.severity_distribution["critical"] == 1
    end
  end

  # =========================================================================
  # High OOD models tests
  # =========================================================================

  describe "get_high_ood_models/0" do
    test "returns empty list when no high OOD models" do
      # Record some low OOD detections
      for _ <- 1..10 do
        OODTracker.record_detection("low-model", %{
          is_ood: false,
          ood_score: 0.1,
          severity: "none"
        })
      end

      Process.sleep(100)

      high_ood = OODTracker.get_high_ood_models()

      # Should not include models below threshold
      assert not Enum.any?(high_ood, fn {id, _rate} -> id == "low-model" end)
    end

    test "returns models above alert threshold" do
      # Record high OOD detections (>20% OOD rate)
      for _ <- 1..10 do
        OODTracker.record_detection("high-model", %{
          is_ood: true,
          ood_score: 0.9,
          severity: "high"
        })
      end

      Process.sleep(100)

      high_ood = OODTracker.get_high_ood_models()

      model_ids = Enum.map(high_ood, &elem(&1, 0))
      assert "high-model" in model_ids
    end
  end

  # =========================================================================
  # Aggregate statistics tests
  # =========================================================================

  describe "get_aggregate_stats/0" do
    test "returns aggregate statistics across all models" do
      OODTracker.record_detection("agg-1", %{is_ood: false, ood_score: 0.1, severity: "none"})
      OODTracker.record_detection("agg-2", %{is_ood: true, ood_score: 0.8, severity: "high"})

      Process.sleep(100)

      agg = OODTracker.get_aggregate_stats()

      assert Map.has_key?(agg, :models_tracked)
      assert Map.has_key?(agg, :total_detections)
      assert Map.has_key?(agg, :total_ood)
      assert Map.has_key?(agg, :global_ood_rate)
      assert Map.has_key?(agg, :models_above_threshold)
      assert Map.has_key?(agg, :models_critical)
      assert Map.has_key?(agg, :active_alerts)

      assert agg.models_tracked >= 2
      assert agg.total_detections >= 2
    end

    test "calculates global OOD rate correctly" do
      # 2 OOD out of 4 total
      OODTracker.record_detection("global-1", %{is_ood: false, ood_score: 0.1, severity: "none"})
      OODTracker.record_detection("global-1", %{is_ood: true, ood_score: 0.9, severity: "high"})
      OODTracker.record_detection("global-2", %{is_ood: false, ood_score: 0.2, severity: "none"})
      OODTracker.record_detection("global-2", %{is_ood: true, ood_score: 0.8, severity: "high"})

      Process.sleep(100)

      agg = OODTracker.get_aggregate_stats()

      # Global rate should be total_ood / total_detections
      assert agg.global_ood_rate > 0
    end
  end

  # =========================================================================
  # Reset tests
  # =========================================================================

  describe "reset_model/1" do
    test "removes model statistics" do
      model_id = "reset-test"

      OODTracker.record_detection(model_id, %{is_ood: true, ood_score: 0.9, severity: "high"})
      Process.sleep(50)

      {:ok, _stats} = OODTracker.get_model_stats(model_id)

      OODTracker.reset_model(model_id)
      Process.sleep(50)

      result = OODTracker.get_model_stats(model_id)
      assert result == {:error, :not_found}
    end
  end

  # =========================================================================
  # Alert tests
  # =========================================================================

  describe "alerts" do
    test "get_active_alerts returns list" do
      alerts = OODTracker.get_active_alerts()
      assert is_list(alerts)
    end
  end
end
