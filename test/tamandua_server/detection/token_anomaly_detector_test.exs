defmodule TamanduaServer.Detection.TokenAnomalyDetectorTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.Detection.TokenAnomalyDetector

  @moduletag :token_anomaly

  setup do
    # Start the GenServer for tests
    start_supervised!(TokenAnomalyDetector)

    # Generate unique agent IDs to avoid test interference
    agent_id = "test-agent-#{System.unique_integer([:positive])}"
    {:ok, agent_id: agent_id}
  end

  describe "learning phase" do
    test "does not flag anomalies during learning phase", %{agent_id: agent_id} do
      # During learning phase (first 20 samples), no anomalies should be flagged
      for i <- 1..19 do
        {:ok, result} =
          TokenAnomalyDetector.detect(agent_id, %{
            input_tokens: 100 + rem(i, 10),
            output_tokens: 500 + rem(i, 50),
            total_tokens: 600 + rem(i, 60)
          })

        assert result.is_anomaly == false
        assert result.details[:learning_phase] == true
        assert result.details[:samples_remaining] == 20 - i
      end
    end

    test "starts detecting after learning phase completes", %{agent_id: agent_id} do
      # Build baseline with 20 samples
      for _ <- 1..20 do
        {:ok, _} =
          TokenAnomalyDetector.detect(agent_id, %{
            input_tokens: 100,
            output_tokens: 500,
            total_tokens: 600
          })
      end

      # 21st sample should have detection enabled
      {:ok, result} =
        TokenAnomalyDetector.detect(agent_id, %{
          input_tokens: 100,
          output_tokens: 500,
          total_tokens: 600
        })

      assert result.details[:learning_phase] == nil
    end
  end

  describe "spike detection" do
    test "detects spike when token count exceeds 3 stddev", %{agent_id: agent_id} do
      # Build baseline with consistent values
      for _ <- 1..25 do
        {:ok, _} =
          TokenAnomalyDetector.detect(agent_id, %{
            input_tokens: 100,
            output_tokens: 500,
            total_tokens: 600
          })
      end

      # Inject a massive spike (10x normal)
      {:ok, result} =
        TokenAnomalyDetector.detect(agent_id, %{
          input_tokens: 1000,
          output_tokens: 5000,
          total_tokens: 6000
        })

      assert result.is_anomaly == true
      assert result.anomaly_type == :spike
      assert result.anomaly_score >= 0.5
      assert result.details.z_scores.total > 3.0
    end

    test "does not flag normal variance as spike", %{agent_id: agent_id} do
      # Build baseline with some variance
      for i <- 1..25 do
        {:ok, _} =
          TokenAnomalyDetector.detect(agent_id, %{
            input_tokens: 80 + rem(i, 40),
            output_tokens: 400 + rem(i, 200),
            total_tokens: 480 + rem(i, 240)
          })
      end

      # Test with value within normal variance
      {:ok, result} =
        TokenAnomalyDetector.detect(agent_id, %{
          input_tokens: 110,
          output_tokens: 550,
          total_tokens: 660
        })

      assert result.is_anomaly == false
      assert result.anomaly_type == nil
    end
  end

  describe "unusual ratio detection" do
    test "detects unusual input/output ratio", %{agent_id: agent_id} do
      # Build baseline with consistent ratio (~5:1 output/input)
      for _ <- 1..25 do
        {:ok, _} =
          TokenAnomalyDetector.detect(agent_id, %{
            input_tokens: 100,
            output_tokens: 500,
            total_tokens: 600
          })
      end

      # Inject unusual ratio (0.1:1 instead of 5:1)
      {:ok, result} =
        TokenAnomalyDetector.detect(agent_id, %{
          input_tokens: 1000,
          output_tokens: 100,
          total_tokens: 1100
        })

      assert result.is_anomaly == true
      # Could be spike or unusual_ratio depending on z-scores
      assert result.anomaly_type in [:spike, :unusual_ratio]
    end
  end

  describe "sustained high detection" do
    test "detects sustained high usage after 5 consecutive high samples", %{agent_id: agent_id} do
      # Build baseline with normal values
      for _ <- 1..25 do
        {:ok, _} =
          TokenAnomalyDetector.detect(agent_id, %{
            input_tokens: 100,
            output_tokens: 500,
            total_tokens: 600
          })
      end

      # Get baseline to check percentile
      {:ok, baseline} = TokenAnomalyDetector.get_baseline(agent_id)
      high_value = round(baseline.percentile_95_total * 1.2)

      # Send 4 high values (below sustained threshold)
      for _ <- 1..4 do
        {:ok, result} =
          TokenAnomalyDetector.detect(agent_id, %{
            input_tokens: div(high_value, 6),
            output_tokens: div(high_value * 5, 6),
            total_tokens: high_value
          })

        # Not yet sustained high
        refute result.anomaly_type == :sustained_high
      end

      # 5th consecutive high should trigger sustained_high
      {:ok, result} =
        TokenAnomalyDetector.detect(agent_id, %{
          input_tokens: div(high_value, 6),
          output_tokens: div(high_value * 5, 6),
          total_tokens: high_value
        })

      assert result.is_anomaly == true
      assert result.anomaly_type == :sustained_high
    end
  end

  describe "baseline management" do
    test "get_baseline returns baseline after samples", %{agent_id: agent_id} do
      for _ <- 1..5 do
        {:ok, _} =
          TokenAnomalyDetector.detect(agent_id, %{
            input_tokens: 100,
            output_tokens: 500,
            total_tokens: 600
          })
      end

      {:ok, baseline} = TokenAnomalyDetector.get_baseline(agent_id)

      assert baseline.sample_count == 5
      assert baseline.mean_total_tokens == 600.0
      assert baseline.mean_input_tokens == 100.0
      assert baseline.mean_output_tokens == 500.0
    end

    test "get_baseline returns error for unknown agent", %{agent_id: agent_id} do
      result = TokenAnomalyDetector.get_baseline("unknown-agent-#{agent_id}")
      assert result == {:error, :not_found}
    end

    test "reset_baseline clears agent baseline", %{agent_id: agent_id} do
      # Build some baseline
      for _ <- 1..5 do
        {:ok, _} =
          TokenAnomalyDetector.detect(agent_id, %{
            input_tokens: 100,
            output_tokens: 500,
            total_tokens: 600
          })
      end

      assert {:ok, _} = TokenAnomalyDetector.get_baseline(agent_id)

      # Reset
      :ok = TokenAnomalyDetector.reset_baseline(agent_id)

      # Should be gone
      assert {:error, :not_found} = TokenAnomalyDetector.get_baseline(agent_id)
    end

    test "update_baseline updates without detection", %{agent_id: agent_id} do
      # Use update_baseline instead of detect
      :ok =
        TokenAnomalyDetector.update_baseline(agent_id, %{
          input_tokens: 100,
          output_tokens: 500,
          total_tokens: 600
        })

      # Allow async cast to complete
      Process.sleep(10)

      {:ok, baseline} = TokenAnomalyDetector.get_baseline(agent_id)
      assert baseline.sample_count == 1
    end
  end

  describe "rolling window" do
    test "sample count caps at 1000", %{agent_id: agent_id} do
      # Use update_baseline for speed
      for _ <- 1..1005 do
        :ok =
          TokenAnomalyDetector.update_baseline(agent_id, %{
            input_tokens: 100,
            output_tokens: 500,
            total_tokens: 600
          })
      end

      # Allow async casts to complete
      Process.sleep(50)

      {:ok, baseline} = TokenAnomalyDetector.get_baseline(agent_id)
      assert baseline.sample_count == 1000
    end
  end

  describe "performance" do
    test "detection completes in under 10ms", %{agent_id: agent_id} do
      # Build baseline
      for _ <- 1..25 do
        {:ok, _} =
          TokenAnomalyDetector.detect(agent_id, %{
            input_tokens: 100,
            output_tokens: 500,
            total_tokens: 600
          })
      end

      # Measure detection time
      start = System.monotonic_time(:millisecond)

      for _ <- 1..100 do
        {:ok, _} =
          TokenAnomalyDetector.detect(agent_id, %{
            input_tokens: 100,
            output_tokens: 500,
            total_tokens: 600
          })
      end

      elapsed = System.monotonic_time(:millisecond) - start
      avg_time = elapsed / 100

      assert avg_time < 10, "Average detection time #{avg_time}ms exceeds 10ms target"
    end
  end

  describe "edge cases" do
    test "handles nil token values gracefully", %{agent_id: agent_id} do
      {:ok, result} =
        TokenAnomalyDetector.detect(agent_id, %{
          input_tokens: nil,
          output_tokens: nil,
          total_tokens: nil
        })

      assert result.is_anomaly == false
    end

    test "handles zero input tokens (no division by zero)", %{agent_id: agent_id} do
      # Build baseline
      for _ <- 1..25 do
        {:ok, _} =
          TokenAnomalyDetector.detect(agent_id, %{
            input_tokens: 100,
            output_tokens: 500,
            total_tokens: 600
          })
      end

      # Zero input should not crash
      {:ok, result} =
        TokenAnomalyDetector.detect(agent_id, %{
          input_tokens: 0,
          output_tokens: 500,
          total_tokens: 500
        })

      assert is_map(result)
    end

    test "handles string keys in token_count", %{agent_id: agent_id} do
      {:ok, result} =
        TokenAnomalyDetector.detect(agent_id, %{
          "input_tokens" => 100,
          "output_tokens" => 500,
          "total_tokens" => 600
        })

      assert result.is_anomaly == false
    end
  end
end
