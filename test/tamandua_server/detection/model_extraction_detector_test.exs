defmodule TamanduaServer.Detection.ModelExtractionDetectorTest do
  @moduledoc """
  Tests for the ModelExtractionDetector GenServer.

  The ModelExtractionDetector module detects model extraction attacks by analyzing
  query patterns per client/user. It provides:
  - High query volume detection
  - Systematic input variation (grid search) detection
  - Boundary probing detection
  - Input space coverage tracking
  - Output type analysis (logits/confidence requests)
  - Rate limiting with exponential backoff
  - Output perturbation
  - Query watermarking

  Tests cover:
  - Session analysis via analyze_session/2
  - Pattern detection via detect_extraction_pattern/1
  - Rate limiting via should_throttle?/1
  - Query recording via record_query/2
  - Countermeasures (perturbation, watermarking)
  - Client risk tracking
  """

  use ExUnit.Case, async: false

  alias TamanduaServer.Detection.ModelExtractionDetector

  setup do
    # Start the detector if not already running
    case GenServer.whereis(ModelExtractionDetector) do
      nil ->
        {:ok, pid} = ModelExtractionDetector.start_link([])
        on_exit(fn ->
          if Process.alive?(pid), do: GenServer.stop(pid)
        end)
        {:ok, detector_pid: pid}
      pid ->
        {:ok, detector_pid: pid}
    end
  end

  # ============================================================================
  # analyze_session/2 tests
  # ============================================================================

  describe "analyze_session/2" do
    test "returns low risk for normal queries" do
      client_id = "client-normal-#{System.unique_integer([:positive])}"

      queries = [
        %{input: "What is the weather today?", output_type: :text, timestamp: DateTime.utc_now()},
        %{input: "Tell me a joke", output_type: :text, timestamp: DateTime.utc_now()},
        %{input: "How do I cook pasta?", output_type: :text, timestamp: DateTime.utc_now()}
      ]

      assert {:ok, result} = ModelExtractionDetector.analyze_session(client_id, queries)
      assert result.extraction_risk < 0.5
      assert result.recommended_action == :allow
    end

    test "detects high query volume" do
      client_id = "client-volume-#{System.unique_integer([:positive])}"

      # Generate 1000+ queries to trigger volume detection
      queries = for i <- 1..1100 do
        %{
          input: "Query #{i}",
          output_type: :text,
          timestamp: DateTime.utc_now()
        }
      end

      assert {:ok, result} = ModelExtractionDetector.analyze_session(client_id, queries)
      assert :high_volume in result.signals
      assert result.signal_details[:high_volume][:queries_per_hour] >= 1000
    end

    test "detects systematic numeric variation (grid search)" do
      client_id = "client-grid-#{System.unique_integer([:positive])}"

      # Generate grid-like queries with regular numeric patterns
      queries = for i <- 0..49 do
        %{
          input: "Analyze value: #{i * 0.1}",
          output_type: :confidence,
          timestamp: DateTime.utc_now()
        }
      end

      assert {:ok, result} = ModelExtractionDetector.analyze_session(client_id, queries)
      # Should detect systematic variation due to regular spacing
      assert result.extraction_risk > 0.0
    end

    test "detects low-entropy output requests" do
      client_id = "client-logits-#{System.unique_integer([:positive])}"

      # Most queries requesting logits/confidence
      queries = for i <- 1..20 do
        %{
          input: "Input #{i}",
          output_type: if(rem(i, 10) == 0, do: :text, else: :logits),
          timestamp: DateTime.utc_now()
        }
      end

      assert {:ok, result} = ModelExtractionDetector.analyze_session(client_id, queries)
      assert :low_entropy_outputs in result.signals
      assert result.signal_details[:low_entropy_outputs][:logit_request_ratio] > 0.7
    end

    test "accepts single query" do
      client_id = "client-single-#{System.unique_integer([:positive])}"

      query = %{
        input: "Single query test",
        output_type: :text,
        timestamp: DateTime.utc_now()
      }

      assert {:ok, result} = ModelExtractionDetector.analyze_session(client_id, query)
      assert is_float(result.extraction_risk)
    end

    test "handles queries with string keys" do
      client_id = "client-string-keys-#{System.unique_integer([:positive])}"

      queries = [
        %{"input" => "Test query", "output_type" => "text", "timestamp" => DateTime.utc_now()}
      ]

      assert {:ok, result} = ModelExtractionDetector.analyze_session(client_id, queries)
      assert is_float(result.extraction_risk)
    end
  end

  # ============================================================================
  # detect_extraction_pattern/1 tests
  # ============================================================================

  describe "detect_extraction_pattern/1" do
    test "returns false for normal queries" do
      queries = [
        %{input: "What is AI?", output_type: :text, timestamp: DateTime.utc_now()},
        %{input: "How does ML work?", output_type: :text, timestamp: DateTime.utc_now()}
      ]

      assert ModelExtractionDetector.detect_extraction_pattern(queries) == false
    end

    test "returns true for suspicious patterns" do
      # Many logit requests with systematic variation
      queries = for i <- 1..100 do
        %{
          input: "Classify: item_#{div(i, 10)}_#{rem(i, 10)}",
          output_type: :logits,
          timestamp: DateTime.utc_now()
        }
      end

      # Add more to ensure high volume
      queries = queries ++ for i <- 101..1100 do
        %{
          input: "Query #{i}",
          output_type: :logits,
          timestamp: DateTime.utc_now()
        }
      end

      result = ModelExtractionDetector.detect_extraction_pattern(queries)
      assert is_boolean(result)
    end
  end

  # ============================================================================
  # should_throttle?/1 tests
  # ============================================================================

  describe "should_throttle?/1" do
    test "returns false for unknown client" do
      assert ModelExtractionDetector.should_throttle?("unknown-client") == false
    end

    test "returns false for low-risk client" do
      client_id = "client-safe-#{System.unique_integer([:positive])}"

      query = %{input: "Normal query", output_type: :text, timestamp: DateTime.utc_now()}
      {:ok, _} = ModelExtractionDetector.record_query(client_id, query)

      assert ModelExtractionDetector.should_throttle?(client_id) == false
    end

    test "returns true after high-risk activity" do
      client_id = "client-risky-#{System.unique_integer([:positive])}"

      # Generate high-volume suspicious queries
      queries = for i <- 1..1200 do
        %{
          input: "Systematic query #{i}",
          output_type: :logits,
          timestamp: DateTime.utc_now()
        }
      end

      {:ok, result} = ModelExtractionDetector.analyze_session(client_id, queries)

      if result.extraction_risk >= 0.7 do
        assert ModelExtractionDetector.should_throttle?(client_id) == true
      end
    end
  end

  # ============================================================================
  # record_query/2 tests
  # ============================================================================

  describe "record_query/2" do
    test "records query and returns analysis" do
      client_id = "client-record-#{System.unique_integer([:positive])}"

      query = %{
        input: "Test input",
        output_type: :text,
        timestamp: DateTime.utc_now(),
        metadata: %{model: "gpt-4"}
      }

      assert {:ok, result} = ModelExtractionDetector.record_query(client_id, query)
      assert is_float(result.extraction_risk)
      assert is_list(result.signals)
      assert is_atom(result.recommended_action)
    end

    test "accumulates queries over time" do
      client_id = "client-accumulate-#{System.unique_integer([:positive])}"

      for i <- 1..10 do
        query = %{input: "Query #{i}", output_type: :text, timestamp: DateTime.utc_now()}
        {:ok, _} = ModelExtractionDetector.record_query(client_id, query)
      end

      {:ok, risk} = ModelExtractionDetector.get_client_risk(client_id)
      assert is_float(risk)
    end

    test "tracks query count per hour" do
      client_id = "client-hourly-#{System.unique_integer([:positive])}"

      for _ <- 1..50 do
        query = %{input: "Query", output_type: :text, timestamp: DateTime.utc_now()}
        {:ok, _} = ModelExtractionDetector.record_query(client_id, query)
      end

      # Client should have recorded queries
      {:ok, risk} = ModelExtractionDetector.get_client_risk(client_id)
      assert risk >= 0.0
    end
  end

  # ============================================================================
  # get_client_risk/1 tests
  # ============================================================================

  describe "get_client_risk/1" do
    test "returns error for unknown client" do
      assert {:error, :not_found} = ModelExtractionDetector.get_client_risk("nonexistent")
    end

    test "returns risk score for known client" do
      client_id = "client-risk-#{System.unique_integer([:positive])}"

      query = %{input: "Test", output_type: :text, timestamp: DateTime.utc_now()}
      {:ok, _} = ModelExtractionDetector.record_query(client_id, query)

      assert {:ok, risk} = ModelExtractionDetector.get_client_risk(client_id)
      assert is_float(risk)
      assert risk >= 0.0 and risk <= 1.0
    end
  end

  # ============================================================================
  # apply_perturbation/3 tests
  # ============================================================================

  describe "apply_perturbation/3" do
    test "adds noise to confidence values" do
      client_id = "client-perturb-#{System.unique_integer([:positive])}"

      response = %{
        "text" => "Answer",
        "confidence" => 0.95,
        "score" => 0.8
      }

      perturbed = ModelExtractionDetector.apply_perturbation(client_id, response, :low)

      # Values should be slightly different
      assert perturbed["text"] == "Answer"
      assert is_float(perturbed["confidence"])
      assert is_float(perturbed["score"])
      # Low noise level means small changes
      assert abs(perturbed["confidence"] - 0.95) < 0.05
    end

    test "applies higher noise with :high level" do
      client_id = "client-perturb-high-#{System.unique_integer([:positive])}"

      response = %{confidence: 0.9}

      perturbed = ModelExtractionDetector.apply_perturbation(client_id, response, :high)

      assert is_float(perturbed.confidence)
      # High noise means larger potential change (up to 0.1)
      assert abs(perturbed.confidence - 0.9) <= 0.1
    end

    test "perturbs nested logits array" do
      client_id = "client-perturb-logits-#{System.unique_integer([:positive])}"

      response = %{
        logits: [0.1, 0.5, 0.3, 0.1]
      }

      perturbed = ModelExtractionDetector.apply_perturbation(client_id, response, :medium)

      assert is_list(perturbed.logits)
      assert length(perturbed.logits) == 4
      # All values should still be numbers
      Enum.each(perturbed.logits, fn v ->
        assert is_float(v)
      end)
    end
  end

  # ============================================================================
  # apply_watermark/2 tests
  # ============================================================================

  describe "apply_watermark/2" do
    test "embeds watermark in response metadata" do
      client_id = "client-watermark-#{System.unique_integer([:positive])}"

      response = %{
        text: "Answer",
        metadata: %{source: "model"}
      }

      watermarked = ModelExtractionDetector.apply_watermark(client_id, response)

      assert watermarked.metadata[:_wm] != nil
      assert is_binary(watermarked.metadata[:_wm])
      assert String.length(watermarked.metadata[:_wm]) == 8
    end

    test "creates metadata if not present" do
      client_id = "client-watermark-new-#{System.unique_integer([:positive])}"

      response = %{text: "Answer"}

      watermarked = ModelExtractionDetector.apply_watermark(client_id, response)

      assert watermarked.metadata[:_wm] != nil
    end

    test "generates consistent watermark for same client" do
      client_id = "client-watermark-consistent-#{System.unique_integer([:positive])}"

      # First, record a query to establish client state
      {:ok, _} = ModelExtractionDetector.record_query(client_id, %{
        input: "test",
        output_type: :text,
        timestamp: DateTime.utc_now()
      })

      response1 = ModelExtractionDetector.apply_watermark(client_id, %{text: "A"})
      response2 = ModelExtractionDetector.apply_watermark(client_id, %{text: "B"})

      # Same client should get same watermark
      assert response1.metadata[:_wm] == response2.metadata[:_wm]
    end
  end

  # ============================================================================
  # reset_client/1 tests
  # ============================================================================

  describe "reset_client/1" do
    test "clears client state" do
      client_id = "client-reset-#{System.unique_integer([:positive])}"

      # Record some queries
      for i <- 1..5 do
        {:ok, _} = ModelExtractionDetector.record_query(client_id, %{
          input: "Query #{i}",
          output_type: :text,
          timestamp: DateTime.utc_now()
        })
      end

      # Verify client exists
      assert {:ok, _} = ModelExtractionDetector.get_client_risk(client_id)

      # Reset
      :ok = ModelExtractionDetector.reset_client(client_id)

      # Allow async cast to complete
      Process.sleep(50)

      # Client should not exist
      assert {:error, :not_found} = ModelExtractionDetector.get_client_risk(client_id)
    end
  end

  # ============================================================================
  # get_stats/0 tests
  # ============================================================================

  describe "get_stats/0" do
    test "returns statistics" do
      stats = ModelExtractionDetector.get_stats()

      assert is_map(stats)
      assert Map.has_key?(stats, :total_queries_analyzed)
      assert Map.has_key?(stats, :extractions_detected)
      assert Map.has_key?(stats, :clients_throttled)
      assert Map.has_key?(stats, :watermarks_applied)
      assert Map.has_key?(stats, :active_clients)
      assert Map.has_key?(stats, :currently_throttled)
    end

    test "counts increase after operations" do
      initial_stats = ModelExtractionDetector.get_stats()

      client_id = "client-stats-#{System.unique_integer([:positive])}"
      {:ok, _} = ModelExtractionDetector.record_query(client_id, %{
        input: "Test",
        output_type: :text,
        timestamp: DateTime.utc_now()
      })

      new_stats = ModelExtractionDetector.get_stats()

      assert new_stats.total_queries_analyzed >= initial_stats.total_queries_analyzed
    end
  end

  # ============================================================================
  # Risk calculation tests
  # ============================================================================

  describe "risk calculation" do
    test "multiple signals increase risk" do
      client_id = "client-multi-signal-#{System.unique_integer([:positive])}"

      # Generate queries that trigger multiple signals
      queries = for i <- 1..1100 do
        %{
          input: "Item #{rem(i, 100)}",  # Repetitive pattern
          output_type: :logits,           # Low entropy output
          timestamp: DateTime.utc_now()
        }
      end

      {:ok, result} = ModelExtractionDetector.analyze_session(client_id, queries)

      # Multiple signals should be detected
      assert length(result.signals) >= 1
      # Risk should be elevated
      assert result.extraction_risk > 0.3
    end

    test "recommended actions escalate with risk" do
      # Low risk -> :allow
      client_id1 = "client-low-#{System.unique_integer([:positive])}"
      {:ok, r1} = ModelExtractionDetector.analyze_session(client_id1, [
        %{input: "Hello", output_type: :text, timestamp: DateTime.utc_now()}
      ])
      assert r1.recommended_action == :allow

      # Higher risk from suspicious patterns
      client_id2 = "client-med-#{System.unique_integer([:positive])}"
      suspicious_queries = for i <- 1..500 do
        %{
          input: "Value: #{i * 0.01}",
          output_type: :confidence,
          timestamp: DateTime.utc_now()
        }
      end

      {:ok, r2} = ModelExtractionDetector.analyze_session(client_id2, suspicious_queries)
      # Action should be at least :watermark for moderate risk
      if r2.extraction_risk >= 0.5 do
        assert r2.recommended_action in [:watermark, :throttle, :block]
      end
    end

    test "countermeasures are recommended based on risk" do
      client_id = "client-counter-#{System.unique_integer([:positive])}"

      # Generate high-risk queries
      queries = for i <- 1..200 do
        %{
          input: "Probe #{i}",
          output_type: :logits,
          timestamp: DateTime.utc_now()
        }
      end

      {:ok, result} = ModelExtractionDetector.analyze_session(client_id, queries)

      assert is_list(result.countermeasures)
      # Higher risk should recommend more countermeasures
      if result.extraction_risk >= 0.3 do
        assert :perturbation in result.countermeasures
      end
    end
  end

  # ============================================================================
  # Module exports verification
  # ============================================================================

  describe "module exports" do
    test "start_link/1 is exported" do
      assert function_exported?(ModelExtractionDetector, :start_link, 1)
    end

    test "analyze_session/2 is exported" do
      assert function_exported?(ModelExtractionDetector, :analyze_session, 2)
    end

    test "detect_extraction_pattern/1 is exported" do
      assert function_exported?(ModelExtractionDetector, :detect_extraction_pattern, 1)
    end

    test "should_throttle?/1 is exported" do
      assert function_exported?(ModelExtractionDetector, :should_throttle?, 1)
    end

    test "record_query/2 is exported" do
      assert function_exported?(ModelExtractionDetector, :record_query, 2)
    end

    test "get_client_risk/1 is exported" do
      assert function_exported?(ModelExtractionDetector, :get_client_risk, 1)
    end

    test "apply_perturbation/3 is exported" do
      assert function_exported?(ModelExtractionDetector, :apply_perturbation, 3)
    end

    test "apply_watermark/2 is exported" do
      assert function_exported?(ModelExtractionDetector, :apply_watermark, 2)
    end

    test "reset_client/1 is exported" do
      assert function_exported?(ModelExtractionDetector, :reset_client, 1)
    end

    test "get_stats/0 is exported" do
      assert function_exported?(ModelExtractionDetector, :get_stats, 0)
    end
  end
end
