defmodule TamanduaServer.Detection.OutputValidatorTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.Detection.OutputValidator
  alias TamanduaServer.Detection.TokenAnomalyDetector
  alias TamanduaServer.Detection.InferenceTracker

  @moduletag :output_validation

  setup do
    # Start required GenServers
    start_supervised!(TokenAnomalyDetector)
    start_supervised!(OutputValidator)

    # Generate unique agent ID
    agent_id = "test-agent-#{System.unique_integer([:positive])}"
    {:ok, agent_id: agent_id}
  end

  describe "validate/2 with raw text" do
    test "returns low risk for benign text", %{agent_id: agent_id} do
      {:ok, result} =
        OutputValidator.validate("Hello, how are you today?", agent_id: agent_id)

      assert result.overall_risk == :low
      assert result.pii.has_pii == false
      assert result.harmful.is_harmful == false
      assert result.violations == []
    end

    test "returns high risk when PII detected", %{agent_id: agent_id} do
      {:ok, result} =
        OutputValidator.validate(
          "Contact me at john.doe@example.com",
          agent_id: agent_id
        )

      assert result.overall_risk == :high
      assert result.pii.has_pii == true
      assert :email in result.pii.pii_types
      assert Enum.any?(result.violations, &String.contains?(&1, "pii_detected"))
    end

    test "returns critical risk for violence content", %{agent_id: agent_id} do
      {:ok, result} =
        OutputValidator.validate(
          "I will kill you",
          agent_id: agent_id
        )

      assert result.overall_risk == :critical
      assert result.harmful.is_harmful == true
      assert result.harmful.category == :violence
      assert Enum.any?(result.violations, &String.contains?(&1, "harmful_content:violence"))
    end

    test "returns critical risk for self-harm content", %{agent_id: agent_id} do
      {:ok, result} =
        OutputValidator.validate(
          "how to kill myself",
          agent_id: agent_id
        )

      assert result.overall_risk == :critical
      assert result.harmful.is_harmful == true
      assert result.harmful.category == :self_harm
    end

    test "returns high risk for hate speech", %{agent_id: agent_id} do
      {:ok, result} =
        OutputValidator.validate(
          "ethnic cleansing is necessary",
          agent_id: agent_id
        )

      assert result.overall_risk == :high
      assert result.harmful.is_harmful == true
      assert result.harmful.category == :hate_speech
    end
  end

  describe "validate/2 with session" do
    test "extracts text from session response", %{agent_id: agent_id} do
      session = %InferenceTracker.Session{
        session_id: "sess-123",
        agent_id: agent_id,
        request: %{},
        response: %{response_preview: "Hello, this is a safe response."},
        status: :complete,
        created_at: DateTime.utc_now(),
        updated_at: DateTime.utc_now(),
        metrics: %{token_count: %{input_tokens: 10, output_tokens: 20, total_tokens: 30}}
      }

      {:ok, result} = OutputValidator.validate(session)

      assert result.overall_risk == :low
      assert result.pii.has_pii == false
    end

    test "handles nil response gracefully", %{agent_id: agent_id} do
      session = %InferenceTracker.Session{
        session_id: "sess-456",
        agent_id: agent_id,
        request: %{},
        response: nil,
        status: :pending,
        created_at: DateTime.utc_now(),
        updated_at: DateTime.utc_now(),
        metrics: nil
      }

      {:ok, result} = OutputValidator.validate(session)

      assert result.overall_risk == :low
    end
  end

  describe "validate/2 with options" do
    test "skips PII detection when skip_pii is true", %{agent_id: agent_id} do
      {:ok, result} =
        OutputValidator.validate(
          "Contact me at john@example.com",
          agent_id: agent_id,
          skip_pii: true
        )

      # Should still not be harmful
      assert result.pii.has_pii == false
      assert result.pii.pii_types == []
    end

    test "skips harmful content when skip_harmful is true", %{agent_id: agent_id} do
      {:ok, result} =
        OutputValidator.validate(
          "I will kill you",
          agent_id: agent_id,
          skip_harmful: true
        )

      # Should not detect harmful
      assert result.harmful.is_harmful == false
    end

    test "skips token anomaly when skip_token_anomaly is true", %{agent_id: agent_id} do
      {:ok, result} =
        OutputValidator.validate(
          "Test content",
          agent_id: agent_id,
          token_count: %{input_tokens: 10000, output_tokens: 50000, total_tokens: 60000},
          skip_token_anomaly: true
        )

      assert result.token_anomaly.is_anomaly == false
    end
  end

  describe "validate/2 with token anomaly" do
    test "detects token spike after baseline established", %{agent_id: agent_id} do
      # Build baseline
      for _ <- 1..25 do
        {:ok, _} =
          TokenAnomalyDetector.detect(agent_id, %{
            input_tokens: 100,
            output_tokens: 500,
            total_tokens: 600
          })
      end

      # Validate with spike
      {:ok, result} =
        OutputValidator.validate(
          "Normal content",
          agent_id: agent_id,
          token_count: %{input_tokens: 1000, output_tokens: 5000, total_tokens: 6000}
        )

      assert result.token_anomaly.is_anomaly == true
      assert result.token_anomaly.anomaly_type == :spike
    end
  end

  describe "risk calculation" do
    test "multiple violations are accumulated", %{agent_id: agent_id} do
      {:ok, result} =
        OutputValidator.validate(
          "Contact john@example.com. ethnic cleansing is needed.",
          agent_id: agent_id
        )

      # Should have both PII and harmful content violations
      assert length(result.violations) >= 2
    end
  end

  describe "validate_async/2" do
    test "returns a task", %{agent_id: agent_id} do
      task = OutputValidator.validate_async("Test content", agent_id: agent_id)
      assert is_struct(task, Task)

      {:ok, result} = Task.await(task, 5000)
      assert result.overall_risk == :low
    end
  end

  describe "latency tracking" do
    test "reports latency in result", %{agent_id: agent_id} do
      {:ok, result} =
        OutputValidator.validate("Test content", agent_id: agent_id)

      assert result.latency_ms >= 0
    end
  end

  describe "violation descriptions" do
    test "includes PII types in violation", %{agent_id: agent_id} do
      {:ok, result} =
        OutputValidator.validate(
          "SSN: 123-45-6789 Email: john@example.com",
          agent_id: agent_id
        )

      pii_violations = Enum.filter(result.violations, &String.contains?(&1, "pii_detected"))
      assert length(pii_violations) == 1
      violation = hd(pii_violations)
      assert String.contains?(violation, "ssn") or String.contains?(violation, "email")
    end

    test "includes harmful category in violation", %{agent_id: agent_id} do
      {:ok, result} =
        OutputValidator.validate(
          "I will kill you",
          agent_id: agent_id
        )

      harmful_violations =
        Enum.filter(result.violations, &String.contains?(&1, "harmful_content"))

      assert length(harmful_violations) >= 1
      violation = hd(harmful_violations)
      assert String.contains?(violation, "violence")
    end
  end

  describe "edge cases" do
    test "handles empty string", %{agent_id: agent_id} do
      {:ok, result} = OutputValidator.validate("", agent_id: agent_id)
      assert result.overall_risk == :low
    end

    test "handles unicode text", %{agent_id: agent_id} do
      {:ok, result} =
        OutputValidator.validate(
          "Bonjour, comment allez-vous?",
          agent_id: agent_id
        )

      assert result.overall_risk == :low
    end

    test "handles long text", %{agent_id: agent_id} do
      long_text = String.duplicate("Safe content. ", 1000)
      {:ok, result} = OutputValidator.validate(long_text, agent_id: agent_id)
      assert result.overall_risk == :low
    end
  end
end
