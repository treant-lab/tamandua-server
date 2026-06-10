defmodule TamanduaServer.Telemetry.CorrelationReadinessFeedbackTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.CorrelationFeedbackFixtures
  alias TamanduaServer.Telemetry.CorrelationEvidence
  alias TamanduaServer.Telemetry.EventContract

  test "feedback fixtures match conservative correlation decisions" do
    for feedback <- CorrelationFeedbackFixtures.feedback_cases() do
      result =
        feedback.dataset
        |> CorrelationFeedbackFixtures.dataset()
        |> CorrelationEvidence.correlate_events()

      assert result.correlations != [] == feedback.expected_link?,
             "#{feedback.dataset} feedback=#{feedback.verdict} reason=#{feedback.reason}"
    end
  end

  test "false-positive feedback cases do not create incidents or campaigns" do
    false_positive_events =
      CorrelationFeedbackFixtures.feedback_cases()
      |> Enum.filter(&(&1.verdict == :false_positive))
      |> Enum.flat_map(&CorrelationFeedbackFixtures.dataset(&1.dataset))

    result = CorrelationEvidence.correlate_events(false_positive_events)

    assert result.correlations == []
    assert result.incident_candidates == []
    assert result.campaign_candidates == []
  end

  test "true-positive feedback cases retain concrete supporting entities" do
    true_positive_events =
      CorrelationFeedbackFixtures.feedback_cases()
      |> Enum.filter(&(&1.verdict == :true_positive))
      |> Enum.flat_map(&CorrelationFeedbackFixtures.dataset(&1.dataset))

    result = CorrelationEvidence.correlate_events(true_positive_events)

    supporting_entities =
      result.correlations |> Enum.flat_map(& &1.sharedEntities) |> MapSet.new()

    assert "file_hash" in supporting_entities
    assert "domain" in supporting_entities
    assert "process_tree" in supporting_entities
  end

  test "readiness fixtures expose correlation_ready and missing-field contract" do
    for readiness <- CorrelationFeedbackFixtures.readiness_cases() do
      summary = EventContract.summarize(readiness.event)

      assert summary["correlation_ready"] == readiness.expected_ready?,
             "#{readiness.name} expected_ready=#{readiness.expected_ready?}"

      for missing <- readiness.missing do
        assert missing in summary["quality"].missing,
               "#{readiness.name} should report missing #{missing}"
      end
    end
  end

  test "readiness metadata is present in telemetry quality without creating correlation" do
    [%{event: incomplete_network}, %{event: dns_without_process}] =
      CorrelationFeedbackFixtures.readiness_cases()
      |> Enum.filter(&(&1.expected_ready? == false))
      |> Enum.take(2)

    network_quality = CorrelationEvidence.telemetry_quality(incomplete_network)
    dns_quality = CorrelationEvidence.telemetry_quality(dns_without_process)

    assert network_quality.level in ["poor", "partial"]
    assert dns_quality.level in ["poor", "partial"]

    assert CorrelationEvidence.correlate_events([incomplete_network, dns_without_process]).correlations ==
             []
  end
end
