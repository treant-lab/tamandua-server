defmodule TamanduaServer.Agents.ModelScanRuntimeTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Agents.ModelScanRuntime

  test "preserves degraded and failed as distinct scan outcomes" do
    summary =
      ModelScanRuntime.summarize([
        %{
          timestamp: 1_720_000_000_000,
          payload: %{
            "ai_discovery" => true,
            "runtime_lane" => "ml_service_http",
            "model_contract_id" => nil,
            "decision_mode" => "detect_only",
            "model_artifacts" => [
              %{
                "artifact_sha256" => String.duplicate("a", 64),
                "threshold" => 0.91,
                "feature_contract_id" => "static-features-v1",
                "calibration_id" => "holdout-2026-07",
                "score_orientation" => "higher_is_more_malicious",
                "model_contract_id" => "detector-contract-v1",
                "component_name" => "sample.onnx"
              }
            ],
            "ensemble_votes" => [
              %{
                "detector_id" => "engine/onnx",
                "status" => "completed",
                "decision" => "malicious",
                "score" => 0.91,
                "confidence" => 0.8
              },
              %{
                "detector_id" => "engine/unsupported",
                "status" => "unsupported",
                "decision" => "unknown",
                "score" => nil,
                "confidence" => 0
              }
            ],
            "model_observations" => [
              %{
                "detector_id" => "engine/histogram",
                "status" => "completed",
                "score" => 0.97,
                "threshold_met" => false,
                "runtime_lane" => "local_service",
                "model_contract_id" => "tamandua.byte-histogram-256.v1",
                "artifact_sha256" => String.duplicate("d", 64),
                "threshold" => 0.9,
                "feature_contract_id" => "tamandua.byte-histogram-256.v1",
                "calibration_id" => "shadow-2026-07",
                "score_orientation" => "higher_is_more_malicious",
                "decision" => "malicious",
                "safe" => false,
                "enforcement" => "block"
              }
            ],
            "model_scan_status" => %{"completed" => 2, "degraded" => 1, "failed" => 1},
            "components" => [
              %{
                "name" => "a.onnx",
                "scan_status" => "degraded",
                "scan_error" => "service_unavailable"
              },
              %{"name" => "b.pkl", "scan_status" => "failed", "scan_error" => "invalid_response"}
            ]
          }
        }
      ])

    assert summary.runtime_lane == "ml_service_http"
    assert summary.decision_mode == "detect_only"
    assert summary.scan_status == "degraded"
    assert Enum.map(summary.ensemble_votes, & &1.status) == ["completed", "unsupported"]
    assert [observation] = summary.model_observations
    assert observation.detector_id == "engine/histogram"
    assert observation.score == 0.97
    refute observation.threshold_met
    assert observation.claim_boundary == "shadow_observation_no_verdict"
    refute Map.has_key?(observation, :decision)
    refute Map.has_key?(observation, :safe)
    refute Map.has_key?(observation, :enforcement)
    assert summary.artifact_sha256 == String.duplicate("a", 64)
    assert summary.threshold == 0.91
    assert summary.feature_contract_id == "static-features-v1"
    assert summary.calibration_id == "holdout-2026-07"
    assert summary.score_orientation == "higher_is_more_malicious"
    assert [%{component_name: "sample.onnx"}] = summary.model_artifacts
    assert summary.status_counts == %{"completed" => 2, "degraded" => 1, "failed" => 1}
    assert Enum.map(summary.scan_errors, & &1.status) == ["degraded", "failed"]
  end

  test "does not claim runtime health when model scan telemetry is absent" do
    assert ModelScanRuntime.summarize([%{payload: %{"ai_discovery" => false}}]) == nil
    assert ModelScanRuntime.summarize([]) == nil
  end

  test "ignores unknown statuses instead of widening the API contract" do
    summary =
      ModelScanRuntime.summarize([
        %{
          payload: %{
            "ai_discovery" => true,
            "model_scan_status" => %{"healthy" => 99, "timeout" => 1}
          }
        }
      ])

    assert summary.scan_status == "timeout"
    assert summary.status_counts == %{"timeout" => 1}
  end

  test "rejects malformed artifact provenance and avoids choosing among multiple artifacts" do
    summary =
      ModelScanRuntime.summarize([
        %{
          payload: %{
            "ai_discovery" => true,
            "model_artifacts" => [
              %{
                "artifact_sha256" => "not-a-hash",
                "threshold" => 0.5,
                "score_orientation" => "higher_is_more_malicious"
              },
              %{
                "artifact_sha256" => String.duplicate("b", 64),
                "threshold" => 0.7,
                "score_orientation" => "higher_is_more_malicious"
              },
              %{
                "artifact_sha256" => String.duplicate("c", 64),
                "threshold" => 0.8,
                "score_orientation" => "lower_is_more_malicious"
              }
            ]
          }
        }
      ])

    assert length(summary.model_artifacts) == 2
    assert summary.artifact_sha256 == nil
    assert summary.threshold == nil
    assert summary.score_orientation == nil
  end
end
