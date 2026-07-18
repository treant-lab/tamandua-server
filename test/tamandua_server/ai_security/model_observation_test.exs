defmodule TamanduaServer.AISecurity.ModelObservationTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.AISecurity.ModelObservation

  test "projects a bounded score-only observation without decision authority" do
    [observation] =
      ModelObservation.project_many([
        %{
          "detector_id" => "generic-static-detector",
          "status" => "observed",
          "score" => 0.73,
          "threshold_met" => true,
          "runtime_lane" => "endpoint_shadow",
          "model_contract_id" => "vendor.feature-contract.v1",
          "artifact_sha256" => String.duplicate("A", 64),
          "threshold" => 0.7,
          "feature_contract_id" => "vendor.features.v1",
          "calibration_id" => "calibration-2026-07",
          "score_orientation" => "higher_is_more_suspicious",
          "decision" => "malicious",
          "safe" => false,
          "enforcement" => "block"
        }
      ])

    assert observation.detector_id == "generic-static-detector"
    assert observation.threshold_met
    assert observation.artifact_sha256 == String.duplicate("a", 64)
    assert observation.claim_boundary == "shadow_observation_no_verdict"
    refute Map.has_key?(observation, :decision)
    refute Map.has_key?(observation, :safe)
    refute Map.has_key?(observation, :enforcement)
  end

  test "rejects malformed observations and caps the collection" do
    valid = %{
      detector_id: "detector",
      status: "observed",
      score: 0.1,
      threshold_met: false,
      runtime_lane: "shadow",
      model_contract_id: "contract"
    }

    observations = ModelObservation.project_many([%{"score" => 1}] ++ List.duplicate(valid, 40))
    assert length(observations) == 31
  end

  test "preserves an explicit false threshold crossing when mixed key shapes disagree" do
    [observation] =
      ModelObservation.project_many([
        %{
          "detector_id" => "detector",
          "status" => "completed",
          "score" => 0.1,
          "threshold_met" => false,
          :threshold_met => true,
          "runtime_lane" => "local_service",
          "model_contract_id" => "contract"
        }
      ])

    refute observation.threshold_met
  end
end
