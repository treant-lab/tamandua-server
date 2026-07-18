defmodule TamanduaServer.Policies.ModelPolicyTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Policies.ModelPolicy
  alias TamanduaServer.Registries.ModelProvenance
  alias TamanduaServer.Repo

  describe "can_load?/1" do
    test "returns {:ok, true} for models with risk_score < 0.3" do
      {:ok, provenance} =
        Repo.insert(%ModelProvenance{
          model_id: "test/clean-model",
          registry: "huggingface",
          status: "clean",
          risk_score: 0.05,
          scanned_at: DateTime.utc_now(),
          downloaded_at: DateTime.utc_now()
        })

      result = ModelPolicy.can_load?(provenance.model_id)
      assert result == {:ok, true}

      Repo.delete(provenance)
    end

    test "returns {:ok, false, reason} for models with risk_score >= 0.3" do
      {:ok, provenance} =
        Repo.insert(%ModelProvenance{
          model_id: "test/high-risk-model",
          registry: "huggingface",
          status: "suspicious",
          risk_score: 0.45,
          scanned_at: DateTime.utc_now(),
          downloaded_at: DateTime.utc_now()
        })

      result = ModelPolicy.can_load?(provenance.model_id)
      assert {:ok, false, reason} = result
      assert reason == "high_risk_score"

      Repo.delete(provenance)
    end

    test "returns {:ok, false, 'unscanned'} for models without provenance" do
      result = ModelPolicy.can_load?("nonexistent/model-xyz")

      assert result == {:ok, false, "unscanned"}
    end

    test "returns {:ok, false, 'malicious_model'} for malicious status" do
      {:ok, provenance} =
        Repo.insert(%ModelProvenance{
          model_id: "test/malicious-model",
          registry: "huggingface",
          status: "malicious",
          risk_score: 0.95,
          scanned_at: DateTime.utc_now(),
          downloaded_at: DateTime.utc_now()
        })

      result = ModelPolicy.can_load?(provenance.model_id)
      assert {:ok, false, reason} = result
      assert reason == "malicious_model"

      Repo.delete(provenance)
    end

    test "allows high-risk models when Model Guard is decision-only" do
      {:ok, provenance} =
        Repo.insert(%ModelProvenance{
          model_id: "test/decision-only-model",
          registry: "huggingface",
          status: "malicious",
          risk_score: 0.9,
          scan_result: %{
            model_guard: %{
              decision: "block",
              enforcement: "decision_only",
              action: "report_only"
            }
          },
          scanned_at: DateTime.utc_now(),
          downloaded_at: DateTime.utc_now()
        })

      assert ModelPolicy.can_load?(provenance.model_id) == {:ok, true}

      Repo.delete(provenance)
    end

    test "returns {:ok, false, 'scan_pending'} for pending status" do
      {:ok, provenance} =
        Repo.insert(%ModelProvenance{
          model_id: "test/pending-model",
          registry: "huggingface",
          status: "pending",
          downloaded_at: DateTime.utc_now()
        })

      result = ModelPolicy.can_load?(provenance.model_id)
      assert {:ok, false, reason} = result
      assert reason == "scan_pending"

      Repo.delete(provenance)
    end

    test "returns {:ok, false, 'scan_in_progress'} for scanning status" do
      {:ok, provenance} =
        Repo.insert(%ModelProvenance{
          model_id: "test/scanning-model",
          registry: "huggingface",
          status: "scanning",
          downloaded_at: DateTime.utc_now()
        })

      result = ModelPolicy.can_load?(provenance.model_id)
      assert {:ok, false, reason} = result
      assert reason == "scan_in_progress"

      Repo.delete(provenance)
    end
  end

  describe "model_guard_summary/1" do
    test "normalizes enforced evidence" do
      summary =
        ModelPolicy.model_guard_summary(%{
          status: "malicious",
          risk_score: 0.9,
          scan_result: %{
            model_guard: %{
              decision: "block",
              enforcement: "enforced",
              action: "block_load",
              evidence: %{findings_count: 2}
            }
          }
        })

      assert summary.status == "enforced"
      assert summary.decision == "block"
      assert summary.action == "block_load"
      assert summary.evidence.findings_count == 2
    end

    test "normalizes failed and unsupported evidence" do
      failed =
        ModelPolicy.model_guard_summary(%{
          status: "error",
          scan_result: %{model_guard: %{status: "failed", enforcement: "failed"}}
        })

      unsupported = ModelPolicy.model_guard_summary(nil)

      assert failed.status == "failed"
      assert failed.enforcement == "failed"
      assert unsupported.status == "unsupported"
      assert unsupported.action == "none"
    end

    test "exposes package scanner, external scores, consensus, and degraded state" do
      summary =
        ModelPolicy.model_guard_summary(%{
          status: "error",
          scan_result: %{
            model_guard: %{
              status: "degraded",
              decision: "unknown",
              enforcement: "degraded",
              evidence: %{
                package_scanner: "collected",
                package_findings_count: 1,
                package_findings: [
                  %{source: "package_scanner", file: "setup.py", type: "network_intent"}
                ],
                external_model_scores_count: 1,
                external_model_scores: %{
                  ember2024: %{score: 0.8, verdict: "malicious", mode: "shadow"}
                },
                model_consensus_state: "divergent",
                model_consensus: %{state: "divergent"},
                enforcement_note: "No enforcement was attempted."
              }
            }
          }
        })

      assert summary.status == "degraded"
      assert summary.enforcement == "degraded"
      assert summary.package_scanner == "collected"
      assert summary.package_findings_count == 1
      assert summary.external_model_scores_count == 1
      assert summary.model_consensus_state == "divergent"
      assert summary.enforcement_note == "No enforcement was attempted."
    end
  end

  describe "is_trusted?/1" do
    test "returns true for status == 'clean' with low risk" do
      {:ok, provenance} =
        Repo.insert(%ModelProvenance{
          model_id: "test/trusted-model",
          registry: "huggingface",
          status: "clean",
          risk_score: 0.02,
          scanned_at: DateTime.utc_now(),
          downloaded_at: DateTime.utc_now()
        })

      assert ModelPolicy.is_trusted?(provenance.model_id) == true

      Repo.delete(provenance)
    end

    test "returns false for status in ['suspicious', 'malicious']" do
      {:ok, p1} =
        Repo.insert(%ModelProvenance{
          model_id: "test/suspicious-model",
          registry: "huggingface",
          status: "suspicious",
          risk_score: 0.25,
          scanned_at: DateTime.utc_now(),
          downloaded_at: DateTime.utc_now()
        })

      {:ok, p2} =
        Repo.insert(%ModelProvenance{
          model_id: "test/malicious-model-2",
          registry: "huggingface",
          status: "malicious",
          risk_score: 0.9,
          scanned_at: DateTime.utc_now(),
          downloaded_at: DateTime.utc_now()
        })

      assert ModelPolicy.is_trusted?(p1.model_id) == false
      assert ModelPolicy.is_trusted?(p2.model_id) == false

      Repo.delete(p1)
      Repo.delete(p2)
    end

    test "returns false for models without provenance" do
      assert ModelPolicy.is_trusted?("nonexistent/model") == false
    end
  end

  describe "list_blocked/0" do
    setup do
      {:ok, p1} =
        Repo.insert(%ModelProvenance{
          model_id: "test/blocked-1",
          registry: "huggingface",
          status: "malicious",
          risk_score: 0.85,
          scanned_at: DateTime.utc_now(),
          downloaded_at: DateTime.utc_now()
        })

      {:ok, p2} =
        Repo.insert(%ModelProvenance{
          model_id: "test/blocked-2",
          registry: "mlflow",
          status: "suspicious",
          risk_score: 0.45,
          scanned_at: DateTime.utc_now(),
          downloaded_at: DateTime.utc_now()
        })

      {:ok, p3} =
        Repo.insert(%ModelProvenance{
          model_id: "test/clean-allowed",
          registry: "ollama",
          status: "clean",
          risk_score: 0.05,
          scanned_at: DateTime.utc_now(),
          downloaded_at: DateTime.utc_now()
        })

      on_exit(fn ->
        Repo.delete(p1)
        Repo.delete(p2)
        Repo.delete(p3)
      end)

      :ok
    end

    test "returns all models with risk_score >= 0.3 or malicious status" do
      blocked = ModelPolicy.list_blocked()

      assert is_list(blocked)
      assert length(blocked) >= 2

      model_ids = Enum.map(blocked, & &1.model_id)
      assert "test/blocked-1" in model_ids
      assert "test/blocked-2" in model_ids
      refute "test/clean-allowed" in model_ids
    end

    test "returns models ordered by risk_score descending" do
      blocked = ModelPolicy.list_blocked()

      if length(blocked) >= 2 do
        scores = Enum.map(blocked, & &1.risk_score)
        assert scores == Enum.sort(scores, :desc)
      end
    end

    test "excludes decision-only high-risk models from effective blocks" do
      {:ok, provenance} =
        Repo.insert(%ModelProvenance{
          model_id: "test/decision-only-listed-model",
          registry: "huggingface",
          status: "malicious",
          risk_score: 0.9,
          scan_result: %{
            model_guard: %{
              decision: "block",
              enforcement: "decision_only",
              action: "report_only"
            }
          },
          scanned_at: DateTime.utc_now(),
          downloaded_at: DateTime.utc_now()
        })

      blocked = ModelPolicy.list_blocked()
      model_ids = Enum.map(blocked, & &1.model_id)

      refute provenance.model_id in model_ids

      Repo.delete(provenance)
    end
  end

  describe "handle_scan_complete/2" do
    test "does not auto-quarantine decision-only block decisions" do
      result =
        ModelPolicy.handle_scan_complete("test/decision-only-scan", %{
          status: "malicious",
          risk_score: 0.95,
          model_guard: %{
            decision: "block",
            enforcement: "decision_only",
            action: "report_only"
          }
        })

      assert result == :ok
      refute ModelPolicy.explicitly_blocked?("test/decision-only-scan")
    end
  end

  describe "block_model/2" do
    test "creates a block entry with reason" do
      model_id = "test/manually-blocked-model"
      reason = "security_review"

      result = ModelPolicy.block_model(model_id, reason)
      assert result == :ok

      assert ModelPolicy.explicitly_blocked?(model_id) == true

      # Clean up
      ModelPolicy.unblock_model(model_id)
    end
  end

  describe "unblock_model/1" do
    test "removes block entry" do
      model_id = "test/unblock-test-model"

      ModelPolicy.block_model(model_id, "test_block")
      assert ModelPolicy.explicitly_blocked?(model_id) == true

      result = ModelPolicy.unblock_model(model_id)
      assert result == :ok

      assert ModelPolicy.explicitly_blocked?(model_id) == false
    end
  end

  describe "allow_list/0" do
    test "returns explicitly trusted model patterns" do
      patterns = ModelPolicy.allow_list()

      assert is_list(patterns)
    end
  end

  describe "integration with explicit blocks" do
    test "explicitly blocked models return false from can_load?" do
      {:ok, provenance} =
        Repo.insert(%ModelProvenance{
          model_id: "test/explicit-block-test",
          registry: "huggingface",
          status: "clean",
          risk_score: 0.01,
          scanned_at: DateTime.utc_now(),
          downloaded_at: DateTime.utc_now()
        })

      # Model is clean but explicitly blocked
      ModelPolicy.block_model(provenance.model_id, "manual_review")

      result = ModelPolicy.can_load?(provenance.model_id)
      assert {:ok, false, "explicitly_blocked"} = result

      # Clean up
      ModelPolicy.unblock_model(provenance.model_id)
      Repo.delete(provenance)
    end
  end
end
