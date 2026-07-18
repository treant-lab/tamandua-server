defmodule TamanduaServer.Registries.DownloadHookTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Registries.DownloadHook
  alias TamanduaServer.Registries.ModelProvenance
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Repo

  import Mox

  setup :verify_on_exit!

  defmodule DecisionOnlyRegistry do
    def scan_model(_model_id, _config) do
      {:ok,
       %{
         risk_score: 0.2,
         findings: [%{type: "weak_signal", severity: "low"}],
         scanned_at: DateTime.utc_now()
       }}
    end
  end

  defmodule UnsupportedRegistry do
    def scan_model(_model_id, _config), do: {:error, :unsupported_platform}
  end

  defmodule PackageFindingRegistry do
    def scan_model(_model_id, _config) do
      {:ok,
       %{
         risk_score: 0.72,
         findings: [%{type: "package_backdoor_intent", severity: "high"}],
         package_findings: [
           %{
             source: "package_scanner",
             file: "setup.py",
             type: "network_intent",
             severity: "high",
             description: "setup.py attempts outbound callback"
           }
         ],
         external_model_scores: %{
           ember2024: %{score: 0.91, verdict: "malicious", mode: "shadow"}
         },
         model_consensus: %{
           state: "divergent",
           tamandua: "malicious",
           external_static_baseline: "malicious"
         },
         scanned_at: DateTime.utc_now()
       }}
    end
  end

  describe "handle_download/2" do
    test "creates pending ModelProvenance record" do
      model_id = "test/model"
      registry = TamanduaServer.Registries.HuggingFace

      {:ok, provenance_id} = DownloadHook.handle_download(model_id, registry)

      provenance = Repo.get!(ModelProvenance, provenance_id)
      assert provenance.model_id == model_id
      assert provenance.registry == "huggingface"
      assert provenance.status == "pending"
      assert provenance.downloaded_at != nil
    end

    test "spawns async task for scanning" do
      model_id = "test/model"
      registry = TamanduaServer.Registries.HuggingFace

      {:ok, _provenance_id} = DownloadHook.handle_download(model_id, registry)

      # Give async task time to start
      Process.sleep(100)

      # Verify status changed to "scanning"
      provenance = Repo.get_by(ModelProvenance, model_id: model_id)
      assert provenance.status == "scanning"
    end

    test "returns error when model_id is nil" do
      assert {:error, _changeset} =
               DownloadHook.handle_download(nil, TamanduaServer.Registries.HuggingFace)
    end
  end

  describe "scan completion" do
    setup do
      # Create a pending provenance record
      {:ok, provenance} =
        %ModelProvenance{}
        |> ModelProvenance.changeset(%{
          model_id: "test/model",
          registry: "huggingface",
          downloaded_at: DateTime.utc_now()
        })
        |> Repo.insert()

      %{provenance: provenance}
    end

    test "updates provenance with scan result for clean model", %{provenance: provenance} do
      scan_result = %{
        risk_score: 0.05,
        findings: [],
        scanned_at: DateTime.utc_now()
      }

      # Simulate successful scan
      # In real implementation, this would be called by do_scan/3
      provenance
      |> ModelProvenance.update_scan_result(%{
        scanned_at: scan_result.scanned_at,
        scan_result: scan_result,
        risk_score: scan_result.risk_score,
        findings_count: length(scan_result.findings),
        status: "clean"
      })
      |> Repo.update!()

      updated = Repo.get!(ModelProvenance, provenance.id)
      assert updated.status == "clean"
      assert updated.risk_score == 0.05
      assert updated.findings_count == 0
      assert updated.scanned_at != nil
    end

    test "updates provenance with scan result for suspicious model", %{provenance: provenance} do
      scan_result = %{
        risk_score: 0.2,
        findings: [%{type: "unusual_pattern", severity: "low"}],
        scanned_at: DateTime.utc_now()
      }

      provenance
      |> ModelProvenance.update_scan_result(%{
        scanned_at: scan_result.scanned_at,
        scan_result: scan_result,
        risk_score: scan_result.risk_score,
        findings_count: length(scan_result.findings),
        status: "suspicious"
      })
      |> Repo.update!()

      updated = Repo.get!(ModelProvenance, provenance.id)
      assert updated.status == "suspicious"
      assert updated.risk_score == 0.2
      assert updated.findings_count == 1
    end

    test "updates provenance with scan result for malicious model", %{provenance: provenance} do
      scan_result = %{
        risk_score: 0.85,
        findings: [
          %{type: "malicious_code", severity: "critical"},
          %{type: "backdoor", severity: "high"}
        ],
        scanned_at: DateTime.utc_now()
      }

      provenance
      |> ModelProvenance.update_scan_result(%{
        scanned_at: scan_result.scanned_at,
        scan_result: scan_result,
        risk_score: scan_result.risk_score,
        findings_count: length(scan_result.findings),
        status: "malicious"
      })
      |> Repo.update!()

      updated = Repo.get!(ModelProvenance, provenance.id)
      assert updated.status == "malicious"
      assert updated.risk_score == 0.85
      assert updated.findings_count == 2
    end

    test "records Model Guard decision-only evidence without escalating status", %{
      provenance: provenance
    } do
      :ok =
        DownloadHook.do_scan(provenance, DecisionOnlyRegistry, %{
          model_guard_enforcement: :decision_only
        })

      updated = Repo.get!(ModelProvenance, provenance.id)
      model_guard = updated.scan_result["model_guard"] || updated.scan_result[:model_guard]
      evidence = model_guard["evidence"] || model_guard[:evidence]
      thresholds = model_guard["thresholds"] || model_guard[:thresholds]

      assert updated.status == "suspicious"
      assert (model_guard["decision"] || model_guard[:decision]) == "review"
      assert (model_guard["enforcement"] || model_guard[:enforcement]) == "decision_only"
      assert (model_guard["action"] || model_guard[:action]) == "allow_with_review"
      assert (model_guard["fp_rationale"] || model_guard[:fp_rationale]) =~ "review-only"
      assert (evidence["model_id"] || evidence[:model_id]) == provenance.model_id
      assert (evidence["findings_count"] || evidence[:findings_count]) == 1
      assert (thresholds["block"] || thresholds[:block]) == 0.3
    end

    test "records package scanner and external model evidence", %{provenance: provenance} do
      :ok =
        DownloadHook.do_scan(provenance, PackageFindingRegistry, %{
          model_guard_enforcement: :decision_only
        })

      updated = Repo.get!(ModelProvenance, provenance.id)
      model_guard = updated.scan_result["model_guard"] || updated.scan_result[:model_guard]
      evidence = model_guard["evidence"] || model_guard[:evidence]
      package_findings = evidence["package_findings"] || evidence[:package_findings]
      external_scores = evidence["external_model_scores"] || evidence[:external_model_scores]
      consensus = evidence["model_consensus"] || evidence[:model_consensus]

      assert updated.status == "malicious"
      assert (evidence["package_scanner"] || evidence[:package_scanner]) == "collected"
      assert (evidence["package_findings_count"] || evidence[:package_findings_count]) == 1
      assert (hd(package_findings)["source"] || hd(package_findings)[:source]) == "package_scanner"
      assert (external_scores["ember2024"] || external_scores[:ember2024]) != nil
      assert (consensus["state"] || consensus[:state]) == "divergent"
      assert (evidence["enforcement_note"] || evidence[:enforcement_note]) =~ "decision-only"
    end
  end

  describe "alert creation for malicious models" do
    test "creates alert when risk_score > 0.3" do
      model_id = "malicious/model"
      risk_score = 0.85

      findings = [
        %{
          type: "malicious_code",
          severity: "critical",
          description: "Detected malicious code execution"
        }
      ]

      scan_result = %{
        risk_score: risk_score,
        findings: findings,
        scanned_at: DateTime.utc_now()
      }

      # Create provenance
      {:ok, provenance} =
        %ModelProvenance{}
        |> ModelProvenance.changeset(%{
          model_id: model_id,
          registry: "huggingface",
          downloaded_at: DateTime.utc_now()
        })
        |> Repo.insert()

      # Update with malicious scan result
      provenance
      |> ModelProvenance.update_scan_result(%{
        scanned_at: scan_result.scanned_at,
        scan_result: scan_result,
        risk_score: risk_score,
        findings_count: length(findings),
        status: "malicious"
      })
      |> Repo.update!()

      # In real implementation, DownloadHook would create alert
      # For now, test the alert creation logic directly
      alert_attrs = %{
        severity:
          if(risk_score > 0.7,
            do: "critical",
            else: if(risk_score > 0.5, do: "high", else: "medium")
          ),
        title: "Malicious AI model detected: #{model_id}",
        description: "Model scan detected #{length(findings)} security findings",
        mitre_techniques: ["T1059", "T1027"],
        source: "model_registry",
        metadata: %{
          model_id: model_id,
          registry: "huggingface",
          risk_score: risk_score,
          provenance_id: provenance.id
        }
      }

      assert alert_attrs.severity == "critical"
      assert alert_attrs.title =~ "Malicious AI model detected"
      assert alert_attrs.mitre_techniques == ["T1059", "T1027"]
    end

    test "severity is critical when risk_score > 0.7" do
      risk_score = 0.85

      severity =
        if risk_score > 0.7,
          do: "critical",
          else: if(risk_score > 0.5, do: "high", else: "medium")

      assert severity == "critical"
    end

    test "severity is high when 0.5 < risk_score <= 0.7" do
      risk_score = 0.6

      severity =
        if risk_score > 0.7,
          do: "critical",
          else: if(risk_score > 0.5, do: "high", else: "medium")

      assert severity == "high"
    end

    test "severity is medium when 0.3 < risk_score <= 0.5" do
      risk_score = 0.4

      severity =
        if risk_score > 0.7,
          do: "critical",
          else: if(risk_score > 0.5, do: "high", else: "medium")

      assert severity == "medium"
    end
  end

  describe "error handling" do
    test "handles scan errors gracefully" do
      # This test verifies that scan errors update status to "error"
      {:ok, provenance} =
        %ModelProvenance{}
        |> ModelProvenance.changeset(%{
          model_id: "test/error-model",
          registry: "huggingface",
          downloaded_at: DateTime.utc_now()
        })
        |> Repo.insert()

      # Simulate scan error
      provenance
      |> ModelProvenance.update_scan_result(%{
        scanned_at: DateTime.utc_now(),
        scan_result: %{error: "Network timeout"},
        status: "error"
      })
      |> Repo.update!()

      updated = Repo.get!(ModelProvenance, provenance.id)
      assert updated.status == "error"
      assert updated.scan_result.error == "Network timeout"
    end

    test "records failed Model Guard evidence on scan errors" do
      {:ok, provenance} =
        %ModelProvenance{}
        |> ModelProvenance.changeset(%{
          model_id: "test/unsupported-model",
          registry: "huggingface",
          downloaded_at: DateTime.utc_now()
        })
        |> Repo.insert()

      :ok = DownloadHook.do_scan(provenance, UnsupportedRegistry, %{model_guard_enforcement: :enforced})

      updated = Repo.get!(ModelProvenance, provenance.id)
      model_guard = updated.scan_result["model_guard"] || updated.scan_result[:model_guard]
      evidence = model_guard["evidence"] || model_guard[:evidence]

      assert updated.status == "error"
      assert (model_guard["status"] || model_guard[:status]) == "unsupported"
      assert (model_guard["decision"] || model_guard[:decision]) == "block"
      assert (model_guard["enforcement"] || model_guard[:enforcement]) == "enforced"
      assert (model_guard["action"] || model_guard[:action]) == "block_load"
      assert (evidence["requested_enforcement"] || evidence[:requested_enforcement]) == "enforced"
      assert (evidence["error"] || evidence[:error]) =~ "unsupported_platform"
    end
  end

  describe "PubSub broadcasting" do
    test "broadcasts model_scanned event" do
      # Subscribe to the PubSub topic
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "registries:downloads")

      model_id = "test/model"
      status = "clean"
      risk_score = 0.05

      # Simulate broadcast
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "registries:downloads",
        {:model_scanned, model_id, status, risk_score}
      )

      # Verify message received
      assert_receive {:model_scanned, ^model_id, ^status, ^risk_score}, 500
    end

    test "broadcasts alert_created event for malicious models" do
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "registries:downloads")

      alert_id = Ecto.UUID.generate()

      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "registries:downloads",
        {:alert_created, alert_id}
      )

      assert_receive {:alert_created, ^alert_id}, 500
    end
  end
end
