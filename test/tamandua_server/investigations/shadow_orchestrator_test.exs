defmodule TamanduaServer.Investigations.ShadowOrchestratorTest do
  use TamanduaServer.DataCase, async: false
  use Oban.Testing, repo: TamanduaServer.Repo

  import Ecto.Query

  alias TamanduaServer.Accounts.{Permission, Role, RolePermission, UserRole}
  alias TamanduaServer.Authorization.RBAC

  alias TamanduaServer.Investigations.{
    DetectorObservationConsensusV1,
    DetectorProducerRegistry,
    InvestigationRun,
    ShadowOrchestrator
  }

  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant
  alias TamanduaServer.Workers.ShadowInvestigationWorker

  setup do
    previous_config =
      Application.get_env(:tamandua_server, ShadowOrchestrator, [])

    on_exit(fn ->
      Application.put_env(:tamandua_server, ShadowOrchestrator, previous_config)
    end)

    organization = insert(:organization)
    other_organization = insert(:organization)
    agent = insert(:agent, organization: organization)

    alert =
      insert(:alert,
        organization: organization,
        agent: agent,
        title: "Suspicious process tree",
        severity: "high",
        threat_score: 0.82
      )

    registry_admin = insert(:user, organization: organization, role: "analyst")
    grant_permission!(registry_admin, organization, :system_settings)

    {:ok, producer_attestation} =
      DetectorProducerRegistry.attest(
        organization.id,
        registry_admin.id,
        producer_attestation_attrs()
      )

    %{
      organization: organization,
      other_organization: other_organization,
      alert: alert,
      producer_attestation: producer_attestation,
      registry_admin: registry_admin
    }
  end

  test "enqueue is tenant-scoped, durable and idempotent", %{organization: org, alert: alert} do
    assert {:ok, first} = ShadowOrchestrator.enqueue(org.id, alert.id)
    assert first.organization_id == org.id
    assert first.alert_id == alert.id
    assert first.mode == "shadow"
    assert first.status == "queued"
    assert first.summary == %{"enforcement" => "disabled"}

    assert_enqueued(
      worker: ShadowInvestigationWorker,
      args: %{"organization_id" => org.id, "run_id" => first.id}
    )

    assert {:ok, second} = ShadowOrchestrator.enqueue(org.id, alert.id)
    assert second.id == first.id

    assert 1 ==
             Repo.aggregate(
               from(job in Oban.Job,
                 where:
                   job.args ==
                     ^%{"organization_id" => org.id, "run_id" => first.id}
               ),
               :count
             )

    assert {:ok, [listed]} = ShadowOrchestrator.list_runs_for_alert(org.id, alert.id)
    assert listed.id == first.id

    serialized = ShadowOrchestrator.serialize_run(listed)
    assert serialized.mode == "shadow"
    assert serialized.policy_version == "shadow-v2"
    assert serialized.admission_disposition == "enqueued"
    assert serialized.admission_reason == "explicit_request"
    assert serialized.enforcement == "disabled"
    refute Map.has_key?(serialized, :organization_id)
    refute Map.has_key?(serialized, :idempotency_key)

    count =
      MultiTenant.with_organization(org.id, fn ->
        Repo.aggregate(
          from(run in InvestigationRun, where: run.organization_id == ^org.id),
          :count
        )
      end)

    assert count == 1
  end

  test "rejects an alert from another organization without persisting a run", %{
    other_organization: other_org,
    alert: alert
  } do
    assert {:error, :alert_not_found_in_organization} =
             ShadowOrchestrator.enqueue(other_org.id, alert.id)

    assert [] ==
             MultiTenant.with_organization(other_org.id, fn ->
               Repo.all(
                 from(run in InvestigationRun,
                   where: run.organization_id == ^other_org.id
                 )
               )
             end)
  end

  test "worker records one evidence snapshot and never emits an enforcement decision", %{
    organization: org,
    alert: alert
  } do
    assert {:ok, run} = ShadowOrchestrator.enqueue(org.id, alert.id)

    assert :ok =
             perform_job(ShadowInvestigationWorker, %{
               "organization_id" => org.id,
               "run_id" => run.id
             })

    observed = ShadowOrchestrator.get_run(org.id, run.id)
    assert observed.status == "observed"
    assert observed.started_at
    assert observed.completed_at

    assert observed.summary == %{
             "decision" => "not_evaluated",
             "enforcement" => "disabled",
             "mode" => "shadow",
             "observation_state" => "observed",
             "evidence_count" => 2,
             "degraded_sources" => [],
             "confidence" => 0.82
           }

    evidence_items = ShadowOrchestrator.list_evidence(org.id, run.id)
    assert length(evidence_items) == 2
    assert Enum.any?(evidence_items, &(&1.kind == "agent_posture"))

    evidence = Enum.find(evidence_items, &(&1.kind == "alert_normalized"))
    assert evidence.source_ref == alert.id
    assert evidence.payload["alert_id"] == alert.id
    assert evidence.payload["severity"] == "high"

    serialized_evidence = ShadowOrchestrator.serialize_evidence(evidence)
    assert serialized_evidence.kind == "alert_normalized"
    assert serialized_evidence.payload["alert_id"] == alert.id
    refute Map.has_key?(serialized_evidence, :organization_id)
    refute Map.has_key?(serialized_evidence, :dedupe_key)

    # Retry is idempotent: terminal runs and their evidence remain unchanged.
    assert :ok =
             perform_job(ShadowInvestigationWorker, %{
               "organization_id" => org.id,
               "run_id" => run.id
             })

    assert evidence_after_retry = ShadowOrchestrator.list_evidence(org.id, run.id)
    assert length(evidence_after_retry) == 2
  end

  test "recommendation mode remains non-enforcing", %{organization: org, alert: alert} do
    assert {:ok, run} = ShadowOrchestrator.enqueue(org.id, alert.id, mode: :recommendation)
    assert run.mode == "recommendation"

    assert :ok =
             perform_job(ShadowInvestigationWorker, %{
               "organization_id" => org.id,
               "run_id" => run.id
             })

    observed = ShadowOrchestrator.get_run(org.id, run.id)
    assert observed.summary["enforcement"] == "disabled"
    assert observed.summary["decision"] == "not_evaluated"
  end

  test "collects bounded existing context into model-agnostic evidence", %{
    organization: org,
    alert: alert
  } do
    process_chain =
      for pid <- 1..30 do
        command_line =
          if pid == 1 do
            "curl https://alice:hunter2@example.invalid --token abc123 " <>
              "--password swordfish -H 'Authorization: Bearer bearer-secret' " <>
              "--api_key=key-secret safe " <> String.duplicate("x", 700)
          else
            String.duplicate("x", 700)
          end

        %{
          "pid" => pid,
          "ppid" => max(pid - 1, 0),
          "name" => "process-#{pid}",
          "command_line" => command_line
        }
      end

    alert =
      MultiTenant.with_organization(org.id, fn ->
        alert
        |> Ecto.Changeset.change(
          contributing_events: ["event-a", "event-b"],
          process_chain: process_chain,
          evidence: %{
            "iocs" => [
              %{"type" => "domain", "value" => "example.invalid", "confidence" => 0.7}
            ],
            "file_hashes" => [%{"sha256" => String.duplicate("a", 64)}]
          },
          detection_metadata: %{
            "triage_agent" => %{"priority" => "p2", "confidence" => 0.76}
          },
          enrichment: %{"risk_score" => 0.81}
        )
        |> Repo.update!()
      end)

    assert {:ok, run} = ShadowOrchestrator.enqueue(org.id, alert.id)
    assert {:ok, observed} = ShadowOrchestrator.process(org.id, run.id)

    assert observed.status == "observed"
    assert observed.summary["enforcement"] == "disabled"
    assert observed.summary["observation_state"] == "observed"
    assert observed.summary["evidence_count"] == 6
    assert observed.summary["degraded_sources"] == []

    evidence = ShadowOrchestrator.list_evidence(org.id, run.id)

    assert Enum.sort(Enum.map(evidence, & &1.kind)) ==
             Enum.sort([
               "alert_normalized",
               "agent_posture",
               "contributing_events",
               "process_chain",
               "indicators",
               "analysis_context"
             ])

    process_evidence = Enum.find(evidence, &(&1.kind == "process_chain"))
    assert length(process_evidence.payload["processes"]) == 25

    redacted_command = hd(process_evidence.payload["processes"])["command_line"]
    assert String.length(redacted_command) == 512
    assert redacted_command =~ "curl https://[REDACTED]@example.invalid"
    assert redacted_command =~ "--token [REDACTED]"
    assert redacted_command =~ "--password [REDACTED]"
    assert redacted_command =~ "Authorization: [REDACTED]"
    assert redacted_command =~ "--api_key=[REDACTED]"
    refute redacted_command =~ "hunter2"
    refute redacted_command =~ "abc123"
    refute redacted_command =~ "swordfish"
    refute redacted_command =~ "bearer-secret"
    refute redacted_command =~ "key-secret"
  end

  test "missing optional source is explicit degradation without aborting observation", %{
    organization: org,
    alert: alert
  } do
    alert =
      MultiTenant.with_organization(org.id, fn ->
        alert |> Ecto.Changeset.change(agent_id: nil) |> Repo.update!()
      end)

    assert {:ok, run} = ShadowOrchestrator.enqueue(org.id, alert.id)
    assert {:ok, observed} = ShadowOrchestrator.process(org.id, run.id)

    assert observed.status == "observed"
    assert observed.summary["observation_state"] == "degraded"
    assert observed.summary["evidence_count"] == 1

    assert [%{"source" => "agent_posture", "reason" => "agent_not_associated"}] =
             observed.summary["degraded_sources"]
  end

  test "worker fails closed for a run outside the supplied tenant", %{
    organization: org,
    other_organization: other_org,
    alert: alert
  } do
    assert {:ok, run} = ShadowOrchestrator.enqueue(org.id, alert.id)

    assert {:discard, :run_not_found_in_organization} =
             ShadowInvestigationWorker.perform(%Oban.Job{
               args: %{"organization_id" => other_org.id, "run_id" => run.id}
             })

    assert ShadowOrchestrator.get_run(org.id, run.id).status == "queued"
  end

  test "worker timeout leaves a bounded finalization margin and failed runs are terminal", %{
    organization: org,
    alert: alert
  } do
    Application.put_env(:tamandua_server, ShadowOrchestrator, worker_timeout_ms: 500)
    assert ShadowInvestigationWorker.timeout(%Oban.Job{}) == 31_000

    assert {:ok, run} = ShadowOrchestrator.enqueue(org.id, alert.id)
    assert {:ok, failed} = ShadowOrchestrator.mark_failed(org.id, run.id, :timeout)
    assert failed.status == "failed"
    assert failed.summary["enforcement"] == "disabled"
    assert failed.summary["decision"] == "not_evaluated"
  end

  test "final worker timeout terminalizes the run", %{organization: org, alert: alert} do
    Application.put_env(:tamandua_server, ShadowOrchestrator, worker_timeout_ms: 1_000)
    assert {:ok, run} = ShadowOrchestrator.enqueue(org.id, alert.id)

    job = %Oban.Job{
      args: %{"organization_id" => org.id, "run_id" => run.id},
      attempt: 3,
      max_attempts: 3
    }

    assert {:discard, :retries_exhausted} =
             ShadowInvestigationWorker.perform_result(job, fn _organization_id, _run_id ->
               Process.sleep(2_000)
               {:ok, :too_late}
             end)

    assert failed = ShadowOrchestrator.get_run(org.id, run.id)
    assert failed.status == "failed"
    assert failed.error_code =~ "worker_timeout"
  end

  test "final worker child exception terminalizes the run", %{organization: org, alert: alert} do
    assert {:ok, run} = ShadowOrchestrator.enqueue(org.id, alert.id)

    job = %Oban.Job{
      args: %{"organization_id" => org.id, "run_id" => run.id},
      attempt: 3,
      max_attempts: 3
    }

    assert {:discard, :retries_exhausted} =
             ShadowInvestigationWorker.perform_result(job, fn _organization_id, _run_id ->
               raise "bounded child failure"
             end)

    assert failed = ShadowOrchestrator.get_run(org.id, run.id)
    assert failed.status == "failed"
    assert failed.error_code =~ "worker_exit"
  end

  test "unsupported modes fail closed", %{organization: org, alert: alert} do
    assert {:error, :unsupported_mode} =
             ShadowOrchestrator.enqueue(org.id, alert.id, mode: :autonomous)
  end

  test "alert creation trigger is disabled by default", %{
    organization: org,
    other_organization: other_org,
    alert: alert
  } do
    Application.put_env(:tamandua_server, ShadowOrchestrator, alert_creation_trigger: :off)

    assert {:disabled, :policy_off} =
             ShadowOrchestrator.enqueue_from_alert_creation(alert)

    assert {:ok, []} = ShadowOrchestrator.list_runs_for_alert(org.id, alert.id)

    assert {:error, :alert_not_found_in_organization} =
             ShadowOrchestrator.list_runs_for_alert(other_org.id, alert.id)
  end

  test "alert creation trigger admits only idempotent shadow runs", %{
    organization: org,
    alert: alert
  } do
    opt_in!(org)

    Application.put_env(:tamandua_server, ShadowOrchestrator,
      alert_creation_trigger: :shadow,
      eligible_severities: ["critical", "high"],
      max_active_per_tenant: 2,
      max_admissions_per_minute: 10
    )

    assert {:ok, first} = ShadowOrchestrator.enqueue_from_alert_creation(alert)
    assert first.mode == "shadow"
    assert first.source == "alert_creation"
    assert first.admission_disposition == "enqueued"
    assert first.admission_reason == "eligible_shadow_observation"
    assert first.summary["enforcement"] == "disabled"

    assert {:ok, second} = ShadowOrchestrator.enqueue_from_alert_creation(alert)
    assert second.id == first.id
  end

  test "alert creation trigger durably degrades recommendation and autonomous configuration", %{
    organization: org,
    alert: alert
  } do
    for unsafe_mode <- [:recommendation, :autonomous] do
      Application.put_env(:tamandua_server, ShadowOrchestrator,
        alert_creation_trigger: unsafe_mode
      )

      assert {:ok, receipt} = ShadowOrchestrator.enqueue_from_alert_creation(alert)
      assert receipt.status == "abstained"
      assert receipt.admission_disposition == "degraded"
      assert receipt.admission_reason == "unsupported_trigger_configuration"
    end

    assert {:ok, [receipt]} = ShadowOrchestrator.list_runs_for_alert(org.id, alert.id)
    assert receipt.policy_version == "shadow-v2"
  end

  test "automatic policy requires explicit tenant opt-in and eligible severity", %{
    organization: org,
    alert: alert
  } do
    Application.put_env(:tamandua_server, ShadowOrchestrator, alert_creation_trigger: :shadow)

    assert {:disabled, :tenant_not_opted_in} =
             ShadowOrchestrator.enqueue_from_alert_creation(alert)

    assert {:ok, [disabled]} = ShadowOrchestrator.list_runs_for_alert(org.id, alert.id)
    assert disabled.admission_disposition == "disabled"

    low_alert = insert(:alert, organization: org, severity: "medium")
    opt_in!(org)

    assert {:ok, ineligible} = ShadowOrchestrator.enqueue_from_alert_creation(low_alert)
    assert ineligible.status == "abstained"
    assert ineligible.admission_disposition == "ineligible"
    assert ineligible.admission_reason == "severity_not_eligible"
  end

  test "automatic policy bounds active and per-minute admissions per tenant", %{
    organization: org,
    alert: alert
  } do
    opt_in!(org)

    Application.put_env(:tamandua_server, ShadowOrchestrator,
      alert_creation_trigger: :shadow,
      max_active_per_tenant: 1,
      max_admissions_per_minute: 10
    )

    assert {:ok, first} = ShadowOrchestrator.enqueue_from_alert_creation(alert)
    assert first.admission_disposition == "enqueued"

    second_alert = insert(:alert, organization: org, severity: "critical")
    assert {:ok, limited} = ShadowOrchestrator.enqueue_from_alert_creation(second_alert)
    assert limited.admission_disposition == "capacity_limited"
    assert limited.admission_reason == "tenant_active_limit"

    assert {:ok, _observed} = ShadowOrchestrator.process(org.id, first.id)

    Application.put_env(:tamandua_server, ShadowOrchestrator,
      alert_creation_trigger: :shadow,
      max_active_per_tenant: 10,
      max_admissions_per_minute: 1
    )

    third_alert = insert(:alert, organization: org, severity: "high")
    assert {:ok, rate_limited} = ShadowOrchestrator.enqueue_from_alert_creation(third_alert)
    assert rate_limited.admission_disposition == "capacity_limited"
    assert rate_limited.admission_reason == "tenant_rate_limit"
  end

  test "validated detector envelope is normalized, hashed and collected as evidence", %{
    organization: org,
    alert: alert,
    producer_attestation: attestation
  } do
    envelope = valid_detector_envelope()
    assert {:ok, normalized} = DetectorObservationConsensusV1.validate_and_normalize(envelope)

    assert {:ok, %{run: run, contract_hash: contract_hash}} =
             ShadowOrchestrator.attach_detector_observation(
               org.id,
               alert.id,
               envelope,
               attestation.id
             )

    assert contract_hash == DetectorObservationConsensusV1.hash(normalized)
    assert {:ok, observed} = ShadowOrchestrator.process(org.id, run.id)
    assert observed.summary["enforcement"] == "disabled"
    assert observed.summary["observation_state"] == "observed"

    contract_evidence =
      org.id
      |> ShadowOrchestrator.list_evidence(run.id)
      |> Enum.find(&(&1.kind == "detector_observation_consensus"))

    assert contract_evidence.payload["contract_hash_sha256"] == contract_hash
    assert contract_evidence.payload["enforcement"] == "disabled"
    assert contract_evidence.payload["consensus_claim"] == "producer_assertion"
    assert hd(contract_evidence.payload["producer_attestations"])["id"] == attestation.id

    assert contract_evidence.payload["envelope"]["api_version"] ==
             "tamandua.io/detector-observation-consensus/v1"
  end

  test "invalid detector envelope becomes degraded reason and never evidence", %{
    organization: org,
    alert: alert,
    producer_attestation: attestation
  } do
    invalid = Map.put(valid_detector_envelope(), "api_version", "unsupported/v9")
    assert {:error, errors} = DetectorObservationConsensusV1.validate_and_normalize(invalid)
    assert errors != []

    assert {:error, {:invalid_envelope, _errors}} =
             ShadowOrchestrator.attach_detector_observation(
               org.id,
               alert.id,
               invalid,
               attestation.id
             )

    assert {:ok, [run]} = ShadowOrchestrator.list_runs_for_alert(org.id, alert.id)
    assert {:ok, observed} = ShadowOrchestrator.process(org.id, run.id)
    assert observed.summary["observation_state"] == "degraded"
    assert observed.summary["enforcement"] == "disabled"

    refute Enum.any?(
             ShadowOrchestrator.list_evidence(org.id, run.id),
             &(&1.kind == "detector_observation_consensus")
           )

    assert Enum.any?(observed.summary["degraded_sources"], fn source ->
             source["source"] == "detector_observation_contract" and
               source["reason"] == "invalid_envelope"
           end)
  end

  test "detector runtime metadata is optional, normalized, and fail-closed for degraded votes" do
    envelope =
      valid_detector_envelope()
      |> put_in(["observations", Access.at(0), "runtime_lane"], "embedded_onnx")
      |> put_in(["observations", Access.at(0), "model_contract_id"], "contract/pe-v1")
      |> put_in(["observations", Access.at(0), "decision_mode"], "detect_only")
      |> put_in(
        ["observations", Access.at(0), "ensemble_votes"],
        [
          %{
            "detector_id" => "engine/bytes",
            "status" => "completed",
            "score" => 0.9,
            "decision" => "malicious",
            "confidence" => 0.8
          },
          %{
            "detector_id" => "engine/static",
            "status" => "unsupported",
            "score" => nil,
            "decision" => "unknown",
            "confidence" => 0
          }
        ]
      )

    assert {:ok, normalized} = DetectorObservationConsensusV1.validate_and_normalize(envelope)
    observation = get_in(normalized, ["observations", Access.at(0)])
    assert observation["runtime_lane"] == "embedded_onnx"
    assert observation["model_contract_id"] == "contract/pe-v1"
    assert observation["decision_mode"] == "detect_only"
    assert get_in(observation, ["ensemble_votes", Access.at(1), "status"]) == "unsupported"

    invalid =
      envelope
      |> put_in(["observations", Access.at(0), "ensemble_votes", Access.at(1), "score"], 0.0)
      |> put_in(
        ["observations", Access.at(0), "ensemble_votes", Access.at(1), "decision"],
        "benign"
      )

    assert {:error, errors} = DetectorObservationConsensusV1.validate_and_normalize(invalid)
    assert Enum.any?(errors, &String.contains?(&1, "must be unknown when degraded"))
  end

  test "completed endpoint shadow is admitted as observation only and cannot claim consensus" do
    envelope = endpoint_shadow_detector_envelope()

    assert {:ok, normalized} = DetectorObservationConsensusV1.validate_and_normalize(envelope)

    observation = get_in(normalized, ["observations", Access.at(0)])
    assert observation["status"] == "completed"
    assert observation["score"] == 0.9
    assert observation["threshold"] == 0.8
    assert observation["decision"] == "unknown"
    assert observation["confidence"] == 0
    assert observation["runtime_lane"] == "endpoint_shadow"
    assert observation["decision_mode"] == "detect_only"
    assert DetectorObservationConsensusV1.consensus_claim_status(normalized) == "not_computed"

    decisive_consensus =
      envelope
      |> put_in(["consensus", "score"], 0.9)
      |> put_in(["consensus", "threshold"], 0.8)
      |> put_in(["consensus", "decision"], "malicious")
      |> put_in(["consensus", "confidence"], 0.9)
      |> put_in(["consensus", "degraded"], false)
      |> put_in(["consensus", "error"], nil)

    assert {:error, errors} =
             DetectorObservationConsensusV1.validate_and_normalize(decisive_consensus)

    assert Enum.any?(errors, &String.contains?(&1, "cannot claim consensus"))
  end

  test "endpoint shadow fails closed for decisions, enforcement and ensemble votes" do
    envelope = endpoint_shadow_detector_envelope()

    for invalid <- [
          put_in(envelope, ["observations", Access.at(0), "decision"], "malicious"),
          put_in(envelope, ["observations", Access.at(0), "confidence"], 0.9),
          put_in(envelope, ["observations", Access.at(0), "decision_mode"], "enforced"),
          put_in(envelope, ["observations", Access.at(0), "ensemble_votes"], [
            %{
              "detector_id" => "detector/one",
              "status" => "completed",
              "score" => 0.9,
              "decision" => "malicious",
              "confidence" => 0.9
            }
          ])
        ] do
      assert {:error, _errors} = DetectorObservationConsensusV1.validate_and_normalize(invalid)
    end
  end

  test "detector envelope admission is tenant scoped", %{
    other_organization: other_org,
    alert: alert,
    producer_attestation: attestation
  } do
    assert {:error, :alert_not_found_in_organization} =
             ShadowOrchestrator.attach_detector_observation(
               other_org.id,
               alert.id,
               valid_detector_envelope(),
               attestation.id
             )

    assert {:error, :alert_not_found_in_organization} =
             ShadowOrchestrator.list_runs_for_alert(other_org.id, alert.id)
  end

  test "detector envelope rejects stale and future telemetry using bounded configuration" do
    previous =
      Application.get_env(
        :tamandua_server,
        DetectorObservationConsensusV1
      )

    Application.put_env(:tamandua_server, DetectorObservationConsensusV1,
      max_age_seconds: 60,
      max_future_skew_seconds: 5
    )

    on_exit(fn ->
      if is_nil(previous) do
        Application.delete_env(:tamandua_server, DetectorObservationConsensusV1)
      else
        Application.put_env(:tamandua_server, DetectorObservationConsensusV1, previous)
      end
    end)

    stale =
      valid_detector_envelope()
      |> put_in(
        ["observations", Access.at(0), "observed_at"],
        DateTime.utc_now() |> DateTime.add(-120, :second) |> DateTime.to_iso8601()
      )

    future =
      valid_detector_envelope()
      |> put_in(
        ["consensus", "generated_at"],
        DateTime.utc_now() |> DateTime.add(30, :second) |> DateTime.to_iso8601()
      )

    assert {:error, stale_errors} =
             DetectorObservationConsensusV1.validate_and_normalize(stale)

    assert Enum.any?(stale_errors, &String.contains?(&1, "older than the admission window"))

    assert {:error, future_errors} =
             DetectorObservationConsensusV1.validate_and_normalize(future)

    assert Enum.any?(future_errors, &String.contains?(&1, "too far in the future"))
  end

  test "detector envelope rejects credential-bearing provenance URIs" do
    for uri <- [
          "https://operator:secret@example.test/model",
          "https://example.test/model?access_token=secret",
          "https://example.test/model?API-KEY=secret"
        ] do
      envelope =
        valid_detector_envelope()
        |> put_in(["observations", Access.at(0), "provenance", "uri"], uri)

      assert {:error, errors} =
               DetectorObservationConsensusV1.validate_and_normalize(envelope)

      assert Enum.any?(errors, &String.contains?(&1, "must not contain credentials"))
    end

    safe =
      valid_detector_envelope()
      |> put_in(
        ["observations", Access.at(0), "provenance", "uri"],
        "https://example.test/model?revision=1"
      )

    assert {:ok, normalized} = DetectorObservationConsensusV1.validate_and_normalize(safe)

    assert get_in(normalized, ["observations", Access.at(0), "provenance", "uri"]) ==
             "https://example.test/model?revision=1"
  end

  test "elevated claims fail closed when the attestation only authorizes contract smoke", %{
    organization: org,
    alert: alert,
    producer_attestation: attestation
  } do
    elevated =
      put_in(valid_detector_envelope(), ["validation_context"], %{
        "evidence_class" => "governed_holdout",
        "claim_scope" => "efficacy",
        "effectiveness_metrics" => ["fpr"]
      })

    assert {:error, {:invalid_envelope, errors}} =
             ShadowOrchestrator.attach_detector_observation(
               org.id,
               alert.id,
               elevated,
               attestation.id
             )

    assert Enum.any?(errors, &String.contains?(&1, "not authorized"))
  end

  test "revoked producer attestation is revalidated before evidence collection", %{
    organization: org,
    alert: alert,
    producer_attestation: attestation,
    registry_admin: registry_admin
  } do
    assert {:ok, %{run: run}} =
             ShadowOrchestrator.attach_detector_observation(
               org.id,
               alert.id,
               valid_detector_envelope(),
               attestation.id
             )

    assert {:ok, _revoked} =
             DetectorProducerRegistry.revoke(org.id, attestation.id, registry_admin.id)

    assert {:ok, observed} = ShadowOrchestrator.process(org.id, run.id)
    assert observed.summary["observation_state"] == "degraded"
    assert observed.summary["enforcement"] == "disabled"
  end

  test "producer registry domain rejects missing and unprivileged actors", %{
    organization: org
  } do
    viewer = insert(:user, organization: org, role: "viewer")

    assert {:error, :unauthorized} =
             DetectorProducerRegistry.attest(org.id, nil, producer_attestation_attrs())

    assert {:error, :unauthorized} =
             DetectorProducerRegistry.attest(org.id, viewer.id, producer_attestation_attrs())
  end

  defp grant_permission!(user, organization, permission_slug) do
    slug = Atom.to_string(permission_slug)

    permission =
      Repo.get_by(Permission, slug: slug) ||
        %Permission{}
        |> Permission.changeset(%{
          name: slug,
          slug: slug,
          description: slug,
          category: "system"
        })
        |> Repo.insert!()

    role =
      %Role{}
      |> Role.changeset(%{
        name: "Detector registry test administrator",
        slug: "detector_registry_test_#{user.id}",
        builtin: false,
        priority: 80,
        organization_id: organization.id
      })
      |> Repo.insert!()

    %RolePermission{}
    |> RolePermission.changeset(%{role_id: role.id, permission_id: permission.id})
    |> Repo.insert!()

    %UserRole{}
    |> UserRole.changeset(%{
      user_id: user.id,
      role_id: role.id,
      granted_at: DateTime.utc_now() |> DateTime.truncate(:microsecond)
    })
    |> Repo.insert!()

    RBAC.invalidate_cache(user)
  end

  defp producer_attestation_attrs do
    %{
      "producer_id" => "tamandua/governed-fixture",
      "detector_id" => "detector/one",
      "detector_type" => "model",
      "detector_version" => "1.0.0",
      "source" => "governed-registry",
      "revision" => "revision-1",
      "artifact_sha256" => String.duplicate("3", 64),
      "input_schema_sha256" => String.duplicate("2", 64),
      "allowed_evidence_classes" => ["contract_smoke"],
      "allowed_claim_scopes" => ["contract_only"]
    }
  end

  defp valid_detector_envelope do
    now = DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601()

    %{
      "api_version" => "tamandua.io/detector-observation-consensus/v1",
      "artifact" => %{
        "artifact_id" => "fixture/artifact-1",
        "sha256" => String.duplicate("1", 64),
        "media_type" => "application/octet-stream",
        "size_bytes" => 4_096
      },
      "input_contract" => %{
        "contract_id" => "tamandua/static-features",
        "contract_version" => "1.0.0",
        "schema_sha256" => String.duplicate("2", 64),
        "feature_set" => "static-v1"
      },
      "observations" => [
        %{
          "detector_id" => "detector/one",
          "detector_type" => "model",
          "detector_version" => "1.0.0",
          "score" => 0.9,
          "score_orientation" => "higher_is_more_malicious",
          "threshold" => 0.8,
          "decision" => "malicious",
          "confidence" => 0.8,
          "latency_ms" => 12,
          "status" => "completed",
          "degraded" => false,
          "error" => nil,
          "provenance" => %{
            "source" => "governed-registry",
            "revision" => "revision-1",
            "artifact_sha256" => String.duplicate("3", 64)
          },
          "observed_at" => now
        }
      ],
      "consensus" => %{
        "strategy" => "weighted",
        "strategy_version" => "1.0.0",
        "member_detector_ids" => ["detector/one"],
        "score" => 0.9,
        "score_orientation" => "higher_is_more_malicious",
        "threshold" => 0.8,
        "decision" => "malicious",
        "confidence" => 0.8,
        "degraded" => false,
        "error" => nil,
        "generated_at" => now
      },
      "validation_context" => %{
        "evidence_class" => "contract_smoke",
        "claim_scope" => "contract_only",
        "effectiveness_metrics" => []
      }
    }
  end

  defp endpoint_shadow_detector_envelope do
    valid_detector_envelope()
    |> put_in(["observations", Access.at(0), "runtime_lane"], "endpoint_shadow")
    |> put_in(["observations", Access.at(0), "decision_mode"], "detect_only")
    |> put_in(["observations", Access.at(0), "decision"], "unknown")
    |> put_in(["observations", Access.at(0), "confidence"], 0)
    |> put_in(["consensus", "score"], nil)
    |> put_in(["consensus", "threshold"], nil)
    |> put_in(["consensus", "decision"], "unknown")
    |> put_in(["consensus", "confidence"], 0)
    |> put_in(["consensus", "degraded"], true)
    |> put_in(["consensus", "error"], %{
      "code" => "not_computed",
      "message" => "endpoint shadow observations do not produce consensus",
      "retryable" => false
    })
  end

  defp opt_in!(organization) do
    MultiTenant.with_organization(organization.id, fn ->
      organization
      |> Ecto.Changeset.change(
        features:
          Map.put(
            organization.features || %{},
            "automatic_investigation_shadow_v2",
            true
          )
      )
      |> Repo.update!()
    end)
  end
end
