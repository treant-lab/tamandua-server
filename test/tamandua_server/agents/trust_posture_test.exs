defmodule TamanduaServer.Agents.TrustPostureTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Agents.TrustPosture

  @now ~U[2026-07-15 18:00:00Z]
  @fresh ~U[2026-07-15 17:58:00Z]

  test "benign fresh signals remain unverified without server proof" do
    posture = TrustPosture.project(benign_signals(), now: @now)

    assert posture.state == "unverified"
    assert posture.risk_score == 10
    assert posture.evidence_completeness.complete
    assert posture.provenance.device_identity.assurance == "unverified"
    assert "identity_not_verified" in posture.reason_codes
    assert posture.history.recovered_sources == []
    assert posture == TrustPosture.project(benign_signals(), now: @now)
  end

  test "missing sources are distinct and degrade the projection" do
    posture = TrustPosture.project(%{}, now: @now)

    assert posture.state == "degraded"

    assert posture.evidence_completeness.missing_sources ==
             ~w(app_guard device_identity offline_checkpoint runtime_integrity)

    assert posture.evidence_completeness.unsupported_sources == []
    assert posture.evidence_completeness.degraded_sources == []
    assert posture.provenance.runtime_integrity.status == "missing"
    assert posture.provenance.runtime_integrity.freshness == "missing"
  end

  test "unsupported, degraded, and missing remain separately observable" do
    signals = %{
      device_identity: %{status: "available", collected_at: @fresh},
      runtime_integrity: %{state: "unsupported", collected_at: @fresh},
      app_guard: %{status: "degraded", collected_at: @fresh},
      offline_checkpoint: nil
    }

    posture = TrustPosture.project(signals, now: @now)

    assert posture.state == "degraded"
    assert posture.evidence_completeness.unsupported_sources == ["runtime_integrity"]
    assert posture.evidence_completeness.degraded_sources == ["app_guard"]
    assert posture.evidence_completeness.missing_sources == ["offline_checkpoint"]
  end

  test "stale evidence is explicit and cannot verify posture" do
    stale = DateTime.add(@now, -3_600, :second)

    posture =
      benign_signals()
      |> put_in([:runtime_integrity, :collected_at], stale)
      |> TrustPosture.project(now: @now, max_age_seconds: 900)

    assert posture.state == "degraded"
    assert posture.evidence_completeness.stale_sources == ["runtime_integrity"]
    assert "source_stale:runtime_integrity" in posture.reason_codes
  end

  test "client claimed platform attestation never produces verified" do
    signals =
      benign_signals()
      |> put_in([:device_identity, :identity_source], "platform_attested")
      |> put_in(
        [:device_identity, :attestation],
        %{
          status: "verified",
          verification_source: "google_play_integrity",
          verification_authority: "client"
        }
      )

    posture = TrustPosture.project(signals, now: @now)

    assert posture.state == "unverified"
    assert posture.provenance.device_identity.assurance == "client_claimed"
    refute posture.provenance.device_identity.server_verified
    assert "client_claimed_attestation_unverified" in posture.reason_codes
  end

  test "server verified attestation with complete fresh evidence produces verified" do
    posture = TrustPosture.project(server_verified_signals(), now: @now)

    assert posture.state == "verified"
    assert posture.confidence == 95
    assert posture.provenance.device_identity.server_verified
    assert posture.provenance.device_identity.assurance == "server_verified"
    assert "identity_server_verified" in posture.reason_codes
  end

  test "corroborated identity drift and runtime tamper produce suspected clone" do
    signals =
      server_verified_signals()
      |> put_in([:device_identity, :drift_indicators], ["device_identity_drift"])
      |> put_in([:runtime_integrity, :transition], "finding_changed")
      |> put_in(
        [:runtime_integrity, :finding_kinds],
        ["instrumentation_library_loaded"]
      )

    posture = TrustPosture.project(signals, now: @now)

    assert posture.state == "suspected_clone"
    assert posture.risk_score >= 80
    assert posture.correlation.corroborated

    assert posture.correlation.contributing_sources ==
             ["device_identity", "runtime_integrity"]

    assert "corroborated_clone_or_tamper" in posture.reason_codes
  end

  test "allowlisted RX mismatch is adverse while non-actionable Preview states are not tamper" do
    mismatch =
      server_verified_signals()
      |> put_in([:device_identity, :drift_indicators], ["device_identity_drift"])
      |> put_in([:runtime_integrity], %{
        runtime_state: "supported",
        status: "mismatch",
        finding_kinds: ["file_backed_executable_page_drift"],
        observed_at: @fresh
      })

    mismatch_without_transition = TrustPosture.project(mismatch, now: @now)
    refute mismatch_without_transition.state == "suspected_clone"
    refute "runtime_integrity_adverse" in mismatch_without_transition.reason_codes

    mismatch_posture =
      mismatch
      |> put_in([:runtime_integrity, :transition], "finding_detected")
      |> TrustPosture.project(now: @now)

    assert mismatch_posture.state == "suspected_clone"

    assert mismatch_posture.provenance.runtime_integrity.finding_kinds ==
             ["file_backed_executable_page_drift"]

    for status <- ~w(disabled degraded unsupported) do
      runtime_state = if status == "disabled", do: "supported", else: "degraded"

      signals =
        server_verified_signals()
        |> put_in([:runtime_integrity], %{
          runtime_state: runtime_state,
          status: status,
          finding_kinds: [],
          observed_at: @fresh
        })

      posture = TrustPosture.project(signals, now: @now)
      refute "runtime_integrity_adverse" in posture.reason_codes
      refute posture.correlation.corroborated
    end
  end

  test "v3 collector_observed is retained as benign provenance without becoming adverse" do
    posture =
      server_verified_signals()
      |> put_in([:runtime_integrity], %{
        runtime_state: "supported",
        status: "partial",
        transition: "collector_observed",
        finding_kinds: [],
        observed_at: @fresh
      })
      |> TrustPosture.project(now: @now)

    assert posture.provenance.runtime_integrity.transition == "collector_observed"
    refute "runtime_integrity_adverse" in posture.reason_codes
    refute posture.correlation.corroborated
  end

  test "stale adverse evidence degrades without corroborating a suspected clone" do
    stale = DateTime.add(@now, -3_600, :second)

    signals =
      server_verified_signals()
      |> put_in([:device_identity, :drift_indicators], ["device_identity_drift"])
      |> put_in([:device_identity, :collected_at], stale)
      |> put_in([:runtime_integrity, :transition], "finding_changed")
      |> put_in(
        [:runtime_integrity, :finding_kinds],
        ["instrumentation_library_loaded"]
      )
      |> put_in([:runtime_integrity, :collected_at], stale)

    posture = TrustPosture.project(signals, now: @now)

    assert posture.state == "degraded"
    refute posture.correlation.corroborated
    refute "corroborated_clone_or_tamper" in posture.reason_codes

    assert posture.evidence_completeness.stale_sources ==
             ["device_identity", "runtime_integrity"]
  end

  test "revocation takes precedence over all other states" do
    signals = put_in(server_verified_signals(), [:device_identity, :status], "revoked")
    posture = TrustPosture.project(signals, now: @now)

    assert posture.state == "revoked"
    assert posture.risk_score == 100
    assert posture.confidence == 100
    assert "device_credential_revoked" in posture.reason_codes
  end

  test "recovery returns to current state while preserving sanitized adverse history" do
    adverse_signals =
      server_verified_signals()
      |> put_in([:device_identity, :clone_suspected], true)
      |> put_in([:runtime_integrity, :transition], "finding_detected")
      |> put_in(
        [:runtime_integrity, :finding_kinds],
        ["instrumentation_library_loaded"]
      )

    previous = TrustPosture.project(adverse_signals, now: @now)

    recovered_signals =
      server_verified_signals()
      |> put_in([:runtime_integrity, :transition], "recovered")

    current = TrustPosture.project(recovered_signals, now: @now, previous: previous)

    assert previous.state == "suspected_clone"
    assert current.state == "verified"
    assert current.history.previous_state == "suspected_clone"
    assert current.history.last_adverse_state == "suspected_clone"
    assert current.history.recovery_observed
    assert "runtime_integrity" in current.history.recovered_sources
  end

  test "projection is tenant neutral and never copies raw paths, addresses, or identifiers" do
    signals =
      server_verified_signals()
      |> Map.put(:organization_id, "org-secret")
      |> Map.put(:tenant_id, "tenant-secret")
      |> put_in([:device_identity, :device_id], "device-secret")
      |> put_in([:runtime_integrity, :raw_path], "C:\\secret\\module.dll")
      |> put_in([:runtime_integrity, :raw_address], "0x7ffdeadbeef")
      |> put_in(
        [:runtime_integrity, :findings],
        [
          %{
            kind: "instrumentation_library_loaded",
            evidence: "C:\\secret\\module.dll at 0x7ffdeadbeef"
          }
        ]
      )

    previous = %{
      state: "degraded",
      reason_codes: ["history-secret", "source_missing:runtime_integrity"],
      provenance: %{}
    }

    posture = TrustPosture.project(signals, now: @now, previous: previous)
    encoded = inspect(posture)

    refute encoded =~ "org-secret"
    refute encoded =~ "tenant-secret"
    refute encoded =~ "device-secret"
    refute encoded =~ "history-secret"
    refute encoded =~ "secret\\module"
    refute encoded =~ "0x7ffdeadbeef"
    assert posture.history.previous_reason_codes == ["source_missing:runtime_integrity"]

    assert posture.provenance.runtime_integrity.finding_kinds ==
             ["instrumentation_library_loaded"]
  end

  test "non-applicable sources can be excluded without hiding their unsupported state" do
    signals =
      server_verified_signals()
      |> put_in([:app_guard, :status], "unsupported")

    posture =
      TrustPosture.project(signals,
        now: @now,
        required_sources: [:device_identity, :runtime_integrity, :offline_checkpoint]
      )

    assert posture.state == "verified"
    assert posture.provenance.app_guard.status == "unsupported"
    refute "app_guard" in posture.evidence_completeness.required_sources
    assert posture.evidence_completeness.unsupported_sources == []
  end

  defp benign_signals do
    %{
      device_identity: %{
        status: "available",
        collected_at: @fresh,
        identity_source: "secure_store_persisted_random_id"
      },
      runtime_integrity: %{
        state: "supported",
        transition: nil,
        finding_kinds: [],
        collected_at: @fresh
      },
      app_guard: %{
        status: "available",
        decision: "allow",
        risk_score: 0,
        active_signals: [],
        collected_at: @fresh
      },
      offline_checkpoint: %{
        status: "available",
        protection: "authenticated",
        checkpoint_result: "verified",
        collected_at: @fresh
      }
    }
  end

  defp server_verified_signals do
    put_in(
      benign_signals(),
      [:device_identity, :attestation],
      %{
        status: "verified",
        verification_source: "server_verified",
        verification_authority: "tamandua_server"
      }
    )
  end
end
