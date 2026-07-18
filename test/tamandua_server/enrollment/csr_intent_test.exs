defmodule TamanduaServer.Enrollment.CSRIntentTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Enrollment.CSRIntent

  test "reservation and exact transition graph preserve fencing and coupled fields" do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    attrs = %{
      organization_id: Ecto.UUID.generate(),
      installation_token_id: Ecto.UUID.generate(),
      fingerprint_key_version: 1,
      idempotency_key_hash: hash("idem"),
      request_fingerprint: hash("request"),
      csr_der: <<1>>,
      csr_sha256: hash("csr"),
      public_key_spki_der: <<2>>,
      public_key_sha256: hash("spki"),
      agent_info_canonical: "{}",
      reserved_agent_id: Ecto.UUID.generate(),
      capacity_slot: 0,
      fencing_token: 10,
      reserved_at: now,
      expires_at: DateTime.add(now, 300, :second)
    }

    assert reservation = CSRIntent.reservation_changeset(attrs)
    assert reservation.valid?
    intent = Ecto.Changeset.apply_changes(reservation)
    assert intent.state == "reserved"

    signing_attrs = %{
      signer_request_id: Ecto.UUID.generate(),
      lease_owner_hash: hash("owner"),
      lease_expires_at: DateTime.add(now, 30, :second),
      attempt_count: 1,
      fencing_token: 11,
      signing_started_at: now
    }

    assert signing = CSRIntent.transition_changeset(intent, "signing", signing_attrs)
    assert signing.valid?
    signing_intent = Ecto.Changeset.apply_changes(signing)

    committed =
      CSRIntent.transition_changeset(signing_intent, "committed", %{
        committed_agent_id: intent.reserved_agent_id,
        signer_receipt_hash: hash("receipt"),
        certificate_sha256: hash("certificate"),
        certificate_response: "certificate-response",
        committed_at: now,
        fencing_token: 11
      })

    assert committed.valid?
    assert Ecto.Changeset.get_change(committed, :lease_owner_hash) == nil
    refute CSRIntent.transition_changeset(intent, "committed", %{}).valid?
    refute CSRIntent.transition_changeset(signing_intent, "reserved", %{}).valid?

    reconciliation =
      CSRIntent.transition_changeset(signing_intent, "reconciliation_required", %{
        recovery_code: "signer-outcome-unknown",
        reconciliation_required_at: now,
        fencing_token: 11
      })

    assert reconciliation.valid?
    reconciliation_intent = Ecto.Changeset.apply_changes(reconciliation)

    stale_commit =
      CSRIntent.transition_changeset(reconciliation_intent, "committed", %{
        committed_agent_id: intent.reserved_agent_id,
        signer_receipt_hash: hash("receipt"),
        certificate_sha256: hash("certificate"),
        certificate_response: "certificate-response",
        committed_at: now,
        fencing_token: 11
      })

    refute stale_commit.valid?

    recovered_commit =
      CSRIntent.transition_changeset(reconciliation_intent, "committed", %{
        committed_agent_id: intent.reserved_agent_id,
        signer_receipt_hash: hash("receipt"),
        certificate_sha256: hash("certificate"),
        certificate_response: "certificate-response",
        committed_at: now,
        fencing_token: 12
      })

    assert recovered_commit.valid?
    assert Ecto.Changeset.get_change(recovered_commit, :reconciliation_required_at) == nil
  end

  test "stale fencing and redaction of active intent fail closed" do
    intent = %CSRIntent{state: "reserved", fencing_token: 9}

    refute CSRIntent.transition_changeset(intent, "signing", %{
             signer_request_id: Ecto.UUID.generate(),
             lease_owner_hash: hash("owner"),
             lease_expires_at: DateTime.utc_now(),
             attempt_count: 1,
             fencing_token: 9,
             signing_started_at: DateTime.utc_now()
           }).valid?

    refute CSRIntent.redact_changeset(intent, DateTime.utc_now()).valid?

    terminal = %CSRIntent{
      state: "failed",
      failed_at: DateTime.utc_now(),
      csr_der: <<1>>,
      public_key_spki_der: <<2>>,
      agent_info_canonical: "{}"
    }

    refute CSRIntent.redact_changeset(terminal, nil).valid?

    redacted = CSRIntent.redact_changeset(terminal, DateTime.add(terminal.failed_at, 1, :second))
    assert redacted.valid?

    refute CSRIntent.redact_changeset(Ecto.Changeset.apply_changes(redacted), DateTime.utc_now()).valid?
  end

  defp hash(value), do: :crypto.hash(:sha256, value)
end
