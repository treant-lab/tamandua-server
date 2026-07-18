defmodule TamanduaServer.Enrollment.CSRB1MigrationSourceTest do
  use ExUnit.Case, async: true

  @migration Path.expand(
               "../../../priv/repo/migrations/20260716009000_create_enrollment_csr_intents.exs",
               __DIR__
             )
  @router Path.expand("../../../lib/tamandua_server_web/router.ex", __DIR__)
  @enrollment Path.expand("../../../lib/tamandua_server/enrollment.ex", __DIR__)

  test "migration has composite token ownership, strict FORCE RLS and bounded state constraints" do
    source = File.read!(@migration)

    assert source =~ "FOREIGN KEY (installation_token_id, organization_id)"
    assert source =~ "REFERENCES installation_tokens(id, organization_id)"
    assert source =~ "ENABLE ROW LEVEL SECURITY"
    assert source =~ "FORCE ROW LEVEL SECURITY"
    assert source =~ "current_setting('app.current_organization_id', true)"
    refute source =~ "rls_bypass"
    assert source =~ "octet_length(csr_der) BETWEEN 1 AND 32768"
    assert source =~ "octet_length(agent_info_canonical) BETWEEN 2 AND 16384"
    assert source =~ "enrollment_csr_intents_state_fields_check"
    assert source =~ "enrollment_csr_intents_active_capacity_uidx"
    assert source =~ "lease_expires_at > signing_started_at"
    assert source =~ "reconciliation_required_at >= signing_started_at"
    assert source =~ "redacted_at >= committed_at"
    assert source =~ "enrollment_csr_intents_redaction_check"
    assert source =~ "csr_der = decode('00', 'hex')"
    assert source =~ "CREATE TRIGGER enrollment_csr_intents_transition_guard"
    assert source =~ "immutable enrollment CSR intent material changed"
    assert source =~ "NEW.id IS DISTINCT FROM OLD.id"
    assert source =~ "NEW.fencing_token <= OLD.fencing_token"
  end

  test "B1 does not open CSR enrollment or add signing execution" do
    router = File.read!(@router)
    enrollment = File.read!(@enrollment)

    assert router =~ "post(\"/csr\", EnrollmentController, :csr_enroll)"
    assert enrollment =~ "def enroll_with_csr"
    assert enrollment =~ "{:error, :enrollment_unavailable}"
    refute File.read!(@migration) =~ "agent_certificates"
  end
end
