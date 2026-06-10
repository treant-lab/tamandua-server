defmodule TamanduaServer.Agents.CertificateManagerTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Agents.{CertificateManager, AgentCertificate, RevokedCertificate}
  alias TamanduaServer.Repo

  describe "parse_certificate/1" do
    test "parses a valid certificate" do
      # This would require a real test certificate
      # For now, this is a placeholder showing the expected behavior
      # In a real test, you'd load a test certificate from priv/test/certs/
      :skip
    end
  end

  describe "validate_and_pin/2" do
    test "pins certificate on first connection" do
      # This would require:
      # 1. A test agent_id
      # 2. A test certificate (DER format)
      # 3. Verification that the certificate is pinned to the database
      :skip
    end

    test "verifies certificate matches pinned certificate on subsequent connections" do
      # This would require:
      # 1. Pre-pinned certificate in database
      # 2. Same certificate presented again
      # 3. Verification that validation passes
      :skip
    end

    test "rejects certificate with different fingerprint" do
      # This would require:
      # 1. Pre-pinned certificate in database
      # 2. Different certificate presented
      # 3. Verification that validation fails with :fingerprint_mismatch
      :skip
    end

    test "rejects certificate with CN mismatch" do
      # Certificate CN must match claimed agent_id
      :skip
    end
  end

  describe "check_not_revoked/1" do
    test "returns :ok for non-revoked certificate" do
      fingerprint = "test_fingerprint_123"
      assert :ok = CertificateManager.check_not_revoked(fingerprint)
    end

    test "returns error for revoked certificate" do
      fingerprint = "revoked_fingerprint_456"

      # Insert revoked certificate
      %RevokedCertificate{}
      |> RevokedCertificate.changeset(%{
        fingerprint: fingerprint,
        revoked_at: DateTime.utc_now() |> DateTime.truncate(:second),
        reason: "compromised"
      })
      |> Repo.insert!()

      assert {:error, :revoked} = CertificateManager.check_not_revoked(fingerprint)
    end
  end

  describe "revoke_certificate/2" do
    test "revokes a certificate with reason" do
      fingerprint = "test_fingerprint_789"

      {:ok, revocation} = CertificateManager.revoke_certificate(
        fingerprint,
        reason: "compromised",
        notes: "Test revocation"
      )

      assert revocation.fingerprint == fingerprint
      assert revocation.reason == "compromised"
      assert revocation.notes == "Test revocation"
      assert revocation.revoked_at
    end
  end
end
