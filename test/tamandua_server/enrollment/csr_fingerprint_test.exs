defmodule TamanduaServer.Enrollment.CSRFingerprintTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Enrollment.CSRFingerprint

  @keyring [current_version: 7, keys: %{7 => :binary.copy(<<0xA5>>, 32)}]

  test "derives deterministic, versioned, domain-separated hashes without a clear token" do
    material = %{
      organization_id: Ecto.UUID.generate(),
      installation_token_digest: digest("clear-token-never-persisted"),
      csr_sha256: :crypto.hash(:sha256, "csr"),
      agent_info_canonical: ~s({"hostname":"host-a"})
    }

    assert {:ok, first} =
             CSRFingerprint.derive(material, "request-idempotency-0001", keyring: @keyring)

    assert {:ok, second} =
             CSRFingerprint.derive(material, "request-idempotency-0001", keyring: @keyring)

    assert first == second
    assert first.fingerprint_key_version == 7
    assert byte_size(first.request_fingerprint) == 32
    assert byte_size(first.idempotency_key_hash) == 32
    refute first.request_fingerprint == first.idempotency_key_hash
    refute inspect(first) =~ "clear-token-never-persisted"
    assert CSRFingerprint.secure_compare(first.request_fingerprint, second.request_fingerprint)
  end

  test "length-prefixing prevents ambiguous material and unknown keys fail closed" do
    base = %{
      organization_id: Ecto.UUID.generate(),
      installation_token_digest: digest("token-a"),
      csr_sha256: :crypto.hash(:sha256, "csr-a"),
      agent_info_canonical: "{}"
    }

    changed = %{base | installation_token_digest: digest("token-b")}

    assert {:ok, left} = CSRFingerprint.derive(base, "idempotency-key-01", keyring: @keyring)
    assert {:ok, right} = CSRFingerprint.derive(changed, "idempotency-key-01", keyring: @keyring)
    refute CSRFingerprint.secure_compare(left.request_fingerprint, right.request_fingerprint)

    assert {:error, :fingerprint_key_unavailable} =
             CSRFingerprint.derive(base, "idempotency-key-01",
               keyring: [current_version: 8, keys: %{}]
             )

    assert {:error, :fingerprint_key_unavailable} =
             CSRFingerprint.derive(base, "idempotency-key-01",
               version: 32_768,
               keyring: [current_version: 32_768, keys: %{32_768 => :binary.copy(<<1>>, 32)}]
             )

    assert {:error, :invalid_fingerprint_material} =
             CSRFingerprint.derive(Map.put(base, :ignored, "not-framed"), "idempotency-key-01",
               keyring: @keyring
             )

    assert {:error, :invalid_fingerprint_material} =
             CSRFingerprint.derive(
               %{base | installation_token_digest: String.upcase(digest("token-a"))},
               "idempotency-key-01",
               keyring: @keyring
             )
  end

  defp digest(value), do: :crypto.hash(:sha256, value) |> Base.encode16(case: :lower)
end
