defmodule TamanduaServer.Enrollment.CSRCanonicalizerTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Enrollment.CSRCanonicalizer

  @public_key "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC5iM0/c6FZmhIJ1pO/PIsyQ2HqESS7LO/VAgEUL/ZFHugMKNzBWyeCKU+UMqW2ubv2/1WF/AU7vIbj+a8aw/BA=="
  @private_key "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZ1B1d3lTMW90U2JsSkREczAKdGVCM2cvK3V5aWJsS3pFeWJxaGVrS3VRTktlaFJBTkNBQVFMbUl6VDl6b1ZtYUVnbldrNzg4aXpKRFllb1JKTApzczc5VUNBUlF2OWtVZTZBd28zTUZiSjRJcFQ1UXlwYmE1dS9iL1ZZWDhCVHU4aHVQNXJ4ckQ4RQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg=="

  test "accepts one signed P-256 DER or PEM request and returns deterministic hashes" do
    der = csr_der(<<0xA0, 0>>)

    assert {:ok, canonical} = CSRCanonicalizer.canonicalize(der)
    assert canonical.csr_der == der
    assert canonical.csr_sha256 == :crypto.hash(:sha256, der)
    assert canonical.public_key_spki_der == Base.decode64!(@public_key)
    assert canonical.key_algorithm == :ecdsa_p256_sha256

    pem = pem(der)
    assert {:ok, from_pem} = CSRCanonicalizer.canonicalize(pem)
    assert from_pem == canonical
  end

  test "rejects signature tampering, client attributes and multiple PEM objects" do
    der = csr_der(<<0xA0, 0>>)
    tampered = binary_part(der, 0, byte_size(der) - 1) <> <<Bitwise.bxor(:binary.last(der), 1)>>
    assert {:error, :invalid_csr_signature} = CSRCanonicalizer.canonicalize(tampered)

    extension_request = tlv(0xA0, tlv(0x30, <<>>))

    assert {:error, :client_extensions_forbidden} =
             CSRCanonicalizer.canonicalize(csr_der(extension_request))

    assert {:error, :invalid_pem} = CSRCanonicalizer.canonicalize(pem(der) <> "\n" <> pem(der))

    assert {:error, :unsupported_csr_version} =
             CSRCanonicalizer.canonicalize(csr_der(<<0xA0, 0>>, tlv(0x02, <<1>>)))

    assert {:error, :invalid_csr_subject} =
             CSRCanonicalizer.canonicalize(
               csr_der(<<0xA0, 0>>, tlv(0x02, <<0>>), tlv(0x31, <<>>))
             )
  end

  test "rejects an RSA modulus whose encoded width masks a sub-2048-bit key" do
    modulus = Bitwise.bsl(1, 2040) + 1
    rsa_key = tlv(0x30, der_integer(modulus) <> der_integer(65_537))

    rsa_algorithm =
      tlv(
        0x30,
        tlv(0x06, <<0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01>>) <>
          tlv(0x05, <<>>)
      )

    spki = tlv(0x30, rsa_algorithm <> tlv(0x03, <<0, rsa_key::binary>>))
    cri = tlv(0x30, tlv(0x02, <<0>>) <> tlv(0x30, <<>>) <> spki <> <<0xA0, 0>>)

    signature_algorithm =
      tlv(
        0x30,
        tlv(0x06, <<0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B>>) <>
          tlv(0x05, <<>>)
      )

    csr = tlv(0x30, cri <> signature_algorithm <> tlv(0x03, <<0, 1>>))
    assert {:error, :unsupported_public_key} = CSRCanonicalizer.canonicalize(csr)
  end

  test "canonicalizes only bounded allowlisted agent information" do
    assert {:ok, canonical} =
             CSRCanonicalizer.canonicalize_agent_info(%{
               "os_type" => "linux",
               "hostname" => "agent-1"
             })

    assert canonical == ~s({"hostname":"agent-1","os_type":"linux"})

    assert {:error, :unsupported_agent_info_field} =
             CSRCanonicalizer.canonicalize_agent_info(%{"role" => "admin"})

    assert {:error, :agent_info_field_too_large} =
             CSRCanonicalizer.canonicalize_agent_info(%{"hostname" => String.duplicate("a", 256)})

    assert {:error, :duplicate_agent_info_field} =
             CSRCanonicalizer.canonicalize_agent_info(%{:hostname => "a", "hostname" => "b"})

    assert {:error, :invalid_agent_info} =
             CSRCanonicalizer.canonicalize_agent_info(%{"hostname" => <<0xFF>>})
  end

  defp csr_der(attributes, version \\ nil, subject \\ nil) do
    spki = Base.decode64!(@public_key)
    version = version || tlv(0x02, <<0>>)
    subject = subject || tlv(0x30, <<>>)

    cri =
      tlv(
        0x30,
        <<version::binary, subject::binary, spki::binary, attributes::binary>>
      )

    signature = :public_key.sign(cri, :sha256, private_key())
    signature_algorithm = tlv(0x30, tlv(0x06, <<0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02>>))
    tlv(0x30, cri <> signature_algorithm <> tlv(0x03, <<0, signature::binary>>))
  end

  defp pem(der) do
    body =
      der
      |> Base.encode64()
      |> String.graphemes()
      |> Enum.chunk_every(64)
      |> Enum.map_join("\n", &Enum.join/1)

    "-----BEGIN CERTIFICATE REQUEST-----\n#{body}\n-----END CERTIFICATE REQUEST-----"
  end

  defp private_key do
    @private_key
    |> Base.decode64!()
    |> :public_key.pem_decode()
    |> hd()
    |> :public_key.pem_entry_decode()
  end

  defp tlv(tag, value) when byte_size(value) < 128, do: <<tag, byte_size(value), value::binary>>

  defp tlv(tag, value) do
    encoded = :binary.encode_unsigned(byte_size(value))
    <<tag, 0x80 + byte_size(encoded), encoded::binary, value::binary>>
  end

  defp der_integer(value) do
    encoded = :binary.encode_unsigned(value)
    encoded = if :binary.first(encoded) >= 0x80, do: <<0, encoded::binary>>, else: encoded
    tlv(0x02, encoded)
  end
end
