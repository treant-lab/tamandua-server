defmodule TamanduaServer.Audit.SignatureTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Audit.Signature

  describe "generate_keypair/0" do
    test "generates valid Ed25519 keypair" do
      keypair = Signature.generate_keypair()

      assert is_binary(keypair.public_key)
      assert is_binary(keypair.private_key)
      assert byte_size(keypair.public_key) == 32
      assert byte_size(keypair.private_key) == 64
    end

    test "generates different keypairs each time" do
      keypair1 = Signature.generate_keypair()
      keypair2 = Signature.generate_keypair()

      assert keypair1.public_key != keypair2.public_key
      assert keypair1.private_key != keypair2.private_key
    end
  end

  describe "sign/2 and verify/3" do
    test "signs and verifies binary data" do
      keypair = Signature.generate_keypair()
      data = "test data to sign"

      signature = Signature.sign(data, keypair.private_key)

      assert is_binary(signature)
      assert byte_size(signature) == 64

      assert Signature.verify(data, signature, keypair.public_key) == true
    end

    test "signs and verifies map data" do
      keypair = Signature.generate_keypair()
      data = %{action: "test", user_id: "123"}

      signature = Signature.sign(data, keypair.private_key)

      assert Signature.verify(data, signature, keypair.public_key) == true
    end

    test "rejects signature with wrong public key" do
      keypair1 = Signature.generate_keypair()
      keypair2 = Signature.generate_keypair()

      data = "test data"
      signature = Signature.sign(data, keypair1.private_key)

      assert Signature.verify(data, signature, keypair2.public_key) == false
    end

    test "rejects signature for tampered data" do
      keypair = Signature.generate_keypair()
      original_data = "original data"
      tampered_data = "tampered data"

      signature = Signature.sign(original_data, keypair.private_key)

      assert Signature.verify(tampered_data, signature, keypair.public_key) == false
    end

    test "rejects corrupted signature" do
      keypair = Signature.generate_keypair()
      data = "test data"

      signature = Signature.sign(data, keypair.private_key)
      corrupted_signature = :binary.part(signature, 0, 63) <> <<0>>

      assert Signature.verify(data, corrupted_signature, keypair.public_key) == false
    end
  end

  describe "changeset/2" do
    setup do
      org = insert(:organization)
      keypair = Signature.generate_keypair()

      attrs = %{
        organization_id: org.id,
        seal_number: 1,
        start_sequence: 1,
        end_sequence: 100,
        entry_count: 100,
        merkle_root: "test_merkle_root_hash",
        signature: keypair.public_key <> keypair.public_key, # 64 bytes
        public_key: keypair.public_key,
        sealed_at: DateTime.utc_now()
      }

      {:ok, attrs: attrs, keypair: keypair}
    end

    test "valid changeset", %{attrs: attrs} do
      changeset = Signature.changeset(%Signature{}, attrs)
      assert changeset.valid?
    end

    test "requires all required fields" do
      changeset = Signature.changeset(%Signature{}, %{})

      refute changeset.valid?
      assert length(changeset.errors) > 0
    end

    test "validates signature size", %{attrs: attrs} do
      # Invalid signature size (not 64 bytes)
      invalid_attrs = %{attrs | signature: "too_short"}
      changeset = Signature.changeset(%Signature{}, invalid_attrs)

      refute changeset.valid?
      assert {"must be 64 bytes (Ed25519 signature)", _} = changeset.errors[:signature]
    end

    test "validates public key size", %{attrs: attrs} do
      # Invalid public key size (not 32 bytes)
      invalid_attrs = %{attrs | public_key: "too_short"}
      changeset = Signature.changeset(%Signature{}, invalid_attrs)

      refute changeset.valid?
      assert {"must be 32 bytes (Ed25519 public key)", _} = changeset.errors[:public_key]
    end

    test "validates entry_count is positive", %{attrs: attrs} do
      invalid_attrs = %{attrs | entry_count: 0}
      changeset = Signature.changeset(%Signature{}, invalid_attrs)

      refute changeset.valid?
    end
  end

  describe "export_public_key_pem/1" do
    test "exports public key in PEM format" do
      keypair = Signature.generate_keypair()
      pem = Signature.export_public_key_pem(keypair.public_key)

      assert String.contains?(pem, "-----BEGIN PUBLIC KEY-----")
      assert String.contains?(pem, "-----END PUBLIC KEY-----")
      assert is_binary(pem)
    end
  end

  describe "verify_seal/1" do
    test "verifies valid seal" do
      org = insert(:organization)
      keypair = Signature.generate_keypair()

      merkle_root = "test_root_hash_12345"
      signature_bytes = Signature.sign(merkle_root, keypair.private_key)

      seal = %Signature{
        organization_id: org.id,
        seal_number: 1,
        start_sequence: 1,
        end_sequence: 100,
        entry_count: 100,
        merkle_root: merkle_root,
        signature: signature_bytes,
        public_key: keypair.public_key,
        sealed_at: DateTime.utc_now()
      }

      assert {:ok, :valid} = Signature.verify_seal(seal)
    end

    test "rejects seal with invalid signature" do
      org = insert(:organization)
      keypair = Signature.generate_keypair()

      merkle_root = "test_root_hash"
      # Sign with one key but use different public key
      wrong_keypair = Signature.generate_keypair()
      signature_bytes = Signature.sign(merkle_root, keypair.private_key)

      seal = %Signature{
        organization_id: org.id,
        seal_number: 1,
        start_sequence: 1,
        end_sequence: 100,
        entry_count: 100,
        merkle_root: merkle_root,
        signature: signature_bytes,
        public_key: wrong_keypair.public_key,
        sealed_at: DateTime.utc_now()
      }

      assert {:error, :invalid_signature} = Signature.verify_seal(seal)
    end

    test "rejects seal with tampered merkle root" do
      org = insert(:organization)
      keypair = Signature.generate_keypair()

      original_root = "original_root_hash"
      tampered_root = "tampered_root_hash"

      signature_bytes = Signature.sign(original_root, keypair.private_key)

      seal = %Signature{
        organization_id: org.id,
        seal_number: 1,
        start_sequence: 1,
        end_sequence: 100,
        entry_count: 100,
        merkle_root: tampered_root, # Changed!
        signature: signature_bytes,
        public_key: keypair.public_key,
        sealed_at: DateTime.utc_now()
      }

      assert {:error, :invalid_signature} = Signature.verify_seal(seal)
    end
  end

  describe "get_or_create_signing_key/1" do
    test "creates signing key for new organization" do
      org = insert(:organization)

      keypair = Signature.get_or_create_signing_key(org.id)

      assert is_binary(keypair.public_key)
      assert is_binary(keypair.private_key)
      assert byte_size(keypair.public_key) == 32
      assert byte_size(keypair.private_key) == 64
    end

    test "returns same key on subsequent calls" do
      org = insert(:organization)

      keypair1 = Signature.get_or_create_signing_key(org.id)
      keypair2 = Signature.get_or_create_signing_key(org.id)

      assert keypair1.public_key == keypair2.public_key
      assert keypair1.private_key == keypair2.private_key
    end
  end

  describe "rotate_signing_key/1" do
    test "generates new keypair for organization" do
      org = insert(:organization)

      original_keypair = Signature.get_or_create_signing_key(org.id)
      {:ok, new_keypair} = Signature.rotate_signing_key(org.id)

      assert new_keypair.public_key != original_keypair.public_key
      assert new_keypair.private_key != original_keypair.private_key
    end

    test "new key is cached for future use" do
      org = insert(:organization)

      {:ok, rotated_keypair} = Signature.rotate_signing_key(org.id)
      cached_keypair = Signature.get_or_create_signing_key(org.id)

      assert cached_keypair.public_key == rotated_keypair.public_key
    end
  end
end
