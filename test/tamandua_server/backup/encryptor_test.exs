defmodule TamanduaServer.Backup.EncryptorTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Backup.Encryptor

  @sample_data "This is sensitive backup data that must be encrypted"
  @large_data String.duplicate("x", 1_000_000)

  describe "encrypt/2" do
    test "encrypts data successfully" do
      {:ok, encrypted, metadata} = Encryptor.encrypt(@sample_data)

      assert is_binary(encrypted)
      assert byte_size(encrypted) > byte_size(@sample_data)
      assert metadata.algorithm == "AES-256-GCM"
      assert metadata.version == 1
      assert is_binary(metadata.dek_id)
      assert %DateTime{} = metadata.encrypted_at
    end

    test "produces different ciphertext for same plaintext" do
      {:ok, encrypted1, _} = Encryptor.encrypt(@sample_data)
      {:ok, encrypted2, _} = Encryptor.encrypt(@sample_data)

      assert encrypted1 != encrypted2
    end

    test "includes custom metadata" do
      custom_meta = %{source: "test", type: "unit_test"}
      {:ok, _encrypted, metadata} = Encryptor.encrypt(@sample_data, metadata: custom_meta)

      assert metadata.source == "test"
      assert metadata.type == "unit_test"
    end

    test "supports different compression levels" do
      {:ok, enc_low, _} = Encryptor.encrypt(@large_data, compression: 1)
      {:ok, enc_high, _} = Encryptor.encrypt(@large_data, compression: 9)

      # Higher compression should produce smaller output
      assert byte_size(enc_high) < byte_size(enc_low)
    end

    test "handles empty data" do
      {:ok, encrypted, metadata} = Encryptor.encrypt("")

      assert is_binary(encrypted)
      assert metadata.algorithm == "AES-256-GCM"
    end

    test "handles binary data" do
      binary_data = <<0, 1, 2, 3, 255, 254, 253>>
      {:ok, encrypted, _metadata} = Encryptor.encrypt(binary_data)

      assert is_binary(encrypted)
    end
  end

  describe "decrypt/2" do
    test "decrypts data successfully" do
      {:ok, encrypted, _metadata} = Encryptor.encrypt(@sample_data)
      {:ok, decrypted} = Encryptor.decrypt(encrypted)

      assert decrypted == @sample_data
    end

    test "decrypts large data successfully" do
      {:ok, encrypted, _metadata} = Encryptor.encrypt(@large_data)
      {:ok, decrypted} = Encryptor.decrypt(encrypted)

      assert decrypted == @large_data
    end

    test "fails with corrupted data" do
      {:ok, encrypted, _metadata} = Encryptor.encrypt(@sample_data)

      # Corrupt a byte in the middle
      corrupted = corrupt_byte(encrypted, div(byte_size(encrypted), 2))

      assert {:error, _reason} = Encryptor.decrypt(corrupted)
    end

    test "fails with invalid HMAC" do
      {:ok, encrypted, _metadata} = Encryptor.encrypt(@sample_data)

      # Corrupt HMAC (last 32 bytes)
      hmac_pos = byte_size(encrypted) - 32
      corrupted = corrupt_byte(encrypted, hmac_pos)

      assert {:error, :hmac_verification_failed} = Encryptor.decrypt(corrupted)
    end

    test "fails with truncated data" do
      {:ok, encrypted, _metadata} = Encryptor.encrypt(@sample_data)

      # Truncate encrypted data
      truncated = binary_part(encrypted, 0, byte_size(encrypted) - 10)

      assert {:error, _reason} = Encryptor.decrypt(truncated)
    end

    test "fails with invalid version" do
      {:ok, encrypted, _metadata} = Encryptor.encrypt(@sample_data)

      # Change version byte to unsupported version
      <<_version::8, rest::binary>> = encrypted
      invalid = <<99::8, rest::binary>>

      assert {:error, {:unsupported_version, 99}} = Encryptor.decrypt(invalid)
    end

    test "fails with too short payload" do
      short_payload = <<1, 2, 3, 4, 5>>

      assert {:error, :invalid_payload_size} = Encryptor.decrypt(short_payload)
    end
  end

  describe "encrypt_file/3 and decrypt_file/3" do
    setup do
      temp_dir = System.tmp_dir!()
      source_file = Path.join(temp_dir, "test_source_#{System.unique_integer()}.txt")
      encrypted_file = Path.join(temp_dir, "test_encrypted_#{System.unique_integer()}.enc")
      decrypted_file = Path.join(temp_dir, "test_decrypted_#{System.unique_integer()}.txt")

      File.write!(source_file, @sample_data)

      on_exit(fn ->
        File.rm_rf(source_file)
        File.rm_rf(encrypted_file)
        File.rm_rf(decrypted_file)
      end)

      %{
        source_file: source_file,
        encrypted_file: encrypted_file,
        decrypted_file: decrypted_file
      }
    end

    test "encrypts and decrypts file successfully", %{
      source_file: source_file,
      encrypted_file: encrypted_file,
      decrypted_file: decrypted_file
    } do
      {:ok, metadata} = Encryptor.encrypt_file(source_file, encrypted_file)
      assert File.exists?(encrypted_file)
      assert metadata.algorithm == "AES-256-GCM"

      :ok = Encryptor.decrypt_file(encrypted_file, decrypted_file)
      assert File.exists?(decrypted_file)

      decrypted_content = File.read!(decrypted_file)
      assert decrypted_content == @sample_data
    end

    test "handles non-existent source file", %{encrypted_file: encrypted_file} do
      non_existent = "/tmp/does_not_exist_#{System.unique_integer()}.txt"

      assert {:error, _reason} = Encryptor.encrypt_file(non_existent, encrypted_file)
    end

    test "handles non-existent encrypted file", %{decrypted_file: decrypted_file} do
      non_existent = "/tmp/does_not_exist_#{System.unique_integer()}.enc"

      assert {:error, _reason} = Encryptor.decrypt_file(non_existent, decrypted_file)
    end
  end

  describe "rotate_keys/2" do
    test "rotates encryption keys successfully" do
      {:ok, encrypted1, metadata1} = Encryptor.encrypt(@sample_data)

      # Rotate keys
      {:ok, encrypted2, metadata2} = Encryptor.rotate_keys(encrypted1)

      # Encrypted data should be different
      assert encrypted1 != encrypted2

      # DEK IDs should be different
      assert metadata1.dek_id != metadata2.dek_id

      # Both should decrypt to same plaintext
      {:ok, decrypted1} = Encryptor.decrypt(encrypted1)
      {:ok, decrypted2} = Encryptor.decrypt(encrypted2)

      assert decrypted1 == @sample_data
      assert decrypted2 == @sample_data
    end

    test "fails with corrupted data" do
      corrupted = <<1, 2, 3, 4, 5>>

      assert {:error, _reason} = Encryptor.rotate_keys(corrupted)
    end
  end

  describe "round-trip encryption" do
    test "preserves data through multiple encrypt/decrypt cycles" do
      # First cycle
      {:ok, encrypted1, _} = Encryptor.encrypt(@sample_data)
      {:ok, decrypted1} = Encryptor.decrypt(encrypted1)
      assert decrypted1 == @sample_data

      # Second cycle
      {:ok, encrypted2, _} = Encryptor.encrypt(decrypted1)
      {:ok, decrypted2} = Encryptor.decrypt(encrypted2)
      assert decrypted2 == @sample_data

      # Third cycle
      {:ok, encrypted3, _} = Encryptor.encrypt(decrypted2)
      {:ok, decrypted3} = Encryptor.decrypt(encrypted3)
      assert decrypted3 == @sample_data
    end

    test "handles unicode characters" do
      unicode_data = "Hello 世界 🌍 Привет مرحبا"
      {:ok, encrypted, _} = Encryptor.encrypt(unicode_data)
      {:ok, decrypted} = Encryptor.decrypt(encrypted)

      assert decrypted == unicode_data
    end

    test "handles all byte values" do
      all_bytes = for i <- 0..255, into: <<>>, do: <<i>>
      {:ok, encrypted, _} = Encryptor.encrypt(all_bytes)
      {:ok, decrypted} = Encryptor.decrypt(encrypted)

      assert decrypted == all_bytes
    end
  end

  describe "encryption format" do
    test "has expected structure" do
      {:ok, encrypted, _metadata} = Encryptor.encrypt(@sample_data)

      # Minimum size: version(1) + IV(12) + encDEK(48) + tag(16) + data + HMAC(32)
      min_size = 1 + 12 + 48 + 16 + 32
      assert byte_size(encrypted) >= min_size

      # Extract version byte
      <<version::8, _rest::binary>> = encrypted
      assert version == 1
    end

    test "IV is random for each encryption" do
      {:ok, enc1, _} = Encryptor.encrypt(@sample_data)
      {:ok, enc2, _} = Encryptor.encrypt(@sample_data)

      # Extract IVs (bytes 1-12)
      <<_v1::8, iv1::binary-size(12), _rest1::binary>> = enc1
      <<_v2::8, iv2::binary-size(12), _rest2::binary>> = enc2

      assert iv1 != iv2
    end

    test "DEK ID is unique for each encryption" do
      {:ok, _enc1, meta1} = Encryptor.encrypt(@sample_data)
      {:ok, _enc2, meta2} = Encryptor.encrypt(@sample_data)

      assert meta1.dek_id != meta2.dek_id
    end
  end

  # Helper Functions

  defp corrupt_byte(binary, position) do
    <<prefix::binary-size(position), byte::8, suffix::binary>> = binary
    corrupted_byte = rem(byte + 1, 256)
    <<prefix::binary, corrupted_byte::8, suffix::binary>>
  end
end
