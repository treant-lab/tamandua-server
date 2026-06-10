defmodule TamanduaServer.Backup.Encryptor do
  @moduledoc """
  AES-256-GCM encryption for Tamandua backups.

  Implements envelope encryption:
  1. Generate random DEK (Data Encryption Key) for each backup
  2. Encrypt backup data with DEK using AES-256-GCM
  3. Encrypt DEK with KEK (Key Encryption Key from Vault)
  4. Store encrypted DEK alongside encrypted backup

  ## Security Features
  - AES-256-GCM authenticated encryption
  - Random IV (Initialization Vector) per encryption
  - HMAC-SHA256 integrity verification
  - Envelope encryption (DEK + KEK)
  - Secure key rotation support

  ## Format
  Encrypted backup file structure:
  ```
  [Version:1byte][IV:12bytes][EncryptedDEK:48bytes][Tag:16bytes][EncryptedData:variable][HMAC:32bytes]
  ```
  """

  require Logger
  alias TamanduaServer.Backup.VaultClient

  @version 1
  @iv_size 12
  @key_size 32
  @tag_size 16
  @encrypted_dek_size 48
  @hmac_size 32

  @type encryption_result :: {:ok, binary(), map()} | {:error, term()}
  @type decryption_result :: {:ok, binary()} | {:error, term()}

  @doc """
  Encrypts data using AES-256-GCM with envelope encryption.

  ## Parameters
  - `data` - Binary data to encrypt
  - `opts` - Options:
    - `:metadata` - Metadata to include (map)
    - `:compression` - Compression level (0-9, default: 6)

  ## Returns
  - `{:ok, encrypted_data, metadata}` - Success with encrypted binary and metadata
  - `{:error, reason}` - Encryption failure

  ## Example
      iex> Encryptor.encrypt("sensitive data", compression: 9)
      {:ok, <<1, ...>>, %{dek_id: "...", timestamp: ~U[...]}}
  """
  @spec encrypt(binary(), keyword()) :: encryption_result()
  def encrypt(data, opts \\ []) do
    with {:ok, kek} <- VaultClient.get_master_key(),
         {:ok, compressed} <- compress_data(data, opts),
         {:ok, dek} <- generate_dek(),
         {:ok, iv} <- generate_iv(),
         {:ok, encrypted_data, tag} <- encrypt_with_dek(compressed, dek, iv),
         {:ok, encrypted_dek} <- encrypt_dek(dek, kek, iv),
         hmac <- compute_hmac(encrypted_data, kek),
         payload <- build_payload(iv, encrypted_dek, tag, encrypted_data, hmac),
         metadata <- build_metadata(dek, opts) do
      Logger.info("Backup encrypted successfully",
        size: byte_size(data),
        compressed_size: byte_size(compressed),
        encrypted_size: byte_size(payload)
      )

      {:ok, payload, metadata}
    else
      {:error, reason} = error ->
        Logger.error("Encryption failed: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Decrypts data encrypted with `encrypt/2`.

  ## Parameters
  - `encrypted_data` - Encrypted binary from `encrypt/2`
  - `opts` - Options (reserved for future use)

  ## Returns
  - `{:ok, decrypted_data}` - Successfully decrypted data
  - `{:error, reason}` - Decryption failure

  ## Example
      iex> Encryptor.decrypt(encrypted_backup)
      {:ok, "sensitive data"}
  """
  @spec decrypt(binary(), keyword()) :: decryption_result()
  def decrypt(encrypted_data, _opts \\ []) do
    with {:ok, components} <- parse_payload(encrypted_data),
         {:ok, kek} <- VaultClient.get_master_key(),
         :ok <- verify_hmac(components.encrypted_data, components.hmac, kek),
         {:ok, dek} <- decrypt_dek(components.encrypted_dek, kek, components.iv),
         {:ok, decrypted} <-
           decrypt_with_dek(
             components.encrypted_data,
             dek,
             components.iv,
             components.tag
           ),
         {:ok, decompressed} <- decompress_data(decrypted) do
      Logger.info("Backup decrypted successfully", size: byte_size(decompressed))
      {:ok, decompressed}
    else
      {:error, reason} = error ->
        Logger.error("Decryption failed: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Encrypts a file and writes to destination.

  ## Parameters
  - `source_path` - Path to file to encrypt
  - `dest_path` - Path for encrypted output
  - `opts` - Encryption options

  ## Returns
  - `{:ok, metadata}` - Success with encryption metadata
  - `{:error, reason}` - Encryption failure
  """
  @spec encrypt_file(Path.t(), Path.t(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def encrypt_file(source_path, dest_path, opts \\ []) do
    with {:ok, data} <- File.read(source_path),
         {:ok, encrypted, metadata} <- encrypt(data, opts),
         :ok <- File.write(dest_path, encrypted) do
      Logger.info("File encrypted", source: source_path, dest: dest_path)
      {:ok, metadata}
    end
  end

  @doc """
  Decrypts a file and writes to destination.

  ## Parameters
  - `source_path` - Path to encrypted file
  - `dest_path` - Path for decrypted output
  - `opts` - Decryption options

  ## Returns
  - `:ok` - Success
  - `{:error, reason}` - Decryption failure
  """
  @spec decrypt_file(Path.t(), Path.t(), keyword()) :: :ok | {:error, term()}
  def decrypt_file(source_path, dest_path, opts \\ []) do
    with {:ok, encrypted} <- File.read(source_path),
         {:ok, decrypted} <- decrypt(encrypted, opts),
         :ok <- File.write(dest_path, decrypted) do
      Logger.info("File decrypted", source: source_path, dest: dest_path)
      :ok
    end
  end

  @doc """
  Rotates encryption keys for a backup.

  Re-encrypts data with a new DEK and current KEK.

  ## Parameters
  - `encrypted_data` - Previously encrypted data
  - `opts` - Rotation options

  ## Returns
  - `{:ok, re_encrypted_data, metadata}` - Success
  - `{:error, reason}` - Rotation failure
  """
  @spec rotate_keys(binary(), keyword()) :: encryption_result()
  def rotate_keys(encrypted_data, opts \\ []) do
    with {:ok, decrypted} <- decrypt(encrypted_data),
         {:ok, re_encrypted, metadata} <- encrypt(decrypted, opts) do
      Logger.info("Keys rotated successfully")
      {:ok, re_encrypted, metadata}
    end
  end

  # Private Functions

  defp generate_dek do
    {:ok, :crypto.strong_rand_bytes(@key_size)}
  end

  defp generate_iv do
    {:ok, :crypto.strong_rand_bytes(@iv_size)}
  end

  defp encrypt_with_dek(data, dek, iv) do
    try do
      {ciphertext, tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, dek, iv, data, "", @tag_size, true)
      {:ok, ciphertext, tag}
    rescue
      e -> {:error, {:encryption_failed, e}}
    end
  end

  defp decrypt_with_dek(ciphertext, dek, iv, tag) do
    try do
      case :crypto.crypto_one_time_aead(:aes_256_gcm, dek, iv, ciphertext, "", tag, false) do
        plaintext when is_binary(plaintext) -> {:ok, plaintext}
        :error -> {:error, :authentication_failed}
      end
    rescue
      e -> {:error, {:decryption_failed, e}}
    end
  end

  defp encrypt_dek(dek, kek, iv) do
    try do
      {encrypted, _tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, kek, iv, dek, "", @tag_size, true)
      # Encrypted DEK should be 32 bytes data + 16 bytes tag = 48 bytes
      {:ok, encrypted}
    rescue
      e -> {:error, {:dek_encryption_failed, e}}
    end
  end

  defp decrypt_dek(encrypted_dek, kek, iv) do
    try do
      # Split encrypted DEK into ciphertext and tag
      ciphertext_size = byte_size(encrypted_dek) - @tag_size
      <<ciphertext::binary-size(ciphertext_size), tag::binary-size(@tag_size)>> = encrypted_dek

      case :crypto.crypto_one_time_aead(:aes_256_gcm, kek, iv, ciphertext, "", tag, false) do
        dek when is_binary(dek) and byte_size(dek) == @key_size -> {:ok, dek}
        :error -> {:error, :dek_authentication_failed}
        _ -> {:error, :invalid_dek_size}
      end
    rescue
      e -> {:error, {:dek_decryption_failed, e}}
    end
  end

  defp compute_hmac(data, key) do
    :crypto.mac(:hmac, :sha256, key, data)
  end

  defp verify_hmac(data, expected_hmac, key) do
    computed_hmac = compute_hmac(data, key)

    if :crypto.hash_equals(computed_hmac, expected_hmac) do
      :ok
    else
      {:error, :hmac_verification_failed}
    end
  end

  defp compress_data(data, opts) do
    level = Keyword.get(opts, :compression, 6)

    try do
      compressed = :zlib.compress(data)
      {:ok, compressed}
    rescue
      e -> {:error, {:compression_failed, e}}
    end
  end

  defp decompress_data(compressed) do
    try do
      decompressed = :zlib.uncompress(compressed)
      {:ok, decompressed}
    rescue
      e -> {:error, {:decompression_failed, e}}
    end
  end

  defp build_payload(iv, encrypted_dek, tag, encrypted_data, hmac) do
    <<@version::8, iv::binary-size(@iv_size), encrypted_dek::binary-size(@encrypted_dek_size),
      tag::binary-size(@tag_size), encrypted_data::binary, hmac::binary-size(@hmac_size)>>
  end

  defp parse_payload(payload) do
    min_size = 1 + @iv_size + @encrypted_dek_size + @tag_size + @hmac_size

    if byte_size(payload) < min_size do
      {:error, :invalid_payload_size}
    else
      <<version::8, iv::binary-size(@iv_size), encrypted_dek::binary-size(@encrypted_dek_size),
        tag::binary-size(@tag_size), rest::binary>> = payload

      if version != @version do
        {:error, {:unsupported_version, version}}
      else
        # Extract HMAC from end
        data_size = byte_size(rest) - @hmac_size
        <<encrypted_data::binary-size(data_size), hmac::binary-size(@hmac_size)>> = rest

        {:ok,
         %{
           version: version,
           iv: iv,
           encrypted_dek: encrypted_dek,
           tag: tag,
           encrypted_data: encrypted_data,
           hmac: hmac
         }}
      end
    end
  end

  defp build_metadata(dek, opts) do
    dek_id = Base.encode16(:crypto.hash(:sha256, dek), case: :lower)
    user_metadata = Keyword.get(opts, :metadata, %{})

    Map.merge(user_metadata, %{
      dek_id: dek_id,
      algorithm: "AES-256-GCM",
      version: @version,
      encrypted_at: DateTime.utc_now()
    })
  end
end
