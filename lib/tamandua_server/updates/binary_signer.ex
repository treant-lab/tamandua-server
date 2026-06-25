defmodule Tamandua.Updates.BinarySigner do
  @moduledoc """
  Ed25519 binary signing and verification for agent updates.

  Provides cryptographic signing of update binaries to ensure authenticity and integrity.
  Uses Ed25519 for fast, secure signatures.
  """

  require Logger

  @type public_key :: binary()
  @type private_key :: binary()
  @type signature :: binary()

  # Ed25519 key and signature lengths
  @public_key_length 32
  @private_key_length 64
  @signature_length 64

  @doc """
  Generate a new Ed25519 keypair for signing.

  Returns {public_key, private_key} as Base64-encoded strings.
  """
  @spec generate_keypair() :: {String.t(), String.t()}
  def generate_keypair do
    {public_key, private_key} = :crypto.generate_key(:eddsa, :ed25519)

    {
      Base.encode64(public_key),
      Base.encode64(private_key)
    }
  end

  @doc """
  Sign a binary file with Ed25519 private key.

  Returns Base64-encoded signature.
  """
  @spec sign_file(Path.t(), String.t()) :: {:ok, String.t()} | {:error, term()}
  def sign_file(file_path, private_key_b64) do
    with {:ok, private_key} <- decode_private_key(private_key_b64),
         {:ok, file_data} <- File.read(file_path) do
      signature = do_sign_data(file_data, private_key)
      {:ok, Base.encode64(signature)}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Sign binary data with Ed25519 private key.

  Returns Base64-encoded signature.
  """
  @spec sign_data(binary(), String.t()) :: {:ok, String.t()} | {:error, term()}
  def sign_data(data, private_key_b64) when is_binary(data) do
    with {:ok, private_key} <- decode_private_key(private_key_b64) do
      signature = do_sign_data(data, private_key)
      {:ok, Base.encode64(signature)}
    end
  end

  @doc """
  Verify a signature for a file.

  Returns :ok if signature is valid, {:error, :invalid_signature} otherwise.
  """
  @spec verify_file(Path.t(), String.t(), String.t()) :: :ok | {:error, term()}
  def verify_file(file_path, signature_b64, public_key_b64) do
    with {:ok, public_key} <- decode_public_key(public_key_b64),
         {:ok, signature} <- decode_signature(signature_b64),
         {:ok, file_data} <- File.read(file_path) do
      verify_data(file_data, signature, public_key)
    else
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Verify a signature for binary data.

  Returns :ok if signature is valid, {:error, :invalid_signature} otherwise.
  """
  @spec verify_data(binary(), String.t(), String.t()) :: :ok | {:error, term()}
  def verify_data(data, signature_b64, public_key_b64) when is_binary(data) do
    with {:ok, public_key} <- decode_public_key(public_key_b64),
         {:ok, signature} <- decode_signature(signature_b64) do
      do_verify_data(data, signature, public_key)
    end
  end

  @doc """
  Compute SHA256 checksum of a file.

  Returns Base64-encoded checksum.
  """
  @spec checksum_file(Path.t()) :: {:ok, String.t()} | {:error, term()}
  def checksum_file(file_path) do
    case File.read(file_path) do
      {:ok, data} ->
        checksum = :crypto.hash(:sha256, data)
        {:ok, Base.encode64(checksum)}
      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Verify file checksum matches expected value.
  """
  @spec verify_checksum(Path.t(), String.t()) :: :ok | {:error, term()}
  def verify_checksum(file_path, expected_checksum_b64) do
    with {:ok, actual_checksum_b64} <- checksum_file(file_path) do
      if actual_checksum_b64 == expected_checksum_b64 do
        :ok
      else
        {:error, :checksum_mismatch}
      end
    end
  end

  @doc """
  Load public key from environment or config.

  Looks for TAMANDUA_UPDATE_PUBLIC_KEY environment variable.
  """
  @spec get_public_key() :: {:ok, String.t()} | {:error, :not_configured}
  def get_public_key do
    case System.get_env("TAMANDUA_UPDATE_PUBLIC_KEY") do
      nil ->
        case Application.get_env(:tamandua_server, :update_public_key) do
          nil -> {:error, :not_configured}
          key -> {:ok, key}
        end
      key -> {:ok, key}
    end
  end

  @doc """
  Load private key from environment or config.

  Looks for TAMANDUA_UPDATE_PRIVATE_KEY environment variable.
  WARNING: Keep this secure! Never commit to version control.
  """
  @spec get_private_key() :: {:ok, String.t()} | {:error, :not_configured}
  def get_private_key do
    case System.get_env("TAMANDUA_UPDATE_PRIVATE_KEY") do
      nil ->
        case Application.get_env(:tamandua_server, :update_private_key) do
          nil -> {:error, :not_configured}
          key -> {:ok, key}
        end
      key -> {:ok, key}
    end
  end

  @doc """
  Create a signed manifest for an update binary.

  Returns manifest with checksum and signature.
  """
  @spec create_signed_manifest(Path.t(), map()) :: {:ok, map()} | {:error, term()}
  def create_signed_manifest(binary_path, base_manifest) do
    with {:ok, private_key} <- get_private_key(),
         {:ok, checksum} <- checksum_file(binary_path),
         {:ok, signature} <- sign_file(binary_path, private_key),
         {:ok, stat} <- File.stat(binary_path) do

      manifest = Map.merge(base_manifest, %{
        checksum_sha256: checksum,
        signature_ed25519: signature,
        size_bytes: stat.size,
        signed_at: DateTime.utc_now()
      })

      {:ok, manifest}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Verify a complete manifest (checksum + signature).
  """
  @spec verify_manifest(Path.t(), map()) :: :ok | {:error, term()}
  def verify_manifest(binary_path, manifest) do
    with {:ok, public_key} <- get_public_key(),
         :ok <- verify_checksum(binary_path, manifest.checksum_sha256),
         :ok <- verify_file(binary_path, manifest.signature_ed25519, public_key) do
      :ok
    else
      {:error, reason} ->
        Logger.error("Manifest verification failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  # Private Helpers

  defp do_sign_data(data, private_key) when is_binary(private_key) do
    :crypto.sign(:eddsa, :sha512, data, [private_key, :ed25519])
  end

  defp do_verify_data(data, signature, public_key) when is_binary(signature) and is_binary(public_key) do
    case :crypto.verify(:eddsa, :sha512, data, signature, [public_key, :ed25519]) do
      true -> :ok
      false -> {:error, :invalid_signature}
    end
  end

  defp decode_public_key(public_key_b64) do
    case Base.decode64(public_key_b64) do
      {:ok, key} when byte_size(key) == @public_key_length -> {:ok, key}
      {:ok, _} -> {:error, :invalid_public_key_length}
      :error -> {:error, :invalid_base64}
    end
  end

  defp decode_private_key(private_key_b64) do
    case Base.decode64(private_key_b64) do
      {:ok, key} when byte_size(key) == @private_key_length -> {:ok, key}
      {:ok, _} -> {:error, :invalid_private_key_length}
      :error -> {:error, :invalid_base64}
    end
  end

  defp decode_signature(signature_b64) do
    case Base.decode64(signature_b64) do
      {:ok, sig} when byte_size(sig) == @signature_length -> {:ok, sig}
      {:ok, _} -> {:error, :invalid_signature_length}
      :error -> {:error, :invalid_base64}
    end
  end
end
