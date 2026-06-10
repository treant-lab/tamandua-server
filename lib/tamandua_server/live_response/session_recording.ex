defmodule TamanduaServer.LiveResponse.SessionRecording do
  @moduledoc """
  Handles compression, encryption, credential scrubbing, and retention
  for live response session recordings.

  ## Storage Format

  Recordings are stored in asciicast v2 format (.cast), then:
  1. Credential patterns are scrubbed (best-effort redaction)
  2. Compressed with gzip (stream-compressed as data arrives)
  3. Optionally encrypted with AES-256-GCM

  The final file on disk has the structure:
  - Unencrypted: raw gzip data with `.cast.gz` extension
  - Encrypted:   `<<nonce::96-bits, tag::128-bits, ciphertext::binary>>` with `.cast.gz.enc` extension

  ## Configuration

      config :tamandua_server, TamanduaServer.LiveResponse.SessionRecording,
        recording_dir: "priv/live_response_recordings",
        encryption_key: System.get_env("TAMANDUA_RECORDING_KEY"),
        retention_days: 90

  If `encryption_key` is nil or not configured, recordings are stored
  compressed but unencrypted, and a warning is logged at startup.
  """

  require Logger

  @recording_dir Application.compile_env(
                   :tamandua_server,
                   [__MODULE__, :recording_dir],
                   "priv/live_response_recordings"
                 )

  @default_retention_days 90

  # AES-256-GCM nonce size in bytes
  @nonce_size 12
  # AES-256-GCM tag size in bytes
  @tag_size 16

  # ============================================================================
  # Credential Scrubbing Patterns
  # ============================================================================

  # AWS Access Key IDs (AKIA followed by 16 alphanumeric characters)
  @aws_key_pattern ~r/(AKIA[0-9A-Z]{16})/

  # AWS Secret Access Keys (40 character base64-ish strings after known prefixes)
  @aws_secret_pattern ~r/((?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|SecretAccessKey)\s*[=:]\s*)([A-Za-z0-9\/+=]{40})/

  # Bearer tokens
  @bearer_pattern ~r/((?:Bearer|bearer|Authorization|authorization)[:\s]+)([A-Za-z0-9\-._~+\/]+=*)/

  # API tokens / keys in common formats
  @api_token_pattern ~r/((?:api[_-]?key|api[_-]?token|api[_-]?secret|token|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[=:]\s*["']?)([A-Za-z0-9\-._~+\/]{20,})/i

  # SSH private key blocks
  @ssh_key_pattern ~r/(-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----)([\s\S]*?)(-----END (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----)/

  # Password prompts followed by input (common sudo/su/ssh patterns)
  # Matches: "Password:" or "password:" followed by non-newline characters up to \r or \n
  @password_prompt_pattern ~r/((?:[Pp]assword|PASSW(?:OR)?D|passwd|pass)\s*:\s*)((?:(?!\r|\n).)+)/

  # Generic secret/password assignment patterns
  @secret_assignment_pattern ~r/((?:password|passwd|secret|credential)\s*[=:]\s*["']?)([^\s"'\r\n]{4,})/i

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Initialize a new recording session. Creates the recording directory,
  writes the asciicast v2 header, and returns a recording state map.

  The state map should be stored in the channel's socket assigns and
  passed to `append_event/3` and `finalize/1`.
  """
  @spec init(String.t(), String.t(), String.t() | integer()) :: map()
  def init(session_id, agent_id, user_id) do
    recording_dir = Path.join([@recording_dir, Date.to_string(Date.utc_today())])
    File.mkdir_p!(recording_dir)

    base_filename = "#{session_id}_#{agent_id}_#{user_id}"
    started_at = DateTime.utc_now()

    # Determine file extension based on whether encryption is available
    {extension, encrypted?} =
      case get_encryption_key() do
        nil -> {".cast.gz", false}
        _key -> {".cast.gz.enc", true}
      end

    path = Path.join(recording_dir, base_filename <> extension)

    # Write asciicast v2 header
    header =
      Jason.encode!(%{
        version: 2,
        width: 120,
        height: 40,
        timestamp: DateTime.to_unix(started_at),
        title: "Live Response Session - Agent #{agent_id}",
        env: %{
          SHELL: "/bin/bash",
          TERM: "xterm-256color"
        }
      })

    # Initialize the gzip stream (zlib deflate context)
    z = :zlib.open()
    :zlib.deflateInit(z, :default, :deflated, 31, 8, :default)

    # Compress the header line
    compressed_chunk = :zlib.deflate(z, header <> "\n", :sync)

    # Write initial compressed chunk to file
    File.write!(path, IO.iodata_to_binary(compressed_chunk))

    expires_at = DateTime.add(started_at, retention_days() * 86400, :second)

    %{
      path: path,
      session_id: session_id,
      agent_id: agent_id,
      user_id: user_id,
      started_at: started_at,
      encrypted: encrypted?,
      z: z,
      content_type: "application/gzip",
      expires_at: expires_at,
      event_count: 0
    }
  end

  @doc """
  Append a recording event. The event data is scrubbed for credentials,
  compressed via the streaming gzip context, and appended to the file.

  `event_type` is either `"i"` (input) or `"o"` (output) per asciicast v2.
  """
  @spec append_event(map(), String.t(), String.t()) :: map()
  def append_event(state, event_type, data) when event_type in ["i", "o"] do
    timestamp =
      DateTime.diff(DateTime.utc_now(), state.started_at, :millisecond) / 1000

    # Scrub credentials from the data before recording
    scrubbed_data = scrub_credentials(data)

    event = Jason.encode!([timestamp, event_type, scrubbed_data])
    line = event <> "\n"

    # Stream-compress the line
    compressed_chunk = :zlib.deflate(state.z, line, :sync)
    chunk_binary = IO.iodata_to_binary(compressed_chunk)

    # Append to file
    if byte_size(chunk_binary) > 0 do
      File.write!(state.path, chunk_binary, [:append])
    end

    %{state | event_count: state.event_count + 1}
  end

  @doc """
  Finalize the recording. Flushes the gzip stream, closes the zlib context,
  and optionally encrypts the entire file.

  Returns `{:ok, metadata}` with recording metadata including path, size, etc.
  """
  @spec finalize(map()) :: {:ok, map()}
  def finalize(state) do
    # Write session end marker and close zlib — wrapped in try to handle
    # already-closed or corrupted contexts (e.g. if append_event crashed
    # mid-stream and the process is now cleaning up).
    try do
      timestamp =
        DateTime.diff(DateTime.utc_now(), state.started_at, :millisecond) / 1000

      end_event = Jason.encode!([timestamp, "o", "\r\n--- Session Ended ---\r\n"])
      end_line = end_event <> "\n"

      # Flush final data and finish the gzip stream
      final_chunks = :zlib.deflate(state.z, end_line, :finish)
      final_binary = IO.iodata_to_binary(final_chunks)

      if byte_size(final_binary) > 0 do
        File.write!(state.path, final_binary, [:append])
      end

      # Clean up zlib resources
      :zlib.deflateEnd(state.z)
      :zlib.close(state.z)
    rescue
      e ->
        Logger.warning(
          "Error finalizing gzip stream for recording #{state.session_id}: #{inspect(e)}. " <>
            "Recording may be truncated."
        )

        # Best-effort cleanup — close the zlib reference if still valid
        try do
          :zlib.close(state.z)
        rescue
          _ -> :ok
        end
    end

    # Now encrypt the file if encryption is enabled
    final_path =
      if state.encrypted do
        encrypt_file!(state.path)
      else
        state.path
      end

    file_size =
      case File.stat(final_path) do
        {:ok, %{size: size}} -> size
        _ -> 0
      end

    ended_at = DateTime.utc_now()
    duration_seconds = DateTime.diff(ended_at, state.started_at, :second)

    metadata = %{
      path: final_path,
      session_id: state.session_id,
      agent_id: state.agent_id,
      user_id: state.user_id,
      started_at: state.started_at,
      ended_at: ended_at,
      duration_seconds: duration_seconds,
      event_count: state.event_count,
      file_size: file_size,
      encrypted: state.encrypted,
      compressed: true,
      content_type: content_type_for(final_path),
      expires_at: state.expires_at
    }

    Logger.info(
      "Live response recording finalized: #{final_path} " <>
        "(#{file_size} bytes, #{state.event_count} events, " <>
        "encrypted=#{state.encrypted}, duration=#{duration_seconds}s)"
    )

    {:ok, metadata}
  end

  @doc """
  Read a recording for playback. Decrypts (if encrypted) and decompresses
  on-the-fly, returning the raw asciicast v2 content.

  Returns `{:ok, content}` or `{:error, reason}`.
  """
  @spec read_recording(String.t()) :: {:ok, binary()} | {:error, atom() | String.t()}
  def read_recording(path) do
    with {:ok, raw_data} <- File.read(path) do
      # Decrypt if the file has .enc extension
      data =
        if String.ends_with?(path, ".enc") do
          case decrypt_data(raw_data) do
            {:ok, decrypted} -> decrypted
            {:error, reason} -> throw({:decrypt_error, reason})
          end
        else
          raw_data
        end

      # Decompress gzip
      case safe_gunzip(data) do
        {:ok, decompressed} -> {:ok, decompressed}
        {:error, reason} -> {:error, "Decompression failed: #{inspect(reason)}"}
      end
    end
  catch
    {:decrypt_error, reason} -> {:error, "Decryption failed: #{inspect(reason)}"}
  end

  @doc """
  Delete a recording file from disk.
  """
  @spec delete_recording(String.t()) :: :ok | {:error, atom()}
  def delete_recording(path) do
    case File.rm(path) do
      :ok ->
        Logger.info("Deleted recording: #{path}")
        :ok

      {:error, reason} ->
        Logger.warning("Failed to delete recording #{path}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  List all recording files, returning their paths and metadata.
  Useful for the retention cleanup worker.
  """
  @spec list_recordings() :: [String.t()]
  def list_recordings do
    recording_dir = @recording_dir

    if File.dir?(recording_dir) do
      recording_dir
      |> File.ls!()
      |> Enum.flat_map(fn date_dir ->
        full_date_dir = Path.join(recording_dir, date_dir)

        if File.dir?(full_date_dir) do
          full_date_dir
          |> File.ls!()
          |> Enum.filter(fn f ->
            String.ends_with?(f, ".cast.gz") or String.ends_with?(f, ".cast.gz.enc")
          end)
          |> Enum.map(&Path.join(full_date_dir, &1))
        else
          []
        end
      end)
    else
      []
    end
  end

  @doc """
  Purge all recordings older than the given DateTime.
  Returns the count of deleted files.
  """
  @spec purge_expired(DateTime.t()) :: {:ok, non_neg_integer()}
  def purge_expired(cutoff \\ nil) do
    cutoff = cutoff || DateTime.add(DateTime.utc_now(), -retention_days() * 86400, :second)

    recordings = list_recordings()

    deleted_count =
      Enum.reduce(recordings, 0, fn path, acc ->
        case File.stat(path, time: :posix) do
          {:ok, %{mtime: mtime}} ->
            # mtime is in seconds since epoch for posix time
            file_time = DateTime.from_unix!(mtime)

            if DateTime.compare(file_time, cutoff) == :lt do
              delete_recording(path)
              acc + 1
            else
              acc
            end

          _ ->
            acc
        end
      end)

    # Clean up empty date directories
    cleanup_empty_dirs()

    Logger.info("Recording retention cleanup: deleted #{deleted_count} expired recordings")
    {:ok, deleted_count}
  end

  @doc """
  Immediately purge all recordings for a specific session.
  """
  @spec purge_session(String.t()) :: {:ok, non_neg_integer()}
  def purge_session(session_id) do
    recordings = list_recordings()

    deleted_count =
      recordings
      |> Enum.filter(&String.contains?(&1, session_id))
      |> Enum.reduce(0, fn path, acc ->
        delete_recording(path)
        acc + 1
      end)

    {:ok, deleted_count}
  end

  @doc """
  Check if encryption is configured and available. Logs a warning
  at startup if no encryption key is set.
  """
  @spec check_encryption_config() :: :ok
  def check_encryption_config do
    # Check the raw key directly (before derivation) for better diagnostics
    raw_key =
      System.get_env("TAMANDUA_RECORDING_KEY") ||
        (Application.get_env(:tamandua_server, __MODULE__, [])
         |> Keyword.get(:encryption_key))

    cond do
      is_nil(raw_key) or raw_key == "" ->
        Logger.warning(
          "[SessionRecording] No TAMANDUA_RECORDING_KEY configured. " <>
            "Recordings will be stored compressed but NOT encrypted. " <>
            "Set the TAMANDUA_RECORDING_KEY environment variable or " <>
            "configure :encryption_key in application config for encrypted storage."
        )

      is_binary(raw_key) and byte_size(raw_key) < 32 ->
        Logger.error(
          "[SessionRecording] TAMANDUA_RECORDING_KEY is too short " <>
            "(#{byte_size(raw_key)} bytes, need at least 32). " <>
            "Encryption will be disabled."
        )

      true ->
        Logger.info("[SessionRecording] Recording encryption is enabled (AES-256-GCM)")
    end

    :ok
  end

  @doc """
  Returns the configured retention period in days.
  """
  @spec retention_days() :: non_neg_integer()
  def retention_days do
    Application.get_env(:tamandua_server, __MODULE__, [])
    |> Keyword.get(:retention_days, @default_retention_days)
  end

  @doc """
  Returns the recording directory path.
  """
  @spec recording_dir() :: String.t()
  def recording_dir, do: @recording_dir

  # ============================================================================
  # Credential Scrubbing (Private)
  # ============================================================================

  @doc false
  def scrub_credentials(data) when is_binary(data) do
    data
    |> scrub_ssh_keys()
    |> scrub_aws_keys()
    |> scrub_aws_secrets()
    |> scrub_bearer_tokens()
    |> scrub_api_tokens()
    |> scrub_password_prompts()
    |> scrub_secret_assignments()
  end

  defp scrub_ssh_keys(data) do
    Regex.replace(@ssh_key_pattern, data, "\\1\n[REDACTED - SSH PRIVATE KEY]\n\\3")
  end

  defp scrub_aws_keys(data) do
    Regex.replace(@aws_key_pattern, data, "[REDACTED-AWS-KEY]")
  end

  defp scrub_aws_secrets(data) do
    Regex.replace(@aws_secret_pattern, data, "\\1[REDACTED]")
  end

  defp scrub_bearer_tokens(data) do
    Regex.replace(@bearer_pattern, data, "\\1[REDACTED]")
  end

  defp scrub_api_tokens(data) do
    Regex.replace(@api_token_pattern, data, "\\1[REDACTED]")
  end

  defp scrub_password_prompts(data) do
    Regex.replace(@password_prompt_pattern, data, "\\1[REDACTED]")
  end

  defp scrub_secret_assignments(data) do
    Regex.replace(@secret_assignment_pattern, data, "\\1[REDACTED]")
  end

  # ============================================================================
  # Encryption (Private)
  # ============================================================================

  defp get_encryption_key do
    # Check environment variable first, then application config
    env_key = System.get_env("TAMANDUA_RECORDING_KEY")

    config_key =
      Application.get_env(:tamandua_server, __MODULE__, [])
      |> Keyword.get(:encryption_key)

    raw_key = env_key || config_key

    case raw_key do
      nil ->
        nil

      key when is_binary(key) and byte_size(key) >= 32 ->
        # Use first 32 bytes as AES-256 key
        binary_part(derive_key(key), 0, 32)

      _short_key ->
        nil
    end
  end

  defp derive_key(secret) do
    # Use HKDF-like derivation: HMAC-SHA256 with a fixed salt
    :crypto.mac(:hmac, :sha256, "tamandua_recording_key_v1", secret)
  end

  defp encrypt_file!(path) do
    key = get_encryption_key()

    unless key do
      raise "Encryption key not available but encrypted recording was requested"
    end

    # Read the compressed data
    compressed_data = File.read!(path)

    # Generate a random nonce
    nonce = :crypto.strong_rand_bytes(@nonce_size)

    # Encrypt with AES-256-GCM
    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(
        :aes_256_gcm,
        key,
        nonce,
        compressed_data,
        _aad = "tamandua_recording",
        _tag_length = @tag_size,
        true
      )

    # Write: nonce || tag || ciphertext
    encrypted_data = nonce <> tag <> ciphertext
    File.write!(path, encrypted_data)

    path
  end

  defp decrypt_data(encrypted_data) do
    key = get_encryption_key()

    unless key do
      {:error, :no_encryption_key}
    else
      if byte_size(encrypted_data) < @nonce_size + @tag_size do
        {:error, :invalid_encrypted_data}
      else
        <<nonce::binary-size(@nonce_size), tag::binary-size(@tag_size),
          ciphertext::binary>> = encrypted_data

        case :crypto.crypto_one_time_aead(
               :aes_256_gcm,
               key,
               nonce,
               ciphertext,
               _aad = "tamandua_recording",
               tag,
               false
             ) do
          :error ->
            {:error, :decryption_failed}

          plaintext ->
            {:ok, plaintext}
        end
      end
    end
  end

  # ============================================================================
  # Compression Helpers (Private)
  # ============================================================================

  defp safe_gunzip(data) do
    {:ok, :zlib.gunzip(data)}
  rescue
    e -> {:error, e}
  end

  # ============================================================================
  # File Helpers (Private)
  # ============================================================================

  defp content_type_for(path) do
    cond do
      String.ends_with?(path, ".cast.gz.enc") -> "application/octet-stream"
      String.ends_with?(path, ".cast.gz") -> "application/gzip"
      true -> "application/octet-stream"
    end
  end

  defp cleanup_empty_dirs do
    recording_dir = @recording_dir

    if File.dir?(recording_dir) do
      recording_dir
      |> File.ls!()
      |> Enum.each(fn entry ->
        full_path = Path.join(recording_dir, entry)

        if File.dir?(full_path) do
          case File.ls(full_path) do
            {:ok, []} -> File.rmdir(full_path)
            _ -> :ok
          end
        end
      end)
    end
  end
end
