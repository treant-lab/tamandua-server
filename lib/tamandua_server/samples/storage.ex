defmodule TamanduaServer.Samples.Storage do
  @moduledoc """
  File storage for binary samples.

  Stores samples on disk organized by date and first 2 characters of the SHA256 hash.
  This provides good distribution and makes cleanup by date easy.

  Directory structure:
    {base_path}/
      2026/
        01/
          28/
            ab/
              abcdef123456...sha256.bin.gz
            cd/
              cdef789012...sha256.bin.gz
  """

  require Logger

  @default_base_path "priv/samples"
  @max_sample_size 100 * 1024 * 1024  # 100 MB max

  @doc """
  Returns the configured base path for sample storage.
  """
  def base_path do
    Application.get_env(:tamandua_server, :sample_storage_path, @default_base_path)
  end

  @doc """
  Store a sample on disk.

  ## Parameters
  - sha256: The SHA256 hash of the sample (hex string)
  - content: The binary content (raw or gzip compressed)
  - opts: Options
    - :compressed - if true, content is already gzip compressed (default: false)
    - :date - date to use for path (default: today)

  ## Returns
  - {:ok, stored_path} on success
  - {:error, reason} on failure
  """
  @spec store(String.t(), binary(), keyword()) :: {:ok, String.t()} | {:error, term()}
  def store(sha256, content, opts \\ []) do
    sha256 = String.downcase(sha256)
    compressed = Keyword.get(opts, :compressed, false)
    date = Keyword.get(opts, :date, Date.utc_today())

    # Validate hash format
    with :ok <- validate_sha256(sha256),
         :ok <- validate_size(content),
         {:ok, dir_path} <- ensure_directory(sha256, date),
         {:ok, file_path} <- write_sample(dir_path, sha256, content, compressed) do
      {:ok, file_path}
    end
  end

  @doc """
  Read a sample from disk.

  ## Parameters
  - stored_path: The path returned from store/3

  ## Returns
  - {:ok, content} with decompressed content
  - {:error, reason} on failure
  """
  @spec read(String.t()) :: {:ok, binary()} | {:error, term()}
  def read(stored_path) do
    case File.read(stored_path) do
      {:ok, compressed} ->
        {:ok, decompress(compressed)}

      {:error, reason} ->
        Logger.error("Failed to read sample from #{stored_path}: #{inspect(reason)}")
        {:error, {:read_failed, reason}}
    end
  end

  @doc """
  Check if a sample exists on disk.
  """
  @spec exists?(String.t()) :: boolean()
  def exists?(stored_path) when is_binary(stored_path) do
    File.exists?(stored_path)
  end

  def exists?(_), do: false

  @doc """
  Delete a sample from disk.
  """
  @spec delete(String.t()) :: :ok | {:error, term()}
  def delete(stored_path) do
    case File.rm(stored_path) do
      :ok ->
        # Try to clean up empty parent directories
        cleanup_empty_dirs(Path.dirname(stored_path))
        :ok

      {:error, reason} ->
        Logger.warning("Failed to delete sample #{stored_path}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Calculate the expected storage path for a SHA256 hash and date.
  """
  @spec expected_path(String.t(), Date.t()) :: String.t()
  def expected_path(sha256, date \\ Date.utc_today()) do
    sha256 = String.downcase(sha256)
    prefix = String.slice(sha256, 0, 2)

    Path.join([
      base_path(),
      Integer.to_string(date.year),
      date.month |> Integer.to_string() |> String.pad_leading(2, "0"),
      date.day |> Integer.to_string() |> String.pad_leading(2, "0"),
      prefix,
      "#{sha256}.bin.gz"
    ])
  end

  @doc """
  List all samples stored for a given date.
  """
  @spec list_by_date(Date.t()) :: {:ok, [String.t()]} | {:error, term()}
  def list_by_date(date) do
    date_path = Path.join([
      base_path(),
      Integer.to_string(date.year),
      date.month |> Integer.to_string() |> String.pad_leading(2, "0"),
      date.day |> Integer.to_string() |> String.pad_leading(2, "0")
    ])

    if File.dir?(date_path) do
      files =
        date_path
        |> File.ls!()
        |> Enum.flat_map(fn prefix_dir ->
          prefix_path = Path.join(date_path, prefix_dir)
          if File.dir?(prefix_path) do
            prefix_path
            |> File.ls!()
            |> Enum.map(&Path.join(prefix_path, &1))
          else
            []
          end
        end)

      {:ok, files}
    else
      {:ok, []}
    end
  end

  @doc """
  Get storage statistics.
  """
  @spec stats() :: map()
  def stats do
    path = base_path()

    if File.dir?(path) do
      {count, total_size} = count_files_and_size(path)
      %{
        base_path: path,
        sample_count: count,
        total_size_bytes: total_size,
        total_size_human: humanize_bytes(total_size)
      }
    else
      %{
        base_path: path,
        sample_count: 0,
        total_size_bytes: 0,
        total_size_human: "0 B"
      }
    end
  end

  # Private functions

  defp validate_sha256(sha256) when byte_size(sha256) == 64 do
    if Regex.match?(~r/^[a-f0-9]{64}$/i, sha256) do
      :ok
    else
      {:error, :invalid_sha256_format}
    end
  end

  defp validate_sha256(_), do: {:error, :invalid_sha256_length}

  defp validate_size(content) when byte_size(content) <= @max_sample_size, do: :ok
  defp validate_size(_), do: {:error, :sample_too_large}

  defp ensure_directory(sha256, date) do
    prefix = String.slice(sha256, 0, 2)

    dir_path = Path.join([
      base_path(),
      Integer.to_string(date.year),
      date.month |> Integer.to_string() |> String.pad_leading(2, "0"),
      date.day |> Integer.to_string() |> String.pad_leading(2, "0"),
      prefix
    ])

    case File.mkdir_p(dir_path) do
      :ok -> {:ok, dir_path}
      {:error, reason} ->
        Logger.error("Failed to create sample directory #{dir_path}: #{inspect(reason)}")
        {:error, {:mkdir_failed, reason}}
    end
  end

  defp write_sample(dir_path, sha256, content, compressed) do
    file_path = Path.join(dir_path, "#{sha256}.bin.gz")

    # Compress if not already compressed
    data = if compressed, do: content, else: compress(content)

    case File.write(file_path, data) do
      :ok ->
        Logger.debug("Stored sample #{sha256} at #{file_path}")
        {:ok, file_path}

      {:error, reason} ->
        Logger.error("Failed to write sample #{sha256}: #{inspect(reason)}")
        {:error, {:write_failed, reason}}
    end
  end

  defp compress(content) do
    :zlib.gzip(content)
  end

  defp decompress(content) do
    :zlib.gunzip(content)
  rescue
    _ -> content  # Return as-is if not compressed
  end

  defp cleanup_empty_dirs(path) do
    base = base_path()

    # Don't go above base path
    if String.starts_with?(path, base) and path != base do
      case File.ls(path) do
        {:ok, []} ->
          File.rmdir(path)
          cleanup_empty_dirs(Path.dirname(path))

        _ ->
          :ok
      end
    end
  end

  defp count_files_and_size(path) do
    case File.ls(path) do
      {:ok, entries} ->
        Enum.reduce(entries, {0, 0}, fn entry, {count, size} ->
          full_path = Path.join(path, entry)

          cond do
            File.dir?(full_path) ->
              {sub_count, sub_size} = count_files_and_size(full_path)
              {count + sub_count, size + sub_size}

            String.ends_with?(entry, ".bin.gz") ->
              file_size = case File.stat(full_path) do
                {:ok, %{size: s}} -> s
                _ -> 0
              end
              {count + 1, size + file_size}

            true ->
              {count, size}
          end
        end)

      {:error, _} ->
        {0, 0}
    end
  end

  defp humanize_bytes(bytes) when bytes < 1024, do: "#{bytes} B"
  defp humanize_bytes(bytes) when bytes < 1024 * 1024 do
    "#{Float.round(bytes / 1024, 1)} KB"
  end
  defp humanize_bytes(bytes) when bytes < 1024 * 1024 * 1024 do
    "#{Float.round(bytes / (1024 * 1024), 1)} MB"
  end
  defp humanize_bytes(bytes) do
    "#{Float.round(bytes / (1024 * 1024 * 1024), 2)} GB"
  end
end
