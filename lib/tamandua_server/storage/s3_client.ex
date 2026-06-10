defmodule TamanduaServer.Storage.S3Client do
  @moduledoc """
  S3-compatible storage client for Tamandua.

  Supports AWS S3, MinIO, Wasabi, Cloudflare R2, and other S3-compatible services.
  All operations are async-safe and return tagged tuples.

  ## Configuration

  Configure in `config/config.exs`:

      config :tamandua_server, TamanduaServer.Storage.S3Client,
        bucket: "tamandua-artifacts",
        host: "s3.amazonaws.com",   # or "minio.local:9000" for MinIO
        scheme: "https://",
        port: "443"

  ## Usage

      # Upload a file
      {:ok, key} = S3Client.upload("models/v1/model.pt", binary_data)

      # Download a file
      {:ok, data} = S3Client.download("models/v1/model.pt")

      # Generate presigned URL for direct client upload
      {:ok, url} = S3Client.presigned_url("uploads/file.bin", :put, expires_in: 3600)
  """

  require Logger

  @doc """
  Upload binary data to S3.

  ## Options
  - `:content_type` - MIME type (default: "application/octet-stream")
  - `:metadata` - Map of custom metadata

  ## Returns
  - `{:ok, key}` - Upload successful
  - `{:error, {:upload_failed, reason}}` - Upload failed
  """
  def upload(key, data, opts \\ []) do
    bucket = get_bucket()
    content_type = Keyword.get(opts, :content_type, "application/octet-stream")
    metadata = Keyword.get(opts, :metadata, %{})

    bucket
    |> ExAws.S3.put_object(key, data, [
      content_type: content_type,
      meta: metadata
    ])
    |> request()
    |> case do
      {:ok, _} ->
        Logger.debug("S3 upload successful: #{key}")
        {:ok, key}

      {:error, reason} ->
        Logger.error("S3 upload failed for #{key}: #{inspect(reason)}")
        {:error, {:upload_failed, reason}}
    end
  end

  @doc """
  Download object from S3.

  ## Returns
  - `{:ok, binary}` - File content
  - `{:error, :not_found}` - Object does not exist
  - `{:error, {:download_failed, reason}}` - Download failed
  """
  def download(key, _opts \\ []) do
    bucket = get_bucket()

    bucket
    |> ExAws.S3.get_object(key)
    |> request()
    |> case do
      {:ok, %{body: body}} ->
        {:ok, body}

      {:error, {:http_error, 404, _}} ->
        {:error, :not_found}

      {:error, {:http_error, 403, _}} ->
        {:error, :access_denied}

      {:error, reason} ->
        Logger.error("S3 download failed for #{key}: #{inspect(reason)}")
        {:error, {:download_failed, reason}}
    end
  end

  @doc """
  Delete object from S3.

  ## Returns
  - `:ok` - Deletion successful (or object didn't exist)
  - `{:error, {:delete_failed, reason}}` - Deletion failed
  """
  def delete(key, _opts \\ []) do
    bucket = get_bucket()

    bucket
    |> ExAws.S3.delete_object(key)
    |> request()
    |> case do
      {:ok, _} ->
        Logger.debug("S3 delete successful: #{key}")
        :ok

      {:error, reason} ->
        Logger.error("S3 delete failed for #{key}: #{inspect(reason)}")
        {:error, {:delete_failed, reason}}
    end
  end

  @doc """
  Generate presigned URL for direct upload/download.

  ## Parameters
  - `key` - Object key
  - `method` - `:get` or `:put`
  - `opts` - Options:
    - `:expires_in` - URL validity in seconds (default: 3600)

  ## Returns
  - `{:ok, url}` - Presigned URL
  - `{:error, reason}` - Failed to generate URL
  """
  def presigned_url(key, method \\ :get, opts \\ []) do
    bucket = get_bucket()
    expires_in = Keyword.get(opts, :expires_in, 3600)

    config = ExAws.Config.new(:s3, build_config())

    case method do
      :get -> ExAws.S3.presigned_url(config, :get, bucket, key, expires_in: expires_in)
      :put -> ExAws.S3.presigned_url(config, :put, bucket, key, expires_in: expires_in)
    end
  end

  @doc """
  Check if object exists in S3.

  ## Returns
  - `true` - Object exists
  - `false` - Object does not exist or error occurred
  """
  def exists?(key) do
    bucket = get_bucket()

    bucket
    |> ExAws.S3.head_object(key)
    |> request()
    |> case do
      {:ok, _} -> true
      {:error, _} -> false
    end
  end

  @doc """
  List objects with prefix.

  ## Options
  - `:max_keys` - Maximum number of keys to return (default: 1000)
  - `:continuation_token` - Token for pagination

  ## Returns
  - `{:ok, [key]}` - List of object keys
  - `{:error, {:list_failed, reason}}` - Failed to list objects
  """
  def list(prefix, opts \\ []) do
    bucket = get_bucket()
    max_keys = Keyword.get(opts, :max_keys, 1000)

    bucket
    |> ExAws.S3.list_objects(prefix: prefix, max_keys: max_keys)
    |> request()
    |> case do
      {:ok, %{body: %{contents: contents}}} when is_list(contents) ->
        {:ok, Enum.map(contents, & &1.key)}

      {:ok, %{body: %{contents: nil}}} ->
        {:ok, []}

      {:ok, %{body: _}} ->
        {:ok, []}

      {:error, reason} ->
        Logger.error("S3 list failed for prefix #{prefix}: #{inspect(reason)}")
        {:error, {:list_failed, reason}}
    end
  end

  @doc """
  Get object metadata (head object).

  ## Returns
  - `{:ok, %{content_length: int, content_type: string, metadata: map}}`
  - `{:error, :not_found}`
  - `{:error, reason}`
  """
  def head(key) do
    bucket = get_bucket()

    bucket
    |> ExAws.S3.head_object(key)
    |> request()
    |> case do
      {:ok, %{headers: headers}} ->
        {:ok, parse_headers(headers)}

      {:error, {:http_error, 404, _}} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Copy object within the same bucket.

  ## Returns
  - `{:ok, dest_key}` - Copy successful
  - `{:error, reason}` - Copy failed
  """
  def copy(source_key, dest_key, opts \\ []) do
    bucket = get_bucket()

    bucket
    |> ExAws.S3.put_object_copy(dest_key, bucket, source_key, Keyword.get(opts, :copy_opts, []))
    |> request()
    |> case do
      {:ok, _} -> {:ok, dest_key}
      {:error, reason} -> {:error, {:copy_failed, reason}}
    end
  end

  @doc """
  Delete multiple objects at once.

  ## Returns
  - `{:ok, deleted_count}` - Number of objects deleted
  - `{:error, reason}` - Deletion failed
  """
  def delete_multiple(keys) when is_list(keys) do
    bucket = get_bucket()

    bucket
    |> ExAws.S3.delete_multiple_objects(Enum.map(keys, &%{key: &1}))
    |> request()
    |> case do
      {:ok, _} -> {:ok, length(keys)}
      {:error, reason} -> {:error, {:delete_failed, reason}}
    end
  end

  # ===========================================================================
  # Private Helpers
  # ===========================================================================

  defp get_bucket do
    Application.get_env(:tamandua_server, __MODULE__)[:bucket] || "tamandua-artifacts"
  end

  defp build_config do
    config = Application.get_env(:tamandua_server, __MODULE__, [])

    base = []

    base =
      if host = config[:host] do
        [{:host, host} | base]
      else
        base
      end

    base =
      if scheme = config[:scheme] do
        [{:scheme, scheme} | base]
      else
        base
      end

    base =
      if port = config[:port] do
        port_int =
          case port do
            p when is_binary(p) -> String.to_integer(p)
            p when is_integer(p) -> p
          end

        [{:port, port_int} | base]
      else
        base
      end

    base
  end

  defp request(operation) do
    config = build_config()
    ExAws.request(operation, config)
  end

  defp parse_headers(headers) do
    headers_map = Enum.into(headers, %{}, fn {k, v} -> {String.downcase(k), v} end)

    %{
      content_length: headers_map["content-length"] |> parse_content_length(),
      content_type: headers_map["content-type"],
      etag: headers_map["etag"],
      last_modified: headers_map["last-modified"],
      metadata: extract_metadata(headers_map)
    }
  end

  defp parse_content_length(nil), do: nil
  defp parse_content_length(str) when is_binary(str) do
    case Integer.parse(str) do
      {int, _} -> int
      :error -> nil
    end
  end
  defp parse_content_length(int) when is_integer(int), do: int

  defp extract_metadata(headers) do
    headers
    |> Enum.filter(fn {k, _} -> String.starts_with?(k, "x-amz-meta-") end)
    |> Enum.into(%{}, fn {k, v} ->
      key = String.replace_prefix(k, "x-amz-meta-", "")
      {key, v}
    end)
  end
end
