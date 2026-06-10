defmodule TamanduaServer.Storage.ModelArtifacts do
  @moduledoc """
  Tenant-scoped model artifact storage.

  All model artifacts are stored with tenant isolation via bucket prefix:
  `tenants/{org_id}/models/{model_id}/{filename}`

  This ensures:
  - Tenant data isolation (different prefixes)
  - Easy cleanup on tenant deletion (delete prefix)
  - Consistent path structure for auditing

  ## Supported Model Formats

  - PyTorch (.pt, .pth)
  - ONNX (.onnx)
  - SafeTensors (.safetensors)
  - GGUF (.gguf)
  - Pickle (.pkl)
  - JSON configs (.json)

  ## Usage

      # Store a model file
      {:ok, info} = ModelArtifacts.store_model(org_id, "model-v1", upload)

      # Retrieve a model file
      {:ok, binary} = ModelArtifacts.get_model(org_id, "model-v1", "model.pt")

      # List all models for a tenant
      {:ok, models} = ModelArtifacts.list_models(org_id)

      # Generate presigned URL for direct download
      {:ok, url} = ModelArtifacts.presigned_url(org_id, "model-v1", "model.pt")
  """

  alias TamanduaServer.Storage.S3Client
  require Logger

  @doc """
  Store a model artifact for a tenant.

  ## Parameters
  - `org_id` - Organization UUID
  - `model_id` - Model identifier (UUID or name-version)
  - `file` - One of:
    - `%Plug.Upload{}` - File upload from Phoenix controller
    - `{:binary, data, filename}` - Binary data with filename
    - `{:path, filepath}` - Path to file on disk

  ## Returns
  - `{:ok, %{key: key, size: size, filename: filename}}` - Upload successful
  - `{:error, reason}` - Upload failed

  ## Example

      {:ok, info} = ModelArtifacts.store_model(
        "org-123",
        "malware-smell-v1",
        %Plug.Upload{path: "/tmp/model.pt", filename: "model.pt"}
      )
  """
  def store_model(org_id, model_id, file) do
    {data, filename, content_type} = extract_file_data(file)
    key = build_key(org_id, model_id, filename)
    size = byte_size(data)

    metadata = %{
      "organization_id" => org_id,
      "model_id" => model_id,
      "original_filename" => filename,
      "uploaded_at" => DateTime.utc_now() |> DateTime.to_iso8601()
    }

    case S3Client.upload(key, data, content_type: content_type, metadata: metadata) do
      {:ok, _} ->
        Logger.info("Stored model artifact: #{key} (#{size} bytes)")
        {:ok, %{key: key, size: size, filename: filename}}

      {:error, reason} ->
        Logger.error("Failed to store model artifact: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Get a model artifact for a tenant.

  ## Returns
  - `{:ok, binary}` - File content
  - `{:error, :not_found}` - Model artifact not found
  - `{:error, reason}` - Download failed
  """
  def get_model(org_id, model_id, filename) do
    key = build_key(org_id, model_id, filename)
    S3Client.download(key)
  end

  @doc """
  Check if a model artifact exists.

  ## Returns
  - `true` - Artifact exists
  - `false` - Artifact does not exist
  """
  def model_exists?(org_id, model_id, filename) do
    key = build_key(org_id, model_id, filename)
    S3Client.exists?(key)
  end

  @doc """
  Get metadata for a model artifact.

  ## Returns
  - `{:ok, %{content_length: int, content_type: string, ...}}`
  - `{:error, :not_found}`
  """
  def get_model_metadata(org_id, model_id, filename) do
    key = build_key(org_id, model_id, filename)
    S3Client.head(key)
  end

  @doc """
  List all model artifacts for a tenant.

  ## Options
  - `:max_keys` - Maximum number of results (default: 1000)

  ## Returns
  - `{:ok, [%{model_id: string, files: [string]}]}`
  - `{:error, reason}`
  """
  def list_models(org_id, opts \\ []) do
    prefix = "tenants/#{org_id}/models/"

    case S3Client.list(prefix, opts) do
      {:ok, keys} ->
        models =
          keys
          |> Enum.map(&parse_key/1)
          |> Enum.reject(&is_nil/1)
          |> Enum.group_by(& &1.model_id)
          |> Enum.map(fn {model_id, files} ->
            %{
              model_id: model_id,
              files: Enum.map(files, & &1.filename),
              file_count: length(files)
            }
          end)
          |> Enum.sort_by(& &1.model_id)

        {:ok, models}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  List files for a specific model.

  ## Returns
  - `{:ok, [filename]}` - List of file names
  - `{:error, reason}`
  """
  def list_model_files(org_id, model_id, opts \\ []) do
    prefix = "tenants/#{org_id}/models/#{model_id}/"

    case S3Client.list(prefix, opts) do
      {:ok, keys} ->
        files =
          keys
          |> Enum.map(&Path.basename/1)
          |> Enum.reject(&(&1 == ""))

        {:ok, files}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Delete a model artifact or all artifacts for a model.

  ## Parameters
  - `org_id` - Organization UUID
  - `model_id` - Model identifier
  - `filename` - Optional. If nil, deletes all files for the model.

  ## Returns
  - `:ok` - Deletion successful
  - `{:error, reason}` - Deletion failed
  """
  def delete_model(org_id, model_id, filename \\ nil) do
    if filename do
      key = build_key(org_id, model_id, filename)
      S3Client.delete(key)
    else
      # Delete all files for this model
      prefix = "tenants/#{org_id}/models/#{model_id}/"

      case S3Client.list(prefix) do
        {:ok, []} ->
          :ok

        {:ok, keys} ->
          case S3Client.delete_multiple(keys) do
            {:ok, _count} -> :ok
            {:error, reason} -> {:error, reason}
          end

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  @doc """
  Generate a presigned URL for direct upload/download.

  ## Parameters
  - `org_id` - Organization UUID
  - `model_id` - Model identifier
  - `filename` - File name
  - `method` - `:get` or `:put` (default: `:get`)
  - `opts` - Options:
    - `:expires_in` - URL validity in seconds (default: 3600)

  ## Returns
  - `{:ok, url}` - Presigned URL
  - `{:error, reason}`
  """
  def presigned_url(org_id, model_id, filename, method \\ :get, opts \\ []) do
    key = build_key(org_id, model_id, filename)
    S3Client.presigned_url(key, method, opts)
  end

  @doc """
  Delete all artifacts for a tenant (used on tenant deletion).

  This removes all stored data for the organization including:
  - Model artifacts
  - Training data
  - Any other tenant-scoped storage

  ## Returns
  - `:ok` - Deletion successful
  - `{:error, reason}` - Deletion failed
  """
  def delete_tenant_artifacts(org_id) do
    prefix = "tenants/#{org_id}/"

    case S3Client.list(prefix, max_keys: 10_000) do
      {:ok, []} ->
        Logger.info("No artifacts to delete for tenant #{org_id}")
        :ok

      {:ok, keys} ->
        Logger.info("Deleting #{length(keys)} artifacts for tenant #{org_id}")

        case S3Client.delete_multiple(keys) do
          {:ok, count} ->
            Logger.info("Deleted #{count} artifacts for tenant #{org_id}")
            :ok

          {:error, reason} ->
            Logger.error("Failed to delete artifacts for tenant #{org_id}: #{inspect(reason)}")
            {:error, reason}
        end

      {:error, reason} ->
        Logger.error("Failed to list artifacts for tenant #{org_id}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Copy a model to a new model ID (for versioning).

  ## Returns
  - `{:ok, new_key}` - Copy successful
  - `{:error, reason}` - Copy failed
  """
  def copy_model(org_id, source_model_id, dest_model_id, filename) do
    source_key = build_key(org_id, source_model_id, filename)
    dest_key = build_key(org_id, dest_model_id, filename)
    S3Client.copy(source_key, dest_key)
  end

  @doc """
  Get total storage used by a tenant.

  ## Returns
  - `{:ok, bytes}` - Total bytes used
  - `{:error, reason}`
  """
  def get_tenant_storage_usage(org_id) do
    prefix = "tenants/#{org_id}/"

    case S3Client.list(prefix, max_keys: 10_000) do
      {:ok, keys} ->
        total_bytes =
          keys
          |> Enum.map(fn key ->
            case S3Client.head(key) do
              {:ok, %{content_length: size}} when is_integer(size) -> size
              _ -> 0
            end
          end)
          |> Enum.sum()

        {:ok, total_bytes}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # ===========================================================================
  # Private Helpers
  # ===========================================================================

  defp build_key(org_id, model_id, filename) do
    "tenants/#{org_id}/models/#{model_id}/#{filename}"
  end

  defp parse_key(key) do
    case String.split(key, "/") do
      ["tenants", _org_id, "models", model_id, filename] when filename != "" ->
        %{model_id: model_id, filename: filename}

      _ ->
        nil
    end
  end

  defp extract_file_data(%Plug.Upload{path: path, filename: filename, content_type: content_type}) do
    {:ok, data} = File.read(path)
    {data, filename, content_type || guess_content_type(filename)}
  end

  defp extract_file_data({:binary, data, filename}) when is_binary(data) do
    {data, filename, guess_content_type(filename)}
  end

  defp extract_file_data({:path, filepath}) when is_binary(filepath) do
    filename = Path.basename(filepath)
    {:ok, data} = File.read(filepath)
    {data, filename, guess_content_type(filename)}
  end

  defp guess_content_type(filename) do
    case Path.extname(filename) |> String.downcase() do
      ".pt" -> "application/x-pytorch"
      ".pth" -> "application/x-pytorch"
      ".onnx" -> "application/onnx"
      ".safetensors" -> "application/x-safetensors"
      ".gguf" -> "application/x-gguf"
      ".pkl" -> "application/x-pickle"
      ".pickle" -> "application/x-pickle"
      ".json" -> "application/json"
      ".yaml" -> "application/x-yaml"
      ".yml" -> "application/x-yaml"
      ".bin" -> "application/octet-stream"
      ".h5" -> "application/x-hdf5"
      ".hdf5" -> "application/x-hdf5"
      ".keras" -> "application/x-keras"
      _ -> "application/octet-stream"
    end
  end
end
