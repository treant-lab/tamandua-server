defmodule TamanduaServer.Backup.MLModelBackup do
  @moduledoc """
  ML model backup utilities for Tamandua.

  Backs up:
  - PyTorch model files (.pt, .pth)
  - Model metadata and configuration
  - Training checkpoints
  - Feature extractors
  """

  require Logger
  alias TamanduaServer.OSCommand

  @ml_models_dir Application.compile_env(:tamandua_server, :ml_models_dir, "/app/models")

  @doc """
  Archives all ML model files into a tar.gz archive.

  Returns path to the created archive.
  """
  @spec archive_models() :: {:ok, Path.t()} | {:error, term()}
  def archive_models do
    output_file =
      Path.join(System.tmp_dir!(), "tamandua_ml_models_#{System.unique_integer()}.tar.gz")

    if File.exists?(@ml_models_dir) do
      case create_model_archive(@ml_models_dir, output_file) do
        {:ok, _} ->
          Logger.info("ML model backup created", output: output_file)
          {:ok, output_file}

        error ->
          error
      end
    else
      Logger.warning("ML models directory not found", dir: @ml_models_dir)
      {:error, :ml_models_dir_not_found}
    end
  end

  @doc """
  Restores ML model files from a tar.gz archive.

  ## Parameters
  - `archive_path` - Path to ML models backup archive
  - `target_dir` - Target directory for restoration (optional, uses config if not provided)

  ## Returns
  - `:ok` - Restore succeeded
  - `{:error, reason}` - Restore failed
  """
  @spec restore_from_archive(Path.t(), String.t() | nil) :: :ok | {:error, term()}
  def restore_from_archive(archive_path, target_dir \\ nil) do
    dest_dir = target_dir || @ml_models_dir

    File.mkdir_p!(dest_dir)

    with :ok <- OSCommand.validate_tar_members(archive_path, :tgz) do
      case OSCommand.run("tar", ["-xzf", archive_path, "-C", dest_dir]) do
        {_output, 0} ->
          Logger.info("ML models restore completed", dest: dest_dir)
          :ok

        {:error, reason} ->
          {:error, reason}

        {error, exit_code} ->
          Logger.error("ML models restore failed", exit_code: exit_code, error: error)
          {:error, {:tar_extraction_failed, exit_code, error}}
      end
    end
  end

  @doc """
  Lists all ML model files in the models directory.

  Returns list of model file paths with metadata.
  """
  @spec list_models() :: {:ok, [map()]} | {:error, term()}
  def list_models do
    if File.exists?(@ml_models_dir) do
      models =
        @ml_models_dir
        |> Path.join("**/*.{pt,pth}")
        |> Path.wildcard()
        |> Enum.map(&get_model_info/1)

      {:ok, models}
    else
      {:error, :ml_models_dir_not_found}
    end
  end

  @doc """
  Validates ML model files for corruption.

  Checks:
  - File exists and is readable
  - File size > 0
  - PyTorch header is valid (magic number check)

  Returns list of validation errors.
  """
  @spec validate_models(Path.t()) :: {:ok, []} | {:ok, [map()]}
  def validate_models(models_dir) do
    if File.exists?(models_dir) do
      errors =
        models_dir
        |> Path.join("**/*.{pt,pth}")
        |> Path.wildcard()
        |> Enum.flat_map(&validate_model_file/1)

      if Enum.empty?(errors) do
        {:ok, []}
      else
        {:ok, errors}
      end
    else
      {:ok,
       [
         %{
           type: :directory_not_found,
           path: models_dir
         }
       ]}
    end
  end

  # Private Functions

  defp create_model_archive(models_dir, output_file) do
    case OSCommand.run("tar", ["-czf", output_file, "-C", models_dir, "."]) do
      {_output, 0} ->
        {:ok, output_file}

      {:error, reason} ->
        {:error, reason}

      {error, exit_code} ->
        Logger.error("Model archive creation failed", exit_code: exit_code, error: error)
        {:error, {:tar_creation_failed, exit_code, error}}
    end
  end

  defp get_model_info(model_path) do
    stats = File.stat!(model_path)

    %{
      path: model_path,
      name: Path.basename(model_path),
      size: stats.size,
      modified_at: stats.mtime,
      checksum: compute_checksum(model_path)
    }
  end

  defp validate_model_file(model_path) do
    errors = []

    errors =
      case File.stat(model_path) do
        {:ok, stats} ->
          if stats.size == 0 do
            [
              %{
                file: model_path,
                type: :empty_file,
                reason: "Model file is empty"
              }
              | errors
            ]
          else
            errors
          end

        {:error, reason} ->
          [
            %{
              file: model_path,
              type: :stat_error,
              reason: inspect(reason)
            }
            | errors
          ]
      end

    # Validate PyTorch magic number
    errors =
      case File.read(model_path) do
        {:ok, <<0x80, 0x02, _rest::binary>>} ->
          # Valid PyTorch pickle format (Python 2)
          errors

        {:ok, <<0x80, 0x03, _rest::binary>>} ->
          # Valid PyTorch pickle format (Python 3)
          errors

        {:ok, <<0x80, 0x04, _rest::binary>>} ->
          # Valid PyTorch pickle format (Protocol 4)
          errors

        {:ok, _} ->
          [
            %{
              file: model_path,
              type: :invalid_format,
              reason: "Not a valid PyTorch model file"
            }
            | errors
          ]

        {:error, reason} ->
          [
            %{
              file: model_path,
              type: :read_error,
              reason: inspect(reason)
            }
            | errors
          ]
      end

    errors
  end

  defp compute_checksum(file_path) do
    case File.read(file_path) do
      {:ok, data} ->
        :crypto.hash(:sha256, data)
        |> Base.encode16(case: :lower)

      {:error, _} ->
        nil
    end
  end
end
