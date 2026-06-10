defmodule TamanduaServer.Backup.ConfigBackup do
  @moduledoc """
  Configuration file backup utilities for Tamandua.

  Backs up:
  - Application configuration files
  - YARA rules
  - Sigma rules
  - IOC lists
  - Custom detection rules
  """

  require Logger
  alias TamanduaServer.OSCommand

  @config_paths [
    "config",
    "priv/yara_rules",
    "priv/sigma_rules",
    "priv/ioc_lists"
  ]

  @doc """
  Archives all configuration files into a tar.gz archive.

  Returns path to the created archive.
  """
  @spec archive_configs() :: {:ok, Path.t()} | {:error, term()}
  def archive_configs do
    output_file =
      Path.join(System.tmp_dir!(), "tamandua_configs_#{System.unique_integer()}.tar.gz")

    app_root = Application.app_dir(:tamandua_server)

    paths_to_backup =
      @config_paths
      |> Enum.map(&Path.join(app_root, &1))
      |> Enum.filter(&File.exists?/1)

    if Enum.empty?(paths_to_backup) do
      Logger.warning("No configuration paths found to backup")
      {:error, :no_configs_found}
    else
      case create_config_archive(paths_to_backup, output_file) do
        {:ok, _} ->
          Logger.info("Configuration backup created",
            output: output_file,
            paths: length(paths_to_backup)
          )

          {:ok, output_file}

        error ->
          error
      end
    end
  end

  @doc """
  Restores configuration files from a tar.gz archive.

  ## Parameters
  - `archive_path` - Path to configuration backup archive
  - `target_dir` - Target directory for restoration (optional, uses app_dir if not provided)

  ## Returns
  - `:ok` - Restore succeeded
  - `{:error, reason}` - Restore failed
  """
  @spec restore_from_archive(Path.t(), String.t() | nil) :: :ok | {:error, term()}
  def restore_from_archive(archive_path, target_dir \\ nil) do
    dest_dir = target_dir || Application.app_dir(:tamandua_server)

    with :ok <- OSCommand.validate_tar_members(archive_path, :tgz) do
      case OSCommand.run("tar", ["-xzf", archive_path, "-C", dest_dir]) do
        {_output, 0} ->
          Logger.info("Configuration restore completed", dest: dest_dir)
          :ok

        {:error, reason} ->
          {:error, reason}

        {error, exit_code} ->
          Logger.error("Configuration restore failed", exit_code: exit_code, error: error)
          {:error, {:tar_extraction_failed, exit_code, error}}
      end
    end
  end

  @doc """
  Validates configuration files for syntax errors.

  Returns list of validation errors, empty list if all valid.
  """
  @spec validate_configs(Path.t()) :: {:ok, []} | {:ok, [map()]} | {:error, term()}
  def validate_configs(config_dir) do
    errors = []

    # Validate YAML files
    yaml_errors = validate_yaml_files(Path.join(config_dir, "config"))
    sigma_errors = validate_sigma_rules(Path.join(config_dir, "priv/sigma_rules"))

    all_errors = yaml_errors ++ sigma_errors

    if Enum.empty?(all_errors) do
      {:ok, []}
    else
      {:ok, all_errors}
    end
  end

  # Private Functions

  defp create_config_archive(paths, output_file) do
    # Build tar command arguments
    # Use relative paths from app root
    app_root = Application.app_dir(:tamandua_server)
    relative_paths = Enum.map(paths, &Path.relative_to(&1, app_root))

    args = ["-czf", output_file, "-C", app_root] ++ relative_paths

    case OSCommand.run("tar", args) do
      {_output, 0} ->
        {:ok, output_file}

      {:error, reason} ->
        {:error, reason}

      {error, exit_code} ->
        Logger.error("Config archive creation failed", exit_code: exit_code, error: error)
        {:error, {:tar_creation_failed, exit_code, error}}
    end
  end

  defp validate_yaml_files(config_dir) do
    if File.exists?(config_dir) do
      config_dir
      |> Path.join("**/*.{yml,yaml}")
      |> Path.wildcard()
      |> Enum.flat_map(&validate_yaml_file/1)
    else
      []
    end
  end

  defp validate_yaml_file(file_path) do
    case YamlElixir.read_from_file(file_path) do
      {:ok, _} ->
        []

      {:error, reason} ->
        [
          %{
            file: file_path,
            type: :yaml_syntax_error,
            reason: inspect(reason)
          }
        ]
    end
  end

  defp validate_sigma_rules(sigma_dir) do
    if File.exists?(sigma_dir) do
      sigma_dir
      |> Path.join("**/*.yml")
      |> Path.wildcard()
      |> Enum.flat_map(&validate_sigma_rule/1)
    else
      []
    end
  end

  defp validate_sigma_rule(file_path) do
    case YamlElixir.read_from_file(file_path) do
      {:ok, rule} ->
        validate_sigma_structure(rule, file_path)

      {:error, reason} ->
        [
          %{
            file: file_path,
            type: :sigma_yaml_error,
            reason: inspect(reason)
          }
        ]
    end
  end

  defp validate_sigma_structure(rule, file_path) do
    required_fields = ["title", "detection", "level"]
    missing_fields = Enum.filter(required_fields, &(!Map.has_key?(rule, &1)))

    if Enum.empty?(missing_fields) do
      []
    else
      [
        %{
          file: file_path,
          type: :sigma_structure_error,
          reason: "Missing required fields: #{Enum.join(missing_fields, ", ")}"
        }
      ]
    end
  end
end
