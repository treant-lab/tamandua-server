defmodule TamanduaServer.Backup.Scheduler do
  @moduledoc """
  Automated backup scheduling for Tamandua.

  Schedules and executes:
  - Daily full backups (PostgreSQL, Redis, ClickHouse, configs, ML models)
  - Hourly incremental backups (PostgreSQL WAL, Redis AOF)
  - Monthly restore verification tests
  - Automatic backup retention (30 days)

  Uses Oban for job scheduling and execution tracking.
  """

  use Oban.Worker,
    queue: :backups,
    max_attempts: 3,
    priority: 1

  require Logger
  alias TamanduaServer.Backup.{Encryptor, PostgresBackup, RedisBackup, ClickHouseBackup, ConfigBackup, MLModelBackup}
  alias TamanduaServer.Repo

  @backup_dir Application.compile_env(:tamandua_server, :backup_dir, "/var/backups/tamandua")
  @retention_days 30

  # Job types
  @full_backup "full_backup"
  @incremental_backup "incremental_backup"
  @verify_restore "verify_restore"
  @cleanup_old_backups "cleanup_old_backups"

  @doc """
  Schedules recurring backup jobs.

  Call this during application startup to configure:
  - Daily full backups at 2 AM
  - Hourly incremental backups
  - Monthly restore verification on 1st of month at 3 AM
  - Daily cleanup at 4 AM
  """
  def schedule_recurring_jobs do
    # Daily full backup at 2 AM
    %{type: @full_backup}
    |> new(schedule: "0 2 * * *")
    |> Oban.insert()

    # Hourly incremental backup
    %{type: @incremental_backup}
    |> new(schedule: "0 * * * *")
    |> Oban.insert()

    # Monthly restore verification on 1st at 3 AM
    %{type: @verify_restore}
    |> new(schedule: "0 3 1 * *")
    |> Oban.insert()

    # Daily cleanup at 4 AM
    %{type: @cleanup_old_backups}
    |> new(schedule: "0 4 * * *")
    |> Oban.insert()

    Logger.info("Backup jobs scheduled")
  end

  @doc """
  Triggers an immediate full backup.

  Returns the backup job for status tracking.
  """
  def trigger_full_backup do
    %{type: @full_backup}
    |> new()
    |> Oban.insert()
  end

  @doc """
  Triggers an immediate incremental backup.
  """
  def trigger_incremental_backup do
    %{type: @incremental_backup}
    |> new()
    |> Oban.insert()
  end

  @doc """
  Triggers an immediate restore verification test.
  """
  def trigger_verify_restore do
    %{type: @verify_restore}
    |> new()
    |> Oban.insert()
  end

  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"type" => @full_backup} = args}) do
    Logger.info("Starting full backup")
    timestamp = DateTime.utc_now() |> DateTime.to_iso8601(:basic)
    backup_path = Path.join(@backup_dir, "full_#{timestamp}")

    with :ok <- ensure_backup_dir(backup_path),
         {:ok, results} <- execute_full_backup(backup_path, args),
         :ok <- write_manifest(backup_path, results) do
      Logger.info("Full backup completed successfully", path: backup_path, results: results)
      :ok
    else
      {:error, reason} = error ->
        Logger.error("Full backup failed", reason: inspect(reason))
        error
    end
  end

  def perform(%Oban.Job{args: %{"type" => @incremental_backup} = args}) do
    Logger.info("Starting incremental backup")
    timestamp = DateTime.utc_now() |> DateTime.to_iso8601(:basic)
    backup_path = Path.join(@backup_dir, "incremental_#{timestamp}")

    with :ok <- ensure_backup_dir(backup_path),
         {:ok, results} <- execute_incremental_backup(backup_path, args),
         :ok <- write_manifest(backup_path, results) do
      Logger.info("Incremental backup completed", path: backup_path)
      :ok
    else
      {:error, reason} = error ->
        Logger.error("Incremental backup failed", reason: inspect(reason))
        error
    end
  end

  def perform(%Oban.Job{args: %{"type" => @verify_restore}}) do
    Logger.info("Starting restore verification test")

    with {:ok, latest_backup} <- find_latest_backup(),
         {:ok, test_results} <- verify_restore_process(latest_backup) do
      if test_results.success do
        Logger.info("Restore verification passed", results: test_results)
        :ok
      else
        Logger.error("Restore verification failed", results: test_results)
        {:error, :restore_verification_failed}
      end
    else
      {:error, reason} = error ->
        Logger.error("Restore verification error", reason: inspect(reason))
        error
    end
  end

  def perform(%Oban.Job{args: %{"type" => @cleanup_old_backups}}) do
    Logger.info("Starting backup cleanup", retention_days: @retention_days)

    cutoff_date = DateTime.utc_now() |> DateTime.add(-@retention_days, :day)

    with {:ok, backups} <- list_backups(),
         {:ok, deleted_count} <- delete_old_backups(backups, cutoff_date) do
      Logger.info("Backup cleanup completed", deleted: deleted_count)
      :ok
    else
      {:error, reason} = error ->
        Logger.error("Backup cleanup failed", reason: inspect(reason))
        error
    end
  end

  # Private Functions - Full Backup

  defp execute_full_backup(backup_path, _args) do
    results = %{
      postgres: backup_postgres(backup_path),
      redis: backup_redis(backup_path),
      clickhouse: backup_clickhouse(backup_path),
      configs: backup_configs(backup_path),
      ml_models: backup_ml_models(backup_path)
    }

    # Check if any backup failed
    failures = Enum.filter(results, fn {_key, result} -> match?({:error, _}, result) end)

    if Enum.empty?(failures) do
      {:ok, results}
    else
      {:error, {:partial_backup_failure, failures}}
    end
  end

  defp backup_postgres(backup_path) do
    dest_file = Path.join(backup_path, "postgres.sql.enc")

    with {:ok, sql_dump} <- PostgresBackup.dump_database(),
         {:ok, _encrypted, metadata} <- Encryptor.encrypt(sql_dump, compression: 9),
         :ok <- Encryptor.encrypt_file(
           Path.join(System.tmp_dir!(), "postgres_dump.sql"),
           dest_file,
           metadata: %{source: "postgresql", type: "full"}
         ) do
      {:ok, %{file: dest_file, size: File.stat!(dest_file).size, metadata: metadata}}
    end
  rescue
    e ->
      Logger.error("PostgreSQL backup failed", error: inspect(e))
      {:error, {:postgres_backup_failed, e}}
  end

  defp backup_redis(backup_path) do
    dest_file = Path.join(backup_path, "redis.rdb.enc")

    with {:ok, rdb_data} <- RedisBackup.save_snapshot(),
         :ok <- Encryptor.encrypt_file(
           Path.join(System.tmp_dir!(), "dump.rdb"),
           dest_file,
           metadata: %{source: "redis", type: "full"}
         ) do
      {:ok, %{file: dest_file, size: File.stat!(dest_file).size}}
    end
  rescue
    e ->
      Logger.error("Redis backup failed", error: inspect(e))
      {:error, {:redis_backup_failed, e}}
  end

  defp backup_clickhouse(backup_path) do
    dest_file = Path.join(backup_path, "clickhouse.tar.enc")

    with {:ok, export_path} <- ClickHouseBackup.export_data(),
         :ok <- Encryptor.encrypt_file(
           export_path,
           dest_file,
           metadata: %{source: "clickhouse", type: "full"}
         ) do
      {:ok, %{file: dest_file, size: File.stat!(dest_file).size}}
    end
  rescue
    e ->
      Logger.error("ClickHouse backup failed", error: inspect(e))
      {:error, {:clickhouse_backup_failed, e}}
  end

  defp backup_configs(backup_path) do
    dest_file = Path.join(backup_path, "configs.tar.enc")

    with {:ok, config_archive} <- ConfigBackup.archive_configs(),
         :ok <- Encryptor.encrypt_file(
           config_archive,
           dest_file,
           metadata: %{source: "configs", type: "full"}
         ) do
      {:ok, %{file: dest_file, size: File.stat!(dest_file).size}}
    end
  rescue
    e ->
      Logger.error("Config backup failed", error: inspect(e))
      {:error, {:config_backup_failed, e}}
  end

  defp backup_ml_models(backup_path) do
    dest_file = Path.join(backup_path, "ml_models.tar.enc")

    with {:ok, models_archive} <- MLModelBackup.archive_models(),
         :ok <- Encryptor.encrypt_file(
           models_archive,
           dest_file,
           metadata: %{source: "ml_models", type: "full"}
         ) do
      {:ok, %{file: dest_file, size: File.stat!(dest_file).size}}
    end
  rescue
    e ->
      Logger.error("ML model backup failed", error: inspect(e))
      {:error, {:ml_model_backup_failed, e}}
  end

  # Private Functions - Incremental Backup

  defp execute_incremental_backup(backup_path, _args) do
    results = %{
      postgres_wal: backup_postgres_wal(backup_path),
      redis_aof: backup_redis_aof(backup_path)
    }

    failures = Enum.filter(results, fn {_key, result} -> match?({:error, _}, result) end)

    if Enum.empty?(failures) do
      {:ok, results}
    else
      {:error, {:partial_backup_failure, failures}}
    end
  end

  defp backup_postgres_wal(backup_path) do
    dest_file = Path.join(backup_path, "postgres_wal.tar.enc")

    with {:ok, wal_archive} <- PostgresBackup.archive_wal_logs(),
         :ok <- Encryptor.encrypt_file(
           wal_archive,
           dest_file,
           metadata: %{source: "postgresql_wal", type: "incremental"}
         ) do
      {:ok, %{file: dest_file, size: File.stat!(dest_file).size}}
    end
  rescue
    e ->
      Logger.error("PostgreSQL WAL backup failed", error: inspect(e))
      {:error, {:postgres_wal_backup_failed, e}}
  end

  defp backup_redis_aof(backup_path) do
    dest_file = Path.join(backup_path, "redis_aof.enc")

    with {:ok, aof_data} <- RedisBackup.get_aof(),
         :ok <- Encryptor.encrypt_file(
           Path.join(System.tmp_dir!(), "appendonly.aof"),
           dest_file,
           metadata: %{source: "redis_aof", type: "incremental"}
         ) do
      {:ok, %{file: dest_file, size: File.stat!(dest_file).size}}
    end
  rescue
    e ->
      Logger.error("Redis AOF backup failed", error: inspect(e))
      {:error, {:redis_aof_backup_failed, e}}
  end

  # Private Functions - Verification

  defp verify_restore_process(backup_path) do
    test_dir = Path.join(System.tmp_dir!(), "tamandua_restore_test_#{System.unique_integer()}")
    File.mkdir_p!(test_dir)

    try do
      manifest_path = Path.join(backup_path, "manifest.json")

      with {:ok, manifest_json} <- File.read(manifest_path),
           {:ok, manifest} <- Jason.decode(manifest_json),
           {:ok, postgres_result} <- test_restore_postgres(backup_path, test_dir),
           {:ok, redis_result} <- test_restore_redis(backup_path, test_dir),
           {:ok, config_result} <- test_restore_configs(backup_path, test_dir) do
        {:ok,
         %{
           success: true,
           postgres: postgres_result,
           redis: redis_result,
           configs: config_result,
           tested_at: DateTime.utc_now()
         }}
      else
        {:error, reason} ->
          {:ok, %{success: false, reason: reason, tested_at: DateTime.utc_now()}}
      end
    after
      File.rm_rf!(test_dir)
    end
  end

  defp test_restore_postgres(backup_path, test_dir) do
    encrypted_file = Path.join(backup_path, "postgres.sql.enc")
    decrypted_file = Path.join(test_dir, "postgres.sql")

    with :ok <- Encryptor.decrypt_file(encrypted_file, decrypted_file),
         {:ok, stats} <- File.stat(decrypted_file),
         true <- stats.size > 0 do
      {:ok, %{verified: true, size: stats.size}}
    else
      _ -> {:error, :postgres_restore_failed}
    end
  end

  defp test_restore_redis(backup_path, test_dir) do
    encrypted_file = Path.join(backup_path, "redis.rdb.enc")
    decrypted_file = Path.join(test_dir, "dump.rdb")

    with :ok <- Encryptor.decrypt_file(encrypted_file, decrypted_file),
         {:ok, stats} <- File.stat(decrypted_file),
         true <- stats.size > 0 do
      {:ok, %{verified: true, size: stats.size}}
    else
      _ -> {:error, :redis_restore_failed}
    end
  end

  defp test_restore_configs(backup_path, test_dir) do
    encrypted_file = Path.join(backup_path, "configs.tar.enc")
    decrypted_file = Path.join(test_dir, "configs.tar")

    with :ok <- Encryptor.decrypt_file(encrypted_file, decrypted_file),
         {:ok, stats} <- File.stat(decrypted_file),
         true <- stats.size > 0 do
      {:ok, %{verified: true, size: stats.size}}
    else
      _ -> {:error, :config_restore_failed}
    end
  end

  # Private Functions - Cleanup

  defp list_backups do
    case File.ls(@backup_dir) do
      {:ok, files} ->
        backups =
          files
          |> Enum.filter(&String.match?(&1, ~r/^(full|incremental)_/))
          |> Enum.map(&Path.join(@backup_dir, &1))
          |> Enum.filter(&File.dir?/1)

        {:ok, backups}

      {:error, reason} ->
        {:error, {:backup_dir_read_failed, reason}}
    end
  end

  defp delete_old_backups(backups, cutoff_date) do
    deleted =
      backups
      |> Enum.filter(fn backup_path ->
        manifest_path = Path.join(backup_path, "manifest.json")

        case read_backup_timestamp(manifest_path) do
          {:ok, timestamp} ->
            DateTime.compare(timestamp, cutoff_date) == :lt

          _ ->
            false
        end
      end)
      |> Enum.map(fn backup_path ->
        File.rm_rf!(backup_path)
        Logger.debug("Deleted old backup", path: backup_path)
        backup_path
      end)

    {:ok, length(deleted)}
  end

  defp read_backup_timestamp(manifest_path) do
    with {:ok, manifest_json} <- File.read(manifest_path),
         {:ok, manifest} <- Jason.decode(manifest_json),
         {:ok, timestamp_str} <- Map.fetch(manifest, "timestamp"),
         {:ok, timestamp, _} <- DateTime.from_iso8601(timestamp_str) do
      {:ok, timestamp}
    else
      _ -> {:error, :invalid_manifest}
    end
  end

  defp find_latest_backup do
    with {:ok, backups} <- list_backups() do
      latest =
        backups
        |> Enum.map(fn backup_path ->
          manifest_path = Path.join(backup_path, "manifest.json")

          case read_backup_timestamp(manifest_path) do
            {:ok, timestamp} -> {backup_path, timestamp}
            _ -> nil
          end
        end)
        |> Enum.reject(&is_nil/1)
        |> Enum.max_by(fn {_path, timestamp} -> DateTime.to_unix(timestamp) end, fn -> nil end)

      case latest do
        {path, _timestamp} -> {:ok, path}
        nil -> {:error, :no_backups_found}
      end
    end
  end

  # Private Functions - Utilities

  defp ensure_backup_dir(path) do
    case File.mkdir_p(path) do
      :ok -> :ok
      {:error, reason} -> {:error, {:mkdir_failed, reason}}
    end
  end

  defp write_manifest(backup_path, results) do
    manifest = %{
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
      results: results,
      version: "1.0"
    }

    manifest_path = Path.join(backup_path, "manifest.json")

    case Jason.encode(manifest, pretty: true) do
      {:ok, json} -> File.write(manifest_path, json)
      {:error, reason} -> {:error, {:manifest_encode_failed, reason}}
    end
  end
end
