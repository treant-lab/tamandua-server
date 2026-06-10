defmodule TamanduaServer.Backup.PostgresBackup do
  @moduledoc """
  PostgreSQL backup utilities for Tamandua.

  Handles:
  - Full database dumps (pg_dump)
  - WAL (Write-Ahead Log) archiving for incremental backups
  - Point-in-time recovery support
  """

  require Logger
  alias TamanduaServer.OSCommand

  @db_config Application.compile_env(:tamandua_server, TamanduaServer.Repo)

  @doc """
  Creates a full PostgreSQL database dump.

  Returns the dump as a binary string (SQL format).
  """
  @spec dump_database() :: {:ok, binary()} | {:error, term()}
  def dump_database do
    db_url = build_database_url()

    case OSCommand.run("pg_dump", [db_url, "--format=plain"],
           env: [{"PGPASSWORD", get_password()}]
         ) do
      {dump, 0} ->
        Logger.info("PostgreSQL dump created", size: byte_size(dump))
        {:ok, dump}

      {:error, reason} ->
        {:error, reason}

      {error, exit_code} ->
        Logger.error("pg_dump failed", exit_code: exit_code, error: error)
        {:error, {:pg_dump_failed, exit_code, error}}
    end
  end

  @doc """
  Archives PostgreSQL WAL (Write-Ahead Log) files.

  Returns path to tar archive containing WAL files.
  """
  @spec archive_wal_logs() :: {:ok, Path.t()} | {:error, term()}
  def archive_wal_logs do
    wal_dir = get_wal_directory()
    output_file = Path.join(System.tmp_dir!(), "postgres_wal_#{System.unique_integer()}.tar")

    case OSCommand.run("tar", ["-cf", output_file, "-C", wal_dir, "."]) do
      {_output, 0} ->
        Logger.info("WAL logs archived", output: output_file)
        {:ok, output_file}

      {:error, reason} ->
        {:error, reason}

      {error, exit_code} ->
        Logger.error("WAL archiving failed", exit_code: exit_code, error: error)
        {:error, {:wal_archive_failed, exit_code, error}}
    end
  end

  @doc """
  Restores a PostgreSQL database from a dump file.

  ## Parameters
  - `dump_file` - Path to SQL dump file
  - `target_db` - Target database name (optional, uses config if not provided)

  ## Returns
  - `{:ok, output}` - Restore succeeded
  - `{:error, reason}` - Restore failed
  """
  @spec restore_from_dump(Path.t(), String.t() | nil) :: {:ok, binary()} | {:error, term()}
  def restore_from_dump(dump_file, target_db \\ nil) do
    db = target_db || get_database_name()

    case OSCommand.run("psql", ["-d", db, "-f", dump_file], env: [{"PGPASSWORD", get_password()}]) do
      {output, 0} ->
        Logger.info("PostgreSQL restore completed", database: db)
        {:ok, output}

      {:error, reason} ->
        {:error, reason}

      {error, exit_code} ->
        Logger.error("PostgreSQL restore failed", exit_code: exit_code, error: error)
        {:error, {:psql_restore_failed, exit_code, error}}
    end
  end

  # Private Functions

  defp build_database_url do
    host = Keyword.get(@db_config, :hostname, "localhost")
    port = Keyword.get(@db_config, :port, 5432)
    database = get_database_name()
    username = Keyword.get(@db_config, :username, "postgres")

    "postgresql://#{username}@#{host}:#{port}/#{database}"
  end

  defp get_database_name do
    Keyword.get(@db_config, :database, "tamandua_dev")
  end

  defp get_password do
    Keyword.get(@db_config, :password, "")
  end

  defp get_wal_directory do
    # Default PostgreSQL WAL directory
    # This should be configured based on your PostgreSQL installation
    Application.get_env(:tamandua_server, :postgres_wal_dir, "/var/lib/postgresql/data/pg_wal")
  end
end
