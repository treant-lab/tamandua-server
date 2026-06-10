defmodule TamanduaServer.Backup.ClickHouseBackup do
  @moduledoc """
  ClickHouse backup utilities for Tamandua.

  Handles:
  - Full table exports
  - Incremental backup support (partition-based)
  - Schema backups
  """

  require Logger
  alias TamanduaServer.OSCommand

  @clickhouse_url Application.compile_env(
                    :tamandua_server,
                    :clickhouse_url,
                    "http://localhost:8123"
                  )
  @clickhouse_db "tamandua"

  @doc """
  Exports all ClickHouse data to a tar archive.

  Returns path to the created archive.
  """
  @spec export_data() :: {:ok, Path.t()} | {:error, term()}
  def export_data do
    output_file = Path.join(System.tmp_dir!(), "clickhouse_export_#{System.unique_integer()}.tar")
    temp_dir = Path.join(System.tmp_dir!(), "clickhouse_export_#{System.unique_integer()}")

    File.mkdir_p!(temp_dir)

    try do
      with {:ok, tables} <- list_tables(),
           :ok <- export_schema(temp_dir),
           :ok <- export_tables(tables, temp_dir),
           {:ok, _} <- create_tar_archive(temp_dir, output_file) do
        Logger.info("ClickHouse export completed", output: output_file)
        {:ok, output_file}
      else
        {:error, reason} = error ->
          Logger.error("ClickHouse export failed", reason: inspect(reason))
          error
      end
    after
      File.rm_rf!(temp_dir)
    end
  end

  @doc """
  Restores ClickHouse data from a tar archive.

  ## Parameters
  - `archive_path` - Path to backup tar archive
  - `target_db` - Target database name (optional, uses config if not provided)

  ## Returns
  - `:ok` - Restore succeeded
  - `{:error, reason}` - Restore failed
  """
  @spec restore_from_archive(Path.t(), String.t() | nil) :: :ok | {:error, term()}
  def restore_from_archive(archive_path, target_db \\ nil) do
    db = target_db || @clickhouse_db
    temp_dir = Path.join(System.tmp_dir!(), "clickhouse_restore_#{System.unique_integer()}")

    File.mkdir_p!(temp_dir)

    try do
      with {:ok, _} <- extract_tar_archive(archive_path, temp_dir),
           :ok <- restore_schema(temp_dir, db),
           :ok <- restore_tables(temp_dir, db) do
        Logger.info("ClickHouse restore completed", database: db)
        :ok
      else
        {:error, reason} = error ->
          Logger.error("ClickHouse restore failed", reason: inspect(reason))
          error
      end
    after
      File.rm_rf!(temp_dir)
    end
  end

  # Private Functions

  defp list_tables do
    query = "SHOW TABLES FROM #{@clickhouse_db}"

    case execute_query(query) do
      {:ok, response} ->
        tables =
          response
          |> String.split("\n", trim: true)

        {:ok, tables}

      error ->
        error
    end
  end

  defp export_schema(temp_dir) do
    query = "SHOW CREATE DATABASE #{@clickhouse_db}"

    with {:ok, schema} <- execute_query(query) do
      schema_file = Path.join(temp_dir, "schema.sql")
      File.write(schema_file, schema)
    end
  end

  defp export_tables(tables, temp_dir) do
    Enum.reduce_while(tables, :ok, fn table, _acc ->
      case export_table(table, temp_dir) do
        :ok -> {:cont, :ok}
        {:error, _} = error -> {:halt, error}
      end
    end)
  end

  defp export_table(table, temp_dir) do
    table_dir = Path.join(temp_dir, table)
    File.mkdir_p!(table_dir)

    # Export table schema
    with :ok <- export_table_schema(table, table_dir),
         :ok <- export_table_data(table, table_dir) do
      Logger.debug("Exported table", table: table)
      :ok
    end
  end

  defp export_table_schema(table, table_dir) do
    query = "SHOW CREATE TABLE #{@clickhouse_db}.#{table}"

    with {:ok, schema} <- execute_query(query) do
      schema_file = Path.join(table_dir, "schema.sql")
      File.write(schema_file, schema)
    end
  end

  defp export_table_data(table, table_dir) do
    query = "SELECT * FROM #{@clickhouse_db}.#{table} FORMAT TabSeparated"

    with {:ok, data} <- execute_query(query) do
      data_file = Path.join(table_dir, "data.tsv")
      File.write(data_file, data)
    end
  end

  defp restore_schema(temp_dir, db) do
    schema_file = Path.join(temp_dir, "schema.sql")

    case File.read(schema_file) do
      {:ok, schema} ->
        # Modify schema to use target database
        modified_schema = String.replace(schema, @clickhouse_db, db)
        execute_query(modified_schema)

      error ->
        error
    end
  end

  defp restore_tables(temp_dir, db) do
    with {:ok, table_dirs} <- File.ls(temp_dir) do
      table_dirs
      |> Enum.filter(fn dir ->
        path = Path.join(temp_dir, dir)
        File.dir?(path) and File.exists?(Path.join(path, "schema.sql"))
      end)
      |> Enum.reduce_while(:ok, fn table_dir, _acc ->
        case restore_table(Path.join(temp_dir, table_dir), table_dir, db) do
          :ok -> {:cont, :ok}
          {:error, _} = error -> {:halt, error}
        end
      end)
      |> case do
        :ok -> :ok
        error -> error
      end
    end
  end

  defp restore_table(table_path, table_name, db) do
    schema_file = Path.join(table_path, "schema.sql")
    data_file = Path.join(table_path, "data.tsv")

    with {:ok, schema} <- File.read(schema_file),
         modified_schema <- String.replace(schema, @clickhouse_db, db),
         {:ok, _} <- execute_query(modified_schema),
         {:ok, data} <- File.read(data_file),
         :ok <- insert_table_data(table_name, data, db) do
      Logger.debug("Restored table", table: table_name)
      :ok
    end
  end

  defp insert_table_data(table_name, data, db) do
    # Use INSERT FORMAT TabSeparated for bulk insert
    query = "INSERT INTO #{db}.#{table_name} FORMAT TabSeparated"

    case post_query(query, data) do
      {:ok, _} -> :ok
      error -> error
    end
  end

  defp create_tar_archive(source_dir, output_file) do
    case OSCommand.run("tar", ["-cf", output_file, "-C", source_dir, "."]) do
      {_output, 0} -> {:ok, output_file}
      {:error, reason} -> {:error, reason}
      {error, exit_code} -> {:error, {:tar_creation_failed, exit_code, error}}
    end
  end

  defp extract_tar_archive(archive_path, dest_dir) do
    with :ok <- OSCommand.validate_tar_members(archive_path, :tar) do
      case OSCommand.run("tar", ["-xf", archive_path, "-C", dest_dir]) do
        {_output, 0} -> {:ok, dest_dir}
        {:error, reason} -> {:error, reason}
        {error, exit_code} -> {:error, {:tar_extraction_failed, exit_code, error}}
      end
    end
  end

  defp execute_query(query) do
    url = "#{@clickhouse_url}/?query=#{URI.encode(query)}"

    case Req.get(url) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, body}

      {:ok, %{status: status, body: error}} ->
        Logger.error("ClickHouse query failed", status: status, error: error)
        {:error, {:clickhouse_error, status, error}}

      {:error, reason} ->
        {:error, {:clickhouse_connection_error, reason}}
    end
  end

  defp post_query(query, data) do
    url = "#{@clickhouse_url}/?query=#{URI.encode(query)}"

    case Req.post(url, body: data) do
      {:ok, %{status: 200}} ->
        {:ok, :success}

      {:ok, %{status: status, body: error}} ->
        Logger.error("ClickHouse POST failed", status: status, error: error)
        {:error, {:clickhouse_error, status, error}}

      {:error, reason} ->
        {:error, {:clickhouse_connection_error, reason}}
    end
  end
end
