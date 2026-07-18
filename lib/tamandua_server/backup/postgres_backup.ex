defmodule TamanduaServer.Backup.PostgresBackup do
  @moduledoc """
  PostgreSQL backup utilities for Tamandua.

  Handles:
  - Full database dumps (pg_dump)
  - WAL (Write-Ahead Log) archiving for incremental backups
  - Point-in-time recovery support
  """

  require Logger

  @doc """
  Creates a full PostgreSQL database dump.

  Returns the dump as a binary string (SQL format).
  """
  @spec dump_database() :: {:ok, binary()} | {:error, term()}
  def dump_database do
    runner = command_runner()

    with {:ok, connection} <- connection_details() do
      case runner.run("pg_dump", [connection.url, "--format=plain"],
             env: [{"PGPASSWORD", connection.password}]
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
  end

  @doc """
  Archives PostgreSQL WAL (Write-Ahead Log) files.

  Returns path to tar archive containing WAL files.
  """
  @spec archive_wal_logs() :: {:ok, Path.t()} | {:error, term()}
  def archive_wal_logs do
    wal_dir = get_wal_directory()
    output_file = Path.join(System.tmp_dir!(), "postgres_wal_#{System.unique_integer()}.tar")
    runner = command_runner()

    case runner.run("tar", ["-cf", output_file, "-C", wal_dir, "."]) do
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
    runner = command_runner()

    with {:ok, connection} <- connection_details(),
         {:ok, target_url} <- restore_target_url(connection.url, target_db) do
      case runner.run("psql", ["-d", target_url, "-f", dump_file],
             env: [{"PGPASSWORD", connection.password}]
           ) do
        {output, 0} ->
          Logger.info("PostgreSQL restore completed", database: target_db || connection.database)
          {:ok, output}

        {:error, reason} ->
          {:error, reason}

        {error, exit_code} ->
          Logger.error("PostgreSQL restore failed", exit_code: exit_code, error: error)
          {:error, {:psql_restore_failed, exit_code, error}}
      end
    end
  end

  # Private Functions

  defp connection_details do
    case Keyword.get(db_config(), :url) do
      url when is_binary(url) and url != "" -> connection_details_from_url(url)
      _ -> connection_details_from_options()
    end
  end

  defp connection_details_from_options do
    config = db_config()
    host = Keyword.get(config, :hostname, "localhost")
    port = Keyword.get(config, :port, 5432)
    username = Keyword.get(config, :username, "postgres")
    database = Keyword.get(config, :database, "tamandua_dev")
    password = Keyword.get(config, :password, "")

    if valid_connection_component?(host) and valid_connection_component?(username) and
         valid_connection_component?(database) and is_integer(port) and port in 1..65_535 do
      uri = %URI{
        scheme: "postgresql",
        host: host,
        port: port,
        userinfo: URI.encode(username, &URI.char_unreserved?/1),
        path: "/" <> URI.encode(database, &URI.char_unreserved?/1)
      }

      {:ok,
       %{
         url: URI.to_string(uri),
         password: if(is_binary(password), do: password, else: ""),
         database: database
       }}
    else
      {:error, :invalid_postgres_connection_config}
    end
  end

  # Keep credentials out of argv/process listings. pg_dump receives the
  # password through PGPASSWORD instead.
  defp connection_details_from_url(url) do
    uri = URI.parse(url)
    database = if is_binary(uri.path), do: String.trim_leading(uri.path, "/"), else: ""

    with true <- uri.scheme in ["ecto", "postgres", "postgresql"],
         true <- valid_connection_component?(uri.host),
         true <- valid_connection_component?(database),
         userinfo when is_binary(userinfo) <- uri.userinfo,
         [username, password] <- String.split(userinfo, ":", parts: 2),
         true <- valid_connection_component?(username) do
      sanitized = %{
        uri
        | scheme: "postgresql",
          userinfo: username,
          path: "/" <> database
      }

      {:ok,
       %{
         url: URI.to_string(sanitized),
         password: URI.decode(password),
         database: URI.decode(database)
       }}
    else
      _ -> {:error, :invalid_postgres_database_url}
    end
  rescue
    ArgumentError -> {:error, :invalid_postgres_database_url}
  end

  defp restore_target_url(url, nil), do: {:ok, url}

  defp restore_target_url(url, target_db) when is_binary(target_db) and target_db != "" do
    encoded_database = URI.encode(target_db, &URI.char_unreserved?/1)
    {:ok, url |> URI.parse() |> Map.put(:path, "/" <> encoded_database) |> URI.to_string()}
  end

  defp restore_target_url(_url, _target_db), do: {:error, :invalid_restore_target_database}

  defp db_config do
    Application.get_env(:tamandua_server, TamanduaServer.Repo, [])
  end

  defp command_runner do
    Application.get_env(
      :tamandua_server,
      :postgres_backup_command_runner,
      TamanduaServer.OSCommand
    )
  end

  defp valid_connection_component?(value),
    do: is_binary(value) and value != "" and not String.contains?(value, <<0>>)

  defp get_wal_directory do
    # Default PostgreSQL WAL directory
    # This should be configured based on your PostgreSQL installation
    Application.get_env(:tamandua_server, :postgres_wal_dir, "/var/lib/postgresql/data/pg_wal")
  end
end
