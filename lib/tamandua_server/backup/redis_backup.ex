defmodule TamanduaServer.Backup.RedisBackup do
  @moduledoc """
  Redis backup utilities for Tamandua.

  Handles:
  - RDB snapshot backups
  - AOF (Append-Only File) backups for incremental recovery
  """

  require Logger

  @redis_url Application.compile_env(:tamandua_server, :redis_url, "redis://localhost:6379")

  @doc """
  Triggers a Redis SAVE command and retrieves the RDB snapshot.

  Returns the RDB file contents as binary.
  """
  @spec save_snapshot() :: {:ok, binary()} | {:error, term()}
  def save_snapshot do
    with {:ok, conn} <- connect_redis(),
         {:ok, "OK"} <- Redix.command(conn, ["SAVE"]),
         {:ok, rdb_path} <- get_rdb_path(conn),
         {:ok, rdb_data} <- File.read(rdb_path) do
      Logger.info("Redis snapshot created", size: byte_size(rdb_data))
      Redix.stop(conn)
      {:ok, rdb_data}
    else
      {:error, reason} = error ->
        Logger.error("Redis snapshot failed", reason: inspect(reason))
        error
    end
  end

  @doc """
  Retrieves the Redis AOF (Append-Only File) for incremental backups.

  Returns the AOF file contents as binary.
  """
  @spec get_aof() :: {:ok, binary()} | {:error, term()}
  def get_aof do
    with {:ok, conn} <- connect_redis(),
         {:ok, aof_path} <- get_aof_path(conn),
         {:ok, aof_data} <- File.read(aof_path) do
      Logger.info("Redis AOF retrieved", size: byte_size(aof_data))
      Redix.stop(conn)
      {:ok, aof_data}
    else
      {:error, reason} = error ->
        Logger.error("Redis AOF retrieval failed", reason: inspect(reason))
        error
    end
  end

  @doc """
  Triggers an asynchronous background save (BGSAVE).

  Non-blocking alternative to `save_snapshot/0`.
  """
  @spec background_save() :: {:ok, :scheduled} | {:error, term()}
  def background_save do
    with {:ok, conn} <- connect_redis(),
         {:ok, "Background saving started"} <- Redix.command(conn, ["BGSAVE"]) do
      Logger.info("Redis background save scheduled")
      Redix.stop(conn)
      {:ok, :scheduled}
    else
      {:error, reason} = error ->
        Logger.error("Redis BGSAVE failed", reason: inspect(reason))
        error
    end
  end

  @doc """
  Restores a Redis database from an RDB file.

  ## Parameters
  - `rdb_file` - Path to RDB snapshot file
  - `target_db` - Target Redis database number (0-15)

  ## Returns
  - `:ok` - Restore succeeded
  - `{:error, reason}` - Restore failed
  """
  @spec restore_from_rdb(Path.t(), integer()) :: :ok | {:error, term()}
  def restore_from_rdb(rdb_file, target_db \\ 0) do
    with {:ok, conn} <- connect_redis(),
         {:ok, redis_dir} <- get_redis_dir(conn),
         {:ok, "OK"} <- Redix.command(conn, ["SELECT", to_string(target_db)]),
         {:ok, "OK"} <- Redix.command(conn, ["FLUSHDB"]),
         :ok <- copy_rdb_to_redis_dir(rdb_file, redis_dir),
         {:ok, "OK"} <- Redix.command(conn, ["SHUTDOWN", "NOSAVE"]) do
      # Redis will restart and load the new RDB file
      Logger.info("Redis restore initiated", db: target_db)
      :ok
    else
      {:error, reason} = error ->
        Logger.error("Redis restore failed", reason: inspect(reason))
        error
    end
  end

  # Private Functions

  defp connect_redis do
    uri = URI.parse(@redis_url)

    opts = [
      host: uri.host || "localhost",
      port: uri.port || 6379
    ]

    opts =
      if uri.userinfo do
        [{:password, uri.userinfo} | opts]
      else
        opts
      end

    Redix.start_link(opts)
  end

  defp get_rdb_path(conn) do
    with {:ok, dir} <- Redix.command(conn, ["CONFIG", "GET", "dir"]),
         {:ok, dbfilename} <- Redix.command(conn, ["CONFIG", "GET", "dbfilename"]) do
      # Redis returns ["dir", "/path/to/dir"] and ["dbfilename", "dump.rdb"]
      [_, redis_dir] = dir
      [_, rdb_file] = dbfilename
      {:ok, Path.join(redis_dir, rdb_file)}
    end
  end

  defp get_aof_path(conn) do
    with {:ok, dir} <- Redix.command(conn, ["CONFIG", "GET", "dir"]),
         {:ok, aof_filename} <- Redix.command(conn, ["CONFIG", "GET", "appendfilename"]) do
      [_, redis_dir] = dir
      [_, aof_file] = aof_filename
      {:ok, Path.join(redis_dir, aof_file)}
    end
  end

  defp get_redis_dir(conn) do
    case Redix.command(conn, ["CONFIG", "GET", "dir"]) do
      {:ok, [_, redis_dir]} -> {:ok, redis_dir}
      error -> error
    end
  end

  defp copy_rdb_to_redis_dir(source_rdb, redis_dir) do
    dest_rdb = Path.join(redis_dir, "dump.rdb")
    File.cp(source_rdb, dest_rdb)
  end
end
