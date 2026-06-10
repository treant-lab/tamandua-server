defmodule TamanduaServer.Persistence do
  @moduledoc """
  Shared DETS-backed persistence helper for ETS tables.

  Provides a uniform way to back ETS tables with DETS files so that
  critical in-memory state survives process crashes and deployments.

  ## Usage

      # In GenServer init:
      {:ok, dets_ref} = Persistence.init_persistent_ets(:my_table, "my_table", opts)

      # Write-through (ETS + DETS):
      Persistence.write_through(:my_table, dets_ref, key, value)

      # Periodic flush (batch ETS -> DETS):
      Persistence.flush(:my_table, dets_ref)

      # Delete from both:
      Persistence.delete_through(:my_table, dets_ref, key)

      # On terminate:
      Persistence.close(dets_ref)

  ## DETS Files

  Files are stored under a configurable data directory. The default
  is `priv/data/` relative to the OTP application root. Override via:

      config :tamandua_server, :persistence_data_dir, "/var/lib/tamandua/data"

  ## Corruption Handling

  If a DETS file is corrupted and cannot be opened, the file is deleted
  and recreated empty. A warning is logged so operators are aware that
  previously persisted state was lost.
  """

  require Logger

  @default_data_subdir "priv/data"

  # ---------------------------------------------------------------------------
  # Public API
  # ---------------------------------------------------------------------------

  @doc """
  Initialize a persistent ETS table backed by DETS.

  1. Creates the ETS table (unless it already exists).
  2. Opens (or creates) a DETS file.
  3. Loads all DETS records into ETS.
  4. Optionally applies a filter function to skip stale/invalid records.

  Returns `{:ok, dets_ref}` on success.

  ## Options

    * `:ets_opts`   - Extra ETS options (default: `[:named_table, :set, :public, read_concurrency: true]`)
    * `:filter_fn`  - `({key, value}) -> boolean()` -- records where this returns `false` are
                      discarded during load (e.g. TTL expiry check). Default: always true.
    * `:version`    - An integer version tag. If the DETS file was written with a different version,
                      all data is discarded and the file is recreated. Useful when the record format
                      changes between releases.
  """
  @spec init_persistent_ets(atom(), String.t(), keyword()) :: {:ok, reference() | atom()} | {:error, term()}
  def init_persistent_ets(ets_name, dets_name, opts \\ []) do
    ets_opts = Keyword.get(opts, :ets_opts, [:named_table, :set, :public, read_concurrency: true])
    filter_fn = Keyword.get(opts, :filter_fn, fn _record -> true end)
    version = Keyword.get(opts, :version, nil)

    # Create ETS table if it doesn't already exist
    ensure_ets_table(ets_name, ets_opts)

    # Open DETS file
    dets_path = dets_file_path(dets_name)
    ensure_data_dir(dets_path)

    case open_dets(dets_name, dets_path) do
      {:ok, dets_ref} ->
        # Version check: if a version is specified, validate it
        if version do
          case check_version(dets_ref, version) do
            :ok ->
              load_dets_into_ets(dets_ref, ets_name, filter_fn)

            :version_mismatch ->
              Logger.warning(
                "[Persistence] Version mismatch for #{dets_name}, resetting DETS file"
              )
              :dets.delete_all_objects(dets_ref)
              :dets.insert(dets_ref, {:__persistence_version__, version})
          end
        else
          load_dets_into_ets(dets_ref, ets_name, filter_fn)
        end

        {:ok, dets_ref}

      {:error, reason} ->
        Logger.error("[Persistence] Failed to open DETS #{dets_name}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Write a key-value pair to both ETS and DETS (write-through).
  """
  @spec write_through(atom(), reference() | atom(), term(), term()) :: :ok
  def write_through(ets_name, dets_ref, key, value) do
    :ets.insert(ets_name, {key, value})
    :dets.insert(dets_ref, {key, value})
    :ok
  end

  @doc """
  Insert a raw tuple into both ETS and DETS. Useful when ETS entries
  have composite tuple shapes (e.g. `{key, value1, value2}`).
  """
  @spec insert_through(atom(), reference() | atom(), tuple()) :: :ok
  def insert_through(ets_name, dets_ref, record) when is_tuple(record) do
    :ets.insert(ets_name, record)
    :dets.insert(dets_ref, record)
    :ok
  end

  @doc """
  Delete a key from both ETS and DETS.
  """
  @spec delete_through(atom(), reference() | atom(), term()) :: :ok
  def delete_through(ets_name, dets_ref, key) do
    :ets.delete(ets_name, key)
    :dets.delete(dets_ref, key)
    :ok
  end

  @doc """
  Flush all ETS records to DETS (batch sync).

  This replaces the entire DETS contents with the current ETS state.
  Suitable for periodic persistence where write-through on every update
  would be too expensive.
  """
  @spec flush(atom(), reference() | atom()) :: :ok
  def flush(ets_name, dets_ref) do
    # Clear DETS and re-insert everything from ETS
    # We keep metadata keys (starting with __persistence_) intact
    try do
      # Preserve metadata
      metadata =
        :dets.match_object(dets_ref, {:__persistence_version__, :_})

      :dets.delete_all_objects(dets_ref)

      # Restore metadata
      Enum.each(metadata, fn record -> :dets.insert(dets_ref, record) end)

      # Insert all ETS records
      :ets.tab2list(ets_name)
      |> Enum.each(fn record -> :dets.insert(dets_ref, record) end)

      :dets.sync(dets_ref)
      :ok
    rescue
      e ->
        Logger.warning("[Persistence] Flush failed for #{ets_name}: #{inspect(e)}")
        :ok
    end
  end

  @doc """
  Sync DETS to disk without replacing contents. Call after a batch of
  write_through operations.
  """
  @spec sync(reference() | atom()) :: :ok
  def sync(dets_ref) do
    :dets.sync(dets_ref)
    :ok
  end

  @doc """
  Close the DETS file. Call from GenServer terminate/2.
  """
  @spec close(reference() | atom()) :: :ok
  def close(dets_ref) do
    try do
      :dets.close(dets_ref)
    rescue
      _ -> :ok
    catch
      :exit, _ -> :ok
    end

    :ok
  end

  @doc """
  Return the data directory path used for DETS files.
  """
  @spec data_dir() :: String.t()
  def data_dir do
    case Application.get_env(:tamandua_server, :persistence_data_dir) do
      nil ->
        app_dir = Application.app_dir(:tamandua_server)
        Path.join(app_dir, @default_data_subdir)

      dir ->
        dir
    end
  rescue
    # Application.app_dir may fail in dev/test if the app isn't in a release
    _ ->
      Path.join(File.cwd!(), @default_data_subdir)
  end

  # ---------------------------------------------------------------------------
  # Private
  # ---------------------------------------------------------------------------

  defp ensure_ets_table(name, opts) do
    # Check if the named ETS table already exists. We use :ets.info/2 which
    # returns :undefined for non-existent tables across all OTP versions.
    case :ets.info(name, :size) do
      :undefined -> :ets.new(name, opts)
      _size -> name
    end
  end

  defp dets_file_path(dets_name) do
    # DETS requires a charlist path
    dir = data_dir()
    Path.join(dir, "#{dets_name}.dets")
  end

  defp ensure_data_dir(dets_path) do
    dir = Path.dirname(dets_path)
    File.mkdir_p!(dir)
  end

  defp open_dets(dets_name, dets_path) do
    # Convert to charlist for :dets
    charlist_path = String.to_charlist(dets_path)
    dets_atom = String.to_atom("dets_#{dets_name}")

    case :dets.open_file(dets_atom, file: charlist_path, auto_save: 60_000, repair: true) do
      {:ok, ref} ->
        {:ok, ref}

      {:error, {:not_closed, _file}} ->
        # DETS wasn't closed properly last time -- force repair by reopening
        Logger.warning("[Persistence] DETS #{dets_name} was not closed properly, repairing")

        case :dets.open_file(dets_atom, file: charlist_path, auto_save: 60_000, repair: :force) do
          {:ok, ref} -> {:ok, ref}
          {:error, _} -> recreate_dets(dets_atom, charlist_path, dets_name)
        end

      {:error, reason} ->
        Logger.warning(
          "[Persistence] DETS #{dets_name} corrupted (#{inspect(reason)}), recreating"
        )
        recreate_dets(dets_atom, charlist_path, dets_name)
    end
  end

  defp recreate_dets(dets_atom, charlist_path, dets_name) do
    # Delete the corrupted file and start fresh
    path_string = List.to_string(charlist_path)
    File.rm(path_string)

    Logger.warning("[Persistence] Deleted corrupted DETS file for #{dets_name}, starting fresh")

    case :dets.open_file(dets_atom, file: charlist_path, auto_save: 60_000) do
      {:ok, ref} -> {:ok, ref}
      {:error, reason} -> {:error, reason}
    end
  end

  defp check_version(dets_ref, expected_version) do
    case :dets.lookup(dets_ref, :__persistence_version__) do
      [{:__persistence_version__, ^expected_version}] ->
        :ok

      [] ->
        # No version stored yet -- set it and accept the data
        :dets.insert(dets_ref, {:__persistence_version__, expected_version})
        :ok

      [{:__persistence_version__, _other}] ->
        :version_mismatch
    end
  end

  defp load_dets_into_ets(dets_ref, ets_name, filter_fn) do
    loaded =
      :dets.foldl(
        fn record, count ->
          # Skip metadata keys
          key = elem(record, 0)

          if is_atom(key) and key |> Atom.to_string() |> String.starts_with?("__persistence_") do
            count
          else
            if filter_fn.(record) do
              :ets.insert(ets_name, record)
              count + 1
            else
              count
            end
          end
        end,
        0,
        dets_ref
      )

    if loaded > 0 do
      Logger.info("[Persistence] Loaded #{loaded} records from DETS into #{ets_name}")
    end

    :ok
  end
end
