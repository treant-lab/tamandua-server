defmodule TamanduaServer.PersistenceTest do
  @moduledoc """
  Unit tests for the TamanduaServer.Persistence module.

  Tests the DETS-backed ETS persistence helper including:
  - init_persistent_ets (table creation, DETS loading)
  - write_through / insert_through
  - flush (batch sync)
  - delete_through
  - version checking and mismatch handling
  - corruption recovery (DETS re-creation)
  - close / sync
  """

  use ExUnit.Case, async: false

  alias TamanduaServer.Persistence

  # Each test gets its own unique table/dets names to avoid interference.
  defp unique_names(test_name) do
    suffix = :erlang.unique_integer([:positive])
    ets_name = :"persistence_test_ets_#{test_name}_#{suffix}"
    dets_name = "persistence_test_dets_#{test_name}_#{suffix}"
    {ets_name, dets_name}
  end

  # Cleanup helper: close DETS and delete the file.
  defp cleanup(ets_name, dets_ref, dets_name) do
    Persistence.close(dets_ref)

    # Delete the ETS table if it exists
    try do
      :ets.delete(ets_name)
    rescue
      _ -> :ok
    end

    # Delete the DETS file
    dir = Persistence.data_dir()
    path = Path.join(dir, "#{dets_name}.dets")
    File.rm(path)
  end

  # ── init_persistent_ets ─────────────────────────────────────────────

  describe "init_persistent_ets/3" do
    test "creates ETS table and opens DETS file" do
      {ets_name, dets_name} = unique_names(:init_basic)
      {:ok, dets_ref} = Persistence.init_persistent_ets(ets_name, dets_name)

      # ETS table should exist
      assert :ets.info(ets_name, :size) != :undefined

      # Should be able to insert into ETS
      :ets.insert(ets_name, {:test_key, "test_value"})
      assert [{:test_key, "test_value"}] = :ets.lookup(ets_name, :test_key)

      cleanup(ets_name, dets_ref, dets_name)
    end

    test "calling init twice on same table does not crash" do
      {ets_name, dets_name} = unique_names(:init_twice)
      {:ok, dets_ref1} = Persistence.init_persistent_ets(ets_name, dets_name)

      # Insert some data
      Persistence.write_through(ets_name, dets_ref1, :key1, "value1")

      # Close and re-init
      Persistence.close(dets_ref1)

      # Delete ETS so it gets recreated
      try do
        :ets.delete(ets_name)
      rescue
        _ -> :ok
      end

      {:ok, dets_ref2} = Persistence.init_persistent_ets(ets_name, dets_name)

      # Data should be restored from DETS
      assert [{:key1, "value1"}] = :ets.lookup(ets_name, :key1)

      cleanup(ets_name, dets_ref2, dets_name)
    end

    test "loads pre-existing DETS records into ETS" do
      {ets_name, dets_name} = unique_names(:restore)

      # First pass: write data and close
      {:ok, dets_ref} = Persistence.init_persistent_ets(ets_name, dets_name)
      Persistence.write_through(ets_name, dets_ref, :restore_key, "restored!")
      Persistence.close(dets_ref)

      # Destroy ETS
      try do
        :ets.delete(ets_name)
      rescue
        _ -> :ok
      end

      # Second pass: should load from DETS
      {:ok, dets_ref2} = Persistence.init_persistent_ets(ets_name, dets_name)
      assert [{:restore_key, "restored!"}] = :ets.lookup(ets_name, :restore_key)

      cleanup(ets_name, dets_ref2, dets_name)
    end

    test "filter_fn excludes records during load" do
      {ets_name, dets_name} = unique_names(:filter)

      # First pass: write multiple records
      {:ok, dets_ref} = Persistence.init_persistent_ets(ets_name, dets_name)
      Persistence.write_through(ets_name, dets_ref, :keep, "yes")
      Persistence.write_through(ets_name, dets_ref, :drop, "no")
      Persistence.close(dets_ref)

      try do
        :ets.delete(ets_name)
      rescue
        _ -> :ok
      end

      # Second pass with filter
      filter_fn = fn {key, _value} -> key == :keep end

      {:ok, dets_ref2} =
        Persistence.init_persistent_ets(ets_name, dets_name, filter_fn: filter_fn)

      assert [{:keep, "yes"}] = :ets.lookup(ets_name, :keep)
      assert [] = :ets.lookup(ets_name, :drop)

      cleanup(ets_name, dets_ref2, dets_name)
    end
  end

  # ── Version checking ────────────────────────────────────────────────

  describe "version checking" do
    test "first init with version sets it and keeps data" do
      {ets_name, dets_name} = unique_names(:version_first)

      {:ok, dets_ref} =
        Persistence.init_persistent_ets(ets_name, dets_name, version: 1)

      Persistence.write_through(ets_name, dets_ref, :v_key, "v_val")
      Persistence.close(dets_ref)

      try do
        :ets.delete(ets_name)
      rescue
        _ -> :ok
      end

      # Re-open with same version -- data should persist
      {:ok, dets_ref2} =
        Persistence.init_persistent_ets(ets_name, dets_name, version: 1)

      assert [{:v_key, "v_val"}] = :ets.lookup(ets_name, :v_key)

      cleanup(ets_name, dets_ref2, dets_name)
    end

    test "version mismatch resets DETS data" do
      {ets_name, dets_name} = unique_names(:version_mismatch)

      # Write with version 1
      {:ok, dets_ref} =
        Persistence.init_persistent_ets(ets_name, dets_name, version: 1)

      Persistence.write_through(ets_name, dets_ref, :old_data, "should_be_gone")
      Persistence.close(dets_ref)

      try do
        :ets.delete(ets_name)
      rescue
        _ -> :ok
      end

      # Re-open with version 2 -- old data should be wiped
      {:ok, dets_ref2} =
        Persistence.init_persistent_ets(ets_name, dets_name, version: 2)

      assert [] = :ets.lookup(ets_name, :old_data)

      cleanup(ets_name, dets_ref2, dets_name)
    end
  end

  # ── write_through ───────────────────────────────────────────────────

  describe "write_through/4" do
    test "writes to both ETS and DETS" do
      {ets_name, dets_name} = unique_names(:write_through)
      {:ok, dets_ref} = Persistence.init_persistent_ets(ets_name, dets_name)

      assert :ok = Persistence.write_through(ets_name, dets_ref, :wt_key, "wt_val")

      # Check ETS
      assert [{:wt_key, "wt_val"}] = :ets.lookup(ets_name, :wt_key)

      # Check DETS
      assert [{:wt_key, "wt_val"}] = :dets.lookup(dets_ref, :wt_key)

      cleanup(ets_name, dets_ref, dets_name)
    end

    test "overwrites existing key" do
      {ets_name, dets_name} = unique_names(:write_overwrite)
      {:ok, dets_ref} = Persistence.init_persistent_ets(ets_name, dets_name)

      Persistence.write_through(ets_name, dets_ref, :ow, "first")
      Persistence.write_through(ets_name, dets_ref, :ow, "second")

      assert [{:ow, "second"}] = :ets.lookup(ets_name, :ow)
      assert [{:ow, "second"}] = :dets.lookup(dets_ref, :ow)

      cleanup(ets_name, dets_ref, dets_name)
    end
  end

  # ── insert_through ──────────────────────────────────────────────────

  describe "insert_through/3" do
    test "inserts composite tuple into both ETS and DETS" do
      {ets_name, dets_name} = unique_names(:insert_through)

      {:ok, dets_ref} =
        Persistence.init_persistent_ets(ets_name, dets_name,
          ets_opts: [:named_table, :set, :public, read_concurrency: true]
        )

      record = {:composite_key, "val_a", "val_b", 42}
      assert :ok = Persistence.insert_through(ets_name, dets_ref, record)

      assert [{:composite_key, "val_a", "val_b", 42}] =
               :ets.lookup(ets_name, :composite_key)

      assert [{:composite_key, "val_a", "val_b", 42}] =
               :dets.lookup(dets_ref, :composite_key)

      cleanup(ets_name, dets_ref, dets_name)
    end
  end

  # ── delete_through ──────────────────────────────────────────────────

  describe "delete_through/3" do
    test "removes key from both ETS and DETS" do
      {ets_name, dets_name} = unique_names(:delete_through)
      {:ok, dets_ref} = Persistence.init_persistent_ets(ets_name, dets_name)

      Persistence.write_through(ets_name, dets_ref, :del_key, "gone")

      # Verify it exists first
      assert [{:del_key, "gone"}] = :ets.lookup(ets_name, :del_key)

      assert :ok = Persistence.delete_through(ets_name, dets_ref, :del_key)

      assert [] = :ets.lookup(ets_name, :del_key)
      assert [] = :dets.lookup(dets_ref, :del_key)

      cleanup(ets_name, dets_ref, dets_name)
    end
  end

  # ── flush ───────────────────────────────────────────────────────────

  describe "flush/2" do
    test "syncs all ETS records to DETS" do
      {ets_name, dets_name} = unique_names(:flush)
      {:ok, dets_ref} = Persistence.init_persistent_ets(ets_name, dets_name)

      # Insert directly into ETS (bypassing DETS write-through)
      :ets.insert(ets_name, {:flush_key1, "a"})
      :ets.insert(ets_name, {:flush_key2, "b"})

      # Before flush, DETS should not have these
      assert [] = :dets.lookup(dets_ref, :flush_key1)

      assert :ok = Persistence.flush(ets_name, dets_ref)

      # After flush, DETS should have both
      assert [{:flush_key1, "a"}] = :dets.lookup(dets_ref, :flush_key1)
      assert [{:flush_key2, "b"}] = :dets.lookup(dets_ref, :flush_key2)

      cleanup(ets_name, dets_ref, dets_name)
    end

    test "flush preserves __persistence_version__ metadata" do
      {ets_name, dets_name} = unique_names(:flush_version)

      {:ok, dets_ref} =
        Persistence.init_persistent_ets(ets_name, dets_name, version: 42)

      :ets.insert(ets_name, {:data, "value"})
      Persistence.flush(ets_name, dets_ref)

      # Version metadata should still be in DETS
      assert [{:__persistence_version__, 42}] =
               :dets.lookup(dets_ref, :__persistence_version__)

      cleanup(ets_name, dets_ref, dets_name)
    end
  end

  # ── sync ────────────────────────────────────────────────────────────

  describe "sync/1" do
    test "returns :ok" do
      {ets_name, dets_name} = unique_names(:sync)
      {:ok, dets_ref} = Persistence.init_persistent_ets(ets_name, dets_name)

      assert :ok = Persistence.sync(dets_ref)

      cleanup(ets_name, dets_ref, dets_name)
    end
  end

  # ── close ───────────────────────────────────────────────────────────

  describe "close/1" do
    test "returns :ok" do
      {ets_name, dets_name} = unique_names(:close)
      {:ok, dets_ref} = Persistence.init_persistent_ets(ets_name, dets_name)

      assert :ok = Persistence.close(dets_ref)

      # Cleanup ETS only (DETS already closed)
      try do
        :ets.delete(ets_name)
      rescue
        _ -> :ok
      end

      dir = Persistence.data_dir()
      path = Path.join(dir, "#{dets_name}.dets")
      File.rm(path)
    end

    test "closing twice does not crash" do
      {ets_name, dets_name} = unique_names(:close_twice)
      {:ok, dets_ref} = Persistence.init_persistent_ets(ets_name, dets_name)

      assert :ok = Persistence.close(dets_ref)
      assert :ok = Persistence.close(dets_ref)

      try do
        :ets.delete(ets_name)
      rescue
        _ -> :ok
      end

      dir = Persistence.data_dir()
      path = Path.join(dir, "#{dets_name}.dets")
      File.rm(path)
    end
  end

  # ── data_dir ────────────────────────────────────────────────────────

  describe "data_dir/0" do
    test "returns a string path" do
      dir = Persistence.data_dir()
      assert is_binary(dir)
      assert String.length(dir) > 0
    end
  end

  # ── Corruption recovery ─────────────────────────────────────────────

  describe "corruption recovery" do
    test "recovers from corrupted DETS file by recreating" do
      {ets_name, dets_name} = unique_names(:corruption)

      dir = Persistence.data_dir()
      File.mkdir_p!(dir)
      dets_path = Path.join(dir, "#{dets_name}.dets")

      # Write garbage to simulate a corrupted file
      File.write!(dets_path, :crypto.strong_rand_bytes(256))

      # init should recover by deleting and recreating the file
      {:ok, dets_ref} = Persistence.init_persistent_ets(ets_name, dets_name)

      # Should be usable after recovery
      Persistence.write_through(ets_name, dets_ref, :after_corrupt, "works")
      assert [{:after_corrupt, "works"}] = :ets.lookup(ets_name, :after_corrupt)

      cleanup(ets_name, dets_ref, dets_name)
    end
  end
end
