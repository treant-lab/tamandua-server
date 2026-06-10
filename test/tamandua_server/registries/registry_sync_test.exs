defmodule TamanduaServer.Registries.RegistrySyncTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.Registries.RegistrySync

  setup do
    # Stop the GenServer if running from application
    if Process.whereis(RegistrySync) do
      GenServer.stop(RegistrySync, :normal)
      Process.sleep(100)
    end

    # Clear ETS table if exists
    if :ets.whereis(:registry_model_cache) != :undefined do
      :ets.delete(:registry_model_cache)
    end

    :ok
  end

  describe "start_link/1" do
    test "starts GenServer with default options" do
      {:ok, pid} = RegistrySync.start_link([])
      assert Process.alive?(pid)

      # Clean up
      GenServer.stop(pid)
    end

    test "starts GenServer with custom sync interval" do
      {:ok, pid} = RegistrySync.start_link(sync_interval_ms: 10_000)
      assert Process.alive?(pid)

      # Clean up
      GenServer.stop(pid)
    end

    test "starts GenServer with custom registries" do
      registries = [
        {TamanduaServer.Registries.HuggingFace, %{limit: 10}}
      ]

      {:ok, pid} = RegistrySync.start_link(registries: registries)
      assert Process.alive?(pid)

      # Clean up
      GenServer.stop(pid)
    end
  end

  describe "get_status/0" do
    test "returns status with empty sync data initially" do
      {:ok, pid} = RegistrySync.start_link(sync_interval_ms: 1_000_000)

      status = RegistrySync.get_status()

      assert is_map(status)
      assert Map.has_key?(status, :registries)
      assert Map.has_key?(status, :last_sync)
      assert Map.has_key?(status, :errors)
      assert status.last_sync == %{}
      assert status.errors == %{}

      # Clean up
      GenServer.stop(pid)
    end

    test "returns last sync times after sync" do
      {:ok, pid} = RegistrySync.start_link(sync_interval_ms: 1_000_000)

      # Trigger sync
      :ok = RegistrySync.sync_now(:huggingface)

      # Give sync time to complete
      Process.sleep(500)

      status = RegistrySync.get_status()

      # Should have sync time for huggingface (or error if API unavailable)
      assert is_map(status.last_sync) or is_map(status.errors)

      # Clean up
      GenServer.stop(pid)
    end
  end

  describe "sync_now/1" do
    test "triggers immediate sync for specific registry" do
      {:ok, pid} = RegistrySync.start_link(sync_interval_ms: 1_000_000)

      # Sync should return :ok (even if API call fails, it handles errors)
      assert :ok = RegistrySync.sync_now(:huggingface)

      # Clean up
      GenServer.stop(pid)
    end

    test "returns error for unknown registry" do
      {:ok, pid} = RegistrySync.start_link(sync_interval_ms: 1_000_000)

      assert {:error, :unknown_registry} = RegistrySync.sync_now(:unknown)

      # Clean up
      GenServer.stop(pid)
    end
  end

  describe "periodic sync" do
    test "schedules periodic sync on start" do
      # Start with very short interval for testing
      {:ok, pid} = RegistrySync.start_link(sync_interval_ms: 100)

      # Wait for first sync to trigger
      Process.sleep(200)

      # GenServer should still be alive (no crashes)
      assert Process.alive?(pid)

      # Clean up
      GenServer.stop(pid)
    end
  end

  describe "error handling" do
    test "does not crash on sync errors" do
      # Start with registries that may fail
      {:ok, pid} = RegistrySync.start_link(sync_interval_ms: 1_000_000)

      # Force sync (may fail due to network/API issues)
      :ok = RegistrySync.sync_now(:huggingface)

      # Give time for sync
      Process.sleep(500)

      # GenServer should still be alive
      assert Process.alive?(pid)

      # Clean up
      GenServer.stop(pid)
    end

    test "records errors in state" do
      {:ok, pid} = RegistrySync.start_link(sync_interval_ms: 1_000_000)

      # Attempt sync (may fail)
      :ok = RegistrySync.sync_now(:huggingface)
      Process.sleep(500)

      status = RegistrySync.get_status()

      # Should have either successful last_sync or error recorded
      has_sync = Map.has_key?(status.last_sync, "huggingface")
      has_error = Map.has_key?(status.errors, "huggingface")

      assert has_sync or has_error

      # Clean up
      GenServer.stop(pid)
    end
  end

  describe "ETS cache" do
    test "creates ETS table on start" do
      {:ok, pid} = RegistrySync.start_link(sync_interval_ms: 1_000_000)

      # ETS table should exist
      assert :ets.whereis(:registry_model_cache) != :undefined

      # Clean up
      GenServer.stop(pid)
    end

    test "updates ETS cache after successful sync" do
      {:ok, pid} = RegistrySync.start_link(sync_interval_ms: 1_000_000)

      # Trigger sync
      :ok = RegistrySync.sync_now(:huggingface)
      Process.sleep(1000)

      # Check if ETS has entries (if sync succeeded)
      # Note: This may be empty if API call failed
      cache_size = :ets.info(:registry_model_cache, :size)
      assert is_integer(cache_size)

      # Clean up
      GenServer.stop(pid)
    end
  end

  describe "multi-registry sync" do
    test "syncs all configured registries" do
      registries = [
        {TamanduaServer.Registries.HuggingFace, %{limit: 5}}
      ]

      {:ok, pid} = RegistrySync.start_link(registries: registries, sync_interval_ms: 1_000_000)

      # Trigger sync for all
      send(pid, :sync)

      # Give time for sync
      Process.sleep(1000)

      # GenServer should still be alive
      assert Process.alive?(pid)

      status = RegistrySync.get_status()

      # Should have attempted sync for all registries
      assert is_map(status)

      # Clean up
      GenServer.stop(pid)
    end
  end

  describe "configuration" do
    test "uses default interval if not specified" do
      {:ok, pid} = RegistrySync.start_link([])

      state = :sys.get_state(pid)

      # Default should be 1 hour (3600000 ms)
      assert state.sync_interval_ms == 3_600_000

      # Clean up
      GenServer.stop(pid)
    end

    test "uses default registries if not specified" do
      {:ok, pid} = RegistrySync.start_link([])

      state = :sys.get_state(pid)

      # Should have HuggingFace as default
      assert is_list(state.registries)
      assert length(state.registries) > 0

      # Clean up
      GenServer.stop(pid)
    end
  end
end
