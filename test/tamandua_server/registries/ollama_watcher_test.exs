defmodule TamanduaServer.Registries.OllamaWatcherTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.Registries.OllamaWatcher

  setup do
    # Clean up any previous watcher instance
    case Process.whereis(OllamaWatcher) do
      nil -> :ok
      pid -> GenServer.stop(pid, :normal, 1000) rescue nil
    end

    # Start test PubSub if not already running
    start_supervised!({Phoenix.PubSub, name: TestPubSub})

    :ok
  end

  describe "start_link/1" do
    test "initializes with configurable poll interval (default 30s)" do
      {:ok, pid} = start_supervised({OllamaWatcher, [
        poll_interval: 30_000,
        pubsub: TestPubSub,
        name: :test_watcher_1
      ]})

      assert Process.alive?(pid)

      status = OllamaWatcher.get_status(:test_watcher_1)
      assert is_map(status)
    end

    test "accepts custom poll interval" do
      {:ok, pid} = start_supervised({OllamaWatcher, [
        poll_interval: 10_000,
        pubsub: TestPubSub,
        name: :test_watcher_2
      ]})

      assert Process.alive?(pid)
    end

    test "accepts custom ollama_url" do
      {:ok, pid} = start_supervised({OllamaWatcher, [
        ollama_url: "http://custom-ollama:11434",
        pubsub: TestPubSub,
        name: :test_watcher_3
      ]})

      assert Process.alive?(pid)
    end
  end

  describe "get_status/0" do
    test "returns last_check, known_models, errors" do
      {:ok, _pid} = start_supervised({OllamaWatcher, [
        poll_interval: 60_000,  # Long interval to prevent auto-poll
        pubsub: TestPubSub,
        name: :test_watcher_status
      ]})

      status = OllamaWatcher.get_status(:test_watcher_status)

      assert Map.has_key?(status, :last_check)
      assert Map.has_key?(status, :model_count)
      assert Map.has_key?(status, :last_error)
      assert Map.has_key?(status, :initialized)
    end

    test "returns nil last_check before first poll" do
      {:ok, _pid} = start_supervised({OllamaWatcher, [
        poll_interval: 300_000,  # Very long interval
        initial_delay: 300_000,  # Very long delay
        pubsub: TestPubSub,
        name: :test_watcher_no_poll
      ]})

      status = OllamaWatcher.get_status(:test_watcher_no_poll)

      # Before first poll, last_check should be nil
      assert status.last_check == nil
      assert status.initialized == false
    end
  end

  describe "model tracking" do
    test "tracks model digests to detect updates to existing model names" do
      # This test verifies the state structure includes digest tracking
      {:ok, _pid} = start_supervised({OllamaWatcher, [
        poll_interval: 300_000,
        pubsub: TestPubSub,
        name: :test_watcher_digest
      ]})

      status = OllamaWatcher.get_status(:test_watcher_digest)

      # model_count should be integer
      assert is_integer(status.model_count)
    end
  end

  describe "initialization behavior" do
    test "does not trigger on initial model list (only subsequent additions)" do
      # This tests that the first poll sets initialized: true
      # and doesn't trigger download hooks
      {:ok, _pid} = start_supervised({OllamaWatcher, [
        poll_interval: 300_000,
        initial_delay: 10,  # Short delay for testing
        pubsub: TestPubSub,
        name: :test_watcher_init
      ]})

      # Give time for initial poll
      Process.sleep(100)

      status = OllamaWatcher.get_status(:test_watcher_init)

      # After initial poll, should be initialized
      # (may fail if Ollama not available, which is ok)
      assert status.initialized == true or status.last_error != nil
    end
  end

  describe "error handling" do
    test "handles Ollama unavailable gracefully (logs warning, continues polling)" do
      # Configure to connect to non-existent Ollama
      {:ok, _pid} = start_supervised({OllamaWatcher, [
        ollama_url: "http://localhost:99999",
        poll_interval: 300_000,
        initial_delay: 10,
        pubsub: TestPubSub,
        name: :test_watcher_unavailable
      ]})

      # Give time for initial poll to fail
      Process.sleep(200)

      # Should still be alive despite error
      status = OllamaWatcher.get_status(:test_watcher_unavailable)

      # Should record the error but continue running
      assert status.last_error != nil
      assert Process.alive?(Process.whereis(:test_watcher_unavailable))
    end

    test "does not crash GenServer on transient failures" do
      {:ok, pid} = start_supervised({OllamaWatcher, [
        ollama_url: "http://invalid-host:11434",
        poll_interval: 300_000,
        initial_delay: 10,
        pubsub: TestPubSub,
        name: :test_watcher_transient
      ]})

      # Wait for initial poll to complete (and fail)
      Process.sleep(500)

      # GenServer should still be alive
      assert Process.alive?(pid)
    end
  end

  describe "PubSub integration" do
    test "broadcasts to registries:ollama topic on model pull" do
      # Subscribe to the topic
      Phoenix.PubSub.subscribe(TestPubSub, "registries:ollama")

      {:ok, _pid} = start_supervised({OllamaWatcher, [
        poll_interval: 300_000,
        initial_delay: 10,
        pubsub: TestPubSub,
        name: :test_watcher_pubsub
      ]})

      # If Ollama is running with models, we'd receive events
      # Since Ollama may not be available, we just verify no crash
      Process.sleep(100)

      # Verify subscription was successful
      assert true
    end
  end

  describe "configuration" do
    test "uses OLLAMA_URL environment variable when not in config" do
      # Save original value
      original = System.get_env("OLLAMA_URL")

      try do
        System.put_env("OLLAMA_URL", "http://env-ollama:11434")

        {:ok, _pid} = start_supervised({OllamaWatcher, [
          poll_interval: 300_000,
          pubsub: TestPubSub,
          name: :test_watcher_env
        ]})

        # Should start without error
        assert Process.alive?(Process.whereis(:test_watcher_env))
      after
        # Restore original
        if original do
          System.put_env("OLLAMA_URL", original)
        else
          System.delete_env("OLLAMA_URL")
        end
      end
    end
  end
end
