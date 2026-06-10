defmodule TamanduaServer.Runtime.ModelIsolationTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Runtime.ModelIsolation

  setup do
    # Start the ModelIsolation GenServer for each test
    start_supervised!(ModelIsolation)
    :ok
  end

  describe "isolate/3" do
    test "isolates an active model" do
      model_id = "test-model-#{System.unique_integer()}"
      agent_id = "test-agent-1"

      # Register the model first
      {:ok, _} = ModelIsolation.register(model_id, agent_id)

      # Isolate it
      assert {:ok, state} =
               ModelIsolation.isolate(model_id, agent_id,
                 mode: :full,
                 reason: "Test isolation",
                 isolated_by: "test_user"
               )

      assert state.status == :isolated
      assert state.isolation_mode == :full
      assert state.reason == "Test isolation"
      assert state.isolated_by == "test_user"
      assert state.isolated_at != nil
    end

    test "isolates an untracked model (creates new entry)" do
      model_id = "new-model-#{System.unique_integer()}"
      agent_id = "test-agent-1"

      assert {:ok, state} =
               ModelIsolation.isolate(model_id, agent_id,
                 mode: :network,
                 reason: "New model isolation"
               )

      assert state.status == :isolated
      assert state.isolation_mode == :network
    end

    test "returns error when isolating already isolated model" do
      model_id = "test-model-#{System.unique_integer()}"
      agent_id = "test-agent-1"

      {:ok, _} = ModelIsolation.isolate(model_id, agent_id, mode: :full)

      assert {:error, :already_isolated} = ModelIsolation.isolate(model_id, agent_id)
    end

    test "returns error when isolating killed model" do
      model_id = "test-model-#{System.unique_integer()}"
      agent_id = "test-agent-1"

      {:ok, _} = ModelIsolation.register(model_id, agent_id)
      {:ok, _} = ModelIsolation.kill(model_id, agent_id)

      assert {:error, :already_killed} = ModelIsolation.isolate(model_id, agent_id)
    end

    test "supports different isolation modes" do
      for mode <- [:network, :process, :memory, :full] do
        model_id = "test-model-#{mode}-#{System.unique_integer()}"
        agent_id = "test-agent-1"

        assert {:ok, state} = ModelIsolation.isolate(model_id, agent_id, mode: mode)
        assert state.isolation_mode == mode
      end
    end
  end

  describe "release/1" do
    test "releases an isolated model" do
      model_id = "test-model-#{System.unique_integer()}"
      agent_id = "test-agent-1"

      {:ok, _} = ModelIsolation.isolate(model_id, agent_id, mode: :full)
      assert {:ok, state} = ModelIsolation.release(model_id)

      assert state.status == :active
      assert state.isolation_mode == :none
      assert state.isolated_at == nil
      assert state.reason == nil
    end

    test "returns error when releasing non-isolated model" do
      model_id = "test-model-#{System.unique_integer()}"
      agent_id = "test-agent-1"

      {:ok, _} = ModelIsolation.register(model_id, agent_id)

      assert {:error, :not_isolated} = ModelIsolation.release(model_id)
    end

    test "returns error when releasing killed model" do
      model_id = "test-model-#{System.unique_integer()}"
      agent_id = "test-agent-1"

      {:ok, _} = ModelIsolation.register(model_id, agent_id)
      {:ok, _} = ModelIsolation.kill(model_id, agent_id)

      assert {:error, :already_killed} = ModelIsolation.release(model_id)
    end

    test "returns error for unknown model" do
      assert {:error, :model_not_found} = ModelIsolation.release("nonexistent-model")
    end
  end

  describe "kill/2" do
    test "kills an active model" do
      model_id = "test-model-#{System.unique_integer()}"
      agent_id = "test-agent-1"

      {:ok, _} = ModelIsolation.register(model_id, agent_id)
      assert {:ok, state} = ModelIsolation.kill(model_id, agent_id)

      assert state.status == :killed
      assert state.isolation_mode == :full
    end

    test "kills an isolated model" do
      model_id = "test-model-#{System.unique_integer()}"
      agent_id = "test-agent-1"

      {:ok, _} = ModelIsolation.isolate(model_id, agent_id, mode: :network)
      assert {:ok, state} = ModelIsolation.kill(model_id, agent_id)

      assert state.status == :killed
    end

    test "returns error when killing already killed model" do
      model_id = "test-model-#{System.unique_integer()}"
      agent_id = "test-agent-1"

      {:ok, _} = ModelIsolation.register(model_id, agent_id)
      {:ok, _} = ModelIsolation.kill(model_id, agent_id)

      assert {:error, :already_killed} = ModelIsolation.kill(model_id, agent_id)
    end

    test "kills untracked model (creates killed entry)" do
      model_id = "new-model-#{System.unique_integer()}"
      agent_id = "test-agent-1"

      assert {:ok, state} = ModelIsolation.kill(model_id, agent_id)
      assert state.status == :killed
    end
  end

  describe "get_state/1" do
    test "returns state for tracked model" do
      model_id = "test-model-#{System.unique_integer()}"
      agent_id = "test-agent-1"

      {:ok, _} = ModelIsolation.register(model_id, agent_id)

      assert {:ok, state} = ModelIsolation.get_state(model_id)
      assert state.model_id == model_id
      assert state.agent_id == agent_id
      assert state.status == :active
    end

    test "returns error for untracked model" do
      assert {:error, :model_not_found} = ModelIsolation.get_state("nonexistent")
    end
  end

  describe "list_isolated/0" do
    test "returns only isolated models" do
      # Create mix of active and isolated models
      {:ok, _} = ModelIsolation.register("active-1", "agent-1")
      {:ok, _} = ModelIsolation.register("active-2", "agent-1")
      {:ok, _} = ModelIsolation.isolate("isolated-1", "agent-2", mode: :full)
      {:ok, _} = ModelIsolation.isolate("isolated-2", "agent-3", mode: :network)

      isolated = ModelIsolation.list_isolated()

      model_ids = Enum.map(isolated, & &1.model_id)
      assert "isolated-1" in model_ids
      assert "isolated-2" in model_ids
      refute "active-1" in model_ids
      refute "active-2" in model_ids
    end

    test "returns empty list when no models isolated" do
      {:ok, _} = ModelIsolation.register("active-1", "agent-1")

      assert ModelIsolation.list_isolated() == []
    end
  end

  describe "list_by_agent/1" do
    test "returns models for specific agent" do
      {:ok, _} = ModelIsolation.register("model-1", "agent-1")
      {:ok, _} = ModelIsolation.register("model-2", "agent-1")
      {:ok, _} = ModelIsolation.register("model-3", "agent-2")
      {:ok, _} = ModelIsolation.isolate("model-4", "agent-1", mode: :full)

      models = ModelIsolation.list_by_agent("agent-1")

      assert length(models) == 3
      model_ids = Enum.map(models, & &1.model_id)
      assert "model-1" in model_ids
      assert "model-2" in model_ids
      assert "model-4" in model_ids
      refute "model-3" in model_ids
    end

    test "returns empty list for unknown agent" do
      assert ModelIsolation.list_by_agent("unknown-agent") == []
    end
  end

  describe "auto-release timer" do
    test "auto-releases model after duration" do
      model_id = "test-model-#{System.unique_integer()}"
      agent_id = "test-agent-1"

      # Isolate with 100ms duration
      {:ok, state} =
        ModelIsolation.isolate(model_id, agent_id,
          mode: :full,
          duration_seconds: 1
        )

      assert state.status == :isolated
      assert state.auto_release_at != nil

      # Wait for auto-release (with some buffer)
      Process.sleep(1500)

      # Check that model is now active
      {:ok, state} = ModelIsolation.get_state(model_id)
      assert state.status == :active
      assert state.isolation_mode == :none
    end

    test "manual release cancels auto-release timer" do
      model_id = "test-model-#{System.unique_integer()}"
      agent_id = "test-agent-1"

      {:ok, _} =
        ModelIsolation.isolate(model_id, agent_id,
          mode: :full,
          duration_seconds: 60
        )

      # Release immediately
      {:ok, state} = ModelIsolation.release(model_id)
      assert state.status == :active

      # Wait a bit and verify still active (timer was cancelled)
      Process.sleep(100)
      {:ok, state} = ModelIsolation.get_state(model_id)
      assert state.status == :active
    end
  end

  describe "concurrent operations" do
    test "handles concurrent isolation attempts" do
      model_id = "test-model-concurrent"
      agent_id = "test-agent-1"

      {:ok, _} = ModelIsolation.register(model_id, agent_id)

      # Spawn multiple concurrent isolation attempts
      tasks =
        for i <- 1..10 do
          Task.async(fn ->
            ModelIsolation.isolate(model_id, agent_id, reason: "Attempt #{i}")
          end)
        end

      results = Enum.map(tasks, &Task.await/1)

      # Exactly one should succeed, rest should fail
      successes = Enum.filter(results, fn r -> match?({:ok, _}, r) end)
      failures = Enum.filter(results, fn r -> match?({:error, :already_isolated}, r) end)

      assert length(successes) == 1
      assert length(failures) == 9
    end
  end

  describe "register/3" do
    test "registers new model in active state" do
      model_id = "test-model-#{System.unique_integer()}"
      agent_id = "test-agent-1"

      assert {:ok, state} = ModelIsolation.register(model_id, agent_id)
      assert state.status == :active
      assert state.isolation_mode == :none
      assert state.model_id == model_id
      assert state.agent_id == agent_id
    end

    test "stores metadata with registration" do
      model_id = "test-model-#{System.unique_integer()}"
      agent_id = "test-agent-1"
      metadata = %{"model_type" => "llama", "version" => "3.1"}

      {:ok, state} = ModelIsolation.register(model_id, agent_id, metadata: metadata)
      assert state.metadata == metadata
    end
  end

  describe "exists?/1" do
    test "returns true for tracked model" do
      model_id = "test-model-#{System.unique_integer()}"
      {:ok, _} = ModelIsolation.register(model_id, "agent-1")

      assert ModelIsolation.exists?(model_id)
    end

    test "returns false for untracked model" do
      refute ModelIsolation.exists?("nonexistent-model")
    end
  end
end
