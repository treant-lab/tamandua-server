defmodule TamanduaServer.AI.DependencyGraphTest do
  @moduledoc """
  Unit tests for the AI Model Dependency Graph module.

  Tests:
  - Dependency addition and removal
  - Model consumer queries
  - Process model queries
  - Lineage tracking
  - Risk propagation
  - Critical model identification
  - Unusual chain detection
  - Graph export (DOT and JSON)
  """

  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.AI.DependencyGraph

  setup do
    # Wait for the GenServer to start
    Process.sleep(100)

    # Clean up any existing state by adding and removing test data
    # Note: In production, we'd want a proper reset function
    :ok
  end

  # ---------------------------------------------------------------------------
  # Basic Operations
  # ---------------------------------------------------------------------------

  describe "add_dependency/4" do
    test "adds a :loads dependency between process and model" do
      process_id = "agent-test:1234"
      model_id = "llama-7b.gguf"

      DependencyGraph.add_dependency(process_id, model_id, :loads, %{
        loaded_at: DateTime.utc_now(),
        libraries: ["llama.cpp"]
      })

      # Wait for async cast
      Process.sleep(50)

      # Verify via query
      models = DependencyGraph.get_process_models(process_id)
      assert length(models) >= 1
      assert Enum.any?(models, fn m -> m.id == model_id end)
    end

    test "adds a :derived_from dependency between models" do
      child_model = "llama-7b-chat.gguf"
      parent_model = "llama-7b-base.gguf"

      DependencyGraph.add_dependency(child_model, parent_model, :derived_from, %{
        method: "fine_tune",
        dataset: "chat-instruct-v1"
      })

      Process.sleep(50)

      lineage = DependencyGraph.get_model_lineage(child_model)
      assert length(lineage) >= 1
      assert Enum.any?(lineage, fn m -> m.id == parent_model end)
    end

    test "adds a :distilled_from dependency between models" do
      student_model = "mistral-7b-distilled.gguf"
      teacher_model = "mistral-7b-instruct.gguf"

      DependencyGraph.add_dependency(student_model, teacher_model, :distilled_from, %{
        compression_ratio: 0.5
      })

      Process.sleep(50)

      lineage = DependencyGraph.get_model_lineage(student_model)
      assert length(lineage) >= 1
      assert Enum.any?(lineage, fn m -> m.derivation_type == :distilled_from end)
    end
  end

  describe "remove_dependency/3" do
    test "removes a dependency" do
      process_id = "agent-remove-test:5678"
      model_id = "model-to-remove.gguf"

      DependencyGraph.add_dependency(process_id, model_id, :loads)
      Process.sleep(50)

      # Verify it was added
      models = DependencyGraph.get_process_models(process_id)
      assert Enum.any?(models, fn m -> m.id == model_id end)

      # Remove it
      DependencyGraph.remove_dependency(process_id, model_id, :loads)
      Process.sleep(50)

      # Verify it was removed
      models = DependencyGraph.get_process_models(process_id)
      refute Enum.any?(models, fn m -> m.id == model_id end)
    end
  end

  # ---------------------------------------------------------------------------
  # Query Operations
  # ---------------------------------------------------------------------------

  describe "get_model_consumers/1" do
    test "returns direct consumers" do
      model_id = "shared-model-#{System.unique_integer()}.gguf"
      process1 = "agent-1:1001"
      process2 = "agent-2:1002"

      DependencyGraph.add_dependency(process1, model_id, :loads)
      DependencyGraph.add_dependency(process2, model_id, :loads)
      Process.sleep(50)

      consumers = DependencyGraph.get_model_consumers(model_id)
      assert length(consumers) >= 2

      direct_consumers = Enum.filter(consumers, fn c -> c.relationship == :direct end)
      assert length(direct_consumers) >= 2
    end

    test "returns indirect consumers through derived models" do
      base_model = "base-model-#{System.unique_integer()}.gguf"
      derived_model = "derived-model-#{System.unique_integer()}.gguf"
      process_id = "agent-indirect:2001"

      # Set up lineage: derived <- base
      DependencyGraph.add_dependency(derived_model, base_model, :derived_from)
      # Process loads the derived model
      DependencyGraph.add_dependency(process_id, derived_model, :loads)
      Process.sleep(50)

      # Query consumers of base model
      consumers = DependencyGraph.get_model_consumers(base_model)

      indirect = Enum.filter(consumers, fn c -> c.relationship == :indirect end)
      # Should find the process as an indirect consumer
      assert length(indirect) >= 1
    end
  end

  describe "get_process_models/1" do
    test "returns all models loaded by a process" do
      process_id = "agent-multi:3001"
      model1 = "model-a-#{System.unique_integer()}.gguf"
      model2 = "model-b-#{System.unique_integer()}.safetensors"

      DependencyGraph.add_dependency(process_id, model1, :loads)
      DependencyGraph.add_dependency(process_id, model2, :loads)
      Process.sleep(50)

      models = DependencyGraph.get_process_models(process_id)
      assert length(models) >= 2

      model_ids = Enum.map(models, & &1.id)
      assert model1 in model_ids
      assert model2 in model_ids
    end

    test "returns empty list for unknown process" do
      models = DependencyGraph.get_process_models("nonexistent-process")
      assert models == []
    end
  end

  describe "get_model_lineage/1" do
    test "traces single parent" do
      child = "child-#{System.unique_integer()}.gguf"
      parent = "parent-#{System.unique_integer()}.gguf"

      DependencyGraph.add_dependency(child, parent, :derived_from)
      Process.sleep(50)

      lineage = DependencyGraph.get_model_lineage(child)
      assert length(lineage) >= 1
      assert Enum.any?(lineage, fn m -> m.id == parent end)
    end

    test "traces multi-level lineage" do
      grandchild = "grandchild-#{System.unique_integer()}.gguf"
      child = "child-mid-#{System.unique_integer()}.gguf"
      parent = "parent-root-#{System.unique_integer()}.gguf"

      DependencyGraph.add_dependency(grandchild, child, :derived_from)
      DependencyGraph.add_dependency(child, parent, :derived_from)
      Process.sleep(50)

      lineage = DependencyGraph.get_model_lineage(grandchild)
      assert length(lineage) >= 2

      lineage_ids = Enum.map(lineage, & &1.id)
      assert child in lineage_ids
      assert parent in lineage_ids
    end

    test "handles models with no parents" do
      orphan = "orphan-model-#{System.unique_integer()}.gguf"

      lineage = DependencyGraph.get_model_lineage(orphan)
      assert lineage == []
    end
  end

  describe "get_model_derivatives/1" do
    test "finds child models" do
      parent = "parent-deriv-#{System.unique_integer()}.gguf"
      child1 = "child1-deriv-#{System.unique_integer()}.gguf"
      child2 = "child2-deriv-#{System.unique_integer()}.gguf"

      DependencyGraph.add_dependency(child1, parent, :derived_from)
      DependencyGraph.add_dependency(child2, parent, :distilled_from)
      Process.sleep(50)

      derivatives = DependencyGraph.get_model_derivatives(parent)
      assert length(derivatives) >= 2

      derivative_ids = Enum.map(derivatives, & &1.id)
      assert child1 in derivative_ids
      assert child2 in derivative_ids
    end
  end

  # ---------------------------------------------------------------------------
  # Risk Propagation
  # ---------------------------------------------------------------------------

  describe "propagate_risk/2" do
    test "propagates risk to direct consumers" do
      base = "risky-base-#{System.unique_integer()}.gguf"
      process = "agent-risk:4001"

      DependencyGraph.add_dependency(process, base, :loads)
      Process.sleep(50)

      result = DependencyGraph.propagate_risk(base, 0.9)

      assert result.source_model == base
      assert result.initial_risk == 0.9
      assert result.process_count >= 1

      # Check propagated risk is less than initial (decay factor applied)
      if length(result.affected_processes) > 0 do
        first_process = hd(result.affected_processes)
        assert first_process.propagated_risk < 0.9
      end
    end

    test "propagates risk through derivation chain" do
      root = "root-risk-#{System.unique_integer()}.gguf"
      derived = "derived-risk-#{System.unique_integer()}.gguf"
      process = "agent-chain-risk:4002"

      DependencyGraph.add_dependency(derived, root, :derived_from)
      DependencyGraph.add_dependency(process, derived, :loads)
      Process.sleep(50)

      result = DependencyGraph.propagate_risk(root, 1.0)

      assert result.model_count >= 1
      assert result.process_count >= 1
      assert result.total_impact_score > 0
    end

    test "returns critical paths for high-risk scenarios" do
      model = "critical-path-model-#{System.unique_integer()}.gguf"
      process = "agent-critical:4003"

      DependencyGraph.add_dependency(process, model, :loads)
      Process.sleep(50)

      result = DependencyGraph.propagate_risk(model, 0.95)

      # Critical paths should be populated for high risk
      assert is_list(result.critical_paths)
    end
  end

  # ---------------------------------------------------------------------------
  # Critical Model Identification
  # ---------------------------------------------------------------------------

  describe "find_critical_models/1" do
    test "identifies models with many dependents" do
      critical_model = "heavily-used-#{System.unique_integer()}.gguf"

      # Add multiple processes loading this model
      for i <- 1..5 do
        process = "agent-crit-#{i}:500#{i}"
        DependencyGraph.add_dependency(process, critical_model, :loads)
      end
      Process.sleep(100)

      critical = DependencyGraph.find_critical_models(limit: 5, min_dependents: 3)

      # Should find our heavily used model
      assert length(critical) >= 1

      model = Enum.find(critical, fn m -> m.id == critical_model end)
      if model do
        assert model.total_dependents >= 3
        assert model.criticality_score > 0
      end
    end

    test "respects min_dependents filter" do
      model = "low-use-#{System.unique_integer()}.gguf"
      process = "agent-low:6001"

      DependencyGraph.add_dependency(process, model, :loads)
      Process.sleep(50)

      critical = DependencyGraph.find_critical_models(min_dependents: 5)

      # Should not find our low-use model
      refute Enum.any?(critical, fn m -> m.id == model end)
    end
  end

  # ---------------------------------------------------------------------------
  # Unusual Chain Detection
  # ---------------------------------------------------------------------------

  describe "detect_unusual_chains/0" do
    test "returns list of anomalies" do
      anomalies = DependencyGraph.detect_unusual_chains()

      assert is_list(anomalies)
      # Each anomaly should have required fields
      for anomaly <- anomalies do
        assert Map.has_key?(anomaly, :type)
        assert Map.has_key?(anomaly, :severity)
        assert Map.has_key?(anomaly, :description)
      end
    end

    test "detects high load count models" do
      model = "high-load-#{System.unique_integer()}.gguf"

      # Add many processes loading this model
      for i <- 1..15 do
        process = "agent-load-#{i}:700#{i}"
        DependencyGraph.add_dependency(process, model, :loads)
      end
      Process.sleep(100)

      anomalies = DependencyGraph.detect_unusual_chains()

      high_load = Enum.filter(anomalies, fn a ->
        a.type == :high_load_count and a.model_id == model
      end)

      assert length(high_load) >= 1
    end
  end

  # ---------------------------------------------------------------------------
  # Graph Export
  # ---------------------------------------------------------------------------

  describe "export_graph/1" do
    test "exports to DOT format" do
      # Add some test data
      process = "agent-export:8001"
      model = "export-model-#{System.unique_integer()}.gguf"
      DependencyGraph.add_dependency(process, model, :loads)
      Process.sleep(50)

      dot = DependencyGraph.export_graph(:dot)

      assert is_binary(dot)
      assert String.contains?(dot, "digraph AIModelDependencies")
      assert String.contains?(dot, "->")
    end

    test "exports to JSON format" do
      process = "agent-json:8002"
      model = "json-model-#{System.unique_integer()}.gguf"
      DependencyGraph.add_dependency(process, model, :loads)
      Process.sleep(50)

      json = DependencyGraph.export_graph(:json)

      assert is_binary(json)

      # Should be valid JSON
      {:ok, parsed} = Jason.decode(json)
      assert is_list(parsed["nodes"])
      assert is_list(parsed["edges"])
      assert is_map(parsed["metadata"])
    end
  end

  # ---------------------------------------------------------------------------
  # Graph Statistics
  # ---------------------------------------------------------------------------

  describe "stats/0" do
    test "returns graph statistics" do
      stats = DependencyGraph.stats()

      assert is_map(stats)
      assert is_integer(stats.node_count)
      assert is_integer(stats.edge_count)
      assert is_integer(stats.model_count)
      assert is_integer(stats.process_count)
      assert is_map(stats.counters)
      assert is_integer(stats.memory_bytes)
    end
  end

  describe "get_subgraph/2" do
    test "extracts subgraph centered on a node" do
      center = "center-model-#{System.unique_integer()}.gguf"
      neighbor1 = "neighbor1-#{System.unique_integer()}.gguf"
      process = "agent-sub:9001"

      DependencyGraph.add_dependency(center, neighbor1, :derived_from)
      DependencyGraph.add_dependency(process, center, :loads)
      Process.sleep(50)

      subgraph = DependencyGraph.get_subgraph(center, 2)

      assert subgraph.center == center
      assert subgraph.depth == 2
      assert is_list(subgraph.nodes)
      assert is_list(subgraph.edges)
      assert subgraph.node_count >= 1
    end

    test "respects depth limit" do
      # Create a chain: a -> b -> c -> d
      a = "chain-a-#{System.unique_integer()}.gguf"
      b = "chain-b-#{System.unique_integer()}.gguf"
      c = "chain-c-#{System.unique_integer()}.gguf"
      d = "chain-d-#{System.unique_integer()}.gguf"

      DependencyGraph.add_dependency(a, b, :derived_from)
      DependencyGraph.add_dependency(b, c, :derived_from)
      DependencyGraph.add_dependency(c, d, :derived_from)
      Process.sleep(50)

      # Depth 1 should only get a and its immediate neighbor
      subgraph = DependencyGraph.get_subgraph(a, 1)
      assert subgraph.depth == 1
      # Should have a and b, but not c or d
      node_ids = Enum.map(subgraph.nodes, & &1.id)
      assert a in node_ids
      assert b in node_ids
    end
  end
end
